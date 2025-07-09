use std::collections::HashMap;
use crate::egui_tools::EguiRenderer;
use egui_wgpu::wgpu::SurfaceError;
use egui_wgpu::{wgpu, ScreenDescriptor};
use std::sync::{Arc, Mutex};
use std::time::Instant;
use capstone::{Capstone, Endian};
use egui::{Color32, FontId, Grid, RichText, ScrollArea, TextStyle};
use egui_extras::{Column, TableBuilder};
use winit::application::ApplicationHandler;
use winit::dpi::PhysicalSize;
use winit::event::WindowEvent;
use winit::event_loop::ActiveEventLoop;
use winit::window::{Window, WindowId};
use librustee::Bus;
use librustee::ee::{EE, Interpreter, JIT};
use librustee::cpu::EmulationBackend;
use capstone::arch::BuildsCapstone;
use capstone::arch::BuildsCapstoneEndian;
use capstone::arch::mips::ArchMode::Mips64;
use librustee::cpu::CPU;

pub struct AppState {
    pub device: wgpu::Device,
    pub queue: wgpu::Queue,
    pub surface_config: wgpu::SurfaceConfiguration,
    pub surface: wgpu::Surface<'static>,
    pub scale_factor: f32,
    pub egui_renderer: EguiRenderer,
}

impl AppState {
    async fn new(
        instance: &wgpu::Instance,
        surface: wgpu::Surface<'static>,
        window: &Window,
        width: u32,
        height: u32,
    ) -> Self {
        let power_pref = wgpu::PowerPreference::default();
        let adapter = instance
            .request_adapter(&wgpu::RequestAdapterOptions {
                power_preference: power_pref,
                force_fallback_adapter: false,
                compatible_surface: Some(&surface),
            })
            .await
            .expect("Failed to find an appropriate adapter");

        let features = wgpu::Features::empty();
        let (device, queue) = adapter
            .request_device(
                &wgpu::DeviceDescriptor {
                    label: None,
                    required_features: features,
                    required_limits: Default::default(),
                    memory_hints: Default::default(),
                },
                None,
            )
            .await
            .expect("Failed to create device");

        let swapchain_capabilities = surface.get_capabilities(&adapter);
        let selected_format = wgpu::TextureFormat::Bgra8UnormSrgb;
        let swapchain_format = swapchain_capabilities
            .formats
            .iter()
            .find(|d| **d == selected_format)
            .expect("failed to select proper surface texture format!");

        let surface_config = wgpu::SurfaceConfiguration {
            usage: wgpu::TextureUsages::RENDER_ATTACHMENT,
            format: *swapchain_format,
            width,
            height,
            present_mode: wgpu::PresentMode::AutoVsync,
            desired_maximum_frame_latency: 0,
            alpha_mode: swapchain_capabilities.alpha_modes[0],
            view_formats: vec![],
        };

        surface.configure(&device, &surface_config);

        let egui_renderer = EguiRenderer::new(&device, surface_config.format, None, 1, window);

        let scale_factor = 1.0;

        Self {
            device,
            queue,
            surface,
            surface_config,
            egui_renderer,
            scale_factor,
        }
    }

    fn resize_surface(&mut self, width: u32, height: u32) {
        self.surface_config.width = width;
        self.surface_config.height = height;
        self.surface.configure(&self.device, &self.surface_config);
    }
}

pub struct Disassembler {
    cs: Capstone,
}

impl Disassembler {
    pub fn new() -> Result<Self, capstone::Error> {
        let cs = Capstone::new()
            .mips()
            .mode(Mips64)
            .endian(Endian::Little)
            .build()?;

        Ok(Self { cs })
    }

    pub fn disassemble(&self, bytes: &[u8], base_addr: u64) -> Result<Vec<String>, capstone::Error> {
        let insns = self.cs.disasm_all(bytes, base_addr)?;

        let mut results = Vec::new();
        for insn in insns.iter() {
            let disassembled = format!(
                "0x{:08x}:\t{}\t{}",
                insn.address(),
                insn.mnemonic().unwrap_or(""),
                insn.op_str().unwrap_or("")
            );
            results.push(disassembled);
        }

        Ok(results)
    }
}

pub struct App {
    instance: wgpu::Instance,
    state: Option<AppState>,
    window: Option<Arc<Window>>,
    ee_backend: Box<dyn EmulationBackend<EE>>,
    ee: Arc<Mutex<EE>>,
    bus: Arc<Mutex<Box<Bus>>>,
    last_frame_time: Instant,
    selected_ee_tab: usize,
    prev_ee_registers: HashMap<usize, u128>,
    change_ee_timers: HashMap<usize, f32>,
    prev_cop0_registers: HashMap<usize, u32>,
    cop0_change_ee_timers: HashMap<usize, f32>,
    disassembly_open: bool,
    disassembly_data: Vec<String>,
    disassembler: Disassembler,
    disassembly_start_addr: u32,
    address_input: String,
    follow_pc: bool,
}

impl App {
    pub fn new(ee: Arc<Mutex<EE>>, bus: Arc<Mutex<Box<Bus>>>, backend: String) -> Self {
        let ee_backend: Box<dyn EmulationBackend<EE>> = match backend.as_str() {
            "interpreter" => {
                let cloned_ee = ee.lock().unwrap().clone();
                Box::new(Interpreter::new(cloned_ee))
            }
            "jit" => {
                let cloned_ee = Box::new(ee.lock().unwrap().clone());
                let static_ee: &'static mut EE = Box::leak(cloned_ee);
                Box::new(JIT::new(static_ee))
            }
            _ => panic!("Unsupported backend: {}", backend),
        };

        App {
            instance: egui_wgpu::wgpu::Instance::new(&wgpu::InstanceDescriptor::default()),
            state: None,
            window: None,
            ee_backend,
            ee,
            bus,
            last_frame_time: Instant::now(),
            selected_ee_tab: 0,
            prev_ee_registers: HashMap::new(),
            change_ee_timers: HashMap::new(),
            prev_cop0_registers: HashMap::new(),
            cop0_change_ee_timers: HashMap::new(),
            disassembler: Disassembler::new().unwrap(),
            disassembly_open: false,
            disassembly_data: Vec::new(),
            disassembly_start_addr: 0,
            address_input: "0x0".to_string(),
            follow_pc: true,
        }
    }

    async fn set_window(&mut self, window: Window) {
        let window = Arc::new(window);
        let initial_width = 1360;
        let initial_height = 768;

        let _ = window.request_inner_size(PhysicalSize::new(initial_width, initial_height));

        let surface = self
            .instance
            .create_surface(window.clone())
            .expect("Failed to create surface!");

        let state = AppState::new(
            &self.instance,
            surface,
            &window,
            initial_width,
            initial_width,
        )
            .await;

        self.window.get_or_insert(window);
        self.state.get_or_insert(state);
    }

    fn handle_resized(&mut self, width: u32, height: u32) {
        if width > 0 && height > 0 {
            self.state.as_mut().unwrap().resize_surface(width, height);
        }
    }

    fn handle_redraw(&mut self) {
        let now = Instant::now();
        let delta = now.duration_since(self.last_frame_time).as_secs_f32();
        self.last_frame_time = now;

        if let Some(window) = self.window.as_ref() {
            if let Some(min) = window.is_minimized() {
                if min {
                    println!("Window is minimized");
                    return;
                }
            }
        }

        let state = self.state.as_mut().unwrap();

        let screen_descriptor = ScreenDescriptor {
            size_in_pixels: [state.surface_config.width, state.surface_config.height],
            pixels_per_point: self.window.as_ref().unwrap().scale_factor() as f32 * state.scale_factor,
        };

        let surface_texture = state.surface.get_current_texture();

        match surface_texture {
            Err(SurfaceError::Outdated) => {
                println!("wgpu surface outdated");
                return;
            }
            Err(_) => {
                surface_texture.expect("Failed to acquire next swap chain texture");
                return;
            }
            Ok(_) => {}
        };

        let surface_texture = surface_texture.unwrap();

        let surface_view = surface_texture
            .texture
            .create_view(&wgpu::TextureViewDescriptor::default());

        let mut encoder = state
            .device
            .create_command_encoder(&wgpu::CommandEncoderDescriptor { label: None });

        let window = self.window.as_ref().unwrap();

        {
            state.egui_renderer.begin_frame(window);

            egui::Window::new("EE CPU State").show(state.egui_renderer.context(), |ui| {
                if let Ok(ee) = self.ee_backend.get_cpu().lock() {
                    for (i, &value) in ee.registers.iter().enumerate() {
                        if let Some(prev_value) = self.prev_ee_registers.get(&i) {
                            if *prev_value != value {
                                self.change_ee_timers.insert(i, 1.0);
                            }
                        }
                        self.prev_ee_registers.insert(i, value);
                    }

                    for timer in self.change_ee_timers.values_mut() {
                        *timer -= delta;
                    }
                    self.change_ee_timers.retain(|_, &mut timer| timer > 0.0);

                    let cop0 = ee.cop0_registers.read().unwrap();
                    for (i, &value) in cop0.iter().enumerate() {
                        if let Some(prev_value) = self.prev_cop0_registers.get(&i) {
                            if *prev_value != value {
                                self.cop0_change_ee_timers.insert(i, 1.0);
                            }
                        }
                        self.prev_cop0_registers.insert(i, value);
                    }

                    for timer in self.cop0_change_ee_timers.values_mut() {
                        *timer -= delta;
                    }
                    self.cop0_change_ee_timers.retain(|_, &mut timer| timer > 0.0);

                    ui.horizontal(|ui| {
                        ui.selectable_value(&mut self.selected_ee_tab, 0, "GP Registers");
                        ui.selectable_value(&mut self.selected_ee_tab, 1, "COP0 Registers");
                    });

                    ui.separator();

                    match self.selected_ee_tab {
                        0 => {
                            ScrollArea::both()
                                .max_height(ui.available_height())
                                .show(ui, |ui| {
                                    TableBuilder::new(ui)
                                        .striped(true)
                                        .column(Column::auto().resizable(true))
                                        .column(Column::remainder())
                                        .header(20.0, |mut header| {
                                            header.col(|ui| { ui.label("Name"); });
                                            header.col(|ui| { ui.label("Value"); });
                                        })
                                        .body(|mut body| {
                                            for (i, &value) in ee.registers.iter().enumerate() {
                                                let name = [
                                                    "zr", "at", "v0", "v1", "a0", "a1", "a2", "a3",
                                                    "t0", "t1", "t2", "t3", "t4", "t5", "t6", "t7",
                                                    "s0", "s1", "s2", "s3", "s4", "s5", "s6", "s7",
                                                    "t8", "t9", "k0", "k1", "gp", "sp", "fp", "ra",
                                                ].get(i).unwrap_or(&"UNK");

                                                let animation_progress = self
                                                    .change_ee_timers
                                                    .get(&i)
                                                    .cloned()
                                                    .unwrap_or(0.0);

                                                let text_color = if animation_progress > 0.0 {
                                                    let t = animation_progress;
                                                    let r = 255.0;
                                                    let g = 255.0 * (1.0 - t);
                                                    let b = 255.0 * (1.0 - t);
                                                    egui::Color32::from_rgb(r as u8, g as u8, b as u8)
                                                } else {
                                                    egui::Color32::WHITE
                                                };

                                                body.row(18.0, |mut row| {
                                                    row.col(|ui| { ui.label(*name); });
                                                    row.col(|ui| {
                                                        ui.colored_label(
                                                            text_color,
                                                            format!("{:#034X}", value),
                                                        );
                                                    });
                                                });
                                            }

                                            body.row(1.0, |mut row| {
                                                row.col(|ui| { ui.separator(); });
                                            });

                                            body.row(18.0, |mut row| {
                                                row.col(|ui| { ui.label("hi"); });
                                                row.col(|ui| { ui.colored_label(egui::Color32::WHITE, format!("{:#034X}", ee.hi)); });
                                            });
                                            body.row(18.0, |mut row| {
                                                row.col(|ui| { ui.label("lo"); });
                                                row.col(|ui| { ui.colored_label(egui::Color32::WHITE, format!("{:#034X}", ee.lo)); });
                                            });
                                            body.row(18.0, |mut row| {
                                                row.col(|ui| { ui.label("pc"); });
                                                row.col(|ui| { ui.colored_label(egui::Color32::WHITE, format!("{:#010X}", ee.pc)); });
                                            });
                                        });
                                });
                        }
                        1 => {
                            ScrollArea::both()
                                .max_width(f32::INFINITY)
                                .max_height(ui.available_height())
                                .show(ui, |ui| {
                                    TableBuilder::new(ui)
                                        .striped(true)
                                        .column(Column::auto().resizable(true))
                                        .column(Column::remainder())
                                        .header(20.0, |mut header| {
                                            header.col(|ui| { ui.label("Register"); });
                                            header.col(|ui| { ui.label("Value"); });
                                        })
                                        .body(|mut body| {
                                            let cop0 = ee.cop0_registers.read().unwrap();
                                            for (i, &value) in cop0.iter().enumerate() {
                                                let name = [
                                                    "Index", "Random", "EntryLo0", "EntryLo1", "Context",
                                                    "PageMask", "Wired", "", "BadVAddr", "Count", "EntryHi",
                                                    "Compare", "Status", "Cause", "EPC", "PRId", "Config",
                                                    "", "", "", "", "", "", "BadPAddr", "Debug", "Perf",
                                                    "", "", "TagLo", "TagHi", "ErrorEPC", ""
                                                ].get(i).unwrap_or(&"UNK");

                                                if name.is_empty() { continue; }

                                                let animation_progress = self
                                                    .cop0_change_ee_timers
                                                    .get(&i)
                                                    .copied()
                                                    .unwrap_or(0.0);

                                                let text_color = if animation_progress > 0.0 {
                                                    let t = animation_progress;
                                                    let r = 255.0;
                                                    let g = 255.0 * (1.0 - t);
                                                    let b = 255.0 * (1.0 - t);
                                                    egui::Color32::from_rgb(r as u8, g as u8, b as u8)
                                                } else {
                                                    egui::Color32::WHITE
                                                };

                                                body.row(18.0, |mut row| {
                                                    row.col(|ui| { ui.label(*name); });
                                                    row.col(|ui| {
                                                        ui.colored_label(
                                                            text_color,
                                                            format!("{:#010X}", value),
                                                        );
                                                    });
                                                });
                                            }
                                        });
                                });
                        }
                        _ => {}
                    }
                } else {
                    ui.label("Unable to lock CPU state.");
                }
            });

            egui::TopBottomPanel::bottom("EE Taskbar").show(state.egui_renderer.context(), |ui| {
                ui.horizontal(|ui| {
                    if ui.button("Step").clicked() {
                        self.ee_backend.step();
                    }
                    if ui.button("Run").clicked() {
                        self.ee_backend.run();
                    }
                    if ui.button("Reset").clicked() {
                        // Reset logic
                    }

                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        ui.label(format!("Frame Time: {:.2} ms", delta * 1000.0));
                    });
                });
            });

            egui::TopBottomPanel::top("Menubar").show(state.egui_renderer.context(), |ui| {
                ui.horizontal(|ui| {
                    if ui.button("Toggle Disassembly").clicked() {
                        self.disassembly_open = !self.disassembly_open;
                    }
                });
            });

            if self.disassembly_open {
                if let Ok(mut ee) = self.ee_backend.get_cpu().lock() {
                    if self.follow_pc {
                        self.disassembly_start_addr = ee.pc;
                    }

                    let pc = ee.pc;
                    let num_instructions = 16;
                    let mut bytes = Vec::new();
                    for offset in 0..num_instructions {
                        let addr = pc.wrapping_add(offset * 4);
                        let word = ee.read32_raw(addr);
                        bytes.extend_from_slice(&word.to_le_bytes());
                    }

                    let disasm = self.disassembler.disassemble(&bytes, pc as u64).unwrap_or_else(|err| {
                        eprintln!("Error during disassembly: {}", err);
                        vec!["Disassembly error".to_string()]
                    });

                    egui::Window::new("Disassembly")
                        .resizable(true)
                        .default_size(egui::vec2(400.0, 300.0))
                        .show(state.egui_renderer.context(), |ui| {
                            egui::ScrollArea::both()
                                .auto_shrink([false, false])
                                .show(ui, |ui| {
                                    let current_pc = ee.pc as u64;
                                    let style = ui.style();
                                    let mono_font: FontId = style.text_styles[&TextStyle::Monospace].clone();
                                    let available_width = ui.available_width();
                                    ui.set_min_width(available_width);

                                    Grid::new("disasm_grid")
                                        .spacing([10.0, 4.0])
                                        .min_col_width(0f32)
                                        .show(ui, |ui| {
                                            for line in &disasm {
                                                if let Some((addr_str, rest)) = line.split_once(':') {
                                                    let address = u64::from_str_radix(addr_str.trim_start_matches("0x"), 16)
                                                        .unwrap_or(0);
                                                    let addr_text = RichText::new(format!("0x{:08x}:", address))
                                                        .font(mono_font.clone())
                                                        .color(if address == current_pc { Color32::LIGHT_BLUE } else { Color32::GRAY });

                                                    let (mnemonic, operands) = if let Some((m, ops)) = rest.trim().split_once('\t') {
                                                        (m, ops)
                                                    } else {
                                                        (rest.trim(), "")
                                                    };

                                                    let mnemonic_text = RichText::new(mnemonic)
                                                        .font(mono_font.clone())
                                                        .color(Color32::LIGHT_GREEN);

                                                    let operands_text = RichText::new(operands)
                                                        .font(mono_font.clone())
                                                        .color(Color32::WHITE);

                                                    ui.label(addr_text);
                                                    ui.label(mnemonic_text);
                                                    ui.label(operands_text);
                                                    ui.end_row();
                                                }
                                            }
                                        });
                                });
                        });


                }
            }

            state.egui_renderer.end_frame_and_draw(
                &state.device,
                &state.queue,
                &mut encoder,
                window,
                &surface_view,
                screen_descriptor,
            );
        }

        state.queue.submit(Some(encoder.finish()));
        surface_texture.present();
    }

}

impl ApplicationHandler for App {
    fn resumed(&mut self, event_loop: &ActiveEventLoop) {
        let window = event_loop
            .create_window(Window::default_attributes())
            .unwrap();
        pollster::block_on(self.set_window(window));
    }

    fn window_event(&mut self, event_loop: &ActiveEventLoop, _: WindowId, event: WindowEvent) {
        // let egui render to process the event first
        self.state
            .as_mut()
            .unwrap()
            .egui_renderer
            .handle_input(self.window.as_ref().unwrap(), &event);

        match event {
            WindowEvent::CloseRequested => {
                println!("The close button was pressed; stopping");
                event_loop.exit();
            }
            WindowEvent::RedrawRequested => {
                self.handle_redraw();

                self.window.as_ref().unwrap().request_redraw();
            }
            WindowEvent::Resized(new_size) => {
                self.handle_resized(new_size.width, new_size.height);
            }
            _ => (),
        }
    }
}
