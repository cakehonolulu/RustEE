use crate::egui_tools::EguiRenderer;
use capstone::arch::BuildsCapstone;
use capstone::arch::BuildsCapstoneEndian;
use capstone::arch::mips::ArchMode::Mips64;
use capstone::{Capstone, Endian};
use egui::{Color32, FontId, Grid, RichText, ScrollArea, TextStyle};
use egui_extras::{Column, TableBuilder};
use egui_plot::{Line, Plot, PlotPoints};
use egui_wgpu::{ScreenDescriptor, wgpu};
use librustee::Bus;
use librustee::bus::tlb::TlbEntry;
use librustee::cpu::CPU;
use librustee::cpu::EmulationBackend;
use librustee::ee::{EE, Interpreter, JIT};
use librustee::gs::renderer::RendererKind;
use librustee::sched::DebugRequest;
use librustee::sched::DebugResponse;
use librustee::sched::FrameData;
use librustee::sched::FrameReceiver;
use librustee::sched::Scheduler;
use std::collections::HashMap;
use std::collections::VecDeque;
use std::ptr::NonNull;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::Instant;
use winit::application::ApplicationHandler;
use winit::dpi::PhysicalSize;
use winit::event::WindowEvent;
use winit::event_loop::ActiveEventLoop;
use winit::window::{Window, WindowId};

pub struct AppState {
    pub device: wgpu::Device,
    pub queue: wgpu::Queue,
    pub surface_config: wgpu::SurfaceConfiguration,
    pub surface: wgpu::Surface<'static>,
    pub scale_factor: f32,
    pub egui_renderer: EguiRenderer,
    pub gs_texture: wgpu::Texture,
    pub gs_texture_id: egui::TextureId,
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
            .request_device(&wgpu::DeviceDescriptor {
                label: None,
                required_features: features,
                required_limits: Default::default(),
                memory_hints: Default::default(),
                experimental_features: Default::default(),
                trace: Default::default(),
            })
            .await
            .expect("Failed to create device");

        let swapchain_capabilities = surface.get_capabilities(&adapter);
        let selected_format = wgpu::TextureFormat::Bgra8Unorm;
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

        let mut egui_renderer = EguiRenderer::new(&device, surface_config.format, None, 1, window);

        let scale_factor = 1.0;

        let gs_texture = device.create_texture(&wgpu::TextureDescriptor {
            label: Some("GS Framebuffer"),
            size: wgpu::Extent3d {
                width: 640,
                height: 480,
                depth_or_array_layers: 1,
            },
            mip_level_count: 1,
            sample_count: 1,
            dimension: wgpu::TextureDimension::D2,
            format: wgpu::TextureFormat::Rgba8Unorm,
            usage: wgpu::TextureUsages::TEXTURE_BINDING | wgpu::TextureUsages::COPY_DST,
            view_formats: &[],
        });

        let gs_texture_id = egui_renderer.renderer.register_native_texture(
            &device,
            &gs_texture.create_view(&Default::default()),
            wgpu::FilterMode::Linear,
        );

        Self {
            device,
            queue,
            surface,
            surface_config,
            egui_renderer,
            scale_factor,
            gs_texture,
            gs_texture_id,
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

    pub fn disassemble(
        &self,
        bytes: &[u8],
        base_addr: u64,
    ) -> Result<Vec<String>, capstone::Error> {
        let insns = self.cs.disasm_all(bytes, base_addr)?;
        let mut results = Vec::new();

        for insn in insns.iter() {
            // 1) pull out the raw bytes for this instruction…
            let raw = insn
                .bytes()
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect::<Vec<_>>()
                .join(" ");

            // 2) format PC, raw bytes, then mnemonic + operands
            let line = format!(
                "0x{:08x}:\t{:<11}\t{:<6}\t{}",
                insn.address(),
                raw,
                insn.mnemonic().unwrap_or(""),
                insn.op_str().unwrap_or("")
            );
            results.push(line);
        }

        Ok(results)
    }
}

pub struct App {
    instance: wgpu::Instance,
    state: Option<AppState>,
    window: Option<Arc<Window>>,
    ee: Arc<Mutex<EE>>,
    bus: Option<Box<Bus>>,
    last_frame_time: Instant,
    selected_ee_tab: usize,
    prev_ee_registers: HashMap<usize, u128>,
    change_ee_timers: HashMap<usize, f32>,
    prev_cop0_registers: HashMap<usize, u32>,
    cop0_change_ee_timers: HashMap<usize, f32>,
    disassembly_open: bool,
    disassembly_pc_cache: u32,
    disassembler: Disassembler,
    disassembly_start_addr: u32,
    address_input: String,
    follow_pc: bool,
    ram_view_open: bool,
    ram_view_addr: u32,
    ram_view_len: usize,
    tlb_view_open: bool,
    emulation_thread: Option<std::thread::JoinHandle<()>>,
    emu_backend: Option<Box<dyn EmulationBackend<EE> + Send>>,
    is_paused: Arc<AtomicBool>,
    frame_rx: Option<FrameReceiver>,
    debug_tx: mpsc::Sender<DebugRequest>,
    debug_rx: mpsc::Receiver<DebugResponse>,
    latest_frame: Option<FrameData>,
    scheduler: Arc<Mutex<Scheduler>>,
    ee_ctl_display_open: bool,
    vram_view_open: bool,
    vram_texture: Option<wgpu::Texture>,
    vram_texture_id: Option<egui::TextureId>,
    selected_renderer: RendererKind,
    backend_debug: Option<(mpsc::Receiver<DebugRequest>, mpsc::Sender<DebugResponse>)>,
    cached_ram_data: Vec<u8>,
    cached_tlb_entries: Vec<Option<TlbEntry>>,
    cached_disassembly_bytes: Vec<u8>,
    perf_view_open: bool,
    frontend_frametimes: VecDeque<f32>,
    backend_frametimes: VecDeque<f32>,
    drop_history: VecDeque<Instant>,
    total_dropped: u32,
}

impl App {
    pub fn new(
        ee: Arc<Mutex<EE>>,
        mut bus: Box<Bus>,
        frame_rx: FrameReceiver,
        backend: String,
        scheduler: Arc<Mutex<Scheduler>>,
    ) -> Self {
        let is_paused = ee.lock().unwrap().is_paused.clone();
        let cloned_ee = ee.lock().unwrap().clone();

        let bus_nonnull = NonNull::new(&mut *bus as *mut Bus).unwrap();

        let emu_backend: Box<dyn EmulationBackend<EE> + Send> = match backend.as_str() {
            "interpreter" => Box::new(Interpreter::new(cloned_ee)),
            "jit" => Box::new(JIT::new(cloned_ee, bus_nonnull)),
            _ => panic!("Unsupported backend: {}", backend),
        };

        let (frontend_debug, backend_channels) = librustee::sched::create_debug_channel();
        let (debug_tx, debug_rx) = frontend_debug;

        App {
            instance: egui_wgpu::wgpu::Instance::new(
                wgpu::InstanceDescriptor::new_without_display_handle(),
            ),
            state: None,
            window: None,
            ee,
            bus: Some(bus),
            frame_rx: Some(frame_rx),
            latest_frame: None,
            last_frame_time: Instant::now(),
            selected_ee_tab: 0,
            prev_ee_registers: HashMap::new(),
            change_ee_timers: HashMap::new(),
            prev_cop0_registers: HashMap::new(),
            cop0_change_ee_timers: HashMap::new(),
            disassembler: Disassembler::new().unwrap(),
            disassembly_open: false,
            disassembly_start_addr: 0,
            disassembly_pc_cache: 0,
            address_input: "0x0".to_string(),
            follow_pc: true,
            ram_view_open: false,
            ram_view_addr: 0x0000_0000,
            ram_view_len: 256, // show 256 bytes by default
            tlb_view_open: false,
            emulation_thread: None,
            emu_backend: Some(emu_backend),
            is_paused,
            scheduler,
            ee_ctl_display_open: false,
            vram_view_open: false,
            vram_texture: None,
            vram_texture_id: None,
            selected_renderer: RendererKind::Software,
            debug_tx,
            debug_rx,
            backend_debug: Some(backend_channels),
            cached_ram_data: Vec::new(),
            cached_tlb_entries: Vec::new(),
            cached_disassembly_bytes: Vec::new(),
            perf_view_open: false,
            frontend_frametimes: VecDeque::with_capacity(600),
            backend_frametimes: VecDeque::with_capacity(600),
            drop_history: VecDeque::new(),
            total_dropped: 0,
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

    fn compute_stats(history: &VecDeque<f32>) -> (f32, f32) {
        if history.is_empty() {
            return (0.0, 0.0);
        }

        let sum: f32 = history.iter().sum();
        let avg = sum / history.len() as f32;

        let mut sorted: Vec<f32> = history.iter().copied().collect();
        sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());

        let idx = (sorted.len() as f32 * 0.99) as usize;
        let one_pct_low = sorted.get(idx).copied().unwrap_or(avg);

        (avg, one_pct_low)
    }

    fn handle_redraw(&mut self) {
        let now = Instant::now();
        let delta = now.duration_since(self.last_frame_time).as_secs_f32();
        self.last_frame_time = now;

        self.frontend_frametimes.push_back(delta);
        if self.frontend_frametimes.len() > 600 {
            self.frontend_frametimes.pop_front();
        }

        if let Some(rx) = &self.frame_rx {
            while let Ok(frame) = rx.try_recv() {
                self.backend_frametimes.push_back(frame.backend_frametime);
                if self.backend_frametimes.len() > 600 {
                    self.backend_frametimes.pop_front();
                }

                self.total_dropped += frame.dropped_frames;
                for _ in 0..frame.dropped_frames {
                    self.drop_history.push_back(Instant::now());
                }

                self.latest_frame = Some(frame);
            }
        }

        let now = Instant::now();
        self.drop_history
            .retain(|&t| now.duration_since(t).as_secs_f32() <= 1.0);
        let drops_last_sec = self.drop_history.len();

        if let Some(window) = self.window.as_ref() {
            if let Some(min) = window.is_minimized() {
                if min {
                    return;
                }
            }
        }

        let state = self.state.as_mut().unwrap();

        let screen_descriptor = ScreenDescriptor {
            size_in_pixels: [state.surface_config.width, state.surface_config.height],
            pixels_per_point: self.window.as_ref().unwrap().scale_factor() as f32
                * state.scale_factor,
        };

        let surface_texture = match state.surface.get_current_texture() {
            wgpu::CurrentSurfaceTexture::Success(texture) => texture,
            wgpu::CurrentSurfaceTexture::Suboptimal(texture) => texture,
            wgpu::CurrentSurfaceTexture::Timeout | wgpu::CurrentSurfaceTexture::Occluded => {
                return;
            }
            wgpu::CurrentSurfaceTexture::Outdated | wgpu::CurrentSurfaceTexture::Lost => {
                state
                    .surface
                    .configure(&state.device, &state.surface_config);
                return;
            }
            wgpu::CurrentSurfaceTexture::Validation => {
                eprintln!("wgpu Surface Validation Error");
                return;
            }
        };

        while let Ok(res) = self.debug_rx.try_recv() {
            match res {
                DebugResponse::Ram { addr: _, data } => {
                    self.cached_ram_data = data;
                }
                DebugResponse::Tlb { entries } => {
                    self.cached_tlb_entries = entries;
                }
                DebugResponse::Disassembly { pc, bytes } => {
                    self.disassembly_pc_cache = pc;
                    self.cached_disassembly_bytes = bytes;
                }
            }
        }

        let (frame_data, original_width, original_height) = match &self.latest_frame {
            Some(f) => (Some(f.pixels.as_slice()), f.width, f.height),
            None => (None, 0u32, 0u32),
        };

        const TARGET_WIDTH: u32 = 640;
        const TARGET_HEIGHT: u32 = 480;

        let tex_width = if original_width > 0 {
            original_width
        } else {
            TARGET_WIDTH
        };
        let tex_height = if original_height > 0 {
            original_height
        } else {
            TARGET_HEIGHT
        };

        let current_texture_size: wgpu::Extent3d = state.gs_texture.size();
        if current_texture_size.width != tex_width || current_texture_size.height != tex_height {
            state
                .egui_renderer
                .renderer
                .free_texture(&state.gs_texture_id);

            state.gs_texture = state.device.create_texture(&wgpu::TextureDescriptor {
                label: Some("GS Framebuffer"),
                size: wgpu::Extent3d {
                    width: tex_width,
                    height: tex_height,
                    depth_or_array_layers: 1,
                },
                mip_level_count: 1,
                sample_count: 1,
                dimension: wgpu::TextureDimension::D2,
                format: wgpu::TextureFormat::Rgba8Unorm,
                usage: wgpu::TextureUsages::TEXTURE_BINDING | wgpu::TextureUsages::COPY_DST,
                view_formats: &[],
            });

            state.gs_texture_id = state.egui_renderer.renderer.register_native_texture(
                &state.device,
                &state.gs_texture.create_view(&Default::default()),
                wgpu::FilterMode::Linear,
            );
        }

        if let Some(original_data) = &frame_data {
            state.queue.write_texture(
                state.gs_texture.as_image_copy(),
                original_data,
                wgpu::TexelCopyBufferLayout {
                    offset: 0,
                    bytes_per_row: Some(original_width * 4),
                    rows_per_image: Some(original_height),
                },
                wgpu::Extent3d {
                    width: original_width,
                    height: original_height,
                    depth_or_array_layers: 1,
                },
            );
        }

        let surface_view = surface_texture
            .texture
            .create_view(&wgpu::TextureViewDescriptor::default());

        let mut encoder = state
            .device
            .create_command_encoder(&wgpu::CommandEncoderDescriptor { label: None });

        let window = self.window.as_ref().unwrap();

        {
            state.egui_renderer.begin_frame(window);

            let screen_rect = state.egui_renderer.context().content_rect();
            let mut root_ui = egui::Ui::new(
                state.egui_renderer.context().clone(),
                egui::Id::new("view"),
                egui::UiBuilder::new().max_rect(screen_rect),
            );

            egui::Panel::top("Menubar").show_inside(&mut root_ui, |ui| {
                ui.horizontal(|ui| {
                    if ui.button("Toggle EE State View").clicked() {
                        self.ee_ctl_display_open = !self.ee_ctl_display_open;
                    }
                    if ui.button("Toggle Disassembly").clicked() {
                        self.disassembly_open = !self.disassembly_open;
                    }
                    if ui.button("Toggle RAM View").clicked() {
                        self.ram_view_open = !self.ram_view_open;
                    }
                    if ui.button("Toggle TLB View").clicked() {
                        self.tlb_view_open = !self.tlb_view_open;
                    }
                    if ui.button("View VRAM").clicked() {
                        self.vram_view_open = !self.vram_view_open;
                    }
                    if ui.button("Toggle Performance Graph").clicked() {
                        self.perf_view_open = !self.perf_view_open;
                    }

                    ui.separator();

                    ui.label("Renderer:");
                    let current_label = self.selected_renderer.display_name();
                    egui::ComboBox::from_id_salt("renderer_selector")
                        .selected_text(current_label)
                        .show_ui(ui, |ui| {
                            for kind in RendererKind::all() {
                                let label = kind.display_name();
                                let is_selected = *kind == self.selected_renderer;
                                if ui.selectable_label(is_selected, label).clicked() && !is_selected
                                {
                                    let _ = self.debug_tx.send(DebugRequest::SwapRenderer(*kind));
                                    self.selected_renderer = *kind;
                                }
                            }
                        });
                });
            });

            egui::Panel::bottom("EE Taskbar").show_inside(&mut root_ui, |ui| {
                ui.horizontal(|ui| {
                    if ui
                        .button(if self.is_paused.load(Ordering::SeqCst) {
                            "Run"
                        } else {
                            "Pause"
                        })
                        .clicked()
                    {
                        if self.emulation_thread.is_none() {
                            let mut backend = self.emu_backend.take().unwrap();
                            let mut bus = self.bus.take().unwrap();
                            let (debug_rx, debug_tx) = self.backend_debug.take().unwrap();

                            let thread = std::thread::spawn(move || {
                                Scheduler::run_main_loop(
                                    &mut *backend,
                                    &mut bus,
                                    &debug_rx,
                                    &debug_tx,
                                );
                            });
                            self.emulation_thread = Some(thread);
                        }
                        let paused = self.is_paused.load(Ordering::SeqCst);
                        self.is_paused.store(!paused, Ordering::SeqCst);
                        if paused {
                            self.emulation_thread.as_ref().unwrap().thread().unpark();
                        }
                    }
                    if ui.button("Reset").clicked() {
                        // Reset logic
                    }

                    let mut sched = self.scheduler.lock().unwrap();

                    let mut disable_throttle = sched.disable_throttle;

                    if ui
                        .checkbox(&mut disable_throttle, "Disable Frame Capping")
                        .changed()
                    {
                        sched.disable_throttle = disable_throttle;

                        if !disable_throttle {
                            sched.reset_timeline();
                        }
                    }

                    let current_fps = sched.internal_fps;
                    drop(sched);

                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        ui.label(format!("| VSYNC/s: : {:.1}", current_fps));
                        ui.label(format!(
                            "| GS Resolution: {}x{}",
                            original_width, original_height
                        ));
                        ui.label(format!("Frontend Frame Time: {:.2} ms", delta * 1000.0));
                    });
                });
            });

            egui::CentralPanel::default().show_inside(&mut root_ui, |ui| {
                ui.painter().rect_filled(
                    ui.available_rect_before_wrap(),
                    0.0,
                    egui::Color32::BLACK,
                );

                if frame_data.is_some() {
                    let available_rect = ui.available_rect_before_wrap();
                    let available_size = available_rect.size();

                    let aspect_ratio = TARGET_WIDTH as f32 / TARGET_HEIGHT as f32;

                    let mut scaled_width = available_size.x;
                    let mut scaled_height = scaled_width / aspect_ratio;

                    if scaled_height > available_size.y {
                        scaled_height = available_size.y;
                        scaled_width = scaled_height * aspect_ratio;
                    }

                    let img_size = egui::vec2(scaled_width, scaled_height);

                    let center_x = available_rect.center().x - scaled_width / 2.0;
                    let center_y = available_rect.center().y - scaled_height / 2.0;
                    let image_rect =
                        egui::Rect::from_min_size(egui::pos2(center_x, center_y), img_size);

                    ui.scope_builder(egui::UiBuilder::new().max_rect(image_rect), |ui| {
                        ui.image((state.gs_texture_id, img_size));
                    });
                }
            });

            if self.ee_ctl_display_open {
                egui::Window::new("EE CPU State")
                    .resizable(true)
                    .default_size(egui::vec2(400.0, 300.0))
                    .show(state.egui_renderer.context(), |ui| {
                        if let Ok(ee) = self.ee.lock() {
                            for (i, reg) in ee.registers.iter().enumerate() {
                                let value = reg.load(Ordering::SeqCst);
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

                            for (i, reg) in ee.cop0_registers.iter().enumerate() {
                                let value = reg.load(Ordering::SeqCst);
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
                            self.cop0_change_ee_timers
                                .retain(|_, &mut timer| timer > 0.0);

                            ui.horizontal(|ui| {
                                ui.selectable_value(&mut self.selected_ee_tab, 0, "GP Registers");
                                ui.selectable_value(&mut self.selected_ee_tab, 1, "COP0 Registers");
                            });

                            ui.separator();

                            match self.selected_ee_tab {
                                0 => {
                                    ScrollArea::both().max_height(ui.available_height()).show(
                                        ui,
                                        |ui| {
                                            TableBuilder::new(ui)
                                                .striped(true)
                                                .column(Column::auto().resizable(true))
                                                .column(Column::remainder())
                                                .header(20.0, |mut header| {
                                                    header.col(|ui| {
                                                        ui.label("Name");
                                                    });
                                                    header.col(|ui| {
                                                        ui.label("Value");
                                                    });
                                                })
                                                .body(|mut body| {
                                                    for (i, reg) in ee.registers.iter().enumerate()
                                                    {
                                                        let value = reg.load(Ordering::SeqCst);
                                                        let name = [
                                                            "zr", "at", "v0", "v1", "a0", "a1",
                                                            "a2", "a3", "t0", "t1", "t2", "t3",
                                                            "t4", "t5", "t6", "t7", "s0", "s1",
                                                            "s2", "s3", "s4", "s5", "s6", "s7",
                                                            "t8", "t9", "k0", "k1", "gp", "sp",
                                                            "fp", "ra",
                                                        ]
                                                        .get(i)
                                                        .unwrap_or(&"UNK");

                                                        let animation_progress = self
                                                            .change_ee_timers
                                                            .get(&i)
                                                            .cloned()
                                                            .unwrap_or(0.0);

                                                        let text_color = if animation_progress > 0.0
                                                        {
                                                            let t = animation_progress;
                                                            let r = 255.0;
                                                            let g = 255.0 * (1.0 - t);
                                                            let b = 255.0 * (1.0 - t);
                                                            egui::Color32::from_rgb(
                                                                r as u8, g as u8, b as u8,
                                                            )
                                                        } else {
                                                            egui::Color32::WHITE
                                                        };

                                                        body.row(18.0, |mut row| {
                                                            row.col(|ui| {
                                                                ui.label(*name);
                                                            });
                                                            row.col(|ui| {
                                                                ui.colored_label(
                                                                    text_color,
                                                                    format!("{:#034X}", value),
                                                                );
                                                            });
                                                        });
                                                    }

                                                    body.row(1.0, |mut row| {
                                                        row.col(|ui| {
                                                            ui.separator();
                                                        });
                                                    });

                                                    body.row(18.0, |mut row| {
                                                        row.col(|ui| {
                                                            ui.label("hi");
                                                        });
                                                        row.col(|ui| {
                                                            ui.colored_label(
                                                                egui::Color32::WHITE,
                                                                format!(
                                                                    "{:#034X}",
                                                                    ee.hi.load(Ordering::Relaxed)
                                                                ),
                                                            );
                                                        });
                                                    });
                                                    body.row(18.0, |mut row| {
                                                        row.col(|ui| {
                                                            ui.label("lo");
                                                        });
                                                        row.col(|ui| {
                                                            ui.colored_label(
                                                                egui::Color32::WHITE,
                                                                format!(
                                                                    "{:#034X}",
                                                                    ee.lo.load(Ordering::Relaxed)
                                                                ),
                                                            );
                                                        });
                                                    });
                                                    body.row(18.0, |mut row| {
                                                        row.col(|ui| {
                                                            ui.label("pc");
                                                        });
                                                        row.col(|ui| {
                                                            ui.colored_label(
                                                                egui::Color32::WHITE,
                                                                format!(
                                                                    "{:#010X}",
                                                                    ee.pc.load(Ordering::Relaxed)
                                                                ),
                                                            );
                                                        });
                                                    });
                                                });
                                        },
                                    );
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
                                                    header.col(|ui| {
                                                        ui.label("Register");
                                                    });
                                                    header.col(|ui| {
                                                        ui.label("Value");
                                                    });
                                                })
                                                .body(|mut body| {
                                                    for (i, reg) in
                                                        ee.cop0_registers.iter().enumerate()
                                                    {
                                                        let value = reg.load(Ordering::SeqCst);
                                                        let name = [
                                                            "Index", "Random", "EntryLo0",
                                                            "EntryLo1", "Context", "PageMask",
                                                            "Wired", "", "BadVAddr", "Count",
                                                            "EntryHi", "Compare", "Status",
                                                            "Cause", "EPC", "PRId", "Config", "",
                                                            "", "", "", "", "", "BadPAddr",
                                                            "Debug", "Perf", "", "", "TagLo",
                                                            "TagHi", "ErrorEPC", "",
                                                        ]
                                                        .get(i)
                                                        .unwrap_or(&"UNK");

                                                        if name.is_empty() {
                                                            continue;
                                                        }

                                                        let animation_progress = self
                                                            .cop0_change_ee_timers
                                                            .get(&i)
                                                            .copied()
                                                            .unwrap_or(0.0);

                                                        let text_color = if animation_progress > 0.0
                                                        {
                                                            let t = animation_progress;
                                                            let r = 255.0;
                                                            let g = 255.0 * (1.0 - t);
                                                            let b = 255.0 * (1.0 - t);
                                                            egui::Color32::from_rgb(
                                                                r as u8, g as u8, b as u8,
                                                            )
                                                        } else {
                                                            egui::Color32::WHITE
                                                        };

                                                        body.row(18.0, |mut row| {
                                                            row.col(|ui| {
                                                                ui.label(*name);
                                                            });
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
            }

            if self.vram_view_open {
                if let Some(frame) = &self.latest_frame {
                    let vram_data = &frame.pixels;
                    let vram_width = frame.width;
                    let vram_height = frame.height;

                    let needs_new_texture = if let Some(existing_texture) = &self.vram_texture {
                        let current_size = existing_texture.size();
                        current_size.width != vram_width || current_size.height != vram_height
                    } else {
                        true
                    };

                    if needs_new_texture {
                        if let Some(old_texture_id) = self.vram_texture_id {
                            state.egui_renderer.renderer.free_texture(&old_texture_id);
                        }

                        let vram_texture = state.device.create_texture(&wgpu::TextureDescriptor {
                            label: Some("VRAM Viewer"),
                            size: wgpu::Extent3d {
                                width: vram_width,
                                height: vram_height,
                                depth_or_array_layers: 1,
                            },
                            mip_level_count: 1,
                            sample_count: 1,
                            dimension: wgpu::TextureDimension::D2,
                            format: wgpu::TextureFormat::Rgba8Unorm,
                            usage: wgpu::TextureUsages::TEXTURE_BINDING
                                | wgpu::TextureUsages::COPY_DST,
                            view_formats: &[],
                        });

                        let vram_texture_id = state.egui_renderer.renderer.register_native_texture(
                            &state.device,
                            &vram_texture.create_view(&Default::default()),
                            wgpu::FilterMode::Linear,
                        );

                        self.vram_texture = Some(vram_texture);
                        self.vram_texture_id = Some(vram_texture_id);
                    }

                    if let (Some(texture), Some(_)) = (&self.vram_texture, &self.vram_texture_id) {
                        state.queue.write_texture(
                            texture.as_image_copy(),
                            vram_data,
                            wgpu::TexelCopyBufferLayout {
                                offset: 0,
                                bytes_per_row: Some(vram_width * 4),
                                rows_per_image: Some(vram_height),
                            },
                            wgpu::Extent3d {
                                width: vram_width,
                                height: vram_height,
                                depth_or_array_layers: 1,
                            },
                        );
                    }

                    egui::Window::new("VRAM Viewer")
                        .resizable(true)
                        .default_size(egui::vec2(800.0, 600.0))
                        .show(state.egui_renderer.context(), |ui| {
                            if let Some(texture_id) = self.vram_texture_id {
                                ui.separator();
                                let available_rect = ui.available_rect_before_wrap();
                                let available_size = available_rect.size();

                                let original_width = vram_width as f32;
                                let original_height = vram_height as f32;
                                let aspect_ratio = original_width / original_height;

                                let mut scaled_width = available_size.x;
                                let mut scaled_height = scaled_width / aspect_ratio;

                                if scaled_height > available_size.y {
                                    scaled_height = available_size.y;
                                    scaled_width = scaled_height * aspect_ratio;
                                }

                                let img_size = egui::vec2(scaled_width, scaled_height);

                                ScrollArea::both()
                                    .auto_shrink([false, false])
                                    .show(ui, |ui| {
                                        ui.image((texture_id, img_size));
                                    });
                            } else {
                                ui.label("No VRAM data available");
                            }
                        });
                } else {
                    egui::Window::new("VRAM Viewer")
                        .resizable(true)
                        .default_size(egui::vec2(800.0, 600.0))
                        .show(state.egui_renderer.context(), |ui| {
                            ui.label("Waiting for frame data...");
                        });
                }
            }

            if self.tlb_view_open {
                let _ = self.debug_tx.send(DebugRequest::ReadTlb);

                egui::Window::new("TLB Viewer")
                    .resizable(true)
                    .default_size(egui::vec2(800.0, 400.0))
                    .show(state.egui_renderer.context(), |ui| {
                        ScrollArea::both().show(ui, |ui| {
                            TableBuilder::new(ui)
                                .striped(true)
                                .column(Column::auto().resizable(true)) // Index
                                .column(Column::auto().resizable(true)) // VPN2
                                .column(Column::auto().resizable(true)) // ASID
                                .column(Column::auto().resizable(true)) // G
                                .column(Column::auto().resizable(true)) // PFN0
                                .column(Column::auto().resizable(true)) // PFN1
                                .column(Column::auto().resizable(true)) // C0
                                .column(Column::auto().resizable(true)) // C1
                                .column(Column::auto().resizable(true)) // D0
                                .column(Column::auto().resizable(true)) // D1
                                .column(Column::auto().resizable(true)) // V0
                                .column(Column::auto().resizable(true)) // V1
                                .column(Column::auto().resizable(true)) // S0
                                .column(Column::auto().resizable(true)) // S1
                                .column(Column::auto().resizable(true)) // Mask
                                .header(20.0, |mut header| {
                                    header.col(|ui| {
                                        ui.label("Index");
                                    });
                                    header.col(|ui| {
                                        ui.label("VPN2");
                                    });
                                    header.col(|ui| {
                                        ui.label("ASID");
                                    });
                                    header.col(|ui| {
                                        ui.label("G");
                                    });
                                    header.col(|ui| {
                                        ui.label("PFN0");
                                    });
                                    header.col(|ui| {
                                        ui.label("PFN1");
                                    });
                                    header.col(|ui| {
                                        ui.label("C0");
                                    });
                                    header.col(|ui| {
                                        ui.label("C1");
                                    });
                                    header.col(|ui| {
                                        ui.label("D0");
                                    });
                                    header.col(|ui| {
                                        ui.label("D1");
                                    });
                                    header.col(|ui| {
                                        ui.label("V0");
                                    });
                                    header.col(|ui| {
                                        ui.label("V1");
                                    });
                                    header.col(|ui| {
                                        ui.label("S0");
                                    });
                                    header.col(|ui| {
                                        ui.label("S1");
                                    });
                                    header.col(|ui| {
                                        ui.label("Mask");
                                    });
                                })
                                .body(|mut body| {
                                    for (index, entry) in self.cached_tlb_entries.iter().enumerate()
                                    {
                                        if let Some(e) = entry {
                                            body.row(18.0, |mut row| {
                                                row.col(|ui| {
                                                    ui.label(format!("{}", index));
                                                });
                                                row.col(|ui| {
                                                    ui.label(format!("0x{:08X}", e.vpn2));
                                                });
                                                row.col(|ui| {
                                                    ui.label(format!("0x{:02X}", e.asid));
                                                });
                                                row.col(|ui| {
                                                    ui.label(if e.g { "1" } else { "0" });
                                                });
                                                row.col(|ui| {
                                                    ui.label(format!("0x{:08X}", e.pfn0));
                                                });
                                                row.col(|ui| {
                                                    ui.label(format!("0x{:08X}", e.pfn1));
                                                });
                                                row.col(|ui| {
                                                    ui.label(format!("{}", e.c0));
                                                });
                                                row.col(|ui| {
                                                    ui.label(format!("{}", e.c1));
                                                });
                                                row.col(|ui| {
                                                    ui.label(if e.d0 { "1" } else { "0" });
                                                });
                                                row.col(|ui| {
                                                    ui.label(if e.d1 { "1" } else { "0" });
                                                });
                                                row.col(|ui| {
                                                    ui.label(if e.v0 { "1" } else { "0" });
                                                });
                                                row.col(|ui| {
                                                    ui.label(if e.v1 { "1" } else { "0" });
                                                });
                                                row.col(|ui| {
                                                    ui.label(if e.s0 { "1" } else { "0" });
                                                });
                                                row.col(|ui| {
                                                    ui.label(if e.s1 { "1" } else { "0" });
                                                });
                                                row.col(|ui| {
                                                    ui.label(format!("0x{:08X}", e.mask));
                                                });
                                            });
                                        } else {
                                            body.row(18.0, |mut row| {
                                                row.col(|ui| {
                                                    ui.label(format!("{}", index));
                                                });
                                                for _ in 0..14 {
                                                    row.col(|ui| {
                                                        ui.label("---");
                                                    });
                                                }
                                            });
                                        }
                                    }
                                });
                        });
                    });
            }

            if self.ram_view_open {
                let _ = self.debug_tx.send(DebugRequest::ReadRam {
                    addr: self.ram_view_addr,
                    len: self.ram_view_len,
                });

                egui::Window::new("RAM Viewer")
                    .resizable(true)
                    .default_size(egui::vec2(400.0, 300.0))
                    .show(state.egui_renderer.context(), |ui| {
                        ui.horizontal(|ui| {
                            ui.label("Addr:");
                            if ui
                                .text_edit_singleline(&mut self.address_input)
                                .lost_focus()
                            {
                                if let Ok(v) = u32::from_str_radix(
                                    self.address_input.trim_start_matches("0x"),
                                    16,
                                ) {
                                    self.ram_view_addr = v;
                                }
                            }
                            ui.label("Len:");
                            ui.add(egui::DragValue::new(&mut self.ram_view_len).range(16..=4096));
                        });

                        ui.separator();

                        let bytes_per_row = 16;
                        let rows = (self.ram_view_len + bytes_per_row - 1) / bytes_per_row;

                        ScrollArea::both()
                            .auto_shrink([false, false])
                            .show(ui, |ui| {
                                egui::Grid::new("ram_grid")
                                    .spacing([8.0, 4.0])
                                    .min_col_width(0.0)
                                    .show(ui, |ui| {
                                        // Header row
                                        ui.label(""); // corner
                                        for i in 0..bytes_per_row {
                                            ui.label(format!("{:02X}", i));
                                        }
                                        ui.end_row();

                                        // Data rows
                                        for row in 0..rows {
                                            let base =
                                                self.ram_view_addr as usize + row * bytes_per_row;
                                            ui.label(format!("0x{:08X}", base));
                                            for col in 0..bytes_per_row {
                                                let idx = row * bytes_per_row + col;
                                                let byte = self
                                                    .cached_ram_data
                                                    .get(idx)
                                                    .copied()
                                                    .unwrap_or(0);
                                                ui.label(format!("{:02X}", byte));
                                            }
                                            ui.end_row();
                                        }
                                    });
                            });
                    });
            }

            if self.disassembly_open {
                let current_pc = if let Ok(ee) = self.ee.lock() {
                    let pc = ee.pc.load(Ordering::SeqCst);
                    if self.follow_pc {
                        self.disassembly_start_addr = pc;
                    }
                    pc as u64
                } else {
                    0
                };

                let _ = self.debug_tx.send(DebugRequest::ReadDisassembly {
                    pc: self.disassembly_start_addr,
                    num_words: 16,
                });

                let disasm = self
                    .disassembler
                    .disassemble(
                        &self.cached_disassembly_bytes,
                        self.disassembly_pc_cache as u64,
                    )
                    .unwrap_or_else(|_| vec!["Awaiting Disassembly Data...".to_string()]);

                egui::Window::new("Disassembly")
                    .resizable(true)
                    .default_size(egui::vec2(400.0, 300.0))
                    .show(state.egui_renderer.context(), |ui| {
                        egui::ScrollArea::both()
                            .auto_shrink([false, false])
                            .show(ui, |ui| {
                                let style = ui.style();
                                let mono_font: FontId =
                                    style.text_styles[&TextStyle::Monospace].clone();
                                let available_width = ui.available_width();
                                ui.set_min_width(available_width);

                                Grid::new("disasm_grid")
                                    .spacing([10.0, 4.0])
                                    .min_col_width(0f32)
                                    .show(ui, |ui| {
                                        for line in &disasm {
                                            if let Some((addr_str, rest)) = line.split_once(':') {
                                                let address = u64::from_str_radix(
                                                    addr_str.trim_start_matches("0x"),
                                                    16,
                                                )
                                                .unwrap_or(0);
                                                let addr_text =
                                                    RichText::new(format!("0x{:08x}:", address))
                                                        .font(mono_font.clone())
                                                        .color(if address == current_pc {
                                                            Color32::LIGHT_BLUE
                                                        } else {
                                                            Color32::GRAY
                                                        });

                                                let (mnemonic, operands) = if let Some((m, ops)) =
                                                    rest.trim().split_once('\t')
                                                {
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

            if self.perf_view_open {
                egui::Window::new("Performance Metrics")
                    .resizable(true)
                    .default_size(egui::vec2(600.0, 400.0))
                    .show(state.egui_renderer.context(), |ui| {
                        let fe_id = ui.id().with("show_fe_plot");
                        let be_id = ui.id().with("show_be_plot");

                        let mut show_fe =
                            ui.data_mut(|d| d.get_temp_mut_or_insert_with(fe_id, || true).clone());
                        let mut show_be =
                            ui.data_mut(|d| d.get_temp_mut_or_insert_with(be_id, || true).clone());

                        ui.horizontal(|ui| {
                            ui.label(
                                RichText::new(format!("Dropped Frames (1s): {}", drops_last_sec))
                                    .color(if drops_last_sec > 0 {
                                        Color32::RED
                                    } else {
                                        Color32::GREEN
                                    }),
                            );
                            ui.separator();
                            ui.label(format!("Total Dropped: {}", self.total_dropped));
                        });

                        let (fe_avg, fe_1pct) = Self::compute_stats(&self.frontend_frametimes);
                        let (be_avg, be_1pct) = Self::compute_stats(&self.backend_frametimes);

                        ui.separator();
                        ui.label(format!(
                            "Frontend Frametime  |  Avg: {:.2} ms  |  1% Low: {:.2} ms",
                            fe_avg * 1000.0,
                            fe_1pct * 1000.0
                        ));
                        ui.label(format!(
                            "Emulator Frametime  |  Avg: {:.2} ms  |  1% Low: {:.2} ms",
                            be_avg * 1000.0,
                            be_1pct * 1000.0
                        ));
                        ui.separator();

                        ui.horizontal(|ui| {
                            ui.label("Toggle Graphs:");
                            ui.checkbox(&mut show_fe, "Frontend");
                            ui.checkbox(&mut show_be, "Emulator (Backend)");
                        });

                        ui.data_mut(|d| d.insert_temp(fe_id, show_fe));
                        ui.data_mut(|d| d.insert_temp(be_id, show_be));

                        let fe_points: PlotPoints = self
                            .frontend_frametimes
                            .iter()
                            .enumerate()
                            .map(|(i, &val)| [i as f64, (val * 1000.0) as f64])
                            .collect();
                        let be_points: PlotPoints = self
                            .backend_frametimes
                            .iter()
                            .enumerate()
                            .map(|(i, &val)| [i as f64, (val * 1000.0) as f64])
                            .collect();

                        Plot::new("frametime_plot")
                            .view_aspect(2.0)
                            .include_y(0.0)
                            .show(ui, |plot_ui| {
                                if show_fe {
                                    plot_ui.line(
                                        Line::new("Frontend", fe_points).color(Color32::LIGHT_BLUE),
                                    );
                                }
                                if show_be {
                                    plot_ui.line(
                                        Line::new("Backend", be_points).color(Color32::LIGHT_GREEN),
                                    );
                                }
                            });
                    });
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
