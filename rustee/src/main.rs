use clap::{Command, arg};
use librustee::{
    BIOS,
    bus::{Bus, BusMode},
    cpu::CPU,
    ee::EE,
};
use std::sync::{Arc, Mutex, RwLock};
use std::{fs, path::Path};

use tracing_subscriber::EnvFilter;
use winit::event_loop::{ControlFlow, EventLoop};

mod app;
mod egui_tools;

fn main() {
    println!("RustEE - A Rust, PlayStation 2 Emulator");
    let arguments = Command::new("RustEE")
        .version("0.0.1")
        .about("A Rust, PlayStation 2 Emulator")
        .arg(arg!(--bios <VALUE>).required(true))
        .arg(
            arg!(--"ee-breakpoint" <BREAKPOINTS>)
                .value_parser(|s: &str| {
                    s.split(',')
                        .map(|val| {
                            let val = val.trim();
                            let hex_str = val.trim_start_matches("0x");
                            u32::from_str_radix(hex_str, 16)
                                .map_err(|_| format!("Invalid 32-bit hex value: '{}'", val))
                        })
                        .collect::<Result<Vec<u32>, String>>()
                })
                .required(false),
        )
        .arg(
            arg!(--"ee-backend" <BACKEND>)
                .value_parser(["interpreter", "jit"])
                .default_value("jit")
                .help("Choose the EE backend: 'interpreter' or 'jit'"),
        )
        .arg(
            arg!(--"bus-mode" <MODE>)
                .value_parser(["ranged", "sw_fastmem", "hw_fastmem"])
                .default_value("hw_fastmem")
                .help("Choose the bus emulation mode: 'ranged', 'sw_fastmem' or 'hw_fastmem'"),
        )
        .arg(
            arg!(--elf <ELFPATH>)
                .required(false)
                .help("Path to an ELF executable to sideload"),
        )
        .get_matches();

    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::new("debug")
                .add_directive("cranelift_codegen=warn".parse().unwrap())
                .add_directive("wgpu_hal::vulkan::instance=error".parse().unwrap())
                .add_directive("wgpu_hal::gles::adapter=error".parse().unwrap())
                .add_directive("wgpu_core::instance=error".parse().unwrap())
                .add_directive("wgpu_hal::gles::wgl=error".parse().unwrap())
                .add_directive("naga::valid::interface=error".parse().unwrap())
                .add_directive("naga::valid::function=error".parse().unwrap())
                .add_directive("egui_wgpu::renderer=error".parse().unwrap())
                .add_directive("wgpu_core::device::global=error".parse().unwrap())
                .add_directive("wgpu_hal::vulkan::adapter=error".parse().unwrap())
                .add_directive("naga::front=error".parse().unwrap())
                .add_directive("wgpu_hal::gles::egl=error".parse().unwrap())
                .add_directive("sctk_adwaita::config=off".parse().unwrap())
                .add_directive("sctk=error".parse().unwrap())
                .add_directive("cranelift_jit=warn".parse().unwrap()),
        )
        .without_time()
        .init();

    tracing::info!("Tracer started");
    if let Some(bios_path) = arguments.get_one::<String>("bios") {
        let bios_path = Path::new(bios_path);
        let bios: BIOS = BIOS::new(bios_path).expect("Failed to load BIOS");

        let bus_mode = match arguments.get_one::<String>("bus-mode").map(String::as_str) {
            Some("sw_fastmem") => BusMode::SoftwareFastMem,
            Some("hw_fastmem") => BusMode::HardwareFastMem,
            _ => BusMode::Ranged,
        };

        let cop0_registers = Arc::new(RwLock::new([0u32; 32]));
        let bus = Arc::new(Mutex::new(Bus::new(
            bus_mode,
            bios,
            Arc::clone(&cop0_registers),
        )));
        let ee = Arc::new(Mutex::new(EE::new(
            Arc::clone(&bus),
            Arc::clone(&cop0_registers),
        )));

        if let Some(breakpoints) = arguments.get_one::<Vec<u32>>("ee-breakpoint") {
            for &addr in breakpoints {
                ee.lock().unwrap().add_breakpoint(addr);
            }
        }

        if let Some(elf) = arguments.get_one::<String>("elf") {
            let mut ee_lock = ee.lock().unwrap();
            ee_lock.elf_path = elf.to_string();
            ee_lock.sideload_elf = true;
        }

        let backend = arguments
            .get_one::<String>("ee-backend")
            .map(String::clone)
            .unwrap_or_else(|| "jit".to_string());

        #[cfg(not(target_arch = "wasm32"))]
        {
            pollster::block_on(run(ee.clone(), bus.clone(), backend));
        }
    } else {
        panic!("No BIOS path provided!");
    }
}

async fn run(ee: Arc<Mutex<EE>>, bus: Arc<Mutex<Box<Bus>>>, backend: String) {
    let event_loop = EventLoop::new().unwrap();

    event_loop.set_control_flow(ControlFlow::Poll);

    let mut app = app::App::new(ee, bus, backend);

    event_loop.run_app(&mut app).expect("Failed to run app");
}
