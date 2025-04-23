use std::path::Path;

use librustee::{bus::{Bus, BusMode}, cpu::{EmulationBackend, CPU}, ee::{Interpreter, EE, JIT}, BIOS};
use clap::{arg, Command};

use tracing_subscriber::EnvFilter;

fn main() {
    println!("RustEE - A Rust, PlayStation 2 Emulator");
    let arguments = Command::new("RustEE")
        .version("0.0.1")
        .about("A Rust, PlayStation 2 Emulator")
        .arg(arg!(--bios <VALUE>).required(true))
        .arg(arg!(--"ee-breakpoint" <BREAKPOINTS>)
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
            .required(false))
        .arg(arg!(--"ee-backend" <BACKEND>)
            .value_parser(["interpreter", "jit"])
            .default_value("jit")
            .help("Choose the EE backend: 'interpreter' or 'jit'"))
        .arg(arg!(--"bus-mode" <MODE>)
            .value_parser(["ranged", "sw_fastmem"])
            .default_value("ranged")
            .help("Choose the bus emulation mode: 'ranged' or 'sw_fastmem'"))
        .get_matches();

        tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::new("debug")
                .add_directive("cranelift_codegen=warn".parse().unwrap())
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
            _ => BusMode::Ranged,
        };

        let bus = Bus::new(bus_mode, bios);
        let mut ee: EE = EE::new(bus);

        if let Some(breakpoints) = arguments.get_one::<Vec<u32>>("ee-breakpoint") {
            for &addr in breakpoints {
                ee.add_breakpoint(addr);
            }
        }

        match arguments.get_one::<String>("ee-backend").map(String::as_str) {
            Some("interpreter") => {
                tracing::info!("Using EE Interpreter backend");
                let mut ee_backend = Interpreter::new(ee);
                ee_backend.run();
            }
            Some("jit") | _ => {
                tracing::info!("Using EE JIT backend");
                let mut ee_backend = JIT::new(&mut ee);
                ee_backend.run();
            }
        }
    } else {
        panic!("No BIOS path provided!");
    }
}
