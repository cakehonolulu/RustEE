use std::path::Path;

use librustee::{bus::{Bus, BusMode}, cpu::EmulationBackend, ee::{EE,Interpreter}, BIOS};
use clap::{arg, Command};

use tracing_subscriber::EnvFilter;


fn main() {
    println!("RustEE - A Rust, PlayStation 2 Emulator");
    let arguments = Command::new("RustEE")
        .version("0.0.1")
        .about("A Rust, PlayStation 2 Emulator")
        .arg(arg!(--bios <VALUE>).required(true))
        .get_matches();

    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::new("debug")) // Allow filtering via RUST_LOG
        .without_time()
        .init();

    tracing::info!("RustEE emulator tracer started");   
    if let Some(bios_path) = arguments.get_one::<String>("bios") {
        let bios_path = Path::new(bios_path);
        let bios: BIOS = BIOS::new(bios_path).expect("Failed to load BIOS");
        let bus = Bus::new(BusMode::Ranged, bios);
        let ee: EE = EE::new(bus);
        let mut ee_backend = Interpreter::new(ee);
        ee_backend.step();
    } else {
        panic!("No BIOS path provided!");
    }
}
