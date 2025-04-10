use std::path::Path;

use librustee::{bus::{Bus, BusMode}, cpu::CPU, ee::EE, BIOS};
use clap::{arg, Command};

fn main() {
    println!("RustEE - A Rust, PlayStation 2 Emulator");
    let arguments = Command::new("RustEE")
        .version("0.0.1")
        .about("A Rust, PlayStation 2 Emulator")
        .arg(arg!(--bios <VALUE>).required(true))
        .get_matches();

    if let Some(bios_path) = arguments.get_one::<String>("bios") {
        let bios_path = Path::new(bios_path);
        let bios: BIOS = BIOS::new(bios_path).expect("Failed to load BIOS");
        let bus = Bus::new(BusMode::Ranged, bios);
        let ee = EE::new(bus);
    } else {
        panic!("No BIOS path provided!");
    }
}
