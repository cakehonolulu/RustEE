/*
    PS2 BIOS Structure
*/

use std::path::Path;
use std::fs;

// BIOS Size is 4MiB
const BIOS_SIZE: u64 = (1024 * 1024) * 4;

pub struct BIOS {
    // BIOS bytes loaded off from a storage device
    pub bytes: Vec<u8>
}

impl BIOS {
    pub fn new(path: &Path) -> Result<BIOS, std::io::Error> {
        let data: Vec<u8> = fs::read(path)?;

        if data.len() == BIOS_SIZE as usize {
            Ok(BIOS {bytes: data})
        } else {
            Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "BIOS file is not the correct size (Is it corrupted?)",
            ))
        }
    }
}