/*
    PS2 BIOS Structure
*/

use std::path::Path;
use std::fs;

// BIOS Size is 4MiB
const BIOS_SIZE: u64 = (1024 * 1024) * 4;

pub struct BIOS {
    // BIOS bytes loaded off from a storage device
    bytes: Vec<u8>
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

    pub fn read32(&self, address: u32) -> u32 {
        let offset = address as usize;
        if offset + 4 <= self.bytes.len() {
            let bytes = &self.bytes[offset..offset + 4];
            match bytes.try_into() {
                Ok(value) => u32::from_le_bytes(value),
                Err(_) => panic!("Failed to convert bytes!")
            }
        } else {
            panic!("Attempted to read out of bounds from BIOS")
        }
    }
}