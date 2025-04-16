/*
    PS2 BIOS Structure
*/

use std::path::Path;
use std::fs;

// BIOS Size is 4MiB
const BIOS_SIZE: u64 = (1024 * 1024) * 4;

#[derive(Clone)]
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

    #[cfg(test)]
    pub fn test_only(bytes: Vec<u8>) -> BIOS {
        let mut padded_bytes = bytes;

        // Pad the bytes to 4 MiB if necessary.
        if padded_bytes.len() < BIOS_SIZE as usize {
            padded_bytes.resize(BIOS_SIZE as usize, 0);
        }

        BIOS { bytes: padded_bytes }
    }
}