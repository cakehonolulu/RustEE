pub mod bios;

use bios::BIOS;

mod map {
    pub struct Range(u32, u32);

    impl Range {
        pub fn contains(self, addr: u32) -> Option<u32> {
            let Range(start, length) = self;

            if addr >= start && addr < start + length {
                Some(addr - start)
            } else {
                None
            }
        }
    }

    pub const BIOS: Range = Range(0xBFC00000, (1024 * 1024) * 4);
    pub const RAM: Range = Range(0x0, 32 * 1024 * 1024); // 32MB RAM
}

pub enum BusMode {
    SoftwareFastMem,
    Ranged,
}

#[derive(Clone)]
pub struct Bus {
    bios: BIOS,
    ram: Vec<u8>,

    // Function pointers for read/write operations
    pub read32: fn(&Bus, u32) -> u32,
    pub write32: fn(&mut Bus, u32, u32),
}

impl Bus {
    pub fn new(mode: BusMode, bios: BIOS) -> Bus {
        let (read32, write32) = match mode {
            BusMode::SoftwareFastMem => (
                Bus::sw_fmem_read32 as fn(&Bus, u32) -> u32,
                Bus::sw_fmem_write32 as fn(&mut Bus, u32, u32),
            ),
            BusMode::Ranged => (
                Bus::ranged_read32 as fn(&Bus, u32) -> u32,
                Bus::ranged_write32 as fn(&mut Bus, u32, u32),
            ),
        };

        Bus {
            bios: bios,
            ram: vec![0; 32 * 1024 * 1024],
            read32,
            write32,
        }
    }

    fn ranged_read32(&self, address: u32) -> u32 {
        if let Some(offset) = map::RAM.contains(address) {
            // Access the RAM bytes directly
            let offset = offset as usize;
            if offset + 4 <= self.ram.len() {
                let bytes = &self.ram[offset..offset + 4];
                u32::from_le_bytes(bytes.try_into().expect("Failed to convert bytes!"))
            } else {
                panic!("Attempted to read out of bounds from RAM");
            }
        } else if let Some(offset) = map::BIOS.contains(address) {
            // Access the BIOS bytes directly
            let offset = offset as usize;
            if offset + 4 <= self.bios.bytes.len() {
                let bytes = &self.bios.bytes[offset..offset + 4];
                u32::from_le_bytes(bytes.try_into().expect("Failed to convert bytes!"))
            } else {
                panic!("Attempted to read out of bounds from BIOS");
            }
        } else {
            panic!("Unhandled 32-bit read from address: 0x{:08X}", address);
        }
    }

    fn ranged_write32(&mut self, address: u32, value: u32) {
        if let Some(offset) = map::RAM.contains(address) {
            // Write to RAM
            let offset = offset as usize;
            if offset + 4 <= self.ram.len() {
                self.ram[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
            } else {
                panic!("Attempted to write out of bounds to RAM");
            }
        } else {
            panic!("Unhandled 32-bit write to address: 0x{:08X}", address);
        }
    }

    fn sw_fmem_read32(&self, address: u32) -> u32 {
        panic!("Unimplemented software fastmem 32-bit read!");
    }

    fn sw_fmem_write32(&mut self, address: u32, value: u32) {
        panic!("Unimplemented software fastmem 32-bit write!");
    }
}