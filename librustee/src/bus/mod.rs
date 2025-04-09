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
}

pub struct Bus {
    bios: BIOS
}

impl Bus {
    pub fn new(bios: BIOS) -> Bus {
        Bus {
            bios: bios
        }
    }

    pub fn read32(&self, addr: u32) -> u32 {

        if let Some(offset) = map::BIOS.contains(addr) {
            return self.bios.read32(offset);
        }

        panic!("Unhandled 32-bit read from address: 0x{:08X}", addr);
    }
}