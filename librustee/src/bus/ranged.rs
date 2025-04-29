use super::map;
use super::Bus;

impl Bus {
    pub fn ranged_read32(&self, address: u32) -> u32 {
        if let Some(offset) = map::RAM.contains(address) {
            let offset = offset as usize;
            if offset + 4 <= self.ram.len() {
                let bytes = &self.ram[offset..offset + 4];
                u32::from_le_bytes(bytes.try_into().expect("Ranged: Failed to convert bytes!"))
            } else {
                panic!("Range: Attempted to read out of bounds from RAM");
            }
        } else if let Some(offset) = map::BIOS.contains(address) {
            let offset = offset as usize;
            if offset + 4 <= self.bios.bytes.len() {
                let bytes = &self.bios.bytes[offset..offset + 4];
                u32::from_le_bytes(bytes.try_into().expect("Ranged: Failed to convert bytes!"))
            } else {
                panic!("Range: Attempted to read out of bounds from BIOS");
            }
        } else {
            panic!("Ranged: Unhandled 32-bit read from address: 0x{:08X}", address);
        }
    }

    pub fn ranged_write32(&mut self, address: u32, value: u32) {
        if let Some(offset) = map::RAM.contains(address) {
            let offset = offset as usize;
            if offset + 4 <= self.ram.len() {
                self.ram[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
            } else {
                panic!("Ranged: Attempted to write out of bounds to RAM");
            }
        } else {
            panic!("Ranged: Unhandled 32-bit write to address: 0x{:08X}", address);
        }
    }
}