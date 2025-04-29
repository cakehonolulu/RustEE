use tracing::debug;

use super::{Bus, PAGE_BITS, PAGE_SIZE};

pub fn init_software_fastmem(bus: &mut Bus) {
    debug!("Initializing Software Fast Memory...");
    for page in 0..(32 * 1024 * 1024 / PAGE_SIZE) {
        let host_ptr = bus.ram.as_ptr() as usize + page * PAGE_SIZE;
        bus.page_read[page] = host_ptr;
        bus.page_write[page] = host_ptr;
    }
    let bios_ptr = bus.bios.bytes.as_ptr() as usize;
    let base = (super::map::BIOS.0 as usize) >> PAGE_BITS;
    let count = bus.bios.bytes.len() / PAGE_SIZE;
    for i in 0..count {
        bus.page_read[base + i] = bios_ptr + i * PAGE_SIZE;
    }
    debug!("Software Fast Memory initialized");
}

impl Bus {
    pub fn sw_fmem_read32(&self, address: u32) -> u32 {
        let page = (address as usize) >> PAGE_BITS;
        let offset = (address as usize) & (PAGE_SIZE - 1);
        let host = self.page_read[page];
        if host != 0 {
            unsafe {
                let ptr = (host as *const u8).add(offset) as *const u32;
                ptr.read_unaligned()
            }
        } else {
            panic!("SoftwareFastMem: Unhandled 32-bit read from address 0x{:08X}", address);
        }
    }

    pub fn sw_fmem_write32(&mut self, address: u32, value: u32) {
        let page = (address as usize) >> PAGE_BITS;
        let offset = (address as usize) & (PAGE_SIZE - 1);
        let host = self.page_write[page];
        if host != 0 {
            unsafe {
                let ptr = (host as *mut u8).add(offset) as *mut u32;
                ptr.write_unaligned(value);
            }
        } else {
            panic!("SoftwareFastMem: Unhandled 32-bit write to address 0x{:08X}", address);
        }
    }
}