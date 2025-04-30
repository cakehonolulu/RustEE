use tracing::debug;
use super::{map, tlb::mask_to_page_size, Bus, PAGE_BITS, PAGE_SIZE};
use crate::bus::tlb::{AccessType, Exception, TlbEntry};

pub fn init_software_fastmem(bus: &mut Bus) {
    debug!("Initializing Software Fast Memory...");
    bus.page_read.fill(0);
    bus.page_write.fill(0);
    debug!("Software Fast Memory tables cleared");
}

impl Bus {
    pub fn sw_fmem_read32(&self, va: u32) -> u32 {
        let page = (va as usize) >> PAGE_BITS;
        let offset = (va as usize) & (PAGE_SIZE - 1);
        let host = self.page_read[page];
        if host != 0 {
            unsafe { (host as *const u8).add(offset).cast::<u32>().read_unaligned() }
        } else {
            self.retry_read(va)
        }
    }

    pub fn sw_fmem_write32(&mut self, va: u32, value: u32) {
        let page = (va as usize) >> PAGE_BITS;
        let offset = (va as usize) & (PAGE_SIZE - 1);
        let host = self.page_write[page];
        if host != 0 {
            unsafe { (host as *mut u8).add(offset).cast::<u32>().write_unaligned(value) }
        } else {
            self.retry_write(va, value);
        }
    }

    fn retry_read(&self, va: u32) -> u32 {
        let mut tlb = self.tlb.borrow_mut();
        let pa = match tlb.translate_address(va, AccessType::Read, self.operating_mode, self.read_cop0_asid()) {
            Ok(p) => p,
            Err(e) => panic!("SW-FMEM TLB exception on read VA=0x{:08X}: {:?}", va, e),
        };

        let vpn    = (va as usize) >> PAGE_BITS;
        let offset = (pa as usize) & (PAGE_SIZE - 1);

        if let Some(roff) = map::RAM.contains(pa) {
            let host = self.ram.as_ptr() as usize + (roff as usize);
            unsafe {
                (self.page_read.as_ptr() as *mut usize).add(vpn).write(host);
                (self.page_write.as_ptr() as *mut usize).add(vpn).write(host);
                return (host as *const u8).add(offset).cast::<u32>().read_unaligned();
            }
        }

        if let Some(boff) = map::BIOS.contains(pa) {
            let host = self.bios.bytes.as_ptr() as usize + (boff as usize);
            unsafe {
                (self.page_read.as_ptr() as *mut usize).add(vpn).write(host);
                (self.page_write.as_ptr() as *mut usize).add(vpn).write(0);
                return (host as *const u8).add(offset).cast::<u32>().read_unaligned();
            }
        }

        tlb.install_sw_fastmem_mapping(self);

        let host = self.page_read[vpn];
        if host == 0 {
            panic!("SW-FMEM retry still unmapped VA=0x{:08X}", va);
        }
        unsafe { (host as *const u8).add(offset).cast::<u32>().read_unaligned() }
    }

    fn retry_write(&mut self, va: u32, value: u32) {
        let mut tlb = self.tlb.borrow_mut();
        let pa = match tlb.translate_address(va, AccessType::Write, self.operating_mode, self.read_cop0_asid()) {
            Ok(p) => p,
            Err(e) => panic!("SW-FMEM TLB exception on write VA=0x{:08X}: {:?}", va, e),
        };

        let vpn    = (va as usize) >> PAGE_BITS;
        let offset = (pa as usize) & (PAGE_SIZE - 1);

        if let Some(roff) = map::RAM.contains(pa) {
            let host = self.ram.as_ptr() as usize + (roff as usize);
            unsafe {
                (self.page_read.as_ptr() as *mut usize).add(vpn).write(host);
                (self.page_write.as_ptr() as *mut usize).add(vpn).write(host);
                (host as *mut u8).add(offset).cast::<u32>().write_unaligned(value);
            }
            return;
        }

        if let Some(boff) = map::BIOS.contains(pa) {
            let host = self.bios.bytes.as_ptr() as usize + (boff as usize);
            unsafe {
                (self.page_read.as_ptr() as *mut usize).add(vpn).write(host);
                (self.page_write.as_ptr() as *mut usize).add(vpn).write(0);
            }
            panic!("SW-FMEM write to read-only BIOS VA=0x{:08X}", va);
        }

        tlb.install_sw_fastmem_mapping(self);

        let host = self.page_write[vpn];
        if host == 0 {
            panic!("SW-FMEM retry still unmapped or read-only VA=0x{:08X}", va);
        }
        unsafe { (host as *mut u8).add(offset).cast::<u32>().write_unaligned(value) }
    }
}

use super::tlb::Tlb;
impl Tlb {
    pub fn install_sw_fastmem_mapping(&self, bus: &Bus) {
        for entry in self.entries.iter().flatten() {
            let page_size = mask_to_page_size(entry.mask) as usize;
            let pages = page_size / PAGE_SIZE;
            let base_vpn = (entry.vpn2 as usize) >> PAGE_BITS & !(pages - 1);
            for i in 0..pages {
                let vpn = base_vpn + i;
                let pfn = if i % 2 == 0 { entry.pfn0 as usize } else { entry.pfn1 as usize };
                let can_write = if i % 2 == 0 { entry.d0 } else { entry.d1 };
                let host_base = (bus.ram.as_ptr() as usize).wrapping_add(pfn << PAGE_BITS);
                let pr_ptr = bus.page_read.as_ptr() as *mut usize;
                let pw_ptr = bus.page_write.as_ptr() as *mut usize;
                unsafe {
                    pr_ptr.add(vpn).write(host_base);
                    pw_ptr.add(vpn).write(if can_write { host_base } else { 0 });
                }
            }
        }
    }

    pub fn clear_sw_fastmem_mapping(&self, bus: &Bus, old: &TlbEntry) {
        let page_size = mask_to_page_size(old.mask) as usize;
        let pages = page_size / PAGE_SIZE;
        let base_vpn = (old.vpn2 as usize) >> PAGE_BITS & !(pages - 1);
        for i in 0..pages {
            let vpn = base_vpn + i;
            let pr_ptr = bus.page_read.as_ptr() as *mut usize;
            let pw_ptr = bus.page_write.as_ptr() as *mut usize;
            unsafe {
                pr_ptr.add(vpn).write(0);
                pw_ptr.add(vpn).write(0);
            }
        }
    }
}
