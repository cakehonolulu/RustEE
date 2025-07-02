use tracing::debug;
use super::{map, tlb::mask_to_page_size, Bus, PAGE_BITS, PAGE_SIZE};
use crate::bus::tlb::{AccessType, TlbEntry};

pub fn init_software_fastmem(bus: &mut Bus) {
    debug!("Initializing Software Fast Memory...");
    bus.page_read.fill(0);
    bus.page_write.fill(0);
    debug!("Software Fast Memory tables cleared");

    let default_mappings = [
        TlbEntry {
            vpn2: 0x0000_0000 >> 13,
            asid: 0,
            g: true,
            pfn0: 0x0000_0000 >> 12,
            pfn1: 0x0010_0000 >> 12,
            v0: true,
            d0: true,
            v1: true,
            d1: true,
            s0: false,
            s1: false,
            c0: 0,
            c1: 0,
            mask: 0x001F_E000,
        },
        TlbEntry {
            vpn2: 0x1FC0_0000 >> 13,
            asid: 0,
            g: true,
            pfn0: 0x1FC0_0000 >> 12,
            pfn1: 0x1FD0_0000 >> 12,
            v0: true,
            d0: false,
            v1: true,
            d1: false,
            s0: false,
            s1: false,
            c0: 0,
            c1: 0,
            mask: 0x001F_E000,
        },
    ];

    let bus_ptr = bus as *mut Bus;
    for (index, entry) in default_mappings.iter().enumerate() {
        {
            let mut tlb_ref = bus.tlb.borrow_mut();
            tlb_ref.write_tlb_entry(bus_ptr, index, *entry);
        }
        bus.tlb.borrow().install_sw_fastmem_mapping(bus, entry);
        debug!("Installed SW-FMEM TLB mapping: {:?}", entry);
    }

    debug!("Software Fast Memory initialized with predefined TLB mappings.");
}

impl Bus {
    pub fn sw_fmem_read32(&mut self, va: u32) -> u32 {
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

    pub fn sw_fmem_write64(&mut self, va: u32, value: u64) {
        let page = (va as usize) >> PAGE_BITS;
        let offset = (va as usize) & (PAGE_SIZE - 1);
        let host = self.page_write[page];
        if host != 0 {
            unsafe { (host as *mut u8).add(offset).cast::<u64>().write_unaligned(value) }
        } else {
            self.retry_write(va, value);
        }
    }

    fn retry_read(&mut self, va: u32) -> u32 {
        let pa = {
            let mut tlb = self.tlb.borrow_mut();
            match tlb.translate_address(va, AccessType::Read, self.operating_mode, self.read_cop0_asid()) {
                Ok(pa) => pa,
                Err(e) => panic!("SW-FMEM TLB exception on read VA=0x{:08X}: {:?}", va, e),
            }
        };

        let vpn = (va as usize) >> PAGE_BITS;
        let offset = (pa as usize) & (PAGE_SIZE - 1);

        if let Some(roff) = map::RAM.contains(pa) {
            let host = self.ram.as_ptr() as usize + (roff as usize);
            unsafe {
                (self.page_read.as_ptr() as *mut usize).add(vpn).write(host);
                (self.page_write.as_ptr() as *mut usize).add(vpn).write(host);
                return (host as *const u8).add(offset).cast::<u32>().read_unaligned();
            }
        } else if let Some(boff) = map::BIOS.contains(pa) {
            let host = self.bios.bytes.as_ptr() as usize + (boff as usize);
            unsafe {
                (self.page_read.as_ptr() as *mut usize).add(vpn).write(host);
                (self.page_write.as_ptr() as *mut usize).add(vpn).write(0);
                return (host as *const u8).add(offset).cast::<u32>().read_unaligned();
            }
        } else if map::IO.contains(pa).is_some() {
            return self.io_read32(pa)
        }

        let tlb = self.tlb.borrow_mut();
        tlb.install_all_sw_fastmem_mappings(self);
        let host = self.page_read[vpn];
        if host == 0 {
            panic!("SW-FMEM retry still unmapped VA=0x{:08X}", va);
        }
        unsafe { (host as *const u8).add(offset).cast::<u32>().read_unaligned() }
    }

    pub fn retry_write<V>(&mut self, va: u32, value: V)
    where
        V: TryInto<u128>,
        V::Error: std::fmt::Debug,
    {
        let pa = {
            let mut tlb = self.tlb.borrow_mut();
            match tlb.translate_address(va, AccessType::Read, self.operating_mode, self.read_cop0_asid()) {
                Ok(pa) => pa,
                Err(e) => panic!("SW-FMEM TLB exception on write VA=0x{:08X}: {:?}", va, e),
            }
        };

        let vpn = (va as usize) >> PAGE_BITS;
        let offset = (pa as usize) & (PAGE_SIZE - 1);

        let val128: u128 = value.try_into().unwrap();
        let size = std::mem::size_of::<V>();

        if let Some(roff) = map::RAM.contains(pa) {
            let host = self.ram.as_ptr() as usize + (roff as usize);
            unsafe {
                (self.page_read .as_ptr() as *mut usize).add(vpn).write(host);
                (self.page_write.as_ptr() as *mut usize).add(vpn).write(host);
                let ptr = (host as *mut u8).add(offset);
                match size {
                    1 => ptr.cast::<u8>().write_unaligned(val128 as u8),
                    2 => ptr.cast::<u16>().write_unaligned(val128 as u16),
                    4 => ptr.cast::<u32>().write_unaligned(val128 as u32),
                    8 => ptr.cast::<u64>().write_unaligned(val128 as u64),
                    16 => ptr.cast::<u128>().write_unaligned(val128),
                    _ => unreachable!("Unsupported write size {}", size),
                }
            }
            return;
        } else if let Some(boff) = map::BIOS.contains(pa) {
            let host = self.bios.bytes.as_ptr() as usize + (boff as usize);
            unsafe {
                (self.page_read .as_ptr() as *mut usize).add(vpn).write(host);
                (self.page_write.as_ptr() as *mut usize).add(vpn).write(0);
            }
            panic!("SW-FMEM write to read-only BIOS VA=0x{:08X}", va);
        } else if map::IO.contains(pa).is_some() {
            match size {
                1 => todo!("IO Write 8"),
                2 => todo!("IO Write 16"),
                4 => self.io_write32(pa, val128 as u32),
                8 => todo!("IO Write 64"),
                _ => unreachable!("Unsupported I/O write size {}", size),
            }
            return;
        }

        let tlb = self.tlb.borrow_mut();
        tlb.install_all_sw_fastmem_mappings(self);
        let host = self.page_write[vpn];
        if host == 0 {
            panic!("SW-FMEM retry still unmapped or read-only VA=0x{:08X}", va);
        }
        unsafe {
            let ptr = (host as usize as *mut u8).add(offset);
            match size {
                1 => ptr.cast::<u8>().write_unaligned(val128 as u8),
                2 => ptr.cast::<u16>().write_unaligned(val128 as u16),
                4 => ptr.cast::<u32>().write_unaligned(val128 as u32),
                8 => ptr.cast::<u64>().write_unaligned(val128 as u64),
                16 => ptr.cast::<u128>().write_unaligned(val128),
                _ => unreachable!("Unsupported write size {}", size),
            }
        }
    }
}

use super::tlb::Tlb;
impl Tlb {
    pub fn install_all_sw_fastmem_mappings(&self, bus: &Bus) {
        for entry in self.entries.iter().flatten() {
            self.install_sw_fastmem_mapping(bus, entry);
        }
    }

    pub fn install_sw_fastmem_mapping(&self, bus: &Bus, entry: &TlbEntry) {
        let page_size = mask_to_page_size(entry.mask) as u64;
        let start_va = (entry.vpn2 as u64) << 13;
        let pfn0 = entry.pfn0 as u64;
        let pfn1 = entry.pfn1 as u64;

        // even page
        if entry.v0 {
            let start_vpn = (start_va >> 12) as usize;
            let end_vpn   = ((start_va + page_size) >> 12) as usize;
            for vpn in start_vpn..end_vpn {
                let offset = ((vpn as u64 * 4096) - start_va) & (page_size - 1);
                let pa = (pfn0 << 12) + offset;
                if let Some(roff) = map::RAM.contains(pa as u32) {
                    let host = bus.ram.as_ptr() as usize + roff as usize;
                    let pr = bus.page_read.as_ptr() as *mut usize;
                    let pw = bus.page_write.as_ptr() as *mut usize;

                    unsafe {
                        *pr.add(vpn) = host;
                        *pw.add(vpn) = if entry.d0 { host } else { 0 };
                    }
                } else if let Some(boff) = map::BIOS.contains(pa as u32) {
                    let host = bus.bios.bytes.as_ptr() as usize + boff as usize;
                    let pr = bus.page_read.as_ptr() as *mut usize;
                    let pw = bus.page_write.as_ptr() as *mut usize;

                    unsafe {
                        *pr.add(vpn) = host;
                        *pw.add(vpn) = 0;
                    }
                } else {
                    let pr = bus.page_read.as_ptr() as *mut usize;
                    let pw = bus.page_write.as_ptr() as *mut usize;

                    unsafe {
                        *pr.add(vpn) = 0;
                        *pw.add(vpn) = 0;
                    }
                }
            }
        }

        // odd page
        if entry.v1 {
            let start_va_odd = start_va + page_size;
            let start_vpn    = (start_va_odd >> 12) as usize;
            let end_vpn      = ((start_va_odd + page_size) >> 12) as usize;
            for vpn in start_vpn..end_vpn {
                let offset = ((vpn as u64 * 4096) - start_va_odd) & (page_size - 1);
                let pa = (pfn1 << 12) + offset;
                if let Some(roff) = map::RAM.contains(pa as u32) {
                    let host = bus.ram.as_ptr() as usize + roff as usize;
                    let pr = bus.page_read.as_ptr() as *mut usize;
                    let pw = bus.page_write.as_ptr() as *mut usize;

                    unsafe {
                        *pr.add(vpn) = host;
                        *pw.add(vpn) = if entry.d1 { host } else { 0 };
                    }
                } else if let Some(boff) = map::BIOS.contains(pa as u32) {
                    let host = bus.bios.bytes.as_ptr() as usize + boff as usize;
                    let pr = bus.page_read.as_ptr() as *mut usize;
                    let pw = bus.page_write.as_ptr() as *mut usize;

                    unsafe {
                        *pr.add(vpn) = host;
                        *pw.add(vpn) = 0;
                    }
                } else {
                    let pr = bus.page_read.as_ptr() as *mut usize;
                    let pw = bus.page_write.as_ptr() as *mut usize;

                    unsafe {
                        *pr.add(vpn) = 0;
                        *pw.add(vpn) = 0;
                    }
                }
            }
        }
    }

    pub fn clear_sw_fastmem_mapping(&self, bus: &mut Bus, entry: &TlbEntry) {
        let page_size = mask_to_page_size(entry.mask) as u64;
        let start_va = (entry.vpn2 as u64) << 13;
        let total_size = 2 * page_size;
        let start_vpn = (start_va >> 12) as usize;
        let end_vpn = ((start_va + total_size) >> 12) as usize;
        for vpn in start_vpn..end_vpn {
            bus.page_read[vpn] = 0;
            bus.page_write[vpn] = 0;
        }
    }
}