use super::{Bus, PAGE_BITS, PAGE_SIZE, map, tlb::mask_to_page_size};
use crate::bus::tlb::{AccessType, TlbEntry};
use tracing::debug;

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
        TlbEntry {
            vpn2: 0x7000_0000 >> 13,
            asid: 0,
            g: true,
            pfn0: 0x7000_0000 >> 12,
            pfn1: 0,
            v0: true,
            d0: true,
            v1: false,
            d1: false,
            s0: false,
            s1: false,
            c0: 0,
            c1: 0,
            mask: 0x0000_6000,
        },
    ];

    let bus_ptr = bus as *mut Bus;
    for (index, entry) in default_mappings.iter().enumerate() {
        {
            let tlb = &mut bus.tlb;
            tlb.write_tlb_entry(bus_ptr, index, *entry);
        }

        bus.tlb.install_sw_fastmem_mapping(bus, entry);
        debug!("Installed SW-FMEM TLB mapping: {:?}", entry);
    }

    let ram_start_va_k0: usize = 0x8000_0000;
    let ram_size: usize = 32 * 1024 * 1024;
    let ram_end_va_k0 = ram_start_va_k0 + ram_size;
    let ram_start_vpn_k0 = ram_start_va_k0 >> PAGE_BITS;
    let ram_end_vpn_k0 = ram_end_va_k0 >> PAGE_BITS;
    for vpn in ram_start_vpn_k0..ram_end_vpn_k0 {
        let va = vpn << PAGE_BITS;
        let offset = va - ram_start_va_k0;
        let host = bus.ram.as_ptr() as usize + offset;
        bus.page_read[vpn] = host;
        bus.page_write[vpn] = host;
    }

    let ram_start_va_k1: usize = 0xA000_0000;
    let ram_end_va_k1 = ram_start_va_k1 + ram_size;
    let ram_start_vpn_k1 = ram_start_va_k1 >> PAGE_BITS;
    let ram_end_vpn_k1 = ram_end_va_k1 >> PAGE_BITS;
    for vpn in ram_start_vpn_k1..ram_end_vpn_k1 {
        let va = vpn << PAGE_BITS;
        let offset = va - ram_start_va_k1;
        let host = bus.ram.as_ptr() as usize + offset;
        bus.page_read[vpn] = host;
        bus.page_write[vpn] = host;
    }

    let bios_start_va_k0: usize = 0x9FC0_0000;
    let bios_size: usize = 4 * 1024 * 1024;
    let bios_end_va_k0 = bios_start_va_k0 + bios_size;
    let bios_start_vpn_k0 = bios_start_va_k0 >> PAGE_BITS;
    let bios_end_vpn_k0 = bios_end_va_k0 >> PAGE_BITS;
    for vpn in bios_start_vpn_k0..bios_end_vpn_k0 {
        let va = vpn << PAGE_BITS;
        let offset = va - bios_start_va_k0;
        let host = bus.bios.bytes.as_ptr() as usize + offset;
        bus.page_read[vpn] = host;
        bus.page_write[vpn] = 0;
    }

    let bios_start_va_k1: usize = 0xBFC0_0000;
    let bios_end_va_k1 = bios_start_va_k1 + bios_size;
    let bios_start_vpn_k1 = bios_start_va_k1 >> PAGE_BITS;
    let bios_end_vpn_k1 = bios_end_va_k1 >> PAGE_BITS;
    for vpn in bios_start_vpn_k1..bios_end_vpn_k1 {
        let va = vpn << PAGE_BITS;
        let offset = va - bios_start_va_k1;
        let host = bus.bios.bytes.as_ptr() as usize + offset;
        bus.page_read[vpn] = host;
        bus.page_write[vpn] = 0;
    }

    debug!("Software Fast Memory initialized with predefined TLB mappings.");
}

impl Bus {
    pub fn sw_fmem_read8(&mut self, va: u32) -> u8 {
        let page = (va as usize) >> PAGE_BITS;
        let offset = (va as usize) & (PAGE_SIZE - 1);
        let host = self.page_read[page];
        if host != 0 {
            unsafe {
                (host as *const u8)
                    .add(offset)
                    .read_unaligned()
            }
        } else {
            if let Some(sp_offset) = map::SCRATCHPAD.contains(va) {
                return unsafe { (self.scratchpad.as_ptr().add(sp_offset as usize) as *const u8).read_unaligned() };
            }

            let cop0_asid = {
                self.read_cop0_asid()
            };
            let operating_mode = self.operating_mode;

            let pa = {
                let tlb = &mut self.tlb;
                tlb.translate_address(
                    va,
                    AccessType::WriteDoubleword,
                    operating_mode,
                    cop0_asid,
                ).unwrap_or_else(|e| va)
            };
            self.io_read8(pa)
        }
    }

    pub fn sw_fmem_read16(&mut self, va: u32) -> u16 {
        let page = (va as usize) >> PAGE_BITS;
        let offset = (va as usize) & (PAGE_SIZE - 1);
        let host = self.page_read[page];
        if host != 0 {
            unsafe {
                (host as *const u8)
                    .add(offset)
                    .cast::<u16>()
                    .read_unaligned()
            }
        } else {
            if let Some(sp_offset) = map::SCRATCHPAD.contains(va) {
                return unsafe { (self.scratchpad.as_ptr().add(sp_offset as usize) as *const u16).read_unaligned() };
            }

            let cop0_asid = {
                self.read_cop0_asid()
            };
            let operating_mode = self.operating_mode;

            let pa = {
                let tlb = &mut self.tlb;
                tlb.translate_address(
                    va,
                    AccessType::WriteDoubleword,
                    operating_mode,
                    cop0_asid,
                ).unwrap_or_else(|e| va)
            };
            self.io_read16(pa)
        }
    }

    pub fn sw_fmem_read32(&mut self, va: u32) -> u32 {
        let page = (va as usize) >> PAGE_BITS;
        let offset = (va as usize) & (PAGE_SIZE - 1);
        let host = self.page_read[page];
        if host != 0 {
            unsafe {
                (host as *const u8)
                    .add(offset)
                    .cast::<u32>()
                    .read_unaligned()
            }
        } else {
            if let Some(sp_offset) = map::SCRATCHPAD.contains(va) {
                return unsafe { (self.scratchpad.as_ptr().add(sp_offset as usize) as *const u32).read_unaligned() };
            }

            let cop0_asid = {
                self.read_cop0_asid()
            };
            let operating_mode = self.operating_mode;

            let pa = {
                let tlb = &mut self.tlb;
                tlb.translate_address(
                    va,
                    AccessType::WriteDoubleword,
                    operating_mode,
                    cop0_asid,
                ).unwrap_or_else(|e| va)
            };
            self.io_read32(pa)
        }
    }

    pub fn sw_fmem_read64(&mut self, va: u32) -> u64 {
        let page = (va as usize) >> PAGE_BITS;
        let offset = (va as usize) & (PAGE_SIZE - 1);
        let host = self.page_read[page];
        if host != 0 {
            unsafe {
                (host as *const u8)
                    .add(offset)
                    .cast::<u64>()
                    .read_unaligned()
            }
        } else {
            if let Some(sp_offset) = map::SCRATCHPAD.contains(va) {
                return unsafe { (self.scratchpad.as_ptr().add(sp_offset as usize) as *const u64).read_unaligned() };
            }

            let cop0_asid = {
                self.read_cop0_asid()
            };
            let operating_mode = self.operating_mode;

            let pa = {
                let tlb = &mut self.tlb;
                tlb.translate_address(
                    va,
                    AccessType::WriteDoubleword,
                    operating_mode,
                    cop0_asid,
                ).unwrap_or_else(|e| va)
            };
            self.io_read64(pa)
        }
    }

    pub fn sw_fmem_read128(&mut self, va: u32) -> u128 {
        let page = (va as usize) >> PAGE_BITS;
        let offset = (va as usize) & (PAGE_SIZE - 1);
        let host = self.page_read[page];
        if host != 0 {
            unsafe {
                (host as *const u8)
                    .add(offset)
                    .cast::<u128>()
                    .read_unaligned()
            }
        } else {
            if let Some(sp_offset) = map::SCRATCHPAD.contains(va) {
                return unsafe { (self.scratchpad.as_ptr().add(sp_offset as usize) as *const u128).read_unaligned() };
            }

            let cop0_asid = {
                self.read_cop0_asid()
            };
            let operating_mode = self.operating_mode;

            let pa = {
                let tlb = &mut self.tlb;
                tlb.translate_address(
                    va,
                    AccessType::WriteDoubleword,
                    operating_mode,
                    cop0_asid,
                ).unwrap_or_else(|e| va)
            };
            self.io_read128(pa)
        }
    }

    pub fn sw_fmem_write8(&mut self, va: u32, value: u8) {
        let page = (va as usize) >> PAGE_BITS;
        let offset = (va as usize) & (PAGE_SIZE - 1);
        let host = self.page_write[page];
        if host != 0 {
            unsafe {
                (host as *mut u8)
                    .add(offset)
                    .write_unaligned(value)
            }
        } else {
            if let Some(sp_offset) = map::SCRATCHPAD.contains(va) {
                unsafe { (self.scratchpad.as_mut_ptr().add(sp_offset as usize) as *mut u8).write_unaligned(value) }
                return;
            }

            let cop0_asid = {
                self.read_cop0_asid()
            };
            let operating_mode = self.operating_mode;

            let pa = {
                let tlb = &mut self.tlb;
                tlb.translate_address(
                    va,
                    AccessType::WriteDoubleword,
                    operating_mode,
                    cop0_asid,
                ).unwrap_or_else(|e| va)
            };
            self.io_write8(pa, value)
        }
    }

    pub fn sw_fmem_write16(&mut self, va: u32, value: u16) {
        let page = (va as usize) >> PAGE_BITS;
        let offset = (va as usize) & (PAGE_SIZE - 1);
        let host = self.page_write[page];
        if host != 0 {
            unsafe {
                (host as *mut u8)
                    .add(offset)
                    .cast::<u16>()
                    .write_unaligned(value)
            }
        } else {
            if let Some(sp_offset) = map::SCRATCHPAD.contains(va) {
                unsafe { (self.scratchpad.as_mut_ptr().add(sp_offset as usize) as *mut u16).write_unaligned(value) }
                return;
            }

            let cop0_asid = {
                self.read_cop0_asid()
            };
            let operating_mode = self.operating_mode;

            let pa = {
                let tlb = &mut self.tlb;
                tlb.translate_address(
                    va,
                    AccessType::WriteDoubleword,
                    operating_mode,
                    cop0_asid,
                ).unwrap_or_else(|e| va)
            };
            self.io_write16(pa, value)
        }
    }

    pub fn sw_fmem_write32(&mut self, va: u32, value: u32) {
        let page = (va as usize) >> PAGE_BITS;
        let offset = (va as usize) & (PAGE_SIZE - 1);
        let host = self.page_write[page];
        if host != 0 {
            unsafe {
                (host as *mut u8)
                    .add(offset)
                    .cast::<u32>()
                    .write_unaligned(value)
            }
        } else {
            if let Some(sp_offset) = map::SCRATCHPAD.contains(va) {
                unsafe { (self.scratchpad.as_mut_ptr().add(sp_offset as usize) as *mut u32).write_unaligned(value) }
                return;
            }

            let cop0_asid = {
                self.read_cop0_asid()
            };
            let operating_mode = self.operating_mode;

            let pa = {
                let tlb = &mut self.tlb;
                tlb.translate_address(
                    va,
                    AccessType::WriteDoubleword,
                    operating_mode,
                    cop0_asid,
                ).unwrap_or_else(|e| va)
            };
            self.io_write32(pa, value)
        }
    }

    pub fn sw_fmem_write64(&mut self, va: u32, value: u64) {
        let page = (va as usize) >> PAGE_BITS;
        let offset = (va as usize) & (PAGE_SIZE - 1);
        let host = self.page_write[page];
        if host != 0 {
            unsafe {
                (host as *mut u8)
                    .add(offset)
                    .cast::<u64>()
                    .write_unaligned(value)
            }
        } else {
            if let Some(sp_offset) = map::SCRATCHPAD.contains(va) {
                unsafe { (self.scratchpad.as_mut_ptr().add(sp_offset as usize) as *mut u64).write_unaligned(value) }
                return;
            }

            let cop0_asid = {
                self.read_cop0_asid()
            };
            let operating_mode = self.operating_mode;

            let pa = {
                let tlb = &mut self.tlb;
                tlb.translate_address(
                    va,
                    AccessType::WriteDoubleword,
                    operating_mode,
                    cop0_asid,
                ).unwrap_or_else(|e| va)
            };
            self.io_write64(pa, value)
        }
    }

    pub fn sw_fmem_write128(&mut self, va: u32, value: u128) {
        let page = (va as usize) >> PAGE_BITS;
        let offset = (va as usize) & (PAGE_SIZE - 1);
        let host = self.page_write[page];
        if host != 0 {
            unsafe {
                (host as *mut u8)
                    .add(offset)
                    .cast::<u128>()
                    .write_unaligned(value)
            }
        } else {
            if let Some(sp_offset) = map::SCRATCHPAD.contains(va) {
                unsafe { (self.scratchpad.as_mut_ptr().add(sp_offset as usize) as *mut u128).write_unaligned(value) }
                return;
            }

            let cop0_asid = {
                self.read_cop0_asid()
            };
            let operating_mode = self.operating_mode;

            let pa = {
                let tlb = &mut self.tlb;
                tlb.translate_address(
                    va,
                    AccessType::WriteDoubleword,
                    operating_mode,
                    cop0_asid,
                ).unwrap_or_else(|e| va)
            };
            self.io_write128(pa, value)
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
            let end_vpn = ((start_va + page_size) >> 12) as usize;
            for vpn in start_vpn..end_vpn {
                let offset = ((vpn as u64 * 4096) - start_va) & (page_size - 1);
                let pa = (pfn0 << 12) + offset;
                let pr = bus.page_read.as_ptr() as *mut usize;
                let pw = bus.page_write.as_ptr() as *mut usize;

                if let Some(roff) = map::RAM.contains(pa as u32) {
                    let host = bus.ram.as_ptr() as usize + roff as usize;
                    unsafe {
                        *pr.add(vpn) = host;
                        *pw.add(vpn) = if entry.d0 { host } else { 0 };
                    }
                } else if let Some(boff) = map::BIOS.contains(pa as u32) {
                    let host = bus.bios.bytes.as_ptr() as usize + boff as usize;
                    unsafe {
                        *pr.add(vpn) = host;
                        *pw.add(vpn) = 0;
                    }
                } else if let Some(soff) = map::SCRATCHPAD.contains(pa as u32) {
                    let host = bus.scratchpad.as_ptr() as usize + soff as usize;
                    unsafe {
                        *pr.add(vpn) = host;
                        *pw.add(vpn) = if entry.d0 { host } else { 0 };
                    }
                } else if let Some(voff) = map::VU0.contains(pa as u32) {
                    let host = if (pa as u32) < 0x1100_1000 {
                        bus.vu0_data.as_ptr() as usize + voff as usize
                    } else {
                        bus.vu0_code.as_ptr() as usize + (voff as usize - 0x1000)
                    };
                    unsafe {
                        *pr.add(vpn) = host;
                        *pw.add(vpn) = if entry.d0 { host } else { 0 };
                    }
                } else if let Some(voff) = map::VU1.contains(pa as u32) {
                    let host = if (pa as u32) < 0x1100_C000 {
                        bus.vu1_data.as_ptr() as usize + voff as usize
                    } else {
                        bus.vu1_code.as_ptr() as usize + (voff as usize - 0x4000)
                    };
                    unsafe {
                        *pr.add(vpn) = host;
                        *pw.add(vpn) = if entry.d0 { host } else { 0 };
                    }
                } else {
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
            let start_vpn = (start_va_odd >> 12) as usize;
            let end_vpn = ((start_va_odd + page_size) >> 12) as usize;
            for vpn in start_vpn..end_vpn {
                let offset = ((vpn as u64 * 4096) - start_va_odd) & (page_size - 1);
                let pa = (pfn1 << 12) + offset;
                let pr = bus.page_read.as_ptr() as *mut usize;
                let pw = bus.page_write.as_ptr() as *mut usize;

                if let Some(roff) = map::RAM.contains(pa as u32) {
                    let host = bus.ram.as_ptr() as usize + roff as usize;
                    unsafe {
                        *pr.add(vpn) = host;
                        *pw.add(vpn) = if entry.d1 { host } else { 0 };
                    }
                } else if let Some(boff) = map::BIOS.contains(pa as u32) {
                    let host = bus.bios.bytes.as_ptr() as usize + boff as usize;
                    unsafe {
                        *pr.add(vpn) = host;
                        *pw.add(vpn) = 0;
                    }
                } else if let Some(soff) = map::SCRATCHPAD.contains(pa as u32) {
                    let host = bus.scratchpad.as_ptr() as usize + soff as usize;
                    unsafe {
                        *pr.add(vpn) = host;
                        *pw.add(vpn) = if entry.d1 { host } else { 0 };
                    }
                } else if let Some(voff) = map::VU0.contains(pa as u32) {
                    let host = if (pa as u32) < 0x1100_1000 {
                        bus.vu0_data.as_ptr() as usize + voff as usize
                    } else {
                        bus.vu0_code.as_ptr() as usize + (voff as usize - 0x1000)
                    };
                    unsafe {
                        *pr.add(vpn) = host;
                        *pw.add(vpn) = if entry.d1 { host } else { 0 };
                    }
                } else if let Some(voff) = map::VU1.contains(pa as u32) {
                    let host = if (pa as u32) < 0x1100_C000 {
                        bus.vu1_data.as_ptr() as usize + voff as usize
                    } else {
                        bus.vu1_code.as_ptr() as usize + (voff as usize - 0x4000)
                    };
                    unsafe {
                        *pr.add(vpn) = host;
                        *pw.add(vpn) = if entry.d1 { host } else { 0 };
                    }
                } else {
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