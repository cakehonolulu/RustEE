use super::Bus;
use super::map;
use super::tlb::{AccessType, TlbEntry};

pub fn init_ranged_tlb_mappings(bus: &mut Bus) {
    tracing::debug!("Initializing Ranged TLB Mappings...");

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
            mask: 0x001F_E000, // 1MB page
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
            mask: 0x001F_E000, // 1MB page
        },
        TlbEntry {
            vpn2: 0x7000_0000 >> 13, // 0x38000
            asid: 0,
            g: true,
            pfn0: 0x7000_0000 >> 12, // 0x70000
            pfn1: 0,
            v0: true,
            d0: true,
            v1: false,
            d1: false,
            s0: false,
            s1: false,
            c0: 0,
            c1: 0,
            mask: 0x0000_6000, // 16KB page
        },
    ];

    let bus_ptr = bus as *mut Bus;
    let tlb = &mut (*bus).tlb;

    for (index, entry) in default_mappings.iter().enumerate() {
        {
            tlb.write_tlb_entry(bus_ptr, index, *entry);
        }
        tracing::debug!("Installed TLB mapping: {:?}", entry);
    }

    tracing::debug!("Ranged TLB Mappings initialized.");
}

impl Bus {
    pub fn ranged_read8(&mut self, va: u32) -> u8 {
        if let Some(offset) = map::SCRATCHPAD.contains(va) {
            let ptr = unsafe { self.scratchpad.as_ptr().add(offset as usize) } as *const u8;
            return unsafe { ptr.read_unaligned() }
        }

        let cop0_asid = {
            self.read_cop0_asid()
        };
        let operating_mode = self.operating_mode;

        let pa = {
            let tlb = &mut self.tlb;
            tlb.translate_address(
                va,
                AccessType::ReadByte,
                operating_mode,
                cop0_asid,
            ).unwrap_or_else(|_e| va)
        };

        if let Some(offset) = map::RAM.contains(pa) {
            let ptr = unsafe { self.ram.as_ptr().add(offset as usize) } as *const u8;
            unsafe { ptr.read_unaligned() }
        } else if let Some(offset) = map::SCRATCHPAD.contains(pa) {
            let ptr = unsafe { self.scratchpad.as_ptr().add(offset as usize) } as *const u8;
            unsafe { ptr.read_unaligned() }
        } else if let Some(offset) = map::BIOS.contains(pa) {
            let ptr = unsafe { self.bios.bytes.as_ptr().add(offset as usize) } as *const u8;
            unsafe { ptr.read_unaligned() }
        } else {
            self.io_read8(pa)
        }
    }

    pub fn ranged_read16(&mut self, va: u32) -> u16 {
        if let Some(offset) = map::SCRATCHPAD.contains(va) {
            let ptr = unsafe { self.scratchpad.as_ptr().add(offset as usize) } as *const u16;
            return unsafe { ptr.read_unaligned() }
        }

        let cop0_asid = {
            self.read_cop0_asid()
        };
        let operating_mode = self.operating_mode;

        let pa = {
            let tlb = &mut self.tlb;
            tlb.translate_address(
                va,
                AccessType::ReadHalfword,
                operating_mode,
                cop0_asid,
            ).unwrap_or_else(|_e| va)
        };

        if let Some(offset) = map::RAM.contains(pa) {
            let ptr = unsafe { self.ram.as_ptr().add(offset as usize) } as *const u16;
            unsafe { ptr.read_unaligned() }
        } else if let Some(offset) = map::SCRATCHPAD.contains(pa) {
            let ptr = unsafe { self.scratchpad.as_ptr().add(offset as usize) } as *const u16;
            unsafe { ptr.read_unaligned() }
        } else if let Some(offset) = map::BIOS.contains(pa) {
            let ptr = unsafe { self.bios.bytes.as_ptr().add(offset as usize) } as *const u16;
            unsafe { ptr.read_unaligned() }
        } else {
            self.io_read16(pa)
        }
    }

    pub fn ranged_read32(&mut self, va: u32) -> u32 {
        if let Some(offset) = map::SCRATCHPAD.contains(va) {
            let ptr = unsafe { self.scratchpad.as_ptr().add(offset as usize) } as *const u32;
            return unsafe { ptr.read_unaligned() }
        }

        let cop0_asid = {
            self.read_cop0_asid()
        };
        let operating_mode = self.operating_mode;

        let pa = {
            let tlb = &mut self.tlb;
            tlb.translate_address(
                va,
                AccessType::ReadWord,
                operating_mode,
                cop0_asid,
            ).unwrap_or_else(|_e| va)
        };

        if let Some(offset) = map::RAM.contains(pa) {
            let ptr = unsafe { self.ram.as_ptr().add(offset as usize) } as *const u32;
            unsafe { ptr.read_unaligned() }
        } else if let Some(offset) = map::SCRATCHPAD.contains(pa) {
            let ptr = unsafe { self.scratchpad.as_ptr().add(offset as usize) } as *const u32;
            unsafe { ptr.read_unaligned() }
        } else if let Some(offset) = map::BIOS.contains(pa) {
            let ptr = unsafe { self.bios.bytes.as_ptr().add(offset as usize) } as *const u32;
            unsafe { ptr.read_unaligned() }
        } else {
            self.io_read32(pa)
        }
    }

    pub fn ranged_read64(&mut self, va: u32) -> u64 {
        if let Some(offset) = map::SCRATCHPAD.contains(va) {
            let ptr = unsafe { self.scratchpad.as_ptr().add(offset as usize) } as *const u64;
            return unsafe { ptr.read_unaligned() }
        }

        let cop0_asid = {
            self.read_cop0_asid()
        };
        let operating_mode = self.operating_mode;

        let pa = {
            let tlb = &mut self.tlb;
            tlb.translate_address(
                va,
                AccessType::ReadDoubleword,
                operating_mode,
                cop0_asid,
            ).unwrap_or_else(|_e| va)
        };

        if let Some(offset) = map::RAM.contains(pa) {
            let ptr = unsafe { self.ram.as_ptr().add(offset as usize) } as *const u64;
            unsafe { ptr.read_unaligned() }
        } else if let Some(offset) = map::SCRATCHPAD.contains(pa) {
            let ptr = unsafe { self.scratchpad.as_ptr().add(offset as usize) } as *const u64;
            unsafe { ptr.read_unaligned() }
        } else if let Some(offset) = map::BIOS.contains(pa) {
            let ptr = unsafe { self.bios.bytes.as_ptr().add(offset as usize) } as *const u64;
            unsafe { ptr.read_unaligned() }
        } else {
            self.io_read64(pa)
        }
    }

    pub fn ranged_read128(&mut self, va: u32) -> u128 {
        if let Some(offset) = map::SCRATCHPAD.contains(va) {
            let ptr = unsafe { self.scratchpad.as_ptr().add(offset as usize) } as *const u128;
            return unsafe { ptr.read_unaligned() }
        }

        let cop0_asid = {
            self.read_cop0_asid()
        };
        let operating_mode = self.operating_mode;

        let pa = {
            let tlb = &mut self.tlb;
            tlb.translate_address(
                va,
                AccessType::ReadDoubleword,
                operating_mode,
                cop0_asid,
            ).unwrap_or_else(|_e| va)
        };

        if let Some(offset) = map::RAM.contains(pa) {
            let ptr = unsafe { self.ram.as_ptr().add(offset as usize) } as *const u128;
            unsafe { ptr.read_unaligned() }
        } else if let Some(offset) = map::SCRATCHPAD.contains(pa) {
            let ptr = unsafe { self.scratchpad.as_ptr().add(offset as usize) } as *const u128;
            unsafe { ptr.read_unaligned() }
        } else if let Some(offset) = map::BIOS.contains(pa) {
            let ptr = unsafe { self.bios.bytes.as_ptr().add(offset as usize) } as *const u128;
            unsafe { ptr.read_unaligned() }
        } else {
            self.io_read128(pa)
        }
    }

    pub fn ranged_write8(&mut self, va: u32, val: u8) {
        if let Some(offset) = map::SCRATCHPAD.contains(va) {
            let ptr = unsafe { self.scratchpad.as_mut_ptr().add(offset as usize) } as *mut u8;
            unsafe { ptr.write_unaligned(val) }
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
                AccessType::WriteByte,
                operating_mode,
                cop0_asid,
            ).unwrap_or_else(|_e| va)
        };

        if let Some(offset) = map::RAM.contains(pa) {
            let ptr = unsafe { self.ram.as_mut_ptr().add(offset as usize) } as *mut u8;
            unsafe { ptr.write_unaligned(val) }
        } else if let Some(offset) = map::SCRATCHPAD.contains(pa) {
            let ptr = unsafe { self.scratchpad.as_mut_ptr().add(offset as usize) } as *mut u8;
            unsafe { ptr.write_unaligned(val) }
        } else {
            self.io_write8(pa, val)
        }
    }

    pub fn ranged_write16(&mut self, va: u32, val: u16) {
        if let Some(offset) = map::SCRATCHPAD.contains(va) {
            let ptr = unsafe { self.scratchpad.as_mut_ptr().add(offset as usize) } as *mut u16;
            unsafe { ptr.write_unaligned(val) }
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
                AccessType::WriteHalfword,
                operating_mode,
                cop0_asid,
            ).unwrap_or_else(|_e| va)
        };

        if let Some(offset) = map::RAM.contains(pa) {
            let ptr = unsafe { self.ram.as_mut_ptr().add(offset as usize) } as *mut u16;
            unsafe { ptr.write_unaligned(val) }
        } else if let Some(offset) = map::SCRATCHPAD.contains(pa) {
            let ptr = unsafe { self.scratchpad.as_mut_ptr().add(offset as usize) } as *mut u16;
            unsafe { ptr.write_unaligned(val) }
        } else {
            self.io_write16(pa, val)
        }
    }

    pub fn ranged_write32(&mut self, va: u32, val: u32) {
        if let Some(offset) = map::SCRATCHPAD.contains(va) {
            let ptr = unsafe { self.scratchpad.as_mut_ptr().add(offset as usize) } as *mut u32;
            unsafe { ptr.write_unaligned(val) }
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
                AccessType::WriteWord,
                operating_mode,
                cop0_asid,
            ).unwrap_or_else(|_e| va)
        };

        if let Some(offset) = map::RAM.contains(pa) {
            let ptr = unsafe { self.ram.as_mut_ptr().add(offset as usize) } as *mut u32;
            unsafe { ptr.write_unaligned(val) }
        } else if let Some(offset) = map::SCRATCHPAD.contains(pa) {
            let ptr = unsafe { self.scratchpad.as_mut_ptr().add(offset as usize) } as *mut u32;
            unsafe { ptr.write_unaligned(val) }
        } else {
            self.io_write32(pa, val)
        }
    }

    pub fn ranged_write64(&mut self, va: u32, val: u64) {
        if let Some(offset) = map::SCRATCHPAD.contains(va) {
            let ptr = unsafe { self.scratchpad.as_mut_ptr().add(offset as usize) } as *mut u64;
            unsafe { ptr.write_unaligned(val) }
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
            ).unwrap_or_else(|_e| va)
        };

        if let Some(offset) = map::RAM.contains(pa) {
            let ptr = unsafe { self.ram.as_mut_ptr().add(offset as usize) as *mut u64 };
            unsafe { ptr.write_unaligned(val) }
        } else if let Some(offset) = map::SCRATCHPAD.contains(pa) {
            let ptr = unsafe { self.scratchpad.as_mut_ptr().add(offset as usize)as *mut u64 };
            unsafe { ptr.write_unaligned(val) }
        } else if let Some(offset) = map::VU0.contains(pa) {
            let ptr = if pa < 0x1100_4000 {
                unsafe { self.vu0_data.as_mut_ptr().add(offset as usize) as *mut u64 }
            } else {
                unsafe { self.vu0_code.as_mut_ptr().add((offset - 0x4000) as usize) as *mut u64 }
            };
            unsafe { ptr.write_unaligned(val) }
        } else if let Some(offset) = map::VU1.contains(pa) {
            let ptr = if pa < 0x1100_C000 {
                unsafe { self.vu1_data.as_mut_ptr().add(offset as usize) as *mut u64 }
            } else {
                unsafe { self.vu1_code.as_mut_ptr().add((offset - 0x4000) as usize) as *mut u64 }
            };
            unsafe { ptr.write_unaligned(val) }
        } else {
            self.io_write64(pa, val)
        }
    }

    pub fn ranged_write128(&mut self, va: u32, val: u128) {
        if let Some(offset) = map::SCRATCHPAD.contains(va) {
            let ptr = unsafe { self.scratchpad.as_mut_ptr().add(offset as usize) } as *mut u128;
            unsafe { ptr.write_unaligned(val) }
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
            ).unwrap_or_else(|_e| va)
        };

        if let Some(offset) = map::RAM.contains(pa) {
            let ptr = unsafe { self.ram.as_mut_ptr().add(offset as usize) } as *mut u128;
            unsafe { ptr.write_unaligned(val) }
        } else if let Some(offset) = map::SCRATCHPAD.contains(pa) {
            let ptr = unsafe { self.scratchpad.as_mut_ptr().add(offset as usize) } as *mut u128;
            unsafe { ptr.write_unaligned(val) }
        } else if let Some(offset) = map::VU0.contains(pa) {
            let ptr = if pa < 0x1100_4000 {
                unsafe { self.vu0_data.as_mut_ptr().add(offset as usize) as *mut u128 }
            } else {
                unsafe { self.vu0_code.as_mut_ptr().add((offset - 0x4000) as usize) as *mut u128 }
            };
            unsafe { ptr.write_unaligned(val) }
        } else if let Some(offset) = map::VU1.contains(pa) {
            let ptr = if pa < 0x1100_C000 {
                unsafe { self.vu1_data.as_mut_ptr().add(offset as usize) as *mut u128 }
            } else {
                unsafe { self.vu1_code.as_mut_ptr().add((offset - 0x4000) as usize) as *mut u128 }
            };
            unsafe { ptr.write_unaligned(val) }
        } else {
            self.io_write128(pa, val)
        }
    }
}