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
            mask: 0x001F_E000,
        },
        TlbEntry {
            vpn2: 0x1FC0_0000 >> 13,
            asid: 0,
            g: true, // Global
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
            bus.tlb.write_tlb_entry(bus_ptr, index, *entry);
        }
        tracing::debug!("Installed TLB mapping: {:?}", entry);
    }

    tracing::debug!("Ranged TLB Mappings initialized.");
}

impl Bus {
    pub fn ranged_read8(&mut self, va: u32) -> u8 {
        let pa = self.tlb.translate_address(va, AccessType::ReadByte, self.operating_mode, self.read_cop0_asid())
            .expect("Ranged: TLB exception on read");

        if let Some(offset) = map::RAM.contains(pa) {
            let ptr = unsafe { self.ram.as_ptr().add(offset as usize) } as *const u8;
            unsafe { ptr.read_unaligned() }
        } else if let Some(io_offset) = map::IO.contains(pa) {
            todo!("IO Read 8");
        } else if let Some(offset) = map::BIOS.contains(pa) {
            let ptr = unsafe { self.bios.bytes.as_ptr().add(offset as usize) } as *const u8;
            unsafe { ptr.read_unaligned() }
        } else {
            panic!("Ranged: Unhandled read from physical address 0x{:08X}", pa);
        }
    }

    pub fn ranged_read16(&mut self, va: u32) -> u16 {
        let pa = self.tlb.translate_address(va, AccessType::ReadHalfword, self.operating_mode, self.read_cop0_asid())
            .expect("Ranged: TLB exception on read");

        if let Some(offset) = map::RAM.contains(pa) {
            let ptr = unsafe { self.ram.as_ptr().add(offset as usize) } as *const u16;
            unsafe { ptr.read_unaligned() }
        } else if let Some(io_offset) = map::IO.contains(pa) {
            todo!("IO Read 16");
        } else if let Some(offset) = map::BIOS.contains(pa) {
            let ptr = unsafe { self.bios.bytes.as_ptr().add(offset as usize) } as *const u16;
            unsafe { ptr.read_unaligned() }
        } else {
            panic!("Ranged: Unhandled read from physical address 0x{:08X}", pa);
        }
    }

    pub fn ranged_read32(&mut self, va: u32) -> u32 {
        let pa = self.tlb.translate_address(va, AccessType::ReadWord, self.operating_mode, self.read_cop0_asid())
            .expect("Ranged: TLB exception on read");

        if let Some(offset) = map::RAM.contains(pa) {
            let ptr = unsafe { self.ram.as_ptr().add(offset as usize) } as *const u32;
            unsafe { ptr.read_unaligned() }
        } else if map::IO.contains(pa).is_some() {
            self.io_read32(pa)
        } else if let Some(offset) = map::BIOS.contains(pa) {
            let ptr = unsafe { self.bios.bytes.as_ptr().add(offset as usize) } as *const u32;
            unsafe { ptr.read_unaligned() }
        } else {
            panic!("Ranged: Unhandled read from physical address 0x{:08X}", pa);
        }
    }

    pub fn ranged_read64(&mut self, va: u32) -> u64 {
        let pa = self.tlb.translate_address(va, AccessType::ReadDoubleword, self.operating_mode, self.read_cop0_asid())
            .expect("Ranged: TLB exception on read");

        if let Some(offset) = map::RAM.contains(pa) {
            let ptr = unsafe { self.ram.as_ptr().add(offset as usize) } as *const u64;
            unsafe { ptr.read_unaligned() }
        } else if map::IO.contains(pa).is_some() {
            todo!("IO Read 64");
        } else if let Some(offset) = map::BIOS.contains(pa) {
            let ptr = unsafe { self.bios.bytes.as_ptr().add(offset as usize) } as *const u64;
            unsafe { ptr.read_unaligned() }
        } else {
            panic!("Ranged: Unhandled read from physical address 0x{:08X}", pa);
        }
    }

    pub fn ranged_read128(&mut self, va: u32) -> u128 {
        let pa = self.tlb.translate_address(va, AccessType::ReadDoubleword, self.operating_mode, self.read_cop0_asid())
            .expect("Ranged: TLB exception on read");

        if let Some(offset) = map::RAM.contains(pa) {
            let ptr = unsafe { self.ram.as_ptr().add(offset as usize) } as *const u128;
            unsafe { ptr.read_unaligned() }
        } else if map::IO.contains(pa).is_some() {
            todo!("IO Read 128");
        } else if let Some(offset) = map::BIOS.contains(pa) {
            let ptr = unsafe { self.bios.bytes.as_ptr().add(offset as usize) } as *const u128;
            unsafe { ptr.read_unaligned() }
        } else {
            panic!("Ranged: Unhandled read from physical address 0x{:08X}", pa);
        }
    }

    pub fn ranged_write8(&mut self, va: u32, val: u8) {
        let pa = self.tlb.translate_address(va, AccessType::WriteByte, self.operating_mode, self.read_cop0_asid())
            .expect("Ranged: TLB exception on write");

        if let Some(offset) = map::RAM.contains(pa) {
            let ptr = unsafe { self.ram.as_mut_ptr().add(offset as usize) } as *mut u8;
            unsafe {
                ptr.write_unaligned(val);
            }
        } else if map::IO.contains(pa).is_some() {
            todo!("IO Write 8");
        } else {
            panic!("Ranged: Unhandled write to physical address 0x{:08X}", pa);
        }
    }

    pub fn ranged_write16(&mut self, va: u32, val: u16) {
        let pa = self.tlb.translate_address(va, AccessType::WriteHalfword, self.operating_mode, self.read_cop0_asid())
            .expect("Ranged: TLB exception on write");

        if let Some(offset) = map::RAM.contains(pa) {
            let ptr = unsafe { self.ram.as_mut_ptr().add(offset as usize) } as *mut u16;
            unsafe {
                ptr.write_unaligned(val);
            }
        } else if map::IO.contains(pa).is_some() {
            todo!("IO Write 16");
        } else {
            panic!("Ranged: Unhandled write to physical address 0x{:08X}", pa);
        }
    }

    pub fn ranged_write32(&mut self, va: u32, val: u32) {
        let pa = self.tlb.translate_address(va, AccessType::WriteWord, self.operating_mode, self.read_cop0_asid())
            .expect("Ranged: TLB exception on write");

        if let Some(offset) = map::RAM.contains(pa) {
            let ptr = unsafe { self.ram.as_mut_ptr().add(offset as usize) } as *mut u32;
            unsafe {
                ptr.write_unaligned(val);
            }
        } else if map::IO.contains(pa).is_some() {
            self.io_write32(pa, val)
        } else {
            panic!("Ranged: Unhandled write to physical address 0x{:08X}", pa);
        }
    }

    pub fn ranged_write64(&mut self, va: u32, val: u64) {
        let pa = self.tlb.translate_address(va, AccessType::WriteDoubleword, self.operating_mode, self.read_cop0_asid())
            .expect("Ranged: TLB exception on write");

        if let Some(offset) = map::RAM.contains(pa) {
            let ptr = unsafe { self.ram.as_mut_ptr().add(offset as usize) } as *mut u64;
            unsafe {
                ptr.write_unaligned(val);
            }
        } else if map::IO.contains(pa).is_some() {
            todo!("IO Write 64");
        } else {
            panic!("Ranged: Unhandled write to physical address 0x{:08X}", pa);
        }
    }

    pub fn ranged_write128(&mut self, va: u32, val: u128) {
        let pa = self.tlb.translate_address(va, AccessType::WriteDoubleword, self.operating_mode, self.read_cop0_asid())
            .expect("Ranged: TLB exception on write");

        if let Some(offset) = map::RAM.contains(pa) {
            let ptr = unsafe { self.ram.as_mut_ptr().add(offset as usize) } as *mut u128;
            unsafe {
                ptr.write_unaligned(val);
            }
        } else if map::IO.contains(pa).is_some() {
            todo!("IO Write 128");
        } else {
            panic!("Ranged: Unhandled write to physical address 0x{:08X}", pa);
        }
    }
}
