use super::map;
use super::tlb::{AccessType, TlbEntry};
use super::Bus;

pub fn init_ranged_tlb_mappings(bus: &mut Bus) {
    tracing::debug!("Initializing Ranged TLB Mappings...");

    let default_mappings = [
        TlbEntry {
            vpn2: 0x0000_0000 >> 13,
            asid: 0,
            g: true,  // Global
            pfn0: 0x0000_0000 >> 12,
            pfn1: 0x0010_0000 >> 12, // Next 1MB block
            v0: true,
            d0: true,                // Writable
            v1: true,
            d1: true,
            s0: false,
            s1: false,
            c0: 0,
            c1: 0,
            mask: 0x001F_E000,       // 1MB page size
        },
        TlbEntry {
            vpn2: 0x1FC0_0000 >> 13,
            asid: 0,
            g: true,  // Global
            pfn0: 0x1FC0_0000 >> 12,
            pfn1: 0x1FD0_0000 >> 12, // Next 1MB block
            v0: true,
            d0: false,               // BIOS is read-only
            v1: true,
            d1: false,               // BIOS is read-only
            s0: false,
            s1: false,
            c0: 0,
            c1: 0,
            mask: 0x001F_E000,       // 1MB page size
        },
    ];

    // Nullify the immutable borrow by storing the pointer outside the block
    let bus_ptr = bus as *mut Bus;

    for (index, entry) in default_mappings.iter().enumerate() {
        {
            let mut tlb_ref = bus.tlb.borrow_mut();
            tlb_ref.write_tlb_entry(bus_ptr, index, *entry);
        }
        tracing::debug!("Installed TLB mapping: {:?}", entry);
    }

    tracing::debug!("Ranged TLB Mappings initialized.");
}

impl Bus {
    pub fn ranged_read32(&self, va: u32) -> u32 {
        let mut tlb = self.tlb.borrow_mut();
        match tlb.translate_address(va, AccessType::Read, self.operating_mode, self.read_cop0_asid()) {
            Ok(pa) => {
                if let Some(offset) = map::RAM.contains(pa) {
                    let ptr = unsafe { self.ram.as_ptr().add(offset as usize) } as *const u32;
                    unsafe { ptr.read_unaligned() }
                } else if let Some(offset) = map::IO.contains(pa) {
                    todo!("Ranged: IO read at 0x{:08X}", pa);
                } else if let Some(offset) = map::BIOS.contains(pa) {
                    let ptr = unsafe { self.bios.bytes.as_ptr().add(offset as usize) } as *const u32;
                    unsafe { ptr.read_unaligned() }
                } else {
                    panic!("Ranged: Unhandled read from physical address 0x{:08X}", pa);
                }
            }
            Err(e) => {
                panic!("Ranged: TLB exception on read: {:?}", e);
            }
        }
    }

    pub fn ranged_write32(&mut self, va: u32, val: u32) {
        let mut tlb = self.tlb.borrow_mut();
        match tlb.translate_address(va, AccessType::Write, self.operating_mode, self.read_cop0_asid()) {
            Ok(pa) => {
                if let Some(offset) = map::RAM.contains(pa) {
                    let ptr = unsafe { self.ram.as_mut_ptr().add(offset as usize) } as *mut u32;
                    unsafe { ptr.write_unaligned(val); }
                } else if let Some(offset) = map::IO.contains(pa) {
                    todo!("Ranged: IO write at 0x{:08X}", pa);
                } else {
                    panic!("Ranged: Unhandled write to physical address 0x{:08X}", pa);
                }
            }
            Err(e) => {
                panic!("Ranged: TLB exception on write: {:?}", e);
            }
        }
    }
}