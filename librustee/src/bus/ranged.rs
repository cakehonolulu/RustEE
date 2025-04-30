use super::map;
use super::tlb::AccessType;
use super::Bus;

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