/*
    MIPS R5900 Emotion Engine CPU
*/

use std::collections::HashSet;
use std::sync::{Arc, RwLock, Mutex};
use crate::Bus;
use crate::cpu::CPU;

pub mod jit;
pub mod interpreter;
pub mod sio;

pub use interpreter::Interpreter;
pub use jit::JIT as JIT;
use crate::bus::map;
use crate::bus::tlb::AccessType;

const EE_RESET_VEC: u32 = 0xBFC00000;

pub struct EE {
    bus: Arc<Mutex<Bus>>,
    pub pc: u32,
    pub registers: [u128; 32],
    pub cop0_registers: Arc<RwLock<[u32; 32]>>,
    pub lo: u128,
    pub hi: u128,
    breakpoints: HashSet<u32>,
}
impl Clone for EE {
    fn clone(&self) -> EE {
        EE {
            bus: Arc::clone(&self.bus),
            pc: self.pc,
            registers: self.registers.clone(),
            cop0_registers: Arc::clone(&self.cop0_registers),
            lo: self.lo,
            hi: self.hi,
            breakpoints: self.breakpoints.clone(),
        }
    }
}

impl EE {
    pub fn new(bus: Arc<Mutex<Bus>>, cop0_registers: Arc<RwLock<[u32; 32]>>) -> Self {
        cop0_registers.write().unwrap()[15] = 0x59;

        let ee = EE {
            pc: EE_RESET_VEC,
            registers: [0; 32],
            cop0_registers,
            lo: 0,
            hi: 0,
            bus,
            breakpoints: HashSet::new(),
        };

        ee
    }
}

impl CPU for EE {
    type RegisterType = u128;

    fn pc(&self) -> u32 {
        self.pc
    }

    fn set_pc(&mut self, value: u32) {
        self.pc = value;
    }

    fn read_register(&self, index: usize) -> Self::RegisterType {
        self.registers[index]
    }

    fn read_hi(&self) -> Self::RegisterType {
        self.hi
    }

    fn read_lo(&self) -> Self::RegisterType {
        self.lo
    }

    fn read_register32(&self, index: usize) -> u32 {
        self.registers[index] as u32
    }

    fn read_register64(&self, index: usize) -> u64 {
        self.registers[index] as u64
    }

    fn write_hi(&mut self, value: Self::RegisterType) {
        self.hi = value;
    }

    fn write_lo(&mut self, value: Self::RegisterType) {
        self.lo = value;
    }

    fn write_register(&mut self, index: usize, value: Self::RegisterType) {
        self.registers[index] = value;
    }

    fn write_register32(&mut self, index: usize, value: u32) {
        let upper_bits = self.registers[index] & 0xFFFFFFFF_FFFFFFFF_00000000_00000000;
        self.registers[index] = upper_bits | (value as u128);
    }

    fn write_register64(&mut self, index: usize, value: u64) {
        let upper_bits = self.registers[index] & 0xFFFFFFFF_FFFFFFFF_00000000_00000000;
        self.registers[index] = upper_bits | (value as u128);
    }

    fn read_cop0_register(&self, index: usize) -> u32 {
        self.cop0_registers.read().unwrap()[index]
    }
    fn write_cop0_register(&mut self, index: usize, value: u32) {
        self.cop0_registers.write().unwrap()[index] = value;
    }

    fn read32(&mut self, addr: u32) -> u32 {
        let mut bus = self.bus.lock().unwrap();
        (bus.read32)(&mut *bus, addr)
    }

    fn read32_raw(&mut self, addr: u32) -> u32 {
        let bus = self.bus.lock().unwrap();
        let pa = match bus.tlb.borrow_mut().translate_address(
            addr,
            AccessType::Read,
            bus.operating_mode,
            bus.read_cop0_asid(),
        ) {
            Ok(pa) => pa,
            Err(_) => return 0,
        };

        if let Some(offset) = map::RAM.contains(pa) {
            let ptr = unsafe { bus.ram.as_ptr().add(offset as usize) } as *const u32;
            unsafe { ptr.read_unaligned() }
        } else if map::IO.contains(pa).is_some() {
            0
        } else if let Some(offset) = map::BIOS.contains(pa) {
            let ptr = unsafe { bus.bios.bytes.as_ptr().add(offset as usize) } as *const u32;
            unsafe { ptr.read_unaligned() }
        } else {
            0
        }
    }

    #[inline(always)]
    fn fetch(&mut self) -> u32 {
        let mut bus = self.bus.lock().unwrap();
        (bus.read32)(&mut *bus, self.pc)
    }

    #[inline(always)]
    fn fetch_at(&mut self, address: u32) -> u32 {
        let mut bus = self.bus.lock().unwrap();
        (bus.read32)(&mut *bus, address)
    }

    fn add_breakpoint(&mut self, addr: u32) {
        self.breakpoints.insert(addr);
    }

    fn remove_breakpoint(&mut self, addr: u32) {
        self.breakpoints.remove(&addr);
    }

    fn has_breakpoint(&self, addr: u32) -> bool {
        self.breakpoints.contains(&addr)
    }
}

#[cfg(test)]
mod test;
