/*
    MIPS R5900 Emotion Engine CPU
*/

use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use crate::Bus;
use crate::cpu::CPU;

pub mod jit;
pub mod interpreter;

pub use interpreter::Interpreter;
pub use jit::JIT as JIT;


const EE_RESET_VEC: u32 = 0xBFC00000;

pub struct EE {
    bus: Arc<Mutex<Bus>>,
    pub pc: u32,
    pub registers: [u128; 32],
    cop0_registers: [u32; 32],
    lo: u128,
    hi: u128,
    breakpoints: HashSet<u32>,
}
impl Clone for EE {
    fn clone(&self) -> EE {
        EE {
            bus: Arc::clone(&self.bus),
            pc: self.pc,
            registers: self.registers.clone(),
            cop0_registers: self.cop0_registers.clone(),
            lo: self.lo,
            hi: self.hi,
            breakpoints: self.breakpoints.clone(),
        }
    }
}

impl EE {
    pub fn new(bus: Arc<Mutex<Bus>>) -> Self {
        let mut ee = EE {
            pc: EE_RESET_VEC,
            registers: [0; 32],
            cop0_registers: [0; 32],
            lo: 0,
            hi: 0,
            bus,
            breakpoints: HashSet::new(),
        };

        ee.cop0_registers[15] = 0x59;

        {
            let mut bus = ee.bus.lock().unwrap();
            bus.cop0_registers_ptr = ee.cop0_registers.as_mut_ptr();
        }

        ee
    }

    pub fn read_register32(&self, index: usize) -> u32 {
        self.registers[index] as u32
    }

    pub fn write_register32(&mut self, index: usize, value: u32) {
        let upper_bits = self.registers[index] & 0xFFFFFFFF_FFFFFFFF_00000000_00000000;
        self.registers[index] = upper_bits | (value as u128);
    }

    pub fn read_register64(&self, index: usize) -> u64 {
        self.registers[index] as u64
    }

    pub fn write_register64(&mut self, index: usize, value: u64) {
        let upper_bits = self.registers[index] & 0xFFFFFFFF_FFFFFFFF_00000000_00000000;
        self.registers[index] = upper_bits | (value as u128);
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

    fn write_register(&mut self, index: usize, value: Self::RegisterType) {
        self.registers[index] = value;
    }

    fn read_cop0_register(&self, index: usize) -> u32 {
        self.cop0_registers[index]
    }

    fn write_cop0_register(&mut self, index: usize, value: u32) {
        self.cop0_registers[index] = value;
    }

    fn read32(&mut self, addr: u32) -> u32 {
        let mut bus = self.bus.lock().unwrap();
        (bus.read32)(&mut *bus, addr)
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
