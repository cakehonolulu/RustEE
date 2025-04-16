/*
    MIPS R5900 Emotion Engine CPU
*/

use std::collections::HashSet;

use crate::Bus;
use crate::cpu::CPU;

pub mod jit;
pub mod interpreter;

pub use interpreter::Interpreter;
pub use jit::JIT as JIT;

use tracing::{info, debug};

const EE_RESET_VEC: u32 = 0xBFC00000;

pub struct EE {
    bus: Bus,
    pc: u32,
    registers: [u128; 32],
    cop0_registers: [u32; 32],
    lo: u128,
    hi: u128,
    breakpoints: HashSet<u32>,
}

impl EE {
    pub fn new(bus: Bus) -> Self {
        EE {
            pc: EE_RESET_VEC, // EE_RESET_VEC
            registers: [0; 32],
            cop0_registers: [0; 32],
            lo: 0,
            hi: 0,
            bus,
            breakpoints: HashSet::new(),
        }
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

    fn read32(&self, addr: u32) -> u32 {
        (self.bus.read32)(&self.bus, addr)
    }

    #[inline(always)]
    fn fetch(&self) -> u32 {
        self.read32(self.pc)
    }

    #[inline(always)]
    fn fetch_at(&self, address: u32) -> u32 {
        self.read32(address)
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
