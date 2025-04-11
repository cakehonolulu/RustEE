/*
    MIPS R5900 Emotion Engine CPU
*/

use crate::Bus;
use crate::cpu::CPU;

pub mod jit;
pub mod interpreter;

pub use interpreter::EEInterpreter as Interpreter;
pub use jit::EEJIT as EEJIT;

use tracing::{info, debug};

const EE_RESET_VEC: u32 = 0xBFC00000;

pub struct EE {
    bus: Bus,
    pc: u32,
    registers: [u128; 32],
    cop0_registers: [u32; 32],
    lo: u128,
    hi: u128,
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
        }
    }

    pub fn interp_step(&mut self) {
        let opcode = self.fetch();
        debug!("Interpreter executing opcode 0x{:08X}", opcode);
        self.decode_execute(opcode);
        self.set_pc(self.pc.wrapping_add(4));
    }

    pub fn jit_step(&mut self) {
        info!("JIT compiling block...");
        let opcode = self.fetch();
        debug!("JIT executing opcode 0x{:08X}", opcode);
        self.decode_execute(opcode);
        self.set_pc(self.pc.wrapping_add(4));
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

    fn decode_execute(&self, opcode: u32) {
        panic!("Unhandled EE interpreter opcode: 0x{:08X}", opcode)
    }
}