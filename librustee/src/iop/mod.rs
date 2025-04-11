/*
    MIPS R3000A IOP CPU
*/

use crate::Bus;
use crate::cpu::CPU;

const IOP_RESET_VEC: u32 = 0xBFC00000;

pub struct IOP {
    bus: Bus,
    pc: u32,
    registers: [u32; 32],
    cop0_registers: [u32; 32],
    lo: u32,
    hi: u32,
}

impl IOP {
    pub fn new(bus: Bus) -> Self {
        IOP {
            pc: IOP_RESET_VEC, // IOP_RESET_VEC
            registers: [0; 32],
            cop0_registers: [0; 32],
            lo: 0,
            hi: 0,
            bus,
        }
    }
}

impl CPU for IOP {
    type RegisterType = u32;

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
        panic!("Unhandled IOP interpreter opcode: 0x{:08X}", opcode)
    }
}