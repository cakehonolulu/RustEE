/*
    MIPS R5900 Emotion Engine CPU
*/

use crate::Bus;

const EE_RESET_VEC: u32 = 0xBFC00000;

pub struct EE {
    bus: Bus,
    pc: u32,
    registers: [u128; 32],
    lo: u128,
    hi: u128,
}

impl EE {
    pub fn new(bus: Bus) -> EE {
        let registers = [0; 32];

        EE {
            bus: bus,
            pc: EE_RESET_VEC,
            registers: registers,
            lo: 0,
            hi: 0,
        }
    }

    pub fn run(&self) {
        loop {
            self.step();
        }
    }

    fn register(&self, index: usize) -> u128 {
        self.registers[index]
    }

    fn set_register(&mut self, index: usize, value: u128) {
        self.registers[index] = value;
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

    fn step(&self) {
        let opcode: u32 = self.fetch();
        self.decode_execute(opcode);
    }
}