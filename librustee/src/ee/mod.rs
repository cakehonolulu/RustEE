/*
    MIPS R5900 Emotion Engine CPU
*/

const EE_RESET_VEC: u32 = 0xBFC00000;

pub struct EE {
    pc: u32,
    registers: [u128; 32],
    lo: u128,
    hi: u128,
}

impl EE {
    pub fn new() -> EE {
        let registers = [0; 32];

        EE {
            pc: EE_RESET_VEC,
            registers: registers,
            lo: 0,
            hi: 0,
        }
    }

    fn register(&self, index: usize) -> u128 {
        self.registers[index]
    }

    fn set_register(&mut self, index: usize, value: u128) {
        self.registers[index] = value;
    }
}