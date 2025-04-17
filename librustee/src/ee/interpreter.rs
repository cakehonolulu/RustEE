use crate::cpu::EmulationBackend;
use crate::ee::EE;
use tracing::error;
use crate::cpu::CPU;

pub struct Interpreter {
    pub cpu: EE,
}

impl Interpreter {
    pub fn new(cpu: EE) -> Self {
        Interpreter { cpu }
    }

    pub fn decode_execute(&mut self, opcode: u32) {
        let function = opcode >> 26;
        match function {
            0x00 => {
                let subfunction = opcode & 0x3F;
                match subfunction {
                    0x00 => {
                        self.sll(opcode);
                    }
                    _ => {
                        error!(
                            "Unhandled EE Interpreter function SPECIAL opcode: 0x{:08X} (Subfunction 0x{:02X})",
                            opcode, subfunction
                        );
                        panic!();
                    }
                }
            }
            0x0A => {
                self.slti(opcode);
            }
            0x10 => {
                let subfunction = (opcode >> 21) & 0x1F;
                match subfunction {
                    0x00 => {
                        self.mfc0(opcode);
                    }
                    _ => {
                        error!(
                            "Unhandled EE Interpreter COP0 opcode: 0x{:08X} (Subfunction 0x{:02X})",
                            opcode, subfunction
                        );
                        panic!();
                    }
                }
            }
            _ => {
                error!(
                    "Unhandled EE Interpreter opcode: 0x{:08X} (Function 0x{:02X})",
                    opcode, function
                );
                panic!();
            }
        }
    }

    fn mfc0(&mut self, opcode: u32) {
        let rt = ((opcode >> 16) & 0x1F) as usize;
        let rd = ((opcode >> 11) & 0x1F) as usize;

        let cop0_val = self.cpu.read_cop0_register(rd);
        self.cpu.write_register32(rt, cop0_val);

        self.cpu.set_pc(self.cpu.pc().wrapping_add(4));
    }

    fn sll(&mut self, opcode: u32) {
        let rt = ((opcode >> 16) & 0x1F) as usize;
        let rd = ((opcode >> 11) & 0x1F) as usize;
        let sa = (opcode >> 6) & 0x1F;

        let value = self.cpu.read_register32(rt);
        let result = value << sa;
        let result: u64 = result as i32 as i64 as u64;

        self.cpu.write_register64(rd, result);

        self.cpu.set_pc(self.cpu.pc().wrapping_add(4));
    }

    fn slti(&mut self, opcode: u32) {
        let rs = ((opcode >> 21) & 0x1F) as usize;
        let rt = ((opcode >> 16) & 0x1F) as usize;

        let imm = opcode as i16 as i64;

        let rs_val = self.cpu.read_register64(rs) as i64;

        let out = if rs_val < imm { 1u64 } else { 0u64 };
        self.cpu.write_register64(rt, out);
        self.cpu.set_pc(self.cpu.pc().wrapping_add(4));
    }
}

impl EmulationBackend<EE> for Interpreter {
    fn step(&mut self) {
        let pc = self.cpu.pc();

        let opcode = self.cpu.fetch();

        self.decode_execute(opcode);
    }

    fn run(&mut self) {
        loop {
            self.step();
        }
    }
}