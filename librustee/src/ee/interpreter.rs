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

    fn do_branch(&mut self, branch_pc: u32, taken: bool, target: u32, is_likely: bool) {
        let delay_pc = branch_pc.wrapping_add(4);

        if taken || !is_likely {
            let slot_opcode = self.cpu.fetch_at(delay_pc);
            self.cpu.set_pc(delay_pc);
            self.decode_execute(slot_opcode);
        }

        let new_pc = if taken {
            target
        } else if is_likely {
            branch_pc.wrapping_add(8)
        } else {
            delay_pc.wrapping_add(4)
        };
        self.cpu.set_pc(new_pc);
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
                            "Unhandled EE Interpreter function SPECIAL opcode: 0x{:08X} (Subfunction 0x{:02X}), PC: 0x{:08X}",
                            opcode, subfunction, self.cpu.pc()
                        );
                        panic!();
                    }
                }
            }
            0x05 => {
                self.bne(opcode);
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
                            "Unhandled EE Interpreter COP0 opcode: 0x{:08X} (Subfunction 0x{:02X}), PC: 0x{:08X}",
                            opcode, subfunction, self.cpu.pc()
                        );
                        panic!();
                    }
                }
            }
            _ => {
                error!(
                    "Unhandled EE Interpreter opcode: 0x{:08X} (Function 0x{:02X}), PC: 0x{:08X}",
                    opcode, function, self.cpu.pc()
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

    fn bne(&mut self, opcode: u32) {
        let branch_pc = self.cpu.pc();
        let rs = ((opcode >> 21) & 0x1F) as usize;
        let rt = ((opcode >> 16) & 0x1F) as usize;
        let imm = (opcode as i16) as i32;
    
        let rs_val = self.cpu.read_register32(rs) as i32;
        let rt_val = self.cpu.read_register32(rt) as i32;
        let taken = rs_val != rt_val;
        let target = branch_pc.wrapping_add(((imm << 2) + 4).try_into().unwrap()); // Adjusted target calculation
    
        self.do_branch(branch_pc, taken, target, false);
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