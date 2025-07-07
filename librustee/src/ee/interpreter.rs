use std::ops::DerefMut;
use std::sync::{Arc, Mutex};
use crate::cpu::EmulationBackend;
use crate::ee::EE;
use crate::Bus;
use tracing::error;
use crate::bus::tlb::TlbEntry;
use crate::cpu::CPU;

pub struct Interpreter {
    pub cpu: EE,
    cycles: usize,
}

impl Interpreter {
    pub fn new(cpu: EE) -> Self {
        Interpreter { cpu, cycles: 0 }
    }

    fn get_instruction_cycles(&self, opcode: u32) -> u32 {
        const DEFAULT: u32 = 9;
        const BRANCH: u32 = 11;
        const COP_DEFAULT: u32 = 7;

        const MULT: u32 = 2 * 8;
        const DIV: u32 = 14 * 8;

        const MMI_MULT: u32 = 3 * 8;
        const MMI_DIV: u32 = 22 * 8;
        const MMI_DEFAULT: u32 = 14;

        const FPU_MULT: u32 = 4 * 8;

        const LD_ST: u32 = 14;

        let primary = opcode >> 26;
        match primary {
            0x00 => {
                let funct = opcode & 0x3F;
                match funct {
                    0x18 | 0x19 => MULT,
                    0x1A | 0x1B => DIV,
                    _ => DEFAULT,
                }
            }
            0x02 | 0x03 => DEFAULT,
            0x04 | 0x05 | 0x06 | 0x07 | 0x01 => BRANCH,
            0x20..=0x27 | 0x28..=0x2F => LD_ST,
            0x10 => COP_DEFAULT,
            0x11 => {
                let fmt = (opcode >> 21) & 0x1F;
                if fmt == 0 {
                    COP_DEFAULT
                } else {
                    let funct = opcode & 0x3F;
                    match funct {
                        0x02 | 0x03 => FPU_MULT,
                        _ => DEFAULT,
                    }
                }
            }
            0x1C => {
                let mmiop = (opcode >> 21) & 0x1F;
                match mmiop {
                    0x00..=0x03 => MMI_MULT,
                    0x04..=0x07 => MMI_DIV,
                    _ => MMI_DEFAULT,
                }
            }
            _ => DEFAULT,
        }
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
                    0x08 => {
                        self.jr(opcode);
                    }
                    0x09 => {
                        self.jalr(opcode);
                    }
                    0x0D => {
                        self.break_();
                    }
                    0x0F => {
                        self.sync();
                    }
                    0x18 => {
                        self.mult(opcode);
                    }
                    0x1B => {
                        self.divu(opcode);
                    }
                    0x25 => {
                        self.or(opcode);
                    }
                    0x2D => {
                        self.daddu(opcode);
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
            0x03 => {
                self.jal(opcode);
            }
            0x04 => {
                self.beq(opcode);
            }
            0x05 => {
                self.bne(opcode);
            }
            0x09 => {
                self.addiu(opcode);
            }
            0x0A => {
                self.slti(opcode);
            }
            0x0C => {
                self.andi(opcode);
            }
            0x0D => {
                self.ori(opcode);
            }
            0x0F => {
                self.lui(opcode);
            }
            0x10 => {
                let subfunction = (opcode >> 21) & 0x1F;
                match subfunction {
                    0x00 => {
                        self.mfc0(opcode);
                    }
                    0x04 => {
                        self.mtc0(opcode);
                    }
                    0x10 => {
                        self.tlbwi();
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
            0x14 => {
                self.beql(opcode);
            }
            0x23 => {
                self.lw(opcode);
            }
            0x2B => {
                self.sw(opcode);
            }
            0x3F => {
                self.sd(opcode);
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

        let count = self.cpu.read_cop0_register(9);
        self.cpu.write_cop0_register(9, count.wrapping_add(self.cycles as u32));

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

        let rs_val = self.cpu.read_register32(rs) as i32 as i64;

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

    fn lui(&mut self, opcode: u32) {
        let rt = ((opcode >> 16) & 0x1F) as usize;
        let imm = (opcode & 0xFFFF) as u32;

        let result = (imm << 16) as u64;

        self.cpu.write_register64(rt, result);
        self.cpu.set_pc(self.cpu.pc().wrapping_add(4));
    }

    fn ori(&mut self, opcode: u32) {
        let rs = ((opcode >> 21) & 0x1F) as usize;
        let rt = ((opcode >> 16) & 0x1F) as usize;
        let imm = (opcode & 0xFFFF) as u32;

        let rs_val = self.cpu.read_register32(rs);
        let result = rs_val | imm;

        self.cpu.write_register32(rt, result);
        self.cpu.set_pc(self.cpu.pc().wrapping_add(4));
    }

    fn jr(&mut self, opcode: u32) {
        let rs = ((opcode >> 21) & 0x1F) as usize;
        let rs_val = self.cpu.read_register32(rs);
        let target = rs_val & 0xFFFFFFFC;

        self.cpu.set_pc(target);
    }

    fn mtc0(&mut self, opcode: u32) {
        let rt = ((opcode >> 16) & 0x1F) as usize;
        let rd = ((opcode >> 11) & 0x1F) as usize;

        let rt_val = self.cpu.read_register32(rt);
        self.cpu.write_cop0_register(rd, rt_val);

        self.cpu.set_pc(self.cpu.pc().wrapping_add(4));
    }

    fn sync(&mut self) {
        // TODO: Implement SYNC instruction properly
        self.cpu.set_pc(self.cpu.pc().wrapping_add(4));
    }

    fn addiu(&mut self, opcode: u32) {
        let rs = ((opcode >> 21) & 0x1F) as usize;
        let rt = ((opcode >> 16) & 0x1F) as usize;
        let imm = (opcode as i16) as i32;

        let rs_val = self.cpu.read_register32(rs) as i32;
        let result = rs_val.wrapping_add(imm);

        self.cpu.write_register32(rt, result as u32);
        self.cpu.set_pc(self.cpu.pc().wrapping_add(4));
    }

    fn sw(&mut self, opcode: u32) {
        let rs = ((opcode >> 21) & 0x1F) as usize;
        let rt = ((opcode >> 16) & 0x1F) as usize;
        let imm = (opcode as i16) as i32;

        let rs_val = self.cpu.read_register32(rs);
        let rt_val = self.cpu.read_register32(rt);

        let address = rs_val.wrapping_add(imm as u32);

        {
            let mut bus = self.cpu.bus.lock().unwrap();
            (bus.write32)(&mut *bus, address, rt_val);
        }
        self.cpu.set_pc(self.cpu.pc().wrapping_add(4));
    }

    fn tlbwi(&mut self) {
        let index = (self.cpu.read_cop0_register(0) & 0x3F) as usize;

        let entry_hi  = self.cpu.read_cop0_register(10);
        let entry_lo0 = self.cpu.read_cop0_register(2);
        let entry_lo1 = self.cpu.read_cop0_register(3);
        let page_mask = self.cpu.read_cop0_register(5);

        let vpn2 = entry_hi >> 13;
        let asid = (entry_hi & 0xFF) as u8;

        let s0   = ((entry_lo0 >> 31) & 0x1) != 0;
        let pfn0 = (entry_lo0 >> 6) & 0x000F_FFFF;
        let c0   = ((entry_lo0 >> 3) & 0x7) as u8;
        let d0   = ((entry_lo0 >> 2) & 0x1) != 0;
        let v0   = ((entry_lo0 >> 1) & 0x1) != 0;
        let g0   =  (entry_lo0 & 0x1) != 0;

        let s1   = ((entry_lo1 >> 31) & 0x1) != 0;
        let pfn1 = (entry_lo1 >> 6) & 0x000F_FFFF;
        let c1   = ((entry_lo1 >> 3) & 0x7) as u8;
        let d1   = ((entry_lo1 >> 2) & 0x1) != 0;
        let v1   = ((entry_lo1 >> 1) & 0x1) != 0;
        let g1   =  (entry_lo1 & 0x1) != 0;

        let g = g0 | g1;

        let new_entry = TlbEntry {
            vpn2,
            asid,
            g,
            pfn0,
            pfn1,
            c0,
            c1,
            d0,
            d1,
            v0,
            v1,
            s0,
            s1,
            mask: page_mask,
        };

        self.cpu.set_pc(self.cpu.pc().wrapping_add(4));

        let bus = self.cpu.bus.lock().unwrap();
        let bus_ptr: *mut Bus = &*bus as *const Bus as *mut Bus;
        let mut tlb_refmut = bus.tlb.borrow_mut();
        tlb_refmut.write_tlb_entry(bus_ptr, index, new_entry);
    }

    fn lw(&mut self, opcode: u32) {
        let rs = ((opcode >> 21) & 0x1F) as usize;
        let rt = ((opcode >> 16) & 0x1F) as usize;
        let imm = (opcode as i16) as i32;

        let rs_val = self.cpu.read_register32(rs);

        let address = rs_val.wrapping_add(imm as u32);

        {
            let loaded_word = {
                let mut bus = self.cpu.bus.lock().unwrap();
                (bus.read32)(bus.deref_mut(), address)
            };

            self.cpu.write_register32(rt, loaded_word);
        }
        self.cpu.set_pc(self.cpu.pc().wrapping_add(4));
    }

    fn jalr(&mut self, opcode: u32) {
        let rs = ((opcode >> 21) & 0x1F) as usize;
        let rd = ((opcode >> 11) & 0x1F) as usize;

        let target = self.cpu.read_register32(rs) & 0xFFFF_FFFC;
        let return_addr = self.cpu.pc().wrapping_add(8);

        let delay_pc = self.cpu.pc().wrapping_add(4);
        let slot_opcode = self.cpu.fetch_at(delay_pc);
        self.cpu.set_pc(delay_pc);
        self.decode_execute(slot_opcode);

        self.cpu.write_register32(rd, return_addr);

        self.cpu.set_pc(target);
    }

    fn sd(&mut self, opcode: u32) {
        let rs = ((opcode >> 21) & 0x1F) as usize;
        let rt = ((opcode >> 16) & 0x1F) as usize;
        let imm = (opcode as i16) as i32;

        let base = (self.cpu.read_register(rs) & 0xFFFF_FFFF) as u32;
        let addr = base.wrapping_add(imm as u32);

        let value = (self.cpu.read_register(rt) & 0xFFFF_FFFF_FFFF_FFFF) as u64;
        {
            let mut bus = self.cpu.bus.lock().unwrap();
            (bus.write64)(bus.deref_mut(), addr, value);
        }

        self.cpu.set_pc(self.cpu.pc().wrapping_add(4));
    }

    fn daddu(&mut self, opcode: u32) {
        let rs = ((opcode >> 21) & 0x1F) as usize;
        let rt = ((opcode >> 16) & 0x1F) as usize;
        let rd = ((opcode >> 11) & 0x1F) as usize;

        let rs_val = self.cpu.read_register64(rs);
        let rt_val = self.cpu.read_register64(rt);
        let result = rs_val.wrapping_add(rt_val);

        self.cpu.write_register64(rd, result);

        self.cpu.set_pc(self.cpu.pc().wrapping_add(4));
    }

    fn jal(&mut self, opcode: u32) {
        let pc = self.cpu.pc();
        let target = pc.wrapping_add(4) & 0xF000_0000;
        let jump_addr = target | ((opcode & 0x03FFFFFF) << 2);
        let next_pc = pc.wrapping_add(8);

        self.cpu.write_register64(31, next_pc as u64);

        let delay_pc = self.cpu.pc().wrapping_add(4);
        let slot_opcode = self.cpu.fetch_at(delay_pc);
        self.cpu.set_pc(delay_pc);
        self.decode_execute(slot_opcode);

        self.cpu.set_pc(jump_addr);
    }

    fn andi(&mut self, opcode: u32) {
        let rs = ((opcode >> 21) & 0x1F) as usize;
        let rt = ((opcode >> 16) & 0x1F) as usize;
        let imm = (opcode & 0xFFFF) as u64;

        let rs_val = self.cpu.read_register64(rs);
        let result = rs_val & imm;

        self.cpu.write_register64(rt, result);
        self.cpu.set_pc(self.cpu.pc().wrapping_add(4));
    }

    fn beq(&mut self, opcode: u32) {
        let branch_pc = self.cpu.pc();
        let rs = ((opcode >> 21) & 0x1F) as usize;
        let rt = ((opcode >> 16) & 0x1F) as usize;
        let imm = (opcode as i16) as i32;

        let rs_val = self.cpu.read_register32(rs) as i32;
        let rt_val = self.cpu.read_register32(rt) as i32;
        let taken = rs_val == rt_val;
        let target = branch_pc.wrapping_add(((imm << 2) + 4) as u32);

        self.do_branch(branch_pc, taken, target, false);
    }

    fn or(&mut self, opcode: u32) {
        let rs = ((opcode >> 21) & 0x1F) as usize;
        let rt = ((opcode >> 16) & 0x1F) as usize;
        let rd = ((opcode >> 11) & 0x1F) as usize;

        let rs_val = self.cpu.read_register64(rs);
        let rt_val = self.cpu.read_register64(rt);
        let result = rs_val | rt_val;

        self.cpu.write_register64(rd, result);
        self.cpu.set_pc(self.cpu.pc().wrapping_add(4));
    }

    fn mult(&mut self, opcode: u32) {
        let rs = ((opcode >> 21) & 0x1F) as usize;
        let rt = ((opcode >> 16) & 0x1F) as usize;
        let rd = ((opcode >> 11) & 0x1F) as usize;

        let rs_val = self.cpu.read_register32(rs) as i32 as i64;
        let rt_val = self.cpu.read_register32(rt) as i32 as i64;
        let prod = rs_val.wrapping_mul(rt_val);

        let lo32 = prod as u32;
        let hi32 = (prod >> 32) as u32;

        let lo_val = lo32 as u128;
        let hi_val = hi32 as u128;

        self.cpu.write_lo(lo_val);
        self.cpu.write_hi(hi_val);

        if rd != 0 {
            self.cpu.write_register64(rd, lo32 as u64);
        }

        self.cpu.set_pc(self.cpu.pc().wrapping_add(4));
    }

    fn divu(&mut self, opcode: u32) {
        let rs = ((opcode >> 21) & 0x1F) as usize;
        let rt = ((opcode >> 16) & 0x1F) as usize;

        let dividend = self.cpu.read_register32(rs) as u64;
        let divisor  = self.cpu.read_register32(rt) as u64;

        let quot = dividend.wrapping_div(divisor);
        let rem  = dividend.wrapping_rem(divisor);

        self.cpu.write_lo(quot as u128);
        self.cpu.write_hi(rem  as u128);

        self.cpu.set_pc(self.cpu.pc().wrapping_add(4));
    }

    fn beql(&mut self, opcode: u32) {
        let branch_pc = self.cpu.pc();
        let rs  = ((opcode >> 21) & 0x1F) as usize;
        let rt  = ((opcode >> 16) & 0x1F) as usize;
        let imm = (opcode as i16) as i32;
        let rs_val = self.cpu.read_register32(rs) as i32;
        let rt_val = self.cpu.read_register32(rt) as i32;
        let taken  = rs_val == rt_val;
        let target = branch_pc.wrapping_add(4).wrapping_add((imm << 2) as u32);
        self.do_branch(branch_pc, taken, target, true);
    }

    fn break_(&mut self) {
        panic!("MIPS BREAK instruction executed at 0x{:08X}", self.cpu.pc());
    }
}

impl EmulationBackend<EE> for Interpreter {
    fn step(&mut self) {
        let opcode = self.cpu.fetch();

        self.decode_execute(opcode);

        self.cycles += self.get_instruction_cycles(opcode) as usize;
    }

    fn run(&mut self) {
        loop {
            self.step();
        }
    }

    fn run_for_cycles(&mut self, cycles: u32) {
        let mut executed_cycles = 0;

        while executed_cycles < cycles {
            let opcode = self.cpu.fetch();

            self.decode_execute(opcode);

            let instruction_cycles = self.get_instruction_cycles(opcode);
            executed_cycles += instruction_cycles;
            self.cycles += instruction_cycles as usize;
        }
    }

    fn get_cpu(&self) -> Arc<Mutex<EE>> {
        Arc::new(Mutex::new(self.cpu.clone()))
    }
}