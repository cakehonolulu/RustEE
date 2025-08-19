use crate::Bus;
use crate::bus::tlb::TlbEntry;
use crate::cpu::CPU;
use crate::cpu::EmulationBackend;
use crate::ee::EE;
use std::fs;
use std::ops::DerefMut;
use std::process::exit;
use std::sync::{Arc, Mutex};
use std::sync::atomic::Ordering;
use tracing::{debug, error};

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
                    0x02 => {
                        self.srl(opcode);
                    }
                    0x03 => {
                        self.sra(opcode);
                    }
                    0x04 => {
                        self.sllv(opcode);
                    }
                    0x06 => {
                        self.srlv(opcode);
                    }
                    0x07 => {
                        self.srav(opcode);
                    }
                    0x08 => {
                        self.jr(opcode);
                    }
                    0x09 => {
                        self.jalr(opcode);
                    }
                    0x0A => {
                        self.movz(opcode);
                    }
                    0x0B => {
                        self.movn(opcode);
                    }
                    0x0C => {
                        self.syscall(opcode);
                    }
                    0x0D => {
                        self.break_();
                    }
                    0x0F => {
                        self.sync();
                    }
                    0x10 => {
                        self.mfhi(opcode);
                    }
                    0x12 => {
                        self.mflo(opcode);
                    }
                    0x14 => {
                        self.dsllv(opcode);
                    }
                    0x17 => {
                        self.dsrav(opcode);
                    }
                    0x18 => {
                        self.mult(opcode);
                    }
                    0x1A => {
                        self.div(opcode);
                    }
                    0x1B => {
                        self.divu(opcode);
                    }
                    0x20 => {
                        self.add(opcode);
                    }
                    0x21 => {
                        self.addu(opcode);
                    }
                    0x22 => {
                        self.sub(opcode);
                    }
                    0x23 => {
                        self.subu(opcode);
                    }
                    0x24 => {
                        self.and(opcode);
                    }
                    0x25 => {
                        self.or(opcode);
                    }
                    0x27 => {
                        self.nor(opcode);
                    }
                    0x2A => self.slt(opcode),
                    0x2B => self.sltu(opcode),
                    0x2D => {
                        self.daddu(opcode);
                    }
                    0x38 => {
                        self.dsll(opcode);
                    }
                    0x3A => {
                        self.dsrl(opcode);
                    }
                    0x3C => {
                        self.dsll32(opcode);
                    }
                    0x3E => {
                        self.dsrl32(opcode);
                    }
                    0x3F => {
                        self.dsra32(opcode);
                    }
                    _ => {
                        error!(
                            "Unhandled EE Interpreter function SPECIAL opcode: 0x{:08X} (Subfunction 0x{:02X}), PC: 0x{:08X}",
                            opcode,
                            subfunction,
                            self.cpu.pc()
                        );
                        panic!();
                    }
                }
            }
            0x01 => {
                let rt = (opcode >> 16) & 0x1F;
                match rt {
                    0x00 => self.bltz(opcode),
                    0x01 => self.bgez(opcode),
                    0x02 => self.bltzl(opcode),
                    0x03 => self.bgezl(opcode),
                    _ => {
                        error!(
                            "Unhandled REGIMM instruction with rt=0x{:02X} at PC=0x{:08X}",
                            rt,
                            self.cpu.pc()
                        );
                        panic!();
                    }
                }
            }
            0x02 => {
                self.j(opcode);
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
            0x06 => {
                self.blez(opcode);
            }
            0x07 => {
                self.bgtz(opcode);
            }
            0x08 => {
                self.addi(opcode);
            }
            0x09 => {
                self.addiu(opcode);
            }
            0x0A => {
                self.slti(opcode);
            }
            0x0B => {
                self.sltiu(opcode);
            }
            0x0C => {
                self.andi(opcode);
            }
            0x0D => {
                self.ori(opcode);
            }
            0x0E => {
                self.xori(opcode);
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
                        let funct = opcode & 0x3F;

                        match funct {
                            0x2 => self.tlbwi(),
                            0x18 => self.eret(),
                            0x38 => self.ei(),
                            0x39 => self.di(),
                            _ => panic!(
                                "Unhandled EE Interpreter C0 opcode: 0x{:08X} (Subfunction 0x{:02X}), PC: 0x{:08X}",
                                opcode,
                                funct,
                                self.cpu.pc()
                            ),
                        }
                    }
                    _ => {
                        panic!(
                            "Unhandled EE Interpreter COP0 opcode: 0x{:08X} (Subfunction 0x{:02X}), PC: 0x{:08X}",
                            opcode,
                            subfunction,
                            self.cpu.pc()
                        );
                    }
                }
            }
            0x11 => {
                // COP1
                self.cpu.set_pc(self.cpu.pc().wrapping_add(4));
            }
            0x12 => {
                let subfunction = (opcode >> 21) & 0x1F;
                match subfunction {
                    0x02 => {
                        self.cfc2(opcode);
                    }
                    0x06 => {
                        self.ctc2(opcode);
                    }
                    0x18 => {
                        // TODO: viswr.x
                        self.cpu.set_pc(self.cpu.pc().wrapping_add(4));
                    }
                    _ => {
                        //
                        self.cpu.set_pc(self.cpu.pc().wrapping_add(4));
                    }
                }
            }
            0x14 => {
                self.beql(opcode);
            }
            0x15 => {
                self.bnel(opcode);
            }
            0x19 => {
                self.daddiu(opcode);
            }
            0x1A => {
                self.ldl(opcode);
            }
            0x1B => {
                self.ldr(opcode);
            }
            0x1C => {
                let subfunction = opcode & 0x3F;

                match subfunction {
                    0x12 => {
                        self.mflo1(opcode);
                    }
                    0x18 => {
                        self.mult1(opcode);
                    }
                    0x1B => {
                        self.divu1(opcode);
                    }
                    0x28 => {
                        let mmi1_function = (opcode >> 6) & 0x1F;

                        match mmi1_function {
                            0x10 => self.padduw(opcode),
                            _ => {
                                panic!(
                                    "Unimplemented MMI1 instruction with funct: 0x{:02X}, PC: 0x{:08X}",
                                    mmi1_function,
                                    self.cpu.pc()
                                );
                            }
                        }
                    }
                    0x29 => {
                        let mmi3_function = (opcode >> 6) & 0x1F;

                        match mmi3_function {
                            0x12 => self.or(opcode),
                            _ => {
                                panic!(
                                    "Unimplemented MMI3 instruction with funct: 0x{:02X}, PC: 0x{:08X}",
                                    mmi3_function,
                                    self.cpu.pc()
                                );
                            }
                        }
                    }
                    _ => {
                        panic!(
                            "Unimplemented MMI instruction with funct: 0x{:02X}",
                            subfunction
                        );
                    }
                }
            }
            0x1E => {
                self.lq(opcode);
            }
            0x1F => {
                self.sq(opcode);
            }
            0x20 => {
                self.lb(opcode);
            }
            0x21 => {
                self.lh(opcode);
            }
            0x23 => {
                self.lw(opcode);
            }
            0x24 => {
                self.lbu(opcode);
            }
            0x25 => {
                self.lhu(opcode);
            }
            0x27 => {
                self.lwu(opcode);
            }
            0x28 => {
                self.sb(opcode);
            }
            0x29 => {
                self.sh(opcode);
            }
            0x2B => {
                self.sw(opcode);
            }
            0x2C => {
                self.sdl(opcode);
            }
            0x2D => {
                self.sdr(opcode);
            }
            0x2F => {
                self.cache();
            }
            0x39 => {
                self.swc1(opcode);
            }
            0x37 => {
                self.ld(opcode);
            }
            0x3F => {
                self.sd(opcode);
            }
            _ => {
                error!(
                    "Unhandled EE Interpreter opcode: 0x{:08X} (Function 0x{:02X}), PC: 0x{:08X}",
                    opcode,
                    function,
                    self.cpu.pc()
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
        self.cpu
            .write_cop0_register(9, count.wrapping_add(self.cycles as u32));

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
        let offset = (imm << 2).wrapping_add(4) as u32;
        let target = branch_pc.wrapping_add(offset);

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
        let imm = (opcode & 0xFFFF) as u64;

        let rs_val = self.cpu.read_register64(rs);

        let result = rs_val | imm;

        self.cpu.write_register64(rt, result);
        self.cpu.set_pc(self.cpu.pc().wrapping_add(4));
    }

    fn jr(&mut self, opcode: u32) {
        let rs = ((opcode >> 21) & 0x1F) as usize;
        let rs_val = self.cpu.read_register32(rs);
        let target = rs_val & 0xFFFFFFFC;

        let delay_pc = self.cpu.pc().wrapping_add(4);
        let slot_opcode = self.cpu.fetch_at(delay_pc);
        self.cpu.set_pc(delay_pc);
        self.decode_execute(slot_opcode);

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

        let entry_hi = self.cpu.read_cop0_register(10);
        let entry_lo0 = self.cpu.read_cop0_register(2);
        let entry_lo1 = self.cpu.read_cop0_register(3);
        let page_mask = self.cpu.read_cop0_register(5);

        let vpn2 = entry_hi >> 13;
        let asid = (entry_hi & 0xFF) as u8;

        let s0 = ((entry_lo0 >> 31) & 0x1) != 0;
        let pfn0 = (entry_lo0 >> 6) & 0x000F_FFFF;
        let c0 = ((entry_lo0 >> 3) & 0x7) as u8;
        let d0 = ((entry_lo0 >> 2) & 0x1) != 0;
        let v0 = ((entry_lo0 >> 1) & 0x1) != 0;
        let g0 = (entry_lo0 & 0x1) != 0;

        let s1 = ((entry_lo1 >> 31) & 0x1) != 0;
        let pfn1 = (entry_lo1 >> 6) & 0x000F_FFFF;
        let c1 = ((entry_lo1 >> 3) & 0x7) as u8;
        let d1 = ((entry_lo1 >> 2) & 0x1) != 0;
        let v1 = ((entry_lo1 >> 1) & 0x1) != 0;
        let g1 = (entry_lo1 & 0x1) != 0;

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
        let bus_ptr: *mut Bus = &**bus as *const Bus as *mut Bus;
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
        let divisor = self.cpu.read_register32(rt) as u64;

        if divisor != 0 {
            let quot32 = dividend / divisor;
            let rem32 = dividend % divisor;

            self.cpu.write_lo0(quot32 as u64);
            self.cpu.write_hi0(rem32 as u64);
        }

        self.cpu.set_pc(self.cpu.pc().wrapping_add(4));
    }

    fn beql(&mut self, opcode: u32) {
        let branch_pc = self.cpu.pc();
        let rs = ((opcode >> 21) & 0x1F) as usize;
        let rt = ((opcode >> 16) & 0x1F) as usize;
        let imm = (opcode as i16) as i32;
        let rs_val = self.cpu.read_register32(rs) as i32;
        let rt_val = self.cpu.read_register32(rt) as i32;
        let taken = rs_val == rt_val;
        let target = branch_pc.wrapping_add(4).wrapping_add((imm << 2) as u32);
        self.do_branch(branch_pc, taken, target, true);
    }

    fn break_(&mut self) {
        panic!("MIPS BREAK instruction executed at 0x{:08X}", self.cpu.pc());
    }

    fn mflo(&mut self, opcode: u32) {
        let rd = ((opcode >> 11) & 0x1F) as usize;
        let lo_val = self.cpu.read_lo();
        self.cpu.write_register64(rd, lo_val as u64);
        self.cpu.set_pc(self.cpu.pc().wrapping_add(4));
    }

    fn sltiu(&mut self, opcode: u32) {
        let rs = ((opcode >> 21) & 0x1F) as usize;
        let rt = ((opcode >> 16) & 0x1F) as usize;
        let imm = (opcode as i16) as i64;

        let rs_val = self.cpu.read_register64(rs);
        let imm_val = imm as u64;

        let result = if rs_val < imm_val { 1u64 } else { 0u64 };
        self.cpu.write_register64(rt, result);
        self.cpu.set_pc(self.cpu.pc().wrapping_add(4));
    }

    fn bnel(&mut self, opcode: u32) {
        let branch_pc = self.cpu.pc();
        let rs = ((opcode >> 21) & 0x1F) as usize;
        let rt = ((opcode >> 16) & 0x1F) as usize;
        let imm = (opcode as i16) as i32;

        let rs_val = self.cpu.read_register32(rs) as i32;
        let rt_val = self.cpu.read_register32(rt) as i32;
        let taken = rs_val != rt_val;
        let target = branch_pc.wrapping_add(4).wrapping_add((imm << 2) as u32);

        self.do_branch(branch_pc, taken, target, true);
    }

    fn lb(&mut self, opcode: u32) {
        let rs = ((opcode >> 21) & 0x1F) as usize;
        let rt = ((opcode >> 16) & 0x1F) as usize;
        let imm = (opcode as i16) as i32;

        let rs_val = self.cpu.read_register32(rs);
        let address = rs_val.wrapping_add(imm as u32);

        let loaded_byte = {
            let mut bus = self.cpu.bus.lock().unwrap();
            (bus.read8)(bus.deref_mut(), address)
        };

        let result = loaded_byte as i8 as i64 as u64;
        self.cpu.write_register64(rt, result);

        self.cpu.set_pc(self.cpu.pc().wrapping_add(4));
    }

    fn swc1(&mut self, opcode: u32) {
        let base = ((opcode >> 21) & 0x1F) as usize;
        let ft = ((opcode >> 16) & 0x1F) as usize;
        let imm = (opcode as i16) as i32;

        let base_val = self.cpu.read_register32(base);
        let address = base_val.wrapping_add(imm as u32);

        let fpu_val = self.cpu.read_fpu_register_as_u32(ft);

        {
            let mut bus = self.cpu.bus.lock().unwrap();
            (bus.write32)(bus.deref_mut(), address, fpu_val);
        }

        self.cpu.set_pc(self.cpu.pc().wrapping_add(4));
    }

    pub fn lbu(&mut self, opcode: u32) {
        let rs = ((opcode >> 21) & 0x1F) as usize;
        let rt = ((opcode >> 16) & 0x1F) as usize;
        let imm = (opcode as i16) as i32;

        let rs_val = self.cpu.read_register32(rs);
        let address = rs_val.wrapping_add(imm as u32);

        let loaded_byte = {
            let mut bus = self.cpu.bus.lock().unwrap();
            (bus.read8)(bus.deref_mut(), address)
        };

        let result = loaded_byte as u64;
        self.cpu.write_register64(rt, result);

        self.cpu.set_pc(self.cpu.pc().wrapping_add(4));
    }

    pub fn sra(&mut self, opcode: u32) {
        let rt = ((opcode >> 16) & 0x1F) as usize;
        let rd = ((opcode >> 11) & 0x1F) as usize;
        let sa = (opcode >> 6) & 0x1F;

        let shifted = (self.cpu.read_register32(rt) as i32) >> sa;
        let result = (shifted as i64) as u64;
        self.cpu.write_register64(rd, result);

        self.cpu.set_pc(self.cpu.pc().wrapping_add(4));
    }

    fn ld(&mut self, opcode: u32) {
        let rs = ((opcode >> 21) & 0x1F) as usize;
        let rt = ((opcode >> 16) & 0x1F) as usize;
        let imm = (opcode as i16) as i32;

        let base = (self.cpu.read_register(rs) & 0xFFFF_FFFF) as u32;
        let addr = base.wrapping_add(imm as u32);

        let loaded_value = {
            let mut bus = self.cpu.bus.lock().unwrap();
            (bus.read64)(bus.deref_mut(), addr)
        };

        self.cpu.write_register64(rt, loaded_value);
        self.cpu.set_pc(self.cpu.pc().wrapping_add(4));
    }

    fn j(&mut self, opcode: u32) {
        let pc = self.cpu.pc();
        let target = pc.wrapping_add(4) & 0xF000_0000;
        let jump_addr = target | ((opcode & 0x03FFFFFF) << 2);

        let delay_pc = self.cpu.pc().wrapping_add(4);
        let slot_opcode = self.cpu.fetch_at(delay_pc);
        self.cpu.set_pc(delay_pc);
        self.decode_execute(slot_opcode);

        self.cpu.set_pc(jump_addr);
    }

    fn sb(&mut self, opcode: u32) {
        let rs = ((opcode >> 21) & 0x1F) as usize;
        let rt = ((opcode >> 16) & 0x1F) as usize;
        let imm = (opcode as i16) as i32;

        let rs_val = self.cpu.read_register32(rs);
        let rt_val = self.cpu.read_register32(rt);

        let address = rs_val.wrapping_add(imm as u32);

        {
            let mut bus = self.cpu.bus.lock().unwrap();
            (bus.write8)(&mut *bus, address, rt_val as u8);
        }
        self.cpu.set_pc(self.cpu.pc().wrapping_add(4));
    }

    fn addu(&mut self, opcode: u32) {
        let rs = ((opcode >> 21) & 0x1F) as usize;
        let rt = ((opcode >> 16) & 0x1F) as usize;
        let rd = ((opcode >> 11) & 0x1F) as usize;

        let rs_val = self.cpu.read_register32(rs);
        let rt_val = self.cpu.read_register32(rt);
        let result = rs_val.wrapping_add(rt_val);

        self.cpu.write_register32(rd, result);
        self.cpu.set_pc(self.cpu.pc().wrapping_add(4));
    }

    fn bgez(&mut self, opcode: u32) {
        let branch_pc = self.cpu.pc();
        let rs = ((opcode >> 21) & 0x1F) as usize;
        let imm = (opcode as i16) as i32;

        let rs_val = self.cpu.read_register32(rs) as i32;
        let taken = rs_val >= 0;

        let target = branch_pc.wrapping_add(((imm << 2) + 4) as u32);
        self.do_branch(branch_pc, taken, target, false);
    }

    fn div(&mut self, opcode: u32) {
        let rs = ((opcode >> 21) & 0x1F) as usize;
        let rt = ((opcode >> 16) & 0x1F) as usize;

        let dividend = self.cpu.read_register32(rs) as i32;
        let divisor = self.cpu.read_register32(rt) as i32;

        let (quot, rem) = if divisor == 0 {
            (0, 0)
        } else if dividend == i32::MIN && divisor == -1 {
            (i32::MIN, 0)
        } else {
            (
                dividend.wrapping_div(divisor),
                dividend.wrapping_rem(divisor),
            )
        };

        let quot_128 = quot as i64 as i128;
        let rem_128 = rem as i64 as i128;

        self.cpu.write_lo(quot_128 as u128);
        self.cpu.write_hi(rem_128 as u128);

        self.cpu.set_pc(self.cpu.pc().wrapping_add(4));
    }

    fn mfhi(&mut self, opcode: u32) {
        let rd = ((opcode >> 11) & 0x1F) as usize;

        let hi_val = self.cpu.read_hi();
        self.cpu.write_register64(rd, hi_val as u64);

        self.cpu.set_pc(self.cpu.pc().wrapping_add(4));
    }

    fn sltu(&mut self, opcode: u32) {
        let rs = ((opcode >> 21) & 0x1F) as usize;
        let rt = ((opcode >> 16) & 0x1F) as usize;
        let rd = ((opcode >> 11) & 0x1F) as usize;

        let rs_val = self.cpu.read_register64(rs);
        let rt_val = self.cpu.read_register64(rt);

        let out = if rs_val < rt_val { 1u64 } else { 0u64 };

        self.cpu.write_register64(rd, out);

        self.cpu.set_pc(self.cpu.pc().wrapping_add(4));
    }

    fn blez(&mut self, opcode: u32) {
        let branch_pc = self.cpu.pc();
        let rs = ((opcode >> 21) & 0x1F) as usize;
        let imm = (opcode as u16) as i16 as i32;

        let rs_val = self.cpu.read_register32(rs) as i32;
        let taken = rs_val <= 0;

        let target = branch_pc.wrapping_add(4).wrapping_add((imm << 2) as u32);

        self.do_branch(branch_pc, taken, target, false);
    }

    fn subu(&mut self, opcode: u32) {
        let rs = ((opcode >> 21) & 0x1F) as usize;
        let rt = ((opcode >> 16) & 0x1F) as usize;
        let rd = ((opcode >> 11) & 0x1F) as usize;

        let a = self.cpu.read_register32(rs);
        let b = self.cpu.read_register32(rt);

        let diff32 = a.wrapping_sub(b);
        let result = (diff32 as i32) as i64 as u64;

        self.cpu.write_register64(rd, result);
        self.cpu.set_pc(self.cpu.pc().wrapping_add(4));
    }

    fn bgtz(&mut self, opcode: u32) {
        let branch_pc = self.cpu.pc();
        let rs = ((opcode >> 21) & 0x1F) as usize;
        let imm = (opcode as u16) as i16 as i32;

        let rs_val = self.cpu.read_register32(rs) as i32;
        let taken = rs_val > 0;

        let target = branch_pc.wrapping_add(4).wrapping_add((imm << 2) as u32);

        self.do_branch(branch_pc, taken, target, false);
    }

    fn movn(&mut self, opcode: u32) {
        let rs = ((opcode >> 21) & 0x1F) as usize;
        let rt = ((opcode >> 16) & 0x1F) as usize;
        let rd = ((opcode >> 11) & 0x1F) as usize;

        let rt_val = self.cpu.read_register64(rt);
        if rt_val != 0 {
            let rs_val = self.cpu.read_register64(rs);
            self.cpu.write_register64(rd, rs_val);
        }
        self.cpu.set_pc(self.cpu.pc().wrapping_add(4));
    }

    fn slt(&mut self, opcode: u32) {
        let rs = ((opcode >> 21) & 0x1F) as usize;
        let rt = ((opcode >> 16) & 0x1F) as usize;
        let rd = ((opcode >> 11) & 0x1F) as usize;

        let rs_val = self.cpu.read_register64(rs) as i64;
        let rt_val = self.cpu.read_register64(rt) as i64;

        let out = if rs_val < rt_val { 1u64 } else { 0u64 };

        self.cpu.write_register64(rd, out);

        self.cpu.set_pc(self.cpu.pc().wrapping_add(4));
    }

    fn and(&mut self, opcode: u32) {
        let rs = ((opcode >> 21) & 0x1F) as usize;
        let rt = ((opcode >> 16) & 0x1F) as usize;
        let rd = ((opcode >> 11) & 0x1F) as usize;

        let a = self.cpu.read_register64(rs);
        let b = self.cpu.read_register64(rt);

        let res = a & b;

        self.cpu.write_register64(rd, res);

        self.cpu.set_pc(self.cpu.pc().wrapping_add(4));
    }

    fn srl(&mut self, opcode: u32) {
        let rt = ((opcode >> 16) & 0x1F) as usize;
        let rd = ((opcode >> 11) & 0x1F) as usize;
        let sa = ((opcode >> 6) & 0x1F) as u32;

        let v = self.cpu.read_register32(rt);
        let shifted = v >> sa;
        let res = (shifted as i32) as i64 as u64;

        self.cpu.write_register64(rd, res);
        self.cpu.set_pc(self.cpu.pc().wrapping_add(4));
    }

    fn lhu(&mut self, opcode: u32) {
        let rs = ((opcode >> 21) & 0x1F) as usize;
        let rt = ((opcode >> 16) & 0x1F) as usize;
        let imm = (opcode as i16) as i32;

        let rs_val = self.cpu.read_register32(rs);
        let address = rs_val.wrapping_add(imm as u32);

        let loaded_byte = {
            let mut bus = self.cpu.bus.lock().unwrap();
            (bus.read16)(bus.deref_mut(), address)
        };

        let result = loaded_byte as u64;
        self.cpu.write_register64(rt, result);

        self.cpu.set_pc(self.cpu.pc().wrapping_add(4));
    }

    fn bltz(&mut self, opcode: u32) {
        let branch_pc = self.cpu.pc();
        let rs = ((opcode >> 21) & 0x1F) as usize;
        let imm = (opcode as i16) as i32;

        let rs_val = self.cpu.read_register32(rs) as i32;
        let taken = rs_val < 0;
        let target = branch_pc.wrapping_add(((imm << 2) + 4) as u32);

        self.do_branch(branch_pc, taken, target, false);
    }

    fn bltzl(&mut self, opcode: u32) {
        let branch_pc = self.cpu.pc();
        let rs = ((opcode >> 21) & 0x1F) as usize;
        let imm = (opcode as i16) as i32;

        let rs_val = self.cpu.read_register32(rs) as i32;
        let taken = rs_val < 0;
        let target = branch_pc.wrapping_add(((imm << 2) + 4) as u32);

        self.do_branch(branch_pc, taken, target, true);
    }

    fn bgezl(&mut self, opcode: u32) {
        let branch_pc = self.cpu.pc();
        let rs = ((opcode >> 21) & 0x1F) as usize;
        let imm = (opcode as i16) as i32;

        let rs_val = self.cpu.read_register32(rs) as i32;
        let taken = rs_val >= 0;
        let target = branch_pc.wrapping_add(((imm << 2) + 4) as u32);

        self.do_branch(branch_pc, taken, target, true);
    }

    fn sh(&mut self, opcode: u32) {
        let rs = ((opcode >> 21) & 0x1F) as usize;
        let rt = ((opcode >> 16) & 0x1F) as usize;
        let imm = (opcode as i16) as i32;

        let rs_val = self.cpu.read_register32(rs);
        let rt_val = self.cpu.read_register32(rt);
        let address = rs_val.wrapping_add(imm as u32);

        {
            let mut bus = self.cpu.bus.lock().unwrap();
            (bus.write16)(&mut *bus, address, rt_val as u16);
        }
        self.cpu.set_pc(self.cpu.pc().wrapping_add(4));
    }

    fn divu1(&mut self, opcode: u32) {
        let rs = ((opcode >> 21) & 0x1F) as usize;
        let rt = ((opcode >> 16) & 0x1F) as usize;

        let rs_val = self.cpu.read_register32(rs) as i64;
        let rt_val = self.cpu.read_register32(rt) as i64;

        let rs_valid = rs_val == ((rs_val as i32) as i64);
        let rt_valid = rt_val == ((rt_val as i32) as i64);

        if !rs_valid || !rt_valid || rt_val == 0 {
            self.cpu.write_lo(0);
            self.cpu.write_hi(0);
        } else {
            let dividend = rs_val as u32 as u64;
            let divisor = rt_val as u32 as u64;

            let quotient = dividend.wrapping_div(divisor);
            let remainder = dividend.wrapping_rem(divisor);

            let lo = (self.cpu.read_lo() & 0xFFFFFFFFFFFFFFFF) | ((quotient as u128) << 64);
            let hi = (self.cpu.read_hi() & 0xFFFFFFFFFFFFFFFF) | ((remainder as u128) << 64);
            self.cpu.write_lo(lo);
            self.cpu.write_hi(hi);
        }

        self.cpu.set_pc(self.cpu.pc().wrapping_add(4));
    }

    fn mtlo1(&mut self, opcode: u32) {
        let rs = ((opcode >> 21) & 0x1F) as usize;

        let rs_val = self.cpu.read_register32(rs) as i64 as u64;
        let lo_current = self.cpu.read_lo();
        let lo_new = (lo_current & 0xFFFFFFFFFFFFFFFF) | ((rs_val as u128) << 64);

        self.cpu.write_lo(lo_new);
        self.cpu.set_pc(self.cpu.pc().wrapping_add(4));
    }

    fn mflo1(&mut self, opcode: u32) {
        let rt = ((opcode >> 11) & 0x1F) as usize;

        let lo_u64 = (self.cpu.read_lo() >> 64) as u64;
        let word = (lo_u64 as u32) as u64;

        self.cpu.write_register(rt, word.into());
        self.cpu.set_pc(self.cpu.pc().wrapping_add(4));
    }

    fn dsrav(&mut self, opcode: u32) {
        let rs = ((opcode >> 21) & 0x1F) as usize;
        let rt = ((opcode >> 16) & 0x1F) as usize;
        let rd = ((opcode >> 11) & 0x1F) as usize;

        let s = self.cpu.read_register64(rs) & 0x3F;
        let rt_val = self.cpu.read_register64(rt) as i64;
        let result = (rt_val >> s) as u64;

        self.cpu.write_register64(rd, result);
        self.cpu.set_pc(self.cpu.pc().wrapping_add(4));
    }

    fn dsll32(&mut self, opcode: u32) {
        let rt = ((opcode >> 16) & 0x1F) as usize;
        let rd = ((opcode >> 11) & 0x1F) as usize;
        let sa = (opcode >> 6) & 0x1F;

        let s = sa + 32;
        let rt_val = self.cpu.read_register64(rt);
        let result = rt_val << s;

        self.cpu.write_register64(rd, result);
        self.cpu.set_pc(self.cpu.pc().wrapping_add(4));
    }

    fn dsra32(&mut self, opcode: u32) {
        let rt = ((opcode >> 16) & 0x1F) as usize;
        let rd = ((opcode >> 11) & 0x1F) as usize;
        let sa = (opcode >> 6) & 0x1F;

        let s = sa + 32;
        let rt_val = self.cpu.read_register64(rt) as i64;
        let result = (rt_val >> s) as u64;

        self.cpu.write_register64(rd, result);
        self.cpu.set_pc(self.cpu.pc().wrapping_add(4));
    }

    fn xori(&mut self, opcode: u32) {
        let rs = ((opcode >> 21) & 0x1F) as usize;
        let rt = ((opcode >> 16) & 0x1F) as usize;
        let imm = (opcode & 0xFFFF) as u64;

        let rs_val = self.cpu.read_register64(rs);
        let result = rs_val ^ imm;

        self.cpu.write_register64(rt, result);
        self.cpu.set_pc(self.cpu.pc().wrapping_add(4));
    }

    fn mult1(&mut self, opcode: u32) {
        let rs = ((opcode >> 21) & 0x1F) as usize;
        let rt = ((opcode >> 16) & 0x1F) as usize;
        let rd = ((opcode >> 11) & 0x1F) as usize;

        let rs_val = self.cpu.read_register32(rs) as i64;
        let rt_val = self.cpu.read_register32(rt) as i64;

        let rs_valid = rs_val == ((rs_val as i32) as i64);
        let rt_valid = rt_val == ((rt_val as i32) as i64);

        if !rs_valid || !rt_valid {
            self.cpu.write_lo(0);
            self.cpu.write_hi(0);
            if rd != 0 {
                self.cpu.write_register64(rd, 0);
            }
        } else {
            let prod = (rs_val as i32 as i64) * (rt_val as i32 as i64);
            let lo32 = prod as u32;
            let hi32 = (prod >> 32) as u32;

            let lo = (self.cpu.read_lo() & 0xFFFFFFFFFFFFFFFF) | ((lo32 as u128) << 64);
            let hi = (self.cpu.read_hi() & 0xFFFFFFFFFFFFFFFF) | ((hi32 as u128) << 64);

            self.cpu.write_lo(lo);
            self.cpu.write_hi(hi);
            if rd != 0 {
                self.cpu.write_register64(rd, lo32 as u64);
            }
        }

        self.cpu.set_pc(self.cpu.pc().wrapping_add(4));
    }

    fn movz(&mut self, opcode: u32) {
        let rs = ((opcode >> 21) & 0x1F) as usize;
        let rt = ((opcode >> 16) & 0x1F) as usize;
        let rd = ((opcode >> 11) & 0x1F) as usize;

        let rt_val = self.cpu.read_register64(rt);
        if rt_val == 0 {
            let rs_val = self.cpu.read_register64(rs);
            self.cpu.write_register64(rd, rs_val);
        }
        self.cpu.set_pc(self.cpu.pc().wrapping_add(4));
    }

    fn dsrl(&mut self, opcode: u32) {
        let rt = ((opcode >> 16) & 0x1F) as usize;
        let rd = ((opcode >> 11) & 0x1F) as usize;
        let sa = ((opcode >> 6) & 0x1F) as u32;

        let value = self.cpu.read_register64(rt);
        let result = value >> sa;
        self.cpu.write_register64(rd, result);
        self.cpu.set_pc(self.cpu.pc().wrapping_add(4));
    }

    fn daddiu(&mut self, opcode: u32) {
        let rs = ((opcode >> 21) & 0x1F) as usize;
        let rt = ((opcode >> 16) & 0x1F) as usize;
        let imm = (opcode as i16) as i64;

        let rs_val = self.cpu.read_register64(rs) as i64;
        let result = rs_val.wrapping_add(imm);
        self.cpu.write_register64(rt, result as u64);
        self.cpu.set_pc(self.cpu.pc().wrapping_add(4));
    }

    fn dsllv(&mut self, opcode: u32) {
        let rs = ((opcode >> 21) & 0x1F) as usize;
        let rt = ((opcode >> 16) & 0x1F) as usize;
        let rd = ((opcode >> 11) & 0x1F) as usize;

        let sa = self.cpu.read_register64(rs) & 0x3F;
        let value = self.cpu.read_register64(rt);
        let result = value << sa;
        self.cpu.write_register64(rd, result);
        self.cpu.set_pc(self.cpu.pc().wrapping_add(4));
    }

    fn lq(&mut self, opcode: u32) {
        let base = ((opcode >> 21) & 0x1F) as usize;
        let rt = ((opcode >> 16) & 0x1F) as usize;
        let offset = (opcode as i16) as i32;

        let base_val = self.cpu.read_register32(base) as u32;
        let vaddr = base_val.wrapping_add(offset as u32);
        let aligned_addr = vaddr & !0xF;

        let value = {
            let mut bus = self.cpu.bus.lock().unwrap();
            (bus.read128)(bus.deref_mut(), aligned_addr)
        };

        self.cpu.write_register(rt, value.into());
        self.cpu.set_pc(self.cpu.pc().wrapping_add(4));
    }

    fn sq(&mut self, opcode: u32) {
        let base = ((opcode >> 21) & 0x1F) as usize;
        let rt = ((opcode >> 16) & 0x1F) as usize;
        let offset = (opcode as i16) as i32;

        let base_val = self.cpu.read_register32(base) as u32;
        let vaddr = base_val.wrapping_add(offset as u32);
        let aligned_addr = vaddr & !0xF;

        let value = self.cpu.read_register(rt);

        {
            let mut bus = self.cpu.bus.lock().unwrap();
            (bus.write128)(bus.deref_mut(), aligned_addr, value);
        }

        self.cpu.set_pc(self.cpu.pc().wrapping_add(4));
    }

    fn lh(&mut self, opcode: u32) {
        let rs = ((opcode >> 21) & 0x1F) as usize;
        let rt = ((opcode >> 16) & 0x1F) as usize;
        let imm = (opcode as i16) as i32;

        let rs_val = self.cpu.read_register32(rs);
        let address = rs_val.wrapping_add(imm as u32);

        let loaded_halfword = {
            let mut bus = self.cpu.bus.lock().unwrap();
            (bus.read16)(bus.deref_mut(), address)
        };

        let result = loaded_halfword as i16 as i64 as u64;
        self.cpu.write_register64(rt, result);

        self.cpu.set_pc(self.cpu.pc().wrapping_add(4));
    }

    fn cache(&mut self) {
        // TODO: Implement CACHE instruction properly
        self.cpu.set_pc(self.cpu.pc().wrapping_add(4));
    }

    fn sllv(&mut self, opcode: u32) {
        let rs = ((opcode >> 21) & 0x1F) as usize;
        let rt = ((opcode >> 16) & 0x1F) as usize;
        let rd = ((opcode >> 11) & 0x1F) as usize;

        let sa = (self.cpu.read_register64(rs) & 0x1F) as u32;
        let value = self.cpu.read_register64(rt) as u32;
        let result = (value << sa) as i64;
        self.cpu.write_register64(rd, result.try_into().unwrap());
        self.cpu.set_pc(self.cpu.pc().wrapping_add(4));
    }

    fn dsll(&mut self, opcode: u32) {
        let rt = ((opcode >> 16) & 0x1F) as usize;
        let rd = ((opcode >> 11) & 0x1F) as usize;
        let sa = (opcode >> 6) & 0x1F;

        let rt_val = self.cpu.read_register64(rt);

        let result = rt_val << sa;

        self.cpu.write_register64(rd, result);
        self.cpu.set_pc(self.cpu.pc().wrapping_add(4));
    }

    fn srav(&mut self, opcode: u32) {
        let rs = ((opcode >> 21) & 0x1F) as usize;
        let rt = ((opcode >> 16) & 0x1F) as usize;
        let rd = ((opcode >> 11) & 0x1F) as usize;

        let s = (self.cpu.read_register64(rs) & 0x1F) as u32;
        let rt_val = self.cpu.read_register64(rt) as i32;
        let result = (rt_val >> s) as i64;

        self.cpu.write_register64(rd, result.try_into().unwrap());
        self.cpu.set_pc(self.cpu.pc().wrapping_add(4));
    }

    fn nor(&mut self, opcode: u32) {
        let rs = ((opcode >> 21) & 0x1F) as usize;
        let rt = ((opcode >> 16) & 0x1F) as usize;
        let rd = ((opcode >> 11) & 0x1F) as usize;

        let rs_val = self.cpu.read_register64(rs);
        let rt_val = self.cpu.read_register64(rt);
        let result = !(rs_val | rt_val);

        self.cpu.write_register64(rd, result);
        self.cpu.set_pc(self.cpu.pc().wrapping_add(4));
    }

    fn cfc2(&mut self, opcode: u32) {
        let rt = ((opcode >> 16) & 0x1F) as usize;
        let vi = ((opcode >> 11) & 0x1F) as usize;

        let vi_val = if vi == 0 || vi > 15 {
            0 // VI[0] is read-only (returns 0), and out-of-range VI indices return 0
        } else {
            self.cpu.vu0.vi[vi]
        };
        let result = vi_val as i16 as i64 as u64; // Sign-extend to 64-bit
        self.cpu.write_register64(rt, result);

        self.cpu.set_pc(self.cpu.pc().wrapping_add(4));
    }

    fn ctc2(&mut self, opcode: u32) {
        let rt = ((opcode >> 16) & 0x1F) as usize;
        let vi = ((opcode >> 11) & 0x1F) as usize;

        if vi != 0 && vi <= 15 {
            // VI[0] is read-only, and ignore out-of-range VI indices
            let rt_val = self.cpu.read_register64(rt);
            self.cpu.vu0.vi[vi] = rt_val as u16;
        }

        self.cpu.set_pc(self.cpu.pc().wrapping_add(4));
    }

    fn lwu(&mut self, opcode: u32) {
        let rs = ((opcode >> 21) & 0x1F) as usize;
        let rt = ((opcode >> 16) & 0x1F) as usize;
        let imm = (opcode as i16) as i32;

        let rs_val = self.cpu.read_register32(rs);
        let address = rs_val.wrapping_add(imm as u32);

        let loaded_word = {
            let mut bus = self.cpu.bus.lock().unwrap();
            (bus.read32)(bus.deref_mut(), address)
        };

        let result = loaded_word as u64;
        self.cpu.write_register64(rt, result);

        self.cpu.set_pc(self.cpu.pc().wrapping_add(4));
    }

    fn ldl(&mut self, opcode: u32) {
        let rs = ((opcode >> 21) & 0x1F) as usize;
        let rt = ((opcode >> 16) & 0x1F) as usize;
        let imm = (opcode as i16) as i32;

        let rs_val = self.cpu.read_register32(rs);
        let v_addr = rs_val.wrapping_add(imm as u32);
        let byte = v_addr & 0x7; // 0..7
        let p_addr = v_addr & !0x7;

        let mem_quad = {
            let mut bus = self.cpu.bus.lock().unwrap();
            (bus.read64)(bus.deref_mut(), p_addr)
        };

        let rt_val = self.cpu.read_register64(rt);
        let shift = (7 - byte) * 8; // max (7-0)*8 = 56
        let mask = !0u64 >> (byte * 8);
        let mem_bytes = mem_quad << shift;
        let result = (rt_val & mask) | mem_bytes;

        self.cpu.write_register64(rt, result);
        self.cpu.set_pc(self.cpu.pc().wrapping_add(4));
    }

    fn ldr(&mut self, opcode: u32) {
        let rs = ((opcode >> 21) & 0x1F) as usize;
        let rt = ((opcode >> 16) & 0x1F) as usize;
        let imm = (opcode as i16) as i32;

        let rs_val = self.cpu.read_register32(rs);
        let v_addr = rs_val.wrapping_add(imm as u32);
        let byte = v_addr & 0x7; // 0..7
        let p_addr = v_addr & !0x7;

        let mem_quad = {
            let mut bus = self.cpu.bus.lock().unwrap();
            (bus.read64)(bus.deref_mut(), p_addr)
        };

        let rt_val = self.cpu.read_register64(rt);
        let shift = byte * 8; // max 56
        let mem_bytes = mem_quad >> shift;

        // **Guard the 64‑bit shift** here:
        let mask_shift = (8 - byte) * 8;
        let mask = if mask_shift < 64 {
            !0u64 << mask_shift
        } else {
            0
        };

        let result = (rt_val & mask) | mem_bytes;

        self.cpu.write_register64(rt, result);
        self.cpu.set_pc(self.cpu.pc().wrapping_add(4));
    }

    fn sdl(&mut self, opcode: u32) {
        let rs = ((opcode >> 21) & 0x1F) as usize;
        let rt = ((opcode >> 16) & 0x1F) as usize;
        let imm = (opcode as i16) as i32;

        let rs_val = self.cpu.read_register32(rs);
        let v_addr = rs_val.wrapping_add(imm as u32);
        let byte = v_addr & 0x7; // 0..7
        let p_addr = v_addr & !0x7;

        let rt_val = self.cpu.read_register64(rt);
        let shift = (7 - byte) * 8; // max 56
        let data_quad = rt_val >> shift;

        {
            let mut bus = self.cpu.bus.lock().unwrap();
            (bus.write64)(bus.deref_mut(), p_addr, data_quad);
        }
        self.cpu.set_pc(self.cpu.pc().wrapping_add(4));
    }

    fn sdr(&mut self, opcode: u32) {
        let rs = ((opcode >> 21) & 0x1F) as usize;
        let rt = ((opcode >> 16) & 0x1F) as usize;
        let imm = (opcode as i16) as i32;

        let rs_val = self.cpu.read_register32(rs);
        let v_addr = rs_val.wrapping_add(imm as u32);
        let byte = v_addr & 0x7; // 0..7
        let p_addr = v_addr & !0x7;

        let rt_val = self.cpu.read_register64(rt);
        let shift = byte * 8; // max 56
        let data_quad = rt_val << shift;

        {
            let mut bus = self.cpu.bus.lock().unwrap();
            (bus.write64)(bus.deref_mut(), p_addr, data_quad);
        }
        self.cpu.set_pc(self.cpu.pc().wrapping_add(4));
    }

    fn srlv(&mut self, opcode: u32) {
        let rs = ((opcode >> 21) & 0x1F) as usize; // shift‐amount register
        let rt = ((opcode >> 16) & 0x1F) as usize; // value register
        let rd = ((opcode >> 11) & 0x1F) as usize; // destination

        let val64 = self.cpu.read_register64(rt);
        let word = val64 as u32; // take low 32 bits
        let shamt = (self.cpu.read_register64(rs) & 0x1F) as u32;

        let shifted32 = word >> shamt; // logical right on 32‐bit
        // sign‑extend the 32‑bit result back to 64:
        let result64 = (shifted32 as i32) as i64 as u64;

        self.cpu.write_register64(rd, result64);
        self.cpu.set_pc(self.cpu.pc().wrapping_add(4));
    }

    fn dsrl32(&mut self, opcode: u32) {
        // decode fields
        let rt = ((opcode >> 16) & 0x1F) as usize;
        let rd = ((opcode >> 11) & 0x1F) as usize;
        let sa5 = ((opcode >> 6) & 0x1F) as u32;

        // compute full shift = sa5 + 32
        let shift = sa5 + 32;

        // read, shift, write
        let val = self.cpu.read_register64(rt);
        let result = val >> shift;
        self.cpu.write_register64(rd, result);

        // advance PC
        self.cpu.set_pc(self.cpu.pc().wrapping_add(4));
    }

    fn padduw(&mut self, opcode: u32) {
        let rs = ((opcode >> 21) & 0x1F) as usize;
        let rt = ((opcode >> 16) & 0x1F) as usize;
        let rd = ((opcode >> 11) & 0x1F) as usize;

        let rs_val = self.cpu.read_register(rs);
        let rt_val = self.cpu.read_register(rt);

        let rs_words = [
            (rs_val & 0xFFFFFFFF) as u32,
            ((rs_val >> 32) & 0xFFFFFFFF) as u32,
            ((rs_val >> 64) & 0xFFFFFFFF) as u32,
            ((rs_val >> 96) & 0xFFFFFFFF) as u32,
        ];
        let rt_words = [
            (rt_val & 0xFFFFFFFF) as u32,
            ((rt_val >> 32) & 0xFFFFFFFF) as u32,
            ((rt_val >> 64) & 0xFFFFFFFF) as u32,
            ((rt_val >> 96) & 0xFFFFFFFF) as u32,
        ];

        let mut result = 0u128;
        for i in 0..4 {
            let sum = (rs_words[i] as u64) + (rt_words[i] as u64);
            let word = if sum > 0xFFFFFFFF {
                0xFFFFFFFF
            } else {
                sum as u32
            };
            result |= (word as u128) << (i * 32);
        }

        self.cpu.write_register(rd, result);
        self.cpu.set_pc(self.cpu.pc().wrapping_add(4));
    }

    fn di(&mut self) {
        let status = self.cpu.read_cop0_register(12);
        let edi = (status >> 10) & 0x1; // Bit 10: EDI
        let exl = (status >> 1) & 0x1; // Bit 1: EXL
        let erl = (status >> 2) & 0x1; // Bit 2: ERL
        let ksu = (status >> 3) & 0x3; // Bits 4:3: KSU

        if edi == 1 || exl == 1 || erl == 1 || ksu == 0 {
            let new_status = status & !(1u32); // Clear EIE (bit 0)
            self.cpu.write_cop0_register(12, new_status);
        }

        self.cpu.set_pc(self.cpu.pc().wrapping_add(4));
    }

    fn eret(&mut self) {
        let status = self.cpu.read_cop0_register(12); // Status register
        let erl = (status >> 2) & 0x1; // Bit 2
        if erl == 1 {
            self.cpu.pc.store(self.cpu.read_cop0_register(30), Ordering::Relaxed); // ErrorEPC
            self.cpu.write_cop0_register(12, status & !(1 << 2)); // Clear ERL
        } else {
            self.cpu.pc.store(self.cpu.read_cop0_register(14), Ordering::Relaxed); // EPC
            self.cpu.write_cop0_register(12, status & !(1 << 1)); // Clear EXL
        }

        if self.cpu.sideload_elf {
            let elf_bytes = fs::read(&self.cpu.elf_path)
                .unwrap_or_else(|e| panic!("Failed to read ELF '{}': {}", self.cpu.elf_path, e));

            self.cpu.load_elf(&elf_bytes);

            self.cpu.sideload_elf = false;
            self.cpu.pc.store(self.cpu.elf_entry_point, Ordering::Relaxed);
        }
    }

    fn syscall(&mut self, opcode: u32) {
        let code = (opcode >> 6) & 0xFFFFF;

        let status = self.cpu.read_cop0_register(12);

        let current_pc = self.cpu.pc();
        self.cpu.write_cop0_register(14, current_pc);

        let new_status = status | (1 << 1);
        self.cpu.write_cop0_register(12, new_status);

        let cause = (8 << 2) | ((code as u32) << 10);
        self.cpu.write_cop0_register(13, cause);

        let exception_vector = 0x80000180;
        self.cpu.set_pc(exception_vector);
    }

    fn sub(&mut self, opcode: u32) {
        let rs = ((opcode >> 21) & 0x1F) as usize;
        let rt = ((opcode >> 16) & 0x1F) as usize;
        let rd = ((opcode >> 11) & 0x1F) as usize;

        let rs_val = self.cpu.read_register32(rs) as i32;
        let rt_val = self.cpu.read_register32(rt) as i32;

        match rs_val.checked_sub(rt_val) {
            Some(result) => {
                let result_extended = result as i64 as u64;
                self.cpu.write_register64(rd, result_extended);
                self.cpu.set_pc(self.cpu.pc().wrapping_add(4));
            }
            None => {
                let status = self.cpu.read_cop0_register(12);
                let current_pc = self.cpu.pc();

                self.cpu.write_cop0_register(14, current_pc);

                let new_status = status | (1 << 1);
                self.cpu.write_cop0_register(12, new_status);

                let cause = self.cpu.read_cop0_register(13);
                let new_cause = (cause & !0x7C) | (12 << 2);
                self.cpu.write_cop0_register(13, new_cause);

                self.cpu.set_pc(0x80000180);
            }
        }
    }

    fn add(&mut self, opcode: u32) {
        let rs = ((opcode >> 21) & 0x1F) as usize;
        let rt = ((opcode >> 16) & 0x1F) as usize;
        let rd = ((opcode >> 11) & 0x1F) as usize;

        let rs_val = self.cpu.read_register32(rs) as i32;
        let rt_val = self.cpu.read_register32(rt) as i32;

        match rs_val.checked_add(rt_val) {
            Some(result) => {
                let result_extended = result as i64 as u64;
                self.cpu.write_register64(rd, result_extended);
                self.cpu.set_pc(self.cpu.pc().wrapping_add(4));
            }
            None => {
                let status = self.cpu.read_cop0_register(12);
                let current_pc = self.cpu.pc();

                self.cpu.write_cop0_register(14, current_pc);

                let new_status = status | (1 << 1);
                self.cpu.write_cop0_register(12, new_status);

                let cause = self.cpu.read_cop0_register(13);
                let new_cause = (cause & !0x7C) | (12 << 2);
                self.cpu.write_cop0_register(13, new_cause);

                self.cpu.set_pc(0x80000180);
            }
        }
    }

    fn addi(&mut self, opcode: u32) {
        let rs = ((opcode >> 21) & 0x1F) as usize;
        let rt = ((opcode >> 16) & 0x1F) as usize;
        let imm = (opcode as i16) as i32;

        let rs_val = self.cpu.read_register32(rs) as i32;

        match rs_val.checked_add(imm) {
            Some(result) => {
                let result_extended = result as i64 as u64;
                self.cpu.write_register64(rt, result_extended);
                self.cpu.set_pc(self.cpu.pc().wrapping_add(4));
            }
            None => {
                let status = self.cpu.read_cop0_register(12);
                let current_pc = self.cpu.pc();

                self.cpu.write_cop0_register(14, current_pc);

                let new_status = status | (1 << 1);
                self.cpu.write_cop0_register(12, new_status);

                let cause = self.cpu.read_cop0_register(13);
                let new_cause = (cause & !0x7C) | (12 << 2);
                self.cpu.write_cop0_register(13, new_cause);

                self.cpu.set_pc(0x80000180);
            }
        }
    }

    fn ei(&mut self) {
        let status = self.cpu.read_cop0_register(12);
        let edi = (status >> 10) & 0x1; // Bit 10: EDI
        let exl = (status >> 1) & 0x1;  // Bit 1: EXL
        let erl = (status >> 2) & 0x1;  // Bit 2: ERL
        let ksu = (status >> 3) & 0x3;  // Bits 4:3: KSU

        if edi == 1 || exl == 1 || erl == 1 || ksu == 0 {
            let new_status = status | 1u32; // Set EIE (bit 0)
            self.cpu.write_cop0_register(12, new_status);
        }

        self.cpu.set_pc(self.cpu.pc().wrapping_add(4));
    }
}

impl EmulationBackend<EE> for Interpreter {
    fn step(&mut self) {
        if self.cpu.has_breakpoint(self.cpu.pc.load(Ordering::Relaxed)) {
            debug!("Breakpoint hit at 0x{:08X}", self.cpu.pc.load(Ordering::Relaxed));
            let pc_value = self.cpu.pc.load(Ordering::Relaxed);
            self.cpu.remove_breakpoint(pc_value);
            return;
        }

        let opcode = self.cpu.fetch();

        self.decode_execute(opcode);

        self.cycles += self.get_instruction_cycles(opcode) as usize;
    }

    fn run(&mut self) {
        loop {
            if self.cpu.is_paused.load(Ordering::Relaxed) {
                std::thread::park();
            }

            self.step();

            if self.cpu.has_breakpoint(self.cpu.pc.load(Ordering::Relaxed)) {
                debug!("Breakpoint hit at 0x{:08X}", self.cpu.pc.load(Ordering::Relaxed));
                let pc_value = self.cpu.pc.load(Ordering::Relaxed);
                self.cpu.remove_breakpoint(pc_value);
                break;
            }
        }
    }

    fn run_for_cycles(&mut self, cycles: u64) -> u64 {
        let mut executed_cycles = 0;

        while executed_cycles < cycles {
            let opcode = self.cpu.fetch();

            self.decode_execute(opcode);

            let instruction_cycles = self.get_instruction_cycles(opcode);
            executed_cycles += instruction_cycles as u64;
            self.cycles += instruction_cycles as usize;
        }

        executed_cycles
    }

    fn get_cpu(&self) -> Arc<Mutex<EE>> {
        Arc::new(Mutex::new(self.cpu.clone()))
    }
}
