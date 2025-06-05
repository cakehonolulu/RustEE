use crate::bus::tlb::TlbEntry;
use crate::cpu::{CPU, EmulationBackend};
use crate::ee::EE;
use crate::Bus;
use cranelift_codegen::ir::condcodes::IntCC;
use cranelift_codegen::ir::{types, AbiParam, InstBuilder, MemFlags, Value};
use cranelift_frontend::{FunctionBuilder, FunctionBuilderContext};
use cranelift_module::{FuncId, Linkage, Module};
use cranelift_jit::{JITBuilder, JITModule};
use lru::LruCache;
use std::num::NonZero;
use tracing::error;

#[derive(Clone)]
pub struct Block {
    pub pc: u32,
    pub func_ptr: fn(),
    pub dirty: bool,
    pub breakpoint: bool,
    pub cycle_count: u32,
}

pub struct JIT<'a> {
    pub cpu: &'a mut EE,
    module: JITModule,
    blocks: LruCache<u32, Block>,
    max_blocks: usize,
    gpr_ptr: *mut u128,
    cop0_ptr: *mut u32,
    pc_ptr: *mut u32,
    cycles: usize,
    bus_write32_func: FuncId,
    tlbwi_func: FuncId,
}

enum BranchTarget {
    Const(u32),
    Reg(Value),
}

const MAX_BLOCKS: NonZero<usize> = NonZero::new(128).unwrap();

fn bus_from_ptr<'a>(bus_ptr: &'a mut Bus) -> &'a mut Bus {
    &mut *bus_ptr
}

pub extern "C" fn __bus_write32<'a>(
    bus_ptr: &'a mut Bus,
    addr: u32,
    value: u32,
) {
    let bus: &mut Bus = bus_from_ptr(bus_ptr);
    (bus.write32)(bus, addr, value);
}

pub extern "C" fn __bus_tlbwi(bus_ptr: *mut Bus) {
    let bus = unsafe { &mut *bus_ptr };
    let mut tlb_ref = bus.tlb.borrow_mut();

    let index = (unsafe { *bus.cop0_registers_ptr.add(0) } & 0x3F) as usize;

    let entry_hi  = unsafe { *bus.cop0_registers_ptr.add(10) }; // EntryHi
    let entry_lo0 = unsafe { *bus.cop0_registers_ptr.add(2)  }; // EntryLo0
    let entry_lo1 = unsafe { *bus.cop0_registers_ptr.add(3)  }; // EntryLo1
    let page_mask = unsafe { *bus.cop0_registers_ptr.add(5)  }; // PageMask

    let vpn2 = entry_hi >> 13;
    let asid = (entry_hi & 0xFF) as u8;

    let s0   = ((entry_lo0 >> 31) & 0x1) != 0;     // scratchpad flag
    let pfn0 = (entry_lo0 >> 6) & 0x000F_FFFF;     // bits [31:6]
    let c0   = ((entry_lo0 >> 3) & 0x7) as u8;     // bits [5:3]
    let d0   = ((entry_lo0 >> 2) & 0x1) != 0;      // bit [2]
    let v0   = ((entry_lo0 >> 1) & 0x1) != 0;      // bit [1]
    let g0   =  (entry_lo0 & 0x1) != 0;            // bit [0]

    let s1   = ((entry_lo1 >> 31) & 0x1) != 0;     // scratchpad flag
    let pfn1 = (entry_lo1 >> 6) & 0x000F_FFFF;     // bits [31:6]
    let c1   = ((entry_lo1 >> 3) & 0x7) as u8;     // bits [5:3]
    let d1   = ((entry_lo1 >> 2) & 0x1) != 0;      // bit [2]
    let v1   = ((entry_lo1 >> 1) & 0x1) != 0;      // bit [1]
    let g1   =  (entry_lo1 & 0x1) != 0;            // bit [0]

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

    tlb_ref.write_tlb_entry(bus_ptr, index, new_entry);
}

impl<'a> JIT<'a> {
    pub fn new(cpu: &'a mut EE) -> Self {

        let mut builder = JITBuilder::new(
            cranelift_module::default_libcall_names()
        ).expect("Failed to create JITBuilder");

        builder.symbol(
            "__bus_write32",
            __bus_write32 as *const u8,
        );

        builder.symbol(
            "__bus_tlbwi",
            __bus_tlbwi as *const u8,
        );

        let mut module = JITModule::new(builder);
        let gpr_ptr = cpu.registers.as_mut_ptr();
        let cop0_ptr = cpu.cop0_registers.as_mut_ptr();
        let pc_ptr = &mut cpu.pc as *mut u32;

        let mut store32_sig = module.make_signature();
        store32_sig.params.push(AbiParam::new(types::I64));
        store32_sig.params.push(AbiParam::new(types::I32));
        store32_sig.params.push(AbiParam::new(types::I32));
        let bus_write32_func: FuncId = module
            .declare_function("__bus_write32", Linkage::Import, &store32_sig)
            .expect("Failed to declare __bus_write32 function!");

        let mut tlbwi_sig = module.make_signature();
        // Parameter: i64 (raw *mut Bus)
        tlbwi_sig.params.push(AbiParam::new(types::I64));
        // Return i32 (unused)
        tlbwi_sig.returns.push(AbiParam::new(types::I32));
        let tlbwi_func: FuncId = module
            .declare_function("__bus_tlbwi", Linkage::Import, &tlbwi_sig)
            .expect("Failed to declare __bus_tlbwi!");

        JIT {
            cpu,
            module,
            blocks: LruCache::new(MAX_BLOCKS),
            max_blocks: MAX_BLOCKS.into(),
            gpr_ptr,
            cop0_ptr,
            pc_ptr,
            cycles: 0,
            bus_write32_func,
            tlbwi_func
        }
    }

    #[inline]
    fn get_instruction_cycles(&self, opcode: u32) -> u32 {
        const DEFAULT:    u32 = 9;
        const BRANCH:     u32 = 11;
        const COP_DEFAULT:u32 = 7;

        const MULT:       u32 = 2 * 8;
        const DIV:        u32 = 14 * 8;

        const MMI_MULT:   u32 = 3 * 8;
        const MMI_DIV:    u32 = 22 * 8;
        const MMI_DEFAULT:u32 = 14;

        const FPU_MULT:   u32 = 4 * 8;

        const LD_ST:      u32 = 14;

        let primary = opcode >> 26;
        match primary {
            0x00 => {
                let funct = opcode & 0x3F;
                match funct {
                    0x18 | 0x19 => MULT,
                    0x1A | 0x1B => DIV,
                    _             => DEFAULT,
                }
            }

            0x02 | 0x03 => DEFAULT,

            0x04 | 0x05
          | 0x06 | 0x07
          | 0x01
                => BRANCH,

            0x20..=0x27
          | 0x28..=0x2F
                => LD_ST,

            0x10
                => COP_DEFAULT,

            0x11 => {
                let fmt = (opcode >> 21) & 0x1F;
                if fmt == 0 {
                    COP_DEFAULT
                } else {
                    let funct = opcode & 0x3F;
                    match funct {
                        0x02 | 0x03 => FPU_MULT,
                        _           => DEFAULT,
                    }
                }
            }

            0x1C => {
                let mmiop = (opcode >> 21) & 0x1F;
                match mmiop {
                    0x00..=0x03 => MMI_MULT,
                    0x04..=0x07 => MMI_DIV,
                    _           => MMI_DEFAULT,
                }
            }

            _ => DEFAULT,
        }
    }

    fn execute(&mut self, single_step: bool) -> (bool, u32) {
        let pc = self.cpu.pc();
        //debug!("execute: Finding block at: 0x{:08X}", pc);

        let block = self.blocks.get(&pc).cloned().unwrap_or_else(|| {
            let (func_ptr, breakpoint, cycles) = self.compile_block(pc, single_step);
            let block = Block {
                pc,
                func_ptr,
                dirty: false,
                breakpoint,
                cycle_count: cycles
            };
            self.blocks.put(pc, block.clone());
            //debug!("execute: Compiled block at: 0x{:08X}", pc);
            block
        });

        if block.dirty {
            let (func_ptr, breakpoint, cycles) = self.compile_block(pc, single_step);
            let block = Block {
                pc,
                func_ptr,
                dirty: false,
                breakpoint,
                cycle_count: cycles
            };
            self.blocks.put(pc, block.clone());

            (block.func_ptr)();

            self.cycles += block.cycle_count as usize;

            return (block.breakpoint, block.cycle_count)
        }

        (block.func_ptr)();

        self.cycles += block.cycle_count as usize;

        (block.breakpoint, block.cycle_count)
    }

    fn compile_block(&mut self, pc: u32, single_step: bool) -> (fn(), bool, u32) {
        let mut ctx = self.module.make_context();
        ctx.func.signature = self.module.make_signature();
        let mut builder_ctx = FunctionBuilderContext::new();
        let mut builder = FunctionBuilder::new(&mut ctx.func, &mut builder_ctx);

        let entry_block = builder.create_block();
        builder.switch_to_block(entry_block);
        builder.seal_block(entry_block);

        let mut breakpoint = false;
        let mut total_cycles = 0;
        let mut current_pc = pc;
        let pc_addr = builder.ins().iconst(types::I64, self.pc_ptr as i64);

        loop {
            if self.cpu.has_breakpoint(current_pc) {
                breakpoint = true;
                break;
            }

            let opcode = self.cpu.fetch_at(current_pc);
            let instruction_cycles = self.get_instruction_cycles(opcode);
            total_cycles += instruction_cycles;

            if let Some((cond, branch_target, is_likely)) =
                self.branch_info(opcode, &mut builder, current_pc)
            {
                // delay slot
                let mut delay_pc = current_pc.wrapping_add(4);

                if is_likely {
                    let then_blk = builder.create_block();
                    let else_blk = builder.create_block();
                    let merge_ds = builder.create_block();
                    builder.ins().brif(cond, then_blk, &[], else_blk, &[]);
                    builder.switch_to_block(then_blk);
                    self.decode(&mut builder, opcode, &mut delay_pc);
                    builder.ins().jump(merge_ds, &[]);
                    builder.seal_block(then_blk);
                    builder.switch_to_block(else_blk);
                    builder.ins().jump(merge_ds, &[]);
                    builder.seal_block(else_blk);
                    builder.switch_to_block(merge_ds);
                    builder.seal_block(merge_ds);
                } else {
                    let delay_opcode = self.cpu.fetch_at(delay_pc);
                    self.decode(&mut builder, delay_opcode, &mut delay_pc);
                    current_pc = current_pc.wrapping_add(8);
                }

                // branch / jump path
                let branch_blk = builder.create_block();
                let fallthrough_blk = builder.create_block();
                let merge_blk = builder.create_block();
                builder.ins().brif(cond, branch_blk, &[], fallthrough_blk, &[]);

                // branch/jump target
                builder.switch_to_block(branch_blk);
                match branch_target {
                    BranchTarget::Const(addr) => {
                        let t = builder.ins().iconst(types::I32, addr as i64);
                        builder.ins().store(MemFlags::new(), t, pc_addr, 0);
                    }
                    BranchTarget::Reg(val) => {
                        let t32 = builder.ins().ireduce(types::I32, val);
                        builder.ins().store(MemFlags::new(), t32, pc_addr, 0);
                    }
                }
                builder.ins().jump(merge_blk, &[]);
                builder.seal_block(branch_blk);

                // fallthrough path
                builder.switch_to_block(fallthrough_blk);
                let fall_val = builder.ins().iconst(types::I32, current_pc as i64);
                builder.ins().store(MemFlags::new(), fall_val, pc_addr, 0);
                builder.ins().jump(merge_blk, &[]);
                builder.seal_block(fallthrough_blk);

                // merge
                builder.switch_to_block(merge_blk);
                builder.seal_block(merge_blk);
                break;
            }

            self.decode(&mut builder, opcode, &mut current_pc);
            if single_step {
                break;
            }
        }

        builder.ins().return_(&[]);
        builder.finalize();

        let func_name = format!("block_{:08X}", pc);
        let func_id = self
            .module
            .declare_function(&func_name, Linkage::Local, &ctx.func.signature)
            .expect("Failed to declare function");

        self.module
            .define_function(func_id, &mut ctx)
            .expect("Failed to define function");
        self.module.clear_context(&mut ctx);
        self.module.finalize_definitions().unwrap();

        let ptr = self.module.get_finalized_function(func_id);

        unsafe { (std::mem::transmute(ptr), breakpoint, total_cycles) }
    }

    fn branch_info(&self, opcode: u32, builder: &mut FunctionBuilder, pc: u32)
        -> Option<(Value, BranchTarget, bool)> {
        let primary = opcode >> 26;
        if primary == 0 {
            // SPECIAL group: check JR (funct 0x08)
            let funct = opcode & 0x3F;
            if funct == 0x08 {
                // Build an always-true condition by comparing 1 != 0
                let one = builder.ins().iconst(types::I32, 1);
                let zero = builder.ins().iconst(types::I32, 0);
                let cond = builder.ins().icmp(IntCC::NotEqual, one, zero);
                // Load target from GPR[rs]
                let rs = ((opcode >> 21) & 0x1F) as i64;
                let addr = Self::ptr_add(builder, self.gpr_ptr as i64, rs, 16);
                let target_i32 = builder.ins().load(types::I32, MemFlags::new(), addr, 0);
                let target64 = builder.ins().uextend(types::I64, target_i32);
                return Some((cond, BranchTarget::Reg(target64), false));
            }
        } else if primary == 0x05 {
            // BNE
            let rs = ((opcode >> 21) & 0x1F) as i64;
            let rt = ((opcode >> 16) & 0x1F) as i64;
            let imm = (opcode as u16) as i16 as i32;
            let raddr = Self::ptr_add(builder, self.gpr_ptr as i64, rs, 16);
            let taddr = Self::ptr_add(builder, self.gpr_ptr as i64, rt, 16);
            let rv = builder.ins().load(types::I32, MemFlags::new(), raddr, 0);
            let tv = builder.ins().load(types::I32, MemFlags::new(), taddr, 0);
            let cond = builder.ins().icmp(IntCC::NotEqual, rv, tv);
            let tgt = pc.wrapping_add(4).wrapping_add((imm << 2) as u32);
            return Some((cond, BranchTarget::Const(tgt), false));
        }
        None
    }

    pub fn mark_block_dirty(&mut self, pc: u32) {
        if let Some(block) = self.blocks.get_mut(&pc) {
            block.dirty = true;
            println!("Marked block at PC 0x{:08X} as dirty.", pc);
        }
    }

    fn decode(&mut self, builder: &mut FunctionBuilder, opcode: u32, current_pc: &mut u32) {
        let function = opcode >> 26;
        //debug!("decode: function: 0x{:02X}", function);
        match function {
            0x00 => {
                let subfunction = opcode & 0x3F;
                match subfunction {
                    0x00 => {
                        self.sll(builder, opcode, current_pc);
                    }
                    0x0F => {
                        self.sync(builder, opcode, current_pc);
                    }
                    _ => {
                        error!("Unhandled EE JIT function SPECIAL opcode: 0x{:08X} (Subfunction 0x{:02X}), PC: 0x{:08X}", opcode, subfunction, current_pc);
                        panic!();
                    }
                }
            }
            0x09 => {
                self.addiu(builder, opcode, current_pc);
            }
            0x0A => {
                self.slti(builder, opcode, current_pc);
            }
            0x0D => {
                self.ori(builder, opcode, current_pc);
            }
            0x0F => {
                self.lui(builder, opcode, current_pc);
            }
            0x10 => {
                let subfunction = (opcode >> 21) & 0x1F;
                match subfunction {
                    0x00 => {
                        self.mfc0(builder, opcode, current_pc);
                    }
                    0x04 => {
                        self.mtc0(builder, opcode, current_pc);
                    }
                    0x10 => {
                        self.tlbwi(builder, opcode, current_pc);
                    }
                    _ => {
                        error!("Unhandled EE JIT COP0 opcode: 0x{:08X} (Subfunction 0x{:02X}), PC: 0x{:08X}", opcode, subfunction, current_pc);
                        panic!();
                    }
                }
            }
            0x2B => {
                self.sw(builder, opcode, current_pc);
            }
            _ => {
                error!("Unhandled EE JIT opcode: 0x{:08X} (Function 0x{:02X}), PC: 0x{:08X}", opcode, function, current_pc);
                panic!();
            }
        }
    }

    fn ptr_add(
        builder: &mut FunctionBuilder,
        base: i64,
        index: i64,
        scale: i64,
    ) -> Value {
        let base_val = builder.ins().iconst(types::I64, base);
        let idx_val = builder.ins().iconst(types::I64, index);
        let scale_val = builder.ins().iconst(types::I64, scale);
        let offset = builder.ins().imul(idx_val, scale_val);
        builder.ins().iadd(base_val, offset)
    }

    #[inline(always)]
    fn load32(builder: &mut FunctionBuilder, addr: Value) -> Value {
        builder.ins().load(types::I32, MemFlags::new(), addr, 0)
    }

    #[inline(always)]
    fn store128(builder: &mut FunctionBuilder, val: Value, addr: Value) {
        builder.ins().store(MemFlags::new(), val, addr, 0);
    }

    #[inline(always)]
    fn increment_pc(builder: &mut FunctionBuilder, pc_ptr: i64) {
        let pc_ptr_val = builder.ins().iconst(types::I64, pc_ptr);
        let pc_val = builder.ins().load(types::I32, MemFlags::new(), pc_ptr_val, 0);
        let pc_inc = builder.ins().iadd_imm(pc_val, 4);
        builder.ins().store(MemFlags::new(), pc_inc, pc_ptr_val, 0);
    }

    fn mfc0(&mut self, builder: &mut FunctionBuilder, opcode: u32, current_pc: &mut u32) {
        let rt = ((opcode >> 16) & 0x1F) as i64;
        let rd = ((opcode >> 11) & 0x1F) as i64;

        let gpr_addr = Self::ptr_add(builder, self.gpr_ptr as i64, rt, 16);
        let cop0_addr = Self::ptr_add(builder, self.cop0_ptr as i64, rd, 4);

        let cop0_val = Self::load32(builder, cop0_addr);
        builder.ins().store(MemFlags::new(), cop0_val, gpr_addr, 0);

        // Add self.cycles to COP0.Count (cop0[9])
        let count_addr = Self::ptr_add(builder, self.cop0_ptr as i64, 9, 4);
        let count_val = Self::load32(builder, count_addr);
        let cycles_val = builder.ins().iconst(types::I32, self.cycles as i64);
        let new_count_val = builder.ins().iadd(count_val, cycles_val);
        builder.ins().store(MemFlags::new(), new_count_val, count_addr, 0);

        Self::increment_pc(builder, self.pc_ptr as i64);
        *current_pc = current_pc.wrapping_add(4);
    }

    fn sll(&mut self, builder: &mut FunctionBuilder, opcode: u32, current_pc: &mut u32) {
        let rd = ((opcode >> 11) & 0x1F) as i64;
        let rt = ((opcode >> 16) & 0x1F) as i64;
        let sa = ((opcode >> 6) & 0x1F) as i64;

        let rd_addr = Self::ptr_add(builder, self.gpr_ptr as i64, rd, 16);
        let rt_addr = Self::ptr_add(builder, self.gpr_ptr as i64, rt, 16);

        let rt_val = builder.ins().load(types::I32, MemFlags::new(), rt_addr, 0);
        let shifted_val = builder.ins().ishl_imm(rt_val, sa as i64);
        let result = builder.ins().sextend(types::I64, shifted_val);
        builder.ins().store(MemFlags::new(), result, rd_addr, 0);
    
        Self::increment_pc(builder, self.pc_ptr as i64);
        *current_pc = current_pc.wrapping_add(4);
    }

    fn slti(&mut self, builder: &mut FunctionBuilder, opcode: u32, current_pc: &mut u32) {
        let rs = ((opcode >> 21) & 0x1F) as i64;
        let rt = ((opcode >> 16) & 0x1F) as i64;
        let imm = (opcode as i16) as i64;

        let rs_a = Self::ptr_add(builder, self.gpr_ptr as i64, rs, 16);
        let rt_a = Self::ptr_add(builder, self.gpr_ptr as i64, rt, 16);

        let rs_val = builder.ins().load(types::I64, MemFlags::new(), rs_a, 0);
        let imm_val = builder.ins().iconst(types::I64, imm);
        let cmp = builder.ins().icmp(IntCC::SignedLessThan, rs_val, imm_val);
        let one = builder.ins().iconst(types::I64, 1);
        let zero = builder.ins().iconst(types::I64, 0);
        let result = builder.ins().select(cmp, one, zero);
        builder.ins().store(MemFlags::new(), result, rt_a, 0);

        Self::increment_pc(builder, self.pc_ptr as i64);
        *current_pc = current_pc.wrapping_add(4);
    }

    fn lui(&mut self, builder: &mut FunctionBuilder, opcode: u32, current_pc: &mut u32) {
        let rt = ((opcode >> 16) & 0x1F) as i64;
        let imm = (opcode & 0xFFFF) as i64;

        let rt_addr = Self::ptr_add(builder, self.gpr_ptr as i64, rt, 16);
        let imm_val = builder.ins().iconst(types::I64, imm << 16);
        builder.ins().store(MemFlags::new(), imm_val, rt_addr, 0);

        Self::increment_pc(builder, self.pc_ptr as i64);
        *current_pc = current_pc.wrapping_add(4);
    }

    fn ori(&mut self, builder: &mut FunctionBuilder, opcode: u32, current_pc: &mut u32) {
        let rs = ((opcode >> 21) & 0x1F) as i64;
        let rt = ((opcode >> 16) & 0x1F) as i64;
        let imm = (opcode & 0xFFFF) as i64;

        let rs_addr = Self::ptr_add(builder, self.gpr_ptr as i64, rs, 16);
        let rt_addr = Self::ptr_add(builder, self.gpr_ptr as i64, rt, 16);

        let rs_val = builder.ins().load(types::I32, MemFlags::new(), rs_addr, 0);
        let imm_val = builder.ins().iconst(types::I32, imm);
        let result = builder.ins().iadd(rs_val, imm_val);
        builder.ins().store(MemFlags::new(), result, rt_addr, 0);

        Self::increment_pc(builder, self.pc_ptr as i64);
        *current_pc = current_pc.wrapping_add(4);
    }

    fn mtc0(&mut self, builder: &mut FunctionBuilder, opcode: u32, current_pc: &mut u32) {
        let rt = ((opcode >> 16) & 0x1F) as i64;
        let rd = ((opcode >> 11) & 0x1F) as i64;

        let gpr_addr = Self::ptr_add(builder, self.gpr_ptr as i64, rt, 16);
        let cop0_addr = Self::ptr_add(builder, self.cop0_ptr as i64, rd, 4);

        let gpr_val = Self::load32(builder, gpr_addr);
        builder.ins().store(MemFlags::new(), gpr_val, cop0_addr, 0);

        Self::increment_pc(builder, self.pc_ptr as i64);
        *current_pc = current_pc.wrapping_add(4);
    }

    fn sync(&mut self, builder: &mut FunctionBuilder, _opcode: u32, current_pc: &mut u32) {
        // TODO: Implement SYNC instruction properly
        Self::increment_pc(builder, self.pc_ptr as i64);
        *current_pc = current_pc.wrapping_add(4);
    }

    fn addiu(&mut self, builder: &mut FunctionBuilder, opcode: u32, current_pc: &mut u32) {
        let rs = ((opcode >> 21) & 0x1F) as i64;
        let rt = ((opcode >> 16) & 0x1F) as i64;
        let imm = (opcode as i16) as i64;

        let rs_addr = Self::ptr_add(builder, self.gpr_ptr as i64, rs, 16);
        let rt_addr = Self::ptr_add(builder, self.gpr_ptr as i64, rt, 16);

        let rs_val = builder.ins().load(types::I32, MemFlags::new(), rs_addr, 0);
        let imm_val = builder.ins().iconst(types::I32, imm);
        let result = builder.ins().iadd(rs_val, imm_val);
        builder.ins().store(MemFlags::new(), result, rt_addr, 0);

        Self::increment_pc(builder, self.pc_ptr as i64);
        *current_pc = current_pc.wrapping_add(4);
    }

    fn sw(&mut self, builder: &mut FunctionBuilder, opcode: u32, current_pc: &mut u32) {
        let base = ((opcode >> 21) & 0x1F) as i64;
        let rt   = ((opcode >> 16) & 0x1F) as i64;
        let imm  = ((opcode as i16) as i64) as i64;
        let base_addr = Self::ptr_add(builder, self.gpr_ptr as i64, base, 16);
        let base_val  = Self::load32(builder, base_addr);
        let addr = builder.ins().iadd_imm(base_val, imm);
        let rt_addr = Self::ptr_add(builder, self.gpr_ptr as i64, rt, 16);
        let store_val = Self::load32(builder, rt_addr);

        let bus_ptr_const = builder.ins().iconst(types::I64, &self.cpu.bus as *const _ as i64);
        let addr_arg = addr;
        let val_arg  = store_val;

        let callee = self.module.declare_func_in_func(self.bus_write32_func, builder.func);
        builder.ins().call(callee, &[bus_ptr_const, addr_arg, val_arg]);

        Self::increment_pc(builder, self.pc_ptr as i64);
        *current_pc = current_pc.wrapping_add(4);
    }

    fn tlbwi(&mut self, builder: &mut FunctionBuilder, opcode: u32, current_pc: &mut u32) {
        let bus_raw = (&mut self.cpu.bus as *mut Bus) as i64;
        let bus_ptr = builder.ins().iconst(types::I64, bus_raw);

        let local_callee = self.module.declare_func_in_func(self.tlbwi_func, builder.func);

        builder.ins().call(local_callee, &[bus_ptr]);

        Self::increment_pc(builder, self.pc_ptr as i64);
        *current_pc = current_pc.wrapping_add(4);
    }

}

impl EmulationBackend<EE> for JIT<'_> {
    fn step(&mut self) {
        let (breakpoint_hit, _) = self.execute(true);

        if breakpoint_hit {
            return;
        }
    }

    fn run(&mut self) {
        loop {
            let (breakpoint_hit, _) = self.execute(false);
            if breakpoint_hit {
                break;
            }
        }
    }

    fn run_for_cycles(&mut self, cycles: u32) {
        let mut executed_cycles = 0;

        while executed_cycles < cycles {
            let (breakpoint_hit, block_cycles) = self.execute(false);

            executed_cycles += block_cycles;

            if breakpoint_hit {
                break;
            }
        }
    }
}