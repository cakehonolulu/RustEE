use crate::cpu::{CPU, EmulationBackend};
use crate::ee::EE;
use cranelift_codegen::ir::condcodes::IntCC;
use cranelift_codegen::ir::{types, InstBuilder, MemFlags, Value};
use cranelift_frontend::{FunctionBuilder, FunctionBuilderContext};
use cranelift_module::{Module, Linkage};
use cranelift_jit::{JITBuilder, JITModule};
use lru::LruCache;
use std::num::NonZero;
use tracing::{debug, error};

#[derive(Clone)]
pub struct Block {
    pub pc: u32,
    pub func_ptr: fn(),
    pub dirty: bool,
    pub breakpoint: bool,
}

pub struct JIT<'a> {
    pub cpu: &'a mut EE,
    module: JITModule,
    blocks: LruCache<u32, Block>,
    max_blocks: usize,
    gpr_ptr: *mut u128,
    cop0_ptr: *mut u32,
    pc_ptr: *mut u32,
}

const MAX_BLOCKS: NonZero<usize> = NonZero::new(128).unwrap();

impl<'a> JIT<'a> {
    pub fn new(cpu: &'a mut EE) -> Self {
        let builder = JITBuilder::new(cranelift_module::default_libcall_names());
        let module = JITModule::new(builder.expect("Failed to create JITModule"));
        let gpr_ptr = cpu.registers.as_mut_ptr();
        let cop0_ptr = cpu.cop0_registers.as_mut_ptr();
        let pc_ptr = &mut cpu.pc as *mut u32;
        JIT {
            cpu,
            module,
            blocks: LruCache::new(MAX_BLOCKS),
            max_blocks: MAX_BLOCKS.into(),
            gpr_ptr,
            cop0_ptr,
            pc_ptr,
        }
    }

    fn execute(&mut self, single_step: bool) -> bool {
        let pc = self.cpu.pc();
        //debug!("execute: Finding block at: 0x{:08X}", pc);

        let block = self.blocks.get(&pc).cloned().unwrap_or_else(|| {
            let (func_ptr, breakpoint) = self.compile_block(pc, single_step);
            let block = Block {
                pc,
                func_ptr,
                dirty: false,
                breakpoint,
            };
            self.blocks.put(pc, block.clone());
            //debug!("execute: Compiled block at: 0x{:08X}", pc);
            block
        });

        if block.dirty {
            let (func_ptr, breakpoint) = self.compile_block(pc, single_step);
            let block = Block {
                pc,
                func_ptr,
                dirty: false,
                breakpoint,
            };
            self.blocks.put(pc, block.clone());

            (block.func_ptr)();

            return block.breakpoint
        }

        (block.func_ptr)();

        block.breakpoint
    }

    fn compile_block(&mut self, pc: u32, single_step: bool) -> (fn(), bool) {
        let mut ctx = self.module.make_context();
        ctx.func.signature = self.module.make_signature();

        let mut builder_ctx = FunctionBuilderContext::new();
        let mut builder = FunctionBuilder::new(&mut ctx.func, &mut builder_ctx);

        let entry_block = builder.create_block();
        builder.switch_to_block(entry_block);
        builder.seal_block(entry_block);

        let mut breakpoint = false;

        let mut current_pc = pc;

        let pc_addr = builder.ins().iconst(types::I64, self.pc_ptr as i64);

        loop {
            if self.cpu.has_breakpoint(current_pc) {
                //debug!("EE JIT Breakpoint hit at 0x{:08X}", current_pc);
                breakpoint = true;
                break;
            }

            let opcode = self.cpu.fetch_at(current_pc);
            //debug!("EE JIT opcode: 0x{:08X} (PC: 0x{:08X})", opcode, current_pc);

            if let Some((cond, target, is_likely)) = self.branch_info(opcode, &mut builder, current_pc) {
                //debug!("EE JIT branch info: cond: {:?}, target: 0x{:08X}, is_likely: {}", cond, target, is_likely);

                let mut delay_pc = current_pc.wrapping_add(4);

                if is_likely {
                    // only run delay‐slot if branch is taken
                    let then_block   = builder.create_block();
                    let else_block   = builder.create_block();
                    let delay_merge  = builder.create_block();

                    // if cond!=0 jump to then_block, else to else_block
                    builder.ins().brif(cond, then_block, &[], else_block, &[]);

                    // then: emit delay‐slot
                    builder.switch_to_block(then_block);
                    self.decode(&mut builder, opcode, &mut delay_pc);
                    builder.ins().jump(delay_merge, &[]);
                    builder.seal_block(then_block);

                    // else: skip it
                    builder.switch_to_block(else_block);
                    builder.ins().jump(delay_merge, &[]);
                    builder.seal_block(else_block);

                    // merge
                    builder.switch_to_block(delay_merge);
                    builder.seal_block(delay_merge);

                } else {
                    // normal branch: always run delay‐slot
                    let delay_opcode = self.cpu.fetch_at(delay_pc);
                    self.decode(&mut builder, delay_opcode, &mut delay_pc);
                    current_pc = current_pc.wrapping_add(8);
                }

                let branch_blk      = builder.create_block();
                let fallthrough_blk = builder.create_block();
                let merge_blk       = builder.create_block();

                // if cond!=0 goto branch_blk else fallthrough
                builder.ins().brif(cond, branch_blk, &[], fallthrough_blk, &[]);

                // branch target path
                builder.switch_to_block(branch_blk);

                // Compute the constant in its own statement:
                let target_val = builder.ins().iconst(types::I32, target as i64);

                builder.ins().store(
                    MemFlags::new(),
                    target_val,
                    pc_addr,
                    0,
                );

                builder.ins().jump(merge_blk, &[]);
                builder.seal_block(branch_blk);

                // fallthrough path
                builder.switch_to_block(fallthrough_blk);
                let fall_pc = current_pc;

                let fall_val = builder.ins().iconst(types::I32, current_pc as i64);
                builder.ins().store(
                    MemFlags::new(),
                    fall_val,
                    pc_addr,
                    0,
                );
                builder.ins().jump(merge_blk, &[]);
                builder.seal_block(fallthrough_blk);

                // merge and return
                builder.switch_to_block(merge_blk);
                builder.seal_block(merge_blk);
                break;
            }

            self.decode(&mut builder, opcode, &mut current_pc);
            //debug!("EE JIT decoded opcode: 0x{:08X} (PC: 0x{:08X})", opcode, current_pc);

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
        self.module.finalize_definitions().expect("Failed to finalize definitions");

        let func_ptr = self.module.get_finalized_function(func_id);

        unsafe { (std::mem::transmute(func_ptr), breakpoint) }
    }

    fn branch_info(
        &self,
        opcode: u32,
        builder: &mut FunctionBuilder,
        pc: u32
    ) -> Option<(cranelift_codegen::ir::Value, u32, bool)> {
        match opcode >> 26 {
            0x05 => {
                //debug!("EE JIT: BNE opcode detected");
                let rs = ((opcode >> 21) & 0x1F) as i64;
                let rt = ((opcode >> 16) & 0x1F) as i64;
                let imm = (opcode as u16) as i16 as i32;
                let rs_addr = Self::ptr_add(builder, self.gpr_ptr as i64, rs, 16);
                let rt_addr = Self::ptr_add(builder, self.gpr_ptr as i64, rt, 16);
                let rs_val = builder.ins().load(types::I32, MemFlags::new(), rs_addr, 0);
                let rt_val = builder.ins().load(types::I32, MemFlags::new(), rt_addr, 0);
                let cond = builder.ins().icmp(IntCC::NotEqual, rs_val, rt_val);
                let offset = (imm << 2) as u32;
                let target = pc.wrapping_add(4).wrapping_add(offset);
                Some((cond, target, false))
            }
            _ => {
                None
            }
        }
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
                    _ => {
                        error!("Unhandled EE JIT function SPECIAL opcode: 0x{:08X} (Subfunction 0x{:02X}), PC: 0x{:08X}", opcode, subfunction, current_pc);
                        panic!();
                    }
                }
            }
            0x0A => {
                self.slti(builder, opcode, current_pc);
            }
            0x10 => {
                let subfunction = (opcode >> 21) & 0x1F;
                match subfunction {
                    0x00 => {
                        self.mfc0(builder, opcode, current_pc);
                    }
                    _ => {
                        error!("Unhandled EE JIT COP0 opcode: 0x{:08X} (Subfunction 0x{:02X}), PC: 0x{:08X}", opcode, subfunction, current_pc);
                        panic!();
                    }
                }
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
}

impl EmulationBackend<EE> for JIT<'_> {
    fn step(&mut self) {
        if self.execute(true) {
            return
        }
    }

    fn run(&mut self) {
        loop {
            if self.execute(false) {
                break
            }
        }
    }
}