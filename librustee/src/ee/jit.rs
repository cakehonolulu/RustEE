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
use std::num::{NonZero, NonZeroU128};
use std::sync::{Arc, Mutex};
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
    fpr_ptr: *mut u32,
    hi_ptr: *mut u128,
    lo_ptr: *mut u128,
    pc_ptr: *mut u32,
    cycles: usize,
    break_func: FuncId,
    bus_write8_func: FuncId,
    bus_write32_func: FuncId,
    bus_write64_func: FuncId,
    bus_read8_func: FuncId,
    bus_read32_func: FuncId,
    bus_read64_func: FuncId,
    tlbwi_func: FuncId,
    read_cop0_func: FuncId,
    write_cop0_func: FuncId,
}

pub enum BranchTarget {
    Const(u32),
    Reg(Value),
}

enum BranchInfo {
    Conditional {
        cond: Value,
        target: BranchTarget,
    },
    Unconditional {
        target: BranchTarget,
    },
    ConditionalLikely {
        cond: Value,
        target: BranchTarget,
    },
}

const MAX_BLOCKS: NonZero<usize> = NonZero::new(128).unwrap();

#[unsafe(no_mangle)]
pub extern "C" fn __break(cpu_ptr: *mut EE) {
    unsafe {
        let cpu = &mut *cpu_ptr;
        panic!("MIPS BREAK instruction executed at 0x{:08X}", cpu.pc());
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn __read_cop0(cpu_ptr: *mut EE, index: u32) -> u32 {
    unsafe {
        let cpu = &mut *cpu_ptr;
        cpu.read_cop0_register(index as usize)
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn __write_cop0(cpu_ptr: *mut EE, index: u32, value: u32) {
    unsafe {
        let cpu = &mut *cpu_ptr;
        cpu.write_cop0_register(index as usize, value)
    }
}

pub extern "C" fn __bus_write8(bus_ptr: *mut Bus, addr: u32, value: u8) {
    unsafe {
        let bus = &mut *bus_ptr;
        (bus.write8)(bus, addr, value);
    }
}

pub extern "C" fn __bus_write32(bus_ptr: *mut Bus, addr: u32, value: u32) {
    unsafe {
        let bus = &mut *bus_ptr;
        (bus.write32)(bus, addr, value);
    }
}

pub extern "C" fn __bus_write64(bus_ptr: *mut Bus, addr: u32, value: u64) {
    unsafe {
        let bus = &mut *bus_ptr;
        (bus.write64)(bus, addr, value);
    }
}

pub extern "C" fn __bus_read8(bus_ptr: *mut Bus, addr: u32) -> u8 {
    unsafe {
        let bus = &mut *bus_ptr;
        (bus.read8)(bus, addr)
    }
}

pub extern "C" fn __bus_read32(bus_ptr: *mut Bus, addr: u32) -> u32 {
    unsafe {
        let bus = &mut *bus_ptr;
        (bus.read32)(bus, addr)
    }
}

pub extern "C" fn __bus_read64(bus_ptr: *mut Bus, addr: u32) -> u64 {
    unsafe {
        let bus = &mut *bus_ptr;
        (bus.read64)(bus, addr)
    }
}

pub extern "C" fn __bus_tlbwi(bus_ptr: *mut Bus) {
    unsafe {
        let bus = &mut *bus_ptr;
        let mut tlb_ref = bus.tlb.borrow_mut();
      

        let index = ((bus.read_cop0_register(0)) & 0x3F) as usize;

        let entry_hi  = bus.read_cop0_register(10); // EntryHi
        let entry_lo0 = bus.read_cop0_register(2); // EntryLo0
        let entry_lo1 = bus.read_cop0_register(3); // EntryLo1
        let page_mask = bus.read_cop0_register(5); // PageMask

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
}

impl<'a> JIT<'a> {
    pub fn new(cpu: &'a mut EE) -> Self {

        let mut builder = JITBuilder::new(
            cranelift_module::default_libcall_names()
        ).expect("Failed to create JITBuilder");

        builder.symbol(
            "__break",
            __bus_tlbwi as *const u8,
        );

        builder.symbol(
            "__bus_write8",
            __bus_write8 as *const u8,
        );

        builder.symbol(
            "__bus_write32",
            __bus_write32 as *const u8,
        );

        builder.symbol(
            "__bus_write64",
            __bus_write64 as *const u8,
        );

        builder.symbol(
            "__bus_read8",
            __bus_read8 as *const u8,
        );

        builder.symbol(
            "__bus_read32",
            __bus_read32 as *const u8,
        );

        builder.symbol(
            "__bus_read64",
            __bus_read64 as *const u8,
        );

        builder.symbol(
            "__bus_tlbwi",
            __bus_tlbwi as *const u8,
        );

        builder.symbol("__read_cop0", __read_cop0 as *const u8);

        builder.symbol("__write_cop0", __write_cop0 as *const u8);

        let mut module = JITModule::new(builder);
        let gpr_ptr = cpu.registers.as_mut_ptr();
        let fpr_ptr = cpu.fpu_registers.as_mut_ptr();
        let hi_ptr = &mut cpu.hi as *mut u128;
        let lo_ptr = &mut cpu.lo as *mut u128;
        let pc_ptr = &mut cpu.pc as *mut u32;

        let mut store8_sig = module.make_signature();
        store8_sig.params.push(AbiParam::new(types::I64)); // bus_ptr
        store8_sig.params.push(AbiParam::new(types::I32)); // addr
        store8_sig.params.push(AbiParam::new(types::I8));  // value
        let bus_write8_func = module
            .declare_function("__bus_write8", Linkage::Import, &store8_sig)
            .expect("Failed to declare __bus_write8");

        let mut store32_sig = module.make_signature();
        store32_sig.params.push(AbiParam::new(types::I64));
        store32_sig.params.push(AbiParam::new(types::I32));
        store32_sig.params.push(AbiParam::new(types::I32));
        let bus_write32_func: FuncId = module
            .declare_function("__bus_write32", Linkage::Import, &store32_sig)
            .expect("Failed to declare __bus_write32 function!");

        let mut store64_sig = module.make_signature();
        store64_sig.params.push(AbiParam::new(types::I64));
        store64_sig.params.push(AbiParam::new(types::I32));
        store64_sig.params.push(AbiParam::new(types::I64));
        let bus_write64_func: FuncId = module
            .declare_function("__bus_write64", Linkage::Import, &store64_sig)
            .expect("Failed to declare __bus_write32 function!");

        let mut load8_sig = module.make_signature();
        load8_sig.params.push(AbiParam::new(types::I64));
        load8_sig.params.push(AbiParam::new(types::I32));
        load8_sig.returns.push(AbiParam::new(types::I8));
        let bus_read8_func = module
            .declare_function("__bus_read8", Linkage::Import, &load8_sig)
            .expect("Failed to declare __bus_read8");

        let mut load32_sig = module.make_signature();
        load32_sig.params.push(AbiParam::new(types::I64));
        load32_sig.params.push(AbiParam::new(types::I32));
        load32_sig.returns.push(AbiParam::new(types::I32));
        let bus_read32_func = module
            .declare_function("__bus_read32", Linkage::Import, &load32_sig)
            .expect("Failed to declare __bus_read32");

        let mut load64_sig = module.make_signature();
        load64_sig.params.push(AbiParam::new(types::I64));
        load64_sig.params.push(AbiParam::new(types::I32));
        load64_sig.returns.push(AbiParam::new(types::I64));
        let bus_read64_func = module
            .declare_function("__bus_read64", Linkage::Import, &load64_sig)
            .expect("Failed to declare __bus_read64");

        let mut tlbwi_sig = module.make_signature();
        // Parameter: i64 (raw *mut Bus)
        tlbwi_sig.params.push(AbiParam::new(types::I64));
        // Return i32 (unused)
        tlbwi_sig.returns.push(AbiParam::new(types::I32));
        let tlbwi_func: FuncId = module
            .declare_function("__bus_tlbwi", Linkage::Import, &tlbwi_sig)
            .expect("Failed to declare __bus_tlbwi!");

        let mut read_cop0_sig = module.make_signature();
        read_cop0_sig.params.push(AbiParam::new(types::I64)); // cpu_ptr
        read_cop0_sig.params.push(AbiParam::new(types::I32)); // index
        read_cop0_sig.returns.push(AbiParam::new(types::I32));
        let read_cop0_func = module
            .declare_function("__read_cop0", Linkage::Import, &read_cop0_sig)
            .expect("Failed to declare __read_cop0");

        let mut write_cop0_sig = module.make_signature();
        write_cop0_sig.params.push(AbiParam::new(types::I64)); // cpu_ptr
        write_cop0_sig.params.push(AbiParam::new(types::I32)); // index
        write_cop0_sig.params.push(AbiParam::new(types::I32)); // value
        let write_cop0_func = module
            .declare_function("__write_cop0", Linkage::Import, &write_cop0_sig)
            .expect("Failed to declare __write_cop0");

        let mut break_sig = module.make_signature();
        break_sig.params.push(AbiParam::new(types::I64)); // cpu_ptr
        let break_func = module
            .declare_function("__break", Linkage::Import, &break_sig)
            .expect("Failed to declare __break");

        JIT {
            cpu,
            module,
            blocks: LruCache::new(MAX_BLOCKS),
            max_blocks: MAX_BLOCKS.into(),
            gpr_ptr,
            fpr_ptr,
            hi_ptr,
            lo_ptr,
            pc_ptr,
            cycles: 0,
            break_func,
            bus_write8_func,
            bus_write32_func,
            bus_write64_func,
            bus_read8_func,
            bus_read32_func,
            bus_read64_func,
            tlbwi_func,
            read_cop0_func,
            write_cop0_func
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

            let branch_info = self.decode(&mut builder, opcode, &mut current_pc);
            if let Some(info) = branch_info {
                match info {
                    BranchInfo::Conditional { cond, target } => {
                        let delay_opcode = self.cpu.fetch_at(current_pc);
                        self.decode(&mut builder, delay_opcode, &mut current_pc);
                        let branch_blk = builder.create_block();
                        let fallthrough_blk = builder.create_block();
                        builder.ins().brif(cond, branch_blk, &[], fallthrough_blk, &[]);
                        builder.seal_block(branch_blk);
                        builder.seal_block(fallthrough_blk);
                        builder.switch_to_block(branch_blk);
                        JIT::set_pc_to_target(&mut builder, target, pc_addr);
                        builder.ins().return_(&[]);
                        builder.switch_to_block(fallthrough_blk);
                        JIT::set_pc_to_const(&mut builder, current_pc, pc_addr);
                    }
                    BranchInfo::Unconditional { target } => {
                        let delay_opcode = self.cpu.fetch_at(current_pc);
                        self.decode(&mut builder, delay_opcode, &mut current_pc);
                        JIT::set_pc_to_target(&mut builder, target, pc_addr);
                    }
                    BranchInfo::ConditionalLikely { cond, target } => {
                        let delay_pc = current_pc;
                        current_pc = delay_pc.wrapping_add(4);
                        let taken_blk = builder.create_block();
                        let not_taken_blk = builder.create_block();
                        builder.ins().brif(cond, taken_blk, &[], not_taken_blk, &[]);
                        builder.seal_block(taken_blk);
                        builder.switch_to_block(taken_blk);
                        let delay_opcode = self.cpu.fetch_at(delay_pc);
                        self.decode(&mut builder, delay_opcode, &mut current_pc);
                        JIT::set_pc_to_target(&mut builder, target, pc_addr);
                        builder.ins().return_(&[]);
                        builder.seal_block(not_taken_blk);
                        builder.switch_to_block(not_taken_blk);
                        let next_pc = delay_pc.wrapping_add(4);
                        JIT::set_pc_to_const(&mut builder, next_pc, pc_addr);
                    }
                }
                break;
            } else if single_step {
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

    pub fn set_pc_to_target(builder: &mut FunctionBuilder, target: BranchTarget, pc_addr: Value) {
        match target {
            BranchTarget::Const(addr) => {
                let t = builder.ins().iconst(types::I32, addr as i64);
                builder.ins().store(MemFlags::new(), t, pc_addr, 0);
            }
            BranchTarget::Reg(val) => {
                let t32 = builder.ins().ireduce(types::I32, val);
                builder.ins().store(MemFlags::new(), t32, pc_addr, 0);
            }
        }
    }

    pub fn set_pc_to_const(builder: &mut FunctionBuilder, addr: u32, pc_addr: Value) {
        let t = builder.ins().iconst(types::I32, addr as i64);
        builder.ins().store(MemFlags::new(), t, pc_addr, 0);
    }

    pub fn mark_block_dirty(&mut self, pc: u32) {
        if let Some(block) = self.blocks.get_mut(&pc) {
            block.dirty = true;
            println!("Marked block at PC 0x{:08X} as dirty.", pc);
        }
    }

    fn decode(&mut self, builder: &mut FunctionBuilder, opcode: u32, current_pc: &mut u32) -> Option<BranchInfo> {
        let function = opcode >> 26;
        //debug!("decode: function: 0x{:02X}", function);
        match function {
            0x00 => {
                let subfunction = opcode & 0x3F;
                match subfunction {
                    0x00 => {
                        self.sll(builder, opcode, current_pc)
                    }
                    0x03 => {
                        self.sra(builder, opcode, current_pc)
                    }
                    0x08 => {
                        self.jr(builder, opcode, current_pc)
                    }
                    0x09 => {
                        self.jalr(builder, opcode, current_pc)
                    }
                    0x0D => {
                        self.break_(builder, opcode, current_pc)
                    }
                    0x0F => {
                        self.sync(builder, opcode, current_pc)
                    }
                    0x12 => {
                        self.mflo(builder, opcode, current_pc)
                    }
                    0x18 => {
                        self.mult(builder, opcode, current_pc)
                    }
                    0x1A => {
                        self.div(builder, opcode, current_pc)
                    }
                    0x1B => {
                        self.divu(builder, opcode, current_pc)
                    }
                    0x21 => {
                        self.addu(builder, opcode, current_pc)
                    }
                    0x25 => {
                        self.or(builder, opcode, current_pc)
                    }
                    0x2D => {
                        self.daddu(builder, opcode, current_pc)
                    }
                    _ => {
                        error!("Unhandled EE JIT function SPECIAL opcode: 0x{:08X} (Subfunction 0x{:02X}), PC: 0x{:08X}", opcode, subfunction, current_pc);
                        panic!();
                    }
                }
            }
            0x01 => {
                self.bgez(builder, opcode, current_pc)
            }
            0x02 => {
                self.j(builder, opcode, current_pc)
            }
            0x03 => {
                self.jal(builder, opcode, current_pc)
            }
            0x04 => {
                self.beq(builder, opcode, current_pc)
            }
            0x05 => {
                self.bne(builder, opcode, current_pc)
            }
            0x09 => {
                self.addiu(builder, opcode, current_pc)
            }
            0x0A => {
                self.slti(builder, opcode, current_pc)
            }
            0x0B => {
                self.sltiu(builder, opcode, current_pc)
            }
            0x0C => {
                self.andi(builder, opcode, current_pc)
            }
            0x0D => {
                self.ori(builder, opcode, current_pc)
            }
            0x0F => {
                self.lui(builder, opcode, current_pc)
            }
            0x10 => {
                let subfunction = (opcode >> 21) & 0x1F;
                match subfunction {
                    0x00 => {
                        self.mfc0(builder, opcode, current_pc)
                    }
                    0x04 => {
                        self.mtc0(builder, opcode, current_pc)
                    }
                    0x10 => {
                        self.tlbwi(builder, current_pc)
                    }
                    _ => {
                        error!("Unhandled EE JIT COP0 opcode: 0x{:08X} (Subfunction 0x{:02X}), PC: 0x{:08X}", opcode, subfunction, current_pc);
                        panic!();
                    }
                }
            }
            0x14 => {
                self.beql(builder, opcode, current_pc)
            }
            0x15 => {
                self.bnel(builder, opcode, current_pc)
            }
            0x20 => {
                self.lb(builder, opcode, current_pc)
            }
            0x23 => {
                self.lw(builder, opcode, current_pc)
            }
            0x24 => {
                self.lbu(builder, opcode, current_pc)
            }
            0x28 => {
                self.sb(builder, opcode, current_pc)
            }
            0x2B => {
                self.sw(builder, opcode, current_pc)
            }
            0x39 => {
                self.swc1(builder, opcode, current_pc)
            }
            0x37 => {
                self.ld(builder, opcode, current_pc)
            }
            0x3F => {
                self.sd(builder, opcode, current_pc)
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
    fn load8(builder: &mut FunctionBuilder, addr: Value) -> Value {
        builder.ins().load(types::I8, MemFlags::new(), addr, 0)
    }

    #[inline(always)]
    fn load32(builder: &mut FunctionBuilder, addr: Value) -> Value {
        builder.ins().load(types::I32, MemFlags::new(), addr, 0)
    }

    #[inline(always)]
    fn load64(builder: &mut FunctionBuilder, addr: Value) -> Value {
        builder.ins().load(types::I64, MemFlags::new(), addr, 0)
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

    fn mfc0(&mut self, builder: &mut FunctionBuilder, opcode: u32, current_pc: &mut u32) -> Option<BranchInfo> {
        let rt = ((opcode >> 16) & 0x1F) as i64;
        let rd = ((opcode >> 11) & 0x1F) as i64;

        let gpr_addr = Self::ptr_add(builder, self.gpr_ptr as i64, rt, 16);

        // Prepare arguments
        let cpu_ptr = self.cpu as *mut EE as i64;
        let cpu_arg = builder.ins().iconst(types::I64, cpu_ptr);
        let rd_arg = builder.ins().iconst(types::I32, rd);

        // Call __read_cop0
        let callee = self.module.declare_func_in_func(self.read_cop0_func, builder.func);
        let call = builder.ins().call(callee, &[cpu_arg, rd_arg]);
        let cop0_val = builder.inst_results(call)[0];

        builder.ins().store(MemFlags::new(), cop0_val, gpr_addr, 0);

        Self::increment_pc(builder, self.pc_ptr as i64);
        *current_pc = current_pc.wrapping_add(4);
        None
    }

    fn sll(&mut self, builder: &mut FunctionBuilder, opcode: u32, current_pc: &mut u32) -> Option<BranchInfo> {
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
        None
    }

    fn slti(&mut self, builder: &mut FunctionBuilder, opcode: u32, current_pc: &mut u32) -> Option<BranchInfo> {
        let rs = ((opcode >> 21) & 0x1F) as i64;
        let rt = ((opcode >> 16) & 0x1F) as i64;
        let imm = (opcode as i16) as i64;

        let rs_a = Self::ptr_add(builder, self.gpr_ptr as i64, rs, 16);
        let rt_a = Self::ptr_add(builder, self.gpr_ptr as i64, rt, 16);

        let rs_val32 = builder.ins().load(types::I32, MemFlags::new(), rs_a, 0);
        let rs_val = builder.ins().sextend(types::I64, rs_val32);
        let imm_val = builder.ins().iconst(types::I64, imm);
        let cmp = builder.ins().icmp(IntCC::SignedLessThan, rs_val, imm_val);
        let one = builder.ins().iconst(types::I64, 1);
        let zero = builder.ins().iconst(types::I64, 0);
        let result = builder.ins().select(cmp, one, zero);
        builder.ins().store(MemFlags::new(), result, rt_a, 0);

        Self::increment_pc(builder, self.pc_ptr as i64);
        *current_pc = current_pc.wrapping_add(4);
        None
    }

    fn lui(&mut self, builder: &mut FunctionBuilder, opcode: u32, current_pc: &mut u32) -> Option<BranchInfo> {
        let rt = ((opcode >> 16) & 0x1F) as i64;
        let imm = (opcode & 0xFFFF) as i64;

        let rt_addr = Self::ptr_add(builder, self.gpr_ptr as i64, rt, 16);
        let imm_val = builder.ins().iconst(types::I64, imm << 16);
        builder.ins().store(MemFlags::new(), imm_val, rt_addr, 0);

        Self::increment_pc(builder, self.pc_ptr as i64);
        *current_pc = current_pc.wrapping_add(4);
        None
    }

    fn ori(&mut self, builder: &mut FunctionBuilder, opcode: u32, current_pc: &mut u32) -> Option<BranchInfo> {
        let rs = ((opcode >> 21) & 0x1F) as i64;
        let rt = ((opcode >> 16) & 0x1F) as i64;
        let imm = (opcode & 0xFFFF) as i64;

        let rs_addr = Self::ptr_add(builder, self.gpr_ptr as i64, rs, 16);
        let rt_addr = Self::ptr_add(builder, self.gpr_ptr as i64, rt, 16);

        let rs_val = builder.ins().load(types::I32, MemFlags::new(), rs_addr, 0);
        let imm_val = builder.ins().iconst(types::I32, imm);
        let result = builder.ins().bor(rs_val, imm_val);
        builder.ins().store(MemFlags::new(), result, rt_addr, 0);

        Self::increment_pc(builder, self.pc_ptr as i64);
        *current_pc = current_pc.wrapping_add(4);
        None
    }

    fn mtc0(&mut self, builder: &mut FunctionBuilder, opcode: u32, current_pc: &mut u32) -> Option<BranchInfo> {
        let rt = ((opcode >> 16) & 0x1F) as i64;
        let rd = ((opcode >> 11) & 0x1F) as i64;

        let gpr_addr = Self::ptr_add(builder, self.gpr_ptr as i64, rt, 16);

        // Prepare arguments
        let cpu_ptr = self.cpu as *mut EE as i64;
        let cpu_arg = builder.ins().iconst(types::I64, cpu_ptr);
        let rd_arg = builder.ins().iconst(types::I32, rd);
        let gpr_val = Self::load32(builder, gpr_addr);

        let callee = self.module.declare_func_in_func(self.write_cop0_func, builder.func);
        builder.ins().call(callee, &[cpu_arg, rd_arg, gpr_val]);

        Self::increment_pc(builder, self.pc_ptr as i64);
        *current_pc = current_pc.wrapping_add(4);
        None
    }

    fn sync(&mut self, builder: &mut FunctionBuilder, _opcode: u32, current_pc: &mut u32) -> Option<BranchInfo> {
        // TODO: Implement SYNC instruction properly
        Self::increment_pc(builder, self.pc_ptr as i64);
        *current_pc = current_pc.wrapping_add(4);
        None
    }

    fn addiu(&mut self, builder: &mut FunctionBuilder, opcode: u32, current_pc: &mut u32) -> Option<BranchInfo> {
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
        None
    }

    fn sw(&mut self, builder: &mut FunctionBuilder, opcode: u32, current_pc: &mut u32) -> Option<BranchInfo> {
        let base = ((opcode >> 21) & 0x1F) as i64;
        let rt   = ((opcode >> 16) & 0x1F) as i64;
        let imm  = ((opcode as i16) as i64) as i64;
        let base_addr = Self::ptr_add(builder, self.gpr_ptr as i64, base, 16);
        let base_val  = Self::load32(builder, base_addr);
        let addr = builder.ins().iadd_imm(base_val, imm);
        let rt_addr = Self::ptr_add(builder, self.gpr_ptr as i64, rt, 16);
        let store_val = Self::load32(builder, rt_addr);

        let bus_lock = self.cpu.bus.lock().unwrap();
        let bus_ptr: *mut Bus = &*bus_lock as *const Bus as *mut Bus;
        let bus_value = builder.ins().iconst(types::I64, bus_ptr as i64);
        let addr_arg = addr;
        let val_arg  = store_val;

        let callee = self.module.declare_func_in_func(self.bus_write32_func, builder.func);
        builder.ins().call(callee, &[bus_value, addr_arg, val_arg]);

        Self::increment_pc(builder, self.pc_ptr as i64);
        *current_pc = current_pc.wrapping_add(4);
        None
    }

    fn tlbwi(&mut self, builder: &mut FunctionBuilder, current_pc: &mut u32) -> Option<BranchInfo> {
        let bus_lock = self.cpu.bus.lock().unwrap();
        let bus_ptr: *mut Bus = &*bus_lock as *const Bus as *mut Bus;
        let bus_value = builder.ins().iconst(types::I64, bus_ptr as i64);

        let local_callee = self.module.declare_func_in_func(self.tlbwi_func, builder.func);

        builder.ins().call(local_callee, &[bus_value]);

        Self::increment_pc(builder, self.pc_ptr as i64);
        *current_pc = current_pc.wrapping_add(4);
        None
    }

    fn lw(&mut self, builder: &mut FunctionBuilder, opcode: u32, current_pc: &mut u32) -> Option<BranchInfo> {
        let base_idx = ((opcode >> 21) & 0x1F) as usize;
        let rt_idx   = ((opcode >> 16) & 0x1F) as usize;
        let imm_i64  = (opcode as i16) as i64;

        let base = base_idx as i64;
        let rt   = rt_idx as i64;

        let base_addr = Self::ptr_add(builder, self.gpr_ptr as i64, base, 16);
        let base_val  = Self::load32(builder, base_addr);

        let addr = builder.ins().iadd_imm(base_val, imm_i64);

        let bus_lock = self.cpu.bus.lock().unwrap();
        let bus_ptr: *mut Bus = &*bus_lock as *const Bus as *mut Bus;
        let bus_value = builder.ins().iconst(types::I64, bus_ptr as i64);
        let bus_read_callee =
            self.module.declare_func_in_func(self.bus_read32_func, builder.func);
        let call_inst = builder.ins().call(bus_read_callee, &[bus_value, addr]);
        let load_val = builder.inst_results(call_inst)[0];

        let rt_addr = Self::ptr_add(builder, self.gpr_ptr as i64, rt, 16);
        builder.ins().store(MemFlags::new(), load_val, rt_addr, 0);

        Self::increment_pc(builder, self.pc_ptr as i64);
        *current_pc = current_pc.wrapping_add(4);
        None
    }

    fn bne(&mut self, builder: &mut FunctionBuilder, opcode: u32, current_pc: &mut u32) -> Option<BranchInfo> {
        let rs = ((opcode >> 21) & 0x1F) as i64;
        let rt = ((opcode >> 16) & 0x1F) as i64;
        let imm = (opcode as u16) as i16 as i32;
        let raddr = Self::ptr_add(builder, self.gpr_ptr as i64, rs, 16);
        let taddr = Self::ptr_add(builder, self.gpr_ptr as i64, rt, 16);
        let rv = builder.ins().load(types::I32, MemFlags::new(), raddr, 0);
        let tv = builder.ins().load(types::I32, MemFlags::new(), taddr, 0);
        let cond = builder.ins().icmp(IntCC::NotEqual, rv, tv);
        let target_addr = current_pc.wrapping_add(4).wrapping_add((imm << 2) as u32);
        *current_pc = current_pc.wrapping_add(4);
        Some(BranchInfo::Conditional {
            cond,
            target: BranchTarget::Const(target_addr),
        })
    }

    fn jr(&mut self, builder: &mut FunctionBuilder, opcode: u32, current_pc: &mut u32) -> Option<BranchInfo> {
        let rs = ((opcode >> 21) & 0x1F) as i64;
        let addr = Self::ptr_add(builder, self.gpr_ptr as i64, rs, 16);
        let target_i32 = builder.ins().load(types::I32, MemFlags::new(), addr, 0);
        let target = builder.ins().uextend(types::I64, target_i32);
        *current_pc = current_pc.wrapping_add(4);
        Some(BranchInfo::Unconditional {
            target: BranchTarget::Reg(target),
        })
    }

    fn jalr(&mut self, builder: &mut FunctionBuilder, opcode: u32, current_pc: &mut u32) -> Option<BranchInfo> {
        let rs = ((opcode >> 21) & 0x1F) as i64;
        let rd = ((opcode >> 11) & 0x1F) as i64;

        let rs_addr = Self::ptr_add(builder, self.gpr_ptr as i64, rs, 16);
        let rd_addr = Self::ptr_add(builder, self.gpr_ptr as i64, rd, 16);

        // The return address is the instruction after the delay slot
        let return_addr = current_pc.wrapping_add(8);
        let ret_val = builder.ins().iconst(types::I64, return_addr as i64);
        builder.ins().store(MemFlags::new(), ret_val, rd_addr, 0);

        let target_i32 = builder.ins().load(types::I32, MemFlags::new(), rs_addr, 0);
        let target = builder.ins().uextend(types::I64, target_i32);

        *current_pc = current_pc.wrapping_add(4);

        Some(BranchInfo::Unconditional {
            target: BranchTarget::Reg(target),
        })
    }

    fn sd(&mut self, builder: &mut FunctionBuilder, opcode: u32, current_pc: &mut u32) -> Option<BranchInfo> {
        let base = ((opcode >> 21) & 0x1F) as i64;
        let rt   = ((opcode >> 16) & 0x1F) as i64;
        let imm  = (opcode as i16) as i64;

        let base_addr = Self::ptr_add(builder, self.gpr_ptr as i64, base, 16);
        let base_val  = Self::load64(builder, base_addr);

        let addr = builder.ins().iadd_imm(base_val, imm);

        let addr32 = builder.ins().ireduce(types::I32, addr);

        let rt_addr   = Self::ptr_add(builder, self.gpr_ptr as i64, rt, 16);
        let store_val = builder.ins().load(types::I64, MemFlags::new(), rt_addr, 0);

        let bus_lock = self.cpu.bus.lock().unwrap();
        let bus_ptr: *mut Bus = &*bus_lock as *const Bus as *mut Bus;
        let bus_value = builder.ins().iconst(types::I64, bus_ptr as i64);

        let callee = self
            .module
            .declare_func_in_func(self.bus_write64_func, builder.func);
        builder.ins().call(callee, &[bus_value, addr32, store_val]);

        Self::increment_pc(builder, self.pc_ptr as i64);
        *current_pc = current_pc.wrapping_add(4);
        None
    }

    fn daddu(&mut self, builder: &mut FunctionBuilder, opcode: u32, current_pc: &mut u32) -> Option<BranchInfo> {
        let rs = ((opcode >> 21) & 0x1F) as i64;
        let rt = ((opcode >> 16) & 0x1F) as i64;
        let rd = ((opcode >> 11) & 0x1F) as i64;

        let rs_addr = Self::ptr_add(builder, self.gpr_ptr as i64, rs, 16);
        let rt_addr = Self::ptr_add(builder, self.gpr_ptr as i64, rt, 16);
        let rd_addr = Self::ptr_add(builder, self.gpr_ptr as i64, rd, 16);

        let rs_val = builder.ins().load(types::I64, MemFlags::new(), rs_addr, 0);
        let rt_val = builder.ins().load(types::I64, MemFlags::new(), rt_addr, 0);
        let result = builder.ins().iadd(rs_val, rt_val);
        builder.ins().store(MemFlags::new(), result, rd_addr, 0);

        Self::increment_pc(builder, self.pc_ptr as i64);
        *current_pc = current_pc.wrapping_add(4);
        None
    }

    fn jal(&mut self, builder: &mut FunctionBuilder, opcode: u32, current_pc: &mut u32) -> Option<BranchInfo> {
        let instr_index = opcode & 0x03FFFFFF;
        let target = (*current_pc).wrapping_add(4) & 0xF0000000 | (instr_index << 2);
        
        let ra_addr = Self::ptr_add(builder, self.gpr_ptr as i64, 31, 16);
        let return_addr = (*current_pc).wrapping_add(8);
        let ret_val = builder.ins().iconst(types::I64, return_addr as i64);
        builder.ins().store(MemFlags::new(), ret_val, ra_addr, 0);
        
        *current_pc = current_pc.wrapping_add(4);
        
        Some(BranchInfo::Unconditional {
            target: BranchTarget::Const(target),
        })
    }

    fn andi(&mut self, builder: &mut FunctionBuilder, opcode: u32, current_pc: &mut u32) -> Option<BranchInfo> {
        let rs = ((opcode >> 21) & 0x1F) as i64;
        let rt = ((opcode >> 16) & 0x1F) as i64;
        let imm = (opcode & 0xFFFF) as i64;

        let rs_addr = Self::ptr_add(builder, self.gpr_ptr as i64, rs, 16);
        let rt_addr = Self::ptr_add(builder, self.gpr_ptr as i64, rt, 16);

        let rs_val = builder.ins().load(types::I64, MemFlags::new(), rs_addr, 0);
        let imm_val = builder.ins().iconst(types::I64, imm);
        let result = builder.ins().band(rs_val, imm_val);
        builder.ins().store(MemFlags::new(), result, rt_addr, 0);

        Self::increment_pc(builder, self.pc_ptr as i64);
        *current_pc = current_pc.wrapping_add(4);
        None
    }

    fn beq(&mut self, builder: &mut FunctionBuilder, opcode: u32, current_pc: &mut u32) -> Option<BranchInfo> {
        let rs = ((opcode >> 21) & 0x1F) as i64;
        let rt = ((opcode >> 16) & 0x1F) as i64;
        let imm = (opcode as u16) as i16 as i32;

        let rs_addr = Self::ptr_add(builder, self.gpr_ptr as i64, rs, 16);
        let rt_addr = Self::ptr_add(builder, self.gpr_ptr as i64, rt, 16);

        let rs_val = builder.ins().load(types::I32, MemFlags::new(), rs_addr, 0);
        let rt_val = builder.ins().load(types::I32, MemFlags::new(), rt_addr, 0);

        let cond = builder.ins().icmp(IntCC::Equal, rs_val, rt_val);

        let target = current_pc.wrapping_add(4).wrapping_add((imm << 2) as u32);
        *current_pc = current_pc.wrapping_add(4);

        Some(BranchInfo::Conditional {
            cond,
            target: BranchTarget::Const(target),
        })
    }

    fn or(&mut self, builder: &mut FunctionBuilder, opcode: u32, current_pc: &mut u32) -> Option<BranchInfo> {
        let rs = ((opcode >> 21) & 0x1F) as i64;
        let rt = ((opcode >> 16) & 0x1F) as i64;
        let rd = ((opcode >> 11) & 0x1F) as i64;

        let rs_addr = Self::ptr_add(builder, self.gpr_ptr as i64, rs, 16);
        let rt_addr = Self::ptr_add(builder, self.gpr_ptr as i64, rt, 16);
        let rd_addr = Self::ptr_add(builder, self.gpr_ptr as i64, rd, 16);

        let rs_val = builder.ins().load(types::I64, MemFlags::new(), rs_addr, 0);
        let rt_val = builder.ins().load(types::I64, MemFlags::new(), rt_addr, 0);
        let result = builder.ins().bor(rs_val, rt_val);
        builder.ins().store(MemFlags::new(), result, rd_addr, 0);

        Self::increment_pc(builder, self.pc_ptr as i64);
        *current_pc = current_pc.wrapping_add(4);
        None
    }

    fn mult(&mut self, builder: &mut FunctionBuilder, opcode: u32, current_pc: &mut u32) -> Option<BranchInfo> {
        let rs = ((opcode >> 21) & 0x1F) as i64;
        let rt = ((opcode >> 16) & 0x1F) as i64;
        let rd = ((opcode >> 11) & 0x1F) as i64;

        let rs_addr = Self::ptr_add(builder, self.gpr_ptr as i64, rs, 16);
        let rt_addr = Self::ptr_add(builder, self.gpr_ptr as i64, rt, 16);
        let rd_addr = Self::ptr_add(builder, self.gpr_ptr as i64, rd, 16);

        let rs_val32 = builder.ins().load(types::I32, MemFlags::new(), rs_addr, 0);
        let rt_val32 = builder.ins().load(types::I32, MemFlags::new(), rt_addr, 0);
        let rs_val64 = builder.ins().sextend(types::I64, rs_val32);
        let rt_val64 = builder.ins().sextend(types::I64, rt_val32);

        let prod = builder.ins().imul(rs_val64, rt_val64);

        let lo32  = builder.ins().ireduce(types::I32, prod);
        let lo64  = builder.ins().uextend(types::I64, lo32);
        let lo128 = builder.ins().uextend(types::I128, lo32);

        let hi_shift = builder.ins().ushr_imm(prod, 32);
        let hi32     = builder.ins().ireduce(types::I32, hi_shift);
        let hi128    = builder.ins().uextend(types::I128, hi32);

        let lo_addr = Self::ptr_add(builder, self.lo_ptr as i64, 0, 16);
        let hi_addr = Self::ptr_add(builder, self.hi_ptr as i64, 0, 16);
        builder.ins().store(MemFlags::new(), lo128, lo_addr, 0);
        builder.ins().store(MemFlags::new(), hi128, hi_addr, 0);

        if rd != 0 {
            builder.ins().store(MemFlags::new(), lo64, rd_addr, 0);
        }

        Self::increment_pc(builder, self.pc_ptr as i64);
        *current_pc = current_pc.wrapping_add(4);

        None
    }

    fn divu(&mut self, builder: &mut FunctionBuilder, opcode: u32, current_pc: &mut u32) -> Option<BranchInfo> {
        let rs = ((opcode >> 21) & 0x1F) as i64;
        let rt = ((opcode >> 16) & 0x1F) as i64;

        let rs_addr = Self::ptr_add(builder, self.gpr_ptr as i64, rs, 16);
        let rt_addr = Self::ptr_add(builder, self.gpr_ptr as i64, rt, 16);

        let dividend32 = builder.ins().load(types::I32, MemFlags::new(), rs_addr, 0);
        let divisor32  = builder.ins().load(types::I32, MemFlags::new(), rt_addr, 0);

        let dividend = builder.ins().uextend(types::I64, dividend32);
        let divisor  = builder.ins().uextend(types::I64, divisor32);

        let quot64 = builder.ins().udiv(dividend, divisor);
        let rem64  = builder.ins().urem(dividend, divisor);

        let quot32 = builder.ins().ireduce(types::I32, quot64);
        let rem32  = builder.ins().ireduce(types::I32, rem64);
        let lo128  = builder.ins().uextend(types::I128, quot32);
        let hi128  = builder.ins().uextend(types::I128, rem32);

        let lo_addr = Self::ptr_add(builder, self.lo_ptr as i64, 0, 16);
        let hi_addr = Self::ptr_add(builder, self.hi_ptr as i64, 0, 16);
        builder.ins().store(MemFlags::new(), lo128, lo_addr, 0);
        builder.ins().store(MemFlags::new(), hi128, hi_addr, 0);

        Self::increment_pc(builder, self.pc_ptr as i64);
        *current_pc = current_pc.wrapping_add(4);
        None
    }

    fn beql(&mut self, builder: &mut FunctionBuilder, opcode: u32, current_pc: &mut u32) -> Option<BranchInfo> {
        let rs = ((opcode >> 21) & 0x1F) as i64;
        let rt = ((opcode >> 16) & 0x1F) as i64;
        let imm = (opcode as u16) as i16 as i32;

        let rs_addr = Self::ptr_add(builder, self.gpr_ptr as i64, rs, 16);
        let rt_addr = Self::ptr_add(builder, self.gpr_ptr as i64, rt, 16);

        let rs_val = builder.ins().load(types::I32, MemFlags::new(), rs_addr, 0);
        let rt_val = builder.ins().load(types::I32, MemFlags::new(), rt_addr, 0);

        let cond = builder.ins().icmp(IntCC::Equal, rs_val, rt_val);

        let target = current_pc.wrapping_add(4).wrapping_add((imm << 2) as u32);
        *current_pc = current_pc.wrapping_add(4);

        Some(BranchInfo::ConditionalLikely {
            cond,
            target: BranchTarget::Const(target),
        })
    }

    fn break_(&mut self, builder: &mut FunctionBuilder, opcode: u32, current_pc: &mut u32) -> Option<BranchInfo> {
        let cpu_ptr = self.cpu as *mut EE as i64;
        let cpu_arg = builder.ins().iconst(types::I64, cpu_ptr);

        let callee = self.module.declare_func_in_func(self.break_func, builder.func);
        builder.ins().call(callee, &[cpu_arg]);

        None
    }

    fn mflo(&mut self, builder: &mut FunctionBuilder, opcode: u32, current_pc: &mut u32) -> Option<BranchInfo> {
        let rd = ((opcode >> 11) & 0x1F) as i64;

        let rd_addr = Self::ptr_add(builder, self.gpr_ptr as i64, rd, 16);

        let lo_ptr_val = builder.ins().iconst(types::I64, self.lo_ptr as i64);
        let lo_val = builder.ins().load(types::I128, MemFlags::new(), lo_ptr_val, 0);

        let lo_val_64 = builder.ins().ireduce(types::I64, lo_val);

        builder.ins().store(MemFlags::new(), lo_val_64, rd_addr, 0);

        Self::increment_pc(builder, self.pc_ptr as i64);
        *current_pc = current_pc.wrapping_add(4);

        None
    }

    fn sltiu(&mut self, builder: &mut FunctionBuilder, opcode: u32, current_pc: &mut u32) -> Option<BranchInfo> {
        let rs = ((opcode >> 21) & 0x1F) as i64;
        let rt = ((opcode >> 16) & 0x1F) as i64;
        let imm = (opcode as i16) as i64;

        let rs_addr = Self::ptr_add(builder, self.gpr_ptr as i64, rs, 16);
        let rt_addr = Self::ptr_add(builder, self.gpr_ptr as i64, rt, 16);

        let rs_val = builder.ins().load(types::I64, MemFlags::new(), rs_addr, 0);
        let imm_val = builder.ins().iconst(types::I64, imm);
        let cmp = builder.ins().icmp(IntCC::UnsignedLessThan, rs_val, imm_val);
        let one = builder.ins().iconst(types::I64, 1);
        let zero = builder.ins().iconst(types::I64, 0);
        let result = builder.ins().select(cmp, one, zero);
        builder.ins().store(MemFlags::new(), result, rt_addr, 0);

        Self::increment_pc(builder, self.pc_ptr as i64);
        *current_pc = current_pc.wrapping_add(4);
        None
    }

    fn bnel(&mut self, builder: &mut FunctionBuilder, opcode: u32, current_pc: &mut u32) -> Option<BranchInfo> {
        let rs = ((opcode >> 21) & 0x1F) as i64;
        let rt = ((opcode >> 16) & 0x1F) as i64;
        let imm = (opcode as u16) as i16 as i32;

        let rs_addr = Self::ptr_add(builder, self.gpr_ptr as i64, rs, 16);
        let rt_addr = Self::ptr_add(builder, self.gpr_ptr as i64, rt, 16);

        let rs_val = builder.ins().load(types::I32, MemFlags::new(), rs_addr, 0);
        let rt_val = builder.ins().load(types::I32, MemFlags::new(), rt_addr, 0);

        let cond = builder.ins().icmp(IntCC::NotEqual, rs_val, rt_val);

        let target = current_pc.wrapping_add(4).wrapping_add((imm << 2) as u32);
        *current_pc = current_pc.wrapping_add(4);

        Some(BranchInfo::ConditionalLikely {
            cond,
            target: BranchTarget::Const(target),
        })
    }

    fn lb(&mut self, builder: &mut FunctionBuilder, opcode: u32, current_pc: &mut u32) -> Option<BranchInfo> {
        let base_idx = ((opcode >> 21) & 0x1F) as usize;
        let rt_idx = ((opcode >> 16) & 0x1F) as usize;
        let imm_i64 = (opcode as i16) as i64;

        let base = base_idx as i64;
        let rt = rt_idx as i64;

        let base_addr = Self::ptr_add(builder, self.gpr_ptr as i64, base, 16);
        let base_val = Self::load32(builder, base_addr);

        let addr = builder.ins().iadd_imm(base_val, imm_i64);

        let bus_lock = self.cpu.bus.lock().unwrap();
        let bus_ptr: *mut Bus = &*bus_lock as *const Bus as *mut Bus;
        let bus_value = builder.ins().iconst(types::I64, bus_ptr as i64);
        let bus_read_callee = self.module.declare_func_in_func(self.bus_read8_func, builder.func);
        let call_inst = builder.ins().call(bus_read_callee, &[bus_value, addr]);
        let load_val = builder.inst_results(call_inst)[0];

        let load_val_i64 = builder.ins().sextend(types::I64, load_val);

        let rt_addr = Self::ptr_add(builder, self.gpr_ptr as i64, rt, 16);
        builder.ins().store(MemFlags::new(), load_val_i64, rt_addr, 0);

        Self::increment_pc(builder, self.pc_ptr as i64);
        *current_pc = current_pc.wrapping_add(4);
        None
    }

    fn swc1(&mut self, builder: &mut FunctionBuilder, opcode: u32, current_pc: &mut u32) -> Option<BranchInfo> {
        let base = ((opcode >> 21) & 0x1F) as i64;
        let ft = ((opcode >> 16) & 0x1F) as i64;
        let imm = (opcode as i16) as i64;

        let base_addr = Self::ptr_add(builder, self.gpr_ptr as i64, base, 16);
        let base_val = Self::load32(builder, base_addr);

        let addr = builder.ins().iadd_imm(base_val, imm);

        let ft_addr = Self::ptr_add(builder, self.fpr_ptr as i64, ft, 4);
        let fpu_val = Self::load32(builder, ft_addr);

        let bus_lock = self.cpu.bus.lock().unwrap();
        let bus_ptr: *mut Bus = &*bus_lock as *const Bus as *mut Bus;
        let bus_value = builder.ins().iconst(types::I64, bus_ptr as i64);

        let callee = self.module.declare_func_in_func(self.bus_write32_func, builder.func);
        builder.ins().call(callee, &[bus_value, addr, fpu_val]);

        Self::increment_pc(builder, self.pc_ptr as i64);
        *current_pc = current_pc.wrapping_add(4);

        None
    }

    fn lbu(&mut self, builder: &mut FunctionBuilder, opcode: u32, current_pc: &mut u32) -> Option<BranchInfo> {
        let base = ((opcode >> 21) & 0x1F) as i64;
        let rt = ((opcode >> 16) & 0x1F) as i64;
        let imm = (opcode as i16) as i64;

        let base_addr = Self::ptr_add(builder, self.gpr_ptr as i64, base, 16);
        let base_val = Self::load32(builder, base_addr);

        let addr = builder.ins().iadd_imm(base_val, imm);

        let bus_lock = self.cpu.bus.lock().unwrap();
        let bus_ptr: *mut Bus = &*bus_lock as *const Bus as *mut Bus;
        let bus_value = builder.ins().iconst(types::I64, bus_ptr as i64);
        let bus_read_callee = self.module.declare_func_in_func(self.bus_read8_func, builder.func);
        let call_inst = builder.ins().call(bus_read_callee, &[bus_value, addr]);
        let load_val = builder.inst_results(call_inst)[0];

        let load_val_i64 = builder.ins().uextend(types::I64, load_val);

        let rt_addr = Self::ptr_add(builder, self.gpr_ptr as i64, rt, 16);
        builder.ins().store(MemFlags::new(), load_val_i64, rt_addr, 0);

        Self::increment_pc(builder, self.pc_ptr as i64);
        *current_pc = current_pc.wrapping_add(4);
        None
    }

    fn sra(&mut self, builder: &mut FunctionBuilder, opcode: u32, current_pc: &mut u32) -> Option<BranchInfo> {
        let rt = ((opcode >> 16) & 0x1F) as i64;
        let rd = ((opcode >> 11) & 0x1F) as i64;
        let sa = ((opcode >> 6) & 0x1F) as i64;

        let rt_addr = Self::ptr_add(builder, self.gpr_ptr as i64, rt, 16);
        let rd_addr = Self::ptr_add(builder, self.gpr_ptr as i64, rd, 16);

        let rt_val_32 = builder.ins().load(types::I32, MemFlags::new(), rt_addr, 0);
        let shifted = builder.ins().sshr_imm(rt_val_32, sa);
        let result = builder.ins().sextend(types::I64, shifted);
        builder.ins().store(MemFlags::new(), result, rd_addr, 0);

        Self::increment_pc(builder, self.pc_ptr as i64);
        *current_pc = current_pc.wrapping_add(4);

        None
    }

    fn ld(&mut self, builder: &mut FunctionBuilder, opcode: u32, current_pc: &mut u32) -> Option<BranchInfo> {
        let base = ((opcode >> 21) & 0x1F) as i64;
        let rt = ((opcode >> 16) & 0x1F) as i64;
        let imm = (opcode as i16) as i64;

        let base_addr = Self::ptr_add(builder, self.gpr_ptr as i64, base, 16);
        let base_val = Self::load32(builder, base_addr);

        let addr = builder.ins().iadd_imm(base_val, imm);

        let bus_lock = self.cpu.bus.lock().unwrap();
        let bus_ptr: *mut Bus = &*bus_lock as *const Bus as *mut Bus;
        let bus_value = builder.ins().iconst(types::I64, bus_ptr as i64);

        let bus_read_callee = self.module.declare_func_in_func(self.bus_read64_func, builder.func);
        let call_inst = builder.ins().call(bus_read_callee, &[bus_value, addr]);
        let load_val = builder.inst_results(call_inst)[0];

        let rt_addr = Self::ptr_add(builder, self.gpr_ptr as i64, rt, 16);
        builder.ins().store(MemFlags::new(), load_val, rt_addr, 0);

        Self::increment_pc(builder, self.pc_ptr as i64);
        *current_pc = current_pc.wrapping_add(4);
        None
    }

    fn j(&mut self, builder: &mut FunctionBuilder, opcode: u32, current_pc: &mut u32) -> Option<BranchInfo> {
        let instr_index = opcode & 0x03FFFFFF;
        let target = (*current_pc).wrapping_add(4) & 0xF0000000 | (instr_index << 2);

        *current_pc = current_pc.wrapping_add(4);
        
        Some(BranchInfo::Unconditional {
            target: BranchTarget::Const(target),
        })
    }

    fn sb(&mut self, builder: &mut FunctionBuilder, opcode: u32, current_pc: &mut u32) -> Option<BranchInfo> {
        let base = ((opcode >> 21) & 0x1F) as i64;
        let rt = ((opcode >> 16) & 0x1F) as i64;
        let imm = (opcode as i16) as i64;

        let base_addr = Self::ptr_add(builder, self.gpr_ptr as i64, base, 16);
        let base_val = Self::load32(builder, base_addr);

        let addr = builder.ins().iadd_imm(base_val, imm);

        let rt_addr = Self::ptr_add(builder, self.gpr_ptr as i64, rt, 16);
        let store_val = Self::load8(builder, rt_addr);

        let bus_lock = self.cpu.bus.lock().unwrap();
        let bus_ptr: *mut Bus = &*bus_lock as *const Bus as *mut Bus;
        let bus_value = builder.ins().iconst(types::I64, bus_ptr as i64);

        let callee = self.module.declare_func_in_func(self.bus_write8_func, builder.func);
        builder.ins().call(callee, &[bus_value, addr, store_val]);

        Self::increment_pc(builder, self.pc_ptr as i64);
        *current_pc = current_pc.wrapping_add(4);
        None
    }

    fn addu(&mut self, builder: &mut FunctionBuilder, opcode: u32, current_pc: &mut u32) -> Option<BranchInfo> {
        let rs = ((opcode >> 21) & 0x1F) as i64;
        let rt = ((opcode >> 16) & 0x1F) as i64;
        let rd = ((opcode >> 11) & 0x1F) as i64;

        let rs_addr = Self::ptr_add(builder, self.gpr_ptr as i64, rs, 16);
        let rt_addr = Self::ptr_add(builder, self.gpr_ptr as i64, rt, 16);
        let rd_addr = Self::ptr_add(builder, self.gpr_ptr as i64, rd, 16);

        let rs_val = builder.ins().load(types::I32, MemFlags::new(), rs_addr, 0);
        let rt_val = builder.ins().load(types::I32, MemFlags::new(), rt_addr, 0);
        let result = builder.ins().iadd(rs_val, rt_val);
        builder.ins().store(MemFlags::new(), result, rd_addr, 0);

        Self::increment_pc(builder, self.pc_ptr as i64);
        *current_pc = current_pc.wrapping_add(4);
        None
    }

    fn bgez(&mut self, builder: &mut FunctionBuilder, opcode: u32, current_pc: &mut u32) -> Option<BranchInfo> {
        let rs = ((opcode >> 21) & 0x1F) as i64;
        let imm = (opcode as u16) as i16 as i32;
        let rs_addr = Self::ptr_add(builder, self.gpr_ptr as i64, rs, 16);
        let rs_val = builder.ins().load(types::I32, MemFlags::new(), rs_addr, 0);

        let zero = builder.ins().iconst(types::I32, 0);
        let cond = builder.ins().icmp(IntCC::SignedGreaterThanOrEqual, rs_val, zero);

        let target = current_pc.wrapping_add(4).wrapping_add((imm << 2) as u32);
        *current_pc = current_pc.wrapping_add(4);

        Some(BranchInfo::Conditional {
            cond,
            target: BranchTarget::Const(target),
        })
    }

    fn div(&mut self, builder: &mut FunctionBuilder, opcode: u32, current_pc: &mut u32) -> Option<BranchInfo> {
        let rs = ((opcode >> 21) & 0x1F) as i64;
        let rt = ((opcode >> 16) & 0x1F) as i64;

        let rs_addr = Self::ptr_add(builder, self.gpr_ptr as i64, rs, 16);
        let rt_addr = Self::ptr_add(builder, self.gpr_ptr as i64, rt, 16);

        let dividend = builder.ins().load(types::I32, MemFlags::new(), rs_addr, 0);
        let divisor = builder.ins().load(types::I32, MemFlags::new(), rt_addr, 0);

        let quot = builder.ins().sdiv(dividend, divisor);
        let rem = builder.ins().srem(dividend, divisor);

        let quot_128 = builder.ins().sextend(types::I128, quot);
        let rem_128 = builder.ins().sextend(types::I128, rem);

        let lo_addr = Self::ptr_add(builder, self.lo_ptr as i64, 0, 16);
        let hi_addr = Self::ptr_add(builder, self.hi_ptr as i64, 0, 16);

        builder.ins().store(MemFlags::new(), quot_128, lo_addr, 0);
        builder.ins().store(MemFlags::new(), rem_128, hi_addr, 0);

        Self::increment_pc(builder, self.pc_ptr as i64);
        *current_pc = current_pc.wrapping_add(4);

        None
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

    fn get_cpu(&self) -> Arc<Mutex<EE>> {
        Arc::new(Mutex::new((*self.cpu).clone()))
    }
}