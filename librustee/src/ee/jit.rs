use crate::Bus;
use crate::bus::tlb::TlbEntry;
use crate::cpu::{CPU, EmulationBackend};
use crate::ee::EE;
use cranelift_codegen::ir::condcodes::IntCC;
use cranelift_codegen::ir::{AbiParam, BlockArg, InstBuilder, MemFlags, Value, types};
use cranelift_codegen::settings::Configurable;
use cranelift_codegen::{isa, settings};
use cranelift_frontend::{FunctionBuilder, FunctionBuilderContext};
use cranelift_jit::{JITBuilder, JITModule};
use cranelift_module::{FuncId, Linkage, Module, default_libcall_names};
use lru::LruCache;
use std::collections::HashMap;
use std::num::{NonZero, NonZeroU128};
use std::sync::{Arc, Mutex};
use std::thread::current;
use target_lexicon::Triple;
use tracing::{debug, error};

#[derive(Clone)]
pub struct Block {
    pub pc: u32,
    pub func_id: FuncId,
    pub func_ptr: fn(),
    pub dirty: bool,
    pub breakpoint: bool,
    pub cycle_count: u32,
}

pub struct JIT<'a> {
    pub cpu: &'a mut EE,
    module: JITModule,
    blocks: LruCache<u32, Block>,
    compiled_funcs: HashMap<u32, FuncId>,
    max_blocks: usize,
    gpr_ptr: *mut u128,
    fpr_ptr: *mut u32,
    hi_ptr: *mut u128,
    lo_ptr: *mut u128,
    pc_ptr: *mut u32,
    cycles: usize,
    break_func: FuncId,
    bus_write8_func: FuncId,
    bus_write16_func: FuncId,
    bus_write32_func: FuncId,
    bus_write64_func: FuncId,
    bus_write128_func: FuncId,
    bus_read8_func: FuncId,
    bus_read16_func: FuncId,
    bus_read32_func: FuncId,
    bus_read64_func: FuncId,
    bus_read128_func: FuncId,
    tlbwi_func: FuncId,
    read_cop0_func: FuncId,
    write_cop0_func: FuncId,
}

pub enum BranchTarget {
    Const(u32),
    Reg(Value),
}

enum BranchInfo {
    Conditional { cond: Value, target: BranchTarget },
    Unconditional { target: BranchTarget },
    ConditionalLikely { cond: Value, target: BranchTarget },
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

pub extern "C" fn __bus_write16(bus_ptr: *mut Bus, addr: u32, value: u16) {
    unsafe {
        let bus = &mut *bus_ptr;
        (bus.write16)(bus, addr, value);
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

pub extern "C" fn __bus_write128(bus_ptr: *mut Bus, addr: u32, value: u128) {
    unsafe {
        let bus = &mut *bus_ptr;
        (bus.write128)(bus, addr, value);
    }
}

pub extern "C" fn __bus_read8(bus_ptr: *mut Bus, addr: u32) -> u8 {
    unsafe {
        let bus = &mut *bus_ptr;
        (bus.read8)(bus, addr)
    }
}

pub extern "C" fn __bus_read16(bus_ptr: *mut Bus, addr: u32) -> u16 {
    unsafe {
        let bus = &mut *bus_ptr;
        (bus.read16)(bus, addr)
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

pub extern "C" fn __bus_read128(bus_ptr: *mut Bus, addr: u32) -> u128 {
    unsafe {
        let bus = &mut *bus_ptr;
        (bus.read128)(bus, addr)
    }
}

pub extern "C" fn __bus_tlbwi(bus_ptr: *mut Bus) {
    unsafe {
        let bus = crate::bus::BUS_PTR as *mut Bus;
        let mut tlb_ref = (*bus).tlb.borrow_mut();

        let index = (((*bus).read_cop0_register(0)) & 0x3F) as usize;

        let entry_hi = (*bus).read_cop0_register(10); // EntryHi
        let entry_lo0 = (*bus).read_cop0_register(2); // EntryLo0
        let entry_lo1 = (*bus).read_cop0_register(3); // EntryLo1
        let page_mask = (*bus).read_cop0_register(5); // PageMask

        let vpn2 = entry_hi >> 13;
        let asid = (entry_hi & 0xFF) as u8;

        let s0 = ((entry_lo0 >> 31) & 0x1) != 0; // scratchpad flag
        let pfn0 = (entry_lo0 >> 6) & 0x000F_FFFF; // bits [31:6]
        let c0 = ((entry_lo0 >> 3) & 0x7) as u8; // bits [5:3]
        let d0 = ((entry_lo0 >> 2) & 0x1) != 0; // bit [2]
        let v0 = ((entry_lo0 >> 1) & 0x1) != 0; // bit [1]
        let g0 = (entry_lo0 & 0x1) != 0; // bit [0]

        let s1 = ((entry_lo1 >> 31) & 0x1) != 0; // scratchpad flag
        let pfn1 = (entry_lo1 >> 6) & 0x000F_FFFF; // bits [31:6]
        let c1 = ((entry_lo1 >> 3) & 0x7) as u8; // bits [5:3]
        let d1 = ((entry_lo1 >> 2) & 0x1) != 0; // bit [2]
        let v1 = ((entry_lo1 >> 1) & 0x1) != 0; // bit [1]
        let g1 = (entry_lo1 & 0x1) != 0; // bit [0]

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

        tlb_ref.write_tlb_entry(bus, index, new_entry);
    }
}

impl<'a> JIT<'a> {
    pub fn new(cpu: &'a mut EE) -> Self {
        let mut shared_builder = settings::builder();
        shared_builder
            .set("enable_llvm_abi_extensions", "true")
            .expect("unknown setting");
        let shared_flags = settings::Flags::new(shared_builder);

        // 2. Look up the host ISA builder and finish it with our shared flags.
        let isa_builder = isa::lookup(Triple::host()).expect("host ISA not available");
        // (you can also tweak ISA‑specific settings here via `isa_builder.set(...)`)
        let isa = isa_builder.finish(shared_flags);

        // 3. Create a JITBuilder for _that_ ISA, with the default libcall names.
        let mut builder = JITBuilder::with_isa(isa.expect("REASON"), default_libcall_names());

        builder.symbol("__break", __bus_tlbwi as *const u8);

        builder.symbol("__bus_write8", __bus_write8 as *const u8);

        builder.symbol("__bus_write16", __bus_write16 as *const u8);

        builder.symbol("__bus_write32", __bus_write32 as *const u8);

        builder.symbol("__bus_write64", __bus_write64 as *const u8);

        builder.symbol("__bus_write128", __bus_write128 as *const u8);

        builder.symbol("__bus_read8", __bus_read8 as *const u8);

        builder.symbol("__bus_read16", __bus_read16 as *const u8);

        builder.symbol("__bus_read32", __bus_read32 as *const u8);

        builder.symbol("__bus_read64", __bus_read64 as *const u8);

        builder.symbol("__bus_read128", __bus_read64 as *const u8);

        builder.symbol("__bus_tlbwi", __bus_tlbwi as *const u8);

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
        store8_sig.params.push(AbiParam::new(types::I8)); // value
        let bus_write8_func = module
            .declare_function("__bus_write8", Linkage::Import, &store8_sig)
            .expect("Failed to declare __bus_write8");

        let mut store16_sig = module.make_signature();
        store16_sig.params.push(AbiParam::new(types::I64));
        store16_sig.params.push(AbiParam::new(types::I32));
        store16_sig.params.push(AbiParam::new(types::I16));
        let bus_write16_func: FuncId = module
            .declare_function("__bus_write16", Linkage::Import, &store16_sig)
            .expect("Failed to declare __bus_write16 function!");

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
            .expect("Failed to declare __bus_write64 function!");

        let mut store128_sig = module.make_signature();
        store128_sig.params.push(AbiParam::new(types::I64));
        store128_sig.params.push(AbiParam::new(types::I32));
        store128_sig.params.push(AbiParam::new(types::I128));
        let bus_write128_func: FuncId = module
            .declare_function("__bus_write128", Linkage::Import, &store128_sig)
            .expect("Failed to declare __bus_write128 function!");

        let mut load8_sig = module.make_signature();
        load8_sig.params.push(AbiParam::new(types::I64));
        load8_sig.params.push(AbiParam::new(types::I32));
        load8_sig.returns.push(AbiParam::new(types::I8));
        let bus_read8_func = module
            .declare_function("__bus_read8", Linkage::Import, &load8_sig)
            .expect("Failed to declare __bus_read8");

        let mut load16_sig = module.make_signature();
        load16_sig.params.push(AbiParam::new(types::I64));
        load16_sig.params.push(AbiParam::new(types::I32));
        load16_sig.returns.push(AbiParam::new(types::I16));
        let bus_read16_func = module
            .declare_function("__bus_read16", Linkage::Import, &load16_sig)
            .expect("Failed to declare __bus_read16");

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

        let mut load128_sig = module.make_signature();
        load128_sig.params.push(AbiParam::new(types::I64));
        load128_sig.params.push(AbiParam::new(types::I32));
        load128_sig.returns.push(AbiParam::new(types::I128));
        let bus_read128_func = module
            .declare_function("__bus_read128", Linkage::Import, &load128_sig)
            .expect("Failed to declare __bus_read128");

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
            compiled_funcs: HashMap::new(),
            max_blocks: MAX_BLOCKS.into(),
            gpr_ptr,
            fpr_ptr,
            hi_ptr,
            lo_ptr,
            pc_ptr,
            cycles: 0,
            break_func,
            bus_write8_func,
            bus_write16_func,
            bus_write32_func,
            bus_write64_func,
            bus_write128_func,
            bus_read8_func,
            bus_read16_func,
            bus_read32_func,
            bus_read64_func,
            bus_read128_func,
            tlbwi_func,
            read_cop0_func,
            write_cop0_func,
        }
    }

    #[inline]
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

    fn execute(&mut self, single_step: bool) -> (bool, u32) {
        let pc = self.cpu.pc();

        let mut block = if let Some(b) = self.blocks.get(&pc).cloned() {
            b
        } else {
            if let Some(&func_id) = self.compiled_funcs.get(&pc) {
                let ptr = self.module.get_finalized_function(func_id);
                let func_ptr = unsafe { std::mem::transmute(ptr) };
                let breakpoint = false;
                let cycle_count = 0;
                let b = Block {
                    pc,
                    func_id,
                    func_ptr,
                    dirty: false,
                    breakpoint,
                    cycle_count,
                };
                self.blocks.put(pc, b.clone());
                b
            } else {
                let (func_id, func_ptr, breakpoint, cycles) = self.compile_block(pc, single_step);
                self.compiled_funcs.insert(pc, func_id);
                let b = Block {
                    pc,
                    func_id,
                    func_ptr,
                    dirty: false,
                    breakpoint,
                    cycle_count: cycles,
                };
                self.blocks.put(pc, b.clone());
                b
            }
        };

        if block.dirty {
            let (func_id, func_ptr, breakpoint, cycles) = self.compile_block(pc, single_step);
            let new_block = Block {
                pc,
                func_id,
                func_ptr,
                dirty: false,
                breakpoint,
                cycle_count: cycles,
            };
            self.blocks.put(pc, new_block.clone());
            block = new_block;
        }

        let ptr = self.module.get_finalized_function(block.func_id);
        let f: fn() = unsafe { std::mem::transmute(ptr) };
        f();

        self.cycles += block.cycle_count as usize;
        (block.breakpoint, block.cycle_count)
    }

    fn compile_block(&mut self, pc: u32, single_step: bool) -> (FuncId, fn(), bool, u32) {
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
                debug!("Breakpoint hit at 0x{:08X}", current_pc);
                breakpoint = true;
                self.cpu.remove_breakpoint(current_pc);
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
                        builder
                            .ins()
                            .brif(cond, branch_blk, &[], fallthrough_blk, &[]);
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

        let func_ptr = unsafe { std::mem::transmute(ptr) };
        (func_id, func_ptr, breakpoint, total_cycles)
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

    fn decode(
        &mut self,
        builder: &mut FunctionBuilder,
        opcode: u32,
        current_pc: &mut u32,
    ) -> Option<BranchInfo> {
        let function = opcode >> 26;
        //debug!("decode: function: 0x{:02X}", function);
        match function {
            0x00 => {
                let subfunction = opcode & 0x3F;
                match subfunction {
                    0x00 => self.sll(builder, opcode, current_pc),
                    0x02 => self.srl(builder, opcode, current_pc),
                    0x03 => self.sra(builder, opcode, current_pc),
                    0x08 => self.jr(builder, opcode, current_pc),
                    0x09 => self.jalr(builder, opcode, current_pc),
                    0x0A => self.movz(builder, opcode, current_pc),
                    0x0B => self.movn(builder, opcode, current_pc),
                    0x0D => self.break_(builder, opcode, current_pc),
                    0x0F => self.sync(builder, opcode, current_pc),
                    0x10 => self.mfhi(builder, opcode, current_pc),
                    0x12 => self.mflo(builder, opcode, current_pc),
                    0x14 => self.dsllv(builder, opcode, current_pc),
                    0x17 => self.dsrav(builder, opcode, current_pc),
                    0x18 => self.mult(builder, opcode, current_pc),
                    0x1A => self.div(builder, opcode, current_pc),
                    0x1B => self.divu(builder, opcode, current_pc),
                    0x21 => self.addu(builder, opcode, current_pc),
                    0x23 => self.subu(builder, opcode, current_pc),
                    0x24 => self.and(builder, opcode, current_pc),
                    0x25 => self.or(builder, opcode, current_pc),
                    0x2A => self.slt(builder, opcode, current_pc),
                    0x2B => self.sltu(builder, opcode, current_pc),
                    0x2D => self.daddu(builder, opcode, current_pc),
                    0x3C => self.dsll32(builder, opcode, current_pc),
                    0x3F => self.dsra32(builder, opcode, current_pc),
                    _ => {
                        error!(
                            "Unhandled EE JIT function SPECIAL opcode: 0x{:08X} (Subfunction 0x{:02X}), PC: 0x{:08X}",
                            opcode, subfunction, current_pc
                        );
                        panic!();
                    }
                }
            }
            0x01 => {
                let rt = (opcode >> 16) & 0x1F;
                match rt {
                    0x00 => self.bltz(builder, opcode, current_pc),
                    0x01 => self.bgez(builder, opcode, current_pc),
                    0x02 => self.bltzl(builder, opcode, current_pc),
                    0x03 => self.bgezl(builder, opcode, current_pc),
                    _ => {
                        error!(
                            "Unhandled REGIMM instruction with rt=0x{:02X} at PC=0x{:08X}",
                            rt, *current_pc
                        );
                        panic!();
                    }
                }
            }
            0x02 => self.j(builder, opcode, current_pc),
            0x03 => self.jal(builder, opcode, current_pc),
            0x04 => self.beq(builder, opcode, current_pc),
            0x05 => self.bne(builder, opcode, current_pc),
            0x06 => self.blez(builder, opcode, current_pc),
            0x07 => self.bgtz(builder, opcode, current_pc),
            0x09 => self.addiu(builder, opcode, current_pc),
            0x0A => self.slti(builder, opcode, current_pc),
            0x0B => self.sltiu(builder, opcode, current_pc),
            0x0C => self.andi(builder, opcode, current_pc),
            0x0D => self.ori(builder, opcode, current_pc),
            0x0E => self.xori(builder, opcode, current_pc),
            0x0F => self.lui(builder, opcode, current_pc),
            0x10 => {
                let subfunction = (opcode >> 21) & 0x1F;
                match subfunction {
                    0x00 => self.mfc0(builder, opcode, current_pc),
                    0x04 => self.mtc0(builder, opcode, current_pc),
                    0x10 => self.tlbwi(builder, current_pc),
                    _ => {
                        error!(
                            "Unhandled EE JIT COP0 opcode: 0x{:08X} (Subfunction 0x{:02X}), PC: 0x{:08X}",
                            opcode, subfunction, current_pc
                        );
                        panic!();
                    }
                }
            }
            0x14 => self.beql(builder, opcode, current_pc),
            0x15 => self.bnel(builder, opcode, current_pc),
            0x19 => self.daddiu(builder, opcode, current_pc),
            0x1C => {
                let subfunction = opcode & 0x3F;

                match subfunction {
                    0x12 => self.mflo1(builder, opcode, current_pc),
                    0x18 => self.mult1(builder, opcode, current_pc),
                    0x1B => self.divu1(builder, opcode, current_pc),
                    0x29 => {
                        let mmi3_function = (opcode >> 6) & 0x1F;

                        match mmi3_function {
                            0x12 => self.or(builder, opcode, current_pc),
                            _ => {
                                panic!(
                                    "Unimplemented MMI3 instruction with funct: 0x{:02X}, PC: 0x{:08X}",
                                    mmi3_function, current_pc
                                );
                            }
                        }
                    }
                    _ => {
                        panic!(
                            "Unimplemented MMI instruction with funct: 0x{:02X}, PC: 0x{:08X}",
                            subfunction, current_pc
                        );
                    }
                }
            }
            0x1E => self.lq(builder, opcode, current_pc),
            0x1F => self.sq(builder, opcode, current_pc),
            0x20 => self.lb(builder, opcode, current_pc),
            0x21 => self.lh(builder, opcode, current_pc),
            0x23 => self.lw(builder, opcode, current_pc),
            0x24 => self.lbu(builder, opcode, current_pc),
            0x25 => self.lhu(builder, opcode, current_pc),
            0x28 => self.sb(builder, opcode, current_pc),
            0x29 => self.sh(builder, opcode, current_pc),
            0x2B => self.sw(builder, opcode, current_pc),
            0x2F => self.cache(builder, opcode, current_pc),
            0x39 => self.swc1(builder, opcode, current_pc),
            0x37 => self.ld(builder, opcode, current_pc),
            0x3F => self.sd(builder, opcode, current_pc),
            _ => {
                error!(
                    "Unhandled EE JIT opcode: 0x{:08X} (Function 0x{:02X}), PC: 0x{:08X}",
                    opcode, function, current_pc
                );
                panic!();
            }
        }
    }

    fn ptr_add(builder: &mut FunctionBuilder, base: i64, index: i64, scale: i64) -> Value {
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
        let pc_val = builder
            .ins()
            .load(types::I32, MemFlags::new(), pc_ptr_val, 0);
        let pc_inc = builder.ins().iadd_imm(pc_val, 4);
        builder.ins().store(MemFlags::new(), pc_inc, pc_ptr_val, 0);
    }

    fn mfc0(
        &mut self,
        builder: &mut FunctionBuilder,
        opcode: u32,
        current_pc: &mut u32,
    ) -> Option<BranchInfo> {
        let rt = ((opcode >> 16) & 0x1F) as i64;
        let rd = ((opcode >> 11) & 0x1F) as i64;

        let gpr_addr = Self::ptr_add(builder, self.gpr_ptr as i64, rt, 16);

        let cpu_ptr = self.cpu as *mut EE as i64;
        let cpu_arg = builder.ins().iconst(types::I64, cpu_ptr);
        let rd_arg = builder.ins().iconst(types::I32, rd);

        let read_cop0 = self
            .module
            .declare_func_in_func(self.read_cop0_func, builder.func);
        let write_cop0 = self
            .module
            .declare_func_in_func(self.write_cop0_func, builder.func);

        let call_rd = builder.ins().call(read_cop0, &[cpu_arg, rd_arg]);
        let cop0_val = builder.inst_results(call_rd)[0];
        builder.ins().store(MemFlags::new(), cop0_val, gpr_addr, 0);

        let idx9 = builder.ins().iconst(types::I32, 9);
        let call_read9 = builder.ins().call(read_cop0, &[cpu_arg, idx9]);
        let old9 = builder.inst_results(call_read9)[0];

        let cycles_val = builder.ins().iconst(types::I32, self.cycles as i64);

        let sum = builder.ins().iadd(old9, cycles_val);

        let _ = builder.ins().call(write_cop0, &[cpu_arg, idx9, sum]);

        Self::increment_pc(builder, self.pc_ptr as i64);
        *current_pc = current_pc.wrapping_add(4);

        None
    }

    fn sll(
        &mut self,
        builder: &mut FunctionBuilder,
        opcode: u32,
        current_pc: &mut u32,
    ) -> Option<BranchInfo> {
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

    fn slti(
        &mut self,
        builder: &mut FunctionBuilder,
        opcode: u32,
        current_pc: &mut u32,
    ) -> Option<BranchInfo> {
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

    fn lui(
        &mut self,
        builder: &mut FunctionBuilder,
        opcode: u32,
        current_pc: &mut u32,
    ) -> Option<BranchInfo> {
        let rt = ((opcode >> 16) & 0x1F) as i64;
        let imm = (opcode & 0xFFFF) as i64;

        let rt_addr = Self::ptr_add(builder, self.gpr_ptr as i64, rt, 16);
        let imm_val = builder.ins().iconst(types::I64, imm << 16);
        builder.ins().store(MemFlags::new(), imm_val, rt_addr, 0);

        Self::increment_pc(builder, self.pc_ptr as i64);
        *current_pc = current_pc.wrapping_add(4);
        None
    }

    fn ori(
        &mut self,
        builder: &mut FunctionBuilder,
        opcode: u32,
        current_pc: &mut u32,
    ) -> Option<BranchInfo> {
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

    fn mtc0(
        &mut self,
        builder: &mut FunctionBuilder,
        opcode: u32,
        current_pc: &mut u32,
    ) -> Option<BranchInfo> {
        let rt = ((opcode >> 16) & 0x1F) as i64;
        let rd = ((opcode >> 11) & 0x1F) as i64;

        let gpr_addr = Self::ptr_add(builder, self.gpr_ptr as i64, rt, 16);

        // Prepare arguments
        let cpu_ptr = self.cpu as *mut EE as i64;
        let cpu_arg = builder.ins().iconst(types::I64, cpu_ptr);
        let rd_arg = builder.ins().iconst(types::I32, rd);
        let gpr_val = Self::load32(builder, gpr_addr);

        let callee = self
            .module
            .declare_func_in_func(self.write_cop0_func, builder.func);
        builder.ins().call(callee, &[cpu_arg, rd_arg, gpr_val]);

        Self::increment_pc(builder, self.pc_ptr as i64);
        *current_pc = current_pc.wrapping_add(4);
        None
    }

    fn sync(
        &mut self,
        builder: &mut FunctionBuilder,
        _opcode: u32,
        current_pc: &mut u32,
    ) -> Option<BranchInfo> {
        // TODO: Implement SYNC instruction properly
        Self::increment_pc(builder, self.pc_ptr as i64);
        *current_pc = current_pc.wrapping_add(4);
        None
    }

    fn addiu(
        &mut self,
        builder: &mut FunctionBuilder,
        opcode: u32,
        current_pc: &mut u32,
    ) -> Option<BranchInfo> {
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

    fn sw(
        &mut self,
        builder: &mut FunctionBuilder,
        opcode: u32,
        current_pc: &mut u32,
    ) -> Option<BranchInfo> {
        let base = ((opcode >> 21) & 0x1F) as i64;
        let rt = ((opcode >> 16) & 0x1F) as i64;
        let imm = ((opcode as i16) as i64) as i64;
        let base_addr = Self::ptr_add(builder, self.gpr_ptr as i64, base, 16);
        let base_val = Self::load32(builder, base_addr);
        let addr = builder.ins().iadd_imm(base_val, imm);
        let rt_addr = Self::ptr_add(builder, self.gpr_ptr as i64, rt, 16);
        let store_val = Self::load32(builder, rt_addr);

        let bus = self.cpu.bus.lock().unwrap();
        let bus_ptr: *mut Bus = &**bus as *const Bus as *mut Bus;
        let bus_value = builder.ins().iconst(types::I64, bus_ptr as i64);
        let addr_arg = addr;
        let val_arg = store_val;

        let callee = self
            .module
            .declare_func_in_func(self.bus_write32_func, builder.func);
        builder.ins().call(callee, &[bus_value, addr_arg, val_arg]);

        Self::increment_pc(builder, self.pc_ptr as i64);
        *current_pc = current_pc.wrapping_add(4);
        None
    }

    fn tlbwi(&mut self, builder: &mut FunctionBuilder, current_pc: &mut u32) -> Option<BranchInfo> {
        let bus = self.cpu.bus.lock().unwrap();
        let bus_ptr: *mut Bus = &**bus as *const Bus as *mut Bus;
        let bus_value = builder.ins().iconst(types::I64, bus_ptr as i64);

        let local_callee = self
            .module
            .declare_func_in_func(self.tlbwi_func, builder.func);

        builder.ins().call(local_callee, &[bus_value]);

        Self::increment_pc(builder, self.pc_ptr as i64);
        *current_pc = current_pc.wrapping_add(4);
        None
    }

    fn lw(
        &mut self,
        builder: &mut FunctionBuilder,
        opcode: u32,
        current_pc: &mut u32,
    ) -> Option<BranchInfo> {
        let base_idx = ((opcode >> 21) & 0x1F) as usize;
        let rt_idx = ((opcode >> 16) & 0x1F) as usize;
        let imm_i64 = (opcode as i16) as i64;

        let base = base_idx as i64;
        let rt = rt_idx as i64;

        let base_addr = Self::ptr_add(builder, self.gpr_ptr as i64, base, 16);
        let base_val = Self::load32(builder, base_addr);

        let addr = builder.ins().iadd_imm(base_val, imm_i64);

        let bus = self.cpu.bus.lock().unwrap();
        let bus_ptr: *mut Bus = &**bus as *const Bus as *mut Bus;
        let bus_value = builder.ins().iconst(types::I64, bus_ptr as i64);
        let bus_read_callee = self
            .module
            .declare_func_in_func(self.bus_read32_func, builder.func);
        let call_inst = builder.ins().call(bus_read_callee, &[bus_value, addr]);
        let load_val = builder.inst_results(call_inst)[0];

        let rt_addr = Self::ptr_add(builder, self.gpr_ptr as i64, rt, 16);
        builder.ins().store(MemFlags::new(), load_val, rt_addr, 0);

        Self::increment_pc(builder, self.pc_ptr as i64);
        *current_pc = current_pc.wrapping_add(4);
        None
    }

    fn bne(
        &mut self,
        builder: &mut FunctionBuilder,
        opcode: u32,
        current_pc: &mut u32,
    ) -> Option<BranchInfo> {
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

    fn jr(
        &mut self,
        builder: &mut FunctionBuilder,
        opcode: u32,
        current_pc: &mut u32,
    ) -> Option<BranchInfo> {
        let rs = ((opcode >> 21) & 0x1F) as i64;
        let addr = Self::ptr_add(builder, self.gpr_ptr as i64, rs, 16);
        let target_i32 = builder.ins().load(types::I32, MemFlags::new(), addr, 0);
        let target = builder.ins().uextend(types::I64, target_i32);
        *current_pc = current_pc.wrapping_add(4);
        Some(BranchInfo::Unconditional {
            target: BranchTarget::Reg(target),
        })
    }

    fn jalr(
        &mut self,
        builder: &mut FunctionBuilder,
        opcode: u32,
        current_pc: &mut u32,
    ) -> Option<BranchInfo> {
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

    fn sd(
        &mut self,
        builder: &mut FunctionBuilder,
        opcode: u32,
        current_pc: &mut u32,
    ) -> Option<BranchInfo> {
        let base = ((opcode >> 21) & 0x1F) as i64;
        let rt = ((opcode >> 16) & 0x1F) as i64;
        let imm = (opcode as i16) as i64;

        let base_addr = Self::ptr_add(builder, self.gpr_ptr as i64, base, 16);
        let base_val = Self::load64(builder, base_addr);

        let addr = builder.ins().iadd_imm(base_val, imm);

        let addr32 = builder.ins().ireduce(types::I32, addr);

        let rt_addr = Self::ptr_add(builder, self.gpr_ptr as i64, rt, 16);
        let store_val = builder.ins().load(types::I64, MemFlags::new(), rt_addr, 0);

        let bus = self.cpu.bus.lock().unwrap();
        let bus_ptr: *mut Bus = &**bus as *const Bus as *mut Bus;
        let bus_value = builder.ins().iconst(types::I64, bus_ptr as i64);

        let callee = self
            .module
            .declare_func_in_func(self.bus_write64_func, builder.func);
        builder.ins().call(callee, &[bus_value, addr32, store_val]);

        Self::increment_pc(builder, self.pc_ptr as i64);
        *current_pc = current_pc.wrapping_add(4);
        None
    }

    fn daddu(
        &mut self,
        builder: &mut FunctionBuilder,
        opcode: u32,
        current_pc: &mut u32,
    ) -> Option<BranchInfo> {
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

    fn jal(
        &mut self,
        builder: &mut FunctionBuilder,
        opcode: u32,
        current_pc: &mut u32,
    ) -> Option<BranchInfo> {
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

    fn andi(
        &mut self,
        builder: &mut FunctionBuilder,
        opcode: u32,
        current_pc: &mut u32,
    ) -> Option<BranchInfo> {
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

    fn beq(
        &mut self,
        builder: &mut FunctionBuilder,
        opcode: u32,
        current_pc: &mut u32,
    ) -> Option<BranchInfo> {
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

    fn or(
        &mut self,
        builder: &mut FunctionBuilder,
        opcode: u32,
        current_pc: &mut u32,
    ) -> Option<BranchInfo> {
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

    fn mult(
        &mut self,
        builder: &mut FunctionBuilder,
        opcode: u32,
        current_pc: &mut u32,
    ) -> Option<BranchInfo> {
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

        let lo32 = builder.ins().ireduce(types::I32, prod);
        let lo64 = builder.ins().uextend(types::I64, lo32);
        let lo128 = builder.ins().uextend(types::I128, lo32);

        let hi_shift = builder.ins().ushr_imm(prod, 32);
        let hi32 = builder.ins().ireduce(types::I32, hi_shift);
        let hi128 = builder.ins().uextend(types::I128, hi32);

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

    fn divu(
        &mut self,
        builder: &mut FunctionBuilder,
        opcode: u32,
        current_pc: &mut u32,
    ) -> Option<BranchInfo> {
        let rs = ((opcode >> 21) & 0x1F) as i64;
        let rt = ((opcode >> 16) & 0x1F) as i64;

        let addr_rs = Self::ptr_add(builder, self.gpr_ptr as i64, rs, 16);
        let addr_rt = Self::ptr_add(builder, self.gpr_ptr as i64, rt, 16);

        let dividend = builder.ins().load(types::I32, MemFlags::new(), addr_rs, 0);
        let divisor = builder.ins().load(types::I32, MemFlags::new(), addr_rt, 0);

        let zero = builder.ins().iconst(types::I32, 0);

        let is_div_zero = builder.ins().icmp(IntCC::Equal, divisor, zero);

        let zero_block = builder.create_block();
        let normal_block = builder.create_block();
        let exit_block = builder.create_block();

        let quot_val = builder.append_block_param(exit_block, types::I32);
        let rem_val = builder.append_block_param(exit_block, types::I32);

        let zero_arg = BlockArg::Value(zero);

        builder
            .ins()
            .brif(is_div_zero, zero_block, &[], normal_block, &[]);

        builder.switch_to_block(zero_block);
        builder.ins().jump(exit_block, &[zero_arg, zero_arg]);
        builder.seal_block(zero_block);

        builder.switch_to_block(normal_block);
        let qn = builder.ins().udiv(dividend, divisor);
        let rn = builder.ins().urem(dividend, divisor);
        builder
            .ins()
            .jump(exit_block, &[BlockArg::Value(qn), BlockArg::Value(rn)]);
        builder.seal_block(normal_block);

        builder.switch_to_block(exit_block);
        let params = builder.block_params(exit_block);
        let quot = params[0];
        let rem = params[1];

        let quot128 = builder.ins().sextend(types::I64, quot);
        let rem128 = builder.ins().sextend(types::I64, rem);

        let lo_addr = Self::ptr_add(builder, self.lo_ptr as i64, 0, 16);
        let hi_addr = Self::ptr_add(builder, self.hi_ptr as i64, 0, 16);

        builder.ins().store(MemFlags::new(), quot128, lo_addr, 0);
        builder.ins().store(MemFlags::new(), rem128, hi_addr, 0);

        builder.seal_block(exit_block);

        Self::increment_pc(builder, self.pc_ptr as i64);
        *current_pc = current_pc.wrapping_add(4);

        None
    }

    fn beql(
        &mut self,
        builder: &mut FunctionBuilder,
        opcode: u32,
        current_pc: &mut u32,
    ) -> Option<BranchInfo> {
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

    fn break_(
        &mut self,
        builder: &mut FunctionBuilder,
        opcode: u32,
        current_pc: &mut u32,
    ) -> Option<BranchInfo> {
        let cpu_ptr = self.cpu as *mut EE as i64;
        let cpu_arg = builder.ins().iconst(types::I64, cpu_ptr);

        let callee = self
            .module
            .declare_func_in_func(self.break_func, builder.func);
        builder.ins().call(callee, &[cpu_arg]);

        None
    }

    fn mflo(
        &mut self,
        builder: &mut FunctionBuilder,
        opcode: u32,
        current_pc: &mut u32,
    ) -> Option<BranchInfo> {
        let rd = ((opcode >> 11) & 0x1F) as i64;

        let rd_addr = Self::ptr_add(builder, self.gpr_ptr as i64, rd, 16);

        let lo_ptr_val = builder.ins().iconst(types::I64, self.lo_ptr as i64);
        let lo_val = builder
            .ins()
            .load(types::I128, MemFlags::new(), lo_ptr_val, 0);

        let lo_val_64 = builder.ins().ireduce(types::I64, lo_val);

        builder.ins().store(MemFlags::new(), lo_val_64, rd_addr, 0);

        Self::increment_pc(builder, self.pc_ptr as i64);
        *current_pc = current_pc.wrapping_add(4);

        None
    }

    fn sltiu(
        &mut self,
        builder: &mut FunctionBuilder,
        opcode: u32,
        current_pc: &mut u32,
    ) -> Option<BranchInfo> {
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

    fn bnel(
        &mut self,
        builder: &mut FunctionBuilder,
        opcode: u32,
        current_pc: &mut u32,
    ) -> Option<BranchInfo> {
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

    fn lb(
        &mut self,
        builder: &mut FunctionBuilder,
        opcode: u32,
        current_pc: &mut u32,
    ) -> Option<BranchInfo> {
        let base_idx = ((opcode >> 21) & 0x1F) as usize;
        let rt_idx = ((opcode >> 16) & 0x1F) as usize;
        let imm_i64 = (opcode as i16) as i64;

        let base = base_idx as i64;
        let rt = rt_idx as i64;

        let base_addr = Self::ptr_add(builder, self.gpr_ptr as i64, base, 16);
        let base_val = Self::load32(builder, base_addr);

        let addr = builder.ins().iadd_imm(base_val, imm_i64);

        let bus = self.cpu.bus.lock().unwrap();
        let bus_ptr: *mut Bus = &**bus as *const Bus as *mut Bus;
        let bus_value = builder.ins().iconst(types::I64, bus_ptr as i64);
        let bus_read_callee = self
            .module
            .declare_func_in_func(self.bus_read8_func, builder.func);
        let call_inst = builder.ins().call(bus_read_callee, &[bus_value, addr]);
        let load_val = builder.inst_results(call_inst)[0];

        let load_val_i64 = builder.ins().sextend(types::I64, load_val);

        let rt_addr = Self::ptr_add(builder, self.gpr_ptr as i64, rt, 16);
        builder
            .ins()
            .store(MemFlags::new(), load_val_i64, rt_addr, 0);

        Self::increment_pc(builder, self.pc_ptr as i64);
        *current_pc = current_pc.wrapping_add(4);
        None
    }

    fn swc1(
        &mut self,
        builder: &mut FunctionBuilder,
        opcode: u32,
        current_pc: &mut u32,
    ) -> Option<BranchInfo> {
        let base = ((opcode >> 21) & 0x1F) as i64;
        let ft = ((opcode >> 16) & 0x1F) as i64;
        let imm = (opcode as i16) as i64;

        let base_addr = Self::ptr_add(builder, self.gpr_ptr as i64, base, 16);
        let base_val = Self::load32(builder, base_addr);

        let addr = builder.ins().iadd_imm(base_val, imm);

        let ft_addr = Self::ptr_add(builder, self.fpr_ptr as i64, ft, 4);
        let fpu_val = Self::load32(builder, ft_addr);

        let bus = self.cpu.bus.lock().unwrap();
        let bus_ptr: *mut Bus = &**bus as *const Bus as *mut Bus;
        let bus_value = builder.ins().iconst(types::I64, bus_ptr as i64);

        let callee = self
            .module
            .declare_func_in_func(self.bus_write32_func, builder.func);
        builder.ins().call(callee, &[bus_value, addr, fpu_val]);

        Self::increment_pc(builder, self.pc_ptr as i64);
        *current_pc = current_pc.wrapping_add(4);

        None
    }

    fn lbu(
        &mut self,
        builder: &mut FunctionBuilder,
        opcode: u32,
        current_pc: &mut u32,
    ) -> Option<BranchInfo> {
        let base = ((opcode >> 21) & 0x1F) as i64;
        let rt = ((opcode >> 16) & 0x1F) as i64;
        let imm = (opcode as i16) as i64;

        let base_addr = Self::ptr_add(builder, self.gpr_ptr as i64, base, 16);
        let base_val = Self::load32(builder, base_addr);

        let addr = builder.ins().iadd_imm(base_val, imm);

        let bus = self.cpu.bus.lock().unwrap();
        let bus_ptr: *mut Bus = &**bus as *const Bus as *mut Bus;
        let bus_value = builder.ins().iconst(types::I64, bus_ptr as i64);
        let bus_read_callee = self
            .module
            .declare_func_in_func(self.bus_read8_func, builder.func);
        let call_inst = builder.ins().call(bus_read_callee, &[bus_value, addr]);
        let load_val = builder.inst_results(call_inst)[0];

        let load_val_i64 = builder.ins().uextend(types::I64, load_val);

        let rt_addr = Self::ptr_add(builder, self.gpr_ptr as i64, rt, 16);
        builder
            .ins()
            .store(MemFlags::new(), load_val_i64, rt_addr, 0);

        Self::increment_pc(builder, self.pc_ptr as i64);
        *current_pc = current_pc.wrapping_add(4);
        None
    }

    fn sra(
        &mut self,
        builder: &mut FunctionBuilder,
        opcode: u32,
        current_pc: &mut u32,
    ) -> Option<BranchInfo> {
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

    fn ld(
        &mut self,
        builder: &mut FunctionBuilder,
        opcode: u32,
        current_pc: &mut u32,
    ) -> Option<BranchInfo> {
        let base = ((opcode >> 21) & 0x1F) as i64;
        let rt = ((opcode >> 16) & 0x1F) as i64;
        let imm = (opcode as i16) as i64;

        let base_addr = Self::ptr_add(builder, self.gpr_ptr as i64, base, 16);
        let base_val = Self::load32(builder, base_addr);

        let addr = builder.ins().iadd_imm(base_val, imm);

        let bus = self.cpu.bus.lock().unwrap();
        let bus_ptr: *mut Bus = &**bus as *const Bus as *mut Bus;
        let bus_value = builder.ins().iconst(types::I64, bus_ptr as i64);

        let bus_read_callee = self
            .module
            .declare_func_in_func(self.bus_read64_func, builder.func);
        let call_inst = builder.ins().call(bus_read_callee, &[bus_value, addr]);
        let load_val = builder.inst_results(call_inst)[0];

        let rt_addr = Self::ptr_add(builder, self.gpr_ptr as i64, rt, 16);
        builder.ins().store(MemFlags::new(), load_val, rt_addr, 0);

        Self::increment_pc(builder, self.pc_ptr as i64);
        *current_pc = current_pc.wrapping_add(4);
        None
    }

    fn j(
        &mut self,
        builder: &mut FunctionBuilder,
        opcode: u32,
        current_pc: &mut u32,
    ) -> Option<BranchInfo> {
        let instr_index = opcode & 0x03FFFFFF;
        let target = (*current_pc).wrapping_add(4) & 0xF0000000 | (instr_index << 2);

        *current_pc = current_pc.wrapping_add(4);

        Some(BranchInfo::Unconditional {
            target: BranchTarget::Const(target),
        })
    }

    fn sb(
        &mut self,
        builder: &mut FunctionBuilder,
        opcode: u32,
        current_pc: &mut u32,
    ) -> Option<BranchInfo> {
        let base = ((opcode >> 21) & 0x1F) as i64;
        let rt = ((opcode >> 16) & 0x1F) as i64;
        let imm = (opcode as i16) as i64;

        let base_addr = Self::ptr_add(builder, self.gpr_ptr as i64, base, 16);
        let base_val = Self::load32(builder, base_addr);

        let addr = builder.ins().iadd_imm(base_val, imm);

        let rt_addr = Self::ptr_add(builder, self.gpr_ptr as i64, rt, 16);
        let store_val = Self::load8(builder, rt_addr);

        let bus = self.cpu.bus.lock().unwrap();
        let bus_ptr: *mut Bus = &**bus as *const Bus as *mut Bus;
        let bus_value = builder.ins().iconst(types::I64, bus_ptr as i64);

        let callee = self
            .module
            .declare_func_in_func(self.bus_write8_func, builder.func);
        builder.ins().call(callee, &[bus_value, addr, store_val]);

        Self::increment_pc(builder, self.pc_ptr as i64);
        *current_pc = current_pc.wrapping_add(4);
        None
    }

    fn addu(
        &mut self,
        builder: &mut FunctionBuilder,
        opcode: u32,
        current_pc: &mut u32,
    ) -> Option<BranchInfo> {
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

    fn bgez(
        &mut self,
        builder: &mut FunctionBuilder,
        opcode: u32,
        current_pc: &mut u32,
    ) -> Option<BranchInfo> {
        let rs = ((opcode >> 21) & 0x1F) as i64;
        let imm = (opcode as u16) as i16 as i32;
        let rs_addr = Self::ptr_add(builder, self.gpr_ptr as i64, rs, 16);
        let rs_val = builder.ins().load(types::I32, MemFlags::new(), rs_addr, 0);

        let zero = builder.ins().iconst(types::I32, 0);
        let cond = builder
            .ins()
            .icmp(IntCC::SignedGreaterThanOrEqual, rs_val, zero);

        let target = current_pc.wrapping_add(4).wrapping_add((imm << 2) as u32);
        *current_pc = current_pc.wrapping_add(4);

        Some(BranchInfo::Conditional {
            cond,
            target: BranchTarget::Const(target),
        })
    }

    fn div(
        &mut self,
        builder: &mut FunctionBuilder,
        opcode: u32,
        current_pc: &mut u32,
    ) -> Option<BranchInfo> {
        let rs = ((opcode >> 21) & 0x1F) as i64;
        let rt = ((opcode >> 16) & 0x1F) as i64;
        let addr_rs = Self::ptr_add(builder, self.gpr_ptr as i64, rs, 16);
        let addr_rt = Self::ptr_add(builder, self.gpr_ptr as i64, rt, 16);
        let dividend = builder.ins().load(types::I32, MemFlags::new(), addr_rs, 0);
        let divisor = builder.ins().load(types::I32, MemFlags::new(), addr_rt, 0);

        let zero = builder.ins().iconst(types::I32, 0);
        let int_min = builder.ins().iconst(types::I32, i32::MIN as i64);
        let minus_one = builder.ins().iconst(types::I32, -1);

        let is_div_zero = builder.ins().icmp(IntCC::Equal, divisor, zero);
        let is_overflow = {
            let a = builder.ins().icmp(IntCC::Equal, dividend, int_min);
            let b = builder.ins().icmp(IntCC::Equal, divisor, minus_one);
            builder.ins().band(a, b)
        };

        let zero_block = builder.create_block();
        let special_test = builder.create_block();
        let overflow_block = builder.create_block();
        let normal_block = builder.create_block();
        let exit_block = builder.create_block();

        let quot_val = builder.append_block_param(exit_block, types::I32);
        let rem_val = builder.append_block_param(exit_block, types::I32);

        let zero_arg = BlockArg::Value(zero);
        let int_min_arg = BlockArg::Value(int_min);

        builder
            .ins()
            .brif(is_div_zero, zero_block, &[], special_test, &[]);

        builder.switch_to_block(zero_block);
        builder.ins().jump(exit_block, &[zero_arg, zero_arg]);
        builder.seal_block(zero_block);

        builder.switch_to_block(special_test);
        builder
            .ins()
            .brif(is_overflow, overflow_block, &[], normal_block, &[]);
        builder.seal_block(special_test);

        builder.switch_to_block(overflow_block);
        builder.ins().jump(exit_block, &[int_min_arg, zero_arg]);
        builder.seal_block(overflow_block);

        builder.switch_to_block(normal_block);
        let qn = builder.ins().sdiv(dividend, divisor);
        let rn = builder.ins().srem(dividend, divisor);
        builder
            .ins()
            .jump(exit_block, &[BlockArg::Value(qn), BlockArg::Value(rn)]);
        builder.seal_block(normal_block);

        builder.switch_to_block(exit_block);
        let params = builder.block_params(exit_block);
        let quot = params[0];
        let rem = params[1];

        let q128 = builder.ins().sextend(types::I128, quot);
        let r128 = builder.ins().sextend(types::I128, rem);
        let lo_addr = Self::ptr_add(builder, self.lo_ptr as i64, 0, 16);
        let hi_addr = Self::ptr_add(builder, self.hi_ptr as i64, 0, 16);
        builder.ins().store(MemFlags::new(), q128, lo_addr, 0);
        builder.ins().store(MemFlags::new(), r128, hi_addr, 0);

        builder.seal_block(exit_block);

        Self::increment_pc(builder, self.pc_ptr as i64);
        *current_pc = current_pc.wrapping_add(4);

        None
    }

    fn mfhi(
        &mut self,
        builder: &mut FunctionBuilder,
        opcode: u32,
        current_pc: &mut u32,
    ) -> Option<BranchInfo> {
        let rd = ((opcode >> 11) & 0x1F) as i64;
        let rd_addr = Self::ptr_add(builder, self.gpr_ptr as i64, rd, 16);

        let hi_ptr_val = builder.ins().iconst(types::I64, self.hi_ptr as i64);
        let hi_val = builder
            .ins()
            .load(types::I128, MemFlags::new(), hi_ptr_val, 0);
        let hi_val_64 = builder.ins().ireduce(types::I64, hi_val);
        builder.ins().store(MemFlags::new(), hi_val_64, rd_addr, 0);

        Self::increment_pc(builder, self.pc_ptr as i64);
        *current_pc = current_pc.wrapping_add(4);

        None
    }

    fn sltu(
        &mut self,
        builder: &mut FunctionBuilder,
        opcode: u32,
        current_pc: &mut u32,
    ) -> Option<BranchInfo> {
        let rs = ((opcode >> 21) & 0x1F) as i64;
        let rt = ((opcode >> 16) & 0x1F) as i64;
        let rd = ((opcode >> 11) & 0x1F) as i64;

        let rs_a = Self::ptr_add(builder, self.gpr_ptr as i64, rs, 16);
        let rt_a = Self::ptr_add(builder, self.gpr_ptr as i64, rt, 16);
        let rd_a = Self::ptr_add(builder, self.gpr_ptr as i64, rd, 16);

        let rs_val = builder.ins().load(types::I64, MemFlags::new(), rs_a, 0);
        let rt_val = builder.ins().load(types::I64, MemFlags::new(), rt_a, 0);

        let cmp = builder.ins().icmp(IntCC::UnsignedLessThan, rs_val, rt_val);

        let one = builder.ins().iconst(types::I64, 1);
        let zero = builder.ins().iconst(types::I64, 0);

        let result = builder.ins().select(cmp, one, zero);

        builder.ins().store(MemFlags::new(), result, rd_a, 0);

        Self::increment_pc(builder, self.pc_ptr as i64);
        *current_pc = current_pc.wrapping_add(4);

        None
    }

    fn blez(
        &mut self,
        builder: &mut FunctionBuilder,
        opcode: u32,
        current_pc: &mut u32,
    ) -> Option<BranchInfo> {
        let rs = ((opcode >> 21) & 0x1F) as i64;
        let imm = (opcode as u16) as i16 as i32;

        let rs_addr = Self::ptr_add(builder, self.gpr_ptr as i64, rs, 16);
        let rs_val = builder.ins().load(types::I32, MemFlags::new(), rs_addr, 0);

        let zero = builder.ins().iconst(types::I32, 0);
        let cond = builder
            .ins()
            .icmp(IntCC::SignedLessThanOrEqual, rs_val, zero);

        let next_pc = current_pc.wrapping_add(4);
        let target = next_pc.wrapping_add((imm << 2) as u32);

        *current_pc = next_pc;

        Some(BranchInfo::Conditional {
            cond,
            target: BranchTarget::Const(target),
        })
    }

    fn subu(
        &mut self,
        builder: &mut FunctionBuilder,
        opcode: u32,
        current_pc: &mut u32,
    ) -> Option<BranchInfo> {
        let rs = ((opcode >> 21) & 0x1F) as i64;
        let rt = ((opcode >> 16) & 0x1F) as i64;
        let rd = ((opcode >> 11) & 0x1F) as i64;

        let rs_a = Self::ptr_add(builder, self.gpr_ptr as i64, rs, 16);
        let rt_a = Self::ptr_add(builder, self.gpr_ptr as i64, rt, 16);
        let rd_a = Self::ptr_add(builder, self.gpr_ptr as i64, rd, 16);

        let a32 = builder.ins().load(types::I32, MemFlags::new(), rs_a, 0);
        let b32 = builder.ins().load(types::I32, MemFlags::new(), rt_a, 0);

        let diff32 = builder.ins().isub(a32, b32);

        let result = builder.ins().sextend(types::I64, diff32);

        builder.ins().store(MemFlags::new(), result, rd_a, 0);

        Self::increment_pc(builder, self.pc_ptr as i64);
        *current_pc = current_pc.wrapping_add(4);

        None
    }

    fn bgtz(
        &mut self,
        builder: &mut FunctionBuilder,
        opcode: u32,
        current_pc: &mut u32,
    ) -> Option<BranchInfo> {
        let rs = ((opcode >> 21) & 0x1F) as i64;
        let imm = (opcode as u16) as i16 as i32;

        let rs_addr = Self::ptr_add(builder, self.gpr_ptr as i64, rs, 16);
        let rs_val = builder.ins().load(types::I32, MemFlags::new(), rs_addr, 0);

        let zero = builder.ins().iconst(types::I32, 0);
        let cond = builder.ins().icmp(IntCC::SignedGreaterThan, rs_val, zero);

        let next_pc = current_pc.wrapping_add(4);
        let target = next_pc.wrapping_add((imm << 2) as u32);

        *current_pc = next_pc;

        Some(BranchInfo::Conditional {
            cond,
            target: BranchTarget::Const(target),
        })
    }

    fn movn(
        &mut self,
        builder: &mut FunctionBuilder,
        opcode: u32,
        current_pc: &mut u32,
    ) -> Option<BranchInfo> {
        let rs = ((opcode >> 21) & 0x1F) as i64;
        let rt = ((opcode >> 16) & 0x1F) as i64;
        let rd = ((opcode >> 11) & 0x1F) as i64;

        let rs_a = Self::ptr_add(builder, self.gpr_ptr as i64, rs, 16);
        let rt_a = Self::ptr_add(builder, self.gpr_ptr as i64, rt, 16);
        let rd_a = Self::ptr_add(builder, self.gpr_ptr as i64, rd, 16);

        let rt_val = builder.ins().load(types::I64, MemFlags::new(), rt_a, 0);
        let zero = builder.ins().iconst(types::I64, 0);
        let cond = builder.ins().icmp(IntCC::NotEqual, rt_val, zero);

        let rs_val = builder.ins().load(types::I64, MemFlags::new(), rs_a, 0);
        let rd_old = builder.ins().load(types::I64, MemFlags::new(), rd_a, 0);

        let new_rd = builder.ins().select(cond, rs_val, rd_old);

        builder.ins().store(MemFlags::new(), new_rd, rd_a, 0);

        Self::increment_pc(builder, self.pc_ptr as i64);
        *current_pc = current_pc.wrapping_add(4);

        None
    }

    fn slt(
        &mut self,
        builder: &mut FunctionBuilder,
        opcode: u32,
        current_pc: &mut u32,
    ) -> Option<BranchInfo> {
        let rs = ((opcode >> 21) & 0x1F) as i64;
        let rt = ((opcode >> 16) & 0x1F) as i64;
        let rd = ((opcode >> 11) & 0x1F) as i64;

        let rs_a = Self::ptr_add(builder, self.gpr_ptr as i64, rs, 16);
        let rt_a = Self::ptr_add(builder, self.gpr_ptr as i64, rt, 16);
        let rd_a = Self::ptr_add(builder, self.gpr_ptr as i64, rd, 16);

        let rs_val = builder.ins().load(types::I64, MemFlags::new(), rs_a, 0);
        let rt_val = builder.ins().load(types::I64, MemFlags::new(), rt_a, 0);

        let cmp = builder.ins().icmp(IntCC::SignedLessThan, rs_val, rt_val);

        let one = builder.ins().iconst(types::I64, 1);
        let zero = builder.ins().iconst(types::I64, 0);
        let result = builder.ins().select(cmp, one, zero);

        builder.ins().store(MemFlags::new(), result, rd_a, 0);

        Self::increment_pc(builder, self.pc_ptr as i64);
        *current_pc = current_pc.wrapping_add(4);

        None
    }

    fn and(
        &mut self,
        builder: &mut FunctionBuilder,
        opcode: u32,
        current_pc: &mut u32,
    ) -> Option<BranchInfo> {
        let rs = ((opcode >> 21) & 0x1F) as i64;
        let rt = ((opcode >> 16) & 0x1F) as i64;
        let rd = ((opcode >> 11) & 0x1F) as i64;

        let rs_a = Self::ptr_add(builder, self.gpr_ptr as i64, rs, 16);
        let rt_a = Self::ptr_add(builder, self.gpr_ptr as i64, rt, 16);
        let rd_a = Self::ptr_add(builder, self.gpr_ptr as i64, rd, 16);

        let a = builder.ins().load(types::I64, MemFlags::new(), rs_a, 0);
        let b = builder.ins().load(types::I64, MemFlags::new(), rt_a, 0);

        let res = builder.ins().band(a, b);

        builder.ins().store(MemFlags::new(), res, rd_a, 0);

        Self::increment_pc(builder, self.pc_ptr as i64);
        *current_pc = current_pc.wrapping_add(4);

        None
    }

    fn srl(
        &mut self,
        builder: &mut FunctionBuilder,
        opcode: u32,
        current_pc: &mut u32,
    ) -> Option<BranchInfo> {
        let rt = ((opcode >> 16) & 0x1F) as i64;
        let rd = ((opcode >> 11) & 0x1F) as i64;
        let sa = ((opcode >> 6) & 0x1F) as i64;

        let rt_a = Self::ptr_add(builder, self.gpr_ptr as i64, rt, 16);
        let rd_a = Self::ptr_add(builder, self.gpr_ptr as i64, rd, 16);

        let v32 = builder.ins().load(types::I32, MemFlags::new(), rt_a, 0);
        let shifted = builder.ins().ushr_imm(v32, sa as i64);
        let res = builder.ins().sextend(types::I64, shifted);

        builder.ins().store(MemFlags::new(), res, rd_a, 0);

        Self::increment_pc(builder, self.pc_ptr as i64);
        *current_pc = current_pc.wrapping_add(4);

        None
    }

    fn lhu(
        &mut self,
        builder: &mut FunctionBuilder,
        opcode: u32,
        current_pc: &mut u32,
    ) -> Option<BranchInfo> {
        let base = ((opcode >> 21) & 0x1F) as i64;
        let rt = ((opcode >> 16) & 0x1F) as i64;
        let imm = (opcode as i16) as i64;

        let base_addr = Self::ptr_add(builder, self.gpr_ptr as i64, base, 16);
        let base_val = Self::load32(builder, base_addr);

        let addr = builder.ins().iadd_imm(base_val, imm);

        let bus = self.cpu.bus.lock().unwrap();
        let bus_ptr: *mut Bus = &**bus as *const Bus as *mut Bus;
        let bus_value = builder.ins().iconst(types::I64, bus_ptr as i64);
        let bus_read_callee = self
            .module
            .declare_func_in_func(self.bus_read16_func, builder.func);
        let call_inst = builder.ins().call(bus_read_callee, &[bus_value, addr]);
        let load_val = builder.inst_results(call_inst)[0];

        let load_val_i64 = builder.ins().uextend(types::I64, load_val);

        let rt_addr = Self::ptr_add(builder, self.gpr_ptr as i64, rt, 16);
        builder
            .ins()
            .store(MemFlags::new(), load_val_i64, rt_addr, 0);

        Self::increment_pc(builder, self.pc_ptr as i64);
        *current_pc = current_pc.wrapping_add(4);
        None
    }

    fn bltz(
        &mut self,
        builder: &mut FunctionBuilder,
        opcode: u32,
        current_pc: &mut u32,
    ) -> Option<BranchInfo> {
        let rs = ((opcode >> 21) & 0x1F) as i64;
        let imm = (opcode as u16) as i16 as i32;

        let rs_addr = Self::ptr_add(builder, self.gpr_ptr as i64, rs, 16);
        let rs_val = builder.ins().load(types::I32, MemFlags::new(), rs_addr, 0);

        let zero = builder.ins().iconst(types::I32, 0);
        let cond = builder.ins().icmp(IntCC::SignedLessThan, rs_val, zero);

        let target = current_pc.wrapping_add(4).wrapping_add((imm << 2) as u32);
        *current_pc = current_pc.wrapping_add(4);

        Some(BranchInfo::Conditional {
            cond,
            target: BranchTarget::Const(target),
        })
    }

    fn bltzl(
        &mut self,
        builder: &mut FunctionBuilder,
        opcode: u32,
        current_pc: &mut u32,
    ) -> Option<BranchInfo> {
        let rs = ((opcode >> 21) & 0x1F) as i64;
        let imm = (opcode as u16) as i16 as i32;

        let rs_addr = Self::ptr_add(builder, self.gpr_ptr as i64, rs, 16);
        let rs_val = builder.ins().load(types::I32, MemFlags::new(), rs_addr, 0);

        let zero = builder.ins().iconst(types::I32, 0);
        let cond = builder.ins().icmp(IntCC::SignedLessThan, rs_val, zero);

        let target = current_pc.wrapping_add(4).wrapping_add((imm << 2) as u32);
        *current_pc = current_pc.wrapping_add(4);

        Some(BranchInfo::ConditionalLikely {
            cond,
            target: BranchTarget::Const(target),
        })
    }

    fn bgezl(
        &mut self,
        builder: &mut FunctionBuilder,
        opcode: u32,
        current_pc: &mut u32,
    ) -> Option<BranchInfo> {
        let rs = ((opcode >> 21) & 0x1F) as i64;
        let imm = (opcode as u16) as i16 as i32;

        let rs_addr = Self::ptr_add(builder, self.gpr_ptr as i64, rs, 16);
        let rs_val = builder.ins().load(types::I32, MemFlags::new(), rs_addr, 0);

        let zero = builder.ins().iconst(types::I32, 0);
        let cond = builder
            .ins()
            .icmp(IntCC::SignedGreaterThanOrEqual, rs_val, zero);

        let target = current_pc.wrapping_add(4).wrapping_add((imm << 2) as u32);
        *current_pc = current_pc.wrapping_add(4);

        Some(BranchInfo::ConditionalLikely {
            cond,
            target: BranchTarget::Const(target),
        })
    }

    fn sh(
        &mut self,
        builder: &mut FunctionBuilder,
        opcode: u32,
        current_pc: &mut u32,
    ) -> Option<BranchInfo> {
        let base = ((opcode >> 21) & 0x1F) as i64;
        let rt = ((opcode >> 16) & 0x1F) as i64;
        let imm = (opcode as i16) as i64;

        let base_addr = Self::ptr_add(builder, self.gpr_ptr as i64, base, 16);
        let base_val = Self::load32(builder, base_addr);
        let addr = builder.ins().iadd_imm(base_val, imm);

        let rt_addr = Self::ptr_add(builder, self.gpr_ptr as i64, rt, 16);
        let store_val = Self::load32(builder, rt_addr);
        let store_val_16 = builder.ins().ireduce(types::I16, store_val);

        let bus = self.cpu.bus.lock().unwrap();
        let bus_ptr: *mut Bus = &**bus as *const Bus as *mut Bus;
        let bus_value = builder.ins().iconst(types::I64, bus_ptr as i64);

        let callee = self
            .module
            .declare_func_in_func(self.bus_write16_func, builder.func);
        builder.ins().call(callee, &[bus_value, addr, store_val_16]);

        Self::increment_pc(builder, self.pc_ptr as i64);
        *current_pc = current_pc.wrapping_add(4);
        None
    }

    fn divu1(
        &mut self,
        builder: &mut FunctionBuilder,
        opcode: u32,
        current_pc: &mut u32,
    ) -> Option<BranchInfo> {
        let rs = ((opcode >> 21) & 0x1F) as i64;
        let rt = ((opcode >> 16) & 0x1F) as i64;

        let rs_addr = Self::ptr_add(builder, self.gpr_ptr as i64, rs, 16);
        let rt_addr = Self::ptr_add(builder, self.gpr_ptr as i64, rt, 16);
        let rs_val = builder
            .ins()
            .load(types::I32, MemFlags::trusted(), rs_addr, 0);
        let rt_val = builder
            .ins()
            .load(types::I32, MemFlags::trusted(), rt_addr, 0);

        let rs64 = builder.ins().uextend(types::I64, rs_val);
        let rt64 = builder.ins().uextend(types::I64, rt_val);

        let rt_zero = builder.ins().icmp_imm(IntCC::Equal, rt64, 0);

        let quot64 = builder.ins().udiv(rs64, rt64);
        let rem64 = builder.ins().urem(rs64, rt64);

        let lo_addr = Self::ptr_add(builder, self.lo_ptr as i64, 1, 4);
        let hi_addr = Self::ptr_add(builder, self.hi_ptr as i64, 1, 4);

        let lo_old = builder
            .ins()
            .load(types::I64, MemFlags::trusted(), lo_addr, 0);
        let hi_old = builder
            .ins()
            .load(types::I64, MemFlags::trusted(), hi_addr, 0);

        let low_mask = builder.ins().iconst(types::I64, 0xFFFF_FFFF);
        let shift32 = builder.ins().iconst(types::I64, 32);

        let quot_shifted = builder.ins().ishl(quot64, shift32);
        let rem_shifted = builder.ins().ishl(rem64, shift32);

        let lo_masked = builder.ins().band(lo_old, low_mask);
        let hi_masked = builder.ins().band(hi_old, low_mask);

        let lo_new = builder.ins().bor(lo_masked, quot_shifted);
        let hi_new = builder.ins().bor(hi_masked, rem_shifted);

        let zero64 = builder.ins().iconst(types::I64, 0);

        let lo_result = builder.ins().select(rt_zero, zero64, lo_new);
        let hi_result = builder.ins().select(rt_zero, zero64, hi_new);

        builder
            .ins()
            .store(MemFlags::trusted(), lo_result, lo_addr, 0);
        builder
            .ins()
            .store(MemFlags::trusted(), hi_result, hi_addr, 0);

        Self::increment_pc(builder, self.pc_ptr as i64);
        *current_pc = current_pc.wrapping_add(4);

        None
    }

    fn mtlo1(
        &mut self,
        builder: &mut FunctionBuilder,
        opcode: u32,
        current_pc: &mut u32,
    ) -> Option<BranchInfo> {
        let rs = ((opcode >> 21) & 0x1F) as i64;

        let rs_addr = Self::ptr_add(builder, self.gpr_ptr as i64, rs, 16);
        let rs_val = builder
            .ins()
            .load(types::I32, MemFlags::trusted(), rs_addr, 0);
        let rs_ext = builder.ins().sextend(types::I64, rs_val);

        let lo_addr = Self::ptr_add(builder, self.lo_ptr as i64, 0, 16);

        let lo_low = builder
            .ins()
            .load(types::I64, MemFlags::trusted(), lo_addr, 0);
        builder.ins().store(MemFlags::trusted(), lo_low, lo_addr, 0);

        builder.ins().store(MemFlags::trusted(), rs_ext, lo_addr, 8);

        Self::increment_pc(builder, self.pc_ptr as i64);
        *current_pc = current_pc.wrapping_add(4);

        None
    }

    fn mflo1(
        &mut self,
        builder: &mut FunctionBuilder,
        opcode: u32,
        current_pc: &mut u32,
    ) -> Option<BranchInfo> {
        let rt = ((opcode >> 11) & 0x1F) as i64;

        let rt_addr = Self::ptr_add(builder, self.gpr_ptr as i64, rt, 16);

        let lo1_addr = Self::ptr_add(builder, self.lo_ptr as i64 + 8, 1, 8);

        let val32 = builder
            .ins()
            .load(types::I32, MemFlags::trusted(), lo1_addr, 0);

        let val64 = builder.ins().uextend(types::I64, val32);

        builder.ins().store(MemFlags::trusted(), val64, rt_addr, 0);

        Self::increment_pc(builder, self.pc_ptr as i64);
        *current_pc = current_pc.wrapping_add(4);

        None
    }

    fn dsrav(
        &mut self,
        builder: &mut FunctionBuilder,
        opcode: u32,
        current_pc: &mut u32,
    ) -> Option<BranchInfo> {
        let rs = ((opcode >> 21) & 0x1F) as i64;
        let rt = ((opcode >> 16) & 0x1F) as i64;
        let rd = ((opcode >> 11) & 0x1F) as i64;

        let rs_addr = Self::ptr_add(builder, self.gpr_ptr as i64, rs, 16);
        let rt_addr = Self::ptr_add(builder, self.gpr_ptr as i64, rt, 16);
        let rd_addr = Self::ptr_add(builder, self.gpr_ptr as i64, rd, 16);

        let rs_val = builder.ins().load(types::I64, MemFlags::new(), rs_addr, 0);
        let rt_val = builder.ins().load(types::I64, MemFlags::new(), rt_addr, 0);

        let sa = builder.ins().band_imm(rs_val, 0x3F);
        let shifted = builder.ins().sshr(rt_val, sa);
        builder.ins().store(MemFlags::new(), shifted, rd_addr, 0);

        Self::increment_pc(builder, self.pc_ptr as i64);
        *current_pc = current_pc.wrapping_add(4);
        None
    }

    fn dsll32(
        &mut self,
        builder: &mut FunctionBuilder,
        opcode: u32,
        current_pc: &mut u32,
    ) -> Option<BranchInfo> {
        let rt = ((opcode >> 16) & 0x1F) as i64;
        let rd = ((opcode >> 11) & 0x1F) as i64;
        let sa = ((opcode >> 6) & 0x1F) as i64;

        let rt_addr = Self::ptr_add(builder, self.gpr_ptr as i64, rt, 16);
        let rd_addr = Self::ptr_add(builder, self.gpr_ptr as i64, rd, 16);

        let rt_val = builder.ins().load(types::I64, MemFlags::new(), rt_addr, 0);
        let shift_amount = sa + 32;
        let shifted = builder.ins().ishl_imm(rt_val, shift_amount);
        builder.ins().store(MemFlags::new(), shifted, rd_addr, 0);

        Self::increment_pc(builder, self.pc_ptr as i64);
        *current_pc = current_pc.wrapping_add(4);
        None
    }

    fn dsra32(
        &mut self,
        builder: &mut FunctionBuilder,
        opcode: u32,
        current_pc: &mut u32,
    ) -> Option<BranchInfo> {
        let rt = ((opcode >> 16) & 0x1F) as i64;
        let rd = ((opcode >> 11) & 0x1F) as i64;
        let sa = ((opcode >> 6) & 0x1F) as i64;

        let rt_addr = Self::ptr_add(builder, self.gpr_ptr as i64, rt, 16);
        let rd_addr = Self::ptr_add(builder, self.gpr_ptr as i64, rd, 16);

        let rt_val = builder.ins().load(types::I64, MemFlags::new(), rt_addr, 0);
        let shift_amount = sa + 32;
        let shifted = builder.ins().sshr_imm(rt_val, shift_amount);
        builder.ins().store(MemFlags::new(), shifted, rd_addr, 0);

        Self::increment_pc(builder, self.pc_ptr as i64);
        *current_pc = current_pc.wrapping_add(4);
        None
    }

    fn xori(
        &mut self,
        builder: &mut FunctionBuilder,
        opcode: u32,
        current_pc: &mut u32,
    ) -> Option<BranchInfo> {
        let rs = ((opcode >> 21) & 0x1F) as i64;
        let rt = ((opcode >> 16) & 0x1F) as i64;
        let imm = (opcode & 0xFFFF) as i64;

        let rs_addr = Self::ptr_add(builder, self.gpr_ptr as i64, rs, 16);
        let rt_addr = Self::ptr_add(builder, self.gpr_ptr as i64, rt, 16);

        let rs_val = builder.ins().load(types::I64, MemFlags::new(), rs_addr, 0);
        let imm_val = builder.ins().iconst(types::I64, imm);
        let result = builder.ins().bxor(rs_val, imm_val);
        builder.ins().store(MemFlags::new(), result, rt_addr, 0);

        Self::increment_pc(builder, self.pc_ptr as i64);
        *current_pc = current_pc.wrapping_add(4);
        None
    }

    fn mult1(
        &mut self,
        builder: &mut FunctionBuilder,
        opcode: u32,
        current_pc: &mut u32,
    ) -> Option<BranchInfo> {
        let rs = ((opcode >> 21) & 0x1F) as i64;
        let rt = ((opcode >> 16) & 0x1F) as i64;
        let rd = ((opcode >> 11) & 0x1F) as i64;

        // Precompute addresses to avoid multiple mutable borrows
        let rs_addr = Self::ptr_add(builder, self.gpr_ptr as i64, rs, 16);
        let rt_addr = Self::ptr_add(builder, self.gpr_ptr as i64, rt, 16);
        let rd_addr = Self::ptr_add(builder, self.gpr_ptr as i64, rd, 16);
        let lo_addr = Self::ptr_add(builder, self.lo_ptr as i64, 1, 4); // Access LO1 (high 32 bits)
        let hi_addr = Self::ptr_add(builder, self.hi_ptr as i64, 1, 4); // Access HI1 (high 32 bits)
        let lo_low_addr = Self::ptr_add(builder, self.lo_ptr as i64, 0, 4); // Access LO0 (low 32 bits)
        let hi_low_addr = Self::ptr_add(builder, self.hi_ptr as i64, 0, 4); // Access HI0 (low 32 bits)

        let rs_val32 = builder
            .ins()
            .load(types::I32, MemFlags::trusted(), rs_addr, 0);
        let rt_val32 = builder
            .ins()
            .load(types::I32, MemFlags::trusted(), rt_addr, 0);
        let rs_val64 = builder.ins().sextend(types::I64, rs_val32);
        let rt_val64 = builder.ins().sextend(types::I64, rt_val32);

        // Check if rs and rt are sign-extended 32-bit values (bits 63..31 must equal bit 31)
        let rs_sign = builder.ins().sshr_imm(rs_val64, 31);
        let rt_sign = builder.ins().sshr_imm(rt_val64, 31);
        let rs_valid = builder.ins().icmp(IntCC::Equal, rs_val64, rs_sign);
        let rt_valid = builder.ins().icmp(IntCC::Equal, rt_val64, rt_sign);
        let inputs_valid = builder.ins().band(rs_valid, rt_valid);

        let valid_block = builder.create_block();
        let invalid_block = builder.create_block();
        let exit_block = builder.create_block();

        builder
            .ins()
            .brif(inputs_valid, valid_block, &[], invalid_block, &[]);
        builder.seal_block(valid_block);
        builder.seal_block(invalid_block);

        // Invalid case: set LO1, HI1, and rd to 0
        builder.switch_to_block(invalid_block);
        let zero32 = builder.ins().iconst(types::I32, 0);
        let lo_old = builder
            .ins()
            .load(types::I32, MemFlags::trusted(), lo_low_addr, 0);
        let hi_old = builder
            .ins()
            .load(types::I32, MemFlags::trusted(), hi_low_addr, 0);
        let low_mask = builder.ins().iconst(types::I32, 0xFFFF_FFFF);
        let lo_masked = builder.ins().band(lo_old, low_mask);
        let hi_masked = builder.ins().band(hi_old, low_mask);
        builder.ins().store(MemFlags::trusted(), zero32, lo_addr, 0);
        builder.ins().store(MemFlags::trusted(), zero32, hi_addr, 0);
        if rd != 0 {
            builder.ins().store(MemFlags::trusted(), zero32, rd_addr, 0);
        }
        builder.ins().jump(exit_block, &[]);

        // Valid case: perform multiplication
        builder.switch_to_block(valid_block);
        let prod = builder.ins().imul(rs_val64, rt_val64);
        let lo32 = builder.ins().ireduce(types::I32, prod);
        let hi_shift = builder.ins().sshr_imm(prod, 32);
        let hi32 = builder.ins().ireduce(types::I32, hi_shift);

        // Store to LO1 (LO[127..64]) and HI1 (HI[127..64])
        builder.ins().store(MemFlags::trusted(), lo32, lo_addr, 0);
        builder.ins().store(MemFlags::trusted(), hi32, hi_addr, 0);

        // Store to rd if not zero
        if rd != 0 {
            builder.ins().store(MemFlags::trusted(), lo32, rd_addr, 0);
        }
        builder.ins().jump(exit_block, &[]);

        // Exit block
        builder.switch_to_block(exit_block);
        builder.seal_block(exit_block);

        Self::increment_pc(builder, self.pc_ptr as i64);
        *current_pc = current_pc.wrapping_add(4);

        None
    }

    fn movz(
        &mut self,
        builder: &mut FunctionBuilder,
        opcode: u32,
        current_pc: &mut u32,
    ) -> Option<BranchInfo> {
        let rs = ((opcode >> 21) & 0x1F) as i64;
        let rt = ((opcode >> 16) & 0x1F) as i64;
        let rd = ((opcode >> 11) & 0x1F) as i64;

        // Precompute addresses to avoid borrow checker issues
        let rs_addr = Self::ptr_add(builder, self.gpr_ptr as i64, rs, 16);
        let rt_addr = Self::ptr_add(builder, self.gpr_ptr as i64, rt, 16);
        let rd_addr = Self::ptr_add(builder, self.gpr_ptr as i64, rd, 16);

        // Load 64-bit values from rs and rt
        let rs_val = builder
            .ins()
            .load(types::I64, MemFlags::trusted(), rs_addr, 0);
        let rt_val = builder
            .ins()
            .load(types::I64, MemFlags::trusted(), rt_addr, 0);

        // Check if rt == 0
        let rt_zero = builder.ins().icmp_imm(IntCC::Equal, rt_val, 0);

        // Conditionally store rs to rd if rt == 0
        if rd != 0 {
            let rd_old = builder
                .ins()
                .load(types::I64, MemFlags::trusted(), rd_addr, 0);
            let rd_new = builder.ins().select(rt_zero, rs_val, rd_old);
            builder.ins().store(MemFlags::trusted(), rd_new, rd_addr, 0);
        }

        Self::increment_pc(builder, self.pc_ptr as i64);
        *current_pc = current_pc.wrapping_add(4);

        None
    }

    fn dsrl(
        &mut self,
        builder: &mut FunctionBuilder,
        opcode: u32,
        current_pc: &mut u32,
    ) -> Option<BranchInfo> {
        let rt = ((opcode >> 16) & 0x1F) as i64;
        let rd = ((opcode >> 11) & 0x1F) as i64;
        let sa = ((opcode >> 6) & 0x1F) as i64;

        let rt_addr = Self::ptr_add(builder, self.gpr_ptr as i64, rt, 16);
        let rd_addr = Self::ptr_add(builder, self.gpr_ptr as i64, rd, 16);

        let value = builder.ins().load(types::I64, MemFlags::new(), rt_addr, 0);
        let shifted = builder.ins().ushr_imm(value, sa);
        builder.ins().store(MemFlags::new(), shifted, rd_addr, 0);

        Self::increment_pc(builder, self.pc_ptr as i64);
        *current_pc = current_pc.wrapping_add(4);
        None
    }

    fn daddiu(
        &mut self,
        builder: &mut FunctionBuilder,
        opcode: u32,
        current_pc: &mut u32,
    ) -> Option<BranchInfo> {
        let rs = ((opcode >> 21) & 0x1F) as i64;
        let rt = ((opcode >> 16) & 0x1F) as i64;
        let imm = (opcode as i16) as i64;

        let rs_addr = Self::ptr_add(builder, self.gpr_ptr as i64, rs, 16);
        let rt_addr = Self::ptr_add(builder, self.gpr_ptr as i64, rt, 16);

        let rs_val = builder.ins().load(types::I64, MemFlags::new(), rs_addr, 0);
        let imm_val = builder.ins().iconst(types::I64, imm);
        let result = builder.ins().iadd(rs_val, imm_val);
        builder.ins().store(MemFlags::new(), result, rt_addr, 0);

        Self::increment_pc(builder, self.pc_ptr as i64);
        *current_pc = current_pc.wrapping_add(4);
        None
    }

    fn dsllv(
        &mut self,
        builder: &mut FunctionBuilder,
        opcode: u32,
        current_pc: &mut u32,
    ) -> Option<BranchInfo> {
        let rs = ((opcode >> 21) & 0x1F) as i64;
        let rt = ((opcode >> 16) & 0x1F) as i64;
        let rd = ((opcode >> 11) & 0x1F) as i64;

        let rs_addr = Self::ptr_add(builder, self.gpr_ptr as i64, rs, 16);
        let rt_addr = Self::ptr_add(builder, self.gpr_ptr as i64, rt, 16);
        let rd_addr = Self::ptr_add(builder, self.gpr_ptr as i64, rd, 16);

        let rs_val = builder.ins().load(types::I64, MemFlags::new(), rs_addr, 0);
        let sa = builder.ins().band_imm(rs_val, 0x3F);
        let value = builder.ins().load(types::I64, MemFlags::new(), rt_addr, 0);
        let shifted = builder.ins().ishl(value, sa);
        builder.ins().store(MemFlags::new(), shifted, rd_addr, 0);

        Self::increment_pc(builder, self.pc_ptr as i64);
        *current_pc = current_pc.wrapping_add(4);
        None
    }

    fn lq(
        &mut self,
        builder: &mut FunctionBuilder,
        opcode: u32,
        current_pc: &mut u32,
    ) -> Option<BranchInfo> {
        let base = ((opcode >> 21) & 0x1F) as i64;
        let rt = ((opcode >> 16) & 0x1F) as i64;
        let offset = (opcode as i16) as i64;

        let base_addr = Self::ptr_add(builder, self.gpr_ptr as i64, base, 16);
        let base_val = builder
            .ins()
            .load(types::I32, MemFlags::new(), base_addr, 0);
        let vaddr = builder.ins().iadd_imm(base_val, offset);
        let aligned_addr = builder.ins().band_imm(vaddr, !0xF);

        let bus = self.cpu.bus.lock().unwrap();
        let bus_ptr: *mut Bus = &**bus as *const Bus as *mut Bus;
        let bus_value = builder.ins().iconst(types::I64, bus_ptr as i64);
        let bus_read128_callee = self
            .module
            .declare_func_in_func(self.bus_read128_func, builder.func);

        let call = builder
            .ins()
            .call(bus_read128_callee, &[bus_value, aligned_addr]);
        let value = builder.inst_results(call)[0];

        let rt_addr = Self::ptr_add(builder, self.gpr_ptr as i64, rt, 16);
        builder.ins().store(MemFlags::new(), value, rt_addr, 0);

        Self::increment_pc(builder, self.pc_ptr as i64);
        *current_pc = current_pc.wrapping_add(4);
        None
    }

    fn sq(
        &mut self,
        builder: &mut FunctionBuilder,
        opcode: u32,
        current_pc: &mut u32,
    ) -> Option<BranchInfo> {
        let base = ((opcode >> 21) & 0x1F) as i64;
        let rt = ((opcode >> 16) & 0x1F) as i64;
        let offset = (opcode as i16) as i64;

        let base_addr = Self::ptr_add(builder, self.gpr_ptr as i64, base, 16);
        let base_val = builder
            .ins()
            .load(types::I32, MemFlags::new(), base_addr, 0);
        let vaddr = builder.ins().iadd_imm(base_val, offset);
        let aligned_addr = builder.ins().band_imm(vaddr, !0xF);

        let rt_addr = Self::ptr_add(builder, self.gpr_ptr as i64, rt, 16);
        let value = builder.ins().load(types::I128, MemFlags::new(), rt_addr, 0);

        let bus = self.cpu.bus.lock().unwrap();
        let bus_ptr: *mut Bus = &**bus as *const Bus as *mut Bus;
        let bus_value = builder.ins().iconst(types::I64, bus_ptr as i64);
        let bus_write128_callee = self
            .module
            .declare_func_in_func(self.bus_write128_func, builder.func);

        builder
            .ins()
            .call(bus_write128_callee, &[bus_value, aligned_addr, value]);

        Self::increment_pc(builder, self.pc_ptr as i64);
        *current_pc = current_pc.wrapping_add(4);
        None
    }

    fn lh(
        &mut self,
        builder: &mut FunctionBuilder,
        opcode: u32,
        current_pc: &mut u32,
    ) -> Option<BranchInfo> {
        let base_idx = ((opcode >> 21) & 0x1F) as usize;
        let rt_idx = ((opcode >> 16) & 0x1F) as usize;
        let imm_i64 = (opcode as i16) as i64;

        let base = base_idx as i64;
        let rt = rt_idx as i64;

        let base_addr = Self::ptr_add(builder, self.gpr_ptr as i64, base, 16);
        let base_val = Self::load32(builder, base_addr);

        let addr = builder.ins().iadd_imm(base_val, imm_i64);

        let bus = self.cpu.bus.lock().unwrap();
        let bus_ptr: *mut Bus = &**bus as *const Bus as *mut Bus;
        let bus_value = builder.ins().iconst(types::I64, bus_ptr as i64);
        let bus_read_callee = self
            .module
            .declare_func_in_func(self.bus_read16_func, builder.func);
        let call_inst = builder.ins().call(bus_read_callee, &[bus_value, addr]);
        let load_val = builder.inst_results(call_inst)[0];

        let load_val_i64 = builder.ins().sextend(types::I64, load_val);

        let rt_addr = Self::ptr_add(builder, self.gpr_ptr as i64, rt, 16);
        builder
            .ins()
            .store(MemFlags::new(), load_val_i64, rt_addr, 0);

        Self::increment_pc(builder, self.pc_ptr as i64);
        *current_pc = current_pc.wrapping_add(4);
        None
    }

    fn cache(
        &mut self,
        builder: &mut FunctionBuilder,
        _opcode: u32,
        current_pc: &mut u32,
    ) -> Option<BranchInfo> {
        // TODO: Implement CACHE instruction properly
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
