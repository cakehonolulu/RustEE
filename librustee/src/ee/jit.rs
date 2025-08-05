use crate::Bus;
use crate::bus::tlb::TlbEntry;
use crate::cpu::{CPU, EmulationBackend};
use crate::ee::EE;
use cranelift_codegen::ir::condcodes::IntCC;
use cranelift_codegen::ir::{types, AbiParam, BlockArg, InstBuilder, MemFlags, StackSlotData, StackSlotKind, Value};
use cranelift_codegen::settings::Configurable;
use cranelift_codegen::{isa, settings};
use cranelift_frontend::{FunctionBuilder, FunctionBuilderContext};
use cranelift_jit::{JITBuilder, JITModule};
use cranelift_module::{FuncId, Linkage, Module, default_libcall_names};
use lru::LruCache;
use std::collections::HashMap;
use std::fs;
use std::num::NonZero;
use std::sync::{Arc, Mutex};
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

pub struct JIT {
    pub cpu: EE,
    module: JITModule,
    blocks: LruCache<u32, Block>,
    compiled_funcs: HashMap<u32, FuncId>,
    max_blocks: usize,
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
    load_elf_func: FuncId,
}

pub enum BranchTarget {
    Const(u32),
    Reg(Value),
}

enum BranchInfo {
    Conditional { cond: Value, target: BranchTarget },
    Unconditional { target: BranchTarget },
    ConditionalLikely { cond: Value, target: BranchTarget },
    Eret { target: BranchTarget },
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

pub extern "C" fn __bus_write8(bus: *mut Bus, addr: u32, value: u8) {
    unsafe {
        ((*bus).write8)(&mut *bus, addr, value);
    }
}

pub extern "C" fn __bus_write16(bus: *mut Bus, addr: u32, value: u16) {
    unsafe {
        ((*bus).write16)(&mut *bus, addr, value);
    }
}

pub extern "C" fn __bus_write32(bus: *mut Bus, addr: u32, value: u32) {
    unsafe {
        ((*bus).write32)(&mut *bus, addr, value);
    }
}

pub extern "C" fn __bus_write64(bus: *mut Bus, addr: u32, value: u64) {
    unsafe {
        ((*bus).write64)(&mut *bus, addr, value);
    }
}

pub extern "C" fn __bus_write128(bus: *mut Bus, addr: u32, lo: u64, hi: u64) {
    let value = (hi as u128) << 64 | (lo as u128);
    unsafe {
        ((*bus).write128)(&mut *bus, addr, value);
    }
}

pub extern "C" fn __bus_read8(bus: *mut Bus, addr: u32) -> u8 {
    unsafe { ((*bus).read8)(&mut *bus, addr) }
}

pub extern "C" fn __bus_read16(bus: *mut Bus, addr: u32) -> u16 {
    unsafe { ((*bus).read16)(&mut *bus, addr) }
}

pub extern "C" fn __bus_read32(bus: *mut Bus, addr: u32) -> u32 {
    unsafe { ((*bus).read32)(&mut *bus, addr) }
}

pub extern "C" fn __bus_read64(bus: *mut Bus, addr: u32) -> u64 {
    unsafe { ((*bus).read64)(&mut *bus, addr) }
}

pub extern "C" fn __bus_read128(bus: *mut Bus, addr: u32, lo: *mut u64, hi: *mut u64) {
    let value: u128 = unsafe { ((*bus).read128)(&mut *bus, addr) };
    unsafe {
        *lo = value as u64;
        *hi = (value >> 64) as u64;
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

pub extern "C" fn __load_elf(cpu_ptr: *mut EE) {
    unsafe {
        let cpu = &mut *cpu_ptr;
        let elf_bytes = fs::read(&cpu.elf_path)
            .unwrap_or_else(|e| panic!("Failed to read ELF '{}': {}", cpu.elf_path, e));
        cpu.load_elf(&elf_bytes);
    }
}

impl JIT {
    pub fn new(mut cpu: EE) -> Self {
        let mut shared_builder = settings::builder();
        shared_builder
            .set("enable_llvm_abi_extensions", "true")
            .expect("unknown setting");
        let shared_flags = settings::Flags::new(shared_builder);

        let isa_builder = isa::lookup(Triple::host()).expect("host ISA not available");
        let isa = isa_builder.finish(shared_flags);

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

        builder.symbol("__bus_read128", __bus_read128 as *const u8);

        builder.symbol("__bus_tlbwi", __bus_tlbwi as *const u8);

        builder.symbol("__read_cop0", __read_cop0 as *const u8);

        builder.symbol("__write_cop0", __write_cop0 as *const u8);

        builder.symbol("__load_elf", __load_elf as *const u8);

        let mut module = JITModule::new(builder);

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
        store128_sig.params.push(AbiParam::new(types::I64)); // Pointer to Bus
        store128_sig.params.push(AbiParam::new(types::I32)); // Address
        store128_sig.params.push(AbiParam::new(types::I64)); // Low 64 bits
        store128_sig.params.push(AbiParam::new(types::I64)); // High 64 bits
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
        load128_sig.params.push(AbiParam::new(types::I64));
        load128_sig.params.push(AbiParam::new(types::I64));
        let bus_read128_func = module
            .declare_function("__bus_read128", Linkage::Import, &load128_sig)
            .expect("Failed to declare __bus_read128");

        let mut tlbwi_sig = module.make_signature();
        tlbwi_sig.params.push(AbiParam::new(types::I64));
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

        let mut load_elf_sig = module.make_signature();
        load_elf_sig.params.push(AbiParam::new(types::I64)); // cpu_ptr
        let load_elf_func = module
            .declare_function("__load_elf", Linkage::Import, &load_elf_sig)
            .expect("Failed to declare __load_elf");

        JIT {
            cpu,
            module,
            blocks: LruCache::new(MAX_BLOCKS),
            compiled_funcs: HashMap::new(),
            max_blocks: MAX_BLOCKS.into(),
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
            load_elf_func,
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
        };

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
        let pc_addr = builder
            .ins()
            .iconst(types::I64, &mut self.cpu.pc as *mut u32 as i64);

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
                    BranchInfo::Eret { target } => {
                        JIT::set_pc_to_target(&mut builder, target, pc_addr);
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
                builder.ins().store(MemFlags::new(), val, pc_addr, 0);
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
                    0x04 => self.sllv(builder, opcode, current_pc),
                    0x06 => self.srlv(builder, opcode, current_pc),
                    0x07 => self.srav(builder, opcode, current_pc),
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
                    0x27 => self.nor(builder, opcode, current_pc),
                    0x2A => self.slt(builder, opcode, current_pc),
                    0x2B => self.sltu(builder, opcode, current_pc),
                    0x2D => self.daddu(builder, opcode, current_pc),
                    0x38 => self.dsll(builder, opcode, current_pc),
                    0x3A => self.dsrl(builder, opcode, current_pc),
                    0x3C => self.dsll32(builder, opcode, current_pc),
                    0x3E => self.dsrl32(builder, opcode, current_pc),
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
                    0x10 => {
                        let funct = opcode & 0x3F;

                        match funct {
                            0x2 => self.tlbwi(builder, current_pc),
                            0x18 => self.eret(builder, opcode, current_pc),
                            0x39 => self.di(builder, opcode, current_pc),
                            _ => panic!(
                                "Unhandled EE JIT C0 opcode: 0x{:08X} (Subfunction 0x{:02X}), PC: 0x{:08X}",
                                opcode,
                                funct,
                                self.cpu.pc()
                            ),
                        }
                    }
                    _ => {
                        error!(
                            "Unhandled EE JIT COP0 opcode: 0x{:08X} (Subfunction 0x{:02X}), PC: 0x{:08X}",
                            opcode, subfunction, current_pc
                        );
                        panic!();
                    }
                }
            }
            0x11 => {
                // COP1
                Self::increment_pc(builder, &mut self.cpu.pc as *mut u32 as i64);
                *current_pc = current_pc.wrapping_add(4);

                None
            }
            0x12 => {
                let subfunction = (opcode >> 21) & 0x1F;
                match subfunction {
                    0x02 => self.cfc2(builder, opcode, current_pc),
                    0x06 => self.ctc2(builder, opcode, current_pc),
                    0x18 => {
                        // TODO: viswr.x
                        Self::increment_pc(builder, &mut self.cpu.pc as *mut u32 as i64);
                        *current_pc = current_pc.wrapping_add(4);

                        None
                    }
                    _ => {
                        //
                        Self::increment_pc(builder, &mut self.cpu.pc as *mut u32 as i64);
                        *current_pc = current_pc.wrapping_add(4);

                        None
                    }
                }
            }
            0x14 => self.beql(builder, opcode, current_pc),
            0x15 => self.bnel(builder, opcode, current_pc),
            0x19 => self.daddiu(builder, opcode, current_pc),
            0x1A => self.ldl(builder, opcode, current_pc),
            0x1B => self.ldr(builder, opcode, current_pc),
            0x1C => {
                let subfunction = opcode & 0x3F;

                match subfunction {
                    0x12 => self.mflo1(builder, opcode, current_pc),
                    0x18 => self.mult1(builder, opcode, current_pc),
                    0x1B => self.divu1(builder, opcode, current_pc),
                    0x28 => {
                        let mmi1_function = (opcode >> 6) & 0x1F;

                        match mmi1_function {
                            0x10 => self.padduw(builder, opcode, current_pc),
                            _ => {
                                panic!(
                                    "Unimplemented MMI1 instruction with funct: 0x{:02X}, PC: 0x{:08X}",
                                    mmi1_function, current_pc
                                );
                            }
                        }
                    }
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
            0x27 => self.lwu(builder, opcode, current_pc),
            0x28 => self.sb(builder, opcode, current_pc),
            0x29 => self.sh(builder, opcode, current_pc),
            0x2B => self.sw(builder, opcode, current_pc),
            0x2C => self.sdl(builder, opcode, current_pc),
            0x2D => self.sdr(builder, opcode, current_pc),
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

        let gpr_addr = Self::ptr_add(builder, self.cpu.registers.as_mut_ptr() as i64, rt, 16);

        let cpu_ptr = &mut self.cpu as *mut EE as i64;
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

        Self::increment_pc(builder, &mut self.cpu.pc as *mut u32 as i64);
        *current_pc = current_pc.wrapping_add(4);

        None
    }

    fn sll(
        &mut self,
        builder: &mut FunctionBuilder,
        opcode: u32,
        current_pc: &mut u32,
    ) -> Option<BranchInfo> {
        let rt = ((opcode >> 16) & 0x1F) as i64;
        let rd = ((opcode >> 11) & 0x1F) as i64;
        let sa = (opcode >> 6) & 0x1F;

        let rt_addr = Self::ptr_add(builder, self.cpu.registers.as_mut_ptr() as i64, rt, 16);
        let rt_val64 = builder.ins().load(types::I64, MemFlags::new(), rt_addr, 0);
        let rt_lo32 = builder.ins().ireduce(types::I32, rt_val64);
        let shifted = builder.ins().ishl_imm(rt_lo32, sa as i64);
        let result64 = builder.ins().sextend(types::I64, shifted);

        let rd_addr = Self::ptr_add(builder, self.cpu.registers.as_mut_ptr() as i64, rd, 16);
        builder.ins().store(MemFlags::new(), result64, rd_addr, 0);

        Self::increment_pc(builder, &mut self.cpu.pc as *mut u32 as i64);
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

        let rs_addr = Self::ptr_add(builder, self.cpu.registers.as_mut_ptr() as i64, rs, 16);
        let rs_val64 = builder.ins().load(types::I64, MemFlags::new(), rs_addr, 0);
        let rs_lo32 = builder.ins().ireduce(types::I32, rs_val64);
        let rs_sext = builder.ins().sextend(types::I64, rs_lo32);

        let imm_val = builder.ins().iconst(types::I64, imm);

        let cmp = builder.ins().icmp(IntCC::SignedLessThan, rs_sext, imm_val);

        let one = builder.ins().iconst(types::I64, 1);
        let zero = builder.ins().iconst(types::I64, 0);
        let out64 = builder.ins().select(cmp, one, zero);

        let rt_addr = Self::ptr_add(builder, self.cpu.registers.as_mut_ptr() as i64, rt, 16);
        builder.ins().store(MemFlags::new(), out64, rt_addr, 0);

        Self::increment_pc(builder, &mut self.cpu.pc as *mut u32 as i64);
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
        let value = imm << 16;

        let result64 = builder.ins().iconst(types::I64, value);

        let rt_addr = Self::ptr_add(builder, self.cpu.registers.as_mut_ptr() as i64, rt, 16);
        builder.ins().store(MemFlags::new(), result64, rt_addr, 0);

        Self::increment_pc(builder, &mut self.cpu.pc as *mut u32 as i64);
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

        let rs_addr = Self::ptr_add(builder, self.cpu.registers.as_mut_ptr() as i64, rs, 16);
        let rs_val64 = builder.ins().load(types::I64, MemFlags::new(), rs_addr, 0);
        let rs_lo32 = builder.ins().ireduce(types::I32, rs_val64);

        let imm32 = builder.ins().iconst(types::I32, imm);

        let or32 = builder.ins().bor(rs_lo32, imm32);
        let result64 = builder.ins().uextend(types::I64, or32);

        let rt_addr = Self::ptr_add(builder, self.cpu.registers.as_mut_ptr() as i64, rt, 16);
        builder.ins().store(MemFlags::new(), result64, rt_addr, 0);

        Self::increment_pc(builder, &mut self.cpu.pc as *mut u32 as i64);
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

        let gpr_addr = Self::ptr_add(builder, self.cpu.registers.as_mut_ptr() as i64, rt, 16);

        let cpu_ptr = &mut self.cpu as *mut EE as i64;
        let cpu_arg = builder.ins().iconst(types::I64, cpu_ptr);
        let rd_arg = builder.ins().iconst(types::I32, rd);
        let gpr_val = Self::load32(builder, gpr_addr);

        let callee = self
            .module
            .declare_func_in_func(self.write_cop0_func, builder.func);
        builder.ins().call(callee, &[cpu_arg, rd_arg, gpr_val]);

        Self::increment_pc(builder, &mut self.cpu.pc as *mut u32 as i64);
        *current_pc = current_pc.wrapping_add(4);
        None
    }

    fn sync(
        &mut self,
        builder: &mut FunctionBuilder,
        _opcode: u32,
        current_pc: &mut u32,
    ) -> Option<BranchInfo> {
        Self::increment_pc(builder, &mut self.cpu.pc as *mut u32 as i64);
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

        let rs_addr = Self::ptr_add(builder, self.cpu.registers.as_mut_ptr() as i64, rs, 16);
        let rs_val64 = builder.ins().load(types::I64, MemFlags::new(), rs_addr, 0);
        let rs_lo32 = builder.ins().ireduce(types::I32, rs_val64);

        let sum32 = builder.ins().iadd_imm(rs_lo32, imm);

        let result64 = builder.ins().uextend(types::I64, sum32);

        let rt_addr = Self::ptr_add(builder, self.cpu.registers.as_mut_ptr() as i64, rt, 16);
        builder.ins().store(MemFlags::new(), result64, rt_addr, 0);

        Self::increment_pc(builder, &mut self.cpu.pc as *mut u32 as i64);
        *current_pc = current_pc.wrapping_add(4);

        None
    }

    fn sw(
        &mut self,
        builder: &mut FunctionBuilder,
        opcode: u32,
        current_pc: &mut u32,
    ) -> Option<BranchInfo> {
        let rs = ((opcode >> 21) & 0x1F) as i64;
        let rt = ((opcode >> 16) & 0x1F) as i64;
        let imm = (opcode as i16) as i64;

        let rs_addr = Self::ptr_add(builder, self.cpu.registers.as_mut_ptr() as i64, rs, 16);
        let rs_val64 = builder.ins().load(types::I64, MemFlags::new(), rs_addr, 0);
        let rs_lo32 = builder.ins().ireduce(types::I32, rs_val64);
        let base64 = builder.ins().sextend(types::I64, rs_lo32);

        let addr64 = builder.ins().iadd_imm(base64, imm);

        let addr32 = builder.ins().ireduce(types::I32, addr64);

        let rt_addr = Self::ptr_add(builder, self.cpu.registers.as_mut_ptr() as i64, rt, 16);
        let store_val64 = builder.ins().load(types::I64, MemFlags::new(), rt_addr, 0);
        let store_val32 = builder.ins().ireduce(types::I32, store_val64);

        let bus = self.cpu.bus.lock().unwrap();
        let bus_ptr = &**bus as *const Bus as *mut Bus;
        let bus_arg = builder.ins().iconst(types::I64, bus_ptr as i64);

        let callee = self
            .module
            .declare_func_in_func(self.bus_write32_func, builder.func);
        builder.ins().call(callee, &[bus_arg, addr32, store_val32]);

        Self::increment_pc(builder, &mut self.cpu.pc as *mut u32 as i64);
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

        Self::increment_pc(builder, &mut self.cpu.pc as *mut u32 as i64);
        *current_pc = current_pc.wrapping_add(4);
        None
    }

    fn lw(
        &mut self,
        builder: &mut FunctionBuilder,
        opcode: u32,
        current_pc: &mut u32,
    ) -> Option<BranchInfo> {
        let rs = ((opcode >> 21) & 0x1F) as i64;
        let rt = ((opcode >> 16) & 0x1F) as i64;
        let imm = (opcode as i16) as i64;

        let rs_addr = Self::ptr_add(builder, self.cpu.registers.as_mut_ptr() as i64, rs, 16);
        let rs_val64 = builder.ins().load(types::I64, MemFlags::new(), rs_addr, 0);
        let rs_lo32 = builder.ins().ireduce(types::I32, rs_val64);
        let base64 = builder.ins().sextend(types::I64, rs_lo32);

        let addr64 = builder.ins().iadd_imm(base64, imm);

        let addr32 = builder.ins().ireduce(types::I32, addr64);

        let bus = self.cpu.bus.lock().unwrap();
        let bus_ptr = &**bus as *const Bus as *mut Bus;
        let bus_arg = builder.ins().iconst(types::I64, bus_ptr as i64);

        let callee = self
            .module
            .declare_func_in_func(self.bus_read32_func, builder.func);
        let call = builder.ins().call(callee, &[bus_arg, addr32]);
        let loaded32 = builder.inst_results(call)[0];

        let loaded64 = builder.ins().uextend(types::I64, loaded32);

        let rt_addr = Self::ptr_add(builder, self.cpu.registers.as_mut_ptr() as i64, rt, 16);
        builder.ins().store(MemFlags::new(), loaded64, rt_addr, 0);

        Self::increment_pc(builder, &mut self.cpu.pc as *mut u32 as i64);
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
        let raddr = Self::ptr_add(builder, self.cpu.registers.as_mut_ptr() as i64, rs, 16);
        let taddr = Self::ptr_add(builder, self.cpu.registers.as_mut_ptr() as i64, rt, 16);
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
        let addr = Self::ptr_add(builder, self.cpu.registers.as_mut_ptr() as i64, rs, 16);
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

        let rs_addr = Self::ptr_add(builder, self.cpu.registers.as_mut_ptr() as i64, rs, 16);
        let rd_addr = Self::ptr_add(builder, self.cpu.registers.as_mut_ptr() as i64, rd, 16);

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

        let base_addr = Self::ptr_add(builder, self.cpu.registers.as_mut_ptr() as i64, base, 16);
        let base_val = Self::load64(builder, base_addr);

        let addr = builder.ins().iadd_imm(base_val, imm);

        let addr32 = builder.ins().ireduce(types::I32, addr);

        let rt_addr = Self::ptr_add(builder, self.cpu.registers.as_mut_ptr() as i64, rt, 16);
        let store_val = builder.ins().load(types::I64, MemFlags::new(), rt_addr, 0);

        let bus = self.cpu.bus.lock().unwrap();
        let bus_ptr: *mut Bus = &**bus as *const Bus as *mut Bus;
        let bus_value = builder.ins().iconst(types::I64, bus_ptr as i64);

        let callee = self
            .module
            .declare_func_in_func(self.bus_write64_func, builder.func);
        builder.ins().call(callee, &[bus_value, addr32, store_val]);

        Self::increment_pc(builder, &mut self.cpu.pc as *mut u32 as i64);
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

        let rs_addr = Self::ptr_add(builder, self.cpu.registers.as_mut_ptr() as i64, rs, 16);
        let rs_val = builder.ins().load(types::I64, MemFlags::new(), rs_addr, 0);

        let rt_addr = Self::ptr_add(builder, self.cpu.registers.as_mut_ptr() as i64, rt, 16);
        let rt_val = builder.ins().load(types::I64, MemFlags::new(), rt_addr, 0);

        let sum = builder.ins().iadd(rs_val, rt_val);

        let rd_addr = Self::ptr_add(builder, self.cpu.registers.as_mut_ptr() as i64, rd, 16);
        builder.ins().store(MemFlags::new(), sum, rd_addr, 0);

        Self::increment_pc(builder, &mut self.cpu.pc as *mut u32 as i64);
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

        let ra_addr = Self::ptr_add(builder, self.cpu.registers.as_mut_ptr() as i64, 31, 16);
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

        let rs_addr = Self::ptr_add(builder, self.cpu.registers.as_mut_ptr() as i64, rs, 16);
        let rs_val = builder.ins().load(types::I64, MemFlags::new(), rs_addr, 0);

        let imm_val = builder.ins().iconst(types::I64, imm);
        let result = builder.ins().band(rs_val, imm_val);

        let rt_addr = Self::ptr_add(builder, self.cpu.registers.as_mut_ptr() as i64, rt, 16);
        builder.ins().store(MemFlags::new(), result, rt_addr, 0);

        Self::increment_pc(builder, &mut self.cpu.pc as *mut u32 as i64);
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

        let rs_addr = Self::ptr_add(builder, self.cpu.registers.as_mut_ptr() as i64, rs, 16);
        let rt_addr = Self::ptr_add(builder, self.cpu.registers.as_mut_ptr() as i64, rt, 16);

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

        let rs_addr = Self::ptr_add(builder, self.cpu.registers.as_mut_ptr() as i64, rs, 16);
        let rs_val = builder.ins().load(types::I64, MemFlags::new(), rs_addr, 0);

        let rt_addr = Self::ptr_add(builder, self.cpu.registers.as_mut_ptr() as i64, rt, 16);
        let rt_val = builder.ins().load(types::I64, MemFlags::new(), rt_addr, 0);

        let result = builder.ins().bor(rs_val, rt_val);

        let rd_addr = Self::ptr_add(builder, self.cpu.registers.as_mut_ptr() as i64, rd, 16);
        builder.ins().store(MemFlags::new(), result, rd_addr, 0);

        Self::increment_pc(builder, &mut self.cpu.pc as *mut u32 as i64);
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

        let rs_addr = Self::ptr_add(builder, self.cpu.registers.as_mut_ptr() as i64, rs, 16);
        let rs_val32 = builder.ins().load(types::I32, MemFlags::new(), rs_addr, 0);
        let rs_val64 = builder.ins().sextend(types::I64, rs_val32);

        let rt_addr = Self::ptr_add(builder, self.cpu.registers.as_mut_ptr() as i64, rt, 16);
        let rt_val32 = builder.ins().load(types::I32, MemFlags::new(), rt_addr, 0);
        let rt_val64 = builder.ins().sextend(types::I64, rt_val32);

        let prod = builder.ins().imul(rs_val64, rt_val64);

        let lo32 = builder.ins().ireduce(types::I32, prod);
        let shift32 = builder.ins().iconst(types::I64, 32);
        let hi32 = builder.ins().sshr(prod, shift32);
        let hi32_32 = builder.ins().ireduce(types::I32, hi32);

        let lo_val = builder.ins().uextend(types::I64, lo32);
        let hi_val = builder.ins().uextend(types::I64, hi32_32);

        let lo_addr = Self::ptr_add(builder, &mut self.cpu.lo as *mut u128 as i64, 0, 16);
        let hi_addr = Self::ptr_add(builder, &mut self.cpu.hi as *mut u128 as i64, 0, 16);
        builder.ins().store(MemFlags::new(), lo_val, lo_addr, 0);
        builder.ins().store(MemFlags::new(), hi_val, hi_addr, 0);

        let rd_val = builder.ins().iconst(types::I64, rd);
        let rd_nonzero = builder.ins().icmp_imm(IntCC::NotEqual, rd_val, 0);
        let rd_addr = Self::ptr_add(builder, self.cpu.registers.as_mut_ptr() as i64, rd, 16);
        let lo64 = builder.ins().uextend(types::I64, lo32);
        let current_rd = builder.ins().load(types::I64, MemFlags::new(), rd_addr, 0);
        let rd_final = builder.ins().select(rd_nonzero, lo64, current_rd);
        builder.ins().store(MemFlags::new(), rd_final, rd_addr, 0);

        Self::increment_pc(builder, &mut self.cpu.pc as *mut u32 as i64);
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

        let rs_addr = Self::ptr_add(builder, self.cpu.registers.as_mut_ptr() as i64, rs, 16);
        let rs_val32 = builder.ins().load(types::I32, MemFlags::new(), rs_addr, 0);
        let rs_val64 = builder.ins().uextend(types::I64, rs_val32);

        let rt_addr = Self::ptr_add(builder, self.cpu.registers.as_mut_ptr() as i64, rt, 16);
        let rt_val32 = builder.ins().load(types::I32, MemFlags::new(), rt_addr, 0);
        let rt_val64 = builder.ins().uextend(types::I64, rt_val32);

        let rt_zero = builder.ins().icmp_imm(IntCC::Equal, rt_val64, 0);

        let quot64 = builder.ins().udiv(rs_val64, rt_val64);
        let rem64 = builder.ins().urem(rs_val64, rt_val64);

        let quot32 = builder.ins().ireduce(types::I32, quot64);
        let rem32 = builder.ins().ireduce(types::I32, rem64);

        let quot_final = builder.ins().uextend(types::I64, quot32);
        let rem_final = builder.ins().uextend(types::I64, rem32);

        let zero64 = builder.ins().iconst(types::I64, 0);
        let quot_store = builder.ins().select(rt_zero, zero64, quot_final);
        let rem_store = builder.ins().select(rt_zero, zero64, rem_final);

        let lo_addr = Self::ptr_add(builder, &mut self.cpu.lo as *mut u128 as i64, 0, 16);
        let hi_addr = Self::ptr_add(builder, &mut self.cpu.hi as *mut u128 as i64, 0, 16);
        builder.ins().store(MemFlags::new(), quot_store, lo_addr, 0);
        builder.ins().store(MemFlags::new(), rem_store, hi_addr, 0);

        Self::increment_pc(builder, &mut self.cpu.pc as *mut u32 as i64);
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

        let rs_addr = Self::ptr_add(builder, self.cpu.registers.as_mut_ptr() as i64, rs, 16);
        let rt_addr = Self::ptr_add(builder, self.cpu.registers.as_mut_ptr() as i64, rt, 16);

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
        let cpu_ptr = &mut self.cpu as *mut EE as i64;
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

        let rd_addr = Self::ptr_add(builder, self.cpu.registers.as_mut_ptr() as i64, rd, 16);

        let lo_ptr_val = builder
            .ins()
            .iconst(types::I64, &mut self.cpu.lo as *mut u128 as i64);
        let lo_val = builder
            .ins()
            .load(types::I128, MemFlags::new(), lo_ptr_val, 0);

        let lo_val_64 = builder.ins().ireduce(types::I64, lo_val);

        builder.ins().store(MemFlags::new(), lo_val_64, rd_addr, 0);

        Self::increment_pc(builder, &mut self.cpu.pc as *mut u32 as i64);
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
        let imm = (opcode as i16) as u64;

        let rs_addr = Self::ptr_add(builder, self.cpu.registers.as_mut_ptr() as i64, rs, 16);
        let rs_val = Self::load64(builder, rs_addr);

        let imm_val = builder.ins().iconst(types::I64, imm as i64);

        let cmp = builder.ins().icmp(IntCC::UnsignedLessThan, rs_val, imm_val);

        let one = builder.ins().iconst(types::I64, 1);
        let zero = builder.ins().iconst(types::I64, 0);
        let out64 = builder.ins().select(cmp, one, zero);

        let rt_addr = Self::ptr_add(builder, self.cpu.registers.as_mut_ptr() as i64, rt, 16);
        builder.ins().store(MemFlags::new(), out64, rt_addr, 0);

        Self::increment_pc(builder, &mut self.cpu.pc as *mut u32 as i64);
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

        let rs_addr = Self::ptr_add(builder, self.cpu.registers.as_mut_ptr() as i64, rs, 16);
        let rt_addr = Self::ptr_add(builder, self.cpu.registers.as_mut_ptr() as i64, rt, 16);

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
        let rs = ((opcode >> 21) & 0x1F) as i64;
        let rt = ((opcode >> 16) & 0x1F) as i64;
        let imm = (opcode as i16) as i64;

        let rs_addr = Self::ptr_add(builder, self.cpu.registers.as_mut_ptr() as i64, rs, 16);
        let rs_val = builder.ins().load(types::I32, MemFlags::new(), rs_addr, 0);
        let rs_sext = builder.ins().sextend(types::I64, rs_val);

        let addr = builder.ins().iadd_imm(rs_sext, imm);

        let bus = self.cpu.bus.lock().unwrap();
        let bus_ptr: *mut Bus = &**bus as *const Bus as *mut Bus;
        let bus_value = builder.ins().iconst(types::I64, bus_ptr as i64);

        let callee = self
            .module
            .declare_func_in_func(self.bus_read8_func, builder.func);

        let addr_i32 = builder.ins().ireduce(types::I32, addr);
        let call = builder.ins().call(callee, &[bus_value, addr_i32]);
        let byte_val = builder.inst_results(call)[0];

        let sext_val = builder.ins().sextend(types::I64, byte_val);

        let rt_addr = Self::ptr_add(builder, self.cpu.registers.as_mut_ptr() as i64, rt, 16);
        builder.ins().store(MemFlags::new(), sext_val, rt_addr, 0);

        Self::increment_pc(builder, &mut self.cpu.pc as *mut u32 as i64);
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

        let base_addr = Self::ptr_add(builder, self.cpu.registers.as_mut_ptr() as i64, base, 16);
        let base_val = Self::load32(builder, base_addr);

        let addr = builder.ins().iadd_imm(base_val, imm);

        let ft_addr = Self::ptr_add(builder, self.cpu.fpu_registers.as_mut_ptr() as i64, ft, 4);
        let fpu_val = Self::load32(builder, ft_addr);

        let bus = self.cpu.bus.lock().unwrap();
        let bus_ptr: *mut Bus = &**bus as *const Bus as *mut Bus;
        let bus_value = builder.ins().iconst(types::I64, bus_ptr as i64);

        let callee = self
            .module
            .declare_func_in_func(self.bus_write32_func, builder.func);
        builder.ins().call(callee, &[bus_value, addr, fpu_val]);

        Self::increment_pc(builder, &mut self.cpu.pc as *mut u32 as i64);
        *current_pc = current_pc.wrapping_add(4);

        None
    }

    fn lbu(
        &mut self,
        builder: &mut FunctionBuilder,
        opcode: u32,
        current_pc: &mut u32,
    ) -> Option<BranchInfo> {
        let rs = ((opcode >> 21) & 0x1F) as i64;
        let rt = ((opcode >> 16) & 0x1F) as i64;
        let imm = (opcode as i16) as i64;

        let rs_addr = Self::ptr_add(builder, self.cpu.registers.as_mut_ptr() as i64, rs, 16);
        let rs_val = Self::load32(builder, rs_addr);
        let addr = builder.ins().iadd_imm(rs_val, imm);

        let bus = self.cpu.bus.lock().unwrap();
        let bus_ptr: *mut Bus = &**bus as *const Bus as *mut Bus;
        let bus_val = builder.ins().iconst(types::I64, bus_ptr as i64);

        let callee = self
            .module
            .declare_func_in_func(self.bus_read8_func, builder.func);

        let call = builder.ins().call(callee, &[bus_val, addr]);
        let loaded = builder.inst_results(call)[0];

        let zext = builder.ins().uextend(types::I64, loaded);

        let rt_addr = Self::ptr_add(builder, self.cpu.registers.as_mut_ptr() as i64, rt, 16);
        builder.ins().store(MemFlags::new(), zext, rt_addr, 0);

        Self::increment_pc(builder, &mut self.cpu.pc as *mut u32 as i64);
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
        let sa = ((opcode >> 6) & 0x1F) as u8;

        let rt_addr = Self::ptr_add(builder, self.cpu.registers.as_mut_ptr() as i64, rt, 16);
        let rt_val64 = builder.ins().load(types::I64, MemFlags::new(), rt_addr, 0);
        let rt_val32 = builder.ins().ireduce(types::I32, rt_val64);

        let shift_amt = builder.ins().iconst(types::I32, sa as i64);
        let result32 = builder.ins().sshr(rt_val32, shift_amt);

        let result64 = builder.ins().sextend(types::I64, result32);

        let rd_addr = Self::ptr_add(builder, self.cpu.registers.as_mut_ptr() as i64, rd, 16);
        builder.ins().store(MemFlags::new(), result64, rd_addr, 0);

        Self::increment_pc(builder, &mut self.cpu.pc as *mut u32 as i64);
        *current_pc = current_pc.wrapping_add(4);
        None
    }

    fn ld(
        &mut self,
        builder: &mut FunctionBuilder,
        opcode: u32,
        current_pc: &mut u32,
    ) -> Option<BranchInfo> {
        let rs = ((opcode >> 21) & 0x1F) as i64;
        let rt = ((opcode >> 16) & 0x1F) as i64;
        let imm = (opcode as i16) as i64;

        let rs_addr = Self::ptr_add(builder, self.cpu.registers.as_mut_ptr() as i64, rs, 16);
        let rs_val64 = builder.ins().load(types::I64, MemFlags::new(), rs_addr, 0);
        let rs_val32 = builder.ins().ireduce(types::I32, rs_val64);
        let base = builder.ins().uextend(types::I64, rs_val32);

        let addr = builder.ins().iadd_imm(base, imm);

        let addr = builder.ins().ireduce(types::I32, addr);

        let bus = self.cpu.bus.lock().unwrap();
        let bus_ptr: *mut Bus = &**bus as *const Bus as *mut Bus;
        let bus_val = builder.ins().iconst(types::I64, bus_ptr as i64);

        let callee = self
            .module
            .declare_func_in_func(self.bus_read64_func, builder.func);
        let call = builder.ins().call(callee, &[bus_val, addr]);
        let loaded = builder.inst_results(call)[0];

        let rt_addr = Self::ptr_add(builder, self.cpu.registers.as_mut_ptr() as i64, rt, 16);
        builder.ins().store(MemFlags::new(), loaded, rt_addr, 0);

        Self::increment_pc(builder, &mut self.cpu.pc as *mut u32 as i64);
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
        let rs = ((opcode >> 21) & 0x1F) as i64;
        let rt = ((opcode >> 16) & 0x1F) as i64;
        let imm = (opcode as i16) as i64;

        let rs_addr = Self::ptr_add(builder, self.cpu.registers.as_mut_ptr() as i64, rs, 16);
        let rs_val64 = builder.ins().load(types::I64, MemFlags::new(), rs_addr, 0);
        let rs_val32 = builder.ins().ireduce(types::I32, rs_val64);
        let base = builder.ins().uextend(types::I64, rs_val32);

        let addr = builder.ins().iadd_imm(base, imm);
        let addr = builder.ins().ireduce(types::I32, addr);

        let rt_addr = Self::ptr_add(builder, self.cpu.registers.as_mut_ptr() as i64, rt, 16);
        let rt_val64 = builder.ins().load(types::I64, MemFlags::new(), rt_addr, 0);
        let rt_val32 = builder.ins().ireduce(types::I32, rt_val64);

        let byte_val = builder.ins().ireduce(types::I8, rt_val32);

        let bus = self.cpu.bus.lock().unwrap();
        let bus_ptr: *mut Bus = &**bus as *const Bus as *mut Bus;
        let bus_val = builder.ins().iconst(types::I64, bus_ptr as i64);

        let callee = self
            .module
            .declare_func_in_func(self.bus_write8_func, builder.func);

        builder.ins().call(callee, &[bus_val, addr, byte_val]);

        Self::increment_pc(builder, &mut self.cpu.pc as *mut u32 as i64);
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

        let rs_addr = Self::ptr_add(builder, self.cpu.registers.as_mut_ptr() as i64, rs, 16);
        let rt_addr = Self::ptr_add(builder, self.cpu.registers.as_mut_ptr() as i64, rt, 16);

        let rs_val = builder.ins().load(types::I32, MemFlags::new(), rs_addr, 0);
        let rt_val = builder.ins().load(types::I32, MemFlags::new(), rt_addr, 0);

        let result = builder.ins().iadd(rs_val, rt_val);

        let rd_addr = Self::ptr_add(builder, self.cpu.registers.as_mut_ptr() as i64, rd, 16);
        builder.ins().store(MemFlags::new(), result, rd_addr, 0);

        Self::increment_pc(builder, &mut self.cpu.pc as *mut u32 as i64);
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
        let rs_addr = Self::ptr_add(builder, self.cpu.registers.as_mut_ptr() as i64, rs, 16);
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

        let rs_addr = Self::ptr_add(builder, self.cpu.registers.as_mut_ptr() as i64, rs, 16);
        let rs_val = builder.ins().load(types::I32, MemFlags::new(), rs_addr, 0);

        let rt_addr = Self::ptr_add(builder, self.cpu.registers.as_mut_ptr() as i64, rt, 16);
        let rt_val = builder.ins().load(types::I32, MemFlags::new(), rt_addr, 0);

        let rt_zero = builder.ins().icmp_imm(IntCC::Equal, rt_val, 0);

        let min_i32 = builder.ins().iconst(types::I32, i32::MIN as i64);
        let minus_one = builder.ins().iconst(types::I32, -1);
        let rs_is_min = builder.ins().icmp(IntCC::Equal, rs_val, min_i32);
        let rt_is_minus_one = builder.ins().icmp(IntCC::Equal, rt_val, minus_one);
        let overflow_cond = builder.ins().band(rs_is_min, rt_is_minus_one);

        let quot = builder.ins().sdiv(rs_val, rt_val);
        let rem = builder.ins().srem(rs_val, rt_val);

        let zero_i32 = builder.ins().iconst(types::I32, 0);
        let quot_select1 = builder.ins().select(overflow_cond, min_i32, quot);
        let quot_final = builder.ins().select(rt_zero, zero_i32, quot_select1);

        let rem_final = builder.ins().select(overflow_cond, zero_i32, rem);
        let rem_store = builder.ins().select(rt_zero, zero_i32, rem_final);

        let quot_64 = builder.ins().sextend(types::I64, quot_final);
        let rem_64 = builder.ins().sextend(types::I64, rem_store);

        let lo_addr = Self::ptr_add(builder, &mut self.cpu.lo as *mut u128 as i64, 0, 16);
        let hi_addr = Self::ptr_add(builder, &mut self.cpu.hi as *mut u128 as i64, 0, 16);
        builder.ins().store(MemFlags::new(), quot_64, lo_addr, 0);
        builder.ins().store(MemFlags::new(), rem_64, hi_addr, 0);

        Self::increment_pc(builder, &mut self.cpu.pc as *mut u32 as i64);
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
        let rd_addr = Self::ptr_add(builder, self.cpu.registers.as_mut_ptr() as i64, rd, 16);

        let hi_ptr_val = builder
            .ins()
            .iconst(types::I64, &mut self.cpu.hi as *mut u128 as i64);
        let hi_val = builder
            .ins()
            .load(types::I128, MemFlags::new(), hi_ptr_val, 0);
        let hi_val_64 = builder.ins().ireduce(types::I64, hi_val);
        builder.ins().store(MemFlags::new(), hi_val_64, rd_addr, 0);

        Self::increment_pc(builder, &mut self.cpu.pc as *mut u32 as i64);
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

        let rs_addr = Self::ptr_add(builder, self.cpu.registers.as_mut_ptr() as i64, rs, 16);
        let rt_addr = Self::ptr_add(builder, self.cpu.registers.as_mut_ptr() as i64, rt, 16);

        let rs_val = builder.ins().load(types::I64, MemFlags::new(), rs_addr, 0);
        let rt_val = builder.ins().load(types::I64, MemFlags::new(), rt_addr, 0);

        let cmp = builder.ins().icmp(IntCC::UnsignedLessThan, rs_val, rt_val);

        let one = builder.ins().iconst(types::I64, 1);
        let zero = builder.ins().iconst(types::I64, 0);
        let out64 = builder.ins().select(cmp, one, zero);

        let rd_addr = Self::ptr_add(builder, self.cpu.registers.as_mut_ptr() as i64, rd, 16);
        builder.ins().store(MemFlags::new(), out64, rd_addr, 0);

        Self::increment_pc(builder, &mut self.cpu.pc as *mut u32 as i64);
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

        let rs_addr = Self::ptr_add(builder, self.cpu.registers.as_mut_ptr() as i64, rs, 16);
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

        let rs_addr = Self::ptr_add(builder, self.cpu.registers.as_mut_ptr() as i64, rs, 16);
        let rt_addr = Self::ptr_add(builder, self.cpu.registers.as_mut_ptr() as i64, rt, 16);

        let rs_val_64 = Self::load64(builder, rs_addr);
        let rt_val_64 = Self::load64(builder, rt_addr);

        let rs_val = builder.ins().ireduce(types::I32, rs_val_64);
        let rt_val = builder.ins().ireduce(types::I32, rt_val_64);

        let diff = builder.ins().isub(rs_val, rt_val);

        let diff_sext = builder.ins().sextend(types::I64, diff);

        let rd_addr = Self::ptr_add(builder, self.cpu.registers.as_mut_ptr() as i64, rd, 16);
        builder.ins().store(MemFlags::new(), diff_sext, rd_addr, 0);

        Self::increment_pc(builder, &mut self.cpu.pc as *mut u32 as i64);
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

        let rs_addr = Self::ptr_add(builder, self.cpu.registers.as_mut_ptr() as i64, rs, 16);
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

        let rs_addr = Self::ptr_add(builder, self.cpu.registers.as_mut_ptr() as i64, rs, 16);
        let rt_addr = Self::ptr_add(builder, self.cpu.registers.as_mut_ptr() as i64, rt, 16);

        let rs_val = Self::load64(builder, rs_addr);
        let rt_val = Self::load64(builder, rt_addr);

        let zero = builder.ins().iconst(types::I64, 0);
        let cond = builder.ins().icmp(IntCC::NotEqual, rt_val, zero);

        let rd_addr = Self::ptr_add(builder, self.cpu.registers.as_mut_ptr() as i64, rd, 16);
        let rd_val = Self::load64(builder, rd_addr);

        let val = builder.ins().select(cond, rs_val, rd_val);

        builder.ins().store(MemFlags::new(), val, rd_addr, 0);

        Self::increment_pc(builder, &mut self.cpu.pc as *mut u32 as i64);
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

        let rs_addr = Self::ptr_add(builder, self.cpu.registers.as_mut_ptr() as i64, rs, 16);
        let rt_addr = Self::ptr_add(builder, self.cpu.registers.as_mut_ptr() as i64, rt, 16);

        let rs_val = Self::load64(builder, rs_addr);
        let rt_val = Self::load64(builder, rt_addr);

        let cmp = builder.ins().icmp(IntCC::SignedLessThan, rs_val, rt_val);

        let result = builder.ins().uextend(types::I64, cmp);

        let rd_addr = Self::ptr_add(builder, self.cpu.registers.as_mut_ptr() as i64, rd, 16);
        builder.ins().store(MemFlags::new(), result, rd_addr, 0);

        Self::increment_pc(builder, &mut self.cpu.pc as *mut u32 as i64);
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

        let rs_addr = Self::ptr_add(builder, self.cpu.registers.as_mut_ptr() as i64, rs, 16);
        let rs_val = Self::load64(builder, rs_addr);

        let rt_addr = Self::ptr_add(builder, self.cpu.registers.as_mut_ptr() as i64, rt, 16);
        let rt_val = Self::load64(builder, rt_addr);

        let res = builder.ins().band(rs_val, rt_val);

        let rd_addr = Self::ptr_add(builder, self.cpu.registers.as_mut_ptr() as i64, rd, 16);
        builder.ins().store(MemFlags::new(), res, rd_addr, 0);

        Self::increment_pc(builder, &mut self.cpu.pc as *mut u32 as i64);
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

        let rt_addr = Self::ptr_add(builder, self.cpu.registers.as_mut_ptr() as i64, rt, 16);
        let rt_val_32 = builder.ins().load(types::I32, MemFlags::new(), rt_addr, 0);

        let rt_val_64 = builder.ins().uextend(types::I64, rt_val_32);

        let shift_amt = builder.ins().iconst(types::I64, sa);
        let shifted = builder.ins().ushr(rt_val_64, shift_amt);

        let rd_addr = Self::ptr_add(builder, self.cpu.registers.as_mut_ptr() as i64, rd, 16);
        builder.ins().store(MemFlags::new(), shifted, rd_addr, 0);

        Self::increment_pc(builder, &mut self.cpu.pc as *mut u32 as i64);
        *current_pc = current_pc.wrapping_add(4);

        None
    }

    fn lhu(
        &mut self,
        builder: &mut FunctionBuilder,
        opcode: u32,
        current_pc: &mut u32,
    ) -> Option<BranchInfo> {
        let rs = ((opcode >> 21) & 0x1F) as i64;
        let rt = ((opcode >> 16) & 0x1F) as i64;
        let imm = (opcode as i16) as i64;

        let rs_addr = Self::ptr_add(builder, self.cpu.registers.as_mut_ptr() as i64, rs, 16);
        let rs_val = Self::load32(builder, rs_addr);
        let addr = builder.ins().iadd_imm(rs_val, imm);

        let bus = self.cpu.bus.lock().unwrap();
        let bus_ptr: *mut Bus = &**bus as *const Bus as *mut Bus;
        let bus_val = builder.ins().iconst(types::I64, bus_ptr as i64);

        let callee = self
            .module
            .declare_func_in_func(self.bus_read16_func, builder.func);

        let call = builder.ins().call(callee, &[bus_val, addr]);
        let loaded = builder.inst_results(call)[0];

        let zext = builder.ins().uextend(types::I64, loaded);

        let rt_addr = Self::ptr_add(builder, self.cpu.registers.as_mut_ptr() as i64, rt, 16);
        builder.ins().store(MemFlags::new(), zext, rt_addr, 0);

        Self::increment_pc(builder, &mut self.cpu.pc as *mut u32 as i64);
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

        let rs_addr = Self::ptr_add(builder, self.cpu.registers.as_mut_ptr() as i64, rs, 16);
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

        let rs_addr = Self::ptr_add(builder, self.cpu.registers.as_mut_ptr() as i64, rs, 16);
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

        let rs_addr = Self::ptr_add(builder, self.cpu.registers.as_mut_ptr() as i64, rs, 16);
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
        let rs = ((opcode >> 21) & 0x1F) as i64;
        let rt = ((opcode >> 16) & 0x1F) as i64;
        let imm = (opcode as i16) as i64;

        let rs_addr = Self::ptr_add(builder, self.cpu.registers.as_mut_ptr() as i64, rs, 16);
        let rs_val = Self::load32(builder, rs_addr);
        let addr = builder.ins().iadd_imm(rs_val, imm);

        let rt_addr = Self::ptr_add(builder, self.cpu.registers.as_mut_ptr() as i64, rt, 16);
        let rt_val = Self::load32(builder, rt_addr);

        let store_val = builder.ins().ireduce(types::I16, rt_val);

        let bus = self.cpu.bus.lock().unwrap();
        let bus_ptr: *mut Bus = &**bus as *const Bus as *mut Bus;
        let bus_val = builder.ins().iconst(types::I64, bus_ptr as i64);

        let callee = self
            .module
            .declare_func_in_func(self.bus_write16_func, builder.func);

        builder.ins().call(callee, &[bus_val, addr, store_val]);

        Self::increment_pc(builder, &mut self.cpu.pc as *mut u32 as i64);
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

        let rs_addr = Self::ptr_add(builder, self.cpu.registers.as_mut_ptr() as i64, rs, 16);
        let rs_val32 = builder.ins().load(types::I32, MemFlags::new(), rs_addr, 0);
        let rs_val64 = builder.ins().sextend(types::I64, rs_val32);

        let rt_addr = Self::ptr_add(builder, self.cpu.registers.as_mut_ptr() as i64, rt, 16);
        let rt_val32 = builder.ins().load(types::I32, MemFlags::new(), rt_addr, 0);
        let rt_val64 = builder.ins().sextend(types::I64, rt_val32);

        let rs_val_i32 = builder.ins().ireduce(types::I32, rs_val64);
        let rs_val_i64_check = builder.ins().sextend(types::I64, rs_val_i32);
        let rs_invalid = builder
            .ins()
            .icmp(IntCC::NotEqual, rs_val64, rs_val_i64_check);

        let rt_val_i32 = builder.ins().ireduce(types::I32, rt_val64);
        let rt_val_i64_check = builder.ins().sextend(types::I64, rt_val_i32);
        let rt_invalid = builder
            .ins()
            .icmp(IntCC::NotEqual, rt_val64, rt_val_i64_check);

        let rt_zero = builder.ins().icmp_imm(IntCC::Equal, rt_val64, 0);

        let invalid = builder.ins().bor(rs_invalid, rt_invalid);
        let invalid_or_zero = builder.ins().bor(invalid, rt_zero);
        let valid = builder.ins().bnot(invalid_or_zero);

        let dividend64 = builder.ins().uextend(types::I64, rs_val_i32);
        let divisor64 = builder.ins().uextend(types::I64, rt_val_i32);
        let quot64 = builder.ins().udiv(dividend64, divisor64);
        let rem64 = builder.ins().urem(dividend64, divisor64);

        let quot32 = builder.ins().ireduce(types::I32, quot64);
        let rem32 = builder.ins().ireduce(types::I32, rem64);

        let quot_final = builder.ins().uextend(types::I64, quot32);
        let rem_final = builder.ins().uextend(types::I64, rem32);

        let zero64 = builder.ins().iconst(types::I64, 0);
        let quot_store = builder.ins().select(invalid_or_zero, zero64, quot_final);
        let rem_store = builder.ins().select(invalid_or_zero, zero64, rem_final);

        let lo_addr = Self::ptr_add(builder, &mut self.cpu.lo as *mut u128 as i64, 0, 16);
        let hi_addr = Self::ptr_add(builder, &mut self.cpu.hi as *mut u128 as i64, 0, 16);
        builder.ins().store(MemFlags::new(), quot_store, lo_addr, 0);
        builder.ins().store(MemFlags::new(), rem_store, hi_addr, 0);

        Self::increment_pc(builder, &mut self.cpu.pc as *mut u32 as i64);
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

        let rs_addr = Self::ptr_add(builder, self.cpu.registers.as_mut_ptr() as i64, rs, 16);
        let rs_val = builder
            .ins()
            .load(types::I32, MemFlags::trusted(), rs_addr, 0);
        let rs_ext = builder.ins().sextend(types::I64, rs_val);

        let lo_addr = Self::ptr_add(builder, &mut self.cpu.lo as *mut u128 as i64, 0, 16);

        let lo_low = builder
            .ins()
            .load(types::I64, MemFlags::trusted(), lo_addr, 0);
        builder.ins().store(MemFlags::trusted(), lo_low, lo_addr, 0);

        builder.ins().store(MemFlags::trusted(), rs_ext, lo_addr, 8);

        Self::increment_pc(builder, &mut self.cpu.pc as *mut u32 as i64);
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

        let rt_addr = Self::ptr_add(builder, self.cpu.registers.as_mut_ptr() as i64, rt, 16);

        let lo1_addr = Self::ptr_add(builder, &mut self.cpu.lo as *mut u128 as i64 + 8, 1, 8);

        let val32 = builder
            .ins()
            .load(types::I32, MemFlags::trusted(), lo1_addr, 0);

        let val64 = builder.ins().uextend(types::I64, val32);

        builder.ins().store(MemFlags::trusted(), val64, rt_addr, 0);

        Self::increment_pc(builder, &mut self.cpu.pc as *mut u32 as i64);
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

        let rs_addr = Self::ptr_add(builder, self.cpu.registers.as_mut_ptr() as i64, rs, 16);
        let rs_val = builder
            .ins()
            .load(types::I64, MemFlags::trusted(), rs_addr, 0);
        let mask = builder.ins().iconst(types::I64, 0x3F);
        let shift_amount = builder.ins().band(rs_val, mask);

        let rt_addr = Self::ptr_add(builder, self.cpu.registers.as_mut_ptr() as i64, rt, 16);
        let rt_val = builder
            .ins()
            .load(types::I64, MemFlags::trusted(), rt_addr, 0);

        let result = builder.ins().sshr(rt_val, shift_amount);

        let rd_addr = Self::ptr_add(builder, self.cpu.registers.as_mut_ptr() as i64, rd, 16);
        builder.ins().store(MemFlags::trusted(), result, rd_addr, 0);

        Self::increment_pc(builder, &mut self.cpu.pc as *mut u32 as i64);
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
        let sa = (opcode >> 6) & 0x1F;

        let shift_amount = builder.ins().iconst(types::I64, (sa + 32) as i64);

        let rt_addr = Self::ptr_add(builder, self.cpu.registers.as_mut_ptr() as i64, rt, 16);
        let rt_val = builder
            .ins()
            .load(types::I64, MemFlags::trusted(), rt_addr, 0);

        let result = builder.ins().ishl(rt_val, shift_amount);

        let rd_addr = Self::ptr_add(builder, self.cpu.registers.as_mut_ptr() as i64, rd, 16);
        builder.ins().store(MemFlags::trusted(), result, rd_addr, 0);

        Self::increment_pc(builder, &mut self.cpu.pc as *mut u32 as i64);
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
        let sa = (opcode >> 6) & 0x1F;

        let shift_amount = builder.ins().iconst(types::I64, (sa + 32) as i64);

        let rt_addr = Self::ptr_add(builder, self.cpu.registers.as_mut_ptr() as i64, rt, 16);
        let rt_val = builder
            .ins()
            .load(types::I64, MemFlags::trusted(), rt_addr, 0);

        let result = builder.ins().sshr(rt_val, shift_amount);

        let rd_addr = Self::ptr_add(builder, self.cpu.registers.as_mut_ptr() as i64, rd, 16);
        builder.ins().store(MemFlags::trusted(), result, rd_addr, 0);

        Self::increment_pc(builder, &mut self.cpu.pc as *mut u32 as i64);
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

        let rs_addr = Self::ptr_add(builder, self.cpu.registers.as_mut_ptr() as i64, rs, 16);
        let rs_val = builder
            .ins()
            .load(types::I64, MemFlags::trusted(), rs_addr, 0);

        let imm_val = builder.ins().iconst(types::I64, imm);
        let result = builder.ins().bxor(rs_val, imm_val);

        let rt_addr = Self::ptr_add(builder, self.cpu.registers.as_mut_ptr() as i64, rt, 16);
        builder.ins().store(MemFlags::trusted(), result, rt_addr, 0);

        Self::increment_pc(builder, &mut self.cpu.pc as *mut u32 as i64);
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

        let rs_addr = Self::ptr_add(builder, self.cpu.registers.as_mut_ptr() as i64, rs, 16);
        let rs_val32 = builder.ins().load(types::I32, MemFlags::new(), rs_addr, 0);
        let rs_val64 = builder.ins().sextend(types::I64, rs_val32);

        let rt_addr = Self::ptr_add(builder, self.cpu.registers.as_mut_ptr() as i64, rt, 16);
        let rt_val32 = builder.ins().load(types::I32, MemFlags::new(), rt_addr, 0);
        let rt_val64 = builder.ins().sextend(types::I64, rt_val32);

        let rs_val_i32 = builder.ins().ireduce(types::I32, rs_val64);
        let rs_val_i64_check = builder.ins().sextend(types::I64, rs_val_i32);
        let rs_invalid = builder
            .ins()
            .icmp(IntCC::NotEqual, rs_val64, rs_val_i64_check);

        let rt_val_i32 = builder.ins().ireduce(types::I32, rt_val64);
        let rt_val_i64_check = builder.ins().sextend(types::I64, rt_val_i32);
        let rt_invalid = builder
            .ins()
            .icmp(IntCC::NotEqual, rt_val64, rt_val_i64_check);

        let invalid = builder.ins().bor(rs_invalid, rt_invalid);
        let valid = builder.ins().bnot(invalid);

        let prod = builder.ins().imul(rs_val64, rt_val64);

        let lo32 = builder.ins().ireduce(types::I32, prod);
        let shift32 = builder.ins().iconst(types::I64, 32);
        let hi32 = builder.ins().sshr(prod, shift32);
        let hi32_32 = builder.ins().ireduce(types::I32, hi32);

        let lo_val = builder.ins().uextend(types::I64, lo32);
        let hi_val = builder.ins().uextend(types::I64, hi32_32);

        let zero64 = builder.ins().iconst(types::I64, 0);
        let lo_final = builder.ins().select(invalid, zero64, lo_val);
        let hi_final = builder.ins().select(invalid, zero64, hi_val);

        let lo_addr = Self::ptr_add(builder, &mut self.cpu.lo as *mut u128 as i64, 0, 16);
        let hi_addr = Self::ptr_add(builder, &mut self.cpu.hi as *mut u128 as i64, 0, 16);
        builder.ins().store(MemFlags::new(), lo_final, lo_addr, 0);
        builder.ins().store(MemFlags::new(), hi_final, hi_addr, 0);

        let rd_val = builder.ins().iconst(types::I64, rd);
        let rd_nonzero = builder.ins().icmp_imm(IntCC::NotEqual, rd_val, 0);
        let store_rd = builder.ins().band(valid, rd_nonzero);
        let rd_addr = Self::ptr_add(builder, self.cpu.registers.as_mut_ptr() as i64, rd, 16);
        let lo64 = builder.ins().uextend(types::I64, lo32);
        let zero64_rd = builder.ins().iconst(types::I64, 0);
        let current_rd = builder.ins().load(types::I64, MemFlags::new(), rd_addr, 0);
        let rd_final = builder.ins().select(store_rd, lo64, current_rd);
        builder.ins().store(MemFlags::new(), rd_final, rd_addr, 0);

        Self::increment_pc(builder, &mut self.cpu.pc as *mut u32 as i64);
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

        let rt_addr = Self::ptr_add(builder, self.cpu.registers.as_mut_ptr() as i64, rt, 16);
        let rt_val = builder
            .ins()
            .load(types::I64, MemFlags::trusted(), rt_addr, 0);

        let rt_zero = builder.ins().icmp_imm(IntCC::Equal, rt_val, 0);

        let rs_addr = Self::ptr_add(builder, self.cpu.registers.as_mut_ptr() as i64, rs, 16);
        let rs_val = builder
            .ins()
            .load(types::I64, MemFlags::trusted(), rs_addr, 0);

        let rd_addr = Self::ptr_add(builder, self.cpu.registers.as_mut_ptr() as i64, rd, 16);

        let current_rd_val = builder
            .ins()
            .load(types::I64, MemFlags::trusted(), rd_addr, 0);
        let result = builder.ins().select(rt_zero, rs_val, current_rd_val);
        builder.ins().store(MemFlags::trusted(), result, rd_addr, 0);

        Self::increment_pc(builder, &mut self.cpu.pc as *mut u32 as i64);
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

        let rt_addr = Self::ptr_add(builder, self.cpu.registers.as_mut_ptr() as i64, rt, 16);
        let rt_val = builder
            .ins()
            .load(types::I64, MemFlags::trusted(), rt_addr, 0);

        let shift_amount = builder.ins().iconst(types::I64, sa);
        let result = builder.ins().ushr(rt_val, shift_amount);

        let rd_addr = Self::ptr_add(builder, self.cpu.registers.as_mut_ptr() as i64, rd, 16);
        builder.ins().store(MemFlags::trusted(), result, rd_addr, 0);

        Self::increment_pc(builder, &mut self.cpu.pc as *mut u32 as i64);
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

        let rs_addr = Self::ptr_add(builder, self.cpu.registers.as_mut_ptr() as i64, rs, 16);
        let rs_val = builder
            .ins()
            .load(types::I64, MemFlags::trusted(), rs_addr, 0);

        let imm_val = builder.ins().iconst(types::I64, imm);
        let result = builder.ins().iadd(rs_val, imm_val);

        let rt_addr = Self::ptr_add(builder, self.cpu.registers.as_mut_ptr() as i64, rt, 16);
        builder.ins().store(MemFlags::trusted(), result, rt_addr, 0);

        Self::increment_pc(builder, &mut self.cpu.pc as *mut u32 as i64);
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

        let rs_addr = Self::ptr_add(builder, self.cpu.registers.as_mut_ptr() as i64, rs, 16);
        let rs_val = builder
            .ins()
            .load(types::I64, MemFlags::trusted(), rs_addr, 0);
        let mask = builder.ins().iconst(types::I64, 0x3F);
        let shift_amount = builder.ins().band(rs_val, mask);

        let rt_addr = Self::ptr_add(builder, self.cpu.registers.as_mut_ptr() as i64, rt, 16);
        let rt_val = builder
            .ins()
            .load(types::I64, MemFlags::trusted(), rt_addr, 0);

        let result = builder.ins().ishl(rt_val, shift_amount);

        let rd_addr = Self::ptr_add(builder, self.cpu.registers.as_mut_ptr() as i64, rd, 16);
        builder.ins().store(MemFlags::trusted(), result, rd_addr, 0);

        Self::increment_pc(builder, &mut self.cpu.pc as *mut u32 as i64);
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

        let base_addr = Self::ptr_add(builder, self.cpu.registers.as_mut_ptr() as i64, base, 16);
        let base_val32 = builder
            .ins()
            .load(types::I32, MemFlags::new(), base_addr, 0);
        let base_val64 = builder.ins().uextend(types::I64, base_val32);

        let vaddr = builder.ins().iadd_imm(base_val64, offset);

        let align_mask = builder.ins().iconst(types::I64, !0xF_i64);
        let aligned_addr = builder.ins().band(vaddr, align_mask);
        let aligned_addr32 = builder.ins().ireduce(types::I32, aligned_addr);

        let bus = self.cpu.bus.lock().unwrap();
        let bus_ptr: *mut Bus = &**bus as *const Bus as *mut Bus;
        let bus_val = builder.ins().iconst(types::I64, bus_ptr as i64);

        let callee = self
            .module
            .declare_func_in_func(self.bus_read128_func, builder.func);

        let ss_lo = builder.create_sized_stack_slot(StackSlotData::new(StackSlotKind::ExplicitSlot, 8, 3));
        let ss_hi = builder.create_sized_stack_slot(StackSlotData::new(StackSlotKind::ExplicitSlot, 8, 3));
        let ptr_lo = builder.ins().stack_addr(types::I64, ss_lo, 0);
        let ptr_hi = builder.ins().stack_addr(types::I64, ss_hi, 0);

        builder.ins().call(callee, &[bus_val, aligned_addr32, ptr_lo, ptr_hi]);

        let low  = builder.ins().load(types::I64, MemFlags::new(), ptr_lo, 0);
        let high = builder.ins().load(types::I64, MemFlags::new(), ptr_hi, 0);

        let low_ext = builder.ins().uextend(types::I128, low);
        let high_ext = builder.ins().uextend(types::I128, high);
        let shifted_high = builder.ins().ishl_imm(high_ext, 64);
        let value = builder.ins().bor(shifted_high, low_ext);

        let rt_addr = Self::ptr_add(builder, self.cpu.registers.as_mut_ptr() as i64, rt, 16);
        builder.ins().store(MemFlags::new(), value, rt_addr, 0);

        Self::increment_pc(builder, &mut self.cpu.pc as *mut u32 as i64);
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

        let base_addr = Self::ptr_add(builder, self.cpu.registers.as_mut_ptr() as i64, base, 16);
        let base_val32 = builder
            .ins()
            .load(types::I32, MemFlags::new(), base_addr, 0);
        let base_val64 = builder.ins().uextend(types::I64, base_val32);

        let vaddr = builder.ins().iadd_imm(base_val64, offset);

        let align_mask = builder.ins().iconst(types::I64, !0xF_i64);
        let aligned_addr = builder.ins().band(vaddr, align_mask);
        let aligned_addr32 = builder.ins().ireduce(types::I32, aligned_addr);

        let rt_addr = Self::ptr_add(builder, self.cpu.registers.as_mut_ptr() as i64, rt, 16);
        let rt_val = builder.ins().load(types::I128, MemFlags::new(), rt_addr, 0);

        let low = builder.ins().ireduce(types::I64, rt_val);
        let upper_bits_shifted = builder.ins().ushr_imm(rt_val, 64);
        let high = builder.ins().ireduce(types::I64, upper_bits_shifted);

        let bus = self.cpu.bus.lock().unwrap();
        let bus_ptr: *mut Bus = &**bus as *const Bus as *mut Bus;
        let bus_val = builder.ins().iconst(types::I64, bus_ptr as i64);

        let callee = self
            .module
            .declare_func_in_func(self.bus_write128_func, builder.func);

        builder
            .ins()
            .call(callee, &[bus_val, aligned_addr32, low, high]);

        Self::increment_pc(builder, &mut self.cpu.pc as *mut u32 as i64);
        *current_pc = current_pc.wrapping_add(4);

        None
    }

    fn lh(
        &mut self,
        builder: &mut FunctionBuilder,
        opcode: u32,
        current_pc: &mut u32,
    ) -> Option<BranchInfo> {
        let rs = ((opcode >> 21) & 0x1F) as i64;
        let rt = ((opcode >> 16) & 0x1F) as i64;
        let imm = (opcode as i16) as i64;

        let rs_addr = Self::ptr_add(builder, self.cpu.registers.as_mut_ptr() as i64, rs, 16);
        let rs_val32 = builder.ins().load(types::I32, MemFlags::new(), rs_addr, 0);
        let rs_val64 = builder.ins().uextend(types::I64, rs_val32);

        let addr = builder.ins().iadd_imm(rs_val64, imm);
        let addr32 = builder.ins().ireduce(types::I32, addr);

        let bus = self.cpu.bus.lock().unwrap();
        let bus_ptr: *mut Bus = &**bus as *const Bus as *mut Bus;
        let bus_val = builder.ins().iconst(types::I64, bus_ptr as i64);

        let callee = self
            .module
            .declare_func_in_func(self.bus_read16_func, builder.func);

        let call = builder.ins().call(callee, &[bus_val, addr32]);
        let halfword_val = builder.inst_results(call)[0];

        let result = builder.ins().sextend(types::I64, halfword_val);

        let rt_addr = Self::ptr_add(builder, self.cpu.registers.as_mut_ptr() as i64, rt, 16);
        builder.ins().store(MemFlags::new(), result, rt_addr, 0);

        Self::increment_pc(builder, &mut self.cpu.pc as *mut u32 as i64);
        *current_pc = current_pc.wrapping_add(4);

        None
    }

    fn cache(
        &mut self,
        builder: &mut FunctionBuilder,
        _opcode: u32,
        current_pc: &mut u32,
    ) -> Option<BranchInfo> {
        Self::increment_pc(builder, &mut self.cpu.pc as *mut u32 as i64);
        *current_pc = current_pc.wrapping_add(4);
        None
    }

    fn sllv(
        &mut self,
        builder: &mut FunctionBuilder,
        opcode: u32,
        current_pc: &mut u32,
    ) -> Option<BranchInfo> {
        let rs = ((opcode >> 21) & 0x1F) as i64;
        let rt = ((opcode >> 16) & 0x1F) as i64;
        let rd = ((opcode >> 11) & 0x1F) as i64;

        let rs_addr = Self::ptr_add(builder, self.cpu.registers.as_mut_ptr() as i64, rs, 16);
        let rs_val = builder.ins().load(types::I64, MemFlags::new(), rs_addr, 0);
        let mask = builder.ins().iconst(types::I64, 0x1F);
        let shift_amount = builder.ins().band(rs_val, mask);

        let rt_addr = Self::ptr_add(builder, self.cpu.registers.as_mut_ptr() as i64, rt, 16);
        let rt_val64 = builder.ins().load(types::I64, MemFlags::new(), rt_addr, 0);
        let rt_val32 = builder.ins().ireduce(types::I32, rt_val64);

        let shift_amount32 = builder.ins().ireduce(types::I32, shift_amount);
        let shifted_val32 = builder.ins().ishl(rt_val32, shift_amount32);

        let result = builder.ins().sextend(types::I64, shifted_val32);

        let rd_addr = Self::ptr_add(builder, self.cpu.registers.as_mut_ptr() as i64, rd, 16);
        builder.ins().store(MemFlags::new(), result, rd_addr, 0);

        Self::increment_pc(builder, &mut self.cpu.pc as *mut u32 as i64);
        *current_pc = current_pc.wrapping_add(4);

        None
    }

    fn dsll(
        &mut self,
        builder: &mut FunctionBuilder,
        opcode: u32,
        current_pc: &mut u32,
    ) -> Option<BranchInfo> {
        let rt = ((opcode >> 16) & 0x1F) as i64;
        let rd = ((opcode >> 11) & 0x1F) as i64;
        let sa = ((opcode >> 6) & 0x1F) as i64;

        let rt_addr = Self::ptr_add(builder, self.cpu.registers.as_mut_ptr() as i64, rt, 16);
        let rt_val = builder.ins().load(types::I64, MemFlags::new(), rt_addr, 0);

        let shift_amount = builder.ins().iconst(types::I64, sa);
        let result = builder.ins().ishl(rt_val, shift_amount);

        let rd_addr = Self::ptr_add(builder, self.cpu.registers.as_mut_ptr() as i64, rd, 16);
        builder.ins().store(MemFlags::new(), result, rd_addr, 0);

        Self::increment_pc(builder, &mut self.cpu.pc as *mut u32 as i64);
        *current_pc = current_pc.wrapping_add(4);

        None
    }

    fn srav(
        &mut self,
        builder: &mut FunctionBuilder,
        opcode: u32,
        current_pc: &mut u32,
    ) -> Option<BranchInfo> {
        let rs = ((opcode >> 21) & 0x1F) as i64;
        let rt = ((opcode >> 16) & 0x1F) as i64;
        let rd = ((opcode >> 11) & 0x1F) as i64;

        let rs_addr = Self::ptr_add(builder, self.cpu.registers.as_mut_ptr() as i64, rs, 16);
        let rs_val = builder.ins().load(types::I64, MemFlags::new(), rs_addr, 0);
        let mask = builder.ins().iconst(types::I64, 0x1F);
        let shift_amount = builder.ins().band(rs_val, mask);

        let rt_addr = Self::ptr_add(builder, self.cpu.registers.as_mut_ptr() as i64, rt, 16);
        let rt_val64 = builder.ins().load(types::I64, MemFlags::new(), rt_addr, 0);
        let rt_val32 = builder.ins().ireduce(types::I32, rt_val64);

        let shift_amount32 = builder.ins().ireduce(types::I32, shift_amount);
        let shifted_val32 = builder.ins().sshr(rt_val32, shift_amount32);

        let result = builder.ins().sextend(types::I64, shifted_val32);

        let rd_addr = Self::ptr_add(builder, self.cpu.registers.as_mut_ptr() as i64, rd, 16);
        builder.ins().store(MemFlags::new(), result, rd_addr, 0);

        Self::increment_pc(builder, &mut self.cpu.pc as *mut u32 as i64);
        *current_pc = current_pc.wrapping_add(4);

        None
    }

    fn nor(
        &mut self,
        builder: &mut FunctionBuilder,
        opcode: u32,
        current_pc: &mut u32,
    ) -> Option<BranchInfo> {
        let rs = ((opcode >> 21) & 0x1F) as i64;
        let rt = ((opcode >> 16) & 0x1F) as i64;
        let rd = ((opcode >> 11) & 0x1F) as i64;

        let rs_addr = Self::ptr_add(builder, self.cpu.registers.as_mut_ptr() as i64, rs, 16);
        let rs_val = builder.ins().load(types::I64, MemFlags::new(), rs_addr, 0);

        let rt_addr = Self::ptr_add(builder, self.cpu.registers.as_mut_ptr() as i64, rt, 16);
        let rt_val = builder.ins().load(types::I64, MemFlags::new(), rt_addr, 0);

        let or_result = builder.ins().bor(rs_val, rt_val);
        let result = builder.ins().bnot(or_result);

        let rd_addr = Self::ptr_add(builder, self.cpu.registers.as_mut_ptr() as i64, rd, 16);
        builder.ins().store(MemFlags::new(), result, rd_addr, 0);

        Self::increment_pc(builder, &mut self.cpu.pc as *mut u32 as i64);
        *current_pc = current_pc.wrapping_add(4);

        None
    }

    fn cfc2(
        &mut self,
        builder: &mut FunctionBuilder,
        opcode: u32,
        current_pc: &mut u32,
    ) -> Option<BranchInfo> {
        let rt = ((opcode >> 16) & 0x1F) as i64;
        let vi = ((opcode >> 11) & 0x1F) as i64;

        let rt_addr = Self::ptr_add(builder, self.cpu.registers.as_mut_ptr() as i64, rt, 16);

        let zero = builder.ins().iconst(types::I64, 0);
        let vi_idx = builder.ins().iconst(types::I64, vi);
        let is_vi0 = builder.ins().icmp_imm(IntCC::Equal, vi_idx, 0);

        let vi_addr = Self::ptr_add(builder, &mut self.cpu.vu0.vi as *mut u16 as i64, vi, 2);

        let vi_val = builder.ins().load(types::I16, MemFlags::new(), vi_addr, 0);

        let vi_val_64 = builder.ins().sextend(types::I64, vi_val);

        let result = builder.ins().select(is_vi0, zero, vi_val_64);

        builder.ins().store(MemFlags::new(), result, rt_addr, 0);

        Self::increment_pc(builder, &mut self.cpu.pc as *mut u32 as i64);
        *current_pc = current_pc.wrapping_add(4);

        None
    }

    fn ctc2(
        &mut self,
        builder: &mut FunctionBuilder,
        opcode: u32,
        current_pc: &mut u32,
    ) -> Option<BranchInfo> {
        let rt = ((opcode >> 16) & 0x1F) as i64;
        let vi = ((opcode >> 11) & 0x1F) as i64;

        let vi_idx = builder.ins().iconst(types::I64, vi);
        let is_vi0 = builder.ins().icmp_imm(IntCC::Equal, vi_idx, 0);
        let write_block = builder.create_block();
        let exit_block = builder.create_block();

        builder
            .ins()
            .brif(is_vi0, exit_block, &[], write_block, &[]);
        builder.switch_to_block(write_block);

        let rt_addr = Self::ptr_add(builder, self.cpu.registers.as_mut_ptr() as i64, rt, 16);
        let vi_addr = Self::ptr_add(builder, &mut self.cpu.vu0.vi as *mut u16 as i64, vi, 2);

        let rt_val = builder.ins().load(types::I64, MemFlags::new(), rt_addr, 0);
        let rt_val_16 = builder.ins().ireduce(types::I16, rt_val);

        builder.ins().store(MemFlags::new(), rt_val_16, vi_addr, 0);

        builder.ins().jump(exit_block, &[]);
        builder.switch_to_block(exit_block);

        builder.seal_block(write_block);
        builder.seal_block(exit_block);

        Self::increment_pc(builder, &mut self.cpu.pc as *mut u32 as i64);
        *current_pc = current_pc.wrapping_add(4);

        None
    }

    fn lwu(
        &mut self,
        builder: &mut FunctionBuilder,
        opcode: u32,
        current_pc: &mut u32,
    ) -> Option<BranchInfo> {
        let rs = ((opcode >> 21) & 0x1F) as i64;
        let rt = ((opcode >> 16) & 0x1F) as i64;
        let imm = (opcode as i16) as i64;

        let rs_addr = Self::ptr_add(builder, self.cpu.registers.as_mut_ptr() as i64, rs, 16);
        let rs_val32 = builder.ins().load(types::I32, MemFlags::new(), rs_addr, 0);
        let rs_val64 = builder.ins().uextend(types::I64, rs_val32);

        let addr = builder.ins().iadd_imm(rs_val64, imm);
        let addr32 = builder.ins().ireduce(types::I32, addr);

        let bus = self.cpu.bus.lock().unwrap();
        let bus_ptr: *mut Bus = &**bus as *const Bus as *mut Bus;
        let bus_val = builder.ins().iconst(types::I64, bus_ptr as i64);

        let callee = self
            .module
            .declare_func_in_func(self.bus_read32_func, builder.func);

        let call = builder.ins().call(callee, &[bus_val, addr32]);
        let word_val = builder.inst_results(call)[0];

        let result = builder.ins().uextend(types::I64, word_val);

        let rt_addr = Self::ptr_add(builder, self.cpu.registers.as_mut_ptr() as i64, rt, 16);
        builder.ins().store(MemFlags::new(), result, rt_addr, 0);

        Self::increment_pc(builder, &mut self.cpu.pc as *mut u32 as i64);
        *current_pc = current_pc.wrapping_add(4);

        None
    }

    fn ldl(
        &mut self,
        builder: &mut FunctionBuilder,
        opcode: u32,
        current_pc: &mut u32,
    ) -> Option<BranchInfo> {
        let rs = ((opcode >> 21) & 0x1F) as i64;
        let rt = ((opcode >> 16) & 0x1F) as i64;
        let imm = (opcode as i16) as i64;

        let rs_addr = Self::ptr_add(builder, self.cpu.registers.as_mut_ptr() as i64, rs, 16);
        let rs_val32 = builder.ins().load(types::I32, MemFlags::new(), rs_addr, 0);
        let rs_val64 = builder.ins().uextend(types::I64, rs_val32);

        let v_addr = builder.ins().iadd_imm(rs_val64, imm);

        let byte_mask = builder.ins().iconst(types::I64, 0x7);
        let byte = builder.ins().band(v_addr, byte_mask);
        let align_mask = builder.ins().iconst(types::I64, !0x7_i64);
        let p_addr = builder.ins().band(v_addr, align_mask);
        let p_addr32 = builder.ins().ireduce(types::I32, p_addr);

        let bus = self.cpu.bus.lock().unwrap();
        let bus_ptr: *mut Bus = &**bus as *const Bus as *mut Bus;
        let bus_val = builder.ins().iconst(types::I64, bus_ptr as i64);

        let callee = self
            .module
            .declare_func_in_func(self.bus_read64_func, builder.func);

        let call = builder.ins().call(callee, &[bus_val, p_addr32]);
        let mem_quad = builder.inst_results(call)[0];

        let rt_addr = Self::ptr_add(builder, self.cpu.registers.as_mut_ptr() as i64, rt, 16);
        let rt_val = builder.ins().load(types::I64, MemFlags::new(), rt_addr, 0);

        let seven = builder.ins().iconst(types::I64, 7);
        let byte_diff = builder.ins().isub(seven, byte);
        let shift = builder.ins().imul_imm(byte_diff, 8);

        let mem_bytes = builder.ins().ishl(mem_quad, shift);

        let byte_shift = builder.ins().imul_imm(byte, 8);
        let full_mask = builder.ins().iconst(types::I64, !0u64 as i64);
        let mask = builder.ins().ushr(full_mask, byte_shift);

        let masked_rt = builder.ins().band(rt_val, mask);
        let result = builder.ins().bor(masked_rt, mem_bytes);

        builder.ins().store(MemFlags::new(), result, rt_addr, 0);

        Self::increment_pc(builder, &mut self.cpu.pc as *mut u32 as i64);
        *current_pc = current_pc.wrapping_add(4);

        None
    }

    fn ldr(
        &mut self,
        builder: &mut FunctionBuilder,
        opcode: u32,
        current_pc: &mut u32,
    ) -> Option<BranchInfo> {
        let rs = ((opcode >> 21) & 0x1F) as i64;
        let rt = ((opcode >> 16) & 0x1F) as i64;
        let imm = (opcode as i16) as i64;

        let rs_addr = Self::ptr_add(builder, self.cpu.registers.as_mut_ptr() as i64, rs, 16);
        let rs_val32 = builder.ins().load(types::I32, MemFlags::new(), rs_addr, 0);
        let rs_val64 = builder.ins().uextend(types::I64, rs_val32);

        let v_addr = builder.ins().iadd_imm(rs_val64, imm);

        let byte_mask = builder.ins().iconst(types::I64, 0x7);
        let byte = builder.ins().band(v_addr, byte_mask);
        let align_mask = builder.ins().iconst(types::I64, !0x7_i64);
        let p_addr = builder.ins().band(v_addr, align_mask);
        let p_addr32 = builder.ins().ireduce(types::I32, p_addr);

        let bus = self.cpu.bus.lock().unwrap();
        let bus_ptr: *mut Bus = &**bus as *const Bus as *mut Bus;
        let bus_val = builder.ins().iconst(types::I64, bus_ptr as i64);

        let callee = self
            .module
            .declare_func_in_func(self.bus_read64_func, builder.func);

        let call = builder.ins().call(callee, &[bus_val, p_addr32]);
        let mem_quad = builder.inst_results(call)[0];

        let rt_addr = Self::ptr_add(builder, self.cpu.registers.as_mut_ptr() as i64, rt, 16);
        let rt_val = builder.ins().load(types::I64, MemFlags::new(), rt_addr, 0);

        let shift = builder.ins().imul_imm(byte, 8);

        let mem_bytes = builder.ins().ushr(mem_quad, shift);

        let eight = builder.ins().iconst(types::I64, 8);
        let byte_diff = builder.ins().isub(eight, byte);
        let mask_shift = builder.ins().imul_imm(byte_diff, 8);
        let full_mask = builder.ins().iconst(types::I64, !0u64 as i64);
        let mask_cmp = builder
            .ins()
            .icmp_imm(IntCC::UnsignedLessThan, mask_shift, 64);
        let shifted_mask = builder.ins().ishl(full_mask, mask_shift);
        let zero_val = builder.ins().iconst(types::I64, 0);
        let mask = builder.ins().select(mask_cmp, shifted_mask, zero_val);

        let masked_rt = builder.ins().band(rt_val, mask);
        let result = builder.ins().bor(masked_rt, mem_bytes);

        builder.ins().store(MemFlags::new(), result, rt_addr, 0);

        Self::increment_pc(builder, &mut self.cpu.pc as *mut u32 as i64);
        *current_pc = current_pc.wrapping_add(4);

        None
    }

    fn sdl(
        &mut self,
        builder: &mut FunctionBuilder,
        opcode: u32,
        current_pc: &mut u32,
    ) -> Option<BranchInfo> {
        let rs = ((opcode >> 21) & 0x1F) as i64;
        let rt = ((opcode >> 16) & 0x1F) as i64;
        let imm = (opcode as i16) as i64;

        let rs_addr = Self::ptr_add(builder, self.cpu.registers.as_mut_ptr() as i64, rs, 16);
        let rs_val32 = builder.ins().load(types::I32, MemFlags::new(), rs_addr, 0);
        let rs_val64 = builder.ins().uextend(types::I64, rs_val32);

        let v_addr = builder.ins().iadd_imm(rs_val64, imm);

        let byte_mask = builder.ins().iconst(types::I64, 0x7);
        let byte = builder.ins().band(v_addr, byte_mask);
        let align_mask = builder.ins().iconst(types::I64, !0x7_i64);
        let p_addr = builder.ins().band(v_addr, align_mask);
        let p_addr32 = builder.ins().ireduce(types::I32, p_addr);

        let rt_addr = Self::ptr_add(builder, self.cpu.registers.as_mut_ptr() as i64, rt, 16);
        let rt_val = builder.ins().load(types::I64, MemFlags::new(), rt_addr, 0);

        let seven = builder.ins().iconst(types::I64, 7);
        let byte_diff = builder.ins().isub(seven, byte);
        let shift = builder.ins().imul_imm(byte_diff, 8);

        let data_quad = builder.ins().ushr(rt_val, shift);

        let bus = self.cpu.bus.lock().unwrap();
        let bus_ptr: *mut Bus = &**bus as *const Bus as *mut Bus;
        let bus_val = builder.ins().iconst(types::I64, bus_ptr as i64);

        let callee = self
            .module
            .declare_func_in_func(self.bus_write64_func, builder.func);

        builder.ins().call(callee, &[bus_val, p_addr32, data_quad]);

        Self::increment_pc(builder, &mut self.cpu.pc as *mut u32 as i64);
        *current_pc = current_pc.wrapping_add(4);

        None
    }

    fn sdr(
        &mut self,
        builder: &mut FunctionBuilder,
        opcode: u32,
        current_pc: &mut u32,
    ) -> Option<BranchInfo> {
        let rs = ((opcode >> 21) & 0x1F) as i64;
        let rt = ((opcode >> 16) & 0x1F) as i64;
        let imm = (opcode as i16) as i64;

        let rs_addr = Self::ptr_add(builder, self.cpu.registers.as_mut_ptr() as i64, rs, 16);
        let rs_val32 = builder.ins().load(types::I32, MemFlags::new(), rs_addr, 0);
        let rs_val64 = builder.ins().uextend(types::I64, rs_val32);

        let v_addr = builder.ins().iadd_imm(rs_val64, imm);

        let byte_mask = builder.ins().iconst(types::I64, 0x7);
        let byte = builder.ins().band(v_addr, byte_mask);
        let align_mask = builder.ins().iconst(types::I64, !0x7_i64);
        let p_addr = builder.ins().band(v_addr, align_mask);
        let p_addr32 = builder.ins().ireduce(types::I32, p_addr);

        let rt_addr = Self::ptr_add(builder, self.cpu.registers.as_mut_ptr() as i64, rt, 16);
        let rt_val = builder.ins().load(types::I64, MemFlags::new(), rt_addr, 0);

        let shift = builder.ins().imul_imm(byte, 8);

        let data_quad = builder.ins().ishl(rt_val, shift);

        let bus = self.cpu.bus.lock().unwrap();
        let bus_ptr: *mut Bus = &**bus as *const Bus as *mut Bus;
        let bus_val = builder.ins().iconst(types::I64, bus_ptr as i64);

        let callee = self
            .module
            .declare_func_in_func(self.bus_write64_func, builder.func);

        builder.ins().call(callee, &[bus_val, p_addr32, data_quad]);

        Self::increment_pc(builder, &mut self.cpu.pc as *mut u32 as i64);
        *current_pc = current_pc.wrapping_add(4);

        None
    }

    fn srlv(
        &mut self,
        builder: &mut FunctionBuilder,
        opcode: u32,
        current_pc: &mut u32,
    ) -> Option<BranchInfo> {
        let rs = ((opcode >> 21) & 0x1F) as i64;
        let rt = ((opcode >> 16) & 0x1F) as i64;
        let rd = ((opcode >> 11) & 0x1F) as i64;

        let rs_addr = Self::ptr_add(builder, self.cpu.registers.as_mut_ptr() as i64, rs, 16);
        let rs_val = builder.ins().load(types::I64, MemFlags::new(), rs_addr, 0);
        let mask = builder.ins().iconst(types::I64, 0x1F);
        let shamt = builder.ins().band(rs_val, mask);
        let shamt32 = builder.ins().ireduce(types::I32, shamt);

        let rt_addr = Self::ptr_add(builder, self.cpu.registers.as_mut_ptr() as i64, rt, 16);
        let rt_val64 = builder.ins().load(types::I64, MemFlags::new(), rt_addr, 0);
        let rt_val32 = builder.ins().ireduce(types::I32, rt_val64);

        let shifted32 = builder.ins().ushr(rt_val32, shamt32);

        let result64 = builder.ins().sextend(types::I64, shifted32);

        let rd_addr = Self::ptr_add(builder, self.cpu.registers.as_mut_ptr() as i64, rd, 16);
        builder.ins().store(MemFlags::new(), result64, rd_addr, 0);

        Self::increment_pc(builder, &mut self.cpu.pc as *mut u32 as i64);
        *current_pc = current_pc.wrapping_add(4);

        None
    }

    fn dsrl32(
        &mut self,
        builder: &mut FunctionBuilder,
        opcode: u32,
        current_pc: &mut u32,
    ) -> Option<BranchInfo> {
        let rt = ((opcode >> 16) & 0x1F) as i64;
        let rd = ((opcode >> 11) & 0x1F) as i64;
        let sa5 = ((opcode >> 6) & 0x1F) as i64;

        let shift_amount = builder.ins().iconst(types::I64, sa5 + 32);

        let rt_addr = Self::ptr_add(builder, self.cpu.registers.as_mut_ptr() as i64, rt, 16);
        let rt_val = builder.ins().load(types::I64, MemFlags::new(), rt_addr, 0);

        let result = builder.ins().ushr(rt_val, shift_amount);

        let rd_addr = Self::ptr_add(builder, self.cpu.registers.as_mut_ptr() as i64, rd, 16);
        builder.ins().store(MemFlags::new(), result, rd_addr, 0);

        Self::increment_pc(builder, &mut self.cpu.pc as *mut u32 as i64);
        *current_pc = current_pc.wrapping_add(4);

        None
    }

    fn padduw(
        &mut self,
        builder: &mut FunctionBuilder,
        opcode: u32,
        current_pc: &mut u32,
    ) -> Option<BranchInfo> {
        let rs = ((opcode >> 21) & 0x1F) as i64;
        let rt = ((opcode >> 16) & 0x1F) as i64;
        let rd = ((opcode >> 11) & 0x1F) as i64;

        let rs_addr_lo = Self::ptr_add(builder, self.cpu.registers.as_mut_ptr() as i64, rs, 16);
        let rs_val_lo = builder
            .ins()
            .load(types::I64, MemFlags::new(), rs_addr_lo, 0);
        let rs_addr_hi = Self::ptr_add(builder, self.cpu.registers.as_mut_ptr() as i64, rs, 24);
        let rs_val_hi = builder
            .ins()
            .load(types::I64, MemFlags::new(), rs_addr_hi, 0);

        let rt_addr_lo = Self::ptr_add(builder, self.cpu.registers.as_mut_ptr() as i64, rt, 16);
        let rt_val_lo = builder
            .ins()
            .load(types::I64, MemFlags::new(), rt_addr_lo, 0);
        let rt_addr_hi = Self::ptr_add(builder, self.cpu.registers.as_mut_ptr() as i64, rt, 24);
        let rt_val_hi = builder
            .ins()
            .load(types::I64, MemFlags::new(), rt_addr_hi, 0);

        let rs_words: [Value; 4] = [
            builder.ins().ireduce(types::I32, rs_val_lo),
            {
                let shifted = builder.ins().ushr_imm(rs_val_lo, 32);
                builder.ins().ireduce(types::I32, shifted)
            },
            builder.ins().ireduce(types::I32, rs_val_hi),
            {
                let shifted = builder.ins().ushr_imm(rs_val_hi, 32);
                builder.ins().ireduce(types::I32, shifted)
            },
        ];
        let rt_words: [Value; 4] = [
            builder.ins().ireduce(types::I32, rt_val_lo),
            {
                let shifted = builder.ins().ushr_imm(rt_val_lo, 32);
                builder.ins().ireduce(types::I32, shifted)
            },
            builder.ins().ireduce(types::I32, rt_val_hi),
            {
                let shifted = builder.ins().ushr_imm(rt_val_hi, 32);
                builder.ins().ireduce(types::I32, shifted)
            },
        ];

        let max_u32 = builder.ins().iconst(types::I64, 0xFFFFFFFF);
        let mut result_words: [Value; 4] = [max_u32; 4];
        for i in 0..4 {
            let rs_word_64 = builder.ins().uextend(types::I64, rs_words[i]);
            let rt_word_64 = builder.ins().uextend(types::I64, rt_words[i]);
            let sum = builder.ins().iadd(rs_word_64, rt_word_64);

            let overflow = builder.ins().icmp(IntCC::UnsignedGreaterThan, sum, max_u32);
            result_words[i] = builder.ins().select(overflow, max_u32, sum);
        }

        let shifted_lo = builder.ins().ishl_imm(result_words[1], 32);
        let result_lo = builder.ins().bor(result_words[0], shifted_lo);
        let shifted_hi = builder.ins().ishl_imm(result_words[3], 32);
        let result_hi = builder.ins().bor(result_words[2], shifted_hi);

        let rd_addr_lo = Self::ptr_add(builder, self.cpu.registers.as_mut_ptr() as i64, rd, 16);
        builder
            .ins()
            .store(MemFlags::new(), result_lo, rd_addr_lo, 0);
        let rd_addr_hi = Self::ptr_add(builder, self.cpu.registers.as_mut_ptr() as i64, rd, 24);
        builder
            .ins()
            .store(MemFlags::new(), result_hi, rd_addr_hi, 0);

        Self::increment_pc(builder, &mut self.cpu.pc as *mut u32 as i64);
        *current_pc = current_pc.wrapping_add(4);

        None
    }

    fn di(
        &mut self,
        builder: &mut FunctionBuilder,
        _opcode: u32,
        current_pc: &mut u32,
    ) -> Option<BranchInfo> {
        let cpu_ptr = &mut self.cpu as *mut EE as i64;
        let cpu_arg = builder.ins().iconst(types::I64, cpu_ptr);
        let status_idx = builder.ins().iconst(types::I32, 12);

        let read_cop0 = self
            .module
            .declare_func_in_func(self.read_cop0_func, builder.func);
        let write_cop0 = self
            .module
            .declare_func_in_func(self.write_cop0_func, builder.func);

        let call_status = builder.ins().call(read_cop0, &[cpu_arg, status_idx]);
        let status = builder.inst_results(call_status)[0];

        let edi_shift = builder.ins().ushr_imm(status, 10);
        let edi = builder.ins().band_imm(edi_shift, 0x1);

        let exl_shift = builder.ins().ushr_imm(status, 1);
        let exl = builder.ins().band_imm(exl_shift, 0x1);

        let erl_shift = builder.ins().ushr_imm(status, 2);
        let erl = builder.ins().band_imm(erl_shift, 0x1);

        let ksu_shift = builder.ins().ushr_imm(status, 3);
        let ksu = builder.ins().band_imm(ksu_shift, 0x3);

        let edi_cond = builder.ins().icmp_imm(IntCC::Equal, edi, 1);
        let exl_cond = builder.ins().icmp_imm(IntCC::Equal, exl, 1);
        let erl_cond = builder.ins().icmp_imm(IntCC::Equal, erl, 1);
        let ksu_cond = builder.ins().icmp_imm(IntCC::Equal, ksu, 0);

        let cond1 = builder.ins().bor(edi_cond, exl_cond);
        let cond2 = builder.ins().bor(cond1, erl_cond);
        let final_cond = builder.ins().bor(cond2, ksu_cond);

        let mask = builder.ins().iconst(types::I32, !(1u32) as i64);
        let new_status = builder.ins().band(status, mask);

        let final_status = builder.ins().select(final_cond, new_status, status);

        builder
            .ins()
            .call(write_cop0, &[cpu_arg, status_idx, final_status]);

        Self::increment_pc(builder, &mut self.cpu.pc as *mut u32 as i64);
        *current_pc = current_pc.wrapping_add(4);

        None
    }

    fn eret(
        &mut self,
        builder: &mut FunctionBuilder,
        _opcode: u32,
        current_pc: &mut u32,
    ) -> Option<BranchInfo> {
        // --- Prep CPU & COP0 helpers ---
        let cpu_ptr = &mut self.cpu as *mut EE as i64;
        let cpu_arg = builder.ins().iconst(types::I64, cpu_ptr);
        let read_cop0 = self
            .module
            .declare_func_in_func(self.read_cop0_func, builder.func);
        let write_cop0 = self
            .module
            .declare_func_in_func(self.write_cop0_func, builder.func);

        // --- Read Status (COP0 idx 12) ---
        let idx12 = builder.ins().iconst(types::I32, 12);
        let call_read12 = builder.ins().call(read_cop0, &[cpu_arg, idx12]);
        let status = builder.inst_results(call_read12)[0];

        // Extract ERL bit and compare to zero
        let erl_mask = builder.ins().iconst(types::I32, 1 << 2);
        let erl_bit = builder.ins().band(status, erl_mask);
        let zero_i32 = builder.ins().iconst(types::I32, 0);
        let erl_nonzero = builder.ins().icmp(IntCC::NotEqual, erl_bit, zero_i32);

        // --- Create blocks & params (Values) ---
        let erl_true_block = builder.create_block();
        let erl_false_block = builder.create_block();
        let sideload_block = builder.create_block();
        let epc_param_val = builder.append_block_param(sideload_block, types::I32);
        let sideload_true_block = builder.create_block();
        let end_block = builder.create_block();
        let final_param_val = builder.append_block_param(end_block, types::I32);

        // --- Branch on ERL ---
        builder
            .ins()
            .brif(erl_nonzero, erl_true_block, &[], erl_false_block, &[]);

        // --- ERL=1 path: ErrorEPC, clear ERL, to sideload_block ---
        builder.switch_to_block(erl_true_block);
        let idx30 = builder.ins().iconst(types::I32, 30);
        let call_read30 = builder.ins().call(read_cop0, &[cpu_arg, idx30]);
        let error_epc = builder.inst_results(call_read30)[0];
        // clear ERL field
        let not_erl_bitmask = builder.ins().iconst(types::I32, !(1 << 2));
        let clear_erl = builder.ins().band(status, not_erl_bitmask);
        builder.ins().call(write_cop0, &[cpu_arg, idx12, clear_erl]);
        builder
            .ins()
            .jump(sideload_block, &[BlockArg::Value(error_epc)]);

        // --- ERL=0 path: EPC, clear EXL, to sideload_block ---
        builder.switch_to_block(erl_false_block);
        let idx14 = builder.ins().iconst(types::I32, 14);
        let call_read14 = builder.ins().call(read_cop0, &[cpu_arg, idx14]);
        let epc = builder.inst_results(call_read14)[0];
        // clear EXL field
        let not_exl_bitmask = builder.ins().iconst(types::I32, !(1 << 1));
        let clear_exl = builder.ins().band(status, not_exl_bitmask);
        builder.ins().call(write_cop0, &[cpu_arg, idx12, clear_exl]);
        builder.ins().jump(sideload_block, &[BlockArg::Value(epc)]);

        // --- Sideload check ---
        builder.switch_to_block(sideload_block);
        let incoming_epc = builder.block_params(sideload_block)[0];
        let sideload_ptr = builder
            .ins()
            .iconst(types::I64, &self.cpu.sideload_elf as *const bool as i64);
        let sideload_val = builder
            .ins()
            .load(types::I8, MemFlags::trusted(), sideload_ptr, 0);
        let zero_i8 = builder.ins().iconst(types::I8, 0);
        let need_sideload = builder.ins().icmp(IntCC::NotEqual, sideload_val, zero_i8);

        builder.ins().brif(
            need_sideload,
            sideload_true_block,
            &[],
            end_block,
            &[BlockArg::Value(incoming_epc)],
        );

        // --- Sideload=true: clear flag, load ELF entry, finish at end_block ---
        builder.switch_to_block(sideload_true_block);
        let load_elf = self
            .module
            .declare_func_in_func(self.load_elf_func, builder.func);
        builder.ins().call(load_elf, &[cpu_arg]);
        builder
            .ins()
            .store(MemFlags::trusted(), zero_i8, sideload_ptr, 0);
        let entry_point_ptr = builder
            .ins()
            .iconst(types::I64, &self.cpu.elf_entry_point as *const u32 as i64);
        let entry_point = builder
            .ins()
            .load(types::I32, MemFlags::trusted(), entry_point_ptr, 0);
        builder
            .ins()
            .jump(end_block, &[BlockArg::Value(entry_point)]);

        // --- End block: pick up final PC ---
        builder.switch_to_block(end_block);
        let final_pc = builder.block_params(end_block)[0];

        builder.seal_all_blocks();
        *current_pc = current_pc.wrapping_add(4);

        Some(BranchInfo::Eret {
            target: BranchTarget::Reg(final_pc),
        })
    }
}

impl EmulationBackend<EE> for JIT {
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
        Arc::new(Mutex::new(self.cpu.clone()))
    }
}
