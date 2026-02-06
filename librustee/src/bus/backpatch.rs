use std::ffi::c_void;
use std::sync::atomic::AtomicBool;

use capstone::{arch::DetailsArchInsn, Capstone};
use capstone::arch::BuildsCapstone;
use tracing::{error, trace};

use super::Bus;

pub struct Context {
    pub bus: *mut Bus,
}

pub static HANDLER_INSTALLED: AtomicBool = AtomicBool::new(false);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AccessWidth {
    B8,
    B16,
    B32,
    B64,
    B128,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AccessKind {
    Read,
    Write,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct AccessInfo {
    pub kind: AccessKind,
    pub width: AccessWidth,
}

#[cfg(any(unix, windows))]
pub struct CurrentArchHandler;

pub trait ArchHandler {
    type Context;
    type Register: Clone + PartialEq + Copy + std::fmt::Debug;

    fn create_disassembler() -> Result<Capstone, capstone::Error>;
    fn encode_stub_call(reg: &Self::Register, stub_addr: u64) -> Option<Vec<u8>>;
    fn get_instruction_pointer(ctx: *mut Self::Context) -> i64;
    fn set_instruction_pointer(ctx: *mut Self::Context, addr: u64);
    fn get_stack_pointer(ctx: *mut Self::Context) -> u64;
    fn advance_instruction_pointer(
        ctx: *mut Self::Context,
        fault_addr: i64,
    ) -> Result<(), &'static str>;
    fn parse_register_from_operand(operand: &str) -> Option<Self::Register>;
    fn register_name(reg: &Self::Register) -> &'static str;
    fn get_helper_pattern() -> &'static [&'static str];
    fn get_call_instruction() -> &'static str;
    fn get_register_value(ctx: *const Self::Context, reg_id: Self::Register) -> u64;
    fn set_register_value(ctx: *mut Self::Context, reg_id: Self::Register, value: u64);
}


unsafe fn get_mov_instruction_length(ip: *const u8) -> usize { unsafe {
    let mut len: usize = 0;

    loop {
        let b = *ip.add(len);
        if (0x40..=0x4F).contains(&b)
            || b == 0x66
            || b == 0x67
            || b == 0xF2 || b == 0xF3
        {
            len += 1;
            if len > 4 { return 0; }
        } else {
            break;
        }
    }

    let opc = *ip.add(len);
    len += 1;

    let is_two_byte = opc == 0x0F;
    let opc_effective = if is_two_byte {
        let opc2 = *ip.add(len);
        len += 1;
        opc2
    } else {
        opc
    };

    if is_two_byte {
        if ![0xB6, 0xB7, 0xBE, 0xBF].contains(&opc_effective) {
            return 0;
        }
    } else {
        if ![0x88, 0x89, 0x8A, 0x8B].contains(&opc_effective) {
            return 0;
        }
    }

    let modrm = *ip.add(len);
    len += 1;
    let mod_bits = modrm >> 6;
    let _reg = (modrm >> 3) & 0x7;
    let rm = modrm & 0x7;

    if mod_bits == 0x3 {
        return 0;
    }

    let mut disp_size: usize = 0;
    if rm == 0x4 {
        let sib = *ip.add(len);
        len += 1;
        let _scale = sib >> 6;
        let _index = (sib >> 3) & 0x7;
        let base = sib & 0x7;

        if mod_bits == 0x0 && base == 0x5 {
            disp_size = 4;
        }
    }

    disp_size = match mod_bits {
        0x0 => if rm == 0x5 { 4 } else { disp_size },
        0x1 => 1,
        0x2 => 4,
        _ => return 0,
    };
    len += disp_size;

    len
}}

    
pub extern "C" fn io_write8_stub(bus: *mut Bus, addr: u32, value: u8) {
    unsafe {
        if bus.is_null() {
            error!(
                "Null bus pointer in io_write8_stub: addr=0x{:08X}, value=0x{:02X}",
                addr, value
            );
            panic!("Null bus pointer in io_write8_stub");
        }
        let bus = &mut *bus;
        bus.io_write8(addr, value);
    }
}

pub extern "C" fn io_write16_stub(bus: *mut Bus, addr: u32, value: u16) {
    unsafe {
        if bus.is_null() {
            error!(
                "Null bus pointer in io_write16_stub: addr=0x{:08X}, value=0x{:04X}",
                addr, value
            );
            panic!("Null bus pointer in io_write16_stub");
        }
        let bus = &mut *bus;
        bus.io_write16(addr, value);
    }
}

pub extern "C" fn io_write32_stub(bus: *mut Bus, addr: u32, value: u32) {
    unsafe {
        if bus.is_null() {
            error!(
                "Null bus pointer in io_write32_stub: addr=0x{:08X}, value=0x{:08X}",
                addr, value
            );
            panic!("Null bus pointer in io_write32_stub");
        }
        let bus = &mut *bus;
        bus.io_write32(addr, value);
    }
}

pub extern "C" fn io_write64_stub(bus: *mut Bus, addr: u32, value: u64) {
    unsafe {
        if bus.is_null() {
            error!(
                "Null bus pointer in io_write64_stub: addr=0x{:08X}, value=0x{:016X}",
                addr, value
            );
            panic!("Null bus pointer in io_write64_stub");
        }
        let bus = &mut *bus;
        bus.io_write64(addr, value);
    }
}

pub extern "C" fn io_write128_stub(bus: *mut Bus, addr: u32, lo: u64, hi: u64) {
    unsafe {
        if bus.is_null() {
            error!(
                "Null bus pointer in io_write128_stub: addr=0x{:08X}, lo=0x{:016X}, hi=0x{:016X}",
                addr, lo, hi
            );
            panic!("Null bus pointer in io_write128_stub");
        }

        let value = ((hi as u128) << 64) | (lo as u128);

        let bus = &mut *bus;
        bus.io_write128(addr, value);
    }
}

pub extern "C" fn io_read8_stub(bus: *mut Bus, addr: u32) -> u8 {
    unsafe {
        if bus.is_null() {
            error!("Null bus pointer in io_read8_stub: addr=0x{:08X}", addr);
            panic!("Null bus pointer in io_read8_stub");
        }
        let bus = &mut *bus;
        bus.io_read8(addr)
    }
}

pub extern "C" fn io_read16_stub(bus: *mut Bus, addr: u32) -> u16 {
    unsafe {
        if bus.is_null() {
            error!("Null bus pointer in io_read16_stub: addr=0x{:08X}", addr);
            panic!("Null bus pointer in io_read16_stub");
        }
        let bus = &mut *bus;
        bus.io_read16(addr)
    }
}

pub extern "C" fn io_read32_stub(bus: *mut Bus, addr: u32) -> u32 {
    unsafe {
        if bus.is_null() {
            error!("Null bus pointer in io_read32_stub: addr=0x{:08X}", addr);
            panic!("Null bus pointer in io_read32_stub");
        }
        let bus = &mut *bus;
        bus.io_read32(addr)
    }
}

pub extern "C" fn io_read64_stub(bus: *mut Bus, addr: u32) -> u64 {
    unsafe {
        if bus.is_null() {
            error!("Null bus pointer in io_read64_stub: addr=0x{:08X}", addr);
            panic!("Null bus pointer in io_read64_stub");
        }
        let bus = &mut *bus;
        bus.io_read64(addr)
    }
}

pub extern "C" fn io_read128_stub(bus: *mut Bus, addr: u32) -> u128 {
    unsafe {
        if bus.is_null() {
            error!("Null bus pointer in io_read128_stub: addr=0x{:08X}", addr);
            panic!("Null bus pointer in io_read128_stub");
        }
        let bus = &mut *bus;
        bus.io_read128(addr)
    }
}

#[cfg(target_arch = "x86_64")]
pub mod x86_64_impl {
    use super::*;
    use capstone::arch::x86::ArchMode;

    #[derive(Clone, PartialEq, Copy, Debug)]
    pub enum X86Register {
        Rax,
        Rcx,
        Rdx,
        Rsi,
        Rdi,
        R8,
        R9,
        R10,
        R11,
    }

    pub fn create_disassembler_impl() -> Result<Capstone, capstone::Error> {
        Capstone::new().x86().mode(ArchMode::Mode64).build()
    }

    pub fn encode_stub_call_impl(reg: &X86Register, stub_addr: u64) -> Option<Vec<u8>> {
        let mut buf = match reg {
            X86Register::Rax => vec![0x48, 0xB8], // movabs rax, imm64
            X86Register::Rcx => vec![0x48, 0xB9], // movabs rcx, imm64
            X86Register::Rdx => vec![0x48, 0xBA], // movabs rdx, imm64
            X86Register::Rsi => vec![0x48, 0xBE], // movabs rsi, imm64
            X86Register::Rdi => vec![0x48, 0xBF], // movabs rdi, imm64
            X86Register::R8 => vec![0x49, 0xB8],  // movabs r8, imm64
            X86Register::R9 => vec![0x49, 0xB9],  // movabs r9, imm64
            X86Register::R10 => vec![0x49, 0xBA], // movabs r10, imm64
            X86Register::R11 => vec![0x49, 0xBB], // movabs r11, imm64
        };

        buf.extend_from_slice(&stub_addr.to_le_bytes());
        Some(buf)
    }

    pub fn parse_register_from_operand_impl(operand: &str) -> Option<X86Register> {
        match operand.trim() {
            "rax" => Some(X86Register::Rax),
            "rcx" => Some(X86Register::Rcx),
            "rdx" => Some(X86Register::Rdx),
            "rsi" => Some(X86Register::Rsi),
            "rdi" => Some(X86Register::Rdi),
            "r8" => Some(X86Register::R8),
            "r9" => Some(X86Register::R9),
            "r10" => Some(X86Register::R10),
            "r11" => Some(X86Register::R11),
            _ => None,
        }
    }

    pub fn register_name_impl(reg: &X86Register) -> &'static str {
        match reg {
            X86Register::Rax => "rax",
            X86Register::Rcx => "rcx",
            X86Register::Rdx => "rdx",
            X86Register::Rsi => "rsi",
            X86Register::Rdi => "rdi",
            X86Register::R8 => "r8",
            X86Register::R9 => "r9",
            X86Register::R10 => "r10",
            X86Register::R11 => "r11",
        }
    }

    pub fn get_helper_pattern_impl() -> &'static [&'static str] {
        &[
            "librustee::ee::jit::__bus_write8",
            "librustee::ee::jit::__bus_write16",
            "librustee::ee::jit::__bus_write32",
            "librustee::ee::jit::__bus_write64",
            "librustee::ee::jit::__bus_write128",
            "librustee::ee::jit::__bus_read8",
            "librustee::ee::jit::__bus_read16",
            "librustee::ee::jit::__bus_read32",
            "librustee::ee::jit::__bus_read64",
            "librustee::ee::jit::__bus_read128",
        ]
    }

    pub fn get_call_instruction_impl() -> &'static str {
        "call"
    }
}

#[cfg(unix)]
impl ArchHandler for CurrentArchHandler {
    type Context = nix::libc::ucontext_t;
    type Register = x86_64_impl::X86Register;

    fn create_disassembler() -> Result<Capstone, capstone::Error> {
        x86_64_impl::create_disassembler_impl()
    }

    fn encode_stub_call(reg: &Self::Register, stub_addr: u64) -> Option<Vec<u8>> {
        x86_64_impl::encode_stub_call_impl(reg, stub_addr)
    }

    fn get_instruction_pointer(ctx: *mut Self::Context) -> i64 {
        unsafe { (*ctx).uc_mcontext.gregs[nix::libc::REG_RIP as usize] }
    }

    fn set_instruction_pointer(ctx: *mut Self::Context, addr: u64) {
        unsafe {
            (*ctx).uc_mcontext.gregs[nix::libc::REG_RIP as usize] = addr as i64;
        }
    }

    fn get_stack_pointer(ctx: *mut Self::Context) -> u64 {
        unsafe { (*ctx).uc_mcontext.gregs[nix::libc::REG_RSP as usize] as u64 }
    }

    fn advance_instruction_pointer(
        ctx: *mut Self::Context,
        fault_addr: i64,
    ) -> Result<(), &'static str> {
        let length = unsafe { get_mov_instruction_length(fault_addr as *const u8) };
        if length == 0 {
            panic!("Unrecognized instruction format at fault address");
        }

        trace!(
            "Advancing IP by {} bytes from 0x{:x}",
            length,
            fault_addr
        );
        Self::set_instruction_pointer(ctx, fault_addr as u64 + length as u64);
        Ok(())
    }

    fn parse_register_from_operand(operand: &str) -> Option<Self::Register> {
        x86_64_impl::parse_register_from_operand_impl(operand)
    }

    fn register_name(reg: &Self::Register) -> &'static str {
        x86_64_impl::register_name_impl(reg)
    }

    fn get_helper_pattern() -> &'static [&'static str] {
        x86_64_impl::get_helper_pattern_impl()
    }

    fn get_call_instruction() -> &'static str {
        x86_64_impl::get_call_instruction_impl()
    }

    fn get_register_value(ctx: *const Self::Context, reg_id: Self::Register) -> u64 {
        unsafe { (*ctx).uc_mcontext.gregs[match reg_id {
            x86_64_impl::X86Register::Rax => nix::libc::REG_RAX as usize,
            x86_64_impl::X86Register::Rcx => nix::libc::REG_RCX as usize,
            x86_64_impl::X86Register::Rdx => nix::libc::REG_RDX as usize,
            x86_64_impl::X86Register::R8 => nix::libc::REG_R8 as usize,
            x86_64_impl::X86Register::R9 => nix::libc::REG_R9 as usize,
            _ => panic!("Unsupported register for value access: {:?}", reg_id),
        }] as u64 }
    }

    fn set_register_value(ctx: *mut Self::Context, reg_id: Self::Register, value: u64) {
        unsafe { (*ctx).uc_mcontext.gregs[match reg_id {
            x86_64_impl::X86Register::Rax => nix::libc::REG_RAX as usize,
            x86_64_impl::X86Register::Rcx => nix::libc::REG_RCX as usize,
            x86_64_impl::X86Register::Rdx => nix::libc::REG_RDX as usize,
            x86_64_impl::X86Register::R8 => nix::libc::REG_R8 as usize,
            x86_64_impl::X86Register::R9 => nix::libc::REG_R9 as usize,
            _ => panic!("Unsupported register for value access: {:?}", reg_id),
        }] = value as i64; }
    }
}

#[cfg(windows)]
impl ArchHandler for CurrentArchHandler {
    type Context = windows_sys::Win32::System::Diagnostics::Debug::CONTEXT;
    type Register = x86_64_impl::X86Register;

    fn create_disassembler() -> Result<Capstone, capstone::Error> {
        x86_64_impl::create_disassembler_impl()
    }

    fn encode_stub_call(reg: &Self::Register, stub_addr: u64) -> Option<Vec<u8>> {
        x86_64_impl::encode_stub_call_impl(reg, stub_addr)
    }

    fn get_instruction_pointer(ctx: *mut Self::Context) -> i64 {
        unsafe { (*ctx).Rip as i64 }
    }

    fn set_instruction_pointer(ctx: *mut Self::Context, addr: u64) {
        unsafe {
            (*ctx).Rip = addr;
        }
    }

    fn get_stack_pointer(ctx: *mut Self::Context) -> u64 {
        unsafe { (*ctx).Rsp }
    }

    fn advance_instruction_pointer(
        ctx: *mut Self::Context,
        fault_addr: i64,
    ) -> Result<(), &'static str> {
        let length = unsafe { get_mov_instruction_length(fault_addr as *const u8) };
        if length == 0 {
            panic!("Unrecognized instruction format at fault address");
        }

        trace!(
            "Advancing IP by {} bytes from 0x{:x}",
            length,
            fault_addr
        );
        Self::set_instruction_pointer(ctx, (fault_addr as u64 + length as u64));
        Ok(())
    }

    fn parse_register_from_operand(operand: &str) -> Option<Self::Register> {
        x86_64_impl::parse_register_from_operand_impl(operand)
    }

    fn register_name(reg: &Self::Register) -> &'static str {
        x86_64_impl::register_name_impl(reg)
    }

    fn get_helper_pattern() -> &'static [&'static str] {
        x86_64_impl::get_helper_pattern_impl()
    }

    fn get_call_instruction() -> &'static str {
        x86_64_impl::get_call_instruction_impl()
    }

    fn get_register_value(ctx: *const Self::Context, reg_id: Self::Register) -> u64 {
        unsafe {
            match reg_id {
                x86_64_impl::X86Register::Rax => (*ctx).Rax,
                x86_64_impl::X86Register::Rcx => (*ctx).Rcx,
                x86_64_impl::X86Register::Rdx => (*ctx).Rdx,
                x86_64_impl::X86Register::R8 => (*ctx).R8,
                x86_64_impl::X86Register::R9 => (*ctx).R9,
                _ => panic!("Unsupported register for value access: {:?}", reg_id),
            }
        }
    }

    fn set_register_value(ctx: *mut Self::Context, reg_id: Self::Register, value: u64) {
        unsafe {
            match reg_id {
                x86_64_impl::X86Register::Rax => (*ctx).Rax = value,
                x86_64_impl::X86Register::Rcx => (*ctx).Rcx = value,
                x86_64_impl::X86Register::Rdx => (*ctx).Rdx = value,
                x86_64_impl::X86Register::R8 => (*ctx).R8 = value,
                x86_64_impl::X86Register::R9 => (*ctx).R9 = value,
                _ => panic!("Unsupported register for value access: {:?}", reg_id),
            }
        }
    }
}

const N_WRITES: usize = 5;
pub(crate) static mut REGISTER_MAP: [Option<x86_64_impl::X86Register>; N_WRITES] = [None; N_WRITES];
pub(crate) static mut REGISTER_PAIR: Option<(x86_64_impl::X86Register, x86_64_impl::X86Register)> = None;


pub fn map_cs_reg(cs_reg: u16) -> Option<x86_64_impl::X86Register> {
    use capstone::arch::x86::X86Reg as X;
    match cs_reg {
        x if x == X::X86_REG_RAX as u16 => Some(x86_64_impl::X86Register::Rax),
        x if x == X::X86_REG_RCX as u16 || x == X::X86_REG_ECX as u16 || x == X::X86_REG_CX as u16 || x == X::X86_REG_CL as u16 => Some(x86_64_impl::X86Register::Rcx),
        x if x == X::X86_REG_RDX as u16 || x == X::X86_REG_EDX as u16 || x == X::X86_REG_DX as u16 || x == X::X86_REG_DL as u16 => Some(x86_64_impl::X86Register::Rdx),
        x if x == X::X86_REG_R8  as u16 || x == X::X86_REG_R8D as u16 => Some(x86_64_impl::X86Register::R8),
        x if x == X::X86_REG_R9  as u16 || x == X::X86_REG_R9D as u16 => Some(x86_64_impl::X86Register::R9),
        _ => None,
    }
}

pub fn find_function_end(cs: &Capstone, func_ptr: *const c_void, size: usize) -> *const c_void {
    let addr = func_ptr as u64;
    let code = unsafe { std::slice::from_raw_parts(addr as *const u8, size) };

    let insns = match cs.disasm_all(code, addr) {
        Ok(list) => list,
        Err(_) => return ((addr as usize) + size) as *const c_void,
    };

    for insn in insns.iter() {
        if let Some(mn) = insn.mnemonic() {
            if mn == "ret" {
                let end_addr = insn.address().wrapping_add(insn.bytes().len() as u64);
                return (end_addr as usize) as *const c_void;
            }
        }
    }

    panic!("No `ret` found in the scanned window!");
}

pub fn find_memory_access_register(
    cs: &Capstone,
    func_ptr: *const c_void,
    is_128: bool,
) -> Option<x86_64_impl::X86Register> {
    let addr = func_ptr as u64;
    let code_size = 150usize;
    let code = unsafe { std::slice::from_raw_parts(addr as *const u8, code_size) };

    let instructions = cs.disasm_all(code, addr).expect("Disassembly failed");

    if is_128 {
        let mut low_reg: Option<x86_64_impl::X86Register> = None;
        let mut high_reg: Option<x86_64_impl::X86Register> = None;

        for insn in instructions
            .iter()
            .rev()
            .skip_while(|i| i.mnemonic().map_or(true, |m| m != "ret"))
            .skip(1)
        {
            if let Ok(detail) = cs.insn_detail(&insn) {
                if let capstone::arch::ArchDetail::X86Detail(x86) = detail.arch_detail() {
                    let ops: Vec<_> = x86.operands().collect();

                    if insn.mnemonic() == Some("mov") && ops.len() == 2 {
                        trace!(
                            "insn {:#x}: found mov (len={} bytes={:x?})",
                            insn.address(),
                            ops.len(),
                            insn.bytes()
                        );

                        use capstone::arch::x86::X86OperandType;

                        if let X86OperandType::Reg(src_cs) = ops[0].op_type {
                            if let X86OperandType::Mem(mem) = ops[1].op_type {
                                if mem.base().0 != 0 {
                                    let src_name = cs.reg_name(src_cs).unwrap_or("??".to_string());
                                    let base_name = cs.reg_name(mem.base()).unwrap_or("??".to_string());
                                    trace!(
                                        "mov detected: src={} -> mem[{} + {:#x}]",
                                        src_name,
                                        base_name,
                                        mem.disp()
                                    );

                                    if let Some(src) = map_cs_reg(src_cs.0) {
                                        if mem.disp() == 0 {
                                            trace!("setting low_reg = {} ({:?})", src_name, src);
                                            low_reg = Some(src);
                                        } else if mem.disp() == 8 {
                                            trace!("setting high_reg = {} ({:?})", src_name, src);
                                            high_reg = Some(src);
                                        }

                                        if let (Some(l), Some(h)) = (low_reg, high_reg) {
                                            unsafe { super::backpatch::REGISTER_PAIR = Some((l, h)); }
                                            trace!("found 128-bit pair early: low={:?}, high={:?}; REGISTER_PAIR set", l, h);
                                            return Some(l);
                                        }
                                    } else {
                                        panic!("unmapped src reg: {}", src_name);
                                    }
                                }
                            }
                        } else if let X86OperandType::Mem(mem) = ops[0].op_type {
                            if let X86OperandType::Reg(src_cs) = ops[1].op_type {
                                if mem.base().0 != 0 {
                                    let src_name = cs.reg_name(src_cs).unwrap_or("??".to_string());
                                    let base_name = cs.reg_name(mem.base()).unwrap_or("??".to_string());
                                    trace!(
                                        "mov detected (rev): src={} -> mem[{} + {:#x}]",
                                        src_name,
                                        base_name,
                                        mem.disp()
                                    );

                                    if let Some(src) = map_cs_reg(src_cs.0) {
                                        if mem.disp() == 0 {
                                            trace!("setting low_reg = {} ({:?})", src_name, src);
                                            low_reg = Some(src);
                                        } else if mem.disp() == 8 {
                                            trace!("setting high_reg = {} ({:?})", src_name, src);
                                            high_reg = Some(src);
                                        }

                                        if let (Some(l), Some(h)) = (low_reg, high_reg) {
                                            unsafe { super::backpatch::REGISTER_PAIR = Some((l, h)); }
                                            trace!("found 128-bit pair early: low={:?}, high={:?}; REGISTER_PAIR set", l, h);
                                            return Some(l);
                                        }
                                    } else {
                                        panic!("unmapped src reg (rev): {}", src_name);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        panic!(
            "no 128-bit pair found (low={:?}, high={:?}) for function at {:#x}",
            low_reg, high_reg, addr
        );
    }

    for insn in instructions
        .iter()
        .rev()
        .skip_while(|i| i.mnemonic().map_or(true, |m| m != "ret"))
        .skip(1)
    {
        if let Ok(detail) = cs.insn_detail(&insn) {
            if let capstone::arch::ArchDetail::X86Detail(x86) = detail.arch_detail() {
                let ops: Vec<_> = x86.operands().collect();

                if insn.mnemonic() == Some("mov") && ops.len() == 2 {
                    trace!(
                        "insn {:#x}: found mov (len={} bytes={:x?}) op_str='{}'",
                        insn.address(),
                        ops.len(),
                        insn.bytes(),
                        insn.op_str().unwrap_or("")
                    );

                    use capstone::arch::x86::X86OperandType;

                    for op in ops.iter() {
                        if let X86OperandType::Reg(regop) = op.op_type {
                            if regop.0 != 0 {
                                let reg_name = cs.reg_name(regop).unwrap_or("??".to_string());

                                if let Some(mapped) = map_cs_reg(regop.0) {
                                    trace!("mapped reg {} -> {:?}", reg_name, mapped);
                                    return Some(mapped);
                                } else {
                                    panic!("encountered unmapped register: {}", reg_name);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    panic!("no single-register mov found for function at {:#x}", addr);
}

pub unsafe fn execute_stub<H: ArchHandler<Register = x86_64_impl::X86Register>>(
    ctx: *mut H::Context,
    access: AccessInfo,
    fault_addr: u32,
) { unsafe {
    let bus_ptr = super::BUS_PTR as *mut Bus;
    let addr = fault_addr;

    use AccessKind::*;
    use AccessWidth::*;

    match (access.kind, access.width) {
        (Write, B8) => {
            let reg_id = REGISTER_MAP[0].expect("no register cached for write8");
            let value = H::get_register_value(ctx, reg_id) as u8;
            io_write8_stub(bus_ptr, addr, value);
        }
        (Write, B16) => {
            let reg_id = REGISTER_MAP[1].expect("no register cached for write16");
            let value = H::get_register_value(ctx, reg_id) as u16;
            io_write16_stub(bus_ptr, addr, value);
        }
        (Write, B32) => {
            let reg_id = REGISTER_MAP[2].expect("no register cached for write32");
            let value = H::get_register_value(ctx, reg_id) as u32;
            io_write32_stub(bus_ptr, addr, value);
        }
        (Write, B64) => {
            let reg_id = REGISTER_MAP[3].expect("no register cached for write64");
            let value = H::get_register_value(ctx, reg_id);
            io_write64_stub(bus_ptr, addr, value);
        }
        (Write, B128) => {
            let (low_reg, high_reg) = REGISTER_PAIR.expect("no register pair cached");
            let low_u64 = H::get_register_value(ctx, low_reg);
            let high_u64 = H::get_register_value(ctx, high_reg);
            io_write128_stub(bus_ptr, addr, low_u64, high_u64);
        }
        (Read, B8) => {
            let value = io_read8_stub(bus_ptr, addr);
            H::set_register_value(ctx, x86_64_impl::X86Register::Rax, value as u64);
        }
        (Read, B16) => {
            let value = io_read16_stub(bus_ptr, addr);
            H::set_register_value(ctx, x86_64_impl::X86Register::Rax, value as u64);
        }
        (Read, B32) => {
            let value = io_read32_stub(bus_ptr, addr);
            H::set_register_value(ctx, x86_64_impl::X86Register::Rax, value as u64);
        }
        (Read, B64) => {
            let value = io_read64_stub(bus_ptr, addr);
            H::set_register_value(ctx, x86_64_impl::X86Register::Rax, value);
        }
        (Read, B128) => {
            let value = io_read128_stub(bus_ptr, addr);
            H::set_register_value(ctx, x86_64_impl::X86Register::Rax, value as u64);
            H::set_register_value(ctx, x86_64_impl::X86Register::Rdx, (value >> 64) as u64);
        }
    }
}}