use std::sync::atomic::AtomicBool;

use capstone::Capstone;
use capstone::arch::BuildsCapstone;
use tracing::{debug, error, trace};

use super::Bus;

pub struct Context {
    pub bus: *mut Bus,
}

pub static HANDLER_INSTALLED: AtomicBool = AtomicBool::new(false);

#[cfg(any(unix, windows))]
pub struct CurrentArchHandler;

pub trait ArchHandler {
    type Context;
    type Register: Clone + PartialEq;

    fn create_disassembler() -> Result<Capstone, capstone::Error>;
    fn encode_stub_call(reg: &Self::Register, stub_addr: u64) -> Option<Vec<u8>>;
    fn get_instruction_pointer(ctx: *mut Self::Context) -> i64;
    fn set_instruction_pointer(ctx: *mut Self::Context, addr: u64);
    fn get_stack_pointer(ctx: *mut Self::Context) -> u64;
    fn advance_instruction_pointer(
        ctx: *mut Self::Context,
        cs: &Capstone,
        fault_addr: i64,
    ) -> Result<(), &'static str>;
    fn parse_register_from_operand(operand: &str) -> Option<Self::Register>;
    fn register_name(reg: &Self::Register) -> &'static str;
    fn get_helper_pattern() -> &'static [&'static str];
    fn get_call_instruction() -> &'static str;
}

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
                "Null bus pointer in io_write32_stub: addr=0x{:08X}, value=0x{:08X}",
                addr, value
            );
            panic!("Null bus pointer in io_write32_stub");
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
                "Null bus pointer in io_write64_stub: addr=0x{:08X}, value=0x{:08X}",
                addr, value
            );
            panic!("Null bus pointer in io_write64_stub");
        }
        let bus = &mut *bus;
        bus.io_write64(addr, value);
    }
}

pub extern "C" fn io_write128_stub(bus: *mut Bus, addr: u32, value: u128) {
    unsafe {
        if bus.is_null() {
            error!(
                "Null bus pointer in io_write128_stub: addr=0x{:08X}, value=0x{:08X}",
                addr, value
            );
            panic!("Null bus pointer in io_write128_stub");
        }
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
    use tracing::error;

    #[derive(Clone, PartialEq)]
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
            _ => {
                panic!(
                    "Unsupported register for stub call: {}",
                    register_name_impl(reg)
                )
            }
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
            _ => panic!("Unsupported register: {}", operand),
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
        cs: &Capstone,
        fault_addr: i64,
    ) -> Result<(), &'static str> {
        let buf_size = 16;
        let buf = unsafe { std::slice::from_raw_parts(fault_addr as *const u8, buf_size) };

        if let Ok(insns) = cs.disasm_all(buf, fault_addr as u64) {
            if let Some(insn) = insns.iter().next() {
                trace!(
                    "Current instruction at 0x{:x}: {} {}",
                    fault_addr,
                    insn.mnemonic().unwrap_or(""),
                    insn.op_str().unwrap_or("")
                );
                Self::set_instruction_pointer(ctx, (fault_addr + insn.bytes().len() as i64) as u64);
                return Ok(());
            }
        }
        Err("Failed to advance instruction pointer")
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
        cs: &Capstone,
        fault_addr: i64,
    ) -> Result<(), &'static str> {
        let buf_size = 16;
        let buf = unsafe { std::slice::from_raw_parts(fault_addr as *const u8, buf_size) };

        if let Ok(insns) = cs.disasm_all(buf, fault_addr as u64) {
            if let Some(insn) = insns.iter().next() {
                trace!(
                    "Current instruction at 0x{:x}: {} {}",
                    fault_addr,
                    insn.mnemonic().unwrap_or(""),
                    insn.op_str().unwrap_or("")
                );
                Self::set_instruction_pointer(ctx, (fault_addr + insn.bytes().len() as i64) as u64);
                return Ok(());
            }
        }
        Err("Failed to advance instruction pointer")
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
}
