use std::ops::Add;
use std::sync::atomic::AtomicBool;

use backtrace::Backtrace;
use capstone::Capstone;
use capstone::arch::BuildsCapstone;
use tracing::trace;

use super::Bus;

pub struct Context {
    pub bus: *mut Bus,
}

pub static HANDLER_INSTALLED: AtomicBool = AtomicBool::new(false);

pub trait ArchHandler {
    type Context;
    type Register: Clone + PartialEq;
    
    fn create_disassembler() -> Result<Capstone, capstone::Error>;
    fn encode_stub_call(reg: &Self::Register, stub_addr: u64) -> Option<Vec<u8>>;
    fn get_instruction_pointer(ctx: *mut Self::Context) -> i64;
    fn set_instruction_pointer(ctx: *mut Self::Context, addr: u64);
    fn get_stack_pointer(ctx: *mut Self::Context) -> u64;
    fn advance_instruction_pointer(ctx: *mut Self::Context, cs: &Capstone, fault_addr: i64) -> Result<(), &'static str>;
    fn parse_register_from_operand(operand: &str) -> Option<Self::Register>;
    fn register_name(reg: &Self::Register) -> &'static str;
    fn get_helper_pattern() -> &'static [&'static str];
    fn get_call_instruction() -> &'static str;
}

// X86-64 common implementation
#[cfg(target_arch = "x86_64")]
pub mod x86_64_impl {
    use super::*;
    use capstone::arch::x86::ArchMode;
    use tracing::error;

    #[derive(Clone, PartialEq)]
    pub enum X86Register {
        Rax,
        Rcx,
        R8,
        R9,
        R10,
        R11,
    }

    pub trait X86HandlerImpl {
        // Implementation methods that any X86_64 architecture handler should provide
            }

            pub fn create_disassembler_impl() -> Result<Capstone, capstone::Error> {
        Capstone::new().x86().mode(ArchMode::Mode64).build()
            }

            pub fn encode_stub_call_impl(reg: &X86Register, stub_addr: u64) -> Option<Vec<u8>> {
        let mut buf = match reg {
            X86Register::Rax => vec![0x48, 0xB8], // movabs rax, imm64
            X86Register::Rcx => vec![0x48, 0xB9], // movabs rcx, imm64
            X86Register::R8  => vec![0x49, 0xB8], // movabs r8, imm64
            X86Register::R9  => vec![0x49, 0xB9], // movabs r9, imm64
            _ => {
                error!(
                "Unsupported register for stub call: {}",
                register_name_impl(reg)
            );
                return None;
            }
        };

        buf.extend_from_slice(&stub_addr.to_le_bytes());
        Some(buf)
            }

            pub fn parse_register_from_operand_impl(operand: &str) -> Option<X86Register> {
        match operand.trim() {
            "rax" => Some(X86Register::Rax),
            "rcx" => Some(X86Register::Rcx),
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
            X86Register::R8 => "r8",
            X86Register::R9 => "r9",
            X86Register::R10 => "r10",
            X86Register::R11 => "r11",
        }
            }

            pub fn get_helper_pattern_impl() -> &'static [&'static str] {
        &[
            "librustee::ee::jit::__bus_write32",
            "librustee::ee::jit::__bus_read32",
        ]
            }

            pub fn get_call_instruction_impl() -> &'static str {
        "call"
            }
    }


#[cfg(not(any(target_arch = "x86_64")))]
compile_error!("Unsupported architecture");

#[unsafe(no_mangle)]
pub extern "C" fn io_write32_stub(bus_ptr: *mut Bus, address: u64, value: u32) {
    let bus = unsafe { &mut *bus_ptr };
    bus.io_write32(address as u32, value);
}

#[unsafe(no_mangle)]
pub extern "C" fn io_read32_stub(bus_ptr: *mut Bus, address: u64) -> u32 {
    let bus = unsafe { &mut *bus_ptr };
    bus.io_read32(address as u32)
}

pub fn patch_stub_call<H: ArchHandler>(
    cs: &Capstone,
    ip: usize,
    scan_back: usize,
    stub_addr: u64
) -> Option<(u64, Vec<u8>)> {
    let adjusted_ip = ip.add(16);
    let scan_start = adjusted_ip.saturating_sub(scan_back);
    let buf: &[u8] = unsafe { std::slice::from_raw_parts(scan_start as *const u8, scan_back) };
    trace!("Disassembling buffer: start=0x{:x}, size={}", scan_start, scan_back);

    if let Ok(insns) = cs.disasm_all(buf, scan_start as u64) {
        let insn_vec = insns.iter().collect::<Vec<_>>();
        for i in 0..insn_vec.len().saturating_sub(1) {
            let insn = &insn_vec[i];
            let mnem = insn.mnemonic().unwrap_or("");
            if mnem == "movabs" {
                let opstr = insn.op_str().unwrap_or("");
                let ops: Vec<&str> = opstr.split(',').map(|s| s.trim()).collect();
                if ops.len() >= 2 {
                    let mov_reg = ops[0];
                    let next_insn = &insn_vec[i + 1];
                    let next_mnem = next_insn.mnemonic().unwrap_or("");
                    if next_mnem == "call" && next_insn.op_str().unwrap_or("").trim() == mov_reg {
                        let movabs_addr = insn.address();
                        if let Some(reg) = H::parse_register_from_operand(mov_reg) {
                            if let Some(patch_bytes) = H::encode_stub_call(&reg, stub_addr) {
                                return Some((movabs_addr, patch_bytes));
                            }
                        }
                    }
                }
            }
        }
    }
    None
}

pub fn find_bus_helper_frame<H: ArchHandler>(backtrace: &Backtrace) -> Option<(usize, &'static str)> {
    for (frame_idx, frame) in backtrace.frames().iter().enumerate() {
        for sym in frame.symbols() {
            if let Some(name) = sym.name() {
                let name_str = name.to_string();
                for &pattern in H::get_helper_pattern().iter() {
                    if name_str.contains(pattern) {
                        trace!(
                            "Found helper symbol `{}` at frame {} (matched `{}`)",
                            name_str, frame_idx, pattern
                        );
                        return Some((frame_idx, pattern));
                    }
                }
            }
        }
    }
    None
}

pub fn detect_access_type(backtrace: &Backtrace) -> (bool, Option<&'static str>) {
    let mut is_jit = false;
    let mut access_type = None;

    for (_frame_idx, frame) in backtrace.frames().iter().enumerate() {
        for sym in frame.symbols() {
            if let Some(name) = sym.name() {
                let name_str = name.to_string();
                if name_str.contains("__bus_write32") || name_str.contains("__bus_read32") {
                    is_jit = true;
                    break;
                } else if name_str.contains("hw_write32") {
                    access_type = Some("write");
                } else if name_str.contains("hw_read32") {
                    access_type = Some("read");
                }
            }
        }
    }

    (is_jit, access_type)
}

pub fn get_stub_addr_from_pattern(pattern: &str) -> Option<u64> {
    if pattern.contains("__bus_write32") {
        Some(io_write32_stub as *const () as u64)
    } else if pattern.contains("__bus_read32") {
        Some(io_read32_stub as *const () as u64)
    } else {
        None
    }
}

#[cfg(target_arch = "x86_64")]
pub struct CurrentArchHandler;

#[cfg(target_arch = "x86_64")]
impl x86_64_impl::X86HandlerImpl for CurrentArchHandler {}

#[cfg(all(target_arch = "x86_64", unix))]
use nix::libc;


#[cfg(all(target_arch = "x86_64", unix))]
impl ArchHandler for CurrentArchHandler {
    type Context = std::ffi::c_void;
    type Register = x86_64_impl::X86Register;
}

#[cfg(all(target_arch = "x86_64", windows))]
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
        #[cfg(unix)]
        unsafe {
            let uc = &*(ctx as *const nix::libc::ucontext_t);
            uc.uc_mcontext.gregs[nix::libc::REG_RIP as usize]
        }

        #[cfg(windows)]
        unsafe {
            let ctx = &*ctx;
            ctx.Rip as i64
        }
    }

    fn set_instruction_pointer(ctx: *mut Self::Context, addr: u64) {
        #[cfg(unix)]
        unsafe {
            let uc = &mut *(ctx as *mut nix::libc::ucontext_t);
            uc.uc_mcontext.gregs[nix::libc::REG_RIP as usize] = addr as i64;
        }

        #[cfg(windows)]
        unsafe {
            let ctx = &mut *ctx;
            ctx.Rip = addr;
        }
    }

    fn get_stack_pointer(ctx: *mut Self::Context) -> u64 {
        #[cfg(unix)]
        unsafe {
            let uc = &*(ctx as *const nix::libc::ucontext_t);
            uc.uc_mcontext.gregs[nix::libc::REG_RSP as usize] as u64
        }

        #[cfg(windows)]
        unsafe {
            let ctx = &*ctx;
            ctx.Rsp
        }
    }

    fn advance_instruction_pointer(ctx: *mut Self::Context, cs: &Capstone, fault_addr: i64) -> Result<(), &'static str> {
        // Find the size of the current instruction to advance RIP
        let instr_size = 10; // Default size for safety

        // Try to disassemble the current instruction to get its size
        let buf_size = 16;
        let buf = unsafe { std::slice::from_raw_parts(fault_addr as *const u8, buf_size) };

        if let Ok(insns) = cs.disasm_all(buf, fault_addr as u64) {
            if let Some(insn) = insns.iter().next() {
                trace!("Current instruction at 0x{:x}: {} {}",
                      fault_addr, insn.mnemonic().unwrap_or(""), insn.op_str().unwrap_or(""));
                Self::set_instruction_pointer(ctx, (fault_addr + insn.bytes().len() as i64) as u64);
                return Ok(());
            }
        }

        // Fallback to fixed instruction size if disassembly fails
        Self::set_instruction_pointer(ctx, (fault_addr + instr_size) as u64);
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
}

#[cfg(not(target_arch = "x86_64"))]
compile_error!("CurrentArchHandler implementation missing for this architecture");