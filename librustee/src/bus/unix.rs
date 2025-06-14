use std::arch::asm;
use std::io;
use std::ops::Add;
use std::os::raw::{c_int, c_void};
use std::sync::atomic::{AtomicBool, Ordering};

use nix::libc;
use nix::sys::signal::{sigaction, SaFlags, SigAction, SigHandler, SigSet, Signal};
use nix::sys::mman::{mprotect, ProtFlags};
use backtrace::Backtrace;
use capstone::Capstone;
use capstone::arch::BuildsCapstone;
use tracing::{debug, error, info, trace};

use super::{Bus, HW_BASE, HW_LENGTH};

struct Context {
    bus: *mut Bus,
}

static HANDLER_INSTALLED: AtomicBool = AtomicBool::new(false);

trait ArchHandler {
    type Context;
    type Register: Clone + PartialEq;
    
    fn create_disassembler() -> Result<Capstone, capstone::Error>;
    fn encode_stub_call(reg: &Self::Register, stub_addr: u64) -> Option<Vec<u8>>;
    fn get_instruction_pointer(ctx: *mut c_void) -> i64;
    fn set_instruction_pointer(ctx: *mut c_void, addr: u64);
    fn get_stack_pointer(ctx: *mut c_void) -> u64;
    fn advance_instruction_pointer(ctx: *mut c_void, cs: &Capstone, fault_addr: i64) -> Result<(), &'static str>;
    fn parse_register_from_operand(operand: &str) -> Option<Self::Register>;
    fn register_name(reg: &Self::Register) -> &'static str;
    fn get_helper_pattern() -> &'static [&'static str];
    fn get_call_instruction() -> &'static str;
}

// X86-64 implementation
#[cfg(target_arch = "x86_64")]
mod x86_64_impl {
    use super::*;
    use capstone::arch::x86::ArchMode;
    use nix::libc;
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
    
    pub struct X86Handler;
    
    impl ArchHandler for X86Handler {
        type Context = libc::ucontext_t;
        type Register = X86Register;
        
        fn create_disassembler() -> Result<Capstone, capstone::Error> {
            Capstone::new().x86().mode(ArchMode::Mode64).build()
        }

        fn encode_stub_call(reg: &Self::Register, stub_addr: u64) -> Option<Vec<u8>> {
            let mut buf = match reg {
                X86Register::Rax => vec![0x48, 0xB8], // movabs rax, imm64
                X86Register::Rcx => vec![0x48, 0xB9], // movabs rcx, imm64
                X86Register::R8  => vec![0x49, 0xB8], // movabs r8, imm64
                X86Register::R9  => vec![0x49, 0xB9], // movabs r9, imm64
                _ => {
                    error!(
                "Unsupported register for stub call: {}",
                Self::register_name(reg)
            );
                    return None;
                }
            };

            buf.extend_from_slice(&stub_addr.to_le_bytes());
            Some(buf)
        }
        
        fn get_instruction_pointer(ctx: *mut c_void) -> i64 {
            let uc = unsafe { &*(ctx as *const libc::ucontext_t) };
            uc.uc_mcontext.gregs[libc::REG_RIP as usize]
        }
        
        fn set_instruction_pointer(ctx: *mut c_void, addr: u64) {
            let uc = unsafe { &mut *(ctx as *mut libc::ucontext_t) };
            uc.uc_mcontext.gregs[libc::REG_RIP as usize] = addr as i64;
        }
        
        fn get_stack_pointer(ctx: *mut c_void) -> u64 {
            let uc = unsafe { &*(ctx as *const libc::ucontext_t) };
            uc.uc_mcontext.gregs[libc::REG_RSP as usize] as u64
        }
        
        fn advance_instruction_pointer(ctx: *mut c_void, cs: &Capstone, fault_addr: i64) -> Result<(), &'static str> {
            let inst_buf: &[u8] = unsafe { std::slice::from_raw_parts(fault_addr as *const u8, 16) };
            
            let instruction_length = if let Ok(insns) = cs.disasm_count(inst_buf, fault_addr.try_into().unwrap(), 1) {
                if let Some(insn) = insns.iter().next() {
                    trace!("avance_instruction_pointer: Instruction at {}", insn.to_string());
                    insn.len() as u64
                } else {
                    return Err("Could not disassemble faulting instruction");
                }
            } else {
                return Err("Failed to disassemble faulting instruction");
            };
            
            let uc = unsafe { &mut *(ctx as *mut libc::ucontext_t) };
            uc.uc_mcontext.gregs[libc::REG_RIP as usize] += instruction_length as i64;
            Ok(())
        }
        
        fn parse_register_from_operand(operand: &str) -> Option<Self::Register> {
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
        
        fn register_name(reg: &Self::Register) -> &'static str {
            match reg {
                X86Register::Rax => "rax",
                X86Register::Rcx => "rcx",
                X86Register::R8 => "r8",
                X86Register::R9 => "r9",
                X86Register::R10 => "r10",
                X86Register::R11 => "r11",
            }
        }
        
        fn get_helper_pattern() -> &'static [&'static str] {
            &[
                "librustee::ee::jit::__bus_write32",
                "librustee::ee::jit::__bus_read32",
            ]
        }

        
        fn get_call_instruction() -> &'static str {
            "call"
        }
    }
}

#[cfg(target_arch = "x86_64")]
type CurrentArchHandler = x86_64_impl::X86Handler;

#[cfg(not(any(target_arch = "x86_64")))]
compile_error!("Unsupported architecture");

#[unsafe(no_mangle)]
extern "C" fn io_write32_stub(bus_ptr: *mut Bus, address: u64, value: u32) {
    let bus = unsafe { &mut *bus_ptr };
    bus.io_write32(address as u32, value);
}

#[unsafe(no_mangle)]
extern "C" fn io_read32_stub(bus_ptr: *mut Bus, address: u64) -> u32 {
    let bus = unsafe { &mut *bus_ptr };
    bus.io_read32(address as u32)
}

fn restore_default_handler_and_raise(signum: c_int) {
    unsafe {
        if let Ok(sig_enum) = Signal::try_from(signum) {
            let default = SigAction::new(SigHandler::SigDfl, SaFlags::empty(), SigSet::empty());
            let _ = sigaction(sig_enum, &default);
        }
        libc::raise(signum);
    }
}

extern "C" fn segv_handler(signum: c_int, info: *mut libc::siginfo_t, ctx: *mut c_void) {
    generic_segv_handler::<CurrentArchHandler>(signum, info, ctx)
}

fn generic_segv_handler<H: ArchHandler>(signum: c_int, info: *mut libc::siginfo_t, ctx: *mut c_void) {
    if info.is_null() || ctx.is_null() {
        error!("Null info or ctx in segv_handler");
        return;
    }

    let guest_addr = unsafe { (*info).si_addr() as usize };
    let base = HW_BASE.load(Ordering::SeqCst);
    let size = HW_LENGTH.load(Ordering::SeqCst);

    if guest_addr < base || guest_addr >= base + size {
        error!(
            "Address 0x{:x} out of bounds (base=0x{:x}, size=0x{:x})",
            guest_addr, base, size
        );
        restore_default_handler_and_raise(signum);
        return;
    }

    let fault_addr = (guest_addr - base) as u32;
    trace!(
        "SIGSEGV at host VA=0x{:x}, guest PA=0x{:08x}",
        guest_addr, fault_addr
    );

    let bt = Backtrace::new();
    let mut is_jit = false;
    let mut access_type = None;

    for (frame_idx, frame) in bt.frames().iter().enumerate() {
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

    let cs = match H::create_disassembler() {
        Ok(c) => c,
        Err(e) => {
            error!("Failed to create disassembler: {}", e);
            restore_default_handler_and_raise(signum);
            return;
        }
    };

    if is_jit {
        trace!("Detected MMIO fastmem access! Patching...");
        let mut bus_frame_index: Option<usize> = None;
        let mut matched_pattern: Option<&'static str> = None;

        for (frame_idx, frame) in bt.frames().iter().enumerate() {
            for sym in frame.symbols() {
                if let Some(name) = sym.name() {
                    let name_str = name.to_string();
                    for &pattern in H::get_helper_pattern().iter() {
                        if name_str.contains(pattern) {
                            bus_frame_index = Some(frame_idx);
                            matched_pattern = Some(pattern);
                            trace!(
                                "Found helper symbol `{}` at frame {} (matched `{}`)",
                                name_str, frame_idx, pattern
                            );
                            break;
                        }
                    }
                }
                if bus_frame_index.is_some() { break; }
            }
            if bus_frame_index.is_some() { break; }
        }

        if bus_frame_index.is_none() {
            error!("No __bus_* frame identified in backtrace for JIT");
            restore_default_handler_and_raise(signum);
            return;
        }

        let stub_addr: u64 = match matched_pattern.unwrap() {
            pattern if pattern.contains("__bus_write32") => io_write32_stub as *const () as u64,
            pattern if pattern.contains("__bus_read32") => io_read32_stub as *const () as u64,
            other => {
                error!("Unrecognized helper pattern: {}", other);
                restore_default_handler_and_raise(signum);
                return;
            }
        };

        let target_frame_index = bus_frame_index.unwrap() + 1;
        if let Some(frame) = bt.frames().get(target_frame_index) {
            let mut ip = frame.ip() as usize;
            trace!("Processing frame at index {} with IP 0x{:x}", target_frame_index, ip);

            let scan_back = 40usize;
            ip = ip.add(16);
            let scan_start = ip.saturating_sub(scan_back);
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
                                let reg = H::parse_register_from_operand(mov_reg).unwrap();
                                let patch_bytes = H::encode_stub_call(&reg, stub_addr).unwrap();
                                patch_instruction(movabs_addr, &patch_bytes).unwrap();
                                H::advance_instruction_pointer(ctx, &cs, H::get_instruction_pointer(ctx)).unwrap();
                                fix_return_address::<H>(ctx, movabs_addr, 12);
                                return;
                            }
                        }
                    }
                }
            }
        }
        error!("Failed to patch JIT code");
        restore_default_handler_and_raise(signum);
    } else if let Some(access) = access_type {
        trace!("Detected interpreter fastmem access, redirecting to I/O...");
        let uc = unsafe { &mut *(ctx as *mut libc::ucontext_t) };
        let bus_ptr = uc.uc_mcontext.gregs[libc::REG_RDI as usize] as *mut Bus;
        let addr = uc.uc_mcontext.gregs[libc::REG_RSI as usize] as u32;
        let fault_rip = uc.uc_mcontext.gregs[libc::REG_RIP as usize];

        if access == "write" {
            let value = uc.uc_mcontext.gregs[libc::REG_RDX as usize] as u32;
            io_write32_stub(bus_ptr, addr as u64, value);
            trace!("Executed io_write32_stub(bus_ptr={:p}, addr=0x{:x}, value=0x{:x})", bus_ptr, addr, value);
        } else {
            let value = io_read32_stub(bus_ptr, addr as u64);
            uc.uc_mcontext.gregs[libc::REG_RAX as usize] = value as i64;
            trace!("Executed io_read32_stub(bus_ptr={:p}, addr=0x{:x}) -> 0x{:x}", bus_ptr, addr, value);
        }

        if let Err(e) = H::advance_instruction_pointer(ctx, &cs, fault_rip) {
            error!("Failed to advance instruction pointer: {}", e);
            restore_default_handler_and_raise(signum);
            return;
        }
    }
}

fn patch_instruction(addr: u64, patch_bytes: &[u8]) -> Result<(), String> {
    let page_size = nix::unistd::sysconf(nix::unistd::SysconfVar::PAGE_SIZE)
        .map_err(|e| format!("Failed to get page size: {}", e))?
        .ok_or("Page size not available")?
        as usize;
    
    let page_start = (addr as usize) & !(page_size - 1);

    trace!(
        "Preparing to patch at 0x{:x}, page_start=0x{:x}, page_size=0x{:x}",
        addr, page_start, page_size
    );

    unsafe {
        mprotect(
            std::ptr::NonNull::new_unchecked(page_start as *mut c_void),
            page_size,
            ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
        ).map_err(|e| format!("mprotect→WRITE failed: {}", e))?;
    }

    unsafe {
        let dest = addr as *mut u8;
        std::ptr::copy_nonoverlapping(patch_bytes.as_ptr(), dest, patch_bytes.len());
    }

    unsafe {
        mprotect(
            std::ptr::NonNull::new_unchecked(page_start as *mut c_void),
            page_size,
            ProtFlags::PROT_READ | ProtFlags::PROT_EXEC,
        ).map_err(|e| format!("mprotect→RX failed: {}", e))?;
    }

    trace!("Successfully patched instruction at 0x{:016x}", addr);
    Ok(())
}

fn fix_return_address<H: ArchHandler>(
    ctx: *mut c_void,
    patch_addr: u64,
    patch_len: usize,
) {
    let old_sp = H::get_stack_pointer(ctx) as usize;
    let original_ret = patch_addr.wrapping_add(patch_len as u64);
    let target_ret = patch_addr;

    trace!(
        "old_sp = 0x{:016x}, original_ret = 0x{:016x}, target_ret = 0x{:016x}",
        old_sp, original_ret, target_ret
    );

    const MAX_SLOTS: usize = 512;
    let mut found = false;
    
    for i in 0..MAX_SLOTS {
        let slot_addr = old_sp + i * 8;
        let candidate: u64 = unsafe { *(slot_addr as *const u64) };

        if candidate == original_ret {
            trace!(
                "Found match at slot[{}] → overwriting with 0x{:016x}",
                i, target_ret
            );
            unsafe { *(slot_addr as *mut u64) = target_ret; }
            found = true;
            trace!("Returning to patched block...");
            break;
        }
    }
    
    if !found {
        debug!("No matching slot found in first {} QWORDs", MAX_SLOTS);
    }
}

pub fn install_handler() -> io::Result<()> {
    if HANDLER_INSTALLED.swap(true, Ordering::SeqCst) {
        debug!("Handler already installed, skipping");
        return Ok(());
    }
    
    let handler = SigHandler::SigAction(segv_handler);
    let flags = SaFlags::SA_SIGINFO;
    let mask = SigSet::empty();
    let action = SigAction::new(handler, flags, mask);

    unsafe {
        sigaction(Signal::SIGSEGV, &action)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        sigaction(Signal::SIGBUS, &action)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
    }

    info!("Signal handlers for SIGSEGV and SIGBUS installed successfully");
    Ok(())
}