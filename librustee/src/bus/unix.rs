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
    fn get_helper_pattern() -> &'static str;
    fn get_call_instruction() -> &'static str;
}

// X86-64 implementation
#[cfg(target_arch = "x86_64")]
mod x86_64_impl {
    use super::*;
    use capstone::arch::x86::ArchMode;
    use nix::libc;
    
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
            let mut buf = vec![0x48, 0xB9]; // movabs rcx, imm64
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
        
        fn get_helper_pattern() -> &'static str {
            "librustee::ee::jit::__bus_write32"
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

    let uc = unsafe { &*(ctx as *const libc::ucontext_t) };

    // Save original register state
    /*let orig_rax = uc.uc_mcontext.gregs[libc::REG_RAX as usize];
    let orig_rbx = uc.uc_mcontext.gregs[libc::REG_RBX as usize];
    let orig_rcx = uc.uc_mcontext.gregs[libc::REG_RCX as usize];
    let orig_rdx = uc.uc_mcontext.gregs[libc::REG_RDX as usize];
    let orig_rsi = uc.uc_mcontext.gregs[libc::REG_RSI as usize];
    let orig_rdi = uc.uc_mcontext.gregs[libc::REG_RDI as usize];

    debug!("RAX: 0x{:X}, RBX: 0x{:X}, RCX: 0x{:X}, RDX: 0x{:X}, RDI: 0x{:X}, RSI: 0x{:X}", orig_rax, orig_rbx, orig_rcx, orig_rdx, orig_rdi, orig_rsi);*/

    let guest_addr = unsafe { (*info).si_addr() as usize };
    let base = HW_BASE.load(Ordering::SeqCst);
    let size = HW_LENGTH.load(Ordering::SeqCst);

    if guest_addr < base || guest_addr >= base + size {
        debug!(
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

    trace!("Detected MMIO fastmem access! Patching...");
    let bt = Backtrace::new();
    let mut bus_frame_index: Option<usize> = None;

    for (index, frame) in bt.frames().iter().enumerate() {
        for sym in frame.symbols() {
            if let Some(name) = sym.name() {
                let name_str = name.to_string();
                if name_str.contains(H::get_helper_pattern()) {
                    bus_frame_index = Some(index);
                    trace!("Found __bus_* symbol at frame {}: {}", index, name_str);
                    break;
                }
                trace!("Found symbol at frame {}: {}", index, name_str);
            }
        }
    }

    if bus_frame_index.is_none() {
        error!("No __bus_* frame identified in backtrace");
        restore_default_handler_and_raise(signum);
        return;
    }

    let stub_addr = io_write32_stub as *const () as u64;
    trace!("Selected stub for write32: 0x{:x}", stub_addr);

    let cs = match H::create_disassembler() {
        Ok(c) => c,
        Err(e) => {
            error!("Failed to create disassembler: {}", e);
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
            trace!("Disassembled instructions starting at 0x{:x}:", scan_start);
            for insn in &insn_vec {
                trace!(
                    "0x{:x}:\t{}\t{}",
                    insn.address(),
                    insn.mnemonic().unwrap_or(""),
                    insn.op_str().unwrap_or("")
                );
            }

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
                        if next_mnem == "call" {
                            let call_opstr = next_insn.op_str().unwrap_or("").trim();
                            if call_opstr == mov_reg {
                                let movabs_addr = insn.address();
                                trace!(
                                    "Found movabs+call pattern at 0x{:x}: {} {}; call {}",
                                    movabs_addr, mnem, opstr, call_opstr
                                );

                                let reg = match H::parse_register_from_operand(mov_reg) {
                                    Some(r) => r,
                                    None => {
                                        error!("Failed to parse register {}", mov_reg);
                                        continue;
                                    }
                                };

                                let patch_bytes = match H::encode_stub_call(&reg, stub_addr) {
                                    Some(bytes) => {
                                        trace!("Generated patch bytes: {:x?}", bytes);
                                        bytes
                                    }
                                    None => {
                                        error!("Failed to encode stub call for register {}", mov_reg);
                                        continue;
                                    }
                                };

                                trace!(
                                    "Patching movabs at 0x{:x} with bytes: {:x?}",
                                    movabs_addr, patch_bytes
                                );
                                if let Err(e) = patch_instruction(movabs_addr, &patch_bytes) {
                                    error!(
                                        "Failed to patch instruction at 0x{:x}: {}",
                                        movabs_addr, e
                                    );
                                    return;
                                }

                                // Advance instruction pointer
                                let fault_rip = H::get_instruction_pointer(ctx);
                                trace!("Fault RIP: 0x{:x}, advancing instruction pointer", 
                                    fault_rip);
                                if let Err(e) = H::advance_instruction_pointer(ctx, &cs, fault_rip) {
                                    error!("Failed to advance instruction pointer: {}", e);
                                    return;
                                }

                                // Fix return address
                                trace!("Fixing return address for patch at 0x{:x}", movabs_addr);
                                fix_return_address::<H>(ctx, movabs_addr, 12);
                                return;
                            }
                        }
                    }
                }
            }

            error!("No movabs+call pattern found in disassembled instructions");
            return;
        }

        error!("Failed to disassemble buffer at 0x{:x}", scan_start);
        return;
    } else {
        error!("No frame found at {} after __bus_*", target_frame_index);
        return;
    }
}


fn check_helper_address_generic<H: ArchHandler>(
    src: &str, 
    instruction: &capstone::Insn, 
    helper_addr: u64
) -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        if src.contains("qword ptr [rip") {
            let offset_str = src
                .split("rip")
                .nth(1)
                .and_then(|s| s.split(']').next())
                .map(|s| s.trim())
                .unwrap_or("");
            if let Some(off_str) = offset_str.strip_prefix("- 0x") {
                if let Ok(off) = u64::from_str_radix(off_str, 16) {
                    let rip_end = instruction.address() + instruction.bytes().len() as u64;
                    let eff = rip_end.wrapping_sub(off);
                    let val = unsafe { *(eff as *const u64) };
                    return val == helper_addr;
                }
            }
        }
    }

    src.contains(&format!("0x{:x}", helper_addr))
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