use std::io;
use std::ops::Add;
use std::os::raw::{c_int, c_void};
use std::sync::atomic::Ordering;
use crate::bus::backpatch::{io_read16_stub, io_write8_stub};
use crate::bus::unix::libc::ucontext_t;
use nix::libc;
use nix::sys::signal::{sigaction, SaFlags, SigAction, SigHandler, SigSet, Signal};
use nix::sys::mman::{mprotect, ProtFlags};
use backtrace::Backtrace;
use tracing::{debug, error, info, trace};

use super::{Bus, HW_BASE, HW_LENGTH};

#[cfg(target_arch = "x86_64")]
use super::backpatch::{ArchHandler, HANDLER_INSTALLED, io_write32_stub, io_read32_stub, CurrentArchHandler};

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
    let ctx = ctx as *mut ucontext_t;
    generic_segv_handler::<CurrentArchHandler>(signum, info, ctx)
}

fn generic_segv_handler<H: ArchHandler>(
    signum: c_int,
    info: *mut libc::siginfo_t,
    ctx: *mut H::Context,
) {
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
                if name_str.contains("__bus_write8") || name_str.contains("__bus_write32") || name_str.contains("__bus_read16")|| name_str.contains("__bus_read32") {
                    is_jit = true;
                    trace!("  Found JIT access at frame {}", frame_idx);
                } else if name_str.contains("hw_write8") {
                    access_type = Some("write8");
                    trace!("  Found write8 access at frame {}", frame_idx);
                } else if name_str.contains("hw_write32") {
                    access_type = Some("write32");
                    trace!("  Found write32 access at frame {}", frame_idx);
                } else if name_str.contains("hw_read16") {
                    access_type = Some("read16");
                    trace!("  Found read16 access at frame {}", frame_idx);
                } else if name_str.contains("hw_read32") {
                    access_type = Some("read32");
                    trace!("  Found read32 access at frame {}", frame_idx);
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
            pattern if pattern.contains("__bus_write8") => io_write8_stub as *const () as u64,
            pattern if pattern.contains("__bus_write32") => io_write32_stub as *const () as u64,
            pattern if pattern.contains("__bus_read16") => io_read16_stub as *const () as u64,
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

            let scan_back = 64usize;
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
                                let reg = H::parse_register_from_operand(mov_reg).unwrap();
                                let patch_bytes = H::encode_stub_call(&reg, stub_addr).unwrap();
                                patch_instruction(movabs_addr, &patch_bytes).unwrap();
                                H::advance_instruction_pointer(ctx, &cs, H::get_instruction_pointer(ctx)).unwrap();
                                fix_return_address::<H>(ctx, movabs_addr, ip);
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

        match access {
            "write8" => {
                let value = uc.uc_mcontext.gregs[libc::REG_RDX as usize] as u8;
                io_write8_stub(bus_ptr, addr, value);
                trace!("Executed io_write8_stub(bus_ptr={:p}, addr=0x{:x}, value=0x{:x})", bus_ptr, addr, value);
            }
            "write32" => {
                let value = uc.uc_mcontext.gregs[libc::REG_RDX as usize] as u32;
                io_write32_stub(bus_ptr, addr, value);
                trace!("Executed io_write32_stub(bus_ptr={:p}, addr=0x{:x}, value=0x{:x})", bus_ptr, addr, value);
            }
            "read16" => {
                let value = io_read16_stub(bus_ptr, addr);
                uc.uc_mcontext.gregs[libc::REG_RAX as usize] = value as i64;
                trace!("Executed io_read16_stub(bus_ptr={:p}, addr=0x{:x}) -> 0x{:x}", bus_ptr, addr, value);
            }
            "read32" => {
                let value = io_read32_stub(bus_ptr, addr);
                uc.uc_mcontext.gregs[libc::REG_RAX as usize] = value as i64;
                trace!("Executed io_read32_stub(bus_ptr={:p}, addr=0x{:x}) -> 0x{:x}", bus_ptr, addr, value);
            }
            _ => {
                error!("Unknown access type: {}", access);
                restore_default_handler_and_raise(signum);
                return;
            }
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
    ctx: *mut H::Context,
    patch_addr: u64,
    patch_len: usize,
) {
    let old_sp = H::get_stack_pointer(ctx) as usize;
    let target_ret = patch_addr;

    trace!(
        "old_sp = 0x{:016x}, original_ret = 0x{:016x}, target_ret = 0x{:016x}",
        old_sp, patch_len, target_ret
    );

    const MAX_SLOTS: usize = 512;
    let mut found = false;

    for i in 0..MAX_SLOTS {
        let slot_addr = old_sp + i * 8;
        let candidate: usize = unsafe { *(slot_addr as *const usize) };

        if candidate.eq(&patch_len ) {
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
        panic!("No matching slot found in first {} QWORDs", MAX_SLOTS);
    }
}

pub fn install_handler() -> io::Result<()> {
    if HANDLER_INSTALLED.swap(true, Ordering::SeqCst) {
        debug!("Handler already installed, skipping");
        return Ok(());
    }

    let handler = SigHandler::SigAction(segv_handler as extern "C" fn(_, _, *mut c_void));
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