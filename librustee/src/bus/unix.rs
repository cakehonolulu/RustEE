use crate::bus::BUS_PTR;
use crate::bus::backpatch::{
    io_read8_stub, io_read16_stub, io_read64_stub, io_read128_stub, io_write8_stub,
    io_write16_stub, io_write64_stub, io_write128_stub,
};
use crate::bus::unix::libc::ucontext_t;
use backtrace::Backtrace;
use nix::libc;
use nix::sys::mman::{ProtFlags, mprotect};
use nix::sys::signal::{SaFlags, SigAction, SigHandler, SigSet, Signal, sigaction};
use std::io;
use std::ops::Add;
use std::os::raw::{c_int, c_void};
use std::sync::atomic::Ordering;
use tracing::{debug, error, info, trace};

use super::{Bus, HW_BASE, HW_LENGTH};

#[cfg(target_arch = "x86_64")]
use super::backpatch::{
    ArchHandler, CurrentArchHandler, HANDLER_INSTALLED, io_read32_stub, io_write32_stub,
};

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
                if name_str.contains("__bus_write8")
                    || name_str.contains("__bus_write16")
                    || name_str.contains("__bus_write32")
                    || name_str.contains("__bus_write64")
                    || name_str.contains("__bus_write128")
                    || name_str.contains("__bus_read8")
                    || name_str.contains("__bus_read16")
                    || name_str.contains("__bus_read32")
                    || name_str.contains("__bus_read64")
                    || name_str.contains("__bus_read128")
                {
                    is_jit = true;
                    trace!("  Found JIT access at frame {}", frame_idx);
                } else if name_str.contains("hw_write8") {
                    access_type = Some("write8");
                    trace!("  Found write8 access at frame {}", frame_idx);
                } else if name_str.contains("hw_write16") {
                    access_type = Some("write16");
                    trace!("  Found write16 access at frame {}", frame_idx);
                } else if name_str.contains("hw_write32") {
                    access_type = Some("write32");
                    trace!("  Found write32 access at frame {}", frame_idx);
                } else if name_str.contains("hw_write64") {
                    access_type = Some("write64");
                    trace!("  Found write64 access at frame {}", frame_idx);
                } else if name_str.contains("hw_write128") {
                    access_type = Some("write128");
                    trace!("  Found write128 access at frame {}", frame_idx);
                } else if name_str.contains("hw_read8") {
                    access_type = Some("read8");
                    trace!("  Found read8 access at frame {}", frame_idx);
                } else if name_str.contains("hw_read16") {
                    access_type = Some("read16");
                    trace!("  Found read16 access at frame {}", frame_idx);
                } else if name_str.contains("hw_read32") {
                    access_type = Some("read32");
                    trace!("  Found read32 access at frame {}", frame_idx);
                } else if name_str.contains("hw_read64") {
                    access_type = Some("read64");
                    trace!("  Found read64 access at frame {}", frame_idx);
                } else if name_str.contains("hw_read128") {
                    access_type = Some("read128");
                    trace!("  Found read128 access at frame {}", frame_idx);
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
                if bus_frame_index.is_some() {
                    break;
                }
            }
            if bus_frame_index.is_some() {
                break;
            }
        }

        if bus_frame_index.is_none() {
            panic!("No __bus_* frame identified in backtrace for JIT");
        }

        let stub_addr: u64 = match matched_pattern.unwrap() {
            pattern if pattern.contains("__bus_write8") => io_write8_stub as *const () as u64,
            pattern if pattern.contains("__bus_write16") => io_write16_stub as *const () as u64,
            pattern if pattern.contains("__bus_write32") => io_write32_stub as *const () as u64,
            pattern if pattern.contains("__bus_write64") => io_write64_stub as *const () as u64,
            pattern if pattern.contains("__bus_write128") => io_write128_stub as *const () as u64,
            pattern if pattern.contains("__bus_read8") => io_read8_stub as *const () as u64,
            pattern if pattern.contains("__bus_read16") => io_read16_stub as *const () as u64,
            pattern if pattern.contains("__bus_read32") => io_read32_stub as *const () as u64,
            pattern if pattern.contains("__bus_read64") => io_read64_stub as *const () as u64,
            pattern if pattern.contains("__bus_read128") => io_read128_stub as *const () as u64,
            other => {
                panic!("Unrecognized helper pattern: {}", other);
            }
        };

        let target_frame_index = bus_frame_index.unwrap() + 1;
        if let Some(frame) = bt.frames().get(target_frame_index) {
            let ip = frame.ip() as usize;
            trace!(
                "Processing frame at index {} with IP 0x{:x}",
                target_frame_index, ip
            );

            let movabs_opcodes = [
                ([0x48, 0xB8], "rax"),
                ([0x48, 0xB9], "rcx"),
                ([0x48, 0xBA], "rdx"),
                ([0x48, 0xBB], "rbx"),
                ([0x48, 0xBC], "rsp"),
                ([0x48, 0xBD], "rbp"),
                ([0x48, 0xBE], "rsi"),
                ([0x48, 0xBF], "rdi"),
                ([0x49, 0xB8], "r8"),
                ([0x49, 0xB9], "r9"),
                ([0x49, 0xBA], "r10"),
                ([0x49, 0xBB], "r11"),
            ];

            let call_opcodes_2byte = [
                ([0xFF, 0xD0], "rax"),
                ([0xFF, 0xD1], "rcx"),
                ([0xFF, 0xD2], "rdx"),
                ([0xFF, 0xD3], "rbx"),
                ([0xFF, 0xD4], "rsp"),
                ([0xFF, 0xD5], "rbp"),
                ([0xFF, 0xD6], "rsi"),
                ([0xFF, 0xD7], "rdi"),
            ];

            let call_opcodes_3byte = [
                ([0x41, 0xFF, 0xD0], "r8"),
                ([0x41, 0xFF, 0xD1], "r9"),
                ([0x41, 0xFF, 0xD2], "r10"),
                ([0x41, 0xFF, 0xD3], "r11"),
            ];

            // Memory validation function
            let validate_memory_region = |start: usize, size: usize| -> Result<(), String> {
                let page_size = nix::unistd::sysconf(nix::unistd::SysconfVar::PAGE_SIZE)
                    .map_err(|e| format!("Failed to get page size: {}", e))?
                    .ok_or("Page size not available")? as usize;
                let page_start = start & !(page_size - 1);
                let page_end = (start + size - 1) | (page_size - 1);
                unsafe {
                    mprotect(
                        std::ptr::NonNull::new_unchecked(page_start as *mut c_void),
                        page_end - page_start + 1,
                        ProtFlags::PROT_READ,
                    )
                    .map_err(|e| format!("mprotect failed: {}", e))?;
                    Ok(())
                }
            };

            // Try backward search first
            let try_patch = |buf_start: usize, buf: &[u8]| -> bool {
                let mut mov_hits = Vec::new();
                for i in 0..=buf.len().saturating_sub(2) {
                    if let Some((_, reg)) = movabs_opcodes
                        .iter()
                        .find(|(opc, _)| buf.get(i..i + 2) == Some(opc))
                    {
                        mov_hits.push((i, reg));
                    }
                }

                let mut call_hits = Vec::new();
                for i in 0..=buf.len().saturating_sub(2) {
                    if let Some((_, reg)) = call_opcodes_2byte
                        .iter()
                        .find(|(opc, _)| buf.get(i..i + 2) == Some(opc))
                    {
                        call_hits.push((i, reg, 2));
                    }
                    if i + 3 <= buf.len() {
                        if let Some((_, reg)) = call_opcodes_3byte
                            .iter()
                            .find(|(opc, _)| buf.get(i..i + 3) == Some(opc))
                        {
                            call_hits.push((i, reg, 3));
                        }
                    }
                }

                for &(mov_off, mov_reg) in &mov_hits {
                    for &(call_off, call_reg, call_len) in &call_hits {
                        if mov_reg == call_reg {
                            let movabs_addr = buf_start + mov_off;
                            let reg = H::parse_register_from_operand(mov_reg).unwrap();
                            let stub_bytes = H::encode_stub_call(&reg, stub_addr).unwrap();
                            if let Err(e) = patch_instruction(movabs_addr as u64, &stub_bytes) {
                                error!("Failed to patch instruction at 0x{:x}: {}", movabs_addr, e);
                                return false;
                            }

                            let uc = unsafe { &mut *(ctx as *mut libc::ucontext_t) };
                            let fault_rip = uc.uc_mcontext.gregs[libc::REG_RIP as usize] as i64;
                            if let Err(e) = H::advance_instruction_pointer(ctx, &cs, fault_rip) {
                                error!("Failed to advance instruction pointer: {}", e);
                                return false;
                            }

                            if let Some(access) = access_type {
                                let bus_ptr = unsafe { BUS_PTR } as *mut Bus;
                                let addr = fault_addr;

                                match access {
                                    "write8" => {
                                        #[cfg(debug_assertions)]
                                        let value: u8 =
                                            uc.uc_mcontext.gregs[libc::REG_RCX as usize] as u8;

                                        #[cfg(not(debug_assertions))]
                                        let value: u8 =
                                            uc.uc_mcontext.gregs[libc::REG_RDX as usize] as u8;
                                        io_write8_stub(bus_ptr, addr, value);
                                        trace!(
                                            "Executed io_write8_stub(bus_ptr={:p}, addr=0x{:x}, value=0x{:x})",
                                            bus_ptr, addr, value
                                        );
                                    }
                                    "write16" => {
                                        #[cfg(debug_assertions)]
                                        let value: u16 =
                                            uc.uc_mcontext.gregs[libc::REG_RCX as usize] as u16;

                                        #[cfg(not(debug_assertions))]
                                        let value: u16 =
                                            uc.uc_mcontext.gregs[libc::REG_RDX as usize] as u16;
                                        io_write16_stub(bus_ptr, addr, value);
                                        trace!(
                                            "Executed io_write16_stub(bus_ptr={:p}, addr=0x{:x}, value=0x{:x})",
                                            bus_ptr, addr, value
                                        );
                                    }
                                    "write32" => {
                                        #[cfg(debug_assertions)]
                                        let value: u32 =
                                            uc.uc_mcontext.gregs[libc::REG_RCX as usize] as u32;

                                        #[cfg(not(debug_assertions))]
                                        let value: u32 =
                                            uc.uc_mcontext.gregs[libc::REG_RDX as usize] as u32;
                                        io_write32_stub(bus_ptr, addr, value);
                                        trace!(
                                            "Executed io_write32_stub(bus_ptr={:p}, addr=0x{:x}, value=0x{:x})",
                                            bus_ptr, addr, value
                                        );
                                    }
                                    "write64" => {
                                        #[cfg(debug_assertions)]
                                        let value: u64 =
                                            uc.uc_mcontext.gregs[libc::REG_RCX as usize] as u64;

                                        #[cfg(not(debug_assertions))]
                                        let value: u64 =
                                            uc.uc_mcontext.gregs[libc::REG_RDX as usize] as u64;
                                        io_write64_stub(bus_ptr, addr, value);
                                        trace!(
                                            "Executed io_write64_stub(bus_ptr={:p}, addr=0x{:x}, value=0x{:x})",
                                            bus_ptr, addr, value
                                        );
                                    }
                                    "write128" => {
                                        let low =
                                            uc.uc_mcontext.gregs[libc::REG_RCX as usize] as u64;
                                        let high =
                                            uc.uc_mcontext.gregs[libc::REG_RDX as usize] as u64;
                                        let value = ((high as u128) << 64) | (low as u128);
                                        io_write128_stub(bus_ptr, addr, low, high);
                                        trace!(
                                            "Executed io_write128_stub(bus_ptr={:p}, addr=0x{:x}, value=0x{:x})",
                                            bus_ptr, addr, value
                                        );
                                    }
                                    "read8" => {
                                        let value = io_read8_stub(bus_ptr, addr);
                                        uc.uc_mcontext.gregs[libc::REG_RAX as usize] = value as i64;
                                        trace!(
                                            "Executed io_read8_stub(bus_ptr={:p}, addr=0x{:x}) -> 0x{:x}",
                                            bus_ptr, addr, value
                                        );
                                    }
                                    "read16" => {
                                        let value = io_read16_stub(bus_ptr, addr);
                                        uc.uc_mcontext.gregs[libc::REG_RAX as usize] = value as i64;
                                        trace!(
                                            "Executed io_read16_stub(bus_ptr={:p}, addr=0x{:x}) -> 0x{:x}",
                                            bus_ptr, addr, value
                                        );
                                    }
                                    "read32" => {
                                        let value = io_read32_stub(bus_ptr, addr);
                                        uc.uc_mcontext.gregs[libc::REG_RAX as usize] = value as i64;
                                        trace!(
                                            "Executed io_read32_stub(bus_ptr={:p}, addr=0x{:x}) -> 0x{:x}",
                                            bus_ptr, addr, value
                                        );
                                    }
                                    "read64" => {
                                        let value = io_read64_stub(bus_ptr, addr);
                                        uc.uc_mcontext.gregs[libc::REG_RAX as usize] = value as i64;
                                        trace!(
                                            "Executed io_read64_stub(bus_ptr={:p}, addr=0x{:x}) -> 0x{:x}",
                                            bus_ptr, addr, value
                                        );
                                    }
                                    "read128" => {
                                        let mut low: u64 = 0;
                                        let mut high: u64 = 0;
                                        io_read128_stub(bus_ptr, addr, &mut low, &mut high);

                                        uc.uc_mcontext.gregs[libc::REG_RAX as usize] = low as i64;
                                        uc.uc_mcontext.gregs[libc::REG_RDX as usize] = high as i64;

                                        trace!(
                                            "Executed io_read128_stub(bus_ptr={:p}, addr=0x{:x}) -> low=0x{:x}, high=0x{:x}",
                                            bus_ptr, addr, low, high
                                        );
                                    }
                                    _ => {
                                        panic!("Unknown access type: {}", access);
                                    }
                                }
                            }

                            trace!("Patched at 0x{:x}", movabs_addr);
                            return true;
                        }
                    }
                }
                false
            };

            // Backward search: 14-byte window ending at IP
            let buf_size = 19;
            let buf_start = ip.saturating_sub(buf_size);
            if validate_memory_region(buf_start, buf_size).is_err() {
                error!(
                    "Memory region 0x{:x}-0x{:x} is not readable",
                    buf_start,
                    buf_start + buf_size
                );
                restore_default_handler_and_raise(signum);
                return;
            }
            let buf: [u8; 19] = unsafe { std::ptr::read(buf_start as *const [u8; 19]) };
            if try_patch(buf_start, &buf) {
                return;
            }

            // Forward search: 14-byte window starting at IP
            if validate_memory_region(ip, buf_size).is_err() {
                error!(
                    "Memory region 0x{:x}-0x{:x} is not readable",
                    ip,
                    ip + buf_size
                );
                restore_default_handler_and_raise(signum);
                return;
            }
            let buf: [u8; 19] = unsafe { std::ptr::read(ip as *const [u8; 19]) };
            if try_patch(ip, &buf) {
                return;
            }
            error!(
                "no movabs+call pair matched in 14-byte window at IP 0x{:x}",
                ip
            );
        } else {
            error!(
                "Frame at index {} not found in backtrace",
                target_frame_index
            );
        }
        error!("Failed to patch JIT code");
        restore_default_handler_and_raise(signum);
    } else if let Some(access) = access_type {
        trace!("Detected interpreter fastmem access, redirecting to I/O...");
        let uc = unsafe { &mut *(ctx as *mut libc::ucontext_t) };
        let bus_ptr = unsafe { BUS_PTR } as *mut Bus;
        let addr = fault_addr;
        let fault_rip = uc.uc_mcontext.gregs[libc::REG_RIP as usize];

        match access {
            "write8" => {
                #[cfg(debug_assertions)]
                let value: u8 = uc.uc_mcontext.gregs[libc::REG_RCX as usize] as u8;

                #[cfg(not(debug_assertions))]
                let value: u8 = uc.uc_mcontext.gregs[libc::REG_RDX as usize] as u8;
                io_write8_stub(bus_ptr, addr, value);
                trace!(
                    "Executed io_write8_stub(bus_ptr={:p}, addr=0x{:x}, value=0x{:x})",
                    bus_ptr, addr, value
                );
            }
            "write16" => {
                #[cfg(debug_assertions)]
                let value: u16 = uc.uc_mcontext.gregs[libc::REG_RCX as usize] as u16;

                #[cfg(not(debug_assertions))]
                let value: u16 = uc.uc_mcontext.gregs[libc::REG_RDX as usize] as u16;
                io_write16_stub(bus_ptr, addr, value);
                trace!(
                    "Executed io_write16_stub(bus_ptr={:p}, addr=0x{:x}, value=0x{:x})",
                    bus_ptr, addr, value
                );
            }
            "write32" => {
                #[cfg(debug_assertions)]
                let value: u32 = uc.uc_mcontext.gregs[libc::REG_RCX as usize] as u32;

                #[cfg(not(debug_assertions))]
                let value: u32 = uc.uc_mcontext.gregs[libc::REG_RDX as usize] as u32;
                io_write32_stub(bus_ptr, addr, value);
                trace!(
                    "Executed io_write32_stub(bus_ptr={:p}, addr=0x{:x}, value=0x{:x})",
                    bus_ptr, addr, value
                );
            }
            "write64" => {
                #[cfg(debug_assertions)]
                let value: u64 = uc.uc_mcontext.gregs[libc::REG_RCX as usize] as u64;

                #[cfg(not(debug_assertions))]
                let value: u64 = uc.uc_mcontext.gregs[libc::REG_RDX as usize] as u64;
                io_write64_stub(bus_ptr, addr, value);
                trace!(
                    "Executed io_write64_stub(bus_ptr={:p}, addr=0x{:x}, value=0x{:x})",
                    bus_ptr, addr, value
                );
            }
            "write128" => {
                let low = uc.uc_mcontext.gregs[libc::REG_RCX as usize] as u64;
                let high = uc.uc_mcontext.gregs[libc::REG_RDX as usize] as u64;
                let value = ((high as u128) << 64) | (low as u128);
                io_write128_stub(bus_ptr, addr, low, high);
                trace!(
                    "Executed io_write128_stub(bus_ptr={:p}, addr=0x{:x}, value=0x{:x})",
                    bus_ptr, addr, value
                );
            }
            "read8" => {
                let value = io_read8_stub(bus_ptr, addr);
                uc.uc_mcontext.gregs[libc::REG_RAX as usize] = value as i64;
                trace!(
                    "Executed io_read8_stub(bus_ptr={:p}, addr=0x{:x}) -> 0x{:x}",
                    bus_ptr, addr, value
                );
            }
            "read16" => {
                let value = io_read16_stub(bus_ptr, addr);
                uc.uc_mcontext.gregs[libc::REG_RAX as usize] = value as i64;
                trace!(
                    "Executed io_read16_stub(bus_ptr={:p}, addr=0x{:x}) -> 0x{:x}",
                    bus_ptr, addr, value
                );
            }
            "read32" => {
                let value = io_read32_stub(bus_ptr, addr);
                uc.uc_mcontext.gregs[libc::REG_RAX as usize] = value as i64;
                trace!(
                    "Executed io_read32_stub(bus_ptr={:p}, addr=0x{:x}) -> 0x{:x}",
                    bus_ptr, addr, value
                );
            }
            "read64" => {
                let value = io_read64_stub(bus_ptr, addr);
                uc.uc_mcontext.gregs[libc::REG_RAX as usize] = value as i64;
                trace!(
                    "Executed io_read64_stub(bus_ptr={:p}, addr=0x{:x}) -> 0x{:x}",
                    bus_ptr, addr, value
                );
            }
            "read128" => {
                let mut low: u64 = 0;
                let mut high: u64 = 0;
                io_read128_stub(bus_ptr, addr, &mut low, &mut high);

                uc.uc_mcontext.gregs[libc::REG_RAX as usize] = low as i64;
                uc.uc_mcontext.gregs[libc::REG_RDX as usize] = high as i64;

                trace!(
                    "Executed io_read128_stub(bus_ptr={:p}, addr=0x{:x}) -> low=0x{:x}, high=0x{:x}",
                    bus_ptr, addr, low, high
                );
            }
            _ => {
                panic!("Unknown access type: {}", access);
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
        .ok_or("Page size not available")? as usize;

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
        )
        .map_err(|e| format!("mprotect→WRITE failed: {}", e))?;
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
        )
        .map_err(|e| format!("mprotect→RX failed: {}", e))?;
    }

    trace!("Successfully patched instruction at 0x{:016x}", addr);
    Ok(())
}

fn fix_return_address<H: ArchHandler>(ctx: *mut H::Context, patch_addr: u64, patch_len: usize) {
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

        if candidate.eq(&patch_len) {
            trace!(
                "Found match at slot[{}] → overwriting with 0x{:016x}",
                i, target_ret
            );
            unsafe {
                *(slot_addr as *mut u64) = target_ret;
            }
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
        sigaction(Signal::SIGSEGV, &action).map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        sigaction(Signal::SIGBUS, &action).map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
    }

    info!("Signal handlers for SIGSEGV and SIGBUS installed successfully");
    Ok(())
}
