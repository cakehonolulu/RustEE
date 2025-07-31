use std::ffi::c_void;
use std::io::{self, ErrorKind};
use std::ptr;
use std::sync::atomic::Ordering;
use std::ops::Add;
use tracing::{debug, error, info, trace};
use windows_sys::Win32::System::Diagnostics::Debug::RtlCaptureStackBackTrace;
use windows_sys::Win32::System::SystemInformation::{GetSystemInfo, SYSTEM_INFO};
use windows_sys::Win32::System::{
        Diagnostics::Debug::{
            AddVectoredExceptionHandler, EXCEPTION_CONTINUE_EXECUTION, EXCEPTION_CONTINUE_SEARCH, 
            EXCEPTION_POINTERS, CONTEXT,
        },
        Memory::{VirtualProtect, PAGE_EXECUTE_READ, PAGE_READWRITE},
    };

use backtrace::resolve;
use crate::bus::backpatch::{io_read128_stub, io_read16_stub, io_read64_stub, io_read8_stub, io_write128_stub, io_write16_stub, io_write64_stub, io_write8_stub};
use super::{Bus, BUS_PTR, HW_BASE, HW_LENGTH};

#[cfg(target_arch = "x86_64")]
use super::backpatch::{ArchHandler, HANDLER_INSTALLED, io_write32_stub, io_read32_stub, CurrentArchHandler};

unsafe fn capture_raw_backtrace(skip: u32, max_frames: u32) -> Vec<*mut c_void> { unsafe {
    let mut buffer: Vec<*mut c_void> = Vec::with_capacity(max_frames as usize);
    buffer.set_len(max_frames as usize);

    let captured = RtlCaptureStackBackTrace(
        skip,
        max_frames,
        buffer.as_mut_ptr(),
        ptr::null_mut(),
    );

    buffer.truncate(captured as usize);
    buffer
}}

unsafe extern "system" fn veh_handler(info: *mut EXCEPTION_POINTERS) -> i32 { unsafe {
    generic_exception_handler::<CurrentArchHandler>(info)
}}

unsafe fn generic_exception_handler<H: ArchHandler<Context = CONTEXT>>(info: *mut EXCEPTION_POINTERS) -> i32 { unsafe {
    if info.is_null() {
        error!("Null info in exception handler");
        return EXCEPTION_CONTINUE_SEARCH;
    }

    let record = (*info).ExceptionRecord;
    let ctx = (*info).ContextRecord;

    if record.is_null() || ctx.is_null() {
        error!("Null record or context in exception handler");
        return EXCEPTION_CONTINUE_SEARCH;
    }

    let exception_code = (*record).ExceptionCode;

    // Handle access violations (0xC0000005)
    if exception_code != 0xC0000005u32 as i32 {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    let guest_addr = (*record).ExceptionInformation[1] as usize;
    let base = HW_BASE.load(Ordering::SeqCst);
    let size = HW_LENGTH.load(Ordering::SeqCst);

    let end = base.saturating_add(size);

    if guest_addr < base || guest_addr >= end {
        error!(
        "Address 0x{:x} out of bounds (base=0x{:x}, size=0x{:x}, valid range=[0x{:x}, 0x{:x}))",
        guest_addr, base, size, base, end
    );
        return EXCEPTION_CONTINUE_SEARCH;
    }

    let fault_addr = (guest_addr - base) as u32;
    trace!(
        "SIGSEGV at host VA=0x{:x}, guest PA=0x{:08x}",
        guest_addr, fault_addr
    );

    trace!("Faulting IP is 0x{:x}", (*ctx).Rip);

    let raw_frames = capture_raw_backtrace(0, 20);
    let mut is_jit = false;
    let mut access_type = None;

    // First pass: detect JIT vs interpreter access using raw frames
    for (frame_idx, &ip) in raw_frames.iter().enumerate() {
        trace!("Checking frame {}: ip={:p}", frame_idx, ip);
        resolve(ip as *mut _, |symbol| {
            if let Some(name) = symbol.name() {
                let demangled = format!("{}", name);
                trace!("  Symbol: {}", demangled);
                if demangled.contains("__bus_write8") ||demangled.contains("__bus_write16") ||demangled.contains("__bus_write32")
                    ||demangled.contains("__bus_write64") ||demangled.contains("__bus_write128")  || demangled.contains("__bus_read8")
                    || demangled.contains("__bus_read16")  || demangled.contains("__bus_read32")  || demangled.contains("__bus_read64")
                    || demangled.contains("__bus_read128") {
                    is_jit = true;
                    trace!("  Found JIT access");
                } else if demangled.contains("hw_write8") {
                    access_type = Some("write8");
                    trace!("  Found write8 access");
                } else if demangled.contains("hw_write16") {
                    access_type = Some("write16");
                    trace!("  Found write16 access");
                } else if demangled.contains("hw_write32") {
                    access_type = Some("write32");
                    trace!("  Found write32 access");
                } else if demangled.contains("hw_write64") {
                    access_type = Some("write64");
                    trace!("  Found write64 access");
                } else if demangled.contains("hw_write128") {
                    access_type = Some("write128");
                    trace!("  Found write128 access")
                } else if demangled.contains("hw_read8") {
                    access_type = Some("read8");
                    trace!("  Found read8 access");
                } else if demangled.contains("hw_read16") {
                    access_type = Some("read16");
                    trace!("  Found read16 access");
                } else if demangled.contains("hw_read32") {
                    access_type = Some("read32");
                    trace!("  Found read32 access");
                } else if demangled.contains("hw_read64") {
                    access_type = Some("read64");
                    trace!("  Found read64 access");
                } else if demangled.contains("hw_read128") {
                    access_type = Some("read128");
                    trace!("  Found read128 access");
                }
            }
        });
    }

    let cs = match H::create_disassembler() {
        Ok(c) => c,
        Err(e) => {
            error!("Failed to create disassembler: {}", e);
            return EXCEPTION_CONTINUE_SEARCH;
        }
    };

    if is_jit {
        trace!("Detected MMIO fastmem access! Patching...");
        let mut bus_frame_index: Option<usize> = None;
        let mut matched_pattern: Option<&'static str> = None;

        // Use raw frames to find the helper pattern
        for (i, &ip) in raw_frames.iter().enumerate() {
            resolve(ip as *mut _, |symbol| {
                if let Some(name) = symbol.name() {
                    let demangled = format!("{}", name);
                    for &pattern in H::get_helper_pattern().iter() {
                        if demangled.contains(pattern) {
                            bus_frame_index = Some(i);
                            matched_pattern = Some(pattern);
                            trace!(
                            "Found helper symbol `{}` at frame {} (matched `{}`)",
                            demangled, i, pattern
                        );
                            break;
                        }
                    }
                }
            });
            if bus_frame_index.is_some() { break; }
        }

        if bus_frame_index.is_none() {
            error!("No __bus_* frame identified in raw backtrace for JIT");
            return EXCEPTION_CONTINUE_SEARCH;
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
                error!("Unrecognized helper pattern: {}", other);
                return EXCEPTION_CONTINUE_SEARCH;
            }
        };

        let target_frame_index = bus_frame_index.unwrap() + 1;
        if target_frame_index < raw_frames.len() {
            let ip = raw_frames[target_frame_index] as usize;
            trace!("Processing frame at index {} with IP 0x{:x}", target_frame_index, ip);

            // load a 14‑byte window ending at IP
            let buf_size = 14;
            let buf_start = ip.saturating_sub(buf_size);
            let buf: [u8; 14] = unsafe { std::ptr::read(buf_start as *const [u8; 14]) };

            let movabs_opcodes = [
                ([0x48, 0xB8], "rax"), ([0x48, 0xB9], "rcx"), ([0x48, 0xBA], "rdx"),
                ([0x48, 0xBB], "rbx"), ([0x48, 0xBC], "rsp"), ([0x48, 0xBD], "rbp"),
                ([0x48, 0xBE], "rsi"), ([0x48, 0xBF], "rdi"), ([0x49, 0xB8], "r8"),
                ([0x49, 0xB9], "r9"), ([0x49, 0xBA], "r10"), ([0x49, 0xBB], "r11"),
            ];

            let call_opcodes_2byte = [
                ([0xFF, 0xD0], "rax"), ([0xFF, 0xD1], "rcx"), ([0xFF, 0xD2], "rdx"),
                ([0xFF, 0xD3], "rbx"), ([0xFF, 0xD4], "rsp"), ([0xFF, 0xD5], "rbp"),
                ([0xFF, 0xD6], "rsi"), ([0xFF, 0xD7], "rdi"),
            ];

            let call_opcodes_3byte = [
                ([0x41, 0xFF, 0xD0], "r8"),  ([0x41, 0xFF, 0xD1], "r9"),
                ([0x41, 0xFF, 0xD2], "r10"), ([0x41, 0xFF, 0xD3], "r11"),
            ];

            // collect all movabs hits
            let mut mov_hits = Vec::new();
            for i in 0..=buf_size-2 {
                if let Some((_, reg)) = movabs_opcodes.iter()
                    .find(|(opc, _)| &buf[i..i+2] == opc)
                {
                    mov_hits.push((i, *reg));
                }
            }

            // collect all call hits
            let mut call_hits = Vec::new();
            for i in 0..=buf_size-2 {
                // 2‑byte calls
                if let Some((_, reg)) = call_opcodes_2byte.iter()
                    .find(|(opc, _)| &buf[i..i+2] == opc)
                {
                    call_hits.push((i, *reg, 2));
                }
                // 3‑byte calls
                if i + 3 <= buf_size {
                    if let Some((_, reg)) = call_opcodes_3byte.iter()
                        .find(|(opc, _)| &buf[i..i+3] == opc)
                    {
                        call_hits.push((i, *reg, 3));
                    }
                }
            }

            for &(mov_off, mov_reg) in &mov_hits {
                for &(_, call_reg, _) in &call_hits {
                    if mov_reg == call_reg {
                        let movabs_addr = buf_start + mov_off;
                        let reg = H::parse_register_from_operand(mov_reg).unwrap();
                        let stub_bytes = H::encode_stub_call(&reg, stub_addr).unwrap();
                        patch_instruction(movabs_addr as u64, &stub_bytes)
                            .expect("failed to write stub");

                        let fault_rip = (*ctx).Rip as i64;
                        if let Err(e) = H::advance_instruction_pointer(ctx, &cs, fault_rip) {
                            error!("Failed to advance instruction pointer: {}", e);
                            return EXCEPTION_CONTINUE_SEARCH;
                        }

                        // Windows x64 calling convention: RCX, RDX, R8, R9
                        let bus_ptr = BUS_PTR as *mut Bus;
                        let addr = fault_addr as u32;

                        if let Some(access) = access_type {
                        match access {
                            "write8" => {
                                let value = (*ctx).Rcx as u8;
                                io_write8_stub(bus_ptr, addr, value);
                                trace!("Executed io_write8_stub(bus_ptr={:p}, addr=0x{:x}, value=0x{:x})", bus_ptr, addr, value);
                            }
                            "write16" => {
                                let value = (*ctx).Rcx as u16;
                                io_write16_stub(bus_ptr, addr, value);
                                trace!("Executed io_write16_stub(bus_ptr={:p}, addr=0x{:x}, value=0x{:x})", bus_ptr, addr, value);
                            }
                            "write32" => {
                                let value = (*ctx).Rcx as u32;
                                io_write32_stub(bus_ptr, addr, value);
                                trace!("Executed io_write32_stub(bus_ptr={:p}, addr=0x{:x}, value=0x{:x})", bus_ptr, addr, value);
                            }
                            "write64" => {
                                let value = (*ctx).Rcx as u64;
                                io_write64_stub(bus_ptr, addr, value);
                                trace!("Executed io_write64_stub(bus_ptr={:p}, addr=0x{:x}, value=0x{:x})", bus_ptr, addr, value);
                            }
                            "write128" => {
                                let low = (*ctx).R8 as u64;
                                let high = (*ctx).R9 as u64;
                                let value = ((high as u128) << 64) | (low as u128);
                                io_write128_stub(bus_ptr, addr, value);
                                trace!("Executed io_write128_stub(bus_ptr={:p}, addr=0x{:x}, value=0x{:x})", bus_ptr, addr, value);
                            }
                            "read8" => {
                                let value = io_read8_stub(bus_ptr, addr);
                                (*ctx).Rax = value as u64;
                                trace!("Executed io_read8_stub(bus_ptr={:p}, addr=0x{:x}) -> 0x{:x}", bus_ptr, addr, value);
                            }
                            "read16" => {
                                let value = io_read16_stub(bus_ptr, addr);
                                (*ctx).Rax = value as u64;
                                trace!("Executed io_read16_stub(bus_ptr={:p}, addr=0x{:x}) -> 0x{:x}", bus_ptr, addr, value);
                            }
                            "read32" => {
                                let value = io_read32_stub(bus_ptr, addr);
                                (*ctx).Rax = value as u64;
                                trace!("Executed io_read32_stub(bus_ptr={:p}, addr=0x{:x}) -> 0x{:x}", bus_ptr, addr, value);
                            }
                            "read64" => {
                                let value = io_read64_stub(bus_ptr, addr);
                                (*ctx).Rax = value as u64;
                                trace!("Executed io_read64_stub(bus_ptr={:p}, addr=0x{:x}) -> 0x{:x}", bus_ptr, addr, value);
                            }
                            "read128" => {
                                let value = io_read128_stub(bus_ptr, addr);
                                let low = (value as u128) as u64;
                                let high = (value >> 64) as u64;
                                (*ctx).Rax = low as u64;
                                (*ctx).Rdx = high as u64;
                                trace!("Executed io_read128_stub(bus_ptr={:p}, addr=0x{:x}) -> 0x{:x}", bus_ptr, addr, value);
                            }
                            _ => {
                                error!("Unknown access type: {}", access);
                                return EXCEPTION_CONTINUE_SEARCH;
                            }
                        }
                    }

                    trace!("Patched at 0x{:x}", movabs_addr);
                                return EXCEPTION_CONTINUE_EXECUTION;
                            }
                        }
                    }
        } else {
            error!("No frame at target index {} (raw_frames.len() = {})", target_frame_index, raw_frames.len());
        }

        error!("Failed to patch JIT code");
        return EXCEPTION_CONTINUE_SEARCH;
    } else if let Some(access) = access_type {
        trace!("Detected interpreter fastmem access, redirecting to I/O...");

        // Windows x64 calling convention: RCX, RDX, R8, R9
        let bus_ptr = BUS_PTR as *mut Bus;
        let addr = fault_addr as u32;
        let fault_rip = (*ctx).Rip as i64;

        match access {
            "write8" => {
                let value = (*ctx).Rcx as u8;
                io_write8_stub(bus_ptr, addr, value);
                trace!("Executed io_write8_stub(bus_ptr={:p}, addr=0x{:x}, value=0x{:x})", bus_ptr, addr, value);
            }
            "write16" => {
                let value = (*ctx).Rcx as u16;
                io_write16_stub(bus_ptr, addr, value);
                trace!("Executed io_write16_stub(bus_ptr={:p}, addr=0x{:x}, value=0x{:x})", bus_ptr, addr, value);
            }
            "write32" => {
                let value = (*ctx).Rcx as u32;
                io_write32_stub(bus_ptr, addr, value);
                trace!("Executed io_write32_stub(bus_ptr={:p}, addr=0x{:x}, value=0x{:x})", bus_ptr, addr, value);
            }
            "write64" => {
                let value = (*ctx).Rcx as u64;
                io_write64_stub(bus_ptr, addr, value);
                trace!("Executed io_write64_stub(bus_ptr={:p}, addr=0x{:x}, value=0x{:x})", bus_ptr, addr, value);
            }
            "write128" => {
                let low = (*ctx).R8 as u64;
                let high = (*ctx).R9 as u64;
                let value = ((high as u128) << 64) | (low as u128);
                //io_write128_stub(bus_ptr, addr, value);
                trace!("Executed io_write128_stub(bus_ptr={:p}, addr=0x{:x}, value=0x{:x})", bus_ptr, addr, value);
            }
            "read8" => {
                let value = io_read8_stub(bus_ptr, addr);
                (*ctx).Rax = value as u64;
                trace!("Executed io_read8_stub(bus_ptr={:p}, addr=0x{:x}) -> 0x{:x}", bus_ptr, addr, value);
            }
            "read16" => {
                let value = io_read16_stub(bus_ptr, addr);
                (*ctx).Rax = value as u64;
                trace!("Executed io_read16_stub(bus_ptr={:p}, addr=0x{:x}) -> 0x{:x}", bus_ptr, addr, value);
            }
            "read32" => {
                let value = io_read32_stub(bus_ptr, addr);
                (*ctx).Rax = value as u64;
                trace!("Executed io_read32_stub(bus_ptr={:p}, addr=0x{:x}) -> 0x{:x}", bus_ptr, addr, value);
            }
            "read64" => {
                let value = io_read64_stub(bus_ptr, addr);
                (*ctx).Rax = value as u64;
                trace!("Executed io_read64_stub(bus_ptr={:p}, addr=0x{:x}) -> 0x{:x}", bus_ptr, addr, value);
            }
            "read128" => {
                let value = io_read128_stub(bus_ptr, addr);
                let low = (value as u128) as u64;
                let high = (value >> 64) as u64;
                (*ctx).Rax = low as u64;
                (*ctx).Rdx = high as u64;
                trace!("Executed io_read128_stub(bus_ptr={:p}, addr=0x{:x}) -> 0x{:x}", bus_ptr, addr, value);
            }
            _ => {
                error!("Unknown access type: {}", access);
                return EXCEPTION_CONTINUE_SEARCH;
            }
        }

        if let Err(e) = H::advance_instruction_pointer(ctx, &cs, fault_rip) {
            error!("Failed to advance instruction pointer: {}", e);
            return EXCEPTION_CONTINUE_SEARCH;
        }

        return EXCEPTION_CONTINUE_EXECUTION;
    }

    EXCEPTION_CONTINUE_SEARCH
}}

fn patch_instruction(addr: u64, patch_bytes: &[u8]) -> Result<(), String> {
    let mut system_info: SYSTEM_INFO = unsafe { std::mem::zeroed() };
    unsafe { GetSystemInfo(&mut system_info) };
    let page_size = system_info.dwPageSize as usize;

    let page_start = (addr as usize) & !(page_size - 1);

    trace!(
        "Preparing to patch at 0x{:x}, page_start=0x{:x}, page_size=0x{:x}",
        addr, page_start, page_size
    );

    let mut old_protect = 0u32;

    // Change protection to writable
    let result = unsafe {
        VirtualProtect(
            page_start as *const std::ffi::c_void,
            page_size,
            PAGE_READWRITE,
            &mut old_protect,
        )
    };

    if result == 0 {
        return Err("VirtualProtect to READWRITE failed".to_string());
    }

    // Apply the patch
    unsafe {
        let dest = addr as *mut u8;
        std::ptr::copy_nonoverlapping(patch_bytes.as_ptr(), dest, patch_bytes.len());
    }

    // Restore executable protection
    let result = unsafe {
        VirtualProtect(
            page_start as *const std::ffi::c_void,
            page_size,
            PAGE_EXECUTE_READ,
            &mut old_protect,
        )
    };

    if result == 0 {
        return Err("VirtualProtect to EXECUTE_READ failed".to_string());
    }

    trace!("Successfully patched instruction at 0x{:016x}", addr);
    Ok(())
}

fn fix_return_address<H: ArchHandler<Context = CONTEXT>>(
    ctx: *mut CONTEXT,
    patch_addr: u64,
    ret_addr: usize,
) {
    let old_sp = H::get_stack_pointer(ctx) as usize;
    let target_ret = patch_addr - 12;

    trace!(
        "old_sp = 0x{:016x}, original_ret = 0x{:016x}, target_ret = 0x{:016x}",
        old_sp, ret_addr, target_ret
    );

    const MAX_SLOTS: usize = 512;
    let mut found = false;

    for i in 0..MAX_SLOTS {
        let slot_addr = old_sp + i * 8;
        let candidate: usize = unsafe { *(slot_addr as *const usize) };

        if candidate.eq(&ret_addr ) {
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
    
    let handle = unsafe { AddVectoredExceptionHandler(1, Some(veh_handler)) };
    if handle.is_null() {
        return Err(io::Error::new(
            ErrorKind::Other,
            "AddVectoredExceptionHandler failed",
        ));
    }

    info!("Vectored exception handler installed successfully");
    Ok(())
}