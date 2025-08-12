use capstone::prelude::ArchDetail;
use std::ffi::c_void;
use std::io::{self, ErrorKind};
use std::mem::zeroed;
use std::ptr;
use std::sync::atomic::Ordering;
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
use capstone::arch::{BuildsCapstone, DetailsArchInsn};
use capstone::{arch, Capstone, RegId};
use capstone::arch::x86::X86Reg;
use once_cell::sync::Lazy;
use regex::Regex;
use crate::bus::backpatch::{execute_stub, find_memory_access_register, io_read128_stub, io_read16_stub, io_read64_stub, io_read8_stub, io_write128_stub, io_write16_stub, io_write64_stub, io_write8_stub};
use super::{Bus, BUS_PTR, HW_BASE, HW_LENGTH};

#[cfg(target_arch = "x86_64")]
use super::backpatch::{ArchHandler, HANDLER_INSTALLED, io_write32_stub, io_read32_stub, CurrentArchHandler, x86_64_impl};

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

unsafe fn generic_exception_handler<
    H: ArchHandler<Context = CONTEXT, Register = x86_64_impl::X86Register>
>(
    info: *mut EXCEPTION_POINTERS
) -> i32 {
    unsafe {
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

    if guest_addr < base || guest_addr >= base + size {
        error!(
            "Address 0x{:x} out of bounds (base=0x{:x}, size=0x{:x})",
            guest_addr, base, size
        );
        return EXCEPTION_CONTINUE_SEARCH;
    }

    let fault_addr = (guest_addr - base) as u32;
    trace!(
        "Exception at host VA=0x{:x}, guest PA=0x{:08x}",
        guest_addr, fault_addr
    );

    let raw_frames = capture_raw_backtrace(0, 20);
    let mut is_jit = false;
    let mut access_type: Option<String> = None;

    static BUS_HW_RE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r"(?:__bus|hw)_(read|write)(8|16|32|64|128)").unwrap()
    });

    for &ip in &raw_frames {
        resolve(ip as *mut _, |symbol| {
            if let Some(name) = symbol.name() {
                let demangled = format!("{}", name);
                let frame_is_jit = demangled.contains("jit");

                if let Some(caps) = BUS_HW_RE.captures(&demangled) {
                    let kind = &caps[1];
                    let width = &caps[2];
                    access_type = Some(format!("{}{}", kind, width));
                    is_jit = frame_is_jit;
                    trace!(
                        "  Found {} access (JIT={})",
                        access_type.as_deref().unwrap(),
                        is_jit
                    );
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
            if bus_frame_index.is_some() {
                break;
            }
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

            let buf_size = 19;
            let buf_start = ip.saturating_sub(buf_size);
            let buf: [u8; 19] = unsafe { std::ptr::read(buf_start as *const [u8; 19]) };

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

            let mut mov_hits = Vec::new();
            for i in 0..=buf_size - 2 {
                if let Some((_, reg)) = movabs_opcodes.iter()
                    .find(|(opc, _)| &buf[i..i + 2] == *opc) {
                    mov_hits.push((i, *reg));
                }
            }

            let mut call_hits = Vec::new();
            for i in 0..=buf_size - 2 {
                if let Some((_, reg)) = call_opcodes_2byte.iter()
                    .find(|(opc, _)| &buf[i..i + 2] == *opc) {
                    call_hits.push((i, *reg, 2));
                }
                if i + 3 <= buf_size {
                    if let Some((_, reg)) = call_opcodes_3byte.iter()
                        .find(|(opc, _)| &buf[i..i + 3] == *opc) {
                        call_hits.push((i, *reg, 3));
                    }
                }
            }

            for &(mov_off, mov_reg) in &mov_hits {
                for &(call_off, call_reg, _) in &call_hits {
                    if mov_reg == call_reg {
                        let movabs_addr = buf_start + mov_off;
                        let reg = H::parse_register_from_operand(mov_reg).unwrap();
                        let stub_bytes = H::encode_stub_call(&reg, stub_addr).unwrap();
                        patch_instruction(movabs_addr as u64, &stub_bytes)
                            .expect("failed to write stub");

                        let fault_rip = H::get_instruction_pointer(ctx);
                        if let Err(e) = H::advance_instruction_pointer(ctx, &cs, fault_rip) {
                            error!("Failed to advance instruction pointer: {}", e);
                            return EXCEPTION_CONTINUE_SEARCH;
                        }

                        if let Some(access) = access_type {
                            execute_stub::<H>(ctx, &access, fault_addr);
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

        execute_stub::<H>(ctx, &access, fault_addr);

        let fault_rip = H::get_instruction_pointer(ctx);

        if let Err(e) = H::advance_instruction_pointer(ctx, &cs, fault_rip) {
            error!("Failed to advance instruction pointer: {}", e);
            return EXCEPTION_CONTINUE_SEARCH;
        }

        return EXCEPTION_CONTINUE_EXECUTION;
    }

    EXCEPTION_CONTINUE_SEARCH
}}

fn patch_instruction(addr: u64, patch_bytes: &[u8]) -> Result<(), String> {
    let mut system_info: SYSTEM_INFO = unsafe { zeroed() };
    unsafe { GetSystemInfo(&mut system_info) };
    let page_size = system_info.dwPageSize as usize;

    let page_start = (addr as usize) & !(page_size - 1);

    trace!(
        "Preparing to patch at 0x{:x}, page_start=0x{:x}, page_size=0x{:x}",
        addr, page_start, page_size
    );

    let mut old_protect = 0u32;

    let result = unsafe {
        VirtualProtect(
            page_start as *const c_void,
            page_size,
            PAGE_READWRITE,
            &mut old_protect,
        )
    };

    if result == 0 {
        return Err("VirtualProtect to READWRITE failed".to_string());
    }

    unsafe {
        let dest = addr as *mut u8;
        ptr::copy_nonoverlapping(patch_bytes.as_ptr(), dest, patch_bytes.len());
    }

    let result = unsafe {
        VirtualProtect(
            page_start as *const c_void,
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

pub fn install_handler() -> io::Result<()> {
    if HANDLER_INSTALLED.swap(true, Ordering::SeqCst) {
        debug!("Handler already installed, skipping");
        return Ok(());
    }

    let cs = Capstone::new()
        .x86()
        .mode(arch::x86::ArchMode::Mode64)
        .detail(true)
        .build()
        .expect("Failed to create Capstone object");

    let write_functions = [
        (Bus::hw_write8 as *const c_void, 0),
        (Bus::hw_write16 as *const c_void, 1),
        (Bus::hw_write32 as *const c_void, 2),
        (Bus::hw_write64 as *const c_void, 3),
        (Bus::hw_write128 as *const c_void, 4),
    ];

    for (func_ptr, index) in write_functions.iter() {
        if let Some(reg) = find_memory_access_register(&cs, *func_ptr, *index == 4) {
            unsafe {
                super::backpatch::REGISTER_MAP[*index] = Some(reg);
            }
        } else {
            error!("Failed to find memory access register for function at {:p}", func_ptr);
        }
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