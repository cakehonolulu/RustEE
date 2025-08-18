use std::collections::HashMap;
use capstone::prelude::ArchDetail;
use std::ffi::c_void;
use std::io::{self, ErrorKind};
use std::mem::zeroed;
use std::ptr;
use std::sync::atomic::Ordering;
use std::sync::RwLock;
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

use capstone::arch::{x86, BuildsCapstone, DetailsArchInsn};
use capstone::{arch, Capstone, RegId};
use capstone::arch::x86::X86Reg;
use once_cell::sync::Lazy;
use crate::bus::backpatch::{execute_stub, find_function_end, find_memory_access_register, io_read128_stub, io_read16_stub, io_read64_stub, io_read8_stub, io_write128_stub, io_write16_stub, io_write64_stub, io_write8_stub, AccessInfo, AccessKind, AccessWidth};
use crate::bus::backpatch::AccessKind::*;
use crate::bus::backpatch::AccessWidth::*;
use super::{Bus, BUS_PTR, HW_BASE, HW_LENGTH};

#[cfg(target_arch = "x86_64")]
use super::backpatch::{ArchHandler, HANDLER_INSTALLED, io_write32_stub, io_read32_stub, CurrentArchHandler, x86_64_impl};

#[derive(Clone, Copy, Debug)]
struct BusFnId {
    is_write: bool,
    width_index: u8,
    is_jit: bool,
}

static BUS_RANGES: Lazy<RwLock<Vec<(u64, u64, BusFnId)>>> =
    Lazy::new(|| RwLock::new(Vec::new()));

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

thread_local! {
    static CAPSTONE: Capstone = Capstone::new()
        .x86()
        .mode(arch::x86::ArchMode::Mode64)
        .detail(true)
        .build()
        .expect("Failed to create Capstone object");
}

static STUB_ADDRS: Lazy<HashMap<AccessInfo, u64>> = Lazy::new(|| {
    let mut m = HashMap::new();
    m.insert(AccessInfo { kind: Write, width: B8 }, io_write8_stub as u64);
    m.insert(AccessInfo { kind: Write, width: B16 }, io_write16_stub as u64);
    m.insert(AccessInfo { kind: Write, width: B32 }, io_write32_stub as u64);
    m.insert(AccessInfo { kind: Write, width: B64 }, io_write64_stub as u64);
    m.insert(AccessInfo { kind: Write, width: B128 }, io_write128_stub as u64);
    m.insert(AccessInfo { kind: Read, width: B8 }, io_read8_stub as u64);
    m.insert(AccessInfo { kind: Read, width: B16 }, io_read16_stub as u64);
    m.insert(AccessInfo { kind: Read, width: B32 }, io_read32_stub as u64);
    m.insert(AccessInfo { kind: Read, width: B64 }, io_read64_stub as u64);
    m.insert(AccessInfo { kind: Read, width: B128 }, io_read128_stub as u64);
    m
});

unsafe fn generic_exception_handler<
    H: ArchHandler<Context = CONTEXT, Register = x86_64_impl::X86Register>
>(
    info: *mut EXCEPTION_POINTERS
) -> i32 {
    if info.is_null() {
        error!("Null info in exception handler");
        return EXCEPTION_CONTINUE_SEARCH;
    }

    let record = &*(*info).ExceptionRecord;
    let ctx = &mut *(*info).ContextRecord;

    if record.ExceptionCode != 0xC0000005u32 as i32 { // STATUS_ACCESS_VIOLATION
        return EXCEPTION_CONTINUE_SEARCH;
    }

    let guest_addr = record.ExceptionInformation[1] as usize;
    let base = HW_BASE.load(Ordering::SeqCst);
    let size = HW_LENGTH.load(Ordering::SeqCst);

    if guest_addr < base || guest_addr >= base + size {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    let fault_addr = (guest_addr - base) as u32;
    trace!(
        "SIGSEGV at host VA=0x{:x}, guest PA=0x{:08x}",
        guest_addr, fault_addr
    );

    let raw_frames = capture_raw_backtrace(0, 10);
    let mut bus_fn_id: Option<BusFnId> = None;
    let mut bus_frame_index: Option<usize> = None;

    let guard = BUS_RANGES.read().expect("BUS_RANGES lock poisoned");

    for (i, &ip) in raw_frames.iter().enumerate() {
        let ip_u64 = ip as u64;
        for &(start, end, fn_id) in guard.iter() {
            if ip_u64 >= start && ip_u64 < end {
                bus_fn_id = Some(fn_id);
                bus_frame_index = Some(i);
            }
        }
    }

    let access_info = match bus_fn_id {
        Some(fn_id) => AccessInfo {
            kind: if fn_id.is_write { Write } else { Read },
            width: match fn_id.width_index {
                0 => B8,
                1 => B16,
                2 => B32,
                3 => B64,
                4 => B128,
                _ => return EXCEPTION_CONTINUE_SEARCH,
            },
        },
        None => return EXCEPTION_CONTINUE_SEARCH,
    };

    let is_jit = bus_fn_id.unwrap().is_jit;

        if is_jit {
            trace!("Detected JIT fastmem access! Attempting to patch call site...");

            let target_frame_index = bus_frame_index.unwrap() + 1;
            if target_frame_index >= raw_frames.len() {
                error!("Cannot find caller frame for JIT patch.");
                return EXCEPTION_CONTINUE_SEARCH;
            }

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
                        let Some(reg) = H::parse_register_from_operand(&mov_reg) else { continue };
                        let Some(stub_addr) = STUB_ADDRS.get(&access_info) else { continue };
                        let Some(stub_bytes) = H::encode_stub_call(&reg, *stub_addr) else { continue };

                        if patch_instruction(movabs_addr as u64, &stub_bytes).is_ok() {
                            trace!("Patched JIT call at 0x{:x}", movabs_addr);
                            execute_stub::<H>(ctx, access_info, fault_addr);
                            CAPSTONE.with(|cs| {
                                H::advance_instruction_pointer(ctx, cs, H::get_instruction_pointer(ctx)).unwrap();
                            });
                            return EXCEPTION_CONTINUE_EXECUTION;
                        }
                    }
                }
            }

            error!("Failed to find instruction pair to patch JIT code at 0x{:x}", ip);
        } else {
            trace!("Detected interpreter fastmem access, redirecting to I/O handler...");
            execute_stub::<H>(ctx, access_info, fault_addr);

            let fault_rip = H::get_instruction_pointer(ctx);
            CAPSTONE.with(|cs| {
                H::advance_instruction_pointer(ctx, cs, fault_rip).unwrap();
            });
            return EXCEPTION_CONTINUE_EXECUTION;
        }

        EXCEPTION_CONTINUE_SEARCH
}

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
        (Bus::hw_write8 as *const c_void, 0usize),
        (Bus::hw_write16 as *const c_void, 1usize),
        (Bus::hw_write32 as *const c_void, 2usize),
        (Bus::hw_write64 as *const c_void, 3usize),
        (Bus::hw_write128 as *const c_void, 4usize),
    ];
    let read_functions = [
        (Bus::hw_read8 as *const c_void, 0u8),
        (Bus::hw_read16 as *const c_void, 1u8),
        (Bus::hw_read32 as *const c_void, 2u8),
        (Bus::hw_read64 as *const c_void, 3u8),
        (Bus::hw_read128 as *const c_void, 4u8),
    ];

    use crate::ee::jit;
    let jit_write_functions = [
        (jit::__bus_write8 as *const c_void, 0usize),
        (jit::__bus_write16 as *const c_void, 1usize),
        (jit::__bus_write32 as *const c_void, 2usize),
        (jit::__bus_write64 as *const c_void, 3usize),
        (jit::__bus_write128 as *const c_void, 4usize),
    ];
    let jit_read_functions = [
        (jit::__bus_read8 as *const c_void, 0u8),
        (jit::__bus_read16 as *const c_void, 1u8),
        (jit::__bus_read32 as *const c_void, 2u8),
        (jit::__bus_read64 as *const c_void, 3u8),
        (jit::__bus_read128 as *const c_void, 4u8),
    ];

    {
        let mut ranges = Vec::new();

        for &(fp, idx) in write_functions.iter() {
            let start = fp as u64;
            let end_ptr = find_function_end(&cs, fp, 150);
            let end = end_ptr as u64;
            ranges.push((start, end, BusFnId { is_write: true, width_index: idx as u8, is_jit: false }));
            trace!("Registered write stub: idx={} start={:#x} end={:#x}", idx, start, end);
        }

        for &(fp, idx) in read_functions.iter() {
            let start = fp as u64;
            let end_ptr = find_function_end(&cs, fp, 150);
            let end = end_ptr as u64;
            ranges.push((start, end, BusFnId { is_write: false, width_index: idx, is_jit: false }));
            trace!("Registered read  stub: idx={} start={:#x} end={:#x}", idx, start, end);
        }

        for &(fp, idx) in jit_write_functions.iter() {
            let start = fp as u64;
            let end_ptr = find_function_end(&cs, fp, 250);
            let end = end_ptr as u64;
            ranges.push((start, end, BusFnId { is_write: true, width_index: idx as u8, is_jit: true }));
            trace!("Registered JIT write stub: idx={} start={:#x} end={:#x}", idx, start, end);
        }

        for &(fp, idx) in jit_read_functions.iter() {
            let start = fp as u64;
            let end_ptr = find_function_end(&cs, fp, 500);
            let end = end_ptr as u64;
            ranges.push((start, end, BusFnId { is_write: false, width_index: idx, is_jit: true }));
            trace!("Registered JIT read  stub: idx={} start={:#x} end={:#x}", idx, start, end);
        }

        let mut guard = BUS_RANGES.write().expect("BUS_RANGES lock poisoned");
        *guard = ranges;
    }

    CAPSTONE.with(|cap| {
        for (func_ptr, index) in write_functions.iter() {
            if let Some(reg) = find_memory_access_register(&cs, *func_ptr, *index == 4) {
                unsafe {
                    super::backpatch::REGISTER_MAP[*index] = Some(reg);
                }
            } else {
                error!("Failed to find memory access register for function at {:p}", func_ptr);
            }
        }
    });

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