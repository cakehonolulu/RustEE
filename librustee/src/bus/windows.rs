use std::ffi::c_void;
use std::io::{self, ErrorKind};
use std::ptr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::ops::Add;
use tracing::{debug, error, info, trace};
use windows_sys::Win32::System::Diagnostics::Debug::RtlCaptureStackBackTrace;
use std::io::Write;
use windows_sys::Win32::System::SystemInformation::{GetSystemInfo, SYSTEM_INFO};
use windows_sys::Win32::{
    Foundation::{HANDLE, HMODULE, NTSTATUS},
    System::{
        Diagnostics::Debug::{
            AddVectoredExceptionHandler, EXCEPTION_CONTINUE_EXECUTION, EXCEPTION_CONTINUE_SEARCH, 
            EXCEPTION_POINTERS, CONTEXT,
        },
        Memory::{VirtualProtect, PAGE_EXECUTE_READ, PAGE_READWRITE},
        LibraryLoader::{GetModuleHandleA, GetProcAddress},
        Threading::GetCurrentThread,
    },
};

use backtrace::{resolve, Backtrace};
use capstone::Capstone;
use capstone::arch::BuildsCapstone;

use super::{Bus, HW_BASE, HW_LENGTH};

static HANDLER_INSTALLED: AtomicBool = AtomicBool::new(false);

unsafe fn capture_raw_backtrace(skip: u32, max_frames: u32) -> Vec<*mut c_void> {
    let mut buffer: Vec<*mut c_void> = Vec::with_capacity(max_frames as usize);
    buffer.set_len(max_frames as usize);

    let captured = unsafe { RtlCaptureStackBackTrace(
        skip,
        max_frames,
        buffer.as_mut_ptr(),
        ptr::null_mut(),
    ) };

    buffer.truncate(captured as usize);
    buffer
}

fn find_frame_ip_by_name(frames: &[ *mut c_void ], pattern: &str) -> Option<*mut c_void> {
    for &ip in frames {
        let mut found = false;
        resolve(ip, |symbol| {
            if let Some(name) = symbol.name() {
                let demangled = format!("{}", name);
                if demangled.contains(pattern) {
                    found = true;
                }
            }
        });
        if found {
            return Some(ip);
        }
    }
    None
}

trait ArchHandler {
    type Context;
    type Register: Clone + PartialEq;
    
    fn create_disassembler() -> Result<Capstone, capstone::Error>;
    fn encode_stub_call(reg: &Self::Register, stub_addr: u64) -> Option<Vec<u8>>;
    fn get_instruction_pointer(ctx: *mut CONTEXT) -> i64;
    fn set_instruction_pointer(ctx: *mut CONTEXT, addr: u64);
    fn get_stack_pointer(ctx: *mut CONTEXT) -> u64;
    fn advance_instruction_pointer(ctx: *mut CONTEXT, cs: &Capstone, fault_addr: i64) -> Result<(), &'static str>;
    fn parse_register_from_operand(operand: &str) -> Option<Self::Register>;
    fn register_name(reg: &Self::Register) -> &'static str;
    fn get_helper_pattern() -> &'static [&'static str];
    fn get_call_instruction() -> &'static str;
}

// X86-64 implementation for Windows
#[cfg(target_arch = "x86_64")]
mod x86_64_impl {
    use super::*;
    use capstone::arch::x86::ArchMode;
    
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
        type Context = CONTEXT;
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

        fn get_instruction_pointer(ctx: *mut CONTEXT) -> i64 {
            unsafe { (*ctx).Rip as i64 }
        }
        
        fn set_instruction_pointer(ctx: *mut CONTEXT, addr: u64) {
            unsafe { (*ctx).Rip = addr }
        }
        
        fn get_stack_pointer(ctx: *mut CONTEXT) -> u64 {
            unsafe { (*ctx).Rsp }
        }
        
        fn advance_instruction_pointer(ctx: *mut CONTEXT, cs: &Capstone, fault_addr: i64) -> Result<(), &'static str> {
            let inst_buf: &[u8] = unsafe { std::slice::from_raw_parts(fault_addr as *const u8, 16) };
            
            let instruction_length = if let Ok(insns) = cs.disasm_count(inst_buf, fault_addr.try_into().unwrap(), 1) {
                if let Some(insn) = insns.iter().next() {
                    trace!("advance_instruction_pointer: Instruction at {}", insn.to_string());
                    insn.len() as u64
                } else {
                    return Err("Could not disassemble faulting instruction");
                }
            } else {
                return Err("Failed to disassemble faulting instruction");
            };
            
            unsafe { (*ctx).Rip += instruction_length };
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

unsafe extern "system" fn veh_handler(info: *mut EXCEPTION_POINTERS) -> i32 {
    generic_exception_handler::<CurrentArchHandler>(info)
}

unsafe fn generic_exception_handler<H: ArchHandler>(info: *mut EXCEPTION_POINTERS) -> i32 {
    if info.is_null() {
        error!("Null info in exception handler");
        return EXCEPTION_CONTINUE_SEARCH;
    }

    let record = unsafe { (*info).ExceptionRecord };
    let ctx = unsafe { (*info).ContextRecord };

    if record.is_null() || ctx.is_null() {
        error!("Null record or context in exception handler");
        return EXCEPTION_CONTINUE_SEARCH;
    }

    let exception_code = unsafe { (*record).ExceptionCode };

    // Handle access violations (0xC0000005)
    if exception_code != 0xC0000005u32 as i32 {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    let guest_addr = unsafe { (*record).ExceptionInformation[1] as usize };
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
    debug!(
        "SIGSEGV at host VA=0x{:x}, guest PA=0x{:08x}",
        guest_addr, fault_addr
    );

    let raw_frames = unsafe { capture_raw_backtrace(0, 20) };
    let mut is_jit = false;
    let mut access_type = None;

    // First pass: detect JIT vs interpreter access using raw frames
    for (frame_idx, &ip) in raw_frames.iter().enumerate() {
        trace!("Checking frame {}: ip={:p}", frame_idx, ip);
        resolve(ip as *mut _, |symbol| {
            if let Some(name) = symbol.name() {
                let demangled = format!("{}", name);
                trace!("  Symbol: {}", demangled);
                if demangled.contains("__bus_write32") || demangled.contains("__bus_read32") {
                    is_jit = true;
                    trace!("  Found JIT access");
                } else if demangled.contains("hw_write32") {
                    access_type = Some("write");
                    trace!("  Found write access");
                } else if demangled.contains("hw_read32") {
                    access_type = Some("read");
                    trace!("  Found read access");
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
            pattern if pattern.contains("__bus_write32") => io_write32_stub as *const () as u64,
            pattern if pattern.contains("__bus_read32") => io_read32_stub as *const () as u64,
            other => {
                error!("Unrecognized helper pattern: {}", other);
                return EXCEPTION_CONTINUE_SEARCH;
            }
        };

        let target_frame_index = bus_frame_index.unwrap() + 1;
        if target_frame_index < raw_frames.len() {
            let ip = raw_frames[target_frame_index] as usize;
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
                                return EXCEPTION_CONTINUE_EXECUTION;
                            }
                        }
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
        let bus_ptr = (*ctx).Rcx as *mut Bus;
        let addr = (*ctx).Rdx as u32;
        let fault_rip = (*ctx).Rip as i64;

        if access == "write" {
            let value = (*ctx).R8 as u32;
            io_write32_stub(bus_ptr, addr as u64, value);
            trace!("Executed io_write32_stub(bus_ptr={:p}, addr=0x{:x}, value=0x{:x})", bus_ptr, addr, value);
        } else {
            let value = io_read32_stub(bus_ptr, addr as u64);
            (*ctx).Rax = value as u64;
            trace!("Executed io_read32_stub(bus_ptr={:p}, addr=0x{:x}) -> 0x{:x}", bus_ptr, addr, value);
        }

        if let Err(e) = H::advance_instruction_pointer(ctx, &cs, fault_rip) {
            error!("Failed to advance instruction pointer: {}", e);
            return EXCEPTION_CONTINUE_SEARCH;
        }

        return EXCEPTION_CONTINUE_EXECUTION;
    }

    EXCEPTION_CONTINUE_SEARCH
}

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

fn fix_return_address<H: ArchHandler>(
    ctx: *mut CONTEXT,
    patch_addr: u64,
    ret_addr: usize,
) {
    let old_sp = H::get_stack_pointer(ctx) as usize;
    let target_ret = patch_addr;

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