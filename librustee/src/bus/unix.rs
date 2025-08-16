use crate::bus::backpatch::{
    execute_stub, find_function_end, find_memory_access_register, io_read128_stub, io_read16_stub,
    io_read32_stub, io_read64_stub, io_read8_stub, io_write128_stub, io_write16_stub,
    io_write32_stub, io_write64_stub, io_write8_stub, AccessInfo, AccessKind, AccessWidth,
    ArchHandler, CurrentArchHandler, HANDLER_INSTALLED, x86_64_impl,
};
use crate::bus::unix::libc::ucontext_t;
use crate::bus::{Bus, HW_BASE, HW_LENGTH};
use capstone::arch::x86::X86Reg;
use capstone::arch::{x86, BuildsCapstone, DetailsArchInsn};
use capstone::{arch, Capstone, RegId};
use nix::libc;
use nix::sys::mman::{mprotect, ProtFlags};
use nix::sys::signal::{sigaction, SaFlags, SigAction, SigHandler, SigSet, Signal};
use once_cell::sync::Lazy;
use std::collections::HashMap;
use std::io;
use std::os::raw::{c_int, c_void};
use std::sync::atomic::Ordering;
use std::sync::RwLock;
use tracing::{debug, error, info, trace};

#[derive(Clone, Copy, Debug)]
struct BusFnId {
    is_write: bool,
    width_index: u8,
    is_jit: bool,
}

static BUS_RANGES: Lazy<RwLock<Vec<(u64, u64, BusFnId)>>> =
    Lazy::new(|| RwLock::new(Vec::new()));

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
    use AccessKind::*;
    use AccessWidth::*;
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

fn generic_segv_handler<
    H: ArchHandler<Context = ucontext_t, Register = x86_64_impl::X86Register>,
>(
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
        restore_default_handler_and_raise(signum);
        return;
    }

    let fault_addr = (guest_addr - base) as u32;
    trace!(
        "SIGSEGV at host VA=0x{:x}, guest PA=0x{:08x}",
        guest_addr,
        fault_addr
    );

    let rip = H::get_instruction_pointer(ctx) as u64;
    let mut bus_fn_id: Option<BusFnId> = None;

    let guard = BUS_RANGES.read().expect("BUS_RANGES lock poisoned");
    for &(start, end, fn_id) in guard.iter() {
        if rip >= start && rip < end {
            bus_fn_id = Some(fn_id);
            break;
        }
    }

    let access_info = match bus_fn_id {
        Some(fn_id) => AccessInfo {
            kind: if fn_id.is_write {
                AccessKind::Write
            } else {
                AccessKind::Read
            },
            width: match fn_id.width_index {
                0 => AccessWidth::B8,
                1 => AccessWidth::B16,
                2 => AccessWidth::B32,
                3 => AccessWidth::B64,
                4 => AccessWidth::B128,
                _ => {
                    restore_default_handler_and_raise(signum);
                    return;
                }
            },
        },
        None => {
            restore_default_handler_and_raise(signum);
            return;
        }
    };

    let is_jit = bus_fn_id.unwrap().is_jit;

    CAPSTONE.with(|cs| {
        if is_jit {
            trace!("Detected JIT fastmem access! Attempting to patch call site...");

            let caller_ret_addr = unsafe { *(H::get_stack_pointer(ctx) as *const u64) };

            const SEARCH_RANGE: u64 = 32;
            let search_start = caller_ret_addr.saturating_sub(SEARCH_RANGE);
            let code_slice = unsafe {
                std::slice::from_raw_parts(search_start as *const u8, SEARCH_RANGE as usize)
            };

            let Ok(insns) = cs.disasm_all(code_slice, search_start) else {
                error!("Failed to disassemble JIT code at 0x{:x}", search_start);
                restore_default_handler_and_raise(signum);
                return;
            };

            let mut mov_addr = 0u64;
            let mut mov_reg: Option<RegId> = None;

            for insn in insns.iter() {
                if insn.address() >= caller_ret_addr {
                    break;
                }

                if insn.mnemonic() == Some("mov") {
                    if let Ok(detail) = cs.insn_detail(insn) {
                        let operands: Vec<_> =
                            detail.arch_detail().x86().unwrap().operands().collect();
                        if operands.len() == 2 {
                            if let &x86::X86OperandType::Reg(reg) = &operands[0].op_type {
                                if let &x86::X86OperandType::Imm(_) = &operands[1].op_type {
                                    mov_addr = insn.address();
                                    mov_reg = Some(reg);
                                }
                            }
                        }
                    }
                }

                if insn.mnemonic() == Some("call")
                    && (insn.address() + insn.bytes().len() as u64 == caller_ret_addr)
                {
                    if let Ok(detail) = cs.insn_detail(insn) {
                        let operands: Vec<_> =
                            detail.arch_detail().x86().unwrap().operands().collect();
                        if operands.len() == 1 {
                            if let (Some(mov_reg_id), &x86::X86OperandType::Reg(call_reg_id)) =
                                (mov_reg, &operands[0].op_type)
                            {
                                if mov_reg_id.0 == call_reg_id.0 {
                                    let reg_name = cs.reg_name(mov_reg_id).unwrap_or_default();
                                    let Some(reg) = H::parse_register_from_operand(&reg_name) else { continue };
                                    let Some(stub_addr) = STUB_ADDRS.get(&access_info) else { continue };
                                    let Some(stub_bytes) = H::encode_stub_call(&reg, *stub_addr) else { continue };

                                    if patch_instruction(mov_addr, &stub_bytes).is_ok() {
                                        trace!("Patched JIT call at 0x{:x}", mov_addr);
                                        unsafe { execute_stub::<H>(ctx, access_info, fault_addr) };
                                        H::advance_instruction_pointer(
                                            ctx,
                                            cs,
                                            H::get_instruction_pointer(ctx),
                                        )
                                        .unwrap();
                                        return;
                                    }
                                }
                            }
                        }
                    }
                }
            }
            error!(
                "Failed to find instruction pair to patch JIT code at 0x{:x}",
                caller_ret_addr
            );
        } else {
            trace!("Detected interpreter fastmem access, redirecting to I/O handler...");
            unsafe { execute_stub::<H>(ctx, access_info, fault_addr) };

            let fault_rip = H::get_instruction_pointer(ctx);
            if H::advance_instruction_pointer(ctx, cs, fault_rip).is_err() {
                error!("Failed to advance instruction pointer in interpreter path.");
                restore_default_handler_and_raise(signum);
            }
            return;
        }
        restore_default_handler_and_raise(signum);
    })
}

fn patch_instruction(addr: u64, patch_bytes: &[u8]) -> Result<(), String> {
    let page_size = nix::unistd::sysconf(nix::unistd::SysconfVar::PAGE_SIZE)
        .map_err(|e| format!("Failed to get page size: {}", e))?
        .ok_or("Page size not available")? as usize;

    let page_start = (addr as usize) & !(page_size - 1);

    trace!(
        "Preparing to patch at 0x{:x}, page_start=0x{:x}, page_size=0x{:x}",
        addr,
        page_start,
        page_size
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
            ranges.push((
                start,
                end,
                BusFnId {
                    is_write: true,
                    width_index: idx as u8,
                    is_jit: false,
                },
            ));
            trace!(
                "Registered write stub: idx={} start={:#x} end={:#x}",
                idx,
                start,
                end
            );
        }

        for &(fp, idx) in read_functions.iter() {
            let start = fp as u64;
            let end_ptr = find_function_end(&cs, fp, 150);
            let end = end_ptr as u64;
            ranges.push((
                start,
                end,
                BusFnId {
                    is_write: false,
                    width_index: idx,
                    is_jit: false,
                },
            ));
            trace!(
                "Registered read  stub: idx={} start={:#x} end={:#x}",
                idx,
                start,
                end
            );
        }

        for &(fp, idx) in jit_write_functions.iter() {
            let start = fp as u64;
            let end_ptr = find_function_end(&cs, fp, 400);
            let end = end_ptr as u64;
            ranges.push((
                start,
                end,
                BusFnId {
                    is_write: true,
                    width_index: idx as u8,
                    is_jit: true,
                },
            ));
            trace!(
                "Registered JIT write stub: idx={} start={:#x} end={:#x}",
                idx,
                start,
                end
            );
        }

        for &(fp, idx) in jit_read_functions.iter() {
            let start = fp as u64;
            let end_ptr = find_function_end(&cs, fp, 500);
            let end = end_ptr as u64;
            ranges.push((
                start,
                end,
                BusFnId {
                    is_write: false,
                    width_index: idx,
                    is_jit: true,
                },
            ));
            trace!(
                "Registered JIT read  stub: idx={} start={:#x} end={:#x}",
                idx,
                start,
                end
            );
        }

        let mut guard = BUS_RANGES.write().expect("BUS_RANGES lock poisoned");
        *guard = ranges;
    }

    CAPSTONE.with(|_cap| {
        for (func_ptr, index) in write_functions.iter() {
            if let Some(reg) = find_memory_access_register(&cs, *func_ptr, *index == 4) {
                unsafe {
                    super::backpatch::REGISTER_MAP[*index] = Some(reg);
                }
            } else {
                error!(
                    "Failed to find memory access register for function at {:p}",
                    func_ptr
                );
            }
        }
    });

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