use libc::{c_void, sigaction, sighandler_t, siginfo_t, ucontext_t, SA_SIGINFO};
use std::sync::atomic::{AtomicBool, Ordering};
use std::io;

static HANDLER_INSTALLED: AtomicBool = AtomicBool::new(false);

unsafe extern "C" fn segv_handler(
    _signo: i32,
    info: *mut siginfo_t,
    ctx: *mut c_void,
) {
    let guest_addr = unsafe { (*info).si_addr() as usize };
    let bus = unsafe { &mut *super::BUS_PTR };
    let base = super::HW_BASE.load(Ordering::SeqCst);
    let size = bus.hw_size;

    if guest_addr >= base && guest_addr < base + size {
        let fault_addr = (guest_addr - base) as u32;
        let uc = unsafe { &mut *(ctx as *mut ucontext_t) };

        panic!(
            "SIGSEGV at host VA=0x{:X}, guest PA=0x{:08X}",
            guest_addr - base,
            fault_addr
        );
    }

    unsafe {
        let default: extern "C" fn(i32) = std::mem::transmute(libc::SIG_DFL);
        default(libc::SIGSEGV);
    }
}

pub unsafe fn install_handler() -> io::Result<()> {
    if HANDLER_INSTALLED.swap(true, Ordering::SeqCst) {
        return Ok(());
    }
    let mut sa: sigaction = unsafe { std::mem::MaybeUninit::zeroed().assume_init() };
    sa.sa_sigaction = segv_handler as sighandler_t;
    sa.sa_flags = SA_SIGINFO;
    unsafe { libc::sigemptyset(&mut sa.sa_mask) };
    unsafe { sigaction(libc::SIGSEGV, &sa, std::ptr::null_mut()) };
    unsafe { sigaction(libc::SIGBUS, &sa, std::ptr::null_mut()) };
    Ok(())
}