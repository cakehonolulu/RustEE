use nix::sys::signal::{
    sigaction, SaFlags, SigAction, SigHandler, SigSet, Signal,
};
use nix::libc;

use std::convert::TryFrom;
use std::sync::atomic::{AtomicBool, Ordering};
use std::io;
use std::os::raw::{c_int, c_void};

use crate::bus::{HW_BASE, HW_LENGTH};

static HANDLER_INSTALLED: AtomicBool = AtomicBool::new(false);

extern "C" fn segv_handler(signum: c_int, info: *mut libc::siginfo_t, _context: *mut c_void) {
    if info.is_null() {
        return;
    }

    let guest_addr = unsafe { (*info).si_addr() as usize };

    let base = HW_BASE.load(Ordering::SeqCst);
    let size = HW_LENGTH.load(Ordering::SeqCst);
    if guest_addr >= base && guest_addr < base + size {
        let fault_addr = (guest_addr - base) as u32;

        panic!(
            "SIGSEGV at host VA=0x{:X}, guest PA=0x{:08X}",
            guest_addr,
            fault_addr
        );
    }

    // Restore default handler and re-raise the signal
    unsafe {
        if let Ok(signal) = Signal::try_from(signum) {
            let default_action = SigAction::new(SigHandler::SigDfl, SaFlags::empty(), SigSet::empty());
            let _ = sigaction(signal, &default_action);
        }
        libc::raise(signum);
    }
}

pub fn install_handler() -> io::Result<()> {
    if HANDLER_INSTALLED.swap(true, Ordering::SeqCst) {
        return Ok(());
    }

    let handler = SigHandler::SigAction(segv_handler);
    let flags = SaFlags::SA_SIGINFO;
    let mask = SigSet::empty();
    let action = SigAction::new(handler, flags, mask);

    unsafe {
        sigaction(Signal::SIGSEGV, &action).map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        sigaction(Signal::SIGBUS, &action).map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
    }

    Ok(())
}
