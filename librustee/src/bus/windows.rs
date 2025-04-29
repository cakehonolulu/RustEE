use std::io::{self, ErrorKind};
use std::ptr::null_mut;
use std::sync::atomic::{AtomicUsize, Ordering};
use windows_sys::Win32::System::Diagnostics::Debug::{
    AddVectoredExceptionHandler, EXCEPTION_CONTINUE_SEARCH, EXCEPTION_POINTERS,
};

pub unsafe extern "system" fn veh_handler(info: *mut EXCEPTION_POINTERS) -> i32 {
    let record = unsafe { (*info).ExceptionRecord };
    if unsafe { (*record).ExceptionCode } == 0xC0000005u32 as i32 {
        let fault_addr = unsafe { (*record).ExceptionInformation[1] as usize };
        let bus = unsafe { &mut *super::BUS_PTR };
        let base = super::HW_BASE.load(Ordering::SeqCst);
        let size = bus.hw_size;
        if fault_addr >= base && fault_addr < base + size {
            let guest_addr = (fault_addr - base) as u32;
            panic!(
                "SEH access violation at host VA=0x{:X}, guest PA=0x{:08X}",
                fault_addr, guest_addr
            );
        }
    }
    EXCEPTION_CONTINUE_SEARCH
}

pub unsafe fn install_handler() -> io::Result<()> {
    let handle = AddVectoredExceptionHandler(1, Some(veh_handler));
    if handle.is_null() {
        Err(io::Error::new(
            ErrorKind::Other,
            "AddVectoredExceptionHandler failed",
        ))
    } else {
        Ok(())
    }
}