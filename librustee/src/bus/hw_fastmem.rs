use super::tlb::{Tlb, TlbEntry, mask_to_page_size};
use super::{Bus, HW_BASE};
use crate::bus::HW_LENGTH;
use backtrace::Backtrace;
use libc::{
    MAP_ANONYMOUS, MAP_FIXED, MAP_PRIVATE, MAP_SHARED, PROT_NONE, PROT_READ, PROT_WRITE, mmap,
    munmap,
};
use nix::fcntl::{OFlag, open};
use nix::sys::mman::{shm_open, shm_unlink};
use nix::sys::stat::Mode;
use nix::unistd::{close, ftruncate};
use std::io::{self, ErrorKind};
use std::os::fd::AsRawFd;
use std::os::raw::c_void;
use std::process::exit;
use std::ptr;
use std::sync::atomic::Ordering;
use tracing::error;
use tracing::{debug, trace};

pub unsafe fn init_hardware_fastmem(bus: &mut Bus) {
    debug!("Initializing Hardware Fast Memory...");
    debug!("Installing handler...");
    super::install_handler().expect("Failed to install handler");
    debug!("Handler installed");

    debug!("Initializing hardware arena...");
    let (base, size) = unsafe { init_hardware_arena(bus).expect("Failed to init arena") };
    debug!("Hardware arena initialized");

    bus.hw_base = base;
    bus.hw_size = size;

    HW_LENGTH.store(size, Ordering::SeqCst);
    HW_BASE.store(base as usize, Ordering::SeqCst);

    debug!(
        "Initialized Hardware Fast Memory: base=0x{:08X}, size={} bytes",
        bus.hw_base as usize, bus.hw_size
    );
}

pub unsafe fn init_hardware_arena(bus: &mut Bus) -> io::Result<(*mut u8, usize)> {
    unsafe {
        let size = 1usize << 32; // 4GB virtual address space

        // Reserve 4GB of virtual address space with no backing
        let base = mmap(
            ptr::null_mut(),
            size,
            PROT_NONE,
            MAP_PRIVATE | MAP_ANONYMOUS,
            -1,
            0,
        );

        if base == libc::MAP_FAILED {
            return Err(io::Error::new(
                ErrorKind::Other,
                "Failed to reserve address space",
            ));
        }

        let base = base as *mut u8;

        // Create shared memory for main RAM (32MB)
        let ram_size = 0x2000000; // 32MB
        let ram_name = c"/rustee_ram";
        let ram_fd = shm_open(
            ram_name,
            OFlag::O_CREAT | OFlag::O_RDWR,
            Mode::S_IRUSR | Mode::S_IWUSR,
        )
        .map_err(|e| {
            io::Error::new(ErrorKind::Other, format!("Failed to create RAM shm: {}", e))
        })?;

        ftruncate(&ram_fd, ram_size as i64).map_err(|e| {
            io::Error::new(ErrorKind::Other, format!("Failed to set RAM size: {}", e))
        })?;

        // Map RAM to fixed kernel segments (these are always mapped)
        map_fixed_region(
            base,
            0x80000000,
            ram_size,
            &ram_fd,
            0,
            PROT_READ | PROT_WRITE,
        )?;
        map_fixed_region(
            base,
            0xA0000000,
            ram_size,
            &ram_fd,
            0,
            PROT_READ | PROT_WRITE,
        )?;

        // Store ram_fd for TLB dynamic mapping
        bus.ram_fd = Some(ram_fd);
        shm_unlink(ram_name).map_err(|e| {
            io::Error::new(ErrorKind::Other, format!("Failed to unlink RAM shm: {}", e))
        })?;

        // Map BIOS (read-only)
        map_bios(bus, base)?;

        // Map other fixed regions
        map_iop_ram(base)?;
        map_scratchpad(base)?;
        map_vu_memory(base)?;

        debug!(
            "Hardware arena initialized: base={:?}, size={} bytes",
            base, size
        );
        Ok((base, size))
    }
}

unsafe fn map_fixed_region(
    base: *mut u8,
    virt_addr: u32,
    size: usize,
    fd: &std::os::fd::OwnedFd,
    offset: i64,
    prot: i32,
) -> io::Result<()> {
    let target = unsafe { base.add(virt_addr as usize) };

    let result = unsafe {
        mmap(
            target as *mut c_void,
            size,
            prot,
            MAP_SHARED | MAP_FIXED,
            fd.as_raw_fd(),
            offset,
        )
    };

    if result == libc::MAP_FAILED {
        return Err(io::Error::new(
            ErrorKind::Other,
            format!("Failed to map fixed region at 0x{:08X}", virt_addr),
        ));
    }

    Ok(())
}

unsafe fn map_bios(bus: &mut Bus, base: *mut u8) -> io::Result<()> {
    let bios_size = 0x400000; // 4MB
    let bios_name = c"/rustee_bios";
    let bios_fd = shm_open(
        bios_name,
        OFlag::O_CREAT | OFlag::O_RDWR,
        Mode::S_IRUSR | Mode::S_IWUSR,
    )
    .map_err(|e| {
        io::Error::new(
            ErrorKind::Other,
            format!("Failed to create BIOS shm: {}", e),
        )
    })?;

    ftruncate(&bios_fd, bios_size as i64)
        .map_err(|e| io::Error::new(ErrorKind::Other, format!("Failed to set BIOS size: {}", e)))?;

    // Copy BIOS data to shared memory
    let temp_map = unsafe {
        mmap(
            ptr::null_mut(),
            bios_size,
            PROT_READ | PROT_WRITE,
            MAP_SHARED,
            bios_fd.as_raw_fd(),
            0,
        )
    };

    if temp_map == libc::MAP_FAILED {
        return Err(io::Error::new(ErrorKind::Other, "Failed to map BIOS temp"));
    }

    unsafe {
        std::ptr::copy_nonoverlapping(
            bus.bios.bytes.as_ptr(),
            temp_map as *mut u8,
            bus.bios.bytes.len(),
        )
    };

    unsafe {
        munmap(temp_map, bios_size);
    };

    // Map BIOS to both kernel segments (read-only)
    unsafe { map_fixed_region(base, 0x1FC00000, bios_size, &bios_fd, 0, PROT_READ) }?;
    unsafe { map_fixed_region(base, 0x9FC00000, bios_size, &bios_fd, 0, PROT_READ) }?;
    unsafe { map_fixed_region(base, 0xBFC00000, bios_size, &bios_fd, 0, PROT_READ) }?;

    close(bios_fd)
        .map_err(|e| io::Error::new(ErrorKind::Other, format!("Failed to close BIOS fd: {}", e)))?;
    shm_unlink(bios_name).map_err(|e| {
        io::Error::new(
            ErrorKind::Other,
            format!("Failed to unlink BIOS shm: {}", e),
        )
    })?;

    Ok(())
}

unsafe fn map_iop_ram(base: *mut u8) -> io::Result<()> {
    let iop_size = 0x200000; // 2MB
    let iop_name = c"/rustee_iop";
    let iop_fd = shm_open(
        iop_name,
        OFlag::O_CREAT | OFlag::O_RDWR,
        Mode::S_IRUSR | Mode::S_IWUSR,
    )
    .map_err(|e| {
        io::Error::new(
            ErrorKind::Other,
            format!("Failed to create IOP RAM shm: {}", e),
        )
    })?;

    ftruncate(&iop_fd, iop_size as i64).map_err(|e| {
        io::Error::new(
            ErrorKind::Other,
            format!("Failed to set IOP RAM size: {}", e),
        )
    })?;

    unsafe {
        map_fixed_region(
            base,
            0x9C000000,
            iop_size,
            &iop_fd,
            0,
            PROT_READ | PROT_WRITE,
        )
    }?;
    unsafe {
        map_fixed_region(
            base,
            0xBC000000,
            iop_size,
            &iop_fd,
            0,
            PROT_READ | PROT_WRITE,
        )
    }?;

    close(iop_fd)
        .map_err(|e| io::Error::new(ErrorKind::Other, format!("Failed to close IOP fd: {}", e)))?;
    shm_unlink(iop_name).map_err(|e| {
        io::Error::new(ErrorKind::Other, format!("Failed to unlink IOP shm: {}", e))
    })?;

    Ok(())
}

unsafe fn map_scratchpad(base: *mut u8) -> io::Result<()> {
    let sp_size = 0x4000; // 16KB
    let sp_name = c"/rustee_scratchpad";
    let sp_fd = shm_open(
        sp_name,
        OFlag::O_CREAT | OFlag::O_RDWR,
        Mode::S_IRUSR | Mode::S_IWUSR,
    )
    .map_err(|e| {
        io::Error::new(
            ErrorKind::Other,
            format!("Failed to create scratchpad shm: {}", e),
        )
    })?;

    ftruncate(&sp_fd, sp_size as i64).map_err(|e| {
        io::Error::new(
            ErrorKind::Other,
            format!("Failed to set scratchpad size: {}", e),
        )
    })?;

    let sp_target = unsafe { base.add(0x70000000) };

    let result = unsafe {
        mmap(
            sp_target as *mut c_void,
            sp_size,
            PROT_READ | PROT_WRITE,
            MAP_SHARED | MAP_FIXED,
            sp_fd.as_raw_fd(),
            0,
        )
    };

    if result == libc::MAP_FAILED {
        return Err(io::Error::new(ErrorKind::Other, "Failed to map scratchpad"));
    }

    close(sp_fd).map_err(|e| {
        io::Error::new(
            ErrorKind::Other,
            format!("Failed to close scratchpad fd: {}", e),
        )
    })?;
    shm_unlink(sp_name).map_err(|e| {
        io::Error::new(
            ErrorKind::Other,
            format!("Failed to unlink scratchpad shm: {}", e),
        )
    })?;

    Ok(())
}

unsafe fn map_vu_memory(base: *mut u8) -> io::Result<()> {
    // VU0 Memory (8KB)
    let vu0_size = 0x8000;
    let vu0_target = unsafe { base.add(0x11000000) };

    let result = unsafe {
        mmap(
            vu0_target as *mut c_void,
            vu0_size,
            PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED,
            -1,
            0,
        )
    };

    if result == libc::MAP_FAILED {
        return Err(io::Error::new(ErrorKind::Other, "Failed to map VU0"));
    }

    // VU1 Memory (32KB)
    let vu1_size = 0x8000;
    let vu1_target = unsafe { base.add(0x11008000) };

    let result = unsafe {
        mmap(
            vu1_target as *mut c_void,
            vu1_size,
            PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED,
            -1,
            0,
        )
    };

    if result == libc::MAP_FAILED {
        return Err(io::Error::new(ErrorKind::Other, "Failed to map VU1"));
    }

    Ok(())
}

impl Tlb {
    pub fn install_hw_fastmem_mapping(&self, bus: &Bus, entry: &TlbEntry) {
        let page_size = mask_to_page_size(entry.mask) as usize;
        let va_start = (entry.vpn2 << 13) as usize;

        // Skip fixed kernel segments - they're always mapped
        if Self::is_fixed_region(va_start, page_size) {
            trace!(
                "Skipping TLB mapping for fixed region: va_start=0x{:08X}",
                va_start
            );
            return;
        }

        let ram_fd = bus.ram_fd.as_ref().expect("RAM file descriptor missing");

        // Map even page if valid
        if entry.v0 {
            let pa_start = (entry.pfn0 << 12) as usize;
            if pa_start <= 0x01FFFFFF {
                let prot = if entry.d0 {
                    PROT_READ | PROT_WRITE
                } else {
                    PROT_READ
                };

                unsafe {
                    let target = bus.hw_base.add(va_start);
                    let _ = mmap(
                        target as *mut c_void,
                        page_size,
                        prot,
                        MAP_SHARED | MAP_FIXED,
                        ram_fd.as_raw_fd(),
                        pa_start as i64,
                    );
                }
            }
        }

        // Map odd page if valid
        if entry.v1 {
            let va_start_odd = va_start + page_size;
            let pa_start_odd = (entry.pfn1 << 12) as usize;
            if pa_start_odd <= 0x01FFFFFF {
                let prot = if entry.d1 {
                    PROT_READ | PROT_WRITE
                } else {
                    PROT_READ
                };

                unsafe {
                    let target = bus.hw_base.add(va_start_odd);
                    let _ = mmap(
                        target as *mut c_void,
                        page_size,
                        prot,
                        MAP_SHARED | MAP_FIXED,
                        ram_fd.as_raw_fd(),
                        pa_start_odd as i64,
                    );
                }
            }
        }
    }

    pub fn clear_hw_fastmem_mapping(&self, bus: &Bus, entry: &TlbEntry) {
        let page_size = mask_to_page_size(entry.mask) as usize;
        let va_start = (entry.vpn2 << 13) as usize;

        // Skip fixed kernel segments
        if Self::is_fixed_region(va_start, page_size) {
            trace!(
                "Skipping TLB clear for fixed region: va_start=0x{:08X}",
                va_start
            );
            return;
        }

        trace!(
            "Clearing TLB: va_start=0x{:08X}, page_size={}",
            va_start, page_size
        );

        unsafe {
            // Unmap even page
            let target = bus.hw_base.add(va_start);
            let _ = munmap(target as *mut c_void, page_size);

            // Unmap odd page
            let target_odd = bus.hw_base.add(va_start + page_size);
            let _ = munmap(target_odd as *mut c_void, page_size);
        }
    }

    fn is_fixed_region(va_start: usize, page_size: usize) -> bool {
        let va_end = va_start + page_size * 2; // Account for even and odd pages
        // KSEG0/KSEG1 RAM mappings
        (va_start < 0x82000000 && va_end > 0x80000000) ||
        (va_start < 0xA2000000 && va_end > 0xA0000000) ||
        // BIOS mappings
        (va_start < 0xA0000000 && va_end > 0x9FC00000) ||
        (va_start < 0xC0000000 && va_end > 0xBFC00000) ||
        (va_start < 0x20000000 && va_end > 0x1FC00000) ||
        // IOP RAM
        (va_start < 0x9C200000 && va_end > 0x9C000000) ||
        (va_start < 0xBC200000 && va_end > 0xBC000000) ||
        // VU memory
        (va_start < 0x11010000 && va_end > 0x11000000) ||
        (va_start < 0x70004000 && va_end > 0x70000000)
    }
}

impl Bus {
    #[inline]
    pub fn hw_read8(&mut self, addr: u32) -> u8 {
        unsafe {
            let host_ptr = self.hw_base.add(addr as usize) as *const u8;
            *host_ptr
        }
    }

    #[inline]
    pub fn hw_read16(&mut self, addr: u32) -> u16 {
        unsafe {
            let host_ptr = self.hw_base.add(addr as usize) as *const u16;
            *host_ptr
        }
    }

    #[inline]
    pub fn hw_read32(&mut self, addr: u32) -> u32 {
        unsafe {
            let host_ptr = self.hw_base.add(addr as usize) as *const u32;
            *host_ptr
        }
    }

    #[inline]
    pub fn hw_read64(&mut self, addr: u32) -> u64 {
        unsafe {
            let host_ptr = self.hw_base.add(addr as usize) as *const u64;
            *host_ptr
        }
    }

    #[inline]
    pub fn hw_read128(&mut self, addr: u32) -> u128 {
        unsafe {
            let host_ptr = self.hw_base.add(addr as usize) as *const u128;
            *host_ptr
        }
    }

    #[inline]
    pub fn hw_write8(&mut self, addr: u32, val: u8) {
        unsafe {
            let host_ptr = self.hw_base.add(addr as usize) as *mut u8;
            *host_ptr = val;
        }
    }

    #[inline]
    pub fn hw_write16(&mut self, addr: u32, val: u16) {
        unsafe {
            let host_ptr = self.hw_base.add(addr as usize) as *mut u16;
            *host_ptr = val;
        }
    }

    #[inline]
    pub fn hw_write32(&mut self, addr: u32, val: u32) {
        unsafe {
            let host_ptr = self.hw_base.add(addr as usize) as *mut u32;
            *host_ptr = val;
        }
    }

    #[inline]
    pub fn hw_write64(&mut self, addr: u32, val: u64) {
        unsafe {
            let host_ptr = self.hw_base.add(addr as usize) as *mut u64;
            *host_ptr = val;
        }
    }

    #[inline]
    pub fn hw_write128(&mut self, addr: u32, val: u128) {
        unsafe {
            let host_ptr = self.hw_base.add(addr as usize) as *mut u128;
            *host_ptr = val;
        }
    }
}
