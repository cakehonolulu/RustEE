use super::tlb::{Tlb, TlbEntry, mask_to_page_size};
use super::{Bus, HW_BASE};
use crate::bus::HW_LENGTH;
use backtrace::Backtrace;

#[cfg(unix)]
use nix::fcntl::{OFlag, open};
#[cfg(unix)]
use nix::sys::mman::{shm_open, shm_unlink};
#[cfg(unix)]
use nix::sys::stat::Mode;
#[cfg(unix)]
use nix::unistd::{close, ftruncate};
#[cfg(unix)]
use std::os::fd::AsRawFd;

use std::io::{self, ErrorKind};
use std::os::raw::c_void;
use std::process::exit;
use std::ptr;
use std::sync::atomic::Ordering;
use tracing::{debug, error, trace};

#[cfg(unix)]
use libc::{
    MAP_ANONYMOUS, MAP_FIXED, MAP_PRIVATE, MAP_SHARED, PROT_NONE, PROT_READ, PROT_WRITE, mmap,
    munmap,
};

#[cfg(windows)]
use winapi::um::handleapi::CloseHandle;
#[cfg(windows)]
use winapi::um::memoryapi::{CreateFileMappingW, MapViewOfFile, MapViewOfFileEx, UnmapViewOfFile, VirtualAlloc};
#[cfg(windows)]
use winapi::um::memoryapi::{FILE_MAP_READ, FILE_MAP_WRITE};
#[cfg(windows)]
use winapi::um::winnt::{
    HANDLE, MEM_COMMIT, MEM_RESERVE, PAGE_NOACCESS, PAGE_READONLY, PAGE_READWRITE,
};
#[cfg(windows)]
use winapi::shared::minwindef::LPVOID;
#[cfg(windows)]
use winapi::um::handleapi::INVALID_HANDLE_VALUE;

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

#[cfg(unix)]
pub unsafe fn init_hardware_arena(bus: &mut Bus) -> io::Result<(*mut u8, usize)> {
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

#[cfg(windows)]
pub unsafe fn init_hardware_arena(bus: &mut Bus) -> io::Result<(*mut u8, usize)> {
    let size = 1usize << 32; // 4GB

    // Try to reserve 4GB of virtual address space at a specific base address
    // Use a fixed address in the lower 32-bit range to avoid conflicts
    let desired_base = 0x10000000usize as LPVOID; // Start at 256MB
    
    let base = VirtualAlloc(desired_base, size, MEM_RESERVE, PAGE_NOACCESS);
    if base.is_null() {
        // If we can't get the desired address, try anywhere
        let base = VirtualAlloc(ptr::null_mut(), size, MEM_RESERVE, PAGE_NOACCESS);
        if base.is_null() {
            return Err(io::Error::new(ErrorKind::Other, "Failed to reserve address space"));
        }
    }

    let base = base as *mut u8;
    debug!("Reserved base address: {:?}", base);

    // Create file mapping for RAM (32MB)
    let ram_size = 0x2000000; // 32MB
    let ram_mapping = CreateFileMappingW(
        INVALID_HANDLE_VALUE,
        ptr::null_mut(),
        PAGE_READWRITE,
        0,
        ram_size as u32,
        ptr::null(),
    );
    if ram_mapping.is_null() {
        return Err(io::Error::new(ErrorKind::Other, "Failed to create RAM file mapping"));
    }
    debug!("RAM mapping handle created: {:?}", ram_mapping);

    // Map RAM to fixed kernel segments
    map_fixed_region_windows(base, 0x80000000, ram_size, ram_mapping, 0, FILE_MAP_READ | FILE_MAP_WRITE)?;
    map_fixed_region_windows(base, 0xA0000000, ram_size, ram_mapping, 0, FILE_MAP_READ | FILE_MAP_WRITE)?;

    // Store ram_mapping for TLB dynamic mapping
    bus.ram_mapping = Some(ram_mapping as *mut std::ffi::c_void);

    // Map BIOS
    map_bios_windows(bus, base)?;

    // Map other fixed regions
    map_iop_ram_windows(base)?;
    map_scratchpad_windows(base)?;
    map_vu_memory_windows(base)?;

    Ok((base, size))
}

#[cfg(unix)]
unsafe fn map_fixed_region(
    base: *mut u8,
    virt_addr: u32,
    size: usize,
    fd: &std::os::fd::OwnedFd,
    offset: i64,
    prot: i32,
) -> io::Result<()> {
    let target = base.add(virt_addr as usize);

    let result = mmap(
        target as *mut c_void,
        size,
        prot,
        MAP_SHARED | MAP_FIXED,
        fd.as_raw_fd(),
        offset,
    );

    if result == libc::MAP_FAILED {
        return Err(io::Error::new(
            ErrorKind::Other,
            format!("Failed to map fixed region at 0x{:08X}", virt_addr),
        ));
    }

    Ok(())
}

#[cfg(windows)]
use winapi::um::errhandlingapi::GetLastError;

#[cfg(windows)]
unsafe fn map_fixed_region_windows(
    base: *mut u8,
    virt_addr: u32,
    size: usize,
    mapping: HANDLE,
    offset: u64,
    access: u32,
) -> io::Result<()> {
    // Calculate the target address within our reserved space
    // We need to map PS2 addresses relative to our base
    let ps2_base = 0u32; // PS2 starts at 0x00000000
    let relative_addr = virt_addr.wrapping_sub(ps2_base) as usize;
    
    // Ensure we don't go outside our reserved space
    if relative_addr >= (1usize << 32) {
        return Err(io::Error::new(
            ErrorKind::Other,
            format!("Virtual address 0x{:08X} outside reserved space", virt_addr),
        ));
    }
    
    let target = base.add(relative_addr) as LPVOID;
    
    debug!("Mapping PS2 addr 0x{:08X} to host addr {:?}", virt_addr, target);
    
    let view = MapViewOfFileEx(
        mapping,
        access,
        (offset >> 32) as u32,
        (offset & 0xFFFFFFFF) as u32,
        size,
        target,
    );
    
    if view.is_null() {
        let error_code = GetLastError();
        return Err(io::Error::new(
            ErrorKind::Other,
            format!("Failed to map fixed region at 0x{:08X} (target: {:?}), error code: {}", 
                   virt_addr, target, error_code),
        ));
    }
    
    debug!("Successfully mapped 0x{:08X} to {:?}", virt_addr, view);
    Ok(())
}

#[cfg(unix)]
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
    let temp_map = mmap(
        ptr::null_mut(),
        bios_size,
        PROT_READ | PROT_WRITE,
        MAP_SHARED,
        bios_fd.as_raw_fd(),
        0,
    );

    if temp_map == libc::MAP_FAILED {
        return Err(io::Error::new(ErrorKind::Other, "Failed to map BIOS temp"));
    }

    std::ptr::copy_nonoverlapping(
        bus.bios.bytes.as_ptr(),
        temp_map as *mut u8,
        bus.bios.bytes.len(),
    );

    munmap(temp_map, bios_size);

    // Map BIOS to both kernel segments (read-only)
    map_fixed_region(base, 0x1FC00000, bios_size, &bios_fd, 0, PROT_READ)?;
    map_fixed_region(base, 0x9FC00000, bios_size, &bios_fd, 0, PROT_READ)?;
    map_fixed_region(base, 0xBFC00000, bios_size, &bios_fd, 0, PROT_READ)?;

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

#[cfg(windows)]
unsafe fn map_bios_windows(bus: &mut Bus, base: *mut u8) -> io::Result<()> {
    let bios_size = 0x400000; // 4MB
    
    // Create a single read-write mapping for initial setup
    let bios_mapping = CreateFileMappingW(
        INVALID_HANDLE_VALUE,
        ptr::null_mut(),
        PAGE_READWRITE,
        0,
        bios_size as u32,
        ptr::null(),
    );
    if bios_mapping.is_null() {
        return Err(io::Error::new(ErrorKind::Other, "Failed to create BIOS file mapping"));
    }

    // Map a temporary view to write BIOS data
    let temp_view = MapViewOfFile(bios_mapping, FILE_MAP_WRITE, 0, 0, bios_size);
    if temp_view.is_null() {
        CloseHandle(bios_mapping);
        return Err(io::Error::new(ErrorKind::Other, "Failed to map BIOS temp view"));
    }

    // Copy BIOS data to the mapping
    std::ptr::copy_nonoverlapping(
        bus.bios.bytes.as_ptr(),
        temp_view as *mut u8,
        bus.bios.bytes.len(),
    );

    // Unmap the temporary view
    UnmapViewOfFile(temp_view);

    // Now map the BIOS to the fixed PS2 addresses with read-only access
    // We'll use the same mapping but with read-only access for the final mappings
    map_fixed_region_windows(base, 0x1FC00000, bios_size, bios_mapping, 0, FILE_MAP_READ)?;
    map_fixed_region_windows(base, 0x9FC00000, bios_size, bios_mapping, 0, FILE_MAP_READ)?;
    map_fixed_region_windows(base, 0xBFC00000, bios_size, bios_mapping, 0, FILE_MAP_READ)?;

    // Don't close the handle yet - the mappings are still using it
    // The handle will be cleaned up when the process exits
    // If you need explicit cleanup, store the handle in the Bus struct
    
    Ok(())
}

#[cfg(unix)]
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

    map_fixed_region(
        base,
        0x9C000000,
        iop_size,
        &iop_fd,
        0,
        PROT_READ | PROT_WRITE,
    )?;
    map_fixed_region(
        base,
        0xBC000000,
        iop_size,
        &iop_fd,
        0,
        PROT_READ | PROT_WRITE,
    )?;

    close(iop_fd)
        .map_err(|e| io::Error::new(ErrorKind::Other, format!("Failed to close IOP fd: {}", e)))?;
    shm_unlink(iop_name).map_err(|e| {
        io::Error::new(ErrorKind::Other, format!("Failed to unlink IOP shm: {}", e))
    })?;

    Ok(())
}

#[cfg(windows)]
unsafe fn map_iop_ram_windows(base: *mut u8) -> io::Result<()> {
    let iop_size = 0x200000; // 2MB
    let iop_mapping = CreateFileMappingW(
        INVALID_HANDLE_VALUE,
        ptr::null_mut(),
        PAGE_READWRITE,
        0,
        iop_size as u32,
        ptr::null(),
    );
    if iop_mapping.is_null() {
        return Err(io::Error::new(ErrorKind::Other, "Failed to create IOP RAM file mapping"));
    }

    map_fixed_region_windows(base, 0x9C000000, iop_size, iop_mapping, 0, FILE_MAP_READ | FILE_MAP_WRITE)?;
    map_fixed_region_windows(base, 0xBC000000, iop_size, iop_mapping, 0, FILE_MAP_READ | FILE_MAP_WRITE)?;

    CloseHandle(iop_mapping);

    Ok(())
}

#[cfg(windows)]
unsafe fn map_scratchpad_windows(base: *mut u8) -> io::Result<()> {
    let sp_size = 0x4000; // 16KB
    
    // Create a file mapping for scratchpad memory
    let sp_mapping = CreateFileMappingW(
        INVALID_HANDLE_VALUE,
        ptr::null_mut(),
        PAGE_READWRITE,
        0,
        sp_size as u32,
        ptr::null(),
    );
    if sp_mapping.is_null() {
        return Err(io::Error::new(ErrorKind::Other, "Failed to create scratchpad file mapping"));
    }
    
    // Map it to the PS2 scratchpad address using our existing helper function
    match map_fixed_region_windows(base, 0x70000000, sp_size, sp_mapping, 0, FILE_MAP_READ | FILE_MAP_WRITE) {
        Ok(_) => {
            // Don't close the handle yet - the mapping is still using it
            // You might want to store this handle in the Bus struct for cleanup
            Ok(())
        }
        Err(e) => {
            CloseHandle(sp_mapping);
            Err(e)
        }
    }
}

#[cfg(unix)]
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

    let sp_target = base.add(0x70000000);

    let result = mmap(
        sp_target as *mut c_void,
        sp_size,
        PROT_READ | PROT_WRITE,
        MAP_SHARED | MAP_FIXED,
        sp_fd.as_raw_fd(),
        0,
    );

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

#[cfg(unix)]
unsafe fn map_vu_memory(base: *mut u8) -> io::Result<()> {
    // VU0 Memory (8KB) - Fixed typo: was vu0_when_size, should be vu0_size
    let vu0_size = 0x8000;
    let vu0_target = base.add(0x11000000);

    let result = mmap(
        vu0_target as *mut c_void,
        vu0_size,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED,
        -1,
        0,
    );

    if result == libc::MAP_FAILED {
        return Err(io::Error::new(ErrorKind::Other, "Failed to map VU0"));
    }

    // VU1 Memory (32KB)
    let vu1_size = 0x8000;
    let vu1_target = base.add(0x11008000);

    let result = mmap(
        vu1_target as *mut c_void,
        vu1_size,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED,
        -1,
        0,
    );

    if result == libc::MAP_FAILED {
        return Err(io::Error::new(ErrorKind::Other, "Failed to map VU1"));
    }

    Ok(())
}

#[cfg(windows)]
unsafe fn map_vu_memory_windows(base: *mut u8) -> io::Result<()> {
    // Create a single larger mapping for both VU0 and VU1 memory
    // VU0: 32KB at 0x11000000
    // VU1: 32KB at 0x11008000
    // Total: 64KB to cover both regions
    let total_vu_size = 0x10000; // 64KB
    let vu_mapping = CreateFileMappingW(
        INVALID_HANDLE_VALUE,
        ptr::null_mut(),
        PAGE_READWRITE,
        0,
        total_vu_size as u32,
        ptr::null(),
    );
    if vu_mapping.is_null() {
        return Err(io::Error::new(ErrorKind::Other, "Failed to create VU memory file mapping"));
    }

    // Map the entire VU region starting at VU0 address
    if let Err(e) = map_fixed_region_windows(base, 0x11000000, total_vu_size, vu_mapping, 0, FILE_MAP_READ | FILE_MAP_WRITE) {
        CloseHandle(vu_mapping);
        return Err(e);
    }

    debug!("Successfully mapped VU memory: VU0 at 0x11000000, VU1 at 0x11008000, total size: {}KB", total_vu_size / 1024);

    // Don't close the handle yet - the mapping is still using it
    // You might want to store this handle in the Bus struct for cleanup
    
    Ok(())
}

impl Tlb {
    #[cfg(unix)]
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
                    let result = mmap(
                        target as *mut c_void,
                        page_size,
                        prot,
                        MAP_SHARED | MAP_FIXED,
                        ram_fd.as_raw_fd(),
                        pa_start as i64,
                    );
                    if result == libc::MAP_FAILED {
                        error!("Failed to map TLB even page at 0x{:08X}", va_start);
                    }
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
                    let result = mmap(
                        target as *mut c_void,
                        page_size,
                        prot,
                        MAP_SHARED | MAP_FIXED,
                        ram_fd.as_raw_fd(),
                        pa_start_odd as i64,
                    );
                    if result == libc::MAP_FAILED {
                        error!("Failed to map TLB odd page at 0x{:08X}", va_start_odd);
                    }
                }
            }
        }
    }

    #[cfg(windows)]
    pub fn install_hw_fastmem_mapping(&self, bus: &Bus, entry: &TlbEntry) {
        let page_size = mask_to_page_size(entry.mask) as usize;
        let va_start = (entry.vpn2 << 13) as usize;

        if Self::is_fixed_region(va_start, page_size) {
            trace!("Skipping TLB mapping for fixed region: va_start=0x{:08X}", va_start);
            return;
        }

        let ram_mapping = bus.ram_mapping.expect("RAM file mapping missing") as winapi::um::winnt::HANDLE;

        // Map even page if valid
        if entry.v0 {
            let pa_start = (entry.pfn0 << 12) as usize;
            if pa_start <= 0x01FFFFFF {
                let access = if entry.d0 { FILE_MAP_READ | FILE_MAP_WRITE } else { FILE_MAP_READ };
                unsafe {
                    let target = bus.hw_base.add(va_start) as LPVOID;
                    let view = MapViewOfFileEx(
                        ram_mapping,
                        access,
                        (pa_start as u64 >> 32) as u32,
                        (pa_start as u64 & 0xFFFFFFFF) as u32,
                        page_size,
                        target,
                    );
                    if view.is_null() {
                        error!("Failed to map TLB even page at 0x{:08X}", va_start);
                    }
                }
            }
        }

        // Map odd page if valid
        if entry.v1 {
            let va_start_odd = va_start + page_size;
            let pa_start_odd = (entry.pfn1 << 12) as usize;
            if pa_start_odd <= 0x01FFFFFF {
                let access = if entry.d1 { FILE_MAP_READ | FILE_MAP_WRITE } else { FILE_MAP_READ };
                unsafe {
                    let target = bus.hw_base.add(va_start_odd) as LPVOID;
                    let view = MapViewOfFileEx(
                        ram_mapping,
                        access,
                        (pa_start_odd as u64 >> 32) as u32,
                        (pa_start_odd as u64 & 0xFFFFFFFF) as u32,
                        page_size,
                        target,
                    );
                    if view.is_null() {
                        error!("Failed to map TLB odd page at 0x{:08X}", va_start_odd);
                    }
                }
            }
        }
    }

    #[cfg(unix)]
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

    #[cfg(windows)]
    pub fn clear_hw_fastmem_mapping(&self, bus: &Bus, entry: &TlbEntry) {
        let page_size = mask_to_page_size(entry.mask) as usize;
        let va_start = (entry.vpn2 << 13) as usize;

        if Self::is_fixed_region(va_start, page_size) {
            trace!("Skipping TLB clear for fixed region: va_start=0x{:08X}", va_start);
            return;
        }

        unsafe {
            // Unmap even page
            let target = bus.hw_base.add(va_start) as LPVOID;
            UnmapViewOfFile(target);

            // Unmap odd page
            let target_odd = bus.hw_base.add(va_start + page_size) as LPVOID;
            UnmapViewOfFile(target_odd);
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