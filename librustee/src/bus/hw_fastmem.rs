use super::tlb::{Tlb, TlbEntry, mask_to_page_size};
use super::{Bus, HW_BASE};
use crate::bus::HW_LENGTH;
use std::ffi::OsStr;

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
use std::ptr;
use std::sync::atomic::Ordering;
use tracing::{debug, error, trace};

#[cfg(unix)]
use libc::{
    MAP_ANONYMOUS, MAP_FIXED, MAP_PRIVATE, MAP_SHARED, PROT_NONE, PROT_READ, PROT_WRITE, mmap,
    munmap,
};

#[cfg(windows)]
use std::os::windows::ffi::OsStrExt;
#[cfg(windows)]
use windows_sys::Win32::Foundation::{HANDLE, INVALID_HANDLE_VALUE};
#[cfg(windows)]
use windows_sys::Win32::System::Memory::{
    CreateFileMapping2, FILE_MAP_READ, FILE_MAP_WRITE, MEM_PRESERVE_PLACEHOLDER, MEM_RELEASE,
    MEM_REPLACE_PLACEHOLDER, MEM_RESERVE, MEM_RESERVE_PLACEHOLDER, MEMORY_MAPPED_VIEW_ADDRESS,
    MapViewOfFile3, PAGE_NOACCESS, PAGE_READONLY, PAGE_READWRITE, UnmapViewOfFile2, VirtualAlloc2,
    VirtualFree,
};
#[cfg(windows)]
use windows_sys::Win32::System::Threading::GetCurrentProcess;

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

    let ram_size = 0x2000000;
    let ram_name = c"/rustee_ram";
    let ram_fd = shm_open(
        ram_name,
        OFlag::O_CREAT | OFlag::O_RDWR,
        Mode::S_IRUSR | Mode::S_IWUSR,
    )
    .map_err(|e| io::Error::new(ErrorKind::Other, format!("Failed to create RAM shm: {}", e)))?;

    ftruncate(&ram_fd, ram_size as i64)
        .map_err(|e| io::Error::new(ErrorKind::Other, format!("Failed to set RAM size: {}", e)))?;

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

    bus.ram_fd = Some(ram_fd);
    shm_unlink(ram_name).map_err(|e| {
        io::Error::new(ErrorKind::Other, format!("Failed to unlink RAM shm: {}", e))
    })?;

    map_bios(bus, base)?;

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
    let base = unsafe {
        VirtualAlloc2(
            ptr::null_mut(),
            ptr::null_mut(),
            size,
            MEM_RESERVE | MEM_RESERVE_PLACEHOLDER,
            PAGE_NOACCESS,
            ptr::null_mut(),
            0,
        )
    };
    if base.is_null() {
        return Err(io::Error::new(
            ErrorKind::Other,
            "Failed to reserve address space",
        ));
    }
    let base = base as *mut u8;
    debug!("Reserved base address: {:p}", base);

    let ram_size = 0x0200_0000;
    let ram_section = unsafe {
        CreateFileMapping2(
            INVALID_HANDLE_VALUE,
            ptr::null_mut(),
            FILE_MAP_READ | FILE_MAP_WRITE,
            PAGE_READWRITE,
            0,
            ram_size as u64,
            OsStr::new("RustEE RAM")
                .encode_wide()
                .chain(Some(0))
                .collect::<Vec<u16>>()
                .as_ptr(),
            ptr::null_mut(),
            0,
        )
    };
    if ram_section == ptr::null_mut() {
        return Err(io::Error::new(
            ErrorKind::Other,
            "Failed to create RAM section",
        ));
    }
    debug!("RAM section handle: {:?}", ram_section);

    let addr1 = unsafe { base.add(0x8000_0000) } as *mut c_void;
    let addr2 = unsafe { base.add(0xA000_0000) } as *mut c_void;
    for &addr in &[addr1, addr2] {
        let res = unsafe { VirtualFree(addr, ram_size, MEM_RELEASE | MEM_PRESERVE_PLACEHOLDER) };
        if res == 0 {
            return Err(io::Error::new(
                ErrorKind::Other,
                "Failed to split placeholder",
            ));
        }
    }

    for &offset in &[0x8000_0000usize, 0xA000_0000usize] {
        let view = unsafe {
            MapViewOfFile3(
                ram_section,
                GetCurrentProcess(),
                base.add(offset) as *const c_void,
                0,
                ram_size,
                MEM_REPLACE_PLACEHOLDER,
                PAGE_READWRITE,
                ptr::null_mut(),
                0,
            )
        };
        if view.Value == ptr::null_mut() {
            return Err(io::Error::new(
                ErrorKind::Other,
                format!("Failed to map RAM view at offset {:#x}", offset),
            ));
        }
        debug!("Mapped RAM at {:p}", view.Value);
    }

    bus.ram_mapping = Some(ram_section as *mut std::ffi::c_void);

    let iop_size: usize = 0x0020_0000;

    let name_iop: Vec<u16> = OsStr::new("RustEE IOP RAM")
        .encode_wide()
        .chain(Some(0))
        .collect();
    let iop_section = unsafe {
        CreateFileMapping2(
            INVALID_HANDLE_VALUE,
            ptr::null_mut(),
            FILE_MAP_READ | FILE_MAP_WRITE,
            PAGE_READWRITE,
            0,
            iop_size as u64,
            name_iop.as_ptr(),
            ptr::null_mut(),
            0,
        )
    };
    if iop_section == ptr::null_mut() {
        return Err(io::Error::new(
            ErrorKind::Other,
            "Failed to create IOP RAM section",
        ));
    }

    for &offset in &[0x9C00_0000usize, 0xBC00_0000usize] {
        let addr = unsafe { base.add(offset) } as *mut c_void;
        let ok = unsafe { VirtualFree(addr, iop_size, MEM_RELEASE | MEM_PRESERVE_PLACEHOLDER) };
        if ok == 0 {
            return Err(io::Error::new(
                ErrorKind::Other,
                "Failed to split IOP placeholder",
            ));
        }
        let view = unsafe {
            MapViewOfFile3(
                iop_section,
                GetCurrentProcess(),
                base.add(offset) as *const c_void,
                0,
                iop_size,
                MEM_REPLACE_PLACEHOLDER,
                PAGE_READWRITE,
                ptr::null_mut(),
                0,
            )
        };
        if view.Value == ptr::null_mut() {
            return Err(io::Error::new(
                ErrorKind::Other,
                format!("Failed to map IOP RAM at offset {:#x}", offset),
            ));
        }
        debug!("Mapped IOP RAM at {:p}", view.Value);
    }

    let sp_total: usize = 0x4000;
    let name_sp: Vec<u16> = OsStr::new("RustEE Scratchpad")
        .encode_wide()
        .chain(Some(0))
        .collect();
    let sp_section = unsafe {
        CreateFileMapping2(
            INVALID_HANDLE_VALUE,
            ptr::null_mut(),
            FILE_MAP_READ | FILE_MAP_WRITE,
            PAGE_READWRITE,
            0,
            sp_total as u64,
            name_sp.as_ptr(),
            ptr::null_mut(),
            0,
        )
    };
    if sp_section == ptr::null_mut() {
        return Err(io::Error::new(
            ErrorKind::Other,
            "Failed to create scratchpad section",
        ));
    }
    let sp_offset = 0x7000_0000usize;
    let sp_addr = unsafe { base.add(sp_offset) } as *mut c_void;
    let ok = unsafe { VirtualFree(sp_addr, sp_total, MEM_RELEASE | MEM_PRESERVE_PLACEHOLDER) };
    if ok == 0 {
        return Err(io::Error::new(
            ErrorKind::Other,
            "Failed to split scratchpad placeholder",
        ));
    }
    let sp_view = unsafe {
        MapViewOfFile3(
            sp_section,
            GetCurrentProcess(),
            base.add(sp_offset) as *const c_void,
            0,
            sp_total,
            MEM_REPLACE_PLACEHOLDER,
            PAGE_READWRITE,
            ptr::null_mut(),
            0,
        )
    };
    if sp_view.Value == ptr::null_mut() {
        return Err(io::Error::new(ErrorKind::Other, "Failed to map scratchpad"));
    }
    debug!(
        "Mapped scratchpad at {:p} (using first 16 KiB)",
        sp_view.Value
    );

    let vu_total: usize = 0x1_0000;
    let vu_slice: usize = 0x8_000;
    let name_vu: Vec<u16> = OsStr::new("RustEE VU")
        .encode_wide()
        .chain(Some(0))
        .collect();

    let vu_section = unsafe {
        CreateFileMapping2(
            INVALID_HANDLE_VALUE,
            ptr::null_mut(),
            FILE_MAP_READ | FILE_MAP_WRITE,
            PAGE_READWRITE,
            0,
            vu_total as u64,
            name_vu.as_ptr(),
            ptr::null_mut(),
            0,
        )
    };
    if vu_section == ptr::null_mut() {
        return Err(io::Error::new(
            ErrorKind::Other,
            "Failed to create VU section",
        ));
    }

    let vu_offsets = [0x1100_0000usize, 0x1100_8000usize];
    for &offset in &vu_offsets {
        let addr = unsafe { base.add(offset) } as *mut c_void;
        let ok = unsafe { VirtualFree(addr, vu_slice, MEM_RELEASE | MEM_PRESERVE_PLACEHOLDER) };
        if ok == 0 {
            return Err(io::Error::new(
                ErrorKind::Other,
                format!("Failed to split VU placeholder at {:#x}", offset),
            ));
        }
    }

    for &offset in &vu_offsets {
        let view = unsafe {
            MapViewOfFile3(
                vu_section,
                GetCurrentProcess(),
                base.add(offset) as *const c_void,
                0,
                vu_slice,
                MEM_REPLACE_PLACEHOLDER,
                PAGE_READWRITE,
                ptr::null_mut(),
                0,
            )
        };
        if view.Value == ptr::null_mut() {
            return Err(io::Error::new(
                ErrorKind::Other,
                format!("Failed to map VU view at offset {:#x}", offset),
            ));
        }
        debug!("Mapped VU at {:p}", view.Value);
    }

    let bios_size = bus.bios.bytes.len();
    assert!(bios_size > 0, "BIOS image must be nonempty");

    let name_bios: Vec<u16> = OsStr::new("RustEE BIOS")
        .encode_wide()
        .chain(Some(0))
        .collect();

    let bios_section = unsafe {
        CreateFileMapping2(
            INVALID_HANDLE_VALUE,
            ptr::null_mut(),
            FILE_MAP_READ | FILE_MAP_WRITE,
            PAGE_READWRITE,
            0,
            bios_size as u64,
            name_bios.as_ptr(),
            ptr::null_mut(),
            0,
        )
    };
    if bios_section == ptr::null_mut() {
        return Err(io::Error::new(
            ErrorKind::Other,
            "Failed to create BIOS section",
        ));
    }
    debug!("BIOS section handle: {:?}", bios_section);

    let bios_offsets = [0x1FC0_0000usize, 0x9FC0_0000usize, 0xBFC0_0000usize];
    for &off in &bios_offsets {
        let addr = unsafe { base.add(off) } as *mut c_void;
        let ok = unsafe { VirtualFree(addr, bios_size, MEM_RELEASE | MEM_PRESERVE_PLACEHOLDER) };
        if ok == 0 {
            return Err(io::Error::new(
                ErrorKind::Other,
                format!("Failed to split BIOS placeholder at {:#x}", off),
            ));
        }
    }

    for (i, &off) in bios_offsets.iter().enumerate() {
        let view = unsafe {
            MapViewOfFile3(
                bios_section,
                GetCurrentProcess(),
                base.add(off) as *const c_void,
                0,
                bios_size,
                MEM_REPLACE_PLACEHOLDER,
                PAGE_READWRITE,
                ptr::null_mut(),
                0,
            )
        };
        if view.Value.is_null() {
            return Err(io::Error::new(
                ErrorKind::Other,
                format!("Failed to map BIOS view as RW at {:#x}", off),
            ));
        }
        let ptr = view.Value as *mut u8;
        debug!("Mapped BIOS as RW at {:p}", ptr);

        if i == 0 {
            unsafe {
                std::ptr::copy_nonoverlapping(bus.bios.bytes.as_ptr(), ptr, bios_size);
            }
            debug!("Copied BIOS data into mapping at {:#x}", off);
        }

        // Unmap the RW mapping
        let view_addr = MEMORY_MAPPED_VIEW_ADDRESS {
            Value: ptr as *mut c_void,
        };
        let unmap_result =
            unsafe { UnmapViewOfFile2(GetCurrentProcess(), view_addr, MEM_PRESERVE_PLACEHOLDER) };
        if unmap_result == 0 {
            return Err(io::Error::new(
                ErrorKind::Other,
                format!("Failed to unmap RW BIOS view at {:#x}", off),
            ));
        }

        debug!("Unmapped RW BIOS view at {:p}", ptr);
    }

    for (i, &off) in bios_offsets.iter().enumerate() {
        let view = unsafe {
            MapViewOfFile3(
                bios_section,
                GetCurrentProcess(),
                base.add(off) as *const c_void,
                0,
                bios_size,
                MEM_REPLACE_PLACEHOLDER,
                PAGE_READONLY,
                ptr::null_mut(),
                0,
            )
        };
        if view.Value.is_null() {
            return Err(io::Error::new(
                ErrorKind::Other,
                format!("Failed to remap BIOS view as RO at {:#x}", off),
            ));
        }
        let ptr = view.Value as *mut u8;
        debug!("Re-mapped BIOS as RO at {:p}", ptr);
    }

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

#[cfg(unix)]
unsafe fn map_bios(bus: &mut Bus, base: *mut u8) -> io::Result<()> {
    let bios_size = 0x400000;
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

#[cfg(unix)]
unsafe fn map_iop_ram(base: *mut u8) -> io::Result<()> {
    let iop_size = 0x200000;
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

#[cfg(unix)]
unsafe fn map_scratchpad(base: *mut u8) -> io::Result<()> {
    let sp_size = 0x4000;
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

impl Tlb {
    #[cfg(unix)]
    pub fn install_hw_fastmem_mapping(&self, bus: &Bus, entry: &TlbEntry) {
        let page_size = mask_to_page_size(entry.mask) as usize;
        let va_start = (entry.vpn2 << 13) as usize;

        if Self::is_fixed_region(va_start, page_size) {
            trace!(
                "Skipping TLB mapping for fixed region: va_start=0x{:08X}",
                va_start
            );
            return;
        }

        let ram_fd = bus.ram_fd.as_ref().expect("RAM file descriptor missing");

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

        // Skip fixed regions
        if Self::is_fixed_region(va_start, page_size) {
            return;
        }

        let ram_size = 0x2000000;
        let ram_section = bus.ram_mapping.expect("RAM section missing") as HANDLE;
        let proc = unsafe { GetCurrentProcess() };

        unsafe {
            for &(valid, pfn, d_bit, is_odd) in &[
                (entry.v0, entry.pfn0, entry.d0, false),
                (entry.v1, entry.pfn1, entry.d1, true),
            ] {
                if !valid {
                    continue;
                }
                let pa = (pfn << 12) as usize;
                if pa >= bus.hw_size || pa >= ram_size {
                    continue;
                }

                let va = va_start + if is_odd { page_size } else { 0 };
                let target = bus.hw_base.add(va);

                let _ = VirtualFree(
                    target as *mut c_void,
                    page_size,
                    MEM_RELEASE | MEM_PRESERVE_PLACEHOLDER,
                );

                let view = MapViewOfFile3(
                    ram_section,
                    proc,
                    target as *const c_void,
                    pa as u64,
                    page_size,
                    MEM_REPLACE_PLACEHOLDER,
                    if d_bit { PAGE_READWRITE } else { PAGE_READONLY },
                    ptr::null_mut(),
                    0,
                );
                if view.Value.is_null() {
                    error!("Failed to map fastmem page at VA=0x{:X}", va);
                    continue;
                }
            }
        }
    }

    #[cfg(unix)]
    pub fn clear_hw_fastmem_mapping(&self, bus: &Bus, entry: &TlbEntry) {
        let page_size = mask_to_page_size(entry.mask) as usize;
        let va_start = (entry.vpn2 << 13) as usize;

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
            let target = bus.hw_base.add(va_start);
            let _ = munmap(target as *mut c_void, page_size);

            let target_odd = bus.hw_base.add(va_start + page_size);
            let _ = munmap(target_odd as *mut c_void, page_size);
        }
    }

    #[cfg(windows)]
    pub fn clear_hw_fastmem_mapping(&self, bus: &Bus, entry: &TlbEntry) {
        let page_size = mask_to_page_size(entry.mask) as usize;
        let va_start = (entry.vpn2 << 13) as usize;

        if Self::is_fixed_region(va_start, page_size) {
            return;
        }

        unsafe {
            // Even page
            let va_even = va_start;
            let addr_even = bus.hw_base.add(va_even) as *mut c_void;
            let view_addr = MEMORY_MAPPED_VIEW_ADDRESS { Value: addr_even };
            let _ = unsafe {
                UnmapViewOfFile2(GetCurrentProcess(), view_addr, MEM_PRESERVE_PLACEHOLDER)
            };

            // Odd page
            let va_odd = va_start + page_size;
            let addr_odd = bus.hw_base.add(va_odd) as *mut c_void;
            let view_addr = MEMORY_MAPPED_VIEW_ADDRESS { Value: addr_odd };
            let _ = unsafe {
                UnmapViewOfFile2(GetCurrentProcess(), view_addr, MEM_PRESERVE_PLACEHOLDER)
            };
        }
        trace!(
            "Cleared fastmem TLB mapping at VA=0x{:08X} (size={})",
            va_start, page_size
        );
    }

    fn is_fixed_region(va_start: usize, page_size: usize) -> bool {
        let va_end = va_start + page_size * 2;
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
    #[unsafe(no_mangle)]
    pub fn hw_read8(&mut self, addr: u32) -> u8 {
        unsafe {
            let host_ptr = self.hw_base.add(addr as usize) as *const u8;
            *host_ptr
        }
    }

    #[unsafe(no_mangle)]
    pub fn hw_read16(&mut self, addr: u32) -> u16 {
        unsafe {
            let host_ptr = self.hw_base.add(addr as usize) as *const u16;
            *host_ptr
        }
    }

    #[unsafe(no_mangle)]
    pub fn hw_read32(&mut self, addr: u32) -> u32 {
        unsafe {
            let host_ptr = self.hw_base.add(addr as usize) as *const u32;
            *host_ptr
        }
    }

    #[unsafe(no_mangle)]
    pub fn hw_read64(&mut self, addr: u32) -> u64 {
        unsafe {
            let host_ptr = self.hw_base.add(addr as usize) as *const u64;
            *host_ptr
        }
    }

    #[unsafe(no_mangle)]
    pub fn hw_read128(&mut self, addr: u32) -> u128 {
        unsafe {
            let host_ptr = self.hw_base.add(addr as usize) as *const u128;
            *host_ptr
        }
    }

    #[unsafe(no_mangle)]
    pub fn hw_write8(&mut self, addr: u32, val: u8) {
        unsafe {
            let host_ptr = self.hw_base.add(addr as usize) as *mut u8;
            *host_ptr = val;
        }
    }

    #[unsafe(no_mangle)]
    pub fn hw_write16(&mut self, addr: u32, val: u16) {
        unsafe {
            let host_ptr = self.hw_base.add(addr as usize) as *mut u16;
            *host_ptr = val;
        }
    }

    #[unsafe(no_mangle)]
    pub fn hw_write32(&mut self, addr: u32, val: u32) {
        unsafe {
            let host_ptr = self.hw_base.add(addr as usize) as *mut u32;
            *host_ptr = val;
        }
    }

    #[unsafe(no_mangle)]
    pub fn hw_write64(&mut self, addr: u32, val: u64) {
        unsafe {
            let host_ptr = self.hw_base.add(addr as usize) as *mut u64;
            *host_ptr = val;
        }
    }

    #[unsafe(no_mangle)]
    pub fn hw_write128(&mut self, addr: u32, val: u128) {
        unsafe {
            let host_ptr = self.hw_base.add(addr as usize) as *mut u128;
            *host_ptr = val;
        }
    }
}
