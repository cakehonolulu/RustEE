use super::tlb::{Tlb, TlbEntry, mask_to_page_size};
use super::{Bus, HW_BASE};
use crate::bus::HW_LENGTH;
use nix::fcntl::{OFlag, open};
use nix::sys::mman::{MapFlags, ProtFlags, mmap, munmap, shm_open, shm_unlink};
use nix::sys::stat::Mode;
use nix::unistd::{close, ftruncate};
use region::{Allocation, Protection};
use std::io::{self, ErrorKind};
use std::num::NonZero;
use std::sync::atomic::Ordering;
use tracing::{debug, trace};

pub unsafe fn init_hardware_fastmem(bus: &mut Bus) {
    debug!("Initializing Hardware Fast Memory...");
    debug!("Installing handler...");
    super::install_handler().expect("Failed to install handler");
    debug!("Handler installed");

    debug!("Initializing hardware arena...");
    let (arena, base, size) = unsafe { init_hardware_arena(bus).expect("Failed to init arena") };
    debug!("Hardware arena initialized");

    bus.hw_base = base;
    bus.hw_size = size;
    bus.arena = Some(arena);

    HW_LENGTH.store(size, Ordering::SeqCst);
    HW_BASE.store(base as usize, Ordering::SeqCst);

    debug!(
        "Initialized Hardware Fast Memory: base=0x{:08X}, size={} bytes",
        bus.hw_base as usize, bus.hw_size
    );
}

pub unsafe fn init_hardware_arena(bus: &Bus) -> io::Result<(Allocation, *mut u8, usize)> {
    unsafe {
        // Allocate a 4GB virtual address arena with no access
        let size = 1 << 32; // 4GB
        let mut alloc = region::alloc(size, Protection::NONE)
            .map_err(|e| io::Error::new(ErrorKind::Other, e))?;
        let base = alloc.as_mut_ptr::<u8>();

        // Platform-specific shared memory mapping for Unix
        #[cfg(unix)]
        {
            // Step 1: Create shared memory object for 32MB RAM

            use std::{os::raw::c_void, ptr::NonNull};
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

            // Set size of shared memory object
            ftruncate(&ram_fd, ram_size as i64).map_err(|e| {
                io::Error::new(ErrorKind::Other, format!("Failed to set RAM size: {}", e))
            })?;

            // Step 2: Unmap kseg0 and kseg1 ranges to avoid conflicts
            let kseg0_start = base.add(0x80000000 as usize);
            let kseg1_start = base.add(0xA0000000 as usize);
            munmap(
                NonNull::new(kseg0_start as *mut c_void)
                    .ok_or_else(|| io::Error::new(ErrorKind::Other, "Invalid kseg0 address"))?,
                ram_size,
            )
            .map_err(|e| {
                io::Error::new(ErrorKind::Other, format!("Failed to unmap kseg0: {}", e))
            })?;
            munmap(
                NonNull::new(kseg1_start as *mut c_void)
                    .ok_or_else(|| io::Error::new(ErrorKind::Other, "Invalid kseg1 address"))?,
                ram_size,
            )
            .map_err(|e| {
                io::Error::new(ErrorKind::Other, format!("Failed to unmap kseg1: {}", e))
            })?;

            // Step 3: Map RAM to kseg0 (0x80000000–0x81FFFFFF)
            let kseg0_map = mmap(
                NonZero::new(kseg0_start as usize),
                NonZero::new(ram_size)
                    .ok_or_else(|| io::Error::new(ErrorKind::Other, "Invalid RAM size"))?,
                ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
                MapFlags::MAP_SHARED | MapFlags::MAP_FIXED_NOREPLACE,
                &ram_fd,
                0,
            )
            .map_err(|e| {
                io::Error::new(ErrorKind::Other, format!("Failed to map kseg0 RAM: {}", e))
            })?;

            // Step 4: Map RAM to kseg1 (0xA0000000–0xA1FFFFFF)
            let kseg1_map = mmap(
                NonZero::new(kseg1_start as usize),
                NonZero::new(ram_size)
                    .ok_or_else(|| io::Error::new(ErrorKind::Other, "Invalid RAM size"))?,
                ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
                MapFlags::MAP_SHARED | MapFlags::MAP_FIXED_NOREPLACE,
                &ram_fd,
                0,
            )
            .map_err(|e| {
                io::Error::new(ErrorKind::Other, format!("Failed to map kseg1 RAM: {}", e))
            })?;

            // Clean up RAM shared memory object
            close(ram_fd).map_err(|e| {
                io::Error::new(ErrorKind::Other, format!("Failed to close RAM fd: {}", e))
            })?;
            shm_unlink(ram_name).map_err(|e| {
                io::Error::new(ErrorKind::Other, format!("Failed to unlink RAM shm: {}", e))
            })?;

            // Step 5: Create shared memory object for 4MB BIOS
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

            ftruncate(&bios_fd, bios_size as i64).map_err(|e| {
                io::Error::new(ErrorKind::Other, format!("Failed to set BIOS size: {}", e))
            })?;

            // Copy BIOS data into shared memory
            let bios_temp = mmap(
                None,
                NonZero::new(bios_size)
                    .ok_or_else(|| io::Error::new(ErrorKind::Other, "Invalid BIOS size"))?,
                ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
                MapFlags::MAP_SHARED,
                &bios_fd,
                0,
            )
            .map_err(|e| {
                io::Error::new(ErrorKind::Other, format!("Failed to map BIOS temp: {}", e))
            })?;
            let bios_len = bus.bios.bytes.len();
            std::ptr::copy_nonoverlapping(
                bus.bios.bytes.as_ptr(),
                bios_temp.as_ptr() as *mut u8,
                bios_len,
            );

            // Unmap BIOS ranges
            let bios_kseg1_start = base.add(0xBFC00000 as usize);
            let bios_kseg0_start = base.add(0x9FC00000 as usize);
            munmap(
                NonNull::new(bios_kseg1_start as *mut c_void).ok_or_else(|| {
                    io::Error::new(ErrorKind::Other, "Invalid kseg1 BIOS address")
                })?,
                bios_size,
            )
            .map_err(|e| {
                io::Error::new(
                    ErrorKind::Other,
                    format!("Failed to unmap kseg1 BIOS: {}", e),
                )
            })?;
            munmap(
                NonNull::new(bios_kseg0_start as *mut c_void).ok_or_else(|| {
                    io::Error::new(ErrorKind::Other, "Invalid kseg0 BIOS address")
                })?,
                bios_size,
            )
            .map_err(|e| {
                io::Error::new(
                    ErrorKind::Other,
                    format!("Failed to unmap kseg0 BIOS: {}", e),
                )
            })?;

            // Map BIOS to kseg1 (0xBFC00000–0xBFFFFFFF)
            let bios_kseg1_map = mmap(
                NonZero::new(bios_kseg1_start as usize),
                NonZero::new(bios_size)
                    .ok_or_else(|| io::Error::new(ErrorKind::Other, "Invalid BIOS size"))?,
                ProtFlags::PROT_READ,
                MapFlags::MAP_SHARED | MapFlags::MAP_FIXED_NOREPLACE,
                &bios_fd,
                0,
            )
            .map_err(|e| {
                io::Error::new(ErrorKind::Other, format!("Failed to map kseg1 BIOS: {}", e))
            })?;

            // Map BIOS to kseg0 (0x9FC00000–0x9FFFFFFF)
            let bios_kseg0_map = mmap(
                NonZero::new(bios_kseg0_start as usize),
                NonZero::new(bios_size)
                    .ok_or_else(|| io::Error::new(ErrorKind::Other, "Invalid BIOS size"))?,
                ProtFlags::PROT_READ,
                MapFlags::MAP_SHARED | MapFlags::MAP_FIXED_NOREPLACE,
                &bios_fd,
                0,
            )
            .map_err(|e| {
                io::Error::new(ErrorKind::Other, format!("Failed to map kseg0 BIOS: {}", e))
            })?;

            // Clean up BIOS shared memory
            munmap(
                NonNull::new(bios_temp.as_ptr())
                    .ok_or_else(|| io::Error::new(ErrorKind::Other, "Invalid BIOS temp address"))?,
                bios_size,
            )
            .map_err(|e| {
                io::Error::new(
                    ErrorKind::Other,
                    format!("Failed to unmap BIOS temp: {}", e),
                )
            })?;
            close(bios_fd).map_err(|e| {
                io::Error::new(ErrorKind::Other, format!("Failed to close BIOS fd: {}", e))
            })?;
            shm_unlink(bios_name).map_err(|e| {
                io::Error::new(
                    ErrorKind::Other,
                    format!("Failed to unlink BIOS shm: {}", e),
                )
            })?;

            // Step 6: Map scratchpad (16KB)
            let sp_size = 0x4000; // 16KB
            let sp_kseg1_start = base.add(0x70000000 as usize);
            region::protect(sp_kseg1_start, sp_size, Protection::READ_WRITE)
                .map_err(|e| io::Error::new(ErrorKind::Other, e))?;
        }

        #[cfg(windows)]
        {
            // Step 1: Create shared memory object for 32MB RAM
            let ram_size = 0x2000000; // 32MB
            let ram_name = windows::core::w!("rustee_ram");
            let ram_handle = CreateFileMappingW(
                INVALID_HANDLE_VALUE,
                None,
                PAGE_READWRITE,
                0,
                ram_size as u32,
                Some(ram_name),
            )
            .map_err(|e| {
                io::Error::new(
                    ErrorKind::Other,
                    format!("Failed to create RAM mapping: {}", e),
                )
            })?;

            // Step 2: Map RAM to kseg0 (0x80000000–0x81FFFFFF)
            let kseg0_start = base.add(0x80000000 as usize);
            let kseg0_map = MapViewOfFileEx(
                ram_handle,
                FILE_MAP_ALL_ACCESS,
                0,
                0,
                ram_size,
                kseg0_start as *mut c_void,
            )
            .map_err(|e| {
                io::Error::new(ErrorKind::Other, format!("Failed to map kseg0 RAM: {}", e))
            })?;

            // Step 3: Map RAM to kseg1 (0xA0000000–0xA1FFFFFF)
            let kseg1_start = base.add(0xA0000000 as usize);
            let kseg1_map = MapViewOfFileEx(
                ram_handle,
                FILE_MAP_ALL_ACCESS,
                0,
                0,
                ram_size,
                kseg1_start as *mut c_void,
            )
            .map_err(|e| {
                io::Error::new(ErrorKind::Other, format!("Failed to map kseg1 RAM: {}", e))
            })?;

            // Step 4: Create shared memory object for 4MB BIOS
            let bios_size = 0x400000; // 4MB
            let bios_name = windows::core::w!("rustee_bios");
            let bios_handle = CreateFileMappingW(
                INVALID_HANDLE_VALUE,
                None,
                PAGE_READWRITE,
                0,
                bios_size as u32,
                Some(bios_name),
            )
            .map_err(|e| {
                io::Error::new(
                    ErrorKind::Other,
                    format!("Failed to create BIOS mapping: {}", e),
                )
            })?;

            // Copy BIOS data
            let bios_temp = MapViewOfFileEx(
                bios_handle,
                FILE_MAP_ALL_ACCESS,
                0,
                0,
                bios_size,
                std::ptr::null_mut(),
            )
            .map_err(|e| {
                io::Error::new(ErrorKind::Other, format!("Failed to map BIOS temp: {}", e))
            })?;
            let bios_len = bus.bios.bytes.len();
            std::ptr::copy_nonoverlapping(
                bus.bios.bytes.as_ptr(),
                bios_temp.0 as *mut u8,
                bios_len,
            );

            // Map BIOS to kseg1 (0xBFC00000–0xBFFFFFFF)
            let bios_kseg1_start = base.add(0xBFC00000 as usize);
            let bios_kseg1_map = MapViewOfFileEx(
                bios_handle,
                FILE_MAP_READ,
                0,
                0,
                bios_size,
                bios_kseg1_start as *mut c_void,
            )
            .map_err(|e| {
                io::Error::new(ErrorKind::Other, format!("Failed to map kseg1 BIOS: {}", e))
            })?;

            // Map BIOS to kseg0 (0x9FC00000–0x9FFFFFFF)
            let bios_kseg0_start = base.add(0x9FC00000 as usize);
            let bios_kseg0_map = MapViewOfFileEx(
                bios_handle,
                FILE_MAP_READ,
                0,
                0,
                bios_size,
                bios_kseg0_start as *mut c_void,
            )
            .map_err(|e| {
                io::Error::new(ErrorKind::Other, format!("Failed to map kseg0 BIOS: {}", e))
            })?;

            // Clean up BIOS temporary mapping and handles
            UnmapViewOfFile(bios_temp).map_err(|e| {
                io::Error::new(
                    ErrorKind::Other,
                    format!("Failed to unmap BIOS temp: {}", e),
                )
            })?;
            CloseHandle(ram_handle).map_err(|e| {
                io::Error::new(
                    ErrorKind::Other,
                    format!("Failed to close RAM handle: {}", e),
                )
            })?;
            CloseHandle(bios_handle).map_err(|e| {
                io::Error::new(
                    ErrorKind::Other,
                    format!("Failed to close BIOS handle: {}", e),
                )
            })?;

            // Step 5: Map scratchpad (16KB)
            let sp_size = 0x4000; // 16KB
            let sp_kseg1_start = base.add(0x70000000 as usize);
            region::protect(sp_kseg1_start, sp_size, Protection::READ_WRITE)
                .map_err(|e| io::Error::new(ErrorKind::Other, e))?;
        }

        debug!(
            "Arena initialized: base=0x{:08X}, size={} bytes",
            base as usize, size
        );
        Ok((alloc, base, size))
    }
}

impl Tlb {
    pub fn install_hw_fastmem_mapping(&self, bus: &Bus, entry: &TlbEntry) {
        let page_size = mask_to_page_size(entry.mask) as usize;
        let va_start = (entry.vpn2 as usize) << 13;

        // Skip kseg0, kseg1, BIOS, and scratchpad regions to avoid overriding fixed mappings
        if (va_start >= 0x80000000 && va_start < 0x82000000)
            || (va_start >= 0xA0000000 && va_start < 0xA2000000)
            || (va_start >= 0x9FC00000 && va_start < 0xA0000000)
            || (va_start >= 0xBFC00000 && va_start < 0xC0000000)
        {
            debug!(
                "Skipping TLB mapping for fixed region: va_start=0x{:08X}",
                va_start
            );
            return;
        }

        // Set protection for even page
        let prot_even = if entry.v0 {
            if entry.d0 {
                Protection::READ_WRITE
            } else {
                Protection::READ
            }
        } else {
            Protection::NONE
        };
        unsafe {
            region::protect(bus.hw_base.add(va_start), page_size, prot_even)
                .expect("Failed to update memory protection");
        }

        // Set protection for odd page
        let prot_odd = if entry.v1 {
            if entry.d1 {
                Protection::READ_WRITE
            } else {
                Protection::READ
            }
        } else {
            Protection::NONE
        };
        let va_start_odd = va_start + page_size;
        unsafe {
            region::protect(bus.hw_base.add(va_start_odd), page_size, prot_odd)
                .expect("Failed to update memory protection");
        }
    }

    pub fn clear_hw_fastmem_mapping(&self, bus: &Bus, entry: &TlbEntry) {
        let page_size = mask_to_page_size(entry.mask) as usize;
        let va_start = (entry.vpn2 as usize) << 13;

        // Skip fixed regions
        if (va_start >= 0x80000000 && va_start < 0x82000000)
            || (va_start >= 0xA0000000 && va_start < 0xA2000000)
            || (va_start >= 0x9FC00000 && va_start < 0xA0000000)
            || (va_start >= 0xBFC00000 && va_start < 0xC0000000)
        {
            debug!(
                "Skipping TLB clear for fixed region: va_start=0x{:08X}",
                va_start
            );
            return;
        }

        // Clear even page
        unsafe {
            region::protect(bus.hw_base.add(va_start), page_size, Protection::NONE)
                .expect("Failed to clear memory protection");
        }

        // Clear odd page
        let va_start_odd = va_start + page_size;
        unsafe {
            region::protect(bus.hw_base.add(va_start_odd), page_size, Protection::NONE)
                .expect("Failed to clear memory protection");
        }
    }
}

impl Bus {
    #[inline]
    pub fn hw_read8(&mut self, addr: u32) -> u8 {
        assert!((addr as usize) < self.hw_size);
        unsafe {
            let host_ptr = self.hw_base.add(addr as usize) as *const u8;
            *host_ptr
        }
    }

    #[inline]
    pub fn hw_read16(&mut self, addr: u32) -> u16 {
        assert!((addr as usize) + 1 < self.hw_size);
        unsafe {
            let host_ptr = self.hw_base.add(addr as usize) as *const u16;
            *host_ptr
        }
    }

    #[inline]
    pub fn hw_read32(&mut self, addr: u32) -> u32 {
        assert!((addr as usize) + 3 < self.hw_size);
        unsafe {
            let host_ptr = self.hw_base.add(addr as usize) as *const u32;
            *host_ptr
        }
    }

    #[inline]
    pub fn hw_read64(&mut self, addr: u32) -> u64 {
        assert!((addr as usize) + 7 < self.hw_size);
        unsafe {
            let host_ptr = self.hw_base.add(addr as usize) as *const u64;
            *host_ptr
        }
    }

    #[inline]
    pub fn hw_read128(&mut self, addr: u32) -> u128 {
        assert!((addr as usize) + 15 < self.hw_size);
        unsafe {
            let host_ptr = self.hw_base.add(addr as usize) as *const u128;
            *host_ptr
        }
    }

    #[inline]
    pub fn hw_write8(&mut self, addr: u32, val: u8) {
        assert!((addr as usize) < self.hw_size);
        unsafe {
            let host_ptr = self.hw_base.add(addr as usize) as *mut u8;
            *host_ptr = val;
        }
    }

    #[inline]
    pub fn hw_write16(&mut self, addr: u32, val: u16) {
        assert!((addr as usize) + 1 < self.hw_size);
        unsafe {
            let host_ptr = self.hw_base.add(addr as usize) as *mut u16;
            *host_ptr = val;
        }
    }

    #[inline]
    pub fn hw_write32(&mut self, addr: u32, val: u32) {
        assert!((addr as usize) + 3 < self.hw_size);
        unsafe {
            let host_ptr = self.hw_base.add(addr as usize) as *mut u32;
            *host_ptr = val;
        }
    }

    #[inline]
    pub fn hw_write64(&mut self, addr: u32, val: u64) {
        assert!((addr as usize) + 7 < self.hw_size);
        unsafe {
            let host_ptr = self.hw_base.add(addr as usize) as *mut u64;
            *host_ptr = val;
        }
    }

    #[inline]
    pub fn hw_write128(&mut self, addr: u32, val: u128) {
        assert!((addr as usize) + 15 < self.hw_size);
        unsafe {
            let host_ptr = self.hw_base.add(addr as usize) as *mut u128;
            *host_ptr = val;
        }
    }
}
