use crate::bus::{map, HW_LENGTH};

use super::{tlb::{mask_to_page_size, Tlb, TlbEntry}, Bus, PAGE_SIZE};
use region::{Allocation, Protection};
use std::io::{self, ErrorKind};
use super::HW_BASE;
use std::sync::atomic::Ordering;
use tracing::debug;

pub unsafe fn init_hardware_fastmem(bus: &mut Bus) {
    debug!("Initializing Hardware Fast Memory...");
    debug!("Installing handler...");
    unsafe { super::install_handler().expect("Failed to install handler") };
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
        "Initialized Hardware Fast Memory: base=0x{:08X}, size={}",
        bus.hw_base as usize, bus.hw_size
    );
}

pub unsafe fn init_hardware_arena(bus: &Bus) -> io::Result<(Allocation, *mut u8, usize)> {
    let size = 1 << 32;
    let mut alloc = region::alloc(size, Protection::NONE)
        .map_err(|e| io::Error::new(ErrorKind::Other, e))?;
    let base = alloc.as_mut_ptr::<u8>();

    // Map kseg0: 0x80000000–0x9FFFFFFF to RAM (0x00000000–0x01FFFFFF)
    unsafe {
        region::protect(base.add(0x80000000 as usize), 0x2000000, Protection::READ_WRITE)
            .map_err(|e| io::Error::new(ErrorKind::Other, e))?;
    };

    // Map kseg1 RAM: 0xA0000000–0xA1FFFFFF → 0x00000000–0x01FFFFFF
    let ram_kseg1_start = 0xA0000000 as usize;
    let ram_size = 0x2000000; // 32MB
    unsafe {
        region::protect(base.add(ram_kseg1_start), ram_size, Protection::READ_WRITE)
            .map_err(|e| io::Error::new(ErrorKind::Other, e))?;
    };

    // Map kseg1 BIOS: 0xBFC00000–0xBFFFFFFF → 0x1FC00000–0x1FFFFFFF
    let bios_kseg1_start = 0xBFC00000 as usize;
    let bios_size = 0x400000; // 4MB (typical BIOS size)
    unsafe {
        region::protect(base.add(bios_kseg1_start), bios_size, Protection::READ_WRITE)
            .map_err(|e| io::Error::new(ErrorKind::Other, e))?;
    };

    // Copy BIOS data into the arena at virtual address 0xBFC00000
    let bios_len = bus.bios.bytes.len();
    let dst = base.add(bios_kseg1_start);
    unsafe {
        std::ptr::copy_nonoverlapping(bus.bios.bytes.as_ptr(), dst, bios_len);
    };

    // Set BIOS region to READ-only after copying
    unsafe {
        region::protect(base.add(bios_kseg1_start), bios_size, Protection::READ)
            .map_err(|e| io::Error::new(ErrorKind::Other, e))?;
    };

    Ok((alloc, base, size))
}

impl Tlb {
    pub fn install_hw_fastmem_mapping(&self, bus: &Bus, entry: &TlbEntry) {
        let page_size = mask_to_page_size(entry.mask) as usize;
        let va_start = (entry.vpn2 as usize) << 13;

        // Set protection for even page
        let prot_even = if entry.v0 {
            if entry.d0 { Protection::READ_WRITE } else { Protection::READ }
        } else {
            Protection::NONE
        };
        unsafe {
            region::protect(bus.hw_base.add(va_start), page_size, prot_even)
                .expect("Failed to update memory protection");
        }

        // Set protection for odd page
        let prot_odd = if entry.v1 {
            if entry.d1 { Protection::READ_WRITE } else { Protection::READ }
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
    pub fn hw_read32(&self, addr: u32) -> u32 {
        if addr >= 0xB000_0000 && addr <= 0xB001_FFFF {
            let pa = addr - 0xA000_0000;
            if map::IO.contains(pa).is_some() {
                todo!("HW Fastmem: IO read at 0x{:08X}", pa);
            }
        }
        assert!((addr as usize) + 4 <= self.hw_size);
        unsafe { (self.hw_base.add(addr as usize) as *const u32).read_unaligned() }
    }

    #[inline]
    pub fn hw_write32(&mut self, addr: u32, val: u32) {
        let pa = addr - 0xA000_0000;
        if map::IO.contains(pa).is_some() {
            todo!("HW Fastmem: IO write at 0x{:08X}", pa);
        }
        assert!((addr as usize) + 4 <= self.hw_size);
        unsafe { (self.hw_base.add(addr as usize) as *mut u32).write_unaligned(val) }
    }
}