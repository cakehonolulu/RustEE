use crate::bus::HW_LENGTH;

use super::{tlb::{mask_to_page_size, Tlb, TlbEntry}, Bus};
use region::{Allocation, Protection};
use std::io::{self, ErrorKind};
use super::HW_BASE;
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

    debug!("Populating TLB mappings for Hardware Fast Memory...");

    let default_mappings = [
        TlbEntry {
            vpn2: 0x00000000 >> 13,
            asid: 0,
            g: true,
            pfn0: 0x00000000 >> 12,
            pfn1: 0x00100000 >> 12,
            v0: true,
            d0: true,
            v1: true,
            d1: true,
            s0: false,
            s1: false,
            c0: 0,
            c1: 0,
            mask: 0x001F_E000,
        },
        TlbEntry {
            vpn2: 0x80000000 >> 13,
            asid: 0,
            g: true,
            pfn0: 0x00000000 >> 12,
            pfn1: 0x00100000 >> 12,
            v0: true,
            d0: true,
            v1: true,
            d1: true,
            s0: false,
            s1: false,
            c0: 0,
            c1: 0,
            mask: 0x001F_E000,
        },
        TlbEntry {
            vpn2: 0xA0000000 >> 13,
            asid: 0,
            g: true,
            pfn0: 0x00000000 >> 12,
            pfn1: 0x00100000 >> 12,
            v0: true,
            d0: true,
            v1: true,
            d1: true,
            s0: false,
            s1: false,
            c0: 0,
            c1: 0,
            mask: 0x001F_E000,
        },
        TlbEntry {
            vpn2: 0xBFC00000 >> 13,
            asid: 0,
            g: true,
            pfn0: 0x1FC00000 >> 12,
            pfn1: 0x1FD00000 >> 12,
            v0: true,
            d0: false,
            v1: true,
            d1: false,
            s0: false,
            s1: false,
            c0: 0,
            c1: 0,
            mask: 0x001F_E000,
        },
    ];

    let bus_ptr = bus as *mut Bus;
    for (index, entry) in default_mappings.iter().enumerate() {
        {
            let mut tlb = bus.tlb.borrow_mut();
            tlb.write_tlb_entry(bus_ptr, index, *entry);
        }
        bus.tlb.borrow().install_hw_fastmem_mapping(bus, entry);
        trace!("Installed HW-FastMem TLB mapping: {:?}", entry);
    }

    debug!(
        "Initialized Hardware Fast Memory: base=0x{:08X}, size={} bytes",
        bus.hw_base as usize, bus.hw_size
    );
}

pub unsafe fn init_hardware_arena(bus: &Bus) -> io::Result<(Allocation, *mut u8, usize)> { unsafe {
    let size = 1 << 32;
    let mut alloc = region::alloc(size, Protection::NONE)
        .map_err(|e| io::Error::new(ErrorKind::Other, e))?;
    let base = alloc.as_mut_ptr::<u8>();

    // Map kseg0: 0x80000000–0x9FFFFFFF to RAM (0x00000000–0x01FFFFFF)
    region::protect(base.add(0x80000000 as usize), 0x2000000, Protection::READ_WRITE)
        .map_err(|e| io::Error::new(ErrorKind::Other, e))?;

    // Map kseg1 RAM: 0xA0000000–0xA1FFFFFF → 0x00000000–0x01FFFFFF
    let ram_kseg1_start = 0xA0000000 as usize;
    let ram_size = 0x2000000; // 32MB
    region::protect(base.add(ram_kseg1_start), ram_size, Protection::READ_WRITE)
        .map_err(|e| io::Error::new(ErrorKind::Other, e))?;

    // Map kseg1 BIOS: 0xBFC00000–0xBFFFFFFF → 0x1FC00000–0x1FFFFFFF
    let bios_kseg1_start = 0xBFC00000 as usize;
    let bios_size = 0x400000; // 4MB (typical BIOS size)
    region::protect(base.add(bios_kseg1_start), bios_size, Protection::READ_WRITE)
        .map_err(|e| io::Error::new(ErrorKind::Other, e))?;

    // Map kseg0 BIOS: 0x9FC00000–0x9FFFFFFF → 0x1FC00000–0x1FFFFFFF
    region::protect(base.add(0x9FC00000 as usize), 0x400000, Protection::READ_WRITE)
        .map_err(|e| io::Error::new(ErrorKind::Other, e))?;
    std::ptr::copy_nonoverlapping(bus.bios.bytes.as_ptr(), base.add(0x9FC00000 as usize), bios_size);

    let sp_kseg1_start = 0x70000000 as usize;
    let sp_size = 0x4000; // 32MB
    region::protect(base.add(sp_kseg1_start), sp_size, Protection::READ_WRITE)
        .map_err(|e| io::Error::new(ErrorKind::Other, e))?;

    // Copy BIOS data into the arena at virtual address 0xBFC00000
    let bios_len = bus.bios.bytes.len();
    let dst = base.add(bios_kseg1_start);
    std::ptr::copy_nonoverlapping(bus.bios.bytes.as_ptr(), dst, bios_len);

    // Set BIOS region to READ-only after copying
    region::protect(base.add(bios_kseg1_start), bios_size, Protection::READ)
        .map_err(|e| io::Error::new(ErrorKind::Other, e))?;
    region::protect(base.add(0x9FC00000 as usize), bios_size, Protection::READ)
        .map_err(|e| io::Error::new(ErrorKind::Other, e))?;

    Ok((alloc, base, size))
}}

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
    pub fn hw_read32(&mut self, addr: u32) -> u32 {
        assert!((addr as usize) + 4 <= self.hw_size);
        unsafe {
            let host_ptr = self.hw_base.add(addr as usize) as *const u32;
            *host_ptr
        }
    }

    #[inline]
    pub fn hw_write32(&mut self, addr: u32, val: u32) {
        assert!((addr as usize) + 4 <= self.hw_size);
        unsafe {
            let host_ptr = self.hw_base.add(addr as usize) as *mut u32;
            *host_ptr = val;
        }
    }

    #[inline]
    pub fn hw_write64(&mut self, addr: u32, val: u64) {
        assert!((addr as usize) + 4 <= self.hw_size);
        unsafe {
            let host_ptr = self.hw_base.add(addr as usize) as *mut u64;
            *host_ptr = val;
        }
    }
}