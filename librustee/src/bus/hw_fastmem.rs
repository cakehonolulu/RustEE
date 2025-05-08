use crate::bus::HW_LENGTH;

use super::{tlb::{mask_to_page_size, Tlb, TlbEntry}, Bus};
use region::{Allocation, Protection};
use std::io::{self, ErrorKind};
use super::HW_BASE;
use std::sync::atomic::Ordering;
use tracing::debug;

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

    bus.is_mmio = [0; 1 << 20];
    let mmio_ranges = [
        // Timers
        (0x10000000, 0x100000FF), // Timer 0
        (0x10000800, 0x100008FF), // Timer 1
        (0x10001000, 0x100010FF), // Timer 2
        (0x10001800, 0x100018FF), // Timer 3

        // Image Processing Unit (IPU)
        (0x10002000, 0x1000203F), // IPU registers
        (0x10007000, 0x1000701F), // IPU FIFOs

        // Graphics Interface (GIF)
        (0x10003000, 0x100030A0), // GIF registers
        (0x10006000, 0x1000600F), // GIF FIFO

        // DMA Controller (DMAC)
        (0x10008000, 0x100080FF), // VIF0 - channel 0
        (0x10009000, 0x100090FF), // VIF1 - channel 1
        (0x1000A000, 0x1000A0FF), // GIF - channel 2
        (0x1000B000, 0x1000B0FF), // IPU_FROM - channel 3
        (0x1000B400, 0x1000B4FF), // IPU_TO - channel 4
        (0x1000C000, 0x1000C0FF), // SIF0 - channel 5
        (0x1000C400, 0x1000C4FF), // SIF1 - channel 6
        (0x1000C800, 0x1000C8FF), // SIF2 - channel 7
        (0x1000D000, 0x1000D0FF), // SPR_FROM - channel 8
        (0x1000D400, 0x1000D4FF), // SPR_TO - channel 9
        (0x1000E000, 0x1000E060), // DMAC control registers
        (0x1000F520, 0x1000F523), // D_ENABLER
        (0x1000F590, 0x1000F593), // D_ENABLEW

        // Interrupt Controller (INTC)
        (0x1000F000, 0x1000F010), // INTC_STAT and INTC_MASK

        // Subsystem Interface (SIF)
        (0x1000F200, 0x1000F240), // SIF registers

        // Privileged GS registers
        (0x12000000, 0x120000E0), // Main GS privileged registers
        (0x12001000, 0x12001080), // Additional GS registers (CSR, IMR, etc.)

        // Miscellaneous registers
        (0x1000F180, 0x1000F180), // KPUTCHAR
        (0x1000F430, 0x1000F433), // MCH_DRD
        (0x1000F440, 0x1000F443), // MCH_RICM
    ];

    for (start, end) in mmio_ranges.iter() {
        let start_page = *start >> 12;
        let end_page = (*end + 0xFFF) >> 12;
        for page in start_page..=end_page {
            bus.is_mmio[page as usize] = 1;
        }
    }

    debug!(
        "Initialized Hardware Fast Memory: base=0x{:08X}, size={}",
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

    // Copy BIOS data into the arena at virtual address 0xBFC00000
    let bios_len = bus.bios.bytes.len();
    let dst = base.add(bios_kseg1_start);
    std::ptr::copy_nonoverlapping(bus.bios.bytes.as_ptr(), dst, bios_len);

    // Set BIOS region to READ-only after copying
    region::protect(base.add(bios_kseg1_start), bios_size, Protection::READ)
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
    pub fn hw_read32(&self, addr: u32) -> u32 {
        let page = (addr >> 12) as usize;
        if self.is_mmio[page] != 0 {
            // Mark function as #[cold]
            todo!("HW Fastmem: IO read at 0x{:08X}", addr);
        } else {
            assert!((addr as usize) + 4 <= self.hw_size);
            unsafe { (self.hw_base.add(addr as usize) as *const u32).read_unaligned() } // RAM path
        }
    }

    #[inline]
    pub fn hw_write32(&mut self, addr: u32, val: u32) {
        let page = (addr >> 12) as usize;
        if self.is_mmio[page] != 0 {
            // Mark function as #[cold]
            todo!("HW Fastmem: IO write at 0x{:08X}", addr);
        } else {
            assert!((addr as usize) + 4 <= self.hw_size);
            unsafe { (self.hw_base.add(addr as usize) as *mut u32).write_unaligned(val) } // RAM path
        }
    }
}