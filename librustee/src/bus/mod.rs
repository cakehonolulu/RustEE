pub mod bios;

use bios::BIOS;
use region::Protection;
use tracing::{debug, info};

use std::ptr::null_mut;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::mem::MaybeUninit;

use std::io::{self, ErrorKind};

mod map {
    pub struct Range(pub u32, pub u32);

    impl Range {
        pub fn contains(self, addr: u32) -> Option<u32> {
            let Range(start, length) = self;
            if addr >= start && addr < start + length {
                Some(addr - start)
            } else {
                None
            }
        }
    }

    pub const BIOS: Range = Range(0xBFC0_0000, (1024 * 1024) * 4);
    pub const RAM:  Range = Range(0x0000_0000, 32 * 1024 * 1024);
}

#[derive(PartialEq, Debug)]
pub enum BusMode {
    SoftwareFastMem,
    Ranged,
    HardwareFastMem,
}

const PAGE_BITS:    usize = 12;                    // 4 KiB pages
const PAGE_SIZE:    usize = 1 << PAGE_BITS;        // 4096
const NUM_PAGES:    usize = 1 << (32 - PAGE_BITS); // 4 GiB / 4 KiB = 1 048 576

pub struct Bus {
    bios: BIOS,
    ram: Vec<u8>,

    page_read:  Vec<usize>,
    page_write: Vec<usize>,

    hw_base: *mut u8,
    hw_size: usize,
    arena: Option<region::Allocation>,

    // Function pointers for read/write operations
    pub read32: fn(&Bus, u32) -> u32,
    pub write32: fn(&mut Bus, u32, u32),
}

static HANDLER_INSTALLED: AtomicBool = AtomicBool::new(false);
static mut BUS_PTR: *mut Bus = null_mut();
static HW_BASE: AtomicUsize = AtomicUsize::new(0);

#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod windows;

/// Reserve guest arena, mprotect subregions for RAM+BIOS, copy BIOS data.
unsafe fn init_hardware_arena(bus: &Bus) -> io::Result<(region::Allocation, *mut u8, usize)> {
    // Total size = BIOS top address + BIOS size
    let hw_size = (map::BIOS.0 as usize) + (map::BIOS.1 as usize);

    // Reserve the whole span with no permissions
    let mut alloc = region::alloc(hw_size, Protection::NONE)
        .map_err(|e| io::Error::new(ErrorKind::Other, e))?;

    let base = alloc.as_mut_ptr::<u8>();

    // Enable RAM region (read/write)
    let ram_addr = unsafe { base.add(map::RAM.0 as usize) };
    unsafe { region::protect(ram_addr, map::RAM.1 as usize, Protection::READ_WRITE)
        .map_err(|e| io::Error::new(ErrorKind::Other, e)) }?;

    // Enable BIOS region (read/write) to allow copy
    let bios_addr = unsafe { base.add(map::BIOS.0 as usize) };
    unsafe { region::protect(bios_addr, map::BIOS.1 as usize, Protection::READ_WRITE)
        .map_err(|e| io::Error::new(ErrorKind::Other, e)) }?;

    // Copy BIOS contents into mapped memory
    let bios_len = map::BIOS.1 as usize;
    let dst: &mut [u8] = unsafe { std::slice::from_raw_parts_mut(bios_addr, bios_len) };
    dst.copy_from_slice(&bus.bios.bytes);

    // Make BIOS region executable (read/exec)
    unsafe { region::protect(bios_addr, map::BIOS.1 as usize, Protection::READ_EXECUTE)
        .map_err(|e| io::Error::new(ErrorKind::Other, e)) }?;

    Ok((alloc, base, hw_size))
}

#[cfg(unix)]
use unix::install_handler;
#[cfg(windows)]
use windows::install_handler;

impl Bus {
    pub fn new(mode: BusMode, bios: BIOS) -> Bus {
        let mut bus = Bus {
            bios,
            ram: vec![0; 32 * 1024 * 1024],
            page_read:  vec![0; NUM_PAGES],
            page_write: vec![0; NUM_PAGES],
            read32:  Bus::sw_fmem_read32,
            write32: Bus::sw_fmem_write32,
            hw_base: null_mut(),
            hw_size: 0,
            arena: None
        };

        unsafe { BUS_PTR = &mut bus; }

        // Setup hardware arena before choosing function pointers
        if mode == BusMode::HardwareFastMem {
            debug!("Initializing Hardware Fast Memory...");
            unsafe {
                debug!("Installing handler...");
                install_handler().expect("Failed to install handler");
                debug!("Handler installed");
                debug!("Initializing hardware arena...");
                let (arena, base, size) = init_hardware_arena(&bus).expect("Failed to init arena");
                debug!("Hardware arena initialized");
                bus.hw_base = base;
                bus.hw_size = size;
                bus.arena = Some(arena);
                HW_BASE.store(base as usize, Ordering::SeqCst);
            }
            debug!("Initialized Hardware Fast Memory: base=0x{:08X}, size={}", bus.hw_base as usize, bus.hw_size);
        }

        (bus.read32, bus.write32) = match mode {
            BusMode::SoftwareFastMem => (
                Bus::sw_fmem_read32 as fn(&Bus, u32) -> u32,
                Bus::sw_fmem_write32 as fn(&mut Bus, u32, u32),
            ),
            BusMode::Ranged => (
                Bus::ranged_read32 as fn(&Bus, u32) -> u32,
                Bus::ranged_write32 as fn(&mut Bus, u32, u32),
            ),
            BusMode::HardwareFastMem => (
                Bus::hw_read32 as fn(&Bus, u32) -> u32,
                Bus::hw_write32 as fn(&mut Bus, u32, u32),
            ),
        };

        if mode == BusMode::SoftwareFastMem {
            for page in 0 .. (32 * 1024 * 1024 / PAGE_SIZE) {
                let host_ptr = bus.ram.as_ptr() as usize + page * PAGE_SIZE;
                bus.page_read[page] = host_ptr;
                bus.page_write[page] = host_ptr;
            }
            let bios_ptr = bus.bios.bytes.as_ptr() as usize;
            let base = (map::BIOS.0 as usize) >> PAGE_BITS;
            let count = bus.bios.bytes.len() / PAGE_SIZE;
            for i in 0..count {
                bus.page_read[base + i] = bios_ptr + i * PAGE_SIZE;
            }
        }

        info!("Bus initialized with mode: {:?}", mode);
        bus
    }

    fn ranged_read32(&self, address: u32) -> u32 {
        if let Some(offset) = map::RAM.contains(address) {
            // Access the RAM bytes directly
            let offset = offset as usize;
            if offset + 4 <= self.ram.len() {
                let bytes = &self.ram[offset..offset + 4];
                u32::from_le_bytes(bytes.try_into().expect("Ranged: Failed to convert bytes!"))
            } else {
                panic!("Range: Attempted to read out of bounds from RAM");
            }
        } else if let Some(offset) = map::BIOS.contains(address) {
            // Access the BIOS bytes directly
            let offset = offset as usize;
            if offset + 4 <= self.bios.bytes.len() {
                let bytes = &self.bios.bytes[offset..offset + 4];
                u32::from_le_bytes(bytes.try_into().expect("Ranged: Failed to convert bytes!"))
            } else {
                panic!("Range: Attempted to read out of bounds from BIOS");
            }
        } else {
            panic!("Ranged: Unhandled 32-bit read from address: 0x{:08X}", address);
        }
    }

    fn ranged_write32(&mut self, address: u32, value: u32) {
        if let Some(offset) = map::RAM.contains(address) {
            // Write to RAM
            let offset = offset as usize;
            if offset + 4 <= self.ram.len() {
                self.ram[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
            } else {
                panic!("Ranged: Attempted to write out of bounds to RAM");
            }
        } else {
            panic!("Ranged: Unhandled 32-bit write to address: 0x{:08X}", address);
        }
    }

    fn sw_fmem_read32(&self, address: u32) -> u32 {
        let page   = (address as usize) >> PAGE_BITS;
        let offset = (address as usize) & (PAGE_SIZE - 1);
        let host   = self.page_read[page];
        if host != 0 {
            unsafe {
                let ptr = (host as *const u8).add(offset) as *const u32;
                ptr.read_unaligned()
            }
        }
        else
        {
            panic!("SoftwareFastMem: Unhandled 32-bit read from address 0x{:08X}", address);
        }
    }

    fn sw_fmem_write32(&mut self, address: u32, value: u32) {
        let page   = (address as usize) >> PAGE_BITS;
        let offset = (address as usize) & (PAGE_SIZE - 1);
        let host   = self.page_write[page];
        if host != 0 {
            unsafe {
                let ptr = (host as *mut u8).add(offset) as *mut u32;
                ptr.write_unaligned(value);
            }
        }
        else
        {
            panic!("SoftwareFastMem: Unhandled 32-bit write to address 0x{:08X}", address);
        }
    }

    #[inline]
    fn hw_read32(&self, addr: u32) -> u32 {
        assert!((addr as usize) + 4 <= self.hw_size);
        unsafe { (self.hw_base.add(addr as usize) as *const u32).read_unaligned() }
    }

    #[inline]
    fn hw_write32(&mut self, addr: u32, val: u32) {
        assert!((addr as usize) + 4 <= self.hw_size);
        unsafe { (self.hw_base.add(addr as usize) as *mut u32).write_unaligned(val) }
    }
}