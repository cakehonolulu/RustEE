pub mod bios;

use bios::BIOS;
use tracing::{info, debug};

use std::sync::{Arc, RwLock};
use std::{cell::RefCell, ptr::null_mut};
use std::sync::atomic::AtomicUsize;

pub mod tlb;
mod ranged;
mod sw_fastmem;
mod hw_fastmem;
pub mod backpatch;

use crate::ee::sio::{SIO};

use tlb::{OperatingMode, Tlb};

#[cfg(unix)]
use unix::install_handler;
#[cfg(windows)]
use windows::install_handler;

#[cfg(unix)]
pub mod unix;
#[cfg(windows)]
mod windows;

static mut BUS_PTR: *mut Bus = null_mut();

static HW_BASE:   AtomicUsize = AtomicUsize::new(0);
static HW_LENGTH: AtomicUsize = AtomicUsize::new(0);

#[derive(PartialEq, Debug, Clone)]
pub enum BusMode {
    SoftwareFastMem,
    Ranged,
    HardwareFastMem,
}

pub mod map {
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

    // Physical address ranges
    pub const RAM:  Range = Range(0x0000_0000, 32 * 1024 * 1024);
    pub const IO:   Range = Range(0x1000_0000, 64 * 1024);
    pub const BIOS: Range = Range(0x1FC0_0000, 4 * 1024 * 1024);
}

const PAGE_BITS:    usize = 12;                    // 4 KiB pages
const PAGE_SIZE:    usize = 1 << PAGE_BITS;        // 4096
const NUM_PAGES:    usize = 1 << (32 - PAGE_BITS); // 4 GiB / 4 KiB = 1 048 576

pub struct Bus {
    pub(crate) bios: BIOS,
    pub(crate) ram: Vec<u8>,

    pub tlb: RefCell<Tlb>,
    pub(crate) operating_mode: OperatingMode,

    pub sio: SIO,

    mode: BusMode,

    page_read:  Vec<usize>,
    page_write: Vec<usize>,

    hw_base: *mut u8,
    hw_size: usize,
    arena: Option<region::Allocation>,

    pub cop0_registers: Arc<RwLock<[u32; 32]>>,

    // Function pointers for read/write operations
    pub read8: fn(&mut Self, u32) -> u8,
    pub read32: fn(&mut Self, u32) -> u32,
    pub read64: fn(&mut Self, u32) -> u64,
    pub write8: fn(&mut Self, u32, u8),
    pub write32: fn(&mut Self, u32, u32),
    pub write64: fn(&mut Self, u32, u64),
}

impl Bus {
    pub fn new(mode: BusMode, bios: BIOS, cop0_registers: Arc<RwLock<[u32; 32]>>) -> Bus {
        let mut bus = Bus {
            bios,
            ram: vec![0; 32 * 1024 * 1024],
            page_read:  vec![0; NUM_PAGES],
            page_write: vec![0; NUM_PAGES],
            sio: SIO::new(),
            mode: mode.clone(),
            read8: Bus::sw_fmem_read8,
            read32:  Bus::sw_fmem_read32,
            read64:  Bus::sw_fmem_read64,
            write8: Bus::sw_fmem_write8,
            write32: Bus::sw_fmem_write32,
            write64: Bus::sw_fmem_write64,
            hw_base: null_mut(),
            hw_size: 0,
            arena: None,
            tlb: Tlb::new().into(),
            operating_mode: OperatingMode::Kernel,
            cop0_registers: Arc::clone(&cop0_registers),
        };

        unsafe { BUS_PTR = &mut bus; }

        match mode {
            BusMode::HardwareFastMem => unsafe {
                hw_fastmem::init_hardware_fastmem(&mut bus);
                bus.read8 = Bus::hw_read8;
                bus.read32 = Bus::hw_read32;
                bus.read64 = Bus::hw_read64;
                bus.write8 = Bus::hw_write8;
                bus.write32 = Bus::hw_write32;
                bus.write64 = Bus::hw_write64;
            },
            BusMode::SoftwareFastMem => {
                sw_fastmem::init_software_fastmem(&mut bus);
                bus.read8 = Bus::sw_fmem_read8;
                bus.read32 = Bus::sw_fmem_read32;
                bus.read64 = Bus::sw_fmem_read64;
                bus.write8 = Bus::sw_fmem_write8;
                bus.write32 = Bus::sw_fmem_write32;
                bus.write64 = Bus::sw_fmem_write64;
            },
            BusMode::Ranged => {
                ranged::init_ranged_tlb_mappings(&mut bus);
                bus.read8 = Bus::ranged_read8;
                bus.read32 = Bus::ranged_read32;
                bus.read64 = Bus::ranged_read64;
                bus.write8 = Bus::ranged_write8;
                bus.write32 = Bus::ranged_write32;
                bus.write64 = Bus::ranged_write64;
            },
        }

        info!("Bus initialized with mode: {:?}", mode);
        bus
    }

    pub fn read_cop0_register(&self, index: usize) -> u32 {
        self.cop0_registers.read().unwrap()[index]
    }

    pub fn write_cop0_register(&mut self, index: usize, value: u32) {
        self.cop0_registers.write().unwrap()[index] = value;
    }

    pub fn read_cop0_asid(&self) -> u8 {
        let entry_hi = self.read_cop0_register(10); // COP0.EntryHi
        (entry_hi & 0xFF) as u8
    }

    pub fn io_write32(&mut self, addr: u32, value: u32) {
        match addr {
            0xB000F100 | 0xB000F110 | 0xB000F120 | 0xB000F130 |
            0xB000F140 | 0xB000F150 | 0xB000F180 | 0xB000F1C0 => {
                self.sio.write(addr, value);
            }
            0xB000F500 => {
                debug!("Memory controller (?) 32-bit write");
            }
            _ => {
                panic!("Invalid IO write32: addr=0x{:08X}, value=0x{:08X}", addr, value);
            }
        }
    }

    pub fn io_read32(&mut self, addr: u32) -> u32 {
        panic!("Invalid IO read32: addr=0x{:08X}", addr);
    }
}