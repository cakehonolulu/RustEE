pub mod bios;

use bios::BIOS;
use tracing::info;

use std::ptr::null_mut;
use std::sync::atomic::AtomicUsize;

mod ranged;
mod sw_fastmem;
mod hw_fastmem;

use crate::ee::EE;

#[cfg(unix)]
use unix::install_handler;
#[cfg(windows)]
use windows::install_handler;

#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod windows;

static mut BUS_PTR: *mut Bus = null_mut();

static HW_BASE:   AtomicUsize = AtomicUsize::new(0);
static HW_LENGTH: AtomicUsize = AtomicUsize::new(0);

#[derive(PartialEq, Debug)]
pub enum BusMode {
    SoftwareFastMem,
    Ranged,
    HardwareFastMem,
}

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

const PAGE_BITS:    usize = 12;                    // 4 KiB pages
const PAGE_SIZE:    usize = 1 << PAGE_BITS;        // 4096
const NUM_PAGES:    usize = 1 << (32 - PAGE_BITS); // 4 GiB / 4 KiB = 1 048 576

pub struct Bus {
    bios: BIOS,
    ram: Vec<u8>,

    pub read_cop0: fn(index: usize, cop0: &[u32; 32]) -> u32,
    pub write_cop0: fn(index: usize, value: u32, cop0: &mut [u32; 32]),

    page_read:  Vec<usize>,
    page_write: Vec<usize>,

    hw_base: *mut u8,
    hw_size: usize,
    arena: Option<region::Allocation>,

    // Function pointers for read/write operations
    pub read32: fn(&Bus, u32) -> u32,
    pub write32: fn(&mut Bus, u32, u32),
}

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
            arena: None,
            read_cop0: EE::read_cop0_static,
            write_cop0: EE::write_cop0_static,
        };

        unsafe { BUS_PTR = &mut bus; }

        match mode {
            BusMode::HardwareFastMem => unsafe {
                hw_fastmem::init_hardware_fastmem(&mut bus);
                bus.read32 = Bus::hw_read32;
                bus.write32 = Bus::hw_write32;
            },
            BusMode::SoftwareFastMem => {
                sw_fastmem::init_software_fastmem(&mut bus);
                bus.read32 = Bus::sw_fmem_read32;
                bus.write32 = Bus::sw_fmem_write32;
            },
            BusMode::Ranged => {
                bus.read32 = Bus::ranged_read32;
                bus.write32 = Bus::ranged_write32;
            },
        }

        info!("Bus initialized with mode: {:?}", mode);
        bus
    }

    pub fn read_cop0_register(&self, index: usize, cop0: &[u32; 32]) -> u32 {
        (self.read_cop0)(index, cop0)
    }

    pub fn write_cop0_register(&mut self, index: usize, value: u32, cop0: &mut [u32; 32]) {
        (self.write_cop0)(index, value, cop0);
    }
}