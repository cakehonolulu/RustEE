pub mod bios;

use bios::BIOS;
use tracing::{debug, info};

#[cfg(unix)]
use std::os::fd::OwnedFd;
#[cfg(windows)]
use std::os::windows::raw::HANDLE;
use std::sync::atomic::AtomicUsize;
use std::sync::{Arc, RwLock};
use std::{cell::RefCell, ptr::null_mut};

pub mod backpatch;
mod hw_fastmem;
mod ranged;
mod rdram;
mod sw_fastmem;
pub mod tlb;

use crate::ee::dmac::EE_Dmac;
use crate::ee::intc::INTC;
use crate::ee::sio::SIO;
use crate::ee::timer::Timers;
use crate::gif::GIF;
use crate::gs::GS;
use crate::ipu::IPU;
use crate::sif::SIF;
use crate::vif::{VIF, VIF0_BASE, VIF1_BASE};

use tlb::{OperatingMode, Tlb};

use crate::bus::rdram::RDRAM;
#[cfg(unix)]
use unix::install_handler;
#[cfg(windows)]
use windows::install_handler;

#[cfg(unix)]
pub mod unix;
#[cfg(windows)]
mod windows;

pub(crate) static mut BUS_PTR: *mut Bus = std::ptr::null_mut();

static HW_BASE: AtomicUsize = AtomicUsize::new(0);
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
    pub const RAM: Range = Range(0x0000_0000, 32 * 1024 * 1024);
    pub const IO: Range = Range(0x1000_0000, 64 * 1024);
    pub const BIOS: Range = Range(0x1FC0_0000, 4 * 1024 * 1024);
    pub const SCRATCHPAD: Range = Range(0x7000_0000, 16 * 1024);
}

const PAGE_BITS: usize = 12; // 4 KiB pages
const PAGE_SIZE: usize = 1 << PAGE_BITS; // 4096
const NUM_PAGES: usize = 1 << (32 - PAGE_BITS); // 4 GiB / 4 KiB = 1 048 576

pub struct Bus {
    pub(crate) bios: BIOS,
    pub ram: Vec<u8>,
    pub iop_ram: Vec<u8>,
    vu0_code: Vec<u8>, // 4 KB VU0 code
    vu0_data: Vec<u8>, // 4 KB VU0 data
    vu1_code: Vec<u8>, // 16 KB VU1 code
    vu1_data: Vec<u8>, // 16 KB VU1 data
    pub(crate) scratchpad: Vec<u8>,

    pub tlb: RefCell<Tlb>,
    pub(crate) operating_mode: OperatingMode,

    #[cfg(unix)]
    ram_fd: Option<OwnedFd>,

    #[cfg(windows)]
    ram_mapping: Option<HANDLE>,

    pub sio: SIO,
    rdram: RDRAM,
    ee_intc: INTC,
    ee_timer: Timers,
    ee_dmac: EE_Dmac,
    sif: SIF,
    gif: GIF,
    gs: GS,
    vif0: VIF,
    vif1: VIF,
    ipu: IPU,

    mode: BusMode,

    page_read: Vec<usize>,
    page_write: Vec<usize>,

    hw_base: *mut u8,
    hw_size: usize,
    arena: Option<region::Allocation>,

    pub cop0_registers: Arc<RwLock<[u32; 32]>>,

    dev9_delay3: u32,

    // Function pointers for read/write operations
    pub read8: fn(&mut Self, u32) -> u8,
    pub read16: fn(&mut Self, u32) -> u16,
    pub read32: fn(&mut Self, u32) -> u32,
    pub read64: fn(&mut Self, u32) -> u64,
    pub read128: fn(&mut Self, u32) -> u128,
    pub write8: fn(&mut Self, u32, u8),
    pub write16: fn(&mut Self, u32, u16),
    pub write32: fn(&mut Self, u32, u32),
    pub write64: fn(&mut Self, u32, u64),
    pub write128: fn(&mut Self, u32, u128),
}

unsafe impl Send for Bus {}

impl Bus {
    pub fn new(mode: BusMode, bios: BIOS, cop0_registers: Arc<RwLock<[u32; 32]>>) -> Box<Bus> {
        let mut bus = Box::new(Bus {
            bios,
            ram: vec![0; 32 * 1024 * 1024],
            scratchpad: vec![0; 16 * 1024],
            iop_ram: vec![0; 2 * 1024 * 1024],
            vu0_code: vec![0; 4 * 1024],
            vu0_data: vec![0; 4 * 1024],
            vu1_code: vec![0; 16 * 1024],
            vu1_data: vec![0; 16 * 1024],
            page_read: vec![0; NUM_PAGES],
            page_write: vec![0; NUM_PAGES],
            sio: SIO::new(),
            rdram: RDRAM::new(),
            ee_intc: INTC::new(),
            ee_timer: Timers::new(),
            ee_dmac: EE_Dmac::new(),
            sif: SIF::new(),
            gif: GIF::new(),
            gs: GS::new(),
            vif0: VIF::new(VIF0_BASE),
            vif1: VIF::new(VIF1_BASE),
            ipu: IPU::new(),
            mode: mode.clone(),
            dev9_delay3: 0,
            read8: Bus::sw_fmem_read8,
            read16: Bus::sw_fmem_read16,
            read32: Bus::sw_fmem_read32,
            read64: Bus::sw_fmem_read64,
            read128: Bus::sw_fmem_read128,
            write8: Bus::sw_fmem_write8,
            write16: Bus::sw_fmem_write16,
            write32: Bus::sw_fmem_write32,
            write64: Bus::sw_fmem_write64,
            write128: Bus::sw_fmem_write128,
            hw_base: null_mut(),
            hw_size: 0,
            arena: None,
            tlb: Tlb::new().into(),
            operating_mode: OperatingMode::Kernel,
            cop0_registers: Arc::clone(&cop0_registers),
            #[cfg(unix)]
            ram_fd: None,
            #[cfg(windows)]
            ram_mapping: None,
        });

        match mode {
            BusMode::HardwareFastMem => unsafe {
                hw_fastmem::init_hardware_fastmem(&mut bus);
                bus.read8 = Bus::hw_read8;
                bus.read16 = Bus::hw_read16;
                bus.read32 = Bus::hw_read32;
                bus.read64 = Bus::hw_read64;
                bus.read128 = Bus::hw_read128;
                bus.write8 = Bus::hw_write8;
                bus.write16 = Bus::hw_write16;
                bus.write32 = Bus::hw_write32;
                bus.write64 = Bus::hw_write64;
                bus.write128 = Bus::hw_write128;
            },
            BusMode::SoftwareFastMem => {
                sw_fastmem::init_software_fastmem(&mut bus);
                bus.read8 = Bus::sw_fmem_read8;
                bus.read16 = Bus::sw_fmem_read16;
                bus.read32 = Bus::sw_fmem_read32;
                bus.read64 = Bus::sw_fmem_read64;
                bus.read128 = Bus::sw_fmem_read128;
                bus.write8 = Bus::sw_fmem_write8;
                bus.write16 = Bus::sw_fmem_write16;
                bus.write32 = Bus::sw_fmem_write32;
                bus.write64 = Bus::sw_fmem_write64;
                bus.write128 = Bus::sw_fmem_write128;
            }
            BusMode::Ranged => {
                ranged::init_ranged_tlb_mappings(&mut bus);
                bus.read8 = Bus::ranged_read8;
                bus.read16 = Bus::ranged_read16;
                bus.read32 = Bus::ranged_read32;
                bus.read64 = Bus::ranged_read64;
                bus.read128 = Bus::ranged_read128;
                bus.write8 = Bus::ranged_write8;
                bus.write16 = Bus::ranged_write16;
                bus.write32 = Bus::ranged_write32;
                bus.write64 = Bus::ranged_write64;
                bus.write128 = Bus::ranged_write128;
            }
        }

        unsafe {
            BUS_PTR = &mut *bus as *mut Bus;
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

    pub fn io_write8(&mut self, mut addr: u32, value: u8) {
        addr &= 0x1FFFFFFF;
        match addr {
            0x1000F180 => {
                self.sio.write(addr, value);
            }
            _ => {
                panic!(
                    "Invalid IO write8: addr=0x{:08X}, value=0x{:02X}",
                    addr, value
                );
            }
        }
    }

    pub fn io_write16(&mut self, mut addr: u32, value: u16) {
        addr &= 0x1FFFFFFF;
        match addr {
            0x1F801470 | 0x1F801472 => {}
            0x1A000006 | 0x1A000008 => {}
            _ => {
                panic!(
                    "Invalid IO write16: addr=0x{:08X}, value=0x{:08X}",
                    addr, value
                );
            }
        }
    }

    pub fn io_write32(&mut self, mut addr: u32, value: u32) {
        addr &= 0x1FFFFFFF;
        match addr {
            0x10000000..=0x10001830 => {
                self.ee_timer.write32(addr, value);
            }
            0x10002000 | 0x10002010 => {
                self.ipu.write32(addr, value);
            }
            0x10003000 => {
                self.gif.write32(addr, value);
            }
            0x10003810 | 0x10003820 | 0x10003830 => {
                self.vif0.write32(addr, value);
            }
            0x10003C00 | 0x10003C10 => {
                self.vif1.write32(addr, value);
            }
            0x10008000..=0x1000D4FF => {
                self.ee_dmac.write_register(addr, value);
            }
            0x1000E000..=0x1000E050 => {
                self.ee_dmac.write_register(addr, value);
            }
            0x1000F000 | 0x1000F010 => {
                self.ee_intc.write32(addr, value);
            }
            0x1000F100 | 0x1000F110 | 0x1000F120 | 0x1000F130 | 0x1000F140 | 0x1000F150
            | 0x1000F180 | 0x1000F1C0 => {
                self.sio.write(addr, value);
            }
            0x1000F200 | 0x1000F210 | 0x1000F220 | 0x1000F230 | 0x1000F240 | 0x1000F260 => {
                self.sif.write32(addr, value);
            }
            0x1000F400 | 0x1000F410 | 0x1000F420 => {}
            0x1000F430 | 0x1000F440 => {
                self.rdram.write(addr, value);
            }
            0x1000F450 | 0x1000F460 => {}
            0x1000F480 => {}
            0x1000F490 => {}
            0x1000F500 => {
                debug!("Memory controller (?) 32-bit write");
            }
            0x1000F510 => {
                // ?
            }
            0x1000F520 | 0x1000F590 => {
                self.ee_dmac.write_register(addr, value);
            }
            0x1F80141C => self.dev9_delay3 = value,
            _ => {
                panic!(
                    "Invalid IO write32: addr=0x{:08X}, value=0x{:08X}",
                    addr, value
                );
            }
        }
    }

    pub fn io_write64(&mut self, mut addr: u32, value: u64) {
        addr &= 0x1FFFFFFF;
        match addr {
            0x12000000 | 0x12000010 | 0x12000020 | 0x12000030 | 0x12000040 | 0x12000050
            | 0x12000060 | 0x12000070 | 0x12000080 | 0x12000090 | 0x120000A0 | 0x120000B0
            | 0x120000C0 | 0x120000D0 | 0x120000E0 | 0x12001010 => self.gs.write64(addr, value),
            0x12001000 => self.gs.write64(addr, value),
            _ => {
                panic!(
                    "Invalid IO write64: addr=0x{:08X}, value=0x{:08X}",
                    addr, value
                );
            }
        }
    }

    pub fn io_write128(&mut self, mut addr: u32, value: u128) {
        addr &= 0x1FFFFFFF;
        match addr {
            0x10004000 => {
                // TODO: VIF0 FIFO
            }
            0x10005000 => {
                // TODO: VIF1 FIFO
            }
            0x10006000 => {
                // TODO: Gif FIFO
            }
            0x10007010 => {
                // TODO: Ifu FIFO
            }
            _ => {
                panic!(
                    "Invalid IO write128: addr=0x{:08X}, value=0x{:08X}",
                    addr, value
                );
            }
        }
    }

    pub fn io_read8(&mut self, mut addr: u32) -> u8 {
        addr &= 0x1FFFFFFF;
        match addr {
            _ => {
                panic!("Invalid IO read8: addr=0x{:08X}", addr);
            }
        }
    }

    pub fn io_read16(&mut self, mut addr: u32) -> u16 {
        addr &= 0x1FFFFFFF;
        match addr {
            0x1F803800 => 0,
            _ => {
                panic!("Invalid IO read16: addr=0x{:08X}", addr);
            }
        }
    }

    pub fn io_read32(&mut self, mut addr: u32) -> u32 {
        addr &= 0x1FFFFFFF;
        match addr {
            0x10002000 | 0x10002010 => self.ipu.read32(addr),
            0x10003020 => self.gif.read32(addr),
            0x10008000..=0x1000D4FF => self.ee_dmac.read_register(addr),
            0x1000E000..=0x1000E050 => self.ee_dmac.read_register(addr),
            0x1000F000 | 0x1000F010 => self.ee_intc.read32(addr),
            0x1000F130 => self.sio.read(addr),
            0x1000F200 | 0x1000F210 | 0x1000F220 | 0x1000F230 | 0x1000F240 | 0x1000F260 => {
                self.sif.read32(addr)
            }
            0x1000F400 | 0x1000F410 => 0,
            0x1000F430 | 0x1000F440 => self.rdram.read(addr),
            0x1000F520 | 0x1000F590 => self.ee_dmac.read_register(addr),
            0x1C0003C0 => 0,
            0x1F80141C => self.dev9_delay3,
            _ => {
                panic!("Invalid IO read32: addr=0x{:08X}", addr);
            }
        }
    }

    pub fn io_read64(&mut self, mut addr: u32) -> u64 {
        addr &= 0x1FFFFFFF;
        match addr {
            0x12000000 | 0x12001000 => self.gs.read64(addr),
            _ => {
                panic!("Invalid IO read64: addr=0x{:08X}", addr);
            }
        }
    }

    pub fn io_read128(&mut self, mut addr: u32) -> u128 {
        addr &= 0x1FFFFFFF;
        match addr {
            _ => {
                panic!("Invalid IO read128: addr=0x{:08X}", addr);
            }
        }
    }
}
