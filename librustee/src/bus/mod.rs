pub mod bios;

use bios::BIOS;
use tracing::info;

mod map {
    pub struct Range(u32, u32);

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

    pub const BIOS: Range = Range(0xBFC00000, (1024 * 1024) * 4);
    pub const RAM: Range = Range(0x0, 32 * 1024 * 1024); // 32MB RAM
}

#[derive(PartialEq, Debug)]
pub enum BusMode {
    SoftwareFastMem,
    Ranged,
}

const PAGE_BITS:    usize = 12;                    // 4 KiB pages
const PAGE_SIZE:    usize = 1 << PAGE_BITS;        // 4096
const NUM_PAGES:    usize = 1 << (32 - PAGE_BITS); // 4 GiB / 4 KiB = 1 048 576

#[derive(Copy, Clone)]
enum PageOwner {
    Ram(usize),
    Bios(usize),
}

#[derive(Clone)]
pub struct Bus {
    bios: BIOS,
    ram: Vec<u8>,

    page_read:  Vec<Option<PageOwner>>,
    page_write: Vec<Option<PageOwner>>,

    // Function pointers for read/write operations
    pub read32: fn(&Bus, u32) -> u32,
    pub write32: fn(&mut Bus, u32, u32),
}

impl Bus {
    pub fn new(mode: BusMode, bios: BIOS) -> Bus {
        let mut bus = Bus {
            bios,
            ram: vec![0; 32 * 1024 * 1024],
            page_read:  vec![None; NUM_PAGES],
            page_write: vec![None; NUM_PAGES],
            read32:  Bus::sw_fmem_read32,
            write32: Bus::sw_fmem_write32,
        };

        (bus.read32, bus.write32) = match mode {
            BusMode::SoftwareFastMem => (
                Bus::sw_fmem_read32 as fn(&Bus, u32) -> u32,
                Bus::sw_fmem_write32 as fn(&mut Bus, u32, u32),
            ),
            BusMode::Ranged => (
                Bus::ranged_read32 as fn(&Bus, u32) -> u32,
                Bus::ranged_write32 as fn(&mut Bus, u32, u32),
            ),
        };

        if mode == BusMode::SoftwareFastMem {
            // map RAM pages for both read & write
            let ram_pages = bus.ram.len() / PAGE_SIZE;
            for page in 0..ram_pages {
                let owner = PageOwner::Ram(page);
                bus.page_read[page]  = Some(owner);
                bus.page_write[page] = Some(owner);
            }

            // map BIOS pages read-only
            let bios_pages = bus.bios.bytes.len() / PAGE_SIZE;
            let base = (0xBFC0_0000_usize) >> PAGE_BITS;
            for i in 0..bios_pages {
                bus.page_read[base + i] = Some(PageOwner::Bios(i));
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
        match self.page_read[page] {
            Some(PageOwner::Ram(p)) => {
                let start = p * PAGE_SIZE + offset;
                let slice = &self.ram[start..start + 4];
                u32::from_le_bytes(slice.try_into().unwrap())
            }
            Some(PageOwner::Bios(p)) => {
                let start = p * PAGE_SIZE + offset;
                let slice = &self.bios.bytes[start..start + 4];
                u32::from_le_bytes(slice.try_into().unwrap())
            }
            None => {
                panic!("SoftwareFastMem: Unhandled 32-bit read from address 0x{:08X}", address);
            }
        }
    }

    fn sw_fmem_write32(&mut self, address: u32, value: u32) {
        let page   = (address as usize) >> PAGE_BITS;
        let offset = (address as usize) & (PAGE_SIZE - 1);
        match self.page_write[page] {
            Some(PageOwner::Ram(p)) => {
                let start = p * PAGE_SIZE + offset;
                let bytes = value.to_le_bytes();
                self.ram[start..start + 4].copy_from_slice(&bytes);
            }
            _ => {
                panic!("SoftwareFastMem: Unhandled 32-bit write to address 0x{:08X}", address);
            }
        }
    }
}