use super::{Bus, PAGE_BITS, PAGE_SIZE, map, tlb::mask_to_page_size};
use crate::bus::tlb::{AccessType, TlbEntry};
use tracing::debug;

#[inline(always)]
fn fast_read<T: Copy>(host: usize, offset: usize) -> T {
    unsafe { (host as *const u8).add(offset).cast::<T>().read_unaligned() }
}

#[inline(always)]
fn fast_write<T: Copy>(host: usize, offset: usize, val: T) {
    unsafe {
        (host as *mut u8)
            .add(offset)
            .cast::<T>()
            .write_unaligned(val)
    }
}

macro_rules! fmem_read {
    ($self:ident, $va:ident, $T:ty, $io_fn:ident) => {{
        let page = ($va as usize) >> PAGE_BITS;
        let offset = ($va as usize) & (PAGE_SIZE - 1);
        let host = $self.page_read[page];

        if host != 0 {
            fast_read::<$T>(host, offset)
        } else {
            if let Some(sp_offset) = map::SCRATCHPAD.contains($va) {
                return fast_read::<$T>($self.scratchpad.as_ptr() as usize, sp_offset as usize);
            }

            let cop0_asid = $self.read_cop0_asid();
            let operating_mode = $self.operating_mode;
            let pa = $self
                .tlb
                .translate_address($va, AccessType::WriteDoubleword, operating_mode, cop0_asid)
                .unwrap_or_else(|_e| $va);
            $self.$io_fn(pa)
        }
    }};
}

macro_rules! fmem_write {
    ($self:ident, $va:ident, $val:ident, $T:ty, $io_fn:ident) => {{
        let page = ($va as usize) >> PAGE_BITS;
        let offset = ($va as usize) & (PAGE_SIZE - 1);
        let host = $self.page_write[page];

        if host != 0 {
            fast_write::<$T>(host, offset, $val)
        } else {
            if let Some(sp_offset) = map::SCRATCHPAD.contains($va) {
                fast_write::<$T>(
                    $self.scratchpad.as_mut_ptr() as usize,
                    sp_offset as usize,
                    $val,
                );
                return;
            }

            let cop0_asid = $self.read_cop0_asid();
            let operating_mode = $self.operating_mode;
            let pa = $self
                .tlb
                .translate_address($va, AccessType::WriteDoubleword, operating_mode, cop0_asid)
                .unwrap_or_else(|_e| $va);
            $self.$io_fn(pa, $val)
        }
    }};
}

pub fn init_software_fastmem(bus: &mut Bus) {
    debug!("Initializing Software Fast Memory...");
    bus.page_read.fill(0);
    bus.page_write.fill(0);
    debug!("Software Fast Memory tables cleared");

    let default_mappings = [
        TlbEntry {
            vpn2: 0x0000_0000 >> 13,
            asid: 0,
            g: true,
            pfn0: 0x0000_0000 >> 12,
            pfn1: 0x0010_0000 >> 12,
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
            vpn2: 0x1FC0_0000 >> 13,
            asid: 0,
            g: true,
            pfn0: 0x1FC0_0000 >> 12,
            pfn1: 0x1FD0_0000 >> 12,
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
        TlbEntry {
            vpn2: 0x7000_0000 >> 13,
            asid: 0,
            g: true,
            pfn0: 0x7000_0000 >> 12,
            pfn1: 0,
            v0: true,
            d0: true,
            v1: false,
            d1: false,
            s0: false,
            s1: false,
            c0: 0,
            c1: 0,
            mask: 0x0000_6000,
        },
    ];

    for (index, entry) in default_mappings.iter().enumerate() {
        bus.write_tlb_entry(index, *entry);
        debug!("Installed SW-FMEM TLB mapping: {:?}", entry);
    }

    let ram_size: usize = 32 * 1024 * 1024;

    let ram_start_va_k0: usize = 0x8000_0000;
    for vpn in (ram_start_va_k0 >> PAGE_BITS)..((ram_start_va_k0 + ram_size) >> PAGE_BITS) {
        let offset = (vpn << PAGE_BITS) - ram_start_va_k0;
        let host = bus.ram.as_ptr() as usize + offset;
        bus.page_read[vpn] = host;
        bus.page_write[vpn] = host;
    }

    let ram_start_va_k1: usize = 0xA000_0000;
    for vpn in (ram_start_va_k1 >> PAGE_BITS)..((ram_start_va_k1 + ram_size) >> PAGE_BITS) {
        let offset = (vpn << PAGE_BITS) - ram_start_va_k1;
        let host = bus.ram.as_ptr() as usize + offset;
        bus.page_read[vpn] = host;
        bus.page_write[vpn] = host;
    }

    let bios_size: usize = 4 * 1024 * 1024;

    let bios_start_va_k0: usize = 0x9FC0_0000;
    for vpn in (bios_start_va_k0 >> PAGE_BITS)..((bios_start_va_k0 + bios_size) >> PAGE_BITS) {
        let offset = (vpn << PAGE_BITS) - bios_start_va_k0;
        bus.page_read[vpn] = bus.bios.bytes.as_ptr() as usize + offset;
        bus.page_write[vpn] = 0; // BIOS is read-only
    }

    let bios_start_va_k1: usize = 0xBFC0_0000;
    for vpn in (bios_start_va_k1 >> PAGE_BITS)..((bios_start_va_k1 + bios_size) >> PAGE_BITS) {
        let offset = (vpn << PAGE_BITS) - bios_start_va_k1;
        bus.page_read[vpn] = bus.bios.bytes.as_ptr() as usize + offset;
        bus.page_write[vpn] = 0; // BIOS is read-only
    }

    debug!("Software Fast Memory initialized with predefined TLB mappings.");
}

impl Bus {
    pub fn sw_fmem_read8(&mut self, va: u32) -> u8 {
        fmem_read!(self, va, u8, io_read8)
    }
    pub fn sw_fmem_read16(&mut self, va: u32) -> u16 {
        fmem_read!(self, va, u16, io_read16)
    }
    pub fn sw_fmem_read32(&mut self, va: u32) -> u32 {
        fmem_read!(self, va, u32, io_read32)
    }
    pub fn sw_fmem_read64(&mut self, va: u32) -> u64 {
        fmem_read!(self, va, u64, io_read64)
    }
    pub fn sw_fmem_read128(&mut self, va: u32) -> u128 {
        fmem_read!(self, va, u128, io_read128)
    }

    pub fn sw_fmem_write8(&mut self, va: u32, value: u8) {
        fmem_write!(self, va, value, u8, io_write8)
    }
    pub fn sw_fmem_write16(&mut self, va: u32, value: u16) {
        fmem_write!(self, va, value, u16, io_write16)
    }
    pub fn sw_fmem_write32(&mut self, va: u32, value: u32) {
        fmem_write!(self, va, value, u32, io_write32)
    }
    pub fn sw_fmem_write64(&mut self, va: u32, value: u64) {
        fmem_write!(self, va, value, u64, io_write64)
    }
    pub fn sw_fmem_write128(&mut self, va: u32, value: u128) {
        fmem_write!(self, va, value, u128, io_write128)
    }
}

pub fn install_sw_fastmem_mapping(bus: &mut Bus, entry: &TlbEntry) {
    let page_size = mask_to_page_size(entry.mask) as u64;
    let start_va = (entry.vpn2 as u64) << 13;

    let mut map_pages = |valid: bool, pfn: u64, dirty: bool, page_start_va: u64| {
        if !valid {
            return;
        }
        let start_vpn = (page_start_va >> 12) as usize;
        let end_vpn = ((page_start_va + page_size) >> 12) as usize;

        for vpn in start_vpn..end_vpn {
            let offset = ((vpn as u64 * 4096) - page_start_va) & (page_size - 1);
            let pa = (pfn << 12) + offset;

            let (read_host, write_host) = if let Some(roff) = map::RAM.contains(pa as u32) {
                let host = bus.ram.as_ptr() as usize + roff as usize;
                (host, if dirty { host } else { 0 })
            } else if let Some(boff) = map::BIOS.contains(pa as u32) {
                let host = bus.bios.bytes.as_ptr() as usize + boff as usize;
                (host, 0) // BIOS is always read-only
            } else if let Some(soff) = map::SCRATCHPAD.contains(pa as u32) {
                let host = bus.scratchpad.as_ptr() as usize + soff as usize;
                (host, if dirty { host } else { 0 })
            } else if let Some(voff) = map::VU0.contains(pa as u32) {
                let host = if (pa as u32) < 0x1100_1000 {
                    bus.vu0_data.as_ptr() as usize + voff as usize
                } else {
                    bus.vu0_code.as_ptr() as usize + (voff as usize - 0x1000)
                };
                (host, if dirty { host } else { 0 })
            } else if let Some(voff) = map::VU1.contains(pa as u32) {
                let host = if (pa as u32) < 0x1100_C000 {
                    bus.vu1_data.as_ptr() as usize + voff as usize
                } else {
                    bus.vu1_code.as_ptr() as usize + (voff as usize - 0x4000)
                };
                (host, if dirty { host } else { 0 })
            } else {
                (0, 0)
            };

            bus.page_read[vpn] = read_host;
            bus.page_write[vpn] = write_host;
        }
    };

    map_pages(entry.v0, entry.pfn0 as u64, entry.d0, start_va);
    map_pages(entry.v1, entry.pfn1 as u64, entry.d1, start_va + page_size);
}

pub fn clear_sw_fastmem_mapping(bus: &mut Bus, entry: &TlbEntry) {
    let page_size = mask_to_page_size(entry.mask) as u64;
    let start_va = (entry.vpn2 as u64) << 13;
    let start_vpn = (start_va >> 12) as usize;
    let end_vpn = ((start_va + 2 * page_size) >> 12) as usize;

    for vpn in start_vpn..end_vpn {
        bus.page_read[vpn] = 0;
        bus.page_write[vpn] = 0;
    }
}
