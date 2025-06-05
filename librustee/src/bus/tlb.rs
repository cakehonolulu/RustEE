
use super::{Bus, BusMode};

#[derive(Clone, Copy, Debug)]
pub struct TlbEntry {
    pub vpn2: u32,        // Virtual Page Number / 2
    pub asid: u8,         // Address Space Identifier
    pub g: bool,          // Global bit
    pub pfn0: u32,        // Page Frame Number (even page)
    pub pfn1: u32,        // Page Frame Number (odd page)
    pub c0: u8,           // Cache mode (even page)
    pub c1: u8,           // Cache mode (odd page)
    pub d0: bool,         // Dirty bit (write permission, even)
    pub d1: bool,         // Dirty bit (write permission, odd)
    pub v0: bool,         // Valid bit (even)
    pub v1: bool,         // Valid bit (odd)
    pub s0: bool,         // Scratchpad RAM flag (even)
    pub s1: bool,         // Scratchpad RAM flag (odd)
    pub mask: u32,        // Page size mask
}

#[derive(Clone, Copy, Debug)]
pub enum OperatingMode {
    User,
    Supervisor,
    Kernel,
}

#[derive(Clone, Copy, Debug)]
pub enum AccessType {
    Read,
    Write,
}

#[derive(Clone, Copy, Debug)]
pub enum Exception {
    TlbRefill,
    TlbInvalid,
    TlbModified,
    AddressError,
}


pub struct Tlb {
    pub entries: [Option<TlbEntry>; 48],
    pub index: u32,
    pub random: u32,
    pub wired: u32,
    pub entry_hi: u32,
    pub entry_lo0: u32,
    pub entry_lo1: u32,
    pub page_mask: u32,
    pub context: u32,
    pub bad_vaddr: u32,
}

pub fn mask_to_page_size(mask: u32) -> u32 {
    match mask {
        0x0000_0000 => 4 * 1024,        // 4 KB
        0x0000_6000 => 16 * 1024,       // 16 KB
        0x0001_E000 => 64 * 1024,       // 64 KB
        0x0007_E000 => 256 * 1024,      // 256 KB
        0x001F_E000 => 1024 * 1024,     // 1 MB
        0x007F_E000 => 4 * 1024 * 1024, // 4 MB
        0x01FF_E000 => 16 * 1024 * 1024,// 16 MB
        _ => 4 * 1024,                  // Default to 4 KB
    }
}

impl Tlb {
    pub fn new() -> Self {
        Tlb {
            entries: [None; 48],
            index: 0,
            random: 47,
            wired: 0,
            entry_hi: 0,
            entry_lo0: 0,
            entry_lo1: 0,
            page_mask: 0,
            context: 0,
            bad_vaddr: 0,
        }
    }

    pub fn translate_address(
        &mut self,
        va: u32,
        access_type: AccessType,
        mode: OperatingMode,
        current_asid: u8,
    ) -> Result<u32, Exception> {
        // Check address alignment
        if va & 0x3 != 0 {
            self.bad_vaddr = va;
            return Err(Exception::AddressError);
        }

        // Segment-based direct mapping
        match mode {
            OperatingMode::Kernel => {
                if va >= 0x8000_0000 && va < 0xA000_0000 {
                    // kseg0: cached, direct-mapped
                    return Ok(va - 0x8000_0000);
                } else if va >= 0xA000_0000 && va < 0xC000_0000 {
                    // kseg1: uncached, direct-mapped
                    return Ok(va - 0xA000_0000);
                }
            }
            OperatingMode::Supervisor => {
                if va >= 0xC000_0000 && va < 0xE000_0000 {
                    // sseg: TLB-mapped
                } else if va < 0x8000_0000 {
                    // useg: TLB-mapped
                } else {
                    self.bad_vaddr = va;
                    return Err(Exception::AddressError);
                }
            }
            OperatingMode::User => {
                if va < 0x8000_0000 {
                    // useg: TLB-mapped
                } else {
                    self.bad_vaddr = va;
                    return Err(Exception::AddressError);
                }
            }
        }

        // TLB lookup for mapped segments
        let mut matched_entry = None;
        let mut entry_index = 0;

        for (i, entry) in self.entries.iter().enumerate() {
            if let Some(e) = entry {
                let page_size = mask_to_page_size(e.mask);
                let vpn_mask = !(page_size - 1);
                let va_vpn = va & vpn_mask;
                let entry_vpn = (e.vpn2 << 13) & vpn_mask;

                if va_vpn == entry_vpn && (e.g || e.asid == current_asid) {
                    matched_entry = Some(e);
                    entry_index = i;
                    break;
                }
            }
        }

        if let Some(entry) = matched_entry {
            let page_size = mask_to_page_size(entry.mask);
            let is_odd = (va & page_size) != 0;
            let (pfn, v, d) = if is_odd {
                (entry.pfn1, entry.v1, entry.d1)
            } else {
                (entry.pfn0, entry.v0, entry.d0)
            };

            if !v {
                self.bad_vaddr = va;
                self.context = (va & 0xFFFF_E000) | (entry_index as u32);
                return Err(Exception::TlbInvalid);
            }

            if let AccessType::Write = access_type {
                if !d {
                    self.bad_vaddr = va;
                    self.context = (va & 0xFFFF_E000) | (entry_index as u32);
                    return Err(Exception::TlbModified);
                }
            }

            let offset_mask = page_size - 1;
            let offset = va & offset_mask;
            let pa = (pfn << 12) | offset;
            Ok(pa)
        } else {
            self.bad_vaddr = va;
            self.context = va & 0xFFFF_E000;
            Err(Exception::TlbRefill)
        }
    }

    pub fn write_tlb_entry(&mut self, bus_ptr: *mut Bus, index: usize, entry: TlbEntry) {
        let bus = unsafe { &mut *bus_ptr };

        if let Some(old_entry) = self.entries[index] {
            if bus.mode == BusMode::HardwareFastMem {
                self.clear_hw_fastmem_mapping(bus, &old_entry);
            }
            else if bus.mode == BusMode::SoftwareFastMem {
                self.clear_sw_fastmem_mapping(bus, &old_entry);
            }
        }

        self.entries[index] = Some(entry);

        if bus.mode == BusMode::HardwareFastMem {
            self.install_hw_fastmem_mapping(bus, &entry);
        } else if bus.mode == BusMode::SoftwareFastMem {
            self.install_sw_fastmem_mapping(bus, &entry);
        }
    }
}