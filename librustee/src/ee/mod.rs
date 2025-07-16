/*
    MIPS R5900 Emotion Engine CPU
*/

use crate::Bus;
use crate::cpu::CPU;
use crate::ee::vu::VU;
use std::collections::HashSet;
use std::sync::{Arc, Mutex, RwLock};

pub mod dmac;
pub mod intc;
pub mod interpreter;
pub mod jit;
pub mod sio;
pub mod timer;
pub mod vu;

use crate::bus::map;
use crate::bus::tlb::AccessType;
use goblin::elf::Elf;
use goblin::elf::program_header::PT_LOAD;
pub use interpreter::Interpreter;
pub use jit::JIT;
use tracing::{error, info};

const EE_RESET_VEC: u32 = 0xBFC00000;

pub struct EE {
    bus: Arc<Mutex<Box<Bus>>>,
    pub pc: u32,
    pub registers: [u128; 32],
    pub cop0_registers: Arc<RwLock<[u32; 32]>>,
    pub lo: u128,
    pub hi: u128,
    breakpoints: HashSet<u32>,
    pub fpu_registers: [u32; 32],
    vu0: VU,
    vu1: VU,
    pub sideload_elf: bool,
    elf_entry_point: u32,
    pub elf_path: String,
}

impl Clone for EE {
    fn clone(&self) -> EE {
        EE {
            bus: Arc::clone(&self.bus),
            pc: self.pc,
            registers: self.registers.clone(),
            cop0_registers: Arc::clone(&self.cop0_registers),
            lo: self.lo,
            hi: self.hi,
            breakpoints: self.breakpoints.clone(),
            fpu_registers: self.fpu_registers.clone(),
            vu0: self.vu0.clone(),
            vu1: self.vu1.clone(),
            sideload_elf: self.sideload_elf,
            elf_entry_point: self.elf_entry_point,
            elf_path: self.elf_path.clone(),
        }
    }
}

impl EE {
    pub fn new(bus: Arc<Mutex<Box<Bus>>>, cop0_registers: Arc<RwLock<[u32; 32]>>) -> Self {
        cop0_registers.write().unwrap()[15] = 0x59;

        let ee = EE {
            pc: EE_RESET_VEC,
            registers: [0; 32],
            cop0_registers,
            lo: 0,
            hi: 0,
            bus,
            breakpoints: HashSet::new(),
            fpu_registers: [0; 32],
            vu0: VU::new(4 * 1024, 4 * 1024),
            vu1: VU::new(16 * 1024, 16 * 1024),
            sideload_elf: false,
            elf_entry_point: 0,
            elf_path: "".to_string(),
        };

        ee
    }

    pub fn read_fpu_register_as_u32(&self, index: usize) -> u32 {
        self.fpu_registers[index]
    }

    pub fn read_fpu_register_as_f32(&self, index: usize) -> f32 {
        f32::from_bits(self.fpu_registers[index])
    }

    pub fn write_fpu_register_from_u32(&mut self, index: usize, value: u32) {
        self.fpu_registers[index] = value;
    }

    pub fn write_fpu_register_from_f32(&mut self, index: usize, value: f32) {
        self.fpu_registers[index] = value.to_bits();
    }

    pub fn load_elf(&mut self, elf_data: &[u8]) {
        // Parse ELF
        let elf = match Elf::parse(elf_data) {
            Ok(e) => e,
            Err(e) => {
                error!("Failed to parse ELF: {:?}", e);
                return;
            }
        };

        info!(
            "ELF parsed: entry=0x{:08X}, {} program headers",
            elf.header.e_entry,
            elf.program_headers.len()
        );

        // Grab a mutable reference to RAM once
        let mut bus = self.bus.lock().unwrap();

        // Iterate all PT_LOAD segments
        for (i, phdr) in elf.program_headers.iter().enumerate() {
            if phdr.p_type != PT_LOAD {
                continue;
            }

            let paddr = phdr.p_paddr as usize;
            let filesz = phdr.p_filesz as usize;
            let memsz = phdr.p_memsz as usize;
            let offset = phdr.p_offset as usize;

            info!(
                "Segment {}: p_paddr=0x{:08X}, filesz=0x{:X}, memsz=0x{:X}, offset=0x{:X}",
                i, phdr.p_paddr, filesz, memsz, phdr.p_offset
            );

            // Bounds check
            if paddr + memsz > bus.ram.len() {
                error!(
                    "Segment {} out of RAM bounds: paddr=0x{:08X}, memsz=0x{:X}",
                    i, phdr.p_paddr, memsz
                );
                continue;
            }

            // Zero entire memsz region (covers BSS)
            for i in paddr..(paddr + memsz) {
                (bus.write8)(&mut bus, i as u32, 0);
            }

            // Copy file data
            if offset + filesz <= elf_data.len() {
                let data = &elf_data[offset..offset + filesz];

                for (i, &b) in data.iter().enumerate() {
                    (bus.write8)(&mut bus, (paddr + i) as u32, b);
                }

                info!(
                    "  → loaded 0x{:X} bytes into RAM[0x{:08X}..]",
                    filesz, paddr
                );
            } else {
                error!(
                    "Segment {} offset+filesz out of bounds: offset=0x{:X}, filesz=0x{:X}",
                    i, phdr.p_offset, filesz
                );
            }
        }

        let entry_point = elf.header.e_entry as u32;

        if entry_point as usize >= bus.ram.len() {
            error!("ELF entry point 0x{:08X} exceeds RAM bounds", entry_point);
            return;
        }

        self.elf_entry_point = entry_point;
        info!(
            "ELF entry point set to physical address 0x{:08X}",
            entry_point
        );
    }
}

impl CPU for EE {
    type RegisterType = u128;

    fn pc(&self) -> u32 {
        self.pc
    }

    fn set_pc(&mut self, value: u32) {
        self.pc = value;
    }

    fn read_register(&self, index: usize) -> Self::RegisterType {
        self.registers[index]
    }

    fn read_hi(&self) -> Self::RegisterType {
        self.hi
    }

    fn read_lo(&self) -> Self::RegisterType {
        self.lo
    }

    fn read_register8(&self, index: usize) -> u8 {
        self.registers[index] as u8
    }

    fn read_register32(&self, index: usize) -> u32 {
        self.registers[index] as u32
    }

    fn read_register64(&self, index: usize) -> u64 {
        self.registers[index] as u64
    }

    fn write_hi0(&mut self, low: u64) {
        let high_mask = !((1u128 << 64) - 1);
        self.hi = (self.hi & high_mask) | (low as u128);
    }

    fn write_hi(&mut self, value: Self::RegisterType) {
        self.hi = value;
    }

    fn write_lo0(&mut self, low: u64) {
        let high_mask = !((1u128 << 64) - 1);
        self.lo = (self.lo & high_mask) | (low as u128);
    }

    fn write_lo(&mut self, value: Self::RegisterType) {
        self.lo = value;
    }

    fn write_register(&mut self, index: usize, value: Self::RegisterType) {
        self.registers[index] = value;
    }

    fn write_register32(&mut self, index: usize, value: u32) {
        let upper_bits = self.registers[index] & 0xFFFFFFFF_FFFFFFFF_00000000_00000000;
        self.registers[index] = upper_bits | (value as u128);
    }

    fn write_register64(&mut self, index: usize, value: u64) {
        let upper_bits = self.registers[index] & 0xFFFFFFFF_FFFFFFFF_00000000_00000000;
        self.registers[index] = upper_bits | (value as u128);
    }

    fn read_cop0_register(&self, index: usize) -> u32 {
        self.cop0_registers.read().unwrap()[index]
    }
    fn write_cop0_register(&mut self, index: usize, value: u32) {
        self.cop0_registers.write().unwrap()[index] = value;
    }

    fn write8(&mut self, addr: u32, value: u8) {
        let mut bus = self.bus.lock().unwrap();
        (bus.write8)(&mut *bus, addr, value)
    }

    fn write16(&mut self, addr: u32, value: u16) {
        let mut bus = self.bus.lock().unwrap();
        (bus.write16)(&mut *bus, addr, value)
    }

    fn write32(&mut self, addr: u32, value: u32) {
        let mut bus = self.bus.lock().unwrap();
        (bus.write32)(&mut *bus, addr, value)
    }

    fn write64(&mut self, addr: u32, value: u64) {
        let mut bus = self.bus.lock().unwrap();
        (bus.write64)(&mut *bus, addr, value)
    }

    fn read8(&mut self, addr: u32) -> u8 {
        let mut bus = self.bus.lock().unwrap();
        (bus.read8)(&mut *bus, addr)
    }

    fn read16(&mut self, addr: u32) -> u16 {
        let mut bus = self.bus.lock().unwrap();
        (bus.read16)(&mut *bus, addr)
    }

    fn read32(&mut self, addr: u32) -> u32 {
        let mut bus = self.bus.lock().unwrap();
        (bus.read32)(&mut *bus, addr)
    }

    fn read64(&mut self, addr: u32) -> u64 {
        let mut bus = self.bus.lock().unwrap();
        (bus.read64)(&mut *bus, addr)
    }

    fn read32_raw(&mut self, addr: u32) -> u32 {
        let bus = self.bus.lock().unwrap();
        let pa = match bus.tlb.borrow_mut().translate_address(
            addr,
            AccessType::ReadWord,
            bus.operating_mode,
            bus.read_cop0_asid(),
        ) {
            Ok(pa) => pa,
            Err(_) => return 0,
        };

        if let Some(offset) = map::RAM.contains(pa) {
            let ptr = unsafe { bus.ram.as_ptr().add(offset as usize) } as *const u32;
            unsafe { ptr.read_unaligned() }
        } else if map::IO.contains(pa).is_some() {
            0
        } else if let Some(offset) = map::BIOS.contains(pa) {
            let ptr = unsafe { bus.bios.bytes.as_ptr().add(offset as usize) } as *const u32;
            unsafe { ptr.read_unaligned() }
        } else {
            0
        }
    }

    #[inline(always)]
    fn fetch(&mut self) -> u32 {
        let mut bus = self.bus.lock().unwrap();
        (bus.read32)(&mut *bus, self.pc)
    }

    #[inline(always)]
    fn fetch_at(&mut self, address: u32) -> u32 {
        let mut bus = self.bus.lock().unwrap();
        (bus.read32)(&mut *bus, address)
    }

    fn add_breakpoint(&mut self, addr: u32) {
        self.breakpoints.insert(addr);
    }

    fn remove_breakpoint(&mut self, addr: u32) {
        self.breakpoints.remove(&addr);
    }

    fn has_breakpoint(&self, addr: u32) -> bool {
        self.breakpoints.contains(&addr)
    }
}

#[cfg(test)]
mod test;
