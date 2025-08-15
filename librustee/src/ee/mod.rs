/*
    MIPS R5900 Emotion Engine CPU
*/

use crate::Bus;
use crate::cpu::CPU;
use crate::ee::vu::VU;
use std::collections::HashSet;
use std::ptr;
use std::sync::{Arc, Mutex, RwLock};
use std::sync::atomic::{AtomicBool, Ordering};

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
use portable_atomic::{AtomicU128, AtomicU32};
pub use interpreter::Interpreter;
pub use jit::JIT;
use tracing::{error, info};

const EE_RESET_VEC: u32 = 0xBFC00000;

#[derive(Copy, Clone)]
struct UnsafeSend<T>(T);
unsafe impl<T> Send for UnsafeSend<T> {}

pub struct EE {
    bus: Arc<Mutex<Box<Bus>>>,
    pub pc: Arc<AtomicU32>,
    pub registers: Arc<[AtomicU128; 32]>,
    pub cop0_registers: Arc<[AtomicU32; 32]>,
    pub lo: Arc<AtomicU128>,
    pub hi: Arc<AtomicU128>,
    breakpoints: HashSet<u32>,
    pub fpu_registers: Arc<[AtomicU32; 32]>,
    vu0: VU,
    vu1: VU,
    pub sideload_elf: bool,
    elf_entry_point: u32,
    pub elf_path: String,
    pub is_paused: Arc<AtomicBool>,
    bus_ptr: UnsafeSend<*mut Bus>,
}

impl Clone for EE {
    fn clone(&self) -> EE {
        EE {
            bus: Arc::clone(&self.bus),
            pc: self.pc.clone(),
            registers: Arc::clone(&self.registers),
            cop0_registers: Arc::clone(&self.cop0_registers),
            lo: self.lo.clone(),
            hi: self.hi.clone(),
            breakpoints: self.breakpoints.clone(),
            fpu_registers: self.fpu_registers.clone(),
            vu0: self.vu0.clone(),
            vu1: self.vu1.clone(),
            sideload_elf: self.sideload_elf,
            elf_entry_point: self.elf_entry_point,
            elf_path: self.elf_path.clone(),
            is_paused: self.is_paused.clone(),
            bus_ptr: self.bus_ptr,
        }
    }
}

impl EE {
    pub fn new(bus: Arc<Mutex<Box<Bus>>>, cop0_registers: Arc<[AtomicU32; 32]>) -> Self {
        cop0_registers[15].store(0x59, Ordering::Relaxed);

        let registers = Arc::new(std::array::from_fn(|_| AtomicU128::new(0u128)));
        let fpu_registers = Arc::new(std::array::from_fn(|_| AtomicU32::new(0)));

        let mut ee = EE {
            pc: Arc::new(AtomicU32::new(EE_RESET_VEC)),
            registers,
            cop0_registers,
            lo: Arc::new(AtomicU128::new(0u128)),
            hi: Arc::new(AtomicU128::new(0u128)),
            bus,
            breakpoints: HashSet::new(),
            fpu_registers,
            vu0: VU::new(4 * 1024, 4 * 1024),
            vu1: VU::new(16 * 1024, 16 * 1024),
            sideload_elf: false,
            elf_entry_point: 0,
            elf_path: "".to_string(),
            is_paused: Arc::new(AtomicBool::new(true)),
            bus_ptr: UnsafeSend(ptr::null_mut()),
        };

        {
            let bus_ptr = &mut **ee.bus.lock().unwrap() as *mut Bus;
            ee.bus_ptr = UnsafeSend(bus_ptr);
        }

        ee
    }

    pub fn read_fpu_register_as_u32(&self, index: usize) -> u32 {
        self.fpu_registers[index].load(Ordering::Relaxed)
    }

    pub fn read_fpu_register_as_f32(&self, index: usize) -> f32 {
        f32::from_bits(self.fpu_registers[index].load(Ordering::Relaxed))
    }

    pub fn write_fpu_register_from_u32(&mut self, index: usize, value: u32) {
        self.fpu_registers[index].store(value, Ordering::Relaxed)
    }

    pub fn write_fpu_register_from_f32(&mut self, index: usize, value: f32) {
        self.fpu_registers[index].store(value.to_bits(), Ordering::Relaxed)
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
        self.pc.load(Ordering::Relaxed)
    }

    fn set_pc(&mut self, value: u32) {
        self.pc.store(value, Ordering::Relaxed);
    }

    fn read_register(&self, index: usize) -> Self::RegisterType {
        self.registers[index].load(Ordering::Relaxed)
    }

    fn read_hi(&self) -> Self::RegisterType {
        self.hi.load(Ordering::Relaxed)
    }

    fn read_lo(&self) -> Self::RegisterType {
        self.lo.load(Ordering::Relaxed)
    }

    fn read_register8(&self, index: usize) -> u8 {
        self.registers[index].load(Ordering::Relaxed) as u8
    }

    fn read_register32(&self, index: usize) -> u32 {
        self.registers[index].load(Ordering::Relaxed) as u32
    }

    fn read_register64(&self, index: usize) -> u64 {
        self.registers[index].load(Ordering::Relaxed) as u64
    }

    fn write_hi0(&mut self, low: u64) {
        let mut hi = self.hi.load(Ordering::SeqCst);
        let high_mask = !((1u128 << 64) - 1);
        self.hi.store((hi & high_mask) | (low as u128), Ordering::Relaxed);
    }

    fn write_hi(&mut self, value: Self::RegisterType) {
        self.hi.store(value, Ordering::Relaxed);
    }

    fn write_lo0(&mut self, low: u64) {
        let mut lo = self.lo.load(Ordering::SeqCst);
        let high_mask = !((1u128 << 64) - 1);
        self.lo.store((lo & high_mask) | (low as u128), Ordering::Relaxed);
    }

    fn write_lo(&mut self, value: Self::RegisterType) {
        self.lo.store(value, Ordering::Relaxed);
    }

    fn write_register(&mut self, index: usize, value: Self::RegisterType) {
        self.registers[index].store(value, Ordering::Relaxed);
    }

    fn write_register32(&mut self, index: usize, value: u32) {
        let upper_bits = self.registers[index].load(Ordering::SeqCst) & 0xFFFFFFFF_FFFFFFFF_00000000_00000000;
        self.registers[index].store(upper_bits | (value as u128), Ordering::Relaxed);
    }

    fn write_register64(&mut self, index: usize, value: u64) {
        let upper_bits = self.registers[index].load(Ordering::SeqCst) & 0xFFFFFFFF_FFFFFFFF_00000000_00000000;
        self.registers[index].store(upper_bits | (value as u128), Ordering::Relaxed);
    }

    fn read_cop0_register(&self, index: usize) -> u32 {
        self.cop0_registers[index].load(Ordering::Relaxed)
    }
    fn write_cop0_register(&mut self, index: usize, value: u32) {
        self.cop0_registers[index].store(value, Ordering::Relaxed);
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
        unsafe { ((*self.bus_ptr.0).read32)(&mut *self.bus_ptr.0, self.pc.load(Ordering::SeqCst)) }
    }

    #[inline(always)]
    fn fetch_at(&mut self, address: u32) -> u32 {
        unsafe { ((*self.bus_ptr.0).read32)(&mut *self.bus_ptr.0, address) }
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

unsafe impl Send for EE {}

#[cfg(test)]
mod test;
