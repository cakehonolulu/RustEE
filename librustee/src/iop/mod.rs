/*
    MIPS R3000A IOP CPU
*/

use std::collections::HashSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use crate::Bus;
use crate::cpu::CPU;

const IOP_RESET_VEC: u32 = 0xBFC00000;

pub struct IOP {
    pub pc: Arc<AtomicU32>,
    pub registers: Arc<[AtomicU32; 32]>,
    pub cop0_registers: Arc<[AtomicU32; 32]>,
    pub lo: Arc<AtomicU32>,
    pub hi: Arc<AtomicU32>,
    breakpoints: HashSet<u32>,
}

impl IOP {
    pub fn new(cop0_registers: Arc<[AtomicU32; 32]>) -> Self {
        let registers = Arc::new(std::array::from_fn(|_| AtomicU32::new(0u32)));

        IOP {
            pc: Arc::new(AtomicU32::new(IOP_RESET_VEC)),
            registers,
            cop0_registers,
            lo: Arc::new(AtomicU32::new(0u32)),
            hi: Arc::new(AtomicU32::new(0u32)),
            breakpoints: HashSet::new(),
        }
    }
}

impl CPU for IOP {
    type RegisterType = u32;

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
        self.registers[index].load(Ordering::Relaxed)
    }

    fn write_hi(&mut self, value: Self::RegisterType) {
        self.hi.store(value, Ordering::Relaxed);
    }

    fn write_lo(&mut self, value: Self::RegisterType) {
        self.lo.store(value, Ordering::Relaxed);
    }

    fn write_register(&mut self, index: usize, value: Self::RegisterType) {
        self.registers[index].store(value, Ordering::Relaxed);
    }

    fn write_register32(&mut self, index: usize, value: u32) {
        self.registers[index].store(value, Ordering::Relaxed);
    }

    fn read_cop0_register(&self, index: usize) -> u32 {
        self.cop0_registers[index].load(Ordering::Relaxed)
    }

    fn write_cop0_register(&mut self, index: usize, value: u32) {
        self.cop0_registers[index].store(value, Ordering::Relaxed);
    }

    fn write8(&mut self, bus: &mut Bus, addr: u32, value: u8) {
        (bus.write8)(bus, addr, value);
    }

    fn write16(&mut self, bus: &mut Bus, addr: u32, value: u16) {
        (bus.write16)(bus, addr, value);
    }

    fn write32(&mut self, bus: &mut Bus, addr: u32, value: u32) {
        (bus.write32)(bus, addr, value);
    }

    fn read8(&mut self, bus: &mut Bus, addr: u32) -> u8 {
        (bus.read8)(bus, addr)
    }

    fn read16(&mut self, bus: &mut Bus, addr: u32) -> u16 {
        (bus.read16)(bus, addr)
    }

    fn read32(&mut self, bus: &mut Bus, addr: u32) -> u32 {
        (bus.read32)(bus, addr)
    }

    fn read32_raw(&mut self, bus: &mut Bus, addr: u32) -> u32 {
        todo!()
    }

    #[inline(always)]
    fn fetch(&self, bus: &mut Bus) -> u32 {
        (bus.read32)(bus, self.pc.load(Ordering::SeqCst))
    }

    #[inline(always)]
    fn fetch_at(&self, bus: &mut Bus, address: u32) -> u32 {
        (bus.read32)(bus, address)
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
