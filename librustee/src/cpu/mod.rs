use std::sync::{Arc, Mutex};

pub trait CPU {
    type RegisterType;

    fn pc(&self) -> u32;
    fn set_pc(&mut self, value: u32);

    fn read_register(&self, index: usize) -> Self::RegisterType;
    fn read_hi(&self) -> Self::RegisterType;
    fn read_lo(&self) -> Self::RegisterType;
    fn read_register8(&self, index: usize) -> u8;
    fn read_register32(&self, index: usize) -> u32;
    fn read_register64(&self, index: usize) -> u64;
    fn write_hi0(&mut self, value: u64);
    fn write_hi(&mut self, value: Self::RegisterType);
    fn write_lo0(&mut self, value: u64);
    fn write_lo(&mut self, value: Self::RegisterType);
    fn write_register(&mut self, index: usize, value: Self::RegisterType);
    fn write_register32(&mut self, index: usize, value: u32);
    fn write_register64(&mut self, index: usize, value: u64);

    fn read_cop0_register(&self, index: usize) -> u32;
    fn write_cop0_register(&mut self, index: usize, value: u32);

    fn write8(&mut self, addr: u32, value: u8);
    fn write16(&mut self, addr: u32, value: u16);
    fn write32(&mut self, addr: u32, value: u32);
    fn write64(&mut self, addr: u32, value: u64);
    fn read8(&mut self, addr: u32) -> u8;
    fn read16(&mut self, addr: u32) -> u16;
    fn read32(&mut self, addr: u32) -> u32;
    fn read64(&mut self, addr: u32) -> u64;
    fn read32_raw(&mut self, addr: u32) -> u32;

    fn fetch(&mut self) -> u32;
    fn fetch_at(&mut self, addr: u32) -> u32;

    fn add_breakpoint(&mut self, addr: u32);
    fn remove_breakpoint(&mut self, addr: u32);
    fn has_breakpoint(&self, addr: u32) -> bool;
}

pub trait EmulationBackend<C> {
    fn step(&mut self);
    fn run(&mut self);
    fn run_for_cycles(&mut self, cycles: u64) -> u64;

    fn get_cpu(&self) -> Arc<Mutex<C>>;
}
