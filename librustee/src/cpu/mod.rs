use std::sync::{Arc, Mutex};

pub trait CPU {
    type RegisterType;

    fn pc(&self) -> u32;
    fn set_pc(&mut self, value: u32);

    fn read_register(&self, index: usize) -> Self::RegisterType;
    fn write_register(&mut self, index: usize, value: Self::RegisterType);

    fn read_cop0_register(&self, index: usize) -> u32;
    fn write_cop0_register(&mut self, index: usize, value: u32);

    fn read32(&mut self, addr: u32) -> u32;

    fn fetch(&mut self) -> u32;
    fn fetch_at(&mut self, addr: u32) -> u32;

    fn add_breakpoint(&mut self, addr: u32);
    fn remove_breakpoint(&mut self, addr: u32);
    fn has_breakpoint(&self, addr: u32) -> bool;
}

pub trait EmulationBackend<C> {
    fn step(&mut self);
    fn run(&mut self);
    fn run_for_cycles(&mut self, cycles: u32);

    fn get_cpu(&self) -> Arc<Mutex<C>>;
}