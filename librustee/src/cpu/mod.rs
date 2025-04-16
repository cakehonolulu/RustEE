pub trait CPU {
    type RegisterType;

    fn pc(&self) -> u32;
    fn set_pc(&mut self, value: u32);

    fn read_register(&self, index: usize) -> Self::RegisterType;
    fn write_register(&mut self, index: usize, value: Self::RegisterType);

    fn read_cop0_register(&self, index: usize) -> u32;
    fn write_cop0_register(&mut self, index: usize, value: u32);

    fn read32(&self, addr: u32) -> u32;

    fn fetch(&self) -> u32;
    fn fetch_at(&self, addr: u32) -> u32;
    fn decode_execute(&self, opcode: u32);

    fn add_breakpoint(&mut self, addr: u32);
    fn remove_breakpoint(&mut self, addr: u32);
    fn has_breakpoint(&self, addr: u32) -> bool;
}

pub trait EmulationBackend<C> {
    fn step(&mut self);

    fn run(&mut self);
}