use crate::cpu::EmulationBackend;
use crate::ee::EE;

pub struct JIT {
    pub cpu: EE,
}

impl JIT {
    pub fn new(cpu: EE) -> Self {
        JIT { cpu }
    }
}

impl EmulationBackend<EE> for JIT {
    fn step(&mut self) {
        self.cpu.jit_step();
    }

    fn run(&mut self) {
        loop {
            self.step();
        }
    }
}