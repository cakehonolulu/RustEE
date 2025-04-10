use crate::cpu::EmulationBackend;
use crate::ee::EE;

pub struct EEJIT {
    pub cpu: EE,
}

impl EEJIT {
    pub fn new(cpu: EE) -> Self {
        EEJIT { cpu }
    }
}

impl EmulationBackend<EE> for EEJIT {
    fn step(&mut self) {
        self.cpu.jit_step();
    }

    fn run(&mut self) {
        loop {
            self.step();
        }
    }
}