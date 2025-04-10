use crate::cpu::EmulationBackend;
use crate::ee::EE;

pub struct EEInterpreter {
    pub cpu: EE,
}

impl EEInterpreter {
    pub fn new(cpu: EE) -> Self {
        EEInterpreter { cpu }
    }
}

impl EmulationBackend<EE> for EEInterpreter {
    fn step(&mut self) {
        self.cpu.interp_step();
    }

    fn run(&mut self) {
        loop {
            self.step();
        }
    }
}