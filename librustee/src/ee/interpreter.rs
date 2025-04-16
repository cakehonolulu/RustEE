use crate::cpu::EmulationBackend;
use crate::ee::EE;

pub struct Interpreter {
    pub cpu: EE,
}

impl Interpreter {
    pub fn new(cpu: EE) -> Self {
        Interpreter { cpu }
    }
}

impl EmulationBackend<EE> for Interpreter {
    fn step(&mut self) {
        todo!();
    }

    fn run(&mut self) {
        loop {
            self.step();
        }
    }
}