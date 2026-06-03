pub mod codegen;
pub mod golden;
pub mod opcodes;
pub mod ps2;
pub mod runner;

use crate::{
    BIOS,
    bus::{Bus, BusMode},
    ee::EE,
    sched::Scheduler,
};
use portable_atomic::AtomicU32;
use std::sync::{Arc, Mutex};

pub use golden::GoldenStore;
pub use runner::TestRunner;

#[derive(Clone, Debug)]
pub struct RegInit {
    pub reg: usize,
    pub val: u128,
}

impl RegInit {
    pub const fn gpr(reg: usize, val: u128) -> Self {
        Self { reg, val }
    }
}

#[derive(Clone, Debug)]
pub struct RegExpect {
    pub reg: usize,
    pub val: u128,
}

impl RegExpect {
    pub const fn gpr(reg: usize, val: u128) -> Self {
        Self { reg, val }
    }
}

#[derive(Clone, Debug)]
pub struct OpcodeTestSpec {
    pub name: &'static str,
    pub family: &'static str,
    pub asm: &'static str,
    pub init_gpr: Vec<RegInit>,
    pub init_hi: Option<u128>,
    pub init_lo: Option<u128>,
    pub expected_gpr: Vec<RegExpect>,
    pub expected_hi: Option<u128>,
    pub expected_lo: Option<u128>,
    pub expected_mem: Vec<(u32, u32)>,
    pub expected_pc: Option<u32>,
}

#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct GoldenState {
    pub pc: u32,
    pub gpr: [u128; 32],
    pub fpr: [u32; 32],
    pub cop0: [u32; 32],
    pub lo: u128,
    pub hi: u128,
    pub memory_checks: Vec<(u32, u32)>,
}

impl GoldenState {
    pub fn from_spec(spec: &OpcodeTestSpec) -> Self {
        let mut g = GoldenState::default();
        g.cop0[15] = 0x59;
        for r in &spec.expected_gpr {
            g.gpr[r.reg] = r.val;
        }
        if let Some(hi) = spec.expected_hi {
            g.hi = hi;
        }
        if let Some(lo) = spec.expected_lo {
            g.lo = lo;
        }
        if let Some(pc) = spec.expected_pc {
            g.pc = pc;
        }
        g.memory_checks = spec.expected_mem.clone();
        g
    }
}

pub fn make_bios(asm: &str) -> BIOS {
    let assembler = mipsasm::Mipsasm::new();
    let words = assembler.assemble(asm).expect("mipsasm assembly failed");
    let bytes: Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
    BIOS::test_only(bytes)
}

pub fn insn_count(asm: &str) -> usize {
    asm.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#') && !l.starts_with("//"))
        .count()
}

pub fn make_ee(bios: BIOS, mode: BusMode) -> (EE, Arc<Mutex<Bus>>) {
    let cop0: Arc<[AtomicU32; 32]> = Arc::new(std::array::from_fn(|_| AtomicU32::new(0)));
    let sched = Arc::new(Mutex::new(Scheduler::new()));
    let bus_boxed = Bus::new(mode, bios, Arc::clone(&cop0), sched);
    let bus = Arc::new(Mutex::new(*bus_boxed));
    let ee = EE::new(Arc::clone(&cop0));
    (ee, bus)
}
