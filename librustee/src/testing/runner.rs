use std::path::PathBuf;

use crate::{
    bus::BusMode,
    cpu::{CPU, EmulationBackend},
    ee::{EE, Interpreter, JIT},
    testing::{
        GoldenState, OpcodeTestSpec, codegen, golden::GoldenStore, insn_count, make_bios, make_ee,
        ps2,
    },
};

#[derive(Debug)]
pub enum TestResult {
    Passed,
    Skipped(String),
    Failed(Vec<String>),
}

impl TestResult {
    pub fn is_pass(&self) -> bool {
        matches!(self, TestResult::Passed)
    }
    pub fn is_skip(&self) -> bool {
        matches!(self, TestResult::Skipped(_))
    }

    pub fn unwrap_or_panic(self) {
        if let TestResult::Failed(errs) = self {
            panic!(
                "Test failed:\n{}",
                errs.iter()
                    .map(|e| format!("  • {e}"))
                    .collect::<Vec<_>>()
                    .join("\n")
            );
        }
    }
}

pub struct TestRunner {
    store: GoldenStore,
    gen_dir: PathBuf,
    modes: Vec<BusMode>,
}

impl TestRunner {
    pub fn new(manifest_dir: &str) -> Self {
        Self {
            store: GoldenStore::new(manifest_dir),
            gen_dir: PathBuf::from(manifest_dir)
                .join("ps2_tests")
                .join("generated"),
            modes: vec![
                BusMode::Ranged,
                BusMode::SoftwareFastMem,
                BusMode::HardwareFastMem,
            ],
        }
    }

    pub fn run(&self, spec: &OpcodeTestSpec) -> TestResult {
        if let Some(ip) = ps2::ps2_ip() {
            if let Err(e) = self.capture_from_hardware(spec, &ip) {
                eprintln!("[hw-capture] {}: {e}", spec.name);
            }
        }

        let golden: Option<GoldenState> = self.store.load(spec.family, spec.name).or_else(|| {
            let has_expected = !spec.expected_gpr.is_empty()
                || spec.expected_hi.is_some()
                || spec.expected_lo.is_some()
                || !spec.expected_mem.is_empty()
                || spec.expected_pc.is_some();
            if has_expected {
                Some(GoldenState::from_spec(spec))
            } else {
                None
            }
        });

        if golden.is_none() {
            return TestResult::Skipped(format!(
                "{}: no golden — run with PS2_IP or add expected_* to spec",
                spec.name
            ));
        }
        let golden = golden.unwrap();

        let mut errors = Vec::new();
        let n = insn_count(spec.asm);

        for mode in &self.modes {
            let tag = format!("[{mode:?}]");

            let (mut ee_i, _bus_i) = make_ee(make_bios(spec.asm), mode.clone());
            apply_init(&mut ee_i, spec);
            ee_i.set_pc(0xBFC00000);
            let mut interp = Interpreter::new(ee_i);
            for _ in 0..n {
                interp.step();
            }

            let (mut ee_j, _bus_j) = make_ee(make_bios(spec.asm), mode.clone());
            apply_init(&mut ee_j, spec);
            ee_j.set_pc(0xBFC00000);
            let mut jit = JIT::new(ee_j);
            for _ in 0..n {
                jit.step();
            }

            diff_vs_golden(&tag, "interp", &interp.cpu, &golden, spec, &mut errors);
            diff_vs_golden(&tag, "jit", &jit.cpu, &golden, spec, &mut errors);
            diff_backends(&tag, &interp.cpu, &jit.cpu, &mut errors);
        }

        if errors.is_empty() {
            TestResult::Passed
        } else {
            TestResult::Failed(errors)
        }
    }

    fn capture_from_hardware(&self, spec: &OpcodeTestSpec, ip: &str) -> Result<(), String> {
        codegen::write_framework(&self.gen_dir).map_err(|e| format!("write_framework: {e}"))?;

        let result_path = self.gen_dir.join(format!("golden_{}.bin", spec.name));
        let cwd = std::env::current_dir().map_err(|e| format!("getcwd: {e}"))?;
        let rel_result = result_path.strip_prefix(&cwd).unwrap_or(&result_path);
        let host_result_path = format!(
            "host:{}",
            rel_result
                .to_str()
                .ok_or("result path contains non-UTF8 characters")?
        );

        let _c_file = codegen::generate_c(spec, &self.gen_dir, &host_result_path)
            .map_err(|e| format!("generate_c: {e}"))?;

        let mk_file = codegen::generate_makefile(spec, &self.gen_dir)
            .map_err(|e| format!("generate_makefile: {e}"))?;

        let elf = ps2::compile_elf(&mk_file, spec.name)?;
        let golden = ps2::run_on_hardware(&elf, spec.name, ip, &result_path)?;

        self.store
            .save(spec.family, spec.name, &golden)
            .map_err(|e| format!("golden cache write: {e}"))?;

        println!("[hw] captured golden for {}", spec.name);
        Ok(())
    }
}

fn apply_init(ee: &mut EE, spec: &OpcodeTestSpec) {
    use crate::cpu::CPU;
    for r in &spec.init_gpr {
        ee.write_register(r.reg, r.val);
    }
    if let Some(hi) = spec.init_hi {
        ee.write_hi(hi);
    }
    if let Some(lo) = spec.init_lo {
        ee.write_lo(lo);
    }
}

const GPR_NAMES: [&str; 32] = [
    "zero", "at", "v0", "v1", "a0", "a1", "a2", "a3", "t0", "t1", "t2", "t3", "t4", "t5", "t6",
    "t7", "s0", "s1", "s2", "s3", "s4", "s5", "s6", "s7", "t8", "t9", "k0", "k1", "gp", "sp", "fp",
    "ra",
];

fn diff_vs_golden(
    tag: &str,
    backend: &str,
    ee: &EE,
    golden: &GoldenState,
    spec: &OpcodeTestSpec,
    errors: &mut Vec<String>,
) {
    use crate::cpu::CPU;

    for exp in &spec.expected_gpr {
        let got = ee.read_register(exp.reg);
        let want = golden.gpr[exp.reg];
        if got != want {
            errors.push(format!(
                "{tag} {backend}: ${} = 0x{got:032X} ≠ golden 0x{want:032X}",
                GPR_NAMES[exp.reg]
            ));
        }
    }

    if spec.expected_hi.is_some() {
        let got = ee.read_hi();
        if got != golden.hi {
            errors.push(format!(
                "{tag} {backend}: HI = 0x{got:032X} ≠ golden 0x{:032X}",
                golden.hi
            ));
        }
    }
    if spec.expected_lo.is_some() {
        let got = ee.read_lo();
        if got != golden.lo {
            errors.push(format!(
                "{tag} {backend}: LO = 0x{got:032X} ≠ golden 0x{:032X}",
                golden.lo
            ));
        }
    }
}

fn diff_backends(tag: &str, interp: &EE, jit: &EE, errors: &mut Vec<String>) {
    use crate::cpu::CPU;

    if interp.pc() != jit.pc() {
        errors.push(format!(
            "{tag} interp/jit PC mismatch: 0x{:08X} ≠ 0x{:08X}",
            interp.pc(),
            jit.pc()
        ));
    }
    for i in 0..32 {
        let a = interp.read_register(i);
        let b = jit.read_register(i);
        if a != b {
            errors.push(format!(
                "{tag} interp/jit ${}: 0x{a:032X} ≠ 0x{b:032X}",
                GPR_NAMES[i]
            ));
        }
    }
    let (a, b) = (interp.read_hi(), jit.read_hi());
    if a != b {
        errors.push(format!("{tag} interp/jit HI: 0x{a:032X} ≠ 0x{b:032X}"));
    }
    let (a, b) = (interp.read_lo(), jit.read_lo());
    if a != b {
        errors.push(format!("{tag} interp/jit LO: 0x{a:032X} ≠ 0x{b:032X}"));
    }
}
