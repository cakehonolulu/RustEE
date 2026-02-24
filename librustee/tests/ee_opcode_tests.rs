/// Usage:
///   cargo test # emulator
///   PS2_IP=192.168.1.x cargo test # hardware
use librustee::testing::{TestRunner, opcodes, runner::TestResult};

fn runner() -> TestRunner {
    TestRunner::new(env!("CARGO_MANIFEST_DIR"))
}

fn run_family(name: &str, specs: Vec<librustee::testing::OpcodeTestSpec>) {
    let r = runner();
    let mut failures: Vec<(&'static str, Vec<String>)> = Vec::new();
    let mut n_skipped = 0usize;

    for spec in &specs {
        match r.run(spec) {
            TestResult::Passed => {
                println!("  ✓ {}", spec.name);
            }
            TestResult::Skipped(msg) => {
                println!("  ⚠ {} — {msg}", spec.name);
                n_skipped += 1;
            }
            TestResult::Failed(errs) => {
                println!("  ✗ {}", spec.name);
                for e in &errs {
                    println!("      {e}");
                }
                failures.push((spec.name, errs));
            }
        }
    }

    if n_skipped > 0 {
        println!(
            "[{name}] {n_skipped}/{} skipped — run with PS2_IP to capture hardware goldens",
            specs.len()
        );
    }

    if !failures.is_empty() {
        let detail: String = failures
            .iter()
            .flat_map(|(n, errs)| {
                std::iter::once(format!("\n  {n}:"))
                    .chain(errs.iter().map(|e| format!("    • {e}")))
            })
            .collect();
        panic!("[{name}] {} test(s) FAILED:{detail}", failures.len());
    }
}

#[test]
fn test_and() {
    run_family("AND", opcodes::and());
}
