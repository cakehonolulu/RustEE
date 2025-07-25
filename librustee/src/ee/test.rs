use std::sync::{Arc, Mutex, RwLock};
use crate::{
    bus::{Bus, BusMode},
    ee::{Interpreter, JIT, EE},
    BIOS,
};
use mipsasm::Mipsasm;
use crate::cpu::{CPU, EmulationBackend};

#[derive(Debug, Default)]
struct GoldenState {
    pc:   u32,
    gpr:  [u128; 32],
    fpr:  [u32; 32],
    cop0: [u32; 32],
    lo:   u128,
    hi:   u128,
    memory_checks: Vec<(u32, u32)>,
}

fn create_mock_bios(assembly: &str) -> BIOS {
    let assembler = Mipsasm::new();
    let binary_u32 = assembler
        .assemble(assembly)
        .expect("Failed to assemble MIPS code");

    let binary_u8: Vec<u8> = binary_u32
        .iter()
        .flat_map(|word| word.to_le_bytes())
        .collect();

    BIOS::test_only(binary_u8)
}

fn count_instructions(assembly: &str) -> usize {
    // Count non-empty lines that aren't just whitespace or comments
    assembly
        .lines()
        .map(|line| line.trim())
        .filter(|line| !line.is_empty() && !line.starts_with('#') && !line.starts_with("//"))
        .count()
}

fn compare_states(
    ee_interpreter: &EE,
    ee_jit: &mut EE,
    golden:         Option<&GoldenState>,
) {
    let names = [
        "zero","at","v0","v1","a0","a1","a2","a3",
        "t0","t1","t2","t3","t4","t5","t6","t7",
        "s0","s1","s2","s3","s4","s5","s6","s7",
        "t8","t9","k0","k1","gp","sp","fp","ra",
    ];

    assert_eq!(
        ee_interpreter.pc(), ee_jit.pc(),
        "PC mismatch: interp=0x{:08X}, jit=0x{:08X}",
        ee_interpreter.pc(), ee_jit.pc(),
    );

    for i in 0..32 {
        assert_eq!(
            ee_interpreter.read_register(i),
            ee_jit.read_register(i),
            "GPR ${} mismatch: interp=0x{:X}, jit=0x{:X}",
            names[i], ee_interpreter.read_register(i), ee_jit.read_register(i),
        );
    }

    for i in 0..32 {
        assert_eq!(
            ee_interpreter.read_cop0_register(i),
            ee_jit.read_cop0_register(i),
            "COP0[{}] mismatch: interp=0x{:X}, jit=0x{:X}",
            i, ee_interpreter.read_cop0_register(i), ee_jit.read_cop0_register(i),
        );
    }

    for i in 0..32 {
        assert_eq!(
            ee_interpreter.read_fpu_register_as_u32(i),
            ee_jit.read_fpu_register_as_u32(i),
            "FPR ${} mismatch: interp=0x{:X}, jit=0x{:X}",
            names[i], ee_interpreter.read_fpu_register_as_u32(i), ee_jit.read_fpu_register_as_u32(i),
        );
    }

    if let Some(g) = golden {
        assert_eq!(
            ee_interpreter.pc(), g.pc,
            "Interpreter PC != golden (0x{:08X} != 0x{:08X})",
            ee_interpreter.pc(), g.pc,
        );
        assert_eq!(
            ee_jit.pc(), g.pc,
            "      JIT PC != golden (0x{:08X} != 0x{:08X})",
            ee_jit.pc(), g.pc,
        );

        for i in 0..32 {
            let interp_val = ee_interpreter.read_register(i);
            let jit_val    = ee_jit.read_register(i);
            let expected   = g.gpr[i].into();
            assert_eq!(
                interp_val, expected,
                "Interp GPR ${} != golden (0x{:X} != 0x{:X})",
                names[i], interp_val, expected,
            );
            assert_eq!(
                jit_val, expected,
                "    JIT GPR ${} != golden (0x{:X} != 0x{:X})",
                names[i], jit_val, expected,
            );
        }

        for i in 0..32 {
            let interp_c = ee_interpreter.read_cop0_register(i);
            let jit_c    = ee_jit.read_cop0_register(i);
            let expected = g.cop0[i];
            assert_eq!(
                interp_c, expected,
                "Interp COP0[{}] != golden (0x{:X} != 0x{:X})",
                i, interp_c, expected,
            );
            assert_eq!(
                jit_c, expected,
                "    JIT COP0[{}] != golden (0x{:X} != 0x{:X})",
                i, jit_c, expected,
            );
        }

        let interp_hi = ee_interpreter.read_hi();
        let interp_lo = ee_interpreter.read_lo();
        let jit_hi    = ee_jit.read_hi();
        let jit_lo    = ee_jit.read_lo();
        let expected_hi = g.hi;
        let expected_lo = g.lo;

        assert_eq!(
            interp_hi, expected_hi,
            "Interp HI != golden (0x{:X} != 0x{:X})",
            interp_hi, expected_hi,
        );

        assert_eq!(
            interp_lo, expected_lo,
            "Interp LO != golden (0x{:X} != 0x{:X})",
            interp_lo, expected_lo,
        );

        assert_eq!(
            jit_hi, expected_hi,
            "JIT HI != golden (0x{:X} != 0x{:X})",
            jit_hi, expected_hi,
        );

        assert_eq!(
            jit_lo, expected_lo,
            "JIT LO != golden (0x{:X} != 0x{:X})",
            jit_lo, expected_lo,
        );

        for (addr, expected) in golden.unwrap().memory_checks.iter() {
            let interp_val = ee_jit.read32(*addr);
            let jit_val = ee_jit.read32(*addr);
            assert_eq!(interp_val, *expected,
                       "Memory at 0x{:08X} mismatch for interpreter: expected 0x{:08X}, got 0x{:08X}",
                       addr, expected, interp_val);
            assert_eq!(jit_val, *expected,
                       "Memory at 0x{:08X} mismatch for JIT: expected 0x{:08X}, got 0x{:08X}",
                       addr, expected, jit_val);
        }
    }
}

struct TestCase {
    name:   &'static str,
    asm:    &'static str,
    setup:  fn(&mut EE),
    golden: Option<GoldenState>,
}

fn run_test(tc: &TestCase) {
    let bus_modes = vec![
        BusMode::Ranged,
        BusMode::SoftwareFastMem,
        BusMode::HardwareFastMem,
    ];

    // Count the number of instructions to execute
    let instruction_count = count_instructions(tc.asm);
    
    for bus_mode in bus_modes {
        println!("Running test `{}` for bus mode {:?} ({} instructions)", 
                 tc.name, bus_mode, instruction_count);

        // Create mock BIOS for both interpreter and JIT
        let bios_i = create_mock_bios(tc.asm);
        let bios_j = create_mock_bios(tc.asm);

        // Create shared cop0_registers for each EE/Bus pair
        let cop0_i = Arc::new(RwLock::new([0u32; 32]));
        let cop0_j = Arc::new(RwLock::new([0u32; 32]));

        // Create buses with the current bus mode
        let bus_i = Bus::new(bus_mode.clone(), bios_i, Arc::clone(&cop0_i));
        let bus_j = Bus::new(bus_mode.clone(), bios_j, Arc::clone(&cop0_j));

        let bus_i = Arc::new(Mutex::new(bus_i));
        let bus_j = Arc::new(Mutex::new(bus_j));

        // Create EE instances for interpreter and JIT
        let mut ee_i = EE::new(Arc::clone(&bus_i), Arc::clone(&cop0_i));
        let mut ee_j = EE::new(Arc::clone(&bus_j), Arc::clone(&cop0_j));

        // Test setup
        (tc.setup)(&mut ee_i);
        (tc.setup)(&mut ee_j);

        // Set program counters
        ee_i.set_pc(0xBFC00000);
        ee_j.set_pc(0xBFC00000);

        // Run the interpreter backend for the required number of steps
        let mut interp = Interpreter::new(ee_i);
        for _ in 0..instruction_count {
            interp.step();
        }

        // Run the JIT backend for the required number of steps
        let mut jit = JIT::new(&mut ee_j);
        for _ in 0..instruction_count {
            jit.step();
        }

        // Compare CPU states
        compare_states(&interp.cpu, jit.cpu, tc.golden.as_ref());

        println!("Test `{}` passed for bus mode {:?}", tc.name, bus_mode);
    }
}


#[test]
fn test_mfc0() {
    let tests = vec![
        TestCase {
            name: "mfc0_basic",
            asm: "mfc0 $v0, $1",
            setup: |ee| ee.write_cop0_register(1, 42),
            golden: {
                let mut g = GoldenState::default();
                g.pc = 0xBFC00004;
                g.gpr[2] = 42;
                g.cop0[1] = 42;
                g.cop0[15] = 0x59;
                Some(g)
            },
        },
        TestCase {
            name: "mfc0_zero",
            asm: "mfc0 $v0, $1",
            setup: |ee| ee.write_cop0_register(1, 0),
            golden: {
                let mut g = GoldenState::default();
                g.pc = 0xBFC00004;
                g.gpr[2] = 0;
                g.cop0[1] = 0;
                g.cop0[15] = 0x59;
                Some(g)
            },
        },
        TestCase {
            name: "mfc0_max",
            asm: "mfc0 $v0, $1",
            setup: |ee| ee.write_cop0_register(1, 0xFFFFFFFF),
            golden: {
                let mut g = GoldenState::default();
                g.pc = 0xBFC00004;
                g.gpr[2] = 0xFFFFFFFF;
                g.cop0[1] = 0xFFFFFFFF;
                g.cop0[15] = 0x59;
                Some(g)
            },
        },
    ];

    for test in tests {
        run_test(&test);
    }
}

#[test]
fn test_sll() {
    let tests = vec![
        TestCase {
            name: "sll_basic",
            asm: "sll $at, $v0, 4",
            setup: |ee| ee.write_register32(2, 0x0000000F),
            golden: {
                let mut g = GoldenState::default();
                g.pc = 0xBFC00004;
                g.gpr[2] = 0x0F;
                g.gpr[1] = 0xF0;
                g.cop0[15] = 0x59;
                Some(g)
            },
        },
        TestCase {
            name: "sll_zero",
            asm: "sll $at, $v0, 4",
            setup: |ee| ee.write_register32(2, 0),
            golden: {
                let mut g = GoldenState::default();
                g.pc = 0xBFC00004;
                g.gpr[2] = 0;
                g.gpr[1] = 0;
                g.cop0[15] = 0x59;
                Some(g)
            },
        },
        TestCase {
            name: "sll_sign_bit",
            asm: "sll $at, $v0, 1",
            setup: |ee| ee.write_register32(2, 0x80000000),
            golden: {
                let mut g = GoldenState::default();
                g.pc = 0xBFC00004;
                g.gpr[2] = 0x80000000;
                g.gpr[1] = 0;
                g.cop0[15] = 0x59;
                Some(g)
            },
        },
        TestCase {
            name: "sll_no_shift",
            asm: "sll $at, $v0, 0",
            setup: |ee| ee.write_register32(2, 0xFF),
            golden: {
                let mut g = GoldenState::default();
                g.pc = 0xBFC00004;
                g.gpr[2] = 0xFF;
                g.gpr[1] = 0xFF;
                g.cop0[15] = 0x59;
                Some(g)
            },
        },
        TestCase {
            name: "sll_max_shift",
            asm: "sll $at, $v0, 31",
            setup: |ee| ee.write_register32(2, 1),
            golden: {
                let mut g = GoldenState::default();
                g.pc = 0xBFC00004;
                g.gpr[2] = 1;
                g.gpr[1] = 0xFFFFFFFF80000000u128;
                g.cop0[15] = 0x59;
                Some(g)
            },
        },
    ];

    for test in tests {
        run_test(&test);
    }
}

#[test]
fn test_slti() {
    let tests = vec![
        TestCase {
            name: "slti_less",
            asm: "slti $v0, $t0, 4",
            setup: |ee| ee.write_register32(8, 2),
            golden: {
                let mut g = GoldenState::default();
                g.pc = 0xBFC00004;
                g.gpr[8] = 2;
                g.gpr[2] = 1;
                g.cop0[15] = 0x59;
                Some(g)
            },
        },
        TestCase {
            name: "slti_equal",
            asm: "slti $v0, $t0, 4",
            setup: |ee| ee.write_register32(8, 4),
            golden: {
                let mut g = GoldenState::default();
                g.pc = 0xBFC00004;
                g.gpr[8] = 4;
                g.gpr[2] = 0;
                g.cop0[15] = 0x59;
                Some(g)
            },
        },
        TestCase {
            name: "slti_greater",
            asm: "slti $v0, $t0, 4",
            setup: |ee| ee.write_register32(8, 5),
            golden: {
                let mut g = GoldenState::default();
                g.pc = 0xBFC00004;
                g.gpr[8] = 5;
                g.gpr[2] = 0;
                g.cop0[15] = 0x59;
                Some(g)
            },
        },
        TestCase {
            name: "slti_negative",
            asm: "slti $v0, $t0, 4",
            setup: |ee| ee.write_register32(8, 0xFFFFFFFF),
            golden: {
                let mut g = GoldenState::default();
                g.pc = 0xBFC00004;
                g.gpr[8] = 0xFFFFFFFF;
                g.gpr[2] = 1;
                g.cop0[15] = 0x59;
                Some(g)
            },
        },
        TestCase {
            name: "slti_max_pos",
            asm: "slti $v0, $t0, 4",
            setup: |ee| ee.write_register32(8, 0x7FFFFFFF),
            golden: {
                let mut g = GoldenState::default();
                g.pc = 0xBFC00004;
                g.gpr[8] = 0x7FFFFFFF;
                g.gpr[2] = 0;
                g.cop0[15] = 0x59;
                Some(g)
            },
        },
    ];

    for test in tests {
        run_test(&test);
    }
}

#[test]
fn test_bne() {
    let tests = vec![
        TestCase {
            name: "bne_taken",
            asm: "bne $t0, $t1, 0x4",
            setup: |ee| {
                ee.write_register32(8, 2);
                ee.write_register32(9, 3);
            },
            golden: {
                let mut g = GoldenState::default();
                g.pc = 0xBFC00004;
                g.gpr[8] = 2;
                g.gpr[9] = 3;
                g.cop0[15] = 0x59;
                Some(g)
            },
        },
        TestCase {
            name: "bne_not_taken",
            asm: "bne $t0, $t1, 0x4",
            setup: |ee| {
                ee.write_register32(8, 5);
                ee.write_register32(9, 5);
            },
            golden: {
                let mut g = GoldenState::default();
                g.pc = 0xBFC00008;
                g.gpr[8] = 5;
                g.gpr[9] = 5;
                g.cop0[15] = 0x59;
                Some(g)
            },
        },
        TestCase {
            name: "bne_zero_vs_nonzero",
            asm: "bne $t0, $t1, 0x4",
            setup: |ee| {
                ee.write_register32(8, 0);
                ee.write_register32(9, 1);
            },
            golden: {
                let mut g = GoldenState::default();
                g.pc = 0xBFC00004;
                g.gpr[8] = 0;
                g.gpr[9] = 1;
                g.cop0[15] = 0x59;
                Some(g)
            },
        },
    ];

    for test in tests {
        run_test(&test);
    }
}

#[test]
fn test_lui() {
    let tests = vec![
        TestCase {
            name: "lui_basic",
            asm: "lui $t0, 0x1234",
            setup: |_| {},
            golden: {
                let mut g = GoldenState::default();
                g.pc = 0xBFC00004;
                g.gpr[8] = 0x12340000;
                g.cop0[15] = 0x59;
                Some(g)
            },
        },
        TestCase {
            name: "lui_zero",
            asm: "lui $t0, 0x0",
            setup: |_| {},
            golden: {
                let mut g = GoldenState::default();
                g.pc = 0xBFC00004;
                g.gpr[8] = 0;
                g.cop0[15] = 0x59;
                Some(g)
            },
        },
        TestCase {
            name: "lui_max",
            asm: "lui $t0, 0xFFFF",
            setup: |_| {},
            golden: {
                let mut g = GoldenState::default();
                g.pc = 0xBFC00004;
                g.gpr[8] = 0xFFFF0000;
                g.cop0[15] = 0x59;
                Some(g)
            },
        },
        TestCase {
            name: "lui_lower_bits",
            asm: "lui $t0, 0x1234",
            setup: |ee| ee.write_register32(8, 0x0000FFFF),
            golden: {
                let mut g = GoldenState::default();
                g.pc = 0xBFC00004;
                g.gpr[8] = 0x12340000;
                g.cop0[15] = 0x59;
                Some(g)
            },
        },
    ];

    for test in tests {
        run_test(&test);
    }
}

#[test]
fn test_ori() {
    let tests = vec![
        TestCase {
            name: "ori_basic",
            asm: "ori $t0, $t0, 0x1234",
            setup: |ee| ee.write_register32(8, 0xFFFF0000),
            golden: {
                let mut g = GoldenState::default();
                g.pc = 0xBFC00004;
                g.gpr[8] = 0xFFFF1234;
                g.cop0[15] = 0x59;
                Some(g)
            },
        },
        TestCase {
            name: "ori_zero_imm",
            asm: "ori $t0, $t0, 0x0",
            setup: |ee| ee.write_register32(8, 0x1234),
            golden: {
                let mut g = GoldenState::default();
                g.pc = 0xBFC00004;
                g.gpr[8] = 0x1234;
                g.cop0[15] = 0x59;
                Some(g)
            },
        },
        TestCase {
            name: "ori_max_imm",
            asm: "ori $t0, $t0, 0xFFFF",
            setup: |ee| ee.write_register32(8, 0),
            golden: {
                let mut g = GoldenState::default();
                g.pc = 0xBFC00004;
                g.gpr[8] = 0xFFFF;
                g.cop0[15] = 0x59;
                Some(g)
            },
        },
        TestCase {
            name: "ori_with_bits",
            asm: "ori $t0, $t0, 0x1234",
            setup: |ee| ee.write_register32(8, 0xFFFF),
            golden: {
                let mut g = GoldenState::default();
                g.pc = 0xBFC00004;
                g.gpr[8] = 0xFFFF | 0x1234;
                g.cop0[15] = 0x59;
                Some(g)
            },
        },
    ];

    for test in tests {
        run_test(&test);
    }
}

#[test]
fn test_jr() {
    let tests = vec![
        TestCase {
            name: "jr_basic",
            asm: "jr $t0",
            setup: |ee| ee.write_register32(8, 0xBFC00008),
            golden: {
                let mut g = GoldenState::default();
                g.pc = 0xBFC00008;
                g.gpr[8] = 0xBFC00008;
                g.cop0[15] = 0x59;
                Some(g)
            },
        },
        TestCase {
            name: "jr_zero",
            asm: "jr $t0",
            setup: |ee| ee.write_register32(8, 0),
            golden: {
                let mut g = GoldenState::default();
                g.pc = 0;
                g.gpr[8] = 0;
                g.cop0[15] = 0x59;
                Some(g)
            },
        },
        TestCase {
            name: "jr_max",
            asm: "jr $t0",
            setup: |ee| ee.write_register32(8, 0xFFFFFFFC),
            golden: {
                let mut g = GoldenState::default();
                g.pc = 0xFFFFFFFC;
                g.gpr[8] = 0xFFFFFFFC;
                g.cop0[15] = 0x59;
                Some(g)
            },
        },
    ];

    for test in tests {
        run_test(&test);
    }
}

#[test]
fn test_mtc0() {
    let tests = vec![
        TestCase {
            name: "mtc0_basic",
            asm: "mtc0 $t0, $1",
            setup: |ee| ee.write_register32(8, 42),
            golden: {
                let mut g = GoldenState::default();
                g.pc = 0xBFC00004;
                g.gpr[8] = 42;
                g.cop0[1] = 42;
                g.cop0[15] = 0x59;
                Some(g)
            },
        },
        TestCase {
            name: "mtc0_zero",
            asm: "mtc0 $t0, $1",
            setup: |ee| ee.write_register32(8, 0),
            golden: {
                let mut g = GoldenState::default();
                g.pc = 0xBFC00004;
                g.gpr[8] = 0;
                g.cop0[1] = 0;
                g.cop0[15] = 0x59;
                Some(g)
            },
        },
        TestCase {
            name: "mtc0_max",
            asm: "mtc0 $t0, $1",
            setup: |ee| ee.write_register32(8, 0xFFFFFFFF),
            golden: {
                let mut g = GoldenState::default();
                g.pc = 0xBFC00004;
                g.gpr[8] = 0xFFFFFFFF;
                g.cop0[1] = 0xFFFFFFFF;
                g.cop0[15] = 0x59;
                Some(g)
            },
        },
    ];

    for test in tests {
        run_test(&test);
    }
}

#[test]
fn test_addiu() {
    let tests = vec![
        TestCase {
            name: "addiu_basic",
            asm: "addiu $t0, $t0, 2",
            setup: |ee| ee.write_register32(8, 40),
            golden: {
                let mut g = GoldenState::default();
                g.pc = 0xBFC00004;
                g.gpr[8] = 42;
                g.cop0[15] = 0x59;
                Some(g)
            },
        },
        TestCase {
            name: "addiu_negative_imm",
            asm: "addiu $t0, $t0, -1",
            setup: |ee| ee.write_register32(8, 0),
            golden: {
                let mut g = GoldenState::default();
                g.pc = 0xBFC00004;
                g.gpr[8] = 0xFFFFFFFF;
                g.cop0[15] = 0x59;
                Some(g)
            },
        },
        TestCase {
            name: "addiu_overflow",
            asm: "addiu $t0, $t0, 1",
            setup: |ee| ee.write_register32(8, 0xFFFFFFFF),
            golden: {
                let mut g = GoldenState::default();
                g.pc = 0xBFC00004;
                g.gpr[8] = 0;
                g.cop0[15] = 0x59;
                Some(g)
            },
        },
        TestCase {
            name: "addiu_negative_reg",
            asm: "addiu $t0, $t0, 2",
            setup: |ee| ee.write_register32(8, 0xFFFFFFFF),
            golden: {
                let mut g = GoldenState::default();
                g.pc = 0xBFC00004;
                g.gpr[8] = 1;
                g.cop0[15] = 0x59;
                Some(g)
            },
        },
    ];

    for test in tests {
        run_test(&test);
    }
}

#[test]
fn test_sw() {
    let tests = vec![
        TestCase {
            name: "sw_basic",
            asm: "sw $t0, 0($t1)",
            setup: |ee| {
                ee.write_register32(8, 42);
                ee.write_register32(9, 0x1000);
            },
            golden: {
                let mut g = GoldenState::default();
                g.pc = 0xBFC00004;
                g.gpr[8] = 42;
                g.gpr[9] = 0x1000;
                g.cop0[15] = 0x59;
                g.memory_checks = vec![(0x1000, 42)];
                Some(g)
            },
        },
        TestCase {
            name: "sw_zero",
            asm: "sw $t0, 0($t1)",
            setup: |ee| {
                ee.write_register32(8, 0);
                ee.write_register32(9, 0x1000);
            },
            golden: {
                let mut g = GoldenState::default();
                g.pc = 0xBFC00004;
                g.gpr[8] = 0;
                g.gpr[9] = 0x1000;
                g.cop0[15] = 0x59;
                g.memory_checks = vec![(0x1000, 0)];
                Some(g)
            },
        },
        TestCase {
            name: "sw_max",
            asm: "sw $t0, 0($t1)",
            setup: |ee| {
                ee.write_register32(8, 0xFFFFFFFF);
                ee.write_register32(9, 0x1004);
            },
            golden: {
                let mut g = GoldenState::default();
                g.pc = 0xBFC00004;
                g.gpr[8] = 0xFFFFFFFF;
                g.gpr[9] = 0x1004;
                g.cop0[15] = 0x59;
                g.memory_checks = vec![(0x1004, 0xFFFFFFFF)];
                Some(g)
            },
        },
        TestCase {
            name: "sw_offset",
            asm: "sw $t0, 4($t1)",
            setup: |ee| {
                ee.write_register32(8, 42);
                ee.write_register32(9, 0x1000);
            },
            golden: {
                let mut g = GoldenState::default();
                g.pc = 0xBFC00004;
                g.gpr[8] = 42;
                g.gpr[9] = 0x1000;
                g.cop0[15] = 0x59;
                g.memory_checks = vec![(0x1004, 42)];
                Some(g)
            },
        },
    ];

    for test in tests {
        run_test(&test);
    }
}

#[test]
fn test_lw() {
    let tests = vec![
        TestCase {
            name: "lw_aligned",
            asm: "lw $t0, 0($t1)",
            setup: |ee| {
                ee.write_register32(9, 0x1000);
                ee.write32(0x1000, 0x12345678);
            },
            golden: {
                let mut g = GoldenState::default();
                g.pc = 0xBFC00004;
                g.gpr[8] = 0x12345678;
                g.gpr[9] = 0x1000;
                g.cop0[15] = 0x59;
                Some(g)
            },
        },
        TestCase {
            name: "lw_signed_bit",
            asm: "lw $t0, 0($t1)",
            setup: |ee| {
                ee.write_register32(9, 0x1000);
                ee.write32(0x1000, 0x80000000);
            },
            golden: {
                let mut g = GoldenState::default();
                g.pc = 0xBFC00004;
                g.gpr[8] = 0x80000000;
                g.gpr[9] = 0x1000;
                g.cop0[15] = 0x59;
                Some(g)
            },
        },
    ];

    for tc in tests {
        run_test(&tc);
    }
}

#[test]
fn test_jalr() {
    let tests = vec![
        TestCase {
            name: "jalr_ra_t0",
            asm: "jalr $ra, $t0",
            setup: |ee| {
                ee.write_register32(8, 0xBFC00010);
            },
            golden: {
                let mut g = GoldenState::default();
                g.pc = 0xBFC00010;
                g.gpr[31] = 0xBFC00008;
                g.gpr[8] = 0xBFC00010;
                g.cop0[15] = 0x59;
                Some(g)
            },
        },
    ];

    for test in tests {
        run_test(&test);
    }
}

#[test]
fn test_sd() {
    let tests = vec![
        TestCase {
            name: "sd_basic",
            asm: "sd $t0, 0($t1)",
            setup: |ee| {
                ee.write_register(8, 0x1122334455667788);
                ee.write_register(9, 0x1000);
            },
            golden: {
                let mut g = GoldenState::default();
                g.pc = 0xBFC00004;
                g.gpr[8] = 0x1122334455667788;
                g.gpr[9] = 0x1000;
                g.cop0[15] = 0x59;
                g.memory_checks = vec![(0x1000, 0x55667788), (0x1004, 0x11223344)];
                Some(g)
            },
        },
        TestCase {
            name: "sd_zero",
            asm: "sd $t0, 0($t1)",
            setup: |ee| {
                ee.write_register(8, 0);
                ee.write_register(9, 0x1000);
            },
            golden: {
                let mut g = GoldenState::default();
                g.pc = 0xBFC00004;
                g.gpr[8] = 0;
                g.gpr[9] = 0x1000;
                g.cop0[15] = 0x59;
                g.memory_checks = vec![(0x1000, 0), (0x1004, 0)];
                Some(g)
            },
        },
        TestCase {
            name: "sd_max",
            asm: "sd $t0, 0($t1)",
            setup: |ee| {
                ee.write_register(8, 0xFFFFFFFFFFFFFFFF);
                ee.write_register(9, 0x1008);
            },
            golden: {
                let mut g = GoldenState::default();
                g.pc = 0xBFC00004;
                g.gpr[8] = 0xFFFFFFFFFFFFFFFF;
                g.gpr[9] = 0x1008;
                g.cop0[15] = 0x59;
                g.memory_checks = vec![(0x1008, 0xFFFFFFFF), (0x100C, 0xFFFFFFFF)];
                Some(g)
            },
        },
        TestCase {
            name: "sd_offset",
            asm: "sd $t0, 8($t1)",
            setup: |ee| {
                ee.write_register(8, 0xAABBCCDDEEFF0011);
                ee.write_register(9, 0x2000);
            },
            golden: {
                let mut g = GoldenState::default();
                g.pc = 0xBFC00004;
                g.gpr[8] = 0xAABBCCDDEEFF0011;
                g.gpr[9] = 0x2000;
                g.cop0[15] = 0x59;
                g.memory_checks = vec![(0x2008, 0xEEFF0011), (0x200C, 0xAABBCCDD)];
                Some(g)
            },
        },
    ];

    for test in tests {
        run_test(&test);
    }
}

#[test]
fn test_daddu() {
    let tests = vec![
        TestCase {
            name: "daddu_basic",
            asm: "daddu $t0, $t1, $t2",
            setup: |ee| {
                ee.write_register(9, 10);
                ee.write_register(10, 20);
            },
            golden: {
                let mut g = GoldenState::default();
                g.pc = 0xBFC00004;
                g.gpr[8] = 30;
                g.gpr[9] = 10;
                g.gpr[10] = 20;
                g.cop0[15] = 0x59;
                Some(g)
            },
        },
        TestCase {
            name: "daddu_overflow",
            asm: "daddu $t0, $t1, $t2",
            setup: |ee| {
                ee.write_register(9, 0xFFFFFFFFFFFFFFFF);
                ee.write_register(10, 2);
            },
            golden: {
                let mut g = GoldenState::default();
                g.pc = 0xBFC00004;
                g.gpr[8] = 1;
                g.gpr[9] = 0xFFFFFFFFFFFFFFFF;
                g.gpr[10] = 2;
                g.cop0[15] = 0x59;
                Some(g)
            },
        },
        TestCase {
            name: "daddu_zero",
            asm: "daddu $t0, $zero, $zero",
            setup: |_| {},
            golden: {
                let mut g = GoldenState::default();
                g.pc = 0xBFC00004;
                g.gpr[8] = 0;
                g.cop0[15] = 0x59;
                Some(g)
            },
        },
        TestCase {
            name: "daddu_negative",
            asm: "daddu $t0, $t1, $t2",
            setup: |ee| {
                ee.write_register(9, 0xFFFFFFFFFFFFFFFE);
                ee.write_register(10, 3);
            },
            golden: {
                let mut g = GoldenState::default();
                g.pc = 0xBFC00004;
                g.gpr[8] = 1;
                g.gpr[9] = 0xFFFFFFFFFFFFFFFE;
                g.gpr[10] = 3;
                g.cop0[15] = 0x59;
                Some(g)
            },
        },
    ];

    for test in tests {
        run_test(&test);
    }
}

#[test]
fn test_jal() {
    let tests = vec![
        TestCase {
            name: "jal_basic",
            asm: "jal 0xBFC00010",
            setup: |_| {},
            golden: {
                let mut g = GoldenState::default();
                g.pc = 0xBFC00010;
                g.gpr[31] = 0xBFC00008;
                g.cop0[15] = 0x59;
                Some(g)
            },
        },
        TestCase {
            name: "jal_zero",
            asm: "jal 0x0",
            setup: |_| {},
            golden: {
                let mut g = GoldenState::default();
                g.pc = 0xB0000000;
                g.gpr[31] = 0xBFC00008;
                g.cop0[15] = 0x59;
                Some(g)
            },
        },
        TestCase {
            name: "jal_max",
            asm: "jal 0x3FFFFFFC",
            setup: |_| {},
            golden: {
                let mut g = GoldenState::default();
                let imm26 = (0x3FFFFFFC >> 2) & 0x03FFFFFF;
                g.pc = ((0xBFC00000 + 4) & 0xF0000000) | (imm26 << 2);
                g.gpr[31] = 0xBFC00008;
                g.cop0[15] = 0x59;
                Some(g)
            },
        },
    ];

    for test in tests {
        run_test(&test);
    }
}

#[test]
fn test_andi() {
    let tests = vec![
        TestCase {
            name: "andi_basic",
            asm: "andi $t0, $t1, 0x1234",
            setup: |ee| ee.write_register32(9, 0xFFFF4321),
            golden: {
                let mut g = GoldenState::default();
                g.pc = 0xBFC00004;
                g.gpr[8] = 0x4321 & 0x1234;
                g.gpr[9] = 0xFFFF4321;
                g.cop0[15] = 0x59;
                Some(g)
            },
        },
        TestCase {
            name: "andi_zero_imm",
            asm: "andi $t0, $t1, 0x0",
            setup: |ee| ee.write_register32(9, 0x12345678),
            golden: {
                let mut g = GoldenState::default();
                g.pc = 0xBFC00004;
                g.gpr[8] = 0;
                g.gpr[9] = 0x12345678;
                g.cop0[15] = 0x59;
                Some(g)
            },
        },
        TestCase {
            name: "andi_max_imm",
            asm: "andi $t0, $t1, 0xFFFF",
            setup: |ee| ee.write_register32(9, 0x1234ABCD),
            golden: {
                let mut g = GoldenState::default();
                g.pc = 0xBFC00004;
                g.gpr[8] = 0xABCD;
                g.gpr[9] = 0x1234ABCD;
                g.cop0[15] = 0x59;
                Some(g)
            },
        },
        TestCase {
            name: "andi_upper_bits",
            asm: "andi $t0, $t1, 0xFF00",
            setup: |ee| ee.write_register32(9, 0x12345678),
            golden: {
                let mut g = GoldenState::default();
                g.pc = 0xBFC00004;
                g.gpr[8] = 0x5678 & 0xFF00;
                g.gpr[9] = 0x12345678;
                g.cop0[15] = 0x59;
                Some(g)
            },
        },
    ];

    for test in tests {
        run_test(&test);
    }
}

#[test]
fn test_beq() {
    let tests = vec![
        TestCase {
            name: "beq_taken",
            asm: "beq $t0, $t1, 0x4",
            setup: |ee| {
                ee.write_register32(8, 5);
                ee.write_register32(9, 5);
            },
            golden: {
                let mut g = GoldenState::default();
                g.pc = 0xBFC00004;
                g.gpr[8] = 5;
                g.gpr[9] = 5;
                g.cop0[15] = 0x59;
                Some(g)
            },
        },
        TestCase {
            name: "beq_not_taken",
            asm: "beq $t0, $t1, 0x4",
            setup: |ee| {
                ee.write_register32(8, 1);
                ee.write_register32(9, 2);
            },
            golden: {
                let mut g = GoldenState::default();
                g.pc = 0xBFC00008;
                g.gpr[8] = 1;
                g.gpr[9] = 2;
                g.cop0[15] = 0x59;
                Some(g)
            },
        },
        TestCase {
            name: "beq_zero_vs_zero",
            asm: "beq $zero, $zero, 0x4",
            setup: |_| {},
            golden: {
                let mut g = GoldenState::default();
                g.pc = 0xBFC00004;
                g.cop0[15] = 0x59;
                Some(g)
            },
        },
    ];

    for test in tests {
        run_test(&test);
    }
}

#[test]
fn test_or() {
    let tests = vec![
        TestCase {
            name: "or_basic",
            asm: "or $t0, $t1, $t2",
            setup: |ee| {
                ee.write_register(9, 0x0F0F0F0F0F0F0F0F);
                ee.write_register(10, 0xF0F0F0F0F0F0F0F0);
            },
            golden: {
                let mut g = GoldenState::default();
                g.pc = 0xBFC00004;
                g.gpr[8] = 0xFFFFFFFFFFFFFFFF;
                g.gpr[9] = 0x0F0F0F0F0F0F0F0F;
                g.gpr[10] = 0xF0F0F0F0F0F0F0F0;
                g.cop0[15] = 0x59;
                Some(g)
            },
        },
        TestCase {
            name: "or_zero",
            asm: "or $t0, $zero, $t2",
            setup: |ee| ee.write_register(10, 0x12345678),
            golden: {
                let mut g = GoldenState::default();
                g.pc = 0xBFC00004;
                g.gpr[8] = 0x12345678;
                g.gpr[10] = 0x12345678;
                g.cop0[15] = 0x59;
                Some(g)
            },
        },
        TestCase {
            name: "or_self",
            asm: "or $t0, $t1, $t1",
            setup: |ee| ee.write_register(9, 0xDEADBEEF),
            golden: {
                let mut g = GoldenState::default();
                g.pc = 0xBFC00004;
                g.gpr[8] = 0xDEADBEEF;
                g.gpr[9] = 0xDEADBEEF;
                g.cop0[15] = 0x59;
                Some(g)
            },
        },
    ];

    for test in tests {
        run_test(&test);
    }
}

#[test]
fn test_mult() {
    let tests = vec![
        TestCase {
            name: "mult_basic",
            asm: "mult $t0, $t1, $t2",
            setup: |ee| {
                ee.write_register32(9, 6);
                ee.write_register32(10, -7i32 as u32);
            },
            golden: {
                let mut g = GoldenState::default();
                let prod = (6i32 as i64).wrapping_mul(-7i32 as i64);
                g.pc = 0xBFC00004;
                g.gpr[8] = (prod as u32 as u64) as u128;
                g.gpr[9] = 6 as u128;
                g.gpr[10] = (-7i32 as u32 as u64) as u128;
                g.lo = (prod as u32 as u64) as u128;
                g.hi = ((prod >> 32) as u32 as u64) as u128;
                g.cop0[15] = 0x59;
                Some(g)
            },
        },
        TestCase {
            name: "mult_zero",
            asm: "mult $t0, $zero",
            setup: |ee| {
                ee.write_register32(10, 1234);
            },
            golden: {
                let mut g = GoldenState::default();
                g.pc = 0xBFC00004;
                g.gpr[8] = 0;
                g.gpr[10] = 1234 as u128;
                g.lo = 0;
                g.hi = 0;
                g.cop0[15] = 0x59;
                Some(g)
            },
        },
        TestCase {
            name: "mult_rd_zero",
            asm: "mult $zero, $t1, $t2",
            setup: |ee| {
                ee.write_register32(9, 2);
                ee.write_register32(10, 3);
            },
            golden: {
                let mut g = GoldenState::default();
                let prod = (2i32 as i64).wrapping_mul(3i32 as i64);
                g.pc = 0xBFC00004;
                g.gpr[9] = 2 as u128;
                g.gpr[10] = 3 as u128;
                g.lo = (prod as u32 as u64) as u128;
                g.hi = ((prod >> 32) as u32 as u64) as u128;
                g.cop0[15] = 0x59;
                Some(g)
            },
        },
    ];

    for test in tests {
        run_test(&test);
    }
}

#[test]
fn test_divu() {
    let tests = vec![
        TestCase {
            name: "divu_basic",
            asm:  "divu $t1, $t2",
            setup: |ee| {
                ee.write_register32(9, 100);
                ee.write_register32(10,  30);
            },
            golden: {
                let mut g = GoldenState::default();
                g.pc = 0xBFC00004;
                g.lo = 3u128;
                g.hi = 10u128;
                g.gpr[9]  = 100u128;
                g.gpr[10] =  30u128;
                g.cop0[15] = 0x59;
                Some(g)
            }
        },
        TestCase {
            name: "divu_small",
            asm:  "divu $t3, $t4",
            setup: |ee| {
                ee.write_register32(11,  5);
                ee.write_register32(12, 10);
            },
            golden: {
                let mut g = GoldenState::default();
                g.pc = 0xBFC00004;
                g.gpr[11] =  5u128;
                g.gpr[12] = 10u128;
                g.lo = 0u128;
                g.hi = 5u128;
                g.cop0[15] = 0x59;
                Some(g)
            }
        },
    ];

    for tc in tests {
        run_test(&tc);
    }
}

#[test]
fn test_beql() {
    let tests = vec![
        TestCase {
            name: "beql_taken",
            asm: "
                beql $t1, $t2, 8
                sll $zero, $zero, 0
                addiu $t4, $zero, 5
            ",
            setup: |ee| {
                ee.write_register32(9, 42);
                ee.write_register32(10, 42);
            },
            golden: {
                let mut g = GoldenState::default();
                g.pc = 0xBFC0000C;
                g.gpr[11] = 0;
                g.gpr[12] = 5;
                g.cop0[15] = 0x59;
                Some(g)
            },
        },
        TestCase {
            name: "beql_not_taken",
            asm: "
                beql $t1, $t2, 16
                sll $zero, $zero, 0
                addiu $t4, $zero, 7
            ",
            setup: |ee| {
                ee.write_register32(9, 1);
                ee.write_register32(10, 2);
            },
            golden: {
                let mut g = GoldenState::default();
                g.pc = 0xBFC00008;
                g.gpr[11] = 0;
                g.gpr[12] = 7;
                g.cop0[15] = 0x59;
                Some(g)
            },
        },
    ];

    for tc in tests {
        run_test(&tc);
    }
}

#[test]
fn test_mflo() {
    let tests = vec![
        TestCase {
            name: "mflo_basic",
            asm: "
                mult $t1, $t2 
                mflo $t0
            ",
            setup: |ee| {
                ee.write_register32(9, 5);
                ee.write_register32(10, 3);
            },
            golden: {
                let mut g = GoldenState::default();
                g.pc = 0xBFC00008;
                g.gpr[8] = 15u128;
                g.gpr[9] = 5u128;
                g.gpr[10] = 3u128;
                g.lo = 15u128;
                g.hi = 0u128;
                g.cop0[15] = 0x59;
                Some(g)
            },
        },
        TestCase {
            name: "mflo_large",
            asm: "
                mult $t1, $t2
                mflo $t0
            ",
            setup: |ee| {
                ee.write_register32(9, 1000);
                ee.write_register32(10, 200);
            },
            golden: {
                let mut g = GoldenState::default();
                g.pc = 0xBFC00008;
                g.gpr[8] = 200000u128;
                g.gpr[9] = 1000u128;
                g.gpr[10] = 200u128;
                g.lo = 200000u128;
                g.hi = 0u128;
                g.cop0[15] = 0x59;
                Some(g)
            },
        },
    ];

    for tc in tests {
        run_test(&tc);
    }
}

#[test]
fn test_sltiu() {
    let tests = vec![
        TestCase {
            name: "sltiu_less",
            asm: "sltiu $v0, $t0, 4",
            setup: |ee| ee.write_register32(8, 2),
            golden: {
                let mut g = GoldenState::default();
                g.pc = 0xBFC00004;
                g.gpr[8] = 2;
                g.gpr[2] = 1;
                g.cop0[15] = 0x59;
                Some(g)
            },
        },
        TestCase {
            name: "sltiu_equal",
            asm: "sltiu $v0, $t0, 4",
            setup: |ee| ee.write_register32(8, 4),
            golden: {
                let mut g = GoldenState::default();
                g.pc = 0xBFC00004;
                g.gpr[8] = 4;
                g.gpr[2] = 0;
                g.cop0[15] = 0x59;
                Some(g)
            },
        },
        TestCase {
            name: "sltiu_greater",
            asm: "sltiu $v0, $t0, 4",
            setup: |ee| ee.write_register32(8, 5),
            golden: {
                let mut g = GoldenState::default();
                g.pc = 0xBFC00004;
                g.gpr[8] = 5;
                g.gpr[2] = 0;
                g.cop0[15] = 0x59;
                Some(g)
            },
        },
        TestCase {
            name: "sltiu_negative",
            asm: "sltiu $v0, $t0, -1",
            setup: |ee| ee.write_register32(8, 0x7FFFFFFF),
            golden: {
                let mut g = GoldenState::default();
                g.pc = 0xBFC00004;
                g.gpr[8] = 0x7FFFFFFF;
                g.gpr[2] = 1;
                g.cop0[15] = 0x59;
                Some(g)
            },
        },
        TestCase {
            name: "sltiu_large",
            asm: "sltiu $v0, $t0, -1",
            setup: |ee| ee.write_register64(8, 0xFFFFFFFFFFFFFFFF),
            golden: {
                let mut g = GoldenState::default();
                g.pc = 0xBFC00004;
                g.gpr[8] = 0xFFFFFFFFFFFFFFFF;
                g.gpr[2] = 0;
                g.cop0[15] = 0x59;
                Some(g)
            },
        },
    ];

    for test in tests {
        run_test(&test);
    }
}

#[test]
fn test_bnel() {
    let tests = vec![
        TestCase {
            name: "bnel_taken",
            asm: "
                bnel $t1, $t2, 8
                sll $zero, $zero, 0
                addiu $t4, $zero, 5
            ",
            setup: |ee| {
                ee.write_register32(9, 42);
                ee.write_register32(10, 43);
            },
            golden: {
                let mut g = GoldenState::default();
                g.pc = 0xBFC0000C;
                g.gpr[12] = 0;
                g.cop0[15] = 0x59;
                Some(g)
            },
        },
        TestCase {
            name: "bnel_not_taken",
            asm: "
                bnel $t1, $t2, 16
                sll $zero, $zero, 0
                addiu $t4, $zero, 7
            ",
            setup: |ee| {
                ee.write_register32(9, 1);
                ee.write_register32(10, 1);
            },
            golden: {
                let mut g = GoldenState::default();
                g.pc = 0xBFC00008;
                g.gpr[12] = 7;
                g.cop0[15] = 0x59;
                Some(g)
            },
        },
    ];

    for tc in tests {
        run_test(&tc);
    }
}

#[test]
fn test_lb() {
    let tests = vec![
        TestCase {
            name: "lb_positive",
            asm: "lb $t0, 0($t1)",
            setup: |ee| {
                ee.write_register32(9, 0x1000);
                ee.write8(0x1000, 0x7F);
            },
            golden: {
                let mut g = GoldenState::default();
                g.pc = 0xBFC00004;
                g.gpr[8] = 0x7F;
                g.gpr[9] = 0x1000;
                g.cop0[15] = 0x59;
                Some(g)
            },
        },
        TestCase {
            name: "lb_negative",
            asm: "lb $t0, 0($t1)",
            setup: |ee| {
                ee.write_register32(9, 0x1004);
                ee.write8(0x1004, 0x80);
            },
            golden: {
                let mut g = GoldenState::default();
                g.pc = 0xBFC00004;
                g.gpr[8] = 0xFFFFFFFFFFFFFF80;
                g.gpr[9] = 0x1004;
                g.cop0[15] = 0x59;
                Some(g)
            },
        },
    ];

    for tc in tests {
        run_test(&tc);
    }
}

#[test]
fn test_swc1() {
    let tests = vec![
        TestCase {
            name: "swc1_basic",
            asm: "swc1 $f0, 0($t0)",
            setup: |ee| {
                ee.write_register32(8, 0x1000);
                ee.write_fpu_register_from_u32(0, f32::to_bits(42.0));
            },
            golden: {
                let mut g = GoldenState::default();
                g.pc = 0xBFC00004;
                g.gpr[8] = 0x1000;
                g.cop0[15] = 0x59;
                g.memory_checks = vec![(0x1000, 0x42280000)];
                Some(g)
            },
        },
        TestCase {
            name: "swc1_zero",
            asm: "swc1 $f0, 0($t0)",
            setup: |ee| {
                ee.write_register32(8, 0x1000);
                ee.write_fpu_register_from_u32(0, f32::to_bits(0.0));
            },
            golden: {
                let mut g = GoldenState::default();
                g.pc = 0xBFC00004;
                g.gpr[8] = 0x1000;
                g.cop0[15] = 0x59;
                g.memory_checks = vec![(0x1000, 0x00000000)];
                Some(g)
            },
        },
        TestCase {
            name: "swc1_negative",
            asm: "swc1 $f0, 0($t0)",
            setup: |ee| {
                ee.write_register32(8, 0x1004);
                ee.write_fpu_register_from_u32(0, f32::to_bits(-1.0));
            },
            golden: {
                let mut g = GoldenState::default();
                g.pc = 0xBFC00004;
                g.gpr[8] = 0x1004;
                g.cop0[15] = 0x59;
                g.memory_checks = vec![(0x1004, 0xBF800000)];
                Some(g)
            },
        },
        TestCase {
            name: "swc1_offset",
            asm: "swc1 $f0, 4($t0)",
            setup: |ee| {
                ee.write_register32(8, 0x1000);
                ee.write_fpu_register_from_u32(0, f32::to_bits(42.0));
            },
            golden: {
                let mut g = GoldenState::default();
                g.pc = 0xBFC00004;
                g.gpr[8] = 0x1000;
                g.cop0[15] = 0x59;
                g.memory_checks = vec![(0x1004, 0x42280000)];
                Some(g)
            },
        },
    ];

    for test in tests {
        run_test(&test);
    }
}

#[test]
fn test_lbu() {
    let tests = vec![
        TestCase {
            name: "lbu_positive",
            asm: "lbu $t0, 0($t1)",
            setup: |ee| {
                ee.write_register32(9, 0x1000);
                ee.write8(0x1000, 0x7F);
            },
            golden: {
                let mut g = GoldenState::default();
                g.pc = 0xBFC00004;
                g.gpr[8] = 0x7F;
                g.gpr[9] = 0x1000;
                g.cop0[15] = 0x59;
                Some(g)
            },
        },
        TestCase {
            name: "lbu_zero",
            asm: "lbu $t0, 0($t1)",
            setup: |ee| {
                ee.write_register32(9, 0x1000);
                ee.write8(0x1000, 0x00);
            },
            golden: {
                let mut g = GoldenState::default();
                g.pc = 0xBFC00004;
                g.gpr[8] = 0x00;
                g.gpr[9] = 0x1000;
                g.cop0[15] = 0x59;
                Some(g)
            },
        },
        TestCase {
            name: "lbu_max",
            asm: "lbu $t0, 0($t1)",
            setup: |ee| {
                ee.write_register32(9, 0x1004);
                ee.write8(0x1004, 0xFF);
            },
            golden: {
                let mut g = GoldenState::default();
                g.pc = 0xBFC00004;
                g.gpr[8] = 0xFF;
                g.gpr[9] = 0x1004;
                g.cop0[15] = 0x59;
                Some(g)
            },
        },
        TestCase {
            name: "lbu_offset",
            asm: "lbu $t0, 4($t1)",
            setup: |ee| {
                ee.write_register32(9, 0x1000);
                ee.write8(0x1004, 0x7F);
            },
            golden: {
                let mut g = GoldenState::default();
                g.pc = 0xBFC00004;
                g.gpr[8] = 0x7F;
                g.gpr[9] = 0x1000;
                g.cop0[15] = 0x59;
                Some(g)
            },
        },
    ];

    for test in tests {
        run_test(&test);
    }
}

#[test]
fn test_sra() {
    let tests = vec![
        TestCase {
            name: "sra_positive",
            asm: "sra $t0, $t1, 4",
            setup: |ee| {
                ee.write_register32(9, 0x7FFF0000);
            },
            golden: {
                let mut g = GoldenState::default();
                g.pc = 0xBFC00004;
                g.gpr[8] = 0x07FFF000;
                g.gpr[9] = 0x7FFF0000;
                g.cop0[15] = 0x59;
                Some(g)
            },
        },
        TestCase {
            name: "sra_negative",
            asm: "sra $t0, $t1, 4",
            setup: |ee| {
                ee.write_register32(9, 0x80000000);
            },
            golden: {
                let mut g = GoldenState::default();
                g.pc = 0xBFC00004;
                g.gpr[8] = 0xFFFFFFFFF8000000;
                g.gpr[9] = 0x80000000;
                g.cop0[15] = 0x59;
                Some(g)
            },
        },
        TestCase {
            name: "sra_zero_shift",
            asm: "sra $t0, $t1, 0",
            setup: |ee| {
                ee.write_register32(9, 0x12345678);
            },
            golden: {
                let mut g = GoldenState::default();
                g.pc = 0xBFC00004;
                g.gpr[8] = 0x12345678;
                g.gpr[9] = 0x12345678;
                g.cop0[15] = 0x59;
                Some(g)
            },
        },
        TestCase {
            name: "sra_max_shift",
            asm: "sra $t0, $t1, 31",
            setup: |ee| {
                ee.write_register32(9, 0x80000000);
            },
            golden: {
                let mut g = GoldenState::default();
                g.pc = 0xBFC00004;
                g.gpr[8] = 0xFFFFFFFFFFFFFFFF;
                g.gpr[9] = 0x80000000;
                g.cop0[15] = 0x59;
                Some(g)
            },
        },
    ];

    for test in tests {
        run_test(&test);
    }
}

#[test]
fn test_ld() {
    let tests = vec![
        TestCase {
            name: "ld_basic",
            asm: "ld $t0, 0($t1)",
            setup: |ee| {
                ee.write_register32(9, 0x1000);
                ee.write64(0x1000, 0x1122334455667788);
            },
            golden: {
                let mut g = GoldenState::default();
                g.pc = 0xBFC00004;
                g.gpr[8] = 0x1122334455667788;
                g.gpr[9] = 0x1000;
                g.cop0[15] = 0x59;
                Some(g)
            },
        },
        TestCase {
            name: "ld_zero",
            asm: "ld $t0, 0($t1)",
            setup: |ee| {
                ee.write_register32(9, 0x1000);
                ee.write64(0x1000, 0x0);
            },
            golden: {
                let mut g = GoldenState::default();
                g.pc = 0xBFC00004;
                g.gpr[8] = 0;
                g.gpr[9] = 0x1000;
                g.cop0[15] = 0x59;
                Some(g)
            },
        },
        TestCase {
            name: "ld_max",
            asm: "ld $t0, 0($t1)",
            setup: |ee| {
                ee.write_register32(9, 0x1008);
                ee.write64(0x1008, 0xFFFFFFFFFFFFFFFF);
            },
            golden: {
                let mut g = GoldenState::default();
                g.pc = 0xBFC00004;
                g.gpr[8] = 0xFFFFFFFFFFFFFFFF;
                g.gpr[9] = 0x1008;
                g.cop0[15] = 0x59;
                Some(g)
            },
        },
        TestCase {
            name: "ld_offset",
            asm: "ld $t0, 8($t1)",
            setup: |ee| {
                ee.write_register32(9, 0x2000);
                ee.write64(0x2008, 0xAABBCCDDEEFF0011);
            },
            golden: {
                let mut g = GoldenState::default();
                g.pc = 0xBFC00004;
                g.gpr[8] = 0xAABBCCDDEEFF0011;
                g.gpr[9] = 0x2000;
                g.cop0[15] = 0x59;
                Some(g)
            },
        },
    ];

    for test in tests {
        run_test(&test);
    }
}

#[test]
fn test_j() {
    let tests = vec![
        TestCase {
            name: "j_basic",
            asm: "j 0xBFC00010",
            setup: |_| {},
            golden: {
                let mut g = GoldenState::default();
                g.pc = 0xBFC00010;
                g.cop0[15] = 0x59;
                Some(g)
            },
        },
        TestCase {
            name: "j_zero",
            asm: "j 0x0",
            setup: |_| {},
            golden: {
                let mut g = GoldenState::default();
                // (0xBFC00000 + 4) & 0xF0000000 = 0xB0000000
                g.pc = 0xB0000000;
                g.cop0[15] = 0x59;
                Some(g)
            },
        },
        TestCase {
            name: "j_max",
            asm: "j 0x3FFFFFFC",
            setup: |_| {},
            golden: {
                let mut g = GoldenState::default();
                let imm26 = (0x3FFFFFFC >> 2) & 0x03FFFFFF;
                g.pc = ((0xBFC00000 + 4) & 0xF0000000) | (imm26 << 2);
                g.cop0[15] = 0x59;
                Some(g)
            },
        },
    ];

    for test in tests {
        run_test(&test);
    }
}

#[test]
fn test_sb() {
    let tests = vec![
        TestCase {
            name: "sb_basic",
            asm: "
                lui $t0, 0x0000
                ori $t0, $t0, 0x1000
                li $t1, 0x42
                sb $t1, 0($t0)
            ",
            setup: |_| {},
            golden: {
                let mut g = GoldenState::default();
                g.pc = 0xBFC00010;
                g.gpr[8] = 0x1000;
                g.gpr[9] = 0x42;
                g.cop0[15] = 0x59;
                g.memory_checks = vec![(0x1000, 0x42)];
                Some(g)
            },
        },
        TestCase {
            name: "sb_zero",
            asm: "
                lui $t0, 0x0000
                ori $t0, $t0, 0x1000
                li $t1, 0x00
                sb $t1, 0($t0)
            ",
            setup: |_| {},
            golden: {
                let mut g = GoldenState::default();
                g.pc = 0xBFC00010;
                g.gpr[8] = 0x1000;
                g.gpr[9] = 0x00;
                g.cop0[15] = 0x59;
                g.memory_checks = vec![(0x1000, 0x00)];
                Some(g)
            },
        },
        TestCase {
            name: "sb_max",
            asm: "
                lui $t0, 0x0000
                ori $t0, $t0, 0x1004
                li $t1, 0xFF
                sb $t1, 0($t0)
            ",
            setup: |_| {},
            golden: {
                let mut g = GoldenState::default();
                g.pc = 0xBFC00010;
                g.gpr[8] = 0x1004;
                g.gpr[9] = 0xFF;
                g.cop0[15] = 0x59;
                g.memory_checks = vec![(0x1004, 0xFF)];
                Some(g)
            },
        },
        TestCase {
            name: "sb_offset",
            asm: "
                lui $t0, 0x0000
                ori $t0, $t0, 0x1000
                li $t1, 0x42
                sb $t1, 4($t0)
            ",
            setup: |_| {},
            golden: {
                let mut g = GoldenState::default();
                g.pc = 0xBFC00010;
                g.gpr[8] = 0x1000;
                g.gpr[9] = 0x42;
                g.cop0[15] = 0x59;
                g.memory_checks = vec![(0x1004, 0x42)];
                Some(g)
            },
        },
    ];

    for test in tests {
        run_test(&test);
    }
}

#[test]
fn test_addu() {
    let tests = vec![
        TestCase {
            name: "addu_basic",
            asm: "addu $t0, $t1, $t2",
            setup: |ee| {
                ee.write_register32(9, 40);
                ee.write_register32(10, 2);
            },
            golden: {
                let mut g = GoldenState::default();
                g.pc = 0xBFC00004;
                g.gpr[8] = 42;
                g.gpr[9] = 40;
                g.gpr[10] = 2;
                g.cop0[15] = 0x59;
                Some(g)
            },
        },
        TestCase {
            name: "addu_zero",
            asm: "addu $t0, $zero, $t2",
            setup: |ee| {
                ee.write_register32(10, 42);
            },
            golden: {
                let mut g = GoldenState::default();
                g.pc = 0xBFC00004;
                g.gpr[8] = 42;
                g.gpr[10] = 42;
                g.cop0[15] = 0x59;
                Some(g)
            },
        },
        TestCase {
            name: "addu_overflow",
            asm: "addu $t0, $t1, $t2",
            setup: |ee| {
                ee.write_register32(9, 0xFFFFFFFF);
                ee.write_register32(10, 1);
            },
            golden: {
                let mut g = GoldenState::default();
                g.pc = 0xBFC00004;
                g.gpr[8] = 0;
                g.gpr[9] = 0xFFFFFFFF;
                g.gpr[10] = 1;
                g.cop0[15] = 0x59;
                Some(g)
            },
        },
        TestCase {
            name: "addu_negative",
            asm: "addu $t0, $t1, $t2",
            setup: |ee| {
                ee.write_register32(9, 0xFFFFFFFF);
                ee.write_register32(10, 0x1);
            },
            golden: {
                let mut g = GoldenState::default();
                g.pc = 0xBFC00004;
                g.gpr[8] = 0;
                g.gpr[9] = 0xFFFFFFFF;
                g.gpr[10] = 1;
                g.cop0[15] = 0x59;
                Some(g)
            },
        },
    ];

    for test in tests {
        run_test(&test);
    }
}

#[test]
fn test_bgez() {
    let tests = vec![
        TestCase {
            name: "bgez_positive",
            asm: "bgez $t1, 4",
            setup: |ee| {
                ee.write_register32(9, 42);
            },
            golden: {
                let mut g = GoldenState::default();
                g.pc = 0xBFC00014;
                g.gpr[9] = 42;
                g.cop0[15] = 0x59;
                Some(g)
            },
        },
        TestCase {
            name: "bgez_zero",
            asm: "bgez $t1, 4",
            setup: |ee| {
                ee.write_register32(9, 0);
            },
            golden: {
                let mut g = GoldenState::default();
                g.pc = 0xBFC00014;
                g.gpr[9] = 0;
                g.cop0[15] = 0x59;
                Some(g)
            },
        },
        TestCase {
            name: "bgez_negative",
            asm: "bgez $t1, 4",
            setup: |ee| {
                ee.write_register32(9, 0xFFFFFFFF);
            },
            golden: {
                let mut g = GoldenState::default();
                g.pc = 0xBFC00008;
                g.gpr[9] = 0xFFFFFFFF;
                g.cop0[15] = 0x59;
                Some(g)
            },
        },
    ];

    for test in tests {
        run_test(&test);
    }
}

#[test]
fn test_div() {
    let tests = vec![
        TestCase {
            name: "div_positive",
            asm: "div $t1, $t2",
            setup: |ee| {
                ee.write_register32(9, 42);
                ee.write_register32(10, 5);
            },
            golden: {
                let mut g = GoldenState::default();
                g.pc = 0xBFC00004;
                g.gpr[9] = 42;
                g.gpr[10] = 5;
                g.lo = 8;
                g.hi = 2;
                g.cop0[15] = 0x59;
                Some(g)
            },
        },
        TestCase {
            name: "div_negative_dividend",
            asm: "div $t1, $t2",
            setup: |ee| {
                ee.write_register32(9, 0xFFFFFFFE);
                ee.write_register32(10, 3);
            },
            golden: {
                let mut g = GoldenState::default();
                g.pc = 0xBFC00004;
                g.gpr[9] = 0xFFFFFFFE;
                g.gpr[10] = 3;
                g.lo = 0;
                g.hi = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE;
                g.cop0[15] = 0x59;
                Some(g)
            },
        },
        TestCase {
            name: "div_negative_divisor",
            asm: "div $t1, $t2",
            setup: |ee| {
                ee.write_register32(9, 42);
                ee.write_register32(10, 0xFFFFFFFB);
            },
            golden: {
                let mut g = GoldenState::default();
                g.pc = 0xBFC00004;
                g.gpr[9] = 42;
                g.gpr[10] = 0xFFFFFFFB;
                g.lo = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF8;
                g.hi = 2;
                g.cop0[15] = 0x59;
                Some(g)
            },
        },
        TestCase {
            name: "div_both_negative",
            asm: "div $t1, $t2",
            setup: |ee| {
                ee.write_register32(9, 0xFFFFFFFE);
                ee.write_register32(10, 0xFFFFFFFB);
            },
            golden: {
                let mut g = GoldenState::default();
                g.pc = 0xBFC00004;
                g.gpr[9] = 0xFFFFFFFE;
                g.gpr[10] = 0xFFFFFFFB;
                g.lo = 0;
                g.hi = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE;
                g.cop0[15] = 0x59;
                Some(g)
            },
        },
        TestCase {
            name: "div_special_case",
            asm: "div $t1, $t2",
            setup: |ee| {
                ee.write_register32(9, 0x80000000);
                ee.write_register32(10, 0xFFFFFFFF);
            },
            golden: {
                let mut g = GoldenState::default();
                g.pc = 0xBFC00004;
                g.gpr[9] = 0x80000000;
                g.gpr[10] = 0xFFFFFFFF;
                g.lo = (i32::MIN as i128) as u128;
                g.hi = 0;
                g.cop0[15] = 0x59;
                Some(g)
            },
        },
        TestCase {
            name: "div_by_zero",
            asm: "div $t1, $t2",
            setup: |ee| {
                ee.write_register32(9, 42);
                ee.write_register32(10, 0);
            },
            golden: {
                let mut g = GoldenState::default();
                g.pc = 0xBFC00004;
                g.gpr[9] = 42;
                g.gpr[10] = 0;
                g.lo = 0;
                g.hi = 0;
                g.cop0[15] = 0x59;
                Some(g)
            },
        },
    ];

    for test in tests {
        run_test(&test);
    }
}

#[test]
fn test_mfhi() {
    let tests = vec![
        TestCase {
            name: "mfhi_after_mult",
            asm: "mult $t1, $t2\nmfhi $t0",
            setup: |ee| {
                ee.write_register32(9, 0x10000);
                ee.write_register32(10, 0x10000);
            },
            golden: {
                let mut g = GoldenState::default();
                g.pc = 0xBFC00008;
                g.gpr[8] = 1;
                g.gpr[9] = 0x10000;
                g.gpr[10] = 0x10000;
                g.lo = 0;
                g.hi = 1;
                g.cop0[15] = 0x59;
                Some(g)
            },
        },
        TestCase {
            name: "mfhi_after_div",
            asm: "div $t1, $t2\nmfhi $t0",
            setup: |ee| {
                ee.write_register32(9, 42);
                ee.write_register32(10, 5);
            },
            golden: {
                let mut g = GoldenState::default();
                g.pc = 0xBFC00008;
                g.gpr[8] = 2;
                g.gpr[9] = 42;
                g.gpr[10] = 5;
                g.lo = 8;
                g.hi = 2;
                g.cop0[15] = 0x59;
                Some(g)
            },
        },
        TestCase {
            name: "mfhi_zero",
            asm: "mult $t1, $t2\nmfhi $t0",
            setup: |ee| {
                ee.write_register32(9, 0);
                ee.write_register32(10, 42);
            },
            golden: {
                let mut g = GoldenState::default();
                g.pc = 0xBFC00008;
                g.gpr[8] = 0;
                g.gpr[9] = 0;
                g.gpr[10] = 42;
                g.lo = 0;
                g.hi = 0;
                g.cop0[15] = 0x59;
                Some(g)
            },
        },
    ];

    for test in tests {
        run_test(&test);
    }
}

#[test]
fn test_sltu() {
    let tests = vec![
        TestCase {
            name: "sltu_less",
            asm: "sltu $t0, $t1, $t2",
            setup: |ee| {
                ee.write_register32(9, 5);
                ee.write_register32(10, 10);
            },
            golden: {
                let mut g = GoldenState::default();
                g.pc = 0xBFC00004;
                g.gpr[8] = 1;
                g.gpr[9] = 5;
                g.gpr[10] = 10;
                g.cop0[15] = 0x59;
                Some(g)
            },
        },
        TestCase {
            name: "sltu_equal",
            asm: "sltu $t0, $t1, $t2",
            setup: |ee| {
                ee.write_register32(9, 42);
                ee.write_register32(10, 42);
            },
            golden: {
                let mut g = GoldenState::default();
                g.pc = 0xBFC00004;
                g.gpr[8] = 0;
                g.gpr[9] = 42;
                g.gpr[10] = 42;
                g.cop0[15] = 0x59;
                Some(g)
            },
        },
        TestCase {
            name: "sltu_greater",
            asm: "sltu $t0, $t1, $t2",
            setup: |ee| {
                ee.write_register32(9, 50);
                ee.write_register32(10, 20);
            },
            golden: {
                let mut g = GoldenState::default();
                g.pc = 0xBFC00004;
                g.gpr[8] = 0;
                g.gpr[9] = 50;
                g.gpr[10] = 20;
                g.cop0[15] = 0x59;
                Some(g)
            },
        },
        TestCase {
            name: "sltu_large_values",
            asm: "sltu $t0, $t1, $t2",
            setup: |ee| {
                ee.write_register64(9, 0x8000000000000000);
                ee.write_register64(10, 0xFFFFFFFFFFFFFFFF);
            },
            golden: {
                let mut g = GoldenState::default();
                g.pc = 0xBFC00004;
                g.gpr[8] = 1;
                g.gpr[9] = 0x8000000000000000;
                g.gpr[10] = 0xFFFFFFFFFFFFFFFF;
                g.cop0[15] = 0x59;
                Some(g)
            },
        },
        TestCase {
            name: "sltu_zero",
            asm: "sltu $t0, $zero, $t2",
            setup: |ee| {
                ee.write_register32(10, 1);
            },
            golden: {
                let mut g = GoldenState::default();
                g.pc = 0xBFC00004;
                g.gpr[8] = 1;
                g.gpr[10] = 1;
                g.cop0[15] = 0x59;
                Some(g)
            },
        },
    ];

    for test in tests {
        run_test(&test);
    }
}

#[test]
fn test_blez() {
    let tests = vec![
        TestCase {
            name: "blez_zero",
            asm: "
                blez $t1, 4
                nop
            ",
            setup: |ee| {
                ee.write_register32(9, 0);
            },
            golden: {
                let mut g = GoldenState::default();
                g.pc = 0xBFC00010;
                g.gpr[9] = 0;
                g.cop0[15] = 0x59;
                Some(g)
            },
        },
        TestCase {
            name: "blez_negative",
            asm: "
                blez $t1, 4
                nop
            ",
            setup: |ee| {
                ee.write_register32(9, 0xFFFFFFFF);
            },
            golden: {
                let mut g = GoldenState::default();
                g.pc = 0xBFC00010;
                g.gpr[9] = 0xFFFFFFFF;
                g.cop0[15] = 0x59;
                Some(g)
            },
        },
        TestCase {
            name: "blez_positive",
            asm: "
                blez $t1, 4
                nop
            ",
            setup: |ee| {
                ee.write_register32(9, 42);
            },
            golden: {
                let mut g = GoldenState::default();
                g.pc = 0xBFC00008;
                g.gpr[9] = 42;
                g.cop0[15] = 0x59;
                Some(g)
            },
        },
        TestCase {
            name: "blez_large_negative",
            asm: "
                blez $t1, 4
                nop
            ",
            setup: |ee| {
                ee.write_register64(9, 0xFFFFFFFFFFFFFFFF);
            },
            golden: {
                let mut g = GoldenState::default();
                g.pc = 0xBFC00010;
                g.gpr[9] = 0xFFFFFFFFFFFFFFFF;
                g.cop0[15] = 0x59;
                Some(g)
            },
        },
    ];

    for test in tests {
        run_test(&test);
    }
}

#[test]
fn test_subu() {
    let tests = vec![
        TestCase {
            name: "subu_basic",
            asm: "subu $t0, $t1, $t2",
            setup: |ee| {
                ee.write_register32(9, 50);
                ee.write_register32(10, 8);
            },
            golden: {
                let mut g = GoldenState::default();
                g.pc = 0xBFC00004;
                g.gpr[8] = 42;
                g.gpr[9] = 50;
                g.gpr[10] = 8;
                g.cop0[15] = 0x59;
                Some(g)
            },
        },
        TestCase {
            name: "subu_zero",
            asm: "subu $t0, $t1, $t2",
            setup: |ee| {
                ee.write_register32(9, 0);
                ee.write_register32(10, 0);
            },
            golden: {
                let mut g = GoldenState::default();
                g.pc = 0xBFC00004;
                g.gpr[8] = 0;
                g.gpr[9] = 0;
                g.gpr[10] = 0;
                g.cop0[15] = 0x59;
                Some(g)
            },
        },
        TestCase {
            name: "subu_overflow",
            asm: "subu $t0, $t1, $t2",
            setup: |ee| {
                ee.write_register32(9, 0);
                ee.write_register32(10, 1);
            },
            golden: {
                let mut g = GoldenState::default();
                g.pc = 0xBFC00004;
                g.gpr[8] = 0xFFFFFFFFFFFFFFFF;
                g.gpr[9] = 0;
                g.gpr[10] = 1;
                g.cop0[15] = 0x59;
                Some(g)
            },
        },
        TestCase {
            name: "subu_negative_result",
            asm: "subu $t0, $t1, $t2",
            setup: |ee| {
                ee.write_register32(9, 10);
                ee.write_register32(10, 20);
            },
            golden: {
                let mut g = GoldenState::default();
                g.pc = 0xBFC00004;
                g.gpr[8] = 0xFFFFFFFFFFFFFFF6;
                g.gpr[9] = 10;
                g.gpr[10] = 20;
                g.cop0[15] = 0x59;
                Some(g)
            },
        },
    ];

    for test in tests {
        run_test(&test);
    }
}

#[test]
fn test_bgtz() {
    let tests = vec![
        TestCase {
            name: "bgtz_positive",
            asm: "
                bgtz $t1, 4
                nop
            ",
            setup: |ee| {
                ee.write_register32(9, 42);
            },
            golden: {
                let mut g = GoldenState::default();
                g.pc = 0xBFC00010;
                g.gpr[9] = 42;
                g.cop0[15] = 0x59;
                Some(g)
            },
        },
        TestCase {
            name: "bgtz_zero",
            asm: "
                bgtz $t1, 4
                nop
            ",
            setup: |ee| {
                ee.write_register32(9, 0);
            },
            golden: {
                let mut g = GoldenState::default();
                g.pc = 0xBFC00008;
                g.gpr[9] = 0;
                g.cop0[15] = 0x59;
                Some(g)
            },
        },
        TestCase {
            name: "bgtz_negative",
            asm: "
                bgtz $t1, 4
                nop
            ",
            setup: |ee| {
                ee.write_register32(9, 0xFFFFFFFF);
            },
            golden: {
                let mut g = GoldenState::default();
                g.pc = 0xBFC00008;
                g.gpr[9] = 0xFFFFFFFF;
                g.cop0[15] = 0x59;
                Some(g)
            },
        },
        TestCase {
            name: "bgtz_large_positive",
            asm: "
                bgtz $t1, 4
                nop
            ",
            setup: |ee| {
                ee.write_register64(9, 0x7FFFFFFFFFFFFFFF);
            },
            golden: {
                let mut g = GoldenState::default();
                g.pc = 0xBFC00010;
                g.gpr[9] = 0x7FFFFFFFFFFFFFFF;
                g.cop0[15] = 0x59;
                Some(g)
            },
        },
    ];

    for test in tests {
        run_test(&test);
    }
}

#[test]
fn test_movn() {
    let tests = vec![
        TestCase {
            name: "movn_not_zero",
            asm: "movn $t0, $t1, $t2",
            setup: |ee| {
                ee.write_register32(9, 42);
                ee.write_register32(10, 1);
            },
            golden: {
                let mut g = GoldenState::default();
                g.pc = 0xBFC00004;
                g.gpr[8] = 42;
                g.gpr[9] = 42;
                g.gpr[10] = 1;
                g.cop0[15] = 0x59;
                Some(g)
            },
        },
        TestCase {
            name: "movn_zero",
            asm: "movn $t0, $t1, $t2",
            setup: |ee| {
                ee.write_register32(9, 42);
                ee.write_register32(10, 0);
            },
            golden: {
                let mut g = GoldenState::default();
                g.pc = 0xBFC00004;
                g.gpr[8] = 0;
                g.gpr[9] = 42;
                g.gpr[10] = 0;
                g.cop0[15] = 0x59;
                Some(g)
            },
        },
        TestCase {
            name: "movn_negative",
            asm: "movn $t0, $t1, $t2",
            setup: |ee| {
                ee.write_register32(9, 0xFFFFFFFF);
                ee.write_register32(10, 0xFFFFFFFE);
            },
            golden: {
                let mut g = GoldenState::default();
                g.pc = 0xBFC00004;
                g.gpr[8] = 0xFFFFFFFF;
                g.gpr[9] = 0xFFFFFFFF;
                g.gpr[10] = 0xFFFFFFFE;
                g.cop0[15] = 0x59;
                Some(g)
            },
        },
        TestCase {
            name: "movn_large_value",
            asm: "movn $t0, $t1, $t2",
            setup: |ee| {
                ee.write_register64(9, 0xFFFFFFFFFFFFFFFF);
                ee.write_register32(10, 1);
            },
            golden: {
                let mut g = GoldenState::default();
                g.pc = 0xBFC00004;
                g.gpr[8] = 0xFFFFFFFFFFFFFFFF;
                g.gpr[9] = 0xFFFFFFFFFFFFFFFF;
                g.gpr[10] = 1;
                g.cop0[15] = 0x59;
                Some(g)
            },
        },
    ];

    for test in tests {
        run_test(&test);
    }
}

#[test]
fn test_slt() {
    let tests = vec![
        TestCase {
            name: "slt_less",
            asm: "slt $t0, $t1, $t2",
            setup: |ee| {
                ee.write_register64(9, 0xFFFFFFFF_FFFFFFFB);
                ee.write_register64(10, 10);
            },
            golden: {
                let mut g = GoldenState::default();
                g.pc = 0xBFC00004;
                g.gpr[8] = 1;
                g.gpr[9] = 0xFFFFFFFF_FFFFFFFB;
                g.gpr[10] = 10;
                g.cop0[15] = 0x59;
                Some(g)
            },
        },
        TestCase {
            name: "slt_equal",
            asm: "slt $t0, $t1, $t2",
            setup: |ee| {
                ee.write_register64(9, 42);
                ee.write_register64(10, 42);
            },
            golden: {
                let mut g = GoldenState::default();
                g.pc = 0xBFC00004;
                g.gpr[8] = 0;
                g.gpr[9] = 42;
                g.gpr[10] = 42;
                g.cop0[15] = 0x59;
                Some(g)
            },
        },
        TestCase {
            name: "slt_greater",
            asm: "slt $t0, $t1, $t2",
            setup: |ee| {
                ee.write_register64(9, 50);
                ee.write_register64(10, 20);
            },
            golden: {
                let mut g = GoldenState::default();
                g.pc = 0xBFC00004;
                g.gpr[8] = 0;
                g.gpr[9] = 50;
                g.gpr[10] = 20;
                g.cop0[15] = 0x59;
                Some(g)
            },
        },
        TestCase {
            name: "slt_negative_both",
            asm: "slt $t0, $t1, $t2",
            setup: |ee| {
                ee.write_register64(9, 0xFFFFFFFF_FFFFFFFE);
                ee.write_register64(10, 0xFFFFFFFF_FFFFFFFF);
            },
            golden: {
                let mut g = GoldenState::default();
                g.pc = 0xBFC00004;
                g.gpr[8] = 1;
                g.gpr[9] = 0xFFFFFFFF_FFFFFFFE;
                g.gpr[10] = 0xFFFFFFFF_FFFFFFFF;
                g.cop0[15] = 0x59;
                Some(g)
            },
        },
        TestCase {
            name: "slt_zero",
            asm: "slt $t0, $zero, $t2",
            setup: |ee| {
                ee.write_register64(10, 1);
            },
            golden: {
                let mut g = GoldenState::default();
                g.pc = 0xBFC00004;
                g.gpr[8] = 1;
                g.gpr[10] = 1;
                g.cop0[15] = 0x59;
                Some(g)
            },
        },
    ];

    for test in tests {
        run_test(&test);
    }
}

#[test]
fn test_and() {
    let tests = vec![
        TestCase {
            name: "and_basic",
            asm: "and $t0, $t1, $t2",
            setup: |ee| {
                ee.write_register32(9, 0xF0F0F0F0);
                ee.write_register32(10, 0x0F0F0F0F);
            },
            golden: {
                let mut g = GoldenState::default();
                g.pc = 0xBFC00004;
                g.gpr[8] = 0;
                g.gpr[9] = 0xF0F0F0F0;
                g.gpr[10] = 0x0F0F0F0F;
                g.cop0[15] = 0x59;
                Some(g)
            },
        },
        TestCase {
            name: "and_same",
            asm: "and $t0, $t1, $t1",
            setup: |ee| {
                ee.write_register32(9, 0x12345678);
            },
            golden: {
                let mut g = GoldenState::default();
                g.pc = 0xBFC00004;
                g.gpr[8] = 0x12345678;
                g.gpr[9] = 0x12345678;
                g.cop0[15] = 0x59;
                Some(g)
            },
        },
        TestCase {
            name: "and_zero",
            asm: "and $t0, $t1, $zero",
            setup: |ee| {
                ee.write_register32(9, 0xFFFFFFFF);
            },
            golden: {
                let mut g = GoldenState::default();
                g.pc = 0xBFC00004;
                g.gpr[8] = 0;
                g.gpr[9] = 0xFFFFFFFF;
                g.cop0[15] = 0x59;
                Some(g)
            },
        },
        TestCase {
            name: "and_max",
            asm: "and $t0, $t1, $t2",
            setup: |ee| {
                ee.write_register64(9, 0xFFFFFFFFFFFFFFFF);
                ee.write_register64(10, 0xFFFFFFFFFFFFFFFF);
            },
            golden: {
                let mut g = GoldenState::default();
                g.pc = 0xBFC00004;
                g.gpr[8] = 0xFFFFFFFFFFFFFFFF;
                g.gpr[9] = 0xFFFFFFFFFFFFFFFF;
                g.gpr[10] = 0xFFFFFFFFFFFFFFFF;
                g.cop0[15] = 0x59;
                Some(g)
            },
        },
    ];

    for test in tests {
        run_test(&test);
    }
}

#[test]
fn test_srl() {
    let tests = vec![
        TestCase {
            name: "srl_basic",
            asm: "srl $t0, $t1, 4",
            setup: |ee| {
                ee.write_register32(9, 0xF0F0F0F0);
            },
            golden: {
                let mut g = GoldenState::default();
                g.pc = 0xBFC00004;
                g.gpr[8] = 0x0F0F0F0F;
                g.gpr[9] = 0xF0F0F0F0;
                g.cop0[15] = 0x59;
                Some(g)
            },
        },
        TestCase {
            name: "srl_zero",
            asm: "srl $t0, $t1, 0",
            setup: |ee| {
                ee.write_register32(9, 0x12345678);
            },
            golden: {
                let mut g = GoldenState::default();
                g.pc = 0xBFC00004;
                g.gpr[8] = 0x12345678;
                g.gpr[9] = 0x12345678;
                g.cop0[15] = 0x59;
                Some(g)
            },
        },
        TestCase {
            name: "srl_max_shift",
            asm: "srl $t0, $t1, 31",
            setup: |ee| {
                ee.write_register32(9, 0x80000000);
            },
            golden: {
                let mut g = GoldenState::default();
                g.pc = 0xBFC00004;
                g.gpr[8] = 1;
                g.gpr[9] = 0x80000000;
                g.cop0[15] = 0x59;
                Some(g)
            },
        },
        TestCase {
            name: "srl_negative",
            asm: "srl $t0, $t1, 1",
            setup: |ee| {
                ee.write_register32(9, 0x80000000);
            },
            golden: {
                let mut g = GoldenState::default();
                g.pc = 0xBFC00004;
                g.gpr[8] = 0x40000000;
                g.gpr[9] = 0x80000000;
                g.cop0[15] = 0x59;
                Some(g)
            },
        },
    ];

    for test in tests {
        run_test(&test);
    }
}

#[test]
fn test_lhu() {
    let tests = vec![
        TestCase {
            name: "lhu_basic",
            asm: "lhu $t0, 0($t1)",
            setup: |ee| {
                ee.write_register32(9, 0x1000);
                ee.write16(0x1000, 0x1234);
            },
            golden: {
                let mut g = GoldenState::default();
                g.pc = 0xBFC00004;
                g.gpr[8] = 0x1234;
                g.gpr[9] = 0x1000;
                g.cop0[15] = 0x59;
                Some(g)
            },
        },
        TestCase {
            name: "lhu_zero",
            asm: "lhu $t0, 0($t1)",
            setup: |ee| {
                ee.write_register32(9, 0x1000);
                ee.write16(0x1000, 0x0000);
            },
            golden: {
                let mut g = GoldenState::default();
                g.pc = 0xBFC00004;
                g.gpr[8] = 0;
                g.gpr[9] = 0x1000;
                g.cop0[15] = 0x59;
                Some(g)
            },
        },
        TestCase {
            name: "lhu_max",
            asm: "lhu $t0, 0($t1)",
            setup: |ee| {
                ee.write_register32(9, 0x1004);
                ee.write16(0x1004, 0xFFFF);
            },
            golden: {
                let mut g = GoldenState::default();
                g.pc = 0xBFC00004;
                g.gpr[8] = 0xFFFF;
                g.gpr[9] = 0x1004;
                g.cop0[15] = 0x59;
                Some(g)
            },
        },
        TestCase {
            name: "lhu_offset",
            asm: "lhu $t0, 2($t1)",
            setup: |ee| {
                ee.write_register32(9, 0x1000);
                ee.write16(0x1002, 0xABCD);
            },
            golden: {
                let mut g = GoldenState::default();
                g.pc = 0xBFC00004;
                g.gpr[8] = 0xABCD;
                g.gpr[9] = 0x1000;
                g.cop0[15] = 0x59;
                Some(g)
            },
        },
    ];

    for test in tests {
        run_test(&test);
    }
}

#[test]
fn test_bltz() {
    let tests = vec![
        TestCase {
            name: "bltz_negative",
            asm: "
                bltz $t1, 4
                nop
            ",
            setup: |ee| {
                ee.write_register32(9, 0xFFFFFFFF);
            },
            golden: {
                let mut g = GoldenState::default();
                g.pc = 0xBFC00010;
                g.gpr[9] = 0xFFFFFFFF;
                g.cop0[15] = 0x59;
                Some(g)
            },
        },
        TestCase {
            name: "bltz_zero",
            asm: "
                bltz $t1, 4
                nop
            ",
            setup: |ee| {
                ee.write_register32(9, 0);
            },
            golden: {
                let mut g = GoldenState::default();
                g.pc = 0xBFC00008;
                g.gpr[9] = 0;
                g.cop0[15] = 0x59;
                Some(g)
            },
        },
        TestCase {
            name: "bltz_positive",
            asm: "
                bltz $t1, 4
                nop
            ",
            setup: |ee| {
                ee.write_register32(9, 42);
            },
            golden: {
                let mut g = GoldenState::default();
                g.pc = 0xBFC00008;
                g.gpr[9] = 42;
                g.cop0[15] = 0x59;
                Some(g)
            },
        },
        TestCase {
            name: "bltz_large_negative",
            asm: "
                bltz $t1, 4
                nop
            ",
            setup: |ee| {
                ee.write_register64(9, 0xFFFFFFFFFFFFFFFF);
            },
            golden: {
                let mut g = GoldenState::default();
                g.pc = 0xBFC00010;
                g.gpr[9] = 0xFFFFFFFFFFFFFFFF;
                g.cop0[15] = 0x59;
                Some(g)
            },
        },
    ];

    for test in tests {
        run_test(&test);
    }
}

#[test]
fn test_bltzl() {
    let tests = vec![
        TestCase {
            name: "bltzl_taken",
            asm: "
                bltzl $t1, 8
                sll $zero, $zero, 0
                addiu $t4, $zero, 5
            ",
            setup: |ee| {
                ee.write_register32(9, 0xFFFFFFFF);
            },
            golden: {
                let mut g = GoldenState::default();
                g.pc = 0xBFC0000C;
                g.gpr[9] = 0xFFFFFFFF;
                g.gpr[12] = 0;
                g.cop0[15] = 0x59;
                Some(g)
            },
        },
        TestCase {
            name: "bltzl_not_taken",
            asm: "
                bltzl $t1, 8
                sll $zero, $zero, 0
                addiu $t4, $zero, 7
            ",
            setup: |ee| {
                ee.write_register32(9, 0);
            },
            golden: {
                let mut g = GoldenState::default();
                g.pc = 0xBFC00008;
                g.gpr[9] = 0;
                g.gpr[12] = 7;
                g.cop0[15] = 0x59;
                Some(g)
            },
        },
        TestCase {
            name: "bltzl_positive",
            asm: "
                bltzl $t1, 8
                sll $zero, $zero, 0
                addiu $t4, $zero, 7
            ",
            setup: |ee| {
                ee.write_register32(9, 42);
            },
            golden: {
                let mut g = GoldenState::default();
                g.pc = 0xBFC00008;
                g.gpr[9] = 42;
                g.gpr[12] = 7;
                g.cop0[15] = 0x59;
                Some(g)
            },
        },
    ];

    for test in tests {
        run_test(&test);
    }
}

#[test]
fn test_bgezl() {
    let tests = vec![
        TestCase {
            name: "bgezl_positive",
            asm: "
                bgezl $t1, 8
                sll $zero, $zero, 0
                addiu $t4, $zero, 5
            ",
            setup: |ee| {
                ee.write_register32(9, 42);
            },
            golden: {
                let mut g = GoldenState::default();
                g.pc = 0xBFC0000C;
                g.gpr[9] = 42;
                g.gpr[12] = 0;
                g.cop0[15] = 0x59;
                Some(g)
            },
        },
        TestCase {
            name: "bgezl_zero",
            asm: "
                bgezl $t1, 8
                sll $zero, $zero, 0
                addiu $t4, $zero, 7
            ",
            setup: |ee| {
                ee.write_register32(9, 0);
            },
            golden: {
                let mut g = GoldenState::default();
                g.pc = 0xBFC0000C;
                g.gpr[9] = 0;
                g.gpr[12] = 0;
                g.cop0[15] = 0x59;
                Some(g)
            },
        },
        TestCase {
            name: "bgezl_negative",
            asm: "
                bgezl $t1, 8
                sll $zero, $zero, 0
                addiu $t4, $zero, 7
            ",
            setup: |ee| {
                ee.write_register32(9, 0xFFFFFFFF);
            },
            golden: {
                let mut g = GoldenState::default();
                g.pc = 0xBFC00008;
                g.gpr[9] = 0xFFFFFFFF;
                g.gpr[12] = 7;
                g.cop0[15] = 0x59;
                Some(g)
            },
        },
    ];

    for test in tests {
        run_test(&test);
    }
}

#[test]
fn test_sh() {
    let tests = vec![
        TestCase {
            name: "sh_basic",
            asm: "
                lui $t0, 0x0000
                ori $t0, $t0, 0x1000
                li $t1, 0x12345678
                sh $t1, 0($t0)
            ",
            setup: |_| {},
            golden: {
                let mut g = GoldenState::default();
                g.pc = 0xBFC00010;
                g.gpr[8] = 0x1000;
                g.gpr[9] = 0x12345678;
                g.cop0[15] = 0x59;
                g.memory_checks = vec![(0x1000, 0x5678)];
                Some(g)
            },
        },
        TestCase {
            name: "sh_zero",
            asm: "
                lui $t0, 0x0000
                ori $t0, $t0, 0x1000
                li $t1, 0x00000000
                sh $t1, 0($t0)
            ",
            setup: |_| {},
            golden: {
                let mut g = GoldenState::default();
                g.pc = 0xBFC00010;
                g.gpr[8] = 0x1000;
                g.gpr[9] = 0x00000000;
                g.cop0[15] = 0x59;
                g.memory_checks = vec![(0x1000, 0x0000)];
                Some(g)
            },
        },
        TestCase {
            name: "sh_max",
            asm: "
                lui $t0, 0x0000
                ori $t0, $t0, 0x1004
                li $t1, 0xFFFFFFFF
                sh $t1, 0($t0)
            ",
            setup: |_| {},
            golden: {
                let mut g = GoldenState::default();
                g.pc = 0xBFC00010;
                g.gpr[8] = 0x1004;
                g.gpr[9] = 0xFFFFFFFF;
                g.cop0[15] = 0x59;
                g.memory_checks = vec![(0x1004, 0xFFFF)];
                Some(g)
            },
        },
        TestCase {
            name: "sh_offset",
            asm: "
                lui $t0, 0x0000
                ori $t0, $t0, 0x1000
                li $t1, 0x12345678
                sh $t1, 4($t0)
            ",
            setup: |_| {},
            golden: {
                let mut g = GoldenState::default();
                g.pc = 0xBFC00010;
                g.gpr[8] = 0x1000;
                g.gpr[9] = 0x12345678;
                g.cop0[15] = 0x59;
                g.memory_checks = vec![(0x1004, 0x5678)];
                Some(g)
            },
        },
    ];

    for test in tests {
        run_test(&test);
    }
}
