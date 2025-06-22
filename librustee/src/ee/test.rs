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
    cop0: [u32; 32],
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

    for bus_mode in bus_modes {
        println!("Running test `{}` for bus mode {:?}", tc.name, bus_mode);

        // Create mock BIOS for both interpreter and JIT
        let bios_i = create_mock_bios(tc.asm);
        let bios_j = create_mock_bios(tc.asm);

        // Create buses with the current bus mode
        let bus_i = Bus::new(bus_mode.clone(), bios_i);
        let bus_j = Bus::new(bus_mode.clone(), bios_j);

        // Create EE instances for interpreter and JIT
        let mut ee_i = EE::new(bus_i);
        let mut ee_j = EE::new(bus_j);

        // Test setup
        (tc.setup)(&mut ee_i);
        (tc.setup)(&mut ee_j);

        // Set program counters
        ee_i.set_pc(0xBFC00000);
        ee_j.set_pc(0xBFC00000);

        // Run the interpreter backend
        let mut interp = Interpreter::new(ee_i);
        interp.step();

        // Run the JIT backend
        let mut jit = JIT::new(&mut ee_j);
        jit.step();

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