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
    ee_jit:         &EE,
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
    }
}

struct TestCase {
    name:   &'static str,
    asm:    &'static str,
    setup:  fn(&mut EE),
    golden: Option<GoldenState>,
}

fn run_test(tc: &TestCase) {
    let bios = create_mock_bios(tc.asm);
    let bus  = Bus::new(BusMode::Ranged, bios);

    let mut ee_i = EE::new(bus.clone());
    let mut ee_j = EE::new(bus.clone());
    (tc.setup)(&mut ee_i);
    (tc.setup)(&mut ee_j);

    ee_i.set_pc(0xBFC00000);
    ee_j.set_pc(0xBFC00000);

    let mut interp = Interpreter::new(ee_i);
    let mut jit    = JIT::new(&mut ee_j);
    interp.step();
    jit.step();

    compare_states(&interp.cpu, &jit.cpu, tc.golden.as_ref());
}

#[test]
fn test_mfc0() {
    let test = TestCase {
        name:  "mfc0",
        asm:   "mfc0 $v0, $1",
        setup: |ee| ee.write_cop0_register(1, 42),
        golden: {
            let mut g = GoldenState::default();
            g.pc          = 0xBFC00004;
            g.cop0[1]     = 42;
            g.gpr[2]      = 42;
            g.cop0[15]  = 0x59;
            Some(g)
        },
    };
    run_test(&test);
}

#[test]
fn test_sll() {
    let test = TestCase {
        name:  "sll",
        asm:   "sll $at, $v0, 4",
        setup: |ee| ee.write_register32(2, 0x0000000F),
        golden: {
            let mut g = GoldenState::default();
            g.pc        = 0xBFC00004;
            g.gpr[2]    = 0x0F;
            g.gpr[1]    = 0xF0;
            g.cop0[15]  = 0x59;
            Some(g)
        },
    };
    run_test(&test);
}

#[test]
fn test_slti() {
    let test = TestCase {
        name:  "slti",
        asm:   "slti $v0, $t0, 4",
        setup: |ee| ee.write_register32(8, 2),
        golden: {
            let mut g = GoldenState::default();
            g.pc        = 0xBFC00004;
            g.gpr[8]    = 2;
            g.gpr[2]    = 1;
            g.cop0[15]  = 0x59;
            Some(g)
        },
    };
    run_test(&test);
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
    ];

    for test in tests {
        println!("Running test case: {}", test.name);
        run_test(&test);
    }
}

#[test]
fn test_lui() {
    let test = TestCase {
        name:  "lui",
        asm:   "lui $t0, 0x1234",
        setup: |ee| ee.write_register32(8, 0),
        golden: {
            let mut g = GoldenState::default();
            g.pc        = 0xBFC00004;
            g.gpr[8]    = 0x12340000;
            g.cop0[15]  = 0x59;
            Some(g)
        },
    };
    run_test(&test);
}

#[test]
fn test_ori() {
    let test = TestCase {
        name:  "ori",
        asm:   "ori $t0, $t0, 0x1234",
        setup: |ee| ee.write_register32(8, 0),
        golden: {
            let mut g = GoldenState::default();
            g.pc        = 0xBFC00004;
            g.gpr[8]    = 0x00001234;
            g.cop0[15]  = 0x59;
            Some(g)
        },
    };
    run_test(&test);
}