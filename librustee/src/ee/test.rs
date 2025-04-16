use crate::{
    bus::{Bus, BusMode},
    cpu::{EmulationBackend, CPU},
    ee::{Interpreter, JIT, EE},
    BIOS,
};
use colored::Colorize;
use mipsasm::Mipsasm;

fn create_mock_bios(assembly: &str) -> BIOS {
    let assembler = Mipsasm::new();

    let binary_u32 = assembler.assemble(assembly).expect("Failed to assemble MIPS code");

    let binary_u8: Vec<u8> = binary_u32
        .iter()
        .flat_map(|word| word.to_le_bytes())
        .collect();

    BIOS::test_only(binary_u8)
}

fn compare_states(ee_interpreter: &EE, ee_jit: &EE) {
    let mips_register_names = [
        "zero", "at", "v0", "v1", "a0", "a1", "a2", "a3", "t0", "t1", "t2", "t3", "t4", "t5", "t6", "t7",
        "s0", "s1", "s2", "s3", "s4", "s5", "s6", "s7", "t8", "t9", "k0", "k1", "gp", "sp", "fp", "ra",
    ];

    assert_eq!(
        ee_interpreter.pc(),
        ee_jit.pc(),
        "{}",
        format!(
            "EE PC mismatch: Interpreter = {}, JIT = {}",
            format!("0x{:08X}", ee_interpreter.pc()).red(),
            format!("0x{:08X}", ee_jit.pc()).red()
        )
    );

    for i in 0..32 {
        assert_eq!(
            ee_interpreter.read_register(i),
            ee_jit.read_register(i),
            "{}",
            format!(
                "EE Register ${} mismatch: Interpreter = {}, JIT = {}",
                mips_register_names[i],
                format!("0x{:032X}", ee_interpreter.read_register(i)).red(),
                format!("0x{:032X}", ee_jit.read_register(i)).red()
            )
        );
    }

    for i in 0..32 {
        assert_eq!(
            ee_interpreter.read_cop0_register(i),
            ee_jit.read_cop0_register(i),
            "{}",
            format!(
                "EE COP0 Register {} mismatch: Interpreter = {}, JIT = {}",
                i,
                format!("0x{:08X}", ee_interpreter.read_cop0_register(i)).red(),
                format!("0x{:08X}", ee_jit.read_cop0_register(i)).red()
            )
        );
    }
}

fn test_opcode<F>(assembly: &str, mut setup: F)
where
    F: FnMut(&mut EE),
{
    let bios = create_mock_bios(assembly);

    let bus = Bus::new(BusMode::Ranged, bios);

    let mut ee_interpreter = EE::new(bus.clone());
    let mut ee_jit = EE::new(bus.clone());

    setup(&mut ee_interpreter);
    setup(&mut ee_jit);

    let mut interpreter = Interpreter::new(ee_interpreter);
    let mut jit = JIT::new(&mut ee_jit);

    interpreter.cpu.set_pc(0xBFC00000);
    jit.cpu.set_pc(0xBFC00000);

    interpreter.step();
    jit.step();

    compare_states(&interpreter.cpu, &jit.cpu);
}

#[test]
fn test_mfc0() {
    let assembly = "mfc0 $1, $0";

    test_opcode(assembly, |ee| {
        ee.write_cop0_register(1, 42);
    });
}
