use crate::testing::{OpcodeTestSpec, RegExpect, RegInit};

const S0: usize = 16;
const S1: usize = 17;
const S2: usize = 18;

const BASE: u32 = 0xBFC0_0000;

pub fn all() -> Vec<OpcodeTestSpec> {
    let mut v = Vec::new();
    v.extend(and());
    v
}

pub fn and() -> Vec<OpcodeTestSpec> {
    vec![
        OpcodeTestSpec {
            name: "and_basic",
            family: "AND",
            asm: "and $s2, $s0, $s1",
            init_gpr: vec![RegInit::gpr(S0, 0xFF00FF00), RegInit::gpr(S1, 0x0F0F0F0F)],
            init_hi: None,
            init_lo: None,
            expected_gpr: vec![RegExpect::gpr(S2, 0x0F000F00)],
            expected_hi: None,
            expected_lo: None,
            expected_mem: vec![],
            expected_pc: Some(BASE + 4),
        },
        OpcodeTestSpec {
            name: "and_with_zero",
            family: "AND",
            asm: "and $s2, $s0, $zero",
            init_gpr: vec![RegInit::gpr(S0, 0xDEAD_BEEF)],
            init_hi: None,
            init_lo: None,
            expected_gpr: vec![RegExpect::gpr(S2, 0)],
            expected_hi: None,
            expected_lo: None,
            expected_mem: vec![],
            expected_pc: Some(BASE + 4),
        },
        OpcodeTestSpec {
            name: "and_all_ones",
            family: "AND",
            asm: "and $s2, $s0, $s1",
            init_gpr: vec![
                RegInit::gpr(S0, u64::MAX as u128),
                RegInit::gpr(S1, u64::MAX as u128),
            ],
            init_hi: None,
            init_lo: None,
            expected_gpr: vec![RegExpect::gpr(S2, u64::MAX as u128)],
            expected_hi: None,
            expected_lo: None,
            expected_mem: vec![],
            expected_pc: Some(BASE + 4),
        },
        OpcodeTestSpec {
            name: "and_preserves_upper_bits",
            family: "AND",
            asm: "and $s2, $s0, $s1",
            init_gpr: vec![
                RegInit::gpr(S0, 0x3),
                RegInit::gpr(S1, 0x1),
                RegInit::gpr(S2, 0x12345678_9ABCDEF0_CAFEBABE_00000000),
            ],
            init_hi: None,
            init_lo: None,
            expected_gpr: vec![RegExpect::gpr(S2, 0x12345678_9ABCDEF0_00000000_00000001)],
            expected_hi: None,
            expected_lo: None,
            expected_mem: vec![],
            expected_pc: Some(BASE + 4),
        },
    ]
}
