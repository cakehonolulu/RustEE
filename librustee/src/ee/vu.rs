use std::boxed::Box;

#[derive(Clone)]
pub struct VU {
    // Vector floating-point registers
    pub vf: [u128; 32],
    // Integer registers
    pub vi: [u16; 16],
    // Special registers
    pub acc: u128, // Accumulator
    pub q: u32,    // Q register (boolean)
    pub p: u32,    // P register (boolean)
    // MAC and Clip flags
    pub mac_flags: u16,
    pub clip_flags: u32,
    pub status_flags: u32,
    // Memory
    pub instr_mem: Vec<u8>,
    pub data_mem: Vec<u8>,
    pub instr_size: usize,
    pub data_size: usize,
}

impl VU {
    /// Create a new VU with given instruction and data memory sizes
    pub fn new(instr_size: usize, data_size: usize) -> Self {
        let mut vu = VU {
            vf: [0; 32],
            vi: [0; 16],
            acc: 0,
            q: 0,
            p: 0,
            mac_flags: 0,
            clip_flags: 0,
            status_flags: 0,
            instr_mem: vec![0; instr_size],
            data_mem: vec![0; data_size],
            instr_size,
            data_size,
        };
        vu.reset();
        vu
    }

    /// Reset VU state and memories
    pub fn reset(&mut self) {
        // Zero memories
        self.instr_mem.fill(0);
        self.data_mem.fill(0);
        // Zero registers
        for reg in &mut self.vf {
            *reg = 0;
        }
        self.vi.fill(0);
        // According to spec, ACC.x = 0, ACC.w = 1.0
        self.acc = 1;
        // Q and P are booleans stored in low bit
        self.q = 0;
        self.p = 0;
        self.mac_flags = 0;
        self.clip_flags = 0;
        self.status_flags = 0;
    }

    /// Execute a single VU micro-instruction (stub)
    pub fn step(&mut self) {
        // TODO: fetch-decode-execute from instr_mem
        unimplemented!("VU step not yet implemented");
    }
}
