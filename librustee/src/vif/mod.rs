use tracing::{error, trace};

/// Base addresses for VIF0 and VIF1 I/O registers
pub const VIF0_BASE: u32 = 0x1000_3800;
pub const VIF1_BASE: u32 = 0x1000_3C00;

/// VIF I/O register offsets
const VIF_STAT_OFFSET: u32 = 0x00; // Status register (R/W for some bits)
const VIF_FBRST_OFFSET: u32 = 0x10; // Force break/reset (W)
const VIF_ERR_OFFSET: u32 = 0x20; // Error control (R/W)
const VIF_MARK_OFFSET: u32 = 0x30; // MARK value (R/W)
const VIF_CYCLE_OFFSET: u32 = 0x40; // Cycle length (R/W)
const VIF_MODE_OFFSET: u32 = 0x50; // Addition mode for UNPACK (R/W)
const VIF_NUM_OFFSET: u32 = 0x60; // Untransferred data (R/W)
const VIF_MASK_OFFSET: u32 = 0x70; // Write mask matrix (R/W)
const VIF_CODE_OFFSET: u32 = 0x80; // Last processed command (R)
const VIF_ITOPS_OFFSET: u32 = 0x90; // ITOPS value (R/W)
const VIF_BASE_OFFSET: u32 = 0xA0; // BASE value (VIF1 only, R/W)
const VIF_OFST_OFFSET: u32 = 0xB0; // OFST value (VIF1 only, R/W)
const VIF_TOPS_OFFSET: u32 = 0xC0; // TOPS value (VIF1 only, R)
const VIF_ITOP_OFFSET: u32 = 0xD0; // ITOP value (R/W)
const VIF_TOP_OFFSET: u32 = 0xE0; // TOP value (VIF1 only, R)
const VIF_R0_OFFSET: u32 = 0x100; // Row filling data 0 (R/W)
const VIF_R1_OFFSET: u32 = 0x110; // Row filling data 1 (R/W)
const VIF_R2_OFFSET: u32 = 0x120; // Row filling data 2 (R/W)
const VIF_R3_OFFSET: u32 = 0x130; // Row filling data 3 (R/W)
const VIF_C0_OFFSET: u32 = 0x140; // Column filling data 0 (R/W)
const VIF_C1_OFFSET: u32 = 0x150; // Column filling data 1 (R/W)
const VIF_C2_OFFSET: u32 = 0x160; // Column filling data 2 (R/W)
const VIF_C3_OFFSET: u32 = 0x170; // Column filling data 3 (R/W)

/// VIF I/O register block
#[derive(Debug)]
pub struct VIF {
    /// Base address (VIF0: 0x10003800, VIF1: 0x10003C00)
    base: u32,
    /// VIF_STAT: status bits
    stat: u32,
    /// VIF_FBRST: force break/reset (write-only)
    fbrst: u32,
    /// VIF_ERR: error control bits
    err: u32,
    /// VIF_MARK: most recently set MARK value
    mark: u32,
    /// VIF_CYCLE: cycle length (CL) and write cycle length (WL)
    cycle: u32,
    /// VIF_MODE: addition mode for UNPACK
    mode: u32,
    /// VIF_NUM: amount of untransferred data
    num: u32,
    /// VIF_MASK: write mask matrix
    mask: u32,
    /// VIF_CODE: last processed command (IMMEDIATE, NUM, CMD)
    code: u32,
    /// VIF_ITOPS: ITOPS value
    itops: u32,
    /// VIF_BASE: BASE value (VIF1 only)
    base_val: u32,
    /// VIF_OFST: OFST value (VIF1 only)
    ofst: u32,
    /// VIF_TOPS: TOPS value (VIF1 only)
    tops: u32,
    /// VIF_ITOP: ITOP value
    itop: u32,
    /// VIF_TOP: TOP value (VIF1 only)
    top: u32,
    /// VIF_RN: row filling data (4 x 32-bit)
    row: [u32; 4],
    /// VIF_CN: column filling data (4 x 32-bit)
    col: [u32; 4],
}

impl VIF {
    /// Create a new VIF I/O block with all registers zeroed
    pub fn new(base: u32) -> Self {
        if base != VIF0_BASE && base != VIF1_BASE {
            error!("Invalid VIF base address: 0x{:08X}", base);
        }
        VIF {
            base,
            stat: 0,
            fbrst: 0,
            err: 0,
            mark: 0,
            cycle: 0,
            mode: 0,
            num: 0,
            mask: 0,
            code: 0,
            itops: 0,
            base_val: 0,
            ofst: 0,
            tops: 0,
            itop: 0,
            top: 0,
            row: [0; 4],
            col: [0; 4],
        }
    }

    /// Write a 32-bit value to a VIF register
    pub fn write32(&mut self, addr: u32, value: u32) {
        let offset = addr - self.base;
        match offset {
            VIF_STAT_OFFSET => {
                // Only specific bits are writable (e.g., clear MRK)
                // Typically, STAT is read-only, but writes may clear flags like MRK
                trace!(
                    "Write to VIF_STAT (offset {:#X}): value=0x{:08X}",
                    offset, value
                );
            }
            VIF_FBRST_OFFSET => {
                self.fbrst = value & 0x0F; // RST, FBK, STP, STC
                if self.fbrst & 0x01 != 0 {
                    // RST: Reset VIF and FIFO
                    self.stat = 0;
                    self.mark = 0;
                    self.num = 0;
                    self.code = 0;
                    trace!("VIF reset triggered");
                }
                if self.fbrst & 0x02 != 0 {
                    // FBK: Force break, set VFS
                    self.stat |= 1 << 9;
                    trace!("VIF force break triggered");
                }
                if self.fbrst & 0x04 != 0 {
                    // STP: Stop VIF, set VSS
                    self.stat |= 1 << 8;
                    trace!("VIF stop triggered");
                }
                if self.fbrst & 0x08 != 0 {
                    // STC: Clear stalls and errors
                    self.stat &=
                        !((1 << 8) | (1 << 9) | (1 << 10) | (1 << 11) | (1 << 12) | (1 << 13));
                    trace!("VIF stall cancel triggered");
                }
            }
            VIF_ERR_OFFSET => {
                self.err = value & 0x07; // MII, ME0, ME1
                trace!(
                    "VIF_ERR set: MII={}, ME0={}, ME1={}",
                    (value & 0x01) != 0,
                    (value & 0x02) != 0,
                    (value & 0x04) != 0
                );
            }
            VIF_MARK_OFFSET => {
                self.mark = value & 0xFFFF; // 16-bit MARK value
                self.stat &= !(1 << 6); // Clear MRK flag
                trace!("VIF_MARK set: value=0x{:04X}, MRK flag cleared", self.mark);
            }
            VIF_CYCLE_OFFSET => {
                self.cycle = value & 0xFFFF; // CL (0-7), WL (8-15)
                trace!(
                    "VIF_CYCLE set: CL={}, WL={}",
                    value & 0xFF,
                    (value >> 8) & 0xFF
                );
            }
            VIF_MODE_OFFSET => {
                self.mode = value & 0x03; // Addition mode (0-1)
                trace!("VIF_MODE set: mode={}", self.mode);
            }
            VIF_NUM_OFFSET => {
                self.num = value & 0xFF; // 8-bit untransferred data
                trace!("VIF_NUM set: num={}", self.num);
            }
            VIF_MASK_OFFSET => {
                self.mask = value; // 32-bit write mask
                trace!("VIF_MASK set: mask=0x{:08X}", self.mask);
            }
            VIF_CODE_OFFSET => {
                trace!(
                    "Attempt to write read-only VIF_CODE (offset {:#X}): value=0x{:08X}",
                    offset, value
                );
            }
            VIF_ITOPS_OFFSET => {
                self.itops = value & 0x3FF; // 10-bit ITOPS
                trace!("VIF_ITOPS set: itops=0x{:03X}", self.itops);
            }
            VIF_BASE_OFFSET if self.base == VIF1_BASE => {
                self.base_val = value & 0x3FF; // 10-bit BASE (VIF1 only)
                trace!("VIF1_BASE set: base=0x{:03X}", self.base_val);
            }
            VIF_OFST_OFFSET if self.base == VIF1_BASE => {
                self.ofst = value & 0x3FF; // 10-bit OFST (VIF1 only)
                trace!("VIF1_OFST set: ofst=0x{:03X}", self.ofst);
            }
            VIF_TOPS_OFFSET => {
                trace!(
                    "Attempt to write read-only VIF_TOPS (offset {:#X}): value=0x{:08X}",
                    offset, value
                );
            }
            VIF_ITOP_OFFSET => {
                self.itop = value & 0x3FF; // 10-bit ITOP
                trace!("VIF_ITOP set: itop=0x{:03X}", self.itop);
            }
            VIF_TOP_OFFSET => {
                trace!(
                    "Attempt to write read-only VIF_TOP (offset {:#X}): value=0x{:08X}",
                    offset, value
                );
            }
            VIF_R0_OFFSET => {
                self.row[0] = value;
                trace!("VIF_R0 set: row[0]=0x{:08X}", value);
            }
            VIF_R1_OFFSET => {
                self.row[1] = value;
                trace!("VIF_R1 set: row[1]=0x{:08X}", value);
            }
            VIF_R2_OFFSET => {
                self.row[2] = value;
                trace!("VIF_R2 set: row[2]=0x{:08X}", value);
            }
            VIF_R3_OFFSET => {
                self.row[3] = value;
                trace!("VIF_R3 set: row[3]=0x{:08X}", value);
            }
            VIF_C0_OFFSET => {
                self.col[0] = value;
                trace!("VIF_C0 set: col[0]=0x{:08X}", value);
            }
            VIF_C1_OFFSET => {
                self.col[1] = value;
                trace!("VIF_C1 set: col[1]=0x{:08X}", value);
            }
            VIF_C2_OFFSET => {
                self.col[2] = value;
                trace!("VIF_C2 set: col[2]=0x{:08X}", value);
            }
            VIF_C3_OFFSET => {
                self.col[3] = value;
                trace!("VIF_C3 set: col[3]=0x{:08X}", value);
            }
            _ => {
                error!("Invalid VIF write offset: {:#X}", offset);
            }
        }
    }

    /// Read a 32-bit value from a VIF register
    pub fn read32(&self, addr: u32) -> u32 {
        let offset = addr - self.base;
        match offset {
            VIF_STAT_OFFSET => {
                // VPS (0-1), VEW (2), VGW (3, VIF1 only), MRK (6), DBF (7, VIF1 only),
                // VSS (8), VFS (9), VIS (10), INT (11), ER0 (12), ER1 (13), FDR (23, VIF1 only), FQC (24-28)
                let fqc_max = if self.base == VIF0_BASE { 8 } else { 16 };
                let mut stat = self.stat & 0x3FFF_7FC7; // Mask out reserved bits
                stat |= ((self.stat >> 24) & 0x1F).min(fqc_max) << 24; // Cap FQC
                stat
            }
            VIF_FBRST_OFFSET => {
                trace!(
                    "Attempt to read write-only VIF_FBRST (offset {:#X})",
                    offset
                );
                0
            }
            VIF_ERR_OFFSET => self.err,
            VIF_MARK_OFFSET => self.mark,
            VIF_CYCLE_OFFSET => self.cycle,
            VIF_MODE_OFFSET => self.mode,
            VIF_NUM_OFFSET => self.num,
            VIF_MASK_OFFSET => self.mask,
            VIF_CODE_OFFSET => self.code,
            VIF_ITOPS_OFFSET => self.itops,
            VIF_BASE_OFFSET if self.base == VIF1_BASE => self.base_val,
            VIF_OFST_OFFSET if self.base == VIF1_BASE => self.ofst,
            VIF_TOPS_OFFSET if self.base == VIF1_BASE => {
                // TOPS = BASE if DBF=0, else BASE + OFST
                if self.stat & (1 << 7) == 0 {
                    self.base_val
                } else {
                    self.base_val.wrapping_add(self.ofst)
                }
            }
            VIF_ITOP_OFFSET => self.itop,
            VIF_TOP_OFFSET if self.base == VIF1_BASE => self.top,
            VIF_R0_OFFSET => self.row[0],
            VIF_R1_OFFSET => self.row[1],
            VIF_R2_OFFSET => self.row[2],
            VIF_R3_OFFSET => self.row[3],
            VIF_C0_OFFSET => self.col[0],
            VIF_C1_OFFSET => self.col[1],
            VIF_C2_OFFSET => self.col[2],
            VIF_C3_OFFSET => self.col[3],
            _ => {
                error!("Invalid VIF read offset: {:#X}", offset);
                0
            }
        }
    }

    /// Update VIF_STAT with new status bits
    pub fn update_stat(
        &mut self,
        vps: u32,
        vew: bool,
        vgw: bool,
        mrk: bool,
        dbf: bool,
        vss: bool,
        vfs: bool,
        vis: bool,
        int: bool,
        er0: bool,
        er1: bool,
        fdr: bool,
        fqc: u32,
    ) {
        let mut stat = (vps & 0x03) | // VPS (0-1)
            ((vew as u32) << 2) | // VEW (2)
            ((vgw as u32) << 3) | // VGW (3, VIF1 only)
            ((mrk as u32) << 6) | // MRK (6)
            ((dbf as u32) << 7) | // DBF (7, VIF1 only)
            ((vss as u32) << 8) | // VSS (8)
            ((vfs as u32) << 9) | // VFS (9)
            ((vis as u32) << 10) | // VIS (10)
            ((int as u32) << 11) | // INT (11)
            ((er0 as u32) << 12) | // ER0 (12)
            ((er1 as u32) << 13) | // ER1 (13)
            ((fdr as u32) << 23); // FDR (23, VIF1 only)
        let fqc_max = if self.base == VIF0_BASE { 8 } else { 16 };
        stat |= (fqc.min(fqc_max)) << 24; // FQC (24-28)
        self.stat = stat;
        trace!(
            "VIF_STAT updated: VPS={}, VEW={}, VGW={}, MRK={}, DBF={}, VSS={}, VFS={}, VIS={}, INT={}, ER0={}, ER1={}, FDR={}, FQC={}",
            vps, vew, vgw, mrk, dbf, vss, vfs, vis, int, er0, er1, fdr, fqc
        );
    }

    /// Update VIF_CODE with the last processed command
    pub fn update_code(&mut self, immediate: u16, num: u8, cmd: u8) {
        self.code = (immediate as u32) | ((num as u32) << 16) | ((cmd as u32) << 24);
        trace!(
            "VIF_CODE updated: IMMEDIATE=0x{:04X}, NUM=0x{:02X}, CMD=0x{:02X}",
            immediate, num, cmd
        );
    }

    /// Update VIF_NUM for untransferred data
    pub fn update_num(&mut self, num: u8) {
        self.num = num as u32;
        trace!("VIF_NUM updated: num=0x{:02X}", num);
    }

    /// Update VIF_TOP and VIF_TOPS (VIF1 only)
    pub fn update_top(&mut self, top: u16) {
        if self.base == VIF1_BASE {
            self.top = (top & 0x3FF) as u32;
            self.tops = if self.stat & (1 << 7) == 0 {
                self.base_val
            } else {
                self.base_val.wrapping_add(self.ofst)
            };
            trace!(
                "VIF1_TOP updated: top=0x{:03X}, tops=0x{:03X}",
                self.top, self.tops
            );
        }
    }
}
