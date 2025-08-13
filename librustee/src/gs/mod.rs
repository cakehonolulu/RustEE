use tracing::{error, trace};
use crate::Bus;

/// Base address for privileged GS registers
pub const GS_BASE: u32 = 0x1200_0000;

/// GS register offsets (size = 8 bytes each)
const PMODE_OFFSET: u32 = GS_BASE + 0x000; // PMODE
const SMODE1_OFFSET: u32 = GS_BASE + 0x010; // SMODE1
const SMODE2_OFFSET: u32 = GS_BASE + 0x020; // SMODE2
const SRFSH_OFFSET: u32 = GS_BASE + 0x030; // SRFSH
const SYNCH1_OFFSET: u32 = GS_BASE + 0x040; // SYNCH1
const SYNCH2_OFFSET: u32 = GS_BASE + 0x050; // SYNCH2
const SYNCV_OFFSET: u32 = GS_BASE + 0x060; // SYNCV
const DISPFB1_OFFSET: u32 = GS_BASE + 0x070; // DISPFB1
const DISPLAY1_OFFSET: u32 = GS_BASE + 0x080; // DISPLAY1
const DISPFB2_OFFSET: u32 = GS_BASE + 0x090; // DISPFB2
const DISPLAY2_OFFSET: u32 = GS_BASE + 0x0A0; // DISPLAY2
const EXTBUF_OFFSET: u32 = GS_BASE + 0x0B0; // EXTBUF
const EXTDATA_OFFSET: u32 = GS_BASE + 0x0C0; // EXTDATA
const EXTWRITE_OFFSET: u32 = GS_BASE + 0x0D0; // EXTWRITE
const BGCOLOR_OFFSET: u32 = GS_BASE + 0x0E0; // BGCOLOR

const GS_CSR_OFFSET: u32 = GS_BASE + 0x1000; // GS_CSR
const GS_IMR_OFFSET: u32 = GS_BASE + 0x1010; // GS_IMR
const BUSDIR_OFFSET: u32 = GS_BASE + 0x1040; // BUSDIR
const SIGLBLID_OFFSET: u32 = GS_BASE + 0x1080; // SIGLBLID

#[derive(Debug)]
pub enum GsEvent {
    None,

    GsCsrVblankOut { delay: u64 },
}

/// Privileged GS register block
#[derive(Debug)]
pub struct GS {
    pub pmode: u64,
    pub smode1: u64,
    pub smode2: u64,
    pub srfsh: u64,
    pub synch1: u64,
    pub synch2: u64,
    pub syncv: u64,
    pub dispfb1: u64,
    pub display1: u64,
    pub dispfb2: u64,
    pub display2: u64,
    pub extbuf: u64,
    pub extdata: u64,
    pub extwrite: u64,
    pub bgcolor: u64,
    pub gs_csr: u64,
    pub gs_imr: u64,
    pub busdir: u64,
    pub siglblid: u64,
    pub internal: [u64; 0x63],
    pub hwreg: u64,
}

impl Default for GS {
    fn default() -> Self {
        GS {
            pmode: 0,
            smode1: 0,
            smode2: 0,
            srfsh: 0,
            synch1: 0,
            synch2: 0,
            syncv: 0,
            dispfb1: 0,
            display1: 0,
            dispfb2: 0,
            display2: 0,
            extbuf: 0,
            extdata: 0,
            extwrite: 0,
            bgcolor: 0,
            gs_csr: 0,
            gs_imr: 0,
            busdir: 0,
            siglblid: 0,
            internal: [0; 0x63],
            hwreg: 0,
        }
    }
}

impl GS {
    /// Create a new privileged GS register block
    pub fn new() -> Self {
        GS {
            internal: [0u64; 0x63],
            hwreg: 0,
            ..Default::default()
        }
    }

    /// Write a 64-bit value to a GS register
    pub fn write64(&mut self, offset: u32, value: u64) -> GsEvent {
        let mut event: GsEvent = GsEvent::None;
        match offset {
            PMODE_OFFSET => self.pmode = value,
            SMODE1_OFFSET => self.smode1 = value,
            SMODE2_OFFSET => self.smode2 = value,
            SRFSH_OFFSET => self.srfsh = value,
            SYNCH1_OFFSET => self.synch1 = value,
            SYNCH2_OFFSET => self.synch2 = value,
            SYNCV_OFFSET => self.syncv = value,
            DISPFB1_OFFSET => self.dispfb1 = value,
            DISPLAY1_OFFSET => self.display1 = value,
            DISPFB2_OFFSET => self.dispfb2 = value,
            DISPLAY2_OFFSET => self.display2 = value,
            EXTBUF_OFFSET => self.extbuf = value,
            EXTDATA_OFFSET => self.extdata = value,
            EXTWRITE_OFFSET => self.extwrite = value,
            BGCOLOR_OFFSET => self.bgcolor = value,
            GS_CSR_OFFSET => {
                self.gs_csr = value;
                event = GsEvent::GsCsrVblankOut { delay: 64000 };

            }
            GS_IMR_OFFSET => self.gs_imr = value,
            BUSDIR_OFFSET => self.busdir = value,
            SIGLBLID_OFFSET => self.siglblid = value,
            _ => {
                panic!("Invalid GS write offset: {:#X}", offset);
            }

        }

        event
    }

    /// Read a 64-bit value from a GS register
    pub fn read64(&self, offset: u32) -> u64 {
        match offset {
            PMODE_OFFSET => self.pmode,
            SMODE1_OFFSET => self.smode1,
            SMODE2_OFFSET => self.smode2,
            SRFSH_OFFSET => self.srfsh,
            SYNCH1_OFFSET => self.synch1,
            SYNCH2_OFFSET => self.synch2,
            SYNCV_OFFSET => self.syncv,
            DISPFB1_OFFSET => self.dispfb1,
            DISPLAY1_OFFSET => self.display1,
            DISPFB2_OFFSET => self.dispfb2,
            DISPLAY2_OFFSET => self.display2,
            EXTBUF_OFFSET => self.extbuf,
            EXTDATA_OFFSET => self.extdata,
            EXTWRITE_OFFSET => self.extwrite,
            BGCOLOR_OFFSET => self.bgcolor,
            GS_CSR_OFFSET => self.gs_csr,
            GS_IMR_OFFSET => self.gs_imr,
            BUSDIR_OFFSET => self.busdir,
            SIGLBLID_OFFSET => self.siglblid,
            _ => {
                error!("Invalid GS read offset: {:#X}", offset);
                0
            }
        }
    }

    pub fn write_internal_reg(&mut self, reg: u8, data: u64) {
        match reg {
            0x00 => {
                // PRIM: only low 10 bits used in many implementations
                self.internal[0x00] = data & 0x3FF;
            }
            0x01 => {
                // RGBAQ — data layout handled so consumers can read both packed color and Q
                // Pack as: [Q (32)] [A(8) R(8) G(8) B(8)] in a single u64 for convenience
                // but keep index 1 equal to the packed value like many emus do.
                let r = (data & 0xFF) as u64;
                let g = ((data >> 8) & 0xFF) as u64;
                let b = ((data >> 16) & 0xFF) as u64;
                let a = ((data >> 24) & 0xFF) as u64;
                let q = (data >> 32) as u64;
                let packed = (q << 32) | ((a << 24) | (r << 16) | (g << 8) | b);
                self.internal[0x01] = packed;
            }
            0x02 => {
                // ST: store S/T low 64 and keep Q in high portion if passed that way
                self.internal[0x02] = data;
            }
            0x03 => {
                // UV: expect 14-bit U and V (packed inside data)
                // Store canonical 32-bit value (U in low 16, V in high 16)
                let u = (data & 0x3fff) as u64;
                let v = ((data >> 16) & 0x3fff) as u64;
                self.internal[0x03] = u | (v << 16);
            }
            0x04 | 0x05 | 0x0C | 0x0D => {
                // XYZF2/XYZ2/XYZF3/XYZ3 — store raw 64-bit value; consumers decode
                let idx = reg as usize;
                if idx < self.internal.len() {
                    self.internal[idx] = data;
                }
            }
            0x0A => {
                // FOG
                self.internal[0x0A] = data;
            }
            0x0E => {
                // A+D (should not normally reach here; handled by GIF side)
                // but if it does, ignore or treat as write to internal reg specified in data low/high
                self.internal[0x0E] = data;
            }
            0x54 => {
                // HWREG — write triggers VRAM transfer
                self.write_hwreg(data);
            }
            // many other internal registers map 1:1; just store them by index
            idx if (idx as usize) < self.internal.len() => {
                self.internal[idx as usize] = data;
            }
            _ => {
                error!("GS: write_internal_reg invalid reg 0x{:02X} = 0x{:016X}", reg, data);
            }
        }
    }

    /// Handle a 128-bit PACKED GIF quadword delivered by DMA.
    /// 'q' is the STQ / RGBAQ 'Q' value from GIF parsing (if applicable).
    pub fn write_packed_gif_data(&mut self, reg: u8, data: u128, q: u32) {
        let low = data as u64;
        let high = (data >> 64) as u64;

        match reg {
            0x00 => {
                // PRIM: low bits of low
                let prim_value = low & 0x3FF;
                self.write_internal_reg(0x00, prim_value);
            }
            0x01 => {
                // RGBAQ: need to extract R,G,B,A from low/high like many emus do.
                // Convention used here (matches many implementations in practice):
                //  R = low & 0xFF
                //  G = (low >> 32) & 0xFF
                //  B = high & 0xFF
                //  A = (high >> 32) & 0xFF
                // Pack as [Q << 32 | A<<24 | R<<16 | G<<8 | B]
                let r = (low & 0xFF) as u64;
                let g = ((low >> 32) & 0xFF) as u64;
                let b = (high & 0xFF) as u64;
                let a = ((high >> 32) & 0xFF) as u64;
                let q64 = q as u64;
                let packed = (q64 << 32) | ((a << 24) | (r << 16) | (g << 8) | b);
                self.write_internal_reg(0x01, packed);
            }
            0x02 => {
                // ST: low contains S/T, high contains Q commonly
                // store S/T in internal[2], and also store Q in high bits for consumers
                let combined = ((high as u64) << 32) | low;
                self.write_internal_reg(0x02, combined);
            }
            0x03 => {
                // UV — pack like earlier helper
                let u = (low & 0x3fff) as u64;
                let v = ((low >> 16) & 0x3fff) as u64;
                self.write_internal_reg(0x03, u | (v << 16));
            }
            0x04 | 0x05 | 0x0C | 0x0D => {
                // XYZ* variants — store low64 and let consumer decode
                self.write_internal_reg(reg, low);
            }
            0x0A => {
                // FOG
                self.write_internal_reg(0x0A, (high << 32) | low);
            }
            0x0E => {
                // A+D: low = data, high low-bits = reg index to write
                let dst_reg = (high & 0xFF) as u8;
                self.write_internal_reg(dst_reg, low);
            }
            0x0F => {
                // NOP
            }
            // default: store lower 64-bits to the internal register index
            idx if (idx as usize) < self.internal.len() => {
                let idx_usize = idx as usize;
                self.internal[idx_usize] = low;
            }
            _ => {
                error!("GS: write_packed_gif_data invalid reg 0x{:02X}", reg);
            }
        }
    }

    /// Write to HWREG (64-bit). You should call your VRAM transfer logic after this.
    pub fn write_hwreg(&mut self, data: u64) {
        self.hwreg = data;
        // call your VRAM transfer routine here, e.g.:
        // self.transfer_vram();
        // (implement transfer_vram() elsewhere using your framebuffer state)
    }
}
