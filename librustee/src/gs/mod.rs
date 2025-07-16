use tracing::{error, trace};

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

/// Privileged GS register block
#[derive(Debug, Default)]
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
}

impl GS {
    /// Create a new privileged GS register block
    pub fn new() -> Self {
        GS::default()
    }

    /// Write a 64-bit value to a GS register
    pub fn write64(&mut self, offset: u32, value: u64) {
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
            GS_CSR_OFFSET => self.gs_csr = value,
            GS_IMR_OFFSET => self.gs_imr = value,
            BUSDIR_OFFSET => self.busdir = value,
            SIGLBLID_OFFSET => self.siglblid = value,
            _ => {
                trace!("Invalid GS write offset: {:#X}", offset);
            }
        }
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
}
