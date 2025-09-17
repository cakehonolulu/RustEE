use tracing::{error, trace};
use crate::Bus;

/// Base address for GIF I/O registers
pub const GIF_BASE: u32 = 0x1000_3000;

/// GIF I/O register offsets
const GIF_CTRL_OFFSET: u32 = 0x00; // Control register (W)
const GIF_MODE_OFFSET: u32 = 0x10; // Mode of operation (W)
const GIF_STAT_OFFSET: u32 = 0x20; // Status register (R)
const GIF_TAG0_OFFSET: u32 = 0x40; // GIFtag bits 0-31 (R)
const GIF_TAG1_OFFSET: u32 = 0x50; // GIFtag bits 32-63 (R)
const GIF_TAG2_OFFSET: u32 = 0x60; // GIFtag bits 64-95 (R)
const GIF_TAG3_OFFSET: u32 = 0x70; // GIFtag bits 96-127 (R)
const GIF_CNT_OFFSET: u32 = 0x80; // GIF_CNT (R)
const GIF_P3CNT_OFFSET: u32 = 0x90; // GIF_P3CNT (R)
const GIF_P3TAG_OFFSET: u32 = 0xA0; // GIF_P3TAG (R)

/// GIF I/O register block
#[derive(Debug, Default)]
pub struct GIF {
    /// GIF_CTRL: bit0=reset, bit3=stop
    ctrl: u32,
    /// GIF_MODE: bit0=mask PATH3, bit2=intermittent
    mode: u32,
    /// GIF_STAT: status bits (computed)
    stat: u32,
    /// Last read GIFtag words
    tag0: u32,
    tag1: u32,
    tag2: u32,
    tag3: u32,
    /// GIF_CNT: backwards loop counter & status fields
    cnt: u32,
    /// GIF_P3CNT: PATH3 loop counter when interrupted
    p3cnt: u32,
    /// GIF_P3TAG: PATH3 GIFtag when interrupted
    p3tag: u32,
    state: State,
    current_gif_addr: u32,
    q_bits: u32,
    current_gif_tag: u128,

    nloop: u32,
    current_nloop: u32,
    nregs: u8,
    regs: u64,
    regs_left: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum State {
    #[default]
    Idle,
    ProcessingPacked,
    ProcessingImage,
}

impl GIF {
    /// Create a new GIF I/O block with all registers zeroed
    pub fn new() -> Self {
        GIF::default()
    }

    pub fn is_path3_masked(&self) -> bool {
        (self.mode & 0x1) != 0
    }

    pub fn write_dmac_data(&mut self, bus: &mut Bus, data: u128, madr: &mut u32, qwc: &mut u32, chain: bool) {
        match self.state {
            State::Idle => {
                self.current_gif_addr = *madr;

                self.q_bits = 0x3f800000u32;

                let low = data as u64;

                self.nloop = (low & 0x7FFF) as u32; // bits 0-14
                let eop = ((low >> 15) & 0x1) != 0; // bit 15
                let enable_prim = ((low >> 46) & 0x1) != 0; // bit 46
                let prim = ((low >> 47) & 0x7FF) as u32; // bits 47-57
                let format = ((low >> 58) & 0x3) as u8; // bits 58-59
                let mut nregs = ((low >> 60) & 0xF) as u8; // bits 60-63
                if nregs == 0 {
                    nregs = 16;
                }
                let regs = ((data >> 64) & 0xFFFF_FFFF_FFFF_FFFFu128) as u64;

                self.current_gif_tag = data;
                self.nregs = nregs;
                self.regs = regs;
                self.regs_left = nregs;
                self.current_nloop = self.nloop;

                if self.nloop == 0 {
                    trace!("GIF: NLOOP == 0 -> tag ignored (only EOP may matter).");
                    return;
                }

                if enable_prim {
                    bus.gs.write_internal_reg(0, prim as u64);
                }

                match format {
                    0 => {
                        self.state = State::ProcessingPacked;
                        trace!("GIF: switching to ProcessingPacked");
                    }
                    2 | 3 => {
                        self.state = State::ProcessingImage;
                        trace!("GIF: switching to ProcessingImage");
                    }
                    other => {
                        panic!("Unsupported GIF data format: {} (tag low: 0x{:016X})", other, low);
                    }
                }
            }

            State::ProcessingPacked => {
                self.current_gif_addr += 16;

                let reg_offset = (self.nregs - self.regs_left) << 2;

                let reg = ((self.regs >> reg_offset) & 0xF) as u8;

                let data = (bus.read128)(bus, self.current_gif_addr);

                bus.gs.write_packed_gif_data(reg, data, self.q_bits);

                self.regs_left -= 1;

                if self.regs_left == 0 {
                    self.regs_left = self.nregs;
                    self.current_nloop -= 1;
                }

                if self.current_nloop == 0 {
                    if ((self.current_gif_tag as u64 >> 15) & 0x1) == 0
                    {
                    }
                    else
                    {
                        self.ctrl |= 0x1;
                    }

                    self.state = State::Idle;
                }
            }

            State::ProcessingImage => {
                bus.gs.write_hwreg(data as u64);
                bus.gs.write_hwreg((data >> 64) as u64);

                self.current_nloop -= 1;

                if self.current_nloop == 0 {
                    if ((self.current_gif_tag as u64 >> 15) & 0x1) == 0
                    {
                    }
                    else
                    {
                        self.ctrl |= 0x1;
                    }
                    self.state = State::Idle;
                }
            }
        }
    }

    /// Write a 32-bit value to a GIF register
    pub fn write32(&mut self, addr: u32, value: u32) {
        let offset = addr - GIF_BASE;
        match addr - GIF_BASE {
            GIF_CTRL_OFFSET => {
                // bit0: reset, bit3: temp stop
                self.ctrl = value & 0b1001;
            }
            GIF_MODE_OFFSET => {
                // bit0: mask PATH3, bit2: intermittent
                self.mode = value & 0b0101;
            }
            GIF_STAT_OFFSET | GIF_TAG0_OFFSET | GIF_TAG1_OFFSET | GIF_TAG2_OFFSET
            | GIF_TAG3_OFFSET | GIF_CNT_OFFSET | GIF_P3CNT_OFFSET | GIF_P3TAG_OFFSET => {
                trace!(
                    "Attempt to write read-only GIF register @ offset {:#X}",
                    offset
                );
            }
            _ => {
                error!("Invalid GIF write offset: {:#X}", offset);
            }
        }
    }

    /// Read a 32-bit value from a GIF register
    pub fn read32(&self, addr: u32) -> u32 {
        let offset = addr - GIF_BASE;
        match offset {
            GIF_CTRL_OFFSET => self.ctrl,
            GIF_MODE_OFFSET => self.mode,
            GIF_STAT_OFFSET => {
                // Compute status bits:
                // bit0: PATH3 masked by MODE.bit0
                // bit2: intermittent active
                // bit3: temporary stop active
                let mut s = 0;
                if self.mode & 0b0001 != 0 {
                    s |= 1 << 0;
                }
                if self.mode & 0b0100 != 0 {
                    s |= 1 << 2;
                }
                if self.ctrl & 0b1000 != 0 {
                    s |= 1 << 3;
                }
                // TODO: populate other STAT bits (queue, FIFO depth, etc.)
                s
            }
            GIF_TAG0_OFFSET => self.tag0,
            GIF_TAG1_OFFSET => self.tag1,
            GIF_TAG2_OFFSET => self.tag2,
            GIF_TAG3_OFFSET => self.tag3,
            GIF_CNT_OFFSET => self.cnt,
            GIF_P3CNT_OFFSET => self.p3cnt,
            GIF_P3TAG_OFFSET => self.p3tag,
            _ => {
                error!("Invalid GIF read offset: {:#X}", offset);
                0
            }
        }
    }

    /// Load the current GIFtag into the internal registers (pause must be active)
    pub fn capture_tag(&mut self, tag: u128) {
        self.tag0 = (tag & 0xFFFF_FFFF) as u32;
        self.tag1 = ((tag >> 32) & 0xFFFF_FFFF) as u32;
        self.tag2 = ((tag >> 64) & 0xFFFF_FFFF) as u32;
        self.tag3 = ((tag >> 96) & 0xFFFF_FFFF) as u32;
    }

    /// Update the GIF_CNT register (e.g. FIFO depth & counters)
    pub fn update_cnt(&mut self, cnt: u32) {
        self.cnt = cnt & 0x1FFF_FFFF;
    }

    /// Update PATH3 interrupt state
    pub fn set_p3_state(&mut self, p3cnt: u32, p3tag: u32) {
        self.p3cnt = p3cnt & 0x7FFF;
        self.p3tag = p3tag;
    }
}
