use tracing::{error, trace};

/// Base address for IPU I/O registers
pub const IPU_BASE: u32 = 0x1000_2000;

/// IPU I/O register offsets
const IPU_CMD_OFFSET: u32 = 0x00; // Command register (R/W)
const IPU_CTRL_OFFSET: u32 = 0x10; // Control/Status register (R/W)
const IPU_BP_OFFSET: u32 = 0x20; // Bitstream position (R)
const IPU_TOP_OFFSET: u32 = 0x30; // Next 32 bits in bitstream (R)

/// IPU I/O register block
#[derive(Debug)]
pub struct IPU {
    /// IPU_CMD: command (28-31) and option (0-27), or FDEC/VDEC result
    cmd: u32,
    /// IPU_CTRL: control and status bits
    ctrl: u32,
    /// IPU_BP: bitstream position and FIFO status
    bp: u32,
    /// IPU_TOP: next 32 bits in bitstream
    top: u32,
    /// Tracks if a command has been sent (for IPU_CMD quirk)
    command_sent: bool,
    /// First 32 bits of bitstream (for IPU_CMD quirk when no command sent)
    bitstream_first: u32,
    /// Busy flag for IPU_CMD and IPU_TOP
    busy: bool,
    /// Internal buffer for unprocessed DMA data (simplified for TOP)
    bitstream_buffer: u32,
}

impl IPU {
    /// Create a new IPU I/O block with all registers zeroed
    pub fn new() -> Self {
        IPU {
            cmd: 0,
            ctrl: 0,
            bp: 0,
            top: 0,
            command_sent: false,
            bitstream_first: 0,
            busy: false,
            bitstream_buffer: 0,
        }
    }

    /// Write a 32-bit value to an IPU register
    pub fn write32(&mut self, addr: u32, value: u32) {
        let offset = addr - IPU_BASE;
        match offset {
            IPU_CMD_OFFSET => {
                // Code (28-31), Option (0-27)
                self.cmd = value;
                self.command_sent = true;
                // Clear ECD and SCD in IPU_CTRL
                self.ctrl &= !((1 << 14) | (1 << 15));
                self.busy = true; // Set busy flag
                trace!(
                    "IPU_CMD write: code=0x{:X}, option=0x{:07X}, busy=true",
                    (value >> 28) & 0xF,
                    value & 0x0FFF_FFFF
                );
                // TODO: Implement actual command processing (e.g., FDEC, VDEC)
                // For now, simulate command completion
                self.busy = false;
            }
            IPU_CTRL_OFFSET => {
                // RST (30) and other writable bits
                if value & (1 << 30) != 0 {
                    // Reset IPU
                    self.cmd = 0;
                    self.ctrl = 0;
                    self.bp = 0;
                    self.top = 0;
                    self.command_sent = false;
                    self.bitstream_first = 0;
                    self.busy = false;
                    self.bitstream_buffer = 0;
                    trace!("IPU reset triggered");
                    // TODO: Trigger IPU interrupt if command was executing
                } else {
                    // Update writable bits: IDP (16-17), AS (20), IVF (21), QST (22), MP1 (23)
                    self.ctrl = (self.ctrl & !0x00F3_0000) | (value & 0x00F3_0000);
                    trace!(
                        "IPU_CTRL write: IDP={}, AS={}, IVF={}, QST={}, MP1={}",
                        (value >> 16) & 0x3,
                        (value >> 20) & 0x1,
                        (value >> 21) & 0x1,
                        (value >> 22) & 0x1,
                        (value >> 23) & 0x1
                    );
                }
            }
            IPU_BP_OFFSET | IPU_TOP_OFFSET => {
                trace!(
                    "Attempt to write read-only IPU register @ offset {:#X}: value=0x{:08X}",
                    offset, value
                );
            }
            _ => {
                error!("Invalid IPU write offset: {:#X}", offset);
            }
        }
    }

    /// Read a 32-bit value from an IPU register
    pub fn read32(&self, addr: u32) -> u32 {
        let offset = addr - IPU_BASE;
        match offset {
            IPU_CMD_OFFSET => {
                if !self.command_sent {
                    // Return first 32 bits of bitstream if no command sent
                    trace!(
                        "IPU_CMD read (no command sent): bitstream_first=0x{:08X}",
                        self.bitstream_first
                    );
                    self.bitstream_first
                } else {
                    // Return FDEC/VDEC result, busy flag in bit 63 (upper 32 bits not readable)
                    let result = self.cmd | ((self.busy as u32) << 31);
                    trace!("IPU_CMD read: result=0x{:08X}, busy={}", result, self.busy);
                    result
                }
            }
            IPU_CTRL_OFFSET => {
                // IFC (0-3), OFC (4-7), CBP (8-13), ECD (14), SCD (15), IDP (16-17),
                // AS (20), IVF (21), QST (22), MP1 (23), Picture type (24-26), Busy (31)
                let result = self.ctrl | ((self.busy as u32) << 31);
                trace!(
                    "IPU_CTRL read: IFC={}, OFC={}, CBP=0x{:02X}, ECD={}, SCD={}, IDP={}, AS={}, IVF={}, QST={}, MP1={}, Picture type={}, Busy={}",
                    self.ctrl & 0xF,
                    (self.ctrl >> 4) & 0xF,
                    (self.ctrl >> 8) & 0x3F,
                    (self.ctrl >> 14) & 0x1,
                    (self.ctrl >> 15) & 0x1,
                    (self.ctrl >> 16) & 0x3,
                    (self.ctrl >> 20) & 0x1,
                    (self.ctrl >> 21) & 0x1,
                    (self.ctrl >> 22) & 0x1,
                    (self.ctrl >> 23) & 0x1,
                    (self.ctrl >> 24) & 0x7,
                    self.busy
                );
                result
            }
            IPU_BP_OFFSET => {
                // BP (0-6), IFC (8-11), FP (16-17)
                trace!(
                    "IPU_BP read: BP={}, IFC={}, FP={}",
                    self.bp & 0x7F,
                    (self.bp >> 8) & 0xF,
                    (self.bp >> 16) & 0x3
                );
                self.bp
            }
            IPU_TOP_OFFSET => {
                // Next 32 bits in bitstream, busy if <32 bits in FIFO
                let result = self.top | ((self.busy as u32) << 31);
                trace!(
                    "IPU_TOP read: bitstream=0x{:08X}, busy={}",
                    self.top, self.busy
                );
                result
            }
            _ => {
                error!("Invalid IPU read offset: {:#X}", offset);
                0
            }
        }
    }

    /// Update IPU_CTRL with status bits
    pub fn update_ctrl(
        &mut self,
        ifc: u32,
        ofc: u32,
        cbp: u32,
        ecd: bool,
        scd: bool,
        idp: u32,
        as_: bool,
        ivf: bool,
        qst: bool,
        mp1: bool,
        picture_type: u32,
    ) {
        self.ctrl = (ifc & 0xF) | // IFC (0-3)
            ((ofc & 0xF) << 4) | // OFC (4-7)
            ((cbp & 0x3F) << 8) | // CBP (8-13)
            ((ecd as u32) << 14) | // ECD (14)
            ((scd as u32) << 15) | // SCD (15)
            ((idp & 0x3) << 16) | // IDP (16-17)
            ((as_ as u32) << 20) | // AS (20)
            ((ivf as u32) << 21) | // IVF (21)
            ((qst as u32) << 22) | // QST (22)
            ((mp1 as u32) << 23) | // MP1 (23)
            ((picture_type & 0x7) << 24); // Picture type (24-26)
        trace!(
            "IPU_CTRL updated: IFC={}, OFC={}, CBP=0x{:02X}, ECD={}, SCD={}, IDP={}, AS={}, IVF={}, QST={}, MP1={}, Picture type={}",
            ifc, ofc, cbp, ecd, scd, idp, as_, ivf, qst, mp1, picture_type
        );
    }

    /// Update IPU_BP with bitstream position and FIFO status
    pub fn update_bp(&mut self, bp: u32, ifc: u32, fp: u32) {
        self.bp = (bp & 0x7F) | // BP (0-6)
            ((ifc & 0xF) << 8) | // IFC (8-11)
            ((fp & 0x3) << 16); // FP (16-17)
        trace!("IPU_BP updated: BP={}, IFC={}, FP={}", bp, ifc, fp);
    }

    /// Update IPU_TOP with the next 32 bits in the bitstream
    pub fn update_top(&mut self, bitstream: u32, busy: bool) {
        self.top = bitstream;
        self.busy = busy;
        trace!(
            "IPU_TOP updated: bitstream=0x{:08X}, busy={}",
            bitstream, busy
        );
    }

    /// Update the first 32 bits of the bitstream (for IPU_CMD quirk)
    pub fn update_bitstream_first(&mut self, bitstream: u32) {
        self.bitstream_first = bitstream;
        trace!("IPU bitstream first 32 bits updated: 0x{:08X}", bitstream);
    }

    /// Simulate DMA data arrival to update bitstream
    pub fn receive_dma_data(&mut self, data: u32) {
        if !self.command_sent {
            self.update_bitstream_first(data);
        }
        self.update_top(data, data.count_ones() < 32); // Busy if <32 bits
        // Update IFC in IPU_CTRL and IPU_BP (simplified, assumes 1 quadword)
        let ifc = 1.min(15); // Example: 1 quadword
        self.update_ctrl(
            ifc,
            self.ctrl >> 4 & 0xF,       // Preserve OFC
            self.ctrl >> 8 & 0x3F,      // Preserve CBP
            self.ctrl >> 14 & 0x1 != 0, // Preserve ECD
            self.ctrl >> 15 & 0x1 != 0, // Preserve SCD
            self.ctrl >> 16 & 0x3,      // Preserve IDP
            self.ctrl >> 20 & 0x1 != 0, // Preserve AS
            self.ctrl >> 21 & 0x1 != 0, // Preserve IVF
            self.ctrl >> 22 & 0x1 != 0, // Preserve QST
            self.ctrl >> 23 & 0x1 != 0, // Preserve MP1
            self.ctrl >> 24 & 0x7,      // Preserve Picture type
        );
        self.update_bp(self.bp & 0x7F, ifc, self.bp >> 16 & 0x3); // Update IFC, preserve BP, FP
    }
}
