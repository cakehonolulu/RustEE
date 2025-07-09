use tracing::{error, info};

/// RDRAM command opcodes
#[repr(u8)]
pub enum RDRAMCommand {
    SRD  = 0b0000,
    SWR  = 0b0001,
    SETR = 0b0010,
    SETF = 0b0100,
    CLRR = 0b1011,
    RSRV = 0b1110,
}

/// RDRAM register addresses (SA bits)
#[repr(u16)]
pub enum RDRAMRegister {
    INIT   = 0x021,
    TEST34 = 0x022,
    NAPX   = 0x045,
    DEVID  = 0x040,
    CCA    = 0x043,
    CCB    = 0x044,
    PDNXA  = 0x046,
    PDNX   = 0x047,
    TPARM  = 0x048,
    TFRM   = 0x049,
    TCDLY1 = 0x04A,
    SKIP   = 0x04B,
    TCYCLE = 0x04C,
    TEST77 = 0x04D,
    TEST78 = 0x04E,
}

/// Single RDRAM IC state
#[derive(Clone, Default)]
pub struct RDRAMIC {
    pub init: u16,
    pub test34: u16,
    pub cnfga: u16,
    pub cnfgb: u16,
    pub devid: u8,
    pub refb: u8,
    pub refr: u16,
    pub cca: u8,
    pub ccb: u8,
    pub napx: u16,
    pub pdnxa: u8,
    pub pdnx: u16,
    pub tparm: u8,
    pub tfrm: u8,
    pub tcdly1: u8,
    pub tcycle: u8,
    pub skip: u8,
    pub test77: u16,
    pub test78: u16,
    pub test79: u16,
}

/// Main RDRAM controller
pub struct RDRAM {
    /// MCH_RICM register raw
    mch_ricm: u32,
    /// MCH_DRD register raw
    mch_drd: u32,
    /// Two RDRAM ICs
    rdram_ic: [RDRAMIC; 2],
}

impl RDRAM {
    pub const MCH_RICM: u32 = 0xB000_F430;
    pub const MCH_DRD: u32  = 0xB000_F440;

    /// Create new controller
    pub fn new() -> Self {
        RDRAM {
            mch_ricm: 0,
            mch_drd: 0,
            rdram_ic: Default::default(),
        }
    }

    /// Read from RDRAM controller
    pub fn read(&self, address: u32) -> u32 {
        let name = match address {
            Self::MCH_RICM => "MCH_RICM",
            Self::MCH_DRD => "MCH_DRD",
            _ => {
                error!("Invalid RDRAM register read at address 0x{:08X}", address);
                panic!("Invalid RDRAM read");
            }
        };
        if address == Self::MCH_RICM {
            self.mch_ricm
        } else {
            self.mch_drd
        }
    }

    /// Write to RDRAM controller
    pub fn write(&mut self, address: u32, value: u32) {
        // set busy bit
        self.mch_ricm |= 1 << 31;

        let name = match address {
            Self::MCH_RICM => {
                self.mch_ricm = value;
                self.cmd();
                "MCH_RICM"
            }
            Self::MCH_DRD => {
                self.mch_drd = value;
                "MCH_DRD"
            }
            _ => {
                error!("Invalid RDRAM register write at address 0x{:08X}", address);
                panic!("Invalid RDRAM write");
            }
        };
        info!("RDRAM register write to {} with value 0x{:08X}", name, value);
    }

    /// Command dispatch
    fn cmd(&mut self) {
        let sop = ((self.mch_ricm >> 6) & 0xF) as u8;
        match sop {
            x if x == RDRAMCommand::SRD as u8 => { info!("RDRAM controller SRD command"); self.srd(); }
            x if x == RDRAMCommand::SWR as u8 => { info!("RDRAM controller SWR command"); self.swr(); }
            x if x == RDRAMCommand::SETR as u8 => { info!("RDRAM controller SETR command"); self.setr(); }
            x if x == RDRAMCommand::SETF as u8 => { info!("RDRAM controller SETF command"); }
            x if x == RDRAMCommand::CLRR as u8 => { info!("RDRAM controller CLRR command"); }
            x if x == RDRAMCommand::RSRV as u8 => { info!("RDRAM controller RSRV command"); }
            _ => {
                error!("Unhandled RDRAM controller command: 0b{:04b}", sop);
                panic!("Unhandled RDRAM command");
            }
        }
        // clear busy
        self.mch_ricm &= !(1 << 31);
    }

    /// Serial Read (SRD)
    fn srd(&mut self) {
        let sa = ((self.mch_ricm >> 16) & 0xFFF) as u16;
        let sdev = (((self.mch_ricm >> 10) & 1) << 5) | ((self.mch_ricm & 0x1F) as u32);
        self.mch_drd = 0;
        match sa {
            x if x == RDRAMRegister::INIT as u16 => {
                for ic in &self.rdram_ic {
                    if ic.init & 0x3F == sdev as u16 {
                        self.mch_drd = ic.init as u32;
                        info!("RDRAM SRD register read from INIT");
                        return;
                    }
                }
            }
            x if x == RDRAMRegister::DEVID as u16 => {
                for ic in &self.rdram_ic {
                    if ic.init & 0x3F == sdev as u16 {
                        self.mch_drd = (ic.devid & 0x1F) as u32;
                        info!("RDRAM SRD register read from DEVID");
                        return;
                    }
                }
            }
            _ => {
                error!("Unhandled RDRAM SRD register: 0x{:03X}", sa);
                panic!("Unhandled SRD register");
            }
        }
    }

    /// Serial Write (SWR)
    fn swr(&mut self) {
        let sa = ((self.mch_ricm >> 16) & 0xFFF) as u16;
        let sdev = (((self.mch_ricm >> 10) & 1) << 5) | ((self.mch_ricm & 0x1F) as u32);
        let sbc = ((self.mch_ricm >> 5) & 1) != 0;
        for ic in &mut self.rdram_ic {
            let target = sbc || (ic.init & 0x3F) == sdev as u16;
            if sa == RDRAMRegister::INIT as u16 && target {
                ic.init = (self.mch_drd & 0x3FFF) as u16;
                info!("RDRAM SWR write to INIT");
                return;
            }
            if sa == RDRAMRegister::TEST34 as u16 && target {
                ic.test34 = self.mch_drd as u16;
                info!("RDRAM SWR write to TEST34");
                return;
            }
            if sa == RDRAMRegister::NAPX as u16 && target {
                ic.napx = (self.mch_drd & 0x7FF) as u16;
                info!("RDRAM SWR write to NAPX");
                return;
            }
            if sa == RDRAMRegister::DEVID as u16 && target {
                ic.devid = (self.mch_drd & 0x1F) as u8;
                info!("RDRAM SWR write to DEVID");
                return;
            }
            if sa == RDRAMRegister::CCA as u16 && target {
                ic.cca = (self.mch_drd & 0xFF) as u8;
                info!("RDRAM SWR write to CCA");
                return;
            }
            if sa == RDRAMRegister::CCB as u16 && target {
                ic.ccb = (self.mch_drd & 0xFF) as u8;
                info!("RDRAM SWR write to CCB");
                return;
            }
            if sa == RDRAMRegister::PDNXA as u16 && target {
                ic.pdnxa = (self.mch_drd & 0x3F) as u8;
                info!("RDRAM SWR write to PDNXA");
                return;
            }
            if sa == RDRAMRegister::PDNX as u16 && target {
                ic.pdnx = (self.mch_drd & 0x7) as u16;
                info!("RDRAM SWR write to PDNX");
                return;
            }
            if sa == RDRAMRegister::TPARM as u16 && target {
                ic.tparm = (self.mch_drd & 0x7F) as u8;
                info!("RDRAM SWR write to TPARM");
                return;
            }
            if sa == RDRAMRegister::TFRM as u16 && target {
                ic.tfrm = (self.mch_drd & 0xF) as u8;
                info!("RDRAM SWR write to TFRM");
                return;
            }
            if sa == RDRAMRegister::TCDLY1 as u16 && target {
                ic.tcdly1 = (self.mch_drd & 0x3) as u8;
                info!("RDRAM SWR write to TCDLY1");
                return;
            }
            if sa == RDRAMRegister::SKIP as u16 && target {
                ic.skip = (self.mch_drd & 0x7) as u8;
                info!("RDRAM SWR write to SKIP");
                return;
            }
            if sa == RDRAMRegister::TCYCLE as u16 && target {
                ic.tcycle = (self.mch_drd & 0x3F) as u8;
                info!("RDRAM SWR write to TCYCLE");
                return;
            }
            if sa == RDRAMRegister::TEST77 as u16 && target {
                ic.test77 = self.mch_drd as u16;
                info!("RDRAM SWR write to TEST77");
                return;
            }
            if sa == RDRAMRegister::TEST78 as u16 && target {
                ic.test78 = self.mch_drd as u16;
                info!("RDRAM SWR write to TEST78");
                return;
            }
        }
        error!("Unhandled RDRAM SWR register: 0x{:03X}", sa);
        panic!("Unhandled SWR register");
    }

    /// Set Reset (SETR)
    fn setr(&mut self) {
        let sbc = ((self.mch_ricm >> 5) & 1) != 0;
        if sbc {
            for ic in &mut self.rdram_ic {
                *ic = RDRAMIC::default();
            }
        } else {
            let idx = (((self.mch_ricm >> 10) & 1) << 5) | (self.mch_ricm & 0x1F);
            let ic = &mut self.rdram_ic[idx as usize];
            *ic = RDRAMIC::default();
        }
    }
}
