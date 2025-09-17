#[repr(u8)]
enum RDRAMCommand {
    SRD = 0b0000,
    SWR = 0b0001,
    SETR = 0b0010,
    SETF = 0b0100,
    CLRR = 0b1011,
}

#[repr(u16)]
enum RDRAMRegister {
    INIT = 0x021,
    TEST34 = 0x022,
    NAPX = 0x045,
    DEVID = 0x040,
    CCA = 0x043,
    CCB = 0x044,
    PDNXA = 0x046,
    PDNX = 0x047,
    TPARM = 0x048,
    TFRM = 0x049,
    TCDLY1 = 0x04A,
    SKIP = 0x04B,
    TCYCLE = 0x04C,
    TEST77 = 0x04D,
    TEST78 = 0x04E,
}

#[derive(Clone, Copy)]
struct RdramIc {
    init: u16,   // 14-bit register, using u16
    test34: u16, // 16-bit register
    cnfga: u16,  // 16-bit register
    cnfgb: u16,  // 16-bit register
    devid: u8,   // 5-bit register
    refb: u8,    // 5-bit register
    refr: u16,   // 9-bit register
    cca: u8,     // 8-bit register
    ccb: u8,     // 8-bit register
    napx: u16,   // 11-bit register
    pdnxa: u8,   // 6-bit register
    pdnx: u16,   // 3-bit register, using u16 as in C++
    tparm: u8,   // 7-bit register
    tfrm: u8,    // 4-bit register
    tcdly1: u8,  // 2-bit register
    tcycle: u8,  // 6-bit register
    skip: u8,    // 3-bit register
    test77: u16, // 16-bit register
    test78: u16, // 16-bit register
    test79: u16, // 16-bit register
}

pub struct RDRAM {
    mch_ricm_: u32,
    mch_drd_: u32,
    rdram_ic: [RdramIc; 2],
}

impl RDRAM {
    const MCH_RICM: u32 = 0x1000F430;
    const MCH_DRD: u32 = 0x1000F440;

    pub fn new() -> Self {
        RDRAM {
            mch_ricm_: 0,
            mch_drd_: 0,
            rdram_ic: [RdramIc {
                init: 0,
                test34: 0,
                cnfga: 0,
                cnfgb: 0,
                devid: 0,
                refb: 0,
                refr: 0,
                cca: 0,
                ccb: 0,
                napx: 0,
                pdnxa: 0,
                pdnx: 0,
                tparm: 0,
                tfrm: 0,
                tcdly1: 0,
                tcycle: 0,
                skip: 0,
                test77: 0,
                test78: 0,
                test79: 0,
            }; 2],
        }
    }

    pub fn read(&self, address: u32) -> u32 {
        match address {
            Self::MCH_RICM => self.mch_ricm_,
            Self::MCH_DRD => self.mch_drd_,
            _ => panic!("Invalid RDRAM register read at address 0x{:08X}", address),
        }
    }

    pub fn write(&mut self, address: u32, value: u32) {
        self.mch_ricm_ |= 1 << 31; // Set busy bit
        match address {
            Self::MCH_RICM => {
                self.mch_ricm_ = value;
                self.cmd();
            }
            Self::MCH_DRD => {
                self.mch_drd_ = value;
            }
            _ => panic!("Invalid RDRAM register write at address 0x{:08X}", address),
        }
    }

    fn cmd(&mut self) {
        let sop = (self.mch_ricm_ >> 6) & 0xF;
        match sop {
            0b0000 => self.srd(),  // SRD
            0b0001 => self.swr(),  // SWR
            0b0010 => self.setr(), // SETR
            0b0100 => {}           // SETF (unimplemented)
            0b1011 => {}           // CLRR (unimplemented)
            0b1110 => {}           // RSRV (unimplemented)
            _ => panic!("Unhandled RDRAM controller command: 0b{:04b}", sop),
        }
        self.mch_ricm_ &= !(1 << 31); // Clear busy bit
    }

    fn srd(&mut self) {
        let reg = (self.mch_ricm_ >> 16) & 0xFFF;
        let sdevid = (((self.mch_ricm_ >> 10) & 1) << 5) | (self.mch_ricm_ & 0x1F);
        match reg {
            0x021 => {
                // INIT
                self.mch_drd_ = 0;
                for ic in &self.rdram_ic {
                    if (ic.init & 0x3F) as u32 == sdevid {
                        self.mch_drd_ = ic.init as u32;
                        return;
                    }
                }
            }
            0x040 => {
                // DEVID
                self.mch_drd_ = 0;
                for ic in &self.rdram_ic {
                    if (ic.init & 0x3F) as u32 == sdevid {
                        self.mch_drd_ = (ic.devid & 0x1F) as u32;
                        return;
                    }
                }
            }
            _ => panic!("Unhandled RDRAM SRD register: 0x{:04X}", reg),
        }
    }

    fn swr(&mut self) {
        let reg = (self.mch_ricm_ >> 16) & 0xFFF;
        let sdevid = (((self.mch_ricm_ >> 10) & 1) << 5) | (self.mch_ricm_ & 0x1F);
        let sbc = (self.mch_ricm_ & (1 << 5)) != 0;
        match reg {
            0x021 => {
                // INIT
                if sbc {
                    for ic in &mut self.rdram_ic {
                        ic.init = (self.mch_drd_ & 0x3FFF) as u16;
                    }
                } else {
                    for ic in &mut self.rdram_ic {
                        if (ic.init & 0x3F) as u32 == sdevid {
                            ic.init = (self.mch_drd_ & 0x3FFF) as u16;
                            return;
                        }
                    }
                }
            }
            0x022 => {
                // TEST34
                if sbc {
                    for ic in &mut self.rdram_ic {
                        ic.test34 = (self.mch_drd_ & 0xFFFF) as u16;
                    }
                } else {
                    for ic in &mut self.rdram_ic {
                        if (ic.init & 0x3F) as u32 == sdevid {
                            ic.test34 = (self.mch_drd_ & 0xFFFF) as u16;
                            return;
                        }
                    }
                }
            }
            0x045 => {
                // NAPX
                if sbc {
                    for ic in &mut self.rdram_ic {
                        ic.napx = (self.mch_drd_ & 0x7FF) as u16;
                    }
                } else {
                    for ic in &mut self.rdram_ic {
                        if (ic.init & 0x3F) as u32 == sdevid {
                            ic.napx = (self.mch_drd_ & 0x7FF) as u16;
                            return;
                        }
                    }
                }
            }
            0x040 => {
                // DEVID
                if sbc {
                    for ic in &mut self.rdram_ic {
                        ic.devid = (self.mch_drd_ & 0x1F) as u8;
                    }
                } else {
                    for ic in &mut self.rdram_ic {
                        if (ic.init & 0x3F) as u32 == sdevid {
                            ic.devid = (self.mch_drd_ & 0x1F) as u8;
                            return;
                        }
                    }
                }
            }
            0x043 => {
                // CCA
                if sbc {
                    for ic in &mut self.rdram_ic {
                        ic.cca = (self.mch_drd_ & 0xFF) as u8;
                    }
                } else {
                    for ic in &mut self.rdram_ic {
                        if (ic.init & 0x3F) as u32 == sdevid {
                            ic.cca = (self.mch_drd_ & 0xFF) as u8;
                            return;
                        }
                    }
                }
            }
            0x044 => {
                // CCB
                if sbc {
                    for ic in &mut self.rdram_ic {
                        ic.ccb = (self.mch_drd_ & 0xFF) as u8;
                    }
                } else {
                    for ic in &mut self.rdram_ic {
                        if (ic.init & 0x3F) as u32 == sdevid {
                            ic.ccb = (self.mch_drd_ & 0xFF) as u8;
                            return;
                        }
                    }
                }
            }
            0x046 => {
                // PDNXA
                if sbc {
                    for ic in &mut self.rdram_ic {
                        ic.pdnxa = (self.mch_drd_ & 0x3F) as u8;
                    }
                } else {
                    for ic in &mut self.rdram_ic {
                        if (ic.init & 0x3F) as u32 == sdevid {
                            ic.pdnxa = (self.mch_drd_ & 0x3F) as u8;
                            return;
                        }
                    }
                }
            }
            0x047 => {
                // PDNX
                if sbc {
                    for ic in &mut self.rdram_ic {
                        ic.pdnx = (self.mch_drd_ & 0x7) as u16;
                    }
                } else {
                    for ic in &mut self.rdram_ic {
                        if (ic.init & 0x3F) as u32 == sdevid {
                            ic.pdnx = (self.mch_drd_ & 0x7) as u16;
                            return;
                        }
                    }
                }
            }
            0x048 => {
                // TPARM
                if sbc {
                    for ic in &mut self.rdram_ic {
                        ic.tparm = (self.mch_drd_ & 0x7F) as u8;
                    }
                } else {
                    for ic in &mut self.rdram_ic {
                        if (ic.init & 0x3F) as u32 == sdevid {
                            ic.tparm = (self.mch_drd_ & 0x7F) as u8;
                            return;
                        }
                    }
                }
            }
            0x049 => {
                // TFRM
                if sbc {
                    for ic in &mut self.rdram_ic {
                        ic.tfrm = (self.mch_drd_ & 0xF) as u8;
                    }
                } else {
                    for ic in &mut self.rdram_ic {
                        if (ic.init & 0x3F) as u32 == sdevid {
                            ic.tfrm = (self.mch_drd_ & 0xF) as u8;
                            return;
                        }
                    }
                }
            }
            0x04A => {
                // TCDLY1
                if sbc {
                    for ic in &mut self.rdram_ic {
                        ic.tcdly1 = (self.mch_drd_ & 0x3) as u8;
                    }
                } else {
                    for ic in &mut self.rdram_ic {
                        if (ic.init & 0x3F) as u32 == sdevid {
                            ic.tcdly1 = (self.mch_drd_ & 0x3) as u8;
                            return;
                        }
                    }
                }
            }
            0x04B => {
                // SKIP
                if sbc {
                    for ic in &mut self.rdram_ic {
                        ic.skip = (self.mch_drd_ & 0x7) as u8;
                    }
                } else {
                    for ic in &mut self.rdram_ic {
                        if (ic.init & 0x3F) as u32 == sdevid {
                            ic.skip = (self.mch_drd_ & 0x7) as u8;
                            return;
                        }
                    }
                }
            }
            0x04C => {
                // TCYCLE
                if sbc {
                    for ic in &mut self.rdram_ic {
                        ic.tcycle = (self.mch_drd_ & 0x3F) as u8;
                    }
                } else {
                    for ic in &mut self.rdram_ic {
                        if (ic.init & 0x3F) as u32 == sdevid {
                            ic.tcycle = (self.mch_drd_ & 0x3F) as u8;
                            return;
                        }
                    }
                }
            }
            0x04D => {
                // TEST77
                if sbc {
                    for ic in &mut self.rdram_ic {
                        ic.test77 = (self.mch_drd_ & 0xFFFF) as u16;
                    }
                } else {
                    for ic in &mut self.rdram_ic {
                        if (ic.init & 0x3F) as u32 == sdevid {
                            ic.test77 = (self.mch_drd_ & 0xFFFF) as u16;
                            return;
                        }
                    }
                }
            }
            0x04E => {
                // TEST78
                if sbc {
                    for ic in &mut self.rdram_ic {
                        ic.test78 = (self.mch_drd_ & 0xFFFF) as u16;
                    }
                } else {
                    for ic in &mut self.rdram_ic {
                        if (ic.init & 0x3F) as u32 == sdevid {
                            ic.test78 = (self.mch_drd_ & 0xFFFF) as u16;
                            return;
                        }
                    }
                }
            }
            _ => panic!("Unhandled RDRAM SWR register: 0x{:04X}", reg),
        }
    }

    fn setr(&mut self) {
        let sbc = (self.mch_ricm_ & (1 << 5)) != 0;
        if sbc {
            for ic in &mut self.rdram_ic {
                ic.init = 0;
                ic.test34 = 0;
                ic.cnfga = 0;
                ic.cnfgb = 0;
                ic.devid = 0;
                ic.refb = 0;
                ic.refr = 0;
                ic.cca = 0;
                ic.ccb = 0;
                ic.napx = 0;
                ic.pdnxa = 0;
                ic.pdnx = 0;
                ic.tparm = 0;
                ic.tfrm = 0;
                ic.tcdly1 = 0;
                ic.tcycle = 0;
                ic.skip = 0;
                ic.test77 = 0;
                ic.test78 = 0;
                ic.test79 = 0;
            }
        } else {
            let index = ((((self.mch_ricm_ >> 10) & 1) << 5) | (self.mch_ricm_ & 0x1F)) as usize;
            let ic = &mut self.rdram_ic[index];
            ic.init = 0;
            ic.test34 = 0;
            ic.cnfga = 0;
            ic.cnfgb = 0;
            ic.devid = 0;
            ic.refb = 0;
            ic.refr = 0;
            ic.cca = 0;
            ic.ccb = 0;
            ic.napx = 0;
            ic.pdnxa = 0;
            ic.pdnx = 0;
            ic.tparm = 0;
            ic.tfrm = 0;
            ic.tcdly1 = 0;
            ic.tcycle = 0;
            ic.skip = 0;
            ic.test77 = 0;
            ic.test78 = 0;
            ic.test79 = 0;
        }
    }
}
