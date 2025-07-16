use tracing::{error, info};

pub struct SIF {
    mscom: u32, // Main CPU (EE) communication register, writable only by EE
    smcom: u32, // Sub CPU (IOP) communication register, writable only by IOP
    msflg: u32, // Main CPU flag register, IOP writes mask
    smflg: u32, // Sub CPU flag register, EE writes mask
    ctrl: u32,  // Control register
    bd6: u32,   // Unknown register, accessed during initialization
}

impl SIF {
    pub fn new() -> Self {
        SIF {
            mscom: 0,
            smcom: 0,
            msflg: 0,
            smflg: 0,
            ctrl: 0,
            bd6: 0,
        }
    }

    /// Read from SIF register
    pub fn read32(&mut self, addr: u32) -> u32 {
        let reg_name = match addr & 0xFF {
            0x00 => "SIF_MSCOM",
            0x10 => "SIF_SMCOM",
            0x20 => "SIF_MSFLG",
            0x30 => "SIF_SMFLG",
            0x40 => "SIF_CTRL",
            0x60 => "SIF_BD6",
            _ => {
                error!("Invalid SIF register read at address 0x{:08X}", addr);
                panic!("Invalid SIF register read at address 0x{:08X}", addr);
            }
        };

        let value = match addr & 0xFF {
            0x00 => self.mscom,
            0x10 => self.smcom,
            0x20 => self.msflg,
            0x30 => {
                // TODO: Remove this hack once we have IOP
                self.smflg |= 0x10000;
                self.smflg
            }
            0x40 => self.ctrl,
            0x60 => self.bd6,
            _ => unreachable!(), // Panic handled above
        };

        info!("SIF register read from {}: 0x{:08X}", reg_name, value);
        value
    }

    /// Write to SIF register
    pub fn write32(&mut self, addr: u32, value: u32) {
        let reg_name = match addr & 0xFF {
            0x00 => "SIF_MSCOM",
            0x10 => "SIF_SMCOM",
            0x20 => "SIF_MSFLG",
            0x30 => "SIF_SMFLG",
            0x40 => "SIF_CTRL",
            0x60 => "SIF_BD6",
            _ => {
                error!(
                    "Invalid SIF register write at address 0x{:08X}, value=0x{:08X}",
                    addr, value
                );
                return;
            }
        };

        match addr & 0xFF {
            0x00 => {
                self.mscom = value;
                info!("SIF register write to {}: 0x{:08X}", reg_name, value);
            }
            0x10 => {
                self.smcom = value;
                info!("SIF register write to {}: 0x{:08X}", reg_name, value);
            }
            0x20 => {
                self.msflg = value;
                info!("SIF register write to {}: 0x{:08X}", reg_name, value);
            }
            0x30 => {
                self.smflg = value;
                info!("SIF register write to {}: 0x{:08X}", reg_name, value);
            }
            0x40 => {
                let mut new_value = value;
                new_value |= 0xF000_0000; // Bits 28-31 always 0xF
                /*
                    new_value &= !0x100; // Bit 8 always 0 for IOP
                */
                new_value |= 0x1; // Bit 1 always 1
                self.ctrl = new_value;
                info!("SIF register write to {}: 0x{:08X}", reg_name, new_value);
            }
            0x60 => {
                self.bd6 = value;
                info!("SIF register write to {}: 0x{:08X}", reg_name, value);
            }
            _ => unreachable!(),
        }
    }
}
