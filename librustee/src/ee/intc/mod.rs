use tracing::{debug, trace};

pub struct INTC {
    i_stat: u32,
    i_mask: u32,
}

impl INTC {
    pub fn new() -> Self {
        INTC {
            i_stat: 0,
            i_mask: 0,
        }
    }

    // Read INTC register
    pub fn read32(&self, addr: u32) -> u32 {
        match addr & 0x1FFFFFFF {
            0x1000F000 => self.i_stat,
            0x1000F010 => self.i_mask,
            _ => {
                panic!("Unknown INTC read32 at addr=0x{:08X}", addr);
            }
        }
    }

    // Write to INTC register
    pub fn write32(&mut self, addr: u32, value: u32) {
        match addr & 0x1FFFFFFF {
            0x1000F000 => {
                // Writing to I_STAT clears interrupts (0 clears the bit, 1 preserves it)
                self.i_stat &= value;
                trace!(
                    "I_STAT write: 0x{:08X}, new I_STAT: 0x{:08X}",
                    value, self.i_stat
                );
            }
            0x1000F010 => {
                // Update I_MASK
                self.i_mask = value;
                trace!("I_MASK write: 0x{:08X}", value);
            }
            _ => {
                panic!(
                    "Unknown INTC write32 at addr=0x{:08X}, value=0x{:08X}",
                    addr, value
                );
            }
        }
    }
}
