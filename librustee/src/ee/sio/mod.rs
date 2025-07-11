use tracing::{debug, error, trace};
use std::sync::{Arc, RwLock};

pub trait SIOValue: Copy {
    fn to_u32(self) -> u32;
    fn from_u32(value: u32) -> Self;
    fn to_char(self) -> Option<char>;
}

impl SIOValue for u32 {
    fn to_u32(self) -> u32 {
        self
    }
    fn from_u32(value: u32) -> Self {
        value
    }
    fn to_char(self) -> Option<char> {
        None
    }
}

impl SIOValue for u8 {
    fn to_u32(self) -> u32 {
        self as u32
    }
    fn from_u32(value: u32) -> Self {
        if value > 0xFF {
            error!("Value 0x{:08X} too large for u8, truncating", value);
            (value & 0xFF) as u8
        } else {
            value as u8
        }
    }
    fn to_char(self) -> Option<char> {
        Some(self as char)
    }
}

#[derive(Clone, Copy)]
pub struct SIORegisters {
    pub lcr: u32,
    pub lsr: u32,
    pub ier: u32,
    pub isr: u32,
    pub fcr: u32,
    pub bgr: u32,
    pub txfifo: u32,
    pub rxfifo: u32,
}

pub struct SIO {
    pub registers: SIORegisters,
    pub ee_tx_buffer: String,
}

impl SIO {
    pub fn new() -> Self {
        SIO {
            registers: SIORegisters {
                lcr: 0,
                lsr: 0,
                ier: 0,
                isr: 0,
                fcr: 0,
                bgr: 0,
                txfifo: 0,
                rxfifo: 0,
            },
            ee_tx_buffer: String::new(),
        }
    }

    pub fn write<V: SIOValue>(&mut self, address: u32, value: V) {
        trace!("SIO::write: self={:p}, address=0x{:08X}, value=0x{:08X}", self, address, value.to_u32());
        match address {
            0x1000F100 => {
                trace!("LCR Write: 0x{:08X}", value.to_u32());
                self.registers.lcr = value.to_u32();
            }
            0x1000F110 => {
                trace!("LSR Write: 0x{:08X}", value.to_u32());
                self.registers.lsr = value.to_u32();
            }
            0x1000F120 => {
                trace!("IER Write: 0x{:08X}", value.to_u32());
                self.registers.ier = value.to_u32();
            }
            0x1000F130 => {
                trace!("ISR Write: 0x{:08X}", value.to_u32());
                self.registers.isr = value.to_u32();
            }
            0x1000F140 => {
                trace!("FCR Write: 0x{:08X}", value.to_u32());
                self.registers.fcr = value.to_u32();
            }
            0x1000F150 => {
                trace!("BGR Write: 0x{:08X}", value.to_u32());
                self.registers.bgr = value.to_u32();
            }
            0x1000F180 => {
                trace!("TXFIFO Write: 0x{:08X}", value.to_u32());
                self.registers.txfifo = value.to_u32();
                if let Some(transmitted_char) = value.to_char() {
                    trace!("Pushing char '{}' to ee_tx_buffer", transmitted_char);
                    if transmitted_char == '\n' {
                        debug!("{}", self.ee_tx_buffer);
                        self.ee_tx_buffer.clear();
                    } else {
                        self.ee_tx_buffer.push(transmitted_char);
                    }
                } else {
                    error!("Invalid type for TXFIFO write: expected u8, got u32");
                }
            }
            0x1000F1C0 => {
                trace!("RXFIFO Write: 0x{:08X}", value.to_u32());
                self.registers.rxfifo = value.to_u32();
            }
            _ => {
                error!("Unknown SIO write address: 0x{:08X}, value: 0x{:08X}", address, value.to_u32());
            }
        }
    }

    pub fn read<V: SIOValue>(&self, address: u32) -> V {
        trace!("SIO::read: self={:p}, address=0x{:08X}", self, address);
        let value = match address {
            0x1000F100 => {
                trace!("LCR Read: 0x{:08X}", self.registers.lcr);
                self.registers.lcr
            }
            0x1000F110 => {
                trace!("LSR Read: 0x{:08X}", self.registers.lsr);
                self.registers.lsr
            }
            0x1000F120 => {
                trace!("IER Read: 0x{:08X}", self.registers.ier);
                self.registers.ier
            }
            0x1000F130 => {
                trace!("ISR Read: 0x{:08X}", self.registers.isr);
                self.registers.isr
            }
            0x1000F140 => {
                trace!("FCR Read: 0x{:08X}", self.registers.fcr);
                self.registers.fcr
            }
            0x1000F150 => {
                trace!("BGR Read: 0x{:08X}", self.registers.bgr);
                self.registers.bgr
            }
            0x1000F180 => {
                trace!("TXFIFO Read: 0x{:08X}", self.registers.txfifo);
                self.registers.txfifo
            }
            0x1000F1C0 => {
                trace!("RXFIFO Read: 0x{:08X}", self.registers.rxfifo);
                self.registers.rxfifo
            }
            _ => {
                error!("Unknown SIO read address: 0x{:08X}", address);
                0
            }
        };
        V::from_u32(value)
    }
}