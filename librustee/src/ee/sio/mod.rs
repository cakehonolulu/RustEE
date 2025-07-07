use tracing::{debug, error};
use std::sync::{Arc, RwLock};

#[derive(Clone, Copy)]
pub struct SIORegisters {
    pub lcr: u32,    // Line Control Register
    pub lsr: u32,    // Line Status Register
    pub ier: u32,    // Interrupt Enable Register
    pub isr: u32,    // Interrupt Status Register
    pub fcr: u32,    // FIFO Control Register
    pub bgr: u32,    // Baud Rate Control Register
    pub txfifo: u32, // Transmit FIFO Register
    pub rxfifo: u32, // Receive FIFO Register
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

    pub fn write(&mut self, address: u32, value: u32) {
        match address {
            0xB000F100 => {
                debug!("LCR Write: 0x{:08X}", value);
                self.registers.lcr = value
            }
            0xB000F110 => {
                debug!("LSR Write: 0x{:08X}", value);
                self.registers.lsr = value
            }
            0xB000F120 => {
                debug!("IER Write: 0x{:08X}", value);
                self.registers.ier = value
            }
            0xB000F130 => {
                debug!("ISR Write: 0x{:08X}", value);
                self.registers.isr = value
            }
            0xB000F140 => {
                debug!("FCR Write: 0x{:08X}", value);
                self.registers.fcr = value
            }
            0xB000F150 => {
                debug!("BGR Write: 0x{:08X}", value);
                self.registers.bgr = value
            }
            0xB000F180 => {
                debug!("TXFIFO Write: 0x{:08X}", value);
                self.registers.txfifo = value;
                let transmitted_char = value as u8 as char;

                if transmitted_char == '\r' {
                    debug!("SIO TX Buffer Output: {}", self.ee_tx_buffer);
                    self.ee_tx_buffer.clear();
                } else {
                    self.ee_tx_buffer.push(transmitted_char);
                }
            }
            0xB000F1C0 => {
                debug!("RXFIFO Write: 0x{:08X}", value);
                self.registers.rxfifo = value
            }
            _ => {
                error!("Unknown SIO write address: 0x{:08X}, value: 0x{:08X}", address, value);
            }
        }
    }

    pub fn read(&self, address: u32) -> u32 {
        match address {
            0xB000F100 => {
                debug!("LCR Read: 0x{:08X}", self.registers.lcr);
                self.registers.lcr
            }
            0xB000F110 => {
                debug!("LSR Read: 0x{:08X}", self.registers.lsr);
                self.registers.lsr
            }
            0xB000F120 => {
                debug!("IER Read: 0x{:08X}", self.registers.ier);
                self.registers.ier
            }
            0xB000F130 => {
                debug!("ISR Read: 0x{:08X}", self.registers.isr);
                self.registers.isr
            }
            0xB000F140 => {
                debug!("FCR Read: 0x{:08X}", self.registers.fcr);
                self.registers.fcr
            }
            0xB000F150 => {
                debug!("BGR Read: 0x{:08X}", self.registers.bgr);
                self.registers.bgr
            }
            0xB000F180 => {
                debug!("TXFIFO Read: 0x{:08X}", self.registers.txfifo);
                self.registers.txfifo
            }
            0xB000F1C0 => {
                debug!("RXFIFO Read: 0x{:08X}", self.registers.rxfifo);
                self.registers.rxfifo
            }
            _ => {
                error!("Unknown SIO read address: 0x{:08X}", address);
                0
            }
        }
    }
}