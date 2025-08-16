use std::collections::HashMap;
use tracing::{debug, error, trace};

// Register offsets within a channel
const CHCR_OFFSET: u32 = 0x00;
const MADR_OFFSET: u32 = 0x10;
const QWC_OFFSET: u32 = 0x20;
const TADR_OFFSET: u32 = 0x30;
const ASR0_OFFSET: u32 = 0x40;
const ASR1_OFFSET: u32 = 0x50;
const SADR_OFFSET: u32 = 0x80;

// Base addresses for DMA channels
pub const VIF0_BASE: u32 = 0x1000_8000;
pub const VIF1_BASE: u32 = 0x1000_9000;
pub const GIF_BASE: u32 = 0x1000_A000;
pub const IPU_FROM_BASE: u32 = 0x1000_B000;
pub const IPU_TO_BASE: u32 = 0x1000_B400;
pub const SIF0_BASE: u32 = 0x1000_C000;
pub const SIF1_BASE: u32 = 0x1000_C400;
pub const SIF2_BASE: u32 = 0x1000_C800;
pub const SPR_FROM_BASE: u32 = 0x1000_D000;
pub const SPR_TO_BASE: u32 = 0x1000_D400;

#[derive(Debug, Copy, Clone)]
pub enum ChannelType {
    Vif0,
    Vif1,
    Gif,
    IpuFrom,
    IpuTo,
    Sif0,
    Sif1,
    Sif2,
    SprFrom,
    SprTo,
}

#[derive(Debug)]
pub struct DmaChannel {
    pub(crate) chcr: u32,
    pub(crate) madr: u32,
    pub(crate) qwc: u32,
    pub(crate) tadr: u32,
    pub(crate) asr0: Option<u32>,
    pub(crate) asr1: Option<u32>,
    sadr: Option<u32>,
    channel_type: ChannelType,
}

impl DmaChannel {
    pub fn new(channel_type: ChannelType, has_asr: bool, has_sadr: bool) -> Self {
        DmaChannel {
            chcr: 0,
            madr: 0,
            qwc: 0,
            tadr: 0,
            asr0: if has_asr { Some(0) } else { None },
            asr1: if has_asr { Some(0) } else { None },
            sadr: if has_sadr { Some(0) } else { None },
            channel_type,
        }
    }

    pub fn read32(&self, offset: u32) -> u32 {
        match offset {
            CHCR_OFFSET => self.chcr,
            MADR_OFFSET => self.madr,
            QWC_OFFSET => self.qwc,
            TADR_OFFSET => self.tadr,
            ASR0_OFFSET => self.asr0.expect("ASR0 not available"),
            ASR1_OFFSET => self.asr1.expect("ASR1 not available"),
            SADR_OFFSET => self.sadr.expect("SADR not available"),
            _ => {
                error!("Invalid channel read offset: {:#X}", offset);
                0
            }
        }
    }

    pub fn write32(&mut self, offset: u32, value: u32) {
        match offset {
            CHCR_OFFSET => {
                self.chcr = (value & 0xFFFF) | (self.chcr & 0xFFFF_0000);
            }
            MADR_OFFSET => {
                self.madr = value & !0xF;
            }
            QWC_OFFSET => {
                self.qwc = value & 0xFFFF;
            }
            TADR_OFFSET => {
                self.tadr = value & !0xF;
            }
            ASR0_OFFSET => {
                if let Some(a) = &mut self.asr0 {
                    *a = value & !0xF;
                } else {
                    trace!("Write to ASR0 on channel without ASR0");
                }
            }
            ASR1_OFFSET => {
                if let Some(a) = &mut self.asr1 {
                    *a = value & !0xF;
                } else {
                    trace!("Write to ASR1 on channel without ASR1");
                }
            }
            SADR_OFFSET => {
                if let Some(s) = &mut self.sadr {
                    *s = value & !0xF;
                } else {
                    trace!("Write to SADR on channel without SADR");
                }
            }
            _ => {
                error!("Invalid channel write offset: {:#X}", offset);
            }
        }
    }

    pub fn is_running(&self) -> bool {
        (self.chcr & 0x100) != 0
    }
}

pub struct EEDMAC {
    pub(crate) channels: HashMap<u32, DmaChannel>,
    d_ctrl: u32,
    d_stat: u32,
    d_pcr: u32,
    d_sqwc: u32,
    d_rbsr: u32,
    d_rbor: u32,
    d_enablew: u32,
}

impl EEDMAC {
    pub fn new() -> Self {
        let mut channels = HashMap::new();
        channels.insert(VIF0_BASE, DmaChannel::new(ChannelType::Vif0, true, false));
        channels.insert(VIF1_BASE, DmaChannel::new(ChannelType::Vif1, true, false));
        channels.insert(GIF_BASE, DmaChannel::new(ChannelType::Gif, true, false));
        channels.insert(IPU_FROM_BASE, DmaChannel::new(ChannelType::IpuFrom, false, false));
        channels.insert(IPU_TO_BASE, DmaChannel::new(ChannelType::IpuTo, false, false));
        channels.insert(SIF0_BASE, DmaChannel::new(ChannelType::Sif0, false, false));
        channels.insert(SIF1_BASE, DmaChannel::new(ChannelType::Sif1, false, false));
        channels.insert(SIF2_BASE, DmaChannel::new(ChannelType::Sif2, false, false));
        channels.insert(SPR_FROM_BASE, DmaChannel::new(ChannelType::SprFrom, false, true));
        channels.insert(SPR_TO_BASE, DmaChannel::new(ChannelType::SprTo, false, true));

        EEDMAC {
            channels,
            d_ctrl: 0,
            d_stat: 0,
            d_pcr: 0,
            d_sqwc: 0,
            d_rbsr: 0,
            d_rbor: 0,
            d_enablew: 0,
        }
    }

    pub fn write_register(&mut self, addr: u32, value: u32) -> Option<ChannelType> {
        let base = addr & 0xFFFF_F000;
        let offset = addr & 0xFF;

        if let Some(ch) = self.channels.get_mut(&base) {
            ch.write32(offset, value);

            if offset == CHCR_OFFSET && ch.is_running() {
                return Some(ch.channel_type);
            }
        } else {
            match addr {
                0x1000_E000 => self.d_ctrl = value,
                0x1000_E010 => self.d_stat = value,
                0x1000_E020 => self.d_pcr = value,
                0x1000_E030 => self.d_sqwc = value,
                0x1000_E040 => self.d_rbsr = value,
                0x1000_E050 => self.d_rbor = value,
                0x1000_F590 => self.d_enablew = value,
                _ => error!("Invalid DMAC write address: {:#X}", addr),
            }
        }

        None
    }

    pub fn read_register(&self, addr: u32) -> u32 {
        let base = addr & 0xFFFF_F000;
        let offset = addr & 0xFF;

        if let Some(ch) = self.channels.get(&base) {
            ch.read32(offset)
        } else {
            match addr {
                0x1000_E000 => self.d_ctrl,
                0x1000_E010 => self.d_stat,
                0x1000_E020 => self.d_pcr,
                0x1000_E030 => self.d_sqwc,
                0x1000_E040 => self.d_rbsr,
                0x1000_E050 => self.d_rbor,
                0x1000_F590 => self.d_enablew,
                _ => {
                    error!("Invalid DMAC read address: {:#X}", addr);
                    0
                }
            }
        }
    }
}