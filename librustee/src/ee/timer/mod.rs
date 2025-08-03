use tracing::trace;

pub struct Timer {
    count: u16,        // TN_COUNT: 16-bit counter
    mode: u32,         // TN_MODE: Configuration and interrupt flags
    comp: u16,         // TN_COMP: Compare value
    hold: Option<u16>, // TN_HOLD: Counter value on SBUS interrupt (T0, T1 only)
}

pub struct Timers {
    timers: [Timer; 4], // Four timers (T0, T1, T2, T3)
}

impl Timer {
    fn new(has_hold: bool) -> Self {
        Timer {
            count: 0,
            mode: 0,
            comp: 0,
            hold: if has_hold { Some(0) } else { None },
        }
    }

    // Read 32-bit value from timer register
    fn read32(&self, offset: u32) -> u32 {
        match offset {
            0x00 => self.count as u32, // TN_COUNT
            0x10 => self.mode,         // TN_MODE
            0x20 => self.comp as u32,  // TN_COMP
            0x30 => {
                if let Some(hold) = self.hold {
                    hold as u32 // TN_HOLD (T0, T1 only)
                } else {
                    panic!(
                        "Read from TN_HOLD on timer without HOLD register at offset 0x{:08X}",
                        offset
                    );
                }
            }
            _ => panic!("Unknown timer read32 at offset 0x{:08X}", offset),
        }
    }

    // Write 32-bit value to timer register
    fn write32(&mut self, offset: u32, value: u32, timer_idx: usize) {
        match offset {
            0x00 => {
                // TN_COUNT: Set 16-bit counter
                self.count = (value & 0xFFFF) as u16;
                trace!("T{} COUNT write: 0x{:04X}", timer_idx, self.count);
            }
            0x10 => {
                // TN_MODE: Update configuration and handle interrupt flags
                let prev_mode = self.mode;
                // Preserve interrupt flags (bits 10, 11) unless cleared by writing 0
                let new_mode = (value & !0xC00) | (prev_mode & (value & 0xC00));
                self.mode = new_mode & 0xFFF; // Mask to 12 bits (0-11)
                trace!(
                    "T{} MODE write: 0x{:08X}, new MODE: 0x{:08X}",
                    timer_idx, value, self.mode
                );
                // Check for edge-triggered interrupts (0->1 transitions)
                let compare_flag_prev = (prev_mode >> 10) & 1;
                let overflow_flag_prev = (prev_mode >> 11) & 1;
                let compare_flag_new = (self.mode >> 10) & 1;
                let overflow_flag_new = (self.mode >> 11) & 1;
                if (compare_flag_prev == 0 && compare_flag_new == 1)
                    || (overflow_flag_prev == 0 && overflow_flag_new == 1)
                {
                    trace!(
                        "T{} interrupt triggered (compare: {}->{}, overflow: {}->{})",
                        timer_idx,
                        compare_flag_prev,
                        compare_flag_new,
                        overflow_flag_prev,
                        overflow_flag_new
                    );
                    // Note: Actual interrupt signaling would go to INTC here
                }
            }
            0x20 => {
                // TN_COMP: Set 16-bit compare value
                self.comp = (value & 0xFFFF) as u16;
                trace!("T{} COMP write: 0x{:04X}", timer_idx, self.comp);
            }
            0x30 => {
                // TN_HOLD: Only for T0, T1
                if let Some(hold) = self.hold.as_mut() {
                    *hold = (value & 0xFFFF) as u16;
                    trace!("T{} HOLD write: 0x{:04X}", timer_idx, *hold);
                } else {
                    panic!(
                        "Write to TN_HOLD on timer without HOLD register at offset 0x{:08X}, value=0x{:08X}",
                        offset, value
                    );
                }
            }
            _ => panic!(
                "Unknown timer write32 at offset 0x{:08X}, value=0x{:08X}",
                offset, value
            ),
        }
    }
}

impl Timers {
    pub fn new() -> Self {
        Timers {
            timers: [
                Timer::new(true),  // T0 (has HOLD)
                Timer::new(true),  // T1 (has HOLD)
                Timer::new(false), // T2 (no HOLD)
                Timer::new(false), // T3 (no HOLD, reserved for BIOS)
            ],
        }
    }

    // Read 32-bit value from timer register
    pub fn read32(&self, addr: u32) -> u32 {
        let addr = addr & 0x1FFFFFFF; // Mask physical address
        let timer_idx = ((addr - 0x10000000) >> 11) as usize; // N = (addr - base) / 0x800
        let offset = addr & 0x7FF; // Offset within timer
        if timer_idx >= 4 {
            panic!("Invalid timer index {} at addr 0x{:08X}", timer_idx, addr);
        }
        self.timers[timer_idx].read32(offset)
    }

    // Write 32-bit value to timer register
    pub fn write32(&mut self, addr: u32, value: u32) {
        let addr = addr & 0x1FFFFFFF; // Mask physical address
        let timer_idx = ((addr - 0x10000000) >> 11) as usize; // N = (addr - base) / 0x800
        let offset = addr & 0x7FF; // Offset within timer
        if timer_idx >= 4 {
            panic!(
                "Invalid timer index {} at addr 0x{:08X}, value=0x{:08X}",
                timer_idx, addr, value
            );
        }
        self.timers[timer_idx].write32(offset, value, timer_idx);
    }
}
