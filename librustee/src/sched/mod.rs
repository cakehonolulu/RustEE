use crate::bus::Bus;
use crate::bus::tlb::TlbEntry;
use crate::cpu::EmulationBackend;
use crate::ee::EE;
use crate::gs::renderer::RendererKind;
use std::collections::BinaryHeap;
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tracing::trace;

pub type EventCallback = Box<dyn FnOnce(&mut Bus) + Send + 'static>;

pub struct Event {
    pub cycle: u64,
    callback: EventCallback,
}

pub struct FrameData {
    pub pixels: Vec<u8>,
    pub width: u32,
    pub height: u32,
    pub backend_frametime: f32,
    pub dropped_frames: u32,
}

pub type FrameSender = mpsc::SyncSender<FrameData>;
pub type FrameReceiver = mpsc::Receiver<FrameData>;

impl std::fmt::Debug for Event {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Event")
            .field("cycle", &self.cycle)
            .field("callback", &"FnOnce(&mut Bus)")
            .finish()
    }
}

impl Ord for Event {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        other.cycle.cmp(&self.cycle)
    }
}

impl PartialOrd for Event {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for Event {
    fn eq(&self, other: &Self) -> bool {
        self.cycle == other.cycle
    }
}

impl Eq for Event {}

pub fn create_frame_channel(back_pressure: usize) -> (FrameSender, FrameReceiver) {
    mpsc::sync_channel(back_pressure)
}

#[derive(Debug)]
pub struct Scheduler {
    events: BinaryHeap<Event>,
    pub current_cycle: u64,
    pub real_time_start: Option<Instant>,
    pub disable_throttle: bool,
    vsync_count: u32,
    last_vsync_time: Instant,
    pub internal_fps: f32,
    pub last_frame_dispatch_time: Option<Instant>,
    pub dropped_frames: u32,
}

pub enum DebugRequest {
    ReadRam { addr: u32, len: usize },
    ReadTlb,
    ReadDisassembly { pc: u32, num_words: usize },
    SwapRenderer(RendererKind),
}

pub enum DebugResponse {
    Ram { addr: u32, data: Vec<u8> },
    Tlb { entries: Vec<Option<TlbEntry>> },
    Disassembly { pc: u32, bytes: Vec<u8> },
}

pub fn create_debug_channel() -> (
    (mpsc::Sender<DebugRequest>, mpsc::Receiver<DebugResponse>),
    (mpsc::Receiver<DebugRequest>, mpsc::Sender<DebugResponse>),
) {
    let (req_tx, req_rx) = mpsc::channel();
    let (res_tx, res_rx) = mpsc::channel();

    ((req_tx, res_rx), (req_rx, res_tx))
}

const EE_FREQUENCY: u64 = 294_912_000;
pub const EE_CYCLES_PER_FRAME: u64 = EE_FREQUENCY / 60;

// NTSC Interlaced timing constants (59.94 Hz)
// Based on DobieStation
const VBLANK_START_CYCLES: u64 = 4_489_019; // Non-VBLANK period (~240 scanlines)
const VBLANK_DURATION: u64 = 431_096; // VBLANK period (~22-23 scanlines)
// Total frame: 4_920_115 cycles

impl Default for Scheduler {
    fn default() -> Self {
        Scheduler {
            events: BinaryHeap::new(),
            current_cycle: 0,
            real_time_start: None,
            disable_throttle: false,
            vsync_count: 0,
            last_vsync_time: Instant::now(),
            internal_fps: 0.0,
            last_frame_dispatch_time: None,
            dropped_frames: 0,
        }
    }
}

impl Scheduler {
    pub fn new() -> Self {
        Scheduler {
            events: BinaryHeap::new(),
            current_cycle: 0,
            real_time_start: None,
            disable_throttle: false,
            vsync_count: 0,
            last_vsync_time: Instant::now(),
            internal_fps: 0.0,
            last_frame_dispatch_time: None,
            dropped_frames: 0,
        }
    }

    pub fn initialize_events(&mut self) {
        self.add_event(VBLANK_START_CYCLES, Self::vblank_start_callback);
    }

    pub fn run_timeslice<B: EmulationBackend<EE> + ?Sized>(
        backend: &mut B,
        scheduler: &mut Scheduler,
        bus: &mut Bus,
    ) {
        if scheduler.real_time_start.is_none() {
            scheduler.real_time_start = Some(Instant::now());
        }

        let cycles_to_run = scheduler.cycles_for_next_timeslice();
        if cycles_to_run > 0 {
            backend.run_for_cycles(bus, cycles_to_run);
        }

        scheduler.advance_cycles(cycles_to_run);
        let callbacks = scheduler.drain_due_events();

        if !callbacks.is_empty() {
            for callback in callbacks {
                callback(bus);
            }
        }

        scheduler.sleep_if_ahead();
    }

    pub fn run_main_loop<B: EmulationBackend<EE> + ?Sized>(
        backend: &mut B,
        bus: &mut Bus,
        debug_rx: &mpsc::Receiver<DebugRequest>,
        debug_tx: &mpsc::Sender<DebugResponse>,
    ) {
        let scheduler_arc = bus.scheduler.clone();

        {
            let mut sched = scheduler_arc.lock().unwrap();
            if sched.real_time_start.is_none() {
                sched.real_time_start = Some(Instant::now());
            }
        }

        loop {
            let cycles_to_run = { scheduler_arc.lock().unwrap().cycles_for_next_timeslice() };

            if cycles_to_run > 0 {
                backend.run_for_cycles(bus, cycles_to_run);
            }

            let callbacks = {
                let mut sched = scheduler_arc.lock().unwrap();
                sched.advance_cycles(cycles_to_run);
                sched.drain_due_events()
            };

            for callback in callbacks {
                callback(bus);
            }

            scheduler_arc.lock().unwrap().sleep_if_ahead();

            let mut req_ram = None;
            let mut req_tlb = false;
            let mut req_disasm = None;

            while let Ok(req) = debug_rx.try_recv() {
                match req {
                    DebugRequest::ReadRam { addr, len } => req_ram = Some((addr, len)),
                    DebugRequest::ReadTlb => req_tlb = true,
                    DebugRequest::ReadDisassembly { pc, num_words } => {
                        req_disasm = Some((pc, num_words))
                    }
                    DebugRequest::SwapRenderer(new_kind) => {
                        bus.gs.swap_renderer(new_kind);
                    }
                }
            }

            if let Some((addr, len)) = req_ram {
                let mut data = vec![0; len];
                for i in 0..len {
                    data[i] = bus.ram.get((addr as usize) + i).copied().unwrap_or(0);
                }
                let _ = debug_tx.send(DebugResponse::Ram { addr, data });
            }

            if req_tlb {
                let _ = debug_tx.send(DebugResponse::Tlb {
                    entries: bus.tlb.entries.to_vec(),
                });
            }

            if let Some((pc, num_words)) = req_disasm {
                let mut bytes = Vec::with_capacity(num_words * 4);

                for i in 0..num_words {
                    let vaddr = pc.wrapping_add((i * 4) as u32);
                    let word = (bus.read32)(bus, vaddr);

                    bytes.extend_from_slice(&word.to_be_bytes());
                }

                let _ = debug_tx.send(DebugResponse::Disassembly { pc, bytes });
            }
        }
    }

    pub fn add_event<F>(&mut self, in_cycles: u64, callback: F)
    where
        F: FnOnce(&mut Bus) + Send + 'static,
    {
        let target_cycle = self.current_cycle.wrapping_add(in_cycles);
        trace!(
            "Adding event for cycle {} (in {} cycles)",
            target_cycle, in_cycles
        );
        self.events.push(Event {
            cycle: target_cycle,
            callback: Box::new(callback),
        });
    }

    pub fn cycles_for_next_timeslice(&self) -> u64 {
        if let Some(next_event) = self.events.peek() {
            let cycles_until_event = next_event.cycle.saturating_sub(self.current_cycle);
            std::cmp::min(cycles_until_event, EE_CYCLES_PER_FRAME)
        } else {
            EE_CYCLES_PER_FRAME
        }
    }

    pub fn advance_cycles(&mut self, cycles: u64) {
        self.current_cycle = self.current_cycle.wrapping_add(cycles);
    }

    pub fn drain_due_events(&mut self) -> Vec<EventCallback> {
        let mut callbacks = Vec::new();
        while let Some(event) = self.events.peek() {
            if event.cycle <= self.current_cycle {
                let event_to_run = self.events.pop().unwrap();
                trace!("Executing event for cycle {}", event_to_run.cycle);
                callbacks.push(event_to_run.callback);
            } else {
                break;
            }
        }
        callbacks
    }

    pub fn sleep_if_ahead(&self) {
        if self.disable_throttle {
            return;
        }
        if let Some(start) = self.real_time_start {
            let emulated_secs = self.current_cycle as f64 / EE_FREQUENCY as f64;
            let expected = start + Duration::from_secs_f64(emulated_secs);
            let now = Instant::now();
            if now < expected {
                trace!("Sleeping for {:?} to sync", expected - now);
                std::thread::sleep(expected - now);
            }
        }
    }

    /* When vertical blanking period starts, set VBLANK bit in GS CSR */
    fn vblank_start_callback(bus: &mut Bus) {
        trace!(
            "vsync_callback CSR state before toggling: 0x{:08X}",
            bus.gs.gs_csr
        );
        bus.gs.gs_csr |= 8;
        trace!(
            "vsync_callback CSR state after toggling: 0x{:08X}",
            bus.gs.gs_csr
        );

        let mut scheduler = bus.scheduler.lock().unwrap();
        scheduler.vsync_count += 1;
        let now = Instant::now();
        let elapsed = now.duration_since(scheduler.last_vsync_time).as_secs_f32();
        if elapsed >= 1.0 {
            scheduler.internal_fps = scheduler.vsync_count as f32 / elapsed;
            scheduler.vsync_count = 0;
            scheduler.last_vsync_time = now;
        }

        scheduler.add_event(VBLANK_DURATION, Self::vblank_end_callback);
    }

    /* When vertical blanking period ends, flush all draws to active framebuffer */
    fn vblank_end_callback(bus: &mut Bus) {
        let mut backend_frametime = 0.0;
        let mut dropped = 0;

        {
            let mut sched = bus.scheduler.lock().unwrap();
            let now = Instant::now();
            if let Some(last) = sched.last_frame_dispatch_time {
                backend_frametime = now.duration_since(last).as_secs_f32();
            }
            sched.last_frame_dispatch_time = Some(now);
            dropped = sched.dropped_frames;
        }

        bus.gs.draw_buffered();
        trace!(
            "Draw batch at cycle {}",
            bus.scheduler.lock().unwrap().current_cycle
        );

        // XXX: Needed?
        // bus.gs.gs_csr &= !8;

        if let Some(tx) = &bus.frame_tx {
            let (pixels_opt, w, h) = bus.gs.get_framebuffer_data();
            if let Some(pixels) = pixels_opt {
                let frame = FrameData {
                    pixels,
                    width: w,
                    height: h,
                    backend_frametime,
                    dropped_frames: dropped,
                };

                match tx.try_send(frame) {
                    Ok(_) => {
                        bus.scheduler.lock().unwrap().dropped_frames = 0;
                    }
                    Err(std::sync::mpsc::TrySendError::Full(_)) => {
                        bus.scheduler.lock().unwrap().dropped_frames += 1;
                    }
                    Err(_) => {}
                }
            }
        }

        let scheduler_clone = bus.scheduler.clone();
        let mut sched = scheduler_clone.lock().unwrap();
        sched.add_event(VBLANK_START_CYCLES, Self::vblank_start_callback);
    }

    pub fn reset_timeline(&mut self) {
        if self.current_cycle > 0 {
            let emulated_secs = self.current_cycle as f64 / EE_FREQUENCY as f64;
            let now = Instant::now();
            let offset = Duration::from_secs_f64(emulated_secs);
            self.real_time_start = now.checked_sub(offset).or(Some(now));
        } else {
            self.real_time_start = Some(Instant::now());
        }
    }
}
