use crate::bus::Bus;
use crate::cpu::{CPU, EmulationBackend};
use crate::ee::EE;
use std::collections::BinaryHeap;
use std::sync::{Arc, Mutex};
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};
use tracing::trace;

pub type EventCallback = Box<dyn FnOnce(&mut Bus) + Send + 'static>;

pub struct Event {
    pub cycle: u64,
    callback: EventCallback,
}

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

#[derive(Debug)]
pub struct Scheduler {
    events: BinaryHeap<Event>,
    pub current_cycle: u64,
    pub real_time_start: Option<Instant>,
    pub disable_throttle: bool,
    vsync_count: u32,
    last_vsync_time: Instant,
    pub internal_fps: f32,
}

const EE_FREQUENCY: u64 = 294_912_000;
pub const EE_CYCLES_PER_FRAME: u64 = EE_FREQUENCY / 60;

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
        }
    }

    pub fn initialize_events(&mut self) {
        self.add_event(4489019, |bus| {
            bus.gs.draw_buffered();

            let scheduler_clone = bus.scheduler.clone();
            let mut scheduler = scheduler_clone.lock().unwrap();
            scheduler.add_event(4489019, Self::draw_batch_callback);
            scheduler.add_event(431096, Self::vsync_callback);
        });
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
            backend.run_for_cycles(cycles_to_run);
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
        scheduler_arc: Arc<Mutex<Scheduler>>,
        bus_arc: Arc<Mutex<Box<Bus>>>,
    ) {
        {
            let mut scheduler = scheduler_arc.lock().unwrap();
            if scheduler.real_time_start.is_none() {
                scheduler.real_time_start = Some(Instant::now());
            }
        }

        loop {
            let cycles_to_run = {
                scheduler_arc.lock().unwrap().cycles_for_next_timeslice()
            };

            if cycles_to_run > 0 {
                backend.run_for_cycles(cycles_to_run);
            }

            let callbacks = {
                let mut scheduler = scheduler_arc.lock().unwrap();
                scheduler.advance_cycles(cycles_to_run);
                scheduler.drain_due_events()
            };

            if !callbacks.is_empty() {
                for callback in callbacks {
                    let mut guard = bus_arc.lock().unwrap();
                    let bus: &mut Bus = &mut *guard;
                    callback(bus);
                }
            }

            {
                let scheduler = scheduler_arc.lock().unwrap();
                scheduler.sleep_if_ahead();
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
            target_cycle,
            in_cycles
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

    fn vsync_callback(bus: &mut Bus) {
        trace!("vsync_callback CSR state before toggling: 0x{:08X}", bus.gs.gs_csr);
        bus.gs.gs_csr |= 8;
        trace!("vsync_callback CSR state after toggling: 0x{:08X}", bus.gs.gs_csr);

        let mut scheduler = bus.scheduler.lock().unwrap();
        scheduler.vsync_count += 1;
        let now = Instant::now();
        let elapsed = now.duration_since(scheduler.last_vsync_time).as_secs_f32();
        if elapsed >= 1.0 {
            scheduler.internal_fps = scheduler.vsync_count as f32 / elapsed;
            scheduler.vsync_count = 0;
            scheduler.last_vsync_time = now;
        }
    }

    fn draw_batch_callback(bus: &mut Bus) {
        bus.gs.draw_buffered();
        trace!("Draw batch at cycle {}", bus.scheduler.lock().unwrap().current_cycle);

        let scheduler_clone = bus.scheduler.clone();
        let mut scheduler = scheduler_clone.lock().unwrap();
        scheduler.add_event(4489019, Self::draw_batch_callback);
        scheduler.add_event(431096, Self::vsync_callback);
    }
}