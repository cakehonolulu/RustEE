use crate::bus::Bus;
use crate::cpu::{CPU, EmulationBackend};
use crate::ee::EE;
use std::cmp::Ordering;
use std::collections::BinaryHeap;
use std::sync::atomic::Ordering as AtomicOrdering;
use std::sync::{Arc, Mutex};
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
    fn cmp(&self, other: &Self) -> Ordering {
        other.cycle.cmp(&self.cycle)
    }
}

impl PartialOrd for Event {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for Event {
    fn eq(&self, other: &Self) -> bool {
        self.cycle == other.cycle
    }
}

impl Eq for Event {}

#[derive(Debug, Default)]
pub struct Scheduler {
    events: BinaryHeap<Event>,
    pub current_cycle: u64,
}

const EE_FREQUENCY: u64 = 294_912_000;
const EE_CYCLES_PER_FRAME: u64 = EE_FREQUENCY / 60;

impl Scheduler {
    pub fn new() -> Self {
        Scheduler {
            events: BinaryHeap::new(),
            current_cycle: 0,
        }
    }

    pub fn run_main_loop<B: EmulationBackend<EE> + ?Sized>(
        backend: &mut B,
        bus_arc: Arc<Mutex<Box<Bus>>>,
    ) {
        loop {
            let ee_arc = backend.get_cpu();
            if ee_arc
                .lock()
                .unwrap()
                .is_paused
                .load(AtomicOrdering::SeqCst)
            {
                std::thread::park();
            }

            let mut bus_guard = bus_arc.lock().unwrap();
            let bus = &mut **bus_guard;

            let cycles_to_run = bus.scheduler.cycles_for_next_timeslice();

            if cycles_to_run > 0 {
                drop(bus_guard);
                backend.run_for_cycles(cycles_to_run);
                bus_guard = bus_arc.lock().unwrap();
                let bus_mut = &mut **bus_guard;

                bus_mut.scheduler.advance_cycles(cycles_to_run);

                let callbacks = bus_mut.scheduler.drain_due_events();
                for callback in callbacks {
                    callback(bus_mut);
                }
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
}