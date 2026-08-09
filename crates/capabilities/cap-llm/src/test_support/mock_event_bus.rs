//! `MockEventBusEmit` for cap-llm's `#[cfg(test)]` modules.

#![cfg(test)]

use std::sync::Mutex;

use advance_shared_types::event::Event;
use advance_shared_types::traits::EventBusEmit;

#[derive(Default)]
pub(crate) struct MockEventBusEmit {
    pub events: Mutex<Vec<Event>>,
}

impl MockEventBusEmit {
    /// Helper: snapshot the recorded events.
    pub fn snapshot(&self) -> Vec<Event> {
        self.events.lock().unwrap().clone()
    }
}

impl EventBusEmit for MockEventBusEmit {
    fn emit(&self, event: Event) {
        self.events.lock().unwrap().push(event);
    }
}
