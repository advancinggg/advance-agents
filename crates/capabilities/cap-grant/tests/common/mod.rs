//! Shared test helpers for cap-grant integration tests.
//!
//! `#![allow(dead_code)]` is load-bearing: each `tests/*.rs` file compiles
//! to its own integration-test crate, and individual tests use only a
//! subset of these helpers (`snapshot` / `count_of` / `first_of` / `all_of`).
//! The crate-level allow keeps clippy quiet without forcing per-method
//! attributes.

#![allow(dead_code)]

use std::sync::{Arc, Mutex};

use advance_database::{R2d2SqliteIndexHandle, SqliteIndexHandle};
use advance_shared_types::event::Event;
use advance_shared_types::traits::EventBusEmit;
use cap_grant::{GrantSqliteIndex, GrantStore};

/// EventBus stub that captures emitted events for assertions.
pub struct RecordingBus {
    events: Mutex<Vec<Event>>,
}

impl RecordingBus {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            events: Mutex::new(Vec::new()),
        })
    }
    pub fn snapshot(&self) -> Vec<Event> {
        self.events.lock().unwrap().clone()
    }
    pub fn count_of(&self, event_type: &str) -> usize {
        self.events
            .lock()
            .unwrap()
            .iter()
            .filter(|e| e.event_type == event_type)
            .count()
    }
    pub fn first_of(&self, event_type: &str) -> Option<Event> {
        self.events
            .lock()
            .unwrap()
            .iter()
            .find(|e| e.event_type == event_type)
            .cloned()
    }
    pub fn all_of(&self, event_type: &str) -> Vec<Event> {
        self.events
            .lock()
            .unwrap()
            .iter()
            .filter(|e| e.event_type == event_type)
            .cloned()
            .collect()
    }
}

impl EventBusEmit for RecordingBus {
    fn emit(&self, event: Event) {
        self.events.lock().unwrap().push(event);
    }
}

/// Build (store, recording_bus, sqlite_handle) for an in-memory test.
pub fn make_store() -> (
    Arc<GrantStore>,
    Arc<RecordingBus>,
    Arc<dyn SqliteIndexHandle>,
) {
    let handle: Arc<dyn SqliteIndexHandle> =
        Arc::new(R2d2SqliteIndexHandle::new_in_memory().expect("in-memory sqlite"));
    let bus = RecordingBus::new();
    let bus_dyn: Arc<dyn EventBusEmit> = bus.clone();
    let index = GrantSqliteIndex::new(handle.clone());
    index.ensure_schema().expect("ensure_schema");
    let store = Arc::new(GrantStore::new(index, bus_dyn));
    (store, bus, handle)
}

/// Build (sqlite_index, recording_bus, sqlite_handle) without a GrantStore —
/// for tests that exercise the SQLite layer directly.
pub fn make_index() -> (
    GrantSqliteIndex,
    Arc<RecordingBus>,
    Arc<dyn SqliteIndexHandle>,
) {
    let handle: Arc<dyn SqliteIndexHandle> =
        Arc::new(R2d2SqliteIndexHandle::new_in_memory().expect("in-memory sqlite"));
    let bus = RecordingBus::new();
    let index = GrantSqliteIndex::new(handle.clone());
    (index, bus, handle)
}
