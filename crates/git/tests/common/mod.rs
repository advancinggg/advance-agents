//! Shared integration-test helpers (Slice C+D).
//!
//! `TestMutableGitConfigProvider` is an integration-test-only implementation
//! of [`advance_git::GitConfigProvider`] supporting hot-reload via a
//! `publish` method. Lives in `tests/common/mod.rs` (not in the library
//! crate) so it stays out of the production API surface.

use advance_git::{GitConfigProvider, GitConfigSnapshot};
use std::sync::{Mutex, RwLock};
use tokio::sync::mpsc;

#[allow(dead_code)] // per-binary dead-code nits; each integration test uses a subset
pub struct TestMutableGitConfigProvider {
    current: RwLock<GitConfigSnapshot>,
    subscribers: Mutex<Vec<mpsc::Sender<GitConfigSnapshot>>>,
}

#[allow(dead_code)]
impl TestMutableGitConfigProvider {
    pub fn new(initial: GitConfigSnapshot) -> Self {
        Self {
            current: RwLock::new(initial),
            subscribers: Mutex::new(Vec::new()),
        }
    }

    /// Publish a new snapshot. Subscribers receive via `try_send`; if a
    /// subscriber's channel is full, the update is dropped (standard
    /// bounded-fan-out pattern). Validates bounds before publishing so an
    /// accidental zero-interval does not drive the gc ticker into
    /// undefined territory — the gc loop ALSO clamps defensively, so this
    /// is defense-in-depth.
    pub fn publish(&self, snapshot: GitConfigSnapshot) {
        assert!(
            snapshot.gc_interval_hours > 0 && snapshot.gc_interval_hours <= 8760,
            "publish: gc_interval_hours out of bounds"
        );
        assert!(
            snapshot.max_tracked_file_mb > 0 && snapshot.max_tracked_file_mb <= 4096,
            "publish: max_tracked_file_mb out of bounds"
        );
        *self.current.write().unwrap_or_else(|e| e.into_inner()) = snapshot;
        let mut subs = self.subscribers.lock().unwrap_or_else(|e| e.into_inner());
        // Prune closed senders opportunistically.
        subs.retain(|s| !s.is_closed());
        for tx in subs.iter() {
            let _ = tx.try_send(snapshot);
        }
    }
}

impl GitConfigProvider for TestMutableGitConfigProvider {
    fn snapshot(&self) -> GitConfigSnapshot {
        *self.current.read().unwrap_or_else(|e| e.into_inner())
    }

    fn subscribe(&self) -> mpsc::Receiver<GitConfigSnapshot> {
        let (tx, rx) = mpsc::channel(16);
        self.subscribers
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(tx);
        rx
    }
}

// Slice E: `CollectingEventBus` — integration-test EventBus impl that
// buffers every emitted `Event` for assertions. Same `#[allow(dead_code)]`
// discipline as `TestMutableGitConfigProvider` because each integration
// test binary (`tests/gc.rs`, `tests/rollback.rs`, etc.) compiles as an
// independent crate and includes this module via `mod common;`; binaries
// that don't exercise `CollectingEventBus` would otherwise trip
// `dead_code` under `-D warnings`.
use advance_shared_types::event::Event;
use advance_shared_types::traits::EventBusEmit;

#[allow(dead_code)]
#[derive(Default)]
pub struct CollectingEventBus {
    events: Mutex<Vec<Event>>,
}

#[allow(dead_code)]
impl CollectingEventBus {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn drain(&self) -> Vec<Event> {
        std::mem::take(&mut *self.events.lock().unwrap_or_else(|e| e.into_inner()))
    }

    pub fn len(&self) -> usize {
        self.events.lock().unwrap_or_else(|e| e.into_inner()).len()
    }
}

impl EventBusEmit for CollectingEventBus {
    fn emit(&self, event: Event) {
        self.events
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(event);
    }
}
