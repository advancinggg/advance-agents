//! Audit/observability sink for `client_api.*` events (§2.14).
//!
//! The core emits [`AuditEvent`]s through an [`AuditSink`]. The default [`NoopSink`] keeps the
//! foundation crate free of a MODULE-019 dependency; a later slice plugs in the real
//! observability emitter without changing the core. **No secret ever enters an `AuditEvent`**
//! (no session token, CSRF token, bootstrap code, or raw body) — the redaction floor of §2.14.

use std::sync::{Arc, Mutex};

/// A projected, secret-free audit record for a client request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditEvent {
    /// Event name, e.g. `client_api.request`, `client_api.response`, `client_api.denied`.
    pub kind: String,
    pub request_id: String,
    /// Resource family (e.g. `session`, `health`), never a secret.
    pub family: String,
    /// HTTP-style method as a string.
    pub method: String,
    /// Denial reason (stable error code string), for `client_api.denied`.
    pub reason: Option<String>,
}

impl AuditEvent {
    pub fn new(
        kind: impl Into<String>,
        request_id: impl Into<String>,
        family: impl Into<String>,
        method: impl Into<String>,
    ) -> Self {
        Self {
            kind: kind.into(),
            request_id: request_id.into(),
            family: family.into(),
            method: method.into(),
            reason: None,
        }
    }

    pub fn with_reason(mut self, reason: impl Into<String>) -> Self {
        self.reason = Some(reason.into());
        self
    }
}

/// Sink for audit events.
pub trait AuditSink: Send + Sync {
    fn emit(&self, event: AuditEvent);
}

/// Default no-op sink (keeps the foundation free of provider deps).
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopSink;

impl AuditSink for NoopSink {
    fn emit(&self, _event: AuditEvent) {}
}

/// A test sink that records every emitted event for assertions (e.g. secret-hygiene checks).
#[derive(Debug, Default, Clone)]
pub struct RecordingSink {
    events: Arc<Mutex<Vec<AuditEvent>>>,
}

impl RecordingSink {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn events(&self) -> Vec<AuditEvent> {
        self.events.lock().expect("recording sink lock").clone()
    }
}

impl AuditSink for RecordingSink {
    fn emit(&self, event: AuditEvent) {
        self.events.lock().expect("recording sink lock").push(event);
    }
}
