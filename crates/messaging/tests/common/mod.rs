//! Shared test fixtures for the `advance-messaging` slice-A integration
//! tests. Each `tests/*.rs` file declares `mod common;` to bring these
//! into scope.
//!
//! Fixtures:
//! - `TestTree` — `AgentTreeReader` impl with hand-rolled HashMaps;
//!   bodies the 2 methods slice-A's `validate_routing` actually calls
//!   (`parent_of`, `agent_exists`); other 4 methods `unimplemented!()`.
//! - `PermissiveValidator` / `RejectingValidator` / `RecordingValidator`
//!   — `ActionValidator` impls covering the 3 test postures.
//! - `RecordingSink` — `RejectionSink` impl capturing rejections.
//! - `MockEventBusEmit` — `EventBusEmit` impl capturing emitted Events.

use std::collections::HashMap;
use std::sync::Mutex;

use advance_messaging::RejectionSink;
use advance_shared_types::agent_tree::{AgentKind, AgentTreeReader, Capability};
use advance_shared_types::event::Event;
use advance_shared_types::mailbox::{AgentAction, Message, MessageKind};
use advance_shared_types::security_validator::{ActionValidator, SecurityError};
use advance_shared_types::traits::EventBusEmit;

/// A minimal source `Message` for the Step-3 `dispatch(agent_id, source, actions)`
/// seam. `origin: None` models the non-channel (POST /msg / agent) path, so the
/// outbound sink takes the registry/gate-only branch, not the channel-egress one.
#[allow(dead_code)]
pub fn test_message() -> Message {
    Message {
        id: "test-msg".to_string(),
        kind: MessageKind::User,
        from: "user:test".to_string(),
        to: "agent:x".to_string(),
        payload: Vec::new(),
        context: None,
        timestamp: std::time::SystemTime::now(),
        origin: None,
    }
}

// ─────────────────────────────────────────────────────────────────────
// TestTree — AgentTreeReader fixture
// ─────────────────────────────────────────────────────────────────────

#[allow(dead_code)]
pub struct TestTree {
    /// Maps agent_id → Some(parent_id) or None (root).
    /// agents not present in this map are not `agent_exists`.
    pub parents: HashMap<String, Option<String>>,
}

#[allow(dead_code)]
impl TestTree {
    pub fn new() -> Self {
        Self {
            parents: HashMap::new(),
        }
    }

    pub fn add_root(mut self, id: &str) -> Self {
        self.parents.insert(id.to_string(), None);
        self
    }

    pub fn add_child(mut self, id: &str, parent: &str) -> Self {
        self.parents
            .insert(id.to_string(), Some(parent.to_string()));
        self
    }
}

impl AgentTreeReader for TestTree {
    fn parent_of(&self, agent_id: &str) -> Option<String> {
        self.parents.get(agent_id).cloned().flatten()
    }

    fn agent_exists(&self, agent_id: &str) -> bool {
        self.parents.contains_key(agent_id)
    }

    fn children_of(&self, _agent_id: &str) -> Vec<String> {
        unimplemented!("TestTree: children_of not used by slice-A validate_routing")
    }

    fn siblings_of(&self, _agent_id: &str) -> Vec<String> {
        unimplemented!("TestTree: siblings_of not used by slice-A validate_routing")
    }

    fn agent_kind(&self, _agent_id: &str) -> Option<AgentKind> {
        unimplemented!("TestTree: agent_kind not used by slice-A")
    }

    fn capabilities(&self, _agent_id: &str) -> Vec<Capability> {
        unimplemented!("TestTree: capabilities not used by slice-A")
    }
}

// ─────────────────────────────────────────────────────────────────────
// ActionValidator fixtures
// ─────────────────────────────────────────────────────────────────────

/// Always returns `Ok(())` — the permissive validator.
#[allow(dead_code)]
pub struct PermissiveValidator;

impl ActionValidator for PermissiveValidator {
    fn validate(&self, _agent_id: &str, _actions: &[AgentAction]) -> Result<(), SecurityError> {
        Ok(())
    }
}

/// Always returns `Err(error)` with a pre-set SecurityError.
#[allow(dead_code)]
pub struct RejectingValidator {
    pub error: SecurityError,
}

impl ActionValidator for RejectingValidator {
    fn validate(&self, _agent_id: &str, _actions: &[AgentAction]) -> Result<(), SecurityError> {
        Err(self.error.clone())
    }
}

/// Records every validate() call. Returns Err per pre-set policy.
#[allow(dead_code)]
pub struct RecordingValidator {
    pub error: Option<SecurityError>,
    pub calls: Mutex<Vec<(String, usize)>>,
}

#[allow(dead_code)]
impl RecordingValidator {
    pub fn new_rejecting(error: SecurityError) -> Self {
        Self {
            error: Some(error),
            calls: Mutex::new(Vec::new()),
        }
    }

    pub fn new_permissive() -> Self {
        Self {
            error: None,
            calls: Mutex::new(Vec::new()),
        }
    }

    pub fn call_count(&self) -> usize {
        self.calls.lock().unwrap().len()
    }
}

impl ActionValidator for RecordingValidator {
    fn validate(&self, agent_id: &str, actions: &[AgentAction]) -> Result<(), SecurityError> {
        self.calls
            .lock()
            .unwrap()
            .push((agent_id.to_string(), actions.len()));
        match &self.error {
            Some(err) => Err(err.clone()),
            None => Ok(()),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────
// RejectionSink fixture
// ─────────────────────────────────────────────────────────────────────

#[allow(dead_code)]
pub struct RecordingSink {
    pub rejections: Mutex<Vec<(String, SecurityError)>>,
}

#[allow(dead_code)]
impl RecordingSink {
    pub fn new() -> Self {
        Self {
            rejections: Mutex::new(Vec::new()),
        }
    }

    pub fn count(&self) -> usize {
        self.rejections.lock().unwrap().len()
    }
}

impl RejectionSink for RecordingSink {
    fn record_rejection(&self, agent_id: &str, error: &SecurityError) {
        self.rejections
            .lock()
            .unwrap()
            .push((agent_id.to_string(), error.clone()));
    }
}

// ─────────────────────────────────────────────────────────────────────
// MockEventBusEmit fixture
// ─────────────────────────────────────────────────────────────────────

#[allow(dead_code)]
pub struct MockEventBusEmit {
    pub events: Mutex<Vec<Event>>,
}

#[allow(dead_code)]
impl MockEventBusEmit {
    pub fn new() -> Self {
        Self {
            events: Mutex::new(Vec::new()),
        }
    }

    pub fn count(&self) -> usize {
        self.events.lock().unwrap().len()
    }
}

impl EventBusEmit for MockEventBusEmit {
    fn emit(&self, event: Event) {
        self.events.lock().unwrap().push(event);
    }
}

// ─────────────────────────────────────────────────────────────────────
// Slice-B fixtures: MessageOrigin builder + channel-registry helper
// ─────────────────────────────────────────────────────────────────────

use advance_messaging::StaticChannelAdapterRegistry;
use advance_shared_types::mailbox::{MessageContext, MessageOrigin};

/// Ergonomic [`MessageOrigin`] builder for trace/reply tests. `received_at`
/// uses `advance_shared_types::chrono::Utc::now()` (chrono is re-exported by
/// shared-types so the integration-test crate need not depend on it
/// directly).
#[allow(dead_code)]
pub fn make_origin(
    message_id: &str,
    original_channel: &str,
    original_sender: &str,
    adapter_id: &str,
) -> MessageOrigin {
    MessageOrigin {
        message_id: message_id.to_string(),
        original_channel: original_channel.to_string(),
        original_sender: original_sender.to_string(),
        adapter_id: adapter_id.to_string(),
        channel_metadata: HashMap::new(),
        received_at: advance_shared_types::chrono::Utc::now(),
        context: None,
    }
}

/// Like [`make_origin`] but with `channel_metadata` + `context` populated —
/// used to assert reply passthrough (AC-06) and context inheritance (AC-07).
#[allow(dead_code)]
pub fn make_origin_full(
    message_id: &str,
    adapter_id: &str,
    metadata: &[(&str, &str)],
    context: Option<MessageContext>,
) -> MessageOrigin {
    let mut cm = HashMap::new();
    for (k, v) in metadata {
        cm.insert(k.to_string(), v.to_string());
    }
    MessageOrigin {
        message_id: message_id.to_string(),
        original_channel: "telegram".to_string(),
        original_sender: "telegram:9001".to_string(),
        adapter_id: adapter_id.to_string(),
        channel_metadata: cm,
        received_at: advance_shared_types::chrono::Utc::now(),
        context,
    }
}

/// Build a [`StaticChannelAdapterRegistry`] from `(channel_id,
/// adapter_agent_id)` pairs (panics on an invalid pair — test-only).
#[allow(dead_code)]
pub fn static_registry(pairs: &[(&str, &str)]) -> StaticChannelAdapterRegistry {
    let mut r = StaticChannelAdapterRegistry::new();
    for (c, a) in pairs {
        r.insert(*c, *a).expect("test registry pair must be valid");
    }
    r
}

/// A `MessageContext` with all six fields set to recognizable values —
/// used to assert verbatim inheritance on reply (AC-07).
#[allow(dead_code)]
pub fn full_context() -> MessageContext {
    MessageContext {
        task_id: Some("task-1".into()),
        run_id: Some("run-1".into()),
        execution_id: Some("exec-1".into()),
        trace_id: Some("trace-1".into()),
        in_reply_to: Some("old-irt".into()),
        correlation_id: Some("corr-1".into()),
    }
}

// ─────────────────────────────────────────────────────────────────────
// Slice-C CB-bus mock + recv-completion poll helper
// ─────────────────────────────────────────────────────────────────────

use advance_runtime::circuit_breaker::{
    BreakerError, BreakerEvent, BreakerScope, CircuitBreaker, CircuitBreakerBus,
};
use advance_shared_types::component::ComponentType;
use std::sync::Arc;
use tokio::sync::mpsc;

/// Minimal `CircuitBreakerBus` impl for slice-C Layer-1 gate testing. Only
/// `is_open_agent` carries real behavior — the constructor's `opened` slice
/// supplies the per-agent `(agent_id, reason)` map. Of the other 6 trait
/// methods, 5 (`is_open_capability` / `is_open_component_type` / `open` /
/// `close` / `half_open`) are explicitly `unimplemented!` so any accidental
/// misuse surfaces loudly; `subscribe` returns an empty receiver (closed on
/// first poll because the sender is dropped immediately) so the future
/// BreakerEvent-subscriber slice can wire a subscriber task against this
/// mock without panicking — the subscriber will see "no events" and exit.
#[allow(dead_code)]
pub struct MockCircuitBreakerBus {
    opened: HashMap<String, String>,
}

#[allow(dead_code)]
impl MockCircuitBreakerBus {
    /// Construct a mock with the given `(agent_id, reason)` entries treated as
    /// agent-scope OPEN breakers. Any agent_id not in the list reports
    /// closed.
    pub fn new(opened: &[(&str, &str)]) -> Self {
        Self {
            opened: opened
                .iter()
                .map(|(a, r)| ((*a).to_string(), (*r).to_string()))
                .collect(),
        }
    }
}

impl CircuitBreakerBus for MockCircuitBreakerBus {
    fn is_open_capability(&self, _cap: &str) -> Option<String> {
        unimplemented!(
            "MockCircuitBreakerBus does not implement is_open_capability — \
             slice-C tests only exercise the agent-scope Layer-1 gate"
        )
    }

    fn is_open_component_type(&self, _kind: ComponentType) -> Option<String> {
        unimplemented!(
            "MockCircuitBreakerBus does not implement is_open_component_type — \
             slice-C tests only exercise the agent-scope Layer-1 gate"
        )
    }

    fn is_open_agent(&self, agent_id: &str) -> Option<String> {
        self.opened.get(agent_id).cloned()
    }

    fn open(&self, _spec: CircuitBreaker) -> Result<(), BreakerError> {
        unimplemented!(
            "MockCircuitBreakerBus does not implement open — slice-C tests \
             configure opened breakers via the constructor's `opened` slice"
        )
    }

    fn close(&self, _scope: BreakerScope, _target: &str) -> Result<(), BreakerError> {
        unimplemented!(
            "MockCircuitBreakerBus does not implement close — slice-C tests \
             swap mock instances rather than mutating one in place"
        )
    }

    fn half_open(&self, _scope: BreakerScope, _target: &str) -> Result<(), BreakerError> {
        unimplemented!(
            "MockCircuitBreakerBus does not implement half_open — slice-C tests \
             do not exercise the half-open transition"
        )
    }

    fn subscribe(&self) -> mpsc::UnboundedReceiver<BreakerEvent> {
        // Adversarial R1 W (mock-friendliness fix): return an empty
        // receiver instead of panicking. The mock has no event source so
        // this receiver will never yield (the dropped sender closes the
        // channel immediately — recv() will return None on first poll).
        // This lets the future BreakerEvent-subscriber slice's tests
        // construct a mock bus + spawn its subscriber task without blowing
        // up; the subscriber will see "no events" and exit cleanly.
        let (_tx, rx) = mpsc::unbounded_channel();
        rx
    }
}

/// Factory shortcut: build an `Arc<dyn CircuitBreakerBus>` from a slice of
/// (agent_id, reason) pairs treated as agent-scope OPEN breakers.
#[allow(dead_code)]
pub fn make_mock_cb_bus(opened: &[(&str, &str)]) -> Arc<dyn CircuitBreakerBus> {
    Arc::new(MockCircuitBreakerBus::new(opened))
}

/// Yield-bounded poll helper for the slice-C Layer-4 recv-blocks-then-drains
/// assertions (T-C09, T-C12). Mirrors the slice-D pattern at
/// `crates/messaging/reply-tracker/tests/session_tree.rs:114-128` — under
/// `#[tokio::test(start_paused = true)]` the spawned task is deterministically
/// allowed to progress on each `yield_now`, since the recv path is timer-free.
/// Returns once the JoinHandle is finished OR the iteration cap is reached;
/// the caller asserts on the resulting `Option<T>` (None ⇒ still blocked).
#[allow(dead_code)]
pub async fn wait_for_recv_completion<T: Send + 'static>(
    handle: &mut tokio::task::JoinHandle<T>,
    max_iters: usize,
) -> Option<T> {
    for _ in 0..max_iters {
        if handle.is_finished() {
            // Take the result. Re-enter the JoinHandle; std::mem::replace
            // pattern is unnecessary here — we drop it after the join.
            return handle.await.ok();
        }
        tokio::task::yield_now().await;
    }
    None
}

// ─────────────────────────────────────────────────────────────────────
// Slice-D AC-09 + AC-13 helpers — event-bus + freeze polling
// ─────────────────────────────────────────────────────────────────────

/// Yield-bounded poll helper: wait until the `MockEventBusEmit` has recorded
/// at least `n` events, or the iteration cap is reached. Returns `true` on
/// success, `false` if the cap is hit first.
///
/// Mirrors the slice-C `wait_for_recv_completion` pattern. Slice-D
/// integration tests use this to wait for the spawned BreakerSubscriber task
/// to drain a BreakerEvent OR for the dispatcher's async emit to land in the
/// mock bus (emit is synchronous in MockEventBusEmit, so the helper is mostly
/// future-proofing for non-synchronous emitters).
#[allow(dead_code)]
pub async fn wait_for_event_count(bus: &MockEventBusEmit, n: usize, max_iters: usize) -> bool {
    for _ in 0..max_iters {
        if bus.count() >= n {
            return true;
        }
        tokio::task::yield_now().await;
    }
    false
}

/// Yield-bounded poll helper: wait until `predicate()` returns true, or the
/// iteration cap is reached. Used by slice-D AC-13 tests to wait for the
/// BreakerSubscriber task to flip a mailbox's frozen state.
#[allow(dead_code)]
pub async fn wait_until<F: FnMut() -> bool>(mut predicate: F, max_iters: usize) -> bool {
    for _ in 0..max_iters {
        if predicate() {
            return true;
        }
        tokio::task::yield_now().await;
    }
    false
}
