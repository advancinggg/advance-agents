//! Tests for CircuitBreakerBus (CONTRACT-002, AC-08 MODULE-001-side clauses 1+2).
//! Clause 3 (mailbox freeze/drain) lives in MODULE-006 and is not covered here.

use advance_runtime::circuit_breaker::{
    AdminOp, BreakerError, BreakerScope, BreakerState, CircuitBreaker, CircuitBreakerBus,
    DefaultCircuitBreakerBus,
};
use advance_shared_types::ComponentType;
use std::time::Duration;

fn breaker_open(scope: BreakerScope, target: &str, reason: &str) -> CircuitBreaker {
    CircuitBreaker {
        scope,
        target: target.to_string(),
        state: BreakerState::Open,
        kill_existing: false,
        reason: reason.to_string(),
    }
}

// ---------- Unit: query behavior ----------

#[test]
fn default_empty_queries_return_none() {
    let bus = DefaultCircuitBreakerBus::new();
    assert!(bus.is_open_capability("llm").is_none());
    assert!(bus.is_open_component_type(ComponentType::Agent).is_none());
    assert!(bus.is_open_agent("a-123").is_none());
}

#[test]
fn open_capability_blocks_matching() {
    let bus = DefaultCircuitBreakerBus::new();
    bus.open(breaker_open(BreakerScope::Capability, "llm", "outage"))
        .unwrap();
    assert_eq!(bus.is_open_capability("llm").as_deref(), Some("outage"));
}

#[test]
fn open_does_not_leak_across_scopes() {
    let bus = DefaultCircuitBreakerBus::new();
    bus.open(breaker_open(BreakerScope::Capability, "foo", "x"))
        .unwrap();
    assert!(bus.is_open_agent("foo").is_none());
    assert!(bus.is_open_component_type(ComponentType::Agent).is_none());
}

#[test]
fn open_component_type_blocks() {
    let bus = DefaultCircuitBreakerBus::new();
    bus.open(breaker_open(
        BreakerScope::ComponentType,
        ComponentType::Cron.as_str(),
        "quota",
    ))
    .unwrap();
    assert_eq!(
        bus.is_open_component_type(ComponentType::Cron).as_deref(),
        Some("quota")
    );
    assert!(bus.is_open_component_type(ComponentType::Agent).is_none());
}

#[test]
fn open_agent_blocks() {
    let bus = DefaultCircuitBreakerBus::new();
    bus.open(breaker_open(BreakerScope::Agent, "a-123", "misbehave"))
        .unwrap();
    assert_eq!(bus.is_open_agent("a-123").as_deref(), Some("misbehave"));
}

// ---------- Unit: state transitions ----------

#[test]
fn close_removes_and_unblocks() {
    let bus = DefaultCircuitBreakerBus::new();
    bus.open(breaker_open(BreakerScope::Capability, "llm", "x"))
        .unwrap();
    bus.close(BreakerScope::Capability, "llm").unwrap();
    assert!(bus.is_open_capability("llm").is_none());
}

#[test]
fn half_open_unblocks() {
    // HalfOpen allows a single probe — is_open_* must return None.
    let bus = DefaultCircuitBreakerBus::new();
    bus.open(breaker_open(BreakerScope::Capability, "llm", "x"))
        .unwrap();
    bus.half_open(BreakerScope::Capability, "llm").unwrap();
    assert!(bus.is_open_capability("llm").is_none());
}

#[test]
fn close_on_nonexistent_returns_notfound() {
    let bus = DefaultCircuitBreakerBus::new();
    let err = bus
        .close(BreakerScope::Capability, "missing")
        .expect_err("expected NotFound");
    assert!(matches!(err, BreakerError::NotFound { .. }));
}

#[test]
fn half_open_on_nonexistent_returns_notfound() {
    let bus = DefaultCircuitBreakerBus::new();
    let err = bus
        .half_open(BreakerScope::Capability, "missing")
        .expect_err("expected NotFound");
    assert!(matches!(err, BreakerError::NotFound { .. }));
}

#[test]
fn open_replaces_existing() {
    let bus = DefaultCircuitBreakerBus::new();
    bus.open(breaker_open(BreakerScope::Capability, "llm", "first"))
        .unwrap();
    bus.open(breaker_open(BreakerScope::Capability, "llm", "second"))
        .unwrap();
    assert_eq!(bus.is_open_capability("llm").as_deref(), Some("second"));
}

#[test]
fn open_with_non_open_state_rejected() {
    let bus = DefaultCircuitBreakerBus::new();
    let mut spec = breaker_open(BreakerScope::Capability, "llm", "x");
    spec.state = BreakerState::Closed;
    let err = bus.open(spec).expect_err("expected InvalidTransition");
    assert!(matches!(err, BreakerError::InvalidTransition { .. }));
}

#[test]
fn open_componenttype_with_invalid_target_rejected() {
    // "Cron" (capital) isn't a canonical ComponentType::as_str() value.
    let bus = DefaultCircuitBreakerBus::new();
    let spec = breaker_open(BreakerScope::ComponentType, "Cron", "x");
    let err = bus.open(spec).expect_err("expected InvalidTarget");
    assert!(matches!(err, BreakerError::InvalidTarget { .. }));
}

#[test]
fn open_with_halfopen_state_rejected() {
    let bus = DefaultCircuitBreakerBus::new();
    let mut spec = breaker_open(BreakerScope::Capability, "llm", "x");
    spec.state = BreakerState::HalfOpen;
    let err = bus.open(spec).expect_err("expected InvalidTransition");
    assert!(matches!(err, BreakerError::InvalidTransition { .. }));
}

#[test]
fn open_with_empty_target_rejected() {
    let bus = DefaultCircuitBreakerBus::new();
    let spec = breaker_open(BreakerScope::Capability, "   ", "x");
    let err = bus.open(spec).expect_err("expected InvalidTarget");
    assert!(matches!(err, BreakerError::InvalidTarget { .. }));
}

#[test]
fn open_with_oversized_reason_rejected() {
    let bus = DefaultCircuitBreakerBus::new();
    let mut spec = breaker_open(BreakerScope::Capability, "llm", "x");
    spec.reason = "x".repeat(1024);
    let err = bus
        .open(spec)
        .expect_err("expected InvalidTarget for reason too long");
    assert!(matches!(err, BreakerError::InvalidTarget { .. }));
}

#[test]
fn open_with_zero_width_target_rejected() {
    let bus = DefaultCircuitBreakerBus::new();
    let spec = breaker_open(BreakerScope::Capability, "ll\u{200B}m", "x");
    let err = bus
        .open(spec)
        .expect_err("expected InvalidTarget for zero-width char");
    assert!(matches!(err, BreakerError::InvalidTarget { .. }));
}

#[test]
fn open_with_bidi_override_target_rejected() {
    // U+202E RIGHT-TO-LEFT OVERRIDE is category Cf (Format), not Cc (Control).
    // Must be explicitly blocked to prevent homograph/log-confusion attacks.
    let bus = DefaultCircuitBreakerBus::new();
    let spec = breaker_open(BreakerScope::Capability, "evil\u{202E}llm", "x");
    let err = bus
        .open(spec)
        .expect_err("expected InvalidTarget for BIDI override");
    assert!(matches!(err, BreakerError::InvalidTarget { .. }));
}

#[test]
fn open_with_ansi_escape_in_reason_rejected() {
    let bus = DefaultCircuitBreakerBus::new();
    let spec = breaker_open(BreakerScope::Capability, "llm", "\x1b[31mred\x1b[0m");
    let err = bus
        .open(spec)
        .expect_err("expected InvalidTarget for ANSI in reason");
    assert!(matches!(err, BreakerError::InvalidTarget { .. }));
}

#[test]
fn open_with_control_char_target_rejected() {
    let bus = DefaultCircuitBreakerBus::new();
    let spec = breaker_open(BreakerScope::Capability, "llm\n", "x");
    let err = bus
        .open(spec)
        .expect_err("expected InvalidTarget for control char");
    assert!(matches!(err, BreakerError::InvalidTarget { .. }));
}

// ---------- Unit: admin bypass ----------

#[test]
fn admin_op_helper_identifies_all_variants() {
    assert!(DefaultCircuitBreakerBus::is_admin_op(
        &AdminOp::TerminateAgent
    ));
    assert!(DefaultCircuitBreakerBus::is_admin_op(&AdminOp::CancelRun));
    assert!(DefaultCircuitBreakerBus::is_admin_op(&AdminOp::Rollback));
}

// ---------- Integration: event subscription ----------

#[tokio::test]
async fn subscriber_receives_open_event() {
    let bus = DefaultCircuitBreakerBus::new();
    let mut rx = bus.subscribe();
    bus.open(breaker_open(BreakerScope::Capability, "llm", "x"))
        .unwrap();
    let ev = tokio::time::timeout(Duration::from_secs(1), rx.recv())
        .await
        .expect("timeout")
        .expect("channel closed");
    assert_eq!(ev.scope, BreakerScope::Capability);
    assert_eq!(ev.target, "llm");
    assert_eq!(ev.new_state, BreakerState::Open);
    assert_eq!(ev.reason, "x");
}

#[tokio::test]
async fn subscriber_receives_close_event() {
    let bus = DefaultCircuitBreakerBus::new();
    let mut rx = bus.subscribe();
    bus.open(breaker_open(BreakerScope::Capability, "llm", "x"))
        .unwrap();
    bus.close(BreakerScope::Capability, "llm").unwrap();
    let e1 = rx.recv().await.unwrap();
    let e2 = rx.recv().await.unwrap();
    assert_eq!(e1.new_state, BreakerState::Open);
    assert_eq!(e2.new_state, BreakerState::Closed);
    // Close event preserves the original reason for audit trail.
    assert_eq!(e2.reason, "x");
}

#[tokio::test]
async fn event_carries_kill_existing() {
    let bus = DefaultCircuitBreakerBus::new();
    let mut rx = bus.subscribe();
    let mut spec = breaker_open(BreakerScope::Agent, "a-1", "policy");
    spec.kill_existing = true;
    bus.open(spec).unwrap();
    let ev = rx.recv().await.unwrap();
    assert!(
        ev.kill_existing,
        "kill_existing must propagate to event for §1.4.4 4-layer enforcement"
    );
}

#[tokio::test]
async fn multiple_subscribers_all_receive() {
    let bus = DefaultCircuitBreakerBus::new();
    let mut rx1 = bus.subscribe();
    let mut rx2 = bus.subscribe();
    bus.open(breaker_open(BreakerScope::Agent, "a", "r"))
        .unwrap();
    let e1 = rx1.recv().await.unwrap();
    let e2 = rx2.recv().await.unwrap();
    assert_eq!(e1, e2);
}

#[tokio::test]
async fn dropped_subscriber_pruned() {
    let bus = DefaultCircuitBreakerBus::new();
    let rx1 = bus.subscribe();
    drop(rx1);

    // Trigger one emit so retain() prunes the dropped sender.
    bus.open(breaker_open(BreakerScope::Capability, "c1", "x"))
        .unwrap();

    // Now add a fresh subscriber and emit another event — it should only see this one.
    let mut rx2 = bus.subscribe();
    bus.open(breaker_open(BreakerScope::Capability, "c2", "y"))
        .unwrap();

    let ev = tokio::time::timeout(Duration::from_secs(1), rx2.recv())
        .await
        .expect("timeout")
        .expect("closed");
    assert_eq!(ev.target, "c2");
}

// ---------- Compile-time: object safety + Send + Sync ----------

#[test]
fn bus_is_send_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<DefaultCircuitBreakerBus>();
}

#[test]
fn trait_is_object_safe() {
    // Compile-time: can construct a trait object.
    let _: std::sync::Arc<dyn CircuitBreakerBus> =
        std::sync::Arc::new(DefaultCircuitBreakerBus::new());
}
