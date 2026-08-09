//! HF-2 builder smoke — `circuit_breaker()` exposes the real, injector-wired breaker bus
//! so a journey can open a breaker and observe its dispatch-blocked / admin-bypass state.
//! This proves the driver is wired; the full "new dispatch blocked / messages frozen /
//! admin-bypass through the real messaging path" journey (SYS-J-39) is Track J round-2.

use advance_runtime::circuit_breaker::{
    AdminOp, BreakerScope, BreakerState, CircuitBreaker, DefaultCircuitBreakerBus,
};
use system_acceptance::{Cap, SystemUnderTest};

const CORE_BYTES: &[u8] =
    include_bytes!("../../runtime/tests/fixtures/guest-rust-j01-skeleton.core.wasm");
const AGENT: &str = "agent:harness";

#[tokio::test(flavor = "multi_thread")]
async fn breaker_knob_opens_and_reports_state() {
    let sut = SystemUnderTest::builder()
        .caps(&[Cap::Fs])
        .build(CORE_BYTES)
        .await;

    let breaker = sut.circuit_breaker();
    assert!(
        breaker.is_open_agent(AGENT).is_none(),
        "the breaker starts closed"
    );

    breaker
        .open(CircuitBreaker {
            scope: BreakerScope::Agent,
            target: AGENT.to_string(),
            state: BreakerState::Open,
            kill_existing: false,
            reason: "harness-smoke".to_string(),
        })
        .expect("open the agent-scope breaker");

    assert_eq!(
        breaker.is_open_agent(AGENT).as_deref(),
        Some("harness-smoke"),
        "the agent breaker now reports open, carrying the reason"
    );

    // Admin control ops bypass breaker state unconditionally (is_admin_op takes &AdminOp).
    assert!(DefaultCircuitBreakerBus::is_admin_op(
        &AdminOp::TerminateAgent
    ));
    assert!(DefaultCircuitBreakerBus::is_admin_op(&AdminOp::CancelRun));
}
