//! D4 / SD-12a: the CONTRACT-002 execution permit.
//!
//! The point of these tests is as much about what the permit does NOT guarantee as what
//! it does. A type whose NAME implies a guarantee its CONSTRUCTION does not provide is
//! precisely the failure mode this lane exists to remove, so the disclaimed property is
//! tested too.

use advance_runtime::circuit_breaker::*;
use advance_shared_types::ComponentType;

#[test]
fn t_sd12a_permit_is_minted_only_when_the_breaker_is_closed() {
    let bus = DefaultCircuitBreakerBus::new();
    // Closed breaker -> permit.
    assert!(
        bus.acquire_execution_permit_for("fs.read").is_ok(),
        "a closed breaker must mint a permit"
    );

    bus.open(CircuitBreaker {
        scope: BreakerScope::Capability,
        target: "fs.read".to_string(),
        state: BreakerState::Open,
        kill_existing: false,
        reason: "manual trip".to_string(),
    })
    .expect("open");

    // Open breaker -> NO permit, and the refusal carries the breaker's own reason rather
    // than a generic error.
    let err = bus
        .acquire_execution_permit_for("fs.read")
        .expect_err("an open breaker must refuse");
    assert!(
        !err.is_empty(),
        "the refusal must carry the breaker's reason, not an empty string"
    );

    // A DIFFERENT capability is unaffected — the gate is scoped, not global.
    assert!(bus.acquire_execution_permit_for("fs.write").is_ok());
}

/// The default body is written in terms of `is_open_capability`, so an implementor cannot
/// obtain a permissive permit path merely by NOT overriding it.
#[test]
fn t_sd12a_default_body_follows_the_implementors_own_breaker_state() {
    struct AlwaysOpen;
    impl CircuitBreakerBus for AlwaysOpen {
        fn is_open_capability(&self, _cap: &str) -> Option<String> {
            Some("always open".into())
        }
        fn is_open_component_type(&self, _k: ComponentType) -> Option<String> {
            None
        }
        fn is_open_agent(&self, _a: &str) -> Option<String> {
            None
        }
        fn open(&self, _s: CircuitBreaker) -> Result<(), BreakerError> {
            Ok(())
        }
        fn close(&self, _s: BreakerScope, _t: &str) -> Result<(), BreakerError> {
            Ok(())
        }
        fn half_open(&self, _s: BreakerScope, _t: &str) -> Result<(), BreakerError> {
            Ok(())
        }
        fn subscribe(&self) -> tokio::sync::mpsc::UnboundedReceiver<BreakerEvent> {
            tokio::sync::mpsc::unbounded_channel().1
        }
    }
    // Not overridden, yet it fails closed because it defers to the implementor's own
    // `is_open_capability`.
    // `ExecutionPermit` is intentionally not `PartialEq` (it is evidence, not a value),
    // so the assertion inspects the Err arm directly.
    match AlwaysOpen.acquire_execution_permit_for("anything") {
        Err(reason) => assert_eq!(reason, "always open"),
        Ok(_) => panic!("an implementor whose breaker is open must not receive a permit"),
    }
}

/// THE DISCLAIMED PROPERTY, tested so the disclaimer cannot quietly become false.
///
/// `DefaultCircuitBreakerBus::new()` is `pub` and starts EMPTY, so any caller can build a
/// permissive bus and get a permit from it. The permit is therefore an ORDERING/HOLDING
/// mechanism, not an unforgeable authority artefact — exactly as its rustdoc says. If a
/// future change made this test fail, the doc comment would have become a lie and would
/// need updating with it.
/// AUDIT-R5: the name used to shout `NOT` in capitals, which tripped `non_snake_case` —
/// a warning nothing surfaced, because the gate's lane-scoped clippy tier covered only
/// `advance-device-mesh` and `system-acceptance` while this lane also writes
/// `advance-runtime`, `cap-grant` and `advance-shared-types`. The emphasis now lives in
/// the doc comment above, where it cannot be silenced by a lint the gate never runs.
#[test]
fn t_sd12a_permit_is_not_unforgeable_and_says_so() {
    let permissive = DefaultCircuitBreakerBus::new();
    assert!(
        permissive
            .acquire_execution_permit_for("anything-at-all")
            .is_ok(),
        "a freshly constructed bus is permissive by construction; the permit's guarantee \
         is composition-based, and this test exists to keep that admission honest"
    );
}
