//! AC-06 verification: `compute_jitter` is deterministic + differentiating
//! through the crate's public `scheduler::compute_jitter` re-export.
//!
//! Existing `cron::tests::determinism_*` covers the same property at the
//! in-source unit-test layer; this file gives AC-06 a discrete verification
//! point at the integration-test layer + exercises the public re-export.

use std::collections::HashSet;
use std::time::Duration;

use advance_scheduler::compute_jitter;

#[test]
fn same_inputs_same_output() {
    // 10 invocations with identical args must produce bit-identical Durations.
    let mut seen = HashSet::new();
    for _ in 0..10 {
        seen.insert(compute_jitter("id-a", "*/5 * * * *", 300_000, 0.1));
    }
    assert_eq!(seen.len(), 1, "compute_jitter must be deterministic");
}

#[test]
fn distinct_ids_distinct_outputs() {
    // 100 distinct ids should produce overwhelmingly distinct jitter values.
    // Threshold ≥ 95 leaves slack for FNV-1a hash collisions but catches
    // constant or near-constant implementations.
    let mut seen = HashSet::new();
    for i in 0..100 {
        let id = format!("cron-{i}");
        seen.insert(compute_jitter(&id, "*/5 * * * *", 300_000, 0.1));
    }
    assert!(
        seen.len() >= 95,
        "expected ≥ 95 distinct jitter values, got {}",
        seen.len()
    );
}

#[test]
fn bounded_by_ceiling() {
    // ratio=1.0 + huge period — jitter is capped at 900_000 ms (15 min).
    for i in 0..1_000 {
        let id = format!("cron-{i}");
        let j = compute_jitter(&id, "* * * * *", u64::MAX / 2, 1.0);
        assert!(
            j < Duration::from_millis(900_000),
            "jitter {j:?} exceeds 15-min ceiling"
        );
    }
}
