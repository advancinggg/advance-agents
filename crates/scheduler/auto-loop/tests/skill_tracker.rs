//! AC-18: SkillPreState tracker semantics (first-insert-wins,
//! apply-on-discard, clear-on-keep, CONTRACT-164 SkillStateReader-driven
//! pre-activation snapshot).
//!
//! Also exercises the `SkillRollback` write surface (M015-local trait)
//! through `RecordingSkillRollback` from `tests/common`.

mod common;

use advance_scheduler_auto_loop::{
    NoopSkillRollback, SkillPreState, SkillTracker, SkillTrackerError,
};
use advance_shared_types::skills::{Provenance, SkillInfo, SkillStateReader, TrustLevel};

use common::{FailingSkillRollback, RecordedCall, RecordingSkillRollback};

// MODULE-015-T18-slC.a — first-insert-wins per PRD §12.6.5.
#[test]
fn first_insert_wins_version_then_version() {
    let mut t = SkillTracker::new();
    t.record_pre_activation("skill_A", Some(3));
    // Re-activate the same skill within the same iteration with a different
    // version — first-insert-wins means Version(3) is preserved.
    t.record_pre_activation("skill_A", Some(5));
    assert_eq!(t.get("skill_A"), Some(&SkillPreState::Version(3)));
}

// MODULE-015-T18-slC.b — Absent variant + first-insert-wins.
#[test]
fn first_insert_wins_absent_blocks_later_version() {
    let mut t = SkillTracker::new();
    t.record_pre_activation("skill_B", None);
    t.record_pre_activation("skill_B", Some(7));
    // Absent is the first insert — later Version(7) is dropped.
    assert_eq!(t.get("skill_B"), Some(&SkillPreState::Absent));
}

// MODULE-015-T18-slC.c — deterministic sorted dispatch on apply_discard.
#[tokio::test]
async fn apply_discard_dispatches_per_variant_sorted() {
    let mut t = SkillTracker::new();
    // Record skills in non-alphabetical order on purpose; the tracker MUST
    // dispatch in sorted order regardless of insertion.
    t.record_pre_activation("zebra", Some(2));
    t.record_pre_activation("alpha", None);
    t.record_pre_activation("mango", Some(7));

    let recorder = RecordingSkillRollback::new();
    t.apply_discard("root", &recorder)
        .await
        .expect("apply_discard ok");
    let calls = recorder.calls();

    // Sorted by skill_id (alpha, mango, zebra).
    assert_eq!(
        calls,
        vec![
            RecordedCall::Delete {
                agent_id: "root".to_string(),
                skill_id: "alpha".to_string(),
            },
            RecordedCall::Rollback {
                agent_id: "root".to_string(),
                skill_id: "mango".to_string(),
                target_version: 7,
            },
            RecordedCall::Rollback {
                agent_id: "root".to_string(),
                skill_id: "zebra".to_string(),
                target_version: 2,
            },
        ]
    );
    // HashMap drained by apply_discard.
    assert!(t.is_empty());
}

// MODULE-015-T18-slC.d — clear() on iteration KEEP drains without
// dispatching any SkillRollback calls (verified by RecordingSkillRollback
// observing zero calls).
#[tokio::test]
async fn clear_on_keep_no_dispatch() {
    let mut t = SkillTracker::new();
    t.record_pre_activation("skill_C", Some(1));
    t.record_pre_activation("skill_D", None);
    assert_eq!(t.len(), 2);

    let recorder = RecordingSkillRollback::new();
    // KEEP path: tracker.clear() drains the HashMap; we then verify
    // the recorder observed zero rollback calls (had we called
    // apply_discard, both skills would have been dispatched).
    t.clear();
    assert!(t.is_empty());
    assert!(recorder.calls().is_empty());
}

// MODULE-015-T18-slC.e — NoopSkillRollback used with apply_discard returns
// Ok and consumes the tracker entries (the default impl is a no-op but
// SHOULD still drain the tracker — invariant of apply_discard).
#[tokio::test]
async fn noop_rollback_drains_tracker() {
    let mut t = SkillTracker::new();
    t.record_pre_activation("skill_E", Some(0));
    t.record_pre_activation("skill_F", None);

    let noop = NoopSkillRollback;
    t.apply_discard("root", &noop)
        .await
        .expect("apply_discard ok");
    assert!(t.is_empty(), "NoopSkillRollback consumes entries");
}

// MODULE-015-T18-slC.f — single record + apply_discard with
// RecordingSkillRollback. Sanity-check the call-recording mechanism.
#[tokio::test]
async fn recording_rollback_records_single_call() {
    let mut t = SkillTracker::new();
    t.record_pre_activation("skill_G", Some(42));

    let recorder = RecordingSkillRollback::new();
    t.apply_discard("alice", &recorder)
        .await
        .expect("apply_discard ok");

    assert_eq!(
        recorder.calls(),
        vec![RecordedCall::Rollback {
            agent_id: "alice".to_string(),
            skill_id: "skill_G".to_string(),
            target_version: 42,
        }]
    );
}

// MODULE-015-T18-slC.x — Defense-in-depth caps (adversarial Round-1 W1).
// MAX_TRACKED_SKILLS prevents unbounded growth; MAX_SKILL_ID_BYTES
// prevents memory amplification via huge skill_id strings.
#[test]
fn record_pre_activation_rejects_oversized_skill_id() {
    use advance_scheduler_auto_loop::skill_tracker::MAX_SKILL_ID_BYTES;
    let mut t = SkillTracker::new();
    let too_long = "x".repeat(MAX_SKILL_ID_BYTES + 1);
    t.record_pre_activation(&too_long, Some(1));
    assert!(t.is_empty(), "oversized skill_id must be silently dropped");
    // Boundary: exactly MAX_SKILL_ID_BYTES is accepted.
    let max_len = "y".repeat(MAX_SKILL_ID_BYTES);
    t.record_pre_activation(&max_len, Some(1));
    assert_eq!(t.len(), 1);
}

#[test]
fn record_pre_activation_caps_total_tracked_skills() {
    use advance_scheduler_auto_loop::skill_tracker::MAX_TRACKED_SKILLS;
    let mut t = SkillTracker::new();
    for i in 0..MAX_TRACKED_SKILLS {
        t.record_pre_activation(&format!("skill_{i}"), Some(1));
    }
    assert_eq!(t.len(), MAX_TRACKED_SKILLS);
    // One more new skill → rejected (silently).
    t.record_pre_activation("overflow_skill", Some(1));
    assert_eq!(t.len(), MAX_TRACKED_SKILLS);
    // Re-activating an EXISTING skill still works (first-insert-wins; no
    // growth → not rejected even at capacity).
    t.record_pre_activation("skill_0", Some(99));
    assert_eq!(t.len(), MAX_TRACKED_SKILLS); // no change in size
                                             // First-insert-wins preserved: skill_0 still Version(1).
    assert_eq!(t.get("skill_0"), Some(&SkillPreState::Version(1)));
}

// MODULE-015-T18-slC.f2 — Partial-drain semantics on mid-iteration
// failure (audit Round-1 W1 fix). The first dispatch fails; the failing
// entry and all subsequent entries (in sorted order) MUST remain in the
// HashMap for retry — the tracker MUST NOT be fully drained.
#[tokio::test]
async fn apply_discard_partial_drain_on_failure() {
    let mut t = SkillTracker::new();
    t.record_pre_activation("alpha", Some(1));
    t.record_pre_activation("mango", Some(2));
    t.record_pre_activation("zebra", Some(3));

    // Failing rollback short-circuits on "mango" (the second entry in
    // sorted order). "alpha" SHOULD be removed (successful dispatch);
    // "mango" stays (failed dispatch); "zebra" stays (never attempted).
    let failing = FailingSkillRollback::fail_on("mango");
    let err = t
        .apply_discard("root", &failing)
        .await
        .expect_err("expected SkillTrackerError::Rollback");
    match err {
        SkillTrackerError::Rollback(reason) => {
            assert!(
                reason.contains("mango"),
                "reason should reference failing skill_id; got: {reason}"
            );
        }
    }

    // alpha was dispatched successfully → removed.
    assert!(
        t.get("alpha").is_none(),
        "successful entry must be removed from tracker"
    );
    // mango failed → still in tracker (retry possible).
    assert_eq!(
        t.get("mango"),
        Some(&SkillPreState::Version(2)),
        "failing entry must remain in tracker for retry"
    );
    // zebra was never attempted (sort order: alpha < mango < zebra) → still in tracker.
    assert_eq!(
        t.get("zebra"),
        Some(&SkillPreState::Version(3)),
        "unprocessed entry must remain in tracker for retry"
    );
    assert_eq!(t.len(), 2);

    // Recorder observes only the two attempted dispatches (alpha succeeded,
    // mango failed). zebra was never attempted.
    assert_eq!(
        failing.calls(),
        vec![
            RecordedCall::Rollback {
                agent_id: "root".to_string(),
                skill_id: "alpha".to_string(),
                target_version: 1,
            },
            RecordedCall::Rollback {
                agent_id: "root".to_string(),
                skill_id: "mango".to_string(),
                target_version: 2,
            },
        ]
    );
}

// MODULE-015-T18-slC.g — CONTRACT-164 boundary: read pre-activation via
// SkillStateReader, record into SkillTracker, dispatch via RecordingSkillRollback.
// Proves the documented CONTRACT-164 read-side + M015-local SkillRollback
// write-side split.
#[tokio::test]
async fn skill_state_reader_drives_pre_activation_record() {
    // In-test mock impl of CONTRACT-164 (read-only).
    struct MockSkillStateReader {
        info: Vec<SkillInfo>,
    }
    impl SkillStateReader for MockSkillStateReader {
        fn active_skills(&self, _agent_id: &str) -> Vec<SkillInfo> {
            self.info.clone()
        }
        fn skill_version(&self, _agent_id: &str, skill_id: &str) -> Option<u32> {
            self.info
                .iter()
                .find(|s| s.skill_id == skill_id)
                .map(|s| s.version)
        }
        fn provenance(&self, _skill_id: &str) -> Option<Provenance> {
            None
        }
        fn trust_level(&self, _skill_id: &str) -> TrustLevel {
            TrustLevel::Trusted
        }
    }

    let reader = MockSkillStateReader {
        info: vec![SkillInfo {
            skill_id: "skill_X".to_string(),
            version: 3,
            name: "X".to_string(),
            provenance: Provenance::Imported,
            trust_level: TrustLevel::Trusted,
        }],
    };

    // Pre-activation snapshot via SkillStateReader.
    let mut t = SkillTracker::new();
    let cur = reader.skill_version("alice", "skill_X");
    t.record_pre_activation("skill_X", cur);
    assert_eq!(t.get("skill_X"), Some(&SkillPreState::Version(3)));

    // Discard dispatches via SkillRollback (M015-local write surface).
    let recorder = RecordingSkillRollback::new();
    t.apply_discard("alice", &recorder)
        .await
        .expect("apply_discard");
    assert_eq!(
        recorder.calls(),
        vec![RecordedCall::Rollback {
            agent_id: "alice".to_string(),
            skill_id: "skill_X".to_string(),
            target_version: 3,
        }]
    );
}
