//! Slice A AC-04 integration tests (T29-T36).

use std::sync::{Arc, Barrier, Mutex};
use std::thread;

use advance_run_manager::{RunConfig, RunManager};
use advance_shared_types::capability::BudgetDecision;
use advance_shared_types::event::Event;
use advance_shared_types::run::{RoundDecision, RoundResult, RunError};
use advance_shared_types::traits::{EventBusEmit, RunBudget};

#[derive(Default)]
struct MockEventBus {
    events: Mutex<Vec<Event>>,
}

impl MockEventBus {
    fn new_arc() -> Arc<Self> {
        Arc::new(Self::default())
    }
}

impl EventBusEmit for MockEventBus {
    fn emit(&self, event: Event) {
        self.events.lock().unwrap().push(event);
    }
}

fn mgr_with_cfg(cfg: RunConfig) -> (RunManager, advance_run_manager::RunId) {
    let bus = MockEventBus::new_arc();
    let mgr = RunManager::new(bus as Arc<dyn EventBusEmit>);
    let id = mgr.ensure_run("task-1", "root", cfg).unwrap();
    (mgr, id)
}

/// T29 — AC-04 token deny + post-commit advance.
#[test]
fn t29_budget_deny_when_tokens_exceed_limit() {
    let (mgr, id) = mgr_with_cfg(RunConfig {
        token_limit: Some(1000),
        ..RunConfig::default()
    });
    let budget = mgr.budget();
    let rid = id.as_ref();

    assert!(matches!(budget.check(rid, 500, 0.0), BudgetDecision::Allow));
    assert!(matches!(
        budget.check(rid, 501, 0.0),
        BudgetDecision::Deny(_)
    ));
    budget.commit(rid, 500, 0.0);
    let snap = mgr.budget_state_snapshot(&id).unwrap();
    assert_eq!(snap.token_used, 500);
    assert_eq!(snap.token_reserved, 0);

    assert!(matches!(
        budget.check(rid, 600, 0.0),
        BudgetDecision::Deny(_)
    ));
    assert!(matches!(budget.check(rid, 500, 0.0), BudgetDecision::Allow));

    let snap = mgr.budget_state_snapshot(&id).unwrap();
    assert_eq!(snap.token_used, 500);
    assert_eq!(snap.token_reserved, 500);
}

/// T30 — AC-04 cost deny + invalid-cost rejection + post-commit advance.
#[test]
fn t30_budget_deny_cost_and_invalid_cost() {
    let (mgr, id) = mgr_with_cfg(RunConfig {
        cost_usd_limit: Some(10.0),
        ..RunConfig::default()
    });
    let budget = mgr.budget();
    let rid = id.as_ref();

    for bad in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY, -1.0] {
        assert!(
            matches!(budget.check(rid, 0, bad), BudgetDecision::Deny(_)),
            "bad cost {bad} must be Deny"
        );
    }
    assert!(matches!(budget.check(rid, 0, 0.5), BudgetDecision::Allow));
    let snap = mgr.budget_state_snapshot(&id).unwrap();
    assert_eq!(snap.cost_reserved, 0.5);

    budget.commit(rid, 0, 0.5);
    let snap = mgr.budget_state_snapshot(&id).unwrap();
    assert_eq!(snap.cost_usd, 0.5);
    assert_eq!(snap.cost_reserved, 0.0);

    assert!(matches!(budget.check(rid, 0, 9.6), BudgetDecision::Deny(_)));
}

/// T31 — AC-04 rounds gate + `>` vs `>=` asymmetry.
#[tokio::test]
async fn t31_budget_deny_rounds_with_asymmetry() {
    let (mgr, id) = mgr_with_cfg(RunConfig {
        rounds_limit: Some(3),
        ..RunConfig::default()
    });
    let budget = mgr.budget();
    let rid = id.as_ref();

    for i in 1..=3 {
        let dec = mgr
            .complete_round(
                &id,
                RoundResult {
                    summary: None,
                    metrics: vec![],
                },
            )
            .await
            .unwrap();
        assert!(matches!(dec, RoundDecision::ContinueAllowed), "round {i}");
        let snap = mgr.budget_state_snapshot(&id).unwrap();
        assert_eq!(snap.rounds_used, i, "rounds_used after round {i}");
        let run = mgr.snapshot_run_for_test(&id).unwrap();
        assert_eq!(run.iteration, i, "iteration after round {i}");
    }
    // Boundary: check() at rounds_used==limit returns Deny (`>=`).
    let dec = budget.check(rid, 0, 0.0);
    assert!(
        matches!(dec, BudgetDecision::Deny(reason) if reason == "budget-exceeded-rounds"),
        "check at rounds_used==limit must Deny"
    );

    let dec = mgr
        .complete_round(
            &id,
            RoundResult {
                summary: None,
                metrics: vec![],
            },
        )
        .await
        .unwrap();
    assert!(
        matches!(dec, RoundDecision::Blocked(reason) if reason == "rounds-exceeded"),
        "4th complete_round must Block (rounds_used>limit)"
    );
    let snap = mgr.budget_state_snapshot(&id).unwrap();
    assert_eq!(snap.rounds_used, 4);
    let run = mgr.snapshot_run_for_test(&id).unwrap();
    assert_eq!(run.iteration, 4);

    assert!(matches!(budget.check(rid, 0, 0.0), BudgetDecision::Deny(_)));
}

/// T32 — AC-04 saturating_add at the addition site.
#[test]
fn t32_budget_commit_overflow_saturates() {
    let (mgr, id) = mgr_with_cfg(RunConfig {
        token_limit: None,
        cost_usd_limit: None,
        rounds_limit: None,
        ..RunConfig::default()
    });
    let budget = mgr.budget();
    let rid = id.as_ref();

    assert!(matches!(
        budget.check(rid, u64::MAX, 0.0),
        BudgetDecision::Allow
    ));
    budget.commit(rid, u64::MAX, 0.0);
    let snap = mgr.budget_state_snapshot(&id).unwrap();
    assert_eq!(snap.token_used, u64::MAX);
    assert_eq!(snap.token_reserved, 0);

    // Now exercise the actual saturating_add at the addition site.
    assert!(matches!(budget.check(rid, 1, 0.0), BudgetDecision::Allow));
    budget.commit(rid, 1, 0.0);
    let snap = mgr.budget_state_snapshot(&id).unwrap();
    assert_eq!(snap.token_used, u64::MAX, "saturating_add at addition site");
    assert_eq!(snap.token_reserved, 0);
}

/// T33 — AC-04 invariant 5: identifier validation.
#[test]
fn t33_budget_rejects_invalid_run_id() {
    let (mgr, _id) = mgr_with_cfg(RunConfig::default());
    let budget = mgr.budget();

    let bads = [
        "",
        "../etc/passwd",
        "with\0null",
        "with\nnewline",
        "with space",
        "user:alice", // `:` not allowed for run_id
        "foo.bar",    // `.` not allowed
    ];
    for bad in bads {
        assert!(
            matches!(budget.check(bad, 1, 0.0), BudgetDecision::Deny(_)),
            "bad run_id {bad:?} must Deny"
        );
        // commit returns no value; silent no-op + eprintln (we just ensure no panic).
        budget.commit(bad, 1, 0.0);
    }
    let overlong = "a".repeat(65);
    assert!(matches!(
        budget.check(&overlong, 1, 0.0),
        BudgetDecision::Deny(_)
    ));
    assert!(matches!(
        budget.check("nonexistent-but-valid", 1, 0.0),
        BudgetDecision::Deny(reason) if reason == "budget-unknown-run"
    ));
}

/// T34 — AC-04 invariant 3: atomicity / no double-spend under concurrent
/// check calls. 16 threads, token_limit=600 ⇒ exactly 6 Allow / 10 Deny.
#[test]
fn t34_concurrent_check_no_double_spend() {
    let (mgr, id) = mgr_with_cfg(RunConfig {
        token_limit: Some(600),
        ..RunConfig::default()
    });
    let mgr = Arc::new(mgr);
    let rid_str: Arc<String> = Arc::new(id.as_ref().to_string());
    let n = 16usize;
    let barrier = Arc::new(Barrier::new(n));
    let allow_count = Arc::new(Mutex::new(0usize));
    let deny_count = Arc::new(Mutex::new(0usize));

    let mut handles = Vec::with_capacity(n);
    for _ in 0..n {
        let m = Arc::clone(&mgr);
        let rid = Arc::clone(&rid_str);
        let b = Arc::clone(&barrier);
        let a = Arc::clone(&allow_count);
        let d = Arc::clone(&deny_count);
        handles.push(thread::spawn(move || {
            let budget = m.budget();
            b.wait();
            match budget.check(rid.as_str(), 100, 0.0) {
                BudgetDecision::Allow => *a.lock().unwrap() += 1,
                BudgetDecision::Deny(_) => *d.lock().unwrap() += 1,
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
    assert_eq!(*allow_count.lock().unwrap(), 6);
    assert_eq!(*deny_count.lock().unwrap(), 10);
    let snap = mgr.budget_state_snapshot(&id).unwrap();
    assert_eq!(snap.token_reserved, 600);
    assert_eq!(snap.token_used, 0);
}

/// T34b — AC-04 check→commit settle cycle under contention.
#[test]
fn t34b_concurrent_check_with_commit_settles() {
    let (mgr, id) = mgr_with_cfg(RunConfig {
        token_limit: Some(600),
        ..RunConfig::default()
    });
    let mgr = Arc::new(mgr);
    let rid_str: Arc<String> = Arc::new(id.as_ref().to_string());
    let n = 16usize;
    let barrier = Arc::new(Barrier::new(n));
    let allow_count = Arc::new(Mutex::new(0usize));
    let commit_count = Arc::new(Mutex::new(0usize));

    let mut handles = Vec::with_capacity(n);
    for _ in 0..n {
        let m = Arc::clone(&mgr);
        let rid = Arc::clone(&rid_str);
        let b = Arc::clone(&barrier);
        let a = Arc::clone(&allow_count);
        let c = Arc::clone(&commit_count);
        handles.push(thread::spawn(move || {
            let budget = m.budget();
            b.wait();
            match budget.check(rid.as_str(), 100, 0.0) {
                BudgetDecision::Allow => {
                    *a.lock().unwrap() += 1;
                    budget.commit(rid.as_str(), 100, 0.0);
                    *c.lock().unwrap() += 1;
                }
                BudgetDecision::Deny(_) => {}
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
    assert_eq!(*allow_count.lock().unwrap(), 6);
    assert_eq!(*commit_count.lock().unwrap(), 6);
    let snap = mgr.budget_state_snapshot(&id).unwrap();
    assert_eq!(snap.token_used, 600);
    assert_eq!(snap.token_reserved, 0);
}

/// T35a — AC-04 clamp-on-commit (over-commit).
#[test]
fn t35a_commit_clamps_excess_tokens_to_reservation() {
    let (mgr, id) = mgr_with_cfg(RunConfig {
        token_limit: Some(1000),
        ..RunConfig::default()
    });
    let budget = mgr.budget();
    let rid = id.as_ref();

    assert!(matches!(budget.check(rid, 500, 0.0), BudgetDecision::Allow));
    budget.commit(rid, 900, 0.0); // clamp to min(900, 500) = 500
    let snap = mgr.budget_state_snapshot(&id).unwrap();
    assert_eq!(snap.token_used, 500);
    assert_eq!(snap.token_reserved, 0);

    assert!(matches!(
        budget.check(rid, 600, 0.0),
        BudgetDecision::Deny(_)
    ));
}

/// T35b — AC-04 under-commit reservation leak.
#[test]
fn t35b_commit_under_reservation_leaks() {
    let (mgr, id) = mgr_with_cfg(RunConfig {
        token_limit: Some(1000),
        ..RunConfig::default()
    });
    let budget = mgr.budget();
    let rid = id.as_ref();

    assert!(matches!(budget.check(rid, 800, 0.0), BudgetDecision::Allow));
    budget.commit(rid, 200, 0.0); // clamp to min(200, 800) = 200
    let snap = mgr.budget_state_snapshot(&id).unwrap();
    assert_eq!(snap.token_used, 200);
    assert_eq!(snap.token_reserved, 600);

    assert!(matches!(
        budget.check(rid, 201, 0.0),
        BudgetDecision::Deny(_)
    ));
    // At-limit boundary Allow: 200+600+200 = 1000 ≤ 1000.
    assert!(matches!(budget.check(rid, 200, 0.0), BudgetDecision::Allow));
    assert!(matches!(
        budget.check(rid, 0, -1.0),
        BudgetDecision::Deny(reason) if reason == "budget-invalid-cost"
    ));
}

/// T36 — AC-04 invariant 1 (commit side): NaN/negative cost silently dropped.
#[test]
fn t36_commit_invalid_inputs_dropped() {
    let (mgr, id) = mgr_with_cfg(RunConfig::default());
    let budget = mgr.budget();
    let rid = id.as_ref();
    // Reserve some headroom first.
    assert!(matches!(budget.check(rid, 1, 0.0), BudgetDecision::Allow));
    let before = mgr.budget_state_snapshot(&id).unwrap();
    budget.commit(rid, 1, f64::NAN);
    budget.commit(rid, 1, -1.0);
    budget.commit(rid, 1, f64::INFINITY);
    let after = mgr.budget_state_snapshot(&id).unwrap();
    assert_eq!(before.token_used, after.token_used);
    assert_eq!(before.cost_usd, after.cost_usd);
}

// Silence unused-import warnings if compiler doesn't reach them.
#[allow(dead_code)]
fn _unused(_e: RunError) {}
