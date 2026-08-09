//! Slice C AC-16 tests (T77–T80b): CostTrackerQuery integration with
//! `max(local, tracker)` fail-safe.

use std::sync::{Arc, Mutex};

use advance_run_manager::{RunConfig, RunManager};
use advance_shared_types::capability::BudgetDecision;
use advance_shared_types::cost::RunCost;
use advance_shared_types::event::Event;
use advance_shared_types::traits::{CostTrackerQuery, EventBusEmit, RunBudget};

#[derive(Default)]
struct MockBus {
    events: Mutex<Vec<Event>>,
}

impl EventBusEmit for MockBus {
    fn emit(&self, event: Event) {
        self.events.lock().unwrap().push(event);
    }
}

struct MockCostTracker {
    return_value: Option<RunCost>,
}

impl CostTrackerQuery for MockCostTracker {
    fn query_run(&self, _run_id: &str) -> Option<RunCost> {
        self.return_value.clone()
    }
    fn query_iteration(&self, _run_id: &str, _iteration: u32) -> Option<RunCost> {
        None
    }
}

fn mgr_with_tracker(tracker: Option<Arc<dyn CostTrackerQuery>>) -> Arc<RunManager> {
    let bus: Arc<dyn EventBusEmit> = Arc::new(MockBus::default());
    let mut mgr = RunManager::new(bus);
    if let Some(t) = tracker {
        mgr = mgr.with_cost_tracker(t);
    }
    Arc::new(mgr)
}

fn rc(cost_usd: f64) -> RunCost {
    RunCost {
        tokens_in: 0,
        tokens_out: 0,
        cost_usd,
        request_count: 0,
    }
}

/// T77 — tracker returns cost_usd=8.0; check(0, 0) under limit=10 → Allow.
#[test]
fn t77_tracker_8_below_limit_allows() {
    let mock: Arc<dyn CostTrackerQuery> = Arc::new(MockCostTracker {
        return_value: Some(rc(8.0)),
    });
    let mgr = mgr_with_tracker(Some(mock));
    let id = mgr
        .ensure_run(
            "task-1",
            "root",
            RunConfig {
                cost_usd_limit: Some(10.0),
                ..RunConfig::default()
            },
        )
        .unwrap();
    let budget = mgr.budget();
    assert!(matches!(
        budget.check(id.as_ref(), 0, 0.0),
        BudgetDecision::Allow
    ));
}

/// T78 — tracker=8.0; check(0, 3.0) under limit=10 → Deny (8+0+3>10).
#[test]
fn t78_tracker_8_plus_3_exceeds_denies() {
    let mock: Arc<dyn CostTrackerQuery> = Arc::new(MockCostTracker {
        return_value: Some(rc(8.0)),
    });
    let mgr = mgr_with_tracker(Some(mock));
    let id = mgr
        .ensure_run(
            "task-1",
            "root",
            RunConfig {
                cost_usd_limit: Some(10.0),
                ..RunConfig::default()
            },
        )
        .unwrap();
    let budget = mgr.budget();
    assert!(matches!(
        budget.check(id.as_ref(), 0, 3.0),
        BudgetDecision::Deny(_)
    ));
}

/// T79 — tracker returns None (no entry yet); check(0, 0.5) under limit=10 →
/// Allow (falls back to local cost_usd=0.0).
#[test]
fn t79_tracker_none_fallback_to_local() {
    let mock: Arc<dyn CostTrackerQuery> = Arc::new(MockCostTracker { return_value: None });
    let mgr = mgr_with_tracker(Some(mock));
    let id = mgr
        .ensure_run(
            "task-1",
            "root",
            RunConfig {
                cost_usd_limit: Some(10.0),
                ..RunConfig::default()
            },
        )
        .unwrap();
    let budget = mgr.budget();
    assert!(matches!(
        budget.check(id.as_ref(), 0, 0.5),
        BudgetDecision::Allow
    ));
}

/// T79b — local cost_usd=7.0 + tracker reports 2.0 (lagging); check(0, 4.0)
/// → Deny (max(7,2)+0+4=11 > 10). Proves fail-safe `max(local, tracker)`.
#[test]
fn t79b_lagging_tracker_uses_local() {
    let mock: Arc<dyn CostTrackerQuery> = Arc::new(MockCostTracker {
        return_value: Some(rc(2.0)),
    });
    let mgr = mgr_with_tracker(Some(mock));
    let id = mgr
        .ensure_run(
            "task-1",
            "root",
            RunConfig {
                cost_usd_limit: Some(10.0),
                ..RunConfig::default()
            },
        )
        .unwrap();
    let budget = mgr.budget();
    // First, drive local cost_usd to 7.0 via check+commit cycle.
    assert!(matches!(
        budget.check(id.as_ref(), 0, 7.0),
        BudgetDecision::Allow
    ));
    budget.commit(id.as_ref(), 0, 7.0);
    // Now check(0, 4.0) — tracker reports 2.0 (lagging), local is 7.0.
    // max(7,2)+0+4 = 11 > 10 → Deny.
    assert!(matches!(
        budget.check(id.as_ref(), 0, 4.0),
        BudgetDecision::Deny(_)
    ));
}

/// T80 — no with_cost_tracker call → Slice A behavior intact.
#[test]
fn t80_no_tracker_slice_a_behavior() {
    let mgr = mgr_with_tracker(None);
    let id = mgr
        .ensure_run(
            "task-1",
            "root",
            RunConfig {
                cost_usd_limit: Some(10.0),
                ..RunConfig::default()
            },
        )
        .unwrap();
    let budget = mgr.budget();
    // No tracker → local cost_usd=0; check(0, 5.0) → Allow.
    assert!(matches!(
        budget.check(id.as_ref(), 0, 5.0),
        BudgetDecision::Allow
    ));
    budget.commit(id.as_ref(), 0, 5.0);
    // Local now 5.0; check(0, 6.0) → Deny.
    assert!(matches!(
        budget.check(id.as_ref(), 0, 6.0),
        BudgetDecision::Deny(_)
    ));
}

/// T80b — tracker reports 15.0 (ahead of local 0.0); check(0, 0.5) → Deny
/// (15+0+0.5 > 10). Proves the tracker-ahead path uses tracker.
#[test]
fn t80b_tracker_ahead_uses_tracker() {
    let mock: Arc<dyn CostTrackerQuery> = Arc::new(MockCostTracker {
        return_value: Some(rc(15.0)),
    });
    let mgr = mgr_with_tracker(Some(mock));
    let id = mgr
        .ensure_run(
            "task-1",
            "root",
            RunConfig {
                cost_usd_limit: Some(10.0),
                ..RunConfig::default()
            },
        )
        .unwrap();
    let budget = mgr.budget();
    assert!(matches!(
        budget.check(id.as_ref(), 0, 0.5),
        BudgetDecision::Deny(_)
    ));
}
