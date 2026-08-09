//! T-S-B-Unit aggregation tests for CostTracker (MODULE-019 §1.3.4 impl).
//!
//! Covers in-scope AC-07 (REQ-075) per the Slice B plan T29..T33.

use std::sync::Arc;

use advance_cost_tracker::CostTracker;
use advance_shared_types::chrono::Utc;
use advance_shared_types::cost::RunCost;
use advance_shared_types::event::Event;
use advance_shared_types::traits::CostTrackerQuery;
use serde_json::json;

fn llm_response_event(run_id: &str, payload: serde_json::Value) -> Event {
    Event {
        id: "evt-1".into(),
        timestamp: Utc::now(),
        agent_id: "agent-a".into(),
        task_id: None,
        run_id: Some(run_id.into()),
        execution_id: None,
        trace_id: "tr-1".into(),
        span_id: "s-1".into(),
        parent_span_id: None,
        event_type: "llm.response".into(),
        payload,
        duration_ms: None,
    }
}

/// MODULE-019-T29 — sum aggregation for query_run.
#[test]
fn t29_query_run_sum_aggregation() {
    let tracker = CostTracker::new();
    let payload = json!({
        "input_tokens": 100u64,
        "output_tokens": 50u64,
        "cost_usd": 0.01,
        "iteration": 0u64
    });
    tracker.observe(&llm_response_event("run-1", payload.clone()));
    tracker.observe(&llm_response_event("run-1", payload));

    let cost = tracker.query_run("run-1").expect("run-1 should be tracked");
    assert_eq!(cost.tokens_in, 200);
    assert_eq!(cost.tokens_out, 100);
    assert!((cost.cost_usd - 0.02).abs() < 1e-12);
    assert_eq!(cost.request_count, 2);
}

/// MODULE-019-T30 — per-iteration partition.
#[test]
fn t30_query_iteration_partition() {
    let tracker = CostTracker::new();
    let mk = |iter: u64| {
        json!({
            "input_tokens": 100u64,
            "output_tokens": 50u64,
            "cost_usd": 0.01,
            "iteration": iter
        })
    };
    tracker.observe(&llm_response_event("run-1", mk(0)));
    tracker.observe(&llm_response_event("run-1", mk(1)));

    let it0 = tracker
        .query_iteration("run-1", 0)
        .expect("iter 0 should be tracked");
    let it1 = tracker
        .query_iteration("run-1", 1)
        .expect("iter 1 should be tracked");

    assert_eq!(it0.request_count, 1);
    assert_eq!(it1.request_count, 1);
    assert_eq!(it0.tokens_in, 100);
    assert_eq!(it1.tokens_in, 100);
}

/// MODULE-019-T31 — non-llm.response events ignored.
#[test]
fn t31_non_llm_response_ignored() {
    let tracker = CostTracker::new();
    let mut event = llm_response_event(
        "run-1",
        json!({
            "input_tokens": 100u64,
            "output_tokens": 50u64,
            "cost_usd": 0.01,
        }),
    );
    event.event_type = "fs.write".into();
    tracker.observe(&event);

    assert!(tracker.query_run("run-1").is_none());
}

/// MODULE-019-T32 — missing iteration field defaults to 0.
#[test]
fn t32_missing_iteration_defaults_to_0() {
    let tracker = CostTracker::new();
    let payload = json!({
        "input_tokens": 100u64,
        "output_tokens": 50u64,
        "cost_usd": 0.01,
        // no `iteration` field
    });
    tracker.observe(&llm_response_event("run-1", payload));

    let it0 = tracker
        .query_iteration("run-1", 0)
        .expect("iter 0 (default) should be tracked");
    assert_eq!(it0.request_count, 1);
    assert_eq!(it0.tokens_in, 100);
}

/// MODULE-019-T33 — Arc<dyn CostTrackerQuery> dyn-construction + dispatch.
#[test]
fn t33_dyn_construction() {
    let tracker = Arc::new(CostTracker::new());
    let payload = json!({
        "input_tokens": 100u64,
        "output_tokens": 50u64,
        "cost_usd": 0.01,
    });
    tracker.observe(&llm_response_event("run-1", payload));

    let dyn_q: Arc<dyn CostTrackerQuery> = tracker.clone();
    let cost = dyn_q.query_run("run-1").expect("dyn dispatch should work");
    assert_eq!(cost.request_count, 1);
}

/// MODULE-019-T07b / CONTRACT-216: no-run and explicit-empty events remain
/// global EventBus data but never enter the per-run budget folds.
#[test]
fn t07b_missing_or_empty_run_id_never_creates_empty_bucket() {
    let tracker = CostTracker::new();
    let mut event = llm_response_event(
        "ignored",
        json!({
            "input_tokens": 100u64,
            "output_tokens": 50u64,
            "cost_usd": 0.01,
        }),
    );
    event.run_id = None;
    tracker.observe(&event);
    event.run_id = Some(String::new());
    tracker.observe(&event);

    assert!(tracker.query_run("").is_none());
    assert!(tracker.query_iteration("", 0).is_none());

    event.run_id = Some("run-real".into());
    tracker.observe(&event);

    let cost = tracker
        .query_run("run-real")
        .expect("genuine non-empty run should aggregate");
    assert_eq!(cost.request_count, 1);
    assert_eq!(
        tracker
            .query_iteration("run-real", 0)
            .expect("genuine iteration should aggregate")
            .request_count,
        1
    );
}

/// MODULE-019 — RunCost::default returns zeroes (DoS guard for missing-key path).
#[test]
fn t_run_cost_default_is_zeroes() {
    let zero = RunCost::default();
    assert_eq!(zero.tokens_in, 0);
    assert_eq!(zero.tokens_out, 0);
    assert_eq!(zero.cost_usd, 0.0);
    assert_eq!(zero.request_count, 0);
}
