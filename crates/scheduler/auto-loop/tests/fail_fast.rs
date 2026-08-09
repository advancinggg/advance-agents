//! Foundation tests for fail-fast monitor primitive (AC-14 verification
//! deferred to integrated-loop slice).

use advance_scheduler_auto_loop::{
    predicate_breached, DefaultFailFastMonitor, EvaluatedMetric, FailFastMetric, FailFastMonitor,
    FailFastOutcome, MetricSource, Op, Predicate,
};

fn file_metric() -> FailFastMetric {
    FailFastMetric {
        metric_source: MetricSource::File {
            path: "metrics/live.json".to_string(),
            key: "loss".to_string(),
        },
        predicate: Some(Predicate {
            op: Op::Gt,
            threshold: Some(100.0),
        }),
    }
}

fn presence_event_metric() -> FailFastMetric {
    FailFastMetric {
        metric_source: MetricSource::Event {
            event_type: "component.error".to_string(),
            payload_key: None,
            filter: Some(serde_json::json!({"id": "training-runner"})),
        },
        // None = presence-based per PRD §4.7.9
        predicate: None,
    }
}

// ─── Default monitor (no readers configured) returns Pass ───────────────

#[test]
fn a_default_monitor_empty_list_pass() {
    let outcome = DefaultFailFastMonitor.check_iteration(&[]);
    assert_eq!(outcome, FailFastOutcome::Pass);
}

// ─── check_with_readings: threshold semantics ────────────────────────────

#[test]
fn b_threshold_breach_triggers() {
    let metrics = vec![file_metric()];
    let readings = vec![EvaluatedMetric::Value(150.0)];
    match DefaultFailFastMonitor::check_with_readings(&metrics, &readings) {
        FailFastOutcome::Trigger { reason } => {
            assert!(reason.contains("fail-fast"));
            assert!(reason.contains("150"));
        }
        other => panic!("expected Trigger, got {other:?}"),
    }
}

#[test]
fn c_threshold_within_bound_passes() {
    let metrics = vec![file_metric()];
    let readings = vec![EvaluatedMetric::Value(50.0)];
    assert_eq!(
        DefaultFailFastMonitor::check_with_readings(&metrics, &readings),
        FailFastOutcome::Pass
    );
}

// ─── Presence-based semantics ────────────────────────────────────────────

#[test]
fn d_presence_event_present_triggers() {
    let metrics = vec![presence_event_metric()];
    let readings = vec![EvaluatedMetric::Present(true)];
    match DefaultFailFastMonitor::check_with_readings(&metrics, &readings) {
        FailFastOutcome::Trigger { reason } => {
            assert!(reason.contains("presence-based"));
        }
        other => panic!("expected Trigger, got {other:?}"),
    }
}

#[test]
fn e_presence_event_absent_passes() {
    let metrics = vec![presence_event_metric()];
    let readings = vec![EvaluatedMetric::Present(false)];
    assert_eq!(
        DefaultFailFastMonitor::check_with_readings(&metrics, &readings),
        FailFastOutcome::Pass
    );
}

// ─── Short-circuit semantics ─────────────────────────────────────────────

#[test]
fn f_short_circuits_on_first_trigger() {
    // First metric triggers; second metric's "Value(0.0)" would also
    // not exceed threshold, but we never get there. The reason string
    // points to the FIRST metric (index 0).
    let metrics = vec![file_metric(), file_metric()];
    let readings = vec![EvaluatedMetric::Value(200.0), EvaluatedMetric::Value(50.0)];
    match DefaultFailFastMonitor::check_with_readings(&metrics, &readings) {
        FailFastOutcome::Trigger { reason } => {
            assert!(reason.contains("index 0"), "{reason}");
        }
        other => panic!("expected Trigger from first metric, got {other:?}"),
    }
}

#[test]
fn g_all_pass_returns_pass() {
    let metrics = vec![file_metric(), file_metric()];
    let readings = vec![EvaluatedMetric::Value(50.0), EvaluatedMetric::Value(20.0)];
    assert_eq!(
        DefaultFailFastMonitor::check_with_readings(&metrics, &readings),
        FailFastOutcome::Pass
    );
}

// ─── predicate_breached pure-function semantics ─────────────────────────

#[test]
fn predicate_breached_gt() {
    let pred = Predicate {
        op: Op::Gt,
        threshold: Some(10.0),
    };
    assert!(predicate_breached(&pred, 11.0));
    assert!(!predicate_breached(&pred, 10.0));
}

#[test]
fn predicate_breached_lt() {
    let pred = Predicate {
        op: Op::Lt,
        threshold: Some(10.0),
    };
    assert!(predicate_breached(&pred, 5.0));
    assert!(!predicate_breached(&pred, 10.0));
}

#[test]
fn predicate_no_threshold_returns_false() {
    // No threshold → "compare against previous_best" (integrated-loop's
    // job, not standalone breach). predicate_breached returns false.
    let pred = Predicate {
        op: Op::Lt,
        threshold: None,
    };
    assert!(!predicate_breached(&pred, 5.0));
}
