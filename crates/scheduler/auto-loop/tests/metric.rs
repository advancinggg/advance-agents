//! AC-06 + AC-07 role × source matrix tests + AC-06 negative test
//! (`event_metric_source_as_primary_rejected`) for the new
//! `validate_role_source` admission-time check.
//!
//! Matrix coverage (9 cells per role × source) — see MODULE-015 §3.8 note 5
//! for the permissive PRD §4.7.4-vs-§4.7.9 resolution.

use advance_scheduler_auto_loop::{
    validate_role_source, validate_role_source_matrix, AutoLoopError, FailFastMetric,
    MetricRoleSourceError, MetricSource, Objective, Op, Predicate, Role, SuccessCriteria,
};

fn file_source() -> MetricSource {
    MetricSource::File {
        path: "metrics/x.json".to_string(),
        key: "y".to_string(),
    }
}

fn event_source_high_fanout_with_filter() -> MetricSource {
    MetricSource::Event {
        event_type: "component.error".to_string(),
        payload_key: None,
        filter: Some(serde_json::json!({"id": "evaluator-bpb"})),
    }
}

fn event_source_high_fanout_no_filter() -> MetricSource {
    MetricSource::Event {
        event_type: "component.error".to_string(),
        payload_key: None,
        filter: None,
    }
}

fn event_source_low_fanout() -> MetricSource {
    MetricSource::Event {
        event_type: "auto.iteration_completed".to_string(),
        payload_key: None,
        filter: None,
    }
}

fn component_source() -> MetricSource {
    MetricSource::Component {
        output_key: "score".to_string(),
    }
}

// ─── 9-cell matrix ────────────────────────────────────────────────────

#[test]
fn a_primary_file_ok() {
    assert_eq!(validate_role_source(Role::Primary, &file_source()), Ok(()));
}

#[test]
fn b_primary_component_ok() {
    assert_eq!(
        validate_role_source(Role::Primary, &component_source()),
        Ok(())
    );
}

#[test]
fn c_primary_event_rejected() {
    assert_eq!(
        validate_role_source(Role::Primary, &event_source_low_fanout()),
        Err(MetricRoleSourceError::EventNotAllowedAsPrimary)
    );
}

#[test]
fn d_guardrail_event_with_filter_ok() {
    assert_eq!(
        validate_role_source(Role::Guardrail, &event_source_high_fanout_with_filter()),
        Ok(())
    );
}

#[test]
fn e_failfast_event_with_filter_ok() {
    assert_eq!(
        validate_role_source(Role::FailFast, &event_source_high_fanout_with_filter()),
        Ok(())
    );
}

#[test]
fn f_guardrail_file_ok() {
    assert_eq!(
        validate_role_source(Role::Guardrail, &file_source()),
        Ok(())
    );
}

// AC-07 high-fanout rule

#[test]
fn g_failfast_file_ok_per_prd_4_7_9() {
    // PRD §4.7.9 explicitly shows fail_fast with type: file. Slice-B
    // resolves the §4.7.4 vs §4.7.9 ambiguity permissively — see
    // MODULE-015 §3.8 note 5.
    assert_eq!(validate_role_source(Role::FailFast, &file_source()), Ok(()));
}

#[test]
fn h_failfast_component_ok_per_permissive_matrix() {
    // Same permissive resolution as test (g).
    assert_eq!(
        validate_role_source(Role::FailFast, &component_source()),
        Ok(())
    );
}

#[test]
fn i_guardrail_high_fanout_event_without_filter_rejected() {
    // AC-07: component.error / component.finished require non-None filter.
    let result = validate_role_source(Role::Guardrail, &event_source_high_fanout_no_filter());
    match result {
        Err(MetricRoleSourceError::FilterRequiredForHighFanout(t)) => {
            assert_eq!(t, "component.error");
        }
        other => panic!("expected FilterRequiredForHighFanout, got {other:?}"),
    }
}

#[test]
fn i_failfast_high_fanout_event_without_filter_rejected() {
    let result = validate_role_source(Role::FailFast, &event_source_high_fanout_no_filter());
    assert!(matches!(
        result,
        Err(MetricRoleSourceError::FilterRequiredForHighFanout(_))
    ));
}

#[test]
fn i_low_fanout_event_without_filter_ok() {
    // Non-high-fanout event_types don't require a filter.
    assert_eq!(
        validate_role_source(Role::Guardrail, &event_source_low_fanout()),
        Ok(())
    );
}

// ─── End-to-end via SuccessCriteria::validate() ────────────────────────

#[test]
fn k_valid_matrix_via_validate() {
    // Primary+File + Guardrail+Event(filter) — all legal.
    let sc = SuccessCriteria {
        evaluator: None,
        objectives: vec![
            Objective {
                name: "val-bpb".to_string(),
                role: Role::Primary,
                metric_source: file_source(),
                predicate: Predicate {
                    op: Op::Lt,
                    threshold: None,
                },
            },
            Objective {
                name: "code-quality".to_string(),
                role: Role::Guardrail,
                metric_source: event_source_high_fanout_with_filter(),
                predicate: Predicate {
                    op: Op::Gt,
                    threshold: Some(0.8),
                },
            },
        ],
        per_iteration_budget: None,
        fail_fast: None,
        safety_valve: None,
    };
    assert!(sc.validate().is_ok());
}

#[test]
fn l_event_metric_source_as_primary_rejected_via_validate() {
    // New AC-06 negative coverage test.
    let sc = SuccessCriteria {
        evaluator: None,
        objectives: vec![Objective {
            name: "bad".to_string(),
            role: Role::Primary,
            metric_source: event_source_high_fanout_with_filter(),
            predicate: Predicate {
                op: Op::Lt,
                threshold: None,
            },
        }],
        per_iteration_budget: None,
        fail_fast: None,
        safety_valve: None,
    };
    let err = sc.validate().unwrap_err();
    match err {
        AutoLoopError::RoleSource(MetricRoleSourceError::EventNotAllowedAsPrimary) => {}
        other => panic!("expected RoleSource(EventNotAllowedAsPrimary), got {other:?}"),
    }
}

#[test]
fn l_fail_fast_high_fanout_without_filter_rejected_via_validate() {
    // fail_fast metrics are validated with implicit Role::FailFast in the
    // matrix walker.
    let sc = SuccessCriteria {
        evaluator: None,
        objectives: vec![Objective {
            name: "val-bpb".to_string(),
            role: Role::Primary,
            metric_source: file_source(),
            predicate: Predicate {
                op: Op::Lt,
                threshold: None,
            },
        }],
        per_iteration_budget: None,
        fail_fast: Some(vec![FailFastMetric {
            metric_source: event_source_high_fanout_no_filter(),
            predicate: None,
        }]),
        safety_valve: None,
    };
    let err = sc.validate().unwrap_err();
    match err {
        AutoLoopError::RoleSource(MetricRoleSourceError::FilterRequiredForHighFanout(_)) => {}
        other => panic!("expected RoleSource(FilterRequiredForHighFanout), got {other:?}"),
    }
}

#[test]
fn matrix_validator_handles_empty_fail_fast() {
    let sc = SuccessCriteria {
        evaluator: None,
        objectives: vec![Objective {
            name: "val-bpb".to_string(),
            role: Role::Primary,
            metric_source: file_source(),
            predicate: Predicate {
                op: Op::Lt,
                threshold: None,
            },
        }],
        per_iteration_budget: None,
        fail_fast: None,
        safety_valve: None,
    };
    assert!(validate_role_source_matrix(&sc).is_ok());
}
