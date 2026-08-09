//! Serde + wire-format tests for `advance_shared_types::run`.

use advance_shared_types::run::{
    MetricSample, RoundDecision, RoundResult, RunError, TaskRunStatus,
};

#[test]
fn metric_sample_round_trip() {
    let m = MetricSample {
        name: "tokens".to_string(),
        value: "1234".to_string(),
    };
    let json = serde_json::to_string(&m).unwrap();
    let back: MetricSample = serde_json::from_str(&json).unwrap();
    assert_eq!(back, m);
}

#[test]
fn metric_sample_deny_unknown_fields() {
    let bad = r#"{"name":"x","value":"y","extra":true}"#;
    let err = serde_json::from_str::<MetricSample>(bad).unwrap_err();
    assert_eq!(err.classify(), serde_json::error::Category::Data);
}

#[test]
fn round_result_round_trip() {
    let r = RoundResult {
        summary: Some("ok".to_string()),
        metrics: vec![MetricSample {
            name: "n".to_string(),
            value: "v".to_string(),
        }],
    };
    let json = serde_json::to_string(&r).unwrap();
    let back: RoundResult = serde_json::from_str(&json).unwrap();
    assert_eq!(back, r);
}

#[test]
fn round_decision_round_trip() {
    for d in [
        RoundDecision::ContinueAllowed,
        RoundDecision::Blocked("budget".to_string()),
    ] {
        let json = serde_json::to_string(&d).unwrap();
        let back: RoundDecision = serde_json::from_str(&json).unwrap();
        assert_eq!(back, d);
    }
}

#[test]
fn run_error_round_trip() {
    for e in [
        RunError::NotFound("x".to_string()),
        RunError::AlreadyExists("x".to_string()),
        RunError::InvalidState("x".to_string()),
        RunError::BudgetExceeded("x".to_string()),
        RunError::PermissionDenied("x".to_string()),
    ] {
        let json = serde_json::to_string(&e).unwrap();
        let back: RunError = serde_json::from_str(&json).unwrap();
        assert_eq!(back, e);
    }
}

#[test]
fn task_run_status_round_trip() {
    for s in [
        TaskRunStatus::Active,
        TaskRunStatus::Suspended,
        TaskRunStatus::Paused,
        TaskRunStatus::Completed,
        TaskRunStatus::Failed("oom".to_string()),
        TaskRunStatus::Cancelled("user".to_string()),
    ] {
        let json = serde_json::to_string(&s).unwrap();
        let back: TaskRunStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(back, s);
    }
}
