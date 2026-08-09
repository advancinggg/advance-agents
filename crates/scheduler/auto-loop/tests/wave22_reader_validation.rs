//! Wave-22 (autoloop-integ) auto-loop-crate unit witnesses:
//! - UT-1: `DefaultFileMetricReader` (real path-confined File metric reader).
//! - UT-3: Component-source `fail_fast` admission validation.
//!
//! These are the MODULE-015-side units for the AC-14 (REQ-078) File-source
//! reader + admission tightening. The cli-side integrated crash-path witnesses
//! (IT-1/IT-2a/IT-2b/IT-3, UT-2/UT-4) live in
//! `crates/cli/tests/auto_loop_integrated_witness.rs`.

use advance_scheduler_auto_loop::config::{
    MetricSource, Objective, Op, Predicate, Role, SuccessCriteria,
};
use advance_scheduler_auto_loop::{
    AutoLoopError, DefaultFileMetricReader, FailFastMetric, FileMetricReader, MetricReadError,
};
use std::fs;

// ─────────────────────────── UT-1: DefaultFileMetricReader ───────────────────

#[test]
fn ut1_reads_in_bounds_json_value() {
    let ws = tempfile::tempdir().unwrap();
    fs::write(ws.path().join("m.json"), br#"{"loss": 0.42, "acc": 0.9}"#).unwrap();
    let r = DefaultFileMetricReader::new(ws.path());
    assert_eq!(r.read_file_metric("m.json", "loss").unwrap(), 0.42);
    assert_eq!(r.read_file_metric("m.json", "acc").unwrap(), 0.9);
}

#[test]
fn ut1_reads_in_bounds_nested_subdir() {
    let ws = tempfile::tempdir().unwrap();
    fs::create_dir_all(ws.path().join("a/b")).unwrap();
    fs::write(ws.path().join("a/b/m.json"), br#"{"x": 3.5}"#).unwrap();
    let r = DefaultFileMetricReader::new(ws.path());
    assert_eq!(r.read_file_metric("a/b/m.json", "x").unwrap(), 3.5);
    // `./`-prefixed relative path stays in-bounds.
    assert_eq!(r.read_file_metric("./a/b/m.json", "x").unwrap(), 3.5);
}

#[test]
fn ut1_in_bounds_absent_is_not_found() {
    let ws = tempfile::tempdir().unwrap();
    let r = DefaultFileMetricReader::new(ws.path());
    match r.read_file_metric("nope.json", "x") {
        Err(MetricReadError::NotFound(m)) => assert!(m.contains("not found"), "{m}"),
        other => panic!("expected NotFound, got {other:?}"),
    }
}

#[test]
fn ut1_missing_key_is_not_found() {
    let ws = tempfile::tempdir().unwrap();
    fs::write(ws.path().join("m.json"), br#"{"loss": 0.1}"#).unwrap();
    let r = DefaultFileMetricReader::new(ws.path());
    match r.read_file_metric("m.json", "absent") {
        Err(MetricReadError::NotFound(m)) => assert!(m.contains("key not found"), "{m}"),
        other => panic!("expected NotFound(key), got {other:?}"),
    }
}

#[test]
fn ut1_non_numeric_key_is_parse() {
    let ws = tempfile::tempdir().unwrap();
    fs::write(ws.path().join("m.json"), br#"{"loss": "high"}"#).unwrap();
    let r = DefaultFileMetricReader::new(ws.path());
    match r.read_file_metric("m.json", "loss") {
        Err(MetricReadError::Parse(m)) => assert!(m.contains("not a number"), "{m}"),
        other => panic!("expected Parse, got {other:?}"),
    }
}

#[test]
fn ut1_unparseable_file_is_parse() {
    let ws = tempfile::tempdir().unwrap();
    fs::write(ws.path().join("m.json"), b"this is : not : valid : json{{").unwrap();
    let r = DefaultFileMetricReader::new(ws.path());
    match r.read_file_metric("m.json", "loss") {
        Err(MetricReadError::Parse(_)) => {}
        other => panic!("expected Parse, got {other:?}"),
    }
}

#[test]
fn ut1_absolute_path_rejected_lexically() {
    let ws = tempfile::tempdir().unwrap();
    let r = DefaultFileMetricReader::new(ws.path());
    // Absolute path never touches the FS — rejected as NotFound(escape).
    match r.read_file_metric("/etc/passwd", "x") {
        Err(MetricReadError::NotFound(m)) => assert!(m.contains("absolute"), "{m}"),
        other => panic!("expected NotFound(absolute), got {other:?}"),
    }
}

#[test]
fn ut1_parent_traversal_rejected_lexically() {
    let ws = tempfile::tempdir().unwrap();
    // Even if a target exists above the workspace, the `..` is rejected lexically
    // BEFORE any FS access.
    let outside = tempfile::tempdir().unwrap();
    fs::write(outside.path().join("secret.json"), br#"{"x": 1.0}"#).unwrap();
    let r = DefaultFileMetricReader::new(ws.path());
    match r.read_file_metric("../secret.json", "x") {
        Err(MetricReadError::NotFound(m)) => assert!(m.contains("traversal"), "{m}"),
        other => panic!("expected NotFound(traversal), got {other:?}"),
    }
    match r.read_file_metric("a/../../secret.json", "x") {
        Err(MetricReadError::NotFound(m)) => assert!(m.contains("traversal"), "{m}"),
        other => panic!("expected NotFound(traversal), got {other:?}"),
    }
}

#[cfg(unix)]
#[test]
fn ut1_symlink_escape_rejected_before_read() {
    let ws = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    fs::write(outside.path().join("secret.json"), br#"{"x": 9.9}"#).unwrap();
    // A symlink INSIDE the workspace whose target is OUTSIDE. `exists()` follows
    // it (target exists), so the reader must canonicalize + reject BEFORE reading.
    std::os::unix::fs::symlink(
        outside.path().join("secret.json"),
        ws.path().join("link.json"),
    )
    .unwrap();
    let r = DefaultFileMetricReader::new(ws.path());
    match r.read_file_metric("link.json", "x") {
        Err(MetricReadError::NotFound(m)) => assert!(m.contains("symlink"), "{m}"),
        other => panic!("expected NotFound(symlink escape), got {other:?}"),
    }
}

#[cfg(unix)]
#[test]
fn ut1_in_bounds_symlink_allowed() {
    // A symlink whose target stays INSIDE the workspace resolves + reads fine.
    let ws = tempfile::tempdir().unwrap();
    fs::write(ws.path().join("real.json"), br#"{"x": 2.0}"#).unwrap();
    std::os::unix::fs::symlink(ws.path().join("real.json"), ws.path().join("link.json")).unwrap();
    let r = DefaultFileMetricReader::new(ws.path());
    assert_eq!(r.read_file_metric("link.json", "x").unwrap(), 2.0);
}

// ─────────────────────────── UT-3: Component fail_fast admission ─────────────

fn primary_file_objective() -> Objective {
    Objective {
        name: "primary".to_string(),
        role: Role::Primary,
        metric_source: MetricSource::File {
            path: "primary.json".to_string(),
            key: "loss".to_string(),
        },
        predicate: Predicate {
            op: Op::Lt,
            threshold: Some(0.5),
        },
    }
}

fn component_fail_fast() -> FailFastMetric {
    FailFastMetric {
        metric_source: MetricSource::Component {
            output_key: "unsafe_score".to_string(),
        },
        predicate: Some(Predicate {
            op: Op::Gt,
            threshold: Some(0.9),
        }),
    }
}

#[test]
fn ut3_component_fail_fast_without_evaluator_is_rejected() {
    let crit = SuccessCriteria {
        evaluator: None,
        objectives: vec![primary_file_objective()],
        per_iteration_budget: None,
        fail_fast: Some(vec![component_fail_fast()]),
        safety_valve: None,
    };
    // Wave-22: a Component-source fail_fast metric now requires a top-level
    // evaluator — same rule the objectives already enforced.
    assert!(matches!(
        crit.validate(),
        Err(AutoLoopError::MissingEvaluator)
    ));
}

#[test]
fn ut3_component_fail_fast_with_evaluator_validates() {
    let crit = SuccessCriteria {
        evaluator: Some("test-evaluator".to_string()),
        objectives: vec![primary_file_objective()],
        per_iteration_budget: None,
        fail_fast: Some(vec![component_fail_fast()]),
        safety_valve: None,
    };
    assert!(crit.validate().is_ok());
}

#[test]
fn ut3_file_fail_fast_without_evaluator_is_allowed() {
    // File-source fail_fast does NOT require an evaluator (only Component does).
    let crit = SuccessCriteria {
        evaluator: None,
        objectives: vec![primary_file_objective()],
        per_iteration_budget: None,
        fail_fast: Some(vec![FailFastMetric {
            metric_source: MetricSource::File {
                path: "ff.json".to_string(),
                key: "err_rate".to_string(),
            },
            predicate: Some(Predicate {
                op: Op::Gt,
                threshold: Some(0.2),
            }),
        }]),
        safety_valve: None,
    };
    assert!(crit.validate().is_ok());
}
