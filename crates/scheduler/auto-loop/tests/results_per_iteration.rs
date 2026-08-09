//! AC-15: `.agent/auto/results.jsonl` per-iteration multi-row + cancel-path
//! coverage. Uses the slice-C `row_from_outcome` helper to build canonical
//! rows from outcome inputs.

use std::collections::BTreeMap;

use advance_scheduler_auto_loop::{
    results::{cost_clamped_to_zero, dropped_metric_keys, row_from_outcome},
    IterationStatus, ResultsWriter,
};

fn metric_with(key: &str, value: f64) -> BTreeMap<String, f64> {
    let mut m = BTreeMap::new();
    m.insert(key.to_string(), value);
    m
}

// MODULE-015-T15-slC.a — multi-iteration writes produce monotonic iter
// counter, all 7 PRD §4.7.10 schema fields present, status snake_case.
#[tokio::test]
async fn multi_iteration_rows_iter_monotonic() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let writer = ResultsWriter::new(tmp.path().to_path_buf());

    // Three sequential appends with row_from_outcome.
    writer
        .append(&row_from_outcome(
            0,
            "auto-baseline".to_string(),
            metric_with("val_bpb", 1.120),
            IterationStatus::Keep,
            0.03,
            45,
            Some("baseline".to_string()),
        ))
        .await
        .expect("append iter=0");
    writer
        .append(&row_from_outcome(
            1,
            "auto-iter-1".to_string(),
            metric_with("val_bpb", 1.085),
            IterationStatus::Keep,
            0.05,
            52,
            Some("kept: bpb improved".to_string()),
        ))
        .await
        .expect("append iter=1");
    writer
        .append(&row_from_outcome(
            2,
            "auto-iter-2".to_string(),
            metric_with("val_bpb", 1.150),
            IterationStatus::Discard,
            0.04,
            48,
            Some("discarded: regression".to_string()),
        ))
        .await
        .expect("append iter=2");

    let content = tokio::fs::read_to_string(writer.jsonl_path())
        .await
        .unwrap();
    let lines: Vec<&str> = content.lines().collect();
    assert_eq!(lines.len(), 3, "3 rows expected");

    for (i, line) in lines.iter().enumerate() {
        let parsed: serde_json::Value =
            serde_json::from_str(line).unwrap_or_else(|e| panic!("parse row {i}: {e}"));
        // All 7 fields present per PRD §4.7.10.
        for field in [
            "iter",
            "checkpoint",
            "metric",
            "status",
            "cost_usd",
            "wall_time_sec",
            "summary",
        ] {
            assert!(
                parsed.get(field).is_some(),
                "row {i} missing field `{field}`"
            );
        }
        let obj = parsed.as_object().unwrap();
        assert_eq!(obj.len(), 7, "row {i}: exactly 7 fields expected");
        assert_eq!(parsed["iter"], i as u64);
    }

    // Status values are snake_case per IterationStatus serialization.
    let row0: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
    let row2: serde_json::Value = serde_json::from_str(lines[2]).unwrap();
    assert_eq!(row0["status"], "keep");
    assert_eq!(row2["status"], "discard");
}

// MODULE-015-T15-slC.b — cancel-path row carries the cancel reason text
// in the summary field. Round-2 W2 fix: explicit cancel-path coverage.
#[tokio::test]
async fn cancel_path_row_writes() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let writer = ResultsWriter::new(tmp.path().to_path_buf());

    // Cancel-path row: status=Crash + summary carries the cancel reason.
    let row = row_from_outcome(
        3,
        "auto-iter-3".to_string(),
        BTreeMap::new(),
        IterationStatus::Crash,
        0.01,
        12,
        Some("cancelled: user-stop".to_string()),
    );
    writer.append(&row).await.expect("append cancel row");

    let content = tokio::fs::read_to_string(writer.jsonl_path())
        .await
        .unwrap();
    let parsed: serde_json::Value = serde_json::from_str(content.lines().next().unwrap()).unwrap();
    assert_eq!(parsed["status"], "crash");
    assert_eq!(parsed["iter"], 3);
    assert_eq!(parsed["summary"], "cancelled: user-stop");
}

// MODULE-015-T15-slC.c — keep-path row carries the summary text.
#[tokio::test]
async fn keep_path_row_carries_summary() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let writer = ResultsWriter::new(tmp.path().to_path_buf());

    let row = row_from_outcome(
        1,
        "auto-iter-1".to_string(),
        metric_with("val_bpb", 1.0),
        IterationStatus::Keep,
        0.02,
        30,
        Some("kept: bpb improved".to_string()),
    );
    writer.append(&row).await.expect("append keep row");

    let content = tokio::fs::read_to_string(writer.jsonl_path())
        .await
        .unwrap();
    let parsed: serde_json::Value = serde_json::from_str(content.lines().next().unwrap()).unwrap();
    assert_eq!(parsed["status"], "keep");
    assert_eq!(parsed["summary"], "kept: bpb improved");
}

// MODULE-015-T15-slC.e — Audit signals for non-finite drops (adversarial
// Round-1 W4 fix). dropped_metric_keys lists keys whose values would be
// silently absent from the jsonl row; cost_clamped_to_zero flags
// non-finite cost_usd that would be clamped to 0.0.
#[tokio::test]
async fn dropped_metric_keys_observable() {
    let mut metric = BTreeMap::new();
    metric.insert("good".to_string(), 1.0);
    metric.insert("nan_one".to_string(), f64::NAN);
    metric.insert("inf_two".to_string(), f64::INFINITY);
    metric.insert("ninf_three".to_string(), f64::NEG_INFINITY);

    let row = row_from_outcome(
        0,
        "auto-baseline".to_string(),
        metric,
        IterationStatus::Discard,
        0.05,
        10,
        None,
    );
    let mut dropped = dropped_metric_keys(&row);
    dropped.sort();
    assert_eq!(
        dropped,
        vec![
            "inf_two".to_string(),
            "nan_one".to_string(),
            "ninf_three".to_string()
        ]
    );
    assert!(!cost_clamped_to_zero(&row), "finite cost_usd must not flag");
}

#[tokio::test]
async fn cost_clamped_observable_when_nan() {
    let row = row_from_outcome(
        0,
        "auto-baseline".to_string(),
        BTreeMap::new(),
        IterationStatus::Crash,
        f64::NAN,
        0,
        None,
    );
    assert!(cost_clamped_to_zero(&row));
    assert!(dropped_metric_keys(&row).is_empty(), "no metric drops");
}

#[tokio::test]
async fn cost_clamped_observable_when_infinite() {
    let row = row_from_outcome(
        0,
        "auto-baseline".to_string(),
        BTreeMap::new(),
        IterationStatus::Crash,
        f64::INFINITY,
        0,
        None,
    );
    assert!(cost_clamped_to_zero(&row));
}

// MODULE-015-T15-slC.d — metric keys serialize in alphabetical order
// (BTreeMap guarantee). Defends downstream readers that rely on
// reproducible row layout.
#[tokio::test]
async fn metric_keys_sorted_btreemap() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let writer = ResultsWriter::new(tmp.path().to_path_buf());

    let mut metric = BTreeMap::new();
    metric.insert("z".to_string(), 3.0);
    metric.insert("a".to_string(), 1.0);
    metric.insert("m".to_string(), 2.0);

    let row = row_from_outcome(
        0,
        "auto-baseline".to_string(),
        metric,
        IterationStatus::Keep,
        0.0,
        1,
        None,
    );
    writer.append(&row).await.expect("append");

    let content = tokio::fs::read_to_string(writer.jsonl_path())
        .await
        .unwrap();
    let line = content.lines().next().unwrap();
    // Locate the metric object substring and verify key order.
    let metric_start = line.find("\"metric\":").expect("metric field");
    let metric_chunk = &line[metric_start..];
    let a_pos = metric_chunk.find("\"a\":").expect("a key present");
    let m_pos = metric_chunk.find("\"m\":").expect("m key present");
    let z_pos = metric_chunk.find("\"z\":").expect("z key present");
    assert!(a_pos < m_pos, "a must come before m: line={line}");
    assert!(m_pos < z_pos, "m must come before z: line={line}");
}
