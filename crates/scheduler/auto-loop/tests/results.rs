//! Foundation tests for results.jsonl writer (AC-15 verification deferred
//! to integrated-loop slice; the schema + append mechanics are unit-tested
//! here).

use std::collections::BTreeMap;

use advance_scheduler_auto_loop::{IterationResult, IterationStatus, ResultsWriter};
use tempfile::tempdir;

fn baseline_row() -> IterationResult {
    let mut metric = BTreeMap::new();
    metric.insert("val_bpb".to_string(), 1.120);
    IterationResult {
        iter: 0,
        checkpoint: "auto-baseline".to_string(),
        metric,
        status: IterationStatus::Keep,
        cost_usd: 0.03,
        wall_time_sec: 45,
        summary: Some("baseline".to_string()),
    }
}

fn discard_row() -> IterationResult {
    let mut metric = BTreeMap::new();
    metric.insert("val_bpb".to_string(), 1.150);
    IterationResult {
        iter: 2,
        checkpoint: "auto-iter-2".to_string(),
        metric,
        status: IterationStatus::Discard,
        cost_usd: 0.04,
        wall_time_sec: 48,
        summary: Some("added dropout".to_string()),
    }
}

fn crash_row() -> IterationResult {
    IterationResult {
        iter: 3,
        checkpoint: "auto-iter-3".to_string(),
        metric: BTreeMap::new(),
        status: IterationStatus::Crash,
        cost_usd: 0.01,
        wall_time_sec: 12,
        summary: None,
    }
}

// ─── (a) append creates file + writes one line ──────────────────────────

#[tokio::test]
async fn a_append_creates_file_and_writes_one_line() {
    let tmp = tempdir().expect("tempdir");
    let writer = ResultsWriter::new(tmp.path().to_path_buf());

    writer.append(&baseline_row()).await.expect("append");

    let content = tokio::fs::read_to_string(writer.jsonl_path())
        .await
        .unwrap();
    let line_count = content.lines().count();
    assert_eq!(line_count, 1);
    let first_line = content.lines().next().unwrap();
    // Parse round-trip
    let parsed: serde_json::Value = serde_json::from_str(first_line).unwrap();
    assert_eq!(parsed["iter"], 0);
    assert_eq!(parsed["checkpoint"], "auto-baseline");
    assert_eq!(parsed["status"], "keep");
}

// ─── (b) second append → two lines ──────────────────────────────────────

#[tokio::test]
async fn b_two_appends_two_lines() {
    let tmp = tempdir().expect("tempdir");
    let writer = ResultsWriter::new(tmp.path().to_path_buf());

    writer.append(&baseline_row()).await.expect("append");
    writer.append(&discard_row()).await.expect("append");

    let content = tokio::fs::read_to_string(writer.jsonl_path())
        .await
        .unwrap();
    assert_eq!(content.lines().count(), 2);
}

// ─── (c) schema verbatim per PRD §4.7.10 ────────────────────────────────

#[tokio::test]
async fn c_schema_snake_case_per_prd() {
    let tmp = tempdir().expect("tempdir");
    let writer = ResultsWriter::new(tmp.path().to_path_buf());

    writer.append(&baseline_row()).await.expect("append");

    let content = tokio::fs::read_to_string(writer.jsonl_path())
        .await
        .unwrap();
    let parsed: serde_json::Value = serde_json::from_str(content.lines().next().unwrap()).unwrap();
    // Schema verbatim per PRD §4.7.10:
    assert!(parsed.get("iter").is_some());
    assert!(parsed.get("checkpoint").is_some());
    assert!(parsed.get("metric").is_some());
    assert!(parsed.get("status").is_some());
    assert!(parsed.get("cost_usd").is_some());
    assert!(parsed.get("wall_time_sec").is_some());
    assert!(parsed.get("summary").is_some());
    // No extra fields (deny_unknown_fields on the round-trip side).
    let obj = parsed.as_object().unwrap();
    assert_eq!(obj.len(), 7);
}

// ─── (d) crash with empty metric + null summary serializes correctly ────

#[tokio::test]
async fn d_crash_row_with_null_summary() {
    let tmp = tempdir().expect("tempdir");
    let writer = ResultsWriter::new(tmp.path().to_path_buf());

    writer.append(&crash_row()).await.expect("append");

    let content = tokio::fs::read_to_string(writer.jsonl_path())
        .await
        .unwrap();
    let line = content.lines().next().unwrap();
    let parsed: serde_json::Value = serde_json::from_str(line).unwrap();
    assert_eq!(parsed["status"], "crash");
    assert_eq!(parsed["metric"], serde_json::json!({}));
    assert!(parsed["summary"].is_null());
}

// ─── (e) creates .agent/auto/ parent dir if absent ──────────────────────

#[tokio::test]
async fn e_creates_parent_dir() {
    let tmp = tempdir().expect("tempdir");
    let writer = ResultsWriter::new(tmp.path().to_path_buf());

    // Parent dir must not exist yet.
    assert!(!writer.jsonl_path().parent().unwrap().exists());

    writer.append(&baseline_row()).await.expect("append");

    assert!(writer.jsonl_path().parent().unwrap().exists());
    assert!(writer.jsonl_path().exists());
}

// ─── (f)/(g) append semantics + read-back ───────────────────────────────

#[tokio::test]
async fn fg_append_then_readback_round_trip() {
    let tmp = tempdir().expect("tempdir");
    let writer = ResultsWriter::new(tmp.path().to_path_buf());

    let row = baseline_row();
    writer.append(&row).await.expect("append");

    let content = tokio::fs::read_to_string(writer.jsonl_path())
        .await
        .unwrap();
    let line = content.lines().next().unwrap();
    let parsed: IterationResult = serde_json::from_str(line).unwrap();
    assert_eq!(parsed, row);
}

// ─── (h) IterationStatus serializes snake_case ──────────────────────────

#[test]
fn h_iteration_status_snake_case() {
    assert_eq!(
        serde_json::to_string(&IterationStatus::Keep).unwrap(),
        "\"keep\""
    );
    assert_eq!(
        serde_json::to_string(&IterationStatus::Discard).unwrap(),
        "\"discard\""
    );
    assert_eq!(
        serde_json::to_string(&IterationStatus::Crash).unwrap(),
        "\"crash\""
    );
}
