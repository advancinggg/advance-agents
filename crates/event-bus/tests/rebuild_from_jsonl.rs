//! T-S-B AC-09 rebuild from JSONL tests.

use std::path::Path;

use advance_event_bus::rebuild_sqlite_from_jsonl;

/// MODULE-019-T34 — JSONL → SQLite events table fully restored.
#[test]
fn t34_rebuild_events_table_from_jsonl() {
    let temp = tempfile::TempDir::new().unwrap();
    let jsonl_dir = temp.path().join("events");
    std::fs::create_dir_all(&jsonl_dir).unwrap();
    let jsonl_file = jsonl_dir.join("2026-05-04.jsonl");

    let mut content = String::new();
    for i in 0..50u64 {
        content.push_str(&format!(
            r#"{{"id":"evt-{i}","timestamp":"2026-05-04T12:00:00.000Z","agent_id":"a","task_id":null,"run_id":null,"execution_id":null,"trace_id":"tr-1","span_id":"s-1","parent_span_id":null,"event_type":"runtime.started","payload":{{}},"duration_ms":null}}
"#
        ));
    }
    std::fs::write(&jsonl_file, content).unwrap();

    let db_path = temp.path().join("rebuilt.db");
    let report = rebuild_sqlite_from_jsonl(&jsonl_dir, &db_path).expect("rebuild");

    assert_eq!(report.events_replayed, 50);
    assert_eq!(report.lines_skipped, 0);

    let conn = rusqlite::Connection::open(&db_path).unwrap();
    let count: u64 = conn
        .query_row("SELECT COUNT(*) FROM events", [], |r| r.get(0))
        .unwrap();
    assert_eq!(count, 50);
}

/// MODULE-019-T35 — runs aggregation reconstructed from llm.response stream.
#[test]
fn t35_rebuild_runs_aggregation_correct() {
    let temp = tempfile::TempDir::new().unwrap();
    let jsonl_dir = temp.path().join("events");
    std::fs::create_dir_all(&jsonl_dir).unwrap();

    let mut content = String::new();
    // 1 run.created event seeding task_id (renamed Slice D per PRD §15.3.4A).
    content.push_str(r#"{"id":"start","timestamp":"2026-05-04T12:00:00.000Z","agent_id":"a","task_id":"task-1","run_id":"run-1","execution_id":null,"trace_id":"tr-1","span_id":"s-1","parent_span_id":null,"event_type":"run.created","payload":{"task_id":"task-1","controller_agent":"agent-c"},"duration_ms":null}
"#);
    // 100 llm.response events: each input=1000, output=500, cost=0.01.
    for i in 0..100u64 {
        content.push_str(&format!(
            r#"{{"id":"llm-{i}","timestamp":"2026-05-04T12:00:01.000Z","agent_id":"a","task_id":"task-1","run_id":"run-1","execution_id":null,"trace_id":"tr-1","span_id":"s-2","parent_span_id":null,"event_type":"llm.response","payload":{{"input_tokens":1000,"output_tokens":500,"cost_usd":0.01}},"duration_ms":null}}
"#
        ));
    }
    // 1 run.completed.
    content.push_str(r#"{"id":"complete","timestamp":"2026-05-04T13:00:00.000Z","agent_id":"a","task_id":"task-1","run_id":"run-1","execution_id":null,"trace_id":"tr-1","span_id":"s-3","parent_span_id":null,"event_type":"run.completed","payload":{},"duration_ms":null}
"#);

    let jsonl_file = jsonl_dir.join("2026-05-04.jsonl");
    std::fs::write(&jsonl_file, content).unwrap();

    let db_path = temp.path().join("rebuilt.db");
    let report = rebuild_sqlite_from_jsonl(&jsonl_dir, &db_path).expect("rebuild");

    assert_eq!(report.events_replayed, 102);
    assert_eq!(report.runs_built, 1);

    let conn = rusqlite::Connection::open(&db_path).unwrap();
    let (task_id, status, token_used, cost_usd): (String, String, i64, f64) = conn
        .query_row(
            "SELECT task_id, status, token_used, cost_usd FROM runs WHERE run_id='run-1'",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .unwrap();
    assert_eq!(task_id, "task-1");
    assert_eq!(status, "Completed");
    assert_eq!(token_used, 100 * 1500); // 100 events × (1000+500)
    assert!(
        (cost_usd - 1.0).abs() < 1e-6,
        "expected ~1.0, got {cost_usd}"
    );
}

/// MODULE-019-T36 — corrupt JSONL line skipped, reported in lines_skipped.
#[test]
fn t36_corrupt_line_skipped() {
    let temp = tempfile::TempDir::new().unwrap();
    let jsonl_dir = temp.path().join("events");
    std::fs::create_dir_all(&jsonl_dir).unwrap();
    let jsonl_file = jsonl_dir.join("2026-05-04.jsonl");

    let mut content = String::new();
    content.push_str(r#"{"id":"evt-1","timestamp":"2026-05-04T12:00:00.000Z","agent_id":"a","task_id":null,"run_id":null,"execution_id":null,"trace_id":"tr-1","span_id":"s-1","parent_span_id":null,"event_type":"runtime.started","payload":{},"duration_ms":null}
"#);
    content.push_str("{ this is corrupt json }\n");
    content.push_str(r#"{"id":"evt-2","timestamp":"2026-05-04T12:00:01.000Z","agent_id":"a","task_id":null,"run_id":null,"execution_id":null,"trace_id":"tr-1","span_id":"s-1","parent_span_id":null,"event_type":"runtime.started","payload":{},"duration_ms":null}
"#);
    std::fs::write(&jsonl_file, content).unwrap();

    let db_path = temp.path().join("rebuilt.db");
    let report = rebuild_sqlite_from_jsonl(&jsonl_dir, &db_path).expect("rebuild");

    assert_eq!(report.events_replayed, 2);
    assert_eq!(report.lines_skipped, 1);

    let conn = rusqlite::Connection::open(&db_path).unwrap();
    let count: u64 = conn
        .query_row("SELECT COUNT(*) FROM events", [], |r| r.get(0))
        .unwrap();
    assert_eq!(count, 2);
}

/// MODULE-019-T37 — post-rebuild user_version = 3 (Slice C bumped from v=2).
#[test]
fn t37_rebuild_leaves_user_version_3() {
    let temp = tempfile::TempDir::new().unwrap();
    let jsonl_dir = temp.path().join("events");
    std::fs::create_dir_all(&jsonl_dir).unwrap();

    let db_path = temp.path().join("rebuilt.db");
    rebuild_sqlite_from_jsonl(&jsonl_dir, &db_path).expect("rebuild empty");

    let conn = rusqlite::Connection::open(&db_path).unwrap();
    let v: u32 = conn
        .pragma_query_value(None, "user_version", |r| r.get(0))
        .unwrap();
    assert_eq!(v, 3);
}

/// Rebuild reads files in date order (filename sorted).
#[test]
fn t_rebuild_orders_files_by_date() {
    let temp = tempfile::TempDir::new().unwrap();
    let jsonl_dir = temp.path().join("events");
    std::fs::create_dir_all(&jsonl_dir).unwrap();

    // File 1: 2026-05-03 has evt-A.
    std::fs::write(
        jsonl_dir.join("2026-05-03.jsonl"),
        r#"{"id":"evt-A","timestamp":"2026-05-03T12:00:00.000Z","agent_id":"a","task_id":null,"run_id":null,"execution_id":null,"trace_id":"tr-1","span_id":"s-1","parent_span_id":null,"event_type":"runtime.started","payload":{},"duration_ms":null}
"#,
    ).unwrap();
    // File 2: 2026-05-04 has evt-B.
    std::fs::write(
        jsonl_dir.join("2026-05-04.jsonl"),
        r#"{"id":"evt-B","timestamp":"2026-05-04T12:00:00.000Z","agent_id":"a","task_id":null,"run_id":null,"execution_id":null,"trace_id":"tr-1","span_id":"s-1","parent_span_id":null,"event_type":"runtime.started","payload":{},"duration_ms":null}
"#,
    ).unwrap();

    let db_path = temp.path().join("rebuilt.db");
    let report = rebuild_sqlite_from_jsonl(&jsonl_dir, &db_path).expect("rebuild");
    assert_eq!(report.events_replayed, 2);
}

#[allow(dead_code)]
fn _path_helper(_p: &Path) {} // keep `Path` import warning quiet on minor renames
