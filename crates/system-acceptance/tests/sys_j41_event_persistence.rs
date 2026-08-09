//! /dev Track J — SYS-J-41 host-function event persistence witness.
//!
//! **SYS-AC-131**: "A host-function event appears as a line in /.runtime/events/YYYY-MM-DD.jsonl
//! and as a row in the SQLite events table with matching id."
//!
//! Drives ONE real wired turn (the production agent loop + `WasmMessageHandler`) over the REAL
//! synchronous `EventBus` (`EventSink::RealBus` → real `EventFileWriter` JSONL + real
//! `EventDbIndexer` SQLite). The committed j01 skeleton guest performs exactly one
//! `agent_fs::write`, so cap-fs emits exactly one `fs.write` event (the co-emitted `meta.updated`
//! is a distinct `event_type`). We assert the SAME event is durable in BOTH sinks with a matching
//! `id`. No mock/stub stands in for any module in the chain (witness-floor).
//!
//! **Path-literal note**: the SYS-AC-131 criterion text names `.runtime/events/YYYY-MM-DD.jsonl`,
//! but the harness/`EventFileWriter` writes under `.runtime/events/jsonl/YYYY-MM-DD.jsonl` (extra
//! `jsonl/` segment). We glob the real implementation path; the substantive dual-sink + matching-id
//! claim is unaffected by the directory drift (a `/spec`-owned criterion-text vs impl nuance).
//!
//! This is the FIRST test to exercise an `fs.*` host-fn event through the RealBus SQLite path:
//! `mode_events_smoke` asserts only `msg.received`; `sys_j01_core` runs the Capturing sink and
//! asserts the file + commit, never the `fs.write` event.
//!
//! Runs under `multi_thread` because the synchronous bus writes inline during the turn (bounded
//! per-turn I/O, deterministic read-back, no drain) — see the harness README.

use std::fs;

use system_acceptance::{Cap, EventSink, SystemUnderTest};

const J01_SKELETON: &[u8] =
    include_bytes!("../../runtime/tests/fixtures/guest-rust-j01-skeleton.core.wasm");

#[tokio::test(flavor = "multi_thread")]
async fn sys_j41_host_fn_event_persists_to_jsonl_and_sqlite_with_matching_id() {
    let sut = SystemUnderTest::builder()
        .caps(&[Cap::Fs])
        .events(EventSink::RealBus)
        .build(J01_SKELETON)
        .await;

    sut.inject_message("alice", b"sys-j41-payload").await;
    sut.run_turn().await;

    // (a) Exactly one `fs.write` row in the real SQLite `events` table. The j01 guest writes once;
    //     the co-emitted `meta.updated` is a distinct event_type, so this filter is exact.
    assert_eq!(
        sut.db_event_count(Some("fs.write")),
        1,
        "exactly one fs.write row persisted to the SQLite events table"
    );
    let db_row = sut.assert_db_event("fs.write", |_| true);
    assert!(
        !db_row.id.is_empty(),
        "the fs.write SQLite row carries a non-empty id"
    );

    // (b) The SAME host-fn event appears as a durable JSONL line. Read EVERY jsonl file the harness
    //     wrote, FILTER to `event_type == "fs.write"` (never "first line"/"last file"), require
    //     exactly one such line, and assert its `id` equals the SQLite row's `id`.
    let jsonl_dir = sut.workspace_root().join(".runtime/events/jsonl");
    let mut fs_write_ids: Vec<String> = Vec::new();
    for entry in fs::read_dir(&jsonl_dir).expect("the RealBus JSONL directory exists after a turn")
    {
        let path = entry.expect("dir entry").path();
        if path.extension().and_then(|e| e.to_str()) != Some("jsonl") {
            continue;
        }
        let content = fs::read_to_string(&path).expect("read JSONL file");
        for line in content.lines().filter(|l| !l.trim().is_empty()) {
            let v: serde_json::Value =
                serde_json::from_str(line).expect("each JSONL line is valid JSON");
            if v.get("event_type").and_then(|t| t.as_str()) == Some("fs.write") {
                let id = v
                    .get("id")
                    .and_then(|i| i.as_str())
                    .expect("a JSONL fs.write line carries a string id")
                    .to_string();
                fs_write_ids.push(id);
            }
        }
    }
    assert_eq!(
        fs_write_ids.len(),
        1,
        "exactly one fs.write line in the JSONL sink (matching the single SQLite row)"
    );
    assert_eq!(
        fs_write_ids[0], db_row.id,
        "the fs.write JSONL line id matches the SQLite events row id — the same host-fn event is \
         durable in BOTH sinks (SYS-AC-131)"
    );

    // (c) The real bus dropped nothing (oversize / dup-id / backpressure).
    sut.assert_no_dropped_events();
}
