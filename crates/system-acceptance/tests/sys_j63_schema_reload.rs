//! Lifecycle-harvest / Stage-B — SYS-J-63 meta-schema hot-reload e2e witnesses
//! (SYS-AC-259 / 260 / 261).
//! (Replaces the Track-A blocker spec: the hotreload pre-build shipped the
//! product watcher + emission, and the `.with_meta_schema_watch()` axis now
//! wires the real schema path + SUT accessors this file's old "un-block path"
//! called for. Stage-B's `.with_sqlite_index()` axis closes the SYS-AC-260
//! recall leg — see the SYS-AC-260 test below.)
//!
//! Wired system: the harness `.with_meta_schema_watch()` axis — the production
//! `cap_fs::MetaSchemaWatcher` (polling watcher, fail-closed reload,
//! `runtime.schema_reloaded` emission, `loader()`/`last_error()`/`is_alive()`
//! accessors) over a real seeded `<ws>/.advance/meta-schema.yaml`, with the
//! SAME `Arc<MetaSchemaLoader>` registered into `register_agent_fs` — so the
//! live schema the watcher reloads IS the schema the real `fs_write`
//! auto-populate consumes during a real guest turn.
//!
//! **SYS-AC-260 (stage-B, now witnessed)**: the recall leg ("the value becomes
//! recall-able — indexed into SQLite") is closed by combining
//! `.with_meta_schema_watch()` with the stage-B `.with_sqlite_index()` axis — the
//! trio now wires `db_sync`, so `sqlite_sync_after_write` runs and the post-reload
//! write fans out to the SQLite index. The 259 test's second half is retained as
//! reload→auto-populate evidence; the SYS-AC-260 test below adds the SQLite-recall
//! leg (the new field lands in `.meta.yaml` AND the written content is FTS-recallable).
//!
//! Same-PID legs: everything runs in this test process — `std::process::id()`
//! asserted unchanged + no `runtime.shutdown` event (the criterion's "without
//! a runtime restart").

use std::time::Duration;

use system_acceptance::{Cap, SystemUnderTest};

const J01_SKELETON: &[u8] =
    include_bytes!("../../runtime/tests/fixtures/guest-rust-j01-skeleton.core.wasm");

/// The seeded schema (the axis writes this exact shape) plus one new OPTIONAL
/// field — the SYS-AC-259 "add an optional field" edit.
const SCHEMA_WITH_PRIORITY: &str = r#"
required:
  name:
    type: string
    auto: filename
optional:
  tags:
    type: list<string>
    default: []
  priority:
    type: integer
    default: 7
"#;

/// Invalid edit (SYS-AC-261): unknown field type.
const SCHEMA_INVALID: &str = r#"
required:
  name:
    type: quux-not-a-type
    auto: filename
"#;

/// Atomic-rename write — the recommended schema-writer pattern (keeps
/// exact-event-count assertions torn-read-free; cap-fs watcher-test crib).
fn write_schema(path: &std::path::Path, content: &str) {
    let tmp = path.with_extension("tmp-write");
    std::fs::write(&tmp, content).expect("write tmp schema");
    std::fs::rename(&tmp, path).expect("rename schema into place");
}

// ── SYS-AC-259 (+ the 260 reload→auto-populate supporting evidence) ────────
#[tokio::test(flavor = "multi_thread")]
async fn sys_ac_259_schema_reload_event_same_pid_and_auto_populate_evidence() {
    let pid_before = std::process::id();
    let sut = SystemUnderTest::builder()
        .caps(&[Cap::Fs])
        .with_meta_schema_watch()
        .build(J01_SKELETON)
        .await;

    // Baseline: the registered loader serves the seeded schema.
    assert!(sut.schema_loader().current().optional.contains_key("tags"));
    assert!(!sut
        .schema_loader()
        .current()
        .optional
        .contains_key("priority"));

    // ── the live edit: add the optional `priority` field ───────────────────
    write_schema(sut.meta_schema_path(), SCHEMA_WITH_PRIORITY);

    // Picked up without a restart (50ms poll; bounded ~3s CI tolerance).
    let mut reloaded = false;
    for _ in 0..600 {
        if sut
            .events()
            .iter()
            .any(|e| e.event_type == "runtime.schema_reloaded")
        {
            reloaded = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert!(reloaded, "runtime.schema_reloaded within the CI tolerance");

    // The event names the change.
    let events = sut.events();
    let reload_events: Vec<_> = events
        .iter()
        .filter(|e| e.event_type == "runtime.schema_reloaded")
        .collect();
    assert_eq!(
        reload_events.len(),
        1,
        "exactly one event per applied reload"
    );
    let e = reload_events[0];
    assert_eq!(e.agent_id, "runtime");
    assert_eq!(e.payload["optional_added"], serde_json::json!(["priority"]));
    assert_eq!(e.payload["optional_added_count"], 1);
    assert_eq!(e.payload["required_added_count"], 0);

    // Same PID / no restart; the registered loader serves the NEW schema.
    assert_eq!(std::process::id(), pid_before, "same PID across the reload");
    assert!(
        !events.iter().any(|e| e.event_type == "runtime.shutdown"),
        "no runtime.shutdown emitted"
    );
    assert!(sut.schema_watcher().is_alive(), "watcher poll thread alive");
    assert!(sut.schema_watcher().last_error().is_none(), "clean reload");
    assert!(
        sut.schema_loader()
            .current()
            .optional
            .contains_key("priority"),
        "the registered loader (the one register_agent_fs consumes) reloaded"
    );

    // ── SYS-AC-260 supporting evidence (reload→auto-populate leg ONLY; the
    //    recall/SQLite leg is a recorded deferral — module header): a real
    //    guest fs-write turn AFTER the reload auto-populates the
    //    newly-declared field into the file's .meta.yaml entry. ─────────────
    sut.inject_message("alice", b"sys-j63-after-reload").await;
    sut.run_turn().await;
    let meta = sut
        .read_workspace_file(".meta.yaml")
        .expect("the turn's fs.write maintained .meta.yaml");
    let meta_text = String::from_utf8(meta).expect("meta yaml utf8");
    assert!(
        meta_text.contains("priority"),
        "newly-declared optional field auto-populated into .meta.yaml: {meta_text}"
    );
    assert!(
        meta_text.contains('7'),
        "the new field carries its schema default: {meta_text}"
    );
}

// ── SYS-AC-260 — post-reload write auto-populates the new field AND becomes
//    recall-able (indexed into SQLite via the trio) ──────────────────────────
#[tokio::test(flavor = "multi_thread")]
async fn sys_ac_260_post_reload_write_autopopulates_and_is_recallable() {
    let sut = SystemUnderTest::builder()
        .caps(&[Cap::Fs])
        .with_meta_schema_watch()
        .with_sqlite_index() // stage-B: wires the trio so the post-reload write syncs to SQLite
        .build(J01_SKELETON)
        .await;

    assert!(!sut
        .schema_loader()
        .current()
        .optional
        .contains_key("priority"));

    // Add the optional `priority` field; wait for the registered loader to reload.
    write_schema(sut.meta_schema_path(), SCHEMA_WITH_PRIORITY);
    let mut reloaded = false;
    for _ in 0..600 {
        if sut
            .schema_loader()
            .current()
            .optional
            .contains_key("priority")
        {
            reloaded = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert!(
        reloaded,
        "registered loader reloaded the new field (no restart)"
    );

    // The next real guest fs-write turn (distinctive content) AFTER the reload.
    sut.inject_message("alice", b"sysj63 reloadrecall quetzalword260")
        .await;
    sut.run_turn().await;

    // Leg 1 — the newly-declared field auto-populated into the file's .meta.yaml entry.
    let meta = sut
        .read_workspace_file(".meta.yaml")
        .expect("the turn's fs.write maintained .meta.yaml");
    let meta_text = String::from_utf8(meta).expect("meta yaml utf8");
    assert!(
        meta_text.contains("priority"),
        "newly-declared optional field auto-populated into .meta.yaml: {meta_text}"
    );

    // Leg 2 — the written content became recall-able (indexed into SQLite via the
    // trio's write-path fan-out — the previously-blocked recall leg). FTS/keyword path
    // (content_vec unpopulated on the write path).
    let agent = sut.agent_m004_id();
    let hits = sut.fts_recall(&agent, "quetzalword260").await;
    assert!(
        hits.iter()
            .any(|r| r.file_path.as_deref() == Some("/agent/j01.txt")),
        "post-reload write is FTS-recall-able from the SQLite index; got {:?}",
        hits.iter().map(|r| r.file_path.clone()).collect::<Vec<_>>()
    );
}

// ── SYS-AC-261 — invalid schema edit is rejected fail-closed ───────────────
#[tokio::test(flavor = "multi_thread")]
async fn sys_ac_261_invalid_schema_fail_closed_old_schema_stays_live() {
    let pid_before = std::process::id();
    let sut = SystemUnderTest::builder()
        .caps(&[Cap::Fs])
        .with_meta_schema_watch()
        .build(J01_SKELETON)
        .await;

    // Invalid edit: unknown field type → reload rejected.
    write_schema(sut.meta_schema_path(), SCHEMA_INVALID);

    // Bounded wait for the watcher to observe + reject (last_error is the
    // observable; nothing is emitted for a rejected reload).
    let mut saw_error = false;
    for _ in 0..600 {
        if sut.schema_watcher().last_error().is_some() {
            saw_error = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert!(saw_error, "rejected reload recorded in last_error()");

    // Fail-closed: previous schema retained, no event, watcher alive.
    assert!(
        sut.schema_loader().current().required.contains_key("name"),
        "previous valid schema still in effect"
    );
    assert!(
        !sut.schema_loader()
            .current()
            .optional
            .contains_key("priority"),
        "rejected edit applied nothing"
    );
    assert!(
        !sut.events()
            .iter()
            .any(|e| e.event_type == "runtime.schema_reloaded"),
        "no runtime.schema_reloaded for a rejected reload"
    );
    assert!(
        sut.schema_watcher().is_alive(),
        "watcher survived the bad edit"
    );
    assert_eq!(std::process::id(), pid_before, "same PID (no restart)");

    // Subsequent writes continue under the prior schema: a real guest
    // fs-write turn still succeeds and maintains .meta.yaml with the OLD
    // schema's fields only.
    sut.inject_message("alice", b"sys-j63-under-old-schema")
        .await;
    sut.run_turn().await;
    let meta = sut
        .read_workspace_file(".meta.yaml")
        .expect("writes continue under the previous schema");
    let meta_text = String::from_utf8(meta).expect("meta yaml utf8");
    assert!(
        meta_text.contains("name"),
        "old-schema field maintained: {meta_text}"
    );
    assert!(
        !meta_text.contains("priority"),
        "no field from the rejected schema: {meta_text}"
    );
}
