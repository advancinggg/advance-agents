//! Track A / Stage-B — SYS-J-46 (boot scan / FS+.meta.yaml drift-fix / SQLite index
//! rebuild). LIVE witnesses for SYS-AC-146/147/148/233 on the REAL wired system.
//!
//! The `.with_sqlite_index()` axis (stage-B) wires the cap-fs triple-sync trio into
//! `register_agent_fs` over a fresh in-memory `R2d2SqliteIndexHandle`, and
//! `sut.boot_reconcile()` runs the REAL `WorkspaceReconciler` (walk + `.meta.yaml`
//! drift-repair) + REAL `IndexRebuild::rebuild_full` against that same handle, emitting
//! `fs.reconcile_completed` (always) + `runtime.index_rebuild` (on the rebuild branch).
//! `sut.fts_recall(agent, query)` recalls via the FTS/keyword path.
//!
//! Territory note: the M004 rebuild scans a directory only if it holds a `.agent/`
//! marker (`rebuild.rs::agent_dirs`), assigning it an agent_id via `derive_agent_id`
//! (e.g. `<ws>/seed148` → "seed148"). Reconcile's WALK (the `.meta.yaml` repair) covers
//! every non-hidden dir regardless. Recall witnesses therefore seed a `.agent/`-marked
//! territory and recall under its derived agent_id.
//!
//! `#[tokio::test(flavor = "multi_thread")]` is mandatory (the synchronous Capturing
//! bus + spawn_blocking SQLite legs). SYS-AC-234 (the reconcile/rebuild SLO) stays a
//! recorded deferral — out of scope here (no perf assertion).

use serde_yml::{Mapping, Value};
use std::path::Path;
use system_acceptance::{Cap, SystemUnderTest};

const J01_SKELETON: &[u8] =
    include_bytes!("../../runtime/tests/fixtures/guest-rust-j01-skeleton.core.wasm");

/// A `.meta.yaml` entry mapping (name/slug/description).
fn entry(name: &str, desc: &str) -> Value {
    let mut m = Mapping::new();
    m.insert(Value::from("name"), Value::from(name));
    m.insert(Value::from("slug"), Value::from("s"));
    m.insert(Value::from("description"), Value::from(desc));
    Value::Mapping(m)
}

/// Mark `dir` as an M004 rebuild territory (a `.agent/` subdir) so `rebuild_full`
/// scans + indexes its files.
fn mark_territory(dir: &Path) {
    std::fs::create_dir_all(dir.join(".agent")).expect("territory marker");
}

// ─────────────────────────────────────────────────────────────────────────────
// SYS-AC-146: corrupt on-disk state (extra file not in .meta.yaml, or stale entry)
// → reboot/reconcile → the directory's .meta.yaml _entries matches actual disk.
// ─────────────────────────────────────────────────────────────────────────────
#[tokio::test(flavor = "multi_thread")]
async fn sys_ac_146_reboot_reconcile_meta_matches_disk() {
    let sut = SystemUnderTest::builder()
        .caps(&[Cap::Fs])
        .with_sqlite_index()
        .build(J01_SKELETON)
        .await;
    let dir = sut.workspace_root().join("seed146");
    std::fs::create_dir_all(&dir).unwrap();

    // On disk: keepme.md (also in meta) + extra.md (NOT in meta). Missing: gone.md
    // (listed in meta but absent on disk → stale entry).
    std::fs::write(dir.join("keepme.md"), b"keep body").unwrap();
    std::fs::write(dir.join("extra.md"), b"extra body not in meta").unwrap();
    let mut root = Mapping::new();
    let mut scope = Mapping::new();
    scope.insert(Value::from("description"), Value::from("seed146 scope"));
    root.insert(Value::from("_scope"), Value::Mapping(scope));
    root.insert(Value::from("keepme.md"), entry("keepme.md", "kept row"));
    root.insert(
        Value::from("gone.md"),
        entry("gone.md", "stale entry, file deleted"),
    );
    std::fs::write(
        dir.join(".meta.yaml"),
        serde_yml::to_string(&Value::Mapping(root)).unwrap(),
    )
    .unwrap();

    sut.boot_reconcile().await;

    // .meta.yaml _entries now matches actual disk: keepme.md + extra.md present, gone.md
    // removed.
    let after = std::fs::read_to_string(dir.join(".meta.yaml")).unwrap();
    assert!(
        after.contains("keepme.md"),
        "kept on-disk file remains:\n{after}"
    );
    assert!(
        after.contains("extra.md"),
        "extra on-disk file added to _entries:\n{after}"
    );
    assert!(
        !after.contains("gone.md"),
        "stale entry (no file on disk) removed:\n{after}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// SYS-AC-147: boot emits fs.reconcile_completed with non-zero
// entries_added/removed/fields_repaired PLUS a runtime.index_rebuild event with
// total_files/total_dirs.
// ─────────────────────────────────────────────────────────────────────────────
#[tokio::test(flavor = "multi_thread")]
async fn sys_ac_147_reconcile_completed_plus_index_rebuild_events() {
    let sut = SystemUnderTest::builder()
        .caps(&[Cap::Fs])
        .with_sqlite_index()
        .build(J01_SKELETON)
        .await;
    let dir = sut.workspace_root().join("seed147");
    std::fs::create_dir_all(&dir).unwrap();
    mark_territory(&dir); // so the rebuild indexes its files → content_rows > 0

    // 3-part corruption seed (the reconcile_existing_meta branch drives ALL THREE
    // counters): (a) added147.md on disk, not in meta → entries_added; (c)
    // repair147.md present with an EMPTY required description → fields_repaired; (b)
    // stale147.md in meta but absent on disk → entries_removed.
    std::fs::write(dir.join("added147.md"), b"added zebra content").unwrap();
    std::fs::write(dir.join("repair147.md"), b"repair body content").unwrap();
    let mut root = Mapping::new();
    let mut scope = Mapping::new();
    scope.insert(Value::from("description"), Value::from("seed147 scope"));
    root.insert(Value::from("_scope"), Value::Mapping(scope));
    root.insert(Value::from("repair147.md"), entry("repair147.md", "")); // empty required desc
    root.insert(
        Value::from("stale147.md"),
        entry("stale147.md", "stale entry, no file"),
    );
    std::fs::write(
        dir.join(".meta.yaml"),
        serde_yml::to_string(&Value::Mapping(root)).unwrap(),
    )
    .unwrap();

    let report = sut.boot_reconcile().await;

    // fs.reconcile_completed: non-zero entries_added / entries_removed / fields_repaired.
    let evs = sut.events();
    let rc = evs
        .iter()
        .find(|e| e.event_type == "fs.reconcile_completed")
        .expect("fs.reconcile_completed emitted");
    let p = &rc.payload["ReconcileCompleted"];
    assert!(
        p["entries_added"].as_u64().unwrap() > 0,
        "entries_added > 0 (added147.md)"
    );
    assert!(
        p["entries_removed"].as_u64().unwrap() > 0,
        "entries_removed > 0 (stale147.md)"
    );
    assert!(
        p["fields_repaired"].as_u64().unwrap() > 0,
        "fields_repaired > 0 (repair147.md empty description)"
    );

    // runtime.index_rebuild: total_files == rebuild content_rows, total_dirs ==
    // reconcile dirs_scanned — asserted against the RETURNED report (non-vacuous).
    let ir = evs
        .iter()
        .find(|e| e.event_type == "runtime.index_rebuild")
        .expect("runtime.index_rebuild emitted on the successful-rebuild branch");
    let rb = report
        .rebuild_report
        .as_ref()
        .expect("rebuild ran (rebuild_report Some)");
    assert_eq!(
        ir.payload["total_files"].as_u64().unwrap(),
        rb.content_rows,
        "total_files == rebuild content_rows"
    );
    assert_eq!(
        ir.payload["total_dirs"].as_u64().unwrap(),
        report.dirs_scanned,
        "total_dirs == reconcile dirs_scanned"
    );
    assert!(
        rb.content_rows > 0,
        "the seeded territory's files were indexed (content_rows > 0)"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// SYS-AC-148: a recall after boot returns on-disk-truth — newly added file findable;
// removed entry no longer returned.
// ─────────────────────────────────────────────────────────────────────────────
#[tokio::test(flavor = "multi_thread")]
async fn sys_ac_148_recall_after_boot_returns_on_disk_truth() {
    let sut = SystemUnderTest::builder()
        .caps(&[Cap::Fs])
        .with_sqlite_index()
        .build(J01_SKELETON)
        .await;
    let dir = sut.workspace_root().join("seed148");
    std::fs::create_dir_all(&dir).unwrap();
    mark_territory(&dir);
    let agent = "seed148"; // derive_agent_id(ws, <ws>/seed148)

    // Seed two indexed files (both in meta + on disk).
    std::fs::write(dir.join("findme.md"), b"findme148zebra keepword").unwrap();
    std::fs::write(dir.join("goneme.md"), b"goneme148yak removeword").unwrap();
    let mut root = Mapping::new();
    let mut scope = Mapping::new();
    scope.insert(Value::from("description"), Value::from("seed148 scope"));
    root.insert(Value::from("_scope"), Value::Mapping(scope));
    root.insert(
        Value::from("findme.md"),
        entry("findme.md", "a findable row"),
    );
    root.insert(
        Value::from("goneme.md"),
        entry("goneme.md", "a soon-removed row"),
    );
    std::fs::write(
        dir.join(".meta.yaml"),
        serde_yml::to_string(&Value::Mapping(root)).unwrap(),
    )
    .unwrap();

    // Boot 1: both indexed + recall-able (establishes goneme WAS returnable).
    sut.boot_reconcile().await;
    assert!(
        sut.fts_recall(agent, "findme148zebra")
            .await
            .iter()
            .any(|r| r.file_path.as_deref() == Some("/seed148/findme.md")),
        "findme indexed after boot 1"
    );
    assert!(
        sut.fts_recall(agent, "goneme148yak")
            .await
            .iter()
            .any(|r| r.file_path.as_deref() == Some("/seed148/goneme.md")),
        "goneme indexed after boot 1"
    );

    // Corrupt disk: delete goneme.md (→ stale meta entry) + add newme.md (→ not in meta).
    std::fs::remove_file(dir.join("goneme.md")).unwrap();
    std::fs::write(dir.join("newme.md"), b"newme148quetzal addword").unwrap();

    // Boot 2: reconcile drops goneme from meta + rebuild reindexes on-disk truth.
    sut.boot_reconcile().await;

    assert!(
        sut.fts_recall(agent, "newme148quetzal")
            .await
            .iter()
            .any(|r| r.file_path.as_deref() == Some("/seed148/newme.md")),
        "newly added file findable after boot 2"
    );
    assert!(
        sut.fts_recall(agent, "findme148zebra")
            .await
            .iter()
            .any(|r| r.file_path.as_deref() == Some("/seed148/findme.md")),
        "kept file still findable"
    );
    assert!(
        sut.fts_recall(agent, "goneme148yak").await.is_empty(),
        "removed entry no longer returned (on-disk truth)"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// SYS-AC-233: a boot reconcile/rebuild whose source contains malformed per-row
// entries still completes in degraded mode — the offending rows are recorded in the
// rebuild report's errors and skipped (rebuild does not abort), and a recall after
// boot still returns the rows that scanned cleanly.
//
// The malformation is a per-row control-char entry_name whose FILE EXISTS on disk:
// cap-fs reconcile sees no drift (the file is present, fields populated) so it does
// NOT rewrite/heal the .meta.yaml (reconcile.rs:534 — write only when `changed`),
// and the M004 rebuild SCANNER rejects the control-char key (id_component_safe /
// rebuild.rs:768) into RebuildReport.errors while still indexing the clean row.
// ─────────────────────────────────────────────────────────────────────────────
#[tokio::test(flavor = "multi_thread")]
async fn sys_ac_233_degraded_reconcile_skips_bad_rows_keeps_clean() {
    let sut = SystemUnderTest::builder()
        .caps(&[Cap::Fs])
        .with_sqlite_index()
        .build(J01_SKELETON)
        .await;
    let dir = sut.workspace_root().join("seed233");
    std::fs::create_dir_all(&dir).unwrap();
    mark_territory(&dir);
    let agent = "seed233";

    let bad_name = "bad\u{1f}row.md"; // C0 control char (U+001F) in the entry_name
    std::fs::write(dir.join("clean233.md"), b"clean233recallword zebra").unwrap();
    std::fs::write(dir.join(bad_name), b"bad row body").unwrap();
    let mut root = Mapping::new();
    let mut scope = Mapping::new();
    scope.insert(Value::from("description"), Value::from("seed233 scope"));
    root.insert(Value::from("_scope"), Value::Mapping(scope));
    root.insert(
        Value::from("clean233.md"),
        entry("clean233.md", "a clean row"),
    );
    // Both entries are "clean" from reconcile's view (file exists + description set) →
    // no drift → reconcile does not rewrite → the control-char key survives to the
    // rebuild scanner.
    root.insert(
        Value::from(bad_name),
        entry(bad_name, "a malformed-key row"),
    );
    std::fs::write(
        dir.join(".meta.yaml"),
        serde_yml::to_string(&Value::Mapping(root)).unwrap(),
    )
    .unwrap();

    let report = sut.boot_reconcile().await;

    // Rebuild completed (did NOT abort) in degraded mode.
    let rb = report
        .rebuild_report
        .as_ref()
        .expect("rebuild ran to completion (degraded, not aborted)");
    // The offending control-char row is recorded in the NESTED rebuild report's errors
    // (reconcile does NOT merge these into the top-level ReconcileReport.errors).
    assert!(
        rb.errors
            .iter()
            .any(|e| e.contains("control chars") || e.contains("\u{1f}")),
        "offending malformed row recorded in rebuild_report.errors; got {:?}",
        rb.errors
    );

    // The clean row still scanned + is recall-able after boot.
    assert!(
        sut.fts_recall(agent, "clean233recallword")
            .await
            .iter()
            .any(|r| r.file_path.as_deref() == Some("/seed233/clean233.md")),
        "clean row still indexed + recall-able in degraded mode"
    );
}
