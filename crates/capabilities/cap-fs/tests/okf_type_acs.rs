//! MODULE-002 AC-18 (OKF entity `type`) + AC-19 (`index.md` non-dependency)
//! integration tests — MODULE-002-T54..T63 (T64 lives in the advance-database
//! crate). ADR `docs/adr/2026-06-29-okf-compatibility-metadata-type.md`
//! Decisions 1–2.
//!
//! Each test builds its own ephemeral fixture (no shared state).

mod common;

use std::path::Path;
use std::sync::Arc;
use std::time::Instant;

use advance_runtime::host_registry::{HostCallContext, HostFunctionHandler};
use advance_shared_types::traits::{AgentTreeSnapshot, EventBusEmit};
use cap_fs::{
    is_reconciler_skipped_name, DefaultAtomicWriter, DefaultVirtualPathResolver, FsScanHandler,
    MetaFile, MetaMaintainer, MetaSchemaLoader, VirtualPathResolver, WorkspaceReconciler,
    DEFAULT_MAX_LIST_ENTRIES,
};
use wasmtime::component::Val;

use common::{single_agent_tree, TestEmitter};

const TRACE_ID: &str = "tr-okf";

fn ctx_for(agent_id: &str) -> HostCallContext {
    HostCallContext {
        agent_id: agent_id.into(),
        trace_id: TRACE_ID.into(),
        turn_id: None,
        capability: "fs".into(),
        function: "advance:runtime/agent-fs::test".into(),
        run_id: None,
        iteration: None,
    }
}

fn schema_loader_for(tempdir_path: &Path) -> Arc<MetaSchemaLoader> {
    Arc::new(MetaSchemaLoader::new_with_default(
        tempdir_path.join("schema.yaml"),
    ))
}

fn maintainer_for(tempdir_path: &Path) -> Arc<MetaMaintainer> {
    Arc::new(MetaMaintainer::new(
        schema_loader_for(tempdir_path),
        Arc::new(DefaultAtomicWriter),
    ))
}

fn make_reconciler(workspace_root: std::path::PathBuf, tempdir_path: &Path) -> WorkspaceReconciler {
    let schema = schema_loader_for(tempdir_path);
    let maintainer = Arc::new(MetaMaintainer::new(
        Arc::clone(&schema),
        Arc::new(DefaultAtomicWriter),
    ));
    WorkspaceReconciler::new(
        workspace_root,
        schema,
        maintainer,
        None,
        Arc::new(TestEmitter::new()) as Arc<dyn EventBusEmit>,
    )
}

/// Load the reconciled `.meta.yaml` at `dir` (fresh maintainer reads on-disk).
async fn load_meta(tempdir_path: &Path, dir: &Path) -> MetaFile {
    maintainer_for(tempdir_path)
        .load(dir)
        .await
        .unwrap()
        .expect("expected a .meta.yaml at dir")
}

fn entry_type<'a>(meta: &'a MetaFile, name: &str) -> &'a str {
    &meta
        .entries
        .get(name)
        .unwrap_or_else(|| panic!("no entry {name}"))
        .r#type
}

// ─────────────────────────────────────────────────────────────────────────────
// MODULE-002-T54 — add_entry_for_write file-default types round-trip to disk.
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn t54_add_entry_types_serialize_to_meta_yaml() {
    let tempdir = tempfile::TempDir::new().unwrap();
    let dir = tempdir.path().join("d");
    std::fs::create_dir_all(&dir).unwrap();
    let mm = maintainer_for(tempdir.path());

    let mut meta = MetaFile::default();
    for (name, body) in [
        ("roadmap.md", b"---\ntype: project\n---\n# R\n".as_slice()),
        ("notes.md", b"# just a heading\n".as_slice()),
        ("photo.png", &[0xFFu8, 0xD8][..]),
    ] {
        let (next, _) = mm
            .add_entry_for_write(Some(meta.clone()), name, body)
            .unwrap();
        meta = next;
    }
    mm.write(&dir, &meta).await.unwrap();

    let loaded = load_meta(tempdir.path(), &dir).await;
    assert_eq!(entry_type(&loaded, "roadmap.md"), "project");
    assert_eq!(entry_type(&loaded, "notes.md"), "document");
    assert_eq!(entry_type(&loaded, "photo.png"), "asset");
    let raw = std::fs::read_to_string(dir.join(".meta.yaml")).unwrap();
    assert!(raw.contains("type: project"));
    assert!(raw.contains("type: document"));
    assert!(raw.contains("type: asset"));
}

// ─────────────────────────────────────────────────────────────────────────────
// MODULE-002-T55 — fs.write first-materialization: scope.type defaults to
// `collection` even on the add_entry_for_write(None) path (r4 W).
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn t55_first_materialized_scope_type_is_collection() {
    let tempdir = tempfile::TempDir::new().unwrap();
    let dir = tempdir.path().join("fresh");
    std::fs::create_dir_all(&dir).unwrap();
    let mm = maintainer_for(tempdir.path());

    // meta_pre = None → unwrap_or_default() → MetaFile::default() → ScopeMeta::default().
    let (meta, _) = mm.add_entry_for_write(None, "notes.md", b"hi").unwrap();
    assert_eq!(meta.scope.r#type.as_deref(), Some("collection"));
    mm.write(&dir, &meta).await.unwrap();

    let loaded = load_meta(tempdir.path(), &dir).await;
    assert_eq!(loaded.scope.r#type.as_deref(), Some("collection"));
    let raw = std::fs::read_to_string(dir.join(".meta.yaml")).unwrap();
    assert!(raw.contains("type: collection"));
}

// ─────────────────────────────────────────────────────────────────────────────
// MODULE-002-T56 — reconcile a real on-disk subdir + frontmatter .md + plain .md
// + .png, NONE listed in .meta.yaml → collection / value / document / asset.
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn t56_reconcile_types_new_entries_from_defaults_table() {
    let tempdir = tempfile::TempDir::new().unwrap();
    let ws = tempdir.path().to_path_buf();
    std::fs::create_dir_all(ws.join("subdir")).unwrap();
    std::fs::write(ws.join("roadmap.md"), b"---\ntype: project\n---\n# R\n").unwrap();
    std::fs::write(ws.join("notes.md"), b"# plain notes\n").unwrap();
    std::fs::write(ws.join("photo.png"), [0xFFu8, 0xD8]).unwrap();

    make_reconciler(ws.clone(), tempdir.path())
        .reconcile("/", "t56")
        .await
        .unwrap();

    let meta = load_meta(tempdir.path(), &ws).await;
    assert_eq!(entry_type(&meta, "subdir"), "collection");
    assert_eq!(entry_type(&meta, "roadmap.md"), "project");
    assert_eq!(entry_type(&meta, "notes.md"), "document");
    assert_eq!(entry_type(&meta, "photo.png"), "asset");
    // The scope itself is a directory → collection.
    assert_eq!(meta.scope.r#type.as_deref(), Some("collection"));
}

// ─────────────────────────────────────────────────────────────────────────────
// MODULE-002-T57 — reconcile repair: EXISTING empty-type entries backfilled;
// a pre-set `type: project` PRESERVED; persisted to disk; sidecar untouched.
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn t57_reconcile_backfills_empty_type_and_preserves_override() {
    let tempdir = tempfile::TempDir::new().unwrap();
    let ws = tempdir.path().to_path_buf();
    std::fs::create_dir_all(ws.join("sub")).unwrap(); // an on-disk subdirectory
                                                      // On-disk files.
    std::fs::write(ws.join("a.md"), b"body").unwrap();
    std::fs::write(ws.join("b.md"), b"body").unwrap();
    // Hand-crafted .meta.yaml: a.md + the `sub` dir entry have an EMPTY type
    // (drift), b.md has a user override `type: project`.
    let yaml = "_scope:\n  description: root\n\
        a.md:\n  name: a.md\n  slug: a\n  description: A\n  type: \"\"\n\
        sub:\n  name: sub\n  slug: sub\n  description: S\n  type: \"\"\n\
        b.md:\n  name: b.md\n  slug: b\n  description: B\n  type: project\n";
    std::fs::write(ws.join(".meta.yaml"), yaml).unwrap();
    // A cap-skills-style sidecar under the reconciler skip-set — must be untouched.
    std::fs::create_dir_all(ws.join(".agent/skills/foo")).unwrap();
    let sidecar = ws.join(".agent/skills/foo/.meta.yaml");
    std::fs::write(&sidecar, "deny_unknown_fields_would_reject_type\n").unwrap();

    let report = make_reconciler(ws.clone(), tempdir.path())
        .reconcile("/", "t57")
        .await
        .unwrap();
    assert!(report.fields_repaired >= 1);

    let meta = load_meta(tempdir.path(), &ws).await;
    assert_eq!(entry_type(&meta, "a.md"), "document"); // empty .md backfilled
    assert_eq!(entry_type(&meta, "sub"), "collection"); // empty dir → collection
    assert_eq!(entry_type(&meta, "b.md"), "project"); // override preserved
                                                      // The write actually persisted (r3 W1 — not discarded).
    let raw = std::fs::read_to_string(ws.join(".meta.yaml")).unwrap();
    assert!(raw.contains("type: document"));
    // The `.agent/skills/**` sidecar is byte-identical (never walked).
    assert_eq!(
        std::fs::read_to_string(&sidecar).unwrap(),
        "deny_unknown_fields_would_reject_type\n"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// MODULE-002-T58 — hardened head-read: a .md-named FIFO never blocks reconcile.
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t58_reconcile_does_not_block_on_md_fifo() {
    let tempdir = tempfile::TempDir::new().unwrap();
    let ws = tempdir.path().to_path_buf();
    std::fs::create_dir_all(&ws).unwrap();
    // A `.md`-named FIFO missing `type` — a plain open() would block until a
    // writer appears. The hardened O_NOFOLLOW|O_NONBLOCK + fstat must reject it.
    let fifo = ws.join("note.md");
    let status = std::process::Command::new("mkfifo")
        .arg(&fifo)
        .status()
        .expect("failed to spawn mkfifo");
    assert!(status.success(), "mkfifo failed");

    // Bound the whole reconcile so a regression (blocking open) fails loudly
    // rather than hanging the test suite.
    let reconciler = make_reconciler(ws.clone(), tempdir.path());
    let report = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        reconciler.reconcile("/", "t58"),
    )
    .await
    .expect("reconcile blocked on the FIFO open() — hardening regression")
    .unwrap();
    assert!(report.dirs_scanned >= 1);

    // The FIFO entry falls back to `document` (non-regular → None frontmatter).
    let meta = load_meta(tempdir.path(), &ws).await;
    assert_eq!(entry_type(&meta, "note.md"), "document");
}

// ─────────────────────────────────────────────────────────────────────────────
// MODULE-002-T59 — ensure_dir_meta parent-leg: the subdir CHILD entry is typed
// `collection` (r5 W), and a scan of the parent exposes it.
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn t59_ensure_dir_meta_parent_leg_types_child_collection() {
    let tempdir = tempfile::TempDir::new().unwrap();
    let parent = tempdir.path().join("parent");
    let subdir = parent.join("topic-a");
    std::fs::create_dir_all(&subdir).unwrap();
    let mm = maintainer_for(tempdir.path());

    mm.ensure_dir_meta(&subdir, Some(&parent)).await.unwrap();

    let parent_meta = load_meta(tempdir.path(), &parent).await;
    assert_eq!(
        entry_type(&parent_meta, "topic-a"),
        "collection",
        "the subdir child entry must be typed collection, not asset"
    );

    // And a scan of `parent` exposes child `topic-a` type == collection.
    let resolver = Arc::new(DefaultVirtualPathResolver::new(
        tempdir.path().to_path_buf(),
        Arc::new(single_agent_tree("parent", parent.clone())) as Arc<dyn AgentTreeSnapshot>,
    ));
    let handler = FsScanHandler {
        resolver: resolver as Arc<dyn VirtualPathResolver>,
        emitter: Arc::new(TestEmitter::new()) as Arc<dyn EventBusEmit>,
        concurrency: common::test_concurrency(),
        maintainer: mm,
        max_entries: DEFAULT_MAX_LIST_ENTRIES,
    };
    let out = handler
        .call(ctx_for("parent"), vec![Val::String(".".into())], 1)
        .await
        .unwrap();
    assert_eq!(scan_child_type(&out, "topic-a"), "collection");
}

// ─────────────────────────────────────────────────────────────────────────────
// MODULE-002-T60 — scan child + scope `type` exposure through CONTRACT-010,
// incl. the [pending] (absent-from-meta) and Some-branch (empty) fallbacks.
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn t60_scan_exposes_child_and_scope_type() {
    let tempdir = tempfile::TempDir::new().unwrap();
    let ws = tempdir.path().to_path_buf();
    let agent_ws = ws.join("agent");
    std::fs::create_dir_all(agent_ws.join("subdir")).unwrap();
    std::fs::write(agent_ws.join("photo.png"), [0u8, 1]).unwrap();
    std::fs::write(agent_ws.join("empty.md"), b"body").unwrap();
    // A `.meta.yaml` where `empty.md` is present but has an EMPTY type (drift),
    // exercising the build_scan_result Some-branch fallback. `subdir`/`photo.png`
    // are ABSENT from meta → the [pending]/None fallback.
    let yaml = "_scope:\n  description: agent\n\
        empty.md:\n  name: empty.md\n  slug: empty\n  description: E\n  type: \"\"\n";
    std::fs::write(agent_ws.join(".meta.yaml"), yaml).unwrap();

    let resolver = Arc::new(DefaultVirtualPathResolver::new(
        ws.clone(),
        Arc::new(single_agent_tree("agent", agent_ws.clone())) as Arc<dyn AgentTreeSnapshot>,
    ));
    let handler = FsScanHandler {
        resolver: resolver as Arc<dyn VirtualPathResolver>,
        emitter: Arc::new(TestEmitter::new()) as Arc<dyn EventBusEmit>,
        concurrency: common::test_concurrency(),
        maintainer: maintainer_for(tempdir.path()),
        max_entries: DEFAULT_MAX_LIST_ENTRIES,
    };
    let out = handler
        .call(ctx_for("agent"), vec![Val::String(".".into())], 1)
        .await
        .unwrap();

    // Absent-from-meta subdir → collection via the [pending] is_dir fallback.
    assert_eq!(scan_child_type(&out, "subdir"), "collection");
    // Absent-from-meta .png → asset.
    assert_eq!(scan_child_type(&out, "photo.png"), "asset");
    // Metaed-but-empty-type .md → non-empty via the Some-branch fallback.
    assert_eq!(scan_child_type(&out, "empty.md"), "document");
    // scope-meta.type == collection (directory scope), and has-agent unchanged.
    assert_eq!(scan_scope_type(&out), Some("collection".to_string()));
    assert_has_agent_positional_intact(&out);
}

// ─────────────────────────────────────────────────────────────────────────────
// MODULE-002-T61 — .md-heavy reconcile SLA: time only reconcile(), bound at the
// literal §1.6 <5s/10K proportional target.
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn t61_reconcile_md_heavy_within_sla() {
    let tempdir = tempfile::TempDir::new().unwrap();
    let ws = tempdir.path().to_path_buf();
    std::fs::create_dir_all(&ws).unwrap();
    // N .md files all missing `type` → the hardened head-read fires per entry.
    const N: usize = 2000;
    for i in 0..N {
        std::fs::write(
            ws.join(format!("f{i}.md")),
            b"---\ntype: note\n---\n# body\n",
        )
        .unwrap();
    }
    let reconciler = make_reconciler(ws.clone(), tempdir.path());
    let start = Instant::now();
    reconciler.reconcile("/", "t61").await.unwrap();
    let elapsed = start.elapsed();
    // GROSS-regression guard (audit r7): the proportional §1.6 target is 1s for
    // N=2000 (5s/10K). A hard-1s wall-clock bound flakes on loaded/shared CI, so
    // we use a 3× CI-jitter budget (3s) — still catches a gross SLA regression
    // (full-body reads, O(N²), or the head-read cap being bypassed, all of which
    // push well past 3× the target), while the PRECISE SLA compliance rests on
    // the bounded head-read design (MAX_FRONTMATTER_HEAD_BYTES) + the t53
    // bounded-parser unit tests rather than this wall-clock witness alone.
    let budget = std::time::Duration::from_millis((N as u64 * 5000 * 3) / 10_000);
    assert!(
        elapsed <= budget,
        "reconcile of {N} .md files took {elapsed:?}, exceeds gross-regression budget {budget:?}"
    );
    // And the frontmatter type was actually read (not the head-read being skipped).
    let meta = load_meta(tempdir.path(), &ws).await;
    assert_eq!(entry_type(&meta, "f0.md"), "note");
}

// ─────────────────────────────────────────────────────────────────────────────
// MODULE-002-T62 — AC-19: index.md / log.md are NOT reconciler-skipped.
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn t62_index_and_log_md_are_not_skipped() {
    assert!(!is_reconciler_skipped_name("index.md"));
    assert!(!is_reconciler_skipped_name("log.md"));
}

// ─────────────────────────────────────────────────────────────────────────────
// MODULE-002-T63 — AC-19: reconcile treats index.md/log.md as ordinary entries;
// the maintainer never creates an index.md.
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn t63_reconcile_treats_index_md_as_ordinary_content() {
    let tempdir = tempfile::TempDir::new().unwrap();
    let ws = tempdir.path().to_path_buf();
    std::fs::create_dir_all(&ws).unwrap();
    std::fs::write(ws.join("index.md"), b"# Index\nnav").unwrap();
    std::fs::write(ws.join("log.md"), b"# Log").unwrap();
    std::fs::write(ws.join("notes.md"), b"# Notes").unwrap();

    make_reconciler(ws.clone(), tempdir.path())
        .reconcile("/", "t63")
        .await
        .unwrap();

    let meta = load_meta(tempdir.path(), &ws).await;
    // index.md / log.md are ordinary `document` entries.
    assert_eq!(entry_type(&meta, "index.md"), "document");
    assert_eq!(entry_type(&meta, "log.md"), "document");
    assert_eq!(entry_type(&meta, "notes.md"), "document");
    // The only file the maintainer creates is `.meta.yaml` — never an index.md
    // beyond the one the user placed. (No NEW index.md was fabricated: exactly
    // the one we wrote exists, with its original content.)
    assert_eq!(
        std::fs::read_to_string(ws.join("index.md")).unwrap(),
        "# Index\nnav"
    );
    assert!(ws.join(".meta.yaml").exists());
}

// ─── scan-result decode helpers ─────────────────────────────────────────────

fn scan_record(out: &[Val]) -> &Vec<(String, Val)> {
    assert_eq!(out.len(), 1);
    let inner = match &out[0] {
        Val::Result(Ok(Some(inner))) => inner.as_ref(),
        other => panic!("expected Ok(Some(ScanResult)), got {other:?}"),
    };
    match inner {
        Val::Record(r) => r,
        other => panic!("expected ScanResult record, got {other:?}"),
    }
}

fn field<'a>(rec: &'a [(String, Val)], key: &str) -> &'a Val {
    rec.iter()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v)
        .unwrap_or_else(|| panic!("missing field {key}"))
}

fn scan_child_type(out: &[Val], name: &str) -> String {
    let rec = scan_record(out);
    let children = match field(rec, "children") {
        Val::List(items) => items,
        _ => panic!("children not a List"),
    };
    for child in children {
        if let Val::Record(fields) = child {
            let cname = match field(fields, "name") {
                Val::String(s) => s.as_str(),
                _ => continue,
            };
            if cname == name {
                return match field(fields, "type") {
                    Val::String(s) => s.clone(),
                    other => panic!("child type not a String: {other:?}"),
                };
            }
        }
    }
    panic!("child {name} not found in scan result");
}

fn scan_scope_type(out: &[Val]) -> Option<String> {
    let rec = scan_record(out);
    let scope = match field(rec, "scope") {
        Val::Record(s) => s,
        _ => panic!("scope not a Record"),
    };
    match field(scope, "type") {
        Val::Option(Some(inner)) => match inner.as_ref() {
            Val::String(s) => Some(s.clone()),
            _ => panic!("scope type inner not String"),
        },
        Val::Option(None) => None,
        other => panic!("scope type not an Option: {other:?}"),
    }
}

/// Assert every child's has-agent field is still at positional index 4 (the
/// append-last `type` did not shift it).
fn assert_has_agent_positional_intact(out: &[Val]) {
    let rec = scan_record(out);
    let children = match field(rec, "children") {
        Val::List(items) => items,
        _ => panic!("children not a List"),
    };
    for child in children {
        if let Val::Record(fields) = child {
            assert_eq!(fields[4].0, "has-agent", "has-agent must stay at index 4");
            assert_eq!(fields[5].0, "type", "type must be appended last at index 5");
        }
    }
}
