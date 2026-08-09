//! Integration witnesses for the slice m011-memory-persist persistence backend
//! (MODULE-011 §3.3 T43–T49 / AC-40 / AC-41 / AC-42).
//!
//! - AC-40: knowledge.jsonl on-disk persistence via `MemoryStore::open` (append
//!   + atomic rewrite + cross-restart hydration + corrupt-line fail-loud).
//! - AC-41: durable rusqlite `SqliteIndex` round-trip across reopen.
//! - AC-42: real `Z`-form `created_at` via a `Clock` injected into
//!   `RememberHandler`, and `recall_at` time-filtering by it.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use advance_runtime::host_registry::{HostCallContext, HostFunctionHandler};
use cap_memory::knowledge::{MemoryEntry, MemoryStatus, MemoryType};
use cap_memory::{
    InMemorySqliteIndex, MemoryIndexRow, MemoryStore, MutableClock, NoopEventBus,
    RusqliteSqliteIndex, SqliteIndex, TaskIndexRow, TurnIndexRow,
};
use wasmtime::component::Val;

fn fact(id: &str, agent: &str, content: &str, created_at: &str) -> MemoryEntry {
    MemoryEntry {
        id: id.into(),
        agent_id: agent.into(),
        entry_type: MemoryType::Fact,
        content: content.into(),
        tags: vec![],
        created_at: created_at.into(),
        task_origin: None,
        is_active: true,
        superseded_by: None,
        status: MemoryStatus::Active,
        supersession_reason: None,
        cluster_id: None,
        sources: vec![],
    }
}

const MAX: usize = cap_memory::DEFAULT_MAX_ACTIVE_PER_AGENT;

// ───────────────────────── AC-40: knowledge.jsonl ─────────────────────────

/// T43 — persist + recall across a store drop+reopen; per-agent isolation;
/// fresh agent empty; a per-agent knowledge.jsonl materializes on disk.
#[test]
fn t43_persist_recall_across_restart() {
    let dir = tempfile::tempdir().unwrap();
    {
        let store = MemoryStore::open(dir.path(), MAX).expect("open");
        store
            .insert(
                "agent:a",
                fact("f1", "agent:a", "Rust is fast", "2026-01-01T00:00:00Z"),
            )
            .expect("insert");
        // A per-agent knowledge.jsonl exists somewhere under the root.
        let found = walk_for_knowledge_jsonl(dir.path());
        assert!(found, "a knowledge.jsonl must materialize under the root");
        assert_eq!(store.recall("agent:a", "rust", 10).len(), 1);
        assert!(
            store.recall("agent:b", "rust", 10).is_empty(),
            "no cross-agent leak"
        );
    }
    // Reopen the SAME dir: the entry is still recall-able (cross-restart).
    let store2 = MemoryStore::open(dir.path(), MAX).expect("reopen");
    let hits = store2.recall("agent:a", "rust", 10);
    assert_eq!(hits.len(), 1, "entry survives restart");
    assert_eq!(hits[0].id, "f1");
    // A fresh agent starts empty.
    assert!(
        store2.recall("agent:c", "", 10).is_empty(),
        "fresh agent empty"
    );
}

/// T44 — every mutation kind survives a reopen with the correct post-state.
#[test]
fn t44_mutations_persist_across_reopen() {
    let dir = tempfile::tempdir().unwrap();
    // forget → excluded after reopen.
    {
        let store = MemoryStore::open(dir.path(), MAX).unwrap();
        store
            .insert(
                "agent:a",
                fact("f1", "agent:a", "hello", "2026-01-01T00:00:00Z"),
            )
            .unwrap();
        store.forget("agent:a", "f1").unwrap();
    }
    {
        let store = MemoryStore::open(dir.path(), MAX).unwrap();
        assert!(
            store.recall("agent:a", "hello", 10).is_empty(),
            "forgotten excluded after reopen"
        );
        let direct = store.get("agent:a", "f1").expect("entry still present");
        assert!(!direct.is_active);
        assert_eq!(direct.status, MemoryStatus::Forgotten);
    }

    // supersede → old superseded + new active after reopen.
    let dir2 = tempfile::tempdir().unwrap();
    {
        let store = MemoryStore::open(dir2.path(), MAX).unwrap();
        store
            .insert(
                "agent:a",
                fact("o1", "agent:a", "v1", "2026-01-01T00:00:00Z"),
            )
            .unwrap();
        store
            .apply_action(
                "agent:a",
                cap_memory::MemoryAction::Supersede {
                    old_id: "o1".into(),
                    new_entry: fact("n1", "agent:a", "v2", "2026-02-01T00:00:00Z"),
                    reason: cap_memory::SupersessionReason::Refinement,
                },
            )
            .unwrap();
    }
    {
        let store = MemoryStore::open(dir2.path(), MAX).unwrap();
        let old = store.get("agent:a", "o1").expect("old present");
        assert_eq!(old.status, MemoryStatus::Superseded);
        assert!(!old.is_active);
        assert_eq!(old.superseded_by.as_deref(), Some("n1"));
        let new = store.get("agent:a", "n1").expect("new present");
        assert!(new.is_active);
        assert_eq!(new.status, MemoryStatus::Active);
    }

    // rollback(ts) → entries with created_at > ts gone after reopen.
    let dir3 = tempfile::tempdir().unwrap();
    {
        let store = MemoryStore::open(dir3.path(), MAX).unwrap();
        store
            .insert(
                "agent:a",
                fact("e", "agent:a", "early", "2026-01-01T00:00:00Z"),
            )
            .unwrap();
        store
            .insert(
                "agent:a",
                fact("l", "agent:a", "late", "2026-06-01T00:00:00Z"),
            )
            .unwrap();
        assert_eq!(
            store.rollback("agent:a", "2026-03-01T00:00:00Z").unwrap(),
            1
        );
    }
    {
        let store = MemoryStore::open(dir3.path(), MAX).unwrap();
        let all = store.list("agent:a");
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].id, "e");
    }
}

/// T48 — a corrupt knowledge.jsonl line makes `open` fail loud.
#[test]
fn t48_corrupt_line_fails_loud() {
    let dir = tempfile::tempdir().unwrap();
    {
        let store = MemoryStore::open(dir.path(), MAX).unwrap();
        store
            .insert(
                "agent:a",
                fact("f1", "agent:a", "ok", "2026-01-01T00:00:00Z"),
            )
            .unwrap();
    }
    // Corrupt the on-disk file: append a non-JSON line to the (single) agent file.
    corrupt_some_knowledge_jsonl(dir.path());
    let err = MemoryStore::open(dir.path(), MAX);
    assert!(err.is_err(), "open must fail loud on a corrupt line");
}

/// T49 — `MemoryStore::new()` keeps the in-memory (None-backend) behaviour:
/// no on-disk file, recall round-trips in memory, and a separate `new()` store
/// does NOT see the first store's entries.
#[test]
fn t49_new_stays_in_memory() {
    let store = MemoryStore::new();
    store
        .insert(
            "agent:a",
            fact("f1", "agent:a", "x", "2026-01-01T00:00:00Z"),
        )
        .unwrap();
    assert_eq!(store.recall("agent:a", "x", 10).len(), 1);
    // A different in-memory store shares nothing.
    let other = MemoryStore::new();
    assert!(other.recall("agent:a", "x", 10).is_empty());
}

/// T-PERSIST cache==disk invariant: when a mutation's disk rewrite FAILS, the
/// in-memory mutation is rolled back (cache==disk) and the error propagates,
/// and the on-disk file is left intact. Forces failure by pre-creating the
/// `knowledge.jsonl.tmp` sibling as a DIRECTORY so `atomic_write`'s temp-file
/// open fails (EISDIR) before the real file is touched. (AC-40 persist-failure
/// path; unix-only.)
#[cfg(unix)]
#[test]
fn t_persist_failure_rolls_back_in_memory() {
    let dir = tempfile::tempdir().unwrap();
    let store = MemoryStore::open(dir.path(), MAX).unwrap();
    store
        .insert(
            "agent:a",
            fact("f1", "agent:a", "keep me", "2026-01-01T00:00:00Z"),
        )
        .unwrap();
    // Locate the per-agent subdir + its knowledge.jsonl, and block the rewrite
    // by occupying the temp path with a directory (open-for-write → EISDIR).
    let agent_dir = std::fs::read_dir(dir.path())
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| p.is_dir())
        .expect("agent dir exists");
    let tmp_blocker = agent_dir.join("knowledge.jsonl.tmp");
    std::fs::create_dir(&tmp_blocker).unwrap();

    // forget triggers a rewrite → must fail → in-memory entry restored (active).
    let r = store.forget("agent:a", "f1");
    assert!(r.is_err(), "forget must error when its rewrite fails");
    let hits = store.recall("agent:a", "keep", 10);
    assert_eq!(
        hits.len(),
        1,
        "cache==disk: failed forget rolled back in memory"
    );
    assert!(
        hits[0].is_active,
        "entry stays active after the rolled-back forget"
    );

    // Remove the blocker; on reopen the entry is still active on disk (the
    // rewrite never landed — the real knowledge.jsonl was never touched).
    std::fs::remove_dir(&tmp_blocker).unwrap();
    let store2 = MemoryStore::open(dir.path(), MAX).unwrap();
    let after = store2.recall("agent:a", "keep", 10);
    assert_eq!(
        after.len(),
        1,
        "on-disk entry still active (rewrite never happened)"
    );
    assert!(after[0].is_active);
}

// ───────────────────────── AC-41: rusqlite index ─────────────────────────

fn turn_row(agent: &str, task: &str, t: u32) -> TurnIndexRow {
    TurnIndexRow {
        agent_id: agent.into(),
        task_id: task.into(),
        turn: t,
        digest: format!("d-{t}"),
        embedding: vec![0.25_f32, -0.5, 1.0, 2.0, -3.0, 0.0, 4.5, 9.0],
        reference_count: 2,
        updated_at: "2026-06-06T00:00:00Z".into(),
    }
}

fn task_row(task: &str, agent: &str) -> TaskIndexRow {
    TaskIndexRow {
        task_id: task.into(),
        agent_id: agent.into(),
        last_turn_at: "2026-06-06T00:00:00Z".into(),
        turns_total: 4,
        updated_at: "2026-06-06T00:00:00Z".into(),
        brief_snapshot: "brief".into(),
        brief_embedding: Some(vec![1.0_f32, 2.0]),
    }
}

fn mem_row(agent: &str, id: &str, status: &str) -> MemoryIndexRow {
    MemoryIndexRow {
        agent_id: agent.into(),
        memory_id: id.into(),
        epistemic_status: status.into(),
        updated_at: "2026-06-06T00:00:00Z".into(),
    }
}

/// T46 — durable round-trip across an index drop+reopen (incl. embeddings).
#[test]
fn t46_rusqlite_durable_across_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("index.sqlite3");
    {
        let ix = RusqliteSqliteIndex::open(&db).expect("open index");
        ix.upsert_turn(turn_row("agent:r", "task-1", 3));
        ix.upsert_task(task_row("task-9", "agent:r"));
        ix.upsert_memory(mem_row("agent:r", "m-1", "contested"));
    }
    let ix2 = RusqliteSqliteIndex::open(&db).expect("reopen index");
    assert_eq!(
        ix2.get_turn("agent:r", "task-1", 3),
        Some(turn_row("agent:r", "task-1", 3))
    );
    assert_eq!(ix2.get_task("task-9"), Some(task_row("task-9", "agent:r")));
    assert_eq!(
        ix2.get_memory("agent:r", "m-1"),
        Some(mem_row("agent:r", "m-1", "contested"))
    );
}

/// T47 — parity with `InMemorySqliteIndex` semantics (upsert-overwrite, list
/// filters by agent, key disambiguation, missing → None).
#[test]
fn t47_rusqlite_parity_with_in_memory() {
    let dir = tempfile::tempdir().unwrap();
    let rusql = RusqliteSqliteIndex::open(dir.path().join("ix.sqlite3")).unwrap();
    let inmem = InMemorySqliteIndex::default();

    for ix in [&rusql as &dyn SqliteIndex, &inmem as &dyn SqliteIndex] {
        // upsert overwrites same key.
        ix.upsert_turn(turn_row("agent:r", "task-1", 1));
        let mut bumped = turn_row("agent:r", "task-1", 1);
        bumped.reference_count = 99;
        ix.upsert_turn(bumped.clone());
        assert_eq!(ix.get_turn("agent:r", "task-1", 1), Some(bumped));
        // list filters by agent; keys disambiguate.
        ix.upsert_turn(turn_row("agent:r", "task-2", 1));
        ix.upsert_turn(turn_row("agent:s", "task-1", 1));
        assert_eq!(ix.list_turns_for_agent("agent:r").len(), 2);
        assert_eq!(ix.list_turns_for_agent("agent:s").len(), 1);
        // missing → None.
        assert_eq!(ix.get_turn("agent:r", "task-1", 999), None);
        assert_eq!(ix.get_task("absent"), None);
        assert_eq!(ix.get_memory("agent:r", "absent"), None);
    }
}

// ───────────────────────── AC-42: real created_at ─────────────────────────

/// T45 — `RememberHandler::with_clock(MutableClock@T)` → the inserted entry's
/// `created_at` is a `Z`-form RFC3339 of T (not the 1970 epoch); a `Z`-form
/// `recall_at` query discriminates by it.
#[tokio::test]
async fn t45_real_created_at_via_clock() {
    use cap_memory::wit_impl::RememberHandler;

    // Fixed instant T = 1_781_078_400s after the epoch = 2026-06-10T08:00:00Z
    // (a deterministic, far-from-epoch time so the Z-form RFC3339 and the
    // recall_at discrimination are unambiguous).
    let t = SystemTime::UNIX_EPOCH + Duration::from_secs(1_781_078_400);
    let clock = Arc::new(MutableClock::new(t));
    let store = Arc::new(MemoryStore::new());
    let handler = RememberHandler::with_clock(store.clone(), Arc::new(NoopEventBus), clock);

    let ctx = ctx_for("agent:a");
    let params = vec![Val::String("remembered thing".into()), Val::List(vec![])];
    let out = handler.call(ctx, params, 1).await.expect("call ok");
    // Extract the returned memory id.
    let id = match &out[0] {
        Val::Result(Ok(Some(boxed))) => match boxed.as_ref() {
            Val::String(s) => s.clone(),
            other => panic!("unexpected ok payload: {other:?}"),
        },
        other => panic!("unexpected remember result: {other:?}"),
    };
    let entry = store.get("agent:a", &id).expect("entry stored");
    // created_at is the SECOND-granularity Z-form RFC3339 of T (matches the
    // knowledge.jsonl schema convention) — NOT epoch, NOT +00:00, NOT millis.
    assert_eq!(
        entry.created_at, "2026-06-10T08:00:00Z",
        "created_at is the second-granularity Z-form RFC3339 of T"
    );
    assert!(entry.created_at.ends_with('Z'), "Z-form");
    assert!(!entry.created_at.contains("+00:00"), "not the +00:00 form");
    assert!(
        !entry.created_at.contains('.'),
        "second-granularity, no fractional millis"
    );
    assert_ne!(
        entry.created_at, "1970-01-01T00:00:00Z",
        "not the epoch stub"
    );

    // recall_at with a Z-form query tightly bracketing T discriminates by the
    // REAL created_at (if it were the 1970 epoch, the "day before T" query
    // would WRONGLY include it). created_at = 2026-06-10T08:00:00.000Z.
    let before = "2026-06-09T00:00:00Z"; // day before T → entry absent as-of then
    let after = "2026-06-11T00:00:00Z"; //  day after T → entry present as-of then
    assert!(
        store.recall_at("agent:a", "", before, 10).is_empty(),
        "entry absent as-of a time before T (proves created_at > epoch)"
    );
    assert_eq!(
        store.recall_at("agent:a", "", after, 10).len(),
        1,
        "entry present as-of a time after T"
    );
}

// ───────────────────────────── helpers ─────────────────────────────

fn ctx_for(agent: &str) -> HostCallContext {
    HostCallContext {
        agent_id: agent.to_string(),
        trace_id: "trace-persist".to_string(),
        turn_id: None,
        capability: "memory".to_string(),
        function: "advance:runtime/agent-memory@0.1.0::remember".to_string(),
        run_id: None,
        iteration: None,
    }
}

fn walk_for_knowledge_jsonl(root: &std::path::Path) -> bool {
    for entry in std::fs::read_dir(root).unwrap() {
        let p = entry.unwrap().path();
        if p.is_dir() && p.join("knowledge.jsonl").is_file() {
            return true;
        }
    }
    false
}

fn corrupt_some_knowledge_jsonl(root: &std::path::Path) {
    use std::io::Write as _;
    for entry in std::fs::read_dir(root).unwrap() {
        let p = entry.unwrap().path();
        let file = p.join("knowledge.jsonl");
        if file.is_file() {
            let mut f = std::fs::OpenOptions::new()
                .append(true)
                .open(&file)
                .unwrap();
            f.write_all(b"{ not valid json\n").unwrap();
            return;
        }
    }
    panic!("no knowledge.jsonl found to corrupt");
}

// ───────────── retention / compaction (dev-task-mem-retention) ─────────────

fn forgotten_fact(id: &str, agent: &str, created_at: &str) -> MemoryEntry {
    let mut e = fact(id, agent, "x", created_at);
    e.is_active = false;
    e.status = MemoryStatus::Forgotten;
    e
}

/// The single per-agent `knowledge.jsonl` under `root` (the tests use exactly one
/// agent, so there is exactly one).
fn find_knowledge_jsonl(root: &std::path::Path) -> std::path::PathBuf {
    for entry in std::fs::read_dir(root).unwrap() {
        let p = entry.unwrap().path();
        let f = p.join("knowledge.jsonl");
        if p.is_dir() && f.is_file() {
            return f;
        }
    }
    panic!("no knowledge.jsonl under {}", root.display());
}

/// Materialize the agent's REAL (slug-derived) `knowledge.jsonl` path — by seeding
/// one entry through the store so the slug dir/file exist — then OVERWRITE that
/// file with `entries`. This guarantees that subsequent store operations
/// (`forget` / `insert`) and the open-time migration rewrite all act on the same
/// file (the store derives the path from a private slug, so a hand-named dir would
/// diverge). Returns the file path.
fn bloat_agent_file(
    root: &std::path::Path,
    agent_id: &str,
    entries: &[MemoryEntry],
) -> std::path::PathBuf {
    {
        let store = MemoryStore::open(root, MAX).unwrap();
        store
            .insert(agent_id, fact("__seed__", agent_id, "x", "t0"))
            .unwrap();
    }
    let file = find_knowledge_jsonl(root);
    let mut buf = String::new();
    for e in entries {
        buf.push_str(&serde_json::to_string(e).unwrap());
        buf.push('\n');
    }
    std::fs::write(&file, buf).unwrap();
    file
}

fn tmp_blocker(file: &std::path::Path) -> std::path::PathBuf {
    let mut t = file.as_os_str().to_owned();
    t.push(".tmp");
    std::path::PathBuf::from(t)
}

/// A pre-fix bloated file (1 active + > the inactive cap forgotten) is compacted
/// on first `open`: the in-memory inactive tail is bounded, the active entry is
/// preserved, the on-disk file shrinks, and a fresh reopen reproduces the set.
#[test]
fn t_open_migrates_prefix_bloated_file() {
    let n = cap_memory::DEFAULT_MAX_INACTIVE_PER_AGENT + 100;
    let mut entries = vec![fact("keep", "agent:a", "alive", "t0000000")];
    for i in 0..n {
        entries.push(forgotten_fact(
            &format!("g{i:07}"),
            "agent:a",
            &format!("t{i:07}"),
        ));
    }
    let dir = tempfile::tempdir().unwrap();
    let file = bloat_agent_file(dir.path(), "agent:a", &entries);
    let before = std::fs::metadata(&file).unwrap().len();

    let store = MemoryStore::open(dir.path(), MAX).unwrap();
    let all = store.list("agent:a");
    let inactive = all.iter().filter(|e| !e.is_active).count();
    assert!(
        inactive <= cap_memory::DEFAULT_MAX_INACTIVE_PER_AGENT,
        "inactive tail bounded on hydration: {inactive}"
    );
    assert!(
        all.iter().any(|e| e.id == "keep" && e.is_active),
        "active entry preserved"
    );
    let after = std::fs::metadata(&file).unwrap().len();
    assert!(
        after < before,
        "on-disk file shrank on migration: {after} < {before}"
    );

    let store2 = MemoryStore::open(dir.path(), MAX).unwrap();
    assert_eq!(
        store2.list("agent:a").len(),
        all.len(),
        "reopen reproduces the bounded set"
    );
}

/// Best-effort migration rewrite: when the open-time compaction rewrite FAILS
/// (blocked `.tmp`), `open` still SUCCEEDS with RAM-bounded buckets (no new boot
/// regression); the disk file stays bloated (self-corrects later).
#[cfg(unix)]
#[test]
fn t_open_compaction_rewrite_failure_is_best_effort() {
    let n = cap_memory::DEFAULT_MAX_INACTIVE_PER_AGENT + 50;
    let mut entries = vec![fact("keep", "agent:a", "alive", "t0000000")];
    for i in 0..n {
        entries.push(forgotten_fact(
            &format!("g{i:07}"),
            "agent:a",
            &format!("t{i:07}"),
        ));
    }
    let dir = tempfile::tempdir().unwrap();
    let file = bloat_agent_file(dir.path(), "agent:a", &entries);
    std::fs::create_dir(tmp_blocker(&file)).unwrap(); // EISDIR on the migration rewrite
    let before = std::fs::metadata(&file).unwrap().len();

    let store = MemoryStore::open(dir.path(), MAX)
        .expect("open succeeds despite a failed best-effort migration rewrite");
    let all = store.list("agent:a");
    assert!(
        all.iter().filter(|e| !e.is_active).count() <= cap_memory::DEFAULT_MAX_INACTIVE_PER_AGENT,
        "in-memory set is RAM-bounded"
    );
    assert!(all.iter().any(|e| e.id == "keep"), "active kept");
    assert_eq!(
        std::fs::metadata(&file).unwrap().len(),
        before,
        "disk stays bloated (best-effort rewrite never landed)"
    );
}

/// A TORN file's heal rewrite is MANDATORY: if it fails (blocked `.tmp`), `open`
/// fails loud — UNCHANGED from the prior behavior (correctness-critical heal).
#[cfg(unix)]
#[test]
fn t_open_torn_heal_rewrite_failure_still_fails_loud() {
    use std::io::Write as _;
    let dir = tempfile::tempdir().unwrap();
    let file = bloat_agent_file(dir.path(), "agent:a", &[fact("f1", "agent:a", "ok", "t1")]);
    // Append a torn (unterminated, unparseable) final line.
    let mut f = std::fs::OpenOptions::new()
        .append(true)
        .open(&file)
        .unwrap();
    f.write_all(b"{\"id\":\"torn").unwrap();
    drop(f);
    std::fs::create_dir(tmp_blocker(&file)).unwrap();
    assert!(
        MemoryStore::open(dir.path(), MAX).is_err(),
        "a torn file whose heal rewrite fails must fail loud"
    );
}

/// Determinism / cache==disk after a best-effort migration failure when the disk
/// is STILL unwritable: the pending agent's next `insert` attempts a reconcile
/// rewrite, which also fails → the insert errors gracefully (pre restored, no
/// partial write), and `memory == hydrate(disk)` still holds.
#[cfg(unix)]
#[test]
fn t_insert_while_still_blocked_errors_and_stays_consistent() {
    let n = cap_memory::DEFAULT_MAX_INACTIVE_PER_AGENT + 50;
    let mut entries = vec![fact("keep", "agent:a", "alive", "t0000000")];
    for i in 0..n {
        entries.push(forgotten_fact(
            &format!("g{i:07}"),
            "agent:a",
            &format!("t{i:07}"),
        ));
    }
    let dir = tempfile::tempdir().unwrap();
    let file = bloat_agent_file(dir.path(), "agent:a", &entries);
    let blocker = tmp_blocker(&file);
    std::fs::create_dir(&blocker).unwrap();

    let store = MemoryStore::open(dir.path(), MAX).expect("open ok (best-effort rewrite failed)");
    let mem_before: Vec<String> = store.list("agent:a").iter().map(|e| e.id.clone()).collect();
    // The agent is pending-rewrite; this insert attempts a reconcile rewrite that
    // ALSO fails (still blocked) → the insert errors and restores pre (no `fresh`).
    let r = store.insert("agent:a", fact("fresh", "agent:a", "new", "t9999999"));
    assert!(
        r.is_err(),
        "insert on a pending+still-blocked agent errors (reconcile fails)"
    );
    let mem_after: Vec<String> = store.list("agent:a").iter().map(|e| e.id.clone()).collect();
    assert_eq!(
        mem_before, mem_after,
        "failed reconcile restored pre (memory unchanged)"
    );

    // Determinism: a fresh reopen (now unblocked) reproduces the in-memory set.
    std::fs::remove_dir(&blocker).unwrap();
    let store2 = MemoryStore::open(dir.path(), MAX).expect("reopen ok");
    let disk: Vec<String> = store2
        .list("agent:a")
        .iter()
        .map(|e| e.id.clone())
        .collect();
    assert_eq!(
        mem_after, disk,
        "memory == hydrate(disk) after the failed reconcile"
    );
    assert!(disk.contains(&"keep".to_string()), "active entry survives");
}

/// Referent-blind safety (Claude-rd5-W2): dropping the OLDEST inactive entries
/// can drop a Superseded tombstone whose `superseded_by` referent is absent — this
/// must NOT brick reopen, because `validate_invariants` checks only the local
/// `status↔superseded_by` biconditional, never referent existence.
#[test]
fn compaction_drops_superseded_tombstone_still_reopens_clean() {
    let n = cap_memory::DEFAULT_MAX_INACTIVE_PER_AGENT + 50;
    let mut entries = vec![fact("act", "agent:a", "alive", "t0000000")];
    for i in 0..n {
        let mut e = fact(&format!("s{i:07}"), "agent:a", "x", &format!("t{i:07}"));
        e.is_active = false;
        e.status = MemoryStatus::Superseded;
        e.superseded_by = Some(format!("ref{i:07}")); // referent not present in the file
        entries.push(e);
    }
    let dir = tempfile::tempdir().unwrap();
    bloat_agent_file(dir.path(), "agent:a", &entries);
    let store = MemoryStore::open(dir.path(), MAX)
        .expect("open compacts superseded tombstones without bricking");
    assert!(
        store
            .list("agent:a")
            .iter()
            .filter(|e| !e.is_active)
            .count()
            <= cap_memory::DEFAULT_MAX_INACTIVE_PER_AGENT
    );
    MemoryStore::open(dir.path(), MAX).expect("clean reopen after tombstone compaction");
}

/// When a mutation's rewrite fails AFTER compaction trimmed the inactive tail, the
/// in-memory bucket is restored to the FULL pre-mutation state (cache==disk).
#[cfg(unix)]
#[test]
fn persist_failure_after_compaction_restores_pre() {
    let n = cap_memory::DEFAULT_MAX_INACTIVE_PER_AGENT + 10;
    let mut entries = vec![fact("act", "agent:a", "keep me", "t9999999")];
    for i in 0..n {
        entries.push(forgotten_fact(
            &format!("g{i:07}"),
            "agent:a",
            &format!("t{i:07}"),
        ));
    }
    let dir = tempfile::tempdir().unwrap();
    let file = bloat_agent_file(dir.path(), "agent:a", &entries);
    let store = MemoryStore::open(dir.path(), MAX).unwrap(); // migrates (rewrite succeeds, no blocker)
    std::fs::create_dir(tmp_blocker(&file)).unwrap(); // block the NEXT rewrite

    // forget("act") flips it inactive → persist_or_restore compacts (drops 1
    // oldest inactive) then the rewrite FAILS → restore the full pre-mutation set.
    let r = store.forget("agent:a", "act");
    assert!(r.is_err(), "forget errors when its rewrite fails");
    let act = store.get("agent:a", "act").expect("act still present");
    assert!(
        act.is_active,
        "act restored to active after the rolled-back forget"
    );
}

/// W2 reconcile (adversarial round): after a FAILED best-effort migration rewrite
/// at open, the agent's NEXT `insert` (even `remember`-only) upgrades to a full
/// reconcile rewrite, re-bounding the on-disk file — so a remember-only agent does
/// not leave the disk bloated indefinitely.
#[cfg(unix)]
#[test]
fn t_reconcile_rewrite_on_insert_after_failed_open_compaction() {
    let n = cap_memory::DEFAULT_MAX_INACTIVE_PER_AGENT + 50;
    let mut entries = vec![fact("keep", "agent:a", "alive", "t0000000")];
    for i in 0..n {
        entries.push(forgotten_fact(
            &format!("g{i:07}"),
            "agent:a",
            &format!("t{i:07}"),
        ));
    }
    let dir = tempfile::tempdir().unwrap();
    let file = bloat_agent_file(dir.path(), "agent:a", &entries);
    let blocker = tmp_blocker(&file);
    std::fs::create_dir(&blocker).unwrap();
    let store = MemoryStore::open(dir.path(), MAX).expect("open ok (best-effort rewrite failed)");
    let bloated = std::fs::metadata(&file).unwrap().len();

    // Clear the block so the reconcile rewrite can land, then a remember-only insert
    // triggers the full reconcile rewrite (NOT a bloat-preserving append).
    std::fs::remove_dir(&blocker).unwrap();
    store
        .insert("agent:a", fact("fresh", "agent:a", "new", "t9999999"))
        .unwrap();
    let after = std::fs::metadata(&file).unwrap().len();
    assert!(
        after < bloated,
        "reconcile rewrite shrank the disk on next insert: {after} < {bloated}"
    );

    // A fresh reopen reproduces the bounded set incl. both active entries.
    let store2 = MemoryStore::open(dir.path(), MAX).unwrap();
    let ids: std::collections::HashSet<String> = store2
        .list("agent:a")
        .iter()
        .map(|e| e.id.clone())
        .collect();
    assert!(
        ids.contains("keep") && ids.contains("fresh"),
        "active entries survive reconcile"
    );
    assert!(
        store2
            .list("agent:a")
            .iter()
            .filter(|e| !e.is_active)
            .count()
            <= cap_memory::DEFAULT_MAX_INACTIVE_PER_AGENT,
        "inactive tail bounded after reconcile"
    );
}
