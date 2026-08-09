//! SAT-B (slice satB-postproc) — PostProcessor on-disk writeback + gating tests.
//!
//! T54 writeback-on-disk · T55 rootless/derived gating · T56 security
//! (traversal / symlink / present-malicious) · T57 durable rusqlite · T58
//! fallback path · T59 colon/bare write-bucket normalization · T60 YAML DoS +
//! invalid-index guard. AC-43/44 (extractor + composition gate) are unit-tested
//! in `crates/cli/src/memory_extractor.rs` + the cli gate test.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use advance_shared_types::mailbox::{ActionResult, Message, MessageContext, MessageKind};
use advance_shared_types::memory::PostProcessorHook;
use cap_memory::{
    post_processor::{CANONICAL_STEPS, MAX_TASK_YAML_BYTES},
    BatchExtractor, BatchExtractorError, Components, Extraction, FailureCooldown,
    InMemorySimilarityIndex, LogOffset, MemoryEntry, MemoryStatus, MemoryStore, MemoryType,
    MutableClock, PostProcessor, Reconciler, RusqliteSqliteIndex, SqliteIndex, StubBatchExtractor,
    TurnEntry, TurnIndex, TurnIndexMeta, DEFAULT_MAX_ACTIVE_PER_AGENT, DEFAULT_THRESHOLD,
    MECHANICAL_TURN_DIGEST,
};

// ── fixtures ──

fn clock() -> Arc<MutableClock> {
    Arc::new(MutableClock::new(
        SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000),
    ))
}

/// `task_id == None` ⇒ `context: None` (true absence). `Some(t)` ⇒ a context
/// carrying that task_id.
fn message(task_id: Option<&str>) -> Message {
    Message {
        id: "msg-satb-1".into(),
        kind: MessageKind::User,
        from: "user:test".into(),
        to: "agent:default".into(),
        payload: b"hello from the user".to_vec(),
        context: task_id.map(|t| MessageContext {
            task_id: Some(t.to_string()),
            run_id: None,
            execution_id: None,
            trace_id: None,
            in_reply_to: None,
            correlation_id: None,
        }),
        timestamp: SystemTime::UNIX_EPOCH,
        origin: None,
    }
}

fn result() -> ActionResult {
    ActionResult {
        new_state: vec![1, 2, 3],
        actions: vec![],
    }
}

fn mem_entry(agent_id: &str, id: &str, content: &str) -> MemoryEntry {
    MemoryEntry {
        id: id.into(),
        agent_id: agent_id.into(),
        entry_type: MemoryType::Fact,
        content: content.into(),
        tags: vec![],
        created_at: "2026-06-16T00:00:00Z".into(),
        task_origin: None,
        is_active: true,
        superseded_by: None,
        status: MemoryStatus::Active,
        supersession_reason: None,
        cluster_id: None,
        sources: vec![],
    }
}

/// An `Extraction` with one knowledge entry (agent_id as given) + an optional digest.
fn extraction(entry_agent_id: &str, digest: Option<&str>) -> Extraction {
    Extraction {
        descriptions: vec![],
        knowledge: vec![mem_entry(
            entry_agent_id,
            "k-1",
            "the parser was refactored",
        )],
        digest: digest.map(str::to_string),
    }
}

fn ok_components(
    store: Arc<MemoryStore>,
    extr: Arc<dyn BatchExtractor + Send + Sync>,
) -> Components {
    let reconciler =
        Reconciler::from_concrete(Arc::new(InMemorySimilarityIndex::new()), DEFAULT_THRESHOLD);
    Components::with_l6_defaults(
        extr,
        reconciler,
        store,
        Arc::new(FailureCooldown::new(600)),
        clock(),
    )
}

fn read_turn_index(p: &std::path::Path) -> TurnIndex {
    serde_yml::from_str(&std::fs::read_to_string(p).expect("read turn-index.yaml")).expect("parse")
}

// ── T54: writeback on disk ──

#[tokio::test]
async fn t54_writeback_to_disk_under_task_dir() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join(".agent/memory");
    let store = Arc::new(MemoryStore::open(&root, DEFAULT_MAX_ACTIVE_PER_AGENT).unwrap());
    let extr = Arc::new(StubBatchExtractor::with_extraction(extraction(
        "a",
        Some("Refactored the tokenizer"),
    )));
    let components = ok_components(Arc::clone(&store), extr)
        .with_fs_root(&root)
        .with_write_agent_id("a");
    let pp = PostProcessor::with_components(components);

    pp.run("a", &message(Some("t1")), &result())
        .await
        .expect("run Ok");

    let task_dir = root.join("tasks").join("t1");
    let summary_path = task_dir.join("summary.yaml");
    let ti_path = task_dir.join("turn-index.yaml");
    assert!(
        summary_path.exists(),
        "summary.yaml written under tasks/t1/"
    );
    assert!(ti_path.exists(), "turn-index.yaml written under tasks/t1/");

    let ti = read_turn_index(&ti_path);
    assert_eq!(ti.turns.len(), 1, "one TurnEntry appended");
    assert_eq!(ti.turns[0].turn, 1);
    assert_eq!(ti.turns[0].agent_id, "a", "keyed by the write_agent_id");
    assert_eq!(ti.turns[0].task_id, "t1");
    assert_eq!(
        ti.turns[0].digest, "Refactored the tokenizer",
        "digest comes verbatim from the extraction"
    );

    let s = std::fs::read_to_string(&summary_path).unwrap();
    assert!(s.contains("turns_total: 1"), "summary turns_total==1: {s}");
    assert!(
        !s.contains("title: ''") && !s.contains("title: \"\""),
        "non-empty title"
    );

    // No .meta.yaml (Step 3 deferred for SAT-B).
    assert!(
        !task_dir.join(".meta.yaml").exists(),
        "Step 3 .meta.yaml deferred"
    );
}

/// SYS-J-03 / SYS-AC-008 producer regression: Step-7 populates `summary.brief` from the
/// turn digest on the AC-28 brief cadence + a first-turn bootstrap, and does NOT overwrite
/// within the 3-turn cadence window. Drives a wired Step-7 directly (no SUT).
#[tokio::test]
async fn t54b_summary_brief_bootstrap_then_cadence_holds() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join(".agent/memory");
    let store = Arc::new(MemoryStore::open(&root, DEFAULT_MAX_ACTIVE_PER_AGENT).unwrap());
    let extr = Arc::new(StubBatchExtractor::with_extraction(extraction(
        "agent:research",
        Some("brief-d1"),
    )));
    // Keep the typed `StubBatchExtractor` handle to vary the digest between turns; pass a
    // trait-object clone into Components (x.clone() + typed let — the coercion-safe form).
    let extr_dyn: Arc<dyn BatchExtractor + Send + Sync> = extr.clone();
    let components = ok_components(Arc::clone(&store), extr_dyn)
        .with_fs_root(&root)
        .with_write_agent_id("agent:research");
    let pp = PostProcessor::with_components(components);
    let summary_path = root.join("tasks").join("tb").join("summary.yaml");

    // Turn 1: empty brief → BOOTSTRAP → brief = "brief-d1", last_brief_update = 1.
    pp.run("agent:research", &message(Some("tb")), &result())
        .await
        .expect("turn-1 run Ok");
    let s1: cap_memory::Summary =
        serde_yml::from_str(&std::fs::read_to_string(&summary_path).unwrap()).unwrap();
    assert_eq!(
        s1.brief, "brief-d1",
        "turn-1 bootstraps the brief from the digest"
    );
    assert_eq!(s1.meta.turns_total, 1);
    assert_eq!(
        s1.meta.last_brief_update, 1,
        "the brief cursor advances on the bootstrap refresh"
    );

    // Turn 2: a DIFFERENT digest, but the cadence delta = 2 - 1 = 1 < 3 → NO overwrite.
    extr.set_response_ok(extraction("agent:research", Some("brief-d2")));
    pp.run("agent:research", &message(Some("tb")), &result())
        .await
        .expect("turn-2 run Ok");
    let s2: cap_memory::Summary =
        serde_yml::from_str(&std::fs::read_to_string(&summary_path).unwrap()).unwrap();
    assert_eq!(
        s2.brief, "brief-d1",
        "turn-2 keeps the turn-1 brief (cadence delta 1 < 3 → no refresh), proving the \
         producer is cadence-gated, not eager"
    );
    assert_eq!(s2.meta.turns_total, 2);
    assert_eq!(
        s2.meta.last_brief_update, 1,
        "the cursor is unchanged when no refresh occurs"
    );
}

// ── T55: rootless + derived-partition gating ──

#[tokio::test]
async fn t55a_rootless_is_trace_only_with_counters() {
    let store = Arc::new(MemoryStore::new());
    let extr = Arc::new(StubBatchExtractor::with_extraction(extraction(
        "agent:research",
        Some("d"),
    )));
    // NO with_fs_root → Steps 7/8 stay trace-only.
    let pp = PostProcessor::with_components(ok_components(store, extr));

    pp.run("agent:research", &message(Some("t1")), &result())
        .await
        .expect("run Ok");

    let trace: Vec<String> = CANONICAL_STEPS.iter().map(|s| s.to_string()).collect();
    assert_eq!(
        pp.trace_snapshot(),
        trace,
        "9-step canonical trace preserved"
    );
    assert_eq!(pp.summary_calls(), 1, "Step-7 summary counter still bumped");
    assert_eq!(
        pp.turn_index_calls(),
        1,
        "Step-7 turn-index counter still bumped"
    );
}

#[tokio::test]
async fn t55b_absent_task_id_derives_agent_partition() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join(".agent/memory");
    let store = Arc::new(MemoryStore::open(&root, DEFAULT_MAX_ACTIVE_PER_AGENT).unwrap());
    let extr = Arc::new(StubBatchExtractor::with_extraction(extraction(
        "agentX",
        Some("d"),
    )));
    let components = ok_components(Arc::clone(&store), extr)
        .with_fs_root(&root)
        .with_write_agent_id("agentX");
    let pp = PostProcessor::with_components(components);

    // context: None ⇒ derive `_agent-agentX`.
    pp.run("agent:default", &message(None), &result())
        .await
        .expect("run Ok");

    let derived = root.join("tasks").join("_agent-agentX");
    assert!(
        derived.join("summary.yaml").exists(),
        "derived partition summary.yaml"
    );
    assert!(
        derived.join("turn-index.yaml").exists(),
        "derived partition turn-index.yaml"
    );
}

// ── T56: security — traversal / symlink / present-malicious ──

#[tokio::test]
async fn t56_security_traversal_symlink_and_present_malicious() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join(".agent/memory");
    std::fs::create_dir_all(&root).unwrap();

    // (a) traversal task_id — sanitize rejects (contains '/'); no write.
    {
        let store = Arc::new(MemoryStore::open(&root, DEFAULT_MAX_ACTIVE_PER_AGENT).unwrap());
        let extr = Arc::new(StubBatchExtractor::with_extraction(extraction(
            "a",
            Some("d"),
        )));
        let pp = PostProcessor::with_components(
            ok_components(store, extr)
                .with_fs_root(&root)
                .with_write_agent_id("a"),
        );
        pp.run("a", &message(Some("../../etc/evil")), &result())
            .await
            .expect("turn survives a malicious task_id");
    }

    // (b) symlinked task dir → outside the root; must be refused.
    {
        let outside = tmp.path().join("outside_escape");
        std::fs::create_dir_all(&outside).unwrap();
        let tasks = root.join("tasks");
        std::fs::create_dir_all(&tasks).unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(&outside, tasks.join("linked")).unwrap();
        #[cfg(unix)]
        {
            let store = Arc::new(MemoryStore::open(&root, DEFAULT_MAX_ACTIVE_PER_AGENT).unwrap());
            let extr = Arc::new(StubBatchExtractor::with_extraction(extraction(
                "a",
                Some("d"),
            )));
            let pp = PostProcessor::with_components(
                ok_components(store, extr)
                    .with_fs_root(&root)
                    .with_write_agent_id("a"),
            );
            pp.run("a", &message(Some("linked")), &result())
                .await
                .expect("turn survives a symlinked task dir");
            assert!(
                !outside.join("summary.yaml").exists(),
                "MUST NOT write through the symlink to outside the root"
            );
        }
    }

    // (c) present-but-malicious task_id → SKIP, NOT redirected to `_agent-*`.
    {
        let store = Arc::new(MemoryStore::open(&root, DEFAULT_MAX_ACTIVE_PER_AGENT).unwrap());
        let extr = Arc::new(StubBatchExtractor::with_extraction(extraction(
            "a",
            Some("d"),
        )));
        let pp = PostProcessor::with_components(
            ok_components(store, extr)
                .with_fs_root(&root)
                .with_write_agent_id("a"),
        );
        pp.run("a", &message(Some("bad/seg")), &result())
            .await
            .expect("turn survives a present-but-malicious task_id");
        // No `_agent-*` fallback dir created (proves SKIP, not silent redirect).
        let tasks = root.join("tasks");
        if tasks.exists() {
            for ent in std::fs::read_dir(&tasks).unwrap() {
                let name = ent.unwrap().file_name();
                assert!(
                    !name.to_string_lossy().starts_with("_agent-"),
                    "malicious present task_id must NOT fall back to a _agent-* partition"
                );
            }
        }
    }

    // No file escaped the tmp root in any branch.
    assert!(!tmp.path().join("outside_escape/summary.yaml").exists());
}

// ── T57: durable rusqlite index ──

#[tokio::test]
async fn t57_durable_rusqlite_index_round_trips_across_reopen() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join(".agent/memory");
    std::fs::create_dir_all(&root).unwrap();
    let db = root.join("index.sqlite");
    let store = Arc::new(MemoryStore::open(&root, DEFAULT_MAX_ACTIVE_PER_AGENT).unwrap());
    let extr = Arc::new(StubBatchExtractor::with_extraction(extraction(
        "a",
        Some("d"),
    )));
    let idx = Arc::new(RusqliteSqliteIndex::open(&db).expect("open rusqlite index"));

    let components = ok_components(Arc::clone(&store), extr)
        .with_fs_root(&root)
        .with_write_agent_id("a")
        .with_sqlite_index(idx.clone());
    let pp = PostProcessor::with_components(components);

    pp.run("a", &message(Some("t1")), &result())
        .await
        .expect("run Ok");

    assert_eq!(
        idx.list_turns_for_agent("a").len(),
        1,
        "Step-8 upserted a turn row"
    );
    assert_eq!(
        idx.list_tasks_for_agent("a").len(),
        1,
        "Step-8 upserted a task row"
    );
    drop(idx);

    // Reopen the same on-disk file: rows persist (durable).
    let idx2 = RusqliteSqliteIndex::open(&db).expect("reopen rusqlite index");
    assert_eq!(
        idx2.list_turns_for_agent("a").len(),
        1,
        "turn row durable across reopen"
    );
    assert_eq!(
        idx2.list_tasks_for_agent("a").len(),
        1,
        "task row durable across reopen"
    );
}

// ── T58: fail-capable extractor → mechanical-digest fallback, still writes ──

#[tokio::test]
async fn t58_llm_failure_fallback_still_writes_mechanical_digest() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join(".agent/memory");
    let store = Arc::new(MemoryStore::open(&root, DEFAULT_MAX_ACTIVE_PER_AGENT).unwrap());
    let extr = Arc::new(StubBatchExtractor::fail_with(
        BatchExtractorError::LlmFailure("upstream 503".into()),
    ));
    let components = ok_components(Arc::clone(&store), extr)
        .with_fs_root(&root)
        .with_write_agent_id("a");
    let pp = PostProcessor::with_components(components);

    pp.run("a", &message(Some("t1")), &result())
        .await
        .expect("turn NOT hard-failed on LLM failure");

    assert_eq!(
        pp.trace_snapshot().len(),
        9,
        "9-step trace preserved on the fallback path"
    );
    let ti = read_turn_index(&root.join("tasks/t1/turn-index.yaml"));
    assert_eq!(ti.turns.len(), 1);
    assert_eq!(
        ti.turns[0].digest, MECHANICAL_TURN_DIGEST,
        "fallback (digest: None) → mechanical single-sentence digest"
    );
}

// ── T59: colon/bare write-bucket normalization ──

#[tokio::test]
async fn t59_writes_under_bare_id_not_colon_id() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join(".agent/memory");
    let store = Arc::new(MemoryStore::open(&root, DEFAULT_MAX_ACTIVE_PER_AGENT).unwrap());
    // Extractor yields a knowledge entry whose own agent_id is the COLON id.
    let extr = Arc::new(StubBatchExtractor::with_extraction(extraction(
        "agent:colon",
        Some("d"),
    )));
    let components = ok_components(Arc::clone(&store), extr)
        .with_fs_root(&root)
        .with_write_agent_id("bare");
    let pp = PostProcessor::with_components(components);

    // run() receives the COLON messaging id; the composition supplies the bare id.
    pp.run("agent:colon", &message(Some("t1")), &result())
        .await
        .expect("Step 5 normalizes entry.agent_id to the bare id → no apply_action mismatch");

    assert_eq!(
        store.list("bare").len(),
        1,
        "entries land under the bare write id"
    );
    assert!(
        store.list("agent:colon").is_empty(),
        "nothing under the colon id"
    );
    // recall under the bare id finds the normalized entry.
    assert_eq!(
        store.recall("bare", "parser", 10).len(),
        1,
        "recall under bare id finds it"
    );
}

// ── T60: YAML DoS guard + invalid-index guard ──

#[tokio::test]
async fn t60a_oversize_turn_index_is_capped_not_deserialized() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join(".agent/memory");
    let task_dir = root.join("tasks/t1");
    std::fs::create_dir_all(&task_dir).unwrap();
    // Pre-seed an oversize turn-index.yaml (> MAX_TASK_YAML_BYTES).
    let big = vec![b'x'; (MAX_TASK_YAML_BYTES as usize) + 1024];
    std::fs::write(task_dir.join("turn-index.yaml"), &big).unwrap();

    let store = Arc::new(MemoryStore::open(&root, DEFAULT_MAX_ACTIVE_PER_AGENT).unwrap());
    let extr = Arc::new(StubBatchExtractor::with_extraction(extraction(
        "a",
        Some("d"),
    )));
    let pp = PostProcessor::with_components(
        ok_components(store, extr)
            .with_fs_root(&root)
            .with_write_agent_id("a"),
    );

    pp.run("a", &message(Some("t1")), &result())
        .await
        .expect("oversize existing index does not DoS the turn");

    // The oversize file was capped (not parsed) → a fresh, small, valid index written.
    let ti_bytes = std::fs::metadata(task_dir.join("turn-index.yaml"))
        .unwrap()
        .len();
    assert!(
        ti_bytes < MAX_TASK_YAML_BYTES,
        "rewritten index is bounded ({ti_bytes} bytes)"
    );
    let ti = read_turn_index(&task_dir.join("turn-index.yaml"));
    assert_eq!(ti.turns.len(), 1, "fresh index started; one new turn");
}

#[tokio::test]
async fn t60b_invalid_turn_index_starts_fresh() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join(".agent/memory");
    let task_dir = root.join("tasks/t2");
    std::fs::create_dir_all(&task_dir).unwrap();
    // A structurally-invalid (but small + parseable) index: inverted log_offset
    // (start_line > end_line) → fails validate_invariants.
    let invalid = TurnIndex {
        meta: TurnIndexMeta {
            last_epoch_turn: 0,
            last_epoch_at: String::new(),
        },
        turns: vec![bad_turn_entry()],
        epochs: vec![],
    };
    std::fs::write(
        task_dir.join("turn-index.yaml"),
        serde_yml::to_string(&invalid).unwrap(),
    )
    .unwrap();

    let store = Arc::new(MemoryStore::open(&root, DEFAULT_MAX_ACTIVE_PER_AGENT).unwrap());
    let extr = Arc::new(StubBatchExtractor::with_extraction(extraction(
        "a",
        Some("d"),
    )));
    let pp = PostProcessor::with_components(
        ok_components(store, extr)
            .with_fs_root(&root)
            .with_write_agent_id("a"),
    );

    pp.run("a", &message(Some("t2")), &result())
        .await
        .expect("invalid existing index does not corrupt the turn");

    // validate_invariants rejected the old index → fresh started (1 turn, valid).
    let ti = read_turn_index(&task_dir.join("turn-index.yaml"));
    assert_eq!(
        ti.turns.len(),
        1,
        "fresh index started (old invalid one discarded)"
    );
    ti.validate_invariants()
        .expect("written index satisfies invariants");
}

fn bad_turn_entry() -> TurnEntry {
    TurnEntry {
        turn: 7,
        timestamp: "2026-06-16T00:00:00Z".into(),
        agent_id: "a".into(),
        task_id: "t2".into(),
        // Inverted range — validate_invariants rejects this.
        log_offset: LogOffset {
            start_line: 100,
            end_line: 50,
        },
        has_user_instruction: false,
        has_user_correction: false,
        has_tool_use: false,
        has_decision: false,
        importance: cap_memory::Importance::Normal,
        digest: "stale".into(),
        collapsed_view: String::new(),
        git_commit: String::new(),
        git_diff_summary: String::new(),
        git_checkpoints: vec![],
        reference_count: 0,
        content_identifiers: vec![],
        read_file_versions: vec![],
        tokens_digest: 0,
        tokens_collapse_excerpt: 0,
        tokens_l0_processed: 0,
    }
}

// ── audit r6 (C1/C2): symlink hardening — write-escape + read-DoS ──

/// Audit r6 C1: a pre-planted `<task_dir>/turn-index.yaml.tmp` SYMLINK pointing
/// outside `fs_root` must NOT be followed by the atomic writer — the outside
/// target stays untouched and a real (regular-file) turn-index.yaml is written.
#[cfg(unix)]
#[tokio::test]
async fn t56b_tmp_symlink_write_escape_is_neutralized() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join(".agent/memory");
    let outside = tmp.path().join("outside_secret.txt");
    std::fs::write(&outside, b"SENTINEL-MUST-NOT-BE-CLOBBERED").unwrap();

    let task_dir = root.join("tasks").join("tsym");
    std::fs::create_dir_all(&task_dir).unwrap();
    // Plant the malicious `.tmp` symlink the atomic writer would otherwise follow.
    std::os::unix::fs::symlink(&outside, task_dir.join("turn-index.yaml.tmp")).unwrap();

    let store = Arc::new(MemoryStore::open(&root, DEFAULT_MAX_ACTIVE_PER_AGENT).unwrap());
    let extr = Arc::new(StubBatchExtractor::with_extraction(extraction(
        "a",
        Some("d"),
    )));
    let components = ok_components(Arc::clone(&store), extr)
        .with_fs_root(&root)
        .with_write_agent_id("a");
    let pp = PostProcessor::with_components(components);

    pp.run("a", &message(Some("tsym")), &result())
        .await
        .expect("run Ok");

    // The outside target is UNTOUCHED — the planted `.tmp` symlink was removed
    // (not followed) before the O_EXCL create.
    assert_eq!(
        std::fs::read_to_string(&outside).unwrap(),
        "SENTINEL-MUST-NOT-BE-CLOBBERED",
        "atomic write must not follow the planted .tmp symlink"
    );
    let ti_path = task_dir.join("turn-index.yaml");
    assert!(
        !std::fs::symlink_metadata(&ti_path)
            .unwrap()
            .file_type()
            .is_symlink(),
        "turn-index.yaml is a regular file"
    );
    assert_eq!(read_turn_index(&ti_path).turns.len(), 1);
}

/// Audit r6 C2: an EXISTING `turn-index.yaml` that is a SYMLINK to an outside
/// file must be refused by the bounded reader (not followed) — Step 7 starts
/// fresh, replaces the symlink with a real index, and the outside file is not
/// read-amplified or clobbered.
#[cfg(unix)]
#[tokio::test]
async fn t60c_symlink_yaml_leaf_is_refused_and_replaced() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join(".agent/memory");
    let outside = tmp.path().join("outside.yaml");
    std::fs::write(
        &outside,
        b"_meta:\n  last_epoch_turn: 0\n  last_epoch_at: ''\nturns: []\nepochs: []\n",
    )
    .unwrap();

    let task_dir = root.join("tasks").join("tleaf");
    std::fs::create_dir_all(&task_dir).unwrap();
    std::os::unix::fs::symlink(&outside, task_dir.join("turn-index.yaml")).unwrap();

    let store = Arc::new(MemoryStore::open(&root, DEFAULT_MAX_ACTIVE_PER_AGENT).unwrap());
    let extr = Arc::new(StubBatchExtractor::with_extraction(extraction(
        "a",
        Some("d"),
    )));
    let components = ok_components(Arc::clone(&store), extr)
        .with_fs_root(&root)
        .with_write_agent_id("a");
    let pp = PostProcessor::with_components(components);

    pp.run("a", &message(Some("tleaf")), &result())
        .await
        .expect("run Ok (symlink refused, starts fresh)");

    let ti_path = task_dir.join("turn-index.yaml");
    // The symlink was REPLACED (tmp+rename) with a real regular file.
    assert!(
        !std::fs::symlink_metadata(&ti_path)
            .unwrap()
            .file_type()
            .is_symlink(),
        "symlinked turn-index.yaml replaced by a regular file"
    );
    // Started fresh (symlinked content NOT read in) ⇒ exactly the one new turn.
    assert_eq!(
        read_turn_index(&ti_path).turns.len(),
        1,
        "fresh index, one new turn"
    );
    // The outside file is unchanged (rename replaced the link, didn't write through it).
    assert!(std::fs::read_to_string(&outside)
        .unwrap()
        .contains("turns: []"));
}

/// Audit r7: a non-symlink SPECIAL file (FIFO) at the read leaf must be refused
/// by the non-regular-file gate — `File::open`+`read_to_string` on a writer-less
/// FIFO would otherwise BLOCK and hang the per-agent turn. The `timeout` turns a
/// regression (a hang) into a test failure instead of an indefinite block.
#[cfg(unix)]
#[tokio::test]
async fn t60d_fifo_yaml_leaf_is_refused_not_blocked() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join(".agent/memory");
    let task_dir = root.join("tasks").join("tfifo");
    std::fs::create_dir_all(&task_dir).unwrap();
    let ti = task_dir.join("turn-index.yaml");
    let st = std::process::Command::new("mkfifo").arg(&ti).status();
    if !matches!(st, Ok(s) if s.success()) {
        eprintln!("t60d skipped: mkfifo unavailable");
        return;
    }

    let store = Arc::new(MemoryStore::open(&root, DEFAULT_MAX_ACTIVE_PER_AGENT).unwrap());
    let extr = Arc::new(StubBatchExtractor::with_extraction(extraction(
        "a",
        Some("d"),
    )));
    let components = ok_components(Arc::clone(&store), extr)
        .with_fs_root(&root)
        .with_write_agent_id("a");
    let pp = PostProcessor::with_components(components);

    let r = tokio::time::timeout(
        Duration::from_secs(10),
        pp.run("a", &message(Some("tfifo")), &result()),
    )
    .await;
    assert!(
        r.is_ok(),
        "run must NOT block on a FIFO yaml leaf (read_capped_yaml is_file gate)"
    );
    r.unwrap().expect("run Ok");

    // FIFO refused on read (start fresh) + replaced by a real regular file on write.
    assert!(
        std::fs::symlink_metadata(&ti)
            .unwrap()
            .file_type()
            .is_file(),
        "FIFO leaf replaced by a regular file"
    );
    assert_eq!(read_turn_index(&ti).turns.len(), 1);
}
