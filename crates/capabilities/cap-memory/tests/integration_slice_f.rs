//! MODULE-011 Slice F — cap-memory within-crate hardening (m011-slice-f).
//!
//! In-scope ACs verified by this file:
//!
//! - **MODULE-011-AC-19** (REQ-226, T38): `Components::sync_turn_index` —
//!   computes the L1 embedding via `Embedder::embed` and upserts a
//!   `TurnIndexRow` into the in-memory `SqliteIndex`. `task_id` is DERIVED
//!   from `turn.task_id` (no separate `task_id` arg — see MODULE-011 §3.8
//!   note 12 (round-3 Warning resolution)).
//!
//! - **MODULE-011-AC-24** (REQ-159, T39): `Components::sync_memory_index` —
//!   mirrors every `MemoryStore` entry's `MemoryStatus` (via the new
//!   `MemoryStatus::as_str` 5-arm method) into `MemoryIndexRow.epistemic_status`.
//!   Test exercises all 5 statuses (Active/Contested/Orphaned/Superseded/
//!   Forgotten) in invariant-respecting transition order.
//!
//! - **MODULE-011-AC-27** (REQ-230, T40): `Components::sync_task_index` —
//!   upserts `TaskIndexRow` with brief-change gate: recomputes
//!   `brief_embedding` ONLY when `summary.brief` differs from the previously-
//!   stored `brief_snapshot` (string equality; deterministic substitute for
//!   semantic similarity per §3.8 note 12 (d)). Uses test-only
//!   `CountingEmbedder` wrapper to assert call_count.
//!
//! - **MODULE-011-AC-31** (REQ-230, T41): `Components::bump_turn_reference` —
//!   get-modify-upsert that increments `reference_count` WITHOUT recomputing
//!   the embedding. T41 seeds via `sync_turn_index`, bumps 3 times, asserts
//!   reference_count == 3 AND embedding bytes-for-bytes equal to the seed
//!   embedding (`// CRITICAL: do NOT recompute embedding here` invariant).
//!
//! - **MODULE-011-AC-08 regression** (T42): adding the 2 new `Components`
//!   fields + 4 new methods + Debug-impl extension MUST NOT perturb the
//!   `PostProcessor::run` 9-step canonical trace order.
//!
//! All 4 ACs are verified at the SEAM level (in-memory `SqliteIndex` stub +
//! `StubEmbedder` deterministic 8-dim sketch). Production rusqlite +
//! real-embedder adapters are deferred per MODULE-011 §3.6 rows
//! "Production rusqlite + sqlite-vec adapter for `SqliteIndex` seam" and
//! "Production `embed()` adapter for `Embedder` seam".

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::SystemTime;

use async_trait::async_trait;

use cap_memory::clock::SystemClock;
use cap_memory::cooldown::FailureCooldown;
use cap_memory::extractor::StubBatchExtractor;
use cap_memory::knowledge::{
    MemoryEntry, MemorySource, MemoryStatus, MemoryType, SupersessionReason,
};
use cap_memory::post_processor::PostProcessor;
use cap_memory::reconcile::{InMemorySimilarityIndex, MemoryAction, Reconciler, DEFAULT_THRESHOLD};
use cap_memory::store::MemoryStore;
use cap_memory::summary::{Summary, SummaryMeta};
use cap_memory::turn_index::{Importance, LogOffset, TurnEntry};
use cap_memory::{
    Components, Embedder, EmbedderError, SqliteIndex, StubEmbedder, STUB_EMBEDDING_DIM,
};

use advance_shared_types::mailbox::{ActionResult, Message, MessageKind};
use advance_shared_types::memory::PostProcessorHook;

// ────────────────────────────────────────────────────────────────────
// Shared test fixtures
// ────────────────────────────────────────────────────────────────────

/// Build a fully-populated [`TurnEntry`] from the minimal interesting fields,
/// defaulting the other 17 to zero-equivalents. Slice F's `sync_turn_index`
/// only consumes 5 of the 21 fields (turn / task_id / digest / collapsed_view
/// / reference_count) but the struct requires all 21 to construct.
fn test_turn_entry(turn: u32, task_id: &str, digest: &str, collapsed_view: &str) -> TurnEntry {
    TurnEntry {
        turn,
        timestamp: "2026-05-22T00:00:00Z".into(),
        agent_id: "agent:r".into(),
        task_id: task_id.into(),
        log_offset: LogOffset {
            start_line: 0,
            end_line: 0,
        },
        has_user_instruction: false,
        has_user_correction: false,
        has_tool_use: false,
        has_decision: false,
        importance: Importance::Normal,
        digest: digest.into(),
        collapsed_view: collapsed_view.into(),
        git_commit: "0000000".into(),
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

/// Minimal `Summary` fixture for the T40 brief-change test. Only `meta.task_id` /
/// `meta.agent_id` / `meta.turns_total` / `meta.last_turn_at` and `brief` are
/// consumed by `sync_task_index`; the other 8 fields are zero-equivalents.
fn test_summary(task_id: &str, agent_id: &str, brief: &str, turns_total: u32) -> Summary {
    Summary {
        meta: SummaryMeta {
            task_id: task_id.into(),
            agent_id: agent_id.into(),
            title: "test-task".into(),
            status: "active".into(),
            profile: "test".into(),
            turns_total,
            last_updated: format!("2026-05-22T00:{turns_total:02}:00Z"),
            last_turn_at: format!("2026-05-22T00:{turns_total:02}:00Z"),
            last_brief_update: 0,
            last_decisions_update: 0,
            last_state_update: 0,
        },
        brief: brief.into(),
        key_decisions: vec![],
        findings: vec![],
        open_questions: vec![],
        current_state: String::new(),
        errors_and_corrections: vec![],
        workflow: String::new(),
    }
}

/// Build a `Components` with the slice-F in-memory stub seams. Caller
/// supplies the `MemoryStore` so the test can pre-seed entries.
fn components_with_store(store: Arc<MemoryStore>) -> Components {
    Components::with_l6_defaults(
        Arc::new(StubBatchExtractor::with_extraction(Default::default())),
        Reconciler::from_concrete(Arc::new(InMemorySimilarityIndex::new()), DEFAULT_THRESHOLD),
        store,
        Arc::new(FailureCooldown::new(600)),
        Arc::new(SystemClock),
    )
}

fn base_active_entry(id: &str) -> MemoryEntry {
    MemoryEntry {
        id: id.into(),
        agent_id: "agent:r".into(),
        entry_type: MemoryType::Fact,
        content: format!("content-of-{id}"),
        tags: vec![],
        created_at: "2026-05-22T00:00:00Z".into(),
        task_origin: Some("task-001".into()),
        is_active: true,
        superseded_by: None,
        status: MemoryStatus::Active,
        supersession_reason: None,
        cluster_id: None,
        sources: vec![MemorySource::TaskTurn {
            task_id: "task-001".into(),
            turn: 1,
        }],
    }
}

// ────────────────────────────────────────────────────────────────────
// CountingEmbedder — test-only Embedder wrapper for T40 call_count tracking.
//
// Wraps any `Arc<dyn Embedder + Send + Sync>` and counts `embed` invocations
// in an `Arc<AtomicUsize>`. Slice F's T40 (AC-27 brief-change gate) needs to
// assert that `Embedder::embed` is called exactly twice across 3 mixed-brief
// `sync_task_index` calls: 1st call (first-write — embeds), 2nd call (brief
// unchanged — does NOT embed; preserves prev `brief_embedding`), 3rd call
// (brief changes — embeds again).
// ────────────────────────────────────────────────────────────────────

struct CountingEmbedder {
    inner: Arc<dyn Embedder + Send + Sync>,
    call_count: Arc<AtomicUsize>,
}

impl CountingEmbedder {
    fn new(inner: Arc<dyn Embedder + Send + Sync>) -> (Self, Arc<AtomicUsize>) {
        let call_count = Arc::new(AtomicUsize::new(0));
        (
            Self {
                inner,
                call_count: Arc::clone(&call_count),
            },
            call_count,
        )
    }
}

#[async_trait]
impl Embedder for CountingEmbedder {
    async fn embed(&self, text: &str) -> Result<Vec<f32>, EmbedderError> {
        self.call_count.fetch_add(1, Ordering::SeqCst);
        self.inner.embed(text).await
    }
}

// ────────────────────────────────────────────────────────────────────
// T38 — AC-19 sync_turn_index
// ────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn module_011_t38_sync_turn_index_writes_embedding_with_task_id_derived_from_turn() {
    let store = Arc::new(MemoryStore::new());
    let components = components_with_store(store);

    let turn = test_turn_entry(7, "task-001", "test digest", "test view");
    components
        .sync_turn_index("agent:r", &turn)
        .await
        .expect("sync_turn_index ok");

    let row = components
        .sqlite_index
        .get_turn("agent:r", "task-001", 7)
        .expect("row written");

    assert_eq!(
        row.embedding.len(),
        STUB_EMBEDDING_DIM,
        "StubEmbedder fixed-width"
    );
    assert!(
        row.embedding.iter().any(|&x| x != 0.0),
        "non-trivial sketch — non-empty input must produce at least one non-zero element"
    );
    assert_eq!(row.digest, "test digest");
    assert_eq!(
        row.task_id, "task-001",
        "task_id MUST be derived from turn.task_id (not separately passed)"
    );
    assert_eq!(row.agent_id, "agent:r");
    assert_eq!(row.turn, 7);
    assert_eq!(row.reference_count, 0);

    // Determinism: a second sync of the same TurnEntry produces a byte-identical row.
    components
        .sync_turn_index("agent:r", &turn)
        .await
        .expect("re-sync ok");
    let row2 = components
        .sqlite_index
        .get_turn("agent:r", "task-001", 7)
        .expect("re-sync row");
    assert_eq!(
        row2.embedding, row.embedding,
        "StubEmbedder is deterministic across re-runs"
    );
}

// ────────────────────────────────────────────────────────────────────
// T39 — AC-24 sync_memory_index across 5 MemoryStatus variants
// ────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn module_011_t39_sync_memory_index_mirrors_all_5_statuses() {
    let store = Arc::new(MemoryStore::new());
    let components = components_with_store(Arc::clone(&store));
    let agent = "agent:r";

    // Seed 5 Active entries e1..e5; then transition 4 in invariant-respecting
    // order. The apply_action(Supersede) auto-inserts a new e6 Active entry
    // as a side effect — T39 asserts presence of e1..e5 (not list equality).
    for id in ["e1", "e2", "e3", "e4", "e5"] {
        store
            .insert(agent, base_active_entry(id))
            .expect("seed insert");
    }
    store.mark_contested(agent, "e2").expect("mark_contested");
    store.mark_orphaned(agent, "e3").expect("mark_orphaned");

    // apply_action(Supersede) on e4 → e4 becomes Superseded; e6 (the
    // `new_entry`) inserted as Active.
    let mut e6 = base_active_entry("e6");
    e6.content = "supersedes-e4".into();
    store
        .apply_action(
            agent,
            MemoryAction::Supersede {
                old_id: "e4".into(),
                new_entry: e6,
                reason: SupersessionReason::Merge,
            },
        )
        .expect("apply_action(Supersede)");

    store.forget(agent, "e5").expect("forget");

    components.sync_memory_index(agent);

    let rows = components.sqlite_index.list_memory_for_agent(agent);
    assert!(rows.len() >= 5, "at least 5 rows present (e6 is extra)");

    // Index rows by memory_id for explicit per-AC assertions.
    let by_id: std::collections::HashMap<String, String> = rows
        .into_iter()
        .map(|r| (r.memory_id, r.epistemic_status))
        .collect();
    assert_eq!(by_id.get("e1"), Some(&"active".to_owned()));
    assert_eq!(by_id.get("e2"), Some(&"contested".to_owned()));
    assert_eq!(by_id.get("e3"), Some(&"orphaned".to_owned()));
    assert_eq!(by_id.get("e4"), Some(&"superseded".to_owned()));
    assert_eq!(by_id.get("e5"), Some(&"forgotten".to_owned()));
}

// ────────────────────────────────────────────────────────────────────
// T40 — AC-27 sync_task_index brief-change gate
// ────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn module_011_t40_sync_task_index_brief_change_gate_uses_string_equality() {
    let store = Arc::new(MemoryStore::new());
    let (counting, call_count) = CountingEmbedder::new(Arc::new(StubEmbedder));
    let counting_arc: Arc<dyn Embedder + Send + Sync> = Arc::new(counting);

    let mut components = components_with_store(store);
    components.embedder = Arc::clone(&counting_arc);

    // Call 1: first-write with brief = "Initial" → embeds (call_count: 1).
    components
        .sync_task_index(&test_summary("task-001", "agent:r", "Initial", 1))
        .await
        .expect("sync 1 ok");
    let row1 = components.sqlite_index.get_task("task-001").expect("row 1");
    assert_eq!(call_count.load(Ordering::SeqCst), 1, "first-write embeds");
    let e1 = row1.brief_embedding.clone().expect("brief_embedding 1");
    assert_eq!(row1.brief_snapshot, "Initial");
    assert_eq!(row1.turns_total, 1);

    // Call 2: same brief = "Initial" → gate fires; does NOT embed (call_count stays 1).
    components
        .sync_task_index(&test_summary("task-001", "agent:r", "Initial", 2))
        .await
        .expect("sync 2 ok");
    let row2 = components.sqlite_index.get_task("task-001").expect("row 2");
    assert_eq!(
        call_count.load(Ordering::SeqCst),
        1,
        "unchanged brief MUST NOT trigger re-embed"
    );
    assert_eq!(
        row2.brief_embedding.as_ref(),
        Some(&e1),
        "brief_embedding preserved verbatim across no-change"
    );
    assert_eq!(row2.brief_snapshot, "Initial");
    assert_eq!(row2.turns_total, 2, "per-turn metadata advances");

    // Call 3: brief changes to "Revised" → embeds (call_count: 2).
    components
        .sync_task_index(&test_summary("task-001", "agent:r", "Revised", 3))
        .await
        .expect("sync 3 ok");
    let row3 = components.sqlite_index.get_task("task-001").expect("row 3");
    assert_eq!(
        call_count.load(Ordering::SeqCst),
        2,
        "brief change re-embeds"
    );
    let e2 = row3.brief_embedding.clone().expect("brief_embedding 3");
    assert_ne!(e2, e1, "distinct briefs yield distinct embeddings");
    assert_eq!(row3.brief_snapshot, "Revised");
    assert_eq!(row3.turns_total, 3);
}

// ────────────────────────────────────────────────────────────────────
// T41 — AC-31 bump_turn_reference embedding-unchanged invariant
// ────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn module_011_t41_bump_turn_reference_preserves_embedding_byte_for_byte() {
    let store = Arc::new(MemoryStore::new());
    let components = components_with_store(store);
    let agent = "agent:r";

    // Seed turn=1 via sync_turn_index; capture embedding bytes.
    let turn1 = test_turn_entry(1, "task-001", "D1", "cv1");
    components
        .sync_turn_index(agent, &turn1)
        .await
        .expect("seed sync_turn_index");
    let e_old = components
        .sqlite_index
        .get_turn(agent, "task-001", 1)
        .expect("seeded row")
        .embedding
        .clone();
    assert_eq!(e_old.len(), STUB_EMBEDDING_DIM);

    // 3 bumps; each returns true; embedding stays bytes-for-bytes.
    for _ in 0..3 {
        let bumped = components.bump_turn_reference(agent, "task-001", 1);
        assert!(bumped, "existing row → returns true");
    }

    let row = components
        .sqlite_index
        .get_turn(agent, "task-001", 1)
        .expect("post-bump row");
    assert_eq!(row.reference_count, 3, "reference_count bumped 3×");
    assert_eq!(
        row.embedding, e_old,
        "embedding MUST NOT be recomputed on reference_count bump (AC-31 invariant)"
    );

    // Negative case: non-existent turn → returns false, no row created.
    let bumped = components.bump_turn_reference(agent, "task-001", 99);
    assert!(!bumped, "non-existent turn → returns false");
    assert!(
        components
            .sqlite_index
            .get_turn(agent, "task-001", 99)
            .is_none(),
        "no row created for non-existent bump"
    );
}

// ────────────────────────────────────────────────────────────────────
// T42 — AC-08 9-step trace order regression
// ────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn module_011_t42_post_processor_run_still_traces_9_steps_in_order_after_slice_f() {
    let store = Arc::new(MemoryStore::new());
    let components = components_with_store(store);
    let pp = PostProcessor::with_components(components);

    let msg = Message {
        id: "msg-test-001".into(),
        kind: MessageKind::User,
        from: "user:test".into(),
        to: "agent:r".into(),
        payload: vec![],
        context: None,
        timestamp: SystemTime::UNIX_EPOCH,
        origin: None,
    };
    let result = ActionResult {
        new_state: vec![],
        actions: vec![],
    };

    pp.run("agent:r", &msg, &result).await.expect("run ok");

    let trace = pp.trace_snapshot();
    let expected: Vec<String> = cap_memory::post_processor::CANONICAL_STEPS
        .iter()
        .map(|s| s.to_string())
        .collect();
    assert_eq!(
        trace, expected,
        "Slice F MUST NOT perturb the 9-step canonical trace (AC-08 regression)"
    );
}

// ────────────────────────────────────────────────────────────────────
// Defense-in-depth: confirm `with_l6_defaults` ctor SIGNATURE is unchanged
// (caller still passes the 5 slice-B/C params; new sqlite_index + embedder
// fields are default-injected internally — round-3 Plan-Eval W1 resolution).
// ────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn module_011_slice_f_components_with_l6_defaults_signature_unchanged() {
    let store = Arc::new(MemoryStore::new());
    // 5-arg call — same shape as existing slice-B/C call sites at
    // integration_pipeline.rs:146/250 + integration_observability.rs:329.
    let _components = Components::with_l6_defaults(
        Arc::new(StubBatchExtractor::with_extraction(Default::default())),
        Reconciler::from_concrete(Arc::new(InMemorySimilarityIndex::new()), DEFAULT_THRESHOLD),
        store,
        Arc::new(FailureCooldown::new(600)),
        Arc::new(SystemClock),
    );
    // sqlite_index + embedder fields are default-injected; access them to
    // confirm they exist on the public struct.
    let _: Arc<dyn SqliteIndex + Send + Sync> = Arc::clone(&_components.sqlite_index);
    let _: Arc<dyn Embedder + Send + Sync> = Arc::clone(&_components.embedder);
}
