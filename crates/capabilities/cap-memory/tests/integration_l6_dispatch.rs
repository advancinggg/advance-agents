//! MODULE-011 slice satC-l6 (SAT-C) — in-process L6 dispatch + Step-5
//! `record_new_entry` integration tests. Drives `PostProcessor::run` through
//! Step-9 with a recording `L6Dispatch` double (modeled on
//! `integration_l6.rs::l6_i_10_post_processor_step9_emit`). Deterministic stubs,
//! in-memory backing. These gate via `cargo test` (the satellite flips no AC).

use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use advance_shared_types::mailbox::{ActionResult, Message, MessageKind};
use advance_shared_types::memory::PostProcessorHook;
use async_trait::async_trait;

use cap_memory::clock::MutableClock;
use cap_memory::knowledge::{MemoryEntry, MemoryStatus, MemoryType};
use cap_memory::l6::{
    InMemoryEmitter, InMemoryLeaseStore, L6Emitter, L6TriggerEvaluator, L6TriggerState,
    LeaseDecision, LeaseStore,
};
use cap_memory::store::MemoryStore;
use cap_memory::{
    Components, Extraction, FailureCooldown, InMemorySimilarityIndex, InMemorySqliteIndex,
    L6CursorStore, L6Dispatch, NoopEventBus, PostProcessor, Reconciler, StubBatchExtractor,
    StubEmbedder, DEFAULT_THRESHOLD,
};

fn t0() -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000)
}

fn fixture_msg() -> Message {
    Message {
        id: "msg-dsp".into(),
        kind: MessageKind::User,
        from: "user:test".into(),
        to: "agent:r".into(),
        payload: vec![],
        context: None,
        timestamp: SystemTime::UNIX_EPOCH,
        origin: None,
    }
}

fn fixture_result() -> ActionResult {
    ActionResult {
        new_state: vec![],
        actions: vec![],
    }
}

fn kentry(id: &str, content: &str) -> MemoryEntry {
    MemoryEntry {
        id: id.into(),
        agent_id: "agent:r".into(),
        entry_type: MemoryType::Fact,
        content: content.into(),
        tags: vec![],
        created_at: "2026-01-01T00:00:00Z".into(),
        task_origin: None,
        is_active: true,
        superseded_by: None,
        status: MemoryStatus::Active,
        supersession_reason: None,
        cluster_id: None,
        sources: vec![],
    }
}

/// A recording `L6Dispatch` double: logs each `(agent_id, lease_token)` and
/// returns a configurable success bool (drives the mark_l6_ran / retry paths).
/// On failure it mirrors the REAL runnable's Err-arm by releasing the lease
/// (token-checked) — so the next trigger's `begin_acquire` succeeds and retries.
struct RecordingDispatch {
    calls: Arc<Mutex<Vec<(String, String)>>>,
    return_ok: bool,
    lease: Option<Arc<InMemoryLeaseStore>>,
}

#[async_trait]
impl L6Dispatch for RecordingDispatch {
    async fn dispatch(&self, agent_id: &str, lease_token: &str) -> bool {
        self.calls
            .lock()
            .unwrap()
            .push((agent_id.to_string(), lease_token.to_string()));
        if !self.return_ok {
            if let Some(l) = &self.lease {
                l.release(agent_id, lease_token);
            }
        }
        self.return_ok
    }
}

/// Build a `Components` with the given shared L6 handles + extraction; no L6
/// handler attached (each test attaches one via `with_l6_handler` if needed).
fn make_components(
    store: Arc<MemoryStore>,
    trigger_state: Arc<Mutex<L6TriggerState>>,
    lease: Arc<InMemoryLeaseStore>,
    emitter: Arc<InMemoryEmitter>,
    extraction: Extraction,
) -> Components {
    let lease_dyn: Arc<dyn LeaseStore + Send + Sync> = lease;
    let emitter_dyn: Arc<dyn L6Emitter + Send + Sync> = emitter;
    Components {
        extractor: Arc::new(StubBatchExtractor::with_extraction(extraction)),
        reconciler: Reconciler::from_concrete(
            Arc::new(InMemorySimilarityIndex::new()),
            DEFAULT_THRESHOLD,
        ),
        store,
        cooldown: Arc::new(FailureCooldown::new(600)),
        clock: Arc::new(MutableClock::new(t0())),
        trigger: Arc::new(L6TriggerEvaluator::new()),
        lease: lease_dyn,
        l6_emitter: emitter_dyn,
        l6_trigger_state: trigger_state,
        event_bus: Arc::new(NoopEventBus),
        sqlite_index: Arc::new(InMemorySqliteIndex::default()),
        embedder: Arc::new(StubEmbedder),
        cursor_store: Arc::new(L6CursorStore::new()),
        fs_root: None,
        write_agent_id: None,
        l6_handler: None,
        description_indexer: None,
    }
}

/// DSP-01 — a firing trigger dispatches once into the attached handler with the
/// agent id + a non-empty live lease token.
#[tokio::test]
async fn dsp_01_step9_dispatches_into_handler_on_trigger() {
    let store = Arc::new(MemoryStore::new());
    // Default trigger state (last_l6_at == None) → HoursSinceLast fires.
    let trigger_state = Arc::new(Mutex::new(L6TriggerState::default()));
    let lease = Arc::new(InMemoryLeaseStore::new());
    let emitter = Arc::new(InMemoryEmitter::new());
    let calls = Arc::new(Mutex::new(Vec::new()));
    let components = make_components(
        Arc::clone(&store),
        Arc::clone(&trigger_state),
        Arc::clone(&lease),
        Arc::clone(&emitter),
        Extraction::default(),
    )
    .with_l6_handler(Arc::new(RecordingDispatch {
        calls: Arc::clone(&calls),
        return_ok: true,
        lease: None,
    }));
    let pp = PostProcessor::with_components(components);
    pp.run("agent:r", &fixture_msg(), &fixture_result())
        .await
        .expect("run ok");
    let c = calls.lock().unwrap();
    assert_eq!(
        c.len(),
        1,
        "Step-9 dispatches exactly once on a firing trigger"
    );
    assert_eq!(c[0].0, "agent:r");
    assert!(!c[0].1.is_empty(), "dispatch receives the live lease token");
}

/// DSP-02 — a second trigger while a lease is already held does NOT start a
/// second consolidation nor re-emit consolidation_due (single-flight; 215 shape).
#[tokio::test]
async fn dsp_02_already_held_lease_skips_dispatch_and_emit() {
    let store = Arc::new(MemoryStore::new());
    let trigger_state = Arc::new(Mutex::new(L6TriggerState::default()));
    let lease = Arc::new(InMemoryLeaseStore::new());
    // Pre-acquire + confirm a live lease so Step-9 begin_acquire → AlreadyHeld.
    let pre = match lease.begin_acquire("agent:r", t0(), Duration::from_secs(600)) {
        LeaseDecision::Acquired { token } => token,
        other => panic!("expected Acquired, got {other:?}"),
    };
    assert!(lease.confirm_acquire("agent:r", &pre));
    let emitter = Arc::new(InMemoryEmitter::new());
    let calls = Arc::new(Mutex::new(Vec::new()));
    let components = make_components(
        Arc::clone(&store),
        Arc::clone(&trigger_state),
        Arc::clone(&lease),
        Arc::clone(&emitter),
        Extraction::default(),
    )
    .with_l6_handler(Arc::new(RecordingDispatch {
        calls: Arc::clone(&calls),
        return_ok: true,
        lease: None,
    }));
    let pp = PostProcessor::with_components(components);
    pp.run("agent:r", &fixture_msg(), &fixture_result())
        .await
        .expect("run ok");
    assert!(
        calls.lock().unwrap().is_empty(),
        "AlreadyHeld lease → no dispatch (single-flight)"
    );
    assert!(
        emitter.consolidation_due().is_empty(),
        "AlreadyHeld → no re-emit of memory.l6_consolidation_due"
    );
}

/// DSP-03 — a SUCCESSFUL dispatch marks the trigger as run (last_l6_at set), so
/// the next turn does NOT re-consolidate (no run-every-turn regression).
#[tokio::test]
async fn dsp_03_success_marks_l6_ran_no_reconsolidate_next_turn() {
    let store = Arc::new(MemoryStore::new());
    let trigger_state = Arc::new(Mutex::new(L6TriggerState::default()));
    let lease = Arc::new(InMemoryLeaseStore::new());
    let emitter = Arc::new(InMemoryEmitter::new());
    let calls = Arc::new(Mutex::new(Vec::new()));
    let components = make_components(
        Arc::clone(&store),
        Arc::clone(&trigger_state),
        Arc::clone(&lease),
        Arc::clone(&emitter),
        Extraction::default(),
    )
    .with_l6_handler(Arc::new(RecordingDispatch {
        calls: Arc::clone(&calls),
        return_ok: true,
        lease: None,
    }));
    let pp = PostProcessor::with_components(components);
    pp.run("agent:r", &fixture_msg(), &fixture_result())
        .await
        .expect("run 1");
    pp.run("agent:r", &fixture_msg(), &fixture_result())
        .await
        .expect("run 2");
    assert_eq!(
        calls.lock().unwrap().len(),
        1,
        "success → mark_l6_ran → the 2nd turn does NOT re-consolidate"
    );
    assert!(
        trigger_state.lock().unwrap().last_l6_at.is_some(),
        "a successful dispatch sets last_l6_at"
    );
}

/// DSP-04 — a FAILED dispatch does NOT mark the trigger as run, so the next
/// trigger retries (216 shape: the next trigger re-attempts).
#[tokio::test]
async fn dsp_04_failure_leaves_trigger_unmarked_next_turn_retries() {
    let store = Arc::new(MemoryStore::new());
    let trigger_state = Arc::new(Mutex::new(L6TriggerState::default()));
    let lease = Arc::new(InMemoryLeaseStore::new());
    let emitter = Arc::new(InMemoryEmitter::new());
    let calls = Arc::new(Mutex::new(Vec::new()));
    let components = make_components(
        Arc::clone(&store),
        Arc::clone(&trigger_state),
        Arc::clone(&lease),
        Arc::clone(&emitter),
        Extraction::default(),
    )
    .with_l6_handler(Arc::new(RecordingDispatch {
        calls: Arc::clone(&calls),
        return_ok: false,
        lease: Some(Arc::clone(&lease)),
    }));
    let pp = PostProcessor::with_components(components);
    pp.run("agent:r", &fixture_msg(), &fixture_result())
        .await
        .expect("run 1");
    pp.run("agent:r", &fixture_msg(), &fixture_result())
        .await
        .expect("run 2");
    assert_eq!(
        calls.lock().unwrap().len(),
        2,
        "a failed dispatch leaves the trigger unmarked → the next turn retries"
    );
    assert!(
        trigger_state.lock().unwrap().last_l6_at.is_none(),
        "a failed dispatch must NOT mark_l6_ran"
    );
}

/// DSP-05 — Step-5 `record_new_entry` increments the L6 ">=20 new entries"
/// watermark once per inserted knowledge entry (068). No L6 handler → no
/// mark_l6_ran reset, so the counter survives the run.
#[tokio::test]
async fn dsp_05_step5_record_new_entry_increments_per_insert() {
    let store = Arc::new(MemoryStore::new());
    let trigger_state = Arc::new(Mutex::new(L6TriggerState::default()));
    let lease = Arc::new(InMemoryLeaseStore::new());
    let emitter = Arc::new(InMemoryEmitter::new());
    let extraction = Extraction {
        knowledge: vec![
            kentry("k1", "alpha fact one"),
            kentry("k2", "beta fact two"),
        ],
        ..Default::default()
    };
    // No handler → Step-9 never dispatches/marks, so the counter is not reset.
    let components = make_components(
        Arc::clone(&store),
        Arc::clone(&trigger_state),
        Arc::clone(&lease),
        Arc::clone(&emitter),
        extraction,
    );
    let pp = PostProcessor::with_components(components);
    pp.run("agent:r", &fixture_msg(), &fixture_result())
        .await
        .expect("run ok");
    assert_eq!(
        trigger_state.lock().unwrap().new_entries_since_last,
        2,
        "record_new_entry increments once per inserted knowledge entry"
    );
}

/// DSP-06 — with NO L6 handler, Step-9 still emits memory.l6_consolidation_due
/// (no panic, 9-step trace preserved) — the pre-SAT-C / degraded-path
/// non-regression.
#[tokio::test]
async fn dsp_06_no_handler_emits_consolidation_due_no_panic() {
    let store = Arc::new(MemoryStore::new());
    let trigger_state = Arc::new(Mutex::new(L6TriggerState::default()));
    let lease = Arc::new(InMemoryLeaseStore::new());
    let emitter = Arc::new(InMemoryEmitter::new());
    let components = make_components(
        Arc::clone(&store),
        Arc::clone(&trigger_state),
        Arc::clone(&lease),
        Arc::clone(&emitter),
        Extraction::default(),
    );
    let pp = PostProcessor::with_components(components);
    pp.run("agent:r", &fixture_msg(), &fixture_result())
        .await
        .expect("run ok (no panic with no L6 handler)");
    assert_eq!(
        emitter.consolidation_due(),
        vec!["agent:r".to_string()],
        "Step-9 still emits consolidation_due when no L6 handler is attached"
    );
    assert_eq!(
        pp.trace_snapshot().len(),
        9,
        "the 9-step canonical trace is preserved"
    );
}

/// DSP-08 (audit r1 C1 regression) — Step-9 dispatches under the BARE write id
/// (set via `with_write_agent_id`), NOT the run() messaging id. Without this,
/// the live L6 runnable would consolidate the colon-id bucket while Steps 5/7/8
/// wrote the memory under the bare cap id — emitting l6_completed while
/// consolidating the wrong/empty bucket.
#[tokio::test]
async fn dsp_08_dispatch_uses_bare_write_id_not_messaging_id() {
    let store = Arc::new(MemoryStore::new());
    let trigger_state = Arc::new(Mutex::new(L6TriggerState::default()));
    let lease = Arc::new(InMemoryLeaseStore::new());
    let emitter = Arc::new(InMemoryEmitter::new());
    let calls = Arc::new(Mutex::new(Vec::new()));
    let components = make_components(
        Arc::clone(&store),
        Arc::clone(&trigger_state),
        Arc::clone(&lease),
        Arc::clone(&emitter),
        Extraction::default(),
    )
    .with_write_agent_id("default-agent")
    .with_l6_handler(Arc::new(RecordingDispatch {
        calls: Arc::clone(&calls),
        return_ok: true,
        lease: None,
    }));
    let pp = PostProcessor::with_components(components);
    // run() receives the COLON messaging id; the dispatch must use the bare id.
    pp.run("agent:default", &fixture_msg(), &fixture_result())
        .await
        .expect("run ok");
    let c = calls.lock().unwrap();
    assert_eq!(c.len(), 1, "Step-9 dispatches once");
    assert_eq!(
        c[0].0, "default-agent",
        "dispatch must use the BARE write id (the memory bucket), not the run() messaging id"
    );
    // The consolidation_due event is keyed by the same bare write id.
    assert_eq!(
        emitter.consolidation_due(),
        vec!["default-agent".to_string()],
        "consolidation_due is emitted under the bare write id"
    );
}
