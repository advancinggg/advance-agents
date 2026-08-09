//! MODULE-011 slice D — AC-37 / T37 observability-emission integration tests
//! (OBS-01..06 + OBS-08). The 5 agent-memory WIT handlers emit canonical PRD
//! §15.3.12 `memory.*` events on the success path; the L6 Step-9 Seam-B path
//! emits `memory.l6_consolidation_due` through a real `EventBusL6Emitter`
//! when `Components` is built via `Components::wired`.
//!
//! Coverage split (MODULE-011 §3.3 T37 / plan): OBS-07 (EventBusL6Emitter
//! wire shape) is the `l6/emit.rs` unit test `eventbus_l6_emitter_wire_shape`;
//! OBS-09 (round-trip non-regression) is `integration_wit.rs`; OBS-10 (AC-14
//! lint) is `advance-observability-xtask` `t73_b…`; OBS-11 (slice-C L6 asserts
//! unchanged) is `integration_l6.rs`.

use std::sync::{Arc, Mutex};

use advance_runtime::host_registry::{HostCallContext, HostRegistry, InMemoryHostRegistry};
use advance_shared_types::event::Event;
use advance_shared_types::traits::EventBusEmit;
use cap_memory::{
    register_agent_memory, L6CursorStore, MemoryEntry, MemoryStatus, MemoryStore, MemoryType,
    CAPABILITY, NAMESPACE,
};
use wasmtime::component::Val;

/// Recording `EventBusEmit` double — captures every emitted `Event`.
#[derive(Default)]
struct RecordingBus {
    events: Mutex<Vec<Event>>,
}

impl RecordingBus {
    fn snapshot(&self) -> Vec<Event> {
        self.events
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }
}

impl EventBusEmit for RecordingBus {
    fn emit(&self, event: Event) {
        self.events
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(event);
    }
}

fn ctx_for(agent: &str) -> HostCallContext {
    HostCallContext {
        agent_id: agent.to_string(),
        trace_id: "trace-obs".to_string(),
        turn_id: None,
        capability: CAPABILITY.to_string(),
        function: format!("{}::test", NAMESPACE),
        run_id: None,
        iteration: None,
    }
}

fn registry_with_bus() -> (
    Arc<InMemoryHostRegistry>,
    Arc<MemoryStore>,
    Arc<RecordingBus>,
) {
    let reg = Arc::new(InMemoryHostRegistry::new());
    let store = Arc::new(MemoryStore::new());
    let bus = Arc::new(RecordingBus::default());
    register_agent_memory(
        reg.as_ref(),
        Arc::clone(&store),
        bus.clone(),
        Arc::new(L6CursorStore::new()),
    );
    (reg, store, bus)
}

fn spec_named<'a>(
    specs: &'a [advance_runtime::host_registry::HostFunctionSpec],
    name: &str,
) -> &'a advance_runtime::host_registry::HostFunctionSpec {
    specs
        .iter()
        .find(|s| s.name == name)
        .unwrap_or_else(|| panic!("no spec named {}", name))
}

fn seed(store: &MemoryStore, agent: &str, id: &str, content: &str, created_at: &str) {
    store
        .insert(
            agent,
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
            },
        )
        .expect("seed insert ok");
}

// ───────────────────────── OBS-01 — memory.remember ─────────────────────────

#[tokio::test]
async fn obs_01_remember_emits_memory_remember() {
    let (reg, _store, bus) = registry_with_bus();
    let specs = reg.lookup(CAPABILITY);
    let remember = spec_named(&specs, "remember");

    let long = "Z".repeat(300);
    remember
        .handler
        .call(
            ctx_for("agent:a"),
            vec![
                Val::String(long.clone()),
                Val::List(vec![Val::String("t1".into()), Val::String("t2".into())]),
            ],
            1,
        )
        .await
        .expect("remember ok");

    let evs = bus.snapshot();
    assert_eq!(evs.len(), 1, "exactly one event on success");
    let e = &evs[0];
    assert_eq!(e.event_type, "memory.remember");
    assert_eq!(e.agent_id, "agent:a");
    assert_eq!(e.trace_id, "trace-obs");
    assert!(e.task_id.is_none());
    let cp = e.payload["content_preview"].as_str().unwrap();
    assert!(cp.ends_with('…'), "long content is truncated");
    assert_eq!(cp.chars().count(), 65, "≤64 chars + the … marker");
    assert_eq!(e.payload["tags"], serde_json::json!(["t1", "t2"]));
    assert_eq!(e.payload["agent_id"], "agent:a");
}

// ───────────────────────── OBS-02 — memory.recall ──────────────────────────

#[tokio::test]
async fn obs_02_recall_emits_memory_recall_with_bounded_query() {
    let (reg, store, bus) = registry_with_bus();
    // Slice-B `recall` substring-matches the *entire* query against entry
    // content (store.rs::matches — no tokenization). To get a non-zero
    // result_count from a >256-char query, the seeded content must contain
    // that query verbatim. OBS-02's contract is that the EMITTED `query`
    // is bounded to ≤256+… while `result_count` still reflects real hits.
    let long_q = "alpha ".repeat(100); // 600 chars > 256
    seed(
        &store,
        "agent:a",
        "m1",
        &format!("{} hit one", long_q),
        "2026-01-01T00:00:00Z",
    );
    seed(
        &store,
        "agent:a",
        "m2",
        &format!("{} hit two", long_q),
        "2026-01-02T00:00:00Z",
    );
    let specs = reg.lookup(CAPABILITY);
    let recall = spec_named(&specs, "recall");

    recall
        .handler
        .call(
            ctx_for("agent:a"),
            vec![Val::String(long_q), Val::U32(10)],
            1,
        )
        .await
        .expect("recall ok");

    let evs = bus.snapshot();
    assert_eq!(evs.len(), 1);
    let e = &evs[0];
    assert_eq!(e.event_type, "memory.recall");
    assert_eq!(e.payload["result_count"], serde_json::json!(2));
    assert!(e.payload["top_score"].is_null(), "slice-B has no scoring");
    let q = e.payload["query"].as_str().unwrap();
    assert!(
        q.ends_with('…') && q.chars().count() == 257,
        "query ≤256 + …"
    );
}

// ───────────────────────── OBS-03 — memory.forget ──────────────────────────

#[tokio::test]
async fn obs_03_forget_emits_memory_forget() {
    let (reg, store, bus) = registry_with_bus();
    seed(
        &store,
        "agent:a",
        "doomed",
        "to be forgotten",
        "2026-01-01T00:00:00Z",
    );
    let specs = reg.lookup(CAPABILITY);
    let forget = spec_named(&specs, "forget");

    forget
        .handler
        .call(ctx_for("agent:a"), vec![Val::String("doomed".into())], 1)
        .await
        .expect("forget ok");

    let evs = bus.snapshot();
    assert_eq!(evs.len(), 1);
    assert_eq!(evs[0].event_type, "memory.forget");
    assert_eq!(evs[0].payload["memory_id"], "doomed");
    assert_eq!(evs[0].payload["agent_id"], "agent:a");
}

// ──────────────────────── OBS-04 — memory.recall_at ────────────────────────

#[tokio::test]
async fn obs_04_recall_at_emits_memory_recall_at() {
    let (reg, store, bus) = registry_with_bus();
    seed(&store, "agent:a", "early", "note", "2026-01-01T00:00:00Z");
    seed(&store, "agent:a", "late", "note", "2026-09-01T00:00:00Z");
    let specs = reg.lookup(CAPABILITY);
    let recall_at = spec_named(&specs, "recall-at");

    recall_at
        .handler
        .call(
            ctx_for("agent:a"),
            vec![
                Val::String("note".into()),
                Val::String("2026-03-01T00:00:00Z".into()),
                Val::U32(10),
            ],
            1,
        )
        .await
        .expect("recall-at ok");

    let evs = bus.snapshot();
    assert_eq!(evs.len(), 1);
    let e = &evs[0];
    assert_eq!(e.event_type, "memory.recall_at");
    assert_eq!(e.payload["query"], "note");
    assert_eq!(e.payload["timestamp"], "2026-03-01T00:00:00Z");
    assert_eq!(
        e.payload["result_count"],
        serde_json::json!(1),
        "only the early entry"
    );
}

// ──────────────────────── OBS-05 — memory.rollback ─────────────────────────

#[tokio::test]
async fn obs_05_rollback_emits_exact_entries_deactivated() {
    let (reg, store, bus) = registry_with_bus();
    // 1 surviving + 3 dropped (created_at > ts).
    seed(&store, "agent:a", "keep", "k", "2026-01-01T00:00:00Z");
    seed(&store, "agent:a", "d1", "x", "2026-06-01T00:00:00Z");
    seed(&store, "agent:a", "d2", "y", "2026-07-01T00:00:00Z");
    seed(&store, "agent:a", "d3", "z", "2026-08-01T00:00:00Z");
    let specs = reg.lookup(CAPABILITY);
    let rollback = spec_named(&specs, "rollback-memory");

    rollback
        .handler
        .call(
            ctx_for("agent:a"),
            vec![Val::String("2026-03-01T00:00:00Z".into())],
            1,
        )
        .await
        .expect("rollback ok");

    let evs = bus.snapshot();
    assert_eq!(evs.len(), 1);
    let e = &evs[0];
    assert_eq!(e.event_type, "memory.rollback");
    assert_eq!(e.payload["target_timestamp"], "2026-03-01T00:00:00Z");
    assert_eq!(
        e.payload["entries_deactivated"],
        serde_json::json!(3),
        "exact atomic dropped-count"
    );
}

// ──────── OBS-06 — emission is success-scoped (error paths emit nothing) ─────

#[tokio::test]
async fn obs_06_error_paths_emit_nothing() {
    use cap_memory::wit_impl::MAX_CONTENT_BYTES;
    let (reg, _store, bus) = registry_with_bus();
    let specs = reg.lookup(CAPABILITY);
    let remember = spec_named(&specs, "remember");
    let forget = spec_named(&specs, "forget");

    // Oversized content → LimitExceeded (validation error early-return).
    remember
        .handler
        .call(
            ctx_for("agent:a"),
            vec![
                Val::String("A".repeat(MAX_CONTENT_BYTES + 1)),
                Val::List(vec![]),
            ],
            1,
        )
        .await
        .expect("dispatch ok");
    // forget unknown id → not-found error.
    forget
        .handler
        .call(ctx_for("agent:a"), vec![Val::String("nope".into())], 1)
        .await
        .expect("dispatch ok");

    assert!(
        bus.snapshot().is_empty(),
        "emission is success-scoped: validation/store errors emit no event"
    );
}

// ───── OBS-08 — Seam B: post-processor Step 9 via Components::wired ─────────

#[tokio::test]
async fn obs_08_step9_emits_l6_consolidation_due_via_real_eventbus() {
    use advance_shared_types::mailbox::{ActionResult, Message, MessageKind};
    use advance_shared_types::memory::PostProcessorHook;
    use cap_memory::post_processor::{Components, PostProcessor};
    use cap_memory::{
        FailureCooldown, InMemorySimilarityIndex, MutableClock, Reconciler, StubBatchExtractor,
        DEFAULT_THRESHOLD,
    };

    let store = Arc::new(MemoryStore::new());
    let bus = Arc::new(RecordingBus::default());
    // `Components::wired` sets l6_emitter = EventBusL6Emitter(bus). Default
    // L6TriggerState (last_l6_at == None) ⇒ Step 9's HoursSinceLast fires, so
    // begin_acquire → confirm_acquire → emit_consolidation_due executes.
    let components = Components::wired(
        Arc::new(StubBatchExtractor::with_extraction(Default::default())),
        Reconciler::from_concrete(Arc::new(InMemorySimilarityIndex::new()), DEFAULT_THRESHOLD),
        Arc::clone(&store),
        Arc::new(FailureCooldown::new(600)),
        Arc::new(MutableClock::new(std::time::SystemTime::UNIX_EPOCH)),
        bus.clone(),
    );
    let pp = PostProcessor::with_components(components);
    let msg = Message {
        id: "msg-obs8".into(),
        kind: MessageKind::User,
        from: "user:test".into(),
        to: "agent:r".into(),
        payload: vec![],
        context: None,
        timestamp: std::time::SystemTime::UNIX_EPOCH,
        origin: None,
    };
    let res = ActionResult {
        new_state: vec![],
        actions: vec![],
    };
    pp.run("agent:r", &msg, &res).await.expect("run ok");

    let evs = bus.snapshot();
    let due: Vec<&Event> = evs
        .iter()
        .filter(|e| e.event_type == "memory.l6_consolidation_due")
        .collect();
    assert_eq!(
        due.len(),
        1,
        "Step 9 fired ⇒ exactly one memory.l6_consolidation_due on the real EventBus"
    );
    let e = due[0];
    assert_eq!(e.agent_id, "agent:r");
    assert_eq!(e.payload["agent_id"], "agent:r");
    let lease_id = e.payload["lease_id"].as_str().expect("lease_id present");
    // lease_id is the NON-SECRET digest of the live lease token — the
    // token-checked bearer secret is NEVER serialized onto the wire
    // (§3.8 note 8). Digest form `l6lease-{16 hex}` (24 chars), never the
    // bare 32-hex `Uuid::simple()` bearer token.
    assert!(
        lease_id.starts_with("l6lease-") && lease_id.len() == 24,
        "lease_id must be the non-secret digest, not the raw bearer token (got {:?})",
        lease_id
    );
    // Exactly the PRD §15.4 {agent_id, lease_id} shape.
    assert_eq!(e.payload.as_object().unwrap().len(), 2);
}
