//! MODULE-011 Slice C — L6 cross-task consolidation integration tests.
//! In-scope ACs: AC-12/13/14/15/16/32/33/34/35/36. Deterministic stubs;
//! in-memory backing. See the /dev plan §3 test design (L6-I-01..10 +
//! L6-I-01b + L6-I-08b) and MODULE-011 §3.3 T12..T16 + T32..T36.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use advance_shared_types::memory::{L6Context, L6Error, L6Handler};
use cap_memory::clock::MutableClock;
use cap_memory::knowledge::{MemoryEntry, MemorySource, MemoryStatus, MemoryType};
use cap_memory::l6::{
    ComponentFinished, FailingCommitter, FixedBatchIdSource, InMemoryCommitter, InMemoryEmitter,
    InMemoryLeaseStore, InMemoryStalenessProbe, KnowledgeMap, L6ClusterBuilder, L6CursorStore,
    L6Runnable, LeaseDecision, LeaseState, LeaseStore, StubL6Classifier, StubSynthesisGenerator,
    L6_CANONICAL_STEPS,
};
use cap_memory::store::MemoryStore;

fn t0() -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000)
}

fn fact(id: &str, content: &str, file_ref: bool) -> MemoryEntry {
    let sources = if file_ref {
        vec![MemorySource::FileRef {
            agent_id: "agent:r".into(),
            vpath: format!("data/{id}.csv"),
            commit_ish: "abc".into(),
            blob_id: format!("blob-{id}"),
            line_range: None,
        }]
    } else {
        vec![MemorySource::TaskTurn {
            task_id: "task-1".into(),
            turn: 1,
        }]
    };
    MemoryEntry {
        id: id.into(),
        agent_id: "agent:r".into(),
        entry_type: MemoryType::Fact,
        content: content.into(),
        tags: vec!["pricing".into()],
        created_at: "2026-01-01T00:00:00Z".into(),
        task_origin: None,
        is_active: true,
        superseded_by: None,
        status: MemoryStatus::Active,
        supersession_reason: None,
        cluster_id: None,
        sources,
    }
}

/// Build an `L6Runnable` with all stub seams + a fixed batch id. Returns the
/// runnable, the shared store, lease, committer, emitter, knowledge_map.
#[allow(clippy::type_complexity)]
fn build_runnable(
    store: Arc<MemoryStore>,
    classifier: StubL6Classifier,
    staleness: InMemoryStalenessProbe,
) -> (
    L6Runnable,
    Arc<InMemoryLeaseStore>,
    Arc<InMemoryCommitter>,
    Arc<InMemoryEmitter>,
    Arc<Mutex<KnowledgeMap>>,
) {
    let lease = Arc::new(InMemoryLeaseStore::new());
    let committer = Arc::new(InMemoryCommitter::new());
    let emitter = Arc::new(InMemoryEmitter::new());
    let km = Arc::new(Mutex::new(KnowledgeMap::new()));
    let runnable = L6Runnable::new(
        "memory.l6",
        Arc::new(MutableClock::new(t0())),
        Arc::new(FixedBatchIdSource("b0c1d2e3".into())),
        Arc::clone(&store),
        Arc::clone(&lease) as Arc<dyn LeaseStore + Send + Sync>,
        Arc::new(staleness),
        Arc::new(L6ClusterBuilder::new()),
        Arc::new(classifier),
        Arc::new(StubSynthesisGenerator),
        Arc::clone(&km),
        Arc::new(Mutex::new(HashMap::new())),
        Arc::clone(&committer) as Arc<InMemoryCommitter> as Arc<_>,
        Arc::clone(&emitter) as Arc<InMemoryEmitter> as Arc<_>,
        Arc::new(cap_memory::l6::L6CursorStore::new()),
    );
    (runnable, lease, committer, emitter, km)
}

/// Acquire+confirm a lease for the agent and return the token.
fn lease_token(lease: &InMemoryLeaseStore) -> String {
    let tok = match lease.begin_acquire("agent:r", t0(), Duration::from_secs(600)) {
        LeaseDecision::Acquired { token } => token,
        other => panic!("expected Acquired, got {other:?}"),
    };
    assert!(lease.confirm_acquire("agent:r", &tok));
    tok
}

fn ctx(token: &str) -> L6Context {
    L6Context {
        agent_id: "agent:r".into(),
        triggered_at: t0(),
        cursor: None,
        lease_token: token.into(),
    }
}

// ───────────────────────────── AC-14 / AC-15 ─────────────────────────────

/// L6-I-01 — full runnable lifecycle trace == L6_CANONICAL_STEPS in order
/// across handle()[1-5] + on_component_finished()[6].
#[tokio::test]
async fn l6_i_01_six_step_lifecycle_trace() {
    let store = Arc::new(MemoryStore::new());
    for id in ["e1", "e2", "e3"] {
        store
            .insert(
                "agent:r",
                fact(id, "rust is memory safe and fast", id == "e1"),
            )
            .unwrap();
    }
    let (runnable, lease, _c, _e, _km) = build_runnable(
        Arc::clone(&store),
        StubL6Classifier::new(),
        InMemoryStalenessProbe::new(),
    );
    let tok = lease_token(&lease);
    runnable.handle(ctx(&tok)).await.expect("handle ok");
    // Step 6 fires on the matching component.finished.
    let cleared = runnable.on_component_finished(
        "agent:r",
        &ComponentFinished {
            component_id: "memory.l6".into(),
            lease_id: tok.clone(),
        },
    );
    assert!(cleared, "matching lease_id must clear");
    assert_eq!(
        runnable.trace_snapshot(),
        L6_CANONICAL_STEPS.to_vec(),
        "runnable lifecycle trace must equal the 6 canonical labels in order"
    );
}

/// L6-I-01b — CONTRACT-102 L6Outcome 5-field return contract.
#[tokio::test]
async fn l6_i_01b_l6outcome_return_contract() {
    let store = Arc::new(MemoryStore::new());
    for id in ["e1", "e2", "e3"] {
        store
            .insert(
                "agent:r",
                fact(id, "rust is memory safe and fast", id == "e1"),
            )
            .unwrap();
    }
    let classifier = StubL6Classifier::new().with_consolidated_preference("prefer-concise");
    // e1's file-ref must resolve so it is NOT stale→orphaned (else synthesis
    // gate (e) correctly fails).
    let probe = InMemoryStalenessProbe::new().with_present("agent:r", "data/e1.csv", "blob-e1");
    let (runnable, lease, _c, emitter, _km) = build_runnable(Arc::clone(&store), classifier, probe);
    let tok = lease_token(&lease);
    let outcome = runnable.handle(ctx(&tok)).await.expect("handle ok");
    assert_eq!(
        outcome.entries_written, 1,
        "one consolidated_preference appended"
    );
    assert_eq!(outcome.syntheses_written, 1, "one synthesis (gates pass)");
    assert!(outcome.knowledge_map_updated);
    assert_eq!(outcome.cluster_deltas, 1, "one multi-entry cluster");
    let payload = &emitter.emitted_l6_completed()[0];
    assert_eq!(
        outcome.health_snapshot, payload.snapshot,
        "L6Outcome.health_snapshot must equal the emitted payload snapshot (one computation)"
    );

    // Negative: empty store ⇒ all-zero/false outcome.
    let empty = Arc::new(MemoryStore::new());
    let (r2, l2, _c2, _e2, _km2) = build_runnable(
        Arc::clone(&empty),
        StubL6Classifier::new(),
        InMemoryStalenessProbe::new(),
    );
    let tok2 = lease_token(&l2);
    let o2 = r2.handle(ctx(&tok2)).await.expect("handle ok");
    assert_eq!(o2.entries_written, 0);
    assert_eq!(o2.syntheses_written, 0);
    assert!(!o2.knowledge_map_updated);
    assert_eq!(o2.cluster_deltas, 0);
}

/// L6-I-02 / AC-15 — persistence sub-step order 5a → 5b → 5c.
#[tokio::test]
async fn l6_i_02_persistence_phase_order() {
    let store = Arc::new(MemoryStore::new());
    store
        .insert("agent:r", fact("e1", "a b c d e", true))
        .unwrap();
    let (runnable, lease, committer, emitter, _km) = build_runnable(
        Arc::clone(&store),
        StubL6Classifier::new(),
        InMemoryStalenessProbe::new(),
    );
    let tok = lease_token(&lease);
    runnable.handle(ctx(&tok)).await.expect("handle ok");
    assert_eq!(
        runnable.sub_trace_5(),
        vec!["5a flush", "5b commit", "5c emit"]
    );
    assert_eq!(committer.commits().len(), 1, "exactly one commit at 5b");
    assert_eq!(emitter.emitted_l6_completed().len(), 1, "one payload at 5c");
}

// ───────────────────────────── AC-34 ─────────────────────────────

/// L6-I-03 — cluster_id writeback + group_by_cluster + journal rollback.
#[tokio::test]
async fn l6_i_03_cluster_id_writeback_and_rollback() {
    let store = Arc::new(MemoryStore::new());
    for id in ["e1", "e2", "e3"] {
        store
            .insert(
                "agent:r",
                fact(id, "rust is memory safe and fast", id == "e1"),
            )
            .unwrap();
    }
    let (runnable, lease, _c, _e, _km) = build_runnable(
        Arc::clone(&store),
        StubL6Classifier::new(),
        InMemoryStalenessProbe::new(),
    );
    let tok = lease_token(&lease);
    runnable.handle(ctx(&tok)).await.expect("handle ok");

    let after = store.list("agent:r");
    let cids: Vec<_> = after.iter().filter_map(|e| e.cluster_id.clone()).collect();
    assert_eq!(cids.len(), 3, "all 3 entries got a cluster_id");
    assert!(cids.iter().all(|c| c == &cids[0]), "identical cluster_id");
    assert!(regex_like(&cids[0]), "cluster_id {} shape", cids[0]);
    let groups = store.group_by_cluster("agent:r");
    assert_eq!(groups.get(&cids[0]).map(|v| v.len()), Some(3));

    // Journal rollback restores cluster_id → None.
    store
        .rollback_l6("agent:r", t0() - Duration::from_secs(1))
        .expect("rollback_l6 ok");
    assert!(
        store.list("agent:r").iter().all(|e| e.cluster_id.is_none()),
        "post-rollback all cluster_id == None"
    );
}

// ───────────────────────────── AC-32 ─────────────────────────────

/// L6-I-04 — consolidated_preferences appended with the l6_batch:{id} tag.
#[tokio::test]
async fn l6_i_04_consolidated_preference_batch_tag() {
    let store = Arc::new(MemoryStore::new());
    store.insert("agent:r", fact("e1", "x", false)).unwrap();
    let classifier = StubL6Classifier::new().with_consolidated_preference("prefer-concise");
    let (runnable, lease, _c, _e, _km) = build_runnable(
        Arc::clone(&store),
        classifier,
        InMemoryStalenessProbe::new(),
    );
    let tok = lease_token(&lease);
    runnable.handle(ctx(&tok)).await.expect("handle ok");
    let prefs: Vec<_> = store
        .list("agent:r")
        .into_iter()
        .filter(|e| e.entry_type == MemoryType::UserPreference)
        .collect();
    assert_eq!(prefs.len(), 1);
    let p = &prefs[0];
    assert!(p.is_active);
    assert_eq!(p.status, MemoryStatus::Active);
    assert!(p.task_origin.is_none());
    assert!(
        p.tags.iter().any(|t| t == "l6_batch:b0c1d2e3"),
        "must carry the fixed l6_batch tag, tags={:?}",
        p.tags
    );
}

// ───────────────────────────── AC-33 ─────────────────────────────

/// L6-I-05 — synthesis 5-gate end-to-end (contested ⇒ no synthesis).
#[tokio::test]
async fn l6_i_05_synthesis_gating_contested_skips() {
    let store = Arc::new(MemoryStore::new());
    for id in ["e1", "e2", "e3"] {
        store
            .insert(
                "agent:r",
                fact(id, "rust is memory safe and fast", id == "e1"),
            )
            .unwrap();
    }
    // Mark the cluster contested via the classifier ⇒ gate (b) fails.
    let classifier = StubL6Classifier::new().with_contested("cl-pricing-b0c1d2e3");
    let (runnable, lease, _c, _e, km) = build_runnable(
        Arc::clone(&store),
        classifier,
        InMemoryStalenessProbe::new(),
    );
    let tok = lease_token(&lease);
    runnable.handle(ctx(&tok)).await.expect("handle ok");
    assert_eq!(
        km.lock().unwrap().topics.len(),
        0,
        "contested cluster must NOT synthesize"
    );

    // Positive control: consistent ⇒ one synthesis.
    let store2 = Arc::new(MemoryStore::new());
    for id in ["e1", "e2", "e3"] {
        store2
            .insert(
                "agent:r",
                fact(id, "rust is memory safe and fast", id == "e1"),
            )
            .unwrap();
    }
    let probe2 = InMemoryStalenessProbe::new().with_present("agent:r", "data/e1.csv", "blob-e1");
    let (r2, l2, _c2, _e2, km2) =
        build_runnable(Arc::clone(&store2), StubL6Classifier::new(), probe2);
    let tok2 = lease_token(&l2);
    r2.handle(ctx(&tok2)).await.expect("handle ok");
    assert_eq!(
        km2.lock().unwrap().topics.len(),
        1,
        "consistent ⇒ synthesize"
    );
}

// ───────────────────────────── AC-35 ─────────────────────────────

/// L6-I-06 — emitted payload delta + snapshot exactness.
#[tokio::test]
async fn l6_i_06_payload_delta_and_snapshot() {
    let store = Arc::new(MemoryStore::new());
    // 3-entry cluster, all file-ref. Mark all 3 blobs present so none is
    // stale→orphaned and the synthesis 5-gate passes.
    for id in ["e1", "e2", "e3"] {
        store
            .insert("agent:r", fact(id, "rust is memory safe and fast", true))
            .unwrap();
    }
    let probe = InMemoryStalenessProbe::new()
        .with_present("agent:r", "data/e1.csv", "blob-e1")
        .with_present("agent:r", "data/e2.csv", "blob-e2")
        .with_present("agent:r", "data/e3.csv", "blob-e3");
    let (runnable, lease, _c, emitter, _km) =
        build_runnable(Arc::clone(&store), StubL6Classifier::new(), probe);
    let tok = lease_token(&lease);
    runnable.handle(ctx(&tok)).await.expect("handle ok");
    let p = &emitter.emitted_l6_completed()[0];
    assert_eq!(p.delta.clusters_merged, 1);
    assert_eq!(p.delta.entries_pruned, 0, "no prune op in the 6-step flow");
    assert_eq!(p.delta.syntheses_generated, 1);
    assert_eq!(p.delta.contested_clusters, 0);
    assert_eq!(p.delta.orphaned_entries, 0);
    // delta/snapshot cross-check.
    assert_eq!(p.delta.contested_clusters, p.snapshot.clusters_contested);
    assert_eq!(p.snapshot.clusters_total, 1);
    assert_eq!(p.snapshot.total_active, 3);
}

// ───────────────────────────── AC-36 ─────────────────────────────

/// L6-I-07 — admin list helpers + < 50 ms latency on 1000 entries.
#[tokio::test]
async fn l6_i_07_admin_helpers_and_latency() {
    use cap_memory::l6::{list_contested, list_orphaned, list_partial_stale};
    use std::collections::HashSet;
    let store = Arc::new(MemoryStore::new());
    // 2 contested in 1 cluster + 1 orphaned + 1 partial-stale.
    let mut c1 = fact("c1", "x", false);
    c1.status = MemoryStatus::Contested;
    c1.cluster_id = Some("cl-x-b0c1d2e3".into());
    let mut c2 = fact("c2", "y", false);
    c2.status = MemoryStatus::Contested;
    c2.cluster_id = Some("cl-x-b0c1d2e3".into());
    let mut o1 = fact("o1", "z", false);
    o1.status = MemoryStatus::Orphaned;
    store.insert("agent:r", c1).unwrap();
    store.insert("agent:r", c2).unwrap();
    store.insert("agent:r", o1).unwrap();
    store.insert("agent:r", fact("p1", "p", false)).unwrap();
    let partial: HashSet<String> = ["p1".to_string()].into_iter().collect();

    let contested = list_contested(&store, "agent:r");
    assert_eq!(contested.len(), 1);
    assert_eq!(contested["cl-x-b0c1d2e3"].len(), 2);
    assert_eq!(list_orphaned(&store, "agent:r").len(), 1);
    assert_eq!(list_partial_stale(&store, "agent:r", &partial).len(), 1);

    let big = Arc::new(MemoryStore::new());
    for i in 0..1000 {
        big.insert("agent:r", fact(&format!("e{i}"), "c", false))
            .unwrap();
    }
    let now = SystemTime::UNIX_EPOCH;
    let started = std::time::Instant::now();
    let _ = list_contested(&big, "agent:r");
    let _ = list_orphaned(&big, "agent:r");
    let _ = list_partial_stale(&big, "agent:r", &HashSet::new());
    let _ = cap_memory::l6::compute_health_snapshot(&big, "agent:r", &HashSet::new(), now);
    let elapsed = started.elapsed();
    assert!(
        elapsed < Duration::from_millis(50),
        "AC-36 §1.4 normative threshold (<50ms, NOT relaxed); took {elapsed:?}"
    );
}

// ───────────────────────────── AC-13 ─────────────────────────────

/// L6-I-08 — two-phase acquire; Step 6 clears on matching lease_id.
#[tokio::test]
async fn l6_i_08_two_phase_and_step6_clear() {
    let store = Arc::new(MemoryStore::new());
    store.insert("agent:r", fact("e1", "x", false)).unwrap();
    let (runnable, lease, _c, _e, _km) = build_runnable(
        Arc::clone(&store),
        StubL6Classifier::new(),
        InMemoryStalenessProbe::new(),
    );
    let tok = lease_token(&lease);
    assert_eq!(lease.state("agent:r", t0()), Some(LeaseState::Active));
    assert_eq!(
        lease.begin_acquire("agent:r", t0(), Duration::from_secs(600)),
        LeaseDecision::AlreadyHeld
    );
    runnable.handle(ctx(&tok)).await.expect("handle ok");
    assert!(runnable.on_component_finished(
        "agent:r",
        &ComponentFinished {
            component_id: "memory.l6".into(),
            lease_id: tok.clone()
        }
    ));
    // Third acquire succeeds after Step 6 cleared it.
    assert!(matches!(
        lease.begin_acquire("agent:r", t0(), Duration::from_secs(600)),
        LeaseDecision::Acquired { .. }
    ));
    // Per-agent isolation: agent:b unaffected.
    assert!(matches!(
        lease.begin_acquire("agent:b", t0(), Duration::from_secs(600)),
        LeaseDecision::Acquired { .. }
    ));
}

/// L6-I-08b — Step 6 late-event mis-clearing defense.
#[tokio::test]
async fn l6_i_08b_step6_misclear_defense() {
    let store = Arc::new(MemoryStore::new());
    store.insert("agent:r", fact("e1", "x", false)).unwrap();
    let (runnable, lease, _c, _e, _km) = build_runnable(
        Arc::clone(&store),
        StubL6Classifier::new(),
        InMemoryStalenessProbe::new(),
    );
    let t1 = lease_token(&lease);
    // A previously-aborted run delivers a stale lease_id t0 ≠ t1.
    let cleared_stale = runnable.on_component_finished(
        "agent:r",
        &ComponentFinished {
            component_id: "memory.l6".into(),
            lease_id: "stale-token-t0".into(),
        },
    );
    assert!(!cleared_stale, "stale lease_id must be a no-op");
    assert_eq!(
        lease.state("agent:r", t0()),
        Some(LeaseState::Active),
        "live lease t1 must survive the stale late event"
    );
    // The matching event clears it.
    assert!(runnable.on_component_finished(
        "agent:r",
        &ComponentFinished {
            component_id: "memory.l6".into(),
            lease_id: t1.clone()
        }
    ));
    assert_eq!(lease.state("agent:r", t0()), None);
}

// ───────────────────────────── AC-14 lease-loss ─────────────────────────────

/// L6-I-09 — lease-loss gate (before-5a) ⇒ zero side effects.
#[tokio::test]
async fn l6_i_09_lease_loss_atomic_abort() {
    let store = Arc::new(MemoryStore::new());
    for id in ["e1", "e2", "e3"] {
        store
            .insert(
                "agent:r",
                fact(id, "rust is memory safe and fast", id == "e1"),
            )
            .unwrap();
    }
    let classifier = StubL6Classifier::new().with_consolidated_preference("prefer-concise");
    let (runnable, lease, committer, emitter, km) = build_runnable(
        Arc::clone(&store),
        classifier,
        InMemoryStalenessProbe::new(),
    );
    let tok = lease_token(&lease);
    // Invalidate the lease BEFORE handle: release t1, re-acquire a fresh one
    // so current_token != tok.
    assert!(lease.release("agent:r", &tok));
    let _other = lease.begin_acquire("agent:r", t0(), Duration::from_secs(600));

    let cursor_before = runnable.cursor_store.read("agent:r");
    let err = runnable
        .handle(ctx(&tok))
        .await
        .expect_err("must LeaseLost");
    assert!(matches!(err, L6Error::LeaseLost));
    // Zero side effects.
    assert!(committer.commits().is_empty(), "no commit");
    assert!(emitter.emitted_l6_completed().is_empty(), "no emit");
    assert!(
        store.list("agent:r").iter().all(|e| e.cluster_id.is_none()),
        "no cluster_id writeback"
    );
    assert!(
        store
            .list("agent:r")
            .iter()
            .all(|e| e.entry_type != MemoryType::UserPreference),
        "no consolidated_preference appended"
    );
    assert_eq!(
        km.lock().unwrap().topics.len(),
        0,
        "no knowledge_map mutation"
    );
    assert_eq!(
        runnable.cursor_store.read("agent:r"),
        cursor_before,
        "cursor UNCHANGED (5a never ran — proves the before-5a gate)"
    );
}

// ───────────────────────────── AC-12 (Step 9 via PostProcessor) ─────────────

/// L6-I-10 — Slice B+C compatibility: 9-step trace intact + Step 9 emit.
#[tokio::test]
async fn l6_i_10_post_processor_step9_emit() {
    use advance_shared_types::mailbox::{ActionResult, Message, MessageKind};
    use advance_shared_types::memory::PostProcessorHook;
    use cap_memory::l6::{InMemoryEmitter, L6TriggerEvaluator, L6TriggerState};
    use cap_memory::post_processor::{Components, PostProcessor};
    use cap_memory::{
        FailureCooldown, InMemorySimilarityIndex, Reconciler, StubBatchExtractor, DEFAULT_THRESHOLD,
    };

    let store = Arc::new(MemoryStore::new());
    let emitter = Arc::new(InMemoryEmitter::new());
    let trigger_state = Arc::new(Mutex::new(L6TriggerState::default()));
    // Seed the trigger so Step 9 fires (3 completed tasks ≥ threshold).
    {
        let mut st = trigger_state.lock().unwrap();
        st.record_task_completed();
        st.record_task_completed();
        st.record_task_completed();
    }
    let components = Components {
        extractor: Arc::new(StubBatchExtractor::with_extraction(Default::default())),
        reconciler: Reconciler::from_concrete(
            Arc::new(InMemorySimilarityIndex::new()),
            DEFAULT_THRESHOLD,
        ),
        store: Arc::clone(&store),
        cooldown: Arc::new(FailureCooldown::new(600)),
        clock: Arc::new(MutableClock::new(t0())),
        trigger: Arc::new(L6TriggerEvaluator::new()),
        lease: Arc::new(InMemoryLeaseStore::new()),
        l6_emitter: Arc::clone(&emitter) as Arc<InMemoryEmitter> as Arc<_>,
        l6_trigger_state: Arc::clone(&trigger_state),
        // Slice D: this test exercises Step-9 emit via the InMemoryEmitter
        // l6_emitter above (Seam B test double); the WIT-handler bus (Seam A)
        // is unused here, so a NoopEventBus keeps the slice-C contract intact.
        event_bus: Arc::new(cap_memory::NoopEventBus),
        // Slice F (m011-slice-f): in-memory SQLite-index + Embedder seam
        // defaults — this test does not exercise the slice-F sync_* methods,
        // so the InMemorySqliteIndex stub + StubEmbedder are passive placeholders
        // that keep `Components`'s public-field contract intact.
        sqlite_index: Arc::new(cap_memory::InMemorySqliteIndex::default()),
        embedder: Arc::new(cap_memory::StubEmbedder),
        // Slice G (m011-slice-g): L6 cursor store seam default — this test
        // does not dispatch WIT rollback-memory, so this field is a passive
        // placeholder keeping the public-field contract intact. The
        // pre-existing runnable's own cursor_store at l6/runnable.rs:79
        // (constructed independently via `L6Runnable::new`'s 14th arg) is
        // what Step-5a's flush exercises.
        cursor_store: Arc::new(cap_memory::L6CursorStore::new()),
        // Slice satB-postproc: write-path seam fields — this test is trace-only
        // for Steps 7/8 (no fs_root) and uses the run() agent id (no override).
        fs_root: None,
        write_agent_id: None,
        // Slice satC-l6: no in-process L6 dispatch (this test asserts Step-9
        // emit only, via the InMemoryEmitter above).
        l6_handler: None,
        // SAT-D: no Step-3 description indexer in this L6-focused test.
        description_indexer: None,
    };
    let pp = PostProcessor::with_components(components);
    let msg = Message {
        id: "msg-l6".into(),
        kind: MessageKind::User,
        from: "user:test".into(),
        to: "agent:r".into(),
        payload: vec![],
        context: None,
        timestamp: SystemTime::UNIX_EPOCH,
        origin: None,
    };
    let res = ActionResult {
        new_state: vec![],
        actions: vec![],
    };
    pp.run("agent:r", &msg, &res).await.expect("run ok");
    assert_eq!(
        pp.trace_snapshot().len(),
        9,
        "Slice B 9-step contract intact"
    );
    assert_eq!(
        emitter.consolidation_due(),
        vec!["agent:r"],
        "Step 9 fired ⇒ emit_consolidation_due exactly once"
    );
}

/// T-lease-cleanup (slice m011-mem-product) — a mid-run Step-5 failure
/// (GitCommitFailed, driven by the PUBLIC `FailingCommitter`) releases the
/// live lease (token-checked) instead of leaving it Active until TTL. The
/// crate-side of SYS-AC-216. `build_runnable` hardcodes `InMemoryCommitter`
/// (always Ok), so the runnable is constructed inline with `FailingCommitter`.
#[tokio::test]
async fn l6_mid_run_failure_releases_lease() {
    let store = Arc::new(MemoryStore::new());
    for id in ["e1", "e2", "e3"] {
        store
            .insert(
                "agent:r",
                fact(id, "rust is memory safe and fast", id == "e1"),
            )
            .unwrap();
    }
    let lease = Arc::new(InMemoryLeaseStore::new());
    let runnable = L6Runnable::new(
        "memory.l6",
        Arc::new(MutableClock::new(t0())),
        Arc::new(FixedBatchIdSource("b0c1d2e3".into())),
        Arc::clone(&store),
        Arc::clone(&lease) as Arc<dyn LeaseStore + Send + Sync>,
        Arc::new(InMemoryStalenessProbe::new()),
        Arc::new(L6ClusterBuilder::new()),
        Arc::new(StubL6Classifier::new()),
        Arc::new(StubSynthesisGenerator),
        Arc::new(Mutex::new(KnowledgeMap::new())),
        Arc::new(Mutex::new(HashMap::new())),
        // The injected failure: commit() always returns Err → GitCommitFailed.
        Arc::new(FailingCommitter::new()),
        Arc::new(InMemoryEmitter::new()),
        Arc::new(L6CursorStore::new()),
    );

    let tok = lease_token(&lease);
    // Pre-condition: the lease IS live at t0 (so a later None proves RELEASE,
    // not expiry — `current_token` filters by liveness `now < deadline`).
    assert_eq!(
        lease.current_token("agent:r", t0()).as_deref(),
        Some(tok.as_str()),
        "lease must be live before the failed run"
    );

    let err = runnable.handle(ctx(&tok)).await.expect_err("commit fails");
    assert!(
        matches!(err, L6Error::GitCommitFailed(_)),
        "mid-run commit failure surfaces as GitCommitFailed, got {err:?}"
    );

    // The live lease was RELEASED (checked at the SAME `now` it was live at —
    // so this is release, not TTL expiry).
    assert_eq!(
        lease.current_token("agent:r", t0()),
        None,
        "mid-run failure must release the live lease (not leave it to TTL)"
    );
    // And the slot is genuinely free: a fresh acquire succeeds.
    assert!(
        matches!(
            lease.begin_acquire("agent:r", t0(), Duration::from_secs(600)),
            LeaseDecision::Acquired { .. }
        ),
        "released lease is immediately re-acquirable"
    );

    // Companion (mis-clearing defense preserved): a stale-token release on the
    // freshly-held lease is a no-op.
    let live = lease
        .current_token("agent:r", t0())
        .expect("re-acquired lease");
    assert!(
        !lease.release("agent:r", "stale-token"),
        "stale release no-op"
    );
    assert_eq!(
        lease.current_token("agent:r", t0()).as_deref(),
        Some(live.as_str()),
        "stale release must not clear the live lease"
    );
}

/// Mimic `^cl-[a-z0-9][a-z0-9-]*-[0-9a-f]{1,16}$` without a regex dep.
fn regex_like(s: &str) -> bool {
    let Some(rest) = s.strip_prefix("cl-") else {
        return false;
    };
    let Some(d) = rest.rfind('-') else {
        return false;
    };
    let (slug, suffix) = (&rest[..d], &rest[d + 1..]);
    if slug.is_empty() || suffix.is_empty() || suffix.len() > 16 {
        return false;
    }
    if !slug.chars().next().unwrap().is_ascii_alphanumeric() {
        return false;
    }
    slug.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        && suffix
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
}

/// DSP-07 (slice satC-l6) — a ROOTED `L6Runnable` (`with_fs_root`) serializes
/// `_knowledge_map.yaml` + the accepted `syntheses/*.md` to disk under
/// `<fs_root>/<agent-slug>/` and hands the committer ABSOLUTE on-disk CommitFile
/// vpaths. (The rootless path — unchanged — is exercised by every other
/// `l6_i_*` test.) The in-memory committer just records, so this asserts the
/// runnable's OWN disk writes (the SAT-C serialization fix for SYS-AC-069).
#[tokio::test]
async fn dsp_07_rooted_runnable_serializes_map_and_syntheses_to_disk() {
    let tmp = tempfile::tempdir().unwrap();
    let store = Arc::new(MemoryStore::new());
    // l6_i_01 seeding: one high-overlap cluster with ≥1 file-ref source → the
    // 5-gate synthesis check passes (default StubL6Classifier = all consistent).
    for id in ["e1", "e2", "e3"] {
        store
            .insert(
                "agent:r",
                fact(id, "rust is memory safe and fast", id == "e1"),
            )
            .unwrap();
    }
    // Mark e1's file-ref blob present so it is NOT stale→orphaned → the
    // synthesis 5-gate passes (mirrors l6_i_05's positive control).
    let probe = InMemoryStalenessProbe::new().with_present("agent:r", "data/e1.csv", "blob-e1");
    let (runnable, lease, committer, _e, _km) =
        build_runnable(Arc::clone(&store), StubL6Classifier::new(), probe);
    let runnable = runnable.with_fs_root(tmp.path().to_path_buf());
    let tok = lease_token(&lease);
    let outcome = runnable.handle(ctx(&tok)).await.expect("handle ok");
    assert!(
        outcome.syntheses_written >= 1,
        "the seeded cluster must generate at least one synthesis (got {})",
        outcome.syntheses_written
    );

    // The runnable wrote real files under a single per-agent slug dir.
    let agent_dir = std::fs::read_dir(tmp.path())
        .unwrap()
        .filter_map(Result::ok)
        .map(|e| e.path())
        .find(|p| p.is_dir())
        .expect("a per-agent slug dir must exist under fs_root");
    assert!(
        agent_dir.join("_knowledge_map.yaml").is_file(),
        "_knowledge_map.yaml must be serialized to disk under the slug dir"
    );
    let md_count = std::fs::read_dir(agent_dir.join("syntheses"))
        .expect("syntheses/ dir must exist")
        .filter_map(Result::ok)
        .filter(|e| e.path().extension().and_then(|x| x.to_str()) == Some("md"))
        .count();
    assert!(md_count >= 1, "at least one syntheses/*.md must be on disk");

    // The CommitFile vpaths handed to the committer are ABSOLUTE on-disk paths
    // under fs_root (the rooted-path fix — NOT the flat `.agent/memory/...`).
    let commits = committer.commits();
    assert_eq!(commits.len(), 1, "exactly one L6 commit");
    for f in &commits[0].files {
        let p = std::path::Path::new(&f.vpath);
        assert!(
            p.is_absolute(),
            "rooted vpath must be absolute: {}",
            f.vpath
        );
        assert!(
            p.starts_with(tmp.path()),
            "rooted vpath must live under fs_root: {}",
            f.vpath
        );
    }
}
