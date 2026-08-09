//! slice wave6-laneB (leg 2, SYS-AC-186/216) — L6 skill-candidate PRODUCER
//! integration tests. CAUSAL witnesses: the candidate is produced by a real
//! `classify() → append_generated` chain inside `L6Runnable::handle`, NOT a
//! seeded file. The 216-shape test drives a FAILING classifier through the
//! fallible-async seam and asserts the lease is cleared + no candidate / no
//! `l6_completed`.

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use advance_shared_types::memory::{L6Context, L6Error, L6Handler};
use async_trait::async_trait;
use cap_memory::clock::MutableClock;
use cap_memory::l6::{
    FixedBatchIdSource, InMemoryCommitter, InMemoryEmitter, InMemoryLeaseStore,
    InMemoryStalenessProbe, KnowledgeMap, L6ClassificationInput, L6ClassificationOutput,
    L6Classifier, L6ClusterBuilder, L6CursorStore, L6Runnable, LeaseDecision, LeaseStore,
    StubL6Classifier, StubSynthesisGenerator,
};
use cap_memory::store::MemoryStore;
use cap_memory::{compute_candidate_id, SkillCandidateStore};

fn t0() -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000)
}

/// A classifier that ALWAYS fails — the fallible-async seam exercised for the
/// 216 shape (the existing `FailingCommitter` only fails the COMMIT path).
struct FailingClassifier;

#[async_trait]
impl L6Classifier for FailingClassifier {
    async fn classify(
        &self,
        _input: &L6ClassificationInput,
    ) -> Result<L6ClassificationOutput, L6Error> {
        Err(L6Error::LlmFailure("test-induced classify failure".into()))
    }
}

#[allow(clippy::type_complexity)]
fn build_producer_runnable(
    store: Arc<MemoryStore>,
    classifier: Arc<dyn L6Classifier + Send + Sync>,
    candidate_dir: &Path,
) -> (
    L6Runnable,
    Arc<InMemoryLeaseStore>,
    Arc<InMemoryEmitter>,
    Arc<SkillCandidateStore>,
) {
    let lease = Arc::new(InMemoryLeaseStore::new());
    let committer = Arc::new(InMemoryCommitter::new());
    let emitter = Arc::new(InMemoryEmitter::new());
    let cand_store = Arc::new(SkillCandidateStore::in_dir(candidate_dir));
    let runnable = L6Runnable::new(
        "memory.l6",
        Arc::new(MutableClock::new(t0())),
        Arc::new(FixedBatchIdSource("b0c1d2e3".into())),
        Arc::clone(&store),
        Arc::clone(&lease) as Arc<dyn LeaseStore + Send + Sync>,
        Arc::new(InMemoryStalenessProbe::new()),
        Arc::new(L6ClusterBuilder::new()),
        classifier,
        Arc::new(StubSynthesisGenerator),
        Arc::new(Mutex::new(KnowledgeMap::new())),
        Arc::new(Mutex::new(HashMap::new())),
        Arc::clone(&committer) as Arc<InMemoryCommitter> as Arc<_>,
        Arc::clone(&emitter) as Arc<InMemoryEmitter> as Arc<_>,
        Arc::new(L6CursorStore::new()),
    )
    .with_skill_candidate_store(Arc::clone(&cand_store));
    (runnable, lease, emitter, cand_store)
}

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

/// L2-produce (186): a classifier returning skill_health=[unhealthy, healthy]
/// CAUSALLY produces exactly ONE candidate (the unhealthy one) into
/// `_skill_candidates.jsonl` with the deterministic sha256 id, list_pending
/// returns it, and the InMemoryEmitter captured one `skill.candidate_generated`.
#[tokio::test]
async fn l2_produce_candidate_from_skill_health_causally() {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(MemoryStore::new());
    let classifier = Arc::new(
        StubL6Classifier::new()
            .with_skill_health("summarize-pr", "unhealthy")
            .with_skill_health("healthy-skill", "healthy")
            .with_skill_health("rusty-skill", "stale"),
    );
    let (runnable, lease, emitter, cand_store) =
        build_producer_runnable(store, classifier, dir.path());
    let tok = lease_token(&lease);

    runnable.handle(ctx(&tok)).await.expect("handle ok");

    // Causal production: only stale/unhealthy promoted (NOT healthy).
    let pending = cand_store.list_pending().expect("list");
    assert_eq!(
        pending.len(),
        2,
        "unhealthy + stale promoted; healthy excluded"
    );
    let names: Vec<&str> = pending.iter().map(|c| c.name.as_str()).collect();
    assert!(names.contains(&"summarize-pr"));
    assert!(names.contains(&"rusty-skill"));
    assert!(!names.contains(&"healthy-skill"));

    // Deterministic candidate_id == length-prefixed sha256 of (name, description).
    let unhealthy = pending.iter().find(|c| c.name == "summarize-pr").unwrap();
    let expected_desc =
        "L6 consolidation flagged skill 'summarize-pr' as unhealthy; candidate for review.";
    assert_eq!(unhealthy.description, expected_desc);
    assert_eq!(
        unhealthy.candidate_id,
        compute_candidate_id("summarize-pr", expected_desc)
    );
    assert_eq!(unhealthy.candidate_id.len(), 64);

    // 5c emitted `skill.candidate_generated` for each NEW candidate.
    let emitted = emitter.emitted_skill_candidates();
    assert_eq!(emitted.len(), 2);
    assert!(emitted.iter().any(|(agent, id, skill)| {
        agent == "agent:r" && id == &unhealthy.candidate_id && skill == "summarize-pr"
    }));
    // l6_completed still emitted on the success path.
    assert_eq!(emitter.emitted_l6_completed().len(), 1);
}

/// L2-idempotent: a second `handle()` does NOT double-append (deterministic id)
/// and does NOT re-emit — the JSONL cannot grow unbounded across L6 runs.
#[tokio::test]
async fn l2_idempotent_no_double_append() {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(MemoryStore::new());
    let classifier =
        Arc::new(StubL6Classifier::new().with_skill_health("summarize-pr", "unhealthy"));
    let (runnable, lease, emitter, cand_store) =
        build_producer_runnable(store, classifier, dir.path());
    let tok = lease_token(&lease);

    runnable.handle(ctx(&tok)).await.expect("handle ok #1");
    assert_eq!(cand_store.event_count().unwrap(), 1);
    assert_eq!(emitter.emitted_skill_candidates().len(), 1);

    // Second run (lease still held on the Ok path) → idempotent, no second line,
    // no re-emit.
    runnable.handle(ctx(&tok)).await.expect("handle ok #2");
    assert_eq!(cand_store.event_count().unwrap(), 1, "no double-append");
    assert_eq!(
        emitter.emitted_skill_candidates().len(),
        1,
        "no re-emit for an already-known candidate"
    );
}

/// L2-fail (216 shape): a FAILING classifier → `handle()` returns
/// `L6Error::LlmFailure`, the lease is RELEASED (token-checked), NO candidate is
/// appended, NO `l6_completed` is emitted (the next trigger retries).
#[tokio::test]
async fn l2_failing_classifier_clears_lease_no_candidate_no_completed() {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(MemoryStore::new());
    let (runnable, lease, emitter, cand_store) =
        build_producer_runnable(store, Arc::new(FailingClassifier), dir.path());
    let tok = lease_token(&lease);
    assert_eq!(lease.current_token("agent:r", t0()), Some(tok.clone()));

    let err = runnable
        .handle(ctx(&tok))
        .await
        .expect_err("classify fails");
    assert!(matches!(err, L6Error::LlmFailure(_)), "got {err:?}");

    // Lease cleared (token-checked release on the Step-3 LLM-failure abort).
    assert_eq!(
        lease.current_token("agent:r", t0()),
        None,
        "lease must be released so the next trigger retries"
    );
    // No candidate appended (failure is at Step 3, before the 5a producer flush).
    assert_eq!(cand_store.event_count().unwrap(), 0);
    assert!(cand_store.list_pending().unwrap().is_empty());
    // No l6_completed / no skill.candidate_generated.
    assert!(emitter.emitted_l6_completed().is_empty());
    assert!(emitter.emitted_skill_candidates().is_empty());
}

/// L2-nonregression: an L6 run with NO candidate store + an all-healthy
/// classifier produces nothing and behaves as before (no candidate side effects).
#[tokio::test]
async fn l2_no_store_no_candidate_side_effects() {
    let store = Arc::new(MemoryStore::new());
    // Build WITHOUT a candidate store (the historical posture).
    let lease = Arc::new(InMemoryLeaseStore::new());
    let emitter = Arc::new(InMemoryEmitter::new());
    let runnable = L6Runnable::new(
        "memory.l6",
        Arc::new(MutableClock::new(t0())),
        Arc::new(FixedBatchIdSource("b0c1d2e3".into())),
        Arc::clone(&store),
        Arc::clone(&lease) as Arc<dyn LeaseStore + Send + Sync>,
        Arc::new(InMemoryStalenessProbe::new()),
        Arc::new(L6ClusterBuilder::new()),
        Arc::new(StubL6Classifier::new().with_skill_health("x", "unhealthy")),
        Arc::new(StubSynthesisGenerator),
        Arc::new(Mutex::new(KnowledgeMap::new())),
        Arc::new(Mutex::new(HashMap::new())),
        Arc::new(InMemoryCommitter::new()) as Arc<_>,
        Arc::clone(&emitter) as Arc<InMemoryEmitter> as Arc<_>,
        Arc::new(L6CursorStore::new()),
    );
    let tok = lease_token(&lease);
    runnable.handle(ctx(&tok)).await.expect("handle ok");
    // No candidate store ⇒ no candidate emission, but l6_completed still fires.
    assert!(emitter.emitted_skill_candidates().is_empty());
    assert_eq!(emitter.emitted_l6_completed().len(), 1);
}
