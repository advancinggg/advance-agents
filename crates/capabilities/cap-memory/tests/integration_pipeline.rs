//! Integration tests for the 9-step post-processor pipeline + slice B
//! wiring (AC-08 trace contract, AC-09 LLM-failure cooldown, AC-10 fact
//! reconciliation, AC-11 user-preference append-only).
//!
//! Slice A AC-08 tests verify the canonical step trace using `PostProcessor::new()`
//! (no Components). Slice B AC-09 / AC-10 / AC-11 tests construct `Components`
//! with `StubBatchExtractor` + `InMemorySimilarityIndex` + `MutableClock` to
//! drive deterministic behavior.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use advance_shared_types::mailbox::{ActionResult, Message, MessageKind};
use advance_shared_types::memory::PostProcessorHook;
use cap_memory::{
    post_processor::CANONICAL_STEPS, BatchExtractorError, Components, Extraction, FailureCooldown,
    InMemorySimilarityIndex, MemoryEntry, MemoryStatus, MemoryStore, MemoryType, MutableClock,
    PostProcessor, Reconciler, StubBatchExtractor, SupersessionReason, DEFAULT_THRESHOLD,
};

fn fixture_message() -> Message {
    Message {
        id: "msg-test-001".into(),
        kind: MessageKind::User,
        from: "user:test".into(),
        to: "agent:research".into(),
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

#[tokio::test]
async fn pipeline_runs_nine_steps_in_order() {
    let pp = PostProcessor::new();
    let msg = fixture_message();
    let result = fixture_result();

    pp.run("agent:research", &msg, &result)
        .await
        .expect("run returns Ok");

    let trace = pp.trace_snapshot();
    let expected: Vec<String> = CANONICAL_STEPS.iter().map(|s| s.to_string()).collect();
    assert_eq!(
        trace, expected,
        "trace must match the canonical §1.3.5 sequence"
    );
}

#[tokio::test]
async fn pipeline_returns_ok_on_happy_path() {
    let pp = PostProcessor::new();
    let msg = fixture_message();
    let result = fixture_result();
    let outcome = pp.run("agent:research", &msg, &result).await;
    assert!(
        outcome.is_ok(),
        "happy-path run must return Ok, got {outcome:?}"
    );
}

#[tokio::test]
async fn pipeline_step_count_matches_spec() {
    let pp = PostProcessor::new();
    pp.run("agent:research", &fixture_message(), &fixture_result())
        .await
        .expect("run returns Ok");
    let trace = pp.trace_snapshot();
    assert_eq!(
        trace.len(),
        9,
        "trace length must equal AC-08's 9-step count"
    );
}

/// Additional belt-and-suspenders: verify §1.3.5's 7a + 7b sub-call
/// structure is implemented at the helper-fn level (observable via the
/// per-helper counters) without breaking the 9-entry trace contract.
#[tokio::test]
async fn pipeline_step_7_internal_split_observable() {
    let pp = PostProcessor::new();
    pp.run("agent:research", &fixture_message(), &fixture_result())
        .await
        .expect("run returns Ok");
    assert_eq!(
        pp.summary_calls(),
        1,
        "step 7a (update_summary_inner) should have been called once"
    );
    assert_eq!(
        pp.turn_index_calls(),
        1,
        "step 7b (update_turn_index_inner) should have been called once"
    );
    // Trace remains 9 entries — counters are an out-of-band observation.
    assert_eq!(pp.trace_snapshot().len(), 9);
}

/// Adversarial Round 2 fix: a long-lived PostProcessor reused across
/// multiple `run()` invocations must NOT accumulate trace entries —
/// each `run()` resets the trace + counters at entry so the canonical
/// 9-step contract holds on every invocation.
#[tokio::test]
async fn pipeline_run_resets_trace_on_second_invocation() {
    let pp = PostProcessor::new();
    let msg = fixture_message();
    let result = fixture_result();
    pp.run("agent:research", &msg, &result)
        .await
        .expect("first run");
    assert_eq!(pp.trace_snapshot().len(), 9, "first run trace == 9");
    assert_eq!(pp.summary_calls(), 1);
    assert_eq!(pp.turn_index_calls(), 1);
    // Second invocation on the SAME instance: trace must reset, not accumulate.
    pp.run("agent:research", &msg, &result)
        .await
        .expect("second run");
    assert_eq!(
        pp.trace_snapshot().len(),
        9,
        "second run trace must be 9 entries (reset), not 18"
    );
    assert_eq!(pp.summary_calls(), 1);
    assert_eq!(pp.turn_index_calls(), 1);
}

// ─────────────────────────────────────────────────────────────────────
// Slice B AC-09: LLM-failure → partial-degrade fallback + 10-min cooldown
// ─────────────────────────────────────────────────────────────────────

fn build_components(
    stub_extractor: Arc<StubBatchExtractor>,
    similarity: Arc<InMemorySimilarityIndex>,
    store: Arc<MemoryStore>,
    clock: Arc<MutableClock>,
) -> Components {
    let reconciler = Reconciler::from_concrete(similarity, DEFAULT_THRESHOLD);
    // Slice C: use the with_l6_defaults ctor so the 4 new L6 fields are filled
    // by throwaway in-memory defaults. Step 9's trigger DOES fire on the
    // default state (last_l6_at==None ⇒ HoursSinceLast), but the side effects
    // land on unreachable throwaway defaults and the canonical Step 9 label is
    // pushed before the trigger check, so the Slice B 9-step trace contract
    // and every Slice B assertion are preserved (see with_l6_defaults rustdoc).
    Components::with_l6_defaults(
        stub_extractor,
        reconciler,
        store,
        Arc::new(FailureCooldown::new(600)),
        clock,
    )
}

/// AC-09 — `BatchExtractor::extract` failing with `LlmFailure` triggers the
/// mechanical-digest fallback; the next run within the cooldown window
/// short-circuits the LLM call (extractor not re-invoked); after the window
/// elapses the LLM call is re-attempted.
#[tokio::test]
async fn ac_09_cooldown_and_partial_degrade() {
    let extractor = Arc::new(StubBatchExtractor::fail_with(
        BatchExtractorError::LlmFailure("upstream".into()),
    ));
    let similarity = Arc::new(InMemorySimilarityIndex::new());
    let store = Arc::new(MemoryStore::new());
    let t0 = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
    let clock = Arc::new(MutableClock::new(t0));
    let components = build_components(
        Arc::clone(&extractor),
        Arc::clone(&similarity),
        Arc::clone(&store),
        Arc::clone(&clock),
    );
    let pp = PostProcessor::with_components(components);
    let msg = fixture_message();
    let result = fixture_result();

    pp.run("agent:research", &msg, &result)
        .await
        .expect("first run: should NOT return Err; partial-degrade fallback runs");
    assert_eq!(
        extractor.call_count(),
        1,
        "first run invokes extractor once"
    );
    // Mechanical-digest fallback wrote one entry to the store.
    let bucket_after_first = store.list("agent:research");
    assert_eq!(bucket_after_first.len(), 1);
    assert!(bucket_after_first[0].content.contains("mechanical-digest"));
    assert_eq!(bucket_after_first[0].status, MemoryStatus::Active);
    assert!(
        pp.trace_snapshot().len() == 9,
        "trace pushes all 9 STEP_* labels on first run"
    );

    // Advance clock by 5 min — still inside cooldown window.
    clock.advance(Duration::from_secs(5 * 60));
    pp.run("agent:research", &msg, &result)
        .await
        .expect("second run: cooldown short-circuits, fallback still runs");
    assert_eq!(
        extractor.call_count(),
        1,
        "second run within cooldown: extractor NOT re-invoked"
    );
    assert!(
        pp.trace_snapshot().len() == 9,
        "trace pushes all 9 STEP_* labels on second run"
    );

    // Advance past the 10-min cooldown.
    clock.advance(Duration::from_secs(6 * 60));
    pp.run("agent:research", &msg, &result)
        .await
        .expect("third run: post-cooldown, extractor re-invoked");
    assert_eq!(
        extractor.call_count(),
        2,
        "third run after cooldown: extractor re-invoked"
    );
}

/// T-clock (slice m011-mem-product) — the mechanical-digest fallback now stamps
/// `created_at` from the injected `Components.clock` via the shared
/// `clock_now_rfc3339_z` helper, NOT the old hardcoded `"1970-01-01T00:00:00Z"`.
/// The stamp is the second-granularity `Z`-form of the clock instant (so it
/// stays lexicographically order-preserving for `recall_at`/`rollback`).
#[tokio::test]
async fn mechanical_digest_fallback_uses_injected_clock() {
    let extractor = Arc::new(StubBatchExtractor::fail_with(
        BatchExtractorError::LlmFailure("upstream".into()),
    ));
    let similarity = Arc::new(InMemorySimilarityIndex::new());
    let store = Arc::new(MemoryStore::new());
    // A known, NON-epoch instant: UNIX_EPOCH + 1_000_000s = 1970-01-12T13:46:40Z.
    let t0 = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
    let clock = Arc::new(MutableClock::new(t0));
    let components = build_components(
        Arc::clone(&extractor),
        Arc::clone(&similarity),
        Arc::clone(&store),
        Arc::clone(&clock),
    );
    let pp = PostProcessor::with_components(components);

    pp.run("agent:research", &fixture_message(), &fixture_result())
        .await
        .expect("partial-degrade fallback runs");

    let bucket = store.list("agent:research");
    assert_eq!(bucket.len(), 1);
    let entry = &bucket[0];
    assert!(entry.content.contains("mechanical-digest"));
    // created_at is the Z-form of the injected clock, NOT the 1970 epoch stub.
    assert_eq!(entry.created_at, "1970-01-12T13:46:40Z");
    assert_ne!(entry.created_at, "1970-01-01T00:00:00Z");
    // It matches the shared helper exactly (same form the remember-handler uses).
    assert_eq!(entry.created_at, cap_memory::clock_now_rfc3339_z(&*clock));
    // Second-granularity Z form: ends with 'Z', no '+00:00', no sub-second '.'.
    assert!(entry.created_at.ends_with('Z'));
    assert!(!entry.created_at.contains('+'));
    assert!(!entry.created_at.contains('.'));
}

// ─────────────────────────────────────────────────────────────────────
// Slice B AC-10: Fact reconciliation — similarity 0.85 → 4-branch MemoryAction
// ─────────────────────────────────────────────────────────────────────

fn fact_entry(id: &str, content: &str, created_at: &str) -> MemoryEntry {
    MemoryEntry {
        id: id.into(),
        agent_id: "agent:research".into(),
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

fn pref_entry(id: &str, content: &str, created_at: &str) -> MemoryEntry {
    MemoryEntry {
        entry_type: MemoryType::UserPreference,
        ..fact_entry(id, content, created_at)
    }
}

fn build_components_with_extraction(
    extraction_to_return: Extraction,
    similarity: Arc<InMemorySimilarityIndex>,
    store: Arc<MemoryStore>,
) -> Components {
    let extractor = Arc::new(StubBatchExtractor::with_extraction(extraction_to_return));
    let clock = Arc::new(MutableClock::new(SystemTime::UNIX_EPOCH));
    let reconciler = Reconciler::from_concrete(similarity, 0.5);
    Components::with_l6_defaults(
        extractor,
        reconciler,
        store,
        Arc::new(FailureCooldown::new(600)),
        clock,
    )
}

#[tokio::test]
async fn ac_10_fact_reconciliation_four_branches() {
    let msg = fixture_message();
    let result = fixture_result();

    // (a) Empty index + new fact → Insert.
    {
        let similarity = Arc::new(InMemorySimilarityIndex::new());
        let store = Arc::new(MemoryStore::new());
        let new = fact_entry("f1", "Rust is fast", "2026-01-01T00:00:00Z");
        let extraction = Extraction {
            descriptions: vec![],
            knowledge: vec![new],
            digest: None,
        };
        let pp = PostProcessor::with_components(build_components_with_extraction(
            extraction,
            Arc::clone(&similarity),
            Arc::clone(&store),
        ));
        pp.run("agent:research", &msg, &result).await.expect("ok");
        let bucket = store.list("agent:research");
        assert_eq!(bucket.len(), 1, "Insert branch: 1 entry");
        assert_eq!(bucket[0].status, MemoryStatus::Active);
    }

    // (b) Seed identical content → Skip.
    {
        let similarity = Arc::new(InMemorySimilarityIndex::new());
        let store = Arc::new(MemoryStore::new());
        let seed = fact_entry("f0", "Rust is memory-safe", "2026-01-01T00:00:00Z");
        similarity.add(seed.clone());
        store
            .insert("agent:research", seed)
            .expect("seed insert ok");
        let new = fact_entry("f1", "Rust is memory-safe", "2026-02-01T00:00:00Z");
        let extraction = Extraction {
            descriptions: vec![],
            knowledge: vec![new],
            digest: None,
        };
        let pp = PostProcessor::with_components(build_components_with_extraction(
            extraction,
            Arc::clone(&similarity),
            Arc::clone(&store),
        ));
        pp.run("agent:research", &msg, &result).await.expect("ok");
        let bucket = store.list("agent:research");
        assert_eq!(bucket.len(), 1, "Skip branch: still only the seed entry");
    }

    // (c) Single high-similarity match, content differs → Supersede{Refinement}.
    {
        let similarity = Arc::new(InMemorySimilarityIndex::new());
        let store = Arc::new(MemoryStore::new());
        let seed = fact_entry("f0", "Rust is memory-safe", "2026-01-01T00:00:00Z");
        similarity.add(seed.clone());
        store
            .insert("agent:research", seed)
            .expect("seed insert ok");
        let new = fact_entry("f1", "Rust is memory-safe and fast", "2026-02-01T00:00:00Z");
        let extraction = Extraction {
            descriptions: vec![],
            knowledge: vec![new],
            digest: None,
        };
        let pp = PostProcessor::with_components(build_components_with_extraction(
            extraction,
            Arc::clone(&similarity),
            Arc::clone(&store),
        ));
        pp.run("agent:research", &msg, &result).await.expect("ok");
        let bucket = store.list("agent:research");
        assert_eq!(bucket.len(), 2);
        let old = bucket.iter().find(|e| e.id == "f0").expect("old");
        let new_e = bucket.iter().find(|e| e.id == "f1").expect("new");
        assert_eq!(old.status, MemoryStatus::Superseded);
        assert!(!old.is_active);
        assert_eq!(
            old.supersession_reason,
            Some(SupersessionReason::Refinement)
        );
        assert_eq!(old.superseded_by, Some("f1".into()));
        assert_eq!(new_e.status, MemoryStatus::Active);
        assert!(new_e.is_active);
        assert!(new_e.superseded_by.is_none());
    }

    // (d) Two seed similar entries → multi-entry cluster → Supersede{Merge}.
    // Both seeds need Jaccard >= 0.5 vs the new content. Tokenized:
    //   new = {rust, is, fast, and, safe}
    //   s1  = {rust, is, fast}        → Jaccard = 3/5 = 0.6
    //   s2  = {rust, is, safe}        → Jaccard = 3/5 = 0.6
    {
        let similarity = Arc::new(InMemorySimilarityIndex::new());
        let store = Arc::new(MemoryStore::new());
        let s1 = fact_entry("f0", "Rust is fast", "2026-01-01T00:00:00Z");
        let s2 = fact_entry("f1", "Rust is safe", "2026-01-02T00:00:00Z");
        similarity.add(s1.clone());
        similarity.add(s2.clone());
        store.insert("agent:research", s1).expect("s1 insert ok");
        store.insert("agent:research", s2).expect("s2 insert ok");
        let new = fact_entry("f2", "Rust is fast and safe", "2026-02-01T00:00:00Z");
        let extraction = Extraction {
            descriptions: vec![],
            knowledge: vec![new],
            digest: None,
        };
        let pp = PostProcessor::with_components(build_components_with_extraction(
            extraction,
            Arc::clone(&similarity),
            Arc::clone(&store),
        ));
        pp.run("agent:research", &msg, &result).await.expect("ok");
        let bucket = store.list("agent:research");
        assert_eq!(bucket.len(), 3, "Merge branch: 2 seed + 1 new");
        let old = bucket
            .iter()
            .find(|e| e.id == "f0")
            .expect("old (first seed)");
        assert_eq!(old.status, MemoryStatus::Superseded);
        assert_eq!(old.supersession_reason, Some(SupersessionReason::Merge));
    }
}

// ─────────────────────────────────────────────────────────────────────
// Slice B AC-11: User-preference append-only
// ─────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn ac_11_user_preference_append_only() {
    let similarity = Arc::new(InMemorySimilarityIndex::new());
    let store = Arc::new(MemoryStore::new());
    let seed = pref_entry("p1", "I prefer concise responses", "2026-01-01T00:00:00Z");
    similarity.add(seed.clone());
    store.insert("agent:research", seed).expect("seed ok");

    let new = pref_entry("p2", "I prefer verbose responses", "2026-02-01T00:00:00Z");
    let extraction = Extraction {
        descriptions: vec![],
        knowledge: vec![new],
        digest: None,
    };
    let initial_call_count = similarity.call_count();
    let pp = PostProcessor::with_components(build_components_with_extraction(
        extraction,
        Arc::clone(&similarity),
        Arc::clone(&store),
    ));
    pp.run("agent:research", &fixture_message(), &fixture_result())
        .await
        .expect("ok");

    let bucket = store.list("agent:research");
    assert_eq!(bucket.len(), 2, "both prefs persist");
    for e in &bucket {
        assert!(e.is_active);
        assert_eq!(e.status, MemoryStatus::Active);
        assert!(e.superseded_by.is_none());
    }
    assert_eq!(
        similarity.call_count(),
        initial_call_count,
        "find_similar must NOT be invoked for the UserPreference branch"
    );
}
