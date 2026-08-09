//! SYS-J-23 (SYS-AC 070 / 215) — the LIVE L6 consolidation dispatch wired onto the
//! `.with_live_memory()` post-processor via the opt-in `.with_live_l6()` /
//! `.with_failing_l6_committer()` axes (Stage-C MAINLINE harvest pass-2).
//!
//! These drive the REAL wired system end-to-end: a generate-calling guest
//! (`guest-rust-hello-llm`) runs a production turn; the components-backed
//! PostProcessor evaluates the L6 trigger at Step-9 and — with the axis on —
//! dispatches the production `attach_l6` construction (GitQueueL6Committer over the
//! harness's REAL `DefaultGitCommitQueue` + L6Runnable + L6DispatchAdapter sharing
//! the live store/lease/l6_emitter/clock). Witness-floor: assertions bind to
//! PRODUCT output — `memory.l6_completed` on the SUT event sink, a real on-disk
//! `CommitType::L6` (`[l6]`) commit via `turn_commits()`, `component.error` on the
//! failure path.
//!
//! The synthesis-eligible cluster is seeded via `.with_seeded_knowledge()` (NOT a
//! `.with_memory_dir()` override) so the L6 synthesis writes/commit land inside the
//! harness's git workspace (a caller dir would be OUTSIDE the workdir → commit fails).
//!
//! SYS-AC-068 (Stage-C MAINLINE harvest pass-3) — the named >=20-EntryCount leg's
//! `consolidation_due` — is NOW witnessed below (`sys_ac_068_entrycount_leg_emits_consolidation_due`)
//! via the `.with_l6_entrycount_isolation()` axis: a frozen `MutableClock` + a seeded
//! `l6_trigger_state{ last_l6_at: now-60s, completed_tasks_delta: 0 }` silence the
//! HoursSinceLast + CompletedTasks legs, so the only way Step-9 emits `consolidation_due` is
//! >=20 NewEntries-since-last. The leg is e2e-attributable on `.with_live_memory()` ALONE —
//! Step-9 emits the due-event in the lease-Acquired branch independent of any L6 handler
//! (post_processor.rs:1331), so no synthesis machinery is needed. Closes the pass-2 deferral.
//!
//! Wave-7 Lane A — the L6 keystone is injected: the production
//! `advance_cli::l6_classifier::LlmL6Classifier` is wired into `attach_l6` via the harness
//! `.with_recording_l6()` / `.with_failing_l6_gateway()` axes, dialing a SEPARATE second
//! loopback gateway (NOT the registered guest/extractor FIFO, so 070/215 stay byte-identical).
//! - SYS-AC-216 is NOW witnessed (`sys_ac_216_l6_llm_call_failure_cleanup`): a non-retryable
//!   gateway failure → `classify()` `LlmFailure` → `component.error` + lease cleared + NO
//!   commit/completed (the NAMED "LLM call fails" trigger, distinct from the
//!   `mid_run_commit_failure_cleanup` committer-failure regression gate retained below).
//! - SYS-AC-069 is NOW witnessed (Wave-10 Lane A — `sys_ac_069_real_probe_writes_synthesis_and_commits`):
//!   the Wave-9 real `ResolverStalenessProbe` landed (`attach_l6_with_stale_resolver`), so the harness
//!   opts into it via the default-off `.with_real_l6_probe()` axis + a real-blob FileRef seeded with
//!   `.with_seeded_workspace_file()`. The Step-1 probe judges the file-ref Valid → not orphaned → the
//!   synthesis 5-gate passes → a real `syntheses/*.md` is written + committed in the `[l6]`
//!   `CommitType::L6` commit, with `delta.syntheses_generated >= 1`. The DISCRIMINATOR (same axis,
//!   mismatched on-disk blob → Stale → orphaned → 0 synthesis) proves the probe's blob verdict is the
//!   cause. The keystone DIAL + the `[l6]` commit on the DEFAULT empty-stub path remain pinned by
//!   `l6_recording_classifier_dials_gateway_and_commits` (which still does NOT itself claim 069 —
//!   that's the dedicated real-probe test's job).

use cap_memory::{
    MemoryEntry, MemorySource, MemoryStatus, MemoryStore, MemoryType, DEFAULT_MAX_ACTIVE_PER_AGENT,
};
use system_acceptance::llm_loopback::ScriptedResponse;
use system_acceptance::{blob_oid_of_bytes, Cap, LlmMode, SystemUnderTest, AGENT_ID};

const HELLO_LLM_CORE: &[u8] =
    include_bytes!("../../runtime/tests/fixtures/guest-rust-hello-llm.core.wasm");

/// A file-ref- or task-turn-sourced Fact (mirrors `l6_production_wiring.rs::fact`) giving the
/// seeded cluster the synthesis-eligible SHAPE (>=3 facts, >=1 file-ref source). NOTE: this helper's
/// file-ref carries a FAKE `blob_id`, so on the DEFAULT empty-stub `attach_l6` path (no
/// `.with_real_l6_probe()`) it is judged Stale → orphaned → the synthesis 5-gate never passes (no
/// `syntheses/*.md`); the cluster still reaches the commit-of-knowledge success path. 069's synthesis
/// clause is witnessed SEPARATELY by `real_fileref_fact` + `.with_real_l6_probe()` (a REAL git blob
/// the real `ResolverStalenessProbe` judges Valid). Carries the harness write agent id so the
/// runnable's `store.list(agent)` sees it.
fn fact(id: &str, content: &str, file_ref: bool) -> MemoryEntry {
    let sources = if file_ref {
        vec![MemorySource::FileRef {
            agent_id: AGENT_ID.into(),
            vpath: format!("data/{id}.csv"),
            commit_ish: "abc".into(),
            blob_id: format!("blob-{id}"),
            line_range: None,
        }]
    } else {
        vec![MemorySource::TaskTurn {
            task_id: "task-seed".into(),
            turn: 1,
        }]
    };
    MemoryEntry {
        id: id.into(),
        agent_id: AGENT_ID.into(),
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

/// A synthesis-eligible cluster: >=3 active facts sharing a tag, one FileRef-sourced
/// — the shape `L6ClusterBuilder` + the synthesis 5-gate accept.
fn cluster_entries() -> Vec<MemoryEntry> {
    vec![
        fact("e1", "rust is memory safe and fast", true),
        fact("e2", "rust is memory safe and fast", false),
        fact("e3", "rust is memory safe and fast", false),
    ]
}

/// Wave-10 Lane A (SYS-AC-069): a FileRef-sourced Fact carrying a REAL `(vpath, blob_id)` that the
/// `.with_real_l6_probe()` `ResolverStalenessProbe` will resolve against a real on-disk blob. Same
/// content/tag as the rest of the cluster so all three facts cluster together (the synthesis 5-gate
/// needs >=3 members). `agent_id == AGENT_ID` matches the resolver tree's `OneAgentTree` node id.
fn real_fileref_fact(id: &str, vpath: &str, blob_id: &str) -> MemoryEntry {
    MemoryEntry {
        id: id.into(),
        agent_id: AGENT_ID.into(),
        entry_type: MemoryType::Fact,
        content: "rust is memory safe and fast".into(),
        tags: vec!["pricing".into()],
        created_at: "2026-01-01T00:00:00Z".into(),
        task_origin: None,
        is_active: true,
        superseded_by: None,
        status: MemoryStatus::Active,
        supersession_reason: None,
        cluster_id: None,
        sources: vec![MemorySource::FileRef {
            agent_id: AGENT_ID.into(),
            vpath: vpath.into(),
            commit_ish: "working-tree".into(),
            blob_id: blob_id.into(),
            line_range: None,
        }],
    }
}

/// A valid extraction-schema response carrying the given knowledge contents.
fn extraction(contents: &[String]) -> String {
    let items: Vec<String> = contents
        .iter()
        .map(|c| format!(r#"{{"content":"{c}","tags":["t"],"kind":"fact"}}"#))
        .collect();
    format!(r#"{{"digest":"d","knowledge":[{}]}}"#, items.join(","))
}

/// 25 deliberately-distinct knowledge contents (minimal shared tokens) so each clears
/// the reconciler dedup and lands as an Insert — the turn-2 re-trigger lever for
/// SYS-AC-215. Each carries the `t2mk` marker so the re-opened store can count exactly
/// the turn-2 contributions.
fn t2_items() -> Vec<String> {
    let subjects = [
        "alpha", "bravo", "charlie", "delta", "echo", "foxtrot", "golf", "hotel", "india",
        "juliet", "kilo", "lima", "mike", "november", "oscar", "papa", "quebec", "romeo", "sierra",
        "tango", "uniform", "victor", "whiskey", "xray", "yankee",
    ];
    let topics = [
        "mountains",
        "rivers",
        "oceans",
        "deserts",
        "forests",
        "glaciers",
        "valleys",
        "canyons",
        "plateaus",
        "islands",
        "volcanoes",
        "reefs",
        "tundra",
        "savanna",
        "wetlands",
        "caves",
        "fjords",
        "dunes",
        "springs",
        "meadows",
        "cliffs",
        "lagoons",
        "steppes",
        "marshes",
        "craters",
    ];
    (0..subjects.len())
        .map(|i| format!("t2mk-{i} {} {}", subjects[i], topics[i]))
        .collect()
}

/// SYS-AC-070 — a `memory.l6_completed` event carrying BOTH a delta block and a
/// KnowledgeHealthSnapshot, plus a real on-disk `[l6]` `CommitType::L6` commit.
#[tokio::test(flavor = "multi_thread")]
async fn sys_ac_070_l6_completed_delta_snapshot() {
    let sut = SystemUnderTest::builder()
        .caps(&[Cap::Memory, Cap::Llm])
        .llm(LlmMode::LoopbackScripted(vec![
            ScriptedResponse::ok_chat("reply", 7, 9),
            ScriptedResponse::ok_chat(&extraction(&["k-070".into()]), 7, 9),
        ]))
        .with_seeded_knowledge(cluster_entries())
        .with_live_memory()
        .with_live_l6()
        .build(HELLO_LLM_CORE)
        .await;
    sut.inject_message_with_task("tester", "task-070", b"go")
        .await;
    sut.run_turn().await;

    let completed: Vec<_> = sut
        .events()
        .into_iter()
        .filter(|e| e.event_type == "memory.l6_completed")
        .collect();
    assert_eq!(
        completed.len(),
        1,
        "exactly one memory.l6_completed; event types = {:?}",
        sut.events()
            .iter()
            .map(|e| e.event_type.clone())
            .collect::<Vec<_>>()
    );
    let p = &completed[0].payload;
    // delta block — the full 5-field L6Delta shape (events.rs::l6_completed_event).
    let delta = p
        .get("delta")
        .and_then(|d| d.as_object())
        .unwrap_or_else(|| panic!("l6_completed carries a delta object; payload={p:?}"));
    for k in [
        "clusters_merged",
        "entries_pruned",
        "syntheses_generated",
        "contested_clusters",
        "orphaned_entries",
    ] {
        assert!(
            delta.contains_key(k),
            "delta block missing `{k}`; delta={delta:?}"
        );
    }
    // KnowledgeHealthSnapshot — the full 10-field shape, incl. every field the
    // criterion names (total_active, contested, orphaned, clusters_total).
    let snap = p
        .get("snapshot")
        .and_then(|s| s.as_object())
        .unwrap_or_else(|| panic!("l6_completed carries a snapshot object; payload={p:?}"));
    for k in [
        "total_active",
        "active",
        "contested",
        "orphaned",
        "forgotten",
        "superseded",
        "partial_stale",
        "zero_access_30d",
        "clusters_total",
        "clusters_contested",
    ] {
        assert!(
            snap.contains_key(k),
            "KnowledgeHealthSnapshot missing `{k}`; snapshot={snap:?}"
        );
    }

    let l6_commits: Vec<_> = sut
        .turn_commits()
        .into_iter()
        .filter(|c| c.message.contains("[l6]"))
        .collect();
    assert_eq!(
        l6_commits.len(),
        1,
        "exactly one real on-disk [l6] CommitType::L6 commit; commit msgs = {:?}",
        sut.turn_commits()
            .iter()
            .map(|c| c.message.clone())
            .collect::<Vec<_>>()
    );

    // Discriminator: axis OFF (`.with_live_memory()` but NO `.with_live_l6()`) →
    // Step-9 emits consolidation_due only, never dispatches → no l6_completed/[l6].
    let off = SystemUnderTest::builder()
        .caps(&[Cap::Memory, Cap::Llm])
        .llm(LlmMode::LoopbackScripted(vec![
            ScriptedResponse::ok_chat("reply", 7, 9),
            ScriptedResponse::ok_chat(&extraction(&["k-070".into()]), 7, 9),
        ]))
        .with_seeded_knowledge(cluster_entries())
        .with_live_memory()
        .build(HELLO_LLM_CORE)
        .await;
    off.inject_message_with_task("tester", "task-070", b"go")
        .await;
    off.run_turn().await;
    assert!(
        !off.events()
            .iter()
            .any(|e| e.event_type == "memory.l6_completed"),
        "discriminator: with the L6 axis OFF the turn emits NO memory.l6_completed"
    );
    assert!(
        !off.turn_commits()
            .iter()
            .any(|c| c.message.contains("[l6]")),
        "discriminator: with the L6 axis OFF no [l6] commit is written"
    );
}

/// SYS-AC-215 — single-flight: a second L6 trigger firing while a consolidation lease
/// is already held does NOT start a second consolidation. Turn-1 succeeds and holds
/// the lease to TTL (the runnable does not release on Ok; the harness delivers no
/// `component.finished`); turn-2's extraction lands >=20 distinct Inserts so its
/// NewEntries leg re-fires, hits `AlreadyHeld`, and starts nothing.
///
/// Anti-fake-green: "exactly one l6_completed" alone would also hold if turn-2 never
/// triggered, so we additionally PROVE turn-2's trigger condition was met — the
/// re-opened store carries >=20 `t2mk` entries (all from turn-2's extraction; turn-1's
/// extraction adds none).
#[tokio::test(flavor = "multi_thread")]
async fn sys_ac_215_single_flight_already_held() {
    let t2 = t2_items();
    let sut = SystemUnderTest::builder()
        .caps(&[Cap::Memory, Cap::Llm])
        .llm(LlmMode::LoopbackScripted(vec![
            // turn-1: generate + a minimal extraction (no t2mk content).
            ScriptedResponse::ok_chat("reply-one", 7, 9),
            ScriptedResponse::ok_chat(&extraction(&["k-215-seed".into()]), 7, 9),
            // turn-2: generate + an extraction landing >=20 distinct Inserts.
            ScriptedResponse::ok_chat("reply-two", 7, 9),
            ScriptedResponse::ok_chat(&extraction(&t2), 7, 9),
        ]))
        .with_seeded_knowledge(cluster_entries())
        .with_live_memory()
        .with_live_l6()
        .build(HELLO_LLM_CORE)
        .await;
    sut.inject_message_with_task("tester", "task-215", b"one")
        .await;
    sut.inject_message_with_task("tester", "task-215", b"two")
        .await;
    sut.run_turns(2).await;

    // Positive observable: turn-2's NewEntries leg condition was MET (>=20 t2mk
    // Inserts, all from turn-2 — turn-1's extraction had none). Re-open the SUT's
    // (still-alive) in-workspace store to count them.
    let store =
        MemoryStore::open(sut.memory_dir(), DEFAULT_MAX_ACTIVE_PER_AGENT).expect("re-open store");
    let t2_landed = store
        .list(AGENT_ID)
        .into_iter()
        .filter(|e| e.is_active && e.content.contains("t2mk"))
        .count();
    assert!(
        t2_landed >= 20,
        "turn-2 must land >=20 distinct Inserts so its NewEntries (>=20) trigger leg \
         re-fires; only {t2_landed} t2mk entries landed (reconciler dedup too aggressive — \
         if irreducible, 215 must DEFER, not fake-green)"
    );

    // Single-flight: the re-fired turn-2 trigger hit AlreadyHeld → no 2nd consolidation.
    let completed = sut
        .events()
        .into_iter()
        .filter(|e| e.event_type == "memory.l6_completed")
        .count();
    assert_eq!(
        completed, 1,
        "EXACTLY ONE memory.l6_completed across both turns (turn-2 AlreadyHeld); got {completed}"
    );
    // Criterion clause "nor re-emit memory.l6_consolidation_due": the due-event is
    // emitted ONLY inside the lease-Acquired branch, so turn-1 (Acquired) emits it and
    // turn-2 (AlreadyHeld) does NOT → exactly one across both turns.
    let due = sut
        .events()
        .into_iter()
        .filter(|e| e.event_type == "memory.l6_consolidation_due")
        .count();
    assert_eq!(
        due, 1,
        "EXACTLY ONE memory.l6_consolidation_due (turn-2 AlreadyHeld → no confirm/emit); got {due}"
    );
    let l6_commits = sut
        .turn_commits()
        .into_iter()
        .filter(|c| c.message.contains("[l6]"))
        .count();
    assert_eq!(
        l6_commits, 1,
        "a SINGLE [l6] commit across both turns (turn-2 started no 2nd consolidation); got {l6_commits}"
    );
}

/// Generic L6 mid-run-failure CLEANUP gate (the commit-failure variant) — a
/// regression test, NOT a SYS-AC-216 witness. 216's criterion names "the L6 batch
/// LLM call fails", which is unreachable while `attach_l6` wires `StubL6Classifier`
/// (no LLM call to fail on the StubL6Classifier path); the NAMED 216 trigger is
/// witnessed by `sys_ac_216_l6_llm_call_failure_cleanup` (`.with_failing_l6_gateway()`). This
/// still pins the failure-mode-agnostic Err-arm contract: a mid-run failure surfaces
/// as `component.error`, the lease is cleared, and NO syntheses commit /
/// `memory.l6_completed` is produced (the next trigger retries). Driven by
/// `.with_failing_l6_committer()` (FailingCommitter). Two turns: both fire
/// HoursSinceLast(None) (the failure path never primes `last_l6_at`), so turn-2
/// RE-fires — proving the lease was cleared after turn-1.
#[tokio::test(flavor = "multi_thread")]
async fn mid_run_commit_failure_cleanup() {
    let sut = SystemUnderTest::builder()
        .caps(&[Cap::Memory, Cap::Llm])
        .llm(LlmMode::LoopbackScripted(vec![
            ScriptedResponse::ok_chat("reply-one", 7, 9),
            ScriptedResponse::ok_chat(&extraction(&["k-216-a".into()]), 7, 9),
            ScriptedResponse::ok_chat("reply-two", 7, 9),
            ScriptedResponse::ok_chat(&extraction(&["k-216-b".into()]), 7, 9),
        ]))
        .with_seeded_knowledge(cluster_entries())
        .with_live_memory()
        .with_failing_l6_committer()
        .build(HELLO_LLM_CORE)
        .await;
    sut.inject_message_with_task("tester", "task-216", b"one")
        .await;
    sut.inject_message_with_task("tester", "task-216", b"two")
        .await;
    sut.run_turns(2).await;

    let errors = sut
        .events()
        .into_iter()
        .filter(|e| e.event_type == "component.error")
        .count();
    assert!(
        errors >= 2,
        "a mid-run commit failure emits component.error on BOTH turns (turn-2 re-fires \
         because the failure cleared the lease + never primed last_l6_at); got {errors}. \
         Event types = {:?}",
        sut.events()
            .iter()
            .map(|e| e.event_type.clone())
            .collect::<Vec<_>>()
    );
    assert!(
        !sut.events()
            .iter()
            .any(|e| e.event_type == "memory.l6_completed"),
        "the failure path emits NO memory.l6_completed"
    );
    assert!(
        !sut.turn_commits()
            .iter()
            .any(|c| c.message.contains("[l6]")),
        "the failure path writes NO [l6] consolidation commit"
    );
}

// ---------------------------------------------------------------------------
// SYS-AC-068 (Stage-C MAINLINE harvest pass-3) — the >=20-EntryCount trigger leg in
// isolation, via the `.with_l6_entrycount_isolation()` clock seam.
// ---------------------------------------------------------------------------

/// SYS-AC-068: when an L6 any-of trigger fires via the >=20-new-knowledge-entries leg, a
/// `memory.l6_consolidation_due {agent_id, lease_id}` event is emitted. The clock seam
/// (`.with_l6_entrycount_isolation()`: frozen `MutableClock` + seeded
/// `l6_trigger_state{ last_l6_at: now-60s, completed_tasks_delta: 0 }`) silences the
/// HoursSinceLast(<24h) and CompletedTasks(<3) legs, so the due-event is attributable SOLELY
/// to the NewEntries(>=20) leg. Bound to `.with_live_memory()` ALONE (no `.with_live_l6()`):
/// Step-9 emits `consolidation_due` in the lease-Acquired branch independent of any L6
/// handler (post_processor.rs:1331), so the witness is the literal criterion (the EVENT),
/// not the synthesis machinery (which would couple 068 to StubL6Classifier — the 069/216
/// gap).
///
/// Anti-fake-green (mirror SYS-AC-215): re-open the live store and assert the EXACT distinct
/// `t2mk` Insert count, so the absent/present split is the COUNT, not over-aggressive dedup.
#[tokio::test(flavor = "multi_thread")]
async fn sys_ac_068_entrycount_leg_emits_consolidation_due() {
    // ── ABSENT: <20 distinct Inserts → NewEntries quiet → NO consolidation_due. ──
    let five: Vec<String> = t2_items().into_iter().take(5).collect();
    let absent = SystemUnderTest::builder()
        .caps(&[Cap::Memory, Cap::Llm])
        .llm(LlmMode::LoopbackScripted(vec![
            ScriptedResponse::ok_chat("reply", 7, 9),
            ScriptedResponse::ok_chat(&extraction(&five), 7, 9),
        ]))
        .with_live_memory()
        .with_l6_entrycount_isolation()
        .build(HELLO_LLM_CORE)
        .await;
    absent
        .inject_message_with_task("tester", "task-068a", b"go")
        .await;
    absent.run_turn().await;

    assert!(
        !absent
            .events()
            .iter()
            .any(|e| e.event_type == "memory.l6_consolidation_due"),
        "ABSENT: <20 NewEntries (+ quiet clock) → no leg fires → NO memory.l6_consolidation_due; \
         event types = {:?}",
        absent
            .events()
            .iter()
            .map(|e| e.event_type.clone())
            .collect::<Vec<_>>()
    );
    assert!(
        !absent
            .events()
            .iter()
            .any(|e| e.event_type == "memory.l6_completed"),
        "ABSENT: no trigger fired (and no live_l6 handler) → no memory.l6_completed"
    );
    // Anti-fake-green: the absence is the COUNT (exactly 5 distinct t2mk Inserts), not dedup.
    let store_a = MemoryStore::open(absent.memory_dir(), DEFAULT_MAX_ACTIVE_PER_AGENT)
        .expect("reopen absent store");
    let landed_a = store_a
        .list(AGENT_ID)
        .into_iter()
        .filter(|e| e.is_active && e.content.contains("t2mk"))
        .count();
    assert_eq!(
        landed_a, 5,
        "ABSENT: exactly 5 distinct t2mk Inserts landed (< 20 → NewEntries quiet by COUNT, \
         not over-aggressive dedup); got {landed_a}"
    );

    // ── PRESENT: >=20 distinct Inserts → NewEntries fires → exactly one consolidation_due. ──
    let present = SystemUnderTest::builder()
        .caps(&[Cap::Memory, Cap::Llm])
        .llm(LlmMode::LoopbackScripted(vec![
            ScriptedResponse::ok_chat("reply", 7, 9),
            ScriptedResponse::ok_chat(&extraction(&t2_items()), 7, 9),
        ]))
        .with_live_memory()
        .with_l6_entrycount_isolation()
        .build(HELLO_LLM_CORE)
        .await;
    present
        .inject_message_with_task("tester", "task-068b", b"go")
        .await;
    present.run_turn().await;

    let due: Vec<_> = present
        .events()
        .into_iter()
        .filter(|e| e.event_type == "memory.l6_consolidation_due")
        .collect();
    assert_eq!(
        due.len(),
        1,
        "PRESENT: the >=20-NewEntries leg fires → EXACTLY ONE memory.l6_consolidation_due; \
         event types = {:?}",
        present
            .events()
            .iter()
            .map(|e| e.event_type.clone())
            .collect::<Vec<_>>()
    );
    // The criterion names a `{agent_id, lease_id}` payload (events.rs::l6_consolidation_due_event).
    let payload = &due[0].payload;
    assert!(
        payload.get("agent_id").is_some(),
        "consolidation_due payload carries agent_id; payload={payload:?}"
    );
    assert!(
        payload.get("lease_id").is_some(),
        "consolidation_due payload carries lease_id; payload={payload:?}"
    );
    // Anti-fake-green: the firing is the COUNT (>=20 distinct t2mk Inserts), all from this
    // turn's extraction (the seeded clock leaves last_l6_at stable, no prior consolidation).
    let store_p = MemoryStore::open(present.memory_dir(), DEFAULT_MAX_ACTIVE_PER_AGENT)
        .expect("reopen present store");
    let landed_p = store_p
        .list(AGENT_ID)
        .into_iter()
        .filter(|e| e.is_active && e.content.contains("t2mk"))
        .count();
    assert!(
        landed_p >= 20,
        "PRESENT: >=20 distinct t2mk Inserts landed so the NewEntries(>=20) leg genuinely \
         fires; only {landed_p} (if dedup is irreducible, 068 must DEFER, not fake-green)"
    );
}

// ---------------------------------------------------------------------------
// SYS-AC-216 (Wave-7 Lane A) — the L6 keystone injected: the production LlmL6Classifier
// dials a SEPARATE recording/failing loopback gateway inside attach_l6. The recording
// axis also backs the SYS-J-60 candidate round-trip (sys_j60_skill_candidate_roundtrip.rs).
// ---------------------------------------------------------------------------

/// Wave-7 Lane A keystone REGRESSION GATE (NOT a SYS-AC-069 witness). Pins that the real
/// production `LlmL6Classifier` is INJECTED into `attach_l6` (`.with_recording_l6()`) and DIALS
/// the SEPARATE recording gateway (`l6_chat_request_count()` + the L6 prompt marker — the
/// load-bearing, non-fake-green dial witness; `memory.l6_completed` alone is NOT a dial, since
/// 070 is green with `StubL6Classifier`), and that the consolidation still commits `[l6]` +
/// completes.
///
/// This DELIBERATELY does NOT itself claim SYS-AC-069 ("writes syntheses/*.md, and commits them"):
/// on the DEFAULT path this test runs (no `.with_real_l6_probe()`), `attach_l6` wires
/// `cap_memory::l6::InMemoryStalenessProbe::new()` (the EMPTY Slice-C stub), so run_stale_detection
/// judges EVERY file-ref entry `Stale` → the runnable Step-4 marks it `Orphaned` → the synthesis
/// 5-gate (`should_synthesize`, requires >=1 NON-orphaned file-ref) NEVER passes →
/// `syntheses_generated == 0`, no `syntheses/*.md`. This run remains the empty-stub DIAL + `[l6]`
/// commit regression gate (which unblocked 216 below). SYS-AC-069's synthesis clause is now
/// witnessed SEPARATELY by `sys_ac_069_real_probe_writes_synthesis_and_commits`, which opts into the
/// Wave-9 real `ResolverStalenessProbe` via `.with_real_l6_probe()` + a real-blob FileRef — the real
/// production probe judging a real git blob, NOT a stub-in-the-chain. Keeping THIS gate on the empty
/// stub guarantees the default `.with_recording_l6()` path stays byte-identical.
#[tokio::test(flavor = "multi_thread")]
async fn l6_recording_classifier_dials_gateway_and_commits() {
    let sut = SystemUnderTest::builder()
        .caps(&[Cap::Memory, Cap::Llm])
        .llm(LlmMode::LoopbackScripted(vec![
            ScriptedResponse::ok_chat("reply", 7, 9),
            ScriptedResponse::ok_chat(&extraction(&["k-069".into()]), 7, 9),
        ]))
        .with_seeded_knowledge(cluster_entries())
        .with_live_memory()
        .with_recording_l6()
        .build(HELLO_LLM_CORE)
        .await;
    sut.inject_message_with_task("tester", "task-069", b"go")
        .await;
    sut.run_turn().await;

    // The REAL L6 classify dial reached the SEPARATE gateway (the keystone this run adds).
    assert!(
        sut.l6_chat_request_count() >= 1,
        "the L6 consolidation must DIAL the gateway >=1 time (real LlmL6Classifier); got {}. \
         l6_completed alone is NOT a dial witness (070 is green with StubL6Classifier).",
        sut.l6_chat_request_count()
    );
    let bodies = sut.l6_chat_request_bodies();
    assert!(
        bodies
            .iter()
            .any(|b| b.contains("L6 cross-task consolidation")),
        "an L6 chat-request body carries the L6 classification prompt; bodies = {bodies:?}"
    );

    // The consolidation still commits [l6] (knowledge artifacts) + completes. NOTE: no synthesis
    // is committed (see the doc — empty staleness probe ⇒ syntheses_generated == 0).
    let l6_commits: Vec<_> = sut
        .turn_commits()
        .into_iter()
        .filter(|c| c.message.contains("[l6]"))
        .collect();
    assert_eq!(
        l6_commits.len(),
        1,
        "exactly one real on-disk [l6] CommitType::L6 commit; commit msgs = {:?}",
        sut.turn_commits()
            .iter()
            .map(|c| c.message.clone())
            .collect::<Vec<_>>()
    );
    assert_eq!(
        sut.events()
            .iter()
            .filter(|e| e.event_type == "memory.l6_completed")
            .count(),
        1,
        "exactly one memory.l6_completed"
    );

    // Discriminator: with the recording axis OFF (plain `.with_live_l6()` → StubL6Classifier)
    // the SEPARATE L6 gateway is never built, so ZERO dials — yet the consolidation still
    // completes. This proves `l6_chat_request_count() >= 1` is the discriminating dial witness.
    let off = SystemUnderTest::builder()
        .caps(&[Cap::Memory, Cap::Llm])
        .llm(LlmMode::LoopbackScripted(vec![
            ScriptedResponse::ok_chat("reply", 7, 9),
            ScriptedResponse::ok_chat(&extraction(&["k-069".into()]), 7, 9),
        ]))
        .with_seeded_knowledge(cluster_entries())
        .with_live_memory()
        .with_live_l6()
        .build(HELLO_LLM_CORE)
        .await;
    off.inject_message_with_task("tester", "task-069", b"go")
        .await;
    off.run_turn().await;
    assert_eq!(
        off.l6_chat_request_count(),
        0,
        "discriminator: recording axis OFF (StubL6Classifier) ⇒ the L6 gateway is never dialed"
    );
    assert!(
        off.events()
            .iter()
            .any(|e| e.event_type == "memory.l6_completed"),
        "discriminator sanity: the StubL6Classifier path still completes a consolidation"
    );
}

/// SYS-AC-216 — if the L6 batch LLM call FAILS mid-run, a `component.error` is written, the
/// lease is cleared, and NO `syntheses/*.md` commit or `memory.l6_completed` event is emitted
/// (the next trigger retries). Driven by `.with_failing_l6_gateway()`: the real
/// `LlmL6Classifier` dials a SEPARATE loopback gateway scripted with a non-retryable HTTP 400,
/// so `classify()` returns `L6Error::LlmFailure` in Step-3, BEFORE the commit. This is the
/// NAMED "LLM call fails" trigger (distinct from `mid_run_commit_failure_cleanup`, whose
/// trigger is a failing COMMITTER). Two turns: both fire `HoursSinceLast(None)` (the
/// classify-failure path never primes `last_l6_at`), so turn-2 RE-fires — proving the lease was
/// cleared after turn-1.
#[tokio::test(flavor = "multi_thread")]
async fn sys_ac_216_l6_llm_call_failure_cleanup() {
    let sut = SystemUnderTest::builder()
        .caps(&[Cap::Memory, Cap::Llm])
        .llm(LlmMode::LoopbackScripted(vec![
            ScriptedResponse::ok_chat("reply-one", 7, 9),
            ScriptedResponse::ok_chat(&extraction(&["k-216-a".into()]), 7, 9),
            ScriptedResponse::ok_chat("reply-two", 7, 9),
            ScriptedResponse::ok_chat(&extraction(&["k-216-b".into()]), 7, 9),
        ]))
        .with_seeded_knowledge(cluster_entries())
        .with_live_memory()
        .with_failing_l6_gateway()
        .build(HELLO_LLM_CORE)
        .await;
    sut.inject_message_with_task("tester", "task-216", b"one")
        .await;
    sut.inject_message_with_task("tester", "task-216", b"two")
        .await;
    sut.run_turns(2).await;

    // The NAMED trigger: the L6 LLM call was ATTEMPTED and FAILED on BOTH turns. EXACTLY one
    // upstream dial per turn (non-retryable 400 ⇒ no retry inflation), and turn-2 re-fired
    // because turn-1's classify-failure cleared the lease (never primed last_l6_at).
    assert_eq!(
        sut.l6_chat_request_count(),
        2,
        "exactly two L6 dials (one failed dial per re-firing turn); got {}",
        sut.l6_chat_request_count()
    );
    // Witness attribution (adversarial r8 Info-1): bind the component.error to the L6 component
    // and the LLM-failure reason — `id == "memory.l6"` (the component id attach_l6 builds with)
    // AND `message == coarse_l6_error(LlmFailure)` — so an UNRELATED component.error can never
    // mask a broken L6 emitter (anti-fake-green). The L6DispatchAdapter emits
    // `emit_component_error(bus, "memory.l6", "l6", "l6 classify or synthesis failure")`.
    let l6_errors = sut
        .events()
        .into_iter()
        .filter(|e| {
            e.event_type == "component.error"
                && e.payload.get("id").and_then(|v| v.as_str()) == Some("memory.l6")
                && e.payload.get("message").and_then(|v| v.as_str())
                    == Some("l6 classify or synthesis failure")
        })
        .count();
    assert!(
        l6_errors >= 2,
        "a mid-run L6 LLM-call failure emits a component.error BOUND to the L6 component \
         (id=memory.l6, message='l6 classify or synthesis failure') on BOTH turns (turn-2 re-fires \
         because the failure cleared the lease + never primed last_l6_at); got {l6_errors}. \
         Event types = {:?}",
        sut.events()
            .iter()
            .map(|e| e.event_type.clone())
            .collect::<Vec<_>>()
    );
    assert!(
        !sut.events()
            .iter()
            .any(|e| e.event_type == "memory.l6_completed"),
        "the LLM-call-failure path emits NO memory.l6_completed"
    );
    assert!(
        !sut.turn_commits()
            .iter()
            .any(|c| c.message.contains("[l6]")),
        "the LLM-call-failure path writes NO [l6] consolidation commit"
    );
}

// ---------------------------------------------------------------------------
// SYS-AC-069 (Wave-10 Lane A) — the synthesis clause, NOW reachable via the Wave-9 real
// `ResolverStalenessProbe`. `.with_real_l6_probe()` swaps the harness `attach_l6` empty-stub shim
// for the PRODUCTION `attach_l6_with_stale_resolver(Some(..))` (the same probe start.rs wires); a
// real-blob FileRef seeded with `.with_seeded_workspace_file()` is judged Valid → not orphaned →
// the synthesis 5-gate passes → a real `syntheses/*.md` is written + committed in the `[l6]`
// `CommitType::L6` commit. Witness-floor: 100% real production fns — the probe judges a REAL git
// blob; NO module in the SYS-J-23 chain is mocked. The discriminator (mismatched on-disk blob →
// Stale → orphaned → 0 synthesis) isolates the probe's blob verdict as the synthesis cause.
// ---------------------------------------------------------------------------

/// Drive ONE real-probe recording-L6 turn over a seeded real-blob FileRef cluster. The seeded
/// FileRef `e1` carries `blob_oid_of_bytes(seed_content)`; the on-disk workspace file at
/// `data/e1.csv` carries `disk_content`. When they MATCH the real `ResolverStalenessProbe` judges
/// `e1` Valid → not orphaned → the synthesis 5-gate passes; when they DIFFER `e1` is Stale →
/// orphaned → the gate fails. Returns `(memory.l6_completed count, delta.syntheses_generated,
/// whether an [l6] commit's tree contains a syntheses/*.md path)`.
async fn drive_real_probe_l6(seed_content: &[u8], disk_content: &[u8]) -> (usize, u64, bool) {
    let blob_id = blob_oid_of_bytes(seed_content);
    let cluster = vec![
        real_fileref_fact("e1", "data/e1.csv", &blob_id),
        fact("e2", "rust is memory safe and fast", false),
        fact("e3", "rust is memory safe and fast", false),
    ];
    let sut = SystemUnderTest::builder()
        .caps(&[Cap::Memory, Cap::Llm])
        .llm(LlmMode::LoopbackScripted(vec![
            ScriptedResponse::ok_chat("reply", 7, 9),
            ScriptedResponse::ok_chat(&extraction(&["k-069".into()]), 7, 9),
        ]))
        .with_seeded_knowledge(cluster)
        // The on-disk blob the real probe resolves `data/e1.csv` to (written at the territory root +
        // committed in a `[seed]` commit BEFORE the turn).
        .with_seeded_workspace_file("data/e1.csv", disk_content)
        .with_live_memory()
        .with_recording_l6()
        .with_real_l6_probe()
        .build(HELLO_LLM_CORE)
        .await;
    sut.inject_message_with_task("tester", "task-069", b"go")
        .await;
    sut.run_turn().await;

    let completed: Vec<_> = sut
        .events()
        .into_iter()
        .filter(|e| e.event_type == "memory.l6_completed")
        .collect();
    let synth_gen = completed
        .first()
        .and_then(|e| e.payload.get("delta"))
        .and_then(|d| d.get("syntheses_generated"))
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    // The [l6] tree paths are workspace-root-relative (e.g. `.agent/memory/<slug>/syntheses/<topic>.md`);
    // `slug` is pub(crate), so glob on the substring + `.md` suffix rather than an exact path.
    let has_synth_md = sut
        .turn_commits()
        .into_iter()
        .filter(|c| c.message.contains("[l6]"))
        .any(|c| {
            c.tree_paths
                .iter()
                .any(|p| p.contains("syntheses/") && p.ends_with(".md"))
        });
    (completed.len(), synth_gen, has_synth_md)
}

/// SYS-AC-069 — the FLIP. The background runnable clusters knowledge, the real `LlmL6Classifier`
/// dials the LLM, and — with the real `ResolverStalenessProbe` judging `e1`'s seeded blob Valid —
/// the synthesis 5-gate passes: a real `syntheses/*.md` is written and committed via the Git queue
/// with `commit_type=l6`, and `memory.l6_completed.delta.syntheses_generated >= 1`.
#[tokio::test(flavor = "multi_thread")]
async fn sys_ac_069_real_probe_writes_synthesis_and_commits() {
    let content: &[u8] = b"col_a,col_b\n1,2\n";
    // seed blob == on-disk blob → e1 Valid.
    let (completed, synth_gen, has_synth_md) = drive_real_probe_l6(content, content).await;
    assert_eq!(
        completed, 1,
        "exactly one memory.l6_completed for the single L6 consolidation"
    );
    assert!(
        synth_gen >= 1,
        "the real ResolverStalenessProbe judges e1 Valid (seeded blob == on-disk blob) → not \
         orphaned → the synthesis 5-gate passes → delta.syntheses_generated >= 1; got {synth_gen}"
    );
    assert!(
        has_synth_md,
        "069: a real syntheses/*.md is written + committed in the [l6] CommitType::L6 commit"
    );
}

/// SYS-AC-069 DISCRIMINATOR (anti-fake-green) — the SAME `.with_real_l6_probe()` + recording axis,
/// but the on-disk blob DIFFERS from the seeded `blob_id`, so the real probe judges `e1` Stale →
/// orphaned → the 5-gate's no-orphaned gate fails → ZERO synthesis. Proves the synthesis is CAUSED
/// by the probe judging the real blob Valid (single variable: only the on-disk content differs), not
/// by the axis being on or the seed.
#[tokio::test(flavor = "multi_thread")]
async fn sys_ac_069_discriminator_mismatched_blob_suppresses_synthesis() {
    let seed: &[u8] = b"col_a,col_b\n1,2\n";
    let on_disk_different: &[u8] = b"totally different bytes - blob mismatch\n";
    let (completed, synth_gen, has_synth_md) = drive_real_probe_l6(seed, on_disk_different).await;
    assert_eq!(
        completed, 1,
        "the consolidation still completes (memory.l6_completed) — only the synthesis is suppressed"
    );
    assert_eq!(
        synth_gen, 0,
        "mismatched on-disk blob → e1 Stale → orphaned → the 5-gate fails → syntheses_generated == 0; \
         got {synth_gen} (if this is >=1 the probe is not actually gating the synthesis = fake-green)"
    );
    assert!(
        !has_synth_md,
        "no syntheses/*.md is committed when the file-ref is judged Stale"
    );
}
