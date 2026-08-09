//! SYS-J-60 (SYS-AC 186 / 187) — the L6 → skill-candidate round-trip, end-to-end on the real
//! wired system (Wave-7 Lane A).
//!
//! Journey (docs/SYSTEM-ACCEPTANCE.md §1): MODULE-011 → MODULE-017 → MODULE-002 → MODULE-019.
//! "An L6 consolidation emits a skill candidate into `_skill_candidates.jsonl`;
//! `list-skill-candidates` returns it while pending and `resolve-skill-candidate`
//! (accept/dismiss) appends a terminal event so it no longer lists as pending."
//!
//! Both legs run the REAL wired system: the PRODUCER is a live L6 consolidation on a real guest
//! turn (the production `LlmL6Classifier` injected via `.with_recording_l6()`, dialing a SEPARATE
//! loopback gateway whose `skill_health` entries drive the runnable Step-5a `append_generated` +
//! Step-5c `skill.candidate_generated`), and the CONSUMER is the REAL `list-skill-candidates` /
//! `resolve-skill-candidate` host-fns, driven through the `call_host_fn` registry boundary
//! (`Val-decode → handler → SingleAgentSkillStoreProvider → SkillStore → Val-encode`). The
//! candidate is CAUSAL (produced by the on-turn classify chain, NOT pre-planted), asserted via
//! the consumer host-fn + the on-disk `_skill_candidates.jsonl` (NOT `turn_commits()` — the JSONL
//! is a runtime store, not part of the L6 git commit set).

use cap_memory::{
    MemoryEntry, MemorySource, MemoryStatus, MemoryType, SkillCandidateEvent, SkillCandidateStore,
};
use system_acceptance::llm_loopback::ScriptedResponse;
use system_acceptance::{Cap, LlmMode, SystemUnderTest, AGENT_ID};
use wasmtime::component::Val;

const HELLO_LLM_CORE: &[u8] =
    include_bytes!("../../runtime/tests/fixtures/guest-rust-hello-llm.core.wasm");

const SKILLS_NS: &str = "advance:runtime/agent-skills@0.1.0";

// ── helpers (mirror sys_j23_l6_consolidation.rs) ──

/// A file-ref- or task-turn-sourced Fact. The seeded cluster has the synthesis-eligible SHAPE
/// (>=3 facts, >=1 file-ref) so the consolidation reaches the full success path — the commit of
/// the knowledge artifacts succeeds and Step-5c runs, which is where `skill.candidate_generated`
/// fires (186/187). NOTE: no actual synthesis is produced — `attach_l6` wires an EMPTY staleness
/// probe so the file-ref is orphaned and the synthesis 5-gate never passes — but 186/187 do NOT
/// need one (the candidates come from `skill_health` at Step-5a, emitted at Step-5c).
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

fn cluster_entries() -> Vec<MemoryEntry> {
    vec![
        fact("e1", "rust is memory safe and fast", true),
        fact("e2", "rust is memory safe and fast", false),
        fact("e3", "rust is memory safe and fast", false),
    ]
}

fn extraction(contents: &[String]) -> String {
    let items: Vec<String> = contents
        .iter()
        .map(|c| format!(r#"{{"content":"{c}","tags":["t"],"kind":"fact"}}"#))
        .collect();
    format!(r#"{{"digest":"d","knowledge":[{}]}}"#, items.join(","))
}

/// A SUT with the L6 → skill-candidate round-trip fully wired: Memory+Llm (producer) +
/// Skills (consumer), a seeded synthesis-eligible cluster, live memory, and the recording L6
/// axis (the real `LlmL6Classifier` returning `skill_health` → candidates).
async fn build_roundtrip_sut(task: &str, k: &str) -> SystemUnderTest {
    let sut = SystemUnderTest::builder()
        .caps(&[Cap::Memory, Cap::Llm, Cap::Skills])
        .llm(LlmMode::LoopbackScripted(vec![
            ScriptedResponse::ok_chat("reply", 7, 9),
            ScriptedResponse::ok_chat(&extraction(&[k.to_string()]), 7, 9),
        ]))
        .with_seeded_knowledge(cluster_entries())
        .with_live_memory()
        .with_recording_l6()
        .build(HELLO_LLM_CORE)
        .await;
    sut.inject_message_with_task("tester", task, b"go").await;
    sut.run_turn().await;
    sut
}

/// Decode a `list-skill-candidates` result Val → the pending `(candidate_id, skill_name)` pairs.
fn pending_candidates(v: &Val) -> Vec<(String, String)> {
    match v {
        Val::Result(Ok(Some(inner))) => match inner.as_ref() {
            Val::List(items) => items.iter().filter_map(record_id_name).collect(),
            other => panic!("list-skill-candidates ok payload is a list, got {other:?}"),
        },
        other => panic!("list-skill-candidates returns result::ok(list), got {other:?}"),
    }
}

fn record_id_name(v: &Val) -> Option<(String, String)> {
    let Val::Record(fields) = v else {
        return None;
    };
    let mut id = None;
    let mut name = None;
    for (k, val) in fields {
        if let Val::String(s) = val {
            match k.as_str() {
                "candidate-id" => id = Some(s.clone()),
                "skill-name" => name = Some(s.clone()),
                _ => {}
            }
        }
    }
    Some((id?, name?))
}

/// Decode a `resolve-skill-candidate` Ok result → `(candidate_id, draft_id)`; `None` on Err.
fn resolve_ok(v: &Val) -> Option<(String, String)> {
    let Val::Result(Ok(Some(inner))) = v else {
        return None;
    };
    let Val::Record(fields) = inner.as_ref() else {
        return None;
    };
    let mut id = None;
    let mut draft = None;
    for (k, val) in fields {
        if let Val::String(s) = val {
            match k.as_str() {
                "candidate-id" => id = Some(s.clone()),
                "draft-id" => draft = Some(s.clone()),
                _ => {}
            }
        }
    }
    Some((id?, draft?))
}

async fn list(sut: &SystemUnderTest) -> Vec<(String, String)> {
    let out = sut
        .call_host_fn("skills", SKILLS_NS, "list-skill-candidates", vec![])
        .await
        .expect("list-skill-candidates dispatch");
    pending_candidates(&out[0])
}

async fn resolve(sut: &SystemUnderTest, candidate_id: &str, action: &str) -> Val {
    let out = sut
        .call_host_fn(
            "skills",
            SKILLS_NS,
            "resolve-skill-candidate",
            vec![
                Val::String(candidate_id.to_string()),
                Val::Enum(action.to_string()),
            ],
        )
        .await
        .expect("resolve-skill-candidate dispatch");
    out.into_iter().next().expect("one result Val")
}

// ── SYS-AC-186 ───────────────────────────────────────────────────────────

/// SYS-AC-186 — an L6-generated skill candidate is appended to
/// `.agent/memory/_skill_candidates.jsonl` with a sha256 candidate_id and a `generated` event,
/// and `list-skill-candidates` returns it with status pending. CAUSAL: the candidate is produced
/// by the real on-turn `classify()→append_generated` chain (a `skill.candidate_generated` event
/// fires on the SUT sink THIS turn), not pre-planted.
#[tokio::test(flavor = "multi_thread")]
async fn sys_ac_186_l6_generated_candidate_pending() {
    let sut = build_roundtrip_sut("task-186", "k-186").await;

    // Causal proof: the on-turn L6 chain emitted skill.candidate_generated (one per skill_health
    // stale/unhealthy entry in the recording output).
    let generated = sut
        .events()
        .into_iter()
        .filter(|e| e.event_type == "skill.candidate_generated")
        .count();
    assert_eq!(
        generated, 2,
        "two skill.candidate_generated events fired on this turn (one per skill_health entry); got {generated}. \
         Event types = {:?}",
        sut.events()
            .iter()
            .map(|e| e.event_type.clone())
            .collect::<Vec<_>>()
    );

    // The consumer host-fn lists BOTH as pending (the real list-skill-candidates boundary).
    let pending = list(&sut).await;
    assert_eq!(
        pending.len(),
        2,
        "list-skill-candidates returns both produced candidates as pending; got {pending:?}"
    );
    assert!(
        pending.iter().any(|(_, name)| name == "summarize-pr"),
        "the summarize-pr candidate is pending; got {pending:?}"
    );
    assert!(
        pending.iter().any(|(_, name)| name == "triage-issues"),
        "the triage-issues candidate is pending; got {pending:?}"
    );
    // Criterion: "a sha256 candidate_id" — 64 lowercase hex chars.
    for (id, _) in &pending {
        assert_eq!(id.len(), 64, "candidate_id is a 64-hex sha256; got {id:?}");
        assert!(
            id.chars().all(|c| c.is_ascii_hexdigit()),
            "candidate_id is hex; got {id:?}"
        );
    }

    // The producer JSONL on disk carries the generated events (the .agent/memory path).
    let store = SkillCandidateStore::in_dir(sut.memory_dir());
    let evs = store.read_events().expect("read candidate events");
    let gen_count = evs
        .iter()
        .filter(|e| matches!(e, SkillCandidateEvent::Generated { .. }))
        .count();
    assert_eq!(
        gen_count, 2,
        "two Generated events persisted in _skill_candidates.jsonl; events = {evs:?}"
    );

    // Discriminator: with the recording axis OFF (StubL6Classifier ⇒ empty skill_health) a real
    // consolidation still runs but produces NO candidate — proving the candidate is causal.
    let off = {
        let off = SystemUnderTest::builder()
            .caps(&[Cap::Memory, Cap::Llm, Cap::Skills])
            .llm(LlmMode::LoopbackScripted(vec![
                ScriptedResponse::ok_chat("reply", 7, 9),
                ScriptedResponse::ok_chat(&extraction(&["k-186-off".into()]), 7, 9),
            ]))
            .with_seeded_knowledge(cluster_entries())
            .with_live_memory()
            .with_live_l6()
            .build(HELLO_LLM_CORE)
            .await;
        off.inject_message_with_task("tester", "task-186-off", b"go")
            .await;
        off.run_turn().await;
        off
    };
    assert!(
        list(&off).await.is_empty(),
        "discriminator: StubL6Classifier emits no skill_health ⇒ no candidate is listed"
    );
}

// ── SYS-AC-187 ───────────────────────────────────────────────────────────

/// SYS-AC-187 — `resolve-skill-candidate(candidate-id, accept/dismiss)` appends a terminal
/// resolved/dismissed event (append-only; the generated row retained) and a subsequent
/// `list-skill-candidates` no longer returns it as pending. Drives BOTH terminal kinds (dismiss
/// one + accept the other), asserts neither remains pending, asserts the precise append-only
/// event shape (2 Generated + 1 Resolved + 1 Dismissed), and that a re-resolve of a terminal
/// candidate is rejected (not-found projection). Its OWN SUT (separate from 186).
#[tokio::test(flavor = "multi_thread")]
async fn sys_ac_187_resolve_candidate_terminal() {
    let sut = build_roundtrip_sut("task-187", "k-187").await;

    let pending = list(&sut).await;
    assert_eq!(
        pending.len(),
        2,
        "two candidates generated before resolve; got {pending:?}"
    );
    let (dismiss_id, _) = pending[0].clone();
    let (accept_id, _) = pending[1].clone();
    assert_ne!(
        dismiss_id, accept_id,
        "the two candidates have distinct ids"
    );

    // Dismiss the first → terminal `dismissed`, empty draft-id.
    let dismissed = resolve(&sut, &dismiss_id, "dismiss").await;
    let (rid, draft) = resolve_ok(&dismissed).expect("dismiss returns Ok(candidate-result)");
    assert_eq!(rid, dismiss_id, "dismiss result echoes the candidate id");
    assert!(
        draft.is_empty(),
        "dismiss carries an empty draft-id; got {draft:?}"
    );

    // Accept the second → terminal `resolved` + a proposed activatable draft (non-empty draft-id).
    let accepted = resolve(&sut, &accept_id, "accept").await;
    let (aid, adraft) = resolve_ok(&accepted).expect("accept returns Ok(candidate-result)");
    assert_eq!(aid, accept_id, "accept result echoes the candidate id");
    assert!(
        !adraft.is_empty(),
        "accept proposes an activatable draft ⇒ non-empty draft-id; got {adraft:?}"
    );

    // A subsequent list no longer returns EITHER as pending.
    let after = list(&sut).await;
    assert!(
        after.is_empty(),
        "after accept+dismiss, neither candidate is pending; got {after:?}"
    );

    // Append-only, precise per-variant event shape: 2 Generated + 1 Resolved + 1 Dismissed
    // (the generated rows are RETAINED alongside the terminal rows).
    let store = SkillCandidateStore::in_dir(sut.memory_dir());
    let evs = store.read_events().expect("read candidate events");
    let gen = evs
        .iter()
        .filter(|e| matches!(e, SkillCandidateEvent::Generated { .. }))
        .count();
    let res = evs
        .iter()
        .filter(|e| matches!(e, SkillCandidateEvent::Resolved { .. }))
        .count();
    let dis = evs
        .iter()
        .filter(|e| matches!(e, SkillCandidateEvent::Dismissed { .. }))
        .count();
    assert_eq!(
        (gen, res, dis),
        (2, 1, 1),
        "append-only: 2 Generated + 1 Resolved + 1 Dismissed; events = {evs:?}"
    );

    // Re-resolving a terminal candidate is rejected (the double-resolve guard → not-found
    // projection), NOT a second terminal event.
    let reresolve = resolve(&sut, &dismiss_id, "accept").await;
    assert!(
        resolve_ok(&reresolve).is_none(),
        "re-resolving an already-terminal candidate is NOT Ok; got {reresolve:?}"
    );
    let evs_after = store
        .read_events()
        .expect("read candidate events after re-resolve");
    assert_eq!(
        evs_after.len(),
        4,
        "the rejected re-resolve appended NO new event (still 2 Generated + 1 Resolved + 1 Dismissed); events = {evs_after:?}"
    );
}
