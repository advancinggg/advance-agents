//! SYS-J-02 / SYS-J-03 (SYS-AC-006 / 008 / 192) — the LIVE memory read-path in the
//! assembled per-turn prompt via the default-off `.with_live_memory()` axis.
//!
//! Stage-C MAINLINE harvest pass-1. With the axis on, the history-aware assembler
//! (`build_context_assembler_for_agent_with_history` + `memory_root`) reads the real
//! `CapMemoryHistoryReader` L2/L3/L4 layers over `<memory_dir>/tasks/{task}/`. A
//! generate-calling guest (`guest-rust-hello-llm`) emits the assembled prompt as its
//! `/v1/chat/completions` request body, captured via `llm_all_chat_request_bodies()`.
//!
//! With live memory ON, a turn also dials the post-turn EXTRACTION call, so the
//! captured bodies interleave [generate, extraction, generate, extraction, …]. The
//! generate bodies (the assembled prompts) are the ones that do NOT carry the
//! extraction system prompt — `assembled_bodies()` filters them out.
//!
//! Witness-floor: assertions bind to PRODUCT output — the captured assembled-prompt
//! bytes drawn from on-disk summary.yaml/turn-index.yaml written by a prior real turn.
//! Each row carries a discriminator (axis-off / empty memory → no such content).

use cap_memory::{
    MemoryEntry, MemoryStatus, MemoryStore, MemoryType, DEFAULT_MAX_ACTIVE_PER_AGENT,
};
use system_acceptance::llm_loopback::ScriptedResponse;
use system_acceptance::{Cap, LlmMode, SystemUnderTest, AGENT_ID};

const HELLO_LLM_CORE: &[u8] =
    include_bytes!("../../runtime/tests/fixtures/guest-rust-hello-llm.core.wasm");

/// A minimal active Fact for pre-seeding the boot-snapshot `KnowledgeMapReader`.
fn fact(id: &str, content: &str) -> MemoryEntry {
    MemoryEntry {
        id: id.into(),
        agent_id: AGENT_ID.into(),
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

/// A valid extraction-schema response whose `digest` carries a unique marker, so a
/// later turn's assembled prompt (which re-reads the on-disk turn-index/summary the
/// extraction produced) can be checked for that exact marker.
fn extraction_with_digest(digest: &str) -> String {
    format!(
        r#"{{"digest":"{digest}","knowledge":[{{"content":"k-{digest}","tags":["t"],"kind":"fact"}}]}}"#
    )
}

/// The assembled-prompt (generate) bodies only — i.e. those that are NOT the
/// post-turn extraction call (whose system message identifies it as the
/// memory-extraction assistant).
fn assembled_bodies(bodies: &[String]) -> Vec<&String> {
    bodies
        .iter()
        .filter(|b| !b.contains("memory-extraction assistant"))
        .collect()
}

/// SYS-AC-006: the second turn's assembled prompt re-includes prior-turn context
/// (summary / turn-index) drawn from local files, not a remote session. Turn-1's live
/// PostProcessor writes `tasks/{slug}/` from a digest carrying a unique marker; turn-2's
/// history-aware assembler reads it back into the assembled prompt.
#[tokio::test(flavor = "multi_thread")]
async fn sys_ac_006_second_turn_assembled_prompt_reincludes_prior_context() {
    const PRIOR: &str = "prior-turn-digest-marker-006";
    const SLUG: &str = "task-006";

    let run = |live: bool| async move {
        let dir = tempfile::tempdir().expect("tempdir");
        let mem = dir.path().join(".agent/memory");
        let mut b = SystemUnderTest::builder().caps(&[Cap::Memory, Cap::Llm]);
        b = if live {
            // FIFO across 2 turns: gen-1, extraction-1 (writes the prior marker),
            // gen-2, extraction-2.
            b.llm(LlmMode::LoopbackScripted(vec![
                ScriptedResponse::ok_chat("reply-one", 7, 9),
                ScriptedResponse::ok_chat(&extraction_with_digest(PRIOR), 7, 9),
                ScriptedResponse::ok_chat("reply-two", 7, 9),
                ScriptedResponse::ok_chat(&extraction_with_digest("d2"), 7, 9),
            ]))
            .with_live_memory()
        } else {
            // Axis off → no extraction, no writeback: 2 plain generate turns.
            b.llm(LlmMode::LoopbackScripted(vec![
                ScriptedResponse::ok_chat("reply-one", 7, 9),
                ScriptedResponse::ok_chat("reply-two", 7, 9),
            ]))
        };
        let sut = b.with_memory_dir(mem).build(HELLO_LLM_CORE).await;
        sut.inject_message_with_task("tester", SLUG, b"first-turn-prompt")
            .await;
        sut.inject_message_with_task("tester", SLUG, b"second-turn-prompt")
            .await;
        sut.run_turns(2).await;
        sut.llm_all_chat_request_bodies()
    };

    let bodies = run(true).await;
    let gen = assembled_bodies(&bodies);
    assert_eq!(
        gen.len(),
        2,
        "two assembled (generate) prompts across the two turns; got {} (all bodies: {})",
        gen.len(),
        bodies.len()
    );
    assert!(
        gen[1].contains(PRIOR),
        "turn-2 assembled prompt must re-include the prior-turn context (the digest \
         marker turn-1 wrote to local summary/turn-index files); body={}",
        gen[1]
    );

    // Discriminator: axis OFF → turn-1 writes nothing, turn-2 reads nothing.
    let off = run(false).await;
    let off_gen = assembled_bodies(&off);
    assert!(
        !off_gen[1].contains(PRIOR),
        "discriminator: with the axis OFF the second turn's prompt carries NO prior-turn \
         file content (no history reader, no write-back)"
    );
}

/// SYS-AC-008 — the assembled prompt carries ALL THREE sources for the routed task: L4
/// `summary.yaml` content (`# Task Summary`), L0/L2 `turn-index.yaml` material (`# Recent
/// Turn Digests`), AND knowledge.jsonl insights (`# Knowledge Map`).
///
/// Wave-15 Lane B wired the L4 producer: Step-7 now populates `summary.brief` from the turn
/// digest (cadence-gated by `should_update_brief` + a first-turn bootstrap, post_processor.rs),
/// so the L4 reader surfaces a non-empty brief and the assembler renders the `# Task Summary`
/// section (skip-on-empty guard at assembler.rs:780). Turn-1's live Step-7 writes the brief to
/// on-disk `summary.yaml`; turn-2's history-aware assembler reads it back into the assembled
/// prompt. The L4 leg is bound to the on-disk brief via the untrusted `memory:l4_task_summary`
/// `<data>…</data>` envelope (robust against the JSON-serialized request body — the same
/// envelope `sys_j19_injection_ingress` asserts), so the match is the L4 section, not the
/// `# Recent Turn Digests` (L2) bleed (the brief == the prior digest, which also renders under
/// L2). Discriminators: `gen[0]` (turn-1's prompt, assembled BEFORE turn-1's writeback) carries
/// no `# Task Summary`, and an empty-memory axis-off prompt carries none of the three.
#[tokio::test(flavor = "multi_thread")]
async fn sys_ac_008_assembled_prompt_carries_l4_l0l2_and_knowledge() {
    const DIGEST: &str = "task-summary-digest-marker-008";
    const KNOW: &str = "preseeded-knowledge-marker-008";
    const SLUG: &str = "task-008";

    let dir = tempfile::tempdir().expect("tempdir");
    let mem = dir.path().join(".agent/memory");
    // Pre-seed knowledge BEFORE build (the Tier-1b KnowledgeMapReader is a boot snapshot).
    {
        let store = MemoryStore::open(&mem, DEFAULT_MAX_ACTIVE_PER_AGENT).expect("seed store");
        store.insert(AGENT_ID, fact("k-008", KNOW)).unwrap();
    }
    let sut = SystemUnderTest::builder()
        .caps(&[Cap::Memory, Cap::Llm])
        .llm(LlmMode::LoopbackScripted(vec![
            ScriptedResponse::ok_chat("reply-one", 7, 9),
            ScriptedResponse::ok_chat(&extraction_with_digest(DIGEST), 7, 9),
            ScriptedResponse::ok_chat("reply-two", 7, 9),
            ScriptedResponse::ok_chat(&extraction_with_digest("d2"), 7, 9),
        ]))
        .with_memory_dir(mem.clone())
        .with_live_memory()
        .build(HELLO_LLM_CORE)
        .await;
    sut.inject_message_with_task("tester", SLUG, b"first").await;
    sut.inject_message_with_task("tester", SLUG, b"second")
        .await;
    sut.run_turns(2).await;

    let bodies = sut.llm_all_chat_request_bodies();
    let gen = assembled_bodies(&bodies);
    // Guard the generate/extraction split (the filter keys off the extractor's system
    // prompt phrase): exactly two assembled (generate) prompts across the two turns.
    assert_eq!(
        gen.len(),
        2,
        "two assembled (generate) prompts expected; got {} (all bodies: {})",
        gen.len(),
        bodies.len()
    );
    // In-run producer-isolating discriminator: gen[0] (turn-1's prompt) is assembled BEFORE
    // turn-1's Step-7 brief writeback, so its on-disk brief is still empty → no L4 section.
    // gen[0] ABSENT + gen[1] PRESENT binds the L4 section to the producer (same axis; the only
    // difference is turn-1's Step-7 write between them).
    assert!(
        !gen[0].contains("# Task Summary") && !gen[0].contains("memory:l4_task_summary"),
        "turn-1's prompt (assembled pre-writeback, empty brief) must NOT carry the L4 section; \
         gen0={}",
        gen[0]
    );
    let p = gen[1]; // turn-2 assembled prompt

    // L0/L2 turn-index material: the prior-turn digest under `# Recent Turn Digests`.
    assert!(
        p.contains("# Recent Turn Digests") && p.contains(DIGEST),
        "turn-2 prompt must carry L0/L2 turn-index material (the prior digest read from \
         turn-index.yaml); p={p}"
    );
    // L4 summary.yaml content: Step-7 now populates `summary.brief` (Wave-15 Lane B), so the
    // assembler renders the `# Task Summary` section. Bind to the ON-DISK brief (independent
    // oracle): read the summary.yaml turn-1 wrote, and assert the rendered L4 envelope carries
    // exactly that brief. Bound to the `memory:l4_task_summary` <data>…</data> envelope (NOT a
    // `\n# ` substring — the captured body is JSON-serialized) so the match is the L4 leg, not
    // the `# Recent Turn Digests` (L2) bleed (brief == the prior digest, which also renders
    // under L2).
    let summary_path = mem.join("tasks").join(SLUG).join("summary.yaml");
    let raw = std::fs::read_to_string(&summary_path)
        .unwrap_or_else(|e| panic!("turn-1 Step-7 must have written {summary_path:?}: {e}"));
    let on_disk: cap_memory::Summary =
        serde_yml::from_str(&raw).expect("on-disk summary.yaml parses as cap_memory::Summary");
    assert!(
        !on_disk.brief.trim().is_empty(),
        "Step-7 must populate a non-empty summary.brief; on-disk summary.yaml: {raw}"
    );
    assert!(
        p.contains("# Task Summary"),
        "turn-2 prompt must carry the L4 `# Task Summary` section now that Step-7 populates \
         summary.brief; p={p}"
    );
    let l4_start = p
        .find("memory:l4_task_summary")
        .unwrap_or_else(|| panic!("L4 `memory:l4_task_summary` envelope absent; p={p}"));
    let l4_tail = &p[l4_start..];
    let l4_end = l4_tail
        .find("</data>")
        .map(|i| i + "</data>".len())
        .unwrap_or(l4_tail.len());
    let l4_block = &l4_tail[..l4_end];
    assert!(
        l4_block.contains(on_disk.brief.trim()),
        "the L4 `memory:l4_task_summary` envelope must carry the on-disk brief ({:?}); \
         l4_block={l4_block}",
        on_disk.brief
    );
    // knowledge.jsonl insights: the seeded knowledge under `# Knowledge Map`.
    assert!(
        p.contains("# Knowledge Map") && p.contains(KNOW),
        "turn-2 prompt must carry knowledge.jsonl insights under `# Knowledge Map`; p={p}"
    );

    // Discriminator: empty memory + axis off → none of the three present.
    let dir2 = tempfile::tempdir().unwrap();
    let sut0 = SystemUnderTest::builder()
        .caps(&[Cap::Memory, Cap::Llm])
        .llm(LlmMode::LoopbackScripted(vec![ScriptedResponse::ok_chat(
            "r", 7, 9,
        )]))
        .with_memory_dir(dir2.path().join(".agent/memory"))
        .build(HELLO_LLM_CORE)
        .await;
    sut0.inject_message_with_task("tester", SLUG, b"only").await;
    sut0.run_turn().await;
    let b0 = sut0.llm_all_chat_request_bodies();
    let g0 = assembled_bodies(&b0);
    assert!(
        !g0[0].contains(DIGEST)
            && !g0[0].contains(KNOW)
            && !g0[0].contains("# Task Summary")
            && !g0[0].contains("memory:l4_task_summary"),
        "discriminator: an empty-memory axis-off prompt carries no L4/turn-index/knowledge content"
    );
}

/// SYS-AC-192: when the routed context cannot fit the token budget, assembly still
/// returns a DEGRADED extreme-mode prompt rather than failing the turn — the live
/// `assemble()` degrade guard drops Tier-2 (tools) when `used > budget`
/// (model_context_window("")=8192 − response_reserve=1228 = 6964 tokens). Needs
/// neither the live-memory axis nor seeded history. Discriminator: an under-budget
/// turn keeps the normal prompt (tools present, tier2 > 0).
#[tokio::test(flavor = "multi_thread")]
async fn sys_ac_192_over_budget_returns_degraded_extreme_prompt() {
    // A generate-calling guest reads msg.payload as the prompt (decoded up to a 64 KiB
    // cap). ~60 KB of ASCII ≈ ~15K tokens, well over the 6964-token budget.
    let big = vec![b'x'; 60 * 1024];

    let run = |payload: Vec<u8>| async move {
        let sut = SystemUnderTest::builder()
            .caps(&[Cap::Llm])
            .llm(LlmMode::LoopbackScripted(vec![ScriptedResponse::ok_chat(
                "reply", 7, 9,
            )]))
            .build(HELLO_LLM_CORE)
            .await;
        sut.inject_message("tester", &payload).await;
        sut.run_turn().await;
        let body = sut
            .llm_all_chat_request_bodies()
            .first()
            .cloned()
            .unwrap_or_default();
        let tier2 = sut
            .events_of_types(&["context.assembled"])
            .first()
            .and_then(|e| {
                e.payload
                    .get("tier_token_counts")
                    .and_then(|c| c.get("tier2"))
                    .and_then(|v| v.as_u64())
            })
            .unwrap_or(u64::MAX);
        (body, tier2)
    };

    let (over_body, over_tier2) = run(big).await;
    let (under_body, under_tier2) = run(b"tiny-prompt".to_vec()).await;

    // Under budget → NORMAL prompt: `# Available Tools` present, tier2 > 0.
    assert!(
        under_body.contains("# Available Tools") && under_tier2 > 0,
        "under-budget assembly is the normal prompt (tools present, tier2={under_tier2})"
    );
    // Over budget → DEGRADED extreme mode (NOT a turn failure): Tier-2 dropped to 0,
    // the `# Available Tools` section gone.
    assert_eq!(
        over_tier2, 0,
        "over-budget assembly degrades to extreme mode: tier2 dropped to 0 (turn not failed)"
    );
    assert!(
        !over_body.contains("# Available Tools"),
        "over-budget degraded prompt drops the Tier-2 `# Available Tools` section; body len={}",
        over_body.len()
    );
}
