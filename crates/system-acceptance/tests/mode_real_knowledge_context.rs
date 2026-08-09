//! B1 backbone — real cap-memory knowledge content in the assembled prompt.
//!
//! The FIRST witness that real memory content reaches the assembled prompt: the
//! cli `build_context_assembler_for_agent` wires a REAL `KnowledgeMapReader`
//! (projecting active `MemoryStore::recall` entries) into Tier 1b when the SUT
//! declared `Cap::Memory`. We pre-seed the persistent store BEFORE `.build()`
//! (the assembler-site store is a boot-time snapshot), drive TWO turns via the
//! production `serve_n_turns`, and assert the seeded knowledge body appears under
//! the `# Knowledge Map` section of each turn's captured LLM request body.
//!
//! Loopback-only (the external LLM provider is the sole double); every module in
//! the assembly chain is real. This is a demonstration / regression-guard for the
//! real KnowledgeMapReader — it is NOT a SYS-AC witness (SYS-AC-008/009 require
//! the un-wired-into-`assemble()` unified_search/L1–L6 surfaces; see MODULE-010
//! §3.6 B1 row). It DOES lock in that real knowledge reaches the prompt.

use cap_memory::{
    MemoryEntry, MemoryStatus, MemoryStore, MemoryType, DEFAULT_MAX_ACTIVE_PER_AGENT,
};
use system_acceptance::llm_loopback::ScriptedResponse;
use system_acceptance::{Cap, LlmMode, SystemUnderTest, AGENT_ID};

const HELLO_LLM_CORE: &[u8] =
    include_bytes!("../../runtime/tests/fixtures/guest-rust-hello-llm.core.wasm");

const PROMPT_TURN_1: &[u8] = b"alpha-first-turn-knowledge-prompt";
const PROMPT_TURN_2: &[u8] = b"bravo-second-turn-knowledge-prompt";
const REPLY_TURN_1: &str = "reply-knowledge-one";
const REPLY_TURN_2: &str = "reply-knowledge-two";

// Distinctive seeded knowledge bodies — unique markers that cannot alias the
// prompts/replies/section headers, so a substring hit proves real recall content.
const KNOWLEDGE_BODY_A: &str = "deploy-key-rotates-every-ninety-days";
const KNOWLEDGE_BODY_B: &str = "prefer-tabs-over-spaces-house-style";

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

#[tokio::test(flavor = "multi_thread")]
async fn real_knowledge_content_reaches_tier1b_across_two_turns() {
    // PRE-SEED on disk BEFORE build (the assembler-site store is a boot snapshot).
    let dir = tempfile::tempdir().expect("tempdir");
    {
        let store =
            MemoryStore::open(dir.path(), DEFAULT_MAX_ACTIVE_PER_AGENT).expect("open seed store");
        store
            .insert(AGENT_ID, fact("k1", KNOWLEDGE_BODY_A))
            .unwrap();
        store
            .insert(AGENT_ID, fact("k2", KNOWLEDGE_BODY_B))
            .unwrap();
    }

    let sut = SystemUnderTest::builder()
        .caps(&[Cap::Memory, Cap::Llm])
        .llm(LlmMode::LoopbackScripted(vec![
            ScriptedResponse::ok_chat(REPLY_TURN_1, 7, 9),
            ScriptedResponse::ok_chat(REPLY_TURN_2, 7, 9),
        ]))
        .with_memory_dir(dir.path().to_path_buf())
        .build(HELLO_LLM_CORE)
        .await;

    sut.inject_message("tester", PROMPT_TURN_1).await;
    sut.inject_message("tester", PROMPT_TURN_2).await;
    sut.run_turns(2).await;

    let bodies = sut.llm_all_chat_request_bodies();
    assert_eq!(
        bodies.len(),
        2,
        "two turns each dial generate once (got {} bodies)",
        bodies.len()
    );

    // Each turn's assembled prompt carries the `# Knowledge Map` section with BOTH
    // real seeded bodies — the first time real memory content reaches the prompt.
    for (i, body) in bodies.iter().enumerate() {
        assert!(
            body.contains("# Knowledge Map"),
            "turn {i}: assembled prompt must carry the Tier-1b '# Knowledge Map' section; body={body}"
        );
        assert!(
            body.contains(KNOWLEDGE_BODY_A) && body.contains(KNOWLEDGE_BODY_B),
            "turn {i}: '# Knowledge Map' must contain BOTH real recalled knowledge bodies \
             (projected from the persistent MemoryStore); body={body}"
        );
    }

    // The context.assembled event's tier1b token count is non-zero on both turns
    // (real content was billed to Tier 1b, not the empty-stub 0).
    let assembled = sut.events_of_types(&["context.assembled"]);
    assert_eq!(
        assembled.len(),
        2,
        "one context.assembled per turn (got {})",
        assembled.len()
    );
    for (i, ev) in assembled.iter().enumerate() {
        let tier1b = ev
            .payload
            .get("tier_token_counts")
            .and_then(|c| c.get("tier1b"))
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        assert!(
            tier1b > 0,
            "turn {i}: context.assembled tier1b token count must be > 0 (real knowledge present); \
             payload = {}",
            ev.payload
        );
    }
}
