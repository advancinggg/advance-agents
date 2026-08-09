//! SYS-J-02 provider-switch recall witness (SYS-AC-005).
//!
//! Wave-16 Lane 2 — deep-content recall. Drives a turn AFTER switching the configured
//! LLM provider and proves the assembled prompt still carries the LOCAL `# Recalled
//! Context` (sourced from the agent's local memory + workspace files via the real cli
//! `build_recall_unified_search` / `build_context_assembler_for_agent_with_recall`
//! production fns, opted into by the default-off `.with_recall_corpus()` SUT axis) —
//! i.e. context is rebuilt LOCALLY each call, not from provider state.
//!
//! SYS-AC-005: "A turn run after switching the configured LLM provider still answers
//! coherently, proving context is rebuilt locally (unified_search) not from provider
//! state." Witnessed (on the FULL real chain — `run_agent` → `run_turn_once` → real
//! `PublishingContextAssembler`/`ContextAssemblerImpl` → real `unified_search`
//! coordinator → real `format_recall_section` Tier-3 → guest `agent-llm/generate` →
//! real cap-llm OpenAI adapter → harness loopback, the ONLY double) by:
//!   (a) the configured provider GENUINELY switched between the two turns — turn-1's
//!       outbound body resolves `model: gpt-4o-mini` (provider `openai`), turn-2's
//!       resolves `model: mistral-large` (provider `mistral`) after
//!       `switch_llm_provider`; the gateway re-reads its config per call;
//!   (b) BOTH turns' assembled prompts carry the SAME local `# Recalled Context`
//!       (`## Files` bound to the seeded `notes.md`, `## Memory` bound to `mem-deploy`)
//!       — recall is rebuilt locally each call, unaffected by the switch;
//!   (c) neither outbound body carries any provider session/conversation key;
//!   (d) both turns delivered a coherent reply through the real action-dispatch seam.
//!
//! The two turns are SEPARATE `run_turn()` calls so `switch_llm_provider` lands BETWEEN
//! the two `generate` calls. The recall corpus (baked into the assembler at `build()`)
//! and the provider config (`InlineConfigProvider`) are HOST-side fields on the
//! persistent SUT, so both survive across the two calls; guest-state continuity is
//! irrelevant to SYS-AC-005.

use cap_memory::{MemoryEntry, MemoryStatus, MemoryType};
use system_acceptance::llm_loopback::ScriptedResponse;
use system_acceptance::{Cap, LlmMode, SystemUnderTest, AGENT_ID};

/// The committed reference guest: `handle-message` reads `msg.payload` as the prompt and
/// calls `agent-llm/generate`, returning the reply text as its single action.
const HELLO_LLM_CORE: &[u8] =
    include_bytes!("../../runtime/tests/fixtures/guest-rust-hello-llm.core.wasm");

const MEM_ID: &str = "mem-deploy";
const FILE_VPATH: &str = "notes.md";
const REPLY_A: &str = "reply-alpha-coherent-answer-one";
const REPLY_B: &str = "reply-bravo-coherent-answer-two";
const PROMPT_1: &[u8] = b"alpha-zero-niner-first-turn-prompt";
const PROMPT_2: &[u8] = b"bravo-seven-three-second-turn-prompt";

/// Provider session/conversation correlation keys a STATELESS LLM request must never carry.
const FORBIDDEN_SESSION_KEYS: &[&str] = &[
    "session",
    "session_id",
    "conversation_id",
    "previous_response_id",
    "thread_id",
];

fn fact(id: &str, content: &str) -> MemoryEntry {
    MemoryEntry {
        id: id.into(),
        agent_id: AGENT_ID.into(), // colon id → seeded under (and recalled by) the assemble id
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

/// Recursively assert no object key in `v` is a provider session/conversation key.
fn assert_no_session_keys(v: &serde_json::Value, where_: &str) {
    match v {
        serde_json::Value::Object(map) => {
            for (k, child) in map {
                assert!(
                    !FORBIDDEN_SESSION_KEYS.contains(&k.as_str()),
                    "{where_}: outbound LLM request carries a provider session/conversation key `{k}`"
                );
                assert_no_session_keys(child, where_);
            }
        }
        serde_json::Value::Array(arr) => {
            for child in arr {
                assert_no_session_keys(child, where_);
            }
        }
        _ => {}
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn sys_ac_005_recall_survives_provider_switch() {
    // Seed the LOCAL corpus: one active memory entry (under the colon AGENT_ID) + one
    // workspace file → the recall corpus has BOTH a `## Files` and a `## Memory` doc.
    let sut = SystemUnderTest::builder()
        .caps(&[Cap::Memory, Cap::Llm])
        .llm(LlmMode::LoopbackScripted(vec![
            ScriptedResponse::ok_chat(REPLY_A, 7, 9),
            ScriptedResponse::ok_chat(REPLY_B, 7, 9),
        ]))
        .with_seeded_knowledge(vec![fact(
            MEM_ID,
            "the deploy script runs cargo build then rsync",
        )])
        .with_seeded_workspace_file(
            FILE_VPATH,
            b"local notes about the rsync mirror deploy plan",
        )
        .with_reply_capture()
        .with_recall_corpus()
        .build(HELLO_LLM_CORE)
        .await;

    // Turn 1 under provider P_A (the default loopback config: openai / gpt-4o-mini).
    sut.inject_message("tester", PROMPT_1).await;
    sut.run_turn().await;

    // Switch the CONFIGURED LLM provider, then Turn 2 under P_B (mistral / mistral-large).
    sut.switch_llm_provider("mistral", "mistral-large");
    sut.inject_message("tester", PROMPT_2).await;
    sut.run_turn().await;

    let bodies = sut.llm_all_chat_request_bodies();
    assert_eq!(
        bodies.len(),
        2,
        "two consecutive turns each dial generate exactly once (got {} bodies)",
        bodies.len()
    );

    let j0: serde_json::Value = serde_json::from_str(&bodies[0])
        .unwrap_or_else(|e| panic!("body0 json: {e}; {}", bodies[0]));
    let j1: serde_json::Value = serde_json::from_str(&bodies[1])
        .unwrap_or_else(|e| panic!("body1 json: {e}; {}", bodies[1]));

    // (a) the configured provider GENUINELY switched — distinct resolved model identities.
    assert_eq!(
        j0["model"].as_str(),
        Some("gpt-4o-mini"),
        "turn-1 resolves provider P_A's model; body0={}",
        bodies[0]
    );
    assert_eq!(
        j1["model"].as_str(),
        Some("mistral-large"),
        "turn-2 resolves the SWITCHED provider P_B's model (gateway re-read its config); body1={}",
        bodies[1]
    );
    assert_ne!(
        j0["model"].as_str(),
        j1["model"].as_str(),
        "the configured provider must differ across the switch"
    );

    // (b) BOTH turns' assembled prompts carry the SAME LOCAL recall section, bound to the
    //     seeded file + memory ids → recall is rebuilt locally each call (provider-independent).
    // (c) neither body carries a provider session/conversation key.
    for (i, body) in bodies.iter().enumerate() {
        let turn = i + 1;
        assert!(
            body.contains("# Recalled Context"),
            "turn-{turn} assembled prompt must carry the local recall section; body={body}"
        );
        assert!(
            body.contains("## Files") && body.contains(FILE_VPATH),
            "turn-{turn} recall must include the local workspace file `{FILE_VPATH}`; body={body}"
        );
        assert!(
            body.contains("## Memory") && body.contains(MEM_ID),
            "turn-{turn} recall must include the local memory entry `{MEM_ID}`; body={body}"
        );
        let j: serde_json::Value = serde_json::from_str(body).unwrap();
        assert_no_session_keys(&j, &format!("body {i}"));
    }

    // (d) both turns produced a coherent delivered reply through the real outbound seam.
    assert_eq!(
        sut.delivered_replies(),
        vec![REPLY_A.as_bytes().to_vec(), REPLY_B.as_bytes().to_vec()],
        "both turns (incl. the post-switch turn) deliver their coherent reply in order"
    );
}

/// Discriminator (anti-fake-green): with the axis OFF — same seeds, but no
/// `.with_recall_corpus()` — the production no-recall builder feeds the assembler an
/// EMPTY `AgentSearchCorpus` + `StubEmbedding`, so `format_recall_section` returns `None`
/// and the assembled prompt has NO `# Recalled Context` (and never mentions the seeded
/// file). This proves the recall section is CAUSED by the populated local corpus, not
/// fabricated by the witness.
#[tokio::test(flavor = "multi_thread")]
async fn sys_ac_005_axis_off_yields_no_recall_section() {
    let sut = SystemUnderTest::builder()
        .caps(&[Cap::Memory, Cap::Llm])
        .llm(LlmMode::LoopbackScripted(vec![ScriptedResponse::ok_chat(
            REPLY_A, 7, 9,
        )]))
        .with_seeded_knowledge(vec![fact(
            MEM_ID,
            "the deploy script runs cargo build then rsync",
        )])
        .with_seeded_workspace_file(
            FILE_VPATH,
            b"local notes about the rsync mirror deploy plan",
        )
        // NO .with_recall_corpus() → empty corpus + StubEmbedding (DORMANT production path).
        .build(HELLO_LLM_CORE)
        .await;

    sut.inject_message("tester", PROMPT_1).await;
    sut.run_turn().await;

    let bodies = sut.llm_all_chat_request_bodies();
    assert_eq!(bodies.len(), 1, "one turn dials generate once");
    assert!(
        !bodies[0].contains("# Recalled Context"),
        "axis OFF → empty corpus → NO recall section; body={}",
        bodies[0]
    );
    // The workspace file reaches the prompt ONLY via the recall `## Files` section; with the
    // axis off it must be absent (the recall corpus is the only reader of arbitrary files).
    assert!(
        !bodies[0].contains(FILE_VPATH),
        "the seeded workspace file must NOT reach the prompt without the recall axis; body={}",
        bodies[0]
    );
}
