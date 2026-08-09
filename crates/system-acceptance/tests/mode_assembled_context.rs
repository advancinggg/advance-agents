//! Backbone Step 2 (2026-06-07) — system-acceptance witnesses for the real
//! `ContextAssemblerImpl` wired onto a real turn through `build_agent_loop`.
//!
//! These are the FIRST tests that drive `SystemUnderTest::run_turn()` WITH a
//! loopback LLM, so they exercise the full real path:
//!   inject_message → run_agent → run_turn_once → **PublishingContextAssembler.assemble**
//!   (the real `ContextAssemblerImpl` runs: emits `context.assembled` + publishes
//!   the assembled tiers into the gateway's per-agent store) → guest
//!   `handle-message` → guest `agent-llm/generate` → the generate handler PREPENDS
//!   the published context → real cap-llm gateway → harness loopback (records the
//!   request body).
//!
//! Witnesses:
//! - **SYS-AC-007** (REQ-224): a `context.assembled` event carries per-tier token
//!   counts (Tier 1a/1b/2/3) + a routing-confidence field.
//! - **SYS-AC-010** (REQ-034): the assembled prompt reaching the LLM contains a
//!   single `# Available Tools` section merging host fns + WASM + MCP tools with
//!   no source labels.
//!
//! Loopback-only (the external LLM provider is doubled); every module in the
//! assembly chain is REAL (the witness-floor substrate for these SYS-AC).

use system_acceptance::llm_loopback::ScriptedResponse;
use system_acceptance::{Cap, LlmMode, SystemUnderTest};

/// The committed reference guest (a real wit-bindgen guest importing agent-llm@0.1.0).
/// Its `handle-message` reads `msg.payload` as the prompt and calls `agent-llm/generate`.
const HELLO_LLM_CORE: &[u8] =
    include_bytes!("../../runtime/tests/fixtures/guest-rust-hello-llm.core.wasm");

const SCRIPTED_REPLY: &str = "assembled-context-witness-reply";

/// Boot a loopback SUT with the real assembler wired, drive one turn.
async fn run_one_turn() -> SystemUnderTest {
    let sut = SystemUnderTest::builder()
        .caps(&[Cap::Llm])
        .llm(LlmMode::LoopbackScripted(vec![ScriptedResponse::ok_chat(
            SCRIPTED_REPLY,
            7,
            9,
        )]))
        .build(HELLO_LLM_CORE)
        .await;
    sut.inject_message("tester", b"summarize the layered context wiring")
        .await;
    sut.run_turn().await;
    sut
}

#[tokio::test(flavor = "multi_thread")]
async fn sys_ac_007_context_assembled_event_carries_tier_counts_and_routing_confidence() {
    let sut = run_one_turn().await;

    let assembled: Vec<_> = sut
        .events()
        .into_iter()
        .filter(|e| e.event_type == "context.assembled")
        .collect();
    assert_eq!(
        assembled.len(),
        1,
        "exactly one context.assembled event expected on a single real turn (got {})",
        assembled.len()
    );

    let payload = &assembled[0].payload;
    // Per-tier token counts (Tier 1a/1b/2/3) — field-presence (values are
    // mode-dependent; SYS-AC-007 requires the counts be carried, not a magnitude).
    let counts = payload
        .get("tier_token_counts")
        .expect("context.assembled payload carries tier_token_counts");
    for tier in ["tier1a", "tier1b", "tier2", "tier3"] {
        assert!(
            counts.get(tier).is_some(),
            "tier_token_counts must carry {tier}; payload = {payload}"
        );
    }
    // Routing confidence — field-presence only (Slice-B placeholder 0.0).
    assert!(
        payload.get("routing_confidence").is_some(),
        "context.assembled payload carries routing_confidence; payload = {payload}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn sys_ac_010_assembled_prompt_has_single_merged_available_tools_section() {
    let sut = run_one_turn().await;

    // The body of the chat request the loopback received = the JSON the real
    // OpenAI adapter put on the wire, i.e. the assembled prompt (tiers prepended
    // by the generate seam) + the guest's prompt.
    let body = sut
        .llm_last_chat_request_body()
        .expect("a /v1/chat/completions request body was recorded (the guest dialed generate)");

    // Single `# Available Tools` section header.
    assert_eq!(
        body.matches("# Available Tools").count(),
        1,
        "exactly one '# Available Tools' section expected in the assembled prompt; body = {body}"
    );

    // The merge contains all three sources' names (host fn + WASM + MCP) the
    // harness populated, proving the homogeneous merge reached the LLM.
    for name in ["generate", "wasmtool", "mcptool"] {
        assert!(
            body.contains(name),
            "the merged '# Available Tools' section must list '{name}'; body = {body}"
        );
    }

    // No framework source-label prefixes leak into the tool lines (AC-18 / SYS-AC-010
    // "no source labels"). The assembler emits `- name(args) — desc`, never
    // `host:`/`tool:`/`mcp:` framework tags.
    assert!(
        !body.contains("host:") && !body.contains("tool:"),
        "tool lines must carry no framework source-label prefix; body = {body}"
    );
}
