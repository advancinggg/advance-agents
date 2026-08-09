//! Backbone Step 4 — SYS-J-02 multi-turn stateless-context witness (SYS-AC-004).
//!
//! Drives TWO consecutive turns on ONE persistent run loop via the production
//! `AgentLoopDriverImpl::serve_n_turns` (bootstrap+init ONCE, then 2 turns carrying
//! `new_state`), through the FULL real chain: `serve_n_turns` → `run_turn_once` →
//! real `PublishingContextAssembler`/`ContextAssemblerImpl` → guest `handle-message`
//! → guest `agent-llm/generate` → real cap-llm OpenAI adapter → harness loopback.
//! The external LLM HTTP peer is the ONLY double (the sanctioned external-peer
//! stand-in); every module in the chain is real.
//!
//! SYS-AC-004: "Two consecutive turns to the same agent both produce coherent
//! answers with no provider session/conversation ID on either outbound LLM request
//! (REQ-221)." Witnessed by:
//!   (a) exactly TWO `/v1/chat/completions` bodies (the guest dialed `generate`
//!       once per turn across the persistent multi-turn loop);
//!   (b) NEITHER body carries any provider session/conversation key (recursively
//!       checked) — cap-llm's adapter is stateless by construction;
//!   (c) each body carries its OWN turn's distinct prompt (local per-call rebuild,
//!       not a server session): body 0 has the turn-1 prompt and not the turn-2
//!       prompt, and vice-versa;
//!   (d) BOTH turns delivered a coherent reply through the real action-dispatch
//!       outbound seam (`delivered_replies() == [reply-A, reply-B]`).
//!
//! (`serve_n_turns`'s bootstrap-init-ONCE property is unit-witnessed separately in
//! `crates/scheduler/tests/serve_n_turns_carries_state.rs`.)

use system_acceptance::llm_loopback::ScriptedResponse;
use system_acceptance::{Cap, LlmMode, SystemUnderTest};

/// The committed reference guest: `handle-message` reads `msg.payload` as the prompt
/// and calls `agent-llm/generate`, returning the reply text as its single action.
const HELLO_LLM_CORE: &[u8] =
    include_bytes!("../../runtime/tests/fixtures/guest-rust-hello-llm.core.wasm");

// Distinct, unique, non-overlapping prompt + reply markers (so the substring checks
// can never alias the prepended assembled-context block or each other).
const PROMPT_TURN_1: &[u8] = b"alpha-zero-niner-first-turn-prompt";
const PROMPT_TURN_2: &[u8] = b"bravo-seven-three-second-turn-prompt";
const REPLY_TURN_1: &str = "reply-alpha-coherent-answer-one";
const REPLY_TURN_2: &str = "reply-bravo-coherent-answer-two";

/// Provider session/conversation correlation keys that a STATELESS LLM request must
/// never carry (REQ-221). cap-llm's OpenAI/Anthropic adapters emit only
/// `model` + `messages` (+ optional sampling params).
const FORBIDDEN_SESSION_KEYS: &[&str] = &[
    "session",
    "session_id",
    "conversation_id",
    "previous_response_id",
    "thread_id",
];

/// Recursively assert no object key in `v` is a provider session/conversation key.
fn assert_no_session_keys(v: &serde_json::Value, where_: &str) {
    match v {
        serde_json::Value::Object(map) => {
            for (k, child) in map {
                assert!(
                    !FORBIDDEN_SESSION_KEYS.contains(&k.as_str()),
                    "{where_}: outbound LLM request carries a provider session/conversation \
                     key `{k}` — REQ-221 requires stateless requests with no provider session"
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
async fn sys_ac_004_two_turns_no_provider_session_both_coherent() {
    // Two scripted 200s → turn 1 gets reply-A, turn 2 gets reply-B (FIFO).
    let sut = SystemUnderTest::builder()
        .caps(&[Cap::Llm])
        .llm(LlmMode::LoopbackScripted(vec![
            ScriptedResponse::ok_chat(REPLY_TURN_1, 7, 9),
            ScriptedResponse::ok_chat(REPLY_TURN_2, 7, 9),
        ]))
        .with_reply_capture()
        .build(HELLO_LLM_CORE)
        .await;

    // Enqueue BOTH turns' messages before driving (each turn's recv awaits one).
    sut.inject_message("tester", PROMPT_TURN_1).await;
    sut.inject_message("tester", PROMPT_TURN_2).await;

    // Drive 2 consecutive turns on ONE persistent run loop (production serve_n_turns).
    sut.run_turns(2).await;

    let bodies = sut.llm_all_chat_request_bodies();

    // (a) exactly two outbound chat requests — one per turn.
    assert_eq!(
        bodies.len(),
        2,
        "two consecutive turns must each dial generate exactly once (got {} bodies)",
        bodies.len()
    );

    let prompt_1 = std::str::from_utf8(PROMPT_TURN_1).unwrap();
    let prompt_2 = std::str::from_utf8(PROMPT_TURN_2).unwrap();

    for (i, body) in bodies.iter().enumerate() {
        let json: serde_json::Value = serde_json::from_str(body)
            .unwrap_or_else(|e| panic!("body {i} is valid JSON: {e}; body={body}"));

        // It must be a well-formed chat request (has `messages`).
        assert!(
            json.get("messages").map(|m| m.is_array()).unwrap_or(false),
            "body {i} must be a chat request with a `messages` array; body={body}"
        );

        // (b) no provider session/conversation key anywhere in the request.
        assert_no_session_keys(&json, &format!("body {i}"));
    }

    // (c) each turn's body carries ITS OWN distinct prompt and not the other turn's
    //     — proves per-call local context reconstruction, not a server-side session.
    assert!(
        bodies[0].contains(prompt_1) && !bodies[0].contains(prompt_2),
        "turn-1 body must carry the turn-1 prompt only (local per-call rebuild)"
    );
    assert!(
        bodies[1].contains(prompt_2) && !bodies[1].contains(prompt_1),
        "turn-2 body must carry the turn-2 prompt only (local per-call rebuild)"
    );

    // (d) both turns produced a coherent delivered reply through the real outbound seam.
    let delivered = sut.delivered_replies();
    assert_eq!(
        delivered,
        vec![
            REPLY_TURN_1.as_bytes().to_vec(),
            REPLY_TURN_2.as_bytes().to_vec(),
        ],
        "both turns must deliver their coherent reply in order via the action-dispatch seam"
    );
}
