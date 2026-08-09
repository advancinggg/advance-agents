//! SYS-J-38 — a repeated tool-triplet or identical LLM output trips the repetition
//! guard (warn-then-terminate), terminating the loop without affecting legitimately-
//! retried calls.
//! Chain: MODULE-008 run-manager → MODULE-009 cap-llm → MODULE-017 → MODULE-010.
//!
//! Witnessed test-local against the REAL `advance_run_manager::RepetitionGuard`
//! passed into the REAL `cap_llm::LlmGateway` (which calls `record_output` once per
//! terminal generate). Only the external LLM provider is the loopback mock.
//!
//! SYS-AC-122 (below) is WITNESSED (Wave-12 flip) — BOTH halves are now production-
//! wired: (front) Wave-11 Lane C hooked `record_tool_call` into the cap-tools
//! `tool-invoke` dispatch (record-before-invoke, cap-tools `host_fn.rs`); (back) Wave-12
//! late-binds the per-agent `ContextAssembler` + `PromptInjectionHelpers` into that
//! SAME production guard (`set_context_assembler` over the `OnceLock` sink) so a
//! repeated tool-triplet's Tier-3 warning surfaces on the next `assemble()`. The
//! `sys_ac_122` witness builds the SUT with `.with_tool_repetition_guard()` (mirrors
//! production cli Step 7) and drives the REAL registered `tool-invoke` handler with an
//! identical triplet 3× → asserts a REAL `run.repetition_detected{warn, tool_call}`
//! event AND a REAL next-turn `assemble()` Tier-3 inject (ONE shared `WarningQueue`).
//! The bare-keyed record/inject (`HostCallContext.agent_id`) and the colon-keyed
//! `assemble()` are reconciled by the Wave-12 agent-id alias bridge. Only the external
//! LLM provider is the loopback mock. (SYS-AC-011, a sibling delegates-section flip in
//! this wave, stays DEFERRED — see `sys_j04_delegates.rs`.)

#[path = "h_loopback/mod.rs"]
mod h_loopback;
use h_loopback::{boot, CapturingBus, GatewayDeps, ScriptedResponse};

use std::sync::Arc;

use advance_run_manager::{RepetitionAction, RepetitionGuard, RunManager};
use advance_shared_types::traits::{RepetitionGuardCheck, RunBudget};
use cap_llm::{ChatMessage, ChatParams, ChatRole, LlmError, LlmGatewayInternal};

const AGENT: &str = "agent:harness";

fn user_msg() -> Vec<ChatMessage> {
    vec![ChatMessage {
        role: ChatRole::User,
        content: "hi".into(),
    }]
}

/// A real `InMemoryRunBudget` that is NEVER consulted on these journeys (chat() uses
/// run_id=None, so the gateway skips the budget gate) — a real product impl, not a mock.
fn unused_real_budget() -> Arc<dyn RunBudget> {
    Arc::new(RunManager::new(Arc::new(CapturingBus::new())).budget())
}

/// SYS-AC-123: a second repetition after the warning terminates the loop with a
/// repetition-terminated error (not rate-limited/provider-error).
#[tokio::test(flavor = "multi_thread")]
async fn sys_ac_123_warn_then_terminate_on_repeated_output() {
    // WarnThenTerminate, repeat_threshold=2: identical output run-length 2 → Warn
    // (first cross), run-length 3 → Terminate (second cross).
    let guard: Arc<dyn RepetitionGuardCheck> = Arc::new(RepetitionGuard::new(
        8,
        2,
        RepetitionAction::WarnThenTerminate,
    ));
    let llm_bus = Arc::new(CapturingBus::new());
    // One scripted reply (NON-whitespace) replays for every call → identical output hash.
    let harness = boot(
        vec![ScriptedResponse::ok_chat("the identical answer", 5, 5)],
        GatewayDeps {
            run_budget: unused_real_budget(),
            repetition_guard: guard,
            event_bus: llm_bus,
            default_agent_id: AGENT.into(),
        },
    )
    .await;

    // Call 1 (run-length 1 < 2) → Pass → Ok.
    assert!(
        harness
            .gateway
            .chat(user_msg(), ChatParams::default())
            .await
            .is_ok(),
        "call 1 succeeds"
    );
    // Call 2 (run-length 2 ≥ 2) → Warn → still Ok.
    assert!(
        harness
            .gateway
            .chat(user_msg(), ChatParams::default())
            .await
            .is_ok(),
        "call 2 warns but succeeds"
    );
    // Call 3 (run-length 3, already warned) → Terminate → Err(RepetitionTerminated).
    match harness
        .gateway
        .chat(user_msg(), ChatParams::default())
        .await
    {
        Err(LlmError::RepetitionTerminated(_)) => {}
        other => panic!("expected RepetitionTerminated on the 3rd identical output, got {other:?}"),
    }
}

/// SYS-AC-124: a runtime-internal retried LLM call (same output across transport
/// retries) does NOT trip the guard — the run continues to a normal result. The
/// gateway records output ONCE at terminal success (not per transport-retry).
///
/// This is witnessed *discriminatingly* with `WarnThenTerminate`, repeat_threshold=2,
/// and a fixed identical reply: a 429→200 retried call (call 1), then two more
/// identical replies (calls 2, 3). With record-ONCE semantics the window advances by
/// exactly one per call → call 1 Pass(Ok), call 2 Warn(Ok), call 3 Terminate(Err).
/// If the retried call 1 had double-recorded (one per HTTP request, incl. the 429),
/// the window would already be at 2 after call 1, so call 2 would Terminate — which
/// the assertions below would catch. The Terminate on call 3 also rules out a vacuous
/// "guard disabled" pass.
#[tokio::test(flavor = "multi_thread")]
async fn sys_ac_124_internal_retry_does_not_trip_guard() {
    let guard: Arc<dyn RepetitionGuardCheck> = Arc::new(RepetitionGuard::new(
        8,
        2,
        RepetitionAction::WarnThenTerminate,
    ));
    let llm_bus = Arc::new(CapturingBus::new());
    // 429 then 200; the trailing 200 ("a normal answer") replays for calls 2 and 3.
    let harness = boot(
        vec![
            ScriptedResponse::err(429, r#"{"error":{"message":"slow down"}}"#),
            ScriptedResponse::ok_chat("a normal answer", 7, 7),
        ],
        GatewayDeps {
            run_budget: unused_real_budget(),
            repetition_guard: guard,
            event_bus: llm_bus,
            default_agent_id: AGENT.into(),
        },
    )
    .await;

    // Call 1 — internally retried (429→200). Returns a normal result, NOT terminated.
    let r1 = harness
        .gateway
        .chat(user_msg(), ChatParams::default())
        .await;
    assert!(
        r1.is_ok(),
        "the retried call returns a normal result: {r1:?}"
    );
    assert_eq!(
        harness.server.recorder().chat_request_count(),
        2,
        "one transport retry actually occurred (429 then 200)"
    );

    // Call 2 — same output. DISCRIMINATOR: with record-once, the window is at 1 after
    // call 1, so call 2 only reaches Warn (still Ok). If call 1 had double-recorded,
    // call 2 would already Terminate (Err) — this assertion would then fail.
    let r2 = harness
        .gateway
        .chat(user_msg(), ChatParams::default())
        .await;
    assert!(
        r2.is_ok(),
        "call 2 only warns (proves the retried call 1 recorded exactly once): {r2:?}"
    );

    // Call 3 — same output. The guard IS armed (rules out a vacuous pass): Terminate.
    match harness
        .gateway
        .chat(user_msg(), ChatParams::default())
        .await
    {
        Err(LlmError::RepetitionTerminated(_)) => {}
        other => panic!("expected Terminate on call 3 (guard is armed), got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// SYS-AC-122 (Wave-12 FLIP) — driven through the REAL wired SUT tool-invoke
// dispatch. The `.with_tool_repetition_guard()` axis mirrors production cli
// `wire_capabilities` Step 7 (`build_repetition_guard_from_config(default)` + PIH)
// + `start.rs` late-bind (`set_context_assembler` on the per-turn assembler), so the
// guard records under the BARE caller "harness" (HostCallContext.agent_id) and the
// COLON assemble turn drains via the [bare, colon] alias bridge — exactly as
// production. Full paths below avoid the h_loopback `ScriptedResponse` name clash.
// ---------------------------------------------------------------------------

const TOOLS_NS_122: &str = "advance:runtime/agent-tools@0.1.0";
const HELLO_LLM_CORE_122: &[u8] =
    include_bytes!("../../runtime/tests/fixtures/guest-rust-hello-llm.core.wasm");

/// The bare cap-id the cap-tools `record_tool_call` keys on (AGENT_ID minus `agent:`).
fn bare_122() -> String {
    system_acceptance::AGENT_ID
        .strip_prefix("agent:")
        .unwrap_or(system_acceptance::AGENT_ID)
        .to_string()
}

/// tool-invoke params `[tool_id, method, params-bytes]`. Identical (tool_id, method,
/// bytes) → identical FNV signature → counted as a repeat.
fn invoke_params_122(tool_id: &str, method: &str) -> Vec<wasmtime::component::Val> {
    use wasmtime::component::Val;
    vec![
        Val::String(tool_id.into()),
        Val::String(method.into()),
        Val::List(vec![Val::U8(1), Val::U8(2), Val::U8(3)]),
    ]
}

/// A SUT with the REAL tool-path repetition guard wired (window 10 / threshold 3 /
/// warn-then-terminate + PIH, late-bound to the per-turn assembler).
async fn guarded_sut_122() -> system_acceptance::SystemUnderTest {
    use system_acceptance::llm_loopback::ScriptedResponse;
    use system_acceptance::{Cap, LlmMode, SystemUnderTest};
    SystemUnderTest::builder()
        .caps(&[Cap::Tools, Cap::Llm])
        .llm(LlmMode::LoopbackScripted(vec![ScriptedResponse::ok_chat(
            "rep-witness-reply",
            5,
            5,
        )]))
        .with_tool_repetition_guard()
        .build(HELLO_LLM_CORE_122)
        .await
}

/// The `run.repetition_detected` events on the SUT bus.
fn rep_events(sut: &system_acceptance::SystemUnderTest) -> Vec<advance_shared_types::event::Event> {
    sut.events()
        .into_iter()
        .filter(|e| e.event_type == "run.repetition_detected")
        .collect()
}

/// Does the next assemble() (COLON AGENT_ID) carry the "Repetition detected" warning?
/// The guard injected under BARE "harness"; the colon assemble drains via the
/// [bare, colon] alias bridge (the SAME inner assembler late-bound into the guard).
async fn next_turn_has_repetition_warning(sut: &system_acceptance::SystemUnderTest) -> bool {
    let inner = sut
        .context_assembler_inner()
        .expect("context_assembler_inner is Some with a loopback LLM");
    let result = inner
        .assemble(stub_assembly_ctx(system_acceptance::AGENT_ID))
        .await
        .expect("assemble");
    result
        .messages
        .iter()
        .any(|m| m.content.contains("Repetition detected"))
}

/// SYS-AC-122: a repeated identical tool-triplet (×3) through the REAL wired
/// tool-invoke dispatch emits `run.repetition_detected` (warn) AND injects a Tier-3
/// warning the next handle-message turn drains.
#[tokio::test(flavor = "multi_thread")]
async fn sys_ac_122_tool_triplet_emits_and_injects_tier3_warning() {
    let sut = guarded_sut_122().await;
    let bare = bare_122();

    // Drive the SAME identical tool-invoke triplet 3× through the REAL registered
    // handler as the BARE caller (record-before-invoke; the tool need not be loaded —
    // the guard records the signature BEFORE dispatch). The 3rd identical call
    // (default repeat_threshold=3, warn-then-terminate) → Warn + event + inject.
    for _ in 0..3 {
        let _ = sut
            .call_host_fn_as_agent_n(
                &bare,
                "tools",
                TOOLS_NS_122,
                "tool-invoke",
                invoke_params_122("fs::read", "read"),
                1,
            )
            .await;
    }

    // (a) exactly one run.repetition_detected, action_taken == "warn", tool-call detection.
    let evs = rep_events(&sut);
    assert_eq!(
        evs.len(),
        1,
        "exactly one run.repetition_detected; event_types = {:?}",
        sut.events()
            .iter()
            .map(|e| e.event_type.clone())
            .collect::<Vec<_>>()
    );
    assert_eq!(
        evs[0].payload["action_taken"], "warn",
        "the 3rd identical triplet warns (warn-then-terminate, 1st stage)"
    );
    assert_eq!(
        evs[0].payload["detection_type"], "tool_call",
        "the detection is a tool-call triplet"
    );

    // (b) the next assemble() Tier-3 segment carries the injected warning.
    assert!(
        next_turn_has_repetition_warning(&sut).await,
        "the injected Tier-3 'Repetition detected' warning surfaces in the next assemble()"
    );
}

/// Discriminator: 2 identical + 1 DIFFERENT tool-invoke → no triplet reaches the
/// threshold → NO run.repetition_detected and NO Tier-3 inject.
#[tokio::test(flavor = "multi_thread")]
async fn sys_ac_122_discriminator_two_identical_plus_one_different() {
    let sut = guarded_sut_122().await;
    let bare = bare_122();

    // 2 identical + 1 with a DIFFERENT method → distinct signature, count < 3.
    for (tool, method) in [
        ("fs::read", "read"),
        ("fs::read", "read"),
        ("fs::read", "write"),
    ] {
        let _ = sut
            .call_host_fn_as_agent_n(
                &bare,
                "tools",
                TOOLS_NS_122,
                "tool-invoke",
                invoke_params_122(tool, method),
                1,
            )
            .await;
    }

    assert!(
        rep_events(&sut).is_empty(),
        "no run.repetition_detected for 2-identical-plus-1-different; event_types = {:?}",
        sut.events()
            .iter()
            .map(|e| e.event_type.clone())
            .collect::<Vec<_>>()
    );
    assert!(
        !next_turn_has_repetition_warning(&sut).await,
        "no Tier-3 inject when the triplet never repeats 3× (discriminator)"
    );
}

/// Minimal `AssemblyContext` (task_id = Some → skips the router) for the given
/// agent, mirroring `cap-tools/tests/callable_inventory.rs::stub_ctx`.
#[cfg(test)]
fn stub_assembly_ctx(agent_id: &str) -> advance_shared_types::context::AssemblyContext {
    use advance_shared_types::agent_tree::{AgentState, AgentStatus};
    use advance_shared_types::context::AssemblyContext;
    use advance_shared_types::mailbox::{Message, MessageKind};
    AssemblyContext {
        agent_id: agent_id.to_string(),
        task_id: Some("task-rep".into()),
        message: Message {
            id: "msg-stub".into(),
            kind: MessageKind::User,
            from: agent_id.to_string(),
            to: agent_id.to_string(),
            payload: Vec::new(),
            context: None,
            timestamp: std::time::SystemTime::UNIX_EPOCH,
            origin: None,
        },
        prompt: String::new(),
        model: "test-model".into(),
        turn_buffer: Vec::new(),
        prior_state: AgentState {
            agent_id: agent_id.to_string(),
            status: AgentStatus::Active,
            current_task_id: None,
            current_run_id: None,
            iteration: 0,
            turn_counter: 0,
            last_handle_message_at: None,
        },
    }
}
