//! Wave-17 Lane 3 — MODULE-005-AC-26 witness: hybrid execution engine.
//!
//! AC-26: "a single agent supports BOTH the deterministic path (returning a
//! SubmitComponent action that creates a cron/daemon/watcher/task) AND the
//! LLM-driven non-deterministic path (handle-message turns), the two coexisting
//! under one agent identity."
//!
//! ONE `SystemUnderTest`, ONE `agent_id` (`agent:hybrid`), drives BOTH paths and
//! asserts both succeed under the SAME identity, with the two legs ordered so
//! neither short-circuits the other (the deterministic component is read back AFTER
//! the LLM turn ran, and vice-versa):
//!
//!   - Deterministic path: `submit_api().submit_component("agent:hybrid", cron-cfg)`
//!     → admitted + persisted to the durable `ComponentRegistry` with
//!     `submitter == "agent:hybrid"` (the SubmitComponent path "creates a cron").
//!   - LLM-driven path: `inject_message` + `run_turn` over the real
//!     `guest-rust-hello-llm` guest → its `handle-message` calls `agent-llm/generate`
//!     → the scripted loopback reply is delivered through the real outbound action
//!     seam (`delivered_replies()`), and the guest dialed the loopback exactly once.
//!
//! **Honest scope** (disclosed, not hidden — see MODULE-005 §3.3 T41 / §3.7): the
//! deterministic leg uses the direct `submit_component` convention. The WIT `action`
//! record is opaque and no production guest-returned-action→`submit_component`
//! decoder exists; the "an agent returns a SubmitComponent action that creates a
//! component" capability is itself already covered by the passed-e2e SYS-AC-108 and
//! the Verified REQ-049. This witness proves AC-26's INCREMENTAL claim — the
//! coexistence-under-one-identity of the two execution paths — with the action-decode
//! substitution disclosed.

use advance_scheduler::types::TriggerConfig;
use advance_scheduler::{ComponentSubmitApi, ComponentSubmitConfig};
use advance_shared_types::capability::CapRequest;
use advance_shared_types::component::ComponentType;

use system_acceptance::llm_loopback::ScriptedResponse;
use system_acceptance::{Cap, LlmMode, SystemUnderTest, AGENT_ID};

/// The committed reference guest: `handle-message` reads `msg.payload` as the prompt
/// and calls `agent-llm/generate`, returning the reply text as its single action.
const HELLO_LLM_CORE: &[u8] =
    include_bytes!("../../runtime/tests/fixtures/guest-rust-hello-llm.core.wasm");

/// The single identity both execution paths run under — the harness's default agent
/// id, which is also the dispatch/routing target the LLM `run_turn` drives. Using it
/// (rather than an override) keeps the LLM turn's routing-target and the submit
/// leg's submitter the SAME identity.
const HYBRID_ID: &str = AGENT_ID;

const PROMPT: &[u8] = b"echo-this-prompt-back-as-an-llm-reply";
const SCRIPTED_REPLY: &str = "non-deterministic-llm-reply-under-one-identity";

fn cron_cfg(
    id: &str,
    capabilities: Vec<CapRequest>,
    trigger: Option<TriggerConfig>,
) -> ComponentSubmitConfig {
    ComponentSubmitConfig {
        sensitive_params: Vec::new(),
        id: id.into(),
        component_type: ComponentType::Cron,
        binary: Vec::new(),
        capabilities,
        output_dir: None,
        trigger,
        restart_policy: None,
        delay: None,
        initial_grants: None,
        preset: None,
        retry: None,
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn m005_ac26_one_identity_runs_both_deterministic_submit_and_llm_turn() {
    // ONE SUT, ONE identity, BOTH execution paths wired: `.with_triggers()` (the
    // deterministic submit seam) + `.llm()` (the non-deterministic LLM gateway) +
    // `.with_reply_capture()` (the outbound action seam) coexist on one builder.
    let sut = SystemUnderTest::builder()
        .caps(&[Cap::Llm])
        .llm(LlmMode::LoopbackScripted(vec![ScriptedResponse::ok_chat(
            SCRIPTED_REPLY,
            7,
            9,
        )]))
        .with_reply_capture()
        .with_triggers()
        .build(HELLO_LLM_CORE)
        .await;

    // ── Leg 1: the DETERMINISTIC path — the agent submits a component (a cron). ──
    let api = sut.submit_api();
    let submitted = api
        .submit_component(HYBRID_ID, cron_cfg("comp-ac26", vec![], None))
        .await
        .expect("the deterministic SubmitComponent path admits a cron component");
    assert_eq!(submitted.as_str(), "comp-ac26");

    // ── Leg 2: the NON-DETERMINISTIC path — an LLM `handle-message` turn under the ──
    // ── SAME identity. The guest calls agent-llm/generate; the scripted reply comes ──
    // ── back through the real outbound action seam. ──
    sut.inject_message("user", PROMPT).await;
    sut.run_turn().await;

    // The LLM turn produced a coherent reply through the action-dispatch seam.
    assert_eq!(
        sut.delivered_replies(),
        vec![SCRIPTED_REPLY.as_bytes().to_vec()],
        "the LLM-driven handle-message turn must deliver the scripted reply under {HYBRID_ID}"
    );
    // The LLM leg actually ran the full guest→gateway→loopback path (not vacuous).
    assert_eq!(
        sut.llm_all_chat_request_bodies().len(),
        1,
        "the guest's agent-llm/generate must dial the loopback exactly once"
    );

    // ── Coexistence under one identity: read the deterministic component back AFTER ──
    // ── the LLM turn ran. It is still durably registered with submitter == the same ──
    // ── identity — the two paths did not interfere, and both belong to {HYBRID_ID}. ──
    let persisted = api
        .list_components_persisted()
        .await
        .expect("durable registry read");
    let row = persisted
        .iter()
        .find(|r| r.id.as_str() == "comp-ac26")
        .expect("the submitted cron persists across the LLM turn (coexistence)");
    assert_eq!(
        row.submitter, HYBRID_ID,
        "the deterministic component is owned by the SAME identity that ran the LLM turn"
    );
}
