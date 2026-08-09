//! SYS-J-04 — the assembled context's "# Available Delegates" section (SYS-AC-011).
//!
//! Journey (docs/SYSTEM-ACCEPTANCE.md §1): MODULE-010 → MODULE-017 → MODULE-005.
//! SYS-AC-011: "The same prompt contains a separate Available Delegates section
//! listing sub-agent names with capability summaries."
//!
//! Wave-12 FLIP — a REAL e2e witness (no synthetic tree). The `.with_real_spawn_tree()`
//! axis wires a REAL bare-id `AgentTreeStore` + the production cap-lifecycle spawn
//! host-fns (`register_agent_spawn`) over it, and feeds that SAME store into the
//! per-turn `ContextAssemblerImpl` (production parity with cli start.rs). The witness
//! drives a REAL `spawn-sub` host-fn as the BARE caller ("harness", the agent:-stripped
//! cap id) → records a `Sub` node under "harness"; the COLON assemble turn
//! ("agent:harness") then lists it via the Wave-12 agent-id alias bridge (the assembler
//! matches `node.parent` against {ctx.agent_id} ∪ [bare, colon]). The tree is populated
//! by the REAL spawn path, NOT a harness-seeded tree.
//!
//! Capability summaries (Wave-15 Lane E FLIP): the WIT spawn cap-lift is now BUILT —
//! `dispatch_spawn` decodes the real `sub-agent-config` record's `capabilities:
//! list<cap-request>` field (`lift_cap_request_list`) and threads it into the recorded
//! `AgentNode.capabilities` (cap-lifecycle/src/wit_impl.rs). The witness drives a REAL
//! `sub-agent-config` `Val::Record` requesting `[fs, tools]` (valid cap-grant families the
//! seeded Root holds, so the production `CapGrantSubsetAdapter` gate admits the subset),
//! and asserts BOTH the committed Sub node caps (recording half, via
//! `real_spawn_tree_snapshot()`) AND the rendered `- <sub> — fs, tools` summary in the
//! assembled prompt (readback half), with the unrequested family `skills` ABSENT.

use system_acceptance::llm_loopback::ScriptedResponse;
use system_acceptance::{Cap, LlmMode, SystemUnderTest, AGENT_ID};
use wasmtime::component::Val;

const HELLO_LLM_CORE: &[u8] =
    include_bytes!("../../runtime/tests/fixtures/guest-rust-hello-llm.core.wasm");

const LIFECYCLE_NS: &str = "advance:runtime/agent-lifecycle@0.2.0";

/// The bare cap-id the spawn host-fns key on (AGENT_ID with the `agent:` prefix
/// stripped — cap-lifecycle rejects a colon).
fn bare_id() -> String {
    AGENT_ID
        .strip_prefix("agent:")
        .unwrap_or(AGENT_ID)
        .to_string()
}

/// A real WIT `cap-request` record `{ capability: string, params: option<list<cap-param>> }`.
fn cap_request(id: &str) -> Val {
    Val::Record(vec![
        ("capability".to_string(), Val::String(id.to_string())),
        ("params".to_string(), Val::Option(None)),
    ])
}

/// Drive the REAL `spawn-sub` host-fn as the BARE caller, passing a real WIT
/// `sub-agent-config` `Val::Record` whose `capabilities: list<cap-request>` requests
/// `caps` (each a valid cap-grant family the seeded Root holds → the subset gate admits
/// the subset). Returns the generated sub-agent id. `results_len = 1` (the SpawnHandler
/// guards this).
async fn spawn_sub(sut: &SystemUnderTest, caps: &[&str]) -> String {
    let config = Val::Record(vec![
        (
            "capabilities".to_string(),
            Val::List(caps.iter().map(|c| cap_request(c)).collect()),
        ),
        ("template-ref".to_string(), Val::Option(None)),
    ]);
    let out = sut
        .call_host_fn_as_agent_n(
            &bare_id(),
            "lifecycle",
            LIFECYCLE_NS,
            "spawn-sub",
            vec![config],
            1,
        )
        .await
        .expect("spawn-sub host-fn call");
    match &out[0] {
        Val::Result(Ok(Some(b))) => match b.as_ref() {
            Val::String(id) => id.clone(),
            other => panic!("spawn-sub returned non-string inner Val: {other:?}"),
        },
        other => panic!("spawn-sub did not return Ok(Some(String)): {other:?}"),
    }
}

/// The `# Available Delegates` message content from a REAL `assemble()` over the
/// COLON `AGENT_ID` (the per-turn id production assembles under) — the SAME inner
/// assembler the driver was wired with (reads the real spawn store).
async fn delegates_section(sut: &SystemUnderTest) -> String {
    let inner = sut
        .context_assembler_inner()
        .expect("context_assembler_inner is Some when a loopback LLM is configured");
    let result = inner
        .assemble(assembly_ctx(AGENT_ID))
        .await
        .expect("assemble ok");
    result
        .messages
        .into_iter()
        .map(|m| m.content)
        .find(|c| c.starts_with("# Available Delegates"))
        .expect("a # Available Delegates section is present in the assembled prompt")
}

fn assembly_ctx(agent_id: &str) -> advance_shared_types::context::AssemblyContext {
    use advance_shared_types::agent_tree::{AgentState, AgentStatus};
    use advance_shared_types::context::AssemblyContext;
    use advance_shared_types::mailbox::{Message, MessageKind};
    AssemblyContext {
        agent_id: agent_id.to_string(),
        // task_id = Some → the assembler skips TaskRouter→embedding.
        task_id: Some("task-deleg".into()),
        message: Message {
            id: "msg-deleg".into(),
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

/// SYS-AC-011 [FLIP, Wave-15 Lane E]: a REAL product-spawned Sub is listed in the
/// assembled prompt's `# Available Delegates` section WITH its capability summary. The
/// witness drives a real `sub-agent-config` record requesting `[fs, tools]`; the
/// production cap-lift (`dispatch_spawn` → `lift_cap_request_list`) records those caps on
/// the committed Sub node (asserted via `real_spawn_tree_snapshot()` — the recording
/// half), and the assembler renders `- <sub> — fs, tools` (the readback half), with the
/// unrequested family `skills` ABSENT (anti-fake-green negative control).
#[tokio::test(flavor = "multi_thread")]
async fn sys_ac_011_available_delegates_lists_real_spawned_sub() {
    let sut = SystemUnderTest::builder()
        .caps(&[Cap::Llm, Cap::Fs])
        .llm(LlmMode::LoopbackScripted(vec![ScriptedResponse::ok_chat(
            "delegates-witness-reply",
            5,
            5,
        )]))
        .with_real_spawn_tree()
        .build(HELLO_LLM_CORE)
        .await;

    // Drive the REAL spawn-sub host-fn (bare caller) requesting caps [fs, tools]
    // (a subset of the seeded Root → admitted by the real subset gate) → records a Sub
    // under "harness" carrying those caps.
    let sub_id = spawn_sub(&sut, &["fs", "tools"]).await;
    assert!(!sub_id.is_empty(), "spawn-sub returned a generated sub id");

    // (a) RECORDING half: the COMMITTED Sub node carries the requested caps (production
    // parity — the cap-lift threads them into AgentNode.capabilities).
    let snap = sut
        .real_spawn_tree_snapshot()
        .expect("real spawn tree present with .with_real_spawn_tree()");
    let sub_node = snap
        .nodes
        .iter()
        .find(|n| n.id.0 == sub_id)
        .expect("the spawned Sub node is in the committed tree");
    let cap_ids: Vec<&str> = sub_node
        .capabilities
        .iter()
        .map(|c| c.id.as_str())
        .collect();
    assert!(
        cap_ids.contains(&"fs") && cap_ids.contains(&"tools"),
        "the committed Sub node records the requested caps [fs, tools]; got {cap_ids:?}"
    );

    // (b) READBACK half: the REAL assembler lists the sub AND renders its capability
    // summary; the unrequested family `skills` is absent (anti-fake-green).
    let section = delegates_section(&sut).await;
    let bullet = section
        .lines()
        .find(|l| l.starts_with("- ") && l.contains(&sub_id))
        .map(|s| s.to_string())
        .unwrap_or_else(|| {
            panic!("the sub is rendered as a delegate bullet; section = {section:?}")
        });
    assert!(
        bullet.contains("fs") && bullet.contains("tools"),
        "the bullet renders the capability summary [fs, tools]; bullet = {bullet:?}"
    );
    assert!(
        !bullet.contains("skills"),
        "an unrequested family (skills) is absent from the summary; bullet = {bullet:?}"
    );

    // (c) End-to-end: that prompt reaches the LLM — the loopback records a body carrying
    // BOTH parallel sections, the real-spawned sub by name, AND its capability summary.
    sut.inject_message("tester", b"do some research").await;
    sut.run_turn().await;
    let body = sut
        .llm_last_chat_request_body()
        .expect("a /v1/chat/completions body was recorded (the guest dialed generate)");
    assert_eq!(
        body.matches("# Available Delegates").count(),
        1,
        "exactly one '# Available Delegates' section; body = {body}"
    );
    assert!(
        body.contains("# Available Tools"),
        "the Tools section is also present (parallel dual positioning); body = {body}"
    );
    assert!(
        body.contains(&sub_id),
        "the real-spawned delegate is listed in the serialized prompt; body = {body}"
    );
    assert!(
        body.contains("fs, tools"),
        "the delegate's capability summary reaches the serialized prompt; body = {body}"
    );
}

/// Discriminator (SYS-AC-011): with NO spawn the real store holds only the seeded
/// Root; the `# Available Delegates` section header is present but lists NO delegate
/// bullet (the section + its summaries are data-driven, not a constant).
#[tokio::test(flavor = "multi_thread")]
async fn sys_ac_011_discriminator_no_spawn_no_delegate_line() {
    let sut = SystemUnderTest::builder()
        .caps(&[Cap::Llm, Cap::Fs])
        .llm(LlmMode::LoopbackScripted(vec![ScriptedResponse::ok_chat(
            "no-delegates-reply",
            5,
            5,
        )]))
        .with_real_spawn_tree()
        .build(HELLO_LLM_CORE)
        .await;
    // No spawn driven.
    let section = delegates_section(&sut).await;
    assert!(
        section.starts_with("# Available Delegates"),
        "the section header is always present; section = {section:?}"
    );
    assert!(
        !section.lines().any(|l| l.starts_with("- ")),
        "no delegate bullet when nothing was spawned; section = {section:?}"
    );
}
