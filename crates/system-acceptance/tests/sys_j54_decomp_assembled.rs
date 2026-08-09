//! SYS-J-54 — SYS-AC-172 e2e witness: on the next turn the assembled context's
//! `# Active Task Decomposition` section lists the active task's non-orphaned subtasks'
//! id/title/status, on the REAL wired SUT.
//!
//! Wired via the default-off `.with_decomposition()` axis: the cap-lifecycle decomposition
//! host-fns (`register_agent_decomposition`) AND the context-assembler's
//! `CapDecompositionReader` share ONE `DefaultDecompositionStore` (the bare-`harness`
//! tree root). The full real path on a turn:
//!   submit-decomposition (a real registered WIT host-fn) writes the LIVE store →
//!   inject_message_with_task + run_turn → run_agent → run_turn_once → the REAL
//!   `ContextAssemblerImpl` reads the SAME store via `CapDecompositionReader` (bare-first
//!   alias resolution: the store is keyed under bare `harness`, the assemble turn runs
//!   under colon `agent:harness`) → renders Tier-2 ⑭ → `PublishingContextAssembler`
//!   publishes it → the guest's `generate` seam PREPENDS it → real cap-llm gateway →
//!   loopback records the request body. Loopback-only (the external LLM is doubled);
//!   every module in the assembly chain is REAL (the witness-floor substrate).
//!
//! - **172 keystone**: a real submit-decomposition (driven directly via the registered WIT
//!   host-fn — `lifecycle` ∉ KNOWN_CAPABILITIES, so no guest links it; the
//!   drive-prod-fn-no-caller precedent) writes the store, and its two subtasks appear in the
//!   NEXT real turn's body, each as the rendered `- {st-id} — {title} [{status}]` line (id +
//!   title + status). Reads the LIVE store the assembler reads, not a harness seed.
//! - **172 discriminator (anti-fake-green)**: an orphaned (InProgress-then-dropped) subtask
//!   is EXCLUDED while the live one is INCLUDED — single-variable proof that the section
//!   reflects the LIVE mutated store + the non-orphaned filter, not a static seed (the
//!   orphaned subtask is left InProgress, not Completed, so only `orphaned` — not status —
//!   can be the reason it is dropped).
//!
//! SYS-AC-171 is FLIPPED (Wave-17 Lane 4, 2026-06-25 — the existing-id lift + status read-back are now
//! on the WIT surface); its witnesses live in `sys_j54_decomposition.rs` + `sys_j54_decomp_update.rs`.

use cap_lifecycle::{
    DecompositionPlan, DecompositionStore, DecompositionStrategy, SubtaskSpec, SubtaskStatus,
};
use system_acceptance::llm_loopback::ScriptedResponse;
use system_acceptance::{Cap, LlmMode, SystemUnderTest};
use wasmtime::component::Val;

/// The committed reference guest: its `handle-message` reads `msg.payload` as the prompt
/// and dials `agent-llm/generate` — so the published Tier-2 decomposition section (prepended
/// by the generate seam) surfaces in the loopback request body.
const HELLO_LLM_CORE: &[u8] =
    include_bytes!("../../runtime/tests/fixtures/guest-rust-hello-llm.core.wasm");

const NS: &str = "advance:runtime/agent-lifecycle@0.2.0";
/// The bare tree-root id the decomposition store is keyed under (cap-lifecycle
/// `validate_agent_id` rejects colons; the assembler runs under the colon `agent:harness`,
/// bridged by the reader's `[bare, colon]` alias set).
const BARE: &str = "harness";
const TASK: &str = "task-decomp-e2e";

/// Build the `submit-decomposition` WIT params: descriptors are
/// `"title|assignee|prompt|dep1,dep2,..."` wire-shape strings (deps optional).
fn submit_params(task: &str, goal: &str, strategy: &str, subtasks: &[&str]) -> Vec<Val> {
    vec![
        Val::String(task.into()),
        Val::String(goal.into()),
        Val::String(strategy.into()),
        Val::List(subtasks.iter().map(|s| Val::String((*s).into())).collect()),
    ]
}

/// `Val::Result(Ok(Some(List(String...))))` → the receipt strings (`title=st-{uuid}`).
fn ok_string_list(v: &Val) -> Vec<String> {
    let Val::Result(Ok(Some(b))) = v else {
        panic!("expected Val::Result(Ok(Some(list))), got {v:?}")
    };
    let Val::List(items) = b.as_ref() else {
        panic!("expected Val::List, got {b:?}")
    };
    items
        .iter()
        .map(|i| {
            let Val::String(s) = i else {
                panic!("expected Val::String, got {i:?}")
            };
            s.clone()
        })
        .collect()
}

/// Extract the `st-{uuid}` id for `title` from a `title=st-...` receipt list.
fn id_of(receipt: &[String], title: &str) -> String {
    receipt
        .iter()
        .find(|r| r.starts_with(&format!("{title}=")))
        .unwrap_or_else(|| panic!("receipt entry for {title:?}: {receipt:?}"))
        .split('=')
        .nth(1)
        .unwrap()
        .to_string()
}

/// A `Decompose`-strategy plan with `(title, assignee)` subtasks (no deps, fresh ids) —
/// for the discriminator's store-API setup.
fn plan(goal: &str, subtasks: &[(&str, &str)]) -> DecompositionPlan {
    DecompositionPlan {
        goal: goal.into(),
        strategy: DecompositionStrategy::Decompose,
        subtasks: subtasks
            .iter()
            .map(|(title, assignee)| SubtaskSpec {
                existing_id: None,
                title: (*title).into(),
                assignee: (*assignee).into(),
                template_ref: None,
                prompt: String::new(),
                depends_on: Vec::new(),
            })
            .collect(),
    }
}

/// Boot a loopback SUT with the decomposition axis wired.
async fn boot() -> SystemUnderTest {
    SystemUnderTest::builder()
        .caps(&[Cap::Llm])
        .with_decomposition()
        .llm(LlmMode::LoopbackScripted(vec![ScriptedResponse::ok_chat(
            "decomp-witness-reply",
            7,
            9,
        )]))
        .build(HELLO_LLM_CORE)
        .await
}

/// SYS-AC-172 (keystone): a real `submit-decomposition` (driven directly via the registered
/// WIT host-fn — `lifecycle` ∉ KNOWN_CAPABILITIES, so no guest links it; the
/// drive-prod-fn-no-caller precedent) writes the live store, and the NEXT turn's assembled
/// `# Active Task Decomposition` section surfaces its non-orphaned subtasks (id/title/status),
/// read from the LIVE shared store the assembler reads.
#[tokio::test(flavor = "multi_thread")]
async fn sys_ac_172_assembled_context_lists_active_subtasks() {
    let sut = boot().await;

    // Drive the REAL registered submit-decomposition host-fn as the bare tree-root owner
    // (results_len=1 — the DecompositionHandler requires it). The live store is written.
    let res = sut
        .call_host_fn_as_agent_n(
            BARE,
            "lifecycle",
            NS,
            "submit-decomposition",
            submit_params(
                TASK,
                "ship the section",
                "decompose",
                &["design schema|_self|draft", "write tests|_self|cover"],
            ),
            1,
        )
        .await
        .expect("submit-decomposition dispatch ok");
    let receipt = ok_string_list(&res[0]);
    assert_eq!(receipt.len(), 2, "two subtasks minted: {receipt:?}");
    let design_id = id_of(&receipt, "design schema");
    let tests_id = id_of(&receipt, "write tests");
    assert!(
        design_id.starts_with("st-") && tests_id.starts_with("st-"),
        "stable st- ids"
    );

    // The NEXT turn: a real message carrying the active task_id drives a real assemble turn.
    sut.inject_message_with_task("tester", TASK, b"continue the work")
        .await;
    sut.run_turn().await;

    // The assembled prompt that reached the LLM carries the section + each non-orphaned
    // subtask's id/title/status. Bound escape-proof: the unique minted `st-` id (a
    // fabricated body could not carry it) + the title-immediately-followed-by-[status]
    // substring (binds title+status; the renderer emits `- {id} — {title} [{status}]`).
    let body = sut
        .llm_last_chat_request_body()
        .expect("the guest dialed generate (decomposition section published)");
    assert!(
        body.contains("# Active Task Decomposition"),
        "assembled prompt has the # Active Task Decomposition section; body = {body}"
    );
    for (id, title) in [(&design_id, "design schema"), (&tests_id, "write tests")] {
        assert!(
            body.contains(id),
            "subtask id {id} listed in the section; body = {body}"
        );
        assert!(
            body.contains(&format!("{title} [pending]")),
            "subtask '{title}' rendered with its status [pending]; body = {body}"
        );
    }
}

/// SYS-AC-172 (discriminator + anti-fake-green): an orphaned (InProgress-then-dropped)
/// subtask is EXCLUDED from the next turn's section while the live one is INCLUDED —
/// single-variable proof the section reflects the LIVE mutated store + the non-orphaned
/// filter (not a static seed). The orphaned subtask is left IN-PROGRESS (not Completed) so a
/// status-based filter bug could not also exclude it — `orphaned` is the sole controlled
/// variable. The setup drives the REAL `DefaultDecompositionStore` (the SAME instance the
/// assembler reads, via the harness accessor).
#[tokio::test(flavor = "multi_thread")]
async fn sys_ac_172_orphaned_subtask_excluded_from_section() {
    let sut = boot().await;
    let store = sut
        .decomposition_store()
        .expect("with_decomposition ⇒ decomposition_store is Some")
        .clone();

    // Submit [alpha, beta]; set alpha IN-PROGRESS (deliberately NOT Completed); re-submit
    // [beta] (omitting alpha) so the InProgress-then-dropped alpha is RETAINED orphaned (the
    // store's orphan rule: a dropped subtask is retained orphaned iff it was Completed OR
    // InProgress — decomposition.rs:333). Using InProgress (not Completed) makes this a
    // SINGLE-VARIABLE proof of the *orphaned* filter (adversarial-r11): a buggy reader
    // filtering on `status == Completed` instead of `!orphaned` would NOT exclude an
    // InProgress subtask, so this test would fail — isolating `orphaned` as the sole reason
    // alpha is dropped from the section.
    let r1 = store
        .submit(
            BARE,
            TASK,
            plan("g", &[("alpha-task", "_self"), ("beta-task", "_self")]),
        )
        .expect("submit 1");
    let alpha_id = r1
        .subtask_ids
        .iter()
        .find(|m| m.title == "alpha-task")
        .map(|m| m.subtask_id.clone())
        .expect("alpha id");
    store
        .update_subtask_status(BARE, TASK, &alpha_id, SubtaskStatus::InProgress, None)
        .expect("set alpha in-progress");
    store
        .submit(BARE, TASK, plan("g", &[("beta-task", "_self")]))
        .expect("submit 2 (drops alpha)");

    // Precondition: alpha is orphaned AND still IN-PROGRESS (the single-variable control —
    // its status is NOT Completed, so ONLY the orphaned-filter can exclude it); beta is live.
    let state = store
        .get(BARE, TASK)
        .expect("get ok")
        .expect("task present");
    let alpha = state
        .subtasks
        .iter()
        .find(|s| s.subtask_id == alpha_id)
        .expect("alpha retained in the store");
    assert!(
        alpha.orphaned,
        "alpha (InProgress-then-dropped) is retained orphaned: {:?}",
        state.subtasks
    );
    assert_eq!(
        alpha.status,
        SubtaskStatus::InProgress,
        "alpha is InProgress (NOT Completed) — the single-variable control vs the orphaned filter"
    );
    assert!(
        state.subtasks.iter().any(|s| !s.orphaned),
        "beta is a live non-orphaned subtask: {:?}",
        state.subtasks
    );

    // The NEXT turn's section lists ONLY the non-orphaned subtask.
    sut.inject_message_with_task("tester", TASK, b"continue")
        .await;
    sut.run_turn().await;
    let body = sut
        .llm_last_chat_request_body()
        .expect("the guest dialed generate (decomposition section published)");
    assert!(
        body.contains("# Active Task Decomposition"),
        "section present; body = {body}"
    );
    assert!(
        body.contains("beta-task [pending]"),
        "the live non-orphaned beta-task is listed; body = {body}"
    );
    assert!(
        !body.contains("alpha-task"),
        "the orphaned alpha-task title is EXCLUDED; body = {body}"
    );
    assert!(
        !body.contains(&alpha_id),
        "the orphaned alpha-task id {alpha_id} is EXCLUDED; body = {body}"
    );
}
