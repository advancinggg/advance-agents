//! SYS-J-54 — **SYS-AC-171 flip witness** on the REAL wired SUT (Wave-17 Lane 4, 2026-06-25).
//!
//! SYS-AC-171's criterion: "update-subtask-status mutates a subtask's status/outcome (emitting
//! task.subtask_updated) and get-decomposition reads back the change; re-submitting with an
//! existing-id preserves the id while submitting without one mints a fresh id." All four legs are now
//! witnessed THROUGH THE WIRED WIT HOST-FN — the two formerly-below-bar legs closed in this slice by
//! widening the `cap-lifecycle` lowering/lift (`wit_impl.rs`):
//!   1. **get-decomposition projects the full `decomposition-state` record.** The lowering returns
//!      `option<decomposition-state>` (goal + strategy + `subtasks` WITH status/outcome) per the
//!      already-declared `agent-lifecycle.wit` contract — was goal-only `Val::String`. So the mutation
//!      `update-subtask-status` makes is observable on the WIT read-back, not just via the yaml/event.
//!   2. **existing-id continuity is reachable through the WIT.** `lift_decomposition_plan` carries an
//!      optional existing-id through the descriptor wire's 5th `|`-field — was hardcoded
//!      `existing_id: None`. So a WIT re-submit carrying a `st-<uuid>` preserves it (the store always
//!      supported this; only the lift withheld it).
//!
//! This drives the production composition root — `SystemUnderTest` with `.with_decomposition()` (the EXACT
//! `register_agent_decomposition` over the shared `DefaultDecompositionStore` cli `wire_capabilities`
//! composes) + the synchronous SQLite RealBus. The WIT read-back is the primary witness; the committed
//! `decomposition.yaml` blob + the `task.subtask_updated{old→new}` RealBus row corroborate it (bound to
//! the specific subtask id). Same harness floor as the passed SYS-J-54 siblings 170/172/242/243.
//!
//! (Sibling: the lighter always-run `sys_j54_decomposition.rs::sys_ac_171_*` — `LifecycleFixture` +
//! in-memory `CapturingBus` — is the baseline regression test for the same behavior; THIS file is the
//! heavier full-SUT + RealBus variant.)

use system_acceptance::llm_loopback::ScriptedResponse;
use system_acceptance::{Cap, EventSink, LlmMode, SystemUnderTest};
use wasmtime::component::Val;

/// The committed reference guest (loopback only — the decomposition axis requires a loopback LLM
/// at build; this witness drives host-fns directly and never runs a turn).
const HELLO_LLM_CORE: &[u8] =
    include_bytes!("../../runtime/tests/fixtures/guest-rust-hello-llm.core.wasm");

const NS: &str = "advance:runtime/agent-lifecycle@0.2.0";
/// The bare tree-root id `.with_decomposition()` keys the store under (cap-lifecycle
/// `validate_agent_id` rejects colons; the SUT agent id is the colon `agent:harness`, stripped to
/// this bare form for the store root — lib.rs:1834-1839).
const BARE: &str = "harness";
const TASK: &str = "task-171-flip";

/// `submit-decomposition` WIT params: descriptors are `"title|assignee|prompt|dep,..|existing-id"` strings
/// (4th field deps optional; 5th field existing-id optional).
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

/// Navigate a `get-decomposition` WIT return — `result<option<decomposition-state>, _>` — and return
/// `(status_tag, outcome)` for the subtask whose `subtask-id` == `subtask_id`. This is the PRIMARY
/// SYS-AC-171 read-back: the WIT now projects `subtasks` WITH status/outcome. Bound structurally to the
/// specific id (a record for another subtask cannot satisfy it).
fn wit_subtask_status_outcome(v: &Val, subtask_id: &str) -> (String, Option<String>) {
    let Val::Result(Ok(Some(opt))) = v else {
        panic!("expected Ok(Some(option)), got {v:?}")
    };
    let Val::Option(Some(state)) = opt.as_ref() else {
        panic!("expected Some(decomposition-state), got {opt:?}")
    };
    let Val::Record(fields) = state.as_ref() else {
        panic!("expected decomposition-state record, got {state:?}")
    };
    let Some((_, Val::List(subs))) = fields.iter().find(|(k, _)| k == "subtasks") else {
        panic!("subtasks list missing from {fields:?}")
    };
    let sub = subs
        .iter()
        .find_map(|s| {
            let Val::Record(sf) = s else { return None };
            let sid = sf
                .iter()
                .find(|(k, _)| k == "subtask-id")
                .and_then(|(_, v)| match v {
                    Val::String(x) => Some(x.as_str()),
                    _ => None,
                })?;
            (sid == subtask_id).then_some(sf)
        })
        .unwrap_or_else(|| panic!("subtask {subtask_id} present in get-decomposition record"));
    let sfield = |name: &str| sub.iter().find(|(k, _)| k == name).map(|(_, v)| v);
    let status = match sfield("status") {
        Some(Val::Variant(tag, _)) => tag.clone(),
        other => panic!("status variant: {other:?}"),
    };
    let outcome = match sfield("outcome") {
        Some(Val::Option(Some(b))) => match b.as_ref() {
            Val::String(s) => Some(s.clone()),
            _ => None,
        },
        Some(Val::Option(None)) => None,
        other => panic!("outcome option: {other:?}"),
    };
    (status, outcome)
}

/// Parse the persisted `decomposition.yaml` and return `(status, outcome)` for the subtask whose id
/// is `subtask_id`. Binds the corroboration to the SPECIFIC subtask via a structured parse — a broad
/// `yaml.contains(..)` could otherwise be satisfied by an orphaned copy or a descriptor token.
fn yaml_subtask_status_outcome(yaml: &str, subtask_id: &str) -> (String, Option<String>) {
    let v: serde_yml::Value = serde_yml::from_str(yaml).expect("parse decomposition.yaml");
    let subtasks = v
        .get("subtasks")
        .and_then(|s| s.as_sequence())
        .expect("decomposition.yaml has a subtasks sequence");
    let st = subtasks
        .iter()
        .find(|s| s.get("subtask_id").and_then(|x| x.as_str()) == Some(subtask_id))
        .unwrap_or_else(|| panic!("subtask {subtask_id} present in yaml:\n{yaml}"));
    let status = st
        .get("status")
        .and_then(|x| x.as_str())
        .expect("subtask status")
        .to_string();
    let outcome = st
        .get("outcome")
        .and_then(|x| x.as_str())
        .map(str::to_string);
    (status, outcome)
}

/// Read the persisted `decomposition.yaml` for `TASK` from `BARE`'s tree workspace.
fn read_yaml(sut: &SystemUnderTest) -> String {
    let path = sut
        .workspace_root()
        .join(BARE)
        .join(".agent/tasks/active")
        .join(TASK)
        .join("decomposition.yaml");
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("decomposition.yaml persisted at {path:?}: {e}"))
}

/// Drive a `get-decomposition` WIT host-fn call as the bare tree-root owner.
async fn get_decomposition(sut: &SystemUnderTest) -> Val {
    let res = sut
        .call_host_fn_as_agent_n(
            BARE,
            "lifecycle",
            NS,
            "get-decomposition",
            vec![Val::String(TASK.into())],
            1,
        )
        .await
        .expect("get-decomposition dispatch ok");
    res.into_iter().next().expect("one result")
}

/// Boot a loopback SUT with the decomposition axis + the synchronous SQLite RealBus.
async fn boot() -> SystemUnderTest {
    SystemUnderTest::builder()
        .caps(&[Cap::Llm])
        .with_decomposition()
        .events(EventSink::RealBus)
        .llm(LlmMode::LoopbackScripted(vec![ScriptedResponse::ok_chat(
            "decomp-171",
            7,
            9,
        )]))
        .build(HELLO_LLM_CORE)
        .await
}

#[tokio::test(flavor = "multi_thread")]
async fn sys_ac_171_wit_readback_and_existing_id_continuity() {
    let sut = boot().await;

    // (1) submit-decomposition (real registered WIT host-fn) → fresh st-uuid receipt. results_len=1
    // (the DecompositionHandler requires it). Driven as the bare tree-root owner.
    let res = sut
        .call_host_fn_as_agent_n(
            BARE,
            "lifecycle",
            NS,
            "submit-decomposition",
            submit_params(
                TASK,
                "iterate",
                "decompose",
                &["alpha|_self|do a", "beta|_self|do b"],
            ),
            1,
        )
        .await
        .expect("submit-decomposition dispatch ok");
    let receipt = ok_string_list(&res[0]);
    let alpha_id = id_of(&receipt, "alpha");
    assert!(
        alpha_id.starts_with("st-"),
        "stable st- id minted: {alpha_id}"
    );

    // (2) update-subtask-status (WIT) → alpha: pending → in-progress, outcome "started".
    let upd = sut
        .call_host_fn_as_agent_n(
            BARE,
            "lifecycle",
            NS,
            "update-subtask-status",
            vec![
                Val::String(TASK.into()),
                Val::String(alpha_id.clone()),
                Val::String("in-progress".into()),
                Val::String("started".into()),
            ],
            1,
        )
        .await
        .expect("update-subtask-status dispatch ok");
    assert!(
        matches!(&upd[0], Val::Result(Ok(None))),
        "update returns ok-unit: {:?}",
        upd[0]
    );

    // (3) PRIMARY read-back — the WIT get-decomposition now projects the full decomposition-state
    // record, so the mutated status/outcome is observable on the wired guest surface (NOT just yaml/event).
    let (wit_status, wit_outcome) =
        wit_subtask_status_outcome(&get_decomposition(&sut).await, &alpha_id);
    assert_eq!(
        wit_status, "in-progress",
        "WIT read-back: alpha's mutated status (bound to alpha_id)"
    );
    assert_eq!(
        wit_outcome.as_deref(),
        Some("started"),
        "WIT read-back: alpha's mutated outcome (bound to alpha_id)"
    );

    // Corroboration A — task.subtask_updated{old→new} on the RealBus (the same persisted `events` store
    // SYS-AC-150/172 use). `DbEventRow.payload` is raw JSON (Option<String>).
    let row = sut.assert_db_event("task.subtask_updated", |r| {
        r.agent_id.as_deref() == Some(BARE)
    });
    let payload: serde_json::Value = serde_json::from_str(
        row.payload
            .as_deref()
            .expect("task.subtask_updated carries a payload"),
    )
    .expect("the payload is JSON");
    assert_eq!(
        payload["subtask_id"],
        alpha_id.as_str(),
        "event names the mutated subtask"
    );
    assert_eq!(
        payload["old_status"], "pending",
        "old_status = the pre-update status"
    );
    assert_eq!(
        payload["new_status"], "in-progress",
        "new_status = the mutation"
    );

    // Corroboration B — the persisted decomposition.yaml blob (the committed channel).
    let (yaml_status, yaml_outcome) = yaml_subtask_status_outcome(&read_yaml(&sut), &alpha_id);
    assert_eq!(
        yaml_status, "in-progress",
        "persisted yaml: alpha's status (bound to alpha_id)"
    );
    assert_eq!(
        yaml_outcome.as_deref(),
        Some("started"),
        "persisted yaml: alpha's outcome"
    );

    // (4) existing-id PRESERVE through the WIT — re-submit WITH alpha's id via the descriptor's 5th
    // `|`-field while alpha STILL holds in-progress/"started". The lift now carries existing_id (was
    // hardcoded None); the store preserves the id + carries over status/outcome (decomposition.rs:295-300).
    let alpha_desc = format!("alpha|_self|do a||{alpha_id}");
    let res2 = sut
        .call_host_fn_as_agent_n(
            BARE,
            "lifecycle",
            NS,
            "submit-decomposition",
            submit_params(
                TASK,
                "iterate",
                "decompose",
                &[alpha_desc.as_str(), "beta|_self|do b"],
            ),
            1,
        )
        .await
        .expect("WIT re-submit with existing id ok");
    let receipt2 = ok_string_list(&res2[0]);
    assert_eq!(
        id_of(&receipt2, "alpha"),
        alpha_id,
        "existing-id PRESERVED across the WIT re-submission"
    );

    // Carry-over corroboration: get-decomposition (WIT) STILL shows alpha (the SAME id) in-progress +
    // started — the status/outcome rode the id carry-over, NOT reset to pending. Bound to alpha_id.
    let (carry_status, carry_outcome) =
        wit_subtask_status_outcome(&get_decomposition(&sut).await, &alpha_id);
    assert_eq!(
        carry_status, "in-progress",
        "existing-id re-submit CARRIES alpha's status (bound to alpha_id)"
    );
    assert_eq!(
        carry_outcome.as_deref(),
        Some("started"),
        "existing-id re-submit CARRIES alpha's outcome"
    );
    let (yaml_status2, _) = yaml_subtask_status_outcome(&read_yaml(&sut), &alpha_id);
    assert_eq!(
        yaml_status2, "in-progress",
        "persisted yaml: carry-over preserved (bound to alpha_id)"
    );

    // (5) Fresh-mint (WIT) — re-submit the titles with NO existing-id ⇒ a FRESH st-uuid for alpha (the
    // old in-progress alpha is retained orphaned and excluded from the non-orphaned receipt).
    let res3 = sut
        .call_host_fn_as_agent_n(
            BARE,
            "lifecycle",
            NS,
            "submit-decomposition",
            submit_params(
                TASK,
                "iterate",
                "decompose",
                &["alpha|_self|do a", "beta|_self|do b"],
            ),
            1,
        )
        .await
        .expect("re-submit ok");
    let alpha_id_3 = id_of(&ok_string_list(&res3[0]), "alpha");
    assert_ne!(
        alpha_id_3, alpha_id,
        "no existing-id ⇒ a FRESH st-uuid is minted"
    );
    assert!(
        alpha_id_3.starts_with("st-"),
        "the fresh id is st-prefixed: {alpha_id_3}"
    );
}
