//! Track C — SYS-J-05 await fan-out witness (SYS-AC-013, 193, 194).
//!
//! Witnesses three atomic criteria of the await/fan-out journey against the
//! **REAL production await provider** — the harness `await_manager()` is the
//! real `advance_reply_tracker::AwaitSessionManagerImpl` wired over the real
//! `advance_messaging::MailboxDispatcherImpl` + the real `HarnessAgentTree`
//! adjacency reader (see `system_acceptance::SystemUnderTest::build`). No module
//! in the await/admission/dispatch chain is mocked or stubbed.
//!
//! This is a **real-provider witness, NOT a guest turn**: the guest→host reply
//! leg (the WASM `reply()` host-fn that would feed `on_reply`) is upstream-
//! blocked (crate README "HF fast-follow blockers"; `cli/agent_loop.rs` "reply
//! leg, deferred"). Per the HF-sanctioned `mode_agents_smoke.rs` pattern we
//! drive the real `AwaitSessionManagerImpl::start` directly from the test and
//! inject the resolving reply via `sut.resolve_await(...)` (the test-side stand-
//! in the harness exposes for exactly this upstream gap). The deterministic
//! session-id factory yields `hf-await-0`, `hf-await-1`, ... per SUT.
//!
//! Deliberately NOT asserted here (this file asserts ONLY the await-manager's
//! admission + aggregation + per-slot dispatch triage observables):
//!   - **SYS-AC-015** (`run.suspended` / `run.resumed` await_complete) is now
//!     WITNESSED separately by `sys_j05_run_suspend_resume.rs` (Backbone Step 4b,
//!     2026-06-08) — a real `AwaitRepliesHandler` drives M008 suspend/resume on
//!     the real wired chain.
//!   - SYS-AC-014: the single-parent turn commit + `run.round_completed` still
//!     needs the guest-driven run loop (upstream-blocked; recorded in §3).
//!   - No `orchestration.*` event is asserted: the reply-tracker crate emits
//!     none (manager.rs:14-18 — emission is the deferred M006 host-fn layer's
//!     job). SYS-AC-193/194 are pure provider-return-value witnesses.

use std::sync::Arc;
use std::time::Duration;

use advance_reply_tracker::{AwaitSessionManager, AwaitSessionManagerImpl};
use advance_shared_types::agent_tree::AgentKind;
use advance_shared_types::await_session::{
    AgentAwaitRequest, AwaitMode, AwaitOptions, AwaitRequest, AwaitSessionStatus,
    ComponentAwaitRequest, OrchestrationError, ReplyResult, ReplyStatus, SessionId, TimeoutPolicy,
};
use system_acceptance::{AgentSpec, Cap, SystemUnderTest};

const CORE_BYTES: &[u8] =
    include_bytes!("../../runtime/tests/fixtures/guest-rust-j01-skeleton.core.wasm");

/// `.agents([root, c1, c2])` — a root with two children. The canonical
/// `agent:` routing ids are what the HarnessAgentTree adjacency reader keys on;
/// the await manager's `caller` arg is the BARE body (`"root"`), mirroring
/// `mode_agents_smoke.rs` (the dispatch layer prepends `agent:` to build
/// `Message.from`).
fn root_and_two_children() -> Vec<AgentSpec> {
    vec![
        AgentSpec {
            id: "agent:root".into(),
            kind: AgentKind::Root,
            parent: None,
            caps: vec![Cap::Fs],
            capabilities: vec![],
        },
        AgentSpec {
            id: "agent:c1".into(),
            kind: AgentKind::Child,
            parent: Some("agent:root".into()),
            caps: vec![],
            capabilities: vec![],
        },
        AgentSpec {
            id: "agent:c2".into(),
            kind: AgentKind::Child,
            parent: Some("agent:root".into()),
            caps: vec![],
            capabilities: vec![],
        },
    ]
}

/// A `ComponentFinished` await request (dispatcher-free → `start()` parks on the
/// oneshot rather than fast-failing; resolved via `on_reply` in-test).
fn component_req(component_id: &str, correlation_id: &str) -> AwaitRequest {
    AwaitRequest::ComponentFinished(ComponentAwaitRequest {
        component_id: component_id.into(),
        correlation_id: correlation_id.into(),
    })
}

/// AllOf options that park indefinitely (1h idle timeout — well under the
/// `MAX_IDLE_TIMEOUT_SECS_CAP` of 3600s) so the test, not a timeout, drives
/// every resolution.
fn allof_long_park() -> AwaitOptions {
    AwaitOptions {
        mode: AwaitMode::AllOf,
        idle_timeout_secs: Some(3600),
        on_idle_timeout: TimeoutPolicy::ReturnPartial,
        keep_losers: false,
    }
}

/// Deterministically wait until session `sid` is admitted (its `start` task has
/// inserted it). A bogus out-of-range `on_reply` probe returns `NotFound` until
/// admission and `InvalidRequest` afterwards — the slot/source validation
/// returns BEFORE any `last_activity`/liveness update, so the probe never
/// resolves or idle-resets the parked session. This is a real-provider witness
/// of admission, not a wall-clock guess. To stay robust against false-FAIL under
/// CI scheduler starvation (these are `multi_thread` tests on a busy machine),
/// the spin yields each iteration and periodically sleeps a real 1 ms so
/// wall-clock advances even if both runtime workers are momentarily starved; it
/// fails LOUD (panic) only if a session genuinely never admits within a generous
/// budget (~several seconds of real time).
async fn wait_admitted(mgr: &Arc<AwaitSessionManagerImpl>, sid: &SessionId) {
    for i in 0..2_000_000u64 {
        let probe = ReplyResult {
            slot: u32::MAX,
            source: "probe:not-a-real-source".to_string(),
            payload: Vec::new(),
            status: ReplyStatus::Completed,
            received_at: chrono::Utc::now(),
            task_id: None,
        };
        match mgr.on_reply(sid, u32::MAX, probe).await {
            Err(OrchestrationError::NotFound(_)) => {
                if i % 256 == 0 {
                    tokio::time::sleep(Duration::from_millis(1)).await;
                } else {
                    tokio::task::yield_now().await;
                }
            }
            _ => return,
        }
    }
    panic!("session {} was never admitted within the budget", sid.0);
}

// ---------------------------------------------------------------------------
// SYS-AC-013 — all-of completion aggregates every slot's reply.
// ---------------------------------------------------------------------------

/// `start("root", [ComponentFinished, ComponentFinished], AllOf)` parks; both
/// slots resolved via `resolve_await`; the real manager returns
/// `status == Completed` with both replies aggregated (`replies.len() == 2`).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sys_ac_013_allof_fanout_aggregates_both_replies() {
    let sut = SystemUnderTest::builder()
        .agents(&root_and_two_children())
        .build(CORE_BYTES)
        .await;
    let mgr = sut.await_manager().expect(".agents() configured");

    // Two dispatcher-free ComponentFinished slots → the session parks on its
    // oneshot (neither hits the all-failed fast path). Caller is BARE "root".
    let requests = vec![
        component_req("comp-a", "corr-a"),
        component_req("comp-b", "corr-b"),
    ];
    let start = tokio::spawn(async move { mgr.start("root", requests, allof_long_park()).await });

    // First session id from the harness's deterministic factory is `hf-await-0`.
    // on_reply enforces source == `component:<component_id>` + slot match exactly
    // and a status-only (empty) payload (manager.rs source/payload validation),
    // so the real provider's reply path is genuinely exercised — a forged source
    // or payload would be rejected, not silently accepted.
    let session = SessionId("hf-await-0".into());
    sut.resolve_await(
        &session,
        0,
        ReplyResult {
            slot: 0,
            source: "component:comp-a".into(),
            payload: Vec::new(),
            status: ReplyStatus::Completed,
            received_at: chrono::Utc::now(),
            task_id: None,
        },
    )
    .await
    .expect("slot 0 resolves");
    sut.resolve_await(
        &session,
        1,
        ReplyResult {
            slot: 1,
            source: "component:comp-b".into(),
            payload: Vec::new(),
            status: ReplyStatus::Completed,
            received_at: chrono::Utc::now(),
            task_id: None,
        },
    )
    .await
    .expect("slot 1 resolves → session completes");

    let result = start
        .await
        .expect("start task joined")
        .expect("await resolved Ok");
    assert_eq!(
        result.status,
        AwaitSessionStatus::Completed,
        "all-of with every slot Completed → Completed"
    );
    assert_eq!(result.mode, AwaitMode::AllOf);
    assert_eq!(
        result.replies.len(),
        2,
        "all-of aggregates one ReplyResult per resolved slot"
    );
    assert!(
        result
            .replies
            .iter()
            .all(|r| r.status == ReplyStatus::Completed),
        "both aggregated slots Completed"
    );
    assert!(
        result.replies.iter().all(|r| r.payload.is_empty()),
        "both ComponentFinished replies stay status-only"
    );
    let sources: Vec<&str> = result.replies.iter().map(|r| r.source.as_str()).collect();
    assert!(sources.contains(&"component:comp-a") && sources.contains(&"component:comp-b"));
}

// ---------------------------------------------------------------------------
// SYS-AC-193 — per-caller in-flight admission cap (MAX_INFLIGHT = 3).
// ---------------------------------------------------------------------------

/// One caller holds `MAX_INFLIGHT` (3) sessions parked concurrently; a 4th
/// `start("root", ...)` is rejected at admission with
/// `Err(SessionLimitExceeded)` (manager.rs per-caller increment gate, the
/// `MAX_INFLIGHT` const). The real provider rejects BEFORE enqueue — no 4th
/// session is admitted.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sys_ac_193_inflight_cap_rejects_fourth_session() {
    let sut = SystemUnderTest::builder()
        .agents(&root_and_two_children())
        .build(CORE_BYTES)
        .await;
    let mgr = sut.await_manager().expect(".agents() configured");

    // Park MAX_INFLIGHT (3) sessions from the SAME caller "root". Each is a
    // single dispatcher-free ComponentFinished slot → parks on its oneshot and
    // never resolves (we never call resolve_await on these), so all three stay
    // counted against the per-caller cap for the duration of the test.
    let mut parked = Vec::new();
    for i in 0..3u32 {
        let m = mgr.clone();
        let comp = format!("comp-{i}");
        let corr = format!("corr-{i}");
        parked.push(tokio::spawn(async move {
            m.start("root", vec![component_req(&comp, &corr)], allof_long_park())
                .await
        }));
    }

    // DETERMINISTICALLY confirm all three root sessions (hf-await-0/1/2) are
    // admitted before the cap probe — no wall-clock guess.
    for n in 0..3u32 {
        wait_admitted(&mgr, &SessionId(format!("hf-await-{n}"))).await;
    }

    // A DISTINCT caller "c1" must ADMIT despite root being at its in-flight cap
    // — the cap is per-caller, not global. c1's session is the next factory id
    // (hf-await-3, deterministic: no rejected start has consumed an id yet), so
    // we confirm c1 actually ADMITS (a real-provider witness it was not capped),
    // rather than the weaker "not yet finished" liveness guess.
    let mc1 = mgr.clone();
    let c1_start = tokio::spawn(async move {
        mc1.start(
            "c1",
            vec![component_req("comp-c1", "corr-c1")],
            allof_long_park(),
        )
        .await
    });
    wait_admitted(&mgr, &SessionId("hf-await-3".to_string())).await;

    // NOW the 4th concurrent session FROM ROOT must be rejected at admission
    // (root already holds its MAX_INFLIGHT=3; c1's separate session does not
    // count against root's per-caller cap).
    let fourth = mgr
        .start(
            "root",
            vec![component_req("comp-x", "corr-x")],
            allof_long_park(),
        )
        .await;
    match fourth {
        Err(OrchestrationError::SessionLimitExceeded(_)) => {}
        other => panic!("4th concurrent root session must be SessionLimitExceeded, got {other:?}"),
    }

    // Tasks are intentionally left parked; the SUT/tempdir drop tears them down.
    drop(parked);
    drop(c1_start);
}

/// SYS-AC-193, max-fanout limb (the criterion is an OR: max-fanout OR
/// max-inflight). A single `start` whose slot count exceeds the hard
/// `MAX_FANOUT` (32) is rejected at admission as a whole-call error — the
/// `requests.len() > MAX_FANOUT` gate runs BEFORE the dispatch loop, so no
/// child message is enqueued. Witnessed with the real `AwaitSessionManagerImpl`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sys_ac_193_fanout_cap_rejects_oversized_request() {
    let sut = SystemUnderTest::builder()
        .agents(&root_and_two_children())
        .build(CORE_BYTES)
        .await;
    let mgr = sut.await_manager().expect(".agents() configured");

    // 40 > MAX_FANOUT(32): a whole-call admission rejection before any dispatch.
    let requests: Vec<AwaitRequest> = (0..40u32)
        .map(|i| component_req(&format!("comp-{i}"), &format!("corr-{i}")))
        .collect();
    let res = mgr.start("root", requests, allof_long_park()).await;
    match res {
        Err(OrchestrationError::InvalidRequest(_)) => {}
        other => panic!(
            "an oversized fan-out (>MAX_FANOUT) must be rejected at admission, got {other:?}"
        ),
    }
}

// ---------------------------------------------------------------------------
// SYS-AC-194 — per-slot unreachable-target dispatch triage (real manager +
// real dispatcher), NOT a whole-call Err.
// ---------------------------------------------------------------------------

/// Mixed slots: one `AgentRequest` to an UNKNOWN target (`agent:nonexistent`)
/// plus one `ComponentFinished`. The real `MailboxDispatcherImpl` rejects the
/// unknown target per-slot (`validate_routing` → `InvalidTarget` → recorded
/// `ReplyStatus::Failed`), while the ComponentFinished slot parks. Resolving the
/// ComponentFinished slot completes the session: the valid slot is `Completed`,
/// the unreachable slot is `Failed` — per-slot triage, the call itself is `Ok`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sys_ac_194_mixed_unreachable_slot_fails_while_valid_completes() {
    let sut = SystemUnderTest::builder()
        .agents(&root_and_two_children())
        .build(CORE_BYTES)
        .await;
    let mgr = sut.await_manager().expect(".agents() configured");

    // Slot 0: AgentRequest to a non-existent target → real dispatcher's
    // validate_routing `agent_exists` fails → InvalidTarget → per-slot Failed.
    // Slot 1: ComponentFinished → dispatch-skipped (Ok) → parks.
    let requests = vec![
        AwaitRequest::AgentRequest(AgentAwaitRequest {
            target: "agent:nonexistent".into(),
            payload: b"x".to_vec(),
            correlation_id: "corr-bad".into(),
            context: None,
        }),
        component_req("comp-ok", "corr-ok"),
    ];
    let start = tokio::spawn(async move { mgr.start("root", requests, allof_long_park()).await });

    // The unreachable slot was recorded Failed during dispatch; resolving the
    // ComponentFinished slot (slot 1) closes the AllOf criterion.
    sut.resolve_await(
        &SessionId("hf-await-0".into()),
        1,
        ReplyResult {
            slot: 1,
            source: "component:comp-ok".into(),
            payload: Vec::new(),
            status: ReplyStatus::Completed,
            received_at: chrono::Utc::now(),
            task_id: None,
        },
    )
    .await
    .expect("ComponentFinished slot resolves → session completes");

    let result = start
        .await
        .expect("start task joined")
        .expect("mixed dispatch is a per-slot triage, NOT a whole-call Err");
    assert_eq!(
        result.status,
        AwaitSessionStatus::Completed,
        "every slot is now filled (one Failed, one Completed) → Completed"
    );
    assert_eq!(result.replies.len(), 2, "all-of keeps every slot");
    let component_reply = result
        .replies
        .iter()
        .find(|reply| reply.slot == 1)
        .expect("ComponentFinished slot retained");
    assert!(
        component_reply.payload.is_empty(),
        "ComponentFinished reply stays status-only"
    );

    let valid = result
        .replies
        .iter()
        .find(|r| r.source == "component:comp-ok")
        .expect("valid slot present");
    assert_eq!(valid.status, ReplyStatus::Completed, "valid slot completed");

    let unreachable = result
        .replies
        .iter()
        .find(|r| r.source == "agent:nonexistent")
        .expect("unreachable slot present");
    match &unreachable.status {
        ReplyStatus::Failed(reason) => assert!(
            reason.starts_with("invalid-target"),
            "unreachable target → per-slot Failed(invalid-target:...), got {reason:?}"
        ),
        other => panic!("unreachable slot must be Failed, got {other:?}"),
    }
}

/// All-fail variant: every slot is an `AgentRequest` to an unknown / non-
/// adjacent target. The real provider returns `Ok(AwaitResult)` with
/// `status == FailedDispatch` and EVERY slot recorded `Failed` (per-slot
/// dispatch triage — a whole-call `Err` would be wrong per PRD §9.2).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sys_ac_194_all_unreachable_returns_ok_failed_dispatch() {
    let sut = SystemUnderTest::builder()
        .agents(&root_and_two_children())
        .build(CORE_BYTES)
        .await;
    let mgr = sut.await_manager().expect(".agents() configured");

    // Both targets canonical `agent:<name>` but absent from the tree → each
    // fails validate_routing's `agent_exists` → per-slot InvalidTarget.
    let requests = vec![
        AwaitRequest::AgentRequest(AgentAwaitRequest {
            target: "agent:nope1".into(),
            payload: Vec::new(),
            correlation_id: "corr-n1".into(),
            context: None,
        }),
        AwaitRequest::AgentRequest(AgentAwaitRequest {
            target: "agent:nope2".into(),
            payload: Vec::new(),
            correlation_id: "corr-n2".into(),
            context: None,
        }),
    ];

    // No resolve_await needed — the all-failed fast path resolves the call
    // synchronously inside `start` (no oneshot park).
    let result = mgr
        .start("root", requests, allof_long_park())
        .await
        .expect("all-failed dispatch returns Ok (per-slot triage), not Err");

    assert_eq!(
        result.status,
        AwaitSessionStatus::FailedDispatch,
        "every slot failed dispatch → FailedDispatch (not Completed, not an Err)"
    );
    assert_eq!(result.replies.len(), 2, "both slots recorded");
    for r in &result.replies {
        match &r.status {
            ReplyStatus::Failed(reason) => assert!(
                reason.starts_with("invalid-target"),
                "each unreachable slot → Failed(invalid-target:...), got {reason:?}"
            ),
            other => panic!("every slot must be Failed, got {other:?}"),
        }
    }
    let sources: Vec<&str> = result.replies.iter().map(|r| r.source.as_str()).collect();
    assert!(sources.contains(&"agent:nope1") && sources.contains(&"agent:nope2"));
}
