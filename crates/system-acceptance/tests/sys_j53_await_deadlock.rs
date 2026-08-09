//! SYS-J-53 await-deadlock admission witnesses (SYS-AC-168 + SYS-AC-169).
//!
//! **SYS-AC-168** ("an await-replies whose sole target is an ANCESTOR of the caller is
//! rejected at admission, the whole call returning orchestration-error::deadlock-detected
//! with no message enqueued to the cyclic target") — witnessed against the REAL wired
//! chain, no module mocked:
//!
//!   - MODULE-005: the real cap-lifecycle `AgentTreeStore` (bare-id, the same store the
//!     `.agents()` spawner mutates) is the `AgentTreeSnapshot` provider, injected as
//!     `ManagerOptions.agent_tree` via the harness `.with_await_deadlock_gate()` axis.
//!   - MODULE-007: the real `AwaitSessionManagerImpl::start` admission gate runs the
//!     `forms_cycle` `parent_of` ancestry walk UP from the CALLER and rejects iff the
//!     TARGET is reached — the direction adjudicated by ADR
//!     `2026-06-10-await-deadlock-direction-adjudication` (clause stands verbatim; the
//!     former inverse-direction product defect was FIXED by dev-task-deadlock-flip).
//!   - MODULE-006: the real `MailboxDispatcherImpl` + `MailboxStore` — the "no message
//!     enqueued" observable reads the same store the dispatcher delivers into.
//!
//! The rejection is whole-call (`Err(OrchestrationError::DeadlockDetected)`): the gate
//! runs pre-lock, BEFORE session creation and BEFORE the dispatch loop, so nothing is
//! enqueued to the cyclic target (asserted against the real mailbox store). The
//! downward-direction control (parent awaits its CHILD — the SYS-J-05 delegation
//! pattern) admits and genuinely dispatches with the SAME gate active, proving the
//! witness exercises a live, direction-correct gate rather than a vacuous one.
//!
//! **SYS-AC-169** (per-slot `deadlock:{id}` triage + `orchestration.deadlock_rejected`
//! event) is witnessed below (Wave-15 Lane A, 2026-06-24) against the REAL wired chain
//! + the SUT `RealBus` (SQLite-persisted EventBus): a multi-slot await from caller `mid`
//! where slot 0's target (`agent:root`, an ANCESTOR — upward) is cyclic while slot 1
//! (`agent:leaf`, a DESCENDANT — downward) is valid → the real `AwaitSessionManagerImpl`
//! admission triage records the cyclic slot `ReplyStatus::Failed("deadlock:agent:root")`
//! (valid slot dispatched + resolved via `on_reply`) AND emits one
//! `orchestration.deadlock_rejected` row into the real `events.db` read back by
//! `assert_db_event` — the same store the sys_j47/mode_events witnesses query. The emit
//! is from the in-boundary manager admission path (`ManagerOptions.event_emitter`,
//! session-stable envelope, empty trace_id — MODULE-007 §1.5 AC-17 / §3.8); the no-cycle
//! discriminator proves the event is causally tied to the rejection.

use std::sync::Arc;
use std::time::Duration;

use advance_reply_tracker::{AwaitSessionManager, AwaitSessionManagerImpl};
use advance_shared_types::agent_tree::AgentKind;
use advance_shared_types::await_session::{
    AgentAwaitRequest, AwaitMode, AwaitOptions, AwaitRequest, OrchestrationError, ReplyResult,
    ReplyStatus, SessionId, TimeoutPolicy,
};
use system_acceptance::{AgentSpec, Cap, EventSink, SystemUnderTest};

const CORE_BYTES: &[u8] =
    include_bytes!("../../runtime/tests/fixtures/guest-rust-j01-skeleton.core.wasm");

/// `.agents([root → mid → leaf])` — a 3-level chain so the core witness rejects a
/// 2-HOP upward await (target is the caller's grand-ancestor), the general ancestor
/// case, not merely the direct parent.
fn three_level_chain() -> Vec<AgentSpec> {
    vec![
        AgentSpec {
            id: "agent:root".into(),
            kind: AgentKind::Root,
            parent: None,
            caps: vec![Cap::Fs],
            capabilities: vec![],
        },
        AgentSpec {
            id: "agent:mid".into(),
            kind: AgentKind::Child,
            parent: Some("agent:root".into()),
            caps: vec![],
            capabilities: vec![],
        },
        AgentSpec {
            id: "agent:leaf".into(),
            kind: AgentKind::Child,
            parent: Some("agent:mid".into()),
            caps: vec![],
            capabilities: vec![],
        },
    ]
}

async fn gated_sut() -> SystemUnderTest {
    SystemUnderTest::builder()
        .agents(&three_level_chain())
        .with_await_deadlock_gate()
        .build(CORE_BYTES)
        .await
}

fn agent_req(target: &str, corr: &str) -> AwaitRequest {
    AwaitRequest::AgentRequest(AgentAwaitRequest {
        target: target.into(),
        payload: b"payload".to_vec(),
        correlation_id: corr.into(),
        context: None,
    })
}

/// AllOf options that park indefinitely (1h idle timeout) so the test, not a
/// timeout, drives every resolution (the sys_j05 pattern).
fn allof_long_park() -> AwaitOptions {
    AwaitOptions {
        mode: AwaitMode::AllOf,
        idle_timeout_secs: Some(3600),
        on_idle_timeout: TimeoutPolicy::ReturnPartial,
        keep_losers: false,
    }
}

/// Deterministically wait until session `sid` is admitted (the sys_j05 probe:
/// a bogus out-of-range `on_reply` returns `NotFound` until admission and a
/// non-`NotFound` error afterwards, without resolving or idle-resetting the
/// parked session).
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
// SYS-AC-168 — sole-target ancestor await: whole-call deadlock-detected at
// admission, no message enqueued to the cyclic target.
// ---------------------------------------------------------------------------

/// Caller `leaf` awaits its 2-hop ancestor `agent:root` (sole target): the real
/// admission gate walks `parent_of` up from the caller (leaf → mid → root),
/// reaches the target, and rejects the WHOLE call with `DeadlockDetected` —
/// before any session is created and before any dispatch, so the cyclic
/// target's mailbox receives nothing. The direct-parent case (`mid` awaits
/// `agent:root`) is rejected identically.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sys_ac_168_ancestor_await_rejected_at_admission_nothing_enqueued() {
    let sut = gated_sut().await;
    let mgr = sut.await_manager().expect(".agents() configured");

    // 2-hop upward (grand-ancestor): caller is BARE "leaf" (the manager's caller
    // convention, mirroring sys_j05); the target is canonical `agent:root`.
    let res = mgr
        .start(
            "leaf",
            vec![agent_req("agent:root", "corr-up-2hop")],
            allof_long_park(),
        )
        .await;
    match res {
        Err(OrchestrationError::DeadlockDetected(_)) => {}
        other => panic!(
            "awaiting a 2-hop ancestor must be a whole-call DeadlockDetected at admission, \
             got {other:?}"
        ),
    }

    // 1-hop upward (direct parent): same whole-call rejection.
    let res = mgr
        .start(
            "mid",
            vec![agent_req("agent:root", "corr-up-1hop")],
            allof_long_park(),
        )
        .await;
    match res {
        Err(OrchestrationError::DeadlockDetected(_)) => {}
        other => panic!(
            "awaiting the direct parent must be a whole-call DeadlockDetected at admission, \
             got {other:?}"
        ),
    }

    // No message was enqueued to the cyclic target: the gate runs BEFORE the
    // dispatch loop, so the target's mailbox (lazily created on first deliver)
    // either does not exist or is empty. This is the same real `MailboxStore`
    // the dispatcher delivers into.
    let enqueued = sut
        .mailbox_store()
        .get("agent:root")
        .map(|mb| mb.depth())
        .unwrap_or(0);
    assert_eq!(
        enqueued, 0,
        "no message enqueued to the cyclic target agent:root"
    );
}

// ---------------------------------------------------------------------------
// Direction control — downward delegation admits THROUGH the active gate.
// ---------------------------------------------------------------------------

/// With the SAME deadlock gate active, the SYS-J-05 delegation direction (caller
/// `root` awaits its CHILD `agent:mid`) is ADMITTED — the session parks and the
/// child's mailbox genuinely receives the dispatched request. This control pins
/// the adjudicated direction e2e (upward rejects, downward admits) and proves
/// the rejection witness above exercises a live gate over real tree ancestry,
/// not a vacuously-empty snapshot (an empty `parent_of` would admit the upward
/// await and fail the rejection test; a direction-inverted gate would reject
/// this delegation and fail here).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sys_ac_168_control_downward_delegation_admits_and_dispatches() {
    let sut = gated_sut().await;
    let mgr = sut.await_manager().expect(".agents() configured");

    let m = mgr.clone();
    let start = tokio::spawn(async move {
        m.start(
            "root",
            vec![agent_req("agent:mid", "corr-down")],
            allof_long_park(),
        )
        .await
    });

    // Deterministically confirm admission (first factory id is hf-await-0).
    wait_admitted(&mgr, &SessionId("hf-await-0".into())).await;

    // The downward request is genuinely dispatched into the child's mailbox.
    // `wait_admitted` only confirms the session was INSERTED (admission); the
    // per-slot delivery into agent:mid's mailbox happens slightly later inside
    // `dispatch_slots`, so poll for it (bounded) rather than checking once —
    // a single immediate check raced the async delivery under heavy concurrent
    // `cargo test --workspace` CPU load (the delivery had not yet landed → depth 0).
    let mut delivered = 0;
    for i in 0..2_000u64 {
        delivered = sut
            .mailbox_store()
            .get("agent:mid")
            .map(|mb| mb.depth())
            .unwrap_or(0);
        if delivered >= 1 {
            break;
        }
        if i % 64 == 0 {
            tokio::time::sleep(Duration::from_millis(1)).await;
        } else {
            tokio::task::yield_now().await;
        }
    }
    assert!(
        delivered >= 1,
        "the downward (parent→child) await dispatched a request into agent:mid's mailbox; \
         depth = {delivered}"
    );

    // The parked task is torn down with the SUT (the sys_j05 precedent).
    drop(start);
}

// ---------------------------------------------------------------------------
// SYS-AC-169 — some-but-not-all-cycle: the cyclic slot returns
// reply-status::error("deadlock:...") while the valid slot proceeds, and an
// orchestration.deadlock_rejected event records the rejection (RealBus oracle).
// ---------------------------------------------------------------------------

/// `gated_sut` + a real SQLite-persisted EventBus so the manager's in-boundary
/// `orchestration.deadlock_rejected` emit lands in `events.db`.
async fn gated_realbus_sut() -> SystemUnderTest {
    SystemUnderTest::builder()
        .agents(&three_level_chain())
        .with_await_deadlock_gate()
        .events(EventSink::RealBus)
        .build(CORE_BYTES)
        .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sys_ac_169_some_but_not_all_cycle_per_slot_error_and_event() {
    let sut = gated_realbus_sut().await;
    let mgr = sut.await_manager().expect(".agents() configured");

    // Caller `mid`: slot 0 `agent:root` is mid's ANCESTOR (upward → cyclic);
    // slot 1 `agent:leaf` is mid's DESCENDANT (downward → valid, SYS-J-05
    // delegation). agent_slot_count=2, deadlock_slots={0} → some-but-not-all
    // (NOT the all-cycle whole-call rejection): the session is admitted, slot 0
    // recorded `Failed("deadlock:agent:root")`, slot 1 dispatched to agent:leaf.
    let m = mgr.clone();
    let start = tokio::spawn(async move {
        m.start(
            "mid",
            vec![
                agent_req("agent:root", "corr-cyclic"),
                agent_req("agent:leaf", "corr-valid"),
            ],
            allof_long_park(),
        )
        .await
    });

    // Deterministically confirm admission (first factory id is hf-await-0).
    let sid = SessionId("hf-await-0".into());
    wait_admitted(&mgr, &sid).await;

    // Resolve the valid sibling (slot 1) so the AllOf session completes and the
    // parked `start` returns Ok — proving the valid slot PROCEEDED while the
    // cyclic slot was rejected per-slot.
    mgr.on_reply(
        &sid,
        1,
        ReplyResult {
            slot: 1,
            source: "agent:leaf".to_string(),
            payload: b"leaf-done".to_vec(),
            status: ReplyStatus::Completed,
            received_at: chrono::Utc::now(),
            task_id: None,
        },
    )
    .await
    .expect("on_reply slot 1 (valid sibling) ok");

    let result = start
        .await
        .expect("start task joined")
        .expect("some-but-not-all cycle resolves Ok (whole call NOT deadlock-detected)");

    // (a) Per-slot: the cyclic slot is Failed("deadlock:agent:root"); the valid
    // sibling Completed.
    let by_slot: std::collections::HashMap<u32, &ReplyResult> =
        result.replies.iter().map(|r| (r.slot, r)).collect();
    let slot0 = by_slot.get(&0).expect("cyclic slot 0 present");
    match &slot0.status {
        ReplyStatus::Failed(reason) => assert_eq!(
            reason, "deadlock:agent:root",
            "cyclic slot returns the canonical per-slot deadlock reason"
        ),
        other => panic!("slot 0 must be Failed(deadlock:agent:root), got {other:?}"),
    }
    let slot1 = by_slot.get(&1).expect("valid slot 1 present");
    assert_eq!(
        slot1.status,
        ReplyStatus::Completed,
        "the valid sibling proceeded and completed"
    );

    // (b) The orchestration.deadlock_rejected event landed in the REAL EventBus
    // SQLite store (the same /query/events store assert_db_event reads),
    // carrying the requester + the cyclic target.
    let row = sut.assert_db_event("orchestration.deadlock_rejected", |r| {
        r.payload
            .as_deref()
            .is_some_and(|p| p.contains("agent:root") && p.contains("\"requester\":\"mid\""))
    });
    let payload = row
        .payload
        .expect("deadlock_rejected row carries a payload");
    assert!(
        payload.contains("\"targets\""),
        "deadlock_rejected payload names the rejected target(s): {payload}"
    );
    assert!(
        sut.db_event_count(Some("orchestration.deadlock_rejected")) >= 1,
        "at least one deadlock_rejected row persisted"
    );
}

/// Discriminator: a no-cycle await (caller `root` awaits its valid descendant
/// `agent:mid`) with the deadlock gate ACTIVE + RealBus emits NO
/// deadlock_rejected event — the event is causally tied to the cyclic
/// rejection, not unconditional.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sys_ac_169_no_cycle_emits_no_deadlock_rejected_event() {
    let sut = gated_realbus_sut().await;
    let mgr = sut.await_manager().expect(".agents() configured");

    let m = mgr.clone();
    let start = tokio::spawn(async move {
        m.start(
            "root",
            vec![agent_req("agent:mid", "corr-down")],
            allof_long_park(),
        )
        .await
    });
    wait_admitted(&mgr, &SessionId("hf-await-0".into())).await;

    assert_eq!(
        sut.db_event_count(Some("orchestration.deadlock_rejected")),
        0,
        "a no-cycle downward await emits no deadlock_rejected"
    );
    drop(start);
}
