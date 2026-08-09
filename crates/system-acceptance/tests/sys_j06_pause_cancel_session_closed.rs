//! Backbone Step 4b (2026-06-08) — SYS-J-06 / SYS-AC-016 + SYS-AC-017 witness on
//! the REAL wired system (Track-H test-side wiring).
//!
//! SYS-AC-016: "Issuing pause-run/cancel-run while the parent is suspended at
//! await-replies returns orchestration-error::session-closed to the awaiting
//! guest call."
//! SYS-AC-017: "After pause, run-status reports Paused with a run.paused event;
//! after cancel, status is Cancelled with run.cancelled."
//!
//! Drives the REAL `AwaitRepliesHandler::call` (parked at an await) then issues a
//! real `RunManager::pause_run` / `cancel_run` (branch-(a) Suspended), which
//! closes the live M007 session via the production `AwaitSessionManagerRef` —
//! resolving the parked await with the WIT `orchestration-error::session-closed`
//! (016) and transitioning the run to Paused/Cancelled with `run.paused` /
//! `run.cancelled` (017). Asserts NO `run.resumed` fires (the resume-vs-pause
//! race fix: resume is gated on Ok, never on Err(SessionClosed)).

#[path = "step4b_support/mod.rs"]
mod support;

use std::sync::Arc;
use std::time::Duration;

use advance_runtime::host_registry::HostFunctionHandler;
use advance_shared_types::run::TaskRunStatus;
use wasmtime::component::Val;

use support::{single_slot_params, wait_until, Wired};

/// Assert the host-fn return Val is the WIT whole-call
/// `orchestration-error::session-closed`.
fn assert_session_closed(result: &[Val]) {
    match &result[0] {
        Val::Result(Err(Some(boxed))) => match boxed.as_ref() {
            Val::Variant(case, _) => assert_eq!(
                case, "session-closed",
                "awaiting guest call must receive orchestration-error::session-closed"
            ),
            other => panic!("expected Variant(session-closed,..), got {other:?}"),
        },
        other => panic!("expected Result(Err(..)), got {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn sys_ac_016_017_pause_suspended_returns_session_closed_and_paused() {
    let w = Wired::build("parent-p");
    let run_id = w.run_id.clone();

    // Drive the real await-replies host-fn; it parks.
    let handler = Arc::clone(&w.handler);
    let ctx = w.ctx();
    let params = single_slot_params("agent:child", "corr-1");
    let join = tokio::spawn(async move { handler.call(ctx, params, 1).await });

    // Wait until the parent is genuinely suspended at the await.
    wait_until(|| w.event_count("run.suspended") == 1, "run.suspended").await;
    assert!(matches!(
        w.rm.run_status(&run_id).expect("status").status,
        TaskRunStatus::Suspended
    ));

    // Operator pause-run while Suspended (branch-a) → closes the session.
    w.rm.pause_run(&run_id, "operator-pause".to_string())
        .await
        .expect("pause_run");

    // SYS-AC-016: the awaiting guest call returns session-closed.
    let result = tokio::time::timeout(Duration::from_secs(5), join)
        .await
        .expect("handler timed out")
        .expect("join")
        .expect("host-fn ok");
    assert_session_closed(&result);

    // SYS-AC-017: status Paused + exactly one run.paused; NO run.resumed (race fix).
    wait_until(|| w.event_count("run.paused") == 1, "run.paused").await;
    assert!(
        matches!(
            w.rm.run_status(&run_id).expect("status").status,
            TaskRunStatus::Paused
        ),
        "run must be Paused after pause_run"
    );
    assert_eq!(w.event_count("run.paused"), 1);
    assert_eq!(
        w.event_count("run.resumed"),
        0,
        "NO run.resumed — resume is skipped on Err(SessionClosed) (race fix)"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn sys_ac_016_017_cancel_suspended_returns_session_closed_and_cancelled() {
    let w = Wired::build("parent-c");
    let run_id = w.run_id.clone();

    let handler = Arc::clone(&w.handler);
    let ctx = w.ctx();
    let params = single_slot_params("agent:child", "corr-1");
    let join = tokio::spawn(async move { handler.call(ctx, params, 1).await });

    wait_until(|| w.event_count("run.suspended") == 1, "run.suspended").await;
    assert!(matches!(
        w.rm.run_status(&run_id).expect("status").status,
        TaskRunStatus::Suspended
    ));

    // Operator cancel-run while Suspended (branch-a) → closes the session.
    w.rm.cancel_run(&run_id, "operator-cancel".to_string())
        .await
        .expect("cancel_run");

    // SYS-AC-016: session-closed to the awaiting guest call.
    let result = tokio::time::timeout(Duration::from_secs(5), join)
        .await
        .expect("handler timed out")
        .expect("join")
        .expect("host-fn ok");
    assert_session_closed(&result);

    // SYS-AC-017: status Cancelled + exactly one run.cancelled; NO run.resumed.
    wait_until(|| w.event_count("run.cancelled") == 1, "run.cancelled").await;
    assert!(
        matches!(
            w.rm.run_status(&run_id).expect("status").status,
            TaskRunStatus::Cancelled(_)
        ),
        "run must be Cancelled after cancel_run"
    );
    assert_eq!(w.event_count("run.cancelled"), 1);
    assert_eq!(
        w.event_count("run.resumed"),
        0,
        "NO run.resumed — resume is skipped on Err(SessionClosed) (race fix)"
    );
}
