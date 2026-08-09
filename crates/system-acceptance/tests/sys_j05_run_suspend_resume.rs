//! Backbone Step 4b (2026-06-08) — SYS-J-05 / SYS-AC-015 witness on the REAL
//! wired system (Track-H test-side wiring).
//!
//! SYS-AC-015: "The parent run transitions run.suspended (root_await set) then
//! run.resumed with reason await_complete once replies arrive."
//!
//! Drives the REAL `AwaitRepliesHandler::call` (the exact path a guest's
//! `await-replies` import resolves to) with a `HostCallContext{run_id:Some}` over
//! a real `AwaitSessionManagerImpl` (M007) + real `RunManager` (M008) + real
//! `AwaitSessionManagerRef` + a recording `EventBusEmit` capturing the real M008
//! `run.*` emissions. Only the external child peer (`OkDispatcher`) and the guest
//! boundary are doubled. Witnesses: a parked await drives `run.suspended`
//! (root_await=session) THEN, once the reply arrives, `run.resumed`
//! (reason `await_complete`), in that order; the run returns to Active with
//! root_await cleared.

#[path = "step4b_support/mod.rs"]
mod support;

use std::sync::Arc;
use std::time::Duration;

use advance_reply_tracker::AwaitSessionManager;
use advance_runtime::host_registry::HostFunctionHandler;
use advance_shared_types::run::TaskRunStatus;

use support::{completed_reply, single_slot_params, wait_until, Wired};

#[tokio::test(flavor = "multi_thread")]
async fn sys_ac_015_run_suspends_then_resumes_await_complete() {
    let w = Wired::build("parent");
    let run_id = w.run_id.clone();

    // Run starts Active (ensure_run). No suspend/resume yet.
    assert_eq!(w.event_count("run.suspended"), 0);
    assert_eq!(w.event_count("run.resumed"), 0);
    assert!(matches!(
        w.rm.run_status(&run_id).expect("status").status,
        TaskRunStatus::Active
    ));

    // Drive the REAL await-replies host-fn with the session run id. It parks.
    let handler = Arc::clone(&w.handler);
    let ctx = w.ctx();
    let params = single_slot_params("agent:child", "corr-1");
    let join = tokio::spawn(async move { handler.call(ctx, params, 1).await });

    // (a) run.suspended fires at the genuine park, with root_await set.
    wait_until(|| w.event_count("run.suspended") == 1, "run.suspended").await;
    let suspended = w.events_of("run.suspended");
    assert_eq!(suspended.len(), 1);
    assert_eq!(suspended[0].run_id.as_deref(), Some(run_id.as_ref()));
    let root_await_in_event = suspended[0]
        .payload
        .get("root_await_session_id")
        .and_then(|v| v.as_str())
        .expect("run.suspended carries root_await_session_id");

    // The run is now Suspended with root_await == the await session id.
    let st = w.rm.run_status(&run_id).expect("status");
    assert!(matches!(st.status, TaskRunStatus::Suspended));
    assert_eq!(st.root_await.as_deref(), Some(root_await_in_event));
    // No resume before the reply.
    assert_eq!(w.event_count("run.resumed"), 0);

    // (b) The child reply arrives → the single AllOf slot completes → the parked
    // await returns Ok → the handler resumes the run with reason await_complete.
    let sids = w.manager.heartbeat_for_target("agent:child", None).await;
    assert_eq!(sids.len(), 1, "exactly one open session awaiting the child");
    w.manager
        .on_reply(&sids[0], 0, completed_reply(0, "agent:child"))
        .await
        .expect("on_reply");

    // The host-fn returned Ok (a coherent await result).
    let _ = tokio::time::timeout(Duration::from_secs(5), join)
        .await
        .expect("handler timed out")
        .expect("join")
        .expect("host-fn ok");

    wait_until(|| w.event_count("run.resumed") == 1, "run.resumed").await;
    let resumed = w.events_of("run.resumed");
    assert_eq!(resumed.len(), 1);
    assert_eq!(resumed[0].run_id.as_deref(), Some(run_id.as_ref()));
    assert_eq!(
        resumed[0].payload.get("reason").and_then(|v| v.as_str()),
        Some("await_complete"),
        "run.resumed must carry reason await_complete"
    );

    // (c) Ordering: run.suspended strictly BEFORE run.resumed.
    let s_idx = w.first_index_of("run.suspended").unwrap();
    let r_idx = w.first_index_of("run.resumed").unwrap();
    assert!(
        s_idx < r_idx,
        "run.suspended (idx {s_idx}) must precede run.resumed (idx {r_idx})"
    );

    // (d) The run is back to Active with root_await cleared (durable wait/resume
    // boundary — MODULE-008-AC-19).
    let st = w.rm.run_status(&run_id).expect("status");
    assert!(
        matches!(st.status, TaskRunStatus::Active),
        "run must be Active after resume, got {:?}",
        st.status
    );
    assert_eq!(st.root_await, None, "root_await cleared after resume");

    // Exactly one suspend/resume pair (no phantom events).
    assert_eq!(w.event_count("run.suspended"), 1);
    assert_eq!(w.event_count("run.resumed"), 1);
}
