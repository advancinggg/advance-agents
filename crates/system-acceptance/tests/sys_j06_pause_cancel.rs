//! Track C — SYS-J-06 (pause/cancel a run while the parent is suspended at await-replies).
//!
//! **SYS-AC-016 + SYS-AC-017 are now WITNESSED** (Backbone Step 4b, 2026-06-08) — see
//! `sys_j06_pause_cancel_session_closed.rs`: a real `RunManager::pause_run`/`cancel_run`
//! (branch-(a) Suspended) closes the live M007 await session via the production
//! `AwaitSessionManagerRef`, returning `orchestration-error::session-closed` to the parked
//! await (016) and transitioning the run to Paused/Cancelled with `run.paused`/`run.cancelled`
//! (017), on the real wired M007+M008+M006+EventBus chain.
//!
//! Still DEFERRED for SYS-J-06 (recorded in `docs/SYSTEM-ACCEPTANCE.md` §3):
//! - **SYS-AC-018** (interrupted turn unwinds with no commit): needs the guest-driven run loop.
//! - **SYS-AC-195** (session-closed within the 100 ms pause-latency bound): perf-SLO unreliable
//!   on shared disk-pressured CI.

#[test]
#[ignore = "SYS-AC-018/195 still deferred (guest run loop / perf-SLO); 016/017 witnessed in sys_j06_pause_cancel_session_closed.rs"]
fn sys_j06_pause_cancel_deferred_run_manager_gap() {
    // SYS-AC-016/017 are now witnessed (sys_j06_pause_cancel_session_closed.rs). This stub
    // covers only the remaining SYS-J-06 deferrals (018 = guest run loop; 195 = perf-SLO),
    // surfaced in SYSTEM-ACCEPTANCE.md §3.
}
