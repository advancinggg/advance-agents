//! MODULE-007 AC-10 — per-session idle monitor (slice m007-B).
//!
//! Virtual time (`start_paused = true` + `tokio::time::advance`). The
//! monitor's `tokio::time::sleep(5s)` and the `LivenessRec.last_activity`
//! (`tokio::time::Instant`) are both clock-aware so advancing virtual time
//! drives the monitor deterministically.
//!
//! T09a: ReturnPartial, no reply/hb, advance > timeout → `PartialTimeout`.
//! T09b: same, Fail policy → `Err(IdleTimeoutExceeded)`.
//! T09c: `on_heartbeat` at vt=20s; advance to 35s → NOT timed out (heartbeat
//!       reset the idle clock — proves the sync `on_heartbeat` idle-reset).
//! T09d: reply completes the session before the deadline; advance past it →
//!       `Completed`; monitor exits promptly (no double-resolve/panic).
//! T09e: reply lands just before the timeout tick (race 2) → reply wins
//!       (`Completed`); `resolve_idle` no-ops; exactly one oneshot result.
//! T09f: AllOf 3-slot, one reply at vt=20s (2 pending), NO heartbeats;
//!       advance to vt=45s → NOT timed out (the reply reset the idle timer);
//!       times out by vt=55s.
//! T09g: HUNG `MailboxDispatcher::deliver()` (never returns) → `start()` is
//!       parked at `dispatch_slots().await` and never reaches `rx.await`,
//!       yet the monitor (spawned BEFORE dispatch) still idle-times-out and
//!       cleans up the session (Adversarial round R20-W1 regression lock —
//!       a lazy post-dispatch spawn would leave the session pinned forever).
//! T09h: SLOW-then-RETURNS `deliver()` (slower than idle_timeout, then Ok):
//!       the monitor idle-resolves the session DURING the slow dispatch;
//!       when `deliver()` returns, `start()`'s recording block sees the
//!       session already gone and must fall through to `rx.await` to return
//!       the monitor's `PartialTimeout` result — NOT a synthesized
//!       `Err(NotFound)` (Adversarial round R21-F2 regression lock —
//!       silent result-corruption / discarded reply payload).

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use chrono::Utc;

use advance_messaging::dispatcher::MailboxDispatcher;
use advance_shared_types::await_session::{
    AgentAwaitRequest, AwaitMode, AwaitOptions, AwaitRequest, AwaitSessionStatus,
    OrchestrationError, ReplyResult, ReplyStatus, TimeoutPolicy,
};
use advance_shared_types::mailbox::{Message, MessageContext, MsgError, NotifyError};

use advance_reply_tracker::{AwaitSessionManager, AwaitSessionManagerImpl, ManagerOptions};

struct MockDispatcher;

#[async_trait]
impl MailboxDispatcher for MockDispatcher {
    async fn deliver(&self, _target: &str, _msg: Message) -> Result<(), MsgError> {
        Ok(())
    }
    async fn reply(
        &self,
        _from: &str,
        _to_message_id: &str,
        _payload: Vec<u8>,
    ) -> Result<(), MsgError> {
        Ok(())
    }
    async fn notify_agent(
        &self,
        _from: &str,
        _target: &str,
        _payload: Vec<u8>,
        _context: Option<MessageContext>,
    ) -> Result<(), NotifyError> {
        Ok(())
    }
}

fn make_agent_req(target: &str, correlation_id: &str) -> AwaitRequest {
    AwaitRequest::AgentRequest(AgentAwaitRequest {
        target: target.to_string(),
        payload: vec![],
        correlation_id: correlation_id.to_string(),
        context: None,
    })
}

fn manager() -> Arc<AwaitSessionManagerImpl> {
    let dispatcher: Arc<dyn MailboxDispatcher> = Arc::new(MockDispatcher);
    Arc::new(AwaitSessionManagerImpl::new(
        dispatcher,
        ManagerOptions::default(),
    ))
}

/// Advance virtual time in monitor-tick-sized steps so the spawned
/// `idle_monitor_task` (which `sleep(5s)`s) actually wakes, evaluates, and
/// (when due) resolves between steps. A single large `advance` would fire
/// all timers at once but not necessarily interleave the monitor's
/// post-sleep work with our assertions.
async fn advance_secs(total: u64) {
    let mut elapsed = 0;
    while elapsed < total {
        tokio::time::advance(Duration::from_secs(5)).await;
        elapsed += 5;
        for _ in 0..4 {
            tokio::task::yield_now().await;
        }
    }
}

// ── T09a ReturnPartial idle timeout → PartialTimeout ──────────────────

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn t09a_return_partial_idle_timeout_resolves_partial() {
    let manager = manager();
    let options = AwaitOptions {
        mode: AwaitMode::AllOf,
        idle_timeout_secs: Some(30),
        on_idle_timeout: TimeoutPolicy::ReturnPartial,
        keep_losers: false,
    };
    let mgr = manager.clone();
    let h = tokio::spawn(async move {
        mgr.start(
            "researcher",
            vec![make_agent_req("agent:t1", "c1")],
            options,
        )
        .await
    });
    for _ in 0..4 {
        tokio::task::yield_now().await;
    }
    advance_secs(35).await;
    let result = h.await.expect("spawn ok").expect("Ok(PartialTimeout)");
    assert_eq!(result.status, AwaitSessionStatus::PartialTimeout);
    assert_eq!(result.replies.len(), 1);
    assert!(matches!(result.replies[0].status, ReplyStatus::TimedOut));
}

// ── T09b Fail idle timeout → Err(IdleTimeoutExceeded) ─────────────────

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn t09b_fail_idle_timeout_resolves_err() {
    let manager = manager();
    let options = AwaitOptions {
        mode: AwaitMode::AllOf,
        idle_timeout_secs: Some(30),
        on_idle_timeout: TimeoutPolicy::Fail,
        keep_losers: false,
    };
    let mgr = manager.clone();
    let h = tokio::spawn(async move {
        mgr.start(
            "researcher",
            vec![make_agent_req("agent:t1", "c1")],
            options,
        )
        .await
    });
    for _ in 0..4 {
        tokio::task::yield_now().await;
    }
    advance_secs(35).await;
    let result = h.await.expect("spawn ok");
    assert!(
        matches!(result, Err(OrchestrationError::IdleTimeoutExceeded(_))),
        "Fail policy → Err(IdleTimeoutExceeded), got {result:?}"
    );
}

// ── T09c heartbeat resets idle clock ──────────────────────────────────

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn t09c_heartbeat_resets_idle_clock() {
    let manager = manager();
    let options = AwaitOptions {
        mode: AwaitMode::AllOf,
        idle_timeout_secs: Some(30),
        on_idle_timeout: TimeoutPolicy::Fail,
        keep_losers: false,
    };
    let mgr = manager.clone();
    let h = tokio::spawn(async move {
        mgr.start(
            "researcher",
            vec![make_agent_req("agent:t1", "c1")],
            options,
        )
        .await
    });
    for _ in 0..4 {
        tokio::task::yield_now().await;
    }
    let session_id = manager.first_open_session_id_for_test().await;

    // Advance to vt≈20s, heartbeat (resets idle clock), then advance another
    // 15s (vt≈35s). Without the heartbeat reset this would have idle-timed
    // out at ~30s; with it, the clock restarted at 20s so 35s total is only
    // 15s idle < 30s.
    advance_secs(20).await;
    assert!(!h.is_finished(), "must not be resolved before any timeout");
    manager.on_heartbeat(&session_id, "agent:t1", Some("progress".into()));
    advance_secs(15).await;
    assert!(
        !h.is_finished(),
        "heartbeat at vt=20s must have reset the idle clock — session NOT timed out at vt=35s"
    );

    // Now go idle for a full timeout window with no heartbeat → it fires.
    advance_secs(35).await;
    let result = h.await.expect("spawn ok");
    assert!(
        matches!(result, Err(OrchestrationError::IdleTimeoutExceeded(_))),
        "after the heartbeat, a full idle window must still time out, got {result:?}"
    );
}

// ── T09d reply completes before deadline; monitor exits cleanly ───────

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn t09d_reply_completes_then_monitor_exits_no_panic() {
    let manager = manager();
    let options = AwaitOptions {
        mode: AwaitMode::AllOf,
        idle_timeout_secs: Some(30),
        on_idle_timeout: TimeoutPolicy::ReturnPartial,
        keep_losers: false,
    };
    let mgr = manager.clone();
    let h = tokio::spawn(async move {
        mgr.start(
            "researcher",
            vec![make_agent_req("agent:t1", "c1")],
            options,
        )
        .await
    });
    for _ in 0..4 {
        tokio::task::yield_now().await;
    }
    let session_id = manager.first_open_session_id_for_test().await;

    // Reply completes the session well before the idle deadline.
    advance_secs(10).await;
    manager
        .on_reply(
            &session_id,
            0,
            ReplyResult {
                slot: 0,
                source: "agent:t1".to_string(),
                payload: vec![],
                status: ReplyStatus::Completed,
                received_at: Utc::now(),
                task_id: None,
            },
        )
        .await
        .expect("on_reply ok");
    let result = h.await.expect("spawn ok").expect("Ok(Completed)");
    assert_eq!(result.status, AwaitSessionStatus::Completed);

    // Advance well past the (now-evicted) deadline: the monitor's next tick
    // sees the liveness entry absent and exits — no double-resolve, no panic.
    advance_secs(60).await;
    // Session id is gone; a second close → NotFound (no resurrection).
    let err = manager.close(&session_id, "again").await;
    assert!(matches!(err, Err(OrchestrationError::NotFound(_))));
}

// ── T09e reply just before the timeout tick (race 2) ──────────────────

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn t09e_reply_wins_race_against_timeout() {
    let manager = manager();
    let options = AwaitOptions {
        mode: AwaitMode::AllOf,
        idle_timeout_secs: Some(30),
        on_idle_timeout: TimeoutPolicy::Fail,
        keep_losers: false,
    };
    let mgr = manager.clone();
    let h = tokio::spawn(async move {
        mgr.start(
            "researcher",
            vec![make_agent_req("agent:t1", "c1")],
            options,
        )
        .await
    });
    for _ in 0..4 {
        tokio::task::yield_now().await;
    }
    let session_id = manager.first_open_session_id_for_test().await;

    // Advance to just before the 30s deadline (vt≈25s), then reply. The
    // reply wins the sessions-remove-once race; resolve_idle (if its tick
    // fires later) sees sessions.remove → None and no-ops.
    advance_secs(25).await;
    manager
        .on_reply(
            &session_id,
            0,
            ReplyResult {
                slot: 0,
                source: "agent:t1".to_string(),
                payload: vec![],
                status: ReplyStatus::Completed,
                received_at: Utc::now(),
                task_id: None,
            },
        )
        .await
        .expect("on_reply ok");

    // Drive past the would-be deadline; the monitor must NOT override the
    // completed result (exactly one oneshot result was sent).
    advance_secs(30).await;
    let result = h
        .await
        .expect("spawn ok")
        .expect("reply won → Ok(Completed)");
    assert_eq!(
        result.status,
        AwaitSessionStatus::Completed,
        "reply must win the race; timeout no-ops"
    );
}

// ── T09f open-keeping reply resets the idle timer (AllOf, no hb) ──────

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn t09f_open_keeping_reply_resets_idle_timer() {
    let manager = manager();
    let options = AwaitOptions {
        mode: AwaitMode::AllOf,
        idle_timeout_secs: Some(30),
        on_idle_timeout: TimeoutPolicy::Fail,
        keep_losers: false,
    };
    let requests = vec![
        make_agent_req("agent:t1", "c1"),
        make_agent_req("agent:t2", "c2"),
        make_agent_req("agent:t3", "c3"),
    ];
    let mgr = manager.clone();
    let h = tokio::spawn(async move { mgr.start("researcher", requests, options).await });
    for _ in 0..4 {
        tokio::task::yield_now().await;
    }
    let session_id = manager.first_open_session_id_for_test().await;

    // One slot replies at vt≈20s (2 still pending), NO heartbeats.
    advance_secs(20).await;
    assert!(!h.is_finished());
    manager
        .on_reply(
            &session_id,
            0,
            ReplyResult {
                slot: 0,
                source: "agent:t1".to_string(),
                payload: vec![],
                status: ReplyStatus::Completed,
                received_at: Utc::now(),
                task_id: None,
            },
        )
        .await
        .expect("on_reply ok");

    // vt≈45s total: only 25s since the reply reset the idle timer (< 30s) →
    // NOT timed out (mirrors slice-A `session.last_activity` on every reply).
    advance_secs(25).await;
    assert!(
        !h.is_finished(),
        "the open-keeping reply at vt=20s reset the idle timer — NOT idle at vt=45s"
    );

    // vt≈55s+ total: now > 30s idle since the reply → times out.
    advance_secs(15).await;
    let result = h.await.expect("spawn ok");
    assert!(
        matches!(result, Err(OrchestrationError::IdleTimeoutExceeded(_))),
        "no further activity → idle timeout fires after the reset window, got {result:?}"
    );
}

// ── T09g monitor guards a HUNG dispatcher (Adversarial R20-W1 lock) ───
//
// A `MailboxDispatcher::deliver()` that never returns parks `start()` at
// `dispatch_slots().await` — it never reaches `rx.await`. The R19-W3 lazy
// post-dispatch monitor spawn would therefore NEVER spawn a monitor for
// this session, leaving it (and its `per_caller_count`/`liveness` state)
// pinned forever with no idle timeout (R20-W1). The corrected design
// spawns the monitor BEFORE dispatch, so it still idle-times-out and
// `resolve_idle`-cleans-up the stuck session. This test FAILS (the final
// `close` is not `NotFound`) without the spawn-before-dispatch fix.
struct HangingDispatcher;

#[async_trait]
impl MailboxDispatcher for HangingDispatcher {
    async fn deliver(&self, _target: &str, _msg: Message) -> Result<(), MsgError> {
        // Under virtual time the test's ~40s advance never elapses this
        // 24h sleep, so `dispatch_slots().await` is effectively hung.
        tokio::time::sleep(Duration::from_secs(86_400)).await;
        Ok(())
    }
    async fn reply(
        &self,
        _from: &str,
        _to_message_id: &str,
        _payload: Vec<u8>,
    ) -> Result<(), MsgError> {
        Ok(())
    }
    async fn notify_agent(
        &self,
        _from: &str,
        _target: &str,
        _payload: Vec<u8>,
        _context: Option<MessageContext>,
    ) -> Result<(), NotifyError> {
        Ok(())
    }
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn t09g_monitor_guards_hung_dispatcher() {
    let dispatcher: Arc<dyn MailboxDispatcher> = Arc::new(HangingDispatcher);
    let manager = Arc::new(AwaitSessionManagerImpl::new(
        dispatcher,
        ManagerOptions::default(),
    ));
    let options = AwaitOptions {
        mode: AwaitMode::AllOf,
        idle_timeout_secs: Some(30),
        on_idle_timeout: TimeoutPolicy::Fail,
        keep_losers: false,
    };
    let mgr = manager.clone();
    let h = tokio::spawn(async move {
        mgr.start(
            "researcher",
            vec![make_agent_req("agent:t1", "c1")],
            options,
        )
        .await
    });
    for _ in 0..4 {
        tokio::task::yield_now().await;
    }
    // The session was inserted and the monitor spawned BEFORE the hung
    // dispatch await (R20-W1 fix). start() is now parked in deliver().
    let sid = manager.first_open_session_id_for_test().await;
    assert!(
        !h.is_finished(),
        "start() must be parked on the hung dispatch"
    );

    // Advance past the 30s idle deadline. The pre-dispatch-spawned monitor
    // fires and resolve_idle removes the session even though start() never
    // reaches rx.await.
    advance_secs(40).await;

    // Proof the monitor guarded the hung dispatch: the session is gone, so
    // a close on its id is NotFound. Without spawn-before-dispatch no
    // monitor would ever have existed (start() parked before a post-dispatch
    // spawn) and the session would still be open here.
    let closed = manager.close(&sid, "post-idle").await;
    assert!(
        matches!(closed, Err(OrchestrationError::NotFound(_))),
        "monitor must idle-resolve + remove the session despite the hung \
         dispatcher (R20-W1); got {closed:?}"
    );

    // start()'s task is still parked on the 24h hung deliver under virtual
    // time — abort it so the test does not retain the task.
    h.abort();
}

// ── T09h slow-then-returns dispatcher → start() returns the monitor's ──
//      PartialTimeout via rx.await, NOT Err(NotFound) (Adversarial R21-F2)
//
// `deliver()` sleeps LONGER than idle_timeout then returns Ok. The
// pre-dispatch monitor idle-resolves the session (ReturnPartial →
// `Ok(PartialTimeout)`) and removes it while start() is still parked in
// `dispatch_slots().await`. When `deliver()` finally returns, start()'s
// recording block finds the session gone (`session_present == false`),
// must NOT take the all_failed fast path, and must fall through to
// `rx.await` to return the monitor's buffered `Ok(PartialTimeout)`.
// Without the R21-F2 fix start() returns `Err(NotFound)`, discarding the
// reply payload — this test would then fail the `PartialTimeout` assert.
struct SlowThenOkDispatcher;

#[async_trait]
impl MailboxDispatcher for SlowThenOkDispatcher {
    async fn deliver(&self, _target: &str, _msg: Message) -> Result<(), MsgError> {
        // 50s > the 30s idle_timeout, but FINITE (unlike T09g's hang): the
        // monitor fires at ~30s; deliver returns at ~50s and start() resumes.
        tokio::time::sleep(Duration::from_secs(50)).await;
        Ok(())
    }
    async fn reply(
        &self,
        _from: &str,
        _to_message_id: &str,
        _payload: Vec<u8>,
    ) -> Result<(), MsgError> {
        Ok(())
    }
    async fn notify_agent(
        &self,
        _from: &str,
        _target: &str,
        _payload: Vec<u8>,
        _context: Option<MessageContext>,
    ) -> Result<(), NotifyError> {
        Ok(())
    }
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn t09h_slow_then_returns_yields_monitor_result_not_notfound() {
    let dispatcher: Arc<dyn MailboxDispatcher> = Arc::new(SlowThenOkDispatcher);
    let manager = Arc::new(AwaitSessionManagerImpl::new(
        dispatcher,
        ManagerOptions::default(),
    ));
    let options = AwaitOptions {
        mode: AwaitMode::AllOf,
        idle_timeout_secs: Some(30),
        on_idle_timeout: TimeoutPolicy::ReturnPartial,
        keep_losers: false,
    };
    let mgr = manager.clone();
    let h = tokio::spawn(async move {
        mgr.start(
            "researcher",
            vec![make_agent_req("agent:t1", "c1")],
            options,
        )
        .await
    });
    for _ in 0..4 {
        tokio::task::yield_now().await;
    }

    // Advance past BOTH the 30s idle deadline (monitor resolves the session,
    // sends Ok(PartialTimeout), removes it) and the 50s slow-deliver (start()
    // resumes from dispatch_slots().await, finds the session gone, falls
    // through to rx.await).
    advance_secs(60).await;

    let result = h.await.expect("spawn ok").expect(
        "start() must return the monitor's Ok(PartialTimeout) via \
                 rx.await, NOT Err(NotFound) (R21-F2)",
    );
    assert_eq!(
        result.status,
        AwaitSessionStatus::PartialTimeout,
        "slow-then-returns: start() must yield the monitor's PartialTimeout \
         result (reply payload preserved), not a synthesized NotFound"
    );
    assert_eq!(result.replies.len(), 1);
    assert!(matches!(result.replies[0].status, ReplyStatus::TimedOut));
}
