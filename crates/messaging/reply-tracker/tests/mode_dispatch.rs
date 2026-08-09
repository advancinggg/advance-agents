//! MODULE-007 AC-03 + AC-04 — per-slot dispatch via MailboxDispatcher +
//! AwaitMode all-of / any-of completion logic (slice m007-A).
//!
//! T03a/b/c — AC-03 per-slot dispatch invariants.
//! T04a/b/c — AC-04 AllOf / AnyOf completion + loser-omission semantics.

use std::sync::Arc;

use async_trait::async_trait;
use chrono::Utc;
use tokio::sync::Mutex;

use advance_messaging::dispatcher::MailboxDispatcher;
use advance_shared_types::await_session::{
    AgentAwaitRequest, AwaitMode, AwaitOptions, AwaitRequest, ComponentAwaitRequest, ReplyResult,
    ReplyStatus, TimeoutPolicy,
};
use advance_shared_types::mailbox::{Message, MessageContext, MsgError, NotifyError};

use advance_reply_tracker::{AwaitSessionManager, AwaitSessionManagerImpl, ManagerOptions};

// ── MockMailboxDispatcher — records every deliver call ──────────────────

#[derive(Clone, Debug, PartialEq, Eq)]
struct DeliverObservation {
    target: String,
    msg_to: String,
    msg_payload: Vec<u8>,
    msg_correlation_id: Option<String>,
}

#[derive(Default)]
struct MockDispatcher {
    calls: Arc<Mutex<Vec<DeliverObservation>>>,
    // Per-target injected error. If a target matches, that call returns
    // `Err(MsgError::InvalidTarget(...))` instead of Ok.
    inject_invalid_target: Arc<Mutex<Vec<String>>>,
}

impl MockDispatcher {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            calls: Arc::new(Mutex::new(Vec::new())),
            inject_invalid_target: Arc::new(Mutex::new(Vec::new())),
        })
    }

    async fn calls(&self) -> Vec<DeliverObservation> {
        self.calls.lock().await.clone()
    }
}

#[async_trait]
impl MailboxDispatcher for MockDispatcher {
    async fn deliver(&self, target: &str, msg: Message) -> Result<(), MsgError> {
        self.calls.lock().await.push(DeliverObservation {
            target: target.to_string(),
            msg_to: msg.to.clone(),
            msg_payload: msg.payload.clone(),
            msg_correlation_id: msg.context.as_ref().and_then(|c| c.correlation_id.clone()),
        });
        let inject = self.inject_invalid_target.lock().await;
        if inject.iter().any(|t| t == target) {
            Err(MsgError::InvalidTarget(target.to_string()))
        } else {
            Ok(())
        }
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

fn make_agent_req(target: &str, payload: Vec<u8>, correlation_id: &str) -> AwaitRequest {
    AwaitRequest::AgentRequest(AgentAwaitRequest {
        target: target.to_string(),
        payload,
        correlation_id: correlation_id.to_string(),
        context: None,
    })
}

// ── T03 AC-03 per-slot dispatch ────────────────────────────────────────

#[tokio::test(flavor = "current_thread")]
async fn t03a_dispatch_3_targets_records_3_deliver_calls() {
    let mock = MockDispatcher::new();
    let dispatcher: Arc<dyn MailboxDispatcher> = mock.clone();
    let manager = Arc::new(AwaitSessionManagerImpl::new(
        dispatcher,
        ManagerOptions::default(),
    ));

    let options = AwaitOptions {
        mode: AwaitMode::AllOf,
        idle_timeout_secs: None,
        on_idle_timeout: TimeoutPolicy::ReturnPartial,
        keep_losers: false,
    };
    let requests = vec![
        make_agent_req("agent:t1", vec![1], "corr-1"),
        make_agent_req("agent:t2", vec![2], "corr-2"),
        make_agent_req("agent:t3", vec![3], "corr-3"),
    ];

    let mgr = manager.clone();
    let start_handle =
        tokio::spawn(async move { mgr.start("researcher", requests, options).await });

    // Yield enough for spawn to register + dispatch.
    for _ in 0..4 {
        tokio::task::yield_now().await;
    }

    let calls = mock.calls().await;
    assert_eq!(
        calls.len(),
        3,
        "expected 3 deliver calls, got {}",
        calls.len()
    );

    // Targets verbatim (canonical agent: prefix, no double-prefix).
    assert_eq!(calls[0].target, "agent:t1");
    assert_eq!(calls[1].target, "agent:t2");
    assert_eq!(calls[2].target, "agent:t3");

    // Message.to mirrors target.
    assert_eq!(calls[0].msg_to, "agent:t1");
    assert_eq!(calls[1].msg_to, "agent:t2");
    assert_eq!(calls[2].msg_to, "agent:t3");

    // Payload + correlation_id propagated correctly.
    assert_eq!(calls[0].msg_payload, vec![1]);
    assert_eq!(calls[0].msg_correlation_id.as_deref(), Some("corr-1"));
    assert_eq!(calls[2].msg_correlation_id.as_deref(), Some("corr-3"));

    // Clean up the dangling session via close so the spawn doesn't hang.
    let session_id = manager.first_open_session_id_for_test().await;
    let _ = manager.close(&session_id, "test-cleanup").await;
    let _ = start_handle.await;
}

#[tokio::test(flavor = "current_thread")]
async fn t03b_single_slot_failure_continues_dispatch() {
    let mock = MockDispatcher::new();
    {
        let mut inject = mock.inject_invalid_target.lock().await;
        inject.push("agent:t2".to_string());
    }
    let dispatcher: Arc<dyn MailboxDispatcher> = mock.clone();
    let manager = Arc::new(AwaitSessionManagerImpl::new(
        dispatcher,
        ManagerOptions::default(),
    ));

    let options = AwaitOptions {
        mode: AwaitMode::AllOf,
        idle_timeout_secs: None,
        on_idle_timeout: TimeoutPolicy::ReturnPartial,
        keep_losers: false,
    };
    let requests = vec![
        make_agent_req("agent:t1", vec![], "corr-1"),
        make_agent_req("agent:t2", vec![], "corr-2"),
        make_agent_req("agent:t3", vec![], "corr-3"),
    ];

    let mgr = manager.clone();
    let start_handle =
        tokio::spawn(async move { mgr.start("researcher", requests, options).await });

    for _ in 0..4 {
        tokio::task::yield_now().await;
    }

    let calls = mock.calls().await;
    // Even with slot 1 failing, slots 0 and 2 deliver normally.
    assert_eq!(calls.len(), 3, "all 3 slots receive deliver attempt");
    assert_eq!(calls[1].target, "agent:t2");

    // Clean up.
    let session_id = manager.first_open_session_id_for_test().await;
    let _ = manager.close(&session_id, "test-cleanup").await;
    let _ = start_handle.await;
}

#[tokio::test(flavor = "current_thread")]
async fn t03c_component_finished_does_not_dispatch() {
    let mock = MockDispatcher::new();
    let dispatcher: Arc<dyn MailboxDispatcher> = mock.clone();
    let manager = Arc::new(AwaitSessionManagerImpl::new(
        dispatcher,
        ManagerOptions::default(),
    ));

    let options = AwaitOptions {
        mode: AwaitMode::AllOf,
        idle_timeout_secs: None,
        on_idle_timeout: TimeoutPolicy::ReturnPartial,
        keep_losers: false,
    };
    let requests = vec![AwaitRequest::ComponentFinished(ComponentAwaitRequest {
        component_id: "comp-001".to_string(),
        correlation_id: "corr-comp".to_string(),
    })];

    let mgr = manager.clone();
    let start_handle =
        tokio::spawn(async move { mgr.start("researcher", requests, options).await });

    for _ in 0..4 {
        tokio::task::yield_now().await;
    }

    let calls = mock.calls().await;
    assert_eq!(
        calls.len(),
        0,
        "ComponentFinished slot must NOT invoke MailboxDispatcher::deliver"
    );

    // Clean up.
    let session_id = manager.first_open_session_id_for_test().await;
    let _ = manager.close(&session_id, "test-cleanup").await;
    let _ = start_handle.await;
}

// ── T04 AC-04 await-mode completion ───────────────────────────────────

#[tokio::test(flavor = "current_thread")]
async fn t04a_all_of_resolves_when_all_slots_completed() {
    let mock = MockDispatcher::new();
    let dispatcher: Arc<dyn MailboxDispatcher> = mock.clone();
    let manager = Arc::new(AwaitSessionManagerImpl::new(
        dispatcher,
        ManagerOptions::default(),
    ));

    let options = AwaitOptions {
        mode: AwaitMode::AllOf,
        idle_timeout_secs: None,
        on_idle_timeout: TimeoutPolicy::ReturnPartial,
        keep_losers: false,
    };
    let requests = vec![
        make_agent_req("agent:t1", vec![], "c1"),
        make_agent_req("agent:t2", vec![], "c2"),
        make_agent_req("agent:t3", vec![], "c3"),
    ];

    let mgr = manager.clone();
    let start_handle =
        tokio::spawn(async move { mgr.start("researcher", requests, options).await });

    for _ in 0..4 {
        tokio::task::yield_now().await;
    }

    let session_id = manager.first_open_session_id_for_test().await;
    for slot in 0..3 {
        manager
            .on_reply(
                &session_id,
                slot,
                ReplyResult {
                    slot,
                    source: format!("agent:t{}", slot + 1),
                    payload: vec![],
                    status: ReplyStatus::Completed,
                    received_at: Utc::now(),
                    task_id: None,
                },
            )
            .await
            .expect("on_reply ok");
    }

    let result = start_handle
        .await
        .expect("spawn ok")
        .expect("start returns Ok");
    assert_eq!(result.mode, AwaitMode::AllOf);
    assert_eq!(result.replies.len(), 3);
    assert!(matches!(
        result.status,
        advance_shared_types::await_session::AwaitSessionStatus::Completed
    ));
}

#[tokio::test(flavor = "current_thread")]
async fn t04b_all_of_does_not_finalize_with_partial_replies() {
    let mock = MockDispatcher::new();
    let dispatcher: Arc<dyn MailboxDispatcher> = mock.clone();
    let manager = Arc::new(AwaitSessionManagerImpl::new(
        dispatcher,
        ManagerOptions::default(),
    ));

    let options = AwaitOptions {
        mode: AwaitMode::AllOf,
        idle_timeout_secs: None,
        on_idle_timeout: TimeoutPolicy::ReturnPartial,
        keep_losers: false,
    };
    let requests = vec![
        make_agent_req("agent:t1", vec![], "c1"),
        make_agent_req("agent:t2", vec![], "c2"),
        make_agent_req("agent:t3", vec![], "c3"),
    ];

    let mgr = manager.clone();
    let start_handle =
        tokio::spawn(async move { mgr.start("researcher", requests, options).await });

    for _ in 0..4 {
        tokio::task::yield_now().await;
    }

    let session_id = manager.first_open_session_id_for_test().await;
    // Only 2 of 3 replies → AllOf should NOT resolve yet.
    for slot in 0..2 {
        manager
            .on_reply(
                &session_id,
                slot,
                ReplyResult {
                    slot,
                    source: format!("agent:t{}", slot + 1),
                    payload: vec![],
                    status: ReplyStatus::Completed,
                    received_at: Utc::now(),
                    task_id: None,
                },
            )
            .await
            .expect("on_reply ok");
    }

    // Use a short timeout to verify the future is not yet ready.
    let timeout_result = tokio::time::timeout(std::time::Duration::from_millis(20), async {
        // Spawn-handle abort would be cleaner, but we need to test that
        // start_handle isn't ready. Use `now_or_never` via a fresh poll.
        let _ = &start_handle;
    })
    .await;
    // The above always finishes — we instead poll the handle directly.
    let _ = timeout_result;

    assert!(
        !start_handle.is_finished(),
        "start_handle must NOT be finished after only 2 of 3 replies in AllOf mode"
    );

    // Clean up: close to drain the handle.
    let _ = manager.close(&session_id, "test-cleanup").await;
    let _ = start_handle.await;
}

#[tokio::test(flavor = "current_thread")]
async fn t04c_any_of_first_wins_with_loser_omission() {
    let mock = MockDispatcher::new();
    let dispatcher: Arc<dyn MailboxDispatcher> = mock.clone();
    let manager = Arc::new(AwaitSessionManagerImpl::new(
        dispatcher,
        ManagerOptions::default(),
    ));

    let options = AwaitOptions {
        mode: AwaitMode::AnyOf,
        idle_timeout_secs: None,
        on_idle_timeout: TimeoutPolicy::ReturnPartial,
        keep_losers: false,
    };
    let requests = vec![
        make_agent_req("agent:t1", vec![], "c1"),
        make_agent_req("agent:t2", vec![], "c2"),
        make_agent_req("agent:t3", vec![], "c3"),
    ];

    let mgr = manager.clone();
    let start_handle =
        tokio::spawn(async move { mgr.start("researcher", requests, options).await });

    for _ in 0..4 {
        tokio::task::yield_now().await;
    }

    let session_id = manager.first_open_session_id_for_test().await;
    // Slot 0 wins.
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

    let result = start_handle
        .await
        .expect("spawn ok")
        .expect("start returns Ok");
    assert_eq!(result.mode, AwaitMode::AnyOf);
    assert_eq!(
        result.replies.len(),
        1,
        "AnyOf with keep_losers=false → only the winner appears in replies (per §2.3 loser-omission)"
    );
    assert_eq!(result.replies[0].slot, 0);
    assert!(matches!(result.replies[0].status, ReplyStatus::Completed));
}

// ─── Slice m007-D regression test (NO new AC claim — pins existing slice-A behavior)
// ─────────────────────────────────────────────────────────────────────────────────────
//
// T13r: snapshot_replies (AnyOf, keep_losers=true) arm regression lock.
//
// PINS: `snapshot_replies`'s `(AnyOf, keep_losers=true)` arm — which returns
// ALL slots (in storage order). **Arm-attribution note (Wave-24)**: before
// Wave-24 this case fell through to the `_ =>` catch-all; Wave-24 gave it a
// DEDICATED `(AnyOf, keep_losers=true)` match arm (which additionally
// materializes any *pending* `None` slot as a `detached` loser). T13r drives
// the all-recorded shape (every slot `Some` before the winner), so
// materialization is a no-op and the returned set is byte-identical to the
// pre-Wave-24 behavior — T13r therefore still pins this arm's inclusion
// contract, now via the dedicated arm (see RT-detach-5 in §3.3).
//
// SEQUENCE NOTE (critical — surfaced by plan-eval round 1 C1): under AnyOf
// the is_complete check tests for slots with ReplyStatus::Completed
// (`matches!(...Some(ReplyStatus::Completed))`). Failed/TimedOut slots do NOT
// trigger is_complete. Therefore the loser slots are emitted FIRST via
// on_reply (without closing the session), and the winner is emitted LAST to
// trigger the on_reply complete-terminal (snapshot-then-remove). Emitting the
// winner first would close the session before the losers can be recorded.
//
// DOES NOT CLAIM AC-13 (which has a 4-rule contract — see §3.6 AC-13 entry).
// Rule (1) of AC-13 (winner returned with task-id preserved) is realized by the
// `ReplyResult.task_id` field (Wave-20 host-internal) + its guest-visible WIT
// `reply-result.task-id` round-trip (Wave-23 wit-widening); T13r only verifies the
// inclusion behavior of snapshot_replies.

#[tokio::test(flavor = "current_thread")]
async fn t13r_any_of_keep_losers_true_returns_all_slots() {
    // **Regression test — no new AC claim**: pins the snapshot_replies
    // (AnyOf, keep_losers=true) arm (dedicated since Wave-24; formerly the
    // `_ =>` fall-through) for the all-recorded shape. Does NOT claim AC-13.
    let mock = MockDispatcher::new();
    let dispatcher: Arc<dyn MailboxDispatcher> = mock.clone();
    let manager = Arc::new(AwaitSessionManagerImpl::new(
        dispatcher,
        ManagerOptions::default(),
    ));

    let options = AwaitOptions {
        mode: AwaitMode::AnyOf,
        idle_timeout_secs: Some(60),
        on_idle_timeout: TimeoutPolicy::Fail,
        keep_losers: true,
    };
    let requests = vec![
        make_agent_req("agent:t1", vec![], "corr-0"),
        make_agent_req("agent:t2", vec![], "corr-1"),
        make_agent_req("agent:t3", vec![], "corr-2"),
    ];

    let mgr = manager.clone();
    let start_handle =
        tokio::spawn(async move { mgr.start("researcher", requests, options).await });

    for _ in 0..4 {
        tokio::task::yield_now().await;
    }

    let session_id = manager.first_open_session_id_for_test().await;

    // ── Emit LOSERS FIRST ─────────────────────────────────────────────
    // Loser status is NOT ReplyStatus::Completed, so session.rs:127's
    // is_complete predicate does NOT return true; the session stays open.

    manager
        .on_reply(
            &session_id,
            1,
            ReplyResult {
                slot: 1,
                source: "agent:t2".to_string(),
                payload: vec![],
                status: ReplyStatus::Failed("agent-error:t2".to_string()),
                received_at: Utc::now(),
                task_id: None,
            },
        )
        .await
        .expect("on_reply slot 1 ok (loser — Failed)");

    manager
        .on_reply(
            &session_id,
            2,
            ReplyResult {
                slot: 2,
                source: "agent:t3".to_string(),
                payload: vec![],
                status: ReplyStatus::TimedOut,
                received_at: Utc::now(),
                task_id: None,
            },
        )
        .await
        .expect("on_reply slot 2 ok (loser — TimedOut)");

    // ── Emit WINNER LAST ──────────────────────────────────────────────
    // Completed status DOES satisfy is_complete under AnyOf → session
    // resolves via the on_reply complete-terminal → snapshot_replies
    // executes the dedicated (AnyOf, keep_losers=true) arm → returns ALL
    // 3 slots in storage order (all recorded → materialization no-op).

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
        .expect("on_reply slot 0 ok (winner — Completed)");

    let result = start_handle
        .await
        .expect("spawn ok")
        .expect("start returns Ok");

    assert_eq!(result.mode, AwaitMode::AnyOf);
    assert!(matches!(
        result.status,
        advance_shared_types::await_session::AwaitSessionStatus::Completed
    ));
    assert_eq!(
        result.replies.len(),
        3,
        "AnyOf with keep_losers=true → ALL slots returned by the snapshot_replies \
         (AnyOf, keep_losers=true) arm (NOT just the winner like keep_losers=false in T04c)"
    );

    // Slot order preserved: snapshot_replies iterates self.received in
    // storage order (slot 0, 1, 2). assert per-slot statuses.
    assert_eq!(result.replies[0].slot, 0);
    assert!(matches!(result.replies[0].status, ReplyStatus::Completed));
    assert_eq!(result.replies[1].slot, 1);
    assert!(matches!(result.replies[1].status, ReplyStatus::Failed(_)));
    assert_eq!(result.replies[2].slot, 2);
    assert!(matches!(result.replies[2].status, ReplyStatus::TimedOut));
}

// ─── Wave-24 (2026-07-09) — keep-losers rule-2 OBSERVABLE HALF (no new AC claim)
// ─────────────────────────────────────────────────────────────────────────────
//
// RT-detach-1..4 pin the PENDING-loser detach materialization (MODULE-007 §2.7 /
// AC-13 rule 2 / PRD §9.2 rule 1 observable half): for (AnyOf, keep_losers=true), a still-pending
// (never-replied) non-winner slot is now MATERIALIZED as a `detached` loser
// (ReplyStatus::Cancelled + task_id substitute-or-clear) instead of being silently
// dropped by snapshot_replies. Terminal (Failed/TimedOut) losers keep their status.
//
// These DO NOT CLAIM AC-13 (full 4-rule conjunction stays `untested` — clearing has
// readers but no writer/locus; rule 3 has no reply-tracker cost DATA; production late
// `send` is not `reply_late`; see §3.6). T13r (above) is RT-detach-5 (winner-LAST, all-recorded →
// materialization no-op → unchanged) and T04c is RT-detach-6 (keep_losers=false →
// omission unchanged) — the regression locks for the untouched paths. The pure
// `materialize_detached_loser` branches are unit-tested in `src/detach.rs`.

fn make_agent_req_ctx(
    target: &str,
    payload: Vec<u8>,
    correlation_id: &str,
    task_id: Option<&str>,
) -> AwaitRequest {
    AwaitRequest::AgentRequest(AgentAwaitRequest {
        target: target.to_string(),
        payload,
        correlation_id: correlation_id.to_string(),
        context: Some(MessageContext {
            task_id: task_id.map(str::to_string),
            run_id: None,
            execution_id: None,
            trace_id: None,
            in_reply_to: None,
            correlation_id: Some(correlation_id.to_string()),
        }),
    })
}

fn make_component_req(component_id: &str, correlation_id: &str) -> AwaitRequest {
    AwaitRequest::ComponentFinished(ComponentAwaitRequest {
        component_id: component_id.to_string(),
        correlation_id: correlation_id.to_string(),
    })
}

fn any_of_keep_losers_opts() -> AwaitOptions {
    AwaitOptions {
        mode: AwaitMode::AnyOf,
        idle_timeout_secs: None,
        on_idle_timeout: TimeoutPolicy::ReturnPartial,
        keep_losers: true,
    }
}

async fn reply_winner(
    manager: &AwaitSessionManagerImpl,
    session_id: &advance_shared_types::await_session::SessionId,
    slot: u32,
    source: &str,
) {
    manager
        .on_reply(
            session_id,
            slot,
            ReplyResult {
                slot,
                source: source.to_string(),
                payload: vec![],
                status: ReplyStatus::Completed,
                received_at: Utc::now(),
                task_id: None,
            },
        )
        .await
        .expect("winner on_reply ok");
}

// RT-detach-1: a pending loser whose request context carried an explicit task-id
// → SUBSTITUTE.
#[tokio::test(flavor = "current_thread")]
async fn t13c_detach_pending_loser_substitutes_task_id() {
    let mock = MockDispatcher::new();
    let dispatcher: Arc<dyn MailboxDispatcher> = mock.clone();
    let manager = Arc::new(AwaitSessionManagerImpl::new(
        dispatcher,
        ManagerOptions::default(),
    ));
    let requests = vec![
        make_agent_req("agent:t1", vec![], "c0"), // slot 0 winner
        make_agent_req_ctx("agent:t2", vec![], "c1", Some("task-x")), // slot 1 pending loser WITH task-id
    ];
    let mgr = manager.clone();
    let start_handle = tokio::spawn(async move {
        mgr.start("researcher", requests, any_of_keep_losers_opts())
            .await
    });
    for _ in 0..4 {
        tokio::task::yield_now().await;
    }
    let session_id = manager.first_open_session_id_for_test().await;
    // Only the winner replies; slot 1 stays pending → materialized detached loser.
    reply_winner(&manager, &session_id, 0, "agent:t1").await;

    let result = start_handle.await.expect("spawn ok").expect("start ok");
    assert_eq!(
        result.replies.len(),
        2,
        "keep_losers=true materializes the pending loser (not dropped)"
    );
    assert_eq!(result.replies[0].slot, 0);
    assert!(matches!(result.replies[0].status, ReplyStatus::Completed));
    // Materialized detached loser: Cancelled + task-id SUBSTITUTED from the request context.
    assert_eq!(result.replies[1].slot, 1);
    assert!(matches!(result.replies[1].status, ReplyStatus::Cancelled));
    assert_eq!(result.replies[1].task_id.as_deref(), Some("task-x"));
    assert_eq!(result.replies[1].source, "agent:t2");
    assert!(result.replies[1].payload.is_empty());
}

// RT-detach-2: a pending loser whose request context carried NO task-id → CLEAR.
#[tokio::test(flavor = "current_thread")]
async fn t13d_detach_pending_loser_clears_task_id() {
    let mock = MockDispatcher::new();
    let dispatcher: Arc<dyn MailboxDispatcher> = mock.clone();
    let manager = Arc::new(AwaitSessionManagerImpl::new(
        dispatcher,
        ManagerOptions::default(),
    ));
    let requests = vec![
        make_agent_req("agent:t1", vec![], "c0"), // slot 0 winner
        make_agent_req_ctx("agent:t2", vec![], "c1", None), // slot 1 pending loser, context has no task-id
    ];
    let mgr = manager.clone();
    let start_handle = tokio::spawn(async move {
        mgr.start("researcher", requests, any_of_keep_losers_opts())
            .await
    });
    for _ in 0..4 {
        tokio::task::yield_now().await;
    }
    let session_id = manager.first_open_session_id_for_test().await;
    reply_winner(&manager, &session_id, 0, "agent:t1").await;

    let result = start_handle.await.expect("spawn ok").expect("start ok");
    assert_eq!(result.replies.len(), 2);
    assert_eq!(result.replies[1].slot, 1);
    assert!(matches!(result.replies[1].status, ReplyStatus::Cancelled));
    assert_eq!(
        result.replies[1].task_id, None,
        "no context task-id → cleared"
    );
}

// RT-detach-3: a terminal (Failed) loser recorded BEFORE the winner keeps its
// status; only the still-pending loser is materialized as detached.
#[tokio::test(flavor = "current_thread")]
async fn t13e_detach_keeps_terminal_loser_status() {
    let mock = MockDispatcher::new();
    let dispatcher: Arc<dyn MailboxDispatcher> = mock.clone();
    let manager = Arc::new(AwaitSessionManagerImpl::new(
        dispatcher,
        ManagerOptions::default(),
    ));
    let requests = vec![
        make_agent_req("agent:t1", vec![], "c0"), // slot 0 winner
        make_agent_req("agent:t2", vec![], "c1"), // slot 1 terminal loser (Failed, recorded first)
        make_agent_req("agent:t3", vec![], "c2"), // slot 2 pending loser
    ];
    let mgr = manager.clone();
    let start_handle = tokio::spawn(async move {
        mgr.start("researcher", requests, any_of_keep_losers_opts())
            .await
    });
    for _ in 0..4 {
        tokio::task::yield_now().await;
    }
    let session_id = manager.first_open_session_id_for_test().await;
    // Terminal loser (Failed) recorded FIRST — does not satisfy AnyOf is_complete.
    manager
        .on_reply(
            &session_id,
            1,
            ReplyResult {
                slot: 1,
                source: "agent:t2".to_string(),
                payload: vec![],
                status: ReplyStatus::Failed("agent-error:t2".to_string()),
                received_at: Utc::now(),
                task_id: None,
            },
        )
        .await
        .expect("terminal loser on_reply ok");
    // Winner LAST resolves the session; slot 2 is still pending.
    reply_winner(&manager, &session_id, 0, "agent:t1").await;

    let result = start_handle.await.expect("spawn ok").expect("start ok");
    assert_eq!(result.replies.len(), 3);
    assert!(matches!(result.replies[0].status, ReplyStatus::Completed)); // winner
                                                                         // Terminal loser UNCLOBBERED (kept Failed, not re-materialized as Cancelled).
    assert_eq!(result.replies[1].slot, 1);
    assert!(matches!(result.replies[1].status, ReplyStatus::Failed(_)));
    // Pending loser MATERIALIZED as detached.
    assert_eq!(result.replies[2].slot, 2);
    assert!(matches!(result.replies[2].status, ReplyStatus::Cancelled));
    assert_eq!(result.replies[2].source, "agent:t3");
}

// RT-detach-4: a pending ComponentFinished loser → materialized with
// `component:{id}` source and cleared task-id.
#[tokio::test(flavor = "current_thread")]
async fn t13f_detach_pending_component_loser() {
    let mock = MockDispatcher::new();
    let dispatcher: Arc<dyn MailboxDispatcher> = mock.clone();
    let manager = Arc::new(AwaitSessionManagerImpl::new(
        dispatcher,
        ManagerOptions::default(),
    ));
    let requests = vec![
        make_agent_req("agent:t1", vec![], "c0"), // slot 0 winner
        make_component_req("comp-x", "c1"),       // slot 1 pending ComponentFinished loser
    ];
    let mgr = manager.clone();
    let start_handle = tokio::spawn(async move {
        mgr.start("researcher", requests, any_of_keep_losers_opts())
            .await
    });
    for _ in 0..4 {
        tokio::task::yield_now().await;
    }
    let session_id = manager.first_open_session_id_for_test().await;
    reply_winner(&manager, &session_id, 0, "agent:t1").await;

    let result = start_handle.await.expect("spawn ok").expect("start ok");
    assert_eq!(result.replies.len(), 2);
    assert_eq!(result.replies[1].slot, 1);
    assert!(matches!(result.replies[1].status, ReplyStatus::Cancelled));
    assert_eq!(result.replies[1].source, "component:comp-x");
    assert_eq!(result.replies[1].task_id, None);
}
