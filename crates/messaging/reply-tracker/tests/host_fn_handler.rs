// Slice E (2026-05-24) — AC-11 + AC-21 integration tests for
// AwaitRepliesHandler + HeartbeatHandler (impl HostFunctionHandler colocated
// in reply-tracker per MODULE-007 §3.6 ADR-via-prose entry).
//
// Tests: T11a-T11g (HeartbeatHandler) + T21a-T21e (AwaitRepliesHandler).
// AC-12 tests live in orchestration_events.rs (event payload + reset invariants).

use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use advance_messaging::MailboxDispatcher;
use advance_reply_tracker::{
    AwaitRepliesHandler, AwaitSessionManager, AwaitSessionManagerImpl, HeartbeatHandler,
    ManagerOptions,
};
use advance_runtime::host_registry::{HostCallContext, HostFunctionHandler};
use advance_shared_types::await_session::{
    AgentAwaitRequest, AwaitMode, AwaitOptions, AwaitRequest, ComponentAwaitRequest, SessionId,
    TimeoutPolicy,
};
use advance_shared_types::event::Event;
use advance_shared_types::mailbox::{Message, MessageContext, MsgError, NotifyError};
use advance_shared_types::traits::EventBusEmit;
use async_trait::async_trait;
use wasmtime::component::Val;

// ─── Fixtures ──────────────────────────────────────────────────────────

#[derive(Default)]
struct RecordingEmitter {
    events: StdMutex<Vec<Event>>,
}
impl EventBusEmit for RecordingEmitter {
    fn emit(&self, event: Event) {
        self.events.lock().unwrap().push(event);
    }
}

/// Mock dispatcher that always returns Ok — manager dispatch slot path
/// succeeds, leaving the session in Open state waiting for replies.
struct OkDispatcher;

#[async_trait]
impl MailboxDispatcher for OkDispatcher {
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

fn test_ctx(agent_id: &str, function: &str) -> HostCallContext {
    HostCallContext {
        agent_id: agent_id.to_string(),
        trace_id: "tr-fresh-test".to_string(),
        turn_id: None,
        capability: "messaging".to_string(),
        function: function.to_string(),
        run_id: Some("run-X".to_string()),
        iteration: None,
    }
}

fn make_manager() -> Arc<AwaitSessionManagerImpl> {
    let dispatcher: Arc<dyn MailboxDispatcher> = Arc::new(OkDispatcher);
    Arc::new(AwaitSessionManagerImpl::new(
        dispatcher,
        ManagerOptions::default(),
    ))
}

fn agent_req(target: &str, correlation_id: &str) -> AwaitRequest {
    AwaitRequest::AgentRequest(AgentAwaitRequest {
        target: target.to_string(),
        payload: vec![],
        correlation_id: correlation_id.to_string(),
        context: None,
    })
}

fn component_req(component_id: &str, correlation_id: &str) -> AwaitRequest {
    AwaitRequest::ComponentFinished(ComponentAwaitRequest {
        component_id: component_id.to_string(),
        correlation_id: correlation_id.to_string(),
    })
}

fn default_options() -> AwaitOptions {
    AwaitOptions {
        mode: AwaitMode::AllOf,
        idle_timeout_secs: Some(60),
        on_idle_timeout: TimeoutPolicy::ReturnPartial,
        keep_losers: false,
    }
}

/// Spawn a start_with_run task that admits a session and waits.
fn spawn_open_session(
    manager: Arc<AwaitSessionManagerImpl>,
    caller: &str,
    requests: Vec<AwaitRequest>,
) -> tokio::task::JoinHandle<()> {
    let caller = caller.to_string();
    tokio::spawn(async move {
        let _ = manager
            .start_with_run(&caller, None, requests, default_options())
            .await;
    })
}

async fn wait_for_session_count(manager: &AwaitSessionManagerImpl, expected: usize) {
    for _ in 0..200 {
        if manager.session_count_for_test().await == expected {
            return;
        }
        tokio::task::yield_now().await;
    }
    panic!(
        "wait_for_session_count: expected {} sessions, got {}",
        expected,
        manager.session_count_for_test().await
    );
}

// ════════════════════════════════════════════════════════════════════════
// T11a-T11g: HeartbeatHandler (AC-11)
// ════════════════════════════════════════════════════════════════════════

/// T11a: no open sessions list `agent:t` as target → 0 events, Ok-unit return.
#[tokio::test]
async fn t11a_heartbeat_no_matching_sessions_emits_nothing() {
    let manager = make_manager();
    let emitter = Arc::new(RecordingEmitter::default());
    let handler = HeartbeatHandler::new(Arc::clone(&manager), emitter.clone());
    let ctx = test_ctx("agent:t", "agent-messaging::heartbeat");

    let result = handler
        .call(
            ctx,
            vec![Val::Option(Some(Box::new(Val::String("p1".into()))))],
            1,
        )
        .await
        .expect("handler returned Err");

    assert_eq!(result.len(), 1);
    assert!(matches!(result[0], Val::Result(Ok(None))));
    assert_eq!(emitter.events.lock().unwrap().len(), 0);
}

/// T11b: 1 open session with `agent:t` as target → 1 on_heartbeat call + 1 event.
#[tokio::test]
async fn t11b_heartbeat_one_session_one_event() {
    let manager = make_manager();
    let emitter = Arc::new(RecordingEmitter::default());
    let handler = HeartbeatHandler::new(Arc::clone(&manager), emitter.clone());

    let _join = spawn_open_session(
        Arc::clone(&manager),
        "a",
        vec![agent_req("agent:t", "corr-1")],
    );
    wait_for_session_count(&manager, 1).await;

    let ctx = test_ctx("agent:t", "agent-messaging::heartbeat");
    let result = handler
        .call(
            ctx,
            vec![Val::Option(Some(Box::new(Val::String("p1".into()))))],
            1,
        )
        .await
        .expect("handler returned Err");

    assert!(matches!(result[0], Val::Result(Ok(None))));
    let events = emitter.events.lock().unwrap();
    assert_eq!(events.len(), 1, "expected exactly 1 await_progress event");
    assert_eq!(events[0].event_type, "orchestration.await_progress");
    let payload = &events[0].payload;
    assert_eq!(payload["target"], "agent:t");
    assert_eq!(payload["progress"], "p1");
}

/// T11c: 2 open sessions where `agent:t` is a target → 2 events.
#[tokio::test]
async fn t11c_heartbeat_two_sessions_two_events() {
    let manager = make_manager();
    let emitter = Arc::new(RecordingEmitter::default());
    let handler = HeartbeatHandler::new(Arc::clone(&manager), emitter.clone());

    let _j1 = spawn_open_session(
        Arc::clone(&manager),
        "a",
        vec![agent_req("agent:t", "corr-a")],
    );
    let _j2 = spawn_open_session(
        Arc::clone(&manager),
        "b",
        vec![agent_req("agent:t", "corr-b")],
    );
    wait_for_session_count(&manager, 2).await;

    let ctx = test_ctx("agent:t", "agent-messaging::heartbeat");
    let result = handler
        .call(ctx, vec![Val::Option(None)], 1)
        .await
        .expect("handler returned Err");

    assert!(matches!(result[0], Val::Result(Ok(None))));
    let events = emitter.events.lock().unwrap();
    assert_eq!(events.len(), 2, "expected 2 await_progress events");
    for ev in events.iter() {
        assert_eq!(ev.event_type, "orchestration.await_progress");
        assert_eq!(ev.payload["target"], "agent:t");
    }
}

/// T11d: only `agent:other` is a target; ctx.agent_id = "agent:t" → 0 events.
#[tokio::test]
async fn t11d_heartbeat_from_target_authorization() {
    let manager = make_manager();
    let emitter = Arc::new(RecordingEmitter::default());
    let handler = HeartbeatHandler::new(Arc::clone(&manager), emitter.clone());

    let _join = spawn_open_session(
        Arc::clone(&manager),
        "a",
        vec![agent_req("agent:other", "corr-o")],
    );
    wait_for_session_count(&manager, 1).await;

    let ctx = test_ctx("agent:t", "agent-messaging::heartbeat");
    let _ = handler
        .call(ctx, vec![Val::Option(None)], 1)
        .await
        .expect("handler returned Err");

    assert_eq!(emitter.events.lock().unwrap().len(), 0);
}

/// T11e: session with `agent:t` as target but resolved via close() → 0 events.
#[tokio::test]
async fn t11e_heartbeat_filters_resolved_sessions() {
    let manager = make_manager();
    let emitter = Arc::new(RecordingEmitter::default());
    let handler = HeartbeatHandler::new(Arc::clone(&manager), emitter.clone());

    let _join = spawn_open_session(
        Arc::clone(&manager),
        "a",
        vec![agent_req("agent:t", "corr-r")],
    );
    wait_for_session_count(&manager, 1).await;

    // Discover the session id via probe, then close it. Probe also emits a
    // heartbeat event (1 reset on 1 matching session), so clear the recorder
    // after the probe completes.
    let session_ids: Vec<SessionId> = manager.heartbeat_for_target("agent:t", None).await;
    emitter.events.lock().unwrap().clear();
    for id in &session_ids {
        let _ = manager.close(id, "test-close").await;
    }
    wait_for_session_count(&manager, 0).await;

    let ctx = test_ctx("agent:t", "agent-messaging::heartbeat");
    let _ = handler
        .call(ctx, vec![Val::Option(None)], 1)
        .await
        .expect("handler returned Err");

    assert_eq!(emitter.events.lock().unwrap().len(), 0);
}

/// T11f: session with ComponentFinished slot, ctx.agent_id = "comp-x" → 0 events.
#[tokio::test]
async fn t11f_heartbeat_excludes_component_slots() {
    let manager = make_manager();
    let emitter = Arc::new(RecordingEmitter::default());
    let handler = HeartbeatHandler::new(Arc::clone(&manager), emitter.clone());

    let _join = spawn_open_session(
        Arc::clone(&manager),
        "a",
        vec![component_req("comp-x", "corr-c")],
    );
    wait_for_session_count(&manager, 1).await;

    let ctx = test_ctx("comp-x", "agent-messaging::heartbeat");
    let _ = handler
        .call(ctx, vec![Val::Option(None)], 1)
        .await
        .expect("handler returned Err");

    assert_eq!(
        emitter.events.lock().unwrap().len(),
        0,
        "ComponentFinished slots must not match heartbeat-for-target"
    );
}

/// T11g: HeartbeatHandler with malformed params → Ok-encoded msg-error::invalid-payload.
#[tokio::test]
async fn t11g_heartbeat_decode_fail_msg_error() {
    let manager = make_manager();
    let emitter = Arc::new(RecordingEmitter::default());
    let handler = HeartbeatHandler::new(manager, emitter.clone());

    let ctx = test_ctx("agent:t", "agent-messaging::heartbeat");
    let result = handler
        .call(ctx, vec![Val::S32(42)], 1)
        .await
        .expect("handler returned Err");

    match &result[0] {
        Val::Result(Err(Some(boxed))) => match boxed.as_ref() {
            Val::Variant(case, _) => {
                assert_eq!(case, "invalid-payload");
            }
            other => panic!("expected Variant(invalid-payload, ..), got {other:?}"),
        },
        other => panic!("expected Result(Err(..)), got {other:?}"),
    }
    assert_eq!(emitter.events.lock().unwrap().len(), 0);
}

// ════════════════════════════════════════════════════════════════════════
// T21a-T21e: AwaitRepliesHandler (AC-21 + decode-fail)
// ════════════════════════════════════════════════════════════════════════

fn val_agent_request(target: &str, correlation_id: &str) -> Val {
    Val::Variant(
        "agent-request".into(),
        Some(Box::new(Val::Record(vec![
            ("target".into(), Val::String(target.into())),
            ("payload".into(), Val::List(vec![])),
            ("correlation-id".into(), Val::String(correlation_id.into())),
            ("context".into(), Val::Option(None)),
        ]))),
    )
}

fn val_await_options_allof() -> Val {
    Val::Record(vec![
        ("mode".into(), Val::Variant("all-of".into(), None)),
        ("idle-timeout-secs".into(), Val::Option(None)),
        (
            "on-idle-timeout".into(),
            Val::Variant("return-partial".into(), None),
        ),
        ("keep-losers".into(), Val::Bool(false)),
    ])
}

/// T21d: malformed params → Ok-encoded orchestration-error::invalid-target("internal:...").
#[tokio::test]
async fn t21d_await_replies_decode_fail_orchestration_error() {
    let manager = make_manager();
    let handler = AwaitRepliesHandler::new(manager);
    let ctx = test_ctx("a", "agent-messaging::await-replies");

    let result = handler
        .call(ctx, vec![Val::S32(42)], 1)
        .await
        .expect("handler returned Err");

    match &result[0] {
        Val::Result(Err(Some(boxed))) => match boxed.as_ref() {
            Val::Variant(case, payload) => {
                assert_eq!(case, "invalid-target");
                if let Some(p) = payload {
                    if let Val::String(s) = p.as_ref() {
                        assert!(
                            s.starts_with("internal:invalid-request:"),
                            "unexpected msg: {s}"
                        );
                    } else {
                        panic!("expected String payload");
                    }
                } else {
                    panic!("expected Some payload");
                }
            }
            other => panic!("expected Variant(invalid-target, ..), got {other:?}"),
        },
        other => panic!("expected Result(Err(..)), got {other:?}"),
    }
}

/// T21b: SessionClosed error returns Ok-encoded orchestration-error::session-closed.
/// Spawn handler; close session externally; handler resolves with Err(SessionClosed).
#[tokio::test]
async fn t21b_await_replies_session_closed_whole_call_err() {
    let manager = make_manager();
    let handler = AwaitRepliesHandler::new(Arc::clone(&manager));
    let ctx = test_ctx("a", "agent-messaging::await-replies");

    let params = vec![
        Val::List(vec![val_agent_request("agent:t", "corr-1")]),
        val_await_options_allof(),
    ];

    let handler_arc = Arc::new(handler);
    let h_for_task = Arc::clone(&handler_arc);
    let join =
        tokio::spawn(async move { h_for_task.call(ctx, params, 1).await.expect("handler Err") });

    wait_for_session_count(&manager, 1).await;

    let session_ids = manager.heartbeat_for_target("agent:t", None).await;
    assert_eq!(session_ids.len(), 1);
    let _ = manager.close(&session_ids[0], "cancel-cascade").await;

    let result = tokio::time::timeout(Duration::from_secs(2), join)
        .await
        .expect("handler timed out")
        .expect("join panic");

    match &result[0] {
        Val::Result(Err(Some(boxed))) => match boxed.as_ref() {
            Val::Variant(case, payload) => {
                assert_eq!(case, "session-closed");
                if let Some(p) = payload {
                    if let Val::String(s) = p.as_ref() {
                        assert!(s.contains("cancel-cascade"), "unexpected msg: {s}");
                    }
                }
            }
            other => panic!("expected Variant(session-closed, ..), got {other:?}"),
        },
        other => panic!("expected Result(Err(..)), got {other:?}"),
    }
}

/// T21c: HeartbeatHandler emits exactly 1 await_progress (cross-link from T11b).
#[tokio::test]
async fn t21c_heartbeat_emits_await_progress_event() {
    let manager = make_manager();
    let emitter = Arc::new(RecordingEmitter::default());
    let handler = HeartbeatHandler::new(Arc::clone(&manager), emitter.clone());

    let _join = spawn_open_session(
        Arc::clone(&manager),
        "a",
        vec![agent_req("agent:t", "corr-21c")],
    );
    wait_for_session_count(&manager, 1).await;

    let ctx = test_ctx("agent:t", "agent-messaging::heartbeat");
    let _ = handler.call(ctx, vec![Val::Option(None)], 1).await;

    let events = emitter.events.lock().unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].event_type, "orchestration.await_progress");
}

/// T21a: per-slot Failed survives Val encoding (mock dispatcher rejects target).
#[tokio::test]
async fn t21a_await_replies_invalid_target_per_slot() {
    struct InvalidTargetDispatcher;
    #[async_trait]
    impl MailboxDispatcher for InvalidTargetDispatcher {
        async fn deliver(&self, target: &str, _msg: Message) -> Result<(), MsgError> {
            if target == "agent:zzz" {
                Err(MsgError::InvalidTarget("agent:zzz".into()))
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

    let dispatcher: Arc<dyn MailboxDispatcher> = Arc::new(InvalidTargetDispatcher);
    let manager = Arc::new(AwaitSessionManagerImpl::new(
        dispatcher,
        ManagerOptions::default(),
    ));
    let handler = AwaitRepliesHandler::new(manager);
    let ctx = test_ctx("a", "agent-messaging::await-replies");

    let params = vec![
        Val::List(vec![val_agent_request("agent:zzz", "corr-bad")]),
        val_await_options_allof(),
    ];

    let result = handler
        .call(ctx, params, 1)
        .await
        .expect("handler returned Err");

    match &result[0] {
        Val::Result(Ok(Some(boxed))) => match boxed.as_ref() {
            Val::Record(fields) => {
                let completed_all = fields.iter().find(|(n, _)| n == "completed-all");
                assert!(
                    matches!(completed_all, Some((_, Val::Bool(true)))),
                    "expected completed-all=true (all-failed-dispatch fast path)"
                );
                let replies = fields.iter().find(|(n, _)| n == "replies");
                if let Some((_, Val::List(items))) = replies {
                    assert_eq!(items.len(), 1, "expected 1 reply slot");
                    if let Val::Record(rfields) = &items[0] {
                        let status = rfields.iter().find(|(n, _)| n == "status");
                        if let Some((_, Val::Variant(case, payload))) = status {
                            assert_eq!(case, "error");
                            if let Some(p) = payload {
                                if let Val::String(s) = p.as_ref() {
                                    assert!(
                                        s.contains("invalid-target"),
                                        "unexpected per-slot reason: {s}"
                                    );
                                }
                            }
                        }
                    }
                }
            }
            other => panic!("expected Record, got {other:?}"),
        },
        other => panic!("expected Result(Ok(Some(..))), got {other:?}"),
    }
}

/// T21e: all-failed-dispatch fast path with multiple targets → completed-all=true.
#[tokio::test]
async fn t21e_await_replies_all_failed_dispatch_completed_all_true() {
    struct AllFailDispatcher;
    #[async_trait]
    impl MailboxDispatcher for AllFailDispatcher {
        async fn deliver(&self, _target: &str, _msg: Message) -> Result<(), MsgError> {
            Err(MsgError::InvalidTarget("any".into()))
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

    let dispatcher: Arc<dyn MailboxDispatcher> = Arc::new(AllFailDispatcher);
    let manager = Arc::new(AwaitSessionManagerImpl::new(
        dispatcher,
        ManagerOptions::default(),
    ));
    let handler = AwaitRepliesHandler::new(manager);
    let ctx = test_ctx("a", "agent-messaging::await-replies");

    let params = vec![
        Val::List(vec![
            val_agent_request("agent:t1", "corr-1"),
            val_agent_request("agent:t2", "corr-2"),
        ]),
        val_await_options_allof(),
    ];

    let result = handler
        .call(ctx, params, 1)
        .await
        .expect("handler returned Err");

    match &result[0] {
        Val::Result(Ok(Some(boxed))) => match boxed.as_ref() {
            Val::Record(fields) => {
                let completed_all = fields.iter().find(|(n, _)| n == "completed-all");
                assert!(matches!(completed_all, Some((_, Val::Bool(true)))));
                let replies = fields.iter().find(|(n, _)| n == "replies");
                if let Some((_, Val::List(items))) = replies {
                    assert_eq!(items.len(), 2);
                    for item in items {
                        if let Val::Record(rfields) = item {
                            let status = rfields.iter().find(|(n, _)| n == "status");
                            assert!(
                                matches!(status, Some((_, Val::Variant(c, _))) if c == "error"),
                                "expected error status, got {status:?}"
                            );
                        }
                    }
                }
            }
            other => panic!("expected Record, got {other:?}"),
        },
        other => panic!("expected Result(Ok(Some(..))), got {other:?}"),
    }
}
