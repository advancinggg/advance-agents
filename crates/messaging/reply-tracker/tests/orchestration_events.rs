// Slice E (2026-05-24) — AC-12 integration tests + T17z byte-parity assertion.

use std::sync::{Arc, Mutex as StdMutex};

use advance_messaging::MailboxDispatcher;
use advance_reply_tracker::{
    AwaitSessionManagerImpl, HeartbeatHandler, ManagerOptions, AWAIT_PROGRESS,
};
use advance_runtime::host_registry::{HostCallContext, HostFunctionHandler};
use advance_shared_types::await_session::{
    AgentAwaitRequest, AwaitMode, AwaitOptions, AwaitRequest, OrchestrationError, TimeoutPolicy,
};
use advance_shared_types::event::Event;
use advance_shared_types::mailbox::{Message, MessageContext, MsgError, NotifyError};
use advance_shared_types::traits::EventBusEmit;
use async_trait::async_trait;
use wasmtime::component::Val;

#[derive(Default)]
struct RecordingEmitter {
    events: StdMutex<Vec<Event>>,
}
impl EventBusEmit for RecordingEmitter {
    fn emit(&self, event: Event) {
        self.events.lock().unwrap().push(event);
    }
}

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

fn test_ctx(agent_id: &str, trace_id: &str, run_id: Option<&str>) -> HostCallContext {
    HostCallContext {
        agent_id: agent_id.to_string(),
        trace_id: trace_id.to_string(),
        turn_id: None,
        capability: "messaging".to_string(),
        function: "agent-messaging::heartbeat".to_string(),
        run_id: run_id.map(|s| s.to_string()),
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

fn options_with_idle(secs: u32) -> AwaitOptions {
    AwaitOptions {
        mode: AwaitMode::AllOf,
        idle_timeout_secs: Some(secs),
        on_idle_timeout: TimeoutPolicy::ReturnPartial,
        keep_losers: false,
    }
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

fn spawn_open_session(
    manager: Arc<AwaitSessionManagerImpl>,
    caller: &str,
    target: &str,
    correlation_id: &str,
) -> tokio::task::JoinHandle<()> {
    let caller = caller.to_string();
    let target = target.to_string();
    let correlation_id = correlation_id.to_string();
    tokio::spawn(async move {
        let _ = manager
            .start_with_run(
                &caller,
                None,
                vec![agent_req(&target, &correlation_id)],
                options_with_idle(60),
            )
            .await;
    })
}

/// T12a: reset via HeartbeatHandler emits await_progress AND session stays Open.
#[tokio::test]
async fn t12a_heartbeat_conjunction_emit_and_session_open() {
    let manager = make_manager();
    let emitter = Arc::new(RecordingEmitter::default());
    let handler = HeartbeatHandler::new(Arc::clone(&manager), emitter.clone());

    let _join = spawn_open_session(Arc::clone(&manager), "a", "agent:t", "corr-12a");
    wait_for_session_count(&manager, 1).await;

    let ctx = test_ctx("agent:t", "tr-12a", Some("run-12a"));
    let _ = handler
        .call(
            ctx,
            vec![Val::Option(Some(Box::new(Val::String("p1".into()))))],
            1,
        )
        .await;

    // EMIT-half: 1 event.
    let events = emitter.events.lock().unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].event_type, AWAIT_PROGRESS);
    // RESET-half: session still Open (not idle-timed-out).
    assert_eq!(manager.session_count_for_test().await, 1);
}

/// T12b: progress=None → payload progress field is JSON null.
#[tokio::test]
async fn t12b_heartbeat_none_progress_payload_null() {
    let manager = make_manager();
    let emitter = Arc::new(RecordingEmitter::default());
    let handler = HeartbeatHandler::new(Arc::clone(&manager), emitter.clone());

    let _join = spawn_open_session(Arc::clone(&manager), "a", "agent:t", "corr-12b");
    wait_for_session_count(&manager, 1).await;

    let ctx = test_ctx("agent:t", "tr-12b", None);
    let _ = handler.call(ctx, vec![Val::Option(None)], 1).await;

    let events = emitter.events.lock().unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].payload["progress"], serde_json::Value::Null);
}

/// T12c: envelope fields populated from HostCallContext.
#[tokio::test]
async fn t12c_heartbeat_envelope_fields() {
    let manager = make_manager();
    let emitter = Arc::new(RecordingEmitter::default());
    let handler = HeartbeatHandler::new(Arc::clone(&manager), emitter.clone());

    let _join = spawn_open_session(Arc::clone(&manager), "a", "agent:t", "corr-12c");
    wait_for_session_count(&manager, 1).await;

    let ctx = test_ctx("agent:t", "tr-fresh-123", Some("run-X"));
    let _ = handler.call(ctx, vec![Val::Option(None)], 1).await;

    let events = emitter.events.lock().unwrap();
    assert_eq!(events.len(), 1);
    let ev = &events[0];
    assert_eq!(ev.agent_id, "agent:t");
    assert_eq!(ev.trace_id, "tr-fresh-123");
    assert_eq!(ev.run_id, Some("run-X".to_string()));
    assert_eq!(ev.task_id, None);
    assert_eq!(ev.execution_id, None);
    assert_eq!(ev.parent_span_id, None);
    assert_eq!(ev.event_type, "orchestration.await_progress");
}

/// T17z: byte-parity assertion against canonical event-bus taxonomy.
/// (Production code defines AWAIT_PROGRESS locally; dev-dep import here.)
/// NOT an AC-17 verification — AC-17 requires all 7 events; this pins ONE.
#[test]
fn t17z_event_type_constant_byte_parity() {
    assert_eq!(
        AWAIT_PROGRESS.as_bytes(),
        advance_event_bus::taxonomy::orchestration::AWAIT_PROGRESS.as_bytes()
    );
}

// ════════════════════════════════════════════════════════════════════════
// Wave-15 Lane A — deadlock_rejected + await_idle_timeout consts/emit (3 of 7).
// ════════════════════════════════════════════════════════════════════════

/// T17z2: byte-parity for the two Wave-15 consts against the canonical taxonomy
/// (the `deadlock_rejected`/`await_idle_timeout` analog of T17z). Pins the
/// canonical event string SYS-AC-169/252 witness against (e.g. SYS-AC-252's
/// criterion "idle_timeout" shorthand → canonical `await_idle_timeout`).
#[test]
fn t17z2_deadlock_idle_const_byte_parity() {
    use advance_reply_tracker::{AWAIT_IDLE_TIMEOUT, DEADLOCK_REJECTED};
    assert_eq!(
        DEADLOCK_REJECTED.as_bytes(),
        advance_event_bus::taxonomy::orchestration::DEADLOCK_REJECTED.as_bytes()
    );
    assert_eq!(
        AWAIT_IDLE_TIMEOUT.as_bytes(),
        advance_event_bus::taxonomy::orchestration::AWAIT_IDLE_TIMEOUT.as_bytes()
    );
}

fn make_manager_with_emitter(
    emitter: Arc<RecordingEmitter>,
    idle_default_sec: u32,
) -> Arc<AwaitSessionManagerImpl> {
    let dispatcher: Arc<dyn MailboxDispatcher> = Arc::new(OkDispatcher);
    let dyn_emitter: Arc<dyn EventBusEmit> = emitter;
    Arc::new(AwaitSessionManagerImpl::new(
        dispatcher,
        ManagerOptions {
            idle_timeout_default_sec: idle_default_sec,
            event_emitter: Some(dyn_emitter),
            ..ManagerOptions::default()
        },
    ))
}

/// SYS-AC-252 module-level emit witness: a parked ReturnPartial AllOf session +
/// `on_idle_timeout_for_test` (the REAL `resolve_idle` body) emits exactly one
/// `orchestration.await_idle_timeout` — empty trace_id (session-stable
/// envelope), agent_id = bare caller, payload `{session_id, target, idle_seconds}`.
#[tokio::test]
async fn idle_return_partial_emits_await_idle_timeout() {
    let emitter = Arc::new(RecordingEmitter::default());
    let manager = make_manager_with_emitter(emitter.clone(), 30);
    let _join = spawn_open_session(Arc::clone(&manager), "researcher", "agent:t", "corr-idle");
    wait_for_session_count(&manager, 1).await;
    let sid = manager.first_open_session_id_for_test().await;

    manager.on_idle_timeout_for_test(&sid).await;

    let events = emitter.events.lock().unwrap();
    let idle: Vec<&Event> = events
        .iter()
        .filter(|e| e.event_type == "orchestration.await_idle_timeout")
        .collect();
    assert_eq!(
        idle.len(),
        1,
        "exactly one await_idle_timeout, got {events:?}"
    );
    let ev = idle[0];
    assert_eq!(ev.trace_id, "", "session-stable envelope ⇒ empty trace_id");
    assert_eq!(ev.agent_id, "researcher", "agent_id = bare caller");
    assert_eq!(
        ev.payload["session_id"],
        serde_json::Value::String(sid.0.clone())
    );
    // spawn_open_session uses options_with_idle(60) (the per-request value).
    assert_eq!(ev.payload["idle_seconds"], serde_json::json!(60));
    // target = the single AgentRequest slot's source, filled TimedOut.
    assert_eq!(
        ev.payload["target"],
        serde_json::Value::String("agent:t".to_string())
    );
}

/// The `Fail` timeout policy emits NO `await_idle_timeout` (the event is the
/// `ReturnPartial`-arm behavior — SYS-AC-252 is ReturnPartial-specific).
#[tokio::test]
async fn idle_fail_policy_emits_no_event() {
    let emitter = Arc::new(RecordingEmitter::default());
    let manager = make_manager_with_emitter(emitter.clone(), 30);
    let m = Arc::clone(&manager);
    let _join = tokio::spawn(async move {
        let opts = AwaitOptions {
            mode: AwaitMode::AllOf,
            idle_timeout_secs: Some(45),
            on_idle_timeout: TimeoutPolicy::Fail,
            keep_losers: false,
        };
        let _ = m
            .start_with_run("a", None, vec![agent_req("agent:t", "corr-fail")], opts)
            .await;
    });
    wait_for_session_count(&manager, 1).await;
    let sid = manager.first_open_session_id_for_test().await;

    manager.on_idle_timeout_for_test(&sid).await;

    let n = emitter
        .events
        .lock()
        .unwrap()
        .iter()
        .filter(|e| e.event_type == "orchestration.await_idle_timeout")
        .count();
    assert_eq!(n, 0, "Fail policy emits no await_idle_timeout");
}

/// Default `ManagerOptions` (no `event_emitter`) → the idle path is inert: no
/// panic, no emit, session still resolves. (The additive `None` default keeps
/// the existing emitter-less tests byte-green.)
#[tokio::test]
async fn idle_no_emitter_is_inert() {
    let manager = make_manager(); // ManagerOptions::default() ⇒ event_emitter None
    let _join = spawn_open_session(Arc::clone(&manager), "a", "agent:t", "corr-none");
    wait_for_session_count(&manager, 1).await;
    let sid = manager.first_open_session_id_for_test().await;

    manager.on_idle_timeout_for_test(&sid).await; // must not panic with no emitter

    assert_eq!(
        manager.session_count_for_test().await,
        0,
        "idle resolution removed the session even with no emitter"
    );
}

// ════════════════════════════════════════════════════════════════════════
// Wave-20 Lane `messagingabi` — the 4 remaining orchestration.* events
// (await_started / await_satisfied / await_session_closed / reply_late),
// closing AC-17 (all 7), + AC-13 rule (1) host-internal winner task-id witness.
// ════════════════════════════════════════════════════════════════════════

use advance_reply_tracker::{
    AwaitSessionManager, AWAIT_SATISFIED, AWAIT_SESSION_CLOSED, AWAIT_STARTED, REPLY_LATE,
};
use advance_shared_types::await_session::{ReplyResult, ReplyStatus};

/// T17z3: byte-parity for the 4 NEW consts against the canonical taxonomy
/// (the await_started/await_satisfied/await_session_closed/reply_late analog of
/// T17z / T17z2). Defends against a silent taxonomy drift on the new consts.
#[test]
fn t17z3_new_event_const_byte_parity() {
    use advance_event_bus::taxonomy::orchestration as tax;
    assert_eq!(AWAIT_STARTED.as_bytes(), tax::AWAIT_STARTED.as_bytes());
    assert_eq!(AWAIT_SATISFIED.as_bytes(), tax::AWAIT_SATISFIED.as_bytes());
    assert_eq!(
        AWAIT_SESSION_CLOSED.as_bytes(),
        tax::AWAIT_SESSION_CLOSED.as_bytes()
    );
    assert_eq!(REPLY_LATE.as_bytes(), tax::REPLY_LATE.as_bytes());
}

fn agent_req_ctx(target: &str, correlation_id: &str, task_id: Option<&str>) -> AwaitRequest {
    AwaitRequest::AgentRequest(AgentAwaitRequest {
        target: target.to_string(),
        payload: vec![],
        correlation_id: correlation_id.to_string(),
        context: task_id.map(|t| MessageContext {
            task_id: Some(t.to_string()),
            run_id: None,
            execution_id: None,
            trace_id: None,
            in_reply_to: None,
            correlation_id: None,
        }),
    })
}

fn winning_reply(slot: u32, source: &str) -> ReplyResult {
    ReplyResult {
        slot,
        source: source.to_string(),
        payload: b"ok".to_vec(),
        status: ReplyStatus::Completed,
        received_at: chrono::Utc::now(),
        // Intentionally None: on_reply OVERRIDES task_id from the originating
        // request's context. A caller-supplied value here must NOT survive
        // (proves the host-authoritative population at the chokepoint).
        task_id: Some("caller-supplied-should-be-overridden".to_string()),
    }
}

fn events_of<'a>(emitter: &'a RecordingEmitter, ty: &str) -> Vec<Event> {
    emitter
        .events
        .lock()
        .unwrap()
        .iter()
        .filter(|e| e.event_type == ty)
        .cloned()
        .collect()
}

/// T17a/T17b: a successful AllOf await emits exactly one `await_started` (at
/// admission) + exactly one `await_satisfied` (at the Completed terminal), both
/// with the session-stable empty-trace_id envelope. AC-13 rule 1 (host-internal):
/// the winner's resolved `ReplyResult.task_id` is the ORIGINATING request's
/// context task-id (`task-7`), NOT the caller-supplied value (overridden at the
/// on_reply chokepoint). Field-absent discriminator: a no-context request →
/// winner `task_id == None`.
#[tokio::test]
async fn wave20_await_started_satisfied_and_task_id_preserved() {
    let emitter = Arc::new(RecordingEmitter::default());
    let manager = make_manager_with_emitter(emitter.clone(), 60);

    // Spawn the parked await; capture its AwaitResult on completion.
    let m = Arc::clone(&manager);
    let join: tokio::task::JoinHandle<advance_shared_types::await_session::AwaitResult> =
        tokio::spawn(async move {
            m.start_with_run(
                "researcher",
                Some("run-9"),
                vec![agent_req_ctx("agent:t", "corr-w20", Some("task-7"))],
                options_with_idle(60),
            )
            .await
            .expect("await resolves Completed")
        });

    wait_for_session_count(&manager, 1).await;
    // await_started fired at admission (before any reply).
    let started = events_of(&emitter, AWAIT_STARTED);
    assert_eq!(started.len(), 1, "exactly one await_started at admission");
    assert_eq!(started[0].trace_id, "", "session-stable ⇒ empty trace_id");
    assert_eq!(started[0].agent_id, "researcher");
    assert_eq!(started[0].run_id, Some("run-9".to_string()));
    assert_eq!(started[0].payload["mode"], serde_json::json!("all-of"));
    assert_eq!(started[0].payload["targets"], serde_json::json!(1));

    let sid = manager.first_open_session_id_for_test().await;
    manager
        .on_reply(&sid, 0, winning_reply(0, "agent:t"))
        .await
        .expect("on_reply ok");

    let result = join.await.expect("join");

    // await_satisfied: exactly one, empty trace_id, envelope.
    let satisfied = events_of(&emitter, AWAIT_SATISFIED);
    assert_eq!(satisfied.len(), 1, "exactly one await_satisfied");
    assert_eq!(satisfied[0].trace_id, "");
    assert_eq!(satisfied[0].agent_id, "researcher");
    assert_eq!(satisfied[0].payload["mode"], serde_json::json!("all-of"));
    assert_eq!(satisfied[0].payload["replies"], serde_json::json!(1));

    // AC-13 rule 1 (host-internal): winner task-id preserved from the request
    // context, OVERRIDING the caller-supplied value.
    assert_eq!(result.replies.len(), 1);
    assert_eq!(
        result.replies[0].task_id,
        Some("task-7".to_string()),
        "winner ReplyResult.task_id == originating request context task-id"
    );
}

/// AC-13 field-absent discriminator: a request with NO context → winner
/// `task_id == None` (so the assertion above is load-bearing, not vacuous).
#[tokio::test]
async fn wave20_no_context_winner_task_id_none() {
    let emitter = Arc::new(RecordingEmitter::default());
    let manager = make_manager_with_emitter(emitter.clone(), 60);
    let m = Arc::clone(&manager);
    let join: tokio::task::JoinHandle<advance_shared_types::await_session::AwaitResult> =
        tokio::spawn(async move {
            m.start_with_run(
                "a",
                None,
                vec![agent_req("agent:t", "corr-noctx")], // context: None
                options_with_idle(60),
            )
            .await
            .expect("resolves")
        });
    wait_for_session_count(&manager, 1).await;
    let sid = manager.first_open_session_id_for_test().await;
    manager
        .on_reply(&sid, 0, winning_reply(0, "agent:t"))
        .await
        .expect("on_reply ok");
    let result = join.await.expect("join");
    assert_eq!(result.replies[0].task_id, None);
}

/// T17c: `close()` emits exactly one `await_session_closed` (reason carried),
/// and NO `await_satisfied`.
#[tokio::test]
async fn wave20_await_session_closed() {
    let emitter = Arc::new(RecordingEmitter::default());
    let manager = make_manager_with_emitter(emitter.clone(), 60);
    let _join = {
        let m = Arc::clone(&manager);
        tokio::spawn(async move {
            let _ = m
                .start_with_run(
                    "closer",
                    Some("run-c"),
                    vec![agent_req("agent:t", "corr-close")],
                    options_with_idle(60),
                )
                .await;
        })
    };
    wait_for_session_count(&manager, 1).await;
    let sid = manager.first_open_session_id_for_test().await;
    manager.close(&sid, "cancel-run").await.expect("close ok");

    let closed = events_of(&emitter, AWAIT_SESSION_CLOSED);
    assert_eq!(closed.len(), 1, "exactly one await_session_closed");
    assert_eq!(closed[0].trace_id, "");
    assert_eq!(closed[0].agent_id, "closer");
    assert_eq!(closed[0].payload["reason"], serde_json::json!("cancel-run"));
    assert_eq!(
        events_of(&emitter, AWAIT_SATISFIED).len(),
        0,
        "close is not a satisfaction"
    );
}

/// T17d / AC-17 orphan path (NOT production AC-13 rule 4 for child `send`): a reply for an already-resolved session emits exactly one
/// `reply_late` (sanitized source), the late reply is NOT routed (the call
/// returns NotFound), and NO second `await_satisfied` fires.
#[tokio::test]
async fn wave20_reply_late_orphan_not_routed() {
    let emitter = Arc::new(RecordingEmitter::default());
    let manager = make_manager_with_emitter(emitter.clone(), 60);
    let m = Arc::clone(&manager);
    let join: tokio::task::JoinHandle<()> = tokio::spawn(async move {
        let _ = m
            .start_with_run(
                "a",
                None,
                vec![agent_req("agent:t", "corr-late")],
                options_with_idle(60),
            )
            .await;
    });
    wait_for_session_count(&manager, 1).await;
    let sid = manager.first_open_session_id_for_test().await;

    // Resolve the session (winner).
    manager
        .on_reply(&sid, 0, winning_reply(0, "agent:t"))
        .await
        .expect("first on_reply resolves");
    let _ = join.await;
    let satisfied_after_resolve = events_of(&emitter, AWAIT_SATISFIED).len();
    assert_eq!(satisfied_after_resolve, 1);

    // A LATE reply for the now-removed session → reply_late + NotFound, not routed.
    let late = manager.on_reply(&sid, 0, winning_reply(0, "agent:t")).await;
    assert!(
        matches!(late, Err(OrchestrationError::NotFound(_))),
        "late reply returns NotFound (not routed), got {late:?}"
    );
    let reply_late = events_of(&emitter, REPLY_LATE);
    assert_eq!(reply_late.len(), 1, "exactly one reply_late");
    assert_eq!(reply_late[0].trace_id, "");
    assert_eq!(
        reply_late[0].payload["session_id"],
        serde_json::json!(sid.0)
    );
    assert_eq!(reply_late[0].payload["slot"], serde_json::json!(0));
    // NOT routed: no SECOND await_satisfied.
    assert_eq!(
        events_of(&emitter, AWAIT_SATISFIED).len(),
        1,
        "late reply did not trigger a second satisfaction"
    );
}
