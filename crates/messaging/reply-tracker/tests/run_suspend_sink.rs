// Backbone Step 4b (2026-06-08) — reply-tracker unit/integration tests for the
// await↔run-manager suspend/resume seam:
//   * MODULE-007-T20a — `start_with_run_and_session` caller-minted-sid parity +
//     `on_park` genuine-park-only (all-failed-dispatch → on_park NOT fired).
//   * SYS-AC-017 race-fix — `AwaitRepliesHandler` suspends on park, resumes ONLY
//     on a genuine reply-completion `Ok`, and SKIPS resume on `Err(SessionClosed)`.
//   * MODULE-007-T23a — `AwaitSessionManagerRef::close` resolves a parked `start`
//     with `SessionClosed`; idempotent (2nd call `Err(NotFound)`, propagated).
//
// These use a MOCK `RunSuspendSink` (records calls); the REAL `RunManager`-backed
// adapter + the full e2e flips (SYS-AC-015/016/017) are witnessed test-side in the
// `system-acceptance` crate.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use async_trait::async_trait;

use advance_messaging::MailboxDispatcher;
use advance_reply_tracker::{
    await_session_ref::AwaitSessionManagerRef, AwaitRepliesHandler, AwaitSessionManager,
    AwaitSessionManagerImpl, ManagerOptions, RunSuspendSink,
};
use advance_runtime::host_registry::{HostCallContext, HostFunctionHandler};
use advance_shared_types::await_session::{
    AgentAwaitRequest, AwaitMode, AwaitOptions, AwaitRequest, AwaitSessionRef, AwaitSessionStatus,
    OrchestrationError, ReplyResult, ReplyStatus, SessionId, TimeoutPolicy,
};
use advance_shared_types::mailbox::{Message, MessageContext, MsgError, NotifyError};
use wasmtime::component::Val;

// ─── Fixtures ──────────────────────────────────────────────────────────

/// Dispatcher whose `deliver` succeeds → slot dispatch OK → the session parks
/// (Open) waiting for replies (the genuine-park path).
struct OkDispatcher;
#[async_trait]
impl MailboxDispatcher for OkDispatcher {
    async fn deliver(&self, _t: &str, _m: Message) -> Result<(), MsgError> {
        Ok(())
    }
    async fn reply(&self, _f: &str, _id: &str, _p: Vec<u8>) -> Result<(), MsgError> {
        Ok(())
    }
    async fn notify_agent(
        &self,
        _f: &str,
        _t: &str,
        _p: Vec<u8>,
        _c: Option<MessageContext>,
    ) -> Result<(), NotifyError> {
        Ok(())
    }
}

/// Dispatcher whose `deliver` FAILS → every slot fails dispatch → the
/// all-failed synchronous fast-path return fires BEFORE `rx.await` (no park).
struct FailDispatcher;
#[async_trait]
impl MailboxDispatcher for FailDispatcher {
    async fn deliver(&self, _t: &str, _m: Message) -> Result<(), MsgError> {
        Err(MsgError::MailboxFull)
    }
    async fn reply(&self, _f: &str, _id: &str, _p: Vec<u8>) -> Result<(), MsgError> {
        Err(MsgError::MailboxFull)
    }
    async fn notify_agent(
        &self,
        _f: &str,
        _t: &str,
        _p: Vec<u8>,
        _c: Option<MessageContext>,
    ) -> Result<(), NotifyError> {
        Err(NotifyError::MailboxFull)
    }
}

/// Mock `RunSuspendSink` recording suspend/resume calls; `on_await_start`
/// returns `true` (suspend "succeeded").
#[derive(Default)]
struct RecordingSink {
    started: StdMutex<Vec<String>>,
    resolved: StdMutex<Vec<String>>,
}
impl RunSuspendSink for RecordingSink {
    fn on_await_start(&self, run_id: &str, _sid: &SessionId) -> bool {
        self.started.lock().unwrap().push(run_id.to_string());
        true
    }
    fn on_await_resolve(&self, run_id: &str, _sid: &SessionId) {
        self.resolved.lock().unwrap().push(run_id.to_string());
    }
}

fn manager_with(dispatcher: Arc<dyn MailboxDispatcher>) -> Arc<AwaitSessionManagerImpl> {
    Arc::new(AwaitSessionManagerImpl::new(
        dispatcher,
        ManagerOptions::default(),
    ))
}

fn agent_req(target: &str, corr: &str) -> AwaitRequest {
    AwaitRequest::AgentRequest(AgentAwaitRequest {
        target: target.to_string(),
        payload: vec![],
        correlation_id: corr.to_string(),
        context: None,
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

fn val_agent_request(target: &str, corr: &str) -> Val {
    Val::Variant(
        "agent-request".into(),
        Some(Box::new(Val::Record(vec![
            ("target".into(), Val::String(target.into())),
            ("payload".into(), Val::List(vec![])),
            ("correlation-id".into(), Val::String(corr.into())),
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

/// AllOf await options with the `Fail` idle-timeout policy (idle timeout resolves
/// the parked `start` with `Err(IdleTimeoutExceeded)`).
fn val_await_options_fail() -> Val {
    Val::Record(vec![
        ("mode".into(), Val::Variant("all-of".into(), None)),
        (
            "idle-timeout-secs".into(),
            Val::Option(Some(Box::new(Val::U32(60)))),
        ),
        ("on-idle-timeout".into(), Val::Variant("fail".into(), None)),
        ("keep-losers".into(), Val::Bool(false)),
    ])
}

fn ctx_with_run(agent_id: &str, run_id: Option<&str>) -> HostCallContext {
    HostCallContext {
        agent_id: agent_id.to_string(),
        trace_id: "tr-fresh".to_string(),
        turn_id: None,
        capability: "messaging".to_string(),
        function: "agent-messaging::await-replies".to_string(),
        run_id: run_id.map(|r| r.to_string()),
        iteration: None,
    }
}

async fn wait_for_session_count(manager: &AwaitSessionManagerImpl, expected: usize) {
    // Real-time sleep (not yield_now): robust under heavy parallel test load where
    // a runtime-local yield may not give a spawned task enough wall-clock time.
    for _ in 0..2000 {
        if manager.session_count_for_test().await == expected {
            return;
        }
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    panic!("session count never reached {expected}");
}

async fn wait_for_flag(flag: &Arc<AtomicBool>) {
    for _ in 0..2000 {
        if flag.load(Ordering::SeqCst) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    panic!("flag never set");
}

/// Wait until the sink has recorded a suspend (`on_park` fires after dispatch,
/// slightly later than session-insert — so poll the sink, not the session count).
async fn wait_started(sink: &RecordingSink) {
    for _ in 0..2000 {
        if !sink.started.lock().unwrap().is_empty() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    panic!("suspend (on_await_start) never fired");
}

fn completed_reply(slot: u32, source: &str) -> ReplyResult {
    ReplyResult {
        slot,
        source: source.to_string(),
        payload: b"ok".to_vec(),
        status: ReplyStatus::Completed,
        received_at: chrono::Utc::now(),
        task_id: None,
    }
}

// ─── MODULE-007-T20a: start_with_run_and_session ────────────────────────

/// The caller-minted SessionId is used verbatim (the factory is NOT consulted),
/// and `on_park` fires for a genuine park.
#[tokio::test(flavor = "multi_thread")]
async fn t20a_caller_minted_sid_used_and_on_park_fires_on_genuine_park() {
    let manager = manager_with(Arc::new(OkDispatcher));
    let sid = SessionId("known-sid-abc".to_string());
    let fired = Arc::new(AtomicBool::new(false));

    let m = Arc::clone(&manager);
    let sid_task = sid.clone();
    let fired_task = Arc::clone(&fired);
    let join = tokio::spawn(async move {
        let on_park: Box<dyn FnOnce() + Send> = {
            let fired = Arc::clone(&fired_task);
            Box::new(move || fired.store(true, Ordering::SeqCst))
        };
        m.start_with_run_and_session(
            sid_task,
            "researcher",
            Some("run-1"),
            vec![agent_req("agent:t", "c1")],
            default_options(),
            Some(on_park),
        )
        .await
    });

    wait_for_session_count(&manager, 1).await;
    // The caller-supplied sid is the live session id (factory not consulted).
    let aref = AwaitSessionManagerRef::new(Arc::clone(&manager));
    assert!(
        aref.exists(&sid),
        "caller-minted sid must be the live session id"
    );
    // on_park fires at the genuine park (after dispatch, before rx.await).
    wait_for_flag(&fired).await;

    // Clean up: close the parked session.
    let _ = manager.close(&sid, "test-cleanup").await;
    let _ = tokio::time::timeout(Duration::from_secs(2), join).await;
}

/// On the all-failed-dispatch path, `start_with_run_and_session` resolves
/// SYNCHRONOUSLY (before `rx.await`) → `on_park` is NEVER fired (no phantom
/// suspend).
#[tokio::test(flavor = "multi_thread")]
async fn t20a_on_park_not_fired_on_all_failed_dispatch() {
    let manager = manager_with(Arc::new(FailDispatcher));
    let fired = Arc::new(AtomicBool::new(false));
    let on_park: Box<dyn FnOnce() + Send> = {
        let fired = Arc::clone(&fired);
        Box::new(move || fired.store(true, Ordering::SeqCst))
    };
    let res = manager
        .start_with_run_and_session(
            SessionId("sid-fail".to_string()),
            "researcher",
            Some("run-1"),
            vec![agent_req("agent:t", "c1")],
            default_options(),
            Some(on_park),
        )
        .await
        .expect("all-failed dispatch returns Ok(FailedDispatch)");
    assert_eq!(res.status, AwaitSessionStatus::FailedDispatch);
    assert!(
        !fired.load(Ordering::SeqCst),
        "on_park MUST NOT fire on a synchronous all-failed-dispatch resolution"
    );
}

// ─── SYS-AC-017 race-fix: handler suspend/resume gating ─────────────────

/// The handler suspends on park then RESUMES on a genuine reply-completion `Ok`.
#[tokio::test(flavor = "multi_thread")]
async fn handler_suspends_then_resumes_on_ok() {
    let manager = manager_with(Arc::new(OkDispatcher));
    let sink = Arc::new(RecordingSink::default());
    let handler = Arc::new(
        AwaitRepliesHandler::new(Arc::clone(&manager))
            .with_run_suspend_sink(Arc::clone(&sink) as Arc<dyn RunSuspendSink>),
    );

    let params = vec![
        Val::List(vec![val_agent_request("agent:t", "c1")]),
        val_await_options_allof(),
    ];
    let h = Arc::clone(&handler);
    let join =
        tokio::spawn(async move { h.call(ctx_with_run("a", Some("run-7")), params, 1).await });

    wait_started(&sink).await;
    // suspend fired at park.
    assert_eq!(sink.started.lock().unwrap().as_slice(), ["run-7"]);
    assert!(
        sink.resolved.lock().unwrap().is_empty(),
        "no resume before reply"
    );

    // Resolve the single AllOf slot → start returns Ok.
    let sid = manager.heartbeat_for_target("agent:t", None).await;
    assert_eq!(sid.len(), 1);
    manager
        .on_reply(&sid[0], 0, completed_reply(0, "agent:t"))
        .await
        .expect("on_reply");

    let _ = tokio::time::timeout(Duration::from_secs(2), join)
        .await
        .expect("handler timed out")
        .expect("join")
        .expect("host-fn ok");
    // resume fired exactly once on the Ok completion.
    assert_eq!(sink.resolved.lock().unwrap().as_slice(), ["run-7"]);
}

/// The handler SKIPS resume when the await returns `Err(SessionClosed)`
/// (pause/cancel owns that transition) — the race fix.
#[tokio::test(flavor = "multi_thread")]
async fn handler_skips_resume_on_session_closed() {
    let manager = manager_with(Arc::new(OkDispatcher));
    let sink = Arc::new(RecordingSink::default());
    let handler = Arc::new(
        AwaitRepliesHandler::new(Arc::clone(&manager))
            .with_run_suspend_sink(Arc::clone(&sink) as Arc<dyn RunSuspendSink>),
    );

    let params = vec![
        Val::List(vec![val_agent_request("agent:t", "c1")]),
        val_await_options_allof(),
    ];
    let h = Arc::clone(&handler);
    let join =
        tokio::spawn(async move { h.call(ctx_with_run("a", Some("run-9")), params, 1).await });

    wait_started(&sink).await;
    assert_eq!(sink.started.lock().unwrap().as_slice(), ["run-9"]);

    // Close the session (the pause/cancel cascade) → start returns SessionClosed.
    let sid = manager.heartbeat_for_target("agent:t", None).await;
    let _ = manager.close(&sid[0], "pause-cascade").await;

    let result = tokio::time::timeout(Duration::from_secs(2), join)
        .await
        .expect("handler timed out")
        .expect("join")
        .expect("host-fn ok");
    // The handler returned the WIT session-closed error...
    match &result[0] {
        Val::Result(Err(Some(b))) => match b.as_ref() {
            Val::Variant(case, _) => assert_eq!(case, "session-closed"),
            other => panic!("expected session-closed variant, got {other:?}"),
        },
        other => panic!("expected Result(Err), got {other:?}"),
    }
    // ...and DID NOT resume (the race fix).
    assert!(
        sink.resolved.lock().unwrap().is_empty(),
        "resume MUST be skipped on Err(SessionClosed) — pause/cancel owns the transition"
    );
}

/// On a `Fail`-policy idle timeout the await returns `Err(IdleTimeoutExceeded)` —
/// the handler RESUMES the run (it must NOT be left stuck Suspended). Adversarial
/// §5.2 fix for the idle-timeout-Fail run-state leak: resume fires on ANY
/// resolution except `Err(SessionClosed)`.
#[tokio::test(flavor = "multi_thread")]
async fn handler_resumes_on_idle_timeout_fail() {
    let manager = manager_with(Arc::new(OkDispatcher));
    let sink = Arc::new(RecordingSink::default());
    let handler = Arc::new(
        AwaitRepliesHandler::new(Arc::clone(&manager))
            .with_run_suspend_sink(Arc::clone(&sink) as Arc<dyn RunSuspendSink>),
    );

    let params = vec![
        Val::List(vec![val_agent_request("agent:t", "c1")]),
        val_await_options_fail(),
    ];
    let h = Arc::clone(&handler);
    let join =
        tokio::spawn(async move { h.call(ctx_with_run("a", Some("run-it")), params, 1).await });

    wait_started(&sink).await;
    assert_eq!(sink.started.lock().unwrap().as_slice(), ["run-it"]);
    assert!(
        sink.resolved.lock().unwrap().is_empty(),
        "no resume before resolution"
    );

    // Trigger the Fail-policy idle timeout → parked start returns Err(IdleTimeoutExceeded).
    let sid = manager.heartbeat_for_target("agent:t", None).await;
    assert_eq!(sid.len(), 1);
    manager.on_idle_timeout_for_test(&sid[0]).await;

    let result = tokio::time::timeout(Duration::from_secs(2), join)
        .await
        .expect("handler timed out")
        .expect("join")
        .expect("host-fn ok");
    // The handler returns the WIT idle-timeout-exceeded error to the guest...
    match &result[0] {
        Val::Result(Err(Some(b))) => match b.as_ref() {
            Val::Variant(case, _) => assert_eq!(case, "idle-timeout-exceeded"),
            other => panic!("expected idle-timeout-exceeded variant, got {other:?}"),
        },
        other => panic!("expected Result(Err), got {other:?}"),
    }
    // ...AND the run is RESUMED (not stuck Suspended) — the §5.2 adversarial fix.
    assert_eq!(
        sink.resolved.lock().unwrap().as_slice(),
        ["run-it"],
        "run MUST resume on idle-timeout-Fail — leaving it Suspended forever is the bug being fixed"
    );
}

// ─── MODULE-007-T23a: AwaitSessionManagerRef::close ─────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn t23a_ref_close_resolves_parked_start_and_is_idempotent() {
    let manager = manager_with(Arc::new(OkDispatcher));
    let aref = AwaitSessionManagerRef::new(Arc::clone(&manager));

    let m = Arc::clone(&manager);
    let join = tokio::spawn(async move {
        m.start_with_run(
            "researcher",
            None,
            vec![agent_req("agent:t", "c1")],
            default_options(),
        )
        .await
    });

    wait_for_session_count(&manager, 1).await;
    let sid = manager.heartbeat_for_target("agent:t", None).await;
    assert_eq!(sid.len(), 1);

    // 1st close resolves the parked start with SessionClosed.
    aref.close(&sid[0], "interrupt")
        .await
        .expect("first close ok");
    let res = tokio::time::timeout(Duration::from_secs(2), join)
        .await
        .expect("start timed out")
        .expect("join");
    assert!(
        matches!(res, Err(OrchestrationError::SessionClosed(_))),
        "parked start must return SessionClosed, got {res:?}"
    );

    // 2nd close is idempotent → Err(NotFound), PROPAGATED (not swallowed).
    let again = aref.close(&sid[0], "interrupt-again").await;
    assert!(
        matches!(again, Err(OrchestrationError::NotFound(_))),
        "second close must return NotFound, got {again:?}"
    );
}
