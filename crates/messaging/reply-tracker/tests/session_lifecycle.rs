//! MODULE-007 AC-02 — AwaitSession create/cancel lifecycle (slice m007-A).
//!
//! Three sub-tests:
//! - T02a: AwaitSession::new construction invariants (single Instant capture).
//! - T02b: AwaitSession::cancel idempotency.
//! - T02c: AwaitSessionManager::start + close end-to-end via tokio::spawn.

use std::sync::Arc;

use advance_messaging::dispatcher::MailboxDispatcher;
use advance_shared_types::await_session::{
    AgentAwaitRequest, AwaitMode, AwaitOptions, AwaitRequest, OrchestrationError, SessionId,
    TimeoutPolicy,
};
use advance_shared_types::mailbox::{Message, MessageContext, MsgError, NotifyError};

use advance_reply_tracker::{
    AwaitSession, AwaitSessionManager, AwaitSessionManagerImpl, ManagerOptions, SessionStatus,
};

#[tokio::test(flavor = "current_thread")]
async fn t02a_await_session_new_construction_invariants() {
    let id = SessionId("test-session-001".to_string());
    let options = AwaitOptions {
        mode: AwaitMode::AllOf,
        idle_timeout_secs: Some(60),
        on_idle_timeout: TimeoutPolicy::ReturnPartial,
        keep_losers: false,
    };
    let expected = vec![AwaitRequest::AgentRequest(AgentAwaitRequest {
        target: "agent:t1".to_string(),
        payload: vec![1, 2, 3],
        correlation_id: "corr-1".to_string(),
        context: None,
    })];
    let session = AwaitSession::new(id.clone(), "researcher".to_string(), options, expected);

    assert_eq!(session.status, SessionStatus::Open);
    // Single-Instant-capture invariant: both fields assigned from one
    // `let now = Instant::now()` in the constructor.
    assert_eq!(
        session.created_at, session.last_activity,
        "AwaitSession::new must assign created_at and last_activity from a single Instant::now() capture"
    );
    assert_eq!(session.id.0, "test-session-001");
    assert_eq!(session.received.len(), 1);
    assert!(session.received[0].is_none());
}

#[tokio::test(flavor = "current_thread")]
async fn t02b_await_session_cancel_idempotent() {
    let id = SessionId("test-session-002".to_string());
    let options = AwaitOptions {
        mode: AwaitMode::AllOf,
        idle_timeout_secs: None,
        on_idle_timeout: TimeoutPolicy::Fail,
        keep_losers: false,
    };
    let expected = vec![AwaitRequest::AgentRequest(AgentAwaitRequest {
        target: "agent:t1".to_string(),
        payload: vec![],
        correlation_id: "corr-1".to_string(),
        context: None,
    })];
    let mut session = AwaitSession::new(id, "researcher".to_string(), options, expected);

    session.cancel("reason-1");
    assert_eq!(session.status, SessionStatus::Cancelled);
    session.cancel("reason-2");
    assert_eq!(
        session.status,
        SessionStatus::Cancelled,
        "second cancel() must be idempotent — status stays Cancelled"
    );
}

// ─── T02c MockMailboxDispatcher ───────────────────────────────────────

struct MockDispatcher;

#[async_trait::async_trait]
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

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn t02c_manager_start_close_end_to_end() {
    let dispatcher: Arc<dyn MailboxDispatcher> = Arc::new(MockDispatcher);
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
    let requests = vec![AwaitRequest::AgentRequest(AgentAwaitRequest {
        target: "agent:t1".to_string(),
        payload: vec![],
        correlation_id: "corr-1".to_string(),
        context: None,
    })];

    let mgr = manager.clone();
    let start_handle =
        tokio::spawn(async move { mgr.start("researcher", requests, options).await });

    // Yield so the spawned task can register the session before we query.
    tokio::task::yield_now().await;
    tokio::task::yield_now().await;

    let session_id = manager.first_open_session_id_for_test().await;
    manager
        .close(&session_id, "external-close")
        .await
        .expect("close should succeed on existing session");

    let result = start_handle.await.expect("spawned task should not panic");
    match result {
        Err(OrchestrationError::SessionClosed(reason)) => {
            assert_eq!(reason, "external-close");
        }
        other => panic!("expected Err(SessionClosed), got {other:?}"),
    }

    // Second close → NotFound (idempotent removal).
    let err = manager
        .close(&session_id, "again")
        .await
        .expect_err("second close should fail with NotFound");
    assert!(matches!(err, OrchestrationError::NotFound(_)));
}
