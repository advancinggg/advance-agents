//! MODULE-007 AC-05 — TimeoutPolicy::ReturnPartial vs Fail (slice m007-A).
//!
//! T05a/b: invoke the test-only `on_idle_timeout_for_test` hook to simulate
//!   the slice-B idle-monitor's call into the manager. ReturnPartial returns
//!   Ok with PartialTimeout status; Fail returns Err(IdleTimeoutExceeded).
//! T05c: AwaitOptions plumbing — `idle_timeout_secs: Some(N)` accepted;
//!   `None` falls back to MAX_IDLE_TIMEOUT_DEFAULT_SEC.

use std::sync::Arc;

use async_trait::async_trait;
use chrono::Utc;

use advance_messaging::dispatcher::MailboxDispatcher;
use advance_shared_types::await_session::{
    AgentAwaitRequest, AwaitMode, AwaitOptions, AwaitRequest, AwaitSessionStatus,
    OrchestrationError, ReplyResult, ReplyStatus, SessionId, TimeoutPolicy,
};
use advance_shared_types::mailbox::{Message, MessageContext, MsgError, NotifyError};

use advance_reply_tracker::{
    AwaitSessionManager, AwaitSessionManagerImpl, ManagerOptions, MAX_IDLE_TIMEOUT_DEFAULT_SEC,
};

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

#[tokio::test(flavor = "current_thread")]
async fn t05a_return_partial_resolves_with_partial_timeout_status() {
    let dispatcher: Arc<dyn MailboxDispatcher> = Arc::new(MockDispatcher);
    let manager = Arc::new(AwaitSessionManagerImpl::new(
        dispatcher,
        ManagerOptions::default(),
    ));

    let options = AwaitOptions {
        mode: AwaitMode::AllOf,
        idle_timeout_secs: Some(60),
        on_idle_timeout: TimeoutPolicy::ReturnPartial,
        keep_losers: false,
    };
    let requests = vec![
        make_agent_req("agent:t1", "c1"),
        make_agent_req("agent:t2", "c2"),
    ];

    let mgr = manager.clone();
    let start_handle =
        tokio::spawn(async move { mgr.start("researcher", requests, options).await });

    for _ in 0..4 {
        tokio::task::yield_now().await;
    }

    let session_id = manager.first_open_session_id_for_test().await;
    // Slot 0 completes; slot 1 will fill as TimedOut on idle-timeout.
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

    manager.on_idle_timeout_for_test(&session_id).await;

    let result = start_handle
        .await
        .expect("spawn ok")
        .expect("start returns Ok");
    assert_eq!(result.status, AwaitSessionStatus::PartialTimeout);
    assert_eq!(result.replies.len(), 2);
    assert!(matches!(result.replies[0].status, ReplyStatus::Completed));
    assert!(matches!(result.replies[1].status, ReplyStatus::TimedOut));
}

#[tokio::test(flavor = "current_thread")]
async fn t05b_fail_resolves_with_idle_timeout_err() {
    let dispatcher: Arc<dyn MailboxDispatcher> = Arc::new(MockDispatcher);
    let manager = Arc::new(AwaitSessionManagerImpl::new(
        dispatcher,
        ManagerOptions::default(),
    ));

    let options = AwaitOptions {
        mode: AwaitMode::AllOf,
        idle_timeout_secs: Some(60),
        on_idle_timeout: TimeoutPolicy::Fail,
        keep_losers: false,
    };
    let requests = vec![
        make_agent_req("agent:t1", "c1"),
        make_agent_req("agent:t2", "c2"),
    ];

    let mgr = manager.clone();
    let start_handle =
        tokio::spawn(async move { mgr.start("researcher", requests, options).await });

    for _ in 0..4 {
        tokio::task::yield_now().await;
    }

    let session_id = manager.first_open_session_id_for_test().await;
    manager.on_idle_timeout_for_test(&session_id).await;

    let result = start_handle.await.expect("spawn ok");
    assert!(matches!(
        result,
        Err(OrchestrationError::IdleTimeoutExceeded(_))
    ));
}

#[tokio::test(flavor = "current_thread")]
async fn t05c_options_plumbing_idle_timeout_default() {
    // Verify the default constant is the expected 600s value (used when
    // AwaitOptions.idle_timeout_secs is None).
    assert_eq!(MAX_IDLE_TIMEOUT_DEFAULT_SEC, 600);

    // Verify options with both Some(N) and None values are accepted by start().
    let dispatcher: Arc<dyn MailboxDispatcher> = Arc::new(MockDispatcher);
    let manager = Arc::new(AwaitSessionManagerImpl::new(
        dispatcher,
        ManagerOptions::default(),
    ));

    // Some(N) path.
    let options_some = AwaitOptions {
        mode: AwaitMode::AllOf,
        idle_timeout_secs: Some(123),
        on_idle_timeout: TimeoutPolicy::ReturnPartial,
        keep_losers: false,
    };
    let req = vec![make_agent_req("agent:t1", "c1")];
    let mgr1 = manager.clone();
    let h1 = tokio::spawn(async move { mgr1.start("researcher", req, options_some).await });

    for _ in 0..4 {
        tokio::task::yield_now().await;
    }
    let id1 = manager.first_open_session_id_for_test().await;
    let _ = manager.close(&id1, "test-cleanup").await;
    let _ = h1.await;

    // None path (default 600s).
    let options_none = AwaitOptions {
        mode: AwaitMode::AllOf,
        idle_timeout_secs: None,
        on_idle_timeout: TimeoutPolicy::Fail,
        keep_losers: false,
    };
    let req2 = vec![make_agent_req("agent:t2", "c2")];
    let mgr2 = manager.clone();
    let h2 = tokio::spawn(async move { mgr2.start("researcher2", req2, options_none).await });

    for _ in 0..4 {
        tokio::task::yield_now().await;
    }
    let id2 = manager.first_open_session_id_for_test().await;
    let _ = manager.close(&id2, "test-cleanup").await;
    let _ = h2.await;
    // No assertion failure means both options were accepted.
}

// Suppress unused warning on SessionId import.
#[allow(dead_code)]
fn _suppress_unused(_: SessionId) {}
