//! MODULE-007 AC-18 — full 5-knob capability config enforcement (slice-C
//! adds the 5th knob `max_depth`).
//!
//! T18h: max_depth=Some(2) + parent at depth 2 → prospective=3 → CapabilityDenied
//! T18i: max_depth=Some(2) + parent at depth 1 → prospective=2 (==cap, inclusive)
//! T18j: max_depth=None (default) → no depth limit (slice-B 4-knob preserved)
//! T18k: max_depth=Some(1) + nested → reject; top-level → admit
//! T18l: All 5 knobs set to non-None plausible values → admit
//! T18m: max_depth=Some(2) + ghost parent → strict-promotion to root depth=1 → admit

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;

use advance_messaging::dispatcher::MailboxDispatcher;
use advance_shared_types::await_session::{
    AgentAwaitRequest, AwaitMode, AwaitOptions, AwaitRequest, OrchestrationError, SessionId,
    TimeoutPolicy,
};
use advance_shared_types::mailbox::{Message, MessageContext, MsgError, NotifyError};

use advance_reply_tracker::{
    AwaitSessionManagerImpl, CapabilityConfig, ManagerOptions, SessionContextProvider,
};

#[derive(Default)]
struct NoopDispatcher;

#[async_trait]
impl MailboxDispatcher for NoopDispatcher {
    async fn deliver(&self, _target: &str, _msg: Message) -> Result<(), MsgError> {
        Ok(())
    }
    async fn reply(&self, _: &str, _: &str, _: Vec<u8>) -> Result<(), MsgError> {
        Ok(())
    }
    async fn notify_agent(
        &self,
        _: &str,
        _: &str,
        _: Vec<u8>,
        _: Option<MessageContext>,
    ) -> Result<(), NotifyError> {
        Ok(())
    }
}

#[derive(Default)]
struct MockSessionContext {
    inner: std::sync::Mutex<std::collections::HashMap<String, SessionId>>,
}

impl MockSessionContext {
    fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }
    fn set(&self, run_id: &str, sid: SessionId) {
        self.inner.lock().unwrap().insert(run_id.to_string(), sid);
    }
}

impl SessionContextProvider for MockSessionContext {
    fn current_session(&self, caller_run_id: &str) -> Option<SessionId> {
        self.inner.lock().unwrap().get(caller_run_id).cloned()
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

fn opts() -> AwaitOptions {
    AwaitOptions {
        mode: AwaitMode::AllOf,
        idle_timeout_secs: Some(60),
        on_idle_timeout: TimeoutPolicy::ReturnPartial,
        keep_losers: false,
    }
}

fn deterministic_factory() -> (
    Arc<std::sync::atomic::AtomicUsize>,
    Arc<dyn Fn() -> SessionId + Send + Sync>,
) {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let counter = Arc::new(AtomicUsize::new(0));
    let counter_for_factory = counter.clone();
    let f: Arc<dyn Fn() -> SessionId + Send + Sync> = Arc::new(move || {
        let n = counter_for_factory.fetch_add(1, Ordering::SeqCst);
        SessionId(format!("sid-{n}"))
    });
    (counter, f)
}

// ─── T18h: max_depth Some(2) + parent at depth 2 → CapabilityDenied ──

#[tokio::test(start_paused = true)]
async fn t18h_max_depth_exceeds_rejects() {
    let ctx = MockSessionContext::new();
    let (_c, factory) = deterministic_factory();

    let mut mo = ManagerOptions::default();
    mo.session_context = Some(ctx.clone() as Arc<dyn SessionContextProvider>);
    mo.session_id_factory = factory;
    mo.capability = CapabilityConfig {
        max_depth: Some(2),
        ..Default::default()
    };
    let manager = Arc::new(AwaitSessionManagerImpl::new(Arc::new(NoopDispatcher), mo));

    // Build root (sid-0) + child (sid-1, parent=sid-0). After this, sid-1
    // is at depth 2.
    let mgr = manager.clone();
    let r = tokio::spawn(async move {
        mgr.start_with_run(
            "a",
            Some("run-1"),
            vec![make_agent_req("agent:t1", "c-r")],
            opts(),
        )
        .await
    });
    tokio::time::sleep(Duration::from_millis(1)).await;
    ctx.set("run-1", SessionId("sid-0".to_string()));

    let mgr = manager.clone();
    let c = tokio::spawn(async move {
        mgr.start_with_run(
            "a",
            Some("run-1"),
            vec![make_agent_req("agent:t2", "c-c")],
            opts(),
        )
        .await
    });
    tokio::time::sleep(Duration::from_millis(1)).await;
    // Now sid-1 is at depth 2; point the provider at it for a grandchild
    // attempt.
    ctx.set("run-1", SessionId("sid-1".to_string()));

    // Grandchild attempt would be at prospective depth 3 > max_depth=2 →
    // reject.
    let res = manager
        .start_with_run(
            "a",
            Some("run-1"),
            vec![make_agent_req("agent:t3", "c-g")],
            opts(),
        )
        .await;
    match res {
        Err(OrchestrationError::CapabilityDenied(msg)) => {
            assert_eq!(msg, "capability:max-depth-exceeded");
        }
        other => panic!("expected CapabilityDenied, got {:?}", other),
    }

    r.abort();
    c.abort();
}

// ─── T18i: max_depth Some(2) + parent at depth 1 → ==cap (inclusive) ──

#[tokio::test(start_paused = true)]
async fn t18i_max_depth_inclusive_boundary_admits() {
    let ctx = MockSessionContext::new();
    let (_c, factory) = deterministic_factory();

    let mut mo = ManagerOptions::default();
    mo.session_context = Some(ctx.clone() as Arc<dyn SessionContextProvider>);
    mo.session_id_factory = factory;
    mo.capability = CapabilityConfig {
        max_depth: Some(2),
        ..Default::default()
    };
    let manager = Arc::new(AwaitSessionManagerImpl::new(Arc::new(NoopDispatcher), mo));

    let mgr = manager.clone();
    let r = tokio::spawn(async move {
        mgr.start_with_run(
            "a",
            Some("run-1"),
            vec![make_agent_req("agent:t1", "c-r")],
            opts(),
        )
        .await
    });
    tokio::time::sleep(Duration::from_millis(1)).await;
    ctx.set("run-1", SessionId("sid-0".to_string()));

    // Child at prospective depth 2 (== max_depth) → admitted.
    let mgr = manager.clone();
    let c = tokio::spawn(async move {
        mgr.start_with_run(
            "a",
            Some("run-1"),
            vec![make_agent_req("agent:t2", "c-c")],
            opts(),
        )
        .await
    });
    tokio::time::sleep(Duration::from_millis(1)).await;
    assert_eq!(manager.session_count_for_test().await, 2);

    r.abort();
    c.abort();
}

// ─── T18j: max_depth None → no limit (slice-B preserved) ──

#[tokio::test(start_paused = true)]
async fn t18j_max_depth_none_no_limit() {
    // Build 5-level chain (within MAX_INFLIGHT? no — MAX_INFLIGHT=3, so use
    // distinct callers per level). Provider keyed on (caller, run_id) →
    // since trait `current_session(run_id)` does not see caller, we use
    // distinct run_ids per level.
    let ctx = MockSessionContext::new();
    let (_c, factory) = deterministic_factory();

    let mut mo = ManagerOptions::default();
    mo.session_context = Some(ctx.clone() as Arc<dyn SessionContextProvider>);
    mo.session_id_factory = factory;
    // CapabilityConfig::default → max_depth=None → no limit.
    let manager = Arc::new(AwaitSessionManagerImpl::new(Arc::new(NoopDispatcher), mo));

    // 3 sequential sessions same caller; each child links to previous.
    let mgr = manager.clone();
    let s1 = tokio::spawn(async move {
        mgr.start_with_run(
            "a",
            Some("run-1"),
            vec![make_agent_req("agent:t1", "c1")],
            opts(),
        )
        .await
    });
    tokio::time::sleep(Duration::from_millis(1)).await;
    ctx.set("run-1", SessionId("sid-0".to_string()));

    let mgr = manager.clone();
    let s2 = tokio::spawn(async move {
        mgr.start_with_run(
            "a",
            Some("run-1"),
            vec![make_agent_req("agent:t2", "c2")],
            opts(),
        )
        .await
    });
    tokio::time::sleep(Duration::from_millis(1)).await;
    ctx.set("run-1", SessionId("sid-1".to_string()));

    let mgr = manager.clone();
    let s3 = tokio::spawn(async move {
        mgr.start_with_run(
            "a",
            Some("run-1"),
            vec![make_agent_req("agent:t3", "c3")],
            opts(),
        )
        .await
    });
    tokio::time::sleep(Duration::from_millis(1)).await;
    assert_eq!(manager.session_count_for_test().await, 3);

    s1.abort();
    s2.abort();
    s3.abort();
}

// ─── T18k: max_depth Some(1) + nested → reject; top-level admit ──

#[tokio::test(start_paused = true)]
async fn t18k_max_depth_one_rejects_nested_admits_root() {
    let ctx = MockSessionContext::new();
    let (_c, factory) = deterministic_factory();

    let mut mo = ManagerOptions::default();
    mo.session_context = Some(ctx.clone() as Arc<dyn SessionContextProvider>);
    mo.session_id_factory = factory;
    mo.capability = CapabilityConfig {
        max_depth: Some(1),
        ..Default::default()
    };
    let manager = Arc::new(AwaitSessionManagerImpl::new(Arc::new(NoopDispatcher), mo));

    // Top-level admitted (no parent → depth 1 == cap).
    let mgr = manager.clone();
    let r = tokio::spawn(async move {
        mgr.start_with_run(
            "a",
            Some("run-1"),
            vec![make_agent_req("agent:t1", "c-r")],
            opts(),
        )
        .await
    });
    tokio::time::sleep(Duration::from_millis(1)).await;
    ctx.set("run-1", SessionId("sid-0".to_string()));

    // Nested rejected (parent at depth 1 → child depth 2 > 1).
    let res = manager
        .start_with_run(
            "a",
            Some("run-1"),
            vec![make_agent_req("agent:t2", "c-c")],
            opts(),
        )
        .await;
    match res {
        Err(OrchestrationError::CapabilityDenied(msg)) => {
            assert_eq!(msg, "capability:max-depth-exceeded");
        }
        other => panic!("expected CapabilityDenied, got {:?}", other),
    }

    r.abort();
}

// ─── T18l: all 5 knobs set + valid request → admit ──

#[tokio::test(start_paused = true)]
async fn t18l_all_five_knobs_valid_request_admits() {
    let ctx = MockSessionContext::new();
    let (_c, factory) = deterministic_factory();

    let mut mo = ManagerOptions::default();
    mo.session_context = Some(ctx.clone() as Arc<dyn SessionContextProvider>);
    mo.session_id_factory = factory;
    mo.capability = CapabilityConfig {
        targets: Some(vec!["t1".to_string()]),
        max_fanout: Some(2),
        max_inflight: Some(3),
        max_idle_timeout_secs: Some(600),
        max_depth: Some(5),
    };
    let manager = Arc::new(AwaitSessionManagerImpl::new(Arc::new(NoopDispatcher), mo));

    // Valid request: 1 slot to agent:t1, no parent, idle_timeout 300 (≤600).
    let req_opts = AwaitOptions {
        mode: AwaitMode::AllOf,
        idle_timeout_secs: Some(300),
        on_idle_timeout: TimeoutPolicy::ReturnPartial,
        keep_losers: false,
    };
    let mgr = manager.clone();
    let t = tokio::spawn(async move {
        mgr.start_with_run(
            "a",
            Some("run-1"),
            vec![make_agent_req("agent:t1", "c1")],
            req_opts,
        )
        .await
    });
    tokio::time::sleep(Duration::from_millis(1)).await;
    assert_eq!(
        manager.session_count_for_test().await,
        1,
        "all 5 gates passed"
    );

    t.abort();
}

// ─── T18m: max_depth + ghost parent → strict-promotion to root ──

#[tokio::test(start_paused = true)]
async fn t18m_max_depth_with_ghost_parent_admits_as_root() {
    let ctx = MockSessionContext::new();
    ctx.set("run-1", SessionId("ghost-sid".to_string()));
    let (_c, factory) = deterministic_factory();

    let mut mo = ManagerOptions::default();
    mo.session_context = Some(ctx.clone() as Arc<dyn SessionContextProvider>);
    mo.session_id_factory = factory;
    mo.capability = CapabilityConfig {
        max_depth: Some(2),
        ..Default::default()
    };
    let manager = Arc::new(AwaitSessionManagerImpl::new(Arc::new(NoopDispatcher), mo));

    // Ghost parent → effective depth=1 (root) → admitted.
    let mgr = manager.clone();
    let t = tokio::spawn(async move {
        mgr.start_with_run(
            "a",
            Some("run-1"),
            vec![make_agent_req("agent:t1", "c1")],
            opts(),
        )
        .await
    });
    tokio::time::sleep(Duration::from_millis(1)).await;
    let parent = manager
        .session_parent_for_test(&SessionId("sid-0".to_string()))
        .await;
    assert_eq!(parent, None, "ghost parent must be strict-promoted to None");

    t.abort();
}
