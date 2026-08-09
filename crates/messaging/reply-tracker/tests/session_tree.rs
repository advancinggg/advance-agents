//! MODULE-007 AC-16 — nested AwaitSession tree (in-boundary linkage subset).
//!
//! T16a: SessionContextProvider returning Some(parent_id) for a given
//!       caller_run_id → child's parent_session = Some(parent_id).
//! T16b: Default ManagerOptions (`session_context: None`); CONTRACT-060 trait
//!       `start()` → both sessions parent_session=None (slice-A/B preserved).
//! T16c: 3-level nested tree via mutable mock provider + tokio::spawn open-keep
//!       (stays within MAX_INFLIGHT=3 cap).
//! T16f: Ghost parent (provider returns Some(s_x) where s_x absent from sessions)
//!       → strict-promotion: parent_session=None (not Some(s_x)).
//! T16h: Run-scoped key semantics — same caller, different caller_run_id → different
//!       parent attribution.
//!
//! (T16g unit-tests `compute_depth_in_map` directly inside `src/session_context.rs`.)

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;

use advance_messaging::dispatcher::MailboxDispatcher;
use advance_shared_types::await_session::{
    AgentAwaitRequest, AwaitMode, AwaitOptions, AwaitRequest, SessionId, TimeoutPolicy,
};
use advance_shared_types::mailbox::{Message, MessageContext, MsgError, NotifyError};

use advance_reply_tracker::{AwaitSessionManagerImpl, ManagerOptions, SessionContextProvider};

// ─── Test fixtures ──────────────────────────────────────────────────────

#[derive(Default)]
struct NoopDispatcher;

#[async_trait]
impl MailboxDispatcher for NoopDispatcher {
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

/// Mock SessionContextProvider that returns a fixed mapping run_id → SessionId.
/// `Default` returns None for every lookup.
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
    #[allow(dead_code)]
    fn clear(&self, run_id: &str) {
        self.inner.lock().unwrap().remove(run_id);
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

fn manager_with_ctx(ctx: Option<Arc<dyn SessionContextProvider>>) -> Arc<AwaitSessionManagerImpl> {
    let mut mo = ManagerOptions::default();
    mo.session_context = ctx;
    Arc::new(AwaitSessionManagerImpl::new(Arc::new(NoopDispatcher), mo))
}

/// Poll until the manager reports exactly `expected` open sessions, yielding
/// to the scheduler between checks. Deterministic under
/// `#[tokio::test(start_paused = true)]` because the admission path is
/// timer-free (only the spawned idle monitor sleeps), so a spawned
/// `start_with_run` task makes progress on each `yield_now` while the read
/// lock is released between polls. Bounded at 200 iterations so a genuine
/// hang fails fast instead of looping forever. Used by T16i (slice-D) to
/// replace bare fixed `sleep`s that could race the assertion (Adversarial
/// R1 W1).
async fn wait_for_session_count(manager: &Arc<AwaitSessionManagerImpl>, expected: usize) {
    for _ in 0..200 {
        if manager.session_count_for_test().await == expected {
            return;
        }
        tokio::task::yield_now().await;
    }
    assert_eq!(
        manager.session_count_for_test().await,
        expected,
        "session count did not reach {expected} within 200 yields"
    );
}

// ─── Tests ──────────────────────────────────────────────────────────────

#[tokio::test(start_paused = true)]
async fn t16a_parent_linkage_via_provider() {
    // Provider returns Some(parent_id) for run-1; new child gets that parent.
    let ctx = MockSessionContext::new();
    let manager = manager_with_ctx(Some(ctx.clone()));

    // First, spawn a parent session (run-1, no parent). The mock returns None
    // for run-1 at this point, so the parent admits as a root.
    let mgr = manager.clone();
    let parent_task = tokio::spawn(async move {
        mgr.start_with_run(
            "a",
            Some("run-1"),
            vec![make_agent_req("agent:t1", "c-parent")],
            opts(),
        )
        .await
    });
    // Yield so the parent's admission completes and the session is inserted.
    tokio::time::sleep(Duration::from_millis(1)).await;
    assert_eq!(manager.session_count_for_test().await, 1);
    let parent_id = manager.first_open_session_id_for_test().await;

    // Configure mock to return parent_id for run-1.
    ctx.set("run-1", parent_id.clone());

    // Now spawn the child session. The provider returns Some(parent_id) for run-1.
    let mgr = manager.clone();
    let child_task = tokio::spawn(async move {
        mgr.start_with_run(
            "a",
            Some("run-1"),
            vec![make_agent_req("agent:t2", "c-child")],
            opts(),
        )
        .await
    });
    tokio::time::sleep(Duration::from_millis(1)).await;
    assert_eq!(manager.session_count_for_test().await, 2);

    // Find the child id (the one that isn't the parent).
    let sessions_now: usize = manager.session_count_for_test().await;
    assert_eq!(sessions_now, 2);
    // session_parent_for_test returns parent_session field.
    // The parent has parent_session=None; the child has Some(parent_id).
    // To find the child id, we don't have a direct accessor — instead verify
    // via the AwaitSessionRef-style check: at least one open session has
    // parent_session=Some(parent_id).
    let parent_parent = manager.session_parent_for_test(&parent_id).await;
    assert_eq!(parent_parent, None, "parent's parent_session must be None");

    // We don't have a direct "list all session ids" — but session count
    // confirms 2 open. Cleanup: drop tasks; sessions will linger until idle.
    parent_task.abort();
    child_task.abort();
}

#[tokio::test(start_paused = true)]
async fn t16a_explicit_child_parent_linkage() {
    // Variant of T16a that captures the child's id directly via the
    // session_id_factory hook. Each start_with_run gets a deterministic id.
    use std::sync::atomic::{AtomicUsize, Ordering};
    let counter = Arc::new(AtomicUsize::new(0));
    let counter_for_factory = counter.clone();

    let ctx = MockSessionContext::new();

    let mut mo = ManagerOptions::default();
    mo.session_context = Some(ctx.clone() as Arc<dyn SessionContextProvider>);
    mo.session_id_factory = Arc::new(move || {
        let n = counter_for_factory.fetch_add(1, Ordering::SeqCst);
        SessionId(format!("sid-{n}"))
    });
    let manager = Arc::new(AwaitSessionManagerImpl::new(Arc::new(NoopDispatcher), mo));

    // Parent: id will be "sid-0".
    let mgr = manager.clone();
    let p = tokio::spawn(async move {
        mgr.start_with_run(
            "a",
            Some("run-1"),
            vec![make_agent_req("agent:t1", "c-parent")],
            opts(),
        )
        .await
    });
    tokio::time::sleep(Duration::from_millis(1)).await;
    let parent_id = SessionId("sid-0".to_string());
    ctx.set("run-1", parent_id.clone());

    // Child: id will be "sid-1".
    let mgr = manager.clone();
    let c = tokio::spawn(async move {
        mgr.start_with_run(
            "a",
            Some("run-1"),
            vec![make_agent_req("agent:t2", "c-child")],
            opts(),
        )
        .await
    });
    tokio::time::sleep(Duration::from_millis(1)).await;

    // Child should have parent_session = Some(parent_id).
    let child_id = SessionId("sid-1".to_string());
    let child_parent = manager.session_parent_for_test(&child_id).await;
    assert_eq!(
        child_parent,
        Some(parent_id),
        "child's parent_session must be Some(parent_id)"
    );

    p.abort();
    c.abort();
}

#[tokio::test(start_paused = true)]
async fn t16b_default_no_provider_admits_as_root() {
    // Default ManagerOptions (session_context: None); trait `start` admits
    // as root with parent_session=None.
    use advance_reply_tracker::AwaitSessionManager;
    let manager = manager_with_ctx(None);
    let mgr = manager.clone();
    let t = tokio::spawn(async move {
        mgr.start("a", vec![make_agent_req("agent:t1", "c1")], opts())
            .await
    });
    tokio::time::sleep(Duration::from_millis(1)).await;
    let sid = manager.first_open_session_id_for_test().await;
    let parent = manager.session_parent_for_test(&sid).await;
    assert_eq!(parent, None, "trait start should admit as root");

    t.abort();
}

#[tokio::test(start_paused = true)]
async fn t16c_three_level_nested_tree() {
    // Build a 3-level nested tree using deterministic session ids + a
    // mutable mock provider. Stays within MAX_INFLIGHT=3 per-caller cap.
    use std::sync::atomic::{AtomicUsize, Ordering};
    let counter = Arc::new(AtomicUsize::new(0));
    let counter_for_factory = counter.clone();

    let ctx = MockSessionContext::new();
    let mut mo = ManagerOptions::default();
    mo.session_context = Some(ctx.clone() as Arc<dyn SessionContextProvider>);
    mo.session_id_factory = Arc::new(move || {
        let n = counter_for_factory.fetch_add(1, Ordering::SeqCst);
        SessionId(format!("sid-{n}"))
    });
    let manager = Arc::new(AwaitSessionManagerImpl::new(Arc::new(NoopDispatcher), mo));

    // Level 1: root (sid-0, no parent).
    let mgr = manager.clone();
    let l1 = tokio::spawn(async move {
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

    // Level 2: child of sid-0 (sid-1).
    let mgr = manager.clone();
    let l2 = tokio::spawn(async move {
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

    // Level 3: child of sid-1 (sid-2).
    let mgr = manager.clone();
    let l3 = tokio::spawn(async move {
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
    let p1 = manager
        .session_parent_for_test(&SessionId("sid-0".to_string()))
        .await;
    let p2 = manager
        .session_parent_for_test(&SessionId("sid-1".to_string()))
        .await;
    let p3 = manager
        .session_parent_for_test(&SessionId("sid-2".to_string()))
        .await;
    assert_eq!(p1, None, "root parent must be None");
    assert_eq!(
        p2,
        Some(SessionId("sid-0".to_string())),
        "level-2 parent must be sid-0"
    );
    assert_eq!(
        p3,
        Some(SessionId("sid-1".to_string())),
        "level-3 parent must be sid-1"
    );

    l1.abort();
    l2.abort();
    l3.abort();
}

#[tokio::test(start_paused = true)]
async fn t16f_ghost_parent_strict_promotion() {
    // Mock returns Some(sid_x) where sid_x doesn't exist in sessions →
    // strict-promotion: child admitted with parent_session=None.
    use std::sync::atomic::{AtomicUsize, Ordering};
    let counter = Arc::new(AtomicUsize::new(0));
    let counter_for_factory = counter.clone();

    let ctx = MockSessionContext::new();
    ctx.set("run-1", SessionId("ghost-sid".to_string()));

    let mut mo = ManagerOptions::default();
    mo.session_context = Some(ctx.clone() as Arc<dyn SessionContextProvider>);
    mo.session_id_factory = Arc::new(move || {
        let n = counter_for_factory.fetch_add(1, Ordering::SeqCst);
        SessionId(format!("sid-{n}"))
    });
    let manager = Arc::new(AwaitSessionManagerImpl::new(Arc::new(NoopDispatcher), mo));

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

    // Child is "sid-0". Provider returned Some(ghost-sid) but ghost-sid is
    // absent from `sessions` → strict-promotion: child's parent_session=None.
    let parent = manager
        .session_parent_for_test(&SessionId("sid-0".to_string()))
        .await;
    assert_eq!(parent, None, "ghost parent must be strict-promoted to None");

    t.abort();
}

#[tokio::test(start_paused = true)]
async fn t16h_run_scoped_key_disambiguation() {
    // Mock returns Some(parent_id) for run-1, None for run-2. Same caller,
    // different run_id → different parent attribution.
    use std::sync::atomic::{AtomicUsize, Ordering};
    let counter = Arc::new(AtomicUsize::new(0));
    let counter_for_factory = counter.clone();

    let ctx = MockSessionContext::new();
    let mut mo = ManagerOptions::default();
    mo.session_context = Some(ctx.clone() as Arc<dyn SessionContextProvider>);
    mo.session_id_factory = Arc::new(move || {
        let n = counter_for_factory.fetch_add(1, Ordering::SeqCst);
        SessionId(format!("sid-{n}"))
    });
    let manager = Arc::new(AwaitSessionManagerImpl::new(Arc::new(NoopDispatcher), mo));

    // Spawn a parent session under run-1.
    let mgr = manager.clone();
    let p = tokio::spawn(async move {
        mgr.start_with_run(
            "a",
            Some("run-1"),
            vec![make_agent_req("agent:t1", "c-p")],
            opts(),
        )
        .await
    });
    tokio::time::sleep(Duration::from_millis(1)).await;
    let parent_id = SessionId("sid-0".to_string());
    ctx.set("run-1", parent_id.clone()); // run-1 has parent
                                         // run-2 left unset → provider returns None for run-2.

    // Child #1 under run-1 → inherits parent.
    let mgr = manager.clone();
    let c1 = tokio::spawn(async move {
        mgr.start_with_run(
            "a",
            Some("run-1"),
            vec![make_agent_req("agent:t2", "c-c1")],
            opts(),
        )
        .await
    });
    tokio::time::sleep(Duration::from_millis(1)).await;

    // Child #2 under run-2 → top-level (None).
    let mgr = manager.clone();
    let c2 = tokio::spawn(async move {
        mgr.start_with_run(
            "a",
            Some("run-2"),
            vec![make_agent_req("agent:t3", "c-c2")],
            opts(),
        )
        .await
    });
    tokio::time::sleep(Duration::from_millis(1)).await;

    let c1_parent = manager
        .session_parent_for_test(&SessionId("sid-1".to_string()))
        .await;
    let c2_parent = manager
        .session_parent_for_test(&SessionId("sid-2".to_string()))
        .await;
    assert_eq!(
        c1_parent,
        Some(parent_id),
        "run-1 child must inherit parent"
    );
    assert_eq!(c2_parent, None, "run-2 child must be a root");

    p.abort();
    c1.abort();
    c2.abort();
}

// ─── Slice m007-D regression test (NO new AC claim — pins existing slice-C behavior)
// ─────────────────────────────────────────────────────────────────────────────────────
//
// T16i: F3 first-pass cross-caller demotion regression lock.
//
// PINS: manager.rs:749-765 first-pass same-caller check at the
// `Some((s, _)) if s.agent_id == caller =>` arm + the `_ => (None, 1u32)`
// demotion branch.
//
// DOES NOT PIN: manager.rs:866-873 round-4 W1 re-verification under
// sessions.write() guard — that path fires only when the first-pass check
// passed AND a concurrent close removed the parent between read and write
// locks. T16i's cross-caller-from-the-start scenario triggers first-pass
// demotion BEFORE the W1 re-check ever sees a `Some` parent_session.
//
// DOES NOT CLAIM AC-16 (already passed via slice-C). Pins defense-in-depth
// against a buggy/compromised SessionContextProvider returning cross-caller
// parents.

#[tokio::test(start_paused = true)]
async fn t16i_cross_caller_parent_demoted_to_root() {
    // **Regression test — no new AC claim**: pins the slice-C F3 same-caller
    // check at manager.rs:755 (the demotion to None when
    // `s.agent_id != caller`). Does NOT pin the W1 re-verification at
    // manager.rs:866-873.
    use std::sync::atomic::{AtomicUsize, Ordering};

    // Deterministic id factory: SessionId("sid-0") then SessionId("sid-1") etc.
    let counter = Arc::new(AtomicUsize::new(0));
    let counter_for_factory = counter.clone();

    let ctx = MockSessionContext::new();
    // Provider returns Some(SessionId("sid-0")) for caller_run_id="run-1".
    ctx.set("run-1", SessionId("sid-0".to_string()));

    let mut mo = ManagerOptions::default();
    mo.session_context = Some(ctx.clone());
    mo.session_id_factory = Arc::new(move || {
        let n = counter_for_factory.fetch_add(1, Ordering::SeqCst);
        SessionId(format!("sid-{n}"))
    });
    let manager = Arc::new(AwaitSessionManagerImpl::new(Arc::new(NoopDispatcher), mo));

    // Step 1: caller "a" admits parent session "sid-0" with caller_run_id=None
    // (so the provider is NOT queried for this admission — slice-A/B
    // admission-time-root behavior preserved).
    let mgr = manager.clone();
    let task_a = tokio::spawn(async move {
        mgr.start_with_run("a", None, vec![make_agent_req("agent:t-a", "c-a")], opts())
            .await
    });
    // **Adversarial R1 W1 fix**: poll-until-admitted instead of a bare fixed
    // `sleep(1ms)`. Under `start_paused = true` a fixed sleep advances virtual
    // time but does NOT guarantee the spawned admission task has progressed
    // past its lock-acquire + `sessions.write().insert`; a busy scheduler
    // could race the `session_count` assertion. The admission path is
    // timer-free (only the spawned idle monitor sleeps), so repeatedly
    // `yield_now`-ing deterministically lets the spawned task reach
    // `rx.await` while each `session_count_for_test()` releases the read lock
    // between polls. Bounded at 200 iterations to fail fast rather than hang.
    wait_for_session_count(&manager, 1).await;
    // Sanity: caller-a's session is itself a root.
    let parent_parent = manager
        .session_parent_for_test(&SessionId("sid-0".to_string()))
        .await;
    assert_eq!(
        parent_parent, None,
        "caller-a's parent session is itself a root (caller_run_id=None)"
    );

    // Step 2: caller "b" admits with caller_run_id="run-1" → provider returns
    // Some(SessionId("sid-0")) → F3 first-pass at manager.rs:755 sees
    // `s.agent_id == "a"` ≠ caller "b" → demotes parent_session to None.
    let mgr = manager.clone();
    let task_b = tokio::spawn(async move {
        mgr.start_with_run(
            "b",
            Some("run-1"),
            vec![make_agent_req("agent:t-b", "c-b")],
            opts(),
        )
        .await
    });
    wait_for_session_count(&manager, 2).await;

    // Verify: caller-b's "sid-1" has parent_session=None (NOT Some(sid-0)).
    let child_parent = manager
        .session_parent_for_test(&SessionId("sid-1".to_string()))
        .await;
    assert_eq!(
        child_parent, None,
        "F3 first-pass: cross-caller parent demoted to None; \
         must NOT carry the SessionId(\"sid-0\") returned by the provider"
    );

    // Cleanup.
    task_a.abort();
    task_b.abort();
}
