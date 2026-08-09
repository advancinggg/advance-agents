//! MODULE-007 REQ-092 code-progress — 4 in-boundary `await-replies`
//! capability admission knobs (slice m007-B). AC-18 itself stays untested
//! (the 5th knob `max-depth` needs the deferred AC-16 nested-tree); this
//! suite proves the 4 in-boundary knobs as honest code-progress.
//!
//! T18a: `targets` allowlist (bare per PRD YAML) — `agent:deny` →
//!       `Err(CapabilityDenied)` 0 deliver; `agent:ok` (normalized "ok" ∈
//!       allowlist) admitted (proves `agent:`-prefix normalization).
//! T18b: `max_fanout: Some(2)` + 3-slot → `Err(InvalidRequest)` pre-dispatch.
//! T18c: `max_inflight: Some(1)` + 2nd concurrent same caller →
//!       `Err(SessionLimitExceeded)`.
//! T18d: `max_idle_timeout_secs: Some(60)` + req `idle_timeout_secs:
//!       Some(120)` → `Err(InvalidRequest)` with the DISCRIMINATOR reason
//!       `"capability:max-idle-timeout-exceeded"`.
//! T18e: default `CapabilityConfig` (all None) → slice-A behavior.
//! T18f: `targets: Some(["ok"])` + malformed target `"agent:a:b"` → NOT
//!       whole-call `CapabilityDenied`; falls through to per-slot dispatch →
//!       `Failed("invalid-target:..")` (AC-07 preserved).
//! T18g: `max_idle_timeout_secs: Some(30)` + caller OMITS `idle_timeout_secs`
//!       (`None`) + manager `idle_timeout_default_sec` = 600 → the EFFECTIVE
//!       idle timeout must be CLAMPED to the capability ceiling (30s), not the
//!       larger default — the session idle-times-out by vt≈35s. Without the
//!       AUDIT-round-16 W2 clamp the effective timeout would be 600s and the
//!       session would NOT resolve at 35s (regression lock for the
//!       omitted-field capability-ceiling bypass).

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;

use advance_messaging::dispatcher::MailboxDispatcher;
use advance_shared_types::await_session::{
    AgentAwaitRequest, AwaitMode, AwaitOptions, AwaitRequest, AwaitSessionStatus,
    OrchestrationError, ReplyStatus, TimeoutPolicy,
};
use advance_shared_types::mailbox::{Message, MessageContext, MsgError, NotifyError};

use advance_reply_tracker::{
    AwaitSessionManager, AwaitSessionManagerImpl, CapabilityConfig, ManagerOptions,
};

#[derive(Default)]
struct MockDispatcher {
    calls: Arc<tokio::sync::Mutex<Vec<String>>>,
}

impl MockDispatcher {
    fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }
    async fn calls(&self) -> Vec<String> {
        self.calls.lock().await.clone()
    }
}

#[async_trait]
impl MailboxDispatcher for MockDispatcher {
    async fn deliver(&self, target: &str, _msg: Message) -> Result<(), MsgError> {
        self.calls.lock().await.push(target.to_string());
        // Reject malformed/odd targets so T18f's slot lands as a per-slot
        // invalid-target failure (slice-A dispatcher pre-validates via
        // is_safe_id too; this keeps the test self-contained).
        if !target.starts_with("agent:") || target.matches(':').count() != 1 {
            return Err(MsgError::InvalidTarget(target.to_string()));
        }
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

fn opts(idle: Option<u32>) -> AwaitOptions {
    AwaitOptions {
        mode: AwaitMode::AllOf,
        idle_timeout_secs: idle,
        on_idle_timeout: TimeoutPolicy::ReturnPartial,
        keep_losers: false,
    }
}

/// Advance virtual time in monitor-tick-sized steps so the spawned
/// `idle_monitor_task` (which `sleep(5s)`s) wakes, evaluates, and (when due)
/// resolves between steps. Mirrors `idle_monitor.rs::advance_secs`.
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

// ── T18a targets allowlist (bare) + agent: normalization both ways ────

#[tokio::test(flavor = "current_thread")]
async fn t18a_targets_allowlist_normalizes_agent_prefix() {
    let mock = MockDispatcher::new();
    let dispatcher: Arc<dyn MailboxDispatcher> = mock.clone();
    let options = ManagerOptions {
        capability: CapabilityConfig {
            targets: Some(vec!["ok".to_string()]),
            ..CapabilityConfig::default()
        },
        ..ManagerOptions::default()
    };
    let manager = Arc::new(AwaitSessionManagerImpl::new(dispatcher, options));

    // agent:deny → "deny" ∉ {"ok"} → whole-call CapabilityDenied, 0 deliver.
    let denied = manager
        .start(
            "researcher",
            vec![make_agent_req("agent:deny", "c1")],
            opts(None),
        )
        .await;
    assert!(
        matches!(denied, Err(OrchestrationError::CapabilityDenied(_))),
        "agent:deny not in allowlist → CapabilityDenied, got {denied:?}"
    );
    assert_eq!(
        mock.calls().await.len(),
        0,
        "0 deliver on capability-denied"
    );

    // agent:ok → normalized "ok" ∈ {"ok"} → admitted + dispatched.
    let mgr = manager.clone();
    let h = tokio::spawn(async move {
        mgr.start(
            "researcher",
            vec![make_agent_req("agent:ok", "c2")],
            opts(None),
        )
        .await
    });
    for _ in 0..6 {
        tokio::task::yield_now().await;
    }
    assert_eq!(mock.calls().await, vec!["agent:ok".to_string()]);
    let session_id = manager.first_open_session_id_for_test().await;
    let _ = manager.close(&session_id, "test-cleanup").await;
    let _ = h.await;
}

// ── T18b max_fanout ────────────────────────────────────────────────────

#[tokio::test(flavor = "current_thread")]
async fn t18b_max_fanout_rejected_pre_dispatch() {
    let mock = MockDispatcher::new();
    let dispatcher: Arc<dyn MailboxDispatcher> = mock.clone();
    let options = ManagerOptions {
        capability: CapabilityConfig {
            max_fanout: Some(2),
            ..CapabilityConfig::default()
        },
        ..ManagerOptions::default()
    };
    let manager = Arc::new(AwaitSessionManagerImpl::new(dispatcher, options));

    let requests = vec![
        make_agent_req("agent:t1", "c1"),
        make_agent_req("agent:t2", "c2"),
        make_agent_req("agent:t3", "c3"),
    ];
    let result = manager.start("researcher", requests, opts(None)).await;
    match result {
        Err(OrchestrationError::InvalidRequest(s)) => {
            assert!(
                s.contains("max_fanout"),
                "reason should reference capability max_fanout, got {s}"
            );
        }
        other => panic!("expected InvalidRequest(max_fanout), got {other:?}"),
    }
    assert_eq!(mock.calls().await.len(), 0, "rejected pre-dispatch");
}

// ── T18c max_inflight ──────────────────────────────────────────────────

#[tokio::test(flavor = "current_thread")]
async fn t18c_max_inflight_second_concurrent_rejected() {
    let mock = MockDispatcher::new();
    let dispatcher: Arc<dyn MailboxDispatcher> = mock.clone();
    let options = ManagerOptions {
        capability: CapabilityConfig {
            max_inflight: Some(1),
            ..CapabilityConfig::default()
        },
        ..ManagerOptions::default()
    };
    let manager = Arc::new(AwaitSessionManagerImpl::new(dispatcher, options));

    // First session occupies the only inflight slot for "researcher".
    let mgr1 = manager.clone();
    let h1 = tokio::spawn(async move {
        mgr1.start(
            "researcher",
            vec![make_agent_req("agent:t1", "c1")],
            opts(None),
        )
        .await
    });
    for _ in 0..6 {
        tokio::task::yield_now().await;
    }

    // Second concurrent start for the same caller → SessionLimitExceeded.
    let result = manager
        .start(
            "researcher",
            vec![make_agent_req("agent:t2", "c2")],
            opts(None),
        )
        .await;
    assert!(
        matches!(result, Err(OrchestrationError::SessionLimitExceeded(_))),
        "2nd concurrent (cap max_inflight=1) → SessionLimitExceeded, got {result:?}"
    );

    let session_id = manager.first_open_session_id_for_test().await;
    let _ = manager.close(&session_id, "test-cleanup").await;
    let _ = h1.await;
}

// ── T18d max_idle_timeout_secs — discriminator reason ─────────────────

#[tokio::test(flavor = "current_thread")]
async fn t18d_max_idle_timeout_discriminator_reason() {
    let dispatcher: Arc<dyn MailboxDispatcher> = MockDispatcher::new();
    let options = ManagerOptions {
        capability: CapabilityConfig {
            max_idle_timeout_secs: Some(60),
            ..CapabilityConfig::default()
        },
        ..ManagerOptions::default()
    };
    let manager = Arc::new(AwaitSessionManagerImpl::new(dispatcher, options));

    // 120 ≤ 3600 (slice-A cap, so NOT the slice-A reject) but 120 > 60
    // (capability ceiling) → the new gate fires with its DISTINCT reason.
    let result = manager
        .start(
            "researcher",
            vec![make_agent_req("agent:t1", "c1")],
            opts(Some(120)),
        )
        .await;
    match result {
        Err(OrchestrationError::InvalidRequest(s)) => {
            assert_eq!(
                s, "capability:max-idle-timeout-exceeded",
                "must be the distinct capability discriminator (not the slice-A \
                 MAX_IDLE_TIMEOUT_SECS_CAP reason)"
            );
        }
        other => panic!("expected InvalidRequest(capability:..), got {other:?}"),
    }
}

// ── T18e default CapabilityConfig → slice-A behavior ──────────────────

#[tokio::test(flavor = "current_thread")]
async fn t18e_default_capability_config_back_compat() {
    let mock = MockDispatcher::new();
    let dispatcher: Arc<dyn MailboxDispatcher> = mock.clone();
    // Plain default — all knobs None.
    let manager = Arc::new(AwaitSessionManagerImpl::new(
        dispatcher,
        ManagerOptions::default(),
    ));
    // Any target allowed, no fanout/idle restriction (slice-A behavior).
    let mgr = manager.clone();
    let h = tokio::spawn(async move {
        mgr.start(
            "researcher",
            vec![
                make_agent_req("agent:anything", "c1"),
                make_agent_req("agent:else", "c2"),
            ],
            opts(Some(120)),
        )
        .await
    });
    for _ in 0..6 {
        tokio::task::yield_now().await;
    }
    let mut calls = mock.calls().await;
    calls.sort();
    assert_eq!(
        calls,
        vec!["agent:anything".to_string(), "agent:else".to_string()]
    );
    let session_id = manager.first_open_session_id_for_test().await;
    let _ = manager.close(&session_id, "test-cleanup").await;
    let _ = h.await;
}

// ── T18f malformed target preserves AC-07 (per-slot, not whole-call) ──

#[tokio::test(flavor = "current_thread")]
async fn t18f_malformed_target_preserves_ac07() {
    let mock = MockDispatcher::new();
    let dispatcher: Arc<dyn MailboxDispatcher> = mock.clone();
    let options = ManagerOptions {
        capability: CapabilityConfig {
            targets: Some(vec!["ok".to_string()]),
            ..CapabilityConfig::default()
        },
        ..ManagerOptions::default()
    };
    let manager = Arc::new(AwaitSessionManagerImpl::new(dispatcher, options));

    // "agent:a:b" is malformed (fails is_safe_id — multi-colon body). It
    // must NOT be converted into a whole-call CapabilityDenied; it falls
    // through to the per-slot dispatch invalid-target path. Single slot →
    // all-failed → Ok(FailedDispatch) per PRD §9.2.
    let result = manager
        .start(
            "researcher",
            vec![make_agent_req("agent:a:b", "c1")],
            opts(None),
        )
        .await
        .expect("malformed target is per-slot, not whole-call CapabilityDenied");
    assert_eq!(result.status, AwaitSessionStatus::FailedDispatch);
    assert_eq!(result.replies.len(), 1);
    match &result.replies[0].status {
        ReplyStatus::Failed(reason) => {
            assert!(
                reason.starts_with("invalid-target:"),
                "malformed target → per-slot invalid-target (AC-07 preserved), got {reason}"
            );
        }
        other => panic!("expected Failed(invalid-target:..), got {other:?}"),
    }
}

// ── T18g omitted idle_timeout + capability ceiling → effective clamp ───
//
// AUDIT round 16 W2/W3 regression lock. The CapabilityConfig
// `max_idle_timeout_secs` gate only fires when the caller supplies
// `idle_timeout_secs` (`Some`). A caller that OMITS the field falls back to
// the manager `idle_timeout_default_sec` (default 600). Before the W2 fix
// that default was used UNCLAMPED, so a `max_idle_timeout_secs: Some(30)`
// capability ceiling was silently bypassed (effective idle = 600s). The W2
// fix clamps the effective idle timeout to the ceiling: effective =
// min(600, 30) = 30. Under virtual time the session must idle-resolve by
// vt≈35s; with the bypass (effective 600s) it would still be pending at 35s
// (this test would then hang on `h.await` / fail the assertion).
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn t18g_omitted_idle_timeout_clamped_to_capability_ceiling() {
    let dispatcher: Arc<dyn MailboxDispatcher> = MockDispatcher::new();
    let options = ManagerOptions {
        capability: CapabilityConfig {
            max_idle_timeout_secs: Some(30),
            ..CapabilityConfig::default()
        },
        // idle_timeout_default_sec defaults to MAX_IDLE_TIMEOUT_DEFAULT_SEC
        // (600) — far larger than the 30s capability ceiling.
        ..ManagerOptions::default()
    };
    let manager = Arc::new(AwaitSessionManagerImpl::new(dispatcher, options));

    // Caller OMITS idle_timeout_secs (None) → the :523 capability gate is
    // skipped (its `Some(req_idle)` pattern fails); the effective timeout is
    // resolved from the default and MUST be clamped to the 30s ceiling.
    // Fail policy → a crisp Err(IdleTimeoutExceeded) on resolution.
    let mgr = manager.clone();
    let h = tokio::spawn(async move {
        mgr.start(
            "researcher",
            vec![make_agent_req("agent:t1", "c1")],
            AwaitOptions {
                mode: AwaitMode::AllOf,
                idle_timeout_secs: None,
                on_idle_timeout: TimeoutPolicy::Fail,
                keep_losers: false,
            },
        )
        .await
    });
    for _ in 0..4 {
        tokio::task::yield_now().await;
    }

    // At vt≈25s (< clamped 30s) the session must still be open — it does NOT
    // resolve before its (clamped) deadline.
    advance_secs(25).await;
    assert!(
        !h.is_finished(),
        "session must not resolve before the clamped 30s deadline (vt≈25s)"
    );

    // At vt≈35s (> clamped 30s) the idle monitor fires. This is only
    // reachable if the effective timeout was clamped to 30s — with the
    // bypassed 600s default it would still be pending here.
    advance_secs(10).await;
    let result = h.await.expect("spawn ok");
    assert!(
        matches!(result, Err(OrchestrationError::IdleTimeoutExceeded(_))),
        "omitted idle_timeout must be CLAMPED to the 30s capability ceiling \
         (effective=min(default 600, cap 30)=30) → idle timeout fires by \
         vt≈35s; got {result:?} (a non-timeout/pending result means the \
         capability ceiling was bypassed by the default fallback)"
    );
}
