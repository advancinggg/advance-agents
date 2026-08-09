//! MODULE-007 AC-07 + AC-15 — admission / dispatch error triage (slice m007-A).
//!
//! T07a/b/c/d: AC-07 admission whole-call + per-slot Err categorization.
//! T15a/b/c: AC-15 error triage rules — exhaustive classifiers + reason format.

use std::sync::Arc;

use async_trait::async_trait;

use advance_messaging::dispatcher::MailboxDispatcher;
use advance_shared_types::await_session::{
    AgentAwaitRequest, AwaitMode, AwaitOptions, AwaitRequest, AwaitSessionStatus,
    ComponentAwaitRequest, OrchestrationError, ReplyStatus, TimeoutPolicy,
};
use advance_shared_types::mailbox::{Message, MessageContext, MsgError, NotifyError};

use advance_reply_tracker::{
    AdmissionError, AwaitSessionManager, AwaitSessionManagerImpl, DispatchSlotError,
    ManagerOptions, MAX_FANOUT, MAX_IDLE_TIMEOUT_SECS_CAP, MAX_INFLIGHT, MAX_PAYLOAD_BYTES,
    MAX_REASON_LEN,
};

// Bring in non-pub fns by re-importing the error module. They are pub from
// `crate::error::*` in lib.rs only as `AdmissionError` / `DispatchSlotError`.
// Direct path access for tests:
use advance_reply_tracker::error::{classify_admission, classify_dispatch, format_per_slot_reason};

// ── MockMailboxDispatcher (with injectable errors) ────────────────────

#[derive(Default)]
struct MockDispatcher {
    inject_invalid_target: Arc<tokio::sync::Mutex<Vec<String>>>,
}

impl MockDispatcher {
    fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }
}

#[async_trait]
impl MailboxDispatcher for MockDispatcher {
    async fn deliver(&self, target: &str, _msg: Message) -> Result<(), MsgError> {
        let inject = self.inject_invalid_target.lock().await;
        if inject.iter().any(|t| t == target) || inject.iter().any(|t| t == "*") {
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

fn make_agent_req(target: &str, correlation_id: &str) -> AwaitRequest {
    AwaitRequest::AgentRequest(AgentAwaitRequest {
        target: target.to_string(),
        payload: vec![],
        correlation_id: correlation_id.to_string(),
        context: None,
    })
}

// ── T07 AC-07 admission + per-slot ────────────────────────────────────

#[tokio::test(flavor = "current_thread")]
async fn t07a_admission_capability_denied_returns_err() {
    let dispatcher: Arc<dyn MailboxDispatcher> = MockDispatcher::new();
    let options = ManagerOptions {
        cap_check: Arc::new(|_caller: &str| false),
        ..ManagerOptions::default()
    };
    let manager = Arc::new(AwaitSessionManagerImpl::new(dispatcher, options));

    let req_options = AwaitOptions {
        mode: AwaitMode::AllOf,
        idle_timeout_secs: None,
        on_idle_timeout: TimeoutPolicy::Fail,
        keep_losers: false,
    };
    let requests = vec![make_agent_req("agent:t1", "c1")];

    let result = manager.start("researcher", requests, req_options).await;
    assert!(matches!(
        result,
        Err(OrchestrationError::CapabilityDenied(_))
    ));
}

#[tokio::test(flavor = "current_thread")]
async fn t07b_admission_empty_requests_returns_err() {
    let dispatcher: Arc<dyn MailboxDispatcher> = MockDispatcher::new();
    let manager = Arc::new(AwaitSessionManagerImpl::new(
        dispatcher,
        ManagerOptions::default(),
    ));

    let options = AwaitOptions {
        mode: AwaitMode::AllOf,
        idle_timeout_secs: None,
        on_idle_timeout: TimeoutPolicy::Fail,
        keep_losers: false,
    };
    let requests = vec![];

    let result = manager.start("researcher", requests, options).await;
    match result {
        Err(OrchestrationError::InvalidRequest(s)) => {
            assert!(s.contains("empty"), "expected 'empty' in message, got {s}");
        }
        other => panic!("expected Err(InvalidRequest), got {other:?}"),
    }
}

#[tokio::test(flavor = "current_thread")]
async fn t07c_admission_session_limit_exceeded() {
    let dispatcher: Arc<dyn MailboxDispatcher> = MockDispatcher::new();
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

    // Spawn MAX_INFLIGHT (3) concurrent sessions for "researcher".
    let mut handles = Vec::new();
    for i in 0..MAX_INFLIGHT {
        let mgr = manager.clone();
        let opts = options.clone();
        let requests = vec![make_agent_req("agent:t1", &format!("corr-{i}"))];
        handles.push(tokio::spawn(async move {
            mgr.start("researcher", requests, opts).await
        }));
    }

    // Yield enough for all spawn'd starts to register sessions.
    for _ in 0..6 {
        tokio::task::yield_now().await;
    }

    // The 4th start should fail with SessionLimitExceeded.
    let result = manager
        .start(
            "researcher",
            vec![make_agent_req("agent:t1", "corr-4")],
            options,
        )
        .await;
    assert!(matches!(
        result,
        Err(OrchestrationError::SessionLimitExceeded(_))
    ));

    // Clean up the dangling spawned tasks by aborting them; the manager
    // holds the oneshot Sender, so dropping the rx via abort causes the
    // start() future to resolve (or be cancelled).
    for h in handles {
        h.abort();
        let _ = h.await;
    }
}

#[tokio::test(flavor = "current_thread")]
async fn t07d_all_failed_dispatch_returns_ok_with_failed_dispatch_status() {
    let mock = MockDispatcher::new();
    {
        let mut inject = mock.inject_invalid_target.lock().await;
        inject.push("*".to_string()); // Inject error on all targets.
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
        make_agent_req("agent:t1", "c1"),
        make_agent_req("agent:t2", "c2"),
        make_agent_req("agent:t3", "c3"),
    ];

    let result = manager.start("researcher", requests, options).await;
    let result = result.expect("all-failed dispatch returns Ok per PRD §9.2");
    assert_eq!(result.status, AwaitSessionStatus::FailedDispatch);
    assert_eq!(result.replies.len(), 3);
    for (idx, reply) in result.replies.iter().enumerate() {
        match &reply.status {
            ReplyStatus::Failed(reason) => {
                assert!(
                    reason.starts_with("invalid-target:"),
                    "expected 'invalid-target:' prefix on slot {idx}, got {reason}"
                );
            }
            other => panic!("slot {idx} should be Failed, got {other:?}"),
        }
    }
}

// ── T15 AC-15 error triage rules ──────────────────────────────────────

#[test]
fn t15a_classify_admission_exhaustive() {
    assert!(matches!(
        classify_admission(AdmissionError::CapabilityDenied("caller".into())),
        OrchestrationError::CapabilityDenied(_)
    ));
    assert!(matches!(
        classify_admission(AdmissionError::SessionLimitExceeded("caller".into())),
        OrchestrationError::SessionLimitExceeded(_)
    ));
    assert!(matches!(
        classify_admission(AdmissionError::DeadlockAll("agent:victim".into())),
        OrchestrationError::DeadlockDetected(_)
    ));
    assert!(matches!(
        classify_admission(AdmissionError::InvalidRequest("empty requests".into())),
        OrchestrationError::InvalidRequest(_)
    ));
}

#[test]
fn t15b_classify_dispatch_exhaustive_5_variants() {
    let target = "agent:t1";

    let r1 = classify_dispatch(MsgError::InvalidTarget(target.into()), target);
    assert!(matches!(r1, DispatchSlotError::InvalidTarget(_)));
    assert_eq!(format_per_slot_reason(&r1), "invalid-target:agent:t1");

    let r2 = classify_dispatch(MsgError::MailboxFull, target);
    assert!(matches!(r2, DispatchSlotError::MailboxFull(_)));
    assert_eq!(format_per_slot_reason(&r2), "mailbox-full:agent:t1");

    let r3 = classify_dispatch(MsgError::CircuitBreakerOpen("breaker-open".into()), target);
    assert!(matches!(r3, DispatchSlotError::CircuitBreakerOpen(_)));
    assert_eq!(
        format_per_slot_reason(&r3),
        "circuit-breaker-open:breaker-open"
    );

    let r4 = classify_dispatch(MsgError::CapabilityDenied("cap-denied".into()), target);
    assert!(matches!(r4, DispatchSlotError::CapabilityDenied(_)));
    assert_eq!(format_per_slot_reason(&r4), "capability-denied:cap-denied");

    let r5 = classify_dispatch(MsgError::InvalidPayload("bad-utf8".into()), target);
    assert!(matches!(r5, DispatchSlotError::InvalidPayload(_)));
    assert_eq!(format_per_slot_reason(&r5), "invalid-payload:bad-utf8");
}

// ── AC-07 admission security caps (Adversarial round 1 fixes) ───────

#[tokio::test(flavor = "current_thread")]
async fn t07e_admission_rejects_invalid_caller_id() {
    let dispatcher: Arc<dyn MailboxDispatcher> = MockDispatcher::new();
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
    let requests = vec![make_agent_req("agent:t1", "c1")];

    // Caller with newline → not a safe id-body.
    let result = manager
        .start("evil\ncaller", requests.clone(), options.clone())
        .await;
    assert!(matches!(result, Err(OrchestrationError::InvalidRequest(_))));

    // Empty caller.
    let result = manager.start("", requests.clone(), options.clone()).await;
    assert!(matches!(result, Err(OrchestrationError::InvalidRequest(_))));

    // Multi-colon body.
    let result = manager.start("foo:bar", requests, options).await;
    assert!(matches!(result, Err(OrchestrationError::InvalidRequest(_))));
}

#[tokio::test(flavor = "current_thread")]
async fn t07f_admission_rejects_oversize_fanout() {
    let dispatcher: Arc<dyn MailboxDispatcher> = MockDispatcher::new();
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

    // MAX_FANOUT + 1 requests → rejected.
    let many: Vec<AwaitRequest> = (0..(MAX_FANOUT + 1))
        .map(|i| make_agent_req(&format!("agent:t{i}"), &format!("c{i}")))
        .collect();
    let result = manager.start("researcher", many, options).await;
    match result {
        Err(OrchestrationError::InvalidRequest(s)) => {
            assert!(s.contains("MAX_FANOUT"));
        }
        other => panic!("expected InvalidRequest(MAX_FANOUT...), got {other:?}"),
    }
}

#[tokio::test(flavor = "current_thread")]
async fn t07g_admission_rejects_oversize_idle_timeout() {
    let dispatcher: Arc<dyn MailboxDispatcher> = MockDispatcher::new();
    let manager = Arc::new(AwaitSessionManagerImpl::new(
        dispatcher,
        ManagerOptions::default(),
    ));
    let options = AwaitOptions {
        mode: AwaitMode::AllOf,
        idle_timeout_secs: Some(MAX_IDLE_TIMEOUT_SECS_CAP + 1),
        on_idle_timeout: TimeoutPolicy::ReturnPartial,
        keep_losers: false,
    };
    let requests = vec![make_agent_req("agent:t1", "c1")];

    let result = manager.start("researcher", requests, options).await;
    match result {
        Err(OrchestrationError::InvalidRequest(s)) => {
            assert!(s.contains("MAX_IDLE_TIMEOUT_SECS_CAP"));
        }
        other => panic!("expected InvalidRequest(idle_timeout_secs...), got {other:?}"),
    }
}

#[test]
fn t15d_format_per_slot_reason_strips_control_chars_and_bounds_length() {
    // Strip control chars: newline, null, CR.
    let err = DispatchSlotError::CapabilityDenied("attacker\nfake:line\0other".to_string());
    let formatted = advance_reply_tracker::error::format_per_slot_reason(&err);
    assert!(
        !formatted.contains('\n') && !formatted.contains('\0') && !formatted.contains('\r'),
        "control chars must be stripped: {formatted:?}"
    );
    // Length bound: a 4000-char payload truncates at MAX_REASON_LEN total.
    let huge = "x".repeat(4000);
    let err = DispatchSlotError::InvalidPayload(huge);
    let formatted = advance_reply_tracker::error::format_per_slot_reason(&err);
    assert!(
        formatted.len() <= MAX_REASON_LEN,
        "reason length {} exceeds MAX_REASON_LEN {MAX_REASON_LEN}",
        formatted.len()
    );
}

// ── AC-15 W4 on_reply OOB slot returns Err ─────────────────────────────

#[tokio::test(flavor = "current_thread")]
async fn t15e_on_reply_oob_slot_returns_err() {
    let dispatcher: Arc<dyn MailboxDispatcher> = MockDispatcher::new();
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
    let requests = vec![make_agent_req("agent:t1", "c1")];
    let mgr = manager.clone();
    let h = tokio::spawn(async move { mgr.start("researcher", requests, options).await });
    for _ in 0..4 {
        tokio::task::yield_now().await;
    }
    let session_id = manager.first_open_session_id_for_test().await;

    let oob_result = manager
        .on_reply(
            &session_id,
            u32::MAX,
            advance_shared_types::await_session::ReplyResult {
                slot: u32::MAX,
                source: "agent:t1".to_string(),
                payload: vec![],
                status: advance_shared_types::await_session::ReplyStatus::Completed,
                received_at: chrono::Utc::now(),
                task_id: None,
            },
        )
        .await;
    assert!(matches!(
        oob_result,
        Err(OrchestrationError::InvalidRequest(_))
    ));

    // Clean up.
    let _ = manager.close(&session_id, "test-cleanup").await;
    let _ = h.await;
    let _ = session_id; // suppress unused if needed
}

// ── Adversarial round 3 fixes — additional admission caps ─────────────

#[tokio::test(flavor = "current_thread")]
async fn t07h_admission_rejects_oversize_payload() {
    let dispatcher: Arc<dyn MailboxDispatcher> = MockDispatcher::new();
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
    // Payload exceeds MAX_PAYLOAD_BYTES (64 KiB).
    let huge = vec![0u8; MAX_PAYLOAD_BYTES + 1];
    let requests = vec![AwaitRequest::AgentRequest(AgentAwaitRequest {
        target: "agent:t1".to_string(),
        payload: huge,
        correlation_id: "c1".to_string(),
        context: None,
    })];

    let result = manager.start("researcher", requests, options).await;
    match result {
        Err(OrchestrationError::InvalidRequest(s)) => {
            assert!(s.contains("MAX_PAYLOAD_BYTES"));
        }
        other => panic!("expected InvalidRequest(MAX_PAYLOAD_BYTES...), got {other:?}"),
    }
}

#[tokio::test(flavor = "current_thread")]
async fn t07i_admission_rejects_unsafe_correlation_id() {
    let dispatcher: Arc<dyn MailboxDispatcher> = MockDispatcher::new();
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
        // Newline injection attempt.
        correlation_id: "c1\nLOG=INJECT".to_string(),
        context: None,
    })];

    let result = manager.start("researcher", requests, options).await;
    assert!(matches!(result, Err(OrchestrationError::InvalidRequest(_))));
}

#[tokio::test(flavor = "current_thread")]
async fn t07j_admission_rejects_unsafe_component_id() {
    let dispatcher: Arc<dyn MailboxDispatcher> = MockDispatcher::new();
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
        component_id: "comp:evil\nINJECTION".to_string(),
        correlation_id: "valid-corr".to_string(),
    })];

    let result = manager.start("researcher", requests, options).await;
    assert!(matches!(result, Err(OrchestrationError::InvalidRequest(_))));
}

#[tokio::test(flavor = "current_thread")]
async fn t15f_on_reply_rejects_slot_mismatch() {
    use advance_shared_types::await_session::ComponentAwaitRequest as CompReq;
    let _ = CompReq {
        component_id: "x".into(),
        correlation_id: "y".into(),
    };

    let dispatcher: Arc<dyn MailboxDispatcher> = MockDispatcher::new();
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
    let requests = vec![make_agent_req("agent:t1", "c1")];
    let mgr = manager.clone();
    let h = tokio::spawn(async move { mgr.start("researcher", requests, options).await });
    for _ in 0..4 {
        tokio::task::yield_now().await;
    }
    let session_id = manager.first_open_session_id_for_test().await;

    // reply.slot mismatched with the function slot arg → InvalidRequest.
    let mismatch_result = manager
        .on_reply(
            &session_id,
            0,
            advance_shared_types::await_session::ReplyResult {
                slot: 99, // mismatched!
                source: "agent:t1".to_string(),
                payload: vec![],
                status: advance_shared_types::await_session::ReplyStatus::Completed,
                received_at: chrono::Utc::now(),
                task_id: None,
            },
        )
        .await;
    assert!(matches!(
        mismatch_result,
        Err(OrchestrationError::InvalidRequest(_))
    ));

    let _ = manager.close(&session_id, "test-cleanup").await;
    let _ = h.await;
}

#[tokio::test(flavor = "current_thread")]
async fn t15g_on_reply_source_mismatch_error_sanitized() {
    let dispatcher: Arc<dyn MailboxDispatcher> = MockDispatcher::new();
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
    let requests = vec![make_agent_req("agent:t1", "c1")];
    let mgr = manager.clone();
    let h = tokio::spawn(async move { mgr.start("researcher", requests, options).await });
    for _ in 0..4 {
        tokio::task::yield_now().await;
    }
    let session_id = manager.first_open_session_id_for_test().await;

    let result = manager
        .on_reply(
            &session_id,
            0,
            advance_shared_types::await_session::ReplyResult {
                slot: 0,
                // Newline-injected source — error message must strip control chars.
                source: "evil\nHIJACK".to_string(),
                payload: vec![],
                status: advance_shared_types::await_session::ReplyStatus::Completed,
                received_at: chrono::Utc::now(),
                task_id: None,
            },
        )
        .await;
    match result {
        Err(OrchestrationError::InvalidRequest(s)) => {
            assert!(
                !s.contains('\n') && !s.contains('\0') && !s.contains('\r'),
                "error message must be sanitized: {s:?}"
            );
        }
        other => panic!("expected InvalidRequest, got {other:?}"),
    }

    let _ = manager.close(&session_id, "test-cleanup").await;
    let _ = h.await;
}

#[test]
fn t15c_orchestration_error_exhaustive_taxonomy() {
    // Compile-time exhaustive match over the 9 OrchestrationError variants
    // proves the slice-A taxonomy is complete. Each variant is annotated
    // with its triage category in this test.
    fn category(e: &OrchestrationError) -> &'static str {
        match e {
            // Admission (whole-call Err)
            OrchestrationError::CapabilityDenied(_) => "admission",
            OrchestrationError::SessionLimitExceeded(_) => "admission",
            OrchestrationError::DeadlockDetected(_) => "admission",
            OrchestrationError::InvalidRequest(_) => "admission",
            // Wait (during oneshot resolution)
            OrchestrationError::SessionClosed(_) => "wait",
            OrchestrationError::IdleTimeoutExceeded(_) => "wait",
            // Internal / lookup (Rust-only — project to WIT invalid-target)
            OrchestrationError::NotFound(_) => "internal",
            OrchestrationError::Downstream(_) => "internal",
            // Bridge variant — admission aggregate OR WIT projection
            OrchestrationError::InvalidTarget(_) => "admission-or-wit-projection",
        }
    }
    // Test passes by virtue of compiling — the exhaustive match means no
    // variant is left unclassified.
    assert_eq!(
        category(&OrchestrationError::CapabilityDenied("x".into())),
        "admission"
    );
    assert_eq!(
        category(&OrchestrationError::NotFound("x".into())),
        "internal"
    );
}

// ── single-pending-target admission constraint (await-leg B-4a) ──
// The code-mandated B-4 activation prerequisite (see `try_route_reply` rustdoc):
// a `send` reply carries no correlation-id, so an owner with ≥2 OPEN slots for the
// SAME agent could mis-route. Admission rejects a duplicate `agent:`-targeted slot;
// the check is gated to the EXACT `try_route_reply` population (`is_safe_id` +
// `agent:`-prefixed), so non-agent / malformed slots are NOT compared.

#[tokio::test(flavor = "current_thread")]
async fn t07spt_a_duplicate_agent_target_rejected() {
    // Two AgentRequest slots to the SAME bare agent → InvalidRequest BEFORE dispatch.
    let dispatcher: Arc<dyn MailboxDispatcher> = MockDispatcher::new();
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
        make_agent_req("agent:dup", "c1"),
        make_agent_req("agent:dup", "c2"),
    ];
    match manager.start("researcher", requests, options).await {
        Err(OrchestrationError::InvalidRequest(s)) => {
            assert!(
                s.contains("single-pending-target"),
                "reason should name the single-pending-target constraint, got: {s:?}"
            );
        }
        other => panic!("expected InvalidRequest(single-pending-target...), got {other:?}"),
    }
}

#[tokio::test(flavor = "current_thread")]
async fn t07spt_b_distinct_agent_targets_admit() {
    // Distinct agent targets are the normal fan-out — admission must PASS. Inject
    // all-dispatch-fail so `start` returns Ok(FailedDispatch) immediately (proving
    // admission passed) instead of parking on the AllOf await.
    let mock = MockDispatcher::new();
    {
        let mut inject = mock.inject_invalid_target.lock().await;
        inject.push("*".to_string());
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
        make_agent_req("agent:a", "c1"),
        make_agent_req("agent:b", "c2"),
    ];
    let result = manager
        .start("researcher", requests, options)
        .await
        .expect("distinct targets admit (all-failed dispatch → Ok, not an admission Err)");
    assert_eq!(result.status, AwaitSessionStatus::FailedDispatch);
}

#[tokio::test(flavor = "current_thread")]
async fn t07spt_c_duplicate_non_agent_target_admits_no_over_rejection() {
    // Two identical NON-agent (`user:`) targets: the constraint's `agent:`-gating
    // EXCLUDES them (they are not reply-routable via `try_route_reply`), so admission
    // must PASS — a naive ungated check would wrongly reject them (AC-07/behaviour
    // regression). Inject all-fail so `start` returns Ok immediately.
    let mock = MockDispatcher::new();
    {
        let mut inject = mock.inject_invalid_target.lock().await;
        inject.push("*".to_string());
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
        make_agent_req("user:x", "c1"),
        make_agent_req("user:x", "c2"),
    ];
    let result = manager
        .start("researcher", requests, options)
        .await
        .expect("non-agent targets are excluded from the constraint → admission passes");
    assert_eq!(result.status, AwaitSessionStatus::FailedDispatch);
}
