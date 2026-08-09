//! AC-11 (REQ-101) — `AgentActionDispatcher::dispatch` invokes
//! `ActionValidator::validate` as the first step + emits
//! `security.action_rejected` on rejection (via `RejectionSink`).
//!
//! T-A15..T-A18: gate + recording sink.
//! T-A19: production `EventBusRejectionSink` emit path.

mod common;

use std::sync::Arc;

use advance_messaging::{AgentActionDispatcherImpl, EventBusRejectionSink, MAX_BATCH_SIZE};
use advance_shared_types::mailbox::{AgentAction, AgentActionDispatcher, DispatchError};
use advance_shared_types::security_validator::{ActionValidator, SecurityError};

use crate::common::{
    test_message, MockEventBusEmit, PermissiveValidator, RecordingSink, RecordingValidator,
};

// T-A15 — validator-Err → ValidationFailed + sink observation.
#[tokio::test]
async fn t_a15_validator_err_routed_to_dispatch_error() {
    let validator: Arc<dyn ActionValidator> = Arc::new(RecordingValidator::new_rejecting(
        SecurityError::OversizedMessage,
    ));
    let sink = Arc::new(RecordingSink::new());
    let dispatcher = AgentActionDispatcherImpl::new(validator.clone(), sink.clone());
    let actions = vec![AgentAction { payload: vec![] }];
    let err = dispatcher
        .dispatch("agent:x", &test_message(), &actions)
        .await
        .expect_err("validator-Err must propagate");
    match err {
        DispatchError::ValidationFailed(SecurityError::OversizedMessage) => {}
        other => panic!("expected ValidationFailed(OversizedMessage), got {other:?}"),
    }
    let rejections = sink.rejections.lock().unwrap();
    assert_eq!(rejections.len(), 1);
    assert_eq!(rejections[0].0, "agent:x");
    assert_eq!(rejections[0].1, SecurityError::OversizedMessage);
}

// T-A16 — permissive validator → Ok, sink unchanged.
#[tokio::test]
async fn t_a16_permissive_validator_ok_no_side_effect() {
    let validator: Arc<dyn ActionValidator> = Arc::new(PermissiveValidator);
    let sink = Arc::new(RecordingSink::new());
    let dispatcher = AgentActionDispatcherImpl::new(validator, sink.clone());
    let actions = vec![AgentAction {
        payload: vec![1, 2, 3],
    }];
    dispatcher
        .dispatch("agent:x", &test_message(), &actions)
        .await
        .expect("permissive validator must return Ok");
    assert_eq!(sink.count(), 0);
}

// T-A17 — validator-first: validator IS called when validator returns Err.
#[tokio::test]
async fn t_a17_validator_is_called_on_rejection_path() {
    let validator = Arc::new(RecordingValidator::new_rejecting(
        SecurityError::InvalidAction("test_invalid".into()),
    ));
    let sink = Arc::new(RecordingSink::new());
    let dispatcher = AgentActionDispatcherImpl::new(validator.clone(), sink.clone());
    let actions = vec![
        AgentAction { payload: vec![] },
        AgentAction { payload: vec![] },
    ];
    let _ = dispatcher
        .dispatch("agent:y", &test_message(), &actions)
        .await;
    assert_eq!(
        validator.call_count(),
        1,
        "validator must be called exactly once"
    );
    assert_eq!(sink.count(), 1, "sink must observe one rejection");
}

// T-A18 — batch_too_large → reject BEFORE validator invocation.
#[tokio::test]
async fn t_a18_batch_too_large_pre_validator_reject() {
    let validator = Arc::new(RecordingValidator::new_permissive());
    let sink = Arc::new(RecordingSink::new());
    let dispatcher = AgentActionDispatcherImpl::new(validator.clone(), sink.clone());
    let actions: Vec<AgentAction> = (0..(MAX_BATCH_SIZE + 1))
        .map(|_| AgentAction { payload: vec![] })
        .collect();
    let err = dispatcher
        .dispatch("agent:z", &test_message(), &actions)
        .await
        .expect_err("oversized batch must reject");
    match err {
        DispatchError::ValidationFailed(SecurityError::InvalidAction(reason)) => {
            assert_eq!(reason, "batch_too_large");
        }
        other => panic!("expected ValidationFailed(InvalidAction(batch_too_large)), got {other:?}"),
    }
    assert_eq!(
        validator.call_count(),
        0,
        "validator must NOT be called for oversized batch"
    );
    assert_eq!(
        sink.count(),
        1,
        "sink must observe the dispatcher-level rejection"
    );
}

// T-A19 — production EventBusRejectionSink emit path.
#[tokio::test]
async fn t_a19_event_bus_rejection_sink_emits_security_event() {
    let validator: Arc<dyn ActionValidator> = Arc::new(RecordingValidator::new_rejecting(
        SecurityError::CapabilityDenied("missing_cap".into()),
    ));
    let bus = Arc::new(MockEventBusEmit::new());
    let sink = Arc::new(EventBusRejectionSink::new(bus.clone()));
    let dispatcher = AgentActionDispatcherImpl::new(validator, sink);
    let actions = vec![AgentAction { payload: vec![] }];
    let _ = dispatcher
        .dispatch("agent:emitter", &test_message(), &actions)
        .await;
    let events = bus.events.lock().unwrap();
    assert_eq!(events.len(), 1, "exactly one event emitted");
    let ev = &events[0];
    assert_eq!(ev.event_type, "security.action_rejected");
    assert_eq!(ev.agent_id, "agent:emitter");
    let kind = ev.payload.get("error_kind").and_then(|v| v.as_str());
    assert_eq!(kind, Some("capability_denied"));
}
