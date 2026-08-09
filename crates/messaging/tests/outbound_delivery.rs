//! Phase-2 reply-delivery slice (slice B) — `OutboundActionSink` post-dispatch
//! delivery seam on `AgentActionDispatcherImpl`.
//!
//! T-OB1: validated batch → outbound `deliver` called once with the payloads;
//!        rejection sink untouched; `Ok(())`.
//! T-OB2: validator-rejected batch → outbound NOT called (validator-first);
//!        rejection sink observes; `Err(ValidationFailed)`.
//! T-OB3: empty validated batch → outbound `deliver` called once with an empty
//!        slice (so a no-action turn is observable); back-compat: a dispatcher
//!        built WITHOUT `with_outbound` stays gate-only (`Ok(())`, no delivery).

mod common;

use std::sync::{Arc, Mutex};

use advance_messaging::{AgentActionDispatcherImpl, OutboundActionSink, MAX_BATCH_SIZE};
use advance_shared_types::mailbox::{AgentAction, AgentActionDispatcher, DispatchError, Message};
use advance_shared_types::outbound::DeliveryReport;
use advance_shared_types::security_validator::{ActionValidator, SecurityError};

use crate::common::{test_message, PermissiveValidator, RecordingSink, RecordingValidator};

/// Test `OutboundActionSink` capturing each `deliver(agent_id, source, actions)` call.
struct RecordingOutbound {
    calls: Mutex<Vec<(String, Vec<Vec<u8>>)>>,
}

impl RecordingOutbound {
    fn new() -> Self {
        Self {
            calls: Mutex::new(Vec::new()),
        }
    }
    fn count(&self) -> usize {
        self.calls.lock().unwrap().len()
    }
    fn calls(&self) -> Vec<(String, Vec<Vec<u8>>)> {
        self.calls.lock().unwrap().clone()
    }
}

#[async_trait::async_trait]
impl OutboundActionSink for RecordingOutbound {
    async fn deliver(
        &self,
        agent_id: &str,
        _source: &Message,
        actions: &[AgentAction],
    ) -> Result<DeliveryReport, DispatchError> {
        let payloads = actions.iter().map(|a| a.payload.clone()).collect();
        self.calls
            .lock()
            .unwrap()
            .push((agent_id.to_string(), payloads));
        Ok(DeliveryReport::empty())
    }
}

// T-OB1 — validated batch routes to the outbound sink exactly once.
#[tokio::test]
async fn t_ob1_validated_batch_routed_to_outbound() {
    let validator: Arc<dyn ActionValidator> = Arc::new(PermissiveValidator);
    let sink = Arc::new(RecordingSink::new());
    let outbound = Arc::new(RecordingOutbound::new());
    let dispatcher =
        AgentActionDispatcherImpl::new(validator, sink.clone()).with_outbound(outbound.clone());
    let actions = vec![AgentAction {
        payload: b"reply text".to_vec(),
    }];
    dispatcher
        .dispatch("agent:x", &test_message(), &actions)
        .await
        .expect("permissive validator → Ok");
    let calls = outbound.calls();
    assert_eq!(calls.len(), 1, "outbound deliver called exactly once");
    assert_eq!(calls[0].0, "agent:x");
    assert_eq!(
        calls[0].1,
        vec![b"reply text".to_vec()],
        "payload routed verbatim"
    );
    assert_eq!(sink.count(), 0, "no rejection on the happy path");
}

// T-OB2 — validator-first: a rejected batch never reaches the outbound sink.
#[tokio::test]
async fn t_ob2_rejected_batch_not_routed_to_outbound() {
    let validator: Arc<dyn ActionValidator> = Arc::new(RecordingValidator::new_rejecting(
        SecurityError::OversizedMessage,
    ));
    let sink = Arc::new(RecordingSink::new());
    let outbound = Arc::new(RecordingOutbound::new());
    let dispatcher =
        AgentActionDispatcherImpl::new(validator, sink.clone()).with_outbound(outbound.clone());
    let actions = vec![AgentAction {
        payload: b"too big".to_vec(),
    }];
    let err = dispatcher
        .dispatch("agent:x", &test_message(), &actions)
        .await
        .expect_err("validator rejects");
    assert!(matches!(
        err,
        DispatchError::ValidationFailed(SecurityError::OversizedMessage)
    ));
    assert_eq!(
        outbound.count(),
        0,
        "outbound must NOT be called on rejection"
    );
    assert_eq!(sink.count(), 1, "rejection recorded");

    // Also: a pre-validator batch-too-large rejection never routes to outbound.
    let outbound2 = Arc::new(RecordingOutbound::new());
    let dispatcher2 = AgentActionDispatcherImpl::new(
        Arc::new(PermissiveValidator),
        Arc::new(RecordingSink::new()),
    )
    .with_outbound(outbound2.clone());
    let big: Vec<AgentAction> = (0..(MAX_BATCH_SIZE + 1))
        .map(|_| AgentAction { payload: vec![] })
        .collect();
    let _ = dispatcher2
        .dispatch("agent:x", &test_message(), &big)
        .await
        .expect_err("batch too large");
    assert_eq!(
        outbound2.count(),
        0,
        "oversized batch must NOT route to outbound"
    );
}

// T-OB3 — empty validated batch still fires outbound once (observable no-action
// turn); and a dispatcher without `with_outbound` stays gate-only.
#[tokio::test]
async fn t_ob3_empty_batch_fires_once_and_gate_only_backcompat() {
    // (a) empty batch → deliver once with an empty slice.
    let outbound = Arc::new(RecordingOutbound::new());
    let dispatcher = AgentActionDispatcherImpl::new(
        Arc::new(PermissiveValidator),
        Arc::new(RecordingSink::new()),
    )
    .with_outbound(outbound.clone());
    dispatcher
        .dispatch("agent:x", &test_message(), &[])
        .await
        .expect("empty batch validates → Ok");
    let calls = outbound.calls();
    assert_eq!(
        calls.len(),
        1,
        "outbound fires once even for an empty batch"
    );
    assert!(calls[0].1.is_empty(), "the batch is empty");

    // (b) back-compat: no `with_outbound` → gate-only (Ok, nothing delivered).
    let gate_only = AgentActionDispatcherImpl::new(
        Arc::new(PermissiveValidator),
        Arc::new(RecordingSink::new()),
    );
    gate_only
        .dispatch(
            "agent:x",
            &test_message(),
            &[AgentAction {
                payload: b"x".to_vec(),
            }],
        )
        .await
        .expect("gate-only dispatcher returns Ok with no outbound wired");
}
