//! SYS-J-19 (action-review half) — an oversized / abusive agent action is caught by
//! action review BEFORE delivery.
//! Chain: MODULE-010 (context) → MODULE-012 (security) → MODULE-006 (messaging).
//!
//! Witnessed test-local against the REAL `advance_messaging::AgentActionDispatcherImpl`
//! (MODULE-006) gating on the REAL `cap_http::DefaultActionValidator` (MODULE-012,
//! CONTRACT-113) — a real cross-module seam, validator-first. No module is mocked.
//!
//! In-scope SYS-AC: 058, 253.
//!
//! Transparency note: `AgentActionDispatcherImpl` (Slice A) is **gate-only** — per-action
//! decode + delivery are deferred to slice B (`action_dispatcher.rs`: "No mailbox
//! dependency … delivery deferred"). So "not delivered" is satisfied by the validator-first
//! `Err` return ahead of the (not-yet-implemented) delivery step; the witnessed substance
//! is the real validator + the validator-first ordering invariant (the criterion's "caught
//! by the ActionValidator before delivery"). The "untrusted content entering context"
//! sanitization half of SYS-J-19 (SYS-AC-056/057) is deferred — MODULE-010's L4/L5 ingress
//! is explicitly un-wired (§3.6 Slice-D(c)).

use std::sync::Arc;

use advance_messaging::{AgentActionDispatcherImpl, RejectionSink};
use advance_shared_types::mailbox::{AgentAction, AgentActionDispatcher, DispatchError};
use advance_shared_types::security_validator::{ActionValidator, SecurityError};
use cap_http::DefaultActionValidator;

const AGENT: &str = "agent:track-e";

/// No-op rejection sink (the production `EventBusRejectionSink` emits an event; the
/// witnessed property here is the validator decision, not the emit).
struct NoSink;
impl RejectionSink for NoSink {
    fn record_rejection(&self, _agent_id: &str, _error: &SecurityError) {}
}

/// Real messaging dispatcher gating on the real cap-http action validator.
fn dispatcher() -> AgentActionDispatcherImpl {
    let validator: Arc<dyn ActionValidator> = Arc::new(DefaultActionValidator::new());
    AgentActionDispatcherImpl::new(validator, Arc::new(NoSink))
}

/// Step-3 dispatch seam source message (origin None → gate-only path).
fn src_msg() -> advance_shared_types::mailbox::Message {
    advance_shared_types::mailbox::Message {
        id: "m".into(),
        kind: advance_shared_types::mailbox::MessageKind::User,
        from: "user:test".into(),
        to: AGENT.into(),
        payload: Vec::new(),
        context: None,
        timestamp: std::time::SystemTime::now(),
        origin: None,
    }
}

#[tokio::test]
async fn sys_ac_058_oversized_action_caught_before_delivery() {
    // Positive control: a valid (sub-1-MiB) action passes the validator (dispatch Ok),
    // proving the validator DISCRIMINATES rather than blanket-rejecting — so the rejection
    // below is specifically attributable to the size check.
    let valid = AgentAction {
        payload: vec![0u8; 1024],
    };
    dispatcher()
        .dispatch(AGENT, &src_msg(), std::slice::from_ref(&valid))
        .await
        .expect("a valid action passes the validator");

    // Payload one byte over the 1 MiB max_message_size → caught by the validator.
    let oversized = AgentAction {
        payload: vec![0u8; (1 << 20) + 1],
    };
    let err = dispatcher()
        .dispatch(AGENT, &src_msg(), std::slice::from_ref(&oversized))
        .await
        .expect_err("oversized action is rejected by the validator before delivery");
    assert!(
        matches!(
            err,
            DispatchError::ValidationFailed(SecurityError::OversizedMessage)
        ),
        "got {err:?}"
    );
}

#[tokio::test]
async fn sys_ac_253_duplicate_payload_burst_caught_before_delivery() {
    // Positive control: 17 DISTINCT payloads (same batch size, no duplicate) pass the
    // validator (dispatch Ok). The dispatcher's pre-validator batch cap is MAX_BATCH_SIZE
    // (128), so 17 is well under it — proving the rejection below is specifically the
    // duplicate-burst check, not a batch-size rejection and not a blanket reject.
    let distinct: Vec<AgentAction> = (0..17u32)
        .map(|i| AgentAction {
            payload: format!("distinct-action-{i}").into_bytes(),
        })
        .collect();
    dispatcher()
        .dispatch(AGENT, &src_msg(), &distinct)
        .await
        .expect("a batch of 17 distinct actions passes the validator");

    // 17 IDENTICAL payloads — one over the default duplicate threshold (16) → caught.
    let dup = AgentAction {
        payload: b"identical-action-payload".to_vec(),
    };
    let batch: Vec<AgentAction> = std::iter::repeat(dup).take(17).collect();
    let err = dispatcher()
        .dispatch(AGENT, &src_msg(), &batch)
        .await
        .expect_err("duplicate-payload burst is rejected by the validator before delivery");
    match err {
        DispatchError::ValidationFailed(SecurityError::InvalidAction(msg)) => {
            assert!(
                msg.contains("duplicate"),
                "rejected via the duplicate-burst path (not batch_too_large): {msg:?}"
            );
        }
        other => panic!("expected ValidationFailed(InvalidAction(duplicate...)), got {other:?}"),
    }
}
