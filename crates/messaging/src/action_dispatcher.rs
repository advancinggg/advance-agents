//! `AgentActionDispatcher` concrete impl with `ActionValidator` gate +
//! `RejectionSink` seam + `EventBusRejectionSink` production adapter.
//!
//! AC-11 verification path: validator-rejection causes
//! `DispatchError::ValidationFailed(SecurityError)` AND an emit of
//! `security.action_rejected` via the wired `RejectionSink`.
//!
//! Slice A ships:
//! - `RejectionSink` trait (long-lived test/production seam)
//! - `EventBusRejectionSink` (production adapter delegating to
//!   `EventBusEmit` per CONTRACT-180)
//! - `AgentActionDispatcherImpl` (validator-first dispatch with
//!   `MAX_BATCH_SIZE` pre-validator cap)
//!
//! No mailbox dependency on `AgentActionDispatcherImpl` by construction:
//! per-action decode + delivery is deferred to slice B with the
//! MessageTrace + payload-kind discriminator design.

use std::sync::Arc;

use async_trait::async_trait;
use chrono::Utc;

use advance_shared_types::event::Event;
use advance_shared_types::mailbox::{AgentAction, AgentActionDispatcher, DispatchError, Message};
use advance_shared_types::outbound::DeliveryReport;
use advance_shared_types::outbound::RoutedOutboundMessage;
use advance_shared_types::progress_card::{
    JointC215C216BindingError, JointC215C216PublicationBinding, JointC215C216PublicationPermit,
};
use advance_shared_types::security_validator::{ActionValidator, SecurityError};
use advance_shared_types::traits::EventBusEmit;

use crate::id_validation::is_safe_id;
use crate::progress_envelope::decode_routed_outbound;

/// Per-batch upper bound — mirrors shared-types `AgentActionDispatcher`
/// invariant 4 (`actions.len()` ≤ 128 recommended). Pre-validator guard
/// so a malicious / buggy guest cannot force the validator to scan a
/// million-element batch.
pub const MAX_BATCH_SIZE: usize = 128;

/// Long-lived seam for rejection notification. Slice A ships two impls:
/// - `EventBusRejectionSink` — production, emits `security.action_rejected`
///   via `EventBusEmit`. AC-11 verification path.
/// - `RecordingSink` (test fixture) — captures rejections into a Vec.
pub trait RejectionSink: Send + Sync {
    fn record_rejection(&self, agent_id: &str, error: &SecurityError);
}

/// Post-validation outbound delivery seam (Phase-2 reply-delivery slice B).
///
/// `AgentActionDispatcherImpl::dispatch` calls `deliver` EXACTLY ONCE per
/// dispatch, AFTER the `ActionValidator` gate passes, with the full validated
/// action batch — including an **empty** slice (so a turn that produced no
/// action is observable as such, which the MODULE-001 `POST /msg` correlation
/// uses to answer "no reply" vs "reply" without hanging). It is NOT called when
/// the validator (or the pre-validator batch/id checks) rejects, so an
/// implementor only ever sees payloads that passed the validator
/// (≤ `MAX_PAYLOAD_BYTES`, ≤ `MAX_BATCH_SIZE`).
///
/// # Phase-2 Step-3 seam extension (ADR 2026-06-05 extensible channel adapter)
///
/// `deliver` is now **async**, carries the **source inbound `Message`**, and
/// returns a [`DeliveryReport`] — so the in-host channel reply path can read
/// `source.origin.channel_metadata` to build a per-message `OutboundTarget` and
/// drive `OutboundTransport::send`, returning the structured receipt. The
/// POST /msg path (`source.origin.is_none()`) fulfils the reply registry and
/// returns an empty report. The action payload kind is still opaque at this
/// layer (MODULE-006 §2.3); interim consumers treat the first action's payload
/// as raw reply bytes (the tagged payload-kind discriminator remains future
/// work — MODULE-006 §3.6).
#[async_trait]
pub trait OutboundActionSink: Send + Sync {
    async fn deliver(
        &self,
        agent_id: &str,
        source: &Message,
        actions: &[AgentAction],
    ) -> Result<DeliveryReport, DispatchError>;
}

/// CONTRACT-215 post-validation typed delivery seam.
///
/// Installing this seam is the C215 publication choice: the dispatcher
/// strictly decodes every action and stamps its route/source before invoking
/// the sink. It is mutually exclusive at call time with the legacy
/// [`OutboundActionSink`], which prevents a valid progress envelope from also
/// leaking through the old raw path. Until composition installs this seam,
/// existing deployments retain the byte-identical legacy behavior.
#[async_trait]
pub trait RoutedOutboundActionSink: Send + Sync {
    async fn deliver_routed(
        &self,
        agent_id: &str,
        source: &Message,
        messages: &[RoutedOutboundMessage],
    ) -> Result<DeliveryReport, DispatchError>;
}

/// Production `RejectionSink` impl — emits `security.action_rejected`
/// events via `EventBusEmit` (CONTRACT-180).
///
/// Event payload shape:
///   { "error_kind": "`discriminator`" }
/// where `<discriminator>` is one of:
///   - "invalid_action"     — SecurityError::InvalidAction(_)
///   - "oversized_message"  — SecurityError::OversizedMessage
///   - "rate_exceeded"      — SecurityError::RateExceeded(_)
///   - "capability_denied"  — SecurityError::CapabilityDenied(_)
///
/// PII discipline (shared-types `Event` invariant 1 + 7): the inner
/// String payloads of `SecurityError` variants are NOT inlined into the
/// event — only the kind discriminator is emitted.
///
/// `trace_id` / `span_id` are fresh UUID v4s per emission — slice A has
/// no upstream HostCallContext threading. Slice B wires real trace
/// context per the cap-channel pattern (`HostCallContext.trace_id`).
pub struct EventBusRejectionSink {
    bus: Arc<dyn EventBusEmit>,
}

impl EventBusRejectionSink {
    pub fn new(bus: Arc<dyn EventBusEmit>) -> Self {
        Self { bus }
    }
}

impl RejectionSink for EventBusRejectionSink {
    fn record_rejection(&self, agent_id: &str, error: &SecurityError) {
        let kind = match error {
            SecurityError::InvalidAction(_) => "invalid_action",
            SecurityError::OversizedMessage => "oversized_message",
            SecurityError::RateExceeded(_) => "rate_exceeded",
            SecurityError::CapabilityDenied(_) => "capability_denied",
        };
        let payload = serde_json::json!({ "error_kind": kind });
        let event = Event {
            id: uuid::Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            agent_id: agent_id.to_string(),
            task_id: None,
            run_id: None,
            execution_id: None,
            trace_id: uuid::Uuid::new_v4().to_string(),
            span_id: uuid::Uuid::new_v4().to_string(),
            parent_span_id: None,
            event_type: "security.action_rejected".to_string(),
            payload,
            duration_ms: None,
        };
        self.bus.emit(event);
    }
}

pub struct AgentActionDispatcherImpl {
    validator: Arc<dyn ActionValidator>,
    sink: Arc<dyn RejectionSink>,
    /// Slice B: optional post-validation delivery seam. `None` (the default) =
    /// gate-only (slice-A behavior). Wired via [`Self::with_outbound`].
    outbound: Option<Arc<dyn OutboundActionSink>>,
    /// CONTRACT-215 typed carrier. When present this is the sole outbound sink
    /// for the batch; `outbound` is not called.
    routed_outbound: Option<JointRoutedOutboundPublication>,
}

struct JointRoutedOutboundPublication {
    binding: JointC215C216PublicationBinding,
    sink: Arc<dyn RoutedOutboundActionSink>,
}

impl AgentActionDispatcherImpl {
    pub fn new(validator: Arc<dyn ActionValidator>, sink: Arc<dyn RejectionSink>) -> Self {
        Self {
            validator,
            sink,
            outbound: None,
            routed_outbound: None,
        }
    }

    /// Slice-B opt-in builder — wire an [`OutboundActionSink`] that receives
    /// every validated action batch (once per dispatch, including an empty
    /// batch). Without it, `dispatch` stays gate-only: validate then `Ok(())`
    /// with payloads discarded (the slice-A behavior; back-compat preserved for
    /// all existing 2-arg `new` callers + the system-acceptance harness).
    pub fn with_outbound(mut self, outbound: Arc<dyn OutboundActionSink>) -> Self {
        self.outbound = Some(outbound);
        self
    }

    /// Jointly publish CONTRACT-215/216's strict decoder and typed handoff.
    ///
    /// The linear permit exists only after the joint authority has verified
    /// the exact C216 runtime-provider and C215 route-provider bindings. There
    /// is deliberately no optional routed builder, so ordinary dispatcher
    /// construction cannot expose a standalone C215 prefix.
    pub fn publish_joint_routed_outbound(
        mut self,
        permit: JointC215C216PublicationPermit,
        outbound: Arc<dyn RoutedOutboundActionSink>,
    ) -> Result<Self, JointC215C216BindingError> {
        let binding = permit.consume_for_publication()?;
        if !binding.authorizes_routed_publication() {
            return Err(JointC215C216BindingError::InvalidPublicationPermit);
        }
        self.routed_outbound = Some(JointRoutedOutboundPublication {
            binding,
            sink: outbound,
        });
        Ok(self)
    }
}

#[async_trait]
impl AgentActionDispatcher for AgentActionDispatcherImpl {
    async fn dispatch(
        &self,
        agent_id: &str,
        source: &Message,
        actions: &[AgentAction],
    ) -> Result<DeliveryReport, DispatchError> {
        // Adversarial-R11 fix (Critical #4): reject control-char / null /
        // newline / Unicode-confusable agent_ids BEFORE any sink emit so
        // forged ids cannot splice the JSONL log via `Event.agent_id`
        // or impersonate other agents in observability streams.
        //
        // Per shared-types `AgentActionDispatcher` invariant 3, `agent_id`
        // MUST be whitelist-validated. Slice A enforces this defense-in-depth
        // inside `dispatch` rather than waiting for the WIT host_fn layer.
        if !is_safe_id(agent_id) {
            return Err(DispatchError::InvalidPayload("invalid_agent_id".into()));
        }
        // Bounded-batch invariant (pre-validator).
        // Routed through SecurityError::InvalidAction so the canonical
        // "rejected as invalid" surface stays consistent across both
        // dispatcher-level and validator-level rejections.
        if actions.len() > MAX_BATCH_SIZE {
            let err = SecurityError::InvalidAction("batch_too_large".into());
            self.sink.record_rejection(agent_id, &err);
            return Err(DispatchError::ValidationFailed(err));
        }
        // VALIDATOR-FIRST invariant (shared-types §2.3 rustdoc).
        if let Err(err) = self.validator.validate(agent_id, actions) {
            self.sink.record_rejection(agent_id, &err);
            return Err(DispatchError::ValidationFailed(err));
        }
        // Slice B: validated. Route the batch to the outbound sink when wired,
        // EXACTLY ONCE per dispatch — including an empty batch (so a no-action
        // turn is observable downstream). When no outbound is wired this stays
        // gate-only (slice-A behavior: validate then return an empty report,
        // payloads discarded). The validator-first ordering above guarantees the
        // sink only ever sees a validated (bounded) batch; a rejected batch
        // returns before reaching here. See MODULE-006 §2.7 + §3.8 (i).
        // Step-3: the sink is async, carries the source `Message`, and returns
        // a `DeliveryReport` (the in-host channel egress path's receipt).
        if let Some(publication) = &self.routed_outbound {
            if !publication.binding.authorizes_routed_publication() {
                return Err(DispatchError::InvalidPayload(
                    "joint-publication-binding-invalid".into(),
                ));
            }
            let messages = actions
                .iter()
                .map(|action| decode_routed_outbound(source, &action.payload))
                .collect::<Result<Vec<_>, _>>()?;
            publication
                .sink
                .deliver_routed(agent_id, source, &messages)
                .await
        } else if let Some(outbound) = &self.outbound {
            outbound.deliver(agent_id, source, actions).await
        } else {
            Ok(DeliveryReport::empty())
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::num::NonZeroU32;
    use std::sync::Mutex;
    use std::time::SystemTime;

    use advance_shared_types::mailbox::{AgentAction, MessageKind, MessageOrigin};
    use advance_shared_types::outbound::OutboundEncoding;
    use advance_shared_types::progress_card::{
        JointC215C216ActivationAuthority, JointC215C216PublicationPermit,
        OutboundRouteProviderBinding, ProgressCardAuthorityFactory,
    };
    use advance_shared_types::progress_lifecycle_recovery::{
        ProgressLifecycleRecoveryJournal, RecoveryJournalConfig,
    };
    use advance_shared_types::turn_attribution::TurnAttributionAuthorityFactory;
    use advance_shared_types::turn_attribution::TurnRuntimeProviderBinding;
    use tempfile::TempDir;
    use zeroize::Zeroizing;

    use super::*;

    struct Allow;

    impl ActionValidator for Allow {
        fn validate(&self, _agent_id: &str, _actions: &[AgentAction]) -> Result<(), SecurityError> {
            Ok(())
        }
    }

    struct IgnoreRejections;

    impl RejectionSink for IgnoreRejections {
        fn record_rejection(&self, _agent_id: &str, _error: &SecurityError) {}
    }

    #[derive(Default)]
    struct RecordingRouted {
        calls: Mutex<Vec<Vec<RoutedOutboundMessage>>>,
    }

    #[async_trait]
    impl RoutedOutboundActionSink for RecordingRouted {
        async fn deliver_routed(
            &self,
            _agent_id: &str,
            _source: &Message,
            messages: &[RoutedOutboundMessage],
        ) -> Result<DeliveryReport, DispatchError> {
            self.calls.lock().unwrap().push(messages.to_vec());
            Ok(DeliveryReport::delivered())
        }
    }

    fn source() -> Message {
        Message {
            id: "source-1".into(),
            kind: MessageKind::User,
            from: "user:1".into(),
            to: "agent:x".into(),
            payload: vec![],
            context: None,
            timestamp: SystemTime::now(),
            origin: Some(MessageOrigin {
                message_id: "guest-cannot-select-this".into(),
                original_channel: "telegram".into(),
                original_sender: "user:1".into(),
                adapter_id: "telegram".into(),
                channel_metadata: HashMap::from([
                    ("channel.subscription_id".into(), "sub-1".into()),
                    ("channel.conversation_id".into(), "chat-1".into()),
                ]),
                received_at: Utc::now(),
                context: None,
            }),
        }
    }

    fn progress(body: &[u8], phase: &str) -> Vec<u8> {
        let key = b"progress.phase";
        let mut payload = Vec::new();
        payload.extend_from_slice(crate::progress_envelope::PROGRESS_ENVELOPE_MAGIC);
        payload.extend_from_slice(&[1, 0, 0]);
        payload.extend_from_slice(&(body.len() as u32).to_be_bytes());
        payload.extend_from_slice(&1u16.to_be_bytes());
        payload.extend_from_slice(body);
        payload.extend_from_slice(&(key.len() as u16).to_be_bytes());
        payload.extend_from_slice(&(phase.len() as u32).to_be_bytes());
        payload.extend_from_slice(key);
        payload.extend_from_slice(phase.as_bytes());
        payload
    }

    struct JointFixture {
        _journal_root: TempDir,
        runtime: TurnRuntimeProviderBinding,
        route: OutboundRouteProviderBinding,
        authority: JointC215C216ActivationAuthority,
    }

    fn joint_fixture() -> JointFixture {
        let journal_root = tempfile::tempdir().expect("journal root");
        let config = RecoveryJournalConfig::new_at_composition(
            journal_root.path().join("journal"),
            journal_root.path().join("anchor").join("root.anchor"),
            NonZeroU32::new(1).expect("non-zero epoch"),
            Zeroizing::new([0x42; 32]),
        )
        .expect("valid journal config");
        let journal =
            ProgressLifecycleRecoveryJournal::open_at_composition(config).expect("journal opens");
        let (turn_recovery, progress_recovery) = journal.split_at_composition();
        let turn = TurnAttributionAuthorityFactory::new_at_composition(
            &mut rand::rngs::OsRng,
            turn_recovery,
        )
        .unwrap();
        let runtime = turn.registry_issuer.runtime_provider_binding();
        let progress = ProgressCardAuthorityFactory::new_with_os_rng_at_composition(
            turn.activation_staging,
            turn.source_quiescence_verifier,
            progress_recovery,
        )
        .unwrap();
        JointFixture {
            _journal_root: journal_root,
            runtime,
            route: progress.outbound_route_seal_issuer.route_provider_binding(),
            authority: progress.joint_activation_authority,
        }
    }

    fn joint_publication_permit() -> JointC215C216PublicationPermit {
        let fixture = joint_fixture();
        fixture
            .authority
            .bind_runtime_and_route_providers(&fixture.runtime, &fixture.route)
            .unwrap()
    }

    #[tokio::test]
    async fn routed_sink_decodes_whole_batch_once_and_preserves_legacy_bytes() {
        let sink = Arc::new(RecordingRouted::default());
        let dispatcher =
            AgentActionDispatcherImpl::new(Arc::new(Allow), Arc::new(IgnoreRejections))
                .publish_joint_routed_outbound(joint_publication_permit(), sink.clone())
                .unwrap();
        dispatcher
            .dispatch(
                "agent:x",
                &source(),
                &[
                    AgentAction {
                        payload: b"legacy\0bytes".to_vec(),
                    },
                    AgentAction {
                        payload: progress(b"working", "progress"),
                    },
                ],
            )
            .await
            .unwrap();
        let calls = sink.calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0][0].encoding, OutboundEncoding::LegacyRaw);
        assert_eq!(calls[0][0].body, b"legacy\0bytes");
        assert_eq!(calls[0][1].encoding, OutboundEncoding::ProgressV1);
        assert_eq!(calls[0][1].source_message_id, "source-1");
    }

    #[tokio::test]
    async fn malformed_later_envelope_rejects_before_any_sink_call() {
        let sink = Arc::new(RecordingRouted::default());
        let dispatcher =
            AgentActionDispatcherImpl::new(Arc::new(Allow), Arc::new(IgnoreRejections))
                .publish_joint_routed_outbound(joint_publication_permit(), sink.clone())
                .unwrap();
        let result = dispatcher
            .dispatch(
                "agent:x",
                &source(),
                &[
                    AgentAction {
                        payload: progress(b"working", "ack"),
                    },
                    AgentAction {
                        payload: b"ADVPRG".to_vec(),
                    },
                ],
            )
            .await;
        assert!(matches!(result, Err(DispatchError::InvalidPayload(_))));
        assert!(sink.calls.lock().unwrap().is_empty());
    }

    #[test]
    fn wrong_factory_provider_bindings_reject_before_dispatcher_publication() {
        let first = joint_fixture();
        let second = joint_fixture();
        let sink = Arc::new(RecordingRouted::default());

        let runtime_error = second
            .authority
            .bind_runtime_and_route_providers(&first.runtime, &first.route)
            .err()
            .expect("crossed C216 runtime provider must reject");
        assert_eq!(
            runtime_error,
            JointC215C216BindingError::C216RuntimeProviderMismatch
        );
        assert_eq!(
            runtime_error.to_string(),
            "joint-activation-c216-runtime-provider-mismatch"
        );

        let route_error = first
            .authority
            .bind_runtime_and_route_providers(&first.runtime, &second.route)
            .err()
            .expect("crossed C215 route provider must reject");
        assert_eq!(
            route_error,
            JointC215C216BindingError::C215RouteProviderMismatch
        );
        assert_eq!(
            route_error.to_string(),
            "joint-activation-c215-route-provider-mismatch"
        );
        assert!(sink.calls.lock().unwrap().is_empty());
    }
}
