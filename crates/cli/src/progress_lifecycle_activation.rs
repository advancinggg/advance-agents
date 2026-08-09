//! Atomic composition barrier for CONTRACT-216 + CONTRACT-215.
//!
//! Every factory product remains local to this function until all role moves,
//! provider construction, and injections have succeeded. The move-only joint
//! authority verifies both exact provider bindings and emits a linear permit;
//! the dispatcher consumes that permit as the final operation, and only then
//! is the activated graph returned to `wire_capabilities`.

use std::fmt;
use std::sync::Arc;

use advance_messaging::{
    stage_progress_route_provider, AgentActionDispatcherImpl, EventBusRejectionSink, MailboxStore,
    ProgressRouteDelivery, ProgressRouteProviderParts, ProgressSourceCloser,
    ProtectedTurnExecutionBoundary as MessagingTurnExecutionBoundary, TurnExecutionBoundaryImpl,
    DEFAULT_CAPACITY,
};
use advance_reply_tracker::{canonical_turn_identity_facades, compose_turn_attribution_facades};
use advance_scheduler::hook::{
    HookError, ProtectedTurnExecutionBoundary as SchedulerTurnExecutionBoundary,
};
use advance_shared_types::mailbox::{
    AgentActionDispatcher, DequeuedTurnGuard, MailboxTurnIdentity,
};
use advance_shared_types::progress_card::{
    ProgressAttemptReconciliationPort, ProgressCardAuthorityParts,
};
use advance_shared_types::traits::EventBusEmit;
use advance_shared_types::turn_attribution::{
    TurnCostAttributionReadPort, TurnReplyRoutingPort, TurnStartOutcome,
    DEFAULT_TURN_ATTRIBUTION_MAX_ENTRIES,
};
use cap_channel::{
    stage_progress_card_provider, stage_typed_outbound_transport, HttpEgress, OutboundTransport,
    ProgressAttemptOutcomeAttester, ProgressCardProviderParts,
};
use cap_http::{DefaultActionValidator, DEFAULT_MAX_DUPLICATE_PAYLOADS};

use crate::channel_egress::{ChannelEgress, StagedRoutedOutboundSink};
use crate::channels_boot::ChannelRuntime;
use crate::execution_turn_ingress::ExecutionTurnIngress;
use crate::progress_lifecycle_bootstrap::{
    ProgressLifecycleBootstrapStaging, StagedTurnAttributionParts,
};
use crate::reply::ReplyRegistry;
use advance_messaging::AgentIdBridge;

/// Stable, non-sensitive activation failures. No variant retains provider
/// errors, paths, identifiers, payloads, or authority material.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ProgressLifecycleActivationError {
    InjectedFailure,
    TurnProviderUnavailable,
    CardProviderUnavailable,
    RouteProviderUnavailable,
    JointProviderBindingMismatch,
}

impl ProgressLifecycleActivationError {
    pub(crate) const fn code(self) -> &'static str {
        match self {
            Self::InjectedFailure => "progress-lifecycle-activation-failpoint",
            Self::TurnProviderUnavailable => "progress-lifecycle-turn-provider-unavailable",
            Self::CardProviderUnavailable => "progress-lifecycle-card-provider-unavailable",
            Self::RouteProviderUnavailable => "progress-lifecycle-route-provider-unavailable",
            Self::JointProviderBindingMismatch => {
                "progress-lifecycle-joint-provider-binding-mismatch"
            }
        }
    }
}

impl fmt::Display for ProgressLifecycleActivationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for ProgressLifecycleActivationError {}

/// Deterministic MODULE-001-T101 checkpoints. Role-move checkpoints precede
/// provider/injection checkpoints, and publication is always last.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ProgressLifecycleActivationFailpoint {
    MoveTurnRegistry,
    MoveMailboxAdmission,
    MoveMailboxRemoval,
    MoveMailboxDequeue,
    MoveMailboxPublish,
    MoveStoreQuiescence,
    MoveSourceRecovery,
    MoveTurnVerifier,
    MoveProtectedCardState,
    MoveCardChallenge,
    MoveOutboundRoute,
    MoveSourceAttestation,
    MoveTransportOutcome,
    MoveAttemptReconciliation,
    MoveCardVerifier,
    MoveJointAuthority,
    InjectTurnFacades,
    InjectMailboxStore,
    InjectExecutionBoundary,
    InjectCardProvider,
    InjectTypedTransport,
    InjectRouteProvider,
    InjectRoutedSink,
    PublishJointDispatcher,
}

impl ProgressLifecycleActivationFailpoint {
    // Failpoint inventory consumed by the composition-harness sweep (MODULE-001-T101
    // class); the lib target itself never reads it, so per-target dead_code would fire.
    #[allow(dead_code)]
    #[cfg(any(test, feature = "test-support"))]
    pub(crate) const ALL: &'static [Self] = &[
        Self::MoveTurnRegistry,
        Self::MoveMailboxAdmission,
        Self::MoveMailboxRemoval,
        Self::MoveMailboxDequeue,
        Self::MoveMailboxPublish,
        Self::MoveStoreQuiescence,
        Self::MoveSourceRecovery,
        Self::MoveTurnVerifier,
        Self::MoveProtectedCardState,
        Self::MoveCardChallenge,
        Self::MoveOutboundRoute,
        Self::MoveSourceAttestation,
        Self::MoveTransportOutcome,
        Self::MoveAttemptReconciliation,
        Self::MoveCardVerifier,
        Self::MoveJointAuthority,
        Self::InjectTurnFacades,
        Self::InjectMailboxStore,
        Self::InjectExecutionBoundary,
        Self::InjectCardProvider,
        Self::InjectTypedTransport,
        Self::InjectRouteProvider,
        Self::InjectRoutedSink,
        Self::PublishJointDispatcher,
    ];
}

fn checkpoint(
    selected: Option<ProgressLifecycleActivationFailpoint>,
    current: ProgressLifecycleActivationFailpoint,
) -> Result<(), ProgressLifecycleActivationError> {
    if selected == Some(current) {
        Err(ProgressLifecycleActivationError::InjectedFailure)
    } else {
        Ok(())
    }
}

/// Fully activated graph. Fields stay crate-private and are exposed only to
/// exact production consumers after the joint publication permit is consumed.
/// Several role handles are HELD here (ownership keeps the moved role alive and
/// single-provider) without being read until the later composition barrier —
/// that custody-not-read shape is why dead_code is allowed on the struct.
#[allow(dead_code)]
pub(crate) struct ProgressLifecycleActivation {
    pub(crate) mailbox_store: Arc<MailboxStore>,
    pub(crate) execution_ingress: Arc<ExecutionTurnIngress>,
    pub(crate) reply_routing: Arc<dyn TurnReplyRoutingPort>,
    pub(crate) cost_attribution: Arc<dyn TurnCostAttributionReadPort>,
    pub(crate) execution_boundary: Arc<dyn SchedulerTurnExecutionBoundary>,
    pub(crate) action_dispatcher: Arc<dyn AgentActionDispatcher>,
    pub(crate) source_closer: Arc<ProgressSourceCloser>,
    pub(crate) route_delivery: Arc<ProgressRouteDelivery>,
    pub(crate) typed_transport: Arc<dyn OutboundTransport>,
    pub(crate) attempt_reconciliation: Arc<dyn ProgressAttemptReconciliationPort>,
    pub(crate) attempt_outcome_attester: Arc<ProgressAttemptOutcomeAttester>,
}

/// Scheduler adapter that joins exact C216 Store completion to C215 source
/// close without inspecting or reconstructing the opaque receipt.
struct JointTurnExecutionBoundary {
    c216: Arc<dyn MessagingTurnExecutionBoundary>,
    source_closer: Arc<ProgressSourceCloser>,
}

impl JointTurnExecutionBoundary {
    fn finish_and_close(
        &self,
        result: advance_shared_types::turn_attribution::TurnFinishResult,
    ) -> Result<(), HookError> {
        if let Some(receipt) = result.into_source_quiesced() {
            self.source_closer
                .close_source(&receipt)
                .map_err(|_| HookError::Failure("progress-source-close-failed".into()))?;
        }
        Ok(())
    }
}

impl SchedulerTurnExecutionBoundary for JointTurnExecutionBoundary {
    fn begin(
        &self,
        identity: &MailboxTurnIdentity,
        guard: DequeuedTurnGuard,
    ) -> Result<TurnStartOutcome, HookError> {
        self.c216
            .begin(identity, guard)
            .map_err(|_| HookError::Failure("protected-turn-start-failed".into()))
    }

    fn finish_drained(
        &self,
        identity: &MailboxTurnIdentity,
        store_incarnation: [u8; 16],
        store_epoch: u64,
    ) -> Result<(), HookError> {
        let result = self
            .c216
            .finish_drained(identity, store_incarnation, store_epoch)
            .map_err(|_| HookError::Failure("protected-turn-finish-failed".into()))?;
        self.finish_and_close(result)
    }

    fn finish_store_destroyed(
        &self,
        identity: &MailboxTurnIdentity,
        store_incarnation: [u8; 16],
    ) -> Result<(), HookError> {
        let result = self
            .c216
            .finish_store_destroyed(identity, store_incarnation)
            .map_err(|_| HookError::Failure("protected-turn-destroy-failed".into()))?;
        self.finish_and_close(result)
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn activate_progress_lifecycle(
    staging: ProgressLifecycleBootstrapStaging,
    progress_egress: Arc<HttpEgress>,
    channel_runtime: Option<&ChannelRuntime>,
    reply_registry: Arc<ReplyRegistry>,
    bridge: Arc<AgentIdBridge>,
    event_bus: Arc<dyn EventBusEmit>,
    max_action_message_size: usize,
    failpoint: Option<ProgressLifecycleActivationFailpoint>,
) -> Result<ProgressLifecycleActivation, ProgressLifecycleActivationError> {
    activate_progress_lifecycle_with_observer(
        staging,
        progress_egress,
        channel_runtime,
        reply_registry,
        bridge,
        event_bus,
        max_action_message_size,
        failpoint,
        || {},
    )
}

#[allow(clippy::too_many_arguments)]
fn activate_progress_lifecycle_with_observer<F>(
    staging: ProgressLifecycleBootstrapStaging,
    progress_egress: Arc<HttpEgress>,
    channel_runtime: Option<&ChannelRuntime>,
    reply_registry: Arc<ReplyRegistry>,
    bridge: Arc<AgentIdBridge>,
    event_bus: Arc<dyn EventBusEmit>,
    max_action_message_size: usize,
    failpoint: Option<ProgressLifecycleActivationFailpoint>,
    on_joint_publication: F,
) -> Result<ProgressLifecycleActivation, ProgressLifecycleActivationError>
where
    F: FnOnce(),
{
    let ProgressLifecycleBootstrapStaging {
        contract216,
        contract215,
    } = staging;
    let StagedTurnAttributionParts {
        registry_issuer,
        mailbox_admission_issuer,
        mailbox_removal_issuer,
        mailbox_dequeue_issuer,
        mailbox_publish_verifier,
        store_quiescence_issuer,
        source_quiescence_recovery_issuer,
        verifier: turn_verifier,
    } = contract216;
    checkpoint(
        failpoint,
        ProgressLifecycleActivationFailpoint::MoveTurnRegistry,
    )?;
    checkpoint(
        failpoint,
        ProgressLifecycleActivationFailpoint::MoveMailboxAdmission,
    )?;
    checkpoint(
        failpoint,
        ProgressLifecycleActivationFailpoint::MoveMailboxRemoval,
    )?;
    checkpoint(
        failpoint,
        ProgressLifecycleActivationFailpoint::MoveMailboxDequeue,
    )?;
    checkpoint(
        failpoint,
        ProgressLifecycleActivationFailpoint::MoveMailboxPublish,
    )?;
    checkpoint(
        failpoint,
        ProgressLifecycleActivationFailpoint::MoveStoreQuiescence,
    )?;
    checkpoint(
        failpoint,
        ProgressLifecycleActivationFailpoint::MoveSourceRecovery,
    )?;
    checkpoint(
        failpoint,
        ProgressLifecycleActivationFailpoint::MoveTurnVerifier,
    )?;

    let ProgressCardAuthorityParts {
        protected_state_issuer,
        coordinator_challenge_issuer,
        outbound_route_seal_issuer,
        source_close_attestation_issuer,
        transport_outcome_receipt_issuer,
        reconciliation_proof_issuer,
        verifier: card_verifier,
        joint_activation_authority,
    } = contract215;
    checkpoint(
        failpoint,
        ProgressLifecycleActivationFailpoint::MoveProtectedCardState,
    )?;
    checkpoint(
        failpoint,
        ProgressLifecycleActivationFailpoint::MoveCardChallenge,
    )?;
    checkpoint(
        failpoint,
        ProgressLifecycleActivationFailpoint::MoveOutboundRoute,
    )?;
    checkpoint(
        failpoint,
        ProgressLifecycleActivationFailpoint::MoveSourceAttestation,
    )?;
    checkpoint(
        failpoint,
        ProgressLifecycleActivationFailpoint::MoveTransportOutcome,
    )?;
    checkpoint(
        failpoint,
        ProgressLifecycleActivationFailpoint::MoveAttemptReconciliation,
    )?;
    checkpoint(
        failpoint,
        ProgressLifecycleActivationFailpoint::MoveCardVerifier,
    )?;
    checkpoint(
        failpoint,
        ProgressLifecycleActivationFailpoint::MoveJointAuthority,
    )?;

    // Capture read-only opaque witnesses before their one-shot issuers move
    // into the exact providers. Rust ownership then guarantees these are the
    // provider instances below, while the joint authority verifies both
    // factory identities immediately before publication.
    let runtime_provider_binding = registry_issuer.runtime_provider_binding();
    let route_provider_binding = outbound_route_seal_issuer.route_provider_binding();

    checkpoint(
        failpoint,
        ProgressLifecycleActivationFailpoint::InjectTurnFacades,
    )?;
    let facades = compose_turn_attribution_facades(
        DEFAULT_TURN_ATTRIBUTION_MAX_ENTRIES,
        registry_issuer,
        turn_verifier,
    )
    .map_err(|_| ProgressLifecycleActivationError::TurnProviderUnavailable)?;
    let (dispatch, execution, reply, mailbox, cost) = facades.move_to_composition();
    let (reply_routing, cost_attribution) = canonical_turn_identity_facades(reply, cost, bridge);

    checkpoint(
        failpoint,
        ProgressLifecycleActivationFailpoint::InjectMailboxStore,
    )?;
    let mailbox_store = Arc::new(MailboxStore::new_with_turn_attribution(
        DEFAULT_CAPACITY,
        mailbox_admission_issuer,
        mailbox_removal_issuer,
        mailbox_dequeue_issuer,
        mailbox_publish_verifier,
        dispatch,
        mailbox,
        Arc::clone(&execution),
    ));
    let execution_ingress = Arc::new(ExecutionTurnIngress::new(Arc::clone(&mailbox_store)));

    checkpoint(
        failpoint,
        ProgressLifecycleActivationFailpoint::InjectExecutionBoundary,
    )?;
    let c216_execution: Arc<dyn MessagingTurnExecutionBoundary> = Arc::new(
        TurnExecutionBoundaryImpl::new(store_quiescence_issuer, execution),
    );

    checkpoint(
        failpoint,
        ProgressLifecycleActivationFailpoint::InjectCardProvider,
    )?;
    let ProgressCardProviderParts {
        renderer,
        source_lifecycle,
        attempt_reconciliation,
        attempt_outcome_attester,
    } = stage_progress_card_provider(
        Arc::clone(&progress_egress),
        protected_state_issuer,
        coordinator_challenge_issuer,
        transport_outcome_receipt_issuer,
        reconciliation_proof_issuer,
        card_verifier,
    )
    .map_err(|_| ProgressLifecycleActivationError::CardProviderUnavailable)?;

    checkpoint(
        failpoint,
        ProgressLifecycleActivationFailpoint::InjectTypedTransport,
    )?;
    let typed_transport = stage_typed_outbound_transport(Arc::clone(&progress_egress), renderer);

    checkpoint(
        failpoint,
        ProgressLifecycleActivationFailpoint::InjectRouteProvider,
    )?;
    let ProgressRouteProviderParts {
        delivery: route_delivery,
        source_close: source_closer,
    } = stage_progress_route_provider(
        outbound_route_seal_issuer,
        source_lifecycle,
        source_close_attestation_issuer,
        source_quiescence_recovery_issuer,
    )
    .map_err(|_| ProgressLifecycleActivationError::RouteProviderUnavailable)?;

    let execution_boundary: Arc<dyn SchedulerTurnExecutionBoundary> =
        Arc::new(JointTurnExecutionBoundary {
            c216: c216_execution,
            source_closer: Arc::clone(&source_closer),
        });

    checkpoint(
        failpoint,
        ProgressLifecycleActivationFailpoint::InjectRoutedSink,
    )?;
    let routed_sink = match channel_runtime {
        Some(runtime) => StagedRoutedOutboundSink::with_channel(
            reply_registry,
            ChannelEgress::new(runtime.transport.clone(), runtime.manager.clone()),
            Arc::clone(&typed_transport),
            Arc::clone(&route_delivery),
        ),
        None => StagedRoutedOutboundSink::registry_only(reply_registry),
    };

    checkpoint(
        failpoint,
        ProgressLifecycleActivationFailpoint::PublishJointDispatcher,
    )?;
    let publication_permit = joint_activation_authority
        .bind_runtime_and_route_providers(&runtime_provider_binding, &route_provider_binding)
        .map_err(|_| ProgressLifecycleActivationError::JointProviderBindingMismatch)?;
    let dispatcher = AgentActionDispatcherImpl::new(
        Arc::new(DefaultActionValidator::with_thresholds(
            max_action_message_size,
            DEFAULT_MAX_DUPLICATE_PAYLOADS,
        )),
        Arc::new(EventBusRejectionSink::new(event_bus)),
    )
    .publish_joint_routed_outbound(publication_permit, routed_sink)
    .map_err(|_| ProgressLifecycleActivationError::JointProviderBindingMismatch)?;
    let action_dispatcher: Arc<dyn AgentActionDispatcher> = Arc::new(dispatcher);
    on_joint_publication();

    Ok(ProgressLifecycleActivation {
        mailbox_store,
        execution_ingress,
        reply_routing,
        cost_attribution,
        execution_boundary,
        action_dispatcher,
        source_closer,
        route_delivery,
        typed_transport,
        attempt_reconciliation,
        attempt_outcome_attester,
    })
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use advance_shared_types::security_validator::{
        HttpCapability, HttpError, HttpRequest, HttpResponse, HttpSecurityChain,
    };
    use async_trait::async_trait;

    use super::*;
    use crate::progress_lifecycle_bootstrap::{
        bootstrap_progress_lifecycle_with_home, ProgressLifecycleBootstrapError,
        ProgressLifecycleBootstrapFailpoint,
    };

    struct NoopBus;

    impl EventBusEmit for NoopBus {
        fn emit(&self, _: advance_shared_types::event::Event) {}
    }

    #[derive(Default)]
    struct CountingHttpChain {
        calls: AtomicUsize,
    }

    #[async_trait]
    impl HttpSecurityChain for CountingHttpChain {
        async fn execute(
            &self,
            _: &str,
            _: HttpRequest,
            _: &HttpCapability,
        ) -> Result<HttpResponse, HttpError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(HttpResponse {
                status: 200,
                headers: Vec::new(),
                body: br#"{"ok":true,"result":{"message_id":1}}"#.to_vec(),
            })
        }
    }

    fn canonical_dir(path: PathBuf) -> PathBuf {
        std::fs::create_dir(&path).expect("create fixture directory");
        std::fs::canonicalize(path).expect("canonical fixture directory")
    }

    fn bootstrap_fixture(
        failpoint: Option<ProgressLifecycleBootstrapFailpoint>,
    ) -> (
        tempfile::TempDir,
        Result<ProgressLifecycleBootstrapStaging, ProgressLifecycleBootstrapError>,
    ) {
        let root = tempfile::tempdir().expect("fixture root");
        let workspace = canonical_dir(root.path().join("workspace"));
        let home = canonical_dir(root.path().join("home"));
        let staging = bootstrap_progress_lifecycle_with_home(
            &[0xabu8; 32],
            &workspace,
            Some(&home),
            failpoint,
        );
        (root, staging)
    }

    fn activate_fixture(
        staging: ProgressLifecycleBootstrapStaging,
        chain: Arc<CountingHttpChain>,
        failpoint: Option<ProgressLifecycleActivationFailpoint>,
        published: Arc<AtomicUsize>,
    ) -> Result<ProgressLifecycleActivation, ProgressLifecycleActivationError> {
        let egress = Arc::new(HttpEgress::new(chain));
        let published_observer = Arc::clone(&published);
        activate_progress_lifecycle_with_observer(
            staging,
            egress,
            None,
            Arc::new(ReplyRegistry::new()),
            Arc::new(AgentIdBridge::from_pairs([(
                "agent:default".to_string(),
                "default-agent".to_string(),
            )])),
            Arc::new(NoopBus),
            1_048_576,
            failpoint,
            move || {
                published_observer.fetch_add(1, Ordering::SeqCst);
            },
        )
    }

    #[test]
    fn t101_factory_failures_publish_neither_contract_and_perform_zero_http() {
        for failpoint in [
            ProgressLifecycleBootstrapFailpoint::Contract216Factory,
            ProgressLifecycleBootstrapFailpoint::Contract215Factory,
        ] {
            let chain = Arc::new(CountingHttpChain::default());
            let published = Arc::new(AtomicUsize::new(0));
            let (_root, result) = bootstrap_fixture(Some(failpoint));

            assert_eq!(
                result.err(),
                Some(ProgressLifecycleBootstrapError::InjectedFailure)
            );
            assert_eq!(published.load(Ordering::SeqCst), 0);
            assert_eq!(chain.calls.load(Ordering::SeqCst), 0);
        }
    }

    #[test]
    fn t101_every_role_move_and_injection_failure_is_zero_publication_zero_http() {
        assert_eq!(
            ProgressLifecycleActivationFailpoint::ALL.len(),
            24,
            "the failpoint matrix must enumerate every fixed role move/injection plus publication"
        );
        for failpoint in ProgressLifecycleActivationFailpoint::ALL.iter().copied() {
            let chain = Arc::new(CountingHttpChain::default());
            let published = Arc::new(AtomicUsize::new(0));
            let (_root, staging) = bootstrap_fixture(None);
            let result = activate_fixture(
                staging.expect("private staging succeeds"),
                Arc::clone(&chain),
                Some(failpoint),
                Arc::clone(&published),
            );

            assert_eq!(
                result.err(),
                Some(ProgressLifecycleActivationError::InjectedFailure),
                "failpoint {failpoint:?} must stop before activation escapes"
            );
            assert_eq!(
                published.load(Ordering::SeqCst),
                0,
                "failpoint {failpoint:?} must publish neither contract"
            );
            assert_eq!(
                chain.calls.load(Ordering::SeqCst),
                0,
                "failpoint {failpoint:?} must perform no card HTTP"
            );
        }
    }

    #[test]
    fn t101_success_publishes_the_joint_graph_exactly_once() {
        let chain = Arc::new(CountingHttpChain::default());
        let published = Arc::new(AtomicUsize::new(0));
        let (_root, staging) = bootstrap_fixture(None);
        let activation = activate_fixture(
            staging.expect("private staging succeeds"),
            Arc::clone(&chain),
            None,
            Arc::clone(&published),
        )
        .expect("all roles inject and the joint permit publishes");

        assert_eq!(published.load(Ordering::SeqCst), 1);
        assert_eq!(chain.calls.load(Ordering::SeqCst), 0);
        let _joint_consumers = (
            &activation.mailbox_store,
            &activation.execution_ingress,
            &activation.reply_routing,
            &activation.cost_attribution,
            &activation.execution_boundary,
            &activation.action_dispatcher,
            &activation.source_closer,
            &activation.route_delivery,
            &activation.typed_transport,
            &activation.attempt_reconciliation,
            &activation.attempt_outcome_attester,
        );
    }
}
