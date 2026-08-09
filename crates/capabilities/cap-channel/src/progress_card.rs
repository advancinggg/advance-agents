//! CONTRACT-215 Telegram mutable progress-card coordinator.
//!
//! The coordinator consumes only host-stamped [`RoutedOutboundMessage`] values.
//! It validates text before touching state, keeps one card per trusted key,
//! writes duplicate-sensitive attempts before transport, edits a known card,
//! finalizes terminal phases, and permits one fallback only for Telegram's two
//! exact edit-target-loss responses.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use advance_shared_types::outbound::{
    DeliveryReport, OutboundEncoding, OutboundRoute, OutboundTarget, RoutedOutboundMessage,
};
use advance_shared_types::progress_card::{
    progress_source_message_id_digest, AttemptReconciliationChallenge, AttemptReconciliationIssuer,
    AttemptReconciliationProof, DurableProgressCardEntry, DurableProgressCardRecord,
    IndeterminateAttemptKind, OutboundRouteRef, ProgressAttemptReconciliationPort,
    ProgressCardAuthorityVerifier, ProgressCardChallengeIssuer, ProgressCardCoordinatorError,
    ProgressCardKey, ProgressLiveCardSnapshot, ProgressPhase, ProgressProtectedStateIssuer,
    ProgressSourceLifecyclePort, ReconciledAttemptOutcome, ReconciliationEvidenceSource,
    SourceCloseChallenge, SourceLifecycleCloseAttestation, TrustedTransportOutcomeReceiptIssuer,
};
use advance_shared_types::security_validator::HttpResponse;
use advance_shared_types::turn_attribution::SourceTurnQuiescedReceipt;
use async_trait::async_trait;
use sha2::{Digest, Sha256};
use tokio::sync::Mutex as AsyncMutex;
use uuid::Uuid;

use crate::error::ChannelError;
use crate::subscription::Subscription;
use crate::types::AdapterType;

pub const MAX_PROGRESS_CARDS: usize = 4_096;
pub const PROGRESS_CARD_TTL_MS: u64 = 24 * 60 * 60 * 1_000;
pub const MAX_TELEGRAM_PROGRESS_SCALARS: usize = 4_096;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum TelegramProgressOperation {
    SendMessage,
    EditMessageText { message_id: i64 },
}

/// A transport error distinguishes a locally proven zero-delivery attempt
/// from every ambiguous/non-retryable result. HTTP timeout, 429, 5xx, auth,
/// and unclassified Telegram responses belong in `Ambiguous`.
#[derive(Debug)]
pub(crate) enum ProgressTransportError {
    DefinitelyNotDelivered(ChannelError),
    Ambiguous(ChannelError),
}

/// The only network seam used by the progress coordinator. `HttpEgress`
/// implements it through the same single `HttpSecurityChain::execute` call site
/// used by legacy channel egress.
#[async_trait]
pub(crate) trait TelegramProgressTransport: Send + Sync {
    /// Apply `ChannelBidi` scanning and return the exact post-scan text. Called
    /// before card lookup/locking/mutation.
    fn prepare_text(&self, text: &str) -> Result<String, ChannelError>;

    async fn execute_progress(
        &self,
        agent_id: &str,
        sub: &Subscription,
        target: &OutboundTarget,
        operation: TelegramProgressOperation,
        text: &str,
    ) -> Result<HttpResponse, ProgressTransportError>;
}

#[derive(Clone, Debug)]
enum ProgressCardRecord {
    Live {
        telegram_message_id: i64,
        last_touched_at_ms: u64,
    },
    Durable(DurableProgressCardRecord),
}

#[derive(Clone, Debug)]
struct ProgressCardEntry {
    generation: u64,
    record: ProgressCardRecord,
}

#[derive(Clone, Copy)]
struct ProgressCardLimits {
    capacity: usize,
    ttl_ms: u64,
}

/// Private concrete implementing the MODULE-016 card state machine. It is not
/// exported as either source-close or reconciliation authority; those ports
/// are attached by the authority layer without widening this rendering API.
pub(crate) struct ProgressCardCoordinator {
    transport: Arc<dyn TelegramProgressTransport>,
    challenge_issuer: Mutex<ProgressCardChallengeIssuer>,
    verifier: ProgressCardAuthorityVerifier,
    durable: ProgressProtectedStateIssuer,
    state: Mutex<HashMap<[u8; 32], ProgressCardEntry>>,
    key_guards: Mutex<HashMap<[u8; 32], Arc<AsyncMutex<()>>>>,
    active_authorities: Mutex<HashMap<[u8; 32], AuthorityReservationKind>>,
    limits: ProgressCardLimits,
    #[cfg(test)]
    eviction_race_hook: Mutex<Option<Arc<EvictionRaceHook>>>,
}

#[cfg(test)]
struct EvictionRaceHook {
    candidate_selected: Arc<std::sync::Barrier>,
    allow_removal: Arc<std::sync::Barrier>,
}

/// Narrow rendering facade exported to product composition.
///
/// The concrete coordinator and its protected-state implementation remain
/// private.  In particular this facade cannot mint close or reconciliation
/// authority; those capabilities are published separately through the two
/// least-privilege shared-type ports in [`ProgressCardProviderParts`].
pub struct ProgressCardRenderer {
    inner: Arc<ProgressCardCoordinator>,
}

impl ProgressCardRenderer {
    /// Render one host-decoded progress message under an already-acquired,
    /// journal-backed route reference.
    pub async fn render(
        &self,
        agent_id: &str,
        sub: &Subscription,
        message: &RoutedOutboundMessage,
        route_ref: &OutboundRouteRef,
    ) -> Result<DeliveryReport, ChannelError> {
        self.inner.render(agent_id, sub, message, route_ref).await
    }
}

/// Products staged by the MODULE-016 provider factory.  No single public
/// object combines rendering, source close, and attempt reconciliation.
pub struct ProgressCardProviderParts {
    pub renderer: Arc<ProgressCardRenderer>,
    pub source_lifecycle: Arc<dyn ProgressSourceLifecyclePort>,
    pub attempt_reconciliation: Arc<dyn ProgressAttemptReconciliationPort>,
    pub attempt_outcome_attester: Arc<ProgressAttemptOutcomeAttester>,
}

impl ProgressCardProviderParts {
    fn from_coordinator(
        inner: Arc<ProgressCardCoordinator>,
        transport_outcomes: TrustedTransportOutcomeReceiptIssuer,
        reconciliation_proofs: AttemptReconciliationIssuer,
    ) -> Self {
        let source_lifecycle: Arc<dyn ProgressSourceLifecyclePort> = inner.clone();
        let attempt_reconciliation: Arc<dyn ProgressAttemptReconciliationPort> = inner.clone();
        Self {
            renderer: Arc::new(ProgressCardRenderer { inner }),
            source_lifecycle,
            attempt_reconciliation,
            attempt_outcome_attester: Arc::new(ProgressAttemptOutcomeAttester {
                transport_outcomes: Mutex::new(transport_outcomes),
                reconciliation_proofs: Mutex::new(reconciliation_proofs),
            }),
        }
    }
}

/// Narrow provider-owned bridge from independently trusted transport evidence
/// to the exact reconciliation proof consumed by the coordinator.  Neither
/// issuer escapes composition, so callers cannot mint either intermediate
/// authority independently.
pub struct ProgressAttemptOutcomeAttester {
    transport_outcomes: Mutex<TrustedTransportOutcomeReceiptIssuer>,
    reconciliation_proofs: Mutex<AttemptReconciliationIssuer>,
}

impl ProgressAttemptOutcomeAttester {
    #[allow(clippy::too_many_arguments)]
    pub fn attest(
        &self,
        challenge: &AttemptReconciliationChallenge,
        outcome: ReconciledAttemptOutcome,
        telegram_message_id: Option<i64>,
        evidence_source: ReconciliationEvidenceSource,
        evidence_id: [u8; 16],
        evidence_digest: [u8; 32],
    ) -> Result<AttemptReconciliationProof, ChannelError> {
        let now_ms = unix_ms()?;
        let receipt = self
            .transport_outcomes
            .lock()
            .map_err(|_| fixed_invalid("progress-card-authority-poisoned"))?
            .issue_outcome(
                challenge,
                outcome,
                telegram_message_id,
                evidence_source,
                evidence_id,
                evidence_digest,
                now_ms,
            )
            .map_err(map_authority_error)
            .map_err(coordinator_error)?;
        self.reconciliation_proofs
            .lock()
            .map_err(|_| fixed_invalid("progress-card-authority-poisoned"))?
            .attest_attempt(challenge, &receipt, now_ms)
            .map_err(map_authority_error)
            .map_err(coordinator_error)
    }
}

/// Stage the MODULE-016 provider products over the exact production
/// [`crate::HttpEgress`] instance retained by channel composition. The
/// concrete coordinator and journal state role are fully consumed here; only
/// the narrow renderer, two disjoint lifecycle ports, and the provider-owned
/// evidence-to-proof attester escape.
pub fn stage_progress_card_provider(
    egress: Arc<crate::HttpEgress>,
    protected_state: ProgressProtectedStateIssuer,
    challenge_issuer: ProgressCardChallengeIssuer,
    transport_outcome_receipt_issuer: TrustedTransportOutcomeReceiptIssuer,
    reconciliation_proof_issuer: AttemptReconciliationIssuer,
    verifier: ProgressCardAuthorityVerifier,
) -> Result<ProgressCardProviderParts, ChannelError> {
    let transport: Arc<dyn TelegramProgressTransport> = egress;
    let coordinator = Arc::new(ProgressCardCoordinator::new(
        transport,
        protected_state,
        challenge_issuer,
        verifier,
    )?);
    Ok(ProgressCardProviderParts::from_coordinator(
        coordinator,
        transport_outcome_receipt_issuer,
        reconciliation_proof_issuer,
    ))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AuthorityReservationKind {
    SourceClose,
    AttemptReconciliation,
}

impl ProgressCardCoordinator {
    pub(crate) fn new(
        transport: Arc<dyn TelegramProgressTransport>,
        durable: ProgressProtectedStateIssuer,
        challenge_issuer: ProgressCardChallengeIssuer,
        verifier: ProgressCardAuthorityVerifier,
    ) -> Result<Self, ChannelError> {
        Self::new_with_limits(
            transport,
            durable,
            challenge_issuer,
            verifier,
            ProgressCardLimits {
                capacity: MAX_PROGRESS_CARDS,
                ttl_ms: PROGRESS_CARD_TTL_MS,
            },
        )
    }

    fn new_with_limits(
        transport: Arc<dyn TelegramProgressTransport>,
        durable: ProgressProtectedStateIssuer,
        challenge_issuer: ProgressCardChallengeIssuer,
        verifier: ProgressCardAuthorityVerifier,
        limits: ProgressCardLimits,
    ) -> Result<Self, ChannelError> {
        let rows = durable.load().map_err(coordinator_error)?;
        if rows.len() > limits.capacity {
            return Err(ChannelError::InvalidConfig(
                "progress-card-capacity".to_string(),
            ));
        }
        let mut state = HashMap::new();
        state
            .try_reserve(limits.capacity)
            .map_err(|_| fixed_invalid("progress-card-capacity"))?;
        for (key, entry) in rows {
            state.insert(
                key,
                ProgressCardEntry {
                    generation: entry.generation,
                    record: ProgressCardRecord::Durable(entry.record),
                },
            );
        }
        let mut key_guards = HashMap::new();
        key_guards
            .try_reserve(limits.capacity)
            .map_err(|_| fixed_invalid("progress-card-capacity"))?;
        let mut active_authorities = HashMap::new();
        active_authorities
            .try_reserve(limits.capacity)
            .map_err(|_| fixed_invalid("progress-card-capacity"))?;
        Ok(Self {
            transport,
            challenge_issuer: Mutex::new(challenge_issuer),
            verifier,
            durable,
            state: Mutex::new(state),
            key_guards: Mutex::new(key_guards),
            active_authorities: Mutex::new(active_authorities),
            limits,
            #[cfg(test)]
            eviction_race_hook: Mutex::new(None),
        })
    }

    /// Render one valid typed Telegram progress checkpoint.
    pub(crate) async fn render(
        &self,
        agent_id: &str,
        sub: &Subscription,
        message: &RoutedOutboundMessage,
        route_ref: &OutboundRouteRef,
    ) -> Result<DeliveryReport, ChannelError> {
        if message.encoding != OutboundEncoding::ProgressV1 {
            return Err(fixed_invalid("progress-encoding-invalid"));
        }
        if sub.config.adapter_type != AdapterType::Telegram {
            return Err(fixed_invalid("progress-adapter-unsupported"));
        }

        // Strict original-text gate, then ChannelBidi scan, then the exact same
        // post-scan scalar gate. All happen before key/state access.
        let original = validate_progress_text(&message.body)?;
        let prepared = self.transport.prepare_text(original)?;
        validate_progress_text(prepared.as_bytes())?;

        let phase = message
            .metadata
            .get("progress.phase")
            .and_then(|value| ProgressPhase::parse(value))
            .ok_or_else(|| fixed_invalid("progress-phase-invalid"))?;
        let key = key_from_message(message)?;
        if key.subscription_id != sub.id.as_str() {
            return Err(fixed_invalid("progress-route-invalid"));
        }
        let key_digest = key
            .digest()
            .map_err(|_| fixed_invalid("progress-key-invalid"))?;
        if self
            .active_authorities
            .lock()
            .map_err(|_| fixed_invalid("progress-journal-unavailable"))?
            .contains_key(&key_digest)
        {
            return Err(fixed_invalid("progress-authority-in-progress"));
        }
        let source_digest = progress_source_message_id_digest(&key.source_message_id)
            .map_err(|_| fixed_invalid("progress-key-invalid"))?;
        self.verifier
            .verify_route_ref_for_delivery(route_ref, key_digest, source_digest)
            .map_err(|_| fixed_invalid("progress-route-ref-invalid"))?;

        let target = OutboundTarget::ChatReply {
            conversation_id: key.conversation_id.clone(),
            reply_address: match &message.route {
                OutboundRoute::Channel { reply_address, .. } => reply_address.clone(),
                OutboundRoute::DirectReply => vec![],
            },
        };
        let now_ms = unix_ms()?;
        let guard = self.acquire_key_guard(key_digest)?;
        let _owned = guard.lock().await;
        if self
            .active_authorities
            .lock()
            .map_err(|_| fixed_invalid("progress-journal-unavailable"))?
            .contains_key(&key_digest)
        {
            return Err(fixed_invalid("progress-authority-in-progress"));
        }
        self.render_serialized(agent_id, sub, &target, key_digest, phase, &prepared, now_ms)
            .await
    }

    async fn render_serialized(
        &self,
        agent_id: &str,
        sub: &Subscription,
        target: &OutboundTarget,
        key_digest: [u8; 32],
        phase: ProgressPhase,
        text: &str,
        now_ms: u64,
    ) -> Result<DeliveryReport, ChannelError> {
        self.evict_expired_live(now_ms, key_digest)?;
        let current = self
            .state
            .lock()
            .map_err(|_| fixed_invalid("progress-journal-unavailable"))?
            .get(&key_digest)
            .cloned();
        match current {
            None => {
                self.ensure_capacity(key_digest, now_ms)?;
                self.initial_send(agent_id, sub, target, key_digest, phase, text, now_ms)
                    .await
            }
            Some(ProgressCardEntry {
                generation,
                record:
                    ProgressCardRecord::Live {
                        telegram_message_id,
                        ..
                    },
            }) => {
                self.edit_live(
                    agent_id,
                    sub,
                    target,
                    key_digest,
                    generation,
                    telegram_message_id,
                    phase,
                    text,
                    now_ms,
                )
                .await
            }
            Some(ProgressCardEntry {
                record:
                    ProgressCardRecord::Durable(DurableProgressCardRecord::TerminalTombstone {
                        terminal_fingerprint,
                        ..
                    }),
                ..
            }) => {
                let requested = terminal_fingerprint_for(key_digest, phase, text)
                    .ok_or_else(|| fixed_invalid("progress-card-closed"))?;
                // A terminal outcome reconciled after restart retains only the
                // normative delivery fingerprint in its durable attempt row;
                // accept that exact post-scan terminal identity as well.
                let reconciled_requested = delivery_fingerprint(key_digest, phase, text);
                if terminal_fingerprint == requested || terminal_fingerprint == reconciled_requested
                {
                    Ok(DeliveryReport::delivered())
                } else {
                    Err(fixed_invalid("progress-card-closed"))
                }
            }
            Some(ProgressCardEntry {
                record:
                    ProgressCardRecord::Durable(DurableProgressCardRecord::IndeterminateSend { .. }),
                ..
            }) => Err(ChannelError::ConnectionFailed(
                "delivery-indeterminate".to_string(),
            )),
            Some(ProgressCardEntry {
                record:
                    ProgressCardRecord::Durable(DurableProgressCardRecord::FallbackExhausted { .. }),
                ..
            }) => Err(ChannelError::ConnectionFailed(
                "progress-fallback-exhausted".to_string(),
            )),
        }
    }

    async fn initial_send(
        &self,
        agent_id: &str,
        sub: &Subscription,
        target: &OutboundTarget,
        key_digest: [u8; 32],
        phase: ProgressPhase,
        text: &str,
        now_ms: u64,
    ) -> Result<DeliveryReport, ChannelError> {
        let delivery_fingerprint = delivery_fingerprint(key_digest, phase, text);
        let generation = 1;
        self.persist_durable(
            key_digest,
            generation,
            DurableProgressCardRecord::IndeterminateSend {
                attempt_id: *Uuid::new_v4().as_bytes(),
                delivery_fingerprint,
                phase,
                attempt_kind: IndeterminateAttemptKind::InitialSend,
                first_attempted_at_ms: now_ms,
            },
        )?;
        let response = self
            .transport
            .execute_progress(
                agent_id,
                sub,
                target,
                TelegramProgressOperation::SendMessage,
                text,
            )
            .await;
        match response {
            Ok(response) => match classify_telegram_response(&response, false) {
                TelegramResponseClass::Success(Some(message_id)) => {
                    self.promote_success(key_digest, generation, phase, text, message_id, now_ms)?;
                    Ok(DeliveryReport::delivered())
                }
                _ => Err(ChannelError::ConnectionFailed(
                    "delivery-indeterminate".to_string(),
                )),
            },
            Err(ProgressTransportError::DefinitelyNotDelivered(error)) => {
                self.remove_card(key_digest)?;
                Err(error)
            }
            Err(ProgressTransportError::Ambiguous(error)) => Err(error),
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn edit_live(
        &self,
        agent_id: &str,
        sub: &Subscription,
        target: &OutboundTarget,
        key_digest: [u8; 32],
        generation: u64,
        telegram_message_id: i64,
        phase: ProgressPhase,
        text: &str,
        now_ms: u64,
    ) -> Result<DeliveryReport, ChannelError> {
        let delivery_fingerprint = delivery_fingerprint(key_digest, phase, text);
        // Every edit is duplicate-sensitive, including ordinary ack/progress
        // updates. Publish the exact attempt before HTTP so a crash, timeout,
        // or unclassified response can only resume through reconciliation.
        let attempt_generation = next_generation(generation)?;
        self.persist_durable(
            key_digest,
            attempt_generation,
            DurableProgressCardRecord::IndeterminateSend {
                attempt_id: *Uuid::new_v4().as_bytes(),
                delivery_fingerprint,
                phase,
                attempt_kind: IndeterminateAttemptKind::Edit {
                    prior_message_id: telegram_message_id,
                },
                first_attempted_at_ms: now_ms,
            },
        )?;

        let response = self
            .transport
            .execute_progress(
                agent_id,
                sub,
                target,
                TelegramProgressOperation::EditMessageText {
                    message_id: telegram_message_id,
                },
                text,
            )
            .await;
        match response {
            Ok(response) => match classify_telegram_response(&response, true) {
                TelegramResponseClass::Success(_) | TelegramResponseClass::NotModified => {
                    if phase.is_terminal() {
                        self.promote_terminal(key_digest, attempt_generation, phase, text, now_ms)?;
                    } else {
                        self.set_live(key_digest, attempt_generation, telegram_message_id, now_ms)?;
                    }
                    Ok(DeliveryReport::delivered())
                }
                TelegramResponseClass::DefinitiveTargetLoss => {
                    self.fallback_send(
                        agent_id,
                        sub,
                        target,
                        key_digest,
                        attempt_generation,
                        telegram_message_id,
                        phase,
                        text,
                        delivery_fingerprint,
                        now_ms,
                    )
                    .await
                }
                TelegramResponseClass::Unclassified => Err(ChannelError::ConnectionFailed(
                    "delivery-indeterminate".to_string(),
                )),
            },
            Err(ProgressTransportError::DefinitelyNotDelivered(error)) => {
                self.set_live(key_digest, attempt_generation, telegram_message_id, now_ms)?;
                Err(error)
            }
            Err(ProgressTransportError::Ambiguous(error)) => Err(error),
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn fallback_send(
        &self,
        agent_id: &str,
        sub: &Subscription,
        target: &OutboundTarget,
        key_digest: [u8; 32],
        generation: u64,
        lost_message_id: i64,
        phase: ProgressPhase,
        text: &str,
        delivery_fingerprint: [u8; 32],
        now_ms: u64,
    ) -> Result<DeliveryReport, ChannelError> {
        let fallback_generation = next_generation(generation)?;
        self.persist_durable(
            key_digest,
            fallback_generation,
            DurableProgressCardRecord::IndeterminateSend {
                attempt_id: *Uuid::new_v4().as_bytes(),
                delivery_fingerprint,
                phase,
                attempt_kind: IndeterminateAttemptKind::FallbackSend {
                    definitively_lost_message_id: lost_message_id,
                },
                first_attempted_at_ms: now_ms,
            },
        )?;
        let response = self
            .transport
            .execute_progress(
                agent_id,
                sub,
                target,
                TelegramProgressOperation::SendMessage,
                text,
            )
            .await;
        match response {
            Ok(response) => match classify_telegram_response(&response, false) {
                TelegramResponseClass::Success(Some(message_id)) => {
                    self.promote_success(
                        key_digest,
                        fallback_generation,
                        phase,
                        text,
                        message_id,
                        now_ms,
                    )?;
                    Ok(DeliveryReport::delivered())
                }
                _ => Err(ChannelError::ConnectionFailed(
                    "delivery-indeterminate".to_string(),
                )),
            },
            Err(ProgressTransportError::DefinitelyNotDelivered(error)) => {
                self.persist_durable(
                    key_digest,
                    next_generation(fallback_generation)?,
                    DurableProgressCardRecord::FallbackExhausted {
                        delivery_fingerprint,
                        definitively_lost_message_id: lost_message_id,
                        reconciled_at_ms: now_ms,
                    },
                )?;
                Err(error)
            }
            Err(ProgressTransportError::Ambiguous(error)) => Err(error),
        }
    }

    fn promote_success(
        &self,
        key_digest: [u8; 32],
        generation: u64,
        phase: ProgressPhase,
        text: &str,
        message_id: i64,
        now_ms: u64,
    ) -> Result<(), ChannelError> {
        if message_id <= 0 {
            return Err(ChannelError::ConnectionFailed(
                "delivery-indeterminate".to_string(),
            ));
        }
        if phase.is_terminal() {
            self.promote_terminal(key_digest, generation, phase, text, now_ms)
        } else {
            self.set_live(key_digest, generation, message_id, now_ms)
        }
    }

    fn promote_terminal(
        &self,
        key_digest: [u8; 32],
        generation: u64,
        phase: ProgressPhase,
        text: &str,
        now_ms: u64,
    ) -> Result<(), ChannelError> {
        let fingerprint = terminal_fingerprint_for(key_digest, phase, text)
            .ok_or_else(|| fixed_invalid("progress-phase-invalid"))?;
        self.persist_durable(
            key_digest,
            next_generation(generation)?,
            DurableProgressCardRecord::TerminalTombstone {
                terminal_fingerprint: fingerprint,
                delivered_at_ms: now_ms,
            },
        )
    }

    fn set_live(
        &self,
        key_digest: [u8; 32],
        generation: u64,
        message_id: i64,
        now_ms: u64,
    ) -> Result<(), ChannelError> {
        if message_id <= 0 {
            return Err(ChannelError::ConnectionFailed(
                "delivery-indeterminate".to_string(),
            ));
        }
        let next_generation = next_generation(generation)?;
        let expected = self.current_durable(key_digest)?;
        self.durable
            .replace(key_digest, expected.as_ref(), None)
            .map_err(coordinator_error)?;
        self.state
            .lock()
            .map_err(|_| fixed_invalid("progress-journal-unavailable"))?
            .insert(
                key_digest,
                ProgressCardEntry {
                    generation: next_generation,
                    record: ProgressCardRecord::Live {
                        telegram_message_id: message_id,
                        last_touched_at_ms: now_ms,
                    },
                },
            );
        Ok(())
    }

    fn persist_durable(
        &self,
        key_digest: [u8; 32],
        generation: u64,
        record: DurableProgressCardRecord,
    ) -> Result<(), ChannelError> {
        let durable_entry = DurableProgressCardEntry {
            generation,
            record: record.clone(),
        };
        let expected = self.current_durable(key_digest)?;
        self.durable
            .replace(key_digest, expected.as_ref(), Some(&durable_entry))
            .map_err(coordinator_error)?;
        self.state
            .lock()
            .map_err(|_| fixed_invalid("progress-journal-unavailable"))?
            .insert(
                key_digest,
                ProgressCardEntry {
                    generation,
                    record: ProgressCardRecord::Durable(record),
                },
            );
        Ok(())
    }

    fn remove_card(&self, key_digest: [u8; 32]) -> Result<(), ChannelError> {
        let expected = self.current_durable(key_digest)?;
        self.durable
            .replace(key_digest, expected.as_ref(), None)
            .map_err(coordinator_error)?;
        self.state
            .lock()
            .map_err(|_| fixed_invalid("progress-journal-unavailable"))?
            .remove(&key_digest);
        Ok(())
    }

    fn current_durable(
        &self,
        key_digest: [u8; 32],
    ) -> Result<Option<DurableProgressCardEntry>, ChannelError> {
        let state = self
            .state
            .lock()
            .map_err(|_| fixed_invalid("progress-journal-unavailable"))?;
        Ok(state
            .get(&key_digest)
            .and_then(|entry| match &entry.record {
                ProgressCardRecord::Durable(record) => Some(DurableProgressCardEntry {
                    generation: entry.generation,
                    record: record.clone(),
                }),
                ProgressCardRecord::Live { .. } => None,
            }))
    }

    fn acquire_key_guard(&self, key_digest: [u8; 32]) -> Result<Arc<AsyncMutex<()>>, ChannelError> {
        let mut guards = self
            .key_guards
            .lock()
            .map_err(|_| fixed_invalid("progress-journal-unavailable"))?;
        if !guards.contains_key(&key_digest) && guards.len() >= self.limits.capacity {
            guards.retain(|_, guard| Arc::strong_count(guard) > 1);
            if guards.len() >= self.limits.capacity {
                return Err(fixed_invalid("progress-card-capacity"));
            }
        }
        if !guards.contains_key(&key_digest) {
            guards
                .try_reserve(1)
                .map_err(|_| fixed_invalid("progress-card-capacity"))?;
        }
        Ok(guards
            .entry(key_digest)
            .or_insert_with(|| Arc::new(AsyncMutex::new(())))
            .clone())
    }

    fn evict_expired_live(&self, now_ms: u64, current: [u8; 32]) -> Result<(), ChannelError> {
        // Global lock order is key_guards -> state. Holding both makes the
        // ownership check and removal one linearized decision: a renderer
        // cannot clone the candidate guard between them.
        let guards = self
            .key_guards
            .lock()
            .map_err(|_| fixed_invalid("progress-journal-unavailable"))?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| fixed_invalid("progress-journal-unavailable"))?;
        let expired = state
            .iter()
            .filter_map(|(key, entry)| match entry.record {
                ProgressCardRecord::Live {
                    last_touched_at_ms, ..
                } if *key != current
                    && !Self::guard_is_owned(&guards, key)
                    && now_ms.saturating_sub(last_touched_at_ms) >= self.limits.ttl_ms =>
                {
                    Some(*key)
                }
                _ => None,
            })
            .collect::<Vec<_>>();
        for key in expired {
            #[cfg(test)]
            self.pause_before_eviction_removal();
            if !Self::guard_is_owned(&guards, &key) {
                state.remove(&key);
            }
        }
        Ok(())
    }

    fn ensure_capacity(&self, current: [u8; 32], now_ms: u64) -> Result<(), ChannelError> {
        self.evict_expired_live(now_ms, current)?;
        // Preserve the same key_guards -> state order used by TTL eviction.
        let guards = self
            .key_guards
            .lock()
            .map_err(|_| fixed_invalid("progress-journal-unavailable"))?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| fixed_invalid("progress-journal-unavailable"))?;
        if state.contains_key(&current) || state.len() < self.limits.capacity {
            return Ok(());
        }
        let candidate = state
            .iter()
            .filter_map(|(key, entry)| match entry.record {
                ProgressCardRecord::Live {
                    last_touched_at_ms, ..
                } if !Self::guard_is_owned(&guards, key) => Some((last_touched_at_ms, *key)),
                _ => None,
            })
            .min();
        if let Some((_, key)) = candidate {
            #[cfg(test)]
            self.pause_before_eviction_removal();
            if Self::guard_is_owned(&guards, &key) {
                Err(fixed_invalid("progress-card-capacity"))
            } else {
                state.remove(&key);
                Ok(())
            }
        } else {
            Err(fixed_invalid("progress-card-capacity"))
        }
    }

    fn guard_is_owned(guards: &HashMap<[u8; 32], Arc<AsyncMutex<()>>>, key: &[u8; 32]) -> bool {
        guards
            .get(key)
            .is_some_and(|guard| Arc::strong_count(guard) > 1)
    }

    #[cfg(test)]
    fn pause_before_eviction_removal(&self) {
        let hook = self
            .eviction_race_hook
            .lock()
            .expect("eviction race hook lock")
            .take();
        if let Some(hook) = hook {
            hook.candidate_selected.wait();
            hook.allow_removal.wait();
        }
    }
}

impl ProgressCardCoordinator {
    fn live_close_snapshot(
        &self,
        key_digest: [u8; 32],
    ) -> Result<Option<ProgressLiveCardSnapshot>, ProgressCardCoordinatorError> {
        let state = self
            .state
            .lock()
            .map_err(|_| ProgressCardCoordinatorError::JournalUnavailable)?;
        Ok(state
            .get(&key_digest)
            .and_then(|entry| match &entry.record {
                ProgressCardRecord::Live {
                    telegram_message_id,
                    ..
                } => Some(ProgressLiveCardSnapshot {
                    generation: entry.generation,
                    telegram_message_id: *telegram_message_id,
                }),
                ProgressCardRecord::Durable(_) => None,
            }))
    }

    fn source_close_busy(
        &self,
        key_digest: [u8; 32],
    ) -> Result<bool, ProgressCardCoordinatorError> {
        Ok(self
            .key_guards
            .lock()
            .map_err(|_| ProgressCardCoordinatorError::JournalUnavailable)?
            .get(&key_digest)
            .is_some_and(|guard| Arc::strong_count(guard) > 1))
    }
}

impl ProgressSourceLifecyclePort for ProgressCardCoordinator {
    fn begin_source_close(
        &self,
        source: &SourceTurnQuiescedReceipt,
    ) -> Result<SourceCloseChallenge, ProgressCardCoordinatorError> {
        let key_digest = source.progress_key_digest();
        let mut active = self
            .active_authorities
            .lock()
            .map_err(|_| ProgressCardCoordinatorError::JournalUnavailable)?;
        if active.contains_key(&key_digest) {
            return Err(ProgressCardCoordinatorError::AuthorityInProgress);
        }
        if self.source_close_busy(key_digest)? {
            return Err(ProgressCardCoordinatorError::Busy);
        }
        active
            .try_reserve(1)
            .map_err(|_| ProgressCardCoordinatorError::CapacityExhausted)?;
        let live = self.live_close_snapshot(key_digest)?;
        let challenge = self
            .challenge_issuer
            .lock()
            .map_err(|_| ProgressCardCoordinatorError::JournalUnavailable)?
            .issue_source_close_for_source(source, live)?;
        active.insert(key_digest, AuthorityReservationKind::SourceClose);
        Ok(challenge)
    }

    fn close_source(
        &self,
        source: &SourceTurnQuiescedReceipt,
        challenge: &SourceCloseChallenge,
        attestation: &SourceLifecycleCloseAttestation,
    ) -> Result<(), ProgressCardCoordinatorError> {
        let key_digest = source.progress_key_digest();
        let mut active = self
            .active_authorities
            .lock()
            .map_err(|_| ProgressCardCoordinatorError::JournalUnavailable)?;
        if active.get(&key_digest) != Some(&AuthorityReservationKind::SourceClose) {
            return Err(ProgressCardCoordinatorError::Replayed);
        }
        if self.source_close_busy(key_digest)? {
            return Err(ProgressCardCoordinatorError::Busy);
        }
        let live = self.live_close_snapshot(key_digest)?;
        self.verifier
            .commit_source_close_for_source(source, live, challenge, attestation)?;
        self.state
            .lock()
            .map_err(|_| ProgressCardCoordinatorError::JournalUnavailable)?
            .remove(&key_digest);
        active.remove(&key_digest);
        Ok(())
    }

    fn cancel_source_close(
        &self,
        source: &SourceTurnQuiescedReceipt,
        challenge: &SourceCloseChallenge,
    ) -> Result<(), ProgressCardCoordinatorError> {
        let key_digest = source.progress_key_digest();
        let mut active = self
            .active_authorities
            .lock()
            .map_err(|_| ProgressCardCoordinatorError::JournalUnavailable)?;
        if active.get(&key_digest) != Some(&AuthorityReservationKind::SourceClose) {
            return Err(ProgressCardCoordinatorError::Replayed);
        }
        let live = self.live_close_snapshot(key_digest)?;
        self.verifier
            .cancel_source_close_for_source(source, live, challenge)?;
        active.remove(&key_digest);
        Ok(())
    }
}

#[derive(Clone)]
struct AttemptSnapshot {
    generation: u64,
    attempt_id: [u8; 16],
    delivery_fingerprint: [u8; 32],
    phase: ProgressPhase,
    attempt_kind: IndeterminateAttemptKind,
}

impl ProgressCardCoordinator {
    fn attempt_snapshot(
        &self,
        key_digest: [u8; 32],
    ) -> Result<AttemptSnapshot, ProgressCardCoordinatorError> {
        let state = self
            .state
            .lock()
            .map_err(|_| ProgressCardCoordinatorError::JournalUnavailable)?;
        let Some(ProgressCardEntry {
            generation,
            record:
                ProgressCardRecord::Durable(DurableProgressCardRecord::IndeterminateSend {
                    attempt_id,
                    delivery_fingerprint,
                    phase,
                    attempt_kind,
                    ..
                }),
        }) = state.get(&key_digest)
        else {
            return Err(ProgressCardCoordinatorError::NotIndeterminate);
        };
        Ok(AttemptSnapshot {
            generation: *generation,
            attempt_id: *attempt_id,
            delivery_fingerprint: *delivery_fingerprint,
            phase: *phase,
            attempt_kind: attempt_kind.clone(),
        })
    }

    fn attempt_transition(
        snapshot: &AttemptSnapshot,
        outcome: ReconciledAttemptOutcome,
        telegram_message_id: Option<i64>,
        now_ms: u64,
    ) -> Result<
        (Option<DurableProgressCardEntry>, Option<ProgressCardEntry>),
        ProgressCardCoordinatorError,
    > {
        let next_generation = snapshot
            .generation
            .checked_add(1)
            .ok_or(ProgressCardCoordinatorError::GenerationExhausted)?;
        let next_record = match outcome {
            ReconciledAttemptOutcome::Delivered => {
                let message_id = telegram_message_id
                    .filter(|message_id| *message_id > 0)
                    .ok_or(ProgressCardCoordinatorError::BindingMismatch)?;
                if snapshot.phase.is_terminal() {
                    Some(ProgressCardRecord::Durable(
                        DurableProgressCardRecord::TerminalTombstone {
                            terminal_fingerprint: snapshot.delivery_fingerprint,
                            delivered_at_ms: now_ms,
                        },
                    ))
                } else {
                    Some(ProgressCardRecord::Live {
                        telegram_message_id: message_id,
                        last_touched_at_ms: now_ms,
                    })
                }
            }
            ReconciledAttemptOutcome::DefinitelyNotDelivered => {
                if telegram_message_id.is_some() {
                    return Err(ProgressCardCoordinatorError::BindingMismatch);
                }
                match &snapshot.attempt_kind {
                    IndeterminateAttemptKind::InitialSend => None,
                    IndeterminateAttemptKind::Edit { prior_message_id } => {
                        Some(ProgressCardRecord::Live {
                            telegram_message_id: *prior_message_id,
                            last_touched_at_ms: now_ms,
                        })
                    }
                    IndeterminateAttemptKind::FallbackSend {
                        definitively_lost_message_id,
                    } => Some(ProgressCardRecord::Durable(
                        DurableProgressCardRecord::FallbackExhausted {
                            delivery_fingerprint: snapshot.delivery_fingerprint,
                            definitively_lost_message_id: *definitively_lost_message_id,
                            reconciled_at_ms: now_ms,
                        },
                    )),
                }
            }
        };

        let durable = next_record.as_ref().and_then(|record| match record {
            ProgressCardRecord::Durable(record) => Some(DurableProgressCardEntry {
                generation: next_generation,
                record: record.clone(),
            }),
            ProgressCardRecord::Live { .. } => None,
        });
        let memory = next_record.map(|record| ProgressCardEntry {
            generation: next_generation,
            record,
        });
        Ok((durable, memory))
    }
}

impl ProgressAttemptReconciliationPort for ProgressCardCoordinator {
    fn begin_attempt_reconciliation(
        &self,
        key: &ProgressCardKey,
    ) -> Result<AttemptReconciliationChallenge, ProgressCardCoordinatorError> {
        let key_digest = key
            .digest()
            .map_err(|_| ProgressCardCoordinatorError::InvalidKey)?;
        let mut active = self
            .active_authorities
            .lock()
            .map_err(|_| ProgressCardCoordinatorError::JournalUnavailable)?;
        if active.contains_key(&key_digest) {
            return Err(ProgressCardCoordinatorError::AuthorityInProgress);
        }
        if self.source_close_busy(key_digest)? {
            return Err(ProgressCardCoordinatorError::Busy);
        }
        active
            .try_reserve(1)
            .map_err(|_| ProgressCardCoordinatorError::CapacityExhausted)?;
        self.attempt_snapshot(key_digest)?;
        let challenge = self
            .challenge_issuer
            .lock()
            .map_err(|_| ProgressCardCoordinatorError::JournalUnavailable)?
            .issue_attempt_reconciliation(key)?;
        active.insert(key_digest, AuthorityReservationKind::AttemptReconciliation);
        Ok(challenge)
    }

    fn reconcile_attempt(
        &self,
        key: &ProgressCardKey,
        challenge: &AttemptReconciliationChallenge,
        proof: &AttemptReconciliationProof,
    ) -> Result<ReconciledAttemptOutcome, ProgressCardCoordinatorError> {
        let key_digest = key
            .digest()
            .map_err(|_| ProgressCardCoordinatorError::InvalidKey)?;
        let mut active = self
            .active_authorities
            .lock()
            .map_err(|_| ProgressCardCoordinatorError::JournalUnavailable)?;
        if active.get(&key_digest) != Some(&AuthorityReservationKind::AttemptReconciliation) {
            return Err(ProgressCardCoordinatorError::Replayed);
        }
        if self.source_close_busy(key_digest)? {
            return Err(ProgressCardCoordinatorError::Busy);
        }
        let snapshot = self.attempt_snapshot(key_digest)?;
        let now_ms = unix_ms().map_err(|_| ProgressCardCoordinatorError::IntegrityFailure)?;
        let verified = self
            .verifier
            .verify_attempt_reconciliation(
                challenge,
                proof,
                key_digest,
                snapshot.generation,
                snapshot.attempt_id,
                &snapshot.attempt_kind,
                snapshot.delivery_fingerprint,
                snapshot.phase,
                now_ms,
            )
            .map_err(map_authority_error)?;
        let (next_durable, next_memory) = Self::attempt_transition(
            &snapshot,
            verified.outcome(),
            verified.telegram_message_id(),
            now_ms,
        )?;
        self.verifier.commit_attempt_reconciliation(
            key,
            challenge,
            proof,
            next_durable.as_ref(),
        )?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| ProgressCardCoordinatorError::JournalUnavailable)?;
        match next_memory {
            Some(entry) => {
                state.insert(key_digest, entry);
            }
            None => {
                state.remove(&key_digest);
            }
        }
        active.remove(&key_digest);
        Ok(verified.outcome())
    }

    fn cancel_attempt_reconciliation(
        &self,
        key: &ProgressCardKey,
        challenge: &AttemptReconciliationChallenge,
    ) -> Result<(), ProgressCardCoordinatorError> {
        let key_digest = key
            .digest()
            .map_err(|_| ProgressCardCoordinatorError::InvalidKey)?;
        let mut active = self
            .active_authorities
            .lock()
            .map_err(|_| ProgressCardCoordinatorError::JournalUnavailable)?;
        if active.get(&key_digest) != Some(&AuthorityReservationKind::AttemptReconciliation) {
            return Err(ProgressCardCoordinatorError::Replayed);
        }
        self.attempt_snapshot(key_digest)?;
        self.verifier
            .cancel_attempt_reconciliation(key, challenge)?;
        active.remove(&key_digest);
        Ok(())
    }
}

fn map_authority_error(
    error: advance_shared_types::progress_card::ProgressCardAuthorityError,
) -> ProgressCardCoordinatorError {
    use advance_shared_types::progress_card::ProgressCardAuthorityError;
    match error {
        ProgressCardAuthorityError::Expired => ProgressCardCoordinatorError::Expired,
        ProgressCardAuthorityError::Replayed => ProgressCardCoordinatorError::Replayed,
        ProgressCardAuthorityError::BindingMismatch
        | ProgressCardAuthorityError::WrongAuthority
        | ProgressCardAuthorityError::InvalidMac
        | ProgressCardAuthorityError::WrongOrder
        | ProgressCardAuthorityError::RoutesNotQuiescent
        | ProgressCardAuthorityError::InvalidInput => ProgressCardCoordinatorError::BindingMismatch,
        ProgressCardAuthorityError::CapacityExhausted => {
            ProgressCardCoordinatorError::CapacityExhausted
        }
        ProgressCardAuthorityError::GenerationExhausted => {
            ProgressCardCoordinatorError::GenerationExhausted
        }
        ProgressCardAuthorityError::JournalUnavailable => {
            ProgressCardCoordinatorError::JournalUnavailable
        }
        ProgressCardAuthorityError::IntegrityFailure => {
            ProgressCardCoordinatorError::IntegrityFailure
        }
    }
}

fn key_from_message(message: &RoutedOutboundMessage) -> Result<ProgressCardKey, ChannelError> {
    match &message.route {
        OutboundRoute::Channel {
            adapter_id,
            subscription_id,
            conversation_id,
            ..
        } => Ok(ProgressCardKey {
            adapter_id: adapter_id.clone(),
            subscription_id: subscription_id.clone(),
            conversation_id: conversation_id.clone(),
            source_message_id: message.source_message_id.clone(),
        }),
        OutboundRoute::DirectReply => Err(fixed_invalid("progress-route-invalid")),
    }
}

fn validate_progress_text(body: &[u8]) -> Result<&str, ChannelError> {
    let text = std::str::from_utf8(body).map_err(|_| fixed_invalid("invalid-progress-text"))?;
    let count = text.chars().count();
    if count == 0 || count > MAX_TELEGRAM_PROGRESS_SCALARS {
        return Err(fixed_invalid("invalid-progress-text"));
    }
    Ok(text)
}

fn delivery_fingerprint(key_digest: [u8; 32], phase: ProgressPhase, text: &str) -> [u8; 32] {
    fingerprint(
        b"advance.contract215.delivery-fingerprint.v1",
        key_digest,
        phase,
        text,
    )
}

fn terminal_fingerprint_for(
    key_digest: [u8; 32],
    phase: ProgressPhase,
    text: &str,
) -> Option<[u8; 32]> {
    phase.is_terminal().then(|| {
        fingerprint(
            b"advance.contract215.terminal-fingerprint.v1",
            key_digest,
            phase,
            text,
        )
    })
}

fn fingerprint(domain: &[u8], key_digest: [u8; 32], phase: ProgressPhase, text: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update([0]);
    hasher.update(key_digest);
    hasher.update([phase as u8]);
    hasher.update((text.len() as u32).to_be_bytes());
    hasher.update(text.as_bytes());
    hasher.finalize().into()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TelegramResponseClass {
    Success(Option<i64>),
    NotModified,
    DefinitiveTargetLoss,
    Unclassified,
}

fn classify_telegram_response(response: &HttpResponse, editing: bool) -> TelegramResponseClass {
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(&response.body) else {
        return TelegramResponseClass::Unclassified;
    };
    if response.status == 200 && value.get("ok").and_then(|value| value.as_bool()) == Some(true) {
        let message_id = value
            .pointer("/result/message_id")
            .and_then(|value| value.as_i64())
            .filter(|value| *value > 0);
        if editing || message_id.is_some() {
            return TelegramResponseClass::Success(message_id);
        }
        return TelegramResponseClass::Unclassified;
    }
    if !editing
        || response.status != 400
        || value.get("ok").and_then(|value| value.as_bool()) != Some(false)
        || value.get("error_code").and_then(|value| value.as_i64()) != Some(400)
    {
        return TelegramResponseClass::Unclassified;
    }
    let Some(description) = value.get("description").and_then(|value| value.as_str()) else {
        return TelegramResponseClass::Unclassified;
    };
    match description {
        "Bad Request: message is not modified" => TelegramResponseClass::NotModified,
        "Bad Request: message to edit not found" | "Bad Request: message can't be edited" => {
            TelegramResponseClass::DefinitiveTargetLoss
        }
        _ => TelegramResponseClass::Unclassified,
    }
}

fn next_generation(value: u64) -> Result<u64, ChannelError> {
    value
        .checked_add(1)
        .ok_or_else(|| fixed_invalid("progress-generation-exhausted"))
}

fn unix_ms() -> Result<u64, ChannelError> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| fixed_invalid("progress-clock-invalid"))?;
    u64::try_from(duration.as_millis()).map_err(|_| fixed_invalid("progress-clock-invalid"))
}

fn coordinator_error(error: ProgressCardCoordinatorError) -> ChannelError {
    ChannelError::InvalidConfig(error.to_string())
}

fn fixed_invalid(reason: &'static str) -> ChannelError {
    ChannelError::InvalidConfig(reason.to_string())
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, VecDeque};
    use std::num::NonZeroU32;
    use std::sync::{mpsc, Barrier};
    use std::thread;
    use std::time::Duration;

    use crate::subscription::{Consumer, Subscription};
    use crate::types::{ChannelConfig, HttpMethod, OutboundConfig, SubscriptionId};
    use advance_shared_types::outbound::TargetOutcome;
    use advance_shared_types::progress_card::{
        AttemptReconciliationIssuer, OutboundRouteBinding, OutboundRouteSealIssuer,
        ProgressCardAuthorityFactory, SourceCloseAttestationIssuer,
        TrustedTransportOutcomeReceiptIssuer,
    };
    use advance_shared_types::progress_lifecycle_recovery::{
        ProgressLifecycleRecoveryJournal, RecoveryJournalConfig,
    };
    use advance_shared_types::turn_attribution::{
        StoreQuiescenceFacts, StoreQuiescenceIssuer, TurnAttributionAuthorityFactory,
        TurnRegistryBinding, TurnRegistryIssuer,
    };
    use tempfile::TempDir;
    use zeroize::Zeroizing;

    use super::*;

    enum Reply {
        Http(HttpResponse),
        DefinitelyNotDelivered,
        Ambiguous,
    }

    #[derive(Default)]
    struct RecordingTransport {
        replies: Mutex<VecDeque<Reply>>,
        calls: Mutex<Vec<TelegramProgressOperation>>,
    }
    impl RecordingTransport {
        fn push(&self, reply: Reply) {
            self.replies.lock().unwrap().push_back(reply);
        }
        fn calls(&self) -> Vec<TelegramProgressOperation> {
            self.calls.lock().unwrap().clone()
        }
    }
    #[async_trait]
    impl TelegramProgressTransport for RecordingTransport {
        fn prepare_text(&self, text: &str) -> Result<String, ChannelError> {
            Ok(text.to_string())
        }
        async fn execute_progress(
            &self,
            _agent_id: &str,
            _sub: &Subscription,
            _target: &OutboundTarget,
            operation: TelegramProgressOperation,
            _text: &str,
        ) -> Result<HttpResponse, ProgressTransportError> {
            self.calls.lock().unwrap().push(operation);
            match self.replies.lock().unwrap().pop_front().unwrap() {
                Reply::Http(response) => Ok(response),
                Reply::DefinitelyNotDelivered => {
                    Err(ProgressTransportError::DefinitelyNotDelivered(
                        ChannelError::ConnectionFailed("not-delivered".into()),
                    ))
                }
                Reply::Ambiguous => Err(ProgressTransportError::Ambiguous(
                    ChannelError::ConnectionFailed("timeout".into()),
                )),
            }
        }
    }

    fn ok(message_id: i64) -> Reply {
        Reply::Http(HttpResponse {
            status: 200,
            headers: vec![],
            body: serde_json::json!({"ok":true,"result":{"message_id":message_id}})
                .to_string()
                .into_bytes(),
        })
    }
    fn target_lost() -> Reply {
        telegram_error(400, 400, "Bad Request: message to edit not found")
    }

    fn telegram_error(status: u16, error_code: i64, description: &str) -> Reply {
        Reply::Http(telegram_error_response(status, error_code, description))
    }

    fn telegram_error_response(status: u16, error_code: i64, description: &str) -> HttpResponse {
        HttpResponse {
            status,
            headers: vec![],
            body: serde_json::json!({
                "ok": false,
                "error_code": error_code,
                "description": description,
            })
            .to_string()
            .into_bytes(),
        }
    }

    fn sub() -> Subscription {
        Subscription::new_with_consumer(
            SubscriptionId("sub-1".into()),
            "agent:default",
            ChannelConfig {
                adapter_type: AdapterType::Telegram,
                params: vec![],
                outbound: Some(OutboundConfig {
                    method: HttpMethod::Post,
                    url_template: "https://api.telegram.org/botTOKEN/sendMessage".into(),
                    headers: vec![],
                }),
            },
            Consumer::HostPump,
        )
    }

    fn message(source: &str, phase: &str, body: &str) -> RoutedOutboundMessage {
        RoutedOutboundMessage {
            encoding: OutboundEncoding::ProgressV1,
            body: body.as_bytes().to_vec(),
            metadata: BTreeMap::from([("progress.phase".into(), phase.into())]),
            source_message_id: source.into(),
            route: OutboundRoute::Channel {
                adapter_id: "telegram".into(),
                subscription_id: "sub-1".into(),
                conversation_id: "chat-42".into(),
                reply_address: vec![("chat_id".into(), "chat-42".into())],
            },
        }
    }

    struct Rig {
        _journal_root: TempDir,
        transport: Arc<RecordingTransport>,
        coordinator: ProgressCardCoordinator,
        route: OutboundRouteSealIssuer,
        binding: OutboundRouteBinding,
        transport_receipts: TrustedTransportOutcomeReceiptIssuer,
        reconciliation: AttemptReconciliationIssuer,
        source_attester: SourceCloseAttestationIssuer,
        turn_registry: TurnRegistryIssuer,
        store_issuer: StoreQuiescenceIssuer,
        turn_binding: TurnRegistryBinding,
    }

    fn coordinator() -> Rig {
        let transport = Arc::new(RecordingTransport::default());
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
        let mut turn = TurnAttributionAuthorityFactory::new_at_composition(
            &mut rand::rngs::OsRng,
            turn_recovery,
        )
        .unwrap();
        let (_, turn_binding) = turn
            .registry_issuer
            .reserve_turn("msg-1", "agent:default")
            .unwrap()
            .into_parts();
        let authority = ProgressCardAuthorityFactory::new_with_os_rng_at_composition(
            turn.activation_staging,
            turn.source_quiescence_verifier,
            progress_recovery,
        )
        .unwrap();
        let mut route = authority.outbound_route_seal_issuer;
        let key = key_from_message(&message("msg-1", "ack", "x")).unwrap();
        let binding = route.arm_before_progress(&key, "agent:default").unwrap();
        let coordinator = ProgressCardCoordinator::new(
            transport.clone(),
            authority.protected_state_issuer,
            authority.coordinator_challenge_issuer,
            authority.verifier,
        )
        .unwrap();
        Rig {
            _journal_root: journal_root,
            transport,
            coordinator,
            route,
            binding,
            transport_receipts: authority.transport_outcome_receipt_issuer,
            reconciliation: authority.reconciliation_proof_issuer,
            source_attester: authority.source_close_attestation_issuer,
            turn_registry: turn.registry_issuer,
            store_issuer: turn.store_quiescence_issuer,
            turn_binding,
        }
    }

    async fn render_with_ref(
        coordinator: &ProgressCardCoordinator,
        route: &mut OutboundRouteSealIssuer,
        _binding: &OutboundRouteBinding,
        message: &RoutedOutboundMessage,
    ) -> Result<DeliveryReport, ChannelError> {
        let key = key_from_message(message)?;
        let binding = route
            .arm_before_progress(&key, "agent:default")
            .map_err(|_| fixed_invalid("progress-route-binding-mismatch"))?;
        let route_ref = route
            .acquire_route_ref(
                &binding,
                advance_shared_types::progress_card::OutboundRouteRefKind::Action,
            )
            .unwrap();
        let rendered = coordinator
            .render("agent:default", &sub(), message, &route_ref)
            .await;
        route.settle_route_ref(&route_ref).unwrap();
        rendered
    }

    #[tokio::test]
    async fn ack_progress_result_uses_one_positive_message_id_and_tombstones() {
        let Rig {
            _journal_root,
            transport,
            coordinator,
            mut route,
            binding,
            ..
        } = coordinator();
        transport.push(ok(77));
        transport.push(ok(77));
        transport.push(ok(77));

        for (phase, body) in [("ack", "working"), ("progress", "half"), ("result", "done")] {
            let report = render_with_ref(
                &coordinator,
                &mut route,
                &binding,
                &message("msg-1", phase, body),
            )
            .await
            .unwrap();
            assert_eq!(report.outcomes, vec![TargetOutcome::Delivered]);
        }
        assert_eq!(
            transport.calls(),
            vec![
                TelegramProgressOperation::SendMessage,
                TelegramProgressOperation::EditMessageText { message_id: 77 },
                TelegramProgressOperation::EditMessageText { message_id: 77 },
            ]
        );
        render_with_ref(
            &coordinator,
            &mut route,
            &binding,
            &message("msg-1", "result", "done"),
        )
        .await
        .unwrap();
        assert_eq!(
            transport.calls().len(),
            3,
            "terminal replay emits zero HTTP"
        );
    }

    #[tokio::test]
    async fn terminal_result_error_close_and_cancel_are_exact_and_replay_safe() {
        for phase in ["result", "error"] {
            let Rig {
                _journal_root,
                transport,
                coordinator,
                mut route,
                binding,
                mut source_attester,
                mut turn_registry,
                mut store_issuer,
                turn_binding,
                ..
            } = coordinator();
            transport.push(ok(77));
            let terminal = message("msg-1", phase, "done");
            render_with_ref(&coordinator, &mut route, &binding, &terminal)
                .await
                .unwrap();
            let key = key_from_message(&terminal).unwrap();
            let facts = StoreQuiescenceFacts {
                turn_id: "msg-1".into(),
                expected_agent: "agent:default".into(),
                store_incarnation: [1; 16],
            };
            let proof = store_issuer.issue_drained(&facts, 1).unwrap();
            let source = turn_registry
                .commit_store_quiescence(&turn_binding, &proof)
                .unwrap()
                .expect("armed terminal source produces a close receipt");
            let mut outbound = route.seal_and_issue_for_source(&source).unwrap();
            let mut challenge = coordinator.begin_source_close(&source).unwrap();

            if phase == "error" {
                coordinator
                    .cancel_source_close(&source, &challenge)
                    .unwrap();
                route.cancel_sealed_receipt(&outbound).unwrap();
                outbound = route.reissue_sealed_for_source(&source).unwrap();
                challenge = coordinator.begin_source_close(&source).unwrap();
            }

            let now_ms = unix_ms().unwrap();
            let attestation = source_attester
                .attest_source_close(&challenge, &source, &outbound, now_ms)
                .unwrap();
            coordinator
                .close_source(&source, &challenge, &attestation)
                .unwrap();
            assert!(coordinator
                .close_source(&source, &challenge, &attestation)
                .is_err());
            assert_eq!(transport.calls().len(), 1);
            assert!(!coordinator
                .state
                .lock()
                .unwrap()
                .contains_key(&key.digest().unwrap()));
        }
    }

    #[tokio::test]
    async fn definitive_target_loss_allows_exactly_one_fallback() {
        let Rig {
            _journal_root,
            transport,
            coordinator,
            mut route,
            binding,
            ..
        } = coordinator();
        transport.push(ok(10));
        transport.push(target_lost());
        transport.push(ok(11));
        render_with_ref(
            &coordinator,
            &mut route,
            &binding,
            &message("msg-1", "ack", "a"),
        )
        .await
        .unwrap();
        render_with_ref(
            &coordinator,
            &mut route,
            &binding,
            &message("msg-1", "progress", "b"),
        )
        .await
        .unwrap();
        assert_eq!(
            transport.calls(),
            vec![
                TelegramProgressOperation::SendMessage,
                TelegramProgressOperation::EditMessageText { message_id: 10 },
                TelegramProgressOperation::SendMessage,
            ]
        );
    }

    #[tokio::test]
    async fn ambiguous_initial_send_blocks_replay_without_second_http() {
        let Rig {
            _journal_root,
            transport,
            coordinator,
            mut route,
            binding,
            ..
        } = coordinator();
        transport.push(Reply::Ambiguous);
        assert!(render_with_ref(
            &coordinator,
            &mut route,
            &binding,
            &message("msg-1", "ack", "a")
        )
        .await
        .is_err());
        assert!(render_with_ref(
            &coordinator,
            &mut route,
            &binding,
            &message("msg-1", "ack", "a")
        )
        .await
        .is_err());
        assert_eq!(transport.calls().len(), 1);
    }

    #[tokio::test]
    async fn ambiguous_progress_edit_is_durable_and_blocks_replay() {
        let Rig {
            _journal_root,
            transport,
            coordinator,
            mut route,
            binding,
            mut transport_receipts,
            mut reconciliation,
            ..
        } = coordinator();
        transport.push(ok(10));
        transport.push(Reply::Ambiguous);
        render_with_ref(
            &coordinator,
            &mut route,
            &binding,
            &message("msg-1", "ack", "working"),
        )
        .await
        .unwrap();

        let progress = message("msg-1", "progress", "half");
        let key_digest = key_from_message(&progress).unwrap().digest().unwrap();
        assert!(
            render_with_ref(&coordinator, &mut route, &binding, &progress)
                .await
                .is_err()
        );

        let rows = coordinator.durable.load().expect("durable progress rows");
        let entry = rows.get(&key_digest).expect("edit attempt is durable");
        assert_eq!(entry.generation, 3);
        assert!(matches!(
            &entry.record,
            DurableProgressCardRecord::IndeterminateSend {
                phase: ProgressPhase::Progress,
                attempt_kind: IndeterminateAttemptKind::Edit {
                    prior_message_id: 10
                },
                ..
            }
        ));

        assert!(
            render_with_ref(&coordinator, &mut route, &binding, &progress)
                .await
                .is_err()
        );
        assert_eq!(
            transport.calls(),
            vec![
                TelegramProgressOperation::SendMessage,
                TelegramProgressOperation::EditMessageText { message_id: 10 },
            ],
            "an ambiguous ordinary edit is reconciled, never replayed"
        );

        let key = key_from_message(&progress).unwrap();
        let challenge = coordinator.begin_attempt_reconciliation(&key).unwrap();
        let now_ms = unix_ms().unwrap();
        let receipt = transport_receipts
            .issue_outcome(
                &challenge,
                ReconciledAttemptOutcome::DefinitelyNotDelivered,
                None,
                ReconciliationEvidenceSource::DurableTransportReceipt,
                [0x31; 16],
                [0x41; 32],
                now_ms,
            )
            .unwrap();
        let proof = reconciliation
            .attest_attempt(&challenge, &receipt, now_ms)
            .unwrap();
        assert_eq!(
            coordinator
                .reconcile_attempt(&key, &challenge, &proof)
                .unwrap(),
            ReconciledAttemptOutcome::DefinitelyNotDelivered
        );
        assert!(matches!(
            coordinator.state.lock().unwrap().get(&key_digest),
            Some(ProgressCardEntry {
                record: ProgressCardRecord::Live {
                    telegram_message_id: 10,
                    ..
                },
                ..
            })
        ));

        transport.push(ok(10));
        render_with_ref(
            &coordinator,
            &mut route,
            &binding,
            &message("msg-1", "progress", "reconciled-retry"),
        )
        .await
        .expect("reconciliation is the only path that unblocks the edit");
        assert_eq!(transport.calls().len(), 3);
    }

    #[tokio::test]
    async fn definitely_not_delivered_progress_edit_restores_prior_live() {
        let Rig {
            _journal_root,
            transport,
            coordinator,
            mut route,
            binding,
            ..
        } = coordinator();
        transport.push(ok(10));
        transport.push(Reply::DefinitelyNotDelivered);
        transport.push(ok(10));
        render_with_ref(
            &coordinator,
            &mut route,
            &binding,
            &message("msg-1", "ack", "working"),
        )
        .await
        .unwrap();

        let first_progress = message("msg-1", "progress", "half");
        let key_digest = key_from_message(&first_progress).unwrap().digest().unwrap();
        assert!(
            render_with_ref(&coordinator, &mut route, &binding, &first_progress)
                .await
                .is_err()
        );
        assert!(!coordinator
            .durable
            .load()
            .unwrap()
            .contains_key(&key_digest));
        assert!(matches!(
            coordinator.state.lock().unwrap().get(&key_digest),
            Some(ProgressCardEntry {
                generation: 4,
                record: ProgressCardRecord::Live {
                    telegram_message_id: 10,
                    ..
                }
            })
        ));

        render_with_ref(
            &coordinator,
            &mut route,
            &binding,
            &message("msg-1", "progress", "retry"),
        )
        .await
        .expect("a proven zero-delivery edit restores the prior Live target");
        assert_eq!(
            transport.calls(),
            vec![
                TelegramProgressOperation::SendMessage,
                TelegramProgressOperation::EditMessageText { message_id: 10 },
                TelegramProgressOperation::EditMessageText { message_id: 10 },
            ]
        );
    }

    #[tokio::test]
    async fn telegram_target_loss_near_misses_never_fallback() {
        for (status, error_code, description) in [
            (400, 400, " Bad Request: message to edit not found"),
            (400, 400, "Bad Request: message to edit not found "),
            (400, 400, "bad Request: message to edit not found"),
            (400, 400, "Bad Request: message to edit not found."),
            (400, 401, "Bad Request: message to edit not found"),
            (401, 400, "Bad Request: message to edit not found"),
        ] {
            let Rig {
                _journal_root,
                transport,
                coordinator,
                mut route,
                binding,
                ..
            } = coordinator();
            transport.push(ok(10));
            transport.push(telegram_error(status, error_code, description));
            render_with_ref(
                &coordinator,
                &mut route,
                &binding,
                &message("msg-1", "ack", "working"),
            )
            .await
            .unwrap();
            let progress = message("msg-1", "progress", "half");
            assert!(
                render_with_ref(&coordinator, &mut route, &binding, &progress)
                    .await
                    .is_err()
            );
            assert!(
                render_with_ref(&coordinator, &mut route, &binding, &progress)
                    .await
                    .is_err()
            );
            assert_eq!(
                transport.calls(),
                vec![
                    TelegramProgressOperation::SendMessage,
                    TelegramProgressOperation::EditMessageText { message_id: 10 },
                ],
                "near-miss description/status/code must stay indeterminate without fallback: {description:?}"
            );
        }
    }

    #[tokio::test]
    async fn exact_reconciliation_unblocks_only_the_original_attempt() {
        let Rig {
            _journal_root,
            transport,
            coordinator,
            mut route,
            binding,
            mut transport_receipts,
            mut reconciliation,
            ..
        } = coordinator();
        let first = message("msg-1", "ack", "working");
        let key = key_from_message(&first).unwrap();

        transport.push(Reply::Ambiguous);
        assert!(render_with_ref(&coordinator, &mut route, &binding, &first)
            .await
            .is_err());
        let challenge = coordinator.begin_attempt_reconciliation(&key).unwrap();
        let now_ms = unix_ms().unwrap();
        let receipt = transport_receipts
            .issue_outcome(
                &challenge,
                ReconciledAttemptOutcome::Delivered,
                Some(90),
                advance_shared_types::progress_card::ReconciliationEvidenceSource::LateHttpCompletion,
                [8; 16],
                [9; 32],
                now_ms,
            )
            .unwrap();
        let proof = reconciliation
            .attest_attempt(&challenge, &receipt, now_ms)
            .unwrap();
        assert_eq!(
            coordinator
                .reconcile_attempt(&key, &challenge, &proof)
                .unwrap(),
            ReconciledAttemptOutcome::Delivered
        );
        assert!(coordinator
            .reconcile_attempt(&key, &challenge, &proof)
            .is_err());

        transport.push(ok(90));
        render_with_ref(
            &coordinator,
            &mut route,
            &binding,
            &message("msg-1", "progress", "half"),
        )
        .await
        .unwrap();
        assert_eq!(
            transport.calls(),
            vec![
                TelegramProgressOperation::SendMessage,
                TelegramProgressOperation::EditMessageText { message_id: 90 },
            ]
        );
    }

    #[tokio::test]
    async fn fallback_proven_not_delivered_is_exhausted_forever() {
        let Rig {
            _journal_root,
            transport,
            coordinator,
            mut route,
            binding,
            ..
        } = coordinator();
        transport.push(ok(10));
        transport.push(target_lost());
        transport.push(Reply::DefinitelyNotDelivered);
        assert!(render_with_ref(
            &coordinator,
            &mut route,
            &binding,
            &message("msg-1", "progress", "a")
        )
        .await
        .is_ok());
        assert!(render_with_ref(
            &coordinator,
            &mut route,
            &binding,
            &message("msg-1", "result", "done")
        )
        .await
        .is_err());
        assert!(render_with_ref(
            &coordinator,
            &mut route,
            &binding,
            &message("msg-1", "result", "done")
        )
        .await
        .is_err());
        assert_eq!(transport.calls().len(), 3);
    }

    #[tokio::test]
    async fn text_gate_and_restart_close_only_happen_before_http() {
        let Rig {
            _journal_root,
            transport,
            coordinator: active_coordinator,
            mut route,
            binding,
            ..
        } = coordinator();
        transport.push(ok(5));
        render_with_ref(
            &active_coordinator,
            &mut route,
            &binding,
            &message("msg-1", "ack", "a"),
        )
        .await
        .unwrap();

        // Live is intentionally not durable. A restarted coordinator may not
        // accept an old-runtime route ref because authority rotates.
        let restarted_rig = coordinator();
        let restarted = &restarted_rig.coordinator;
        let refreshed = route
            .arm_before_progress(
                &key_from_message(&message("msg-1", "ack", "again")).unwrap(),
                "agent:default",
            )
            .unwrap();
        let old_ref = route
            .acquire_route_ref(
                &refreshed,
                advance_shared_types::progress_card::OutboundRouteRefKind::Action,
            )
            .unwrap();
        assert!(restarted
            .render(
                "agent:default",
                &sub(),
                &message("msg-1", "ack", "again"),
                &old_ref,
            )
            .await
            .is_err());
        route.settle_route_ref(&old_ref).unwrap();
        assert_eq!(transport.calls().len(), 1);

        let invalid = RoutedOutboundMessage {
            body: vec![0xff],
            ..message("msg-1", "ack", "x")
        };
        let refreshed = route
            .arm_before_progress(&key_from_message(&invalid).unwrap(), "agent:default")
            .unwrap();
        let invalid_ref = route
            .acquire_route_ref(
                &refreshed,
                advance_shared_types::progress_card::OutboundRouteRefKind::Action,
            )
            .unwrap();
        assert!(active_coordinator
            .render("agent:default", &sub(), &invalid, &invalid_ref)
            .await
            .is_err());
        route.settle_route_ref(&invalid_ref).unwrap();
        assert_eq!(transport.calls().len(), 1);
    }

    #[test]
    fn ttl_and_lru_guard_acquisition_is_atomic_with_live_removal() {
        let Rig {
            _journal_root,
            mut coordinator,
            ..
        } = coordinator();
        coordinator.limits = ProgressCardLimits {
            capacity: 1,
            ttl_ms: u64::MAX,
        };
        let coordinator = Arc::new(coordinator);
        let candidate = [0x61; 32];
        let current = [0x62; 32];
        coordinator.state.lock().unwrap().insert(
            candidate,
            ProgressCardEntry {
                generation: 1,
                record: ProgressCardRecord::Live {
                    telegram_message_id: 10,
                    last_touched_at_ms: 0,
                },
            },
        );

        let selected = Arc::new(Barrier::new(2));
        let allow_removal = Arc::new(Barrier::new(2));
        *coordinator.eviction_race_hook.lock().unwrap() = Some(Arc::new(EvictionRaceHook {
            candidate_selected: Arc::clone(&selected),
            allow_removal: Arc::clone(&allow_removal),
        }));

        let evictor = {
            let coordinator = Arc::clone(&coordinator);
            thread::spawn(move || coordinator.ensure_capacity(current, 0))
        };
        selected.wait();

        let (started_tx, started_rx) = mpsc::channel();
        let (acquired_tx, acquired_rx) = mpsc::channel();
        let contender = {
            let coordinator = Arc::clone(&coordinator);
            thread::spawn(move || {
                started_tx.send(()).unwrap();
                let guard = coordinator.acquire_key_guard(candidate).unwrap();
                acquired_tx.send(guard).unwrap();
            })
        };
        started_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        assert!(
            acquired_rx.recv_timeout(Duration::from_millis(50)).is_err(),
            "guard acquisition must not linearize between selection and removal"
        );

        allow_removal.wait();
        evictor.join().unwrap().unwrap();
        let acquired = acquired_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        contender.join().unwrap();
        assert!(!coordinator.state.lock().unwrap().contains_key(&candidate));

        // The opposite ordering is equally safe: once a renderer owns the
        // candidate guard, both TTL and LRU eviction must leave Live intact.
        coordinator.state.lock().unwrap().insert(
            candidate,
            ProgressCardEntry {
                generation: 2,
                record: ProgressCardRecord::Live {
                    telegram_message_id: 10,
                    last_touched_at_ms: 0,
                },
            },
        );
        let locked = acquired.try_lock().expect("candidate guard is held");
        coordinator.evict_expired_live(u64::MAX, current).unwrap();
        assert!(coordinator.state.lock().unwrap().contains_key(&candidate));
        assert!(coordinator.ensure_capacity(current, 0).is_err());
        assert!(coordinator.state.lock().unwrap().contains_key(&candidate));
        drop(locked);
        drop(acquired);
        coordinator.ensure_capacity(current, 0).unwrap();
        assert!(!coordinator.state.lock().unwrap().contains_key(&candidate));
    }

    #[test]
    fn classifier_requires_raw_exact_telegram_descriptions() {
        assert_eq!(
            classify_telegram_response(
                &telegram_error_response(400, 400, "Bad Request: message is not modified"),
                true,
            ),
            TelegramResponseClass::NotModified
        );
        for description in [
            "Bad Request: message to edit not found",
            "Bad Request: message can't be edited",
        ] {
            assert_eq!(
                classify_telegram_response(&telegram_error_response(400, 400, description), true,),
                TelegramResponseClass::DefinitiveTargetLoss
            );
        }
        for description in [
            " Bad Request: message is not modified",
            "Bad Request: message is not modified ",
            "bad Request: message is not modified",
            "Bad Request: message is not modified.",
        ] {
            assert_eq!(
                classify_telegram_response(&telegram_error_response(400, 400, description), true,),
                TelegramResponseClass::Unclassified
            );
        }
    }

    #[test]
    fn fingerprint_vectors_match_contract() {
        let key = [0x11; 32];
        assert_eq!(
            hex(delivery_fingerprint(key, ProgressPhase::Progress, "ok")),
            "c52f27614449d21ca4031e5f2506b8ed9721650fea1a4aafa291ebde9188133b"
        );
        assert_eq!(
            hex(terminal_fingerprint_for(key, ProgressPhase::Result, "done").unwrap()),
            "342ce86ce35c4da6318447c5a81e8a6b50dd549ef668da206a33ea863956327e"
        );
    }

    fn hex(bytes: [u8; 32]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }
}
