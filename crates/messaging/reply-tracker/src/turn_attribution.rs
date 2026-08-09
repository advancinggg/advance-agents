//! Private in-memory CONTRACT-216 provider.
//!
//! One poison-tolerant mutex owns lifecycle, reply settlement, issuance and
//! verification.  This gives claim/detach/cost projections a single
//! linearization point and keeps the registry strictly bounded.

use advance_messaging::AgentIdBridge;
use advance_shared_types::turn_attribution::*;
use advance_shared_types::SessionId;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ClaimPhase {
    Claimed,
    DeliveryStarted,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RecoveryMarker {
    Accepted([u8; 32]),
    NotAccepted([u8; 32]),
    // Designed C216 recovery vocabulary: minted by `record_reply_terminal`, whose
    // provider wiring is a later composition slice (see that method's allow note).
    #[allow(dead_code)]
    Terminal,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ReplyState {
    Open,
    Claimed {
        token_digest: [u8; 32],
        phase: ClaimPhase,
        marker: Option<RecoveryMarker>,
    },
    RecoveryPending {
        token_digest: [u8; 32],
        marker: Option<RecoveryMarker>,
    },
    Consumed {
        token_digest: [u8; 32],
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LateState {
    Open,
    Claimed { token_digest: [u8; 32] },
    Completed { token_digest: [u8; 32] },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ProviderState {
    Reserved,
    Queued,
    DequeuedPendingStart {
        receipt_digest: [u8; 32],
        handoff_complete: bool,
    },
    Running {
        execution_finished: bool,
        proof_digest: Option<[u8; 32]>,
    },
    FinishedNoReply {
        proof_digest: [u8; 32],
    },
    Detached {
        from: DetachOrigin,
        execution_finished: bool,
        proof_digest: Option<[u8; 32]>,
        queued_cleanup_digest: Option<[u8; 32]>,
    },
}

struct TurnEntry {
    spec: QueuedTurnSpec,
    binding: TurnRegistryBinding,
    state: ProviderState,
    reply: ReplyState,
    late: LateState,
}

struct RegistryCore {
    entries: HashMap<String, TurnEntry>,
    issuer: TurnRegistryIssuer,
    verifier: TurnAttributionVerifier,
}

impl RegistryCore {
    fn find_entry_key(&self, claims: &VerifiedTurnCredential) -> Option<String> {
        self.entries
            .iter()
            .find(|(_, entry)| {
                claims.matches_identity(&entry.spec.turn_id, &entry.spec.expected_agent)
                    && self
                        .verifier
                        .credential_matches_binding_stable(claims, &entry.binding)
            })
            .map(|(key, _)| key.clone())
    }
}

/// Concrete provider.  Composition should expose five separate
/// `Arc<dyn Turn*Port>` views, never this type, to downstream consumers.
pub(crate) struct TurnAttributionRegistry {
    core: Mutex<RegistryCore>,
    max_entries: usize,
}

impl TurnAttributionRegistry {
    pub(crate) fn new(
        max_entries: usize,
        issuer: TurnRegistryIssuer,
        verifier: TurnAttributionVerifier,
    ) -> Result<Self, TurnDispatchError> {
        if max_entries == 0 || max_entries > MAX_TURN_ATTRIBUTION_MAX_ENTRIES {
            return Err(TurnDispatchError::InvalidRoute);
        }
        Ok(Self {
            core: Mutex::new(RegistryCore {
                entries: HashMap::with_capacity(max_entries),
                issuer,
                verifier,
            }),
            max_entries,
        })
    }

    #[cfg(test)]
    pub(crate) fn entry_count(&self) -> usize {
        self.try_lock()
            .map(|core| core.entries.len())
            .unwrap_or(self.max_entries)
    }

    /// Provider-owned session callback: seal an accepted marker only for the
    /// exact live claim.  This is intentionally absent from the routing port.
    pub(crate) fn record_reply_accepted(
        &self,
        token: &ActiveReplyClaimToken,
    ) -> Result<ReplyAcceptedReceipt, TurnReplyError> {
        let mut core = self.try_lock().map_err(|_| TurnReplyError::StateConflict)?;
        let claims = core
            .verifier
            .active_claim_claims(token)
            .ok_or(TurnReplyError::TokenRejected)?;
        let key = core
            .find_entry_key(&claims)
            .ok_or(TurnReplyError::StaleClaim)?;
        let token_digest = claims.correlation_digest();
        match core.entries.get(&key).map(|entry| entry.reply) {
            Some(ReplyState::Claimed {
                token_digest: expected,
                phase: ClaimPhase::DeliveryStarted,
                ..
            }) if expected == token_digest => {}
            Some(ReplyState::Claimed { .. }) => return Err(TurnReplyError::InvalidSettlement),
            Some(ReplyState::RecoveryPending { .. }) => {
                return Err(TurnReplyError::RecoveryPending)
            }
            Some(ReplyState::Consumed { .. }) => return Err(TurnReplyError::AlreadyConsumed),
            _ => return Err(TurnReplyError::StaleClaim),
        }
        let receipt = {
            let RegistryCore {
                entries, issuer, ..
            } = &mut *core;
            let entry = entries.get(&key).ok_or(TurnReplyError::StaleClaim)?;
            issuer.issue_reply_accepted_for(&entry.binding, token)?
        };
        let receipt_digest = core
            .verifier
            .reply_accepted_claims(&receipt)
            .ok_or(TurnReplyError::ReceiptRejected)?
            .correlation_digest();
        if let Some(entry) = core.entries.get_mut(&key) {
            if let ReplyState::Claimed { marker, .. } = &mut entry.reply {
                *marker = Some(RecoveryMarker::Accepted(receipt_digest));
            }
        }
        Ok(receipt)
    }

    /// Provider-owned session callback for an exact definite rejection.
    pub(crate) fn record_reply_not_accepted(
        &self,
        token: &ActiveReplyClaimToken,
    ) -> Result<ReplyNotAcceptedReceipt, TurnReplyError> {
        let mut core = self.try_lock().map_err(|_| TurnReplyError::StateConflict)?;
        let claims = core
            .verifier
            .active_claim_claims(token)
            .ok_or(TurnReplyError::TokenRejected)?;
        let key = core
            .find_entry_key(&claims)
            .ok_or(TurnReplyError::StaleClaim)?;
        let token_digest = claims.correlation_digest();
        match core.entries.get(&key).map(|entry| entry.reply) {
            Some(ReplyState::Claimed {
                token_digest: expected,
                phase: ClaimPhase::DeliveryStarted,
                ..
            }) if expected == token_digest => {}
            Some(ReplyState::Claimed { .. }) => return Err(TurnReplyError::InvalidSettlement),
            Some(ReplyState::RecoveryPending { .. }) => {
                return Err(TurnReplyError::RecoveryPending)
            }
            Some(ReplyState::Consumed { .. }) => return Err(TurnReplyError::AlreadyConsumed),
            _ => return Err(TurnReplyError::StaleClaim),
        }
        let receipt = {
            let RegistryCore {
                entries, issuer, ..
            } = &mut *core;
            let entry = entries.get(&key).ok_or(TurnReplyError::StaleClaim)?;
            issuer.issue_reply_not_accepted_for(&entry.binding, token)?
        };
        let receipt_digest = core
            .verifier
            .reply_not_accepted_claims(&receipt)
            .ok_or(TurnReplyError::ReceiptRejected)?
            .correlation_digest();
        if let Some(entry) = core.entries.get_mut(&key) {
            if let ReplyState::Claimed { marker, .. } = &mut entry.reply {
                *marker = Some(RecoveryMarker::NotAccepted(receipt_digest));
            }
        }
        Ok(receipt)
    }

    /// Mark the session slot terminal/missing for provider recovery.  No
    /// payload is retained and recovery never invokes delivery again.
    #[allow(dead_code)] // designed C216 provider-recovery surface; production caller lands with the composition barrier slice
    pub(crate) fn record_reply_terminal(
        &self,
        token: &ActiveReplyClaimToken,
    ) -> Result<(), TurnReplyError> {
        let mut core = self.try_lock().map_err(|_| TurnReplyError::StateConflict)?;
        let claims = core
            .verifier
            .active_claim_claims(token)
            .ok_or(TurnReplyError::TokenRejected)?;
        let key = core
            .find_entry_key(&claims)
            .ok_or(TurnReplyError::StaleClaim)?;
        let digest = claims.correlation_digest();
        let entry = core
            .entries
            .get_mut(&key)
            .ok_or(TurnReplyError::StaleClaim)?;
        match &mut entry.reply {
            ReplyState::Claimed {
                token_digest,
                marker,
                ..
            }
            | ReplyState::RecoveryPending {
                token_digest,
                marker,
            } if *token_digest == digest => {
                *marker = Some(RecoveryMarker::Terminal);
                Ok(())
            }
            ReplyState::Consumed { .. } => Err(TurnReplyError::AlreadyConsumed),
            _ => Err(TurnReplyError::StaleClaim),
        }
    }

    fn try_lock(&self) -> Result<std::sync::MutexGuard<'_, RegistryCore>, ()> {
        // A panic while holding the authority lock may leave coupled lifecycle,
        // reply, and token state inconsistent.  Never recover the poisoned
        // inner value: every port stays fail-closed for the process lifetime.
        self.core.lock().map_err(|_| ())
    }
}

/// Move-only composition result containing exactly the five CONTRACT-216
/// least-privilege facades.  The concrete registry is never returned.
pub struct TurnAttributionFacades {
    dispatch: Arc<dyn TurnDispatchLifecyclePort>,
    execution: Arc<dyn TurnExecutionLifecyclePort>,
    reply: Arc<dyn TurnReplyRoutingPort>,
    mailbox: Arc<dyn TurnMailboxLifecyclePort>,
    cost: Arc<dyn TurnCostAttributionReadPort>,
}

impl TurnAttributionFacades {
    #[allow(clippy::type_complexity)]
    pub fn move_to_composition(
        self,
    ) -> (
        Arc<dyn TurnDispatchLifecyclePort>,
        Arc<dyn TurnExecutionLifecyclePort>,
        Arc<dyn TurnReplyRoutingPort>,
        Arc<dyn TurnMailboxLifecyclePort>,
        Arc<dyn TurnCostAttributionReadPort>,
    ) {
        (
            self.dispatch,
            self.execution,
            self.reply,
            self.mailbox,
            self.cost,
        )
    }
}

impl std::fmt::Debug for TurnAttributionFacades {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TurnAttributionFacades(<five-role-split>)")
    }
}

pub fn compose_turn_attribution_facades(
    max_entries: usize,
    issuer: TurnRegistryIssuer,
    verifier: TurnAttributionVerifier,
) -> Result<TurnAttributionFacades, TurnDispatchError> {
    let registry = Arc::new(TurnAttributionRegistry::new(max_entries, issuer, verifier)?);
    let dispatch: Arc<dyn TurnDispatchLifecyclePort> = registry.clone();
    let execution: Arc<dyn TurnExecutionLifecyclePort> = registry.clone();
    let reply: Arc<dyn TurnReplyRoutingPort> = registry.clone();
    let mailbox: Arc<dyn TurnMailboxLifecyclePort> = registry.clone();
    let cost: Arc<dyn TurnCostAttributionReadPort> = registry;
    Ok(TurnAttributionFacades {
        dispatch,
        execution,
        reply,
        mailbox,
        cost,
    })
}

/// Composition adapter for the runtime's authenticated bare `agent_id`
/// grammar. The registry remains strictly colon-canonical; only the injected,
/// host-owned bridge may translate a known member. Unknown aliases fail closed
/// and no guest/control value can install a mapping.
pub fn canonical_turn_identity_facades(
    reply: Arc<dyn TurnReplyRoutingPort>,
    cost: Arc<dyn TurnCostAttributionReadPort>,
    bridge: Arc<AgentIdBridge>,
) -> (
    Arc<dyn TurnReplyRoutingPort>,
    Arc<dyn TurnCostAttributionReadPort>,
) {
    (
        Arc::new(CanonicalTurnReplyPort {
            inner: reply,
            bridge: Arc::clone(&bridge),
        }),
        Arc::new(CanonicalTurnCostPort {
            inner: cost,
            bridge,
        }),
    )
}

struct CanonicalTurnReplyPort {
    inner: Arc<dyn TurnReplyRoutingPort>,
    bridge: Arc<AgentIdBridge>,
}

impl CanonicalTurnReplyPort {
    fn canonical(&self, authenticated_agent: &str) -> Option<String> {
        self.bridge
            .resolve_owned(authenticated_agent)
            .map(|(_, mailbox)| mailbox)
    }
}

impl TurnReplyRoutingPort for CanonicalTurnReplyPort {
    fn classify_send(
        &self,
        turn_id: &str,
        expected_agent: &str,
        destination: &str,
    ) -> SendTurnClassification {
        let Some(expected_agent) = self.canonical(expected_agent) else {
            return SendTurnClassification::IdentityMismatch;
        };
        self.inner
            .classify_send(turn_id, &expected_agent, destination)
    }

    fn claim_active_reply(
        &self,
        turn_id: &str,
        expected_agent: &str,
        destination: &str,
    ) -> Result<ReplyRouteClaim, TurnReplyError> {
        let expected_agent = self
            .canonical(expected_agent)
            .ok_or(TurnReplyError::IdentityMismatch)?;
        self.inner
            .claim_active_reply(turn_id, &expected_agent, destination)
    }

    fn begin_reply_delivery(&self, token: &ActiveReplyClaimToken) -> Result<(), TurnReplyError> {
        self.inner.begin_reply_delivery(token)
    }

    fn settle_reply_accepted(
        &self,
        token: &ActiveReplyClaimToken,
    ) -> Result<ReplySettlement, TurnReplyError> {
        self.inner.settle_reply_accepted(token)
    }

    fn settle_reply_not_accepted(
        &self,
        token: &ActiveReplyClaimToken,
    ) -> Result<ReplySettlement, TurnReplyError> {
        self.inner.settle_reply_not_accepted(token)
    }

    fn complete_reply(
        &self,
        token: &ActiveReplyClaimToken,
        receipt: ReplyAcceptedReceipt,
    ) -> Result<ReplySettlement, TurnReplyError> {
        self.inner.complete_reply(token, receipt)
    }

    fn abort_reply(
        &self,
        token: &ActiveReplyClaimToken,
        proof: ReplyAbortProof,
    ) -> Result<ReplySettlement, TurnReplyError> {
        self.inner.abort_reply(token, proof)
    }

    fn abandon_reply(&self, token: &ActiveReplyClaimToken) -> Result<(), TurnReplyError> {
        self.inner.abandon_reply(token)
    }

    fn claim_reply_late(
        &self,
        turn_id: &str,
        expected_agent: &str,
        destination: &str,
    ) -> Result<LateReplyClaim, TurnReplyError> {
        let expected_agent = self
            .canonical(expected_agent)
            .ok_or(TurnReplyError::IdentityMismatch)?;
        self.inner
            .claim_reply_late(turn_id, &expected_agent, destination)
    }

    fn complete_reply_late(&self, token: LateReplyDispositionToken) -> Result<(), TurnReplyError> {
        self.inner.complete_reply_late(token)
    }
}

struct CanonicalTurnCostPort {
    inner: Arc<dyn TurnCostAttributionReadPort>,
    bridge: Arc<AgentIdBridge>,
}

impl TurnCostAttributionReadPort for CanonicalTurnCostPort {
    fn cost_attribution(&self, turn_id: &str, expected_agent: &str) -> CostAttributionLookup {
        let Some((_, expected_agent)) = self.bridge.resolve_owned(expected_agent) else {
            return CostAttributionLookup::IdentityMismatch;
        };
        self.inner.cost_attribution(turn_id, &expected_agent)
    }
}

impl TurnDispatchLifecyclePort for TurnAttributionRegistry {
    fn reserve_queued(
        &self,
        spec: QueuedTurnSpec,
    ) -> Result<QueuedTurnReservation, TurnDispatchError> {
        spec.validate()?;
        let mut core = self
            .try_lock()
            .map_err(|_| TurnDispatchError::RecoveryJournalUnavailable)?;
        recover_pending_locked(&mut core);
        if core.entries.len() >= self.max_entries {
            return Err(TurnDispatchError::CapacityExhausted);
        }
        if core.entries.contains_key(&spec.turn_id) {
            return Err(TurnDispatchError::DuplicateTurn);
        }
        // Reserve the only fallible in-memory allocation before the issuer
        // durably inserts the corresponding ActiveSource journal row.
        core.entries
            .try_reserve(1)
            .map_err(|_| TurnDispatchError::CapacityExhausted)?;
        let issued = core
            .issuer
            .reserve_turn(&spec.turn_id, &spec.expected_agent)?;
        let (reservation, binding) = issued.into_parts();
        core.entries.insert(
            spec.turn_id.clone(),
            TurnEntry {
                spec,
                binding,
                state: ProviderState::Reserved,
                reply: ReplyState::Open,
                late: LateState::Open,
            },
        );
        Ok(reservation)
    }

    fn confirm_mailbox_admission(
        &self,
        reservation: &QueuedTurnReservation,
        receipt: &MailboxAdmissionReceipt,
    ) -> Result<ConfirmedTurnAdmission, TurnDispatchError> {
        let mut core = self
            .try_lock()
            .map_err(|_| TurnDispatchError::RecoveryJournalUnavailable)?;
        let reservation_claims = core
            .verifier
            .reservation_claims(&reservation)
            .ok_or(TurnDispatchError::ReservationRejected)?;
        let key = core
            .find_entry_key(&reservation_claims)
            .ok_or(TurnDispatchError::ReservationRejected)?;
        let entry = core
            .entries
            .get(&key)
            .ok_or(TurnDispatchError::ReservationRejected)?;
        if entry.state != ProviderState::Reserved
            || !core
                .verifier
                .reservation_matches_binding(&reservation, &entry.binding)
        {
            return Err(TurnDispatchError::ReservationReplayed);
        }
        let RegistryCore {
            entries, issuer, ..
        } = &mut *core;
        let entry = entries
            .get_mut(&key)
            .ok_or(TurnDispatchError::StateConflict)?;
        let confirmed = issuer.confirm_admission(&mut entry.binding, &receipt)?;
        entry.state = ProviderState::Queued;
        Ok(confirmed)
    }

    fn abort_non_admitted(
        &self,
        reservation: &QueuedTurnReservation,
        receipt: &MailboxRemovalReceipt,
    ) -> Result<(), TurnDispatchError> {
        let mut core = self
            .try_lock()
            .map_err(|_| TurnDispatchError::RecoveryJournalUnavailable)?;
        let claims = core
            .verifier
            .reservation_claims(&reservation)
            .ok_or(TurnDispatchError::ReservationRejected)?;
        core.verifier
            .verify_removal(&receipt)
            .map_err(|_| TurnDispatchError::ReceiptRejected)?;
        if !core.verifier.removal_matches(
            &receipt,
            &claims,
            MailboxRemovalDisposition::NeverAdmitted,
        ) {
            return Err(TurnDispatchError::ReceiptRejected);
        }
        let key = core
            .find_entry_key(&claims)
            .ok_or(TurnDispatchError::ReservationReplayed)?;
        let Some(entry) = core.entries.get(&key) else {
            return Err(TurnDispatchError::ReservationReplayed);
        };
        if entry.state != ProviderState::Reserved
            || !core
                .verifier
                .reservation_matches_binding(&reservation, &entry.binding)
        {
            return Err(TurnDispatchError::ReservationReplayed);
        }
        retire_unbound_for_dispatch(&mut core, &key)?;
        core.entries.remove(&key);
        Ok(())
    }

    fn abort_confirmed_admission(
        &self,
        cleanup: &ConfirmedAdmissionCleanupToken,
        receipt: &MailboxRemovalReceipt,
    ) -> Result<(), TurnDispatchError> {
        let mut core = self
            .try_lock()
            .map_err(|_| TurnDispatchError::RecoveryJournalUnavailable)?;
        let claims = core
            .verifier
            .confirmed_cleanup_claims(&cleanup)
            .ok_or(TurnDispatchError::CleanupTokenRejected)?;
        core.verifier
            .verify_removal(&receipt)
            .map_err(|_| TurnDispatchError::ReceiptRejected)?;
        if !core.verifier.removal_matches(
            &receipt,
            &claims,
            MailboxRemovalDisposition::RemovedBeforeDequeue,
        ) {
            return Err(TurnDispatchError::ReceiptRejected);
        }
        let key = core
            .find_entry_key(&claims)
            .ok_or(TurnDispatchError::CleanupTokenReplayed)?;
        let entry = core
            .entries
            .get(&key)
            .ok_or(TurnDispatchError::CleanupTokenReplayed)?;
        if entry.state != ProviderState::Queued
            || !core
                .verifier
                .confirmed_cleanup_matches_binding(&cleanup, &entry.binding)
        {
            return Err(TurnDispatchError::CleanupTokenReplayed);
        }
        retire_unbound_for_dispatch(&mut core, &key)?;
        core.entries.remove(&key);
        Ok(())
    }

    fn batch_detach(
        &self,
        session_id: &SessionId,
        turns: &[RegisteredTurnHandle],
    ) -> Result<DetachBatchOutcome, TurnDispatchError> {
        if turns.is_empty() {
            return Err(TurnDispatchError::BatchInvalid);
        }
        let mut core = self
            .try_lock()
            .map_err(|_| TurnDispatchError::RecoveryJournalUnavailable)?;
        let mut seen = HashSet::with_capacity(turns.len());
        let mut validated = Vec::with_capacity(turns.len());
        for handle in turns {
            let claims = core
                .verifier
                .registered_claims(handle)
                .ok_or(TurnDispatchError::BatchInvalid)?;
            if !seen.insert(claims.correlation_digest()) {
                return Err(TurnDispatchError::BatchInvalid);
            }
            let key = core
                .find_entry_key(&claims)
                .ok_or(TurnDispatchError::BatchInvalid)?;
            let entry = core
                .entries
                .get(&key)
                .ok_or(TurnDispatchError::BatchInvalid)?;
            if &entry.spec.session_id != session_id
                || !core
                    .verifier
                    .registered_matches_binding(handle, &entry.binding)
                || !matches!(
                    entry.state,
                    ProviderState::Queued
                        | ProviderState::DequeuedPendingStart { .. }
                        | ProviderState::Running { .. }
                        | ProviderState::FinishedNoReply { .. }
                )
            {
                return Err(TurnDispatchError::BatchInvalid);
            }
            // A reply that has already been consumed belongs to a completed
            // slot (the AnyOf winner, or one of the completed AllOf slots),
            // not to the unresolved loser set.  PreparedTurnBatch retains all
            // registration handles until its terminal cleanup, so the provider
            // must preserve consumed turns while atomically detaching only the
            // unresolved entries in the batch.
            if matches!(entry.reply, ReplyState::Consumed { .. }) {
                continue;
            }
            core.issuer
                .validate_detach(&entry.binding, entry.state == ProviderState::Queued)?;
            validated.push(key);
        }
        let mut queued_tokens = Vec::new();
        let RegistryCore {
            entries,
            issuer,
            verifier,
        } = &mut *core;
        for key in validated {
            let entry = entries.get_mut(&key).expect("validated entry exists");
            let (from, execution_finished, proof_digest) = match entry.state {
                ProviderState::Queued => (DetachOrigin::Queued, false, None),
                ProviderState::DequeuedPendingStart { .. } => {
                    (DetachOrigin::DequeuedPendingStart, true, None)
                }
                ProviderState::Running {
                    execution_finished,
                    proof_digest,
                } => (DetachOrigin::Running, execution_finished, proof_digest),
                ProviderState::FinishedNoReply { proof_digest } => {
                    (DetachOrigin::FinishedNoReply, true, Some(proof_digest))
                }
                _ => return Err(TurnDispatchError::StateConflict),
            };
            let cleanup =
                issuer.advance_detach(&mut entry.binding, from == DetachOrigin::Queued)?;
            let queued_cleanup_digest = cleanup.as_ref().map(|token| {
                verifier
                    .queued_cleanup_claims(token)
                    .expect("issuer and verifier share authority")
                    .correlation_digest()
            });
            if let Some(token) = cleanup {
                queued_tokens.push(token);
            }
            entry.state = ProviderState::Detached {
                from,
                execution_finished,
                proof_digest,
                queued_cleanup_digest,
            };
        }
        Ok(issuer.assemble_detach_outcome(queued_tokens))
    }

    fn recover_abandoned_claims(&self) -> Result<ReplyRecoverySummary, TurnDispatchError> {
        let mut core = self
            .try_lock()
            .map_err(|_| TurnDispatchError::RecoveryJournalUnavailable)?;
        Ok(recover_pending_locked(&mut core))
    }
}

impl TurnExecutionLifecyclePort for TurnAttributionRegistry {
    fn start_turn(
        &self,
        dequeued: &DequeuedTurnHandle,
    ) -> Result<TurnStartOutcome, TurnExecutionError> {
        let mut core = self
            .try_lock()
            .map_err(|_| TurnExecutionError::RecoveryJournalUnavailable)?;
        let claims = core
            .verifier
            .dequeued_claims(&dequeued)
            .ok_or(TurnExecutionError::ProofRejected)?;
        let key = core
            .find_entry_key(&claims)
            .ok_or(TurnExecutionError::NonCallable)?;
        let state = core
            .entries
            .get(&key)
            .map(|entry| entry.state)
            .ok_or(TurnExecutionError::NonCallable)?;
        match state {
            ProviderState::DequeuedPendingStart {
                receipt_digest,
                handoff_complete: true,
            } if core
                .verifier
                .verified_context_matches(&claims, receipt_digest) =>
            {
                let entry = core.entries.get_mut(&key).expect("entry exists");
                entry.state = ProviderState::Running {
                    execution_finished: false,
                    proof_digest: None,
                };
                Ok(TurnStartOutcome::Execute)
            }
            ProviderState::Detached {
                from: DetachOrigin::DequeuedPendingStart,
                ..
            } => {
                retire_unbound_for_execution(&mut core, &key)?;
                core.entries.remove(&key);
                Ok(TurnStartOutcome::DoNotExecute)
            }
            _ => Err(TurnExecutionError::NonCallable),
        }
    }

    fn abandon_before_start(
        &self,
        dequeued: &DequeuedTurnHandle,
    ) -> Result<(), TurnExecutionError> {
        let mut core = self
            .try_lock()
            .map_err(|_| TurnExecutionError::RecoveryJournalUnavailable)?;
        let claims = core
            .verifier
            .dequeued_claims(&dequeued)
            .ok_or(TurnExecutionError::ProofRejected)?;
        let key = core
            .find_entry_key(&claims)
            .ok_or(TurnExecutionError::ProofReplayed)?;
        let state = core.entries.get(&key).map(|entry| entry.state);
        if !matches!(
            state,
            Some(ProviderState::DequeuedPendingStart { .. })
                | Some(ProviderState::Detached {
                    from: DetachOrigin::DequeuedPendingStart,
                    ..
                })
        ) {
            return Err(TurnExecutionError::NonCallable);
        }
        retire_unbound_for_execution(&mut core, &key)?;
        core.entries.remove(&key);
        Ok(())
    }

    fn finish_turn(
        &self,
        proof: StoreQuiescenceProof,
    ) -> Result<TurnFinishResult, TurnExecutionError> {
        let mut core = self
            .try_lock()
            .map_err(|_| TurnExecutionError::RecoveryJournalUnavailable)?;
        core.verifier.verify_store(&proof)?;
        let claims = core
            .verifier
            .store_proof_claims(&proof)
            .ok_or(TurnExecutionError::ProofRejected)?;
        let key = find_entry_key_by_identity(&core.entries, &claims)
            .ok_or(TurnExecutionError::NonCallable)?;
        let proof_digest = claims.correlation_digest();
        let (state, reply, late, completion_owner) = {
            let entry = core
                .entries
                .get(&key)
                .ok_or(TurnExecutionError::NonCallable)?;
            (
                entry.state,
                entry.reply,
                entry.late,
                entry.spec.completion_owner.clone(),
            )
        };
        if !matches!(
            state,
            ProviderState::Running {
                execution_finished: false,
                ..
            } | ProviderState::Detached {
                execution_finished: false,
                ..
            }
        ) {
            return Err(match state {
                ProviderState::Running {
                    execution_finished: true,
                    ..
                }
                | ProviderState::Detached {
                    execution_finished: true,
                    ..
                } => TurnExecutionError::ProofReplayed,
                _ => TurnExecutionError::NonCallable,
            });
        }
        let source_quiesced = {
            let RegistryCore {
                entries, issuer, ..
            } = &mut *core;
            let entry = entries.get(&key).ok_or(TurnExecutionError::NonCallable)?;
            issuer.commit_store_quiescence(&entry.binding, &proof)?
        };
        match state {
            ProviderState::Running {
                execution_finished: false,
                ..
            } => match reply {
                ReplyState::Open if completion_owner == TurnCompletionOwner::ExecutionBoundary => {
                    core.entries.remove(&key);
                    Ok(TurnFinishResult::from_provider(
                        TurnFinishOutcome::Removed,
                        source_quiesced,
                    ))
                }
                ReplyState::Open => {
                    core.entries.get_mut(&key).expect("entry exists").state =
                        ProviderState::FinishedNoReply { proof_digest };
                    Ok(TurnFinishResult::from_provider(
                        TurnFinishOutcome::FinishedNoReply,
                        source_quiesced,
                    ))
                }
                ReplyState::Consumed { .. } => {
                    core.entries.remove(&key);
                    Ok(TurnFinishResult::from_provider(
                        TurnFinishOutcome::Removed,
                        source_quiesced,
                    ))
                }
                ReplyState::Claimed { .. } | ReplyState::RecoveryPending { .. } => {
                    core.entries.get_mut(&key).expect("entry exists").state =
                        ProviderState::Running {
                            execution_finished: true,
                            proof_digest: Some(proof_digest),
                        };
                    Ok(TurnFinishResult::from_provider(
                        TurnFinishOutcome::FinishedNoReply,
                        source_quiesced,
                    ))
                }
            },
            ProviderState::Detached {
                from,
                execution_finished: false,
                queued_cleanup_digest,
                ..
            } => {
                let retain = matches!(
                    reply,
                    ReplyState::Claimed { .. } | ReplyState::RecoveryPending { .. }
                ) || matches!(late, LateState::Claimed { .. });
                if retain {
                    core.entries.get_mut(&key).expect("entry exists").state =
                        ProviderState::Detached {
                            from,
                            execution_finished: true,
                            proof_digest: Some(proof_digest),
                            queued_cleanup_digest,
                        };
                    Ok(TurnFinishResult::from_provider(
                        TurnFinishOutcome::DetachedRetained,
                        source_quiesced,
                    ))
                } else {
                    core.entries.remove(&key);
                    Ok(TurnFinishResult::from_provider(
                        TurnFinishOutcome::DetachedRemoved,
                        source_quiesced,
                    ))
                }
            }
            _ => Err(TurnExecutionError::NonCallable),
        }
    }
}

impl TurnReplyRoutingPort for TurnAttributionRegistry {
    fn classify_send(
        &self,
        turn_id: &str,
        expected_agent: &str,
        destination: &str,
    ) -> SendTurnClassification {
        let Ok(core) = self.try_lock() else {
            return SendTurnClassification::IdentityMismatch;
        };
        let Some(entry) = core.entries.get(turn_id) else {
            return SendTurnClassification::Untracked;
        };
        if entry.spec.expected_agent != expected_agent {
            return SendTurnClassification::IdentityMismatch;
        }
        match entry.state {
            ProviderState::Reserved
            | ProviderState::Queued
            | ProviderState::DequeuedPendingStart { .. } => {
                SendTurnClassification::NonCallable(NonCallableTurnPhase::Queued)
            }
            // ExecutionBoundary owns completion, not guest messaging. Once its
            // Store turn is Running it is deliberately outside the await-parent
            // reply route, so an ordinary `messaging.send` must follow the
            // untracked delivery path. `claim_active_reply` remains defensive
            // and rejects this owner if a caller attempts to bypass classification.
            ProviderState::Running { .. }
                if entry.spec.completion_owner == TurnCompletionOwner::ExecutionBoundary =>
            {
                SendTurnClassification::Untracked
            }
            ProviderState::Running { .. } if destination == entry.spec.parent_agent => {
                SendTurnClassification::ActiveParent
            }
            ProviderState::Running { .. } => SendTurnClassification::Untracked,
            ProviderState::FinishedNoReply { .. } => {
                SendTurnClassification::NonCallable(NonCallableTurnPhase::FinishedNoReply)
            }
            ProviderState::Detached { .. } if destination == entry.spec.parent_agent => {
                SendTurnClassification::DetachedParent
            }
            ProviderState::Detached { .. } => SendTurnClassification::DetachedUnrelated,
        }
    }

    fn claim_active_reply(
        &self,
        turn_id: &str,
        expected_agent: &str,
        destination: &str,
    ) -> Result<ReplyRouteClaim, TurnReplyError> {
        let mut core = self.try_lock().map_err(|_| TurnReplyError::StateConflict)?;
        let entry = core
            .entries
            .get(turn_id)
            .ok_or(TurnReplyError::NonCallable)?;
        if entry.spec.expected_agent != expected_agent {
            return Err(TurnReplyError::IdentityMismatch);
        }
        if entry.spec.completion_owner == TurnCompletionOwner::ExecutionBoundary {
            return Err(TurnReplyError::NonCallable);
        }
        if entry.spec.parent_agent != destination {
            return Err(TurnReplyError::StateConflict);
        }
        if matches!(entry.state, ProviderState::Detached { .. }) {
            return claim_detached_locked(&mut core, turn_id).map(|claim| match claim {
                LateReplyClaim::Claimed(token) => ReplyRouteClaim::DetachedLate(token),
                LateReplyClaim::AlreadyHandled => ReplyRouteClaim::AlreadyHandled,
            });
        }
        if !matches!(entry.state, ProviderState::Running { .. }) {
            return Err(TurnReplyError::NonCallable);
        }
        match entry.reply {
            ReplyState::Open => {}
            ReplyState::Claimed { .. } => return Err(TurnReplyError::InProgress),
            ReplyState::RecoveryPending { .. } => return Err(TurnReplyError::RecoveryPending),
            ReplyState::Consumed { .. } => return Ok(ReplyRouteClaim::AlreadyHandled),
        }
        let route = {
            let entry = core.entries.get(turn_id).expect("entry exists");
            ExactReplyRoute {
                parent_agent: entry.spec.parent_agent.clone(),
                session_id: entry.spec.session_id.clone(),
                slot: entry.spec.slot,
            }
        };
        let token = {
            let RegistryCore {
                entries, issuer, ..
            } = &mut *core;
            let entry = entries.get(turn_id).expect("entry exists");
            issuer.claim_active(&entry.binding)
        };
        let digest = core
            .verifier
            .active_claim_claims(&token)
            .ok_or(TurnReplyError::TokenRejected)?
            .correlation_digest();
        core.entries.get_mut(turn_id).expect("entry exists").reply = ReplyState::Claimed {
            token_digest: digest,
            phase: ClaimPhase::Claimed,
            marker: None,
        };
        Ok(ReplyRouteClaim::Active(
            core.issuer.assemble_claimed_active_reply(route, token),
        ))
    }

    fn begin_reply_delivery(&self, token: &ActiveReplyClaimToken) -> Result<(), TurnReplyError> {
        let mut core = self.try_lock().map_err(|_| TurnReplyError::StateConflict)?;
        let claims = core
            .verifier
            .active_claim_claims(token)
            .ok_or(TurnReplyError::TokenRejected)?;
        let key = core
            .find_entry_key(&claims)
            .ok_or(TurnReplyError::StaleClaim)?;
        let digest = claims.correlation_digest();
        let entry = core
            .entries
            .get_mut(&key)
            .ok_or(TurnReplyError::StaleClaim)?;
        match &mut entry.reply {
            ReplyState::Claimed {
                token_digest,
                phase,
                ..
            } if *token_digest == digest && *phase == ClaimPhase::Claimed => {
                *phase = ClaimPhase::DeliveryStarted;
                Ok(())
            }
            ReplyState::Claimed { .. } => Err(TurnReplyError::InProgress),
            ReplyState::RecoveryPending { .. } => Err(TurnReplyError::RecoveryPending),
            ReplyState::Consumed { .. } => Err(TurnReplyError::TokenReplayed),
            ReplyState::Open => Err(TurnReplyError::StaleClaim),
        }
    }

    fn settle_reply_accepted(
        &self,
        token: &ActiveReplyClaimToken,
    ) -> Result<ReplySettlement, TurnReplyError> {
        let receipt = self.record_reply_accepted(token)?;
        self.complete_reply(token, receipt)
    }

    fn settle_reply_not_accepted(
        &self,
        token: &ActiveReplyClaimToken,
    ) -> Result<ReplySettlement, TurnReplyError> {
        let receipt = self.record_reply_not_accepted(token)?;
        self.abort_reply(token, ReplyAbortProof::DefinitelyNotAccepted(receipt))
    }

    fn complete_reply(
        &self,
        token: &ActiveReplyClaimToken,
        receipt: ReplyAcceptedReceipt,
    ) -> Result<ReplySettlement, TurnReplyError> {
        let mut core = self.try_lock().map_err(|_| TurnReplyError::StateConflict)?;
        let claims = core
            .verifier
            .active_claim_claims(&token)
            .ok_or(TurnReplyError::TokenRejected)?;
        let receipt_claims = core
            .verifier
            .reply_accepted_claims(&receipt)
            .ok_or(TurnReplyError::ReceiptRejected)?;
        if !core
            .verifier
            .same_verified_lineage(&claims, &receipt_claims)
            || !core
                .verifier
                .verified_context_matches(&receipt_claims, claims.correlation_digest())
        {
            return Err(TurnReplyError::ReceiptRejected);
        }
        let key = core
            .find_entry_key(&claims)
            .ok_or(TurnReplyError::StaleClaim)?;
        let token_digest = claims.correlation_digest();
        let receipt_digest = receipt_claims.correlation_digest();
        let (state, marker) = {
            let entry = core.entries.get(&key).ok_or(TurnReplyError::StaleClaim)?;
            let marker = match entry.reply {
                ReplyState::Claimed {
                    token_digest: expected,
                    phase: ClaimPhase::DeliveryStarted,
                    marker,
                } if expected == token_digest => marker,
                ReplyState::Consumed {
                    token_digest: expected,
                } if expected == token_digest => return Err(TurnReplyError::TokenReplayed),
                ReplyState::RecoveryPending { .. } => return Err(TurnReplyError::RecoveryPending),
                _ => return Err(TurnReplyError::InvalidSettlement),
            };
            (entry.state, marker)
        };
        if marker != Some(RecoveryMarker::Accepted(receipt_digest)) {
            return Err(TurnReplyError::ReceiptRejected);
        }
        core.entries.get_mut(&key).expect("entry exists").reply =
            ReplyState::Consumed { token_digest };
        match state {
            ProviderState::Detached { .. } => Ok(ReplySettlement::Detached),
            ProviderState::Running {
                execution_finished: true,
                ..
            } => {
                core.entries.remove(&key);
                Ok(ReplySettlement::Consumed)
            }
            ProviderState::Running { .. } => Ok(ReplySettlement::Consumed),
            _ => Err(TurnReplyError::InvalidSettlement),
        }
    }

    fn abort_reply(
        &self,
        token: &ActiveReplyClaimToken,
        proof: ReplyAbortProof,
    ) -> Result<ReplySettlement, TurnReplyError> {
        let mut core = self.try_lock().map_err(|_| TurnReplyError::StateConflict)?;
        let claims = core
            .verifier
            .active_claim_claims(&token)
            .ok_or(TurnReplyError::TokenRejected)?;
        let key = core
            .find_entry_key(&claims)
            .ok_or(TurnReplyError::StaleClaim)?;
        let token_digest = claims.correlation_digest();
        let (required_phase, required_marker) = match proof {
            ReplyAbortProof::BeforeDelivery => (ClaimPhase::Claimed, None),
            ReplyAbortProof::DefinitelyNotAccepted(receipt) => {
                let receipt_claims = core
                    .verifier
                    .reply_not_accepted_claims(&receipt)
                    .ok_or(TurnReplyError::ReceiptRejected)?;
                if !core
                    .verifier
                    .same_verified_lineage(&claims, &receipt_claims)
                    || !core
                        .verifier
                        .verified_context_matches(&receipt_claims, token_digest)
                {
                    return Err(TurnReplyError::ReceiptRejected);
                }
                (
                    ClaimPhase::DeliveryStarted,
                    Some(RecoveryMarker::NotAccepted(
                        receipt_claims.correlation_digest(),
                    )),
                )
            }
        };
        let (state, marker) = {
            let entry = core.entries.get(&key).ok_or(TurnReplyError::StaleClaim)?;
            match entry.reply {
                ReplyState::Claimed {
                    token_digest: expected,
                    phase,
                    marker,
                } if expected == token_digest && phase == required_phase => (entry.state, marker),
                ReplyState::Consumed {
                    token_digest: expected,
                } if expected == token_digest => return Err(TurnReplyError::TokenReplayed),
                ReplyState::RecoveryPending { .. } => return Err(TurnReplyError::RecoveryPending),
                _ => return Err(TurnReplyError::InvalidSettlement),
            }
        };
        if marker != required_marker {
            return Err(TurnReplyError::ReceiptRejected);
        }
        if matches!(state, ProviderState::Detached { .. }) {
            core.entries.get_mut(&key).expect("entry exists").reply =
                ReplyState::Consumed { token_digest };
            return Ok(ReplySettlement::Detached);
        }
        match state {
            ProviderState::Running {
                execution_finished: false,
                ..
            } => {
                core.entries.get_mut(&key).expect("entry exists").reply = ReplyState::Open;
                Ok(ReplySettlement::Reopened)
            }
            ProviderState::Running {
                execution_finished: true,
                proof_digest: Some(proof_digest),
            } => {
                let entry = core.entries.get_mut(&key).expect("entry exists");
                entry.reply = ReplyState::Open;
                entry.state = ProviderState::FinishedNoReply { proof_digest };
                Ok(ReplySettlement::FinishedNoReply)
            }
            _ => Err(TurnReplyError::InvalidSettlement),
        }
    }

    fn abandon_reply(&self, token: &ActiveReplyClaimToken) -> Result<(), TurnReplyError> {
        let mut core = self.try_lock().map_err(|_| TurnReplyError::StateConflict)?;
        let claims = core
            .verifier
            .active_claim_claims(token)
            .ok_or(TurnReplyError::TokenRejected)?;
        let key = core
            .find_entry_key(&claims)
            .ok_or(TurnReplyError::StaleClaim)?;
        let digest = claims.correlation_digest();
        let entry = core
            .entries
            .get_mut(&key)
            .ok_or(TurnReplyError::StaleClaim)?;
        match entry.reply {
            ReplyState::Claimed {
                token_digest,
                phase: ClaimPhase::DeliveryStarted,
                marker,
            } if token_digest == digest => {
                entry.reply = ReplyState::RecoveryPending {
                    token_digest,
                    marker,
                };
                Ok(())
            }
            ReplyState::Claimed { .. } => Err(TurnReplyError::InvalidSettlement),
            ReplyState::RecoveryPending { .. } => Err(TurnReplyError::RecoveryPending),
            ReplyState::Consumed { .. } => Err(TurnReplyError::TokenReplayed),
            ReplyState::Open => Err(TurnReplyError::StaleClaim),
        }
    }

    fn claim_reply_late(
        &self,
        turn_id: &str,
        expected_agent: &str,
        destination: &str,
    ) -> Result<LateReplyClaim, TurnReplyError> {
        let mut core = self.try_lock().map_err(|_| TurnReplyError::StateConflict)?;
        let entry = core
            .entries
            .get(turn_id)
            .ok_or(TurnReplyError::NonCallable)?;
        if entry.spec.expected_agent != expected_agent {
            return Err(TurnReplyError::IdentityMismatch);
        }
        if entry.spec.parent_agent != destination {
            return Err(TurnReplyError::StateConflict);
        }
        claim_detached_locked(&mut core, turn_id)
    }

    fn complete_reply_late(&self, token: LateReplyDispositionToken) -> Result<(), TurnReplyError> {
        let mut core = self.try_lock().map_err(|_| TurnReplyError::StateConflict)?;
        let claims = core
            .verifier
            .late_disposition_claims(&token)
            .ok_or(TurnReplyError::TokenRejected)?;
        let key = core
            .find_entry_key(&claims)
            .ok_or(TurnReplyError::StaleClaim)?;
        let digest = claims.correlation_digest();
        let entry = core
            .entries
            .get_mut(&key)
            .ok_or(TurnReplyError::StaleClaim)?;
        match entry.late {
            LateState::Claimed { token_digest } if token_digest == digest => {
                entry.late = LateState::Completed {
                    token_digest: digest,
                };
                if detached_can_cleanup(entry) {
                    core.entries.remove(&key);
                }
                Ok(())
            }
            LateState::Completed { token_digest } if token_digest == digest => {
                Err(TurnReplyError::TokenReplayed)
            }
            _ => Err(TurnReplyError::StaleClaim),
        }
    }
}

impl TurnMailboxLifecyclePort for TurnAttributionRegistry {
    fn record_dequeued(
        &self,
        receipt: &MailboxDequeueReceipt,
    ) -> Result<RecordedDequeueHandoff, TurnMailboxError> {
        let mut core = self.try_lock().map_err(|_| TurnMailboxError::Busy)?;
        core.verifier.verify_dequeue(receipt)?;
        let claims = core
            .verifier
            .dequeue_receipt_claims(receipt)
            .ok_or(TurnMailboxError::ReceiptRejected)?;
        let key = core
            .find_entry_key(&claims)
            .ok_or(TurnMailboxError::StateConflict)?;
        let entry = core
            .entries
            .get(&key)
            .ok_or(TurnMailboxError::StateConflict)?;
        if entry.state != ProviderState::Queued
            || !core
                .verifier
                .dequeue_matches_binding(receipt, &entry.binding)
        {
            return Err(TurnMailboxError::StateConflict);
        }
        let receipt_digest = claims.correlation_digest();
        let recorded = {
            let RegistryCore {
                entries, issuer, ..
            } = &mut *core;
            let entry = entries.get(&key).ok_or(TurnMailboxError::StateConflict)?;
            issuer.record_dequeue(&entry.binding, receipt)?
        };
        core.entries.get_mut(&key).expect("entry exists").state =
            ProviderState::DequeuedPendingStart {
                receipt_digest,
                handoff_complete: false,
            };
        Ok(recorded)
    }

    fn complete_dequeue_handoff(
        &self,
        receipt: &MailboxDequeueReceipt,
        recorded: &RecordedDequeueHandoff,
    ) -> Result<DequeuedTurnHandle, TurnMailboxError> {
        let mut core = self.try_lock().map_err(|_| TurnMailboxError::Busy)?;
        core.verifier.verify_dequeue(&receipt)?;
        let receipt_claims = core
            .verifier
            .dequeue_receipt_claims(&receipt)
            .ok_or(TurnMailboxError::ReceiptRejected)?;
        let recorded_claims = core
            .verifier
            .recorded_dequeue_claims(&recorded)
            .ok_or(TurnMailboxError::TokenRejected)?;
        if !core
            .verifier
            .same_verified_lineage(&receipt_claims, &recorded_claims)
            || !core
                .verifier
                .verified_context_matches(&recorded_claims, receipt_claims.correlation_digest())
        {
            return Err(TurnMailboxError::TokenRejected);
        }
        let key = core
            .find_entry_key(&receipt_claims)
            .ok_or(TurnMailboxError::StateConflict)?;
        let entry = core
            .entries
            .get(&key)
            .ok_or(TurnMailboxError::StateConflict)?;
        if entry.state
            != (ProviderState::DequeuedPendingStart {
                receipt_digest: receipt_claims.correlation_digest(),
                handoff_complete: false,
            })
        {
            return Err(TurnMailboxError::Replayed);
        }
        let dequeued = {
            let RegistryCore {
                entries, issuer, ..
            } = &mut *core;
            let entry = entries.get(&key).ok_or(TurnMailboxError::StateConflict)?;
            issuer.complete_dequeue(&entry.binding, &receipt, &recorded)?
        };
        core.entries.get_mut(&key).expect("entry exists").state =
            ProviderState::DequeuedPendingStart {
                receipt_digest: receipt_claims.correlation_digest(),
                handoff_complete: true,
            };
        Ok(dequeued)
    }

    fn abandon_dequeuing(&self, receipt: &MailboxDequeueReceipt) -> Result<(), TurnMailboxError> {
        let mut core = self.try_lock().map_err(|_| TurnMailboxError::Busy)?;
        core.verifier.verify_dequeue(&receipt)?;
        let claims = core
            .verifier
            .dequeue_receipt_claims(&receipt)
            .ok_or(TurnMailboxError::ReceiptRejected)?;
        let key = core
            .find_entry_key(&claims)
            .ok_or(TurnMailboxError::Replayed)?;
        let receipt_digest = claims.correlation_digest();
        let state = core.entries.get(&key).map(|entry| entry.state);
        let valid = match state {
            Some(ProviderState::Queued) => true,
            Some(ProviderState::DequeuedPendingStart {
                receipt_digest: expected,
                ..
            }) => expected == receipt_digest,
            Some(ProviderState::Detached {
                from: DetachOrigin::DequeuedPendingStart,
                ..
            }) => true,
            _ => false,
        };
        if !valid {
            return Err(TurnMailboxError::StateConflict);
        }
        retire_unbound_for_mailbox(&mut core, &key)?;
        core.entries.remove(&key);
        Ok(())
    }

    fn settle_removed_queued(
        &self,
        cleanup: &QueuedDetachCleanupToken,
        receipt: &MailboxRemovalReceipt,
    ) -> Result<(), TurnMailboxError> {
        let mut core = self.try_lock().map_err(|_| TurnMailboxError::Busy)?;
        let claims = core
            .verifier
            .queued_cleanup_claims(&cleanup)
            .ok_or(TurnMailboxError::TokenRejected)?;
        core.verifier.verify_removal(&receipt)?;
        if !core.verifier.removal_matches(
            &receipt,
            &claims,
            MailboxRemovalDisposition::RemovedBeforeDequeue,
        ) {
            return Err(TurnMailboxError::ReceiptRejected);
        }
        let key = core
            .find_entry_key(&claims)
            .ok_or(TurnMailboxError::Replayed)?;
        let entry = core.entries.get(&key).ok_or(TurnMailboxError::Replayed)?;
        if !core
            .verifier
            .queued_cleanup_matches_binding(&cleanup, &entry.binding)
        {
            return Err(TurnMailboxError::TokenRejected);
        }
        match entry.state {
            ProviderState::Detached {
                from: DetachOrigin::Queued,
                queued_cleanup_digest: Some(expected),
                ..
            } if expected == claims.correlation_digest() => {
                retire_unbound_for_mailbox(&mut core, &key)?;
                core.entries.remove(&key);
                Ok(())
            }
            _ => Err(TurnMailboxError::StateConflict),
        }
    }
}

impl TurnCostAttributionReadPort for TurnAttributionRegistry {
    fn cost_attribution(&self, turn_id: &str, expected_agent: &str) -> CostAttributionLookup {
        let Ok(core) = self.try_lock() else {
            return CostAttributionLookup::IdentityMismatch;
        };
        let Some(entry) = core.entries.get(turn_id) else {
            return CostAttributionLookup::Untracked;
        };
        if entry.spec.expected_agent != expected_agent {
            return CostAttributionLookup::IdentityMismatch;
        }
        let state = match entry.state {
            ProviderState::Reserved
            | ProviderState::Queued
            | ProviderState::DequeuedPendingStart { .. } => {
                CostTurnState::NonCallable(NonCallableTurnPhase::Queued)
            }
            ProviderState::Running { .. } => CostTurnState::Active,
            ProviderState::FinishedNoReply { .. } => {
                CostTurnState::NonCallable(NonCallableTurnPhase::FinishedNoReply)
            }
            ProviderState::Detached {
                from,
                execution_finished,
                ..
            } => CostTurnState::Detached {
                from,
                execution_finished,
            },
        };
        CostAttributionLookup::Tracked(CostAttributionSnapshot {
            original_task_id: entry.spec.original_task_id.clone(),
            original_run_id: entry.spec.original_run_id.clone(),
            state,
        })
    }
}

fn claim_detached_locked(
    core: &mut RegistryCore,
    turn_id: &str,
) -> Result<LateReplyClaim, TurnReplyError> {
    let entry = core
        .entries
        .get(turn_id)
        .ok_or(TurnReplyError::NonCallable)?;
    if !matches!(entry.state, ProviderState::Detached { .. }) {
        return Err(TurnReplyError::NonCallable);
    }
    match entry.reply {
        ReplyState::Claimed { .. } => return Err(TurnReplyError::InProgress),
        ReplyState::RecoveryPending { .. } => return Err(TurnReplyError::RecoveryPending),
        ReplyState::Open | ReplyState::Consumed { .. } => {}
    }
    match entry.late {
        LateState::Open => {}
        LateState::Claimed { .. } | LateState::Completed { .. } => {
            return Ok(LateReplyClaim::AlreadyHandled)
        }
    }
    let token = {
        let RegistryCore {
            entries, issuer, ..
        } = core;
        let entry = entries.get(turn_id).expect("entry exists");
        issuer.claim_late(&entry.binding)
    };
    let digest = core
        .verifier
        .late_disposition_claims(&token)
        .ok_or(TurnReplyError::TokenRejected)?
        .correlation_digest();
    core.entries.get_mut(turn_id).expect("entry exists").late = LateState::Claimed {
        token_digest: digest,
    };
    Ok(LateReplyClaim::Claimed(token))
}

fn recover_pending_locked(core: &mut RegistryCore) -> ReplyRecoverySummary {
    let mut summary = ReplyRecoverySummary::default();
    let keys: Vec<String> = core.entries.keys().cloned().collect();
    for key in keys {
        let Some(entry) = core.entries.get_mut(&key) else {
            continue;
        };
        let ReplyState::RecoveryPending {
            token_digest,
            marker,
        } = entry.reply
        else {
            continue;
        };
        match marker {
            Some(RecoveryMarker::Accepted(_)) => {
                entry.reply = ReplyState::Consumed { token_digest };
                if matches!(entry.state, ProviderState::Detached { .. }) {
                    summary.recovered_detached += 1;
                } else {
                    summary.recovered_accepted += 1;
                }
            }
            Some(RecoveryMarker::NotAccepted(_)) => {
                if matches!(entry.state, ProviderState::Detached { .. }) {
                    entry.reply = ReplyState::Consumed { token_digest };
                    summary.recovered_detached += 1;
                } else if let ProviderState::Running {
                    execution_finished: true,
                    proof_digest: Some(proof_digest),
                } = entry.state
                {
                    entry.reply = ReplyState::Open;
                    entry.state = ProviderState::FinishedNoReply { proof_digest };
                    summary.recovered_not_accepted += 1;
                } else {
                    entry.reply = ReplyState::Open;
                    summary.recovered_not_accepted += 1;
                }
            }
            Some(RecoveryMarker::Terminal) => {
                entry.reply = ReplyState::Consumed { token_digest };
                summary.recovered_detached +=
                    usize::from(matches!(entry.state, ProviderState::Detached { .. }));
            }
            None => summary.pending += 1,
        }
    }
    summary
}

fn detached_can_cleanup(entry: &TurnEntry) -> bool {
    matches!(
        entry.state,
        ProviderState::Detached {
            execution_finished: true,
            ..
        }
    ) && !matches!(
        entry.reply,
        ReplyState::Claimed { .. } | ReplyState::RecoveryPending { .. }
    )
}

fn retire_unbound_for_dispatch(
    core: &mut RegistryCore,
    key: &str,
) -> Result<(), TurnDispatchError> {
    let RegistryCore {
        entries, issuer, ..
    } = core;
    let entry = entries.get(key).ok_or(TurnDispatchError::StateConflict)?;
    issuer.retire_unbound_source(&entry.binding)
}

fn retire_unbound_for_execution(
    core: &mut RegistryCore,
    key: &str,
) -> Result<(), TurnExecutionError> {
    retire_unbound_for_dispatch(core, key).map_err(|error| match error {
        TurnDispatchError::RecoveryCapacityExhausted | TurnDispatchError::CapacityExhausted => {
            TurnExecutionError::RecoveryCapacityExhausted
        }
        TurnDispatchError::RecoveryJournalUnavailable | TurnDispatchError::AnchorUnavailable => {
            TurnExecutionError::RecoveryJournalUnavailable
        }
        TurnDispatchError::AnchorConflict | TurnDispatchError::RollbackDetected => {
            TurnExecutionError::RollbackDetected
        }
        _ => TurnExecutionError::StateConflict,
    })
}

fn retire_unbound_for_mailbox(core: &mut RegistryCore, key: &str) -> Result<(), TurnMailboxError> {
    retire_unbound_for_dispatch(core, key).map_err(|error| match error {
        TurnDispatchError::RecoveryJournalUnavailable | TurnDispatchError::AnchorUnavailable => {
            TurnMailboxError::Busy
        }
        _ => TurnMailboxError::StateConflict,
    })
}

fn find_entry_key_by_identity(
    entries: &HashMap<String, TurnEntry>,
    claims: &VerifiedTurnCredential,
) -> Option<String> {
    entries
        .iter()
        .find(|(_, entry)| claims.matches_identity(&entry.spec.turn_id, &entry.spec.expected_agent))
        .map(|(key, _)| key.clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use advance_shared_types::progress_lifecycle_recovery::{
        ProgressLifecycleRecoveryJournal, RecoveryJournalConfig,
    };
    use std::num::{NonZeroU32, NonZeroUsize};
    use tempfile::TempDir;
    use zeroize::Zeroizing;

    struct Rig {
        _journal_root: TempDir,
        registry: TurnAttributionRegistry,
        admission: MailboxAdmissionIssuer,
        removal: MailboxRemovalIssuer,
        dequeue: MailboxDequeueIssuer,
        publish: MailboxPublishVerifier,
        store: StoreQuiescenceIssuer,
    }

    struct Confirmed {
        registered: RegisteredTurnHandle,
        publish: MailboxPublishPermit,
        rollback: ConfirmedAdmissionCleanupToken,
        admission: MailboxAdmissionReceipt,
        facts: MailboxEntryFacts,
    }

    fn rig(max_entries: usize) -> Rig {
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
        let (turn_recovery, _progress_recovery) = journal.split_at_composition();
        let parts = TurnAttributionAuthorityFactory::new_at_composition(
            &mut rand::rngs::OsRng,
            turn_recovery,
        )
        .expect("authority factory should initialize");
        let TurnAttributionAuthorityParts {
            activation_staging: _,
            registry_issuer,
            mailbox_admission_issuer,
            mailbox_removal_issuer,
            mailbox_dequeue_issuer,
            mailbox_publish_verifier,
            store_quiescence_issuer,
            source_quiescence_recovery_issuer: _,
            source_quiescence_verifier: _,
            verifier,
        } = parts;
        Rig {
            _journal_root: journal_root,
            registry: TurnAttributionRegistry::new(max_entries, registry_issuer, verifier)
                .expect("valid capacity"),
            admission: mailbox_admission_issuer,
            removal: mailbox_removal_issuer,
            dequeue: mailbox_dequeue_issuer,
            publish: mailbox_publish_verifier,
            store: store_quiescence_issuer,
        }
    }

    fn spec(turn_id: &str, session: &str) -> QueuedTurnSpec {
        QueuedTurnSpec {
            turn_id: turn_id.into(),
            expected_agent: "agent:child".into(),
            parent_agent: "agent:parent".into(),
            session_id: SessionId(session.into()),
            slot: 0,
            completion_owner: TurnCompletionOwner::AwaitSession,
            original_task_id: Some("task-original".into()),
            original_run_id: Some("run-original".into()),
            original_reply_to: Some("agent:parent".into()),
        }
    }

    fn facts(turn_id: &str, discriminator: u8) -> MailboxEntryFacts {
        MailboxEntryFacts {
            turn_id: turn_id.into(),
            expected_agent: "agent:child".into(),
            message_id: turn_id.into(),
            mailbox_incarnation: [discriminator; 16],
            staged_entry_id: [discriminator.wrapping_add(1); 16],
        }
    }

    fn confirm(rig: &mut Rig, turn_id: &str, session: &str, discriminator: u8) -> Confirmed {
        let reservation = rig
            .registry
            .reserve_queued(spec(turn_id, session))
            .expect("reservation");
        let facts = facts(turn_id, discriminator);
        let admission = rig
            .admission
            .seal_staged_admission(&reservation, &facts)
            .expect("staged admission");
        let retained_admission = rig
            .admission
            .duplicate_for_mailbox_owner(&admission)
            .expect("owner can retain exact receipt");
        let confirmed = rig
            .registry
            .confirm_mailbox_admission(&reservation, &admission)
            .expect("confirm");
        let (registered, publish, rollback) = confirmed.into_parts();
        Confirmed {
            registered,
            publish,
            rollback,
            admission: retained_admission,
            facts,
        }
    }

    fn start_running(rig: &mut Rig, confirmed: Confirmed) -> RegisteredTurnHandle {
        let published = rig
            .publish
            .verify_publish(confirmed.publish, &confirmed.admission, &confirmed.facts)
            .expect("publish verification");
        let prepared = rig
            .dequeue
            .prepare_visible_dequeue(&published, &confirmed.facts, [0xA5; 32])
            .expect("prepare exact dequeue");
        let receipt = prepared.commit_exact_take();
        let recorded = rig
            .registry
            .record_dequeued(&receipt)
            .expect("record dequeue");
        let handle = rig
            .registry
            .complete_dequeue_handoff(&receipt, &recorded)
            .expect("same-lineage handoff");
        assert_eq!(
            rig.registry.start_turn(&handle).expect("start"),
            TurnStartOutcome::Execute
        );
        confirmed.registered
    }

    fn finish_proof(rig: &mut Rig, turn_id: &str) -> StoreQuiescenceProof {
        rig.store
            .issue_drained(
                &StoreQuiescenceFacts {
                    turn_id: turn_id.into(),
                    expected_agent: "agent:child".into(),
                    store_incarnation: [0x71; 16],
                },
                9,
            )
            .expect("store proof")
    }

    #[test]
    fn active_claim_exact_settlement_and_finish() {
        let mut rig = rig(8);
        let confirmed = confirm(&mut rig, "turn-active", "session-a", 1);
        let registered = start_running(&mut rig, confirmed);
        assert!(matches!(
            rig.registry.cost_attribution("turn-active", "agent:child"),
            CostAttributionLookup::Tracked(CostAttributionSnapshot {
                state: CostTurnState::Active,
                ..
            })
        ));
        assert_eq!(
            rig.registry.cost_attribution("turn-active", "agent:wrong"),
            CostAttributionLookup::IdentityMismatch
        );

        let claim = rig
            .registry
            .claim_active_reply("turn-active", "agent:child", "agent:parent")
            .expect("claim");
        let ReplyRouteClaim::Active(claimed) = claim else {
            panic!("expected active claim")
        };
        assert_eq!(claimed.route().session_id, SessionId("session-a".into()));
        let (_, token) = claimed.into_parts();
        rig.registry
            .begin_reply_delivery(&token)
            .expect("begin delivery");
        let accepted = rig
            .registry
            .record_reply_accepted(&token)
            .expect("accepted marker");
        assert_eq!(
            rig.registry
                .complete_reply(&token, accepted)
                .expect("complete exact claim"),
            ReplySettlement::Consumed
        );
        let proof = finish_proof(&mut rig, "turn-active");
        assert_eq!(
            rig.registry.finish_turn(proof).expect("finish").outcome,
            TurnFinishOutcome::Removed
        );
        assert_eq!(rig.registry.entry_count(), 0);
        assert_eq!(
            rig.registry.cost_attribution("turn-active", "agent:child"),
            CostAttributionLookup::Untracked
        );
        drop(registered);
    }

    #[test]
    fn detach_freezes_owned_snapshot_and_late_disposes_once() {
        let mut rig = rig(8);
        let confirmed = confirm(&mut rig, "turn-detach", "session-d", 2);
        let registered = start_running(&mut rig, confirmed);
        let frozen = rig.registry.cost_attribution("turn-detach", "agent:child");
        rig.registry
            .batch_detach(&SessionId("session-d".into()), &[registered])
            .expect("detach exact handle");

        assert!(matches!(
            frozen,
            CostAttributionLookup::Tracked(CostAttributionSnapshot {
                state: CostTurnState::Active,
                ..
            })
        ));
        assert!(matches!(
            rig.registry.cost_attribution("turn-detach", "agent:child"),
            CostAttributionLookup::Tracked(CostAttributionSnapshot {
                state: CostTurnState::Detached {
                    from: DetachOrigin::Running,
                    execution_finished: false,
                },
                ..
            })
        ));

        let ReplyRouteClaim::DetachedLate(late) = rig
            .registry
            .claim_active_reply("turn-detach", "agent:child", "agent:parent")
            .expect("classification race resolves to late")
        else {
            panic!("expected detached-late claim")
        };
        rig.registry
            .complete_reply_late(late)
            .expect("late disposition");
        assert!(matches!(
            rig.registry
                .claim_reply_late("turn-detach", "agent:child", "agent:parent")
                .expect("idempotent late"),
            LateReplyClaim::AlreadyHandled
        ));
        let proof = finish_proof(&mut rig, "turn-detach");
        assert_eq!(
            rig.registry
                .finish_turn(proof)
                .expect("finish detached")
                .outcome,
            TurnFinishOutcome::DetachedRemoved
        );
    }

    #[test]
    fn batch_detach_preserves_consumed_winner_and_detaches_unresolved_loser() {
        let mut rig = rig(8);
        let winner = confirm(&mut rig, "turn-winner", "session-keep-losers", 14);
        let loser = confirm(&mut rig, "turn-loser", "session-keep-losers", 15);
        let winner_registered = start_running(&mut rig, winner);
        let loser_registered = start_running(&mut rig, loser);

        let ReplyRouteClaim::Active(claimed) = rig
            .registry
            .claim_active_reply("turn-winner", "agent:child", "agent:parent")
            .expect("winner claim")
        else {
            panic!("expected active winner claim")
        };
        let (_, token) = claimed.into_parts();
        rig.registry
            .begin_reply_delivery(&token)
            .expect("begin winner delivery");
        let accepted = rig
            .registry
            .record_reply_accepted(&token)
            .expect("winner accepted marker");
        assert_eq!(
            rig.registry
                .complete_reply(&token, accepted)
                .expect("settle winner"),
            ReplySettlement::Consumed
        );

        rig.registry
            .batch_detach(
                &SessionId("session-keep-losers".into()),
                &[winner_registered, loser_registered],
            )
            .expect("detach unresolved loser set");

        assert!(matches!(
            rig.registry.cost_attribution("turn-winner", "agent:child"),
            CostAttributionLookup::Tracked(CostAttributionSnapshot {
                state: CostTurnState::Active,
                ..
            })
        ));
        assert!(matches!(
            rig.registry.cost_attribution("turn-loser", "agent:child"),
            CostAttributionLookup::Tracked(CostAttributionSnapshot {
                state: CostTurnState::Detached {
                    from: DetachOrigin::Running,
                    execution_finished: false,
                },
                ..
            })
        ));
    }

    #[test]
    fn post_begin_abandon_recovers_marker_without_redelivery() {
        let mut rig = rig(8);
        let confirmed = confirm(&mut rig, "turn-recovery", "session-r", 3);
        let registered = start_running(&mut rig, confirmed);
        let ReplyRouteClaim::Active(claimed) = rig
            .registry
            .claim_active_reply("turn-recovery", "agent:child", "agent:parent")
            .expect("claim")
        else {
            panic!("expected active")
        };
        let (_, token) = claimed.into_parts();
        rig.registry.begin_reply_delivery(&token).expect("begin");
        let _accepted = rig
            .registry
            .record_reply_accepted(&token)
            .expect("marker is recorded before cancellation");
        rig.registry.abandon_reply(&token).expect("abandon");
        rig.registry
            .batch_detach(&SessionId("session-r".into()), &[registered])
            .expect("detach claim in progress");

        let summary = rig
            .registry
            .recover_abandoned_claims()
            .expect("bounded recovery");
        assert_eq!(summary.recovered_detached, 1);
        assert_eq!(summary.pending, 0);
        assert!(matches!(
            rig.registry
                .claim_active_reply("turn-recovery", "agent:child", "agent:parent")
                .expect("consumed route drops idempotently"),
            ReplyRouteClaim::DetachedLate(_) | ReplyRouteClaim::AlreadyHandled
        ));
    }

    #[test]
    fn claim_cleanup_waits_through_registry_lock_contention_instead_of_losing_token() {
        let mut rig = rig(8);
        let confirmed = confirm(&mut rig, "turn-contention", "session-lock", 13);
        let _registered = start_running(&mut rig, confirmed);
        let Rig {
            _journal_root,
            registry,
            admission: _,
            removal: _,
            dequeue: _,
            publish: _,
            store: _,
        } = rig;
        let registry = Arc::new(registry);
        let ReplyRouteClaim::Active(claimed) = registry
            .claim_active_reply("turn-contention", "agent:child", "agent:parent")
            .expect("claim")
        else {
            panic!("expected active claim")
        };
        let (_, token) = claimed.into_parts();
        registry.begin_reply_delivery(&token).expect("begin");

        let authority_lock = registry.core.lock().expect("healthy authority lock");
        let retry_registry = Arc::clone(&registry);
        let (entered_tx, entered_rx) = std::sync::mpsc::channel();
        let cleanup = std::thread::spawn(move || {
            entered_tx.send(()).unwrap();
            retry_registry.abandon_reply(&token)
        });
        entered_rx.recv().unwrap();
        std::thread::yield_now();
        drop(authority_lock);
        cleanup
            .join()
            .expect("cleanup thread")
            .expect("blocking authority acquisition eventually settles");
        drop(_journal_root);
    }

    #[test]
    fn definite_rejection_reopens_exactly_once() {
        let mut rig = rig(8);
        let confirmed = confirm(&mut rig, "turn-reopen", "session-o", 4);
        let _registered = start_running(&mut rig, confirmed);
        let ReplyRouteClaim::Active(claimed) = rig
            .registry
            .claim_active_reply("turn-reopen", "agent:child", "agent:parent")
            .expect("first claim")
        else {
            panic!("expected active")
        };
        let (_, token) = claimed.into_parts();
        rig.registry.begin_reply_delivery(&token).expect("begin");
        let rejected = rig
            .registry
            .record_reply_not_accepted(&token)
            .expect("definite rejection marker");
        assert_eq!(
            rig.registry
                .abort_reply(&token, ReplyAbortProof::DefinitelyNotAccepted(rejected))
                .expect("abort exact"),
            ReplySettlement::Reopened
        );
        assert!(matches!(
            rig.registry
                .claim_active_reply("turn-reopen", "agent:child", "agent:parent")
                .expect("second claim"),
            ReplyRouteClaim::Active(_)
        ));
    }

    #[test]
    fn capacity_and_batch_validation_are_fail_closed() {
        let mut one = rig(1);
        let reservation = one
            .registry
            .reserve_queued(spec("turn-cap-1", "session-c"))
            .expect("first reserve");
        assert_eq!(
            one.registry
                .reserve_queued(spec("turn-cap-2", "session-c"))
                .expect_err("full registry must reject"),
            TurnDispatchError::CapacityExhausted
        );
        let facts = facts("turn-cap-1", 5);
        let removed = one
            .removal
            .seal_exact_removal(
                MailboxRemovalAuthority::NeverAdmitted(&reservation),
                None,
                &facts,
            )
            .expect("never-admitted receipt");
        one.registry
            .abort_non_admitted(&reservation, &removed)
            .expect("exact cleanup releases capacity");
        assert_eq!(one.registry.entry_count(), 0);

        let mut batch = rig(4);
        let first = confirm(&mut batch, "turn-batch-1", "session-one", 6);
        let second = confirm(&mut batch, "turn-batch-2", "session-two", 8);
        assert_eq!(
            batch
                .registry
                .batch_detach(
                    &SessionId("session-one".into()),
                    &[first.registered, second.registered],
                )
                .expect_err("mixed-session batch changes nothing"),
            TurnDispatchError::BatchInvalid
        );
        assert_eq!(batch.registry.entry_count(), 2);
        drop((first.rollback, second.rollback));
    }

    #[test]
    fn poisoned_authority_lock_remains_fail_closed_for_every_port_shape() {
        let mut rig = rig(8);

        let execution = confirm(&mut rig, "turn-poison-exec", "session-p", 10);
        let execution_published = rig
            .publish
            .verify_publish(execution.publish, &execution.admission, &execution.facts)
            .expect("publish execution row");
        let execution_receipt = rig
            .dequeue
            .prepare_visible_dequeue(&execution_published, &execution.facts, [0x31; 32])
            .expect("prepare execution row")
            .commit_exact_take();
        let recorded = rig
            .registry
            .record_dequeued(&execution_receipt)
            .expect("record execution row");
        let execution_handle = rig
            .registry
            .complete_dequeue_handoff(&execution_receipt, &recorded)
            .expect("complete execution handoff");

        let mailbox = confirm(&mut rig, "turn-poison-mailbox", "session-p", 12);
        let mailbox_published = rig
            .publish
            .verify_publish(mailbox.publish, &mailbox.admission, &mailbox.facts)
            .expect("publish mailbox row");
        let mailbox_receipt = rig
            .dequeue
            .prepare_visible_dequeue(&mailbox_published, &mailbox.facts, [0x32; 32])
            .expect("prepare mailbox row")
            .commit_exact_take();

        let poisoned = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = rig.registry.core.lock().expect("initial lock is healthy");
            panic!("inject authority-lock poison");
        }));
        assert!(poisoned.is_err());

        assert_eq!(
            rig.registry
                .reserve_queued(spec("turn-after-poison", "session-p"))
                .expect_err("dispatch must reject poison"),
            TurnDispatchError::RecoveryJournalUnavailable
        );
        assert_eq!(
            rig.registry
                .start_turn(&execution_handle)
                .expect_err("execution must reject poison"),
            TurnExecutionError::RecoveryJournalUnavailable
        );
        assert_eq!(
            rig.registry
                .record_dequeued(&mailbox_receipt)
                .expect_err("mailbox must reject poison"),
            TurnMailboxError::Busy
        );
        assert_eq!(
            rig.registry
                .claim_active_reply("turn-poison-exec", "agent:child", "agent:parent",)
                .expect_err("reply routing must reject poison"),
            TurnReplyError::StateConflict
        );
        assert_eq!(
            rig.registry
                .classify_send("turn-poison-exec", "agent:child", "agent:parent"),
            SendTurnClassification::IdentityMismatch
        );
        assert_eq!(
            rig.registry
                .cost_attribution("turn-poison-exec", "agent:child"),
            CostAttributionLookup::IdentityMismatch
        );
        assert_eq!(rig.registry.entry_count(), 8);
    }

    #[test]
    fn execution_boundary_publish_outlives_producer_and_finishes_after_dequeue() {
        use advance_messaging::{
            MailboxStore, ProtectedTurnExecutionBoundary, TurnExecutionBoundaryImpl,
            TurnMailboxDelivery,
        };
        use advance_shared_types::mailbox::{Message, MessageKind};

        let Rig {
            _journal_root,
            registry,
            admission,
            removal,
            dequeue,
            publish,
            store,
        } = rig(8);
        let registry = Arc::new(registry);
        let dispatch: Arc<dyn TurnDispatchLifecyclePort> = registry.clone();
        let lifecycle: Arc<dyn TurnMailboxLifecyclePort> = registry.clone();
        let execution: Arc<dyn TurnExecutionLifecyclePort> = registry.clone();
        let mailboxes = Arc::new(MailboxStore::new_with_turn_attribution(
            NonZeroUsize::new(4).unwrap(),
            admission,
            removal,
            dequeue,
            publish,
            dispatch,
            lifecycle,
            Arc::clone(&execution),
        ));
        let boundary = TurnExecutionBoundaryImpl::new(store, execution);
        let turn_id = "external-turn-1";
        let target = "agent:child";
        mailboxes
            .publish_execution_turn(TurnMailboxDelivery {
                target: target.into(),
                message: Message {
                    id: turn_id.into(),
                    kind: MessageKind::User,
                    from: "user:alice".into(),
                    to: target.into(),
                    payload: b"hello".to_vec(),
                    context: None,
                    timestamp: std::time::SystemTime::UNIX_EPOCH,
                    origin: None,
                },
                spec: QueuedTurnSpec {
                    turn_id: turn_id.into(),
                    expected_agent: target.into(),
                    parent_agent: "user:alice".into(),
                    session_id: SessionId("exec_turn_1".into()),
                    slot: 0,
                    completion_owner: TurnCompletionOwner::ExecutionBoundary,
                    original_task_id: Some("task-external".into()),
                    original_run_id: None,
                    original_reply_to: Some("user:alice".into()),
                },
            })
            .expect("authenticated external publish");

        // The method-local PreparedTurnBatch has already dropped. Execution
        // ownership must remain in the mailbox instead of await-detaching.
        let mailbox = mailboxes.get(target).expect("target mailbox");
        assert_eq!(mailbox.depth(), 1);
        assert_eq!(registry.entry_count(), 1);
        let envelope = mailbox
            .poll_turn()
            .expect("protected poll")
            .expect("published envelope");
        let (message, identity, guard) = envelope.into_parts();
        assert_eq!(message.id, turn_id);
        let identity = identity.expect("trusted identity");
        assert_eq!(
            registry.classify_send(turn_id, target, "user:alice"),
            SendTurnClassification::NonCallable(NonCallableTurnPhase::Queued)
        );
        assert_eq!(
            boundary
                .begin(&identity, guard.expect("dequeue guard"))
                .expect("start exact turn"),
            TurnStartOutcome::Execute
        );
        assert_eq!(
            registry.classify_send(turn_id, target, "user:alice"),
            SendTurnClassification::Untracked,
            "a running external turn must retain ordinary messaging.send"
        );
        assert_eq!(
            registry
                .claim_active_reply(turn_id, target, "user:alice")
                .expect_err("execution owner is never an await-parent reply route"),
            TurnReplyError::NonCallable
        );
        let finished = boundary
            .finish_drained(&identity, [0x77; 16], 1)
            .expect("finish after store quiescence");
        assert_eq!(finished.outcome, TurnFinishOutcome::Removed);
        assert_eq!(registry.entry_count(), 0);
        drop(_journal_root);
    }

    #[test]
    fn canonical_identity_facades_translate_trusted_root_and_reject_unknown_alias() {
        let Rig {
            _journal_root,
            registry,
            mut admission,
            removal: _,
            mut dequeue,
            mut publish,
            store: _,
        } = rig(8);
        let registry = Arc::new(registry);
        let spec = QueuedTurnSpec {
            turn_id: "turn-root-alias".into(),
            expected_agent: "agent:default".into(),
            parent_agent: "agent:parent".into(),
            session_id: SessionId("session-root-alias".into()),
            slot: 0,
            completion_owner: TurnCompletionOwner::AwaitSession,
            original_task_id: None,
            original_run_id: None,
            original_reply_to: Some("agent:parent".into()),
        };
        let reservation = registry.reserve_queued(spec).expect("reserve root turn");
        let facts = MailboxEntryFacts {
            turn_id: "turn-root-alias".into(),
            expected_agent: "agent:default".into(),
            message_id: "turn-root-alias".into(),
            mailbox_incarnation: [0x61; 16],
            staged_entry_id: [0x62; 16],
        };
        let admission_for_confirm = admission
            .seal_staged_admission(&reservation, &facts)
            .expect("admission");
        let admission_for_mailbox = admission
            .duplicate_for_mailbox_owner(&admission_for_confirm)
            .expect("mailbox copy");
        let confirmed = registry
            .confirm_mailbox_admission(&reservation, &admission_for_confirm)
            .expect("confirm");
        let (_registered, permit, _cleanup) = confirmed.into_parts();
        let published = publish
            .verify_publish(permit, &admission_for_mailbox, &facts)
            .expect("publish");
        let receipt = dequeue
            .prepare_visible_dequeue(&published, &facts, [0x63; 32])
            .expect("prepare dequeue")
            .commit_exact_take();
        let recorded = registry.record_dequeued(&receipt).expect("record dequeue");
        let handle = registry
            .complete_dequeue_handoff(&receipt, &recorded)
            .expect("complete handoff");
        assert_eq!(
            registry.start_turn(&handle).expect("start"),
            TurnStartOutcome::Execute
        );

        let reply_inner: Arc<dyn TurnReplyRoutingPort> = registry.clone();
        let cost_inner: Arc<dyn TurnCostAttributionReadPort> = registry;
        let bridge = Arc::new(AgentIdBridge::from_pairs([(
            "agent:default",
            "default-agent",
        )]));
        let (reply, cost) = canonical_turn_identity_facades(reply_inner, cost_inner, bridge);
        assert_eq!(
            reply.classify_send("turn-root-alias", "default-agent", "agent:parent"),
            SendTurnClassification::ActiveParent
        );
        assert!(matches!(
            cost.cost_attribution("turn-root-alias", "default-agent"),
            CostAttributionLookup::Tracked(CostAttributionSnapshot {
                state: CostTurnState::Active,
                ..
            })
        ));
        assert_eq!(
            reply.classify_send("turn-root-alias", "unknown-agent", "agent:parent"),
            SendTurnClassification::IdentityMismatch
        );
        assert_eq!(
            cost.cost_attribution("turn-root-alias", "unknown-agent"),
            CostAttributionLookup::IdentityMismatch
        );
        drop(_journal_root);
    }
}
