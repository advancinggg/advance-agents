//! MODULE-006 CONTRACT-215 journal-backed outbound route lifecycle.
//!
//! The concrete factory product owns the route issuer emitted by the joint
//! C215/C216 authority factory. Every arm/ref/settle/seal operation therefore
//! commits through the shared anti-rollback journal before the opaque result is
//! published. No product in-memory lifecycle or public raw journal seam exists.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use advance_shared_types::progress_card::{
    OutboundRouteRef, OutboundRouteRefKind, OutboundRouteSealIssuer, ProgressCardAuthorityError,
    ProgressCardCoordinatorError, ProgressCardKey, ProgressSourceLifecyclePort,
    SourceCloseAttestationIssuer,
};
use advance_shared_types::turn_attribution::{
    SourceQuiescenceRecoveryIssuer, SourceTurnQuiescedReceipt, TurnExecutionError,
};
use parking_lot::Mutex;

pub const MAX_PROGRESS_ROUTE_LIFECYCLES: usize = 16_384;
pub const MAX_PROGRESS_ROUTE_REFS_PER_SOURCE: usize = 250_000;

#[derive(Debug)]
pub enum ProgressSourceLifecycleError {
    Authority(ProgressCardAuthorityError),
    Coordinator(ProgressCardCoordinatorError),
    Recovery(TurnExecutionError),
    Capacity,
    BindingMismatch,
    RoutesSealed,
    RoutesNotQuiescent,
    Missing,
    Poisoned,
}

impl std::fmt::Display for ProgressSourceLifecycleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Authority(error) => return error.fmt(f),
            Self::Coordinator(error) => return error.fmt(f),
            Self::Recovery(error) => return error.fmt(f),
            Self::Capacity => "progress-card-capacity",
            Self::BindingMismatch => "progress-route-binding-mismatch",
            Self::RoutesSealed => "progress-routes-sealed",
            Self::RoutesNotQuiescent => "progress-routes-not-quiescent",
            Self::Missing => "progress-record-unavailable",
            Self::Poisoned => "progress-journal-unavailable",
        })
    }
}

impl std::error::Error for ProgressSourceLifecycleError {}

impl From<ProgressCardAuthorityError> for ProgressSourceLifecycleError {
    fn from(value: ProgressCardAuthorityError) -> Self {
        Self::Authority(value)
    }
}

impl From<ProgressCardCoordinatorError> for ProgressSourceLifecycleError {
    fn from(value: ProgressCardCoordinatorError) -> Self {
        Self::Coordinator(value)
    }
}

impl From<TurnExecutionError> for ProgressSourceLifecycleError {
    fn from(value: TurnExecutionError) -> Self {
        Self::Recovery(value)
    }
}

struct ProgressRouteAuthorityState {
    issuer: OutboundRouteSealIssuer,
    /// Failed settlements retain the exact move-only authority until a later
    /// prepare/seal retries it. Capacity for every in-flight lease is reserved
    /// before the journal publishes its route ref.
    pending_settlements: Vec<OutboundRouteRef>,
    outstanding_slots: usize,
}

struct ProgressRouteAuthority {
    state: Mutex<ProgressRouteAuthorityState>,
}

impl ProgressRouteAuthority {
    fn drain_pending(
        state: &mut ProgressRouteAuthorityState,
    ) -> Result<(), ProgressSourceLifecycleError> {
        while let Some(route_ref) = state.pending_settlements.pop() {
            if let Err(error) = state.issuer.settle_route_ref(&route_ref) {
                // `pop` never shrinks capacity, so restoring this token is
                // allocation-free and cannot strand authority on this path.
                state.pending_settlements.push(route_ref);
                return Err(error.into());
            }
        }
        Ok(())
    }

    fn prepare(
        self: &Arc<Self>,
        key: &ProgressCardKey,
        expected_agent: &str,
        kind: OutboundRouteRefKind,
    ) -> Result<ProgressRouteDeliveryLease, ProgressSourceLifecycleError> {
        let mut state = self.state.lock();
        Self::drain_pending(&mut state)?;
        if state.outstanding_slots >= MAX_PROGRESS_ROUTE_REFS_PER_SOURCE {
            return Err(ProgressSourceLifecycleError::Capacity);
        }
        // One allocation-free fallback slot per outstanding lease. This must
        // happen before `acquire_route_ref` durably publishes a new token.
        let reservation = state.outstanding_slots + 1;
        state
            .pending_settlements
            .try_reserve_exact(reservation)
            .map_err(|_| ProgressSourceLifecycleError::Capacity)?;
        let binding = state.issuer.arm_before_progress(key, expected_agent)?;
        let route_ref = state.issuer.acquire_route_ref(&binding, kind)?;
        state.outstanding_slots = state
            .outstanding_slots
            .checked_add(1)
            .ok_or(ProgressSourceLifecycleError::Capacity)?;
        drop(state);
        Ok(ProgressRouteDeliveryLease {
            authority: Arc::clone(self),
            route_ref: Some(route_ref),
        })
    }

    fn finish_ref(&self, route_ref: OutboundRouteRef) -> Result<(), ProgressSourceLifecycleError> {
        let mut state = self.state.lock();
        state.outstanding_slots = state
            .outstanding_slots
            .checked_sub(1)
            .ok_or(ProgressSourceLifecycleError::BindingMismatch)?;
        match state.issuer.settle_route_ref(&route_ref) {
            Ok(()) => Ok(()),
            Err(error) => {
                // Capacity was reserved before publication; no fallible
                // allocation occurs while retaining failed authority.
                state.pending_settlements.push(route_ref);
                Err(error.into())
            }
        }
    }

    fn seal_and_issue(
        &self,
        source: &SourceTurnQuiescedReceipt,
    ) -> Result<
        advance_shared_types::progress_card::OutboundRoutesSealedReceipt,
        ProgressSourceLifecycleError,
    > {
        let mut state = self.state.lock();
        Self::drain_pending(&mut state)?;
        if state.outstanding_slots != 0 {
            return Err(ProgressSourceLifecycleError::RoutesNotQuiescent);
        }
        match state.issuer.seal_and_issue_for_source(source) {
            Ok(receipt) => Ok(receipt),
            // Cancellation leaves the durable route lifecycle sealed. A fresh
            // exact source receipt may therefore reissue (not reseal) the
            // bounded close authority. Any other mismatch is rejected again
            // by the exact reissue binding checks.
            Err(ProgressCardAuthorityError::BindingMismatch) => state
                .issuer
                .reissue_sealed_for_source(source)
                .map_err(Into::into),
            Err(error) => Err(error.into()),
        }
    }

    fn cancel_sealed_receipt(
        &self,
        receipt: &advance_shared_types::progress_card::OutboundRoutesSealedReceipt,
    ) -> Result<(), ProgressSourceLifecycleError> {
        self.state
            .lock()
            .issuer
            .cancel_sealed_receipt(receipt)
            .map_err(Into::into)
    }
}

/// Move-only route reference held around exactly one renderer invocation.
/// Cancellation is safe: `Drop` synchronously attempts settlement and retains
/// the exact token in an allocation-free pending slot on failure. Subsequent
/// prepare/seal operations drain pending settlements or fail closed.
pub struct ProgressRouteDeliveryLease {
    authority: Arc<ProgressRouteAuthority>,
    route_ref: Option<OutboundRouteRef>,
}

impl ProgressRouteDeliveryLease {
    pub fn route_ref(&self) -> &OutboundRouteRef {
        self.route_ref
            .as_ref()
            .expect("a settled progress route lease is consumed")
    }
}

impl Drop for ProgressRouteDeliveryLease {
    fn drop(&mut self) {
        let Some(route_ref) = self.route_ref.take() else {
            return;
        };
        let _retained_on_error = self.authority.finish_ref(route_ref);
    }
}

impl std::fmt::Debug for ProgressRouteDeliveryLease {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProgressRouteDeliveryLease")
            .field("route_ref", &"<opaque>")
            .finish()
    }
}

/// Narrow M006 product used only by the routed outbound sink.
pub struct ProgressRouteDelivery {
    authority: Arc<ProgressRouteAuthority>,
}

impl ProgressRouteDelivery {
    pub fn prepare(
        &self,
        key: &ProgressCardKey,
        expected_agent: &str,
        kind: OutboundRouteRefKind,
    ) -> Result<ProgressRouteDeliveryLease, ProgressSourceLifecycleError> {
        self.authority.prepare(key, expected_agent, kind)
    }

    pub fn settle(
        &self,
        mut lease: ProgressRouteDeliveryLease,
    ) -> Result<(), ProgressSourceLifecycleError> {
        let route_ref = lease
            .route_ref
            .take()
            .ok_or(ProgressSourceLifecycleError::BindingMismatch)?;
        self.authority.finish_ref(route_ref)
    }
}

impl std::fmt::Debug for ProgressRouteDelivery {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ProgressRouteDelivery([opaque])")
    }
}

/// Separate source-close product. It cannot render or reconcile attempts.
pub struct ProgressSourceCloser {
    authority: Arc<ProgressRouteAuthority>,
    cards: Arc<dyn ProgressSourceLifecyclePort>,
    attester: Mutex<SourceCloseAttestationIssuer>,
    recovery: Mutex<SourceQuiescenceRecoveryIssuer>,
}

impl ProgressSourceCloser {
    pub fn close_source(
        &self,
        source: &SourceTurnQuiescedReceipt,
    ) -> Result<(), ProgressSourceLifecycleError> {
        let outbound = self.authority.seal_and_issue(source)?;
        let challenge = match self.cards.begin_source_close(source) {
            Ok(challenge) => challenge,
            Err(error) => {
                let _ = self.authority.cancel_sealed_receipt(&outbound);
                return Err(error.into());
            }
        };
        let now_ms = match current_unix_ms() {
            Ok(now_ms) => now_ms,
            Err(error) => {
                let _ = self.cards.cancel_source_close(source, &challenge);
                let _ = self.authority.cancel_sealed_receipt(&outbound);
                return Err(error);
            }
        };
        let attestation = match self
            .attester
            .lock()
            .attest_source_close(&challenge, source, &outbound, now_ms)
        {
            Ok(attestation) => attestation,
            Err(error) => {
                let _ = self.cards.cancel_source_close(source, &challenge);
                let _ = self.authority.cancel_sealed_receipt(&outbound);
                return Err(error.into());
            }
        };
        match self.cards.close_source(source, &challenge, &attestation) {
            Ok(()) => Ok(()),
            Err(error) => {
                // Challenge cancellation releases the coordinator's bounded
                // in-process reservation. Every published close authority is
                // moved terminal before the sealed route can be exactly
                // reissued for a fresh challenge.
                let _ = self.attester.lock().cancel_attestation(&attestation);
                let _ = self.cards.cancel_source_close(source, &challenge);
                let _ = self.authority.cancel_sealed_receipt(&outbound);
                Err(error.into())
            }
        }
    }

    /// Boot-only bounded convergence entry. Every receipt is freshly signed
    /// from the journal's durable source→key binding; no raw key or in-process
    /// routing map is consulted.
    pub fn recover_pending_sources(&self) -> Result<usize, ProgressSourceLifecycleError> {
        let receipts = self.recovery.lock().reissue_pending_progress_sources()?;
        let count = receipts.len();
        for source in receipts {
            self.close_source(&source)?;
        }
        Ok(count)
    }
}

impl std::fmt::Debug for ProgressSourceCloser {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ProgressSourceCloser([opaque])")
    }
}

pub struct ProgressRouteProviderParts {
    pub delivery: Arc<ProgressRouteDelivery>,
    pub source_close: Arc<ProgressSourceCloser>,
}

/// Stage both disjoint M006 route products while consuming every route/close
/// authority role. Pending retired sources converge before this returns; new
/// delivery remains unreachable until the joint dispatcher barrier publishes
/// the routed sink.
pub fn stage_progress_route_provider(
    issuer: OutboundRouteSealIssuer,
    cards: Arc<dyn ProgressSourceLifecyclePort>,
    attester: SourceCloseAttestationIssuer,
    recovery: SourceQuiescenceRecoveryIssuer,
) -> Result<ProgressRouteProviderParts, ProgressSourceLifecycleError> {
    let authority = Arc::new(ProgressRouteAuthority {
        state: Mutex::new(ProgressRouteAuthorityState {
            issuer,
            pending_settlements: Vec::new(),
            outstanding_slots: 0,
        }),
    });
    let parts = ProgressRouteProviderParts {
        delivery: Arc::new(ProgressRouteDelivery {
            authority: Arc::clone(&authority),
        }),
        source_close: Arc::new(ProgressSourceCloser {
            authority,
            cards,
            attester: Mutex::new(attester),
            recovery: Mutex::new(recovery),
        }),
    };
    parts.source_close.recover_pending_sources()?;
    Ok(parts)
}

fn current_unix_ms() -> Result<u64, ProgressSourceLifecycleError> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ProgressSourceLifecycleError::Poisoned)?;
    u64::try_from(duration.as_millis()).map_err(|_| ProgressSourceLifecycleError::Capacity)
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU32;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    use advance_shared_types::progress_card::{
        OutboundRouteRefKind, ProgressCardAuthorityFactory, ProgressCardAuthorityVerifier,
        ProgressCardChallengeIssuer, ProgressCardKey, SourceCloseChallenge,
        SourceLifecycleCloseAttestation,
    };
    use advance_shared_types::progress_lifecycle_recovery::{
        ProgressLifecycleRecoveryJournal, RecoveryJournalConfig,
    };
    use advance_shared_types::turn_attribution::{
        StoreQuiescenceFacts, TurnAttributionAuthorityFactory,
    };
    use zeroize::Zeroizing;

    use super::*;

    struct FailOnceCloseCards {
        challenge: Mutex<ProgressCardChallengeIssuer>,
        verifier: ProgressCardAuthorityVerifier,
        fail_once: AtomicBool,
        fail_first_cancel: AtomicBool,
        cancellations: AtomicUsize,
    }

    impl ProgressSourceLifecyclePort for FailOnceCloseCards {
        fn begin_source_close(
            &self,
            source: &SourceTurnQuiescedReceipt,
        ) -> Result<SourceCloseChallenge, ProgressCardCoordinatorError> {
            self.challenge
                .lock()
                .issue_source_close_for_source(source, None)
        }

        fn close_source(
            &self,
            source: &SourceTurnQuiescedReceipt,
            challenge: &SourceCloseChallenge,
            attestation: &SourceLifecycleCloseAttestation,
        ) -> Result<(), ProgressCardCoordinatorError> {
            if self.fail_once.swap(false, Ordering::SeqCst) {
                if self.fail_first_cancel.swap(false, Ordering::SeqCst) {
                    self.verifier
                        .test_fail_next_journal_transaction_after_prepared_fsync()
                        .map_err(|_| ProgressCardCoordinatorError::JournalUnavailable)?;
                }
                return Err(ProgressCardCoordinatorError::JournalUnavailable);
            }
            self.verifier
                .commit_source_close_for_source(source, None, challenge, attestation)
        }

        fn cancel_source_close(
            &self,
            source: &SourceTurnQuiescedReceipt,
            challenge: &SourceCloseChallenge,
        ) -> Result<(), ProgressCardCoordinatorError> {
            self.verifier
                .cancel_source_close_for_source(source, None, challenge)?;
            self.cancellations.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    #[test]
    fn cancellation_settles_normally_and_journal_failure_retains_authority_fail_closed() {
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
        .expect("turn authority");
        let (_, turn_binding) = turn
            .registry_issuer
            .reserve_turn("msg-1", "agent:default")
            .expect("active source")
            .into_parts();
        let parts = ProgressCardAuthorityFactory::new_with_os_rng_at_composition(
            turn.activation_staging,
            turn.source_quiescence_verifier,
            progress_recovery,
        )
        .expect("progress authority");
        let authority = Arc::new(ProgressRouteAuthority {
            state: Mutex::new(ProgressRouteAuthorityState {
                issuer: parts.outbound_route_seal_issuer,
                pending_settlements: Vec::new(),
                outstanding_slots: 0,
            }),
        });
        let delivery = ProgressRouteDelivery {
            authority: Arc::clone(&authority),
        };
        let key = ProgressCardKey {
            adapter_id: "telegram".into(),
            subscription_id: "sub-1".into(),
            conversation_id: "chat-42".into(),
            source_message_id: "msg-1".into(),
        };
        let lease = delivery
            .prepare(&key, "agent:default", OutboundRouteRefKind::Action)
            .expect("route lease");
        drop(lease);

        let store_facts = StoreQuiescenceFacts {
            turn_id: "msg-1".into(),
            expected_agent: "agent:default".into(),
            store_incarnation: [1; 16],
        };
        let store_proof = turn
            .store_quiescence_issuer
            .issue_drained(&store_facts, 1)
            .expect("store proof");
        let source = turn
            .registry_issuer
            .commit_store_quiescence(&turn_binding, &store_proof)
            .expect("quiescence commit")
            .expect("bound source receipt");
        authority
            .seal_and_issue(&source)
            .expect("drop settled the only ref before route seal");

        let _second_source = turn
            .registry_issuer
            .reserve_turn("msg-2", "agent:default")
            .expect("second active source");
        let second_key = ProgressCardKey {
            adapter_id: "telegram".into(),
            subscription_id: "sub-1".into(),
            conversation_id: "chat-42".into(),
            source_message_id: "msg-2".into(),
        };
        let failed_lease = delivery
            .prepare(&second_key, "agent:default", OutboundRouteRefKind::Action)
            .expect("second route lease");
        authority
            .state
            .lock()
            .issuer
            .test_fail_next_journal_transaction_after_prepared_fsync()
            .expect("journal failpoint armed");
        drop(failed_lease);
        assert_eq!(authority.state.lock().pending_settlements.len(), 1);
        assert!(delivery
            .prepare(&second_key, "agent:default", OutboundRouteRefKind::Action,)
            .is_err());
        assert_eq!(
            authority.state.lock().pending_settlements.len(),
            1,
            "failed durable settlement retains its exact token"
        );
    }

    #[test]
    fn final_close_failure_cancels_and_exact_reissue_retries_to_completion() {
        let journal_root = tempfile::tempdir().expect("journal root");
        let config = RecoveryJournalConfig::new_at_composition(
            journal_root.path().join("journal"),
            journal_root.path().join("anchor").join("root.anchor"),
            NonZeroU32::new(1).expect("non-zero epoch"),
            Zeroizing::new([0x43; 32]),
        )
        .expect("valid journal config");
        let journal =
            ProgressLifecycleRecoveryJournal::open_at_composition(config).expect("journal opens");
        let (turn_recovery, progress_recovery) = journal.split_at_composition();
        let mut turn = TurnAttributionAuthorityFactory::new_at_composition(
            &mut rand::rngs::OsRng,
            turn_recovery,
        )
        .expect("turn authority");
        let (_, turn_binding) = turn
            .registry_issuer
            .reserve_turn("msg-close", "agent:default")
            .expect("active source")
            .into_parts();
        let parts = ProgressCardAuthorityFactory::new_with_os_rng_at_composition(
            turn.activation_staging,
            turn.source_quiescence_verifier,
            progress_recovery,
        )
        .expect("progress authority");
        let cards = Arc::new(FailOnceCloseCards {
            challenge: Mutex::new(parts.coordinator_challenge_issuer),
            verifier: parts.verifier,
            fail_once: AtomicBool::new(true),
            fail_first_cancel: AtomicBool::new(false),
            cancellations: AtomicUsize::new(0),
        });
        let cards_port: Arc<dyn ProgressSourceLifecyclePort> = cards.clone();
        let provider = stage_progress_route_provider(
            parts.outbound_route_seal_issuer,
            cards_port,
            parts.source_close_attestation_issuer,
            turn.source_quiescence_recovery_issuer,
        )
        .expect("route provider stages");
        let key = ProgressCardKey {
            adapter_id: "telegram".into(),
            subscription_id: "sub-1".into(),
            conversation_id: "chat-42".into(),
            source_message_id: "msg-close".into(),
        };
        drop(
            provider
                .delivery
                .prepare(&key, "agent:default", OutboundRouteRefKind::Action)
                .expect("arm route lifecycle"),
        );
        let facts = StoreQuiescenceFacts {
            turn_id: "msg-close".into(),
            expected_agent: "agent:default".into(),
            store_incarnation: [2; 16],
        };
        let proof = turn
            .store_quiescence_issuer
            .issue_drained(&facts, 1)
            .unwrap();
        let source = turn
            .registry_issuer
            .commit_store_quiescence(&turn_binding, &proof)
            .unwrap()
            .expect("source receipt");

        assert!(provider.source_close.close_source(&source).is_err());
        assert_eq!(cards.cancellations.load(Ordering::SeqCst), 1);
        provider
            .source_close
            .close_source(&source)
            .expect("sealed route receipt is exactly reissued for retry");
        assert!(provider.source_close.close_source(&source).is_err());
    }

    #[test]
    fn cancel_failure_drops_tokens_but_reopen_auto_converges_durably() {
        let journal_root = tempfile::tempdir().expect("journal root");
        let journal_path = journal_root.path().join("journal");
        let anchor_path = journal_root.path().join("anchor").join("root.anchor");
        let config = || {
            RecoveryJournalConfig::new_at_composition(
                journal_path.clone(),
                anchor_path.clone(),
                NonZeroU32::new(1).expect("non-zero epoch"),
                Zeroizing::new([0x45; 32]),
            )
            .expect("valid journal config")
        };
        let source_for_audit;

        {
            let journal = ProgressLifecycleRecoveryJournal::open_at_composition(config())
                .expect("first runtime opens");
            let (turn_recovery, progress_recovery) = journal.split_at_composition();
            let mut turn = TurnAttributionAuthorityFactory::new_at_composition(
                &mut rand::rngs::OsRng,
                turn_recovery,
            )
            .expect("turn authority");
            let (_, turn_binding) = turn
                .registry_issuer
                .reserve_turn("msg-cancel-fail", "agent:default")
                .expect("active source")
                .into_parts();
            let progress = ProgressCardAuthorityFactory::new_with_os_rng_at_composition(
                turn.activation_staging,
                turn.source_quiescence_verifier,
                progress_recovery,
            )
            .expect("progress authority");
            let cards = Arc::new(FailOnceCloseCards {
                challenge: Mutex::new(progress.coordinator_challenge_issuer),
                verifier: progress.verifier,
                fail_once: AtomicBool::new(true),
                fail_first_cancel: AtomicBool::new(true),
                cancellations: AtomicUsize::new(0),
            });
            let cards_port: Arc<dyn ProgressSourceLifecyclePort> = cards.clone();
            let provider = stage_progress_route_provider(
                progress.outbound_route_seal_issuer,
                cards_port,
                progress.source_close_attestation_issuer,
                turn.source_quiescence_recovery_issuer,
            )
            .expect("first route provider stages");
            let key = ProgressCardKey {
                adapter_id: "telegram".into(),
                subscription_id: "sub-1".into(),
                conversation_id: "chat-42".into(),
                source_message_id: "msg-cancel-fail".into(),
            };
            drop(
                provider
                    .delivery
                    .prepare(&key, "agent:default", OutboundRouteRefKind::Action)
                    .expect("route lifecycle armed"),
            );
            let facts = StoreQuiescenceFacts {
                turn_id: "msg-cancel-fail".into(),
                expected_agent: "agent:default".into(),
                store_incarnation: [4; 16],
            };
            let proof = turn
                .store_quiescence_issuer
                .issue_drained(&facts, 1)
                .unwrap();
            let source = turn
                .registry_issuer
                .commit_store_quiescence(&turn_binding, &proof)
                .unwrap()
                .expect("source receipt");
            assert!(provider.source_close.close_source(&source).is_err());
            assert_eq!(
                cards.cancellations.load(Ordering::SeqCst),
                0,
                "the injected journal failure prevents all three cancellation writes"
            );
            source_for_audit = source;
        }

        {
            let journal = ProgressLifecycleRecoveryJournal::open_at_composition(config())
                .expect("reopen recovers unanchored cancellation prepare");
            let (turn_recovery, progress_recovery) = journal.split_at_composition();
            let turn = TurnAttributionAuthorityFactory::new_at_composition(
                &mut rand::rngs::OsRng,
                turn_recovery,
            )
            .expect("fresh turn authority");
            let progress = ProgressCardAuthorityFactory::new_with_os_rng_at_composition(
                turn.activation_staging,
                turn.source_quiescence_verifier,
                progress_recovery,
            )
            .expect("fresh progress authority");
            let cards = Arc::new(FailOnceCloseCards {
                challenge: Mutex::new(progress.coordinator_challenge_issuer),
                verifier: progress.verifier,
                fail_once: AtomicBool::new(false),
                fail_first_cancel: AtomicBool::new(false),
                cancellations: AtomicUsize::new(0),
            });
            let cards_port: Arc<dyn ProgressSourceLifecyclePort> = cards.clone();
            stage_progress_route_provider(
                progress.outbound_route_seal_issuer,
                cards_port,
                progress.source_close_attestation_issuer,
                turn.source_quiescence_recovery_issuer,
            )
            .expect("boot retirement cancels stale rows and closes pending source");
            assert_eq!(
                cards
                    .verifier
                    .test_live_authority_count_for_source(&source_for_audit)
                    .expect("source authority terminality audit"),
                0,
                "reopen leaves no live route, challenge, or attestation authority"
            );
        }

        {
            let journal = ProgressLifecycleRecoveryJournal::open_at_composition(config())
                .expect("third runtime opens");
            let (turn_recovery, _progress_recovery) = journal.split_at_composition();
            let mut turn = TurnAttributionAuthorityFactory::new_at_composition(
                &mut rand::rngs::OsRng,
                turn_recovery,
            )
            .expect("third turn authority");
            assert!(turn
                .source_quiescence_recovery_issuer
                .reissue_pending_progress_sources()
                .expect("pending source enumeration")
                .is_empty());
        }
    }

    #[test]
    fn restart_discards_raw_key_and_stale_authority_then_auto_converges() {
        let journal_root = tempfile::tempdir().expect("journal root");
        let journal_path = journal_root.path().join("journal");
        let anchor_path = journal_root.path().join("anchor").join("root.anchor");
        let config = || {
            RecoveryJournalConfig::new_at_composition(
                journal_path.clone(),
                anchor_path.clone(),
                NonZeroU32::new(1).expect("non-zero epoch"),
                Zeroizing::new([0x44; 32]),
            )
            .expect("valid journal config")
        };

        // Runtime one creates and seals a lifecycle, then dies with all three
        // source-close authorities live. The raw canonical key is scoped to
        // this block and is deliberately unavailable to every recovery phase.
        {
            let journal = ProgressLifecycleRecoveryJournal::open_at_composition(config())
                .expect("first runtime opens");
            let (turn_recovery, progress_recovery) = journal.split_at_composition();
            let mut turn = TurnAttributionAuthorityFactory::new_at_composition(
                &mut rand::rngs::OsRng,
                turn_recovery,
            )
            .expect("turn authority");
            let (_, turn_binding) = turn
                .registry_issuer
                .reserve_turn("msg-restart", "agent:default")
                .expect("active source")
                .into_parts();
            let mut progress = ProgressCardAuthorityFactory::new_with_os_rng_at_composition(
                turn.activation_staging,
                turn.source_quiescence_verifier,
                progress_recovery,
            )
            .expect("progress authority");
            let key = ProgressCardKey {
                adapter_id: "telegram".into(),
                subscription_id: "sub-1".into(),
                conversation_id: "chat-42".into(),
                source_message_id: "msg-restart".into(),
            };
            let binding = progress
                .outbound_route_seal_issuer
                .arm_before_progress(&key, "agent:default")
                .expect("route lifecycle armed");
            let route_ref = progress
                .outbound_route_seal_issuer
                .acquire_route_ref(&binding, OutboundRouteRefKind::Action)
                .expect("route reference");
            progress
                .outbound_route_seal_issuer
                .settle_route_ref(&route_ref)
                .expect("route settled");
            let facts = StoreQuiescenceFacts {
                turn_id: "msg-restart".into(),
                expected_agent: "agent:default".into(),
                store_incarnation: [3; 16],
            };
            let proof = turn
                .store_quiescence_issuer
                .issue_drained(&facts, 1)
                .unwrap();
            let source = turn
                .registry_issuer
                .commit_store_quiescence(&turn_binding, &proof)
                .unwrap()
                .expect("source receipt");
            let outbound = progress
                .outbound_route_seal_issuer
                .seal_and_issue_for_source(&source)
                .expect("routes sealed");
            let challenge = progress
                .coordinator_challenge_issuer
                .issue_source_close_for_source(&source, None)
                .expect("close challenge");
            progress
                .source_close_attestation_issuer
                .attest_source_close(&challenge, &source, &outbound, current_unix_ms().unwrap())
                .expect("close attestation");
        }

        // Runtime two has no raw key and no in-process source map. Opening the
        // journal retires the old sealed lifecycle and cancels stale authority;
        // route staging enumerates a fresh opaque receipt and closes it.
        {
            let journal = ProgressLifecycleRecoveryJournal::open_at_composition(config())
                .expect("second runtime opens");
            let (turn_recovery, progress_recovery) = journal.split_at_composition();
            let turn = TurnAttributionAuthorityFactory::new_at_composition(
                &mut rand::rngs::OsRng,
                turn_recovery,
            )
            .expect("fresh turn authority");
            let progress = ProgressCardAuthorityFactory::new_with_os_rng_at_composition(
                turn.activation_staging,
                turn.source_quiescence_verifier,
                progress_recovery,
            )
            .expect("fresh progress authority");
            let cards: Arc<dyn ProgressSourceLifecyclePort> = Arc::new(FailOnceCloseCards {
                challenge: Mutex::new(progress.coordinator_challenge_issuer),
                verifier: progress.verifier,
                fail_once: AtomicBool::new(false),
                fail_first_cancel: AtomicBool::new(false),
                cancellations: AtomicUsize::new(0),
            });
            let provider = stage_progress_route_provider(
                progress.outbound_route_seal_issuer,
                cards,
                progress.source_close_attestation_issuer,
                turn.source_quiescence_recovery_issuer,
            )
            .expect("boot recovery converges before publication");
            drop(provider);
        }

        // A third runtime proves the source/close pair was consumed rather
        // than merely hidden in runtime-two memory.
        {
            let journal = ProgressLifecycleRecoveryJournal::open_at_composition(config())
                .expect("third runtime opens");
            let (turn_recovery, _progress_recovery) = journal.split_at_composition();
            let mut turn = TurnAttributionAuthorityFactory::new_at_composition(
                &mut rand::rngs::OsRng,
                turn_recovery,
            )
            .expect("third turn authority");
            assert!(turn
                .source_quiescence_recovery_issuer
                .reissue_pending_progress_sources()
                .expect("bounded recovery enumeration")
                .is_empty());
        }
    }
}
