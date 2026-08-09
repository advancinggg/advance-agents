//! Narrow C216 mailbox-to-runtime execution boundary.
//!
//! The scheduler owns ordering: begin before guest execution, then call one
//! terminal method only after the Store is drained or destroyed and every
//! action/postprocess/progress side effect has settled. The returned
//! `TurnFinishResult` is intentionally not unpacked here; composition may
//! forward only its `SourceTurnQuiescedReceipt` to the C215 closer.

use std::sync::{Arc, Mutex};

use advance_shared_types::mailbox::{DequeuedTurnGuard, MailboxTurnIdentity};
use advance_shared_types::turn_attribution::{
    StoreQuiescenceFacts, StoreQuiescenceIssuer, TurnExecutionError, TurnExecutionLifecyclePort,
    TurnFinishResult, TurnStartOutcome,
};

/// Scheduler-facing least-privilege execution surface. It cannot reserve,
/// publish, detach, classify replies, or mint arbitrary source receipts.
pub trait ProtectedTurnExecutionBoundary: Send + Sync {
    /// Cross the mailbox's before-start RAII boundary immediately before the
    /// trusted turn identity is stamped into the guest Store.
    fn begin(
        &self,
        identity: &MailboxTurnIdentity,
        guard: DequeuedTurnGuard,
    ) -> Result<TurnStartOutcome, TurnExecutionError>;

    /// Normal terminal path after all effects settled and the live Store was
    /// synchronously drained to the supplied monotonic epoch.
    fn finish_drained(
        &self,
        identity: &MailboxTurnIdentity,
        store_incarnation: [u8; 16],
        store_epoch: u64,
    ) -> Result<TurnFinishResult, TurnExecutionError>;

    /// Trap/cancel/error terminal path after the Store was cleared/poisoned
    /// and destroyed, making further host calls for this incarnation
    /// impossible.
    fn finish_store_destroyed(
        &self,
        identity: &MailboxTurnIdentity,
        store_incarnation: [u8; 16],
    ) -> Result<TurnFinishResult, TurnExecutionError>;
}

/// Concrete composition adapter joining the store-proof issuer to the exact
/// C216 registry lifecycle provider.
pub struct TurnExecutionBoundaryImpl {
    store_issuer: Mutex<StoreQuiescenceIssuer>,
    lifecycle: Arc<dyn TurnExecutionLifecyclePort>,
}

impl TurnExecutionBoundaryImpl {
    pub fn new(
        store_issuer: StoreQuiescenceIssuer,
        lifecycle: Arc<dyn TurnExecutionLifecyclePort>,
    ) -> Self {
        Self {
            store_issuer: Mutex::new(store_issuer),
            lifecycle,
        }
    }

    fn facts(identity: &MailboxTurnIdentity, store_incarnation: [u8; 16]) -> StoreQuiescenceFacts {
        StoreQuiescenceFacts {
            turn_id: identity.turn_id.clone(),
            expected_agent: identity.expected_agent.clone(),
            store_incarnation,
        }
    }
}

impl ProtectedTurnExecutionBoundary for TurnExecutionBoundaryImpl {
    fn begin(
        &self,
        identity: &MailboxTurnIdentity,
        guard: DequeuedTurnGuard,
    ) -> Result<TurnStartOutcome, TurnExecutionError> {
        if identity.turn_id.is_empty() || identity.expected_agent.is_empty() {
            return Err(TurnExecutionError::IdentityMismatch);
        }
        guard.start()
    }

    fn finish_drained(
        &self,
        identity: &MailboxTurnIdentity,
        store_incarnation: [u8; 16],
        store_epoch: u64,
    ) -> Result<TurnFinishResult, TurnExecutionError> {
        let proof = self
            .store_issuer
            .lock()
            .map_err(|_| TurnExecutionError::Busy)?
            .issue_drained(&Self::facts(identity, store_incarnation), store_epoch)?;
        self.lifecycle.finish_turn(proof)
    }

    fn finish_store_destroyed(
        &self,
        identity: &MailboxTurnIdentity,
        store_incarnation: [u8; 16],
    ) -> Result<TurnFinishResult, TurnExecutionError> {
        let proof = self
            .store_issuer
            .lock()
            .map_err(|_| TurnExecutionError::Busy)?
            .issue_store_destroyed(&Self::facts(identity, store_incarnation))?;
        self.lifecycle.finish_turn(proof)
    }
}
