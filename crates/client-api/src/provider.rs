//! CONTRACT-190 provider ports (m020-s2).
//!
//! The run/message/tool families consume the host-side MODULE-008/006/017 surfaces through these
//! **client-api-owned SYNC provider ports**. The ports are expressed only in client-api DTOs +
//! primitives + [`ProviderError`] — the client-api lib takes NO dependency on the provider crates.
//! Concrete adapters that bind the REAL `RunManager` / `MailboxDispatcher` / `CallableInventory`
//! (bridging their async methods with an adapter-owned `tokio` runtime + `block_on`) live in the CLI
//! composition root (Wave-25); m020-s2 witnesses them with real-provider test adapters.
//!
//! **Fail-closed**: each family's provider is an [interior-mutable slot](RunProviderSlot). A handler
//! reads the slot; an empty slot yields `module_unavailable`. Routes are ALWAYS registered, so an
//! absent provider yields `module_unavailable` (not `unknown_route`). Absence MUST be structural (the
//! slot is `None`) — an `EmptyCallableInventory` and a genuinely-wired-but-empty inventory are
//! indistinguishable at the reader surface, so the port never adapts the Empty placeholder.

use std::sync::{Arc, RwLock};

use advance_shared_types::security_validator::LeakDetector;
use advance_shared_types::sensitive_observation::SensitiveObservationRedactor;

use crate::cursor::ClientCursorCodec;
use crate::envelope::{ClientError, ClientErrorCode};
use crate::events::ClientEventProvider;
use crate::messages::{ClientMessageAck, ClientMessageStatus};
use crate::providers::grants::BoundGrantApprovalPort;
use crate::providers::history::BoundHistoryReadPort;
use crate::runs::{ClientAgentTreeNode, ClientRunMutation, ClientRunSummary};
use crate::tools::ClientToolInventory;

/// A client-safe provider error. Adapters map raw `RunError`/`MsgError`/`SkillError` to a
/// `ProviderError` VARIANT (operation-scoped; the only inner-string match is
/// `MsgError::InvalidTarget("reply_not_authorized")`), and the handler maps `ProviderError` to a
/// stable [`ClientErrorCode`]. A raw provider error struct never reaches the client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProviderError {
    /// A run/message/agent named by the request does not exist. → `not_found`
    NotFound(String),
    /// A reply is attempted by a principal other than the inbound recipient. → `reply_not_authorized`
    NotAuthorized(String),
    /// The operation is not valid for the resource's current state. → `invalid_state`
    InvalidState(String),
    /// The caller is not permitted (host-side authorization). → `forbidden`
    Forbidden(String),
    /// The request payload exceeds a provider-side bound. → `request_too_large`
    TooLarge(String),
    /// The provider is absent/unhealthy (or a bridged call failed). → `module_unavailable`
    Unavailable(String),
}

impl ProviderError {
    /// Project to the stable client-facing [`ClientError`] with a FIXED, client-safe message per
    /// code. The `ProviderError` inner string (a PII-free internal identifier, retained for
    /// logging/`Debug`) is intentionally NOT forwarded to the client-visible message — so projection
    /// safety is STRUCTURALLY enforced: no adapter (including the Wave-25 production adapter) can
    /// leak a raw provider reason string into `ClientError.message` even by mistake. Clients switch
    /// on the stable code, not the message (§2.12).
    pub fn into_client_error(self) -> ClientError {
        let (code, message): (ClientErrorCode, &'static str) = match self {
            ProviderError::NotFound(_) => (ClientErrorCode::NotFound, "resource not found"),
            ProviderError::NotAuthorized(_) => {
                (ClientErrorCode::ReplyNotAuthorized, "reply not authorized")
            }
            ProviderError::InvalidState(_) => (
                ClientErrorCode::InvalidState,
                "operation not valid for the resource's current state",
            ),
            ProviderError::Forbidden(_) => (ClientErrorCode::Forbidden, "insufficient scope"),
            ProviderError::TooLarge(_) => (ClientErrorCode::RequestTooLarge, "request too large"),
            ProviderError::Unavailable(_) => {
                (ClientErrorCode::ModuleUnavailable, "provider unavailable")
            }
        };
        ClientError::new(code, message)
    }
}

/// Run-control provider (MODULE-008, CONTRACT-070/071). Run CREATION is NOT here — runs are created
/// via messaging/submit and appear in [`list_runs`](RunControlProvider::list_runs).
pub trait RunControlProvider: Send + Sync {
    fn list_runs(&self) -> Result<Vec<ClientRunSummary>, ProviderError>;
    fn agent_tree(&self) -> Result<Vec<ClientAgentTreeNode>, ProviderError>;
    fn pause(&self, run_id: &str, reason: Option<&str>)
        -> Result<ClientRunMutation, ProviderError>;
    fn resume(
        &self,
        run_id: &str,
        reason: Option<&str>,
    ) -> Result<ClientRunMutation, ProviderError>;
    fn cancel(
        &self,
        run_id: &str,
        reason: Option<&str>,
    ) -> Result<ClientRunMutation, ProviderError>;
}

/// Messaging provider (MODULE-006, CONTRACT-050). The client-adapter sender identity (an agent-style
/// id present in the tree) is owned by the adapter, not the client-api layer.
pub trait MessagingProvider: Send + Sync {
    fn send(&self, to: &str, payload: &[u8]) -> Result<ClientMessageAck, ProviderError>;
    fn message_status(&self, message_id: &str) -> Result<ClientMessageStatus, ProviderError>;
}

/// Tool/skill/MCP inventory provider (MODULE-017, CONTRACT-165). The returned inventory is already
/// grant-filtered + client-safe projected.
pub trait ToolsProvider: Send + Sync {
    fn inventory(&self, agent_id: &str) -> Result<ClientToolInventory, ProviderError>;
}

/// An interior-mutable provider slot: `None` until the composition root injects a concrete adapter.
pub type ProviderSlot<T> = Arc<RwLock<Option<Arc<T>>>>;
pub type RunProviderSlot = ProviderSlot<dyn RunControlProvider>;
pub type MessagingProviderSlot = ProviderSlot<dyn MessagingProvider>;
pub type ToolsProviderSlot = ProviderSlot<dyn ToolsProvider>;
/// m020-s3: event provider / leak detector / cursor codec slots.
pub type EventProviderSlot = ProviderSlot<dyn ClientEventProvider>;
pub type LeakDetectorSlot = ProviderSlot<dyn LeakDetector>;
pub type CursorCodecSlot = ProviderSlot<dyn ClientCursorCodec>;
pub type BoundGrantProviderSlot = ProviderSlot<dyn BoundGrantApprovalPort>;
pub type BoundHistoryProviderSlot = ProviderSlot<dyn BoundHistoryReadPort>;
pub type ObservationRedactorSlot = ProviderSlot<SensitiveObservationRedactor>;
/// Read a provider out of its slot (cloning the `Arc` and releasing the lock before the call), or a
/// `module_unavailable` denial when the slot is empty. This is the ONLY absence discriminator.
pub(crate) fn provider_or_unavailable<T: ?Sized>(
    slot: &ProviderSlot<T>,
) -> Result<Arc<T>, ClientError> {
    let guard = slot.read().unwrap_or_else(|e| e.into_inner());
    guard
        .as_ref()
        .map(Arc::clone)
        .ok_or_else(|| ClientError::new(ClientErrorCode::ModuleUnavailable, "provider not wired"))
}

/// Same as [`provider_or_unavailable`] with an exact static absence message (event path D8).
pub(crate) fn provider_or_unavailable_msg<T: ?Sized>(
    slot: &ProviderSlot<T>,
    message: &'static str,
) -> Result<Arc<T>, ClientError> {
    let guard = slot.read().unwrap_or_else(|e| e.into_inner());
    guard
        .as_ref()
        .map(Arc::clone)
        .ok_or_else(|| ClientError::new(ClientErrorCode::ModuleUnavailable, message))
}
