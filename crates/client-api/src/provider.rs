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

use crate::agents::{
    ClientAgentDeleteResult, ClientAgentDetail, ClientAgentSummary, ClientAgentTemplate,
    ClientCreateAgentRequest, ClientDeleteAgentRequest, ClientUpdateAgentRequest,
};
use crate::costs::{
    ClientAgentCostEntry, ClientAgentCostReport, ClientProviderCostEntry, ClientProviderCostReport,
    ValidatedCostWindow,
};
use crate::cursor::ClientCursorCodec;
use crate::envelope::{ClientError, ClientErrorCode};
use crate::events::ClientEventProvider;
use crate::messages::{ClientMessageAck, ClientMessageStatus};
use crate::packs::{
    ClientPackDetail, ClientPackInstallRequest, ClientPackInstallResult, ClientPackSummary,
    ClientPackUninstallResult,
};
use crate::provider_admin::{
    ClientCreateProviderRequest, ClientProviderDeleteResult, ClientProviderKeyResult,
    ClientProviderPreflightResult, ClientProviderSummary, ClientUpdateProviderRequest,
    ProviderAdminOutcome,
};
use crate::providers::grants::BoundGrantApprovalPort;
use crate::providers::history::BoundHistoryReadPort;
use crate::runs::{ClientAgentTreeNode, ClientRunMutation, ClientRunSummary};
use crate::tools::ClientToolInventory;

/// The `ClientError.details` token carried by an `invalid_request` whose cause is an agent
/// `llm.provider` that names no configured `llm-providers[].id` (lane agent-llm-policy).
pub const UNKNOWN_PROVIDER_DETAIL: &str = "unknown_provider";

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
    /// The resource a create names already exists (agent id / workspace territory taken).
    /// → `already_exists`
    AlreadyExists(String),
    /// The request is well-formed at the envelope level but semantically invalid for the
    /// provider (unknown template, unparseable config document, a root agent named by a delete,
    /// a Sub named as a parent, …). → `invalid_request`
    InvalidRequest(String),
    /// Lane agent-llm-policy: an agent's `llm.provider` names an `llm-providers[].id` that is
    /// not in the live runtime config. → `invalid_request` with details `["unknown_provider"]`
    /// (the ONE stable detail token clients may switch on; the inner id is log-only).
    UnknownProvider(String),
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
            ProviderError::AlreadyExists(_) => {
                (ClientErrorCode::AlreadyExists, "resource already exists")
            }
            ProviderError::InvalidRequest(_) => {
                (ClientErrorCode::InvalidRequest, "invalid request")
            }
            ProviderError::UnknownProvider(_) => {
                return ClientError::new(ClientErrorCode::InvalidRequest, "invalid request")
                    .with_details(vec![UNKNOWN_PROVIDER_DETAIL.to_string()]);
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

/// Agent administration provider (MODULE-005 tree + workspace territories, CONTRACT-040/041 host
/// side) behind the `agents` family. The adapter owns the real `AgentTreeStore`, spawner, terminate
/// controller, and the `.agent/config.yaml` / display-name files; every argument it receives has
/// already passed the handler-side validation in [`crate::agents`]. Read results are client-safe
/// projections (workspace paths are workspace-root-relative, never absolute host paths).
pub trait AgentAdminProvider: Send + Sync {
    fn list_agents(&self) -> Result<Vec<ClientAgentSummary>, ProviderError>;
    fn get_agent(&self, agent_id: &str) -> Result<ClientAgentDetail, ProviderError>;
    /// Materialize a child agent under `request.parent` (root by default), record it in the
    /// declared hierarchy so it survives a daemon restart, and return its detail document.
    fn create_agent(
        &self,
        request: &ClientCreateAgentRequest,
    ) -> Result<ClientAgentDetail, ProviderError>;
    /// Replace the display name and/or the config document (validated before the write).
    fn update_agent(
        &self,
        agent_id: &str,
        request: &ClientUpdateAgentRequest,
    ) -> Result<ClientAgentDetail, ProviderError>;
    /// Terminate the agent and every descendant (the MODULE-005 cascade), remove it from the
    /// declared hierarchy, and remove its `.agent/` marker (plus the workspace when requested).
    fn delete_agent(
        &self,
        agent_id: &str,
        request: &ClientDeleteAgentRequest,
    ) -> Result<ClientAgentDeleteResult, ProviderError>;
    fn list_templates(&self) -> Result<Vec<ClientAgentTemplate>, ProviderError>;
}

/// LLM spend attribution provider (MODULE-019 durable cost ledger, lane cost-attribution) behind
/// the `costs` family. The adapter binds the runtime's `CostLedgerQuery` (persisted
/// `llm.response` rows, survives restart) and projects to client DTOs. Every id/window it receives
/// has already passed handler-side validation in [`crate::costs`]. Unknown ids answer the zero
/// aggregate (the ledger does not know the agent tree); a failed store read is `Unavailable`.
pub trait CostProvider: Send + Sync {
    /// Per-agent totals, `cost_usd` descending then agent id.
    fn agent_totals(
        &self,
        window: &ValidatedCostWindow,
    ) -> Result<Vec<ClientAgentCostEntry>, ProviderError>;
    /// One agent's total + split by provider id.
    fn agent_report(
        &self,
        agent_id: &str,
        window: &ValidatedCostWindow,
    ) -> Result<ClientAgentCostReport, ProviderError>;
    /// Per-provider totals, `cost_usd` descending then provider id.
    fn provider_totals(
        &self,
        window: &ValidatedCostWindow,
    ) -> Result<Vec<ClientProviderCostEntry>, ProviderError>;
    /// One provider's total + split by agent id.
    fn provider_report(
        &self,
        provider_id: &str,
        window: &ValidatedCostWindow,
    ) -> Result<ClientProviderCostReport, ProviderError>;
}

/// Pack administration provider (MODULE-018 pack system) behind the `packs` family. The cli
/// adapter binds the ONE production `PackRegistry` (rescanned at boot and after every install /
/// uninstall) plus an `Installer` built from `RuntimeConfig.pack` (trust roots, registry url,
/// fetch timeout, capability catalog). Every id / request it receives has already passed
/// handler-side validation in [`crate::packs`].
///
/// Error projection: a pack that is already installed → `AlreadyExists`; an unknown
/// `{name}@{version}` → `NotFound`; an uninstall blocked by dependents → `InvalidState`; a
/// manifest whose `required-capabilities` exceed the request's `accepted_capabilities` →
/// `Forbidden`; a malformed / unsigned-but-claiming / checksum-failing pack → `InvalidRequest`;
/// a fetch / IO failure → `Unavailable`.
pub trait PackAdminProvider: Send + Sync {
    /// Installed packs, ordered by name then version.
    fn list_packs(&self) -> Result<Vec<ClientPackSummary>, ProviderError>;
    /// One installed pack with its declared provides.
    fn get_pack(&self, name: &str, version: &str) -> Result<ClientPackDetail, ProviderError>;
    /// Run the full install flow (source → fetch → checksum → approval → deps → copy → index →
    /// rescan) with the request's accepted capabilities as the approval decision.
    fn install_pack(
        &self,
        request: &ClientPackInstallRequest,
    ) -> Result<ClientPackInstallResult, ProviderError>;
    /// Remove an installed pack (refused while another installed pack depends on it).
    fn uninstall_pack(
        &self,
        name: &str,
        version: &str,
    ) -> Result<ClientPackUninstallResult, ProviderError>;
}

/// LLM provider administration provider (MODULE-001 `llm-providers` config + MODULE-012 key
/// custody) behind the `providers` family (lane providers-family). The cli adapter owns the
/// workspace's `runtime-config.yaml` writer (advance-home), the daemon's LIVE `SecretStore`
/// (the same instance the LLM egress chain resolves keys from — a second `FileSecretStorage`
/// would not see the write), the config watcher it waits on for the applied reload, and the
/// first-open preflight port. Every id / request it receives has already passed handler-side
/// validation in [`crate::provider_admin`]. Summaries never carry key material.
///
/// Error projection: unknown id → `NotFound`; duplicate id → `AlreadyExists`; the runtime's
/// `load_config` rejecting the rewritten document → `InvalidRequest`; deleting the last entry
/// or an entry an agent's `llm.provider` pins → `InvalidState`; a config / secret-store read or
/// write failure → `Unavailable`. A FAILED preflight is not an error: `set_key` answers
/// `stored: false` with the verdict and leaves the old key untouched.
pub trait ProviderAdminProvider: Send + Sync {
    /// Every entry in YAML order (index 0 is `selected`).
    fn list_providers(&self) -> Result<Vec<ClientProviderSummary>, ProviderError>;
    fn get_provider(&self, provider_id: &str) -> Result<ClientProviderSummary, ProviderError>;
    /// Append a new entry (never selected unless it is the only one) — no key material.
    fn create_provider(
        &self,
        request: &ClientCreateProviderRequest,
    ) -> Result<ProviderAdminOutcome<ClientProviderSummary>, ProviderError>;
    /// Replace the request's fields on an existing entry; untouched keys survive verbatim.
    fn update_provider(
        &self,
        provider_id: &str,
        request: &ClientUpdateProviderRequest,
    ) -> Result<ProviderAdminOutcome<ClientProviderSummary>, ProviderError>;
    /// Remove an entry (refused for the last one / a referenced one). Stored keys are kept.
    fn delete_provider(
        &self,
        provider_id: &str,
    ) -> Result<ProviderAdminOutcome<ClientProviderDeleteResult>, ProviderError>;
    /// Preflight (cloud-http) then store the key under the entry's `api-key-secret` name.
    fn set_key(
        &self,
        provider_id: &str,
        key: &str,
    ) -> Result<ProviderAdminOutcome<ClientProviderKeyResult>, ProviderError>;
    /// Drop the stored key (no-op when absent).
    fn clear_key(&self, provider_id: &str) -> Result<ClientProviderSummary, ProviderError>;
    /// Re-check the stored key against the provider's generate path.
    fn preflight(&self, provider_id: &str) -> Result<ClientProviderPreflightResult, ProviderError>;
    /// Move the entry to index 0 (the runtime's default provider).
    fn select_provider(
        &self,
        provider_id: &str,
    ) -> Result<ProviderAdminOutcome<ClientProviderSummary>, ProviderError>;
}

/// An interior-mutable provider slot: `None` until the composition root injects a concrete adapter.
pub type ProviderSlot<T> = Arc<RwLock<Option<Arc<T>>>>;
pub type RunProviderSlot = ProviderSlot<dyn RunControlProvider>;
pub type MessagingProviderSlot = ProviderSlot<dyn MessagingProvider>;
pub type ToolsProviderSlot = ProviderSlot<dyn ToolsProvider>;
pub type AgentProviderSlot = ProviderSlot<dyn AgentAdminProvider>;
pub type CostProviderSlot = ProviderSlot<dyn CostProvider>;
pub type PackProviderSlot = ProviderSlot<dyn PackAdminProvider>;
pub type ProviderAdminSlot = ProviderSlot<dyn ProviderAdminProvider>;
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
