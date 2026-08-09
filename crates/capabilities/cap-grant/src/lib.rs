//! cap-grant — MODULE-013 Slice A foundation.
//!
//! Library crate providing:
//! - [`Grant`] data model + 5 supporting enums per MODULE-013 §1.4.1.
//! - [`GrantStore`] (in-memory `RwLock<HashMap>` per index, matching §2.5)
//!   + `insert / consume / expire_ids / revoke_by_grantee / cascade_revoke
//!   / cascade_by_issuer` operations.
//! - [`StaticConfigCompiler`] reading `.agent/config.yaml` per the canonical
//!   PRD §5.7.2 mapping schema.
//! - [`TtlSweeper`] (test seam + periodic spawn).
//! - [`GrantCheckImpl`] implementing CONTRACT-121.
//! - [`GrantSqliteIndex`] dual-write + cold-start recovery against a M004
//!   `SqliteIndexHandle`.
//! - 4 EventBus events (`grant.issued / .revoked / .consumed / .expired`).
//! - [`register_cap_grant`] entry point — returns an `Arc<dyn GrantCheck>`
//!   for a future MODULE-001 bootstrap slice to plug into a
//!   `CapabilityInjector`.
//!
//! Slice A is library-only (matches cap-fs / cap-secrets / cap-llm
//! Slice-A precedent). Production wiring is deferred to a future M001
//! bootstrap slice.

#![forbid(unsafe_code)]

pub mod approval_intake;
pub mod capability_subset;
pub mod cascade;
pub mod check;
pub mod compile;
pub mod data;
pub mod error;
pub mod events;
pub mod preset;
pub mod resolver;
pub mod sqlite;
pub mod store;
pub mod subset;
pub mod sweeper;
pub mod wit_impl;

pub use approval_intake::{
    GrantApprovalIntake, PendingApprovalView, MAX_PENDING_PER_CALLER, MAX_PENDING_REQUESTS,
};
pub use capability_subset::validate_capability_subset;
pub use cascade::CascadeResult;
pub use check::{AuthzLevel, GrantCheckImpl, ToolsGrantReaderImpl};
pub use compile::{StaticConfigCompiler, MAX_YAML_BYTES};
pub use data::{
    CapParam, ChainDecision, ComponentId, Grant, GrantDraft, GrantId, GrantIssuer, GrantProvenance,
    GrantRequest, GrantStatus, GrantTtl, ResolverOutcome,
};
pub use error::{CapGrantError, Result};
pub use events::{
    authz_checked_event, grant_consumed_event, grant_delegated_event, grant_expired_event,
    grant_issued_event, grant_narrowed_event, grant_revoked_event, preset_applied_event,
    resolver_invoked_event,
};
pub use preset::{
    ApplyPresetResult, Preset, PresetRegistry, PRESET_AUTONOMOUS, PRESET_RESTRICT,
    PRESET_SUPERVISED,
};
pub use resolver::{
    AutoDenyResolver, BudgetCheckResolver, ChannelApprovalDecision, ChannelApprovalError,
    ChannelApprovalPort, ChannelApprovalRequest, ChannelResolver, ParentApprovalResolver, Resolver,
    ResolverChain, ResolverContext, SubsetAutoApproveResolver,
};
pub use sqlite::GrantSqliteIndex;
pub use store::GrantStore;
pub use subset::{url_pattern_subset, SubsetValidator, SubsetValidatorImpl};
pub use sweeper::TtlSweeper;
pub use wit_impl::{
    register_agent_grant, AgentGrantBundle, AGENT_GRANT_CAPABILITY, AGENT_GRANT_NAMESPACE,
};

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use advance_database::SqliteIndexHandle;
use advance_shared_types::traits::{EventBusEmit, GrantCheck};
use tokio::task::JoinHandle;

/// Bundle returned by [`register_cap_grant`].
pub struct CapGrantHandles {
    pub store: Arc<GrantStore>,
    pub grant_check: Arc<dyn GrantCheck>,
    /// `Some` iff [`register_cap_grant`] was invoked with
    /// `sweeper_interval == Some(_)`. Holding the strong `Arc<TtlSweeper>`
    /// keeps the periodic ticker alive (the spawned task holds only a
    /// `Weak` reference); dropping this field stops the ticker on its
    /// next tick.
    pub sweeper: Option<Arc<TtlSweeper>>,
    /// `Some` iff `sweeper_interval == Some(_)`. Awaitable handle for
    /// the spawned task; not strictly required for shutdown but useful
    /// for tests that want to await termination.
    pub sweeper_handle: Option<JoinHandle<()>>,
}

/// Register the `cap-grant` foundation.
///
/// **Runtime requirement**: when `sweeper_interval == Some(_)`, this
/// function must be called from a context with an active Tokio runtime
/// (e.g. inside `#[tokio::main]` or `#[tokio::test]`), because
/// [`TtlSweeper::spawn`] calls `tokio::spawn` internally and panics if
/// no runtime is active. Pass `None` for `sweeper_interval` to skip
/// the sweeper entirely (callers can drive [`TtlSweeper::tick`]
/// themselves on a different schedule).
///
/// **Cold-start ordering** (PRD §A.18): SQLite `recover_active_grants`
/// runs FIRST (rebuilds in-memory store from `status='active'` rows);
/// THEN YAML `compile_from_path` runs and UPSERTs deterministic-id
/// `static:{grantee}:{capability}` grants on top. Side effect: a
/// previously-revoked static grant whose YAML row was never removed
/// will be RESURRECTED on next start because (a) recovery filters out
/// the revoked SQLite row and (b) YAML compile re-emits the static
/// grant and `store.insert` UPSERTs the SQLite row from `revoked` back
/// to `active`. This is intentional: PRD §A.18 declares YAML is the
/// source of truth for static-config grants; to permanently revoke a
/// static grant, remove the entry from `.agent/config.yaml`. Dynamic
/// grants (slice B+) are not affected because they use UUID ids, not
/// deterministic ones.
///
/// **Caller-side `run_migrations`**: `R2d2SqliteIndexHandle::new()`
/// already calls `run_migrations()` at construction. This function does
/// NOT call it again — double-call would be a redundant write transaction.
pub fn register_cap_grant(
    sqlite: Arc<dyn SqliteIndexHandle>,
    event_bus: Arc<dyn EventBusEmit>,
    static_config_path: Option<&Path>,
    workspace_root_agent: String,
    sweeper_interval: Option<Duration>,
) -> std::result::Result<CapGrantHandles, CapGrantError> {
    let index = GrantSqliteIndex::new(sqlite);
    index.ensure_schema()?;

    let store = Arc::new(GrantStore::new(index.clone(), event_bus.clone()));

    // Cold-start recovery (AC-18 secondary path).
    for g in index.recover_active_grants()? {
        store.insert_no_dual_write(g);
    }

    // Layer YAML on top. Deterministic ids prevent accumulation across
    // restarts (T-A7 regression).
    if let Some(p) = static_config_path {
        for g in StaticConfigCompiler::compile_from_path(p, &workspace_root_agent)? {
            store.insert(g)?;
        }
    }

    let (sweeper, sweeper_handle) = if let Some(d) = sweeper_interval {
        let s = TtlSweeper::new(store.clone(), event_bus.clone());
        let h = s.clone().spawn(d);
        (Some(s), Some(h))
    } else {
        (None, None)
    };

    let grant_check: Arc<dyn GrantCheck> = Arc::new(GrantCheckImpl::new(store.clone()));
    Ok(CapGrantHandles {
        store,
        grant_check,
        sweeper,
        sweeper_handle,
    })
}
