//! Production adapters wiring cap-lifecycle's enforcement seams to cap-grant's
//! CONTRACT-122 subset rules (MODULE-005-AC-06 + MODULE-013-AC-15;
//! m013-slice-e, 2026-05-23).
//!
//! Two types:
//! - [`CapGrantSubsetAdapter`] — production [`SpawnerSubsetGate`] impl wrapping
//!   `cap_grant::validate_capability_subset`. Used by `DefaultSpawner` for the
//!   spawn-child / spawn-sub enforcement points.
//! - [`SubsetCheckedComponentSubmit`] — Rust-API wrapper around any
//!   `Arc<dyn ComponentSubmitGate>` + `Arc<dyn SpawnerSubsetGate>` that
//!   performs the Capability-first subset check BEFORE delegating to the
//!   inner gate. The submit-component enforcement point.
//!
//! WIT-level submit-component continues to pass `Vec::new()` capabilities
//! into the inner `ComponentSubmitGate` (because `advance.wit`'s
//! `submit-component` signature does not yet lift capabilities from the
//! WASM call frame, and `advance.wit` is out-of-scope this slice). The
//! future M014 bridge that lifts capabilities MUST wire them through
//! [`SubsetCheckedComponentSubmit`] (or call
//! `cap_grant::validate_capability_subset` directly) — otherwise a
//! regression silently re-opens the fail-open path this slice closes.

use std::sync::Arc;

use advance_shared_types::agent_tree::Capability;

use cap_grant::{validate_capability_subset, CapGrantError};

use crate::component_submit::{ComponentId, ComponentSubmitConfig, ComponentSubmitGate};
use crate::error::SpawnError;
use crate::spawn::SpawnerSubsetGate;

/// Production [`SpawnerSubsetGate`] impl backed by cap-grant's Capability-first
/// `validate_capability_subset` entry. Surfaces `SpawnError::SubsetViolation`
/// for every fail path — including the defensive catch-all on non-`SubsetViolation`
/// `CapGrantError` variants (defense in depth: any unexpected error from the
/// projection MUST NOT silently approve).
pub struct CapGrantSubsetAdapter;

impl CapGrantSubsetAdapter {
    pub fn new() -> Self {
        Self
    }
}

impl Default for CapGrantSubsetAdapter {
    fn default() -> Self {
        Self::new()
    }
}

impl SpawnerSubsetGate for CapGrantSubsetAdapter {
    fn check(&self, parent: &[Capability], child: &[Capability]) -> Result<(), SpawnError> {
        match validate_capability_subset(parent, child) {
            Ok(()) => Ok(()),
            Err(CapGrantError::SubsetViolation(msg)) => Err(SpawnError::SubsetViolation(msg)),
            Err(other) => Err(SpawnError::SubsetViolation(format!(
                "cap-grant projection error: {other}"
            ))),
        }
    }
}

/// Subset-checked `submit-component` wrapper. Performs the Capability-first
/// subset check via the injected `SpawnerSubsetGate` BEFORE delegating to
/// the inner `ComponentSubmitGate`. On violation: the inner gate is NEVER
/// called and the error surfaces as `SpawnError::SubsetViolation`.
///
/// As of m017-slice-l it ALSO runs the AC-29 point-3 binary-shape admission
/// gate ([`crate::component_submit::admit_runnable_binary`]) AFTER the subset
/// check and BEFORE delegating: a non-empty submitted binary must export
/// `runnable` (mutually exclusive with `tool-exports`), else
/// `SpawnError::InvalidConfig` is returned and the inner gate is not called.
///
/// The inner `ComponentSubmitGate` may be the production scheduler bridge
/// or any stub — the wrapper only requires the trait. The `subset_gate`
/// is typically a [`CapGrantSubsetAdapter`] but any `SpawnerSubsetGate`
/// implementation is accepted (the wrapper composes orthogonally with
/// `DefaultSpawner`'s subset gate).
///
/// # TOCTOU contract (adversarial round-2 Warning 3 mitigation — m013-slice-e)
///
/// `submit_component_with_subset` takes `parent_capabilities: &[Capability]`
/// as a SNAPSHOT of the submitting agent's grant set at the moment the
/// caller wishes to gate against. Between the subset check (line 1 of
/// `submit_component_with_subset`'s body) and the inner gate's
/// `.await`-suspended delegation, the live agent-tree may revoke grants,
/// narrow capabilities, or terminate the agent — the wrapper does NOT
/// re-validate, hold a tree-read-lock across the await, or thread the
/// snapshot into the inner gate.
///
/// **Caller responsibility**: capture `parent_capabilities` from the
/// `AgentTreeStore::snapshot()` (CONTRACT-040 Implementer Invariant 2)
/// at the same time the request is constructed; do NOT rely on the
/// snapshot reflecting live tree state after `submit_component_with_subset`
/// returns. Defense-in-depth at the downstream invocation gate (cap-grant
/// `GrantCheckImpl::check`) re-validates against the live grant store at
/// every host-call boundary — the subset gate here is the admission-time
/// gate, not a runtime invariant.
pub struct SubsetCheckedComponentSubmit {
    inner: Arc<dyn ComponentSubmitGate>,
    subset_gate: Arc<dyn SpawnerSubsetGate>,
}

impl SubsetCheckedComponentSubmit {
    pub fn new(
        inner: Arc<dyn ComponentSubmitGate>,
        subset_gate: Arc<dyn SpawnerSubsetGate>,
    ) -> Self {
        Self { inner, subset_gate }
    }

    /// Subset-checked submit. `parent_capabilities` is the submitting agent's
    /// active grant set; `requested_capabilities` is what the component
    /// requests. On capability-subset violation: `Err(SpawnError::SubsetViolation)`
    /// is returned BEFORE the inner gate is called (no side effect at the inner
    /// gate). On binary-shape violation (AC-29 point 3 — a non-empty binary that
    /// does not export `runnable`): `Err(SpawnError::InvalidConfig)` is returned,
    /// also before the inner gate.
    pub async fn submit_component_with_subset(
        &self,
        submitter: &str,
        config: ComponentSubmitConfig,
        parent_capabilities: &[Capability],
        requested_capabilities: &[Capability],
    ) -> Result<ComponentId, SpawnError> {
        self.subset_gate
            .check(parent_capabilities, requested_capabilities)?;
        // AC-29 point 3 (m017-slice-l): binary-shape admission. Runs AFTER the
        // capability-subset check and BEFORE the inner gate, so a shape
        // rejection — like a subset rejection — never reaches the inner gate.
        // An empty binary passes through (pre-advance.wit-lift placeholder).
        crate::component_submit::admit_runnable_binary(&config.binary)?;
        self.inner.submit_component(submitter, config).await
    }
}
