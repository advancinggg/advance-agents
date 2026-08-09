//! Slice C — `submit-component` WIT family seam (MODULE-005 AC-01).
//!
//! `ComponentSubmitGate` mirrors CONTRACT-130 `scheduler::ComponentSubmitApi`
//! at the **trait-signature** level (async; same method names; the canonical
//! `list_components` returns a bare `Vec`, NOT a `Result`). This is the same
//! dependency-inversion discipline as Slice-A `SpawnerSubsetGate` and Slice-B
//! `WorkspaceRollbackGate` — NO library-side impl; the production
//! scheduler-bridge is a downstream M014 slice.
//!
//! **Drift discipline (R4-W6, honest):** cap-lifecycle deliberately does NOT
//! take a `scheduler` crate dependency (that would invert the M014→M005
//! contract direction). The authoritative shapes are
//! `scheduler::{ComponentSubmitConfig, ComponentInfo, ComponentState,
//! ComponentId}` and `scheduler::ComponentSubmitApi`; the production bridge
//! adapter (M014-side) converts between these local mirrors and the scheduler
//! types. There is intentionally NO compile-time byte-for-byte static-assert
//! (it would require the declined scheduler dep) — drift discipline is this
//! rustdoc pointer plus the WIT-registration test confirming the handler
//! dispatches. The local mirrors are deliberately minimal: AC-06's
//! subset-enforcement at `submit-component` now ships in Slice E
//! (m013-slice-e, 2026-05-23) via the [`SubsetCheckedComponentSubmit`]
//! adapter (see `cap_grant_adapter.rs`). The adapter wraps an inner
//! `ComponentSubmitGate` and performs the Capability-first subset check
//! BEFORE delegation. CONTRACT-217 v0.2 now lifts the complete configuration,
//! including capability requests, binary bytes, triggers, grants, retry policy,
//! and sensitive names. The production M014 bridge routes capability requests
//! through the scheduler's injected submitter-subset gate; unrepresentable
//! parameterized requests are rejected rather than silently widened.
//!
//! [`SubsetCheckedComponentSubmit`]: crate::cap_grant_adapter::SubsetCheckedComponentSubmit

/// Mirror of `scheduler::ComponentId`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ComponentId(pub String);

/// Minimal mirror of `scheduler::ComponentSubmitConfig` — only the fields the
/// WIT lift populates pre-bridge. The production M014 bridge maps this onto
/// the full `scheduler::ComponentSubmitConfig` (component_type / trigger /
/// restart_policy / retry / grants sub-tree).
#[derive(Clone, Debug, PartialEq)]
pub struct ComponentSubmitConfig {
    pub id: String,
    /// `cron` / `daemon` / `watcher` / `task` — opaque string at the M005
    /// seam; the bridge parses it into `scheduler::ComponentType`.
    pub component_type: String,
    pub binary: Vec<u8>,
    /// Raw capability request descriptors (opaque at this seam).
    pub capabilities: Vec<String>,
    pub output_dir: Option<String>,
}

/// CONTRACT-217 canonical v0.2 submission carrier.
///
/// The complete WIT record is retained as canonical JSON so the M005 boundary
/// cannot silently synthesize or discard scheduler fields.  The production
/// M014 bridge performs the typed `ComponentSubmitConfig` decode.  Keeping the
/// legacy mirror above lets old Rust-only test gates remain source compatible;
/// the public WIT path exclusively calls [`ComponentSubmitGate::submit_component_v2`].
#[derive(Clone, Debug, PartialEq)]
pub struct ComponentSubmitConfigV2 {
    canonical: serde_json::Value,
}

impl ComponentSubmitConfigV2 {
    pub fn from_canonical_json(canonical: serde_json::Value) -> Result<Self, SpawnError> {
        let object = canonical.as_object().ok_or_else(|| {
            SpawnError::InvalidConfig("component-submit-config must be an object".to_owned())
        })?;
        const FIELDS: [&str; 12] = [
            "id",
            "component-type",
            "binary",
            "capabilities",
            "output-dir",
            "trigger",
            "restart-policy",
            "delay",
            "initial-grants",
            "preset",
            "retry",
            "sensitive-params",
        ];
        if object.len() != FIELDS.len() || FIELDS.iter().any(|field| !object.contains_key(*field)) {
            return Err(SpawnError::InvalidConfig(
                "component-submit-config has an invalid field set".to_owned(),
            ));
        }
        let names = object
            .get("sensitive-params")
            .and_then(serde_json::Value::as_array)
            .ok_or_else(|| {
                SpawnError::InvalidConfig("sensitive-params must be a list".to_owned())
            })?;
        if names.len() > 64 {
            return Err(SpawnError::InvalidConfig(
                "sensitive-params exceeds the 64-name bound".to_owned(),
            ));
        }
        let mut unique = std::collections::HashSet::with_capacity(names.len());
        for name in names {
            let name = name.as_str().ok_or_else(|| {
                SpawnError::InvalidConfig("sensitive-params names must be strings".to_owned())
            })?;
            if name.is_empty() || name.len() > 128 || !unique.insert(name) {
                return Err(SpawnError::InvalidConfig(
                    "sensitive-params names must be unique and 1..=128 UTF-8 bytes".to_owned(),
                ));
            }
        }
        Ok(Self { canonical })
    }

    pub fn canonical_json(&self) -> &serde_json::Value {
        &self.canonical
    }

    pub fn into_canonical_json(self) -> serde_json::Value {
        self.canonical
    }

    fn into_legacy(self) -> Result<ComponentSubmitConfig, SpawnError> {
        let object = self.canonical.as_object().ok_or_else(|| {
            SpawnError::InvalidConfig("component-submit-config must be an object".to_owned())
        })?;
        let extended = [
            "trigger",
            "restart-policy",
            "delay",
            "initial-grants",
            "preset",
            "retry",
        ];
        if extended
            .iter()
            .any(|field| object.get(*field).is_some_and(|value| !value.is_null()))
            || object
                .get("sensitive-params")
                .and_then(serde_json::Value::as_array)
                .is_some_and(|values| !values.is_empty())
        {
            return Err(SpawnError::InvalidConfig(
                "v0.2 fields require the production scheduler bridge".to_owned(),
            ));
        }
        let id = object
            .get("id")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| SpawnError::InvalidConfig("invalid component id".to_owned()))?
            .to_owned();
        let component_type = object
            .get("component-type")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| SpawnError::InvalidConfig("invalid component type".to_owned()))?
            .to_owned();
        let binary = object
            .get("binary")
            .and_then(serde_json::Value::as_array)
            .ok_or_else(|| SpawnError::InvalidConfig("invalid component binary".to_owned()))?
            .iter()
            .map(|value| {
                value
                    .as_u64()
                    .and_then(|byte| u8::try_from(byte).ok())
                    .ok_or_else(|| SpawnError::InvalidConfig("invalid component binary".to_owned()))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let capabilities = object
            .get("capabilities")
            .and_then(serde_json::Value::as_array)
            .ok_or_else(|| SpawnError::InvalidConfig("invalid capabilities".to_owned()))?
            .iter()
            .map(|value| {
                let cap = value.as_object().ok_or_else(|| {
                    SpawnError::InvalidConfig("invalid capability request".to_owned())
                })?;
                if cap.get("params").is_some_and(|params| !params.is_null()) {
                    return Err(SpawnError::InvalidConfig(
                        "parameterized capability requests are not representable by CONTRACT-130"
                            .to_owned(),
                    ));
                }
                cap.get("capability")
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_owned)
                    .ok_or_else(|| {
                        SpawnError::InvalidConfig("invalid capability request".to_owned())
                    })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let output_dir = object
            .get("output-dir")
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned);
        Ok(ComponentSubmitConfig {
            id,
            component_type,
            binary,
            capabilities,
            output_dir,
        })
    }
}

/// Mirror of `scheduler::ComponentState`.
#[derive(Clone, Debug, PartialEq)]
pub enum ComponentState {
    Pending,
    Running,
    Completed,
    Failed(String),
    Killed,
}

/// Mirror of `scheduler::ComponentInfo`.
#[derive(Clone, Debug, PartialEq)]
pub struct ComponentInfo {
    pub id: ComponentId,
    pub component_type: String,
    pub status: ComponentState,
    pub created_at: String,
}

use crate::error::SpawnError;

/// Mirrors `scheduler::ComponentSubmitApi` (CONTRACT-130). `list_components`
/// returns a bare `Vec` (NOT `Result`) — verbatim with the canonical
/// signature.
#[async_trait::async_trait]
pub trait ComponentSubmitGate: Send + Sync {
    /// Canonical CONTRACT-217 entry. Production adapters override this method
    /// and decode every v0.2 field into CONTRACT-130. The default is a strict
    /// compatibility path for existing Rust-only gates and rejects any field it
    /// cannot represent instead of dropping it.
    async fn submit_component_v2(
        &self,
        submitter: &str,
        config: ComponentSubmitConfigV2,
    ) -> Result<ComponentId, SpawnError> {
        self.submit_component(submitter, config.into_legacy()?)
            .await
    }

    async fn submit_component(
        &self,
        submitter: &str,
        config: ComponentSubmitConfig,
    ) -> Result<ComponentId, SpawnError>;
    async fn kill_component(&self, id: &str) -> Result<(), SpawnError>;
    async fn component_status(&self, id: &str) -> Result<ComponentState, SpawnError>;
    async fn list_components(&self) -> Vec<ComponentInfo>;
}

/// AC-29 point 3 (m017-slice-l) — `submit-component` admission gate: a submitted
/// component binary MUST export `runnable` (and, by mutual exclusion, NOT
/// `tool-exports`). Delegates to the cap-tools validator (CONTRACT-163,
/// `validate_runnable_component`); no matcher is reimplemented here.
///
/// **Empty binary → `Ok(())`** remains for legacy Rust-only compatibility gates.
/// The v0.2 WIT path lifts the actual binary and the production scheduler bridge
/// routes it through this admission gate. A NON-empty
/// binary that is not a `runnable` component — a `tool-exports` component, a
/// `tool-exports`+`runnable` mutual-exclusion violation, or unparseable bytes —
/// is rejected with [`SpawnError::InvalidConfig`].
/// Defense-in-depth size cap on a submitted component binary (adversarial round 4
/// Info): bounds the bytes the MODULE-014 bridge can feed through this gate.
/// 256 MiB matches the pack-manager skill-`tool.wasm` install bound.
pub const MAX_SUBMIT_COMPONENT_BYTES: usize = 256 * 1024 * 1024;

pub fn admit_runnable_binary(binary: &[u8]) -> Result<(), SpawnError> {
    if binary.is_empty() {
        return Ok(());
    }
    if binary.len() > MAX_SUBMIT_COMPONENT_BYTES {
        return Err(SpawnError::InvalidConfig(format!(
            "submit-component: binary exceeds max {MAX_SUBMIT_COMPONENT_BYTES} bytes ({} bytes)",
            binary.len()
        )));
    }
    cap_tools::validate_runnable_component(binary)
        .map(|_| ())
        .map_err(|e| SpawnError::InvalidConfig(format!("submit-component: {e}")))
}
