//! `InMemoryComponentSubmitApi` — Slice D real admission rules.
//!
//! Replaces the Slice A stub with in-memory admission logic for AC-16 / AC-17 /
//! AC-24, extended by the sched-residue slice with the adjudicated Gate-1
//! trigger-event whitelist (ADR `2026-06-10-trigger-whitelist-submit-admission-gate`)
//! and the submitter-grant subset port. Admission rules (apply in order; first
//! rejecting rule wins; **every rejection precedes the rule-6 critical section,
//! so a rejected submit consumes no quota slot, writes no registry row, and
//! inserts no store row**):
//!
//! 1. **Agent component-type forbidden** (PRD §9.5: submit-component does NOT
//!    create agent components; agents are spawned via agent-lifecycle).
//! 2. **AC-24 daemon controller-cap rejection** (PRD §3.7 daemon-as-worker
//!    constraint): daemon + any cap in {`lifecycle.spawn-child`,
//!    `lifecycle.spawn-sub`, `lifecycle.submit-decomposition`} → CapabilityDenied.
//! 3. **AC-16 daemon-no-trigger-event rejection** (recursive AnyOf walker):
//!    daemon + a trigger tree containing `TriggerEvent` (at any nesting depth
//!    bounded by `MAX_TRIGGER_NESTING_DEPTH=8`) → InvalidConfig.
//! 4. **Gate-1 trigger-event whitelist** (sched-residue; ALL component types,
//!    PRD §3.8 line 366 "非白名单事件在 submit 准入被拒"): any
//!    `TriggerEvent(sub).event_type` in the trigger tree that fails the pure
//!    `is_event_whitelisted` predicate → InvalidConfig naming the offending
//!    event_type, BEFORE registry persistence. AnyOf is fail-closed (any one
//!    offending leaf rejects the whole config). **Two-gate layering per the
//!    ADR**: this is the fail-fast, user-observable gate (CONTRACT-131
//!    `subscribe()` has no Result channel and silently no-ops on rejection);
//!    the trigger-bus subscription-admission gate (`validate_subscription`,
//!    `trigger_bus.rs`) stays authoritative for bus invariants (whitelist +
//!    caps) on every registration path incl. restart-time resubscription.
//!    Both gates consume the single `is_event_whitelisted` predicate so
//!    policy cannot drift if the whitelist becomes extensible.
//! 5. **Submitter-grant subset admission** (sched-residue; PRD §5.7.4 :1550 /
//!    §10 :3206; only when a [`SubmitSubsetGate`] is injected via
//!    `with_subset_gate`): requested capabilities not covered by the
//!    submitter's grant set → `SpawnError::SubsetViolation`. Default `None`
//!    skips the gate (byte-compatible pre-seam behavior) — see the
//!    [`SubmitSubsetGate`] rustdoc for the production-adapter obligation.
//! 6. **Happy path** (critical section): dup-check → AC-09 quota → AC-05
//!    registry write-through → store insert; return Ok.
//!
//! Storage is an in-memory `Arc<Mutex<HashMap<ComponentId, AdmissionRow>>>` —
//! the registry-backed persistence integration (AC-05) is deferred to Slice E.
//! `kill_component(id)` is **idempotent**: missing id returns Ok (no error)
//! per AC-17 "no submitter-cascade" semantic — the admission API has no
//! mapping from submitter id to component id, so admission cannot distinguish
//! "unknown id" from "submitter-id misused as component-id". Slice E may
//! revisit when full registry-backed lifecycle is wired.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::Mutex;

use crate::contracts::ComponentSubmitApi;
use crate::registry::{ComponentRegistry, ComponentRegistryRow, RegistryError};
use crate::trigger_bus::is_event_whitelisted;
use crate::trigger_source::MAX_TRIGGER_NESTING_DEPTH;
use crate::types::{
    format_rfc3339_ms, now_unix_ms, ComponentId, ComponentInfo, ComponentState,
    ComponentSubmitConfig, SpawnError, TriggerConfig, DEFAULT_MAX_SCHEDULED_COMPONENTS,
    MAX_EVENT_TYPE_LEN,
};
use advance_shared_types::agent_tree::Capability;
use advance_shared_types::capability::CapParams;
use advance_shared_types::component::ComponentType;
use advance_shared_types::contract218_previsible::{
    ComponentPublicationResult, PrevisibleProofIssuerRole,
};
use advance_shared_types::observation_identity::ComponentObservationSourceIssuer;

use crate::sensitive_params::RegistrySensitiveParamProvider;

/// Submitter-grant subset admission port (sched-residue; admission rule 5).
///
/// Resolver-style and submitter-keyed: CONTRACT-130 `submit_component` carries
/// only `submitter: &str`, so the parent grant snapshot cannot come from the
/// caller without a contract change — the gate impl owns grant resolution.
/// Sync by precedent (`cap_lifecycle::SpawnerSubsetGate` is sync; the two
/// canonical building blocks — `GrantStore::list_by_grantee` and
/// `cap_grant::validate_capability_subset` — are sync).
///
/// `requested` is the submitted config's capability list projected to
/// shared-types `Capability` with `CapParams::empty()` (= `Value::Null`,
/// whole-capability semantics — `CapRequest` is id-only today, the
/// pre-existing Slice-A PRD §9.5 deviation). A whole-capability request
/// correctly fails closed against a param-restricted parent grant.
///
/// **Production-adapter obligation** (the cap-lifecycle
/// `SubsetCheckedComponentSubmit` "future bridge MUST route through this
/// gate" contract): the composition root that wires a real gate should adapt
/// `cap_grant::validate_capability_subset` over
/// `GrantStore::list_by_grantee(submitter)` filtered to `GrantStatus::Active`,
/// re-projecting `Grant.params` CSV values back into JSON arrays (cap-grant's
/// projection rejects raw `,`-bearing strings) and handling the
/// `agent:`-prefix vs bare-id grantee duality. Map
/// `CapGrantError::SubsetViolation(msg)` → `SpawnError::SubsetViolation(msg)`
/// and EVERY other error variant to `SubsetViolation` too (fail-closed: an
/// unexpected resolver/projection error never approves — the
/// `CapGrantSubsetAdapter` precedent). Until that adapter is injected, the
/// default `None` skips this rule entirely (pre-seam behavior).
pub trait SubmitSubsetGate: Send + Sync {
    /// `Err(SpawnError::SubsetViolation)` when `requested` is not covered by
    /// the submitter's grant set; any `Err` rejects admission with zero side
    /// effects (rule 5 runs before the rule-6 critical section).
    fn check(&self, submitter: &str, requested: &[Capability]) -> Result<(), SpawnError>;
}

/// Slice E (m014-slice-e) AC-05: map a `RegistryError` from the write-through
/// `registry.insert` path onto the `ComponentSubmitApi` error surface
/// (`SpawnError`). Fail-closed: the id-UNIQUE violation surfaces as
/// `AlreadyExists`; every other registry failure (I/O, SQL, serde,
/// path-confinement, invalid-filename, not-found) collapses to
/// `InvalidConfig` so a persistence failure never silently admits a
/// component. Complete over all 7 `RegistryError` variants.
fn registry_err_to_spawn_err(e: RegistryError) -> SpawnError {
    match e {
        RegistryError::AlreadyExists(id) => {
            SpawnError::AlreadyExists(format!("component id {id} already exists"))
        }
        RegistryError::Io(m)
        | RegistryError::Sql(m)
        | RegistryError::Serde(m)
        | RegistryError::NotFound(m)
        | RegistryError::PathConfinement(m)
        | RegistryError::InvalidFilename(m)
        | RegistryError::ObservationState(m)
        | RegistryError::ObservationRecoveryRequired(m)
        | RegistryError::ObservationCapacityExceeded(m) => {
            SpawnError::InvalidConfig(format!("registry persistence failed: {m}"))
        }
    }
}

/// Capabilities forbidden on `component-type: daemon` per PRD §3.7 / REQ-031.
/// These three cap-ids elevate a worker into a controller; admission rejects.
const DAEMON_FORBIDDEN_CAPS: &[&str] = &[
    "lifecycle.spawn-child",
    "lifecycle.spawn-sub",
    "lifecycle.submit-decomposition",
];

/// Per-component row recorded at admission time. Keyed by `ComponentId` in
/// the internal HashMap.
///
/// Audit Round-2 fix: `cfg` is no longer stored in full. Slice D admission
/// does not USE the cfg fields anywhere (status/kill paths only need the
/// key set; submitter_of returns only the submitter string); persisting the
/// 64-MiB-bounded binary + capabilities + initial_grants list per accepted
/// admission was a memory-amplification surface. Slice E may re-introduce
/// the full cfg behind the registry-backed persistence path.
#[derive(Clone, Debug)]
struct AdmissionRow {
    submitter: String,
    component_type: ComponentType,
    submitted_at_ms: i64,
}

/// Slice D real-admission `ComponentSubmitApi` implementation, extended in
/// Slice E (m014-slice-e) with AC-09 per-submitter quota + AC-05 write-through
/// registry persistence.
///
/// - `store`: in-memory admission map — the source of truth for
///   `list_components`/`component_status`/`kill_component` and the AC-09
///   quota count (the registry-backed read/quota/restart-recovery path is the
///   explicitly waived Slice-E "full submit-component lifecycle integration").
/// - `registry`: optional write-through durability sink (AC-05). When `Some`,
///   the happy path persists every admitted component via `registry.insert`
///   (one-shot `interval_ms: None`); when `None`, Slice-D in-memory-only
///   behavior is preserved (back-compat).
/// - `max_scheduled`: per-submitter AC-09 quota (default
///   `DEFAULT_MAX_SCHEDULED_COMPONENTS` = 20).
///
/// **`impl Default` is hand-written, NOT derived**: a derived `Default` would
/// set `max_scheduled = 0`, making the quota gate reject every submit
/// (including the first). Same derived-`Default`-zeroes-a-cap class of bug as
/// the Slice-B `TriggerBusDispatchImpl::max_chain_depth` Round-4 Critical-1
/// fix.
pub struct InMemoryComponentSubmitApi {
    store: Arc<Mutex<HashMap<ComponentId, AdmissionRow>>>,
    registry: Option<Arc<ComponentRegistry>>,
    max_scheduled: usize,
    subset_gate: Option<Arc<dyn SubmitSubsetGate>>,
    observation_provider: Option<Arc<RegistrySensitiveParamProvider>>,
    observation_ready_issuer: Option<Arc<PrevisibleProofIssuerRole>>,
}

impl Default for InMemoryComponentSubmitApi {
    fn default() -> Self {
        Self {
            store: Arc::new(Mutex::new(HashMap::new())),
            registry: None,
            max_scheduled: DEFAULT_MAX_SCHEDULED_COMPONENTS,
            subset_gate: None,
            observation_provider: None,
            observation_ready_issuer: None,
        }
    }
}

impl InMemoryComponentSubmitApi {
    pub fn new() -> Self {
        Self::default()
    }

    /// AC-05 builder: attach a write-through `ComponentRegistry`. The happy
    /// path then persists every admitted component (one-shot row,
    /// `interval_ms: None`) before the in-memory store insert
    /// (registry-first ordering — see `submit_component`).
    pub fn with_registry(mut self, registry: Arc<ComponentRegistry>) -> Self {
        self.registry = Some(registry);
        self.observation_provider = None;
        self.observation_ready_issuer = None;
        self
    }

    /// CONTRACT-218 production persistence path. Admission rules and quota are
    /// still evaluated by this API, but the critical-section write becomes the
    /// anchored hidden→ready→published identity transaction rather than a raw
    /// registry insert.
    pub fn with_observation_provider(
        mut self,
        provider: Arc<RegistrySensitiveParamProvider>,
        ready_issuer: Arc<PrevisibleProofIssuerRole>,
    ) -> Self {
        self.registry = None;
        self.observation_provider = Some(provider);
        self.observation_ready_issuer = Some(ready_issuer);
        self
    }

    /// AC-09 builder: override the per-submitter `max-scheduled-components`
    /// quota (default `DEFAULT_MAX_SCHEDULED_COMPONENTS` = 20). A value of
    /// `0` is floored to an effective cap of `1` at the quota gate (see
    /// `submit_component`'s `effective_cap`), so `with_quota(0)` cannot
    /// brick all submission (adversarial r14 W#2b).
    pub fn with_quota(mut self, max_scheduled: usize) -> Self {
        self.max_scheduled = max_scheduled;
        self
    }

    /// sched-residue builder: attach a [`SubmitSubsetGate`] enforcing the
    /// PRD §5.7.4 submitter-grant subset rule as admission rule 5. Without
    /// this builder the gate defaults to `None` and rule 5 is skipped
    /// (byte-compatible pre-seam behavior) — enforcement requires the
    /// composition root to inject a production adapter (see the trait
    /// rustdoc for the adapter obligation).
    pub fn with_subset_gate(mut self, gate: Arc<dyn SubmitSubsetGate>) -> Self {
        self.subset_gate = Some(gate);
        self
    }

    /// **Slice D test seam** (NOT part of `ComponentSubmitApi` trait — Slice E
    /// may revisit when full registry-backed lifecycle is wired).
    ///
    /// Returns the submitter string for a registered component, or `None` if
    /// the id is unknown. Used by AC-17 verification tests in
    /// `tests/agent_submits_worker.rs` to assert "submitter recorded as
    /// metadata only" + "no submitter-cascade rule in admission".
    ///
    /// Public (NOT `pub(crate)`) because integration tests under
    /// `crates/scheduler/tests/` are external to the crate.
    ///
    /// Audit Round-3 hardening:
    /// - `async fn` + `.lock().await` (was `try_lock().ok()?` which silently
    ///   conflated lock contention with "id not found").
    /// - Routes through `ComponentId::new` to enforce `MAX_COMPONENT_ID_LEN`
    ///   (consistent with the round-2 `kill_component`/`component_status`
    ///   hardening). Over-cap id returns `None`.
    pub async fn submitter_of(&self, id: &str) -> Option<String> {
        let key = ComponentId::new(id.to_owned()).ok()?;
        let store = self.store.lock().await;
        store.get(&key).map(|row| row.submitter.clone())
    }

    /// sched-triggers (trigger-chain product pre-build): registry-backed durable
    /// read accessor.
    ///
    /// Returns the components persisted in the write-through
    /// [`ComponentRegistry`] (`registry.list()`), surfacing the **durable** rows
    /// rather than the in-memory admission map that backs the trait-level
    /// [`ComponentSubmitApi::list_components`]. A submitted component is durable
    /// and queryable here independently of the submitter's in-memory metadata
    /// (future-witness SYS-AC-108 persisted+queryable / SYS-AC-109
    /// submitter-independent durability).
    ///
    /// When no registry is configured (`with_registry` not called), returns an
    /// empty `Ok(vec![])` (back-compat — there is no durable store to read).
    ///
    /// This is an **additive inherent method**, NOT a `ComponentSubmitApi` trait
    /// method, so it introduces no contract change. It deliberately does NOT
    /// reopen the Slice-E-waived "registry-backed READ/quota/restart-recovery"
    /// path (store rebuild, quota/status/kill served from the registry); it is a
    /// thin durable-view accessor over what write-through already persists.
    pub async fn list_components_persisted(&self) -> Result<Vec<ComponentRegistryRow>, SpawnError> {
        match self.registry.as_ref() {
            Some(registry) => registry.list().await.map_err(registry_err_to_spawn_err),
            None => Ok(Vec::new()),
        }
    }
}

#[async_trait]
impl ComponentSubmitApi for InMemoryComponentSubmitApi {
    async fn submit_component(
        &self,
        submitter: &str,
        config: ComponentSubmitConfig,
    ) -> Result<ComponentId, SpawnError> {
        // Rule 1: agent-type forbidden via submit-component (PRD §9.5).
        // Runs BEFORE the lifecycle-cap check so an agent + lifecycle.spawn-child
        // still gets the agent-rejection error (not the cap-denied error).
        if config.component_type == ComponentType::Agent {
            return Err(SpawnError::InvalidConfig(
                "submit-component cannot create agent components — \
                 agents are spawned via agent-lifecycle, not submit-component"
                    .to_owned(),
            ));
        }

        // Rule 2: daemon + lifecycle controller cap → CapabilityDenied (AC-24).
        if config.component_type == ComponentType::Daemon {
            for cap in &config.capabilities {
                let cap_id = cap.capability.as_ref();
                if DAEMON_FORBIDDEN_CAPS
                    .iter()
                    .any(|forbidden| *forbidden == cap_id)
                {
                    return Err(SpawnError::CapabilityDenied(format!(
                        "daemon components cannot hold lifecycle controller \
                         capabilities: {cap_id}"
                    )));
                }
            }
        }

        // Rule 3: daemon + TriggerEvent (anywhere in trigger tree) → InvalidConfig (AC-16).
        if config.component_type == ComponentType::Daemon {
            if let Some(ref trigger) = config.trigger {
                if contains_trigger_event(trigger, 0)? {
                    return Err(SpawnError::InvalidConfig(
                        "daemon components cannot subscribe to trigger-event — \
                         Daemon is a persistent worker role, trigger-event \
                         subscriptions belong to Watcher"
                            .to_owned(),
                    ));
                }
            }
        }

        // Rule 4 (sched-residue, Gate-1 of the adjudicated two-gate
        // architecture, ADR 2026-06-10-trigger-whitelist-submit-admission-gate):
        // ANY component type whose trigger tree contains a TriggerEvent
        // subscription to a non-whitelisted event_type is rejected at submit
        // admission, BEFORE registry persistence. AnyOf is fail-closed (one
        // offending leaf rejects the whole config). The walker routes through
        // the named pure `is_event_whitelisted` predicate — the same policy
        // source as the bus-side gate (`validate_subscription`) — so the two
        // gates cannot drift.
        if let Some(ref trigger) = config.trigger {
            if let Some(offending) = find_non_whitelisted_trigger_event(trigger, 0)? {
                return Err(SpawnError::InvalidConfig(format!(
                    "trigger-event subscription to non-whitelisted event \
                     {offending:?} rejected at submit admission (PRD §3.8 \
                     Trigger Bus whitelist)"
                )));
            }
        }

        // Rule 5 (sched-residue): submitter-grant subset admission via the
        // injected port. Skipped when no gate is wired (`None` default —
        // pre-seam behavior). Runs BEFORE the critical section so a
        // SubsetViolation consumes no quota slot and persists nothing.
        if let Some(ref gate) = self.subset_gate {
            let requested: Vec<Capability> = config
                .capabilities
                .iter()
                .map(|c| Capability {
                    id: c.capability.clone(),
                    params: CapParams::empty(),
                })
                .collect();
            gate.check(submitter, &requested)?;
        }

        // Rule 6 (Slice E AC-05 + AC-09): registry-first single-
        // `tokio::sync::Mutex` critical section. `tokio::sync::Mutex` is
        // held across the `registry.insert().await` (await-safe, unlike
        // `std::sync::Mutex`; the `clippy::await_holding_lock` footgun is
        // std-only). Ordering: dup-check → AC-09 quota → AC-05 write-through
        // `registry.insert` → in-memory `store.insert` (synchronous, no
        // `.await` after the registry write). Registry-first means a
        // cancellation during the only in-section `.await` leaves `store`
        // un-mutated → no orphan in-memory row; the bounded
        // committed-registry-row-not-in-cache residual (≤1/cancellation
        // in-process quota under-count; no cross-restart self-heal) is
        // documented in §3.8 (v).
        let id = ComponentId::new(config.id.clone())?;
        let mut store = self.store.lock().await;
        if store.contains_key(&id) {
            return Err(SpawnError::AlreadyExists(format!(
                "component id {} already exists",
                id.as_str()
            )));
        }
        // AC-09: per-submitter `max-scheduled-components` quota. Counts this
        // submitter's existing admission rows in the in-memory store; the
        // (N+1)th is rejected once the count reaches the cap. Runs BEFORE
        // the registry write so an over-quota submit never persists.
        // Defensive `.max(1)` floor, symmetric with `run_expired_catchup`'s
        // `max_concurrent.max(1)`: a `with_quota(0)` (or any 0) must NOT
        // brick every submit for every submitter (self-inflicted DoS). 0
        // floors to an effective cap of 1 — the 1st submit is admitted,
        // the 2nd rejected — rather than rejecting the 1st (adversarial
        // r14 W#2b). DEFAULT (20) and any positive override are unaffected.
        let effective_cap = self.max_scheduled.max(1);
        let submitter_count = store.values().filter(|r| r.submitter == submitter).count();
        if submitter_count >= effective_cap {
            return Err(SpawnError::ResourceLimit(format!(
                "submitter {submitter} exceeds max-scheduled-components quota \
                 ({}/{})",
                submitter_count + 1,
                effective_cap
            )));
        }
        // AC-05: write-through persistence BEFORE the in-memory store insert.
        // Every admitted component persists as a one-shot row
        // (`interval_ms: None`) — admission persistence is component-type
        // agnostic; recurring `interval_ms` derivation is the waived
        // Slice-E full-lifecycle tick-tracking. On registry error the store
        // is left untouched (fail-closed: no admission without durability
        // when a registry is wired).
        if let (Some(provider), Some(ready_issuer)) = (
            self.observation_provider.as_ref(),
            self.observation_ready_issuer.as_ref(),
        ) {
            let operation_id = format!("component-submit-{}-{}", id.as_str(), now_unix_ms());
            let committed = provider
                .commit_component_unpublished(
                    operation_id,
                    submitter.to_owned(),
                    config.clone(),
                    None,
                )
                .await
                .map_err(|error| {
                    SpawnError::InvalidConfig(format!(
                        "anchored component persistence failed: {error}"
                    ))
                })?;
            let activation = provider
                .issue_component_source(&committed)
                .map_err(|error| {
                    SpawnError::InvalidConfig(format!(
                        "component observation-source issuance failed: {error:?}"
                    ))
                })?;
            let receipts = ready_issuer
                .issue_composition_ready_receipts(&activation)
                .map_err(|error| {
                    SpawnError::InvalidConfig(format!(
                        "component observation owners were not ready: {error:?}"
                    ))
                })?;
            let ready = ready_issuer
                .issue_ready_proof(&activation, receipts)
                .map_err(|error| {
                    SpawnError::InvalidConfig(format!(
                        "component ready-proof issuance failed: {error:?}"
                    ))
                })?;
            let mut publication = provider.publish_component_source(activation, ready);
            loop {
                publication = match publication {
                    ComponentPublicationResult::Published(_) => break,
                    ComponentPublicationResult::Rejected(_) => {
                        return Err(SpawnError::InvalidConfig(
                            "anchored component publication was rejected".to_owned(),
                        ));
                    }
                    ComponentPublicationResult::OutcomeUnknown(recovery) => {
                        provider.recover_component_publication(recovery)
                    }
                };
            }
        } else if self.observation_provider.is_some() || self.observation_ready_issuer.is_some() {
            return Err(SpawnError::InvalidConfig(
                "incomplete CONTRACT-218 component persistence composition".to_owned(),
            ));
        } else if let Some(ref registry) = self.registry {
            registry
                .insert(submitter, &config, None)
                .await
                .map_err(registry_err_to_spawn_err)?;
        }
        let row = AdmissionRow {
            submitter: submitter.to_owned(),
            component_type: config.component_type,
            submitted_at_ms: now_unix_ms(),
        };
        store.insert(id.clone(), row);
        Ok(id)
    }

    async fn kill_component(&self, id: &str) -> Result<(), SpawnError> {
        // Slice D semantic: idempotent. Missing id returns Ok (no cascade rule).
        // The admission API has no submitter→component mapping, so it cannot
        // distinguish "unknown id" from "submitter-id misused as component-id".
        // Audit Round-2 fix: route through `ComponentId::new` to enforce
        // MAX_COMPONENT_ID_LEN at the kill/status entry surface — defends
        // against a multi-MB `id` argument allocating a HashMap key.
        // Over-cap id is treated as "unknown id" (Ok-idempotent).
        let key = match ComponentId::new(id.to_owned()) {
            Ok(k) => k,
            Err(_) => return Ok(()),
        };
        let mut store = self.store.lock().await;
        store.remove(&key);
        Ok(())
    }

    async fn component_status(&self, id: &str) -> Result<ComponentState, SpawnError> {
        // Audit Round-2 fix: route through `ComponentId::new` to enforce
        // MAX_COMPONENT_ID_LEN at lookup time. Over-cap id is treated as
        // "not found" (matching the existing missing-id return path).
        let key = match ComponentId::new(id.to_owned()) {
            Ok(k) => k,
            Err(_) => return Err(SpawnError::InvalidConfig(format!("not found: {id}"))),
        };
        let store = self.store.lock().await;
        if store.contains_key(&key) {
            // Slice D admission ships all components as Pending — driver-side
            // lifecycle transitions land in Slice E.
            Ok(ComponentState::Pending)
        } else {
            Err(SpawnError::InvalidConfig(format!("not found: {id}")))
        }
    }

    async fn list_components(&self) -> Vec<ComponentInfo> {
        let store = self.store.lock().await;
        store
            .iter()
            .map(|(id, row)| ComponentInfo {
                id: id.clone(),
                component_type: row.component_type,
                status: ComponentState::Pending,
                created_at: format_rfc3339_ms(row.submitted_at_ms),
            })
            .collect()
    }
}

/// Recursive walker over a `TriggerConfig` tree looking for any `TriggerEvent`
/// variant — used by rule 3 (AC-16) to reject daemon admission for TriggerEvent
/// subscriptions anywhere in the trigger tree (including nested inside `AnyOf`).
///
/// Depth-cap: reuses `MAX_TRIGGER_NESTING_DEPTH = 8` from `trigger_source.rs`.
/// Depth exceeded returns `Err(InvalidConfig(...))` (fail-closed). This is a
/// correctness gate on the already-deserialized tree; serde's per-level
/// `MAX_ANY_OF = 64` width cap + `MAX_WIRE_BYTES_LEN = 64 MiB` are the
/// operative DoS bounds at Deserialize time.
fn contains_trigger_event(t: &TriggerConfig, depth: usize) -> Result<bool, SpawnError> {
    if depth > MAX_TRIGGER_NESTING_DEPTH {
        return Err(SpawnError::InvalidConfig(format!(
            "TriggerConfig nesting depth {depth} exceeds \
             MAX_TRIGGER_NESTING_DEPTH {MAX_TRIGGER_NESTING_DEPTH} during admission"
        )));
    }
    match t {
        TriggerConfig::TriggerEvent(_) => Ok(true),
        TriggerConfig::AnyOf(children) => {
            for c in children {
                if contains_trigger_event(c, depth + 1)? {
                    return Ok(true);
                }
            }
            Ok(false)
        }
        // Leaf variants without nested TriggerConfig: Schedule, FileWatch, Webhook.
        TriggerConfig::Schedule(_) | TriggerConfig::FileWatch(_) | TriggerConfig::Webhook(_) => {
            Ok(false)
        }
    }
}

/// Recursive walker over a `TriggerConfig` tree returning the first
/// `TriggerEvent` leaf whose `event_type` fails the PRD §3.8 whitelist —
/// used by admission rule 4 (sched-residue Gate-1, ADR
/// `2026-06-10-trigger-whitelist-submit-admission-gate`). Deliberately a
/// SIBLING of [`contains_trigger_event`] (which stays byte-stable for the
/// AC-16 daemon rule) rather than an extension: rule 3 is daemon-only,
/// rule 4 applies to ALL component types.
///
/// Per-leaf checks, in `validate_subscription`'s order (gate-2 symmetry):
/// 1. `event_type.len() > MAX_EVENT_TYPE_LEN` (= 128) → `Err(InvalidConfig)`
///    length message. Defense-in-depth: serde already caps wire strings at
///    `MAX_WIRE_STRING_LEN` (4096), but in-memory-constructed configs never
///    pass serde, and the length-first order bounds the whitelist-miss
///    error echo to ≤128 bytes.
/// 2. `!is_event_whitelisted(event_type)` → `Ok(Some(event_type))` (the
///    offending leaf, surfaced into the rule-4 `InvalidConfig` message).
///    MUST stay routed through the named pure predicate (never an inline
///    `WHITELIST.contains`) per the ADR's single-predicate no-drift rule.
///
/// Depth-cap: reuses `MAX_TRIGGER_NESTING_DEPTH = 8` (fail-closed
/// `Err(InvalidConfig)` on overflow), identical to `contains_trigger_event`.
fn find_non_whitelisted_trigger_event<'t>(
    t: &'t TriggerConfig,
    depth: usize,
) -> Result<Option<&'t str>, SpawnError> {
    if depth > MAX_TRIGGER_NESTING_DEPTH {
        return Err(SpawnError::InvalidConfig(format!(
            "TriggerConfig nesting depth {depth} exceeds \
             MAX_TRIGGER_NESTING_DEPTH {MAX_TRIGGER_NESTING_DEPTH} during admission"
        )));
    }
    match t {
        TriggerConfig::TriggerEvent(sub) => {
            if sub.event_type.len() > MAX_EVENT_TYPE_LEN {
                return Err(SpawnError::InvalidConfig(format!(
                    "trigger-event event_type length {} exceeds MAX_EVENT_TYPE_LEN \
                     {MAX_EVENT_TYPE_LEN} during admission",
                    sub.event_type.len()
                )));
            }
            if !is_event_whitelisted(&sub.event_type) {
                Ok(Some(sub.event_type.as_str()))
            } else {
                Ok(None)
            }
        }
        TriggerConfig::AnyOf(children) => {
            for c in children {
                if let Some(offending) = find_non_whitelisted_trigger_event(c, depth + 1)? {
                    return Ok(Some(offending));
                }
            }
            Ok(None)
        }
        // Leaf variants without nested TriggerConfig: Schedule, FileWatch, Webhook.
        TriggerConfig::Schedule(_) | TriggerConfig::FileWatch(_) | TriggerConfig::Webhook(_) => {
            Ok(None)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::TriggerSubscription;
    use advance_shared_types::capability::{CapRequest, CapabilityId};

    fn dummy_task_config() -> ComponentSubmitConfig {
        ComponentSubmitConfig {
            sensitive_params: Vec::new(),
            id: "x".into(),
            component_type: ComponentType::Task,
            binary: Vec::new(),
            capabilities: Vec::new(),
            output_dir: None,
            trigger: None,
            restart_policy: None,
            delay: None,
            initial_grants: None,
            preset: None,
            retry: None,
        }
    }

    #[tokio::test]
    async fn submit_component_default_config_accepted() {
        // Slice D rewrite: Slice A stub returned Err on every call; now the
        // happy path (Task component-type, no caps, no trigger) returns Ok.
        let api = InMemoryComponentSubmitApi::new();
        let id = api
            .submit_component("agent:root", dummy_task_config())
            .await
            .expect("happy path should accept");
        assert_eq!(id.as_str(), "x");
    }

    #[tokio::test]
    async fn submit_component_agent_type_rejected() {
        let api = InMemoryComponentSubmitApi::new();
        let mut cfg = dummy_task_config();
        cfg.component_type = ComponentType::Agent;
        cfg.id = "a".into();
        let err = api.submit_component("agent:root", cfg).await.unwrap_err();
        match err {
            SpawnError::InvalidConfig(msg) => {
                assert!(msg.contains("agent components"), "unexpected msg: {msg}");
            }
            other => panic!("expected InvalidConfig, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn submit_component_daemon_with_lifecycle_cap_rejected() {
        let api = InMemoryComponentSubmitApi::new();
        let mut cfg = dummy_task_config();
        cfg.component_type = ComponentType::Daemon;
        cfg.id = "d".into();
        cfg.capabilities = vec![CapRequest {
            capability: CapabilityId::new("lifecycle.spawn-child"),
        }];
        let err = api.submit_component("agent:root", cfg).await.unwrap_err();
        assert!(matches!(err, SpawnError::CapabilityDenied(_)));
    }

    #[tokio::test]
    async fn submit_component_daemon_with_trigger_event_rejected() {
        let api = InMemoryComponentSubmitApi::new();
        let mut cfg = dummy_task_config();
        cfg.component_type = ComponentType::Daemon;
        cfg.id = "d2".into();
        cfg.trigger = Some(TriggerConfig::TriggerEvent(TriggerSubscription {
            event_type: "grant.issued".into(),
            filter: None,
            debounce_ms: None,
        }));
        let err = api.submit_component("agent:root", cfg).await.unwrap_err();
        match err {
            SpawnError::InvalidConfig(msg) => {
                assert!(msg.contains("daemon"), "unexpected msg: {msg}");
                assert!(msg.contains("trigger-event"), "unexpected msg: {msg}");
            }
            other => panic!("expected InvalidConfig, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn kill_component_missing_id_is_idempotent() {
        // Slice D semantic shift: Slice A stub returned Err; now Ok-idempotent.
        let api = InMemoryComponentSubmitApi::new();
        api.kill_component("comp-a")
            .await
            .expect("missing id should be idempotent Ok");
    }

    #[tokio::test]
    async fn component_status_missing_id_returns_err() {
        let api = InMemoryComponentSubmitApi::new();
        let err = api.component_status("comp-a").await.unwrap_err();
        assert!(matches!(err, SpawnError::InvalidConfig(_)));
    }

    #[tokio::test]
    async fn list_components_returns_empty_vec_when_no_submits() {
        let api = InMemoryComponentSubmitApi::new();
        let v = api.list_components().await;
        assert!(v.is_empty());
    }

    #[tokio::test]
    async fn submit_then_list_returns_one() {
        let api = InMemoryComponentSubmitApi::new();
        let _ = api
            .submit_component("agent:root", dummy_task_config())
            .await
            .unwrap();
        let v = api.list_components().await;
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].id.as_str(), "x");
    }

    #[tokio::test]
    async fn submit_duplicate_id_returns_already_exists() {
        let api = InMemoryComponentSubmitApi::new();
        let _ = api
            .submit_component("agent:root", dummy_task_config())
            .await
            .unwrap();
        let err = api
            .submit_component("agent:root", dummy_task_config())
            .await
            .unwrap_err();
        assert!(matches!(err, SpawnError::AlreadyExists(_)));
    }

    // ── sched-residue: direct walker unit coverage (rule 4 helper) ──

    fn sub(event_type: &str) -> TriggerConfig {
        TriggerConfig::TriggerEvent(TriggerSubscription {
            event_type: event_type.into(),
            filter: None,
            debounce_ms: None,
        })
    }

    #[test]
    fn walker_top_level_offender_found() {
        let t = sub("fs.write");
        assert_eq!(
            find_non_whitelisted_trigger_event(&t, 0).unwrap(),
            Some("fs.write")
        );
    }

    #[test]
    fn walker_nested_offender_found() {
        let t = TriggerConfig::AnyOf(vec![
            sub("grant.issued"),
            TriggerConfig::AnyOf(vec![sub("secrets.read")]),
        ]);
        assert_eq!(
            find_non_whitelisted_trigger_event(&t, 0).unwrap(),
            Some("secrets.read")
        );
    }

    #[test]
    fn walker_clean_tree_none() {
        let t = TriggerConfig::AnyOf(vec![
            TriggerConfig::Schedule("@hourly".into()),
            sub("component.finished"),
        ]);
        assert_eq!(find_non_whitelisted_trigger_event(&t, 0).unwrap(), None);
    }

    #[test]
    fn walker_depth_overflow_errs() {
        let mut t = sub("grant.issued");
        for _ in 0..9 {
            t = TriggerConfig::AnyOf(vec![t]);
        }
        let err = find_non_whitelisted_trigger_event(&t, 0).unwrap_err();
        assert!(matches!(err, SpawnError::InvalidConfig(_)));
    }

    #[test]
    fn walker_overlong_event_type_errs_before_whitelist() {
        let t = sub(&"x".repeat(200));
        let err = find_non_whitelisted_trigger_event(&t, 0).unwrap_err();
        match err {
            SpawnError::InvalidConfig(msg) => {
                assert!(msg.contains("MAX_EVENT_TYPE_LEN"), "got: {msg}");
            }
            other => panic!("expected InvalidConfig, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn submitter_of_records_metadata() {
        // AC-17 verification helper: submitter is recorded as metadata.
        let api = InMemoryComponentSubmitApi::new();
        let _ = api
            .submit_component("agent:research", dummy_task_config())
            .await
            .unwrap();
        assert_eq!(
            api.submitter_of("x").await,
            Some("agent:research".to_owned())
        );
        assert_eq!(api.submitter_of("ghost").await, None);
    }
}
