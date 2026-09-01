//! CONTRACT-123 `GrantApprovalIntake` — host-side operator approval surface
//! (MODULE-013 §2.7, AC-24, m013-intake).
//!
//! The supervised resolver chain's [`crate::resolver::ChannelResolver`] holds an
//! injected [`ChannelApprovalPort`]. `GrantApprovalIntake` IS that port AND the
//! operator-facing surface, so a parked `grant-decision::pending` routes THROUGH
//! it and the requester's CONTRACT-120 retry observes the operator's
//! approve / deny / narrow decision:
//!
//! ```text
//! guest request-capability --chain--> ChannelResolver.request_approval()
//!     --> intake parks {request_id, Pending}  (WIT returns grant-decision::pending)
//! operator: list_pending() -> approve | deny | narrow(subset) | revoke | apply_preset
//! guest retry --chain--> ChannelResolver.decision(request_id)
//!     = Approved -> take_approved() (atomic consume + narrow) -> Approve(draft) -> grant.issued
//!     = Denied   -> resolved() -> Deny
//! ```
//!
//! ## Consumed by
//! MODULE-020 (registers as the approval backend that pending resolver decisions
//! route through; the SYS-J-66 client journey witnesses the e2e leg — a Wave-25
//! MODULE-020 concern, out of this provider-leg's scope).
//!
//! ## Invariants
//! - **Lock ordering:** the intake never holds its `pending` Mutex across a call
//!   into [`GrantStore`] / [`PresetRegistry`] (which acquire store RwLocks). This
//!   is what makes `apply_preset` deadlock-free against a concurrent
//!   request-capability (which holds the store read barrier while the delivery
//!   worker wants the pending Mutex).
//! - **`apply_preset` is invalidate-FIRST:** it invalidates the target's parked
//!   entries (in-memory, pending Mutex) BEFORE applying the preset (store write
//!   barrier). This both respects the lock order AND closes the stale-approval
//!   race — a concurrent approved-retry that inserts a grant between the operator's
//!   approve and the preset apply holds the read barrier the preset's write barrier
//!   waits on, so its grant is revoked by the preset.
//! - **Fail-safe `decision`:** `decision()` for an unknown / evicted `request_id`
//!   returns `Pending`, never `Approved`.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};

use advance_shared_types::traits::EventBusEmit;
use chrono::Utc;

use crate::data::{
    CapParam, Grant, GrantDraft, GrantId, GrantIssuer, GrantProvenance, GrantStatus, GrantTtl,
};
use crate::error::{CapGrantError, Result};
use crate::events::resolver_invoked_event;
use crate::preset::PresetRegistry;
use crate::resolver::{
    ChannelApprovalDecision, ChannelApprovalError, ChannelApprovalPort, ChannelApprovalRequest,
};
use crate::store::GrantStore;
use crate::subset::SubsetValidator;

/// Maximum simultaneously-parked approval requests (across all agents). On
/// overflow the intake first evicts the oldest TERMINAL (Approved/Denied)
/// entries; only when all 1024 are LIVE `Pending` does
/// [`GrantApprovalIntake::request_approval`] fail closed (the `ChannelResolver`
/// then denies `channel-approval-unavailable`). A live `Pending` is NEVER
/// evicted, so there is no intake-side invisible-pending.
pub const MAX_PENDING_REQUESTS: usize = 1024;

/// Per-agent live-`Pending` cap. The registry is process-global (one intake per
/// runtime, shared by every agent through the single production resolver chain),
/// and the request fingerprint includes the guest-controlled `justification`, so
/// WITHOUT this cap a single grant-capable guest could mint enough distinct
/// requests to fill [`MAX_PENDING_REQUESTS`] and starve every other agent's
/// channel-approval leg (a fail-closed cross-agent DoS). This per-caller ceiling
/// bounds one agent's share so it cannot monopolize the shared registry; a caller
/// that hits it is denied (fail-closed) while other agents retain capacity.
pub const MAX_PENDING_PER_CALLER: usize = 64;

/// Per-narrow parameter bounds (parity with the guest-facing WIT caps in
/// `wit_impl.rs` §2.11) so an operator/console `narrow` cannot persist an
/// unbounded grant into the store + `grant.issued` event.
const MAX_NARROW_PARAMS_ENTRIES: usize = 64;
const MAX_NARROW_PARAM_KEY_BYTES: usize = 256;
const MAX_NARROW_PARAM_VALUE_BYTES: usize = 4096;
const MAX_NARROW_PARAMS_TOTAL_BYTES: usize = 4096;

/// `resolver_type` tag used for the action-time `resolver.invoked` audit events
/// the intake emits on approve / deny / narrow. Deliberately distinct from the 5
/// built-in resolver names so audit consumers counting the chain's resolvers are
/// not perturbed.
pub const INTAKE_RESOLVER_TYPE: &str = "GrantApprovalIntake";

/// Recorded operator decision for a parked request.
#[derive(Clone, Debug)]
enum IntakeDecision {
    Pending,
    /// `None` = approve as-requested; `Some(params)` = operator narrowed to a
    /// CONTRACT-122-validated subset (atomically consumed + surfaced to the
    /// resolver via [`ChannelApprovalPort::take_approved`]).
    Approved(Option<Vec<CapParam>>),
    Denied(String),
}

impl IntakeDecision {
    fn is_pending(&self) -> bool {
        matches!(self, IntakeDecision::Pending)
    }
    fn is_denied(&self) -> bool {
        matches!(self, IntakeDecision::Denied(_))
    }
}

struct PendingEntry {
    request: ChannelApprovalRequest,
    decision: IntakeDecision,
    /// Monotonic insertion order — drives deterministic `list_pending` ordering
    /// and oldest-first terminal-entry eviction on overflow.
    seq: u64,
}

/// Read-only view of a parked pending request, returned by
/// [`GrantApprovalIntake::list_pending`]. This is the operator/console surface —
/// exactly what an operator needs to decide (who asked for what).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingApprovalView {
    pub request_id: String,
    pub caller: String,
    pub capability: String,
    pub params: Option<Vec<CapParam>>,
    pub ttl: GrantTtl,
    pub justification: Option<String>,
    pub generation: u64,
}

/// Full-registry inspect result for CONTRACT-123 decide / recover.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RequestInspect {
    Decided,
    Pending {
        caller: String,
        generation: u64,
        capability: String,
        params: Option<Vec<CapParam>>,
        ttl: GrantTtl,
        justification: Option<String>,
    },
}

struct PendingRegistry {
    entries: HashMap<String, PendingEntry>,
    next_seq: u64,
}

impl PendingRegistry {
    fn try_next_seq(&mut self) -> std::result::Result<u64, ChannelApprovalError> {
        let s = self.next_seq;
        if s == 0 {
            return Err(ChannelApprovalError::new(
                "grant-approval-intake: pending generation counter wrapped",
            ));
        }
        self.next_seq = s.checked_add(1).ok_or_else(|| {
            ChannelApprovalError::new(
                "grant-approval-intake: pending generation counter wrapped",
            )
        })?;
        Ok(s)
    }

    /// Evict the oldest TERMINAL (Approved/Denied) entry. Returns `true` if one
    /// was evicted. NEVER evicts a live `Pending` entry.
    fn evict_one_terminal(&mut self) -> bool {
        let victim = self
            .entries
            .iter()
            .filter(|(_, e)| !e.decision.is_pending())
            .min_by_key(|(_, e)| e.seq)
            .map(|(id, _)| id.clone());
        match victim {
            Some(id) => {
                self.entries.remove(&id);
                true
            }
            None => false,
        }
    }
}

/// CONTRACT-123. Host-side operator approval intake — see module docs.
pub struct GrantApprovalIntake {
    pending: Mutex<PendingRegistry>,
    validator: Arc<dyn SubsetValidator>,
    store: Arc<GrantStore>,
    presets: Arc<PresetRegistry>,
    event_bus: Arc<dyn EventBusEmit>,
}

impl GrantApprovalIntake {
    pub fn new(
        store: Arc<GrantStore>,
        validator: Arc<dyn SubsetValidator>,
        presets: Arc<PresetRegistry>,
        event_bus: Arc<dyn EventBusEmit>,
    ) -> Self {
        Self {
            pending: Mutex::new(PendingRegistry {
                entries: HashMap::new(),
                next_seq: 1,
            }),
            validator,
            store,
            presets,
            event_bus,
        }
    }

    fn lock_pending(&self) -> MutexGuard<'_, PendingRegistry> {
        self.pending.lock().unwrap_or_else(|p| p.into_inner())
    }

    // ---- operator surface -------------------------------------------------

    /// List the currently-parked `Pending` approval requests (deterministic
    /// insertion order). A pure read — emits no audit event.
    pub fn list_pending(&self) -> Vec<PendingApprovalView> {
        let reg = self.lock_pending();
        let mut ordered: Vec<(u64, PendingApprovalView)> = reg
            .entries
            .values()
            .filter(|e| e.decision.is_pending())
            .map(|e| {
                (
                    e.seq,
                    PendingApprovalView {
                        request_id: e.request.request_id.clone(),
                        caller: e.request.caller.clone(),
                        capability: e.request.capability.clone(),
                        params: e.request.params.clone(),
                        ttl: e.request.ttl.clone(),
                        justification: e.request.justification.clone(),
                        generation: e.seq,
                    },
                )
            })
            .collect();
        ordered.sort_by_key(|(seq, _)| *seq);
        ordered.into_iter().map(|(_, v)| v).collect()
    }

    /// Approve a pending request as-submitted. Emits `resolver.invoked`
    /// (`GrantApprovalIntake`, `approve`). The requester's retry observes
    /// `grant-decision::approved`.
    pub fn approve(&self, request_id: &str) -> Result<()> {
        let (caller, capability) = self.set_decision(request_id, IntakeDecision::Approved(None))?;
        self.event_bus.emit(resolver_invoked_event(
            &caller,
            &capability,
            INTAKE_RESOLVER_TYPE,
            "approve",
        ));
        Ok(())
    }

    /// Deny a pending request. Emits `resolver.invoked` (`GrantApprovalIntake`,
    /// `deny`). The requester's retry observes `grant-decision::denied`.
    pub fn deny(&self, request_id: &str, reason: impl Into<String>) -> Result<()> {
        let (caller, capability) =
            self.set_decision(request_id, IntakeDecision::Denied(reason.into()))?;
        self.event_bus.emit(resolver_invoked_event(
            &caller,
            &capability,
            INTAKE_RESOLVER_TYPE,
            "deny",
        ));
        Ok(())
    }

    /// Narrow a pending request: approve a parameter-subset of the original
    /// request, validated against it by CONTRACT-122 [`SubsetValidator`]. The
    /// requester's retry observes `grant-decision::approved` with the NARROWED
    /// params. A non-subset `new_params` returns
    /// [`CapGrantError::SubsetViolation`] and leaves the request Pending
    /// (fail-closed). Emits `resolver.invoked` (`GrantApprovalIntake`, `approve`).
    pub fn narrow(&self, request_id: &str, new_params: Vec<CapParam>) -> Result<()> {
        // Bound the operator-supplied narrowed params (parity with the guest WIT
        // caps) BEFORE anything, so a narrow cannot persist an unbounded grant into
        // the store + `grant.issued` event (defence-in-depth vs a compromised /
        // buggy console).
        if new_params.len() > MAX_NARROW_PARAMS_ENTRIES {
            return Err(CapGrantError::InvalidConfig(format!(
                "narrow: params exceeds {MAX_NARROW_PARAMS_ENTRIES}-entry cap (got {})",
                new_params.len()
            )));
        }
        let mut total = 0usize;
        for p in &new_params {
            if p.key.len() > MAX_NARROW_PARAM_KEY_BYTES {
                return Err(CapGrantError::InvalidConfig(format!(
                    "narrow: cap-param key exceeds {MAX_NARROW_PARAM_KEY_BYTES}-byte cap (got {})",
                    p.key.len()
                )));
            }
            if p.value.len() > MAX_NARROW_PARAM_VALUE_BYTES {
                return Err(CapGrantError::InvalidConfig(format!(
                    "narrow: cap-param value exceeds {MAX_NARROW_PARAM_VALUE_BYTES}-byte cap (got {})",
                    p.value.len()
                )));
            }
            total = total
                .saturating_add(p.key.len())
                .saturating_add(p.value.len());
        }
        if total > MAX_NARROW_PARAMS_TOTAL_BYTES {
            return Err(CapGrantError::InvalidConfig(format!(
                "narrow: aggregate params exceed {MAX_NARROW_PARAMS_TOTAL_BYTES}-byte cap (got {total})"
            )));
        }

        // Snapshot the original request under the lock; do NOT hold it across the
        // (pure) subset validation.
        let (caller, capability, orig_params, ttl) = {
            let reg = self.lock_pending();
            let entry = reg
                .entries
                .get(request_id)
                .ok_or_else(|| CapGrantError::NotFound(GrantId::new(request_id)))?;
            if !entry.decision.is_pending() {
                return Err(already_decided(request_id));
            }
            (
                entry.request.caller.clone(),
                entry.request.capability.clone(),
                entry.request.params.clone().unwrap_or_default(),
                entry.request.ttl.clone(),
            )
        };

        // Validate: the narrowed params must be a subset of the original request
        // (an empty original ⇒ whole-capability ⇒ any subset passes).
        let parent = synthetic_parent_grant(&caller, &capability, orig_params);
        let child = GrantDraft {
            capability: capability.clone(),
            params: new_params.clone(),
            ttl,
        };
        self.validator.validate(&parent, &child)?;

        // Re-check still-pending (TOCTOU-safe against a concurrent decide) and
        // record the narrowed approval.
        {
            let mut reg = self.lock_pending();
            let entry = reg
                .entries
                .get_mut(request_id)
                .ok_or_else(|| CapGrantError::NotFound(GrantId::new(request_id)))?;
            if !entry.decision.is_pending() {
                return Err(already_decided(request_id));
            }
            entry.decision = IntakeDecision::Approved(Some(new_params));
        }
        self.event_bus.emit(resolver_invoked_event(
            &caller,
            &capability,
            INTAKE_RESOLVER_TYPE,
            "approve",
        ));
        Ok(())
    }

    /// Approve only if the parked generation still matches.
    pub fn approve_if_generation(&self, request_id: &str, expected_gen: u64) -> Result<()> {
        let (caller, capability) = {
            let mut reg = self.lock_pending();
            let entry = reg
                .entries
                .get_mut(request_id)
                .ok_or_else(|| CapGrantError::NotFound(GrantId::new(request_id)))?;
            if !entry.decision.is_pending() {
                return Err(already_decided(request_id));
            }
            if entry.seq != expected_gen {
                return Err(CapGrantError::InvalidConfig(format!(
                    "grant-approval-intake: stale pending generation for {request_id}"
                )));
            }
            entry.decision = IntakeDecision::Approved(None);
            (
                entry.request.caller.clone(),
                entry.request.capability.clone(),
            )
        };
        self.event_bus.emit(resolver_invoked_event(
            &caller,
            &capability,
            INTAKE_RESOLVER_TYPE,
            "approve",
        ));
        Ok(())
    }

    /// Deny only if the parked generation still matches.
    pub fn deny_if_generation(
        &self,
        request_id: &str,
        expected_gen: u64,
        reason: impl Into<String>,
    ) -> Result<()> {
        let (caller, capability) = {
            let mut reg = self.lock_pending();
            let entry = reg
                .entries
                .get_mut(request_id)
                .ok_or_else(|| CapGrantError::NotFound(GrantId::new(request_id)))?;
            if !entry.decision.is_pending() {
                return Err(already_decided(request_id));
            }
            if entry.seq != expected_gen {
                return Err(CapGrantError::InvalidConfig(format!(
                    "grant-approval-intake: stale pending generation for {request_id}"
                )));
            }
            entry.decision = IntakeDecision::Denied(reason.into());
            (
                entry.request.caller.clone(),
                entry.request.capability.clone(),
            )
        };
        self.event_bus.emit(resolver_invoked_event(
            &caller,
            &capability,
            INTAKE_RESOLVER_TYPE,
            "deny",
        ));
        Ok(())
    }

    /// Narrow only if the parked generation still matches after the unlocked
    /// CONTRACT-122 subset check.
    pub fn narrow_if_generation(
        &self,
        request_id: &str,
        expected_gen: u64,
        new_params: Vec<CapParam>,
    ) -> Result<()> {
        if new_params.len() > MAX_NARROW_PARAMS_ENTRIES {
            return Err(CapGrantError::InvalidConfig(format!(
                "narrow: params exceeds {MAX_NARROW_PARAMS_ENTRIES}-entry cap (got {})",
                new_params.len()
            )));
        }
        let mut total = 0usize;
        for p in &new_params {
            if p.key.len() > MAX_NARROW_PARAM_KEY_BYTES {
                return Err(CapGrantError::InvalidConfig(format!(
                    "narrow: cap-param key exceeds {MAX_NARROW_PARAM_KEY_BYTES}-byte cap (got {})",
                    p.key.len()
                )));
            }
            if p.value.len() > MAX_NARROW_PARAM_VALUE_BYTES {
                return Err(CapGrantError::InvalidConfig(format!(
                    "narrow: cap-param value exceeds {MAX_NARROW_PARAM_VALUE_BYTES}-byte cap (got {})",
                    p.value.len()
                )));
            }
            total = total
                .saturating_add(p.key.len())
                .saturating_add(p.value.len());
        }
        if total > MAX_NARROW_PARAMS_TOTAL_BYTES {
            return Err(CapGrantError::InvalidConfig(format!(
                "narrow: aggregate params exceed {MAX_NARROW_PARAMS_TOTAL_BYTES}-byte cap (got {total})"
            )));
        }

        let (caller, capability, orig_params, ttl) = {
            let reg = self.lock_pending();
            let entry = reg
                .entries
                .get(request_id)
                .ok_or_else(|| CapGrantError::NotFound(GrantId::new(request_id)))?;
            if !entry.decision.is_pending() {
                return Err(already_decided(request_id));
            }
            if entry.seq != expected_gen {
                return Err(CapGrantError::InvalidConfig(format!(
                    "grant-approval-intake: stale pending generation for {request_id}"
                )));
            }
            (
                entry.request.caller.clone(),
                entry.request.capability.clone(),
                entry.request.params.clone().unwrap_or_default(),
                entry.request.ttl.clone(),
            )
        };

        let parent = synthetic_parent_grant(&caller, &capability, orig_params);
        let child = GrantDraft {
            capability: capability.clone(),
            params: new_params.clone(),
            ttl,
        };
        self.validator.validate(&parent, &child)?;

        {
            let mut reg = self.lock_pending();
            let entry = reg
                .entries
                .get_mut(request_id)
                .ok_or_else(|| CapGrantError::NotFound(GrantId::new(request_id)))?;
            if !entry.decision.is_pending() {
                return Err(already_decided(request_id));
            }
            if entry.seq != expected_gen {
                return Err(CapGrantError::InvalidConfig(format!(
                    "grant-approval-intake: stale pending generation for {request_id}"
                )));
            }
            entry.decision = IntakeDecision::Approved(Some(new_params));
        }
        self.event_bus.emit(resolver_invoked_event(
            &caller,
            &capability,
            INTAKE_RESOLVER_TYPE,
            "approve",
        ));
        Ok(())
    }

    /// Inspect the full registry (Pending and terminal). Absent → `None`.
    pub fn inspect_request(&self, request_id: &str) -> Option<RequestInspect> {
        let reg = self.lock_pending();
        let entry = reg.entries.get(request_id)?;
        if entry.decision.is_pending() {
            Some(RequestInspect::Pending {
                caller: entry.request.caller.clone(),
                generation: entry.seq,
                capability: entry.request.capability.clone(),
                params: entry.request.params.clone(),
                ttl: entry.request.ttl.clone(),
                justification: entry.request.justification.clone(),
            })
        } else {
            Some(RequestInspect::Decided)
        }
    }

    /// Snapshot one grant from the store. Missing → `None`.
    pub fn snapshot_grant(&self, grant_id: &str) -> Option<Grant> {
        self.store.get(grant_id)
    }

    /// Revoke a dynamic grant (root + provenance descendants). Delegates to
    /// [`GrantStore::cascade_revoke`], which emits `grant.revoked` per grant.
    /// Returns the total number of grants revoked (root + descendants, ≥1 for any
    /// active grant). Holds no pending Mutex across the store call.
    pub fn revoke(&self, grant_id: &str) -> Result<usize> {
        match self.store.get(grant_id) {
            Some(grant) if matches!(grant.provenance, GrantProvenance::StaticConfig) => {
                return Err(CapGrantError::NotFound(GrantId::new(grant_id)));
            }
            None => return Err(CapGrantError::NotFound(GrantId::new(grant_id))),
            Some(_) => {}
        }
        let result = self.store.cascade_revoke(grant_id)?;
        Ok(result.revoked.len())
    }

    /// Apply a preset to `target` (INVALIDATE-FIRST — see module docs). Step 1
    /// supersedes the target's parked entries to a terminal
    /// `Denied("superseded-by-preset")` under the pending Mutex; step 2 applies
    /// the preset via [`PresetRegistry::apply_preset`] (store write barrier;
    /// emits `preset.applied`). The pending Mutex is released before the store
    /// barrier is acquired. Returns the ids of the created preset grants.
    pub fn apply_preset(&self, target: &str, preset_name: &str) -> Result<Vec<GrantId>> {
        // Validate the preset name (bounded + control-byte-safe) FIRST, symmetric
        // with `PresetRegistry::apply_preset`'s own name gate — so a malformed
        // unknown name cannot echo unbounded / control-byte content back via
        // `PresetNotFound(name)` Display.
        if preset_name.is_empty() {
            return Err(CapGrantError::InvalidConfig(
                "apply_preset: preset name must not be empty".to_string(),
            ));
        }
        if preset_name.len() > 256 {
            return Err(CapGrantError::InvalidConfig(format!(
                "apply_preset: preset name exceeds 256-byte cap (got {} bytes)",
                preset_name.len()
            )));
        }
        if preset_name.chars().any(|c| c.is_control()) {
            return Err(CapGrantError::InvalidConfig(
                "apply_preset: preset name contains control bytes".to_string(),
            ));
        }
        // Pre-check the preset exists BEFORE invalidating the target's pending
        // queue, so an unknown/typo'd (but well-formed) preset name does not
        // needlessly supersede in-flight approvals. (A preset that exists but fails
        // the Step-2 subset check still invalidates-then-fails — fail-closed,
        // disclosed in §3.6; closing that would duplicate the subset validation.)
        if self.presets.get(preset_name).is_none() {
            return Err(CapGrantError::PresetNotFound(preset_name.to_string()));
        }
        self.invalidate_pending_for(target);
        let result = self.presets.apply_preset(
            preset_name,
            target,
            &self.store,
            &*self.validator,
            target,
        )?;
        Ok(result.created)
    }

    /// `#[doc(hidden)]` test/console observability accessor — the FULL registry
    /// size including terminal entries. **Must be a plain `pub fn`** (not
    /// `#[cfg(test)]`) so the integration test crate — which links the lib built
    /// without `cfg(test)` — can observe `resolved()` consuming an entry (which
    /// `list_pending`, being Pending-only, cannot).
    #[doc(hidden)]
    pub fn total_entries(&self) -> usize {
        self.lock_pending().entries.len()
    }

    // ---- internals --------------------------------------------------------

    /// Set the decision on a still-Pending entry; returns `(caller, capability)`
    /// for the audit event. Errors `NotFound` if absent, `PermissionDenied` if
    /// already decided.
    fn set_decision(&self, request_id: &str, decision: IntakeDecision) -> Result<(String, String)> {
        let mut reg = self.lock_pending();
        let entry = reg
            .entries
            .get_mut(request_id)
            .ok_or_else(|| CapGrantError::NotFound(GrantId::new(request_id)))?;
        if !entry.decision.is_pending() {
            return Err(already_decided(request_id));
        }
        entry.decision = decision;
        Ok((
            entry.request.caller.clone(),
            entry.request.capability.clone(),
        ))
    }

    /// Supersede every non-Denied entry for `target` to a terminal
    /// `Denied("superseded-by-preset")`. In-memory only (pending Mutex); no store
    /// lock. Setting (not removing) the entry keeps it observable to the
    /// requester's retry, which consumes it via `resolved()` — keeping the intake
    /// registry and the resolver's `SentApprovalCache` in sync.
    fn invalidate_pending_for(&self, target: &str) {
        let mut reg = self.lock_pending();
        for entry in reg.entries.values_mut() {
            if entry.request.caller == target && !entry.decision.is_denied() {
                entry.decision = IntakeDecision::Denied("superseded-by-preset".to_string());
            }
        }
    }
}

/// A synthetic parent [`Grant`] representing the ORIGINAL requested
/// capability+params, for the narrow subset check. Only `capability` + `params`
/// (+ `Active` status) are load-bearing for [`SubsetValidator::validate`].
fn synthetic_parent_grant(grantee: &str, capability: &str, params: Vec<CapParam>) -> Grant {
    Grant {
        id: GrantId::new(format!("intake-narrow-parent:{grantee}:{capability}")),
        grantee: grantee.to_string(),
        capability: capability.to_string(),
        params,
        ttl: GrantTtl::Once,
        issuer: GrantIssuer::Admin,
        provenance: GrantProvenance::Requested,
        status: GrantStatus::Active,
        created_at: Utc::now(),
        expires_at: None,
    }
}

fn already_decided(request_id: &str) -> CapGrantError {
    CapGrantError::PermissionDenied(format!(
        "grant-approval-intake: request {request_id} already decided"
    ))
}

impl ChannelApprovalPort for GrantApprovalIntake {
    fn decision(&self, request_id: &str) -> ChannelApprovalDecision {
        let reg = self.lock_pending();
        match reg.entries.get(request_id) {
            Some(e) => match &e.decision {
                IntakeDecision::Pending => ChannelApprovalDecision::Pending,
                IntakeDecision::Approved(_) => ChannelApprovalDecision::Approved,
                IntakeDecision::Denied(reason) => ChannelApprovalDecision::Denied(reason.clone()),
            },
            // Fail-safe HINGE: an unknown/evicted id is never Approved.
            None => ChannelApprovalDecision::Pending,
        }
    }

    fn request_approval(
        &self,
        request: ChannelApprovalRequest,
    ) -> std::result::Result<(), ChannelApprovalError> {
        let mut reg = self.lock_pending();
        let is_new = !reg.entries.contains_key(&request.request_id);
        if is_new {
            // Per-agent cap FIRST: one caller cannot monopolize the shared
            // registry (fail-closed cross-agent DoS defense — see
            // MAX_PENDING_PER_CALLER).
            let caller_pending = reg
                .entries
                .values()
                .filter(|e| e.request.caller == request.caller && e.decision.is_pending())
                .count();
            if caller_pending >= MAX_PENDING_PER_CALLER {
                return Err(ChannelApprovalError::new(
                    "grant-approval-intake: per-agent pending approval limit reached",
                ));
            }
            // Global cap: evict an oldest TERMINAL entry, else fail closed (never
            // evict a live Pending). Channel maps the Err to
            // `channel-approval-unavailable`.
            if reg.entries.len() >= MAX_PENDING_REQUESTS && !reg.evict_one_terminal() {
                return Err(ChannelApprovalError::new(
                    "grant-approval-intake: pending registry full (1024 live pending approvals)",
                ));
            }
        }
        let seq = reg.try_next_seq()?;
        reg.entries.insert(
            request.request_id.clone(),
            PendingEntry {
                request,
                decision: IntakeDecision::Pending,
                seq,
            },
        );
        Ok(())
    }

    fn take_approved(&self, request_id: &str) -> Option<Option<Vec<CapParam>>> {
        let mut reg = self.lock_pending();
        // Consume atomically under the pending lock, but ONLY when the entry is
        // currently Approved — a concurrent retry that already consumed it, or a
        // supersede-to-Denied, yields `None` so the ChannelResolver does not
        // fall back to the wider original draft.
        match reg.entries.get(request_id).map(|e| &e.decision) {
            Some(IntakeDecision::Approved(_)) => match reg.entries.remove(request_id) {
                Some(PendingEntry {
                    decision: IntakeDecision::Approved(narrowed),
                    ..
                }) => Some(narrowed),
                _ => None,
            },
            _ => None,
        }
    }

    fn resolved(&self, request_id: &str) {
        self.lock_pending().entries.remove(request_id);
    }
}

// ============================================================================
// In-src AC-21 barrier test (AI-09) — reaches `pub(crate)`
// `with_dynamic_insert_read_barrier` / `insert_dynamic_inner`, unreachable from
// the external integration-test crate.
// ============================================================================
#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::mpsc;
    use std::time::Duration;

    use crate::data::GrantProvenance;
    use crate::sqlite::GrantSqliteIndex;
    use crate::subset::SubsetValidatorImpl;
    use advance_database::{R2d2SqliteIndexHandle, SqliteIndexHandle};
    use advance_shared_types::event::Event;

    struct SilentBus;
    impl EventBusEmit for SilentBus {
        fn emit(&self, _event: Event) {}
    }

    fn make_store() -> Arc<GrantStore> {
        let handle: Arc<dyn SqliteIndexHandle> =
            Arc::new(R2d2SqliteIndexHandle::new_in_memory().expect("in-memory sqlite"));
        let index = GrantSqliteIndex::new(handle);
        index.ensure_schema().expect("ensure_schema");
        let bus: Arc<dyn EventBusEmit> = Arc::new(SilentBus);
        Arc::new(GrantStore::new(index, bus))
    }

    fn dynamic_grant(id: &str, grantee: &str, capability: &str) -> Grant {
        Grant {
            id: GrantId::new(id),
            grantee: grantee.to_string(),
            capability: capability.to_string(),
            params: Vec::new(),
            ttl: GrantTtl::Lifecycle,
            issuer: GrantIssuer::Admin,
            provenance: GrantProvenance::Requested,
            status: GrantStatus::Active,
            created_at: Utc::now(),
            expires_at: None,
        }
    }

    fn intake_over(store: Arc<GrantStore>) -> GrantApprovalIntake {
        GrantApprovalIntake::new(
            store,
            Arc::new(SubsetValidatorImpl::new()),
            Arc::new(PresetRegistry::with_builtins()),
            Arc::new(SilentBus),
        )
    }

    /// AI-09: `intake.apply_preset` participates in the AC-21 dynamic-insert
    /// barrier and does not deadlock against a concurrent request-capability
    /// snapshot→insert that holds the read barrier. The preset apply blocks on
    /// the store WRITE barrier while the read barrier is held, then — once the
    /// racing insert commits and the barrier releases — revokes it, converging
    /// to exactly the preset (restrict ⇒ empty) set. The test completing is
    /// itself the no-deadlock witness (invalidate-FIRST releases the pending
    /// Mutex before the store write barrier is taken).
    #[test]
    fn apply_preset_is_atomic_and_deadlock_free_against_concurrent_insert() {
        let store = make_store();
        store
            .insert_dynamic(dynamic_grant("seed", "agent:a", "fs"))
            .expect("seed a dynamic grant to revoke");
        let intake = Arc::new(intake_over(store.clone()));

        let (snapshot_tx, snapshot_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let insert_store = store.clone();
        let insert_handle = std::thread::spawn(move || {
            insert_store.with_dynamic_insert_read_barrier(|| {
                // Barrier held: signal, wait for release, THEN insert a racing
                // dynamic grant for the same grantee.
                snapshot_tx.send(()).expect("signal barrier held");
                release_rx
                    .recv_timeout(Duration::from_secs(2))
                    .expect("release insert");
                insert_store
                    .insert_dynamic_inner(dynamic_grant("racing", "agent:a", "fs"))
                    .expect("racing insert");
            });
        });

        snapshot_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("insert thread holds the read barrier");

        let apply_done = Arc::new(AtomicBool::new(false));
        let apply_done_t = apply_done.clone();
        let apply_intake = intake.clone();
        let apply_handle = std::thread::spawn(move || {
            let created = apply_intake
                .apply_preset("agent:a", "restrict")
                .expect("apply restrict preset");
            apply_done_t.store(true, Ordering::SeqCst);
            created
        });

        // The preset apply must NOT complete while the read barrier is held.
        std::thread::sleep(Duration::from_millis(50));
        assert!(
            !apply_done.load(Ordering::SeqCst),
            "apply_preset completed while the dynamic-insert read barrier was held"
        );

        release_tx.send(()).expect("release insert");
        insert_handle.join().expect("insert thread joins");
        let created = apply_handle.join().expect("apply thread joins");

        // restrict creates nothing; both the seed and the racing insert are
        // revoked → no active dynamic grants remain for the target.
        assert!(created.is_empty(), "restrict preset creates no grants");
        let active_dynamic: Vec<GrantId> = store
            .list_by_grantee("agent:a")
            .into_iter()
            .filter(|g| {
                g.status == GrantStatus::Active
                    && !matches!(g.provenance, GrantProvenance::StaticConfig)
            })
            .map(|g| g.id)
            .collect();
        assert!(
            active_dynamic.is_empty(),
            "restrict revokes all dynamic grants incl. the racing insert; got {active_dynamic:?}"
        );
    }
}
