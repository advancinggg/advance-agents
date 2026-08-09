//! `agent-grant` WIT bindings (CONTRACT-120, MODULE-013 §2.3 + §2.7 + §2.8).
//!
//! Slice D — 7 `HostFunctionHandler` impls + `register_agent_grant` entry
//! point. Each handler lowers WIT `Val` payloads into the existing Slice
//! A/B/C `GrantStore` / `PresetRegistry` / `ResolverChain` operations and
//! lowers errors per the §2.8 mapping table.
//!
//! ## Constraints (per §2.7)
//!
//! - Caller identity is sourced from `HostCallContext.agent_id` (the WASM
//!   guest's identity per the call frame), never from a caller-supplied
//!   string.
//! - Every path that lifts `parent_grants` applies the
//!   [`filter_active_unexpired`] private helper. This mirrors the canonical
//!   defence-in-depth pattern at `check.rs:139-145` / `preset.rs:358-372` /
//!   `store.rs:1094-1112`. The upstream gap in
//!   `SubsetAutoApproveResolver::resolve` (resolver.rs:180-211 — status-only
//!   filter) is mitigated at the WIT layer until a future hardening slice
//!   folds the filter into resolver.rs.
//! - `grant-status` and `delegate-grant` parent inference sort candidates by
//!   `Grant.id` lex-ASC before "first match" picks, closing the
//!   `list_by_grantee` HashSet-iter non-determinism (store.rs:179-190).
//! - `narrow-grant` / `revoke-grant` / `apply-preset` are SELF-ONLY at the
//!   WIT layer until M005 hierarchy + admin policy land
//!   (`target != ctx.agent_id` → `permission-denied`). `delegate-grant` IS
//!   cross-agent (target = child agent).
//! - `request-capability` defaults TTL to `GrantTtl::Once` (most
//!   conservative; supervised's documented default per §1.4.4 line 260).

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use advance_runtime::host_registry::{
    HostCallContext, HostCallError, HostFunctionHandler, HostFunctionSpec, HostRegistry,
};
use advance_shared_types::traits::EventBusEmit;
use chrono::{DateTime, Utc};
use wasmtime::component::Val;

use crate::data::{
    CapParam, ChainDecision, Grant, GrantDraft, GrantIssuer, GrantProvenance, GrantRequest,
    GrantStatus, GrantTtl,
};
use crate::error::CapGrantError;
use crate::preset::PresetRegistry;
use crate::resolver::{ResolverChain, ResolverContext};
use crate::store::GrantStore;
use crate::subset::SubsetValidator;

/// Capability identifier used for spec registration.
pub const AGENT_GRANT_CAPABILITY: &str = "grant";

/// Namespace for the `agent-grant` WIT interface.
pub const AGENT_GRANT_NAMESPACE: &str = "advance:runtime/agent-grant@0.1.0";

// Defensive caps applied at WIT-handler entry per MODULE-013 §2.7 table.
// Defence-in-depth — the underlying ops re-check; symmetric with
// Slice C's check.rs Adversarial-fix R2.
const MAX_CAPABILITY_BYTES: usize = 256;
const MAX_JUSTIFICATION_BYTES: usize = 1024;
const MAX_PARAMS_ENTRIES: usize = 64;
const MAX_PARAM_KEY_BYTES: usize = 256;
const MAX_PARAM_VALUE_BYTES: usize = 4096;
/// Aggregate cap on `sum(key.len() + value.len())` across `params: list<cap-param>`.
/// Matches the underlying `narrow` (store.rs:800 `NARROW_MAX_PARAMS_BYTES = 4096`)
/// and `delegate_grant` (store.rs:1148 `MAX_PARAMS_BYTES = 4096`) total-bytes
/// invariants. Slice D Audit-fix R2 — without this aggregate cap, the WIT layer
/// would accept up to 64 × 4096 ≈ 272 KB of params payload before underlying
/// re-checks reject; clones into `GrantRequest.params` / `GrantDraft.params`
/// would pay that cost on the WIT hot path.
const MAX_PARAMS_TOTAL_BYTES: usize = 4096;
const MAX_TARGET_BYTES: usize = 256;
const MAX_PRESET_NAME_BYTES: usize = 256;
/// `grant-id` strings: same 256-byte cap as identifier fields. Slice D
/// Audit-fix R2 — without this cap, `narrow-grant` / `revoke-grant` would
/// hash + compare unbounded byte strings against the in-memory store map
/// before any rejection.
const MAX_GRANT_ID_BYTES: usize = 256;
/// Maximum number of grants returned by `active-grants` / picked-from by
/// `grant-status`. Slice D Adversarial-fix R1 (Claude Adv R1 W1/W2) bound
/// on the per-call clone amplification surface: `list_by_grantee` returns
/// the full grant set for the agent regardless of status, and the WIT
/// layer must not let an attacker who has accumulated many historical
/// grants amplify each idempotent read into a multi-megabyte allocation.
/// 1024 is generous for legitimate use (a typical agent holds tens of
/// active grants) and bounds peak per-call memory at ~270 MB worst-case
/// (1024 grants × 64 params × 4096 bytes per value); for the typical
/// case (10s of grants, sparse params) this cap is unreachable.
const MAX_ACTIVE_GRANTS_RESPONSE: usize = 1024;

/// Bundle of dependencies used by the 7 WIT handlers. Constructed once at
/// runtime boot and passed to [`register_agent_grant`]; each handler holds
/// `Arc::clone`s of only the fields it needs.
///
/// Per §2.7: the `resolver_chain` is the **global default** chain — Slice D
/// continues Slice B's deferral of per-agent chain state (§1.4.4 step 5).
/// All `request-capability` calls run against this single chain regardless
/// of which preset the calling agent has applied. Future slice owns
/// per-agent chain selection.
pub struct AgentGrantBundle {
    pub store: Arc<GrantStore>,
    pub validator: Arc<dyn SubsetValidator>,
    pub presets: Arc<PresetRegistry>,
    pub resolver_chain: Arc<ResolverChain>,
    pub event_bus: Arc<dyn EventBusEmit>,
}

/// Register all 7 `agent-grant` host functions on `registry`.
///
/// Spec count: exactly 7, all under capability `"grant"` and namespace
/// `"advance:runtime/agent-grant@0.1.0"`. Idempotent flags: `active-grants` and
/// `grant-status` are read-only (`true`); the other 5 mutate state (`false`).
pub fn register_agent_grant(registry: &dyn HostRegistry, bundle: AgentGrantBundle) {
    let cap = AGENT_GRANT_CAPABILITY.to_string();
    let ns = AGENT_GRANT_NAMESPACE.to_string();

    registry.register(HostFunctionSpec {
        capability: cap.clone(),
        namespace: ns.clone(),
        name: "active-grants".to_string(),
        handler: Arc::new(ActiveGrantsHandler {
            store: Arc::clone(&bundle.store),
        }),
        idempotent: true,
    });
    registry.register(HostFunctionSpec {
        capability: cap.clone(),
        namespace: ns.clone(),
        name: "grant-status".to_string(),
        handler: Arc::new(GrantStatusHandler {
            store: Arc::clone(&bundle.store),
        }),
        idempotent: true,
    });
    registry.register(HostFunctionSpec {
        capability: cap.clone(),
        namespace: ns.clone(),
        name: "request-capability".to_string(),
        handler: Arc::new(RequestCapabilityHandler {
            store: Arc::clone(&bundle.store),
            resolver_chain: Arc::clone(&bundle.resolver_chain),
            event_bus: Arc::clone(&bundle.event_bus),
        }),
        idempotent: false,
    });
    registry.register(HostFunctionSpec {
        capability: cap.clone(),
        namespace: ns.clone(),
        name: "delegate-grant".to_string(),
        handler: Arc::new(DelegateGrantHandler {
            store: Arc::clone(&bundle.store),
            validator: Arc::clone(&bundle.validator),
        }),
        idempotent: false,
    });
    registry.register(HostFunctionSpec {
        capability: cap.clone(),
        namespace: ns.clone(),
        name: "narrow-grant".to_string(),
        handler: Arc::new(NarrowGrantHandler {
            store: Arc::clone(&bundle.store),
            validator: Arc::clone(&bundle.validator),
        }),
        idempotent: false,
    });
    registry.register(HostFunctionSpec {
        capability: cap.clone(),
        namespace: ns.clone(),
        name: "revoke-grant".to_string(),
        handler: Arc::new(RevokeGrantHandler {
            store: Arc::clone(&bundle.store),
        }),
        idempotent: false,
    });
    registry.register(HostFunctionSpec {
        capability: cap,
        namespace: ns,
        name: "apply-preset".to_string(),
        handler: Arc::new(ApplyPresetHandler {
            store: Arc::clone(&bundle.store),
            validator: Arc::clone(&bundle.validator),
            presets: Arc::clone(&bundle.presets),
        }),
        idempotent: false,
    });
}

// ============================================================================
// `filter_active_unexpired` helper — defence-in-depth
// ============================================================================

/// Symmetric with the canonical pattern at `check.rs:139-145`,
/// `preset.rs:358-372`, `store.rs:1094-1112`. Keeps only grants that are
/// `Active` AND have not yet passed their `expires_at` deadline.
///
/// `expires_at == None` (Persistent / Lifecycle / Once) is treated as
/// "no time-based deadline" and passes the filter. `Duration` / `Until`
/// grants compare against `Utc::now()`.
fn filter_active_unexpired(grants: Vec<Grant>) -> Vec<Grant> {
    let now = Utc::now();
    grants
        .into_iter()
        .filter(|g| g.status == GrantStatus::Active && g.expires_at.map_or(true, |t| t > now))
        .collect()
}

// ============================================================================
// Handler structs
// ============================================================================

pub struct ActiveGrantsHandler {
    pub store: Arc<GrantStore>,
}

impl HostFunctionHandler for ActiveGrantsHandler {
    fn call(
        &self,
        ctx: HostCallContext,
        params: Vec<Val>,
        results_len: usize,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<Val>, HostCallError>> + Send + 'static>> {
        let store = Arc::clone(&self.store);
        Box::pin(async move {
            check_results_len("active-grants", results_len, 1)?;
            check_params_len("active-grants", &params, 0)?;
            let mut grants = filter_active_unexpired(store.list_by_grantee(&ctx.agent_id));
            // Deterministic ordering for stable WIT response.
            grants.sort_by(|a, b| a.id.0.cmp(&b.id.0));
            // Adversarial-fix R1 (Claude Adv R1 W1): cap response size to
            // bound per-call clone amplification. Slice D is the first
            // surface to expose `list_by_grantee` to guest WASM via an
            // idempotent read; without this cap, an attacker who has
            // accumulated many historical grants could amplify each
            // call into a multi-MB Val::List clone.
            grants.truncate(MAX_ACTIVE_GRANTS_RESPONSE);
            let val = grant_info_list_to_val(&grants);
            Ok(vec![ok_some(val)])
        })
    }
}

pub struct GrantStatusHandler {
    pub store: Arc<GrantStore>,
}

impl HostFunctionHandler for GrantStatusHandler {
    fn call(
        &self,
        ctx: HostCallContext,
        params: Vec<Val>,
        results_len: usize,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<Val>, HostCallError>> + Send + 'static>> {
        let store = Arc::clone(&self.store);
        Box::pin(async move {
            check_results_len("grant-status", results_len, 1)?;
            let capability = match params.as_slice() {
                [Val::String(s)] => s.clone(),
                _ => {
                    return Err(HostCallError::HandlerError(
                        "grant-status: expected single Val::String parameter".into(),
                    ));
                }
            };
            if let Some(err) = validate_capability_string(&capability) {
                return Ok(vec![ok_err(&err)]);
            }
            // Adversarial-fix R2 W1: filter by capability BEFORE applying the
            // response cap. The R1 form did `truncate(1024)` on the unsorted
            // `filter_active_unexpired` output, which — when an agent had
            // accumulated >1024 active grants — could discard the matching
            // grant in a HashMap-iteration-order tail and return a
            // non-deterministic false-negative `option::none`. grant-status
            // returns at most 1 grant; the cap belongs on the post-filter set.
            let all = filter_active_unexpired(store.list_by_grantee(&ctx.agent_id));
            let mut matching: Vec<Grant> = all
                .into_iter()
                .filter(|g| g.capability == capability)
                .collect();
            matching.sort_by(|a, b| a.id.0.cmp(&b.id.0));
            matching.truncate(MAX_ACTIVE_GRANTS_RESPONSE);
            let val = match matching.first() {
                Some(g) => Val::Option(Some(Box::new(grant_info_to_val(g)))),
                None => Val::Option(None),
            };
            Ok(vec![ok_some(val)])
        })
    }
}

pub struct RequestCapabilityHandler {
    pub store: Arc<GrantStore>,
    pub resolver_chain: Arc<ResolverChain>,
    pub event_bus: Arc<dyn EventBusEmit>,
}

impl HostFunctionHandler for RequestCapabilityHandler {
    fn call(
        &self,
        ctx: HostCallContext,
        params: Vec<Val>,
        results_len: usize,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<Val>, HostCallError>> + Send + 'static>> {
        let store = Arc::clone(&self.store);
        let chain = Arc::clone(&self.resolver_chain);
        let bus = Arc::clone(&self.event_bus);
        Box::pin(async move {
            check_results_len("request-capability", results_len, 1)?;
            let req_val = single_record(&params, "request-capability")?;
            let (capability, params_opt, justification) = match grant_request_from_val(req_val) {
                Ok(t) => t,
                Err(e) => return Ok(vec![ok_err(&e)]),
            };
            if let Some(e) = validate_capability_string(&capability) {
                return Ok(vec![ok_err(&e)]);
            }
            if let Some(j) = &justification {
                if j.len() > MAX_JUSTIFICATION_BYTES {
                    return Ok(vec![ok_err(&CapGrantError::InvalidConfig(format!(
                        "request-capability: justification exceeds {MAX_JUSTIFICATION_BYTES}-byte cap (got {} bytes)",
                        j.len()
                    )))]);
                }
                // Adversarial-fix R2 INFO#3: reject control bytes symmetric
                // with capability/caller_id/preset-name validators. A future
                // resolver or log path that echoes justification could
                // otherwise carry forged log lines / ANSI escapes.
                if j.chars().any(|c| c.is_control()) {
                    return Ok(vec![ok_err(&CapGrantError::InvalidConfig(
                        "request-capability: justification must not contain control characters"
                            .into(),
                    ))]);
                }
            }
            if let Some(p) = &params_opt {
                if let Some(e) = check_params_caps(p, "request-capability") {
                    return Ok(vec![ok_err(&e)]);
                }
            }

            // Slice D: TTL defaults to Once (most conservative; supervised's
            // documented default per §1.4.4 line 260). Trade-off documented
            // in §2.7.
            let req = GrantRequest {
                caller: ctx.agent_id.clone(),
                capability,
                params: params_opt,
                ttl: GrantTtl::Once,
                justification,
            };

            // Symmetric defense-in-depth: pre-filter parent_grants by
            // status+expiry because SubsetAutoApproveResolver::resolve at
            // resolver.rs:180-211 checks status only, not expires_at.
            // Closes the orphan expired-parent window for the WIT path.
            //
            // Audit-fix R2 reversal (Codex Diff R2 W1): we do NOT pre-filter
            // by capability. ResolverContext (resolver.rs:55-64) is
            // documented to carry the caller's FULL active grant set —
            // BudgetCheck / Channel / future custom resolvers may consult
            // unrelated-capability grants for routing, quota, or
            // approval-routing decisions. SubsetAutoApprove already runs
            // its own per-resolver `parent.capability == req.capability`
            // filter at resolver.rs:202, so cross-capability grants flowing
            // into the chain never auto-approve. Pre-filtering at the WIT
            // layer would silently narrow the documented ResolverContext
            // contract.
            let run_id = ctx.run_id.clone();
            let decision = tokio::task::spawn_blocking(move || {
                store.with_dynamic_insert_read_barrier(|| {
                    let parent_grants =
                        filter_active_unexpired(store.list_by_grantee(&ctx.agent_id));
                    let context = ResolverContext {
                        parent_grants: &parent_grants,
                        // Thread the per-request run id so a resolver chain configured
                        // with a live RunBudget can deny exhausted runs before later
                        // approval resolvers.
                        run_id: run_id.as_deref(),
                    };
                    chain.evaluate_with_dynamic_insert_barrier(req, context, &store, &bus)
                })
            })
            .await
            .map_err(|e| {
                HostCallError::HandlerError(format!("request-capability resolver failed: {e}"))
            })?;
            let val = chain_decision_to_val(&decision);
            Ok(vec![ok_some(val)])
        })
    }
}

pub struct DelegateGrantHandler {
    pub store: Arc<GrantStore>,
    pub validator: Arc<dyn SubsetValidator>,
}

impl HostFunctionHandler for DelegateGrantHandler {
    fn call(
        &self,
        ctx: HostCallContext,
        params: Vec<Val>,
        results_len: usize,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<Val>, HostCallError>> + Send + 'static>> {
        let store = Arc::clone(&self.store);
        let validator = Arc::clone(&self.validator);
        Box::pin(async move {
            check_results_len("delegate-grant", results_len, 1)?;
            let (target, draft_val) = match params.as_slice() {
                [Val::String(t), v] => (t.clone(), v.clone()),
                _ => {
                    return Err(HostCallError::HandlerError(
                        "delegate-grant: expected (string, grant-draft) parameters".into(),
                    ));
                }
            };
            if let Some(e) = target_too_long(&target) {
                return Ok(vec![ok_err(&e)]);
            }
            let draft = match grant_draft_from_val(&draft_val) {
                Ok(d) => d,
                Err(e) => return Ok(vec![ok_err(&e)]),
            };
            if let Some(e) = validate_capability_string(&draft.capability) {
                return Ok(vec![ok_err(&e)]);
            }
            if let Some(e) = check_params_caps(&draft.params, "delegate-grant") {
                return Ok(vec![ok_err(&e)]);
            }

            // Deterministic parent inference: walk caller's active+unexpired
            // grants matching draft.capability sorted by Grant.id lex-ASC,
            // try validator.validate per candidate. Exactly-one-pass → use it.
            // Zero / multi → permission-denied.
            let mut candidates: Vec<Grant> =
                filter_active_unexpired(store.list_by_grantee(&ctx.agent_id))
                    .into_iter()
                    .filter(|g| g.capability == draft.capability)
                    .collect();
            candidates.sort_by(|a, b| a.id.0.cmp(&b.id.0));

            let mut covers: Vec<&Grant> = Vec::new();
            for parent in &candidates {
                if validator.validate(parent, &draft).is_ok() {
                    covers.push(parent);
                }
            }
            let parent = match covers.as_slice() {
                [p] => *p,
                [] => {
                    return Ok(vec![ok_err(&CapGrantError::PermissionDenied(format!(
                        "delegate-grant: no parent grant covers requested draft for capability {:?}",
                        draft.capability
                    )))]);
                }
                multi => {
                    return Ok(vec![ok_err(&CapGrantError::PermissionDenied(format!(
                        "delegate-grant: ambiguous parent — caller holds {} active grants covering this draft for capability {:?}; future slice will expose explicit parent-grant-id",
                        multi.len(),
                        draft.capability
                    )))]);
                }
            };

            match store.delegate_grant(
                parent.id.as_str(),
                &target,
                draft,
                &ctx.agent_id,
                &*validator,
            ) {
                Ok(id) => Ok(vec![ok_some(Val::String(id.0))]),
                Err(e) => Ok(vec![ok_err(&e)]),
            }
        })
    }
}

pub struct NarrowGrantHandler {
    pub store: Arc<GrantStore>,
    pub validator: Arc<dyn SubsetValidator>,
}

impl HostFunctionHandler for NarrowGrantHandler {
    fn call(
        &self,
        ctx: HostCallContext,
        params: Vec<Val>,
        results_len: usize,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<Val>, HostCallError>> + Send + 'static>> {
        let store = Arc::clone(&self.store);
        let validator = Arc::clone(&self.validator);
        Box::pin(async move {
            check_results_len("narrow-grant", results_len, 1)?;
            let (target, grant_id, params_val) = match params.as_slice() {
                [Val::String(t), Val::String(g), v] => (t.clone(), g.clone(), v.clone()),
                _ => {
                    return Err(HostCallError::HandlerError(
                        "narrow-grant: expected (string, grant-id, list<cap-param>) parameters"
                            .into(),
                    ));
                }
            };
            if let Some(e) = target_too_long(&target) {
                return Ok(vec![ok_err(&e)]);
            }
            if let Some(e) = grant_id_too_long(&grant_id) {
                return Ok(vec![ok_err(&e)]);
            }
            // Slice D self-only constraint (per §2.3 / §2.7).
            if target != ctx.agent_id {
                return Ok(vec![ok_err(&CapGrantError::PermissionDenied(
                    "narrow-grant: cross-agent narrow not yet supported (Slice D constraint until M005 hierarchy lands)"
                        .to_string(),
                ))]);
            }
            let new_params = match cap_param_list_from_val(&params_val) {
                Ok(p) => p,
                Err(e) => return Ok(vec![ok_err(&e)]),
            };
            if let Some(e) = check_params_caps(&new_params, "narrow-grant") {
                return Ok(vec![ok_err(&e)]);
            }
            // Adversarial-fix R1 (Claude Adv R1 C1): collapse the
            // existence-oracle gap symmetric with `revoke-grant`'s ownership
            // pre-check. Without this gate, store.narrow returns distinct
            // `NotFound` (id missing or non-Active) vs `PermissionDenied`
            // (id exists, Active, owned by another agent), letting a
            // malicious guest enumerate other agents' Active grant IDs by
            // probing predictable static-config IDs (`static:{grantee}:{capability}`
            // form). The WIT layer collapses both cases into
            // `permission-denied` by checking ownership first.
            let owned = store
                .list_by_grantee(&ctx.agent_id)
                .into_iter()
                .any(|g| g.id.as_str() == grant_id);
            if !owned {
                return Ok(vec![ok_err(&CapGrantError::PermissionDenied(format!(
                    "narrow-grant: caller does not own grant {grant_id:?}"
                )))]);
            }
            match store.narrow(&grant_id, new_params, &ctx.agent_id, &*validator) {
                Ok(id) => Ok(vec![ok_some(Val::String(id.0))]),
                Err(e) => Ok(vec![ok_err(&e)]),
            }
        })
    }
}

pub struct RevokeGrantHandler {
    pub store: Arc<GrantStore>,
}

impl HostFunctionHandler for RevokeGrantHandler {
    fn call(
        &self,
        ctx: HostCallContext,
        params: Vec<Val>,
        results_len: usize,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<Val>, HostCallError>> + Send + 'static>> {
        let store = Arc::clone(&self.store);
        Box::pin(async move {
            check_results_len("revoke-grant", results_len, 1)?;
            let (target, grant_id) = match params.as_slice() {
                [Val::String(t), Val::String(g)] => (t.clone(), g.clone()),
                _ => {
                    return Err(HostCallError::HandlerError(
                        "revoke-grant: expected (string, grant-id) parameters".into(),
                    ));
                }
            };
            if let Some(e) = target_too_long(&target) {
                return Ok(vec![ok_err(&e)]);
            }
            if let Some(e) = grant_id_too_long(&grant_id) {
                return Ok(vec![ok_err(&e)]);
            }
            // Slice D self-only constraint: target must equal caller, and
            // the grant must be one the caller owns. Look up via
            // list_by_grantee so a grant_id from another agent's set is
            // surfaced as permission-denied (the caller has no authority
            // to revoke someone else's grants regardless of id).
            if target != ctx.agent_id {
                return Ok(vec![ok_err(&CapGrantError::PermissionDenied(
                    "revoke-grant: cross-agent revoke not yet supported (Slice D constraint)"
                        .to_string(),
                ))]);
            }
            let owned = store
                .list_by_grantee(&ctx.agent_id)
                .into_iter()
                .any(|g| g.id.as_str() == grant_id);
            if !owned {
                return Ok(vec![ok_err(&CapGrantError::PermissionDenied(format!(
                    "revoke-grant: caller does not own grant {grant_id:?}"
                )))]);
            }
            match store.cascade_revoke(&grant_id) {
                // Result type for revoke-grant is `result<_, grant-error>` — unit OK arm.
                Ok(_) => Ok(vec![Val::Result(Ok(None))]),
                Err(e) => Ok(vec![ok_err(&e)]),
            }
        })
    }
}

pub struct ApplyPresetHandler {
    pub store: Arc<GrantStore>,
    pub validator: Arc<dyn SubsetValidator>,
    pub presets: Arc<PresetRegistry>,
}

impl HostFunctionHandler for ApplyPresetHandler {
    fn call(
        &self,
        ctx: HostCallContext,
        params: Vec<Val>,
        results_len: usize,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<Val>, HostCallError>> + Send + 'static>> {
        let store = Arc::clone(&self.store);
        let validator = Arc::clone(&self.validator);
        let presets = Arc::clone(&self.presets);
        Box::pin(async move {
            check_results_len("apply-preset", results_len, 1)?;
            let (target, preset_name) = match params.as_slice() {
                [Val::String(t), Val::String(n)] => (t.clone(), n.clone()),
                _ => {
                    return Err(HostCallError::HandlerError(
                        "apply-preset: expected (string, string) parameters".into(),
                    ));
                }
            };
            if let Some(e) = target_too_long(&target) {
                return Ok(vec![ok_err(&e)]);
            }
            if preset_name.len() > MAX_PRESET_NAME_BYTES {
                return Ok(vec![ok_err(&CapGrantError::InvalidConfig(format!(
                    "apply-preset: preset-name exceeds {MAX_PRESET_NAME_BYTES}-byte cap (got {} bytes)",
                    preset_name.len()
                )))]);
            }
            if preset_name.chars().any(|c| c.is_control()) {
                return Ok(vec![ok_err(&CapGrantError::InvalidConfig(
                    "apply-preset: preset-name contains control bytes".to_string(),
                ))]);
            }
            // Slice D self-only constraint.
            if target != ctx.agent_id {
                return Ok(vec![ok_err(&CapGrantError::PermissionDenied(
                    "apply-preset: cross-target apply not yet supported (Slice D constraint)"
                        .to_string(),
                ))]);
            }
            match presets.apply_preset(&preset_name, &target, &store, &*validator, &ctx.agent_id) {
                Ok(result) => {
                    let ids: Vec<Val> = result
                        .created
                        .into_iter()
                        .map(|id| Val::String(id.0))
                        .collect();
                    Ok(vec![ok_some(Val::List(ids))])
                }
                Err(e) => Ok(vec![ok_err(&e)]),
            }
        })
    }
}

// ============================================================================
// Lowering helpers
// ============================================================================

fn check_results_len(fn_name: &str, got: usize, want: usize) -> Result<(), HostCallError> {
    if got == want {
        Ok(())
    } else {
        Err(HostCallError::HandlerError(format!(
            "{fn_name}: expected results_len == {want}, got {got}"
        )))
    }
}

fn check_params_len(fn_name: &str, got: &[Val], want: usize) -> Result<(), HostCallError> {
    if got.len() == want {
        Ok(())
    } else {
        Err(HostCallError::HandlerError(format!(
            "{fn_name}: expected {want} parameter(s), got {}",
            got.len()
        )))
    }
}

fn single_record<'a>(params: &'a [Val], fn_name: &str) -> Result<&'a Val, HostCallError> {
    match params {
        [v] => Ok(v),
        _ => Err(HostCallError::HandlerError(format!(
            "{fn_name}: expected single record parameter, got {} params",
            params.len()
        ))),
    }
}

fn validate_capability_string(s: &str) -> Option<CapGrantError> {
    // Audit-fix R2 (Codex Diff W1): the WIT layer must reject malformed
    // capability identifiers symmetric with the existing
    // `insert`/`compile.rs` convention: no `:` (deterministic-id
    // separator) and no ASCII control bytes (log-injection / string
    // truncation). `insert_dynamic_inner` only rejects empty capability
    // strings, so without this gate a resolver that approves "as
    // requested" could persist a Grant with a poisoned `capability`
    // field.
    if s.is_empty() {
        return Some(CapGrantError::InvalidConfig(
            "capability must not be empty".to_string(),
        ));
    }
    if s.len() > MAX_CAPABILITY_BYTES {
        return Some(CapGrantError::InvalidConfig(format!(
            "capability exceeds {MAX_CAPABILITY_BYTES}-byte cap (got {} bytes)",
            s.len()
        )));
    }
    if s.contains(':') {
        return Some(CapGrantError::InvalidConfig(format!(
            "capability contains forbidden character ':' (got: {s:?})"
        )));
    }
    if s.chars().any(|c| c.is_control()) {
        return Some(CapGrantError::InvalidConfig(
            "capability contains ASCII control bytes — forbidden for persistent identifiers"
                .to_string(),
        ));
    }
    None
}

fn target_too_long(s: &str) -> Option<CapGrantError> {
    if s.len() > MAX_TARGET_BYTES {
        Some(CapGrantError::InvalidConfig(format!(
            "target exceeds {MAX_TARGET_BYTES}-byte cap (got {} bytes)",
            s.len()
        )))
    } else {
        None
    }
}

fn grant_id_too_long(s: &str) -> Option<CapGrantError> {
    if s.len() > MAX_GRANT_ID_BYTES {
        Some(CapGrantError::InvalidConfig(format!(
            "grant-id exceeds {MAX_GRANT_ID_BYTES}-byte cap (got {} bytes)",
            s.len()
        )))
    } else {
        None
    }
}

fn check_params_caps(params: &[CapParam], fn_name: &str) -> Option<CapGrantError> {
    if params.len() > MAX_PARAMS_ENTRIES {
        return Some(CapGrantError::InvalidConfig(format!(
            "{fn_name}: params exceeds {MAX_PARAMS_ENTRIES}-entry cap (got {} entries)",
            params.len()
        )));
    }
    let mut total: usize = 0;
    for p in params {
        if p.key.len() > MAX_PARAM_KEY_BYTES {
            return Some(CapGrantError::InvalidConfig(format!(
                "{fn_name}: cap-param key exceeds {MAX_PARAM_KEY_BYTES}-byte cap (got {} bytes)",
                p.key.len()
            )));
        }
        if p.value.len() > MAX_PARAM_VALUE_BYTES {
            return Some(CapGrantError::InvalidConfig(format!(
                "{fn_name}: cap-param value exceeds {MAX_PARAM_VALUE_BYTES}-byte cap (got {} bytes)",
                p.value.len()
            )));
        }
        total = total
            .saturating_add(p.key.len())
            .saturating_add(p.value.len());
    }
    // Audit-fix R2 (Claude Diff W2): aggregate-bytes cap symmetric with
    // store.rs:800 NARROW_MAX_PARAMS_BYTES + store.rs:1148 MAX_PARAMS_BYTES.
    // Closes the 64×4096≈272KB pre-rejection processing surface.
    if total > MAX_PARAMS_TOTAL_BYTES {
        return Some(CapGrantError::InvalidConfig(format!(
            "{fn_name}: params total bytes exceed {MAX_PARAMS_TOTAL_BYTES}-byte aggregate cap (got {total} bytes)"
        )));
    }
    None
}

fn cap_param_from_val(v: &Val) -> Result<CapParam, CapGrantError> {
    match v {
        Val::Record(fields) => {
            let mut key: Option<String> = None;
            let mut value: Option<String> = None;
            for (name, vv) in fields {
                match (name.as_str(), vv) {
                    ("key", Val::String(s)) => key = Some(s.clone()),
                    ("value", Val::String(s)) => value = Some(s.clone()),
                    _ => {}
                }
            }
            match (key, value) {
                (Some(k), Some(v)) => Ok(CapParam { key: k, value: v }),
                _ => Err(CapGrantError::InvalidConfig(
                    "cap-param record missing key/value field".to_string(),
                )),
            }
        }
        _ => Err(CapGrantError::InvalidConfig(
            "cap-param: expected Val::Record".to_string(),
        )),
    }
}

fn cap_param_to_val(p: &CapParam) -> Val {
    Val::Record(vec![
        ("key".to_string(), Val::String(p.key.clone())),
        ("value".to_string(), Val::String(p.value.clone())),
    ])
}

fn cap_param_list_from_val(v: &Val) -> Result<Vec<CapParam>, CapGrantError> {
    match v {
        Val::List(items) => items.iter().map(cap_param_from_val).collect(),
        _ => Err(CapGrantError::InvalidConfig(
            "expected Val::List for cap-param list".to_string(),
        )),
    }
}

fn grant_ttl_from_val(v: &Val) -> Result<GrantTtl, CapGrantError> {
    match v {
        Val::Variant(case, payload) => match (case.as_str(), payload.as_deref()) {
            ("once", None) => Ok(GrantTtl::Once),
            ("lifecycle", None) => Ok(GrantTtl::Lifecycle),
            ("persistent", None) => Ok(GrantTtl::Persistent),
            ("duration", Some(Val::U64(n))) => Ok(GrantTtl::Duration(*n)),
            ("until", Some(Val::String(s))) => {
                let dt = s.parse::<DateTime<Utc>>().map_err(|e| {
                    CapGrantError::InvalidConfig(format!(
                        "grant-ttl::until: invalid timestamp {s:?}: {e}"
                    ))
                })?;
                Ok(GrantTtl::Until(dt))
            }
            (other, _) => Err(CapGrantError::InvalidConfig(format!(
                "grant-ttl: unknown variant case {other:?}"
            ))),
        },
        _ => Err(CapGrantError::InvalidConfig(
            "grant-ttl: expected Val::Variant".to_string(),
        )),
    }
}

fn grant_ttl_to_val(t: &GrantTtl) -> Val {
    match t {
        GrantTtl::Once => Val::Variant("once".to_string(), None),
        GrantTtl::Lifecycle => Val::Variant("lifecycle".to_string(), None),
        GrantTtl::Persistent => Val::Variant("persistent".to_string(), None),
        GrantTtl::Duration(n) => Val::Variant("duration".to_string(), Some(Box::new(Val::U64(*n)))),
        GrantTtl::Until(t) => Val::Variant(
            "until".to_string(),
            Some(Box::new(Val::String(t.to_rfc3339()))),
        ),
    }
}

fn grant_status_to_val(s: &GrantStatus) -> Val {
    let case = match s {
        GrantStatus::Active => "active",
        GrantStatus::Consumed => "consumed",
        GrantStatus::Expired => "expired",
        GrantStatus::Revoked => "revoked",
    };
    Val::Variant(case.to_string(), None)
}

fn issuer_to_string(i: &GrantIssuer) -> String {
    match i {
        GrantIssuer::Config => "config".to_string(),
        GrantIssuer::Parent(id) => format!("parent:{id}"),
        GrantIssuer::Resolver(name) => format!("resolver:{name}"),
        GrantIssuer::Admin => "admin".to_string(),
    }
}

fn provenance_to_string(p: &GrantProvenance) -> String {
    match p {
        GrantProvenance::StaticConfig => "static-config".to_string(),
        GrantProvenance::Delegated(id) => format!("delegated:{id}"),
        GrantProvenance::Requested => "requested".to_string(),
        GrantProvenance::Preset(name) => format!("preset:{name}"),
    }
}

fn grant_info_to_val(g: &Grant) -> Val {
    let params: Vec<Val> = g.params.iter().map(cap_param_to_val).collect();
    Val::Record(vec![
        ("id".to_string(), Val::String(g.id.0.clone())),
        ("grantee".to_string(), Val::String(g.grantee.clone())),
        ("capability".to_string(), Val::String(g.capability.clone())),
        ("params".to_string(), Val::List(params)),
        ("ttl".to_string(), grant_ttl_to_val(&g.ttl)),
        (
            "issuer".to_string(),
            Val::String(issuer_to_string(&g.issuer)),
        ),
        (
            "provenance".to_string(),
            Val::String(provenance_to_string(&g.provenance)),
        ),
        ("status".to_string(), grant_status_to_val(&g.status)),
        (
            "created-at".to_string(),
            Val::String(g.created_at.to_rfc3339()),
        ),
        (
            "expires-at".to_string(),
            match g.expires_at {
                Some(t) => Val::Option(Some(Box::new(Val::String(t.to_rfc3339())))),
                None => Val::Option(None),
            },
        ),
    ])
}

fn grant_info_list_to_val(grants: &[Grant]) -> Val {
    Val::List(grants.iter().map(grant_info_to_val).collect())
}

fn grant_request_from_val(
    v: &Val,
) -> Result<(String, Option<Vec<CapParam>>, Option<String>), CapGrantError> {
    let fields = match v {
        Val::Record(f) => f,
        _ => {
            return Err(CapGrantError::InvalidConfig(
                "grant-request: expected Val::Record".to_string(),
            ));
        }
    };
    let mut capability: Option<String> = None;
    let mut params: Option<Option<Vec<CapParam>>> = None;
    let mut justification: Option<Option<String>> = None;
    for (name, vv) in fields {
        match (name.as_str(), vv) {
            ("capability", Val::String(s)) => capability = Some(s.clone()),
            ("params", Val::Option(opt)) => match opt.as_deref() {
                None => params = Some(None),
                Some(inner) => params = Some(Some(cap_param_list_from_val(inner)?)),
            },
            ("justification", Val::Option(opt)) => match opt.as_deref() {
                None => justification = Some(None),
                Some(Val::String(s)) => justification = Some(Some(s.clone())),
                Some(other) => {
                    return Err(CapGrantError::InvalidConfig(format!(
                        "grant-request: justification expected option<string>, got {other:?}"
                    )));
                }
            },
            _ => {}
        }
    }
    let capability = capability.ok_or_else(|| {
        CapGrantError::InvalidConfig("grant-request: missing capability field".to_string())
    })?;
    // Audit-fix R3 (Codex Diff R3 W1): the WIT record `grant-request` declares
    // `params` and `justification` as `option<...>` fields, which means the
    // VALUE may be `option::none` but the FIELD itself must be present in the
    // encoded `Val::Record`. Defaulting a missing field to `None` would let
    // malformed input through; require the field to appear so a guest with a
    // mistyped record encoding gets `invalid-params` rather than silent
    // acceptance.
    let params = params.ok_or_else(|| {
        CapGrantError::InvalidConfig("grant-request: missing params field".to_string())
    })?;
    let justification = justification.ok_or_else(|| {
        CapGrantError::InvalidConfig("grant-request: missing justification field".to_string())
    })?;
    Ok((capability, params, justification))
}

fn grant_draft_from_val(v: &Val) -> Result<GrantDraft, CapGrantError> {
    let fields = match v {
        Val::Record(f) => f,
        _ => {
            return Err(CapGrantError::InvalidConfig(
                "grant-draft: expected Val::Record".to_string(),
            ));
        }
    };
    let mut capability: Option<String> = None;
    let mut params: Option<Vec<CapParam>> = None;
    let mut ttl: Option<GrantTtl> = None;
    for (name, vv) in fields {
        match (name.as_str(), vv) {
            ("capability", Val::String(s)) => capability = Some(s.clone()),
            ("params", v) => params = Some(cap_param_list_from_val(v)?),
            ("ttl", v) => ttl = Some(grant_ttl_from_val(v)?),
            _ => {}
        }
    }
    Ok(GrantDraft {
        capability: capability.ok_or_else(|| {
            CapGrantError::InvalidConfig("grant-draft: missing capability field".to_string())
        })?,
        // Audit-fix R2 (Codex Diff W2): the WIT contract declares `params:
        // list<cap-param>` as a REQUIRED field. Silently defaulting a missing
        // record field to `vec![]` would let malformed input through; the
        // empty-parent rule in the SubsetValidator (subset.rs:64) would then
        // accept any child params, allowing forward-shaped attacks against
        // the parent-cover invariant.
        params: params.ok_or_else(|| {
            CapGrantError::InvalidConfig("grant-draft: missing params field".to_string())
        })?,
        ttl: ttl.ok_or_else(|| {
            CapGrantError::InvalidConfig("grant-draft: missing ttl field".to_string())
        })?,
    })
}

fn chain_decision_to_val(d: &ChainDecision) -> Val {
    match d {
        ChainDecision::Approved(id) => Val::Variant(
            "approved".to_string(),
            Some(Box::new(Val::String(id.0.clone()))),
        ),
        ChainDecision::Denied(reason) => Val::Variant(
            "denied".to_string(),
            Some(Box::new(Val::String(reason.clone()))),
        ),
        ChainDecision::Pending => Val::Variant("pending".to_string(), None),
    }
}

/// 5 PRD `grant-error` variants ↔ 7 Rust `CapGrantError` variants.
/// `Db` and `Yaml` collapse onto `invalid-params("internal-error")` opaque
/// per §2.8 — never leaks raw `{e}` to WASM guests.
fn cap_grant_error_to_val(err: &CapGrantError) -> Val {
    let (case, payload) = match err {
        CapGrantError::NotFound(id) => ("not-found", id.0.clone()),
        CapGrantError::PermissionDenied(msg) => ("permission-denied", msg.clone()),
        CapGrantError::SubsetViolation(msg) => ("subset-violation", msg.clone()),
        CapGrantError::InvalidConfig(msg) => ("invalid-params", msg.clone()),
        CapGrantError::PresetNotFound(name) => ("preset-not-found", name.clone()),
        CapGrantError::Db(_) | CapGrantError::Yaml(_) => {
            ("invalid-params", "internal-error".to_string())
        }
    };
    Val::Variant(case.to_string(), Some(Box::new(Val::String(payload))))
}

/// Wrap a successful payload into the WIT `result<T, grant-error>` Ok arm.
fn ok_some(val: Val) -> Val {
    Val::Result(Ok(Some(Box::new(val))))
}

/// Wrap a [`CapGrantError`] into the WIT `result<T, grant-error>` error arm.
fn ok_err(err: &CapGrantError) -> Val {
    Val::Result(Err(Some(Box::new(cap_grant_error_to_val(err)))))
}
