//! `GrantCheck` impl (CONTRACT-121, MODULE-001 L1 gate).
//!
//! Capability-level: returns `Allow` if the grantee has any `Active`,
//! non-expired grant for the requested capability; `Deny` otherwise.
//! Parameter-level (MODULE-013-AC-23, dev-task-cascade-subset): a non-empty
//! `CapParams` is additionally validated against the held grants via
//! `SubsetValidatorImpl` — `Allow` iff a held grant covers the request.
//!
//! Slice C (2026-05-08): widened to surface `function: &str` (3rd arg)
//! per CONTRACT-121 trait widen. `authz.checked` event emission lives
//! here (NOT on `CapabilityInjector`); the impl reuses the store's
//! event_bus accessor (no separate `event_bus` field on `GrantCheckImpl`)
//! and consults its `authz_level: AuthzLevel` policy:
//!
//! - `AuthzLevel::DeniedOnly` (default per PRD §15.3.18 line 5510): emit
//!   `authz.checked` only on Deny outcomes (high-frequency Allow path
//!   unaffected — NFR `<5µs` per check stays intact via lazy `grant_id`
//!   computation).
//! - `AuthzLevel::All`: emit on every check (Allow + Deny).
//!
//! Parameter subset (MODULE-013-AC-23): a non-empty `CapParams` is projected
//! via the shared fail-closed `capability_subset::project_params` and validated
//! against the agent's held grants with `SubsetValidatorImpl::validate` — Allow
//! iff some held `Active`, non-expired grant for the capability covers the
//! request; a request whose params fail the projection returns Deny
//! (fail-closed preserved). `CapParams::Null` keeps the capability-level path.
//! The `function` arg is observability-only. WASM-call-frame param lowering into
//! `CapParams` remains a future M001 bootstrap concern, but the L1 subset
//! enforcement itself is wired; until a real caller supplies non-empty params,
//! the only production caller (`capability_injector`) passes `CapParams::empty()`,
//! so the subset path is reachable today only via direct Rust / tests.

use std::sync::Arc;

use advance_shared_types::capability::{CapParams, GrantDecision};
use advance_shared_types::traits::{GrantCheck, ToolsGrantReader};

use crate::data::{GrantId, GrantStatus};
use crate::events::authz_checked_event;
use crate::store::GrantStore;
use crate::subset::SubsetValidator;

/// Runtime-config knob for `authz.checked` emission policy. Constructor-only
/// in Slice C; future M001 bootstrap slice will thread `event-bus.authz-level`
/// from `runtime-config.yaml` (PRD §15.3.18 line 5510 hyphenated form is
/// canonical; MODULE-019 §2.10 line 520's underscore form `eventbus.authz_level`
/// reconciles to the hyphenated form in that future slice).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthzLevel {
    /// Default per PRD §15.3.18: emit `authz.checked` only on Deny outcomes.
    /// Allow path is high-frequency in production; suppressing it keeps the
    /// observability budget bounded and the L1 hot-path latency target intact.
    DeniedOnly,
    /// Opt-in policy: emit on both Allow and Deny outcomes. Used for audit-
    /// heavy deployments and for AC-14 + AC-21 verification fixtures.
    All,
}

/// `GrantCheck` impl (widened in Slice C; parameter-subset wired in
/// dev-task-cascade-subset / MODULE-013-AC-23). For a `CapParams::Null`
/// (whole-capability) call it authorizes at the capability level (held `Active`,
/// non-expired grant for the capability). For a non-empty `CapParams` it
/// ADDITIONALLY enforces CONTRACT-122 subset: the request is projected via the
/// shared fail-closed `capability_subset::project_params` and `Allow`ed iff a
/// held grant COVERS it (`SubsetValidatorImpl::validate`); a request whose params
/// fail projection → `Deny`. This closes the would-be elevation-of-privilege
/// where a narrowly-scoped grant (e.g. `fs.read: { read-paths: /tmp/foo }`) must
/// not authorize an `fs.read` request for a different path. The held grant's
/// stored `Vec<CapParam>` is canonical (validated at issue time); only the
/// request is projected.
pub struct GrantCheckImpl {
    store: Arc<GrantStore>,
    authz_level: AuthzLevel,
}

impl GrantCheckImpl {
    /// Construct with the default `AuthzLevel::DeniedOnly` policy.
    pub fn new(store: Arc<GrantStore>) -> Self {
        Self {
            store,
            authz_level: AuthzLevel::DeniedOnly,
        }
    }

    /// Construct with an explicit policy. Used by AC-14/AC-21 fixtures and
    /// (eventually) the M001 bootstrap slice that threads the runtime-config
    /// knob `event-bus.authz-level` into this constructor.
    pub fn with_authz_level(store: Arc<GrantStore>, authz_level: AuthzLevel) -> Self {
        Self { store, authz_level }
    }
}

impl GrantCheck for GrantCheckImpl {
    fn check(
        &self,
        agent_id: &str,
        capability: &str,
        function: &str,
        params: &CapParams,
    ) -> GrantDecision {
        // Step 0 — defense-in-depth length cap on `function` (closes Audit-fix
        // R4 Diff Warning 1): an attacker that can drive Deny outcomes (no
        // grant + arbitrary capability/function) could pump multi-megabyte
        // `function` strings into the event bus on the L1 hot path. Truncate
        // to 256 bytes BEFORE emit. **Behavior is silent-truncate** (NOT
        // Deny-on-overflow) — distinct from `consume`'s `consumed_by_function`
        // cap which returns InvalidConfig on overflow; check.rs's path is the
        // L1 invocation gate where returning Deny on a long function name
        // would block the call entirely (an authorization decision should
        // not depend on identifier length). Truncation preserves the
        // authorization outcome and bounds observability cost. Production
        // callers (M001 capability_injector) only pass
        // `format!("{namespace}::{name}")` strings bounded by HostFunctionSpec's
        // namespace+name registry, so the cap is unreachable in well-formed
        // runs (closes Audit-fix R8 Diff W1 misleading-comment finding).
        // Truncation produces an owned String only on the rare overflow path
        // (so the common <=256-byte case stays zero-alloc). On overflow we
        // append a `…` marker (Audit-fix R9 Diff W1) so auditors reading the
        // emitted event can distinguish truncation from a legitimate
        // 256-byte name. Adversarial-fix R2 (round 2): symmetric caps now
        // applied to `agent_id` + `capability` (Adv W4) + `function` so
        // attacker-influenced strings cannot exceed the bounded payload.
        // Control-char strip (Adv W5): replace ASCII control bytes (NUL,
        // newline, CR, escape, etc.) with `?` to prevent log-injection
        // into line-delimited downstream consumers.
        // Authorization uses the RAW inputs (agent_id, capability, function);
        // sanitization applies ONLY to event-bus emit (output safety).
        // Step 1 — MODULE-013-AC-23 (dev-task-cascade-subset): non-empty
        // `CapParams` are now wired into the L1 path. Project the request params
        // via the SHARED fail-closed projection (`capability_subset::project_params`
        // — identical whitelist / identity-loss guards as the spawn/submit
        // admission gate) and Allow iff some held `Active`, non-expired grant for
        // this capability COVERS the request under the CONTRACT-122 subset rules
        // (`SubsetValidatorImpl::validate(held_grant, request_draft)`). A request
        // whose params fail the projection → Deny (fail-closed preserved). The
        // held grant's stored `Vec<CapParam>` is already canonical (validated at
        // issue time); only the request is projected. `CapParams::Null`
        // (whole-capability) falls through to the unchanged capability-level path
        // (Step 2).
        if !matches!(params.as_value(), serde_json::Value::Null) {
            let now = chrono::Utc::now();
            let child_params =
                match crate::capability_subset::project_params(capability, params.as_value()) {
                    Ok(p) => p,
                    Err(e) => {
                        let decision = GrantDecision::Deny(format!(
                            "cap-grant L1 subset: request params rejected by fail-closed \
                             projection: {e}"
                        ));
                        self.maybe_emit(
                            agent_id, capability, function, &decision,
                            /* allowed_grant_id = */ None,
                        );
                        return decision;
                    }
                };
            // `ttl` is not consulted by `SubsetValidatorImpl::validate` (it reads
            // only `capability` + `params`); Persistent is a neutral placeholder.
            let child_draft = crate::data::GrantDraft {
                capability: capability.to_string(),
                params: child_params,
                ttl: crate::data::GrantTtl::Persistent,
            };
            let validator = crate::subset::SubsetValidatorImpl::new();
            let candidates = self.store.list_by_grantee(agent_id);
            // Pick the lex-min id among grants that ACTUALLY COVER the request
            // (status + capability + non-expired AND pass subset validation), so
            // the emitted Allow-path `grant_id` is the covering grant, not merely
            // a capability match. Deterministic via id sort.
            let covering_id: Option<GrantId> = {
                let mut matched: Vec<&crate::data::Grant> = candidates
                    .iter()
                    .filter(|g| {
                        g.status == GrantStatus::Active
                            && g.capability == capability
                            && g.expires_at.map_or(true, |t| t > now)
                            && validator.validate(g, &child_draft).is_ok()
                    })
                    .collect();
                matched.sort_by(|a, b| a.id.as_str().cmp(b.id.as_str()));
                matched.first().map(|g| g.id.clone())
            };
            let decision = if covering_id.is_some() {
                GrantDecision::Allow
            } else {
                GrantDecision::Deny(format!(
                    "no active grant covers {capability} with the requested params"
                ))
            };
            self.maybe_emit_picked(
                agent_id,
                capability,
                function,
                &decision,
                covering_id.as_ref(),
            );
            return decision;
        }

        // Step 2 — capability-level grant check (raw inputs).
        // Adversarial-fix R6 W3 — defense-in-depth: also verify
        // `expires_at > now()` so an effectively-expired grant in the
        // pre-sweeper window (between deadline and next sweeper tick,
        // ~1s default) does NOT authorize. The sweeper's `expire_ids`
        // flips status from Active → Expired asynchronously; without this
        // check, the L1 hot path Allows during the orphan window. Cost:
        // one Utc::now() + per-candidate compare; negligible vs the
        // RwLock acquisitions already present.
        let now = chrono::Utc::now();
        let candidates = self.store.list_by_grantee(agent_id);
        let allowed = candidates.iter().any(|g| {
            g.status == GrantStatus::Active
                && g.capability == capability
                && g.expires_at.map_or(true, |t| t > now)
        });

        // Step 3 — emit-or-skip decision.
        let decision = if allowed {
            GrantDecision::Allow
        } else {
            GrantDecision::Deny(format!("no active grant for {capability}"))
        };

        // Step 4 — lazy grant_id selection, only if we will actually emit.
        // Pass the same `now` used in step 2 to keep the matched-grant
        // predicate consistent across both checks (closes Adversarial R7
        // I1: avoids a race where the second Utc::now() call sees a
        // candidate's expires_at flipping mid-call).
        let allowed_grant_id = if allowed { Some(()) } else { None };
        self.maybe_emit_with_lookup(
            agent_id,
            capability,
            function,
            &decision,
            allowed_grant_id,
            &candidates,
            now,
        );

        decision
    }
}

/// Sanitize a caller-supplied string for event-bus emit:
/// - Truncate to ≤ `cap` bytes at the largest UTF-8-safe boundary.
/// - Replace ASCII control bytes (`\0`, `\n`, `\r`, ESC, etc.) with `?`
///   to prevent log-injection into line-delimited downstream consumers.
/// - Append `…` (U+2026) on truncation so auditors can distinguish.
///
/// Common <=cap-byte + control-free path stays close to zero-alloc
/// (avoids `String` build when input passes through unchanged).
fn sanitize_event_string(s: &str, cap: usize) -> String {
    let needs_truncate = s.len() > cap;
    let mut out = String::with_capacity(if needs_truncate { cap + 4 } else { s.len() });
    let bound = if needs_truncate { cap } else { s.len() };
    // Find UTF-8-safe boundary at or below `bound`.
    let mut end = bound;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    for ch in s[..end].chars() {
        // Strip ASCII control chars (`Cc` general category) AND Unicode
        // bidi/format chars (`Cf` general category — RLM/LRM, ZWJ/ZWNJ,
        // LRE/RLE/PDF/LRO/RLO, LRI/RLI/FSI/PDI). Both classes are
        // log-display-spoofing vectors when echoed into line-rendered
        // downstream consumers. Rust's `char::is_control()` covers Cc
        // only; we enumerate the relevant Cf ranges inline.
        // Closes Adversarial round-13 W1.
        let is_bidi_format = matches!(
            ch,
            '\u{200C}' | '\u{200D}' | '\u{200E}' | '\u{200F}' |
            '\u{202A}'..='\u{202E}' |
            '\u{2066}'..='\u{2069}'
        );
        if ch.is_control() || is_bidi_format {
            out.push('?');
        } else {
            out.push(ch);
        }
    }
    if needs_truncate {
        out.push('\u{2026}');
    }
    out
}

impl GrantCheckImpl {
    /// Emit `authz.checked` for the fail-closed precondition path (no
    /// candidates to look up — grant_id is always `""`).
    ///
    /// `agent_id` is passed through RAW (preserves Event.actor routing
    /// integrity — M001 ComponentCtx supplies it from a trusted runtime
    /// path, so sanitization is unnecessary AND would collapse distinct
    /// actors whose identifiers differ only beyond byte-256 / via control
    /// bytes — closes Adversarial round-3 W1).
    fn maybe_emit(
        &self,
        agent_id: &str,
        capability: &str,
        function: &str,
        decision: &GrantDecision,
        _allowed_grant_id: Option<()>,
    ) {
        if !self.should_emit(decision) {
            return;
        }
        const STR_CAP: usize = 256;
        // Sanitize OUTPUT-bound payload fields only; agent_id is the routing
        // key for Event.actor and must remain raw.
        let capability_s = sanitize_event_string(capability, STR_CAP);
        let function_s = sanitize_event_string(function, STR_CAP);
        let (decision_str, grant_id) = decision_to_payload(decision, None);
        self.store.event_bus().emit(authz_checked_event(
            agent_id,
            capability_s.as_str(),
            function_s.as_str(),
            decision_str,
            grant_id,
        ));
    }

    /// Emit `authz.checked` with a pre-selected `grant_id`. Used by the L1
    /// subset path (MODULE-013-AC-23), which computes the covering grant itself,
    /// so the emitted Allow-path `grant_id` is the grant that actually passed
    /// subset validation (not merely a capability match). `picked` is `None` on
    /// the Deny path; `decision_to_payload` maps it to the `""` sentinel.
    fn maybe_emit_picked(
        &self,
        agent_id: &str,
        capability: &str,
        function: &str,
        decision: &GrantDecision,
        picked: Option<&GrantId>,
    ) {
        if !self.should_emit(decision) {
            return;
        }
        let (decision_str, grant_id_str) = decision_to_payload(decision, picked);
        const STR_CAP: usize = 256;
        // Sanitize OUTPUT-bound payload fields only; agent_id stays raw (routing key).
        let capability_s = sanitize_event_string(capability, STR_CAP);
        let function_s = sanitize_event_string(function, STR_CAP);
        self.store.event_bus().emit(authz_checked_event(
            agent_id,
            capability_s.as_str(),
            function_s.as_str(),
            decision_str,
            grant_id_str,
        ));
    }

    /// Emit `authz.checked` with lazy `grant_id` selection from candidates
    /// (sort + pick first only when allowed AND will emit).
    fn maybe_emit_with_lookup(
        &self,
        agent_id: &str,
        capability: &str,
        function: &str,
        decision: &GrantDecision,
        allowed_grant_id: Option<()>,
        candidates: &[crate::data::Grant],
        now: chrono::DateTime<chrono::Utc>,
    ) {
        if !self.should_emit(decision) {
            return;
        }
        // Lazy: only sort + pick when emit is happening AND outcome is Allow.
        // Filter mirrors Step 2's predicate (status==Active + capability match
        // + expires_at>now) using the SAME `now` value passed from check()
        // so the picked grant_id corresponds to the actual allow-deciding
        // grant (closes Adversarial R7 I1 race-window inconsistency).
        let picked: Option<GrantId> = match (decision, allowed_grant_id) {
            (GrantDecision::Allow, Some(())) => {
                let mut matched: Vec<&crate::data::Grant> = candidates
                    .iter()
                    .filter(|g| {
                        g.status == GrantStatus::Active
                            && g.capability == capability
                            && g.expires_at.map_or(true, |t| t > now)
                    })
                    .collect();
                matched.sort_by(|a, b| a.id.as_str().cmp(b.id.as_str()));
                matched.first().map(|g| g.id.clone())
            }
            _ => None,
        };
        let (decision_str, grant_id_str) = decision_to_payload(decision, picked.as_ref());
        const STR_CAP: usize = 256;
        // Sanitize OUTPUT-bound payload fields only; agent_id is the routing
        // key for Event.actor and must remain raw (closes Adversarial
        // round-3 W1).
        let capability_s = sanitize_event_string(capability, STR_CAP);
        let function_s = sanitize_event_string(function, STR_CAP);
        self.store.event_bus().emit(authz_checked_event(
            agent_id,
            capability_s.as_str(),
            function_s.as_str(),
            decision_str,
            grant_id_str,
        ));
    }

    fn should_emit(&self, decision: &GrantDecision) -> bool {
        match (decision, self.authz_level) {
            (GrantDecision::Deny(_), _) => true,
            (GrantDecision::Allow, AuthzLevel::All) => true,
            (GrantDecision::Allow, AuthzLevel::DeniedOnly) => false,
        }
    }
}

/// Map (decision, picked_grant_id) → ("allowed"|"denied", grant_id_str).
/// `grant_id_str` is "" sentinel for Deny or when no match.
fn decision_to_payload<'a>(
    decision: &GrantDecision,
    picked: Option<&'a GrantId>,
) -> (&'static str, &'a str) {
    match decision {
        GrantDecision::Allow => ("allowed", picked.map(|g| g.as_str()).unwrap_or("")),
        GrantDecision::Deny(_) => ("denied", ""),
    }
}

/// CONTRACT-183 — `ToolsGrantReader` provider (Wave-15 Lane E).
///
/// Projects an agent's effective WASM-tool allowlist from the `tools.ids` subset
/// key of its active, unexpired `"tools"` grants, REALIZING CONTRACT-165's
/// documented `list_wasm_tools` post-L1-`tools`-grant filter (consumed by
/// MODULE-017 cap-tools' `CallableInventory`). Read-only LIST projection — NOT an
/// authorization gate (cf. [`GrantCheckImpl`]).
pub struct ToolsGrantReaderImpl {
    store: Arc<GrantStore>,
}

impl ToolsGrantReaderImpl {
    pub fn new(store: Arc<GrantStore>) -> Self {
        Self { store }
    }
}

// Manual `Debug`: `GrantStore` is not `Debug` (it holds `Arc<dyn EventBusEmit>`),
// so `#[derive(Debug)]` would not compile. The `ToolsGrantReader` trait requires
// a `Debug` supertrait (so MODULE-017's `CallableInventory` keeps `#[derive(Debug)]`);
// `finish_non_exhaustive` satisfies it without exposing the store internals.
impl std::fmt::Debug for ToolsGrantReaderImpl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ToolsGrantReaderImpl")
            .finish_non_exhaustive()
    }
}

impl ToolsGrantReader for ToolsGrantReaderImpl {
    fn tool_allowlist(&self, agent_id: &str) -> Option<Vec<String>> {
        let now = chrono::Utc::now();
        // Colon→bare grantee bridge: a grant may be seeded under the bare cap-id OR
        // the colon `agent:`-prefixed id; query both forms (de-duped by `GrantId`) so
        // the assembler's colon `ctx.agent_id` resolves a bare-keyed grant too.
        let mut grants = self.store.list_by_grantee(agent_id);
        if let Some(bare) = agent_id.strip_prefix("agent:") {
            if bare != agent_id {
                for g in self.store.list_by_grantee(bare) {
                    if !grants.iter().any(|h| h.id == g.id) {
                        grants.push(g);
                    }
                }
            }
        }

        let mut ids: Vec<String> = Vec::new();
        let mut has_tools_grant = false;
        let mut wildcard = false;
        for g in &grants {
            if g.status == GrantStatus::Active
                && g.capability == "tools"
                && g.expires_at.map_or(true, |t| t > now)
            {
                has_tools_grant = true;
                match g.params.iter().find(|p| p.key == "ids") {
                    // Own inline CSV split (NOT subset.rs's private `parse_csv`/`get_param`);
                    // matches cap-grant's `tools.ids` CSV encoding.
                    Some(p) => {
                        for id in p.value.split(',').map(str::trim).filter(|s| !s.is_empty()) {
                            if !ids.iter().any(|x| x == id) {
                                ids.push(id.to_string());
                            }
                        }
                    }
                    // A `"tools"` grant with no `ids` narrowing ⇒ wildcard (all WASM
                    // tools), parity with the capability-level `GrantCheck` allow.
                    None => wildcard = true,
                }
            }
        }

        if !has_tools_grant {
            // No active `"tools"` grant ⇒ deny all WASM tools.
            return Some(Vec::new());
        }
        if wildcard {
            // Unrestricted ⇒ no filtering (the consumer returns the full set).
            return None;
        }
        Some(ids)
    }
}
