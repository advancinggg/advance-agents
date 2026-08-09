//! EventBus payload-builder helpers for all 9 PRD §15.3.18 events
//! (MODULE-013 §2.3).
//!
//! Slice A (4 events): grant.issued, grant.revoked, grant.consumed, grant.expired.
//! Slice B (3 events): grant.narrowed, preset.applied, resolver.invoked.
//! Slice C (2 events): authz.checked, grant.delegated. Slice C also widens
//! grant.consumed to include `consumed_by_function` per PRD §15.3.18.

use advance_shared_types::event::Event;
use chrono::Utc;
use serde_json::json;
use uuid::Uuid;

use crate::data::{CapParam, Grant, GrantId, GrantTtl};

fn new_event(agent_id: &str, event_type: &str, payload: serde_json::Value) -> Event {
    Event {
        id: Uuid::new_v4().to_string(),
        timestamp: Utc::now(),
        agent_id: agent_id.to_string(),
        task_id: None,
        run_id: None,
        execution_id: None,
        trace_id: String::new(),
        span_id: String::new(),
        parent_span_id: None,
        event_type: event_type.to_string(),
        payload,
        duration_ms: None,
    }
}

fn ttl_string(ttl: &GrantTtl) -> String {
    match ttl {
        GrantTtl::Once => "once".to_string(),
        GrantTtl::Lifecycle => "lifecycle".to_string(),
        GrantTtl::Persistent => "persistent".to_string(),
        GrantTtl::Duration(ms) => format!("duration:{ms}"),
        GrantTtl::Until(t) => format!("until:{}", t.to_rfc3339()),
    }
}

fn issuer_string(g: &Grant) -> String {
    match &g.issuer {
        crate::data::GrantIssuer::Config => "config".to_string(),
        crate::data::GrantIssuer::Parent(id) => format!("parent:{id}"),
        crate::data::GrantIssuer::Resolver(c) => format!("resolver:{c}"),
        crate::data::GrantIssuer::Admin => "admin".to_string(),
    }
}

fn provenance_string(g: &Grant) -> String {
    match &g.provenance {
        crate::data::GrantProvenance::StaticConfig => "static-config".to_string(),
        crate::data::GrantProvenance::Delegated(id) => format!("delegated:{id}"),
        crate::data::GrantProvenance::Requested => "requested".to_string(),
        crate::data::GrantProvenance::Preset(n) => format!("preset:{n}"),
    }
}

/// `grant.issued` — 7 PRD-mandated fields verbatim.
pub fn grant_issued_event(g: &Grant) -> Event {
    let payload = json!({
        "grant_id": g.id.as_str(),
        "grantee": g.grantee,
        "capability": g.capability,
        "params": g.params,
        "ttl": ttl_string(&g.ttl),
        "issuer": issuer_string(g),
        "provenance": provenance_string(g),
    });
    new_event(&g.grantee, "grant.issued", payload)
}

/// `grant.revoked` — 5-field PRD-verbatim. `cascade_count` semantic:
/// root carries the descendant count; descendants carry 0; flat sweeps
/// (`revoke_by_grantee`) carry 0 per emission.
pub fn grant_revoked_event(
    grant_id: &GrantId,
    grantee: &str,
    capability: &str,
    revoked_by: &str,
    cascade_count: usize,
) -> Event {
    let payload = json!({
        "grant_id": grant_id.as_str(),
        "grantee": grantee,
        "capability": capability,
        "revoked_by": revoked_by,
        "cascade_count": cascade_count,
    });
    new_event(grantee, "grant.revoked", payload)
}

/// `grant.consumed` — 4-field PRD §15.3.18 payload (Slice C widened from
/// the Slice-A 3-field shape). `consumed_by_function` is the host-fn name
/// passed to `GrantStore::consume(id, consumed_by_function)`. Non-empty
/// validation only — host-fn names like `ns-fs::scan` legitimately contain
/// `::` so the bilateral `:` ban does NOT apply to this field.
pub fn grant_consumed_event(
    grant_id: &GrantId,
    grantee: &str,
    capability: &str,
    consumed_by_function: &str,
) -> Event {
    let payload = json!({
        "grant_id": grant_id.as_str(),
        "grantee": grantee,
        "capability": capability,
        "consumed_by_function": consumed_by_function,
    });
    new_event(grantee, "grant.consumed", payload)
}

/// `grant.expired` — 4-field PRD-verbatim. `original_ttl` is the wire-format
/// string of the `GrantTtl` that caused expiration.
pub fn grant_expired_event(
    grant_id: &GrantId,
    grantee: &str,
    capability: &str,
    original_ttl: &GrantTtl,
) -> Event {
    let payload = json!({
        "grant_id": grant_id.as_str(),
        "grantee": grantee,
        "capability": capability,
        "original_ttl": ttl_string(original_ttl),
    });
    new_event(grantee, "grant.expired", payload)
}

// ============================================================================
// Slice B event helpers (PRD §15.3.18, MODULE-013 §2.3 — 3 new event types).
// ============================================================================

/// `grant.narrowed` — 4-field PRD-verbatim payload. Emitted by
/// `GrantStore::narrow` after the new (narrowed) grant is inserted.
///
/// `narrowed_by` is a caller-supplied actor id (Slice B test fixtures pass
/// a stable test string; Slice D's WIT layer passes the actual WIT caller
/// id). PRD §15.3.18 does not formally constrain the actor identity; the
/// caller-supplied parameter keeps Slice B agnostic to WIT-layer concerns.
pub fn grant_narrowed_event(
    new_grant_id: &GrantId,
    old_params: &[CapParam],
    new_params: &[CapParam],
    narrowed_by: &str,
) -> Event {
    let payload = json!({
        "grant_id": new_grant_id.as_str(),
        "old_params": old_params,
        "new_params": new_params,
        "narrowed_by": narrowed_by,
    });
    // agent_id field on the Event is informational; we use `narrowed_by` so
    // event consumers can group narrow events by the actor that issued them.
    new_event(narrowed_by, "grant.narrowed", payload)
}

/// `preset.applied` — 4-field PRD payload. `grants_revoked` and
/// `grants_created` are SCALAR COUNTS (matches the `cascade_count` precedent
/// in `grant.revoked` rather than emitting a list of grant ids — keeps the
/// event payload bounded; full id lists are returned to the caller via
/// `ApplyPresetResult` instead).
pub fn preset_applied_event(
    target_agent: &str,
    preset_name: &str,
    grants_revoked: usize,
    grants_created: usize,
) -> Event {
    let payload = json!({
        "target_agent": target_agent,
        "preset_name": preset_name,
        "grants_revoked": grants_revoked,
        "grants_created": grants_created,
    });
    new_event(target_agent, "preset.applied", payload)
}

/// `resolver.invoked` — 4-field PRD-verbatim payload. Emitted by
/// `ResolverChain::evaluate` after each resolver runs. Spec §2.3 explicitly
/// excludes `pending` from the `decision` enum: the Pending state is internal
/// to MODULE-013 and surfaces via `grant-decision::pending` at the WIT
/// boundary, NOT as an event. Pending outcomes therefore emit `decision:
/// "abstain"` for telemetry-payload conformance; the actual chain-level
/// decision still propagates via `ChainDecision::Pending`.
pub fn resolver_invoked_event(
    agent_id: &str,
    capability: &str,
    resolver_type: &str,
    decision: &str,
) -> Event {
    debug_assert!(
        matches!(decision, "approve" | "deny" | "abstain"),
        "resolver.invoked.decision must be approve|deny|abstain per PRD §15.3.18 (got {decision:?})"
    );
    let payload = json!({
        "agent_id": agent_id,
        "capability": capability,
        "resolver_type": resolver_type,
        "decision": decision,
    });
    new_event(agent_id, "resolver.invoked", payload)
}

// ============================================================================
// Slice C event helpers (PRD §15.3.18, MODULE-013 §2.3 — 2 new event types).
// ============================================================================

/// `authz.checked` — 5-field PRD-verbatim payload. Emitted by
/// `GrantCheckImpl::check` per its `AuthzLevel` policy (DeniedOnly default;
/// opt-in All via the future M001 bootstrap slice that wires
/// `event-bus.authz-level` from runtime-config).
///
/// `decision` is `"allowed"` | `"denied"`. `grant_id` is the matching grant id
/// for Allow (lexicographic-ASC first) or empty string for Deny (sentinel —
/// PRD §15.3.18 schema is unconstrained on emptiness).
pub fn authz_checked_event(
    agent_id: &str,
    capability: &str,
    function: &str,
    decision: &str,
    grant_id: &str,
) -> Event {
    debug_assert!(
        matches!(decision, "allowed" | "denied"),
        "authz.checked.decision must be allowed|denied per PRD §15.3.18 (got {decision:?})"
    );
    let payload = json!({
        "agent_id": agent_id,
        "capability": capability,
        "function": function,
        "decision": decision,
        "grant_id": grant_id,
    });
    new_event(agent_id, "authz.checked", payload)
}

/// `grant.delegated` — 6-field PRD-verbatim payload. Emitted by
/// `GrantStore::delegate_grant` after the new child grant is inserted.
///
/// `parent_agent` = `caller_id` = parent grant's grantee per Slice-C semantic
/// (the agent that holds the parent grant initiates the delegation).
/// Cross-agent delegation policy lands in Slice D's WIT layer.
pub fn grant_delegated_event(
    grant_id: &GrantId,
    parent_grant_id: &GrantId,
    parent_agent: &str,
    child_agent: &str,
    capability: &str,
    params: &[CapParam],
) -> Event {
    let payload = json!({
        "grant_id": grant_id.as_str(),
        "parent_grant_id": parent_grant_id.as_str(),
        "parent_agent": parent_agent,
        "child_agent": child_agent,
        "capability": capability,
        "params": params,
    });
    new_event(parent_agent, "grant.delegated", payload)
}
