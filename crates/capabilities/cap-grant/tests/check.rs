//! GrantCheck regression: T-A5 (Slice A) + T-C1..T-C2c + T-C10 (Slice C).

mod common;

use advance_shared_types::capability::{CapParams, GrantDecision};
use advance_shared_types::traits::GrantCheck;
use cap_grant::data::{
    CapParam, Grant, GrantId, GrantIssuer, GrantProvenance, GrantStatus, GrantTtl,
};
use cap_grant::{AuthzLevel, GrantCheckImpl};
use chrono::Utc;
use std::sync::Arc;

use crate::common::make_store;

/// Helper: build a Persistent fs grant for `agent` with id `g_id`.
fn fs_grant(g_id: &str, agent: &str) -> Grant {
    Grant {
        id: GrantId::new(g_id),
        grantee: agent.to_string(),
        capability: "fs".to_string(),
        params: vec![],
        ttl: GrantTtl::Persistent,
        issuer: GrantIssuer::Config,
        provenance: GrantProvenance::StaticConfig,
        status: GrantStatus::Active,
        created_at: Utc::now(),
        expires_at: None,
    }
}

// T-A5 — Regression — GrantCheckImpl Allow then Deny.
#[test]
fn grant_check_impl_allows_then_denies() {
    let (store, _bus, _h) = make_store();

    // No grants → Deny.
    let check: Arc<dyn GrantCheck> = Arc::new(GrantCheckImpl::new(store.clone()));
    let d1 = check.check("alice", "fs", "ns-fs::read", &CapParams::empty());
    assert!(matches!(d1, GrantDecision::Deny(_)));

    // Insert grant for ("alice", "fs") → Allow.
    let g = Grant {
        id: GrantId::new("g1"),
        grantee: "alice".to_string(),
        capability: "fs".to_string(),
        params: vec![],
        ttl: GrantTtl::Persistent,
        issuer: GrantIssuer::Config,
        provenance: GrantProvenance::StaticConfig,
        status: GrantStatus::Active,
        created_at: Utc::now(),
        expires_at: None,
    };
    store.insert(g).unwrap();
    let d2 = check.check("alice", "fs", "ns-fs::read", &CapParams::empty());
    assert!(matches!(d2, GrantDecision::Allow));

    // Different capability → Deny.
    let d3 = check.check("alice", "http", "ns-http::get", &CapParams::empty());
    assert!(matches!(d3, GrantDecision::Deny(_)));

    // Different grantee → Deny.
    let d4 = check.check("bob", "fs", "ns-fs::read", &CapParams::empty());
    assert!(matches!(d4, GrantDecision::Deny(_)));
}

// ============================================================================
// Slice C tests — AC-14 GrantCheck.check trait widen + authz.checked emission.
// ============================================================================

// T-C1 — DeniedOnly + no grants → 1 authz.checked Deny event with grant_id="".
#[test]
fn grant_check_emits_authz_checked_on_deny_default_policy() {
    let (store, bus, _h) = make_store();
    let check: Arc<dyn GrantCheck> = Arc::new(GrantCheckImpl::new(store.clone()));
    let d = check.check("alice", "fs", "ns-fs::read", &CapParams::empty());
    assert!(matches!(d, GrantDecision::Deny(_)));
    assert_eq!(bus.count_of("authz.checked"), 1);
    let evt = bus.first_of("authz.checked").expect("event present");
    assert_eq!(evt.payload["decision"], "denied");
    assert_eq!(evt.payload["grant_id"], "");
    assert_eq!(evt.payload["function"], "ns-fs::read");
    assert_eq!(evt.payload["agent_id"], "alice");
    assert_eq!(evt.payload["capability"], "fs");
}

// T-C2 — DeniedOnly + Allow path → 0 authz.checked events.
#[test]
fn grant_check_no_emit_on_allow_under_denied_only() {
    let (store, bus, _h) = make_store();
    store.insert(fs_grant("g-alice-fs", "alice")).unwrap();
    let check: Arc<dyn GrantCheck> = Arc::new(GrantCheckImpl::new(store.clone()));
    let d = check.check("alice", "fs", "ns-fs::read", &CapParams::empty());
    assert!(matches!(d, GrantDecision::Allow));
    assert_eq!(bus.count_of("authz.checked"), 0);
}

// T-C2b — All policy + Allow path → 1 authz.checked Allow event with deterministic grant_id.
#[test]
fn grant_check_emits_on_allow_under_authz_level_all() {
    let (store, bus, _h) = make_store();
    store.insert(fs_grant("g-alice-fs", "alice")).unwrap();
    let check: Arc<dyn GrantCheck> = Arc::new(GrantCheckImpl::with_authz_level(
        store.clone(),
        AuthzLevel::All,
    ));
    let d = check.check("alice", "fs", "ns-fs::read", &CapParams::empty());
    assert!(matches!(d, GrantDecision::Allow));
    assert_eq!(bus.count_of("authz.checked"), 1);
    let evt = bus.first_of("authz.checked").expect("event present");
    assert_eq!(evt.payload["decision"], "allowed");
    assert_eq!(evt.payload["grant_id"], "g-alice-fs");
    assert_eq!(evt.payload["function"], "ns-fs::read");
}

// T-C2c — non-empty CapParams Deny regression. NOTE (dev-task-cascade-subset /
// AC-23): this no longer Denies because "non-empty params are unconditionally
// fail-closed" — that behavior was replaced by real L1 subset validation. It
// Denies because the key `"path"` is NOT in the `fs` projection whitelist
// (`read-paths` / `write-paths` only), so the shared fail-closed projection
// rejects the request → Deny. (A valid-key whole-capability/subset Allow is
// covered by the AC-23 tests below.)
#[test]
fn grant_check_fail_closed_on_unprojectable_cap_params() {
    let (store, bus, _h) = make_store();
    store.insert(fs_grant("g-alice-fs", "alice")).unwrap();
    let check: Arc<dyn GrantCheck> = Arc::new(GrantCheckImpl::new(store.clone()));
    let cap_params = CapParams::from(serde_json::json!({"path": "/foo"}));
    let d = check.check("alice", "fs", "ns-fs::read", &cap_params);
    assert!(matches!(d, GrantDecision::Deny(_)));
    // DeniedOnly emits the Deny event.
    assert_eq!(bus.count_of("authz.checked"), 1);
    let evt = bus.first_of("authz.checked").expect("event present");
    assert_eq!(evt.payload["decision"], "denied");
    assert_eq!(evt.payload["grant_id"], "");
}

// T-C10 — function arg propagates from check arg → event payload.
#[test]
fn grant_check_function_field_propagates_to_authz_event() {
    let (store, bus, _h) = make_store();
    let check: Arc<dyn GrantCheck> = Arc::new(GrantCheckImpl::new(store.clone()));
    let _ = check.check("alice", "secrets", "ns-secrets::get", &CapParams::empty());
    let evt = bus.first_of("authz.checked").expect("event present");
    assert_eq!(evt.payload["function"], "ns-secrets::get");
}

// ============================================================================
// MODULE-013-T38 — AC-23: L1 invocation-gate parameter subset
// (dev-task-cascade-subset). Non-empty CapParams validated against held grants
// via SubsetValidatorImpl; Allow iff a held grant covers the request.
// ============================================================================

/// Build a grant with explicit capability + params + id for `agent`.
fn grant_with_params(g_id: &str, agent: &str, capability: &str, params: Vec<CapParam>) -> Grant {
    Grant {
        id: GrantId::new(g_id),
        grantee: agent.to_string(),
        capability: capability.to_string(),
        params,
        ttl: GrantTtl::Persistent,
        issuer: GrantIssuer::Config,
        provenance: GrantProvenance::StaticConfig,
        status: GrantStatus::Active,
        created_at: Utc::now(),
        expires_at: None,
    }
}

fn cp(key: &str, value: &str) -> CapParam {
    CapParam {
        key: key.to_string(),
        value: value.to_string(),
    }
}

// T38-1 — exact-equal params → Allow.
#[test]
fn ac23_l1_subset_allow_on_exact_equal_params() {
    let (store, _bus, _h) = make_store();
    store
        .insert(grant_with_params(
            "g1",
            "alice",
            "fs",
            vec![cp("read-paths", "/tmp")],
        ))
        .unwrap();
    let check: Arc<dyn GrantCheck> = Arc::new(GrantCheckImpl::new(store.clone()));
    let req = CapParams::from(serde_json::json!({"read-paths": "/tmp"}));
    assert!(matches!(
        check.check("alice", "fs", "ns-fs::read", &req),
        GrantDecision::Allow
    ));
}

// T38-2 — strict subset (child path under parent) → Allow.
#[test]
fn ac23_l1_subset_allow_on_strict_subset() {
    let (store, _bus, _h) = make_store();
    store
        .insert(grant_with_params(
            "g1",
            "alice",
            "fs",
            vec![cp("read-paths", "/tmp")],
        ))
        .unwrap();
    let check: Arc<dyn GrantCheck> = Arc::new(GrantCheckImpl::new(store.clone()));
    let req = CapParams::from(serde_json::json!({"read-paths": "/tmp/foo"}));
    assert!(matches!(
        check.check("alice", "fs", "ns-fs::read", &req),
        GrantDecision::Allow
    ));
}

// T38-3 — non-subset (child path outside parent) → Deny.
#[test]
fn ac23_l1_subset_deny_on_non_subset() {
    let (store, _bus, _h) = make_store();
    store
        .insert(grant_with_params(
            "g1",
            "alice",
            "fs",
            vec![cp("read-paths", "/tmp")],
        ))
        .unwrap();
    let check: Arc<dyn GrantCheck> = Arc::new(GrantCheckImpl::new(store.clone()));
    let req = CapParams::from(serde_json::json!({"read-paths": "/etc"}));
    assert!(matches!(
        check.check("alice", "fs", "ns-fs::read", &req),
        GrantDecision::Deny(_)
    ));
}

// T38-4 — no grant covers the capability (non-empty params) → Deny.
#[test]
fn ac23_l1_subset_deny_when_no_grant() {
    let (store, _bus, _h) = make_store();
    let check: Arc<dyn GrantCheck> = Arc::new(GrantCheckImpl::new(store.clone()));
    let req = CapParams::from(serde_json::json!({"read-paths": "/tmp"}));
    assert!(matches!(
        check.check("alice", "fs", "ns-fs::read", &req),
        GrantDecision::Deny(_)
    ));
}

// T38-5 — whole-capability grant (empty params) covers any non-empty request → Allow.
#[test]
fn ac23_l1_subset_whole_capability_grant_covers_any() {
    let (store, _bus, _h) = make_store();
    store
        .insert(grant_with_params("g1", "alice", "fs", vec![]))
        .unwrap();
    let check: Arc<dyn GrantCheck> = Arc::new(GrantCheckImpl::new(store.clone()));
    let req = CapParams::from(serde_json::json!({"read-paths": "/anything/deep"}));
    assert!(matches!(
        check.check("alice", "fs", "ns-fs::read", &req),
        GrantDecision::Allow
    ));
}

// T38-6 — numeric `≤` family (messaging.max-fanout): subset Allow, exceed Deny.
#[test]
fn ac23_l1_subset_numeric_le() {
    let (store, _bus, _h) = make_store();
    store
        .insert(grant_with_params(
            "g1",
            "alice",
            "messaging",
            vec![cp("max-fanout", "5")],
        ))
        .unwrap();
    let check: Arc<dyn GrantCheck> = Arc::new(GrantCheckImpl::new(store.clone()));
    let ok = CapParams::from(serde_json::json!({"max-fanout": 3}));
    assert!(matches!(
        check.check("alice", "messaging", "ns-msg::send", &ok),
        GrantDecision::Allow
    ));
    let bad = CapParams::from(serde_json::json!({"max-fanout": 9}));
    assert!(matches!(
        check.check("alice", "messaging", "ns-msg::send", &bad),
        GrantDecision::Deny(_)
    ));
}

// T38-7 — fail-closed projection: unknown key + nested object → Deny.
#[test]
fn ac23_l1_subset_fail_closed_on_unprojectable() {
    let (store, _bus, _h) = make_store();
    store
        .insert(grant_with_params(
            "g1",
            "alice",
            "fs",
            vec![cp("read-paths", "/tmp")],
        ))
        .unwrap();
    let check: Arc<dyn GrantCheck> = Arc::new(GrantCheckImpl::new(store.clone()));
    // Unknown key for fs (whitelist = read-paths/write-paths).
    let unknown = CapParams::from(serde_json::json!({"path": "/tmp/foo"}));
    assert!(matches!(
        check.check("alice", "fs", "ns-fs::read", &unknown),
        GrantDecision::Deny(_)
    ));
    // Nested object value.
    let nested = CapParams::from(serde_json::json!({"read-paths": {"x": 1}}));
    assert!(matches!(
        check.check("alice", "fs", "ns-fs::read", &nested),
        GrantDecision::Deny(_)
    ));
}

// T38-8 — expired covering grant does not authorize.
#[test]
fn ac23_l1_subset_expired_grant_denies() {
    let (store, _bus, _h) = make_store();
    let mut g = grant_with_params("g1", "alice", "fs", vec![cp("read-paths", "/tmp")]);
    g.expires_at = Some(Utc::now() - chrono::Duration::seconds(60));
    store.insert(g).unwrap();
    let check: Arc<dyn GrantCheck> = Arc::new(GrantCheckImpl::new(store.clone()));
    let req = CapParams::from(serde_json::json!({"read-paths": "/tmp/foo"}));
    assert!(matches!(
        check.check("alice", "fs", "ns-fs::read", &req),
        GrantDecision::Deny(_)
    ));
}

// T38-9 — authz.checked Allow grant_id is the COVERING grant, not a mere
// capability match (closes the round-1 Codex W3 grant-id selection bug).
// Seed a non-covering grant lexically BEFORE the covering one.
#[test]
fn ac23_l1_subset_authz_emits_covering_grant_id() {
    let (store, bus, _h) = make_store();
    // g-aaa-no: capability fs, active, but read-paths=/etc → does NOT cover /tmp/foo.
    store
        .insert(grant_with_params(
            "g-aaa-no",
            "alice",
            "fs",
            vec![cp("read-paths", "/etc")],
        ))
        .unwrap();
    // g-bbb-yes: read-paths=/tmp → COVERS /tmp/foo.
    store
        .insert(grant_with_params(
            "g-bbb-yes",
            "alice",
            "fs",
            vec![cp("read-paths", "/tmp")],
        ))
        .unwrap();
    let check: Arc<dyn GrantCheck> = Arc::new(GrantCheckImpl::with_authz_level(
        store.clone(),
        AuthzLevel::All,
    ));
    let req = CapParams::from(serde_json::json!({"read-paths": "/tmp/foo"}));
    assert!(matches!(
        check.check("alice", "fs", "ns-fs::read", &req),
        GrantDecision::Allow
    ));
    let evt = bus.first_of("authz.checked").expect("event present");
    assert_eq!(evt.payload["decision"], "allowed");
    // The emitted grant_id must be the covering grant, NOT the lex-min capability
    // match (which would be "g-aaa-no" under the old predicate).
    assert_eq!(evt.payload["grant_id"], "g-bbb-yes");
}

// T38-10 — capability mismatch: a grant for a DIFFERENT capability does not cover.
#[test]
fn ac23_l1_subset_capability_mismatch_denies() {
    let (store, _bus, _h) = make_store();
    store
        .insert(grant_with_params(
            "g1",
            "alice",
            "http",
            vec![cp("allowlist", "https://x/*")],
        ))
        .unwrap();
    let check: Arc<dyn GrantCheck> = Arc::new(GrantCheckImpl::new(store.clone()));
    let req = CapParams::from(serde_json::json!({"read-paths": "/tmp"}));
    assert!(matches!(
        check.check("alice", "fs", "ns-fs::read", &req),
        GrantDecision::Deny(_)
    ));
}
