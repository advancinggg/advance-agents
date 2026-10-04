//! GrantCheck regression: T-A5 (Slice A) + T-C1..T-C2c + T-C10 (Slice C).

mod common;

use advance_shared_types::capability::{CapParams, GrantDecision};
use advance_shared_types::mcp::SERVER_WIDE_TOOL;
use advance_shared_types::traits::GrantCheck;
use cap_grant::data::{
    CapParam, Grant, GrantId, GrantIssuer, GrantProvenance, GrantStatus, GrantTtl,
};
use cap_grant::{AuthzLevel, GrantCheckImpl};
use chrono::Utc;
use serde_json::json;
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

// ============================================================================
// `mcp` call requests: literal server ids and tool names, each held grant judged
// on its own.
// ============================================================================

fn allows(check: &dyn GrantCheck, agent: &str, request: serde_json::Value) -> bool {
    matches!(
        check.check(
            agent,
            "mcp",
            "advance:runtime/mcp-client@0.1.0::invoke-mcp-tool",
            &CapParams::from(request)
        ),
        GrantDecision::Allow
    )
}

#[test]
fn mcp_calls_are_checked_against_the_grant_tool_patterns() {
    let (store, _bus, _h) = make_store();
    store
        .insert(grant_with_params(
            "g1",
            "alice",
            "mcp",
            vec![cp("servers", "github"), cp("tool-patterns", "get_*")],
        ))
        .unwrap();
    let check = GrantCheckImpl::new(store.clone());
    assert!(allows(
        &check,
        "alice",
        json!({"servers": "github", "tool-patterns": "get_issue"})
    ));
    assert!(allows(&check, "alice", json!({"servers": "github"})));
    assert!(allows(
        &check,
        "alice",
        json!({"servers": ["github"], "tool-patterns": ["get_issue", "get_pr"]})
    ));
    for denied in [
        json!({"servers": "github", "tool-patterns": "delete_repo"}),
        json!({"servers": "github", "tool-patterns": ["get_issue", "delete_repo"]}),
        json!({"servers": "slack"}),
        json!({"servers": "slack", "tool-patterns": "get_issue"}),
        json!({"tool-patterns": "get_issue"}),
        json!({"servers": "github", "tool-patterns": SERVER_WIDE_TOOL}),
    ] {
        assert!(!allows(&check, "alice", denied.clone()), "{denied}");
    }
    assert!(!allows(
        &check,
        "bob",
        json!({"servers": "github", "tool-patterns": "get_issue"})
    ));
}

#[test]
fn mcp_whole_capability_grant_covers_every_call() {
    let (store, _bus, _h) = make_store();
    store
        .insert(grant_with_params("g1", "alice", "mcp", vec![]))
        .unwrap();
    let check = GrantCheckImpl::new(store.clone());
    assert!(allows(
        &check,
        "alice",
        json!({"servers": "any", "tool-patterns": "anything"})
    ));
    assert!(allows(
        &check,
        "alice",
        json!({"servers": "any", "tool-patterns": SERVER_WIDE_TOOL})
    ));
    // Even an unrestricted grant needs the request to name its server.
    assert!(!allows(
        &check,
        "alice",
        json!({"tool-patterns": "anything"})
    ));
}

#[test]
fn mcp_grants_are_never_merged_across_axes() {
    let (store, _bus, _h) = make_store();
    store
        .insert(grant_with_params(
            "g-a",
            "alice",
            "mcp",
            vec![cp("servers", "a"), cp("tool-patterns", "x*")],
        ))
        .unwrap();
    store
        .insert(grant_with_params(
            "g-b",
            "alice",
            "mcp",
            vec![cp("servers", "b")],
        ))
        .unwrap();
    let check = GrantCheckImpl::new(store.clone());
    let call = |server: &str, tool: &str| json!({"servers": server, "tool-patterns": tool});
    assert!(allows(&check, "alice", call("a", "x1")));
    assert!(allows(&check, "alice", call("b", "y")));
    // `y` on `a` would need g-a's server and g-b's open tool axis at once.
    assert!(!allows(&check, "alice", call("a", "y")));
    // One request spanning both servers is judged against each grant alone.
    assert!(!allows(
        &check,
        "alice",
        json!({"servers": ["a", "b"], "tool-patterns": "x1"})
    ));
}

// The `data` tool authorizes by `fs`: a read sends `read-paths` alone, a write sends
// `read-paths` and `write-paths` on the same file, and `query` / `promote` / `demote` ask for
// `/`. The call-time path keeps those decisions exactly.
#[test]
fn data_tool_fs_requests_keep_their_decisions() {
    let read = |path: &str| json!({"read-paths": path});
    let write = |path: &str| json!({"read-paths": path, "write-paths": path});
    let cases: [(Vec<CapParam>, Vec<(serde_json::Value, bool)>); 3] = [
        (
            vec![cp("read-paths", "/notes")],
            vec![
                (read("/notes/a.md"), true),
                (write("/notes/a.md"), false),
                (read("/"), false),
                (read("/launch.md"), false),
            ],
        ),
        (
            vec![cp("read-paths", "/"), cp("write-paths", "/notes")],
            vec![
                (read("/launch.md"), true),
                (read("/"), true),
                (write("/notes/a.md"), true),
                (write("/launch.md"), false),
                (write("/"), false),
            ],
        ),
        (
            vec![],
            vec![
                (read("/launch.md"), true),
                (write("/launch.md"), true),
                (write("/"), true),
            ],
        ),
    ];
    for (held, requests) in cases {
        let (store, _bus, _h) = make_store();
        store
            .insert(grant_with_params("g1", "alice", "fs", held.clone()))
            .unwrap();
        let check = GrantCheckImpl::new(store.clone());
        for (request, expected) in requests {
            let decision = check.check(
                "alice",
                "fs",
                "data.patch",
                &CapParams::from(request.clone()),
            );
            assert_eq!(
                matches!(decision, GrantDecision::Allow),
                expected,
                "held {held:?}, request {request}"
            );
        }
    }
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
