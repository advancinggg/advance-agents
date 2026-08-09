//! Slice C negative-path tests: T-C-N1..T-C-N3, T-C-N5..T-C-N8.
//!
//! Closes Codex round-6 W3+W4: ADD new caller-mismatch tests for narrow +
//! apply_preset (no Slice B fixtures asserted SubsetViolation for these
//! paths) + new validation negative tests for consume + delegate_grant.

mod common;

use cap_grant::data::{
    CapParam, Grant, GrantDraft, GrantId, GrantIssuer, GrantProvenance, GrantStatus, GrantTtl,
};
use cap_grant::{CapGrantError, PresetRegistry, SubsetValidatorImpl, PRESET_RESTRICT};
use chrono::Utc;

use crate::common::make_store;

fn http_grant_for(agent: &str, id: &str) -> Grant {
    Grant {
        id: GrantId::new(id),
        grantee: agent.to_string(),
        capability: "http".to_string(),
        params: vec![],
        ttl: GrantTtl::Persistent,
        issuer: GrantIssuer::Config,
        provenance: GrantProvenance::StaticConfig,
        status: GrantStatus::Active,
        created_at: Utc::now(),
        expires_at: None,
    }
}

// T-C-N1 — narrow caller-mismatch returns PermissionDenied (Slice C migration).
#[test]
fn narrow_caller_not_grantee_returns_permission_denied() {
    let (store, bus, _h) = make_store();
    store
        .insert(http_grant_for("alice", "static:alice:http"))
        .unwrap();
    let validator = SubsetValidatorImpl;
    let err = store
        .narrow(
            "static:alice:http",
            vec![CapParam {
                key: "allowlist".into(),
                value: "https://api.example.com/v1/*".into(),
            }],
            "mallory",
            &validator,
        )
        .unwrap_err();
    assert!(
        matches!(err, CapGrantError::PermissionDenied(_)),
        "expected PermissionDenied, got {err:?}"
    );
    assert_eq!(bus.count_of("grant.narrowed"), 0);
}

// T-C-N2 — apply_preset caller != target returns PermissionDenied (Slice C migration).
#[test]
fn apply_preset_caller_not_target_returns_permission_denied() {
    let (store, bus, _h) = make_store();
    let validator = SubsetValidatorImpl;
    let registry = PresetRegistry::with_builtins();
    let err = registry
        .apply_preset(PRESET_RESTRICT, "alice", &store, &validator, "bob")
        .unwrap_err();
    assert!(
        matches!(err, CapGrantError::PermissionDenied(_)),
        "expected PermissionDenied, got {err:?}"
    );
    assert_eq!(bus.count_of("preset.applied"), 0);
}

// T-C-N3 — consume rejects empty consumed_by_function.
#[test]
fn consume_rejects_empty_consumed_by_function() {
    let (store, bus, _h) = make_store();
    let g = Grant {
        id: GrantId::new("g-once"),
        grantee: "alice".to_string(),
        capability: "fs".to_string(),
        params: vec![],
        ttl: GrantTtl::Once,
        issuer: GrantIssuer::Config,
        provenance: GrantProvenance::StaticConfig,
        status: GrantStatus::Active,
        created_at: Utc::now(),
        expires_at: None,
    };
    store.insert(g).unwrap();
    let err = store.consume("g-once", "").unwrap_err();
    assert!(
        matches!(err, CapGrantError::InvalidConfig(_)),
        "expected InvalidConfig, got {err:?}"
    );
    assert_eq!(bus.count_of("grant.consumed"), 0);
}

// T-C-N5 — delegate_grant rejects empty caller_id.
#[test]
fn delegate_grant_rejects_empty_caller_id() {
    let (store, bus, _h) = make_store();
    store
        .insert(http_grant_for("alice", "static:alice:http"))
        .unwrap();
    let validator = SubsetValidatorImpl;
    let draft = GrantDraft {
        capability: "http".to_string(),
        params: vec![],
        ttl: GrantTtl::Lifecycle,
    };
    let err = store
        .delegate_grant("static:alice:http", "bob", draft, "", &validator)
        .unwrap_err();
    assert!(
        matches!(err, CapGrantError::InvalidConfig(_)),
        "expected InvalidConfig, got {err:?}"
    );
    assert_eq!(bus.count_of("grant.delegated"), 0);
}

// T-C-N6 — delegate_grant rejects empty child_agent.
#[test]
fn delegate_grant_rejects_empty_child_agent() {
    let (store, bus, _h) = make_store();
    store
        .insert(http_grant_for("alice", "static:alice:http"))
        .unwrap();
    let validator = SubsetValidatorImpl;
    let draft = GrantDraft {
        capability: "http".to_string(),
        params: vec![],
        ttl: GrantTtl::Lifecycle,
    };
    let err = store
        .delegate_grant("static:alice:http", "", draft, "alice", &validator)
        .unwrap_err();
    assert!(
        matches!(err, CapGrantError::InvalidConfig(_)),
        "expected InvalidConfig, got {err:?}"
    );
    assert_eq!(bus.count_of("grant.delegated"), 0);
}

// T-C-N7 — delegate_grant rejects a MALFORMED-colon caller_id ("ali:ce" — not a canonical
// `agent:`/bare id). After the 2026-06-06 colon-id reconciliation the gate accepts bare or
// canonical `agent:<body>` ids but still rejects non-canonical colon ids like this one.
#[test]
fn delegate_grant_rejects_caller_id_with_colon() {
    let (store, bus, _h) = make_store();
    store
        .insert(http_grant_for("alice", "static:alice:http"))
        .unwrap();
    let validator = SubsetValidatorImpl;
    let draft = GrantDraft {
        capability: "http".to_string(),
        params: vec![],
        ttl: GrantTtl::Lifecycle,
    };
    let err = store
        .delegate_grant("static:alice:http", "bob", draft, "ali:ce", &validator)
        .unwrap_err();
    assert!(
        matches!(err, CapGrantError::InvalidConfig(_)),
        "expected InvalidConfig, got {err:?}"
    );
    assert_eq!(bus.count_of("grant.delegated"), 0);
}

// T-C-N8 — delegate_grant rejects a MALFORMED-colon child_agent ("bo:b" — not a canonical
// `agent:`/bare id). The 2026-06-06 colon-id reconciliation accepts bare or canonical
// `agent:<body>` ids but still rejects non-canonical colon ids like this one.
#[test]
fn delegate_grant_rejects_child_agent_with_colon() {
    let (store, bus, _h) = make_store();
    store
        .insert(http_grant_for("alice", "static:alice:http"))
        .unwrap();
    let validator = SubsetValidatorImpl;
    let draft = GrantDraft {
        capability: "http".to_string(),
        params: vec![],
        ttl: GrantTtl::Lifecycle,
    };
    let err = store
        .delegate_grant("static:alice:http", "bo:b", draft, "alice", &validator)
        .unwrap_err();
    assert!(
        matches!(err, CapGrantError::InvalidConfig(_)),
        "expected InvalidConfig, got {err:?}"
    );
    assert_eq!(bus.count_of("grant.delegated"), 0);
}
