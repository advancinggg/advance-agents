//! Slice C `delegate_grant` integration tests: T-C5..T-C9.

mod common;

use cap_grant::data::{
    Grant, GrantDraft, GrantId, GrantIssuer, GrantProvenance, GrantStatus, GrantTtl,
};
use cap_grant::{CapGrantError, SubsetValidatorImpl};
use chrono::{Duration as ChronoDuration, Utc};

use crate::common::make_store;

fn alice_http_grant(id: &str) -> Grant {
    Grant {
        id: GrantId::new(id),
        grantee: "alice".to_string(),
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

fn empty_draft(cap: &str) -> GrantDraft {
    GrantDraft {
        capability: cap.to_string(),
        params: vec![],
        ttl: GrantTtl::Lifecycle,
    }
}

// T-C5 — happy path: alice delegates http to bob.
#[test]
fn delegate_grant_happy_path() {
    let (store, bus, _h) = make_store();
    store.insert(alice_http_grant("static:alice:http")).unwrap();
    let validator = SubsetValidatorImpl;

    let result = store.delegate_grant(
        "static:alice:http",
        "bob",
        empty_draft("http"),
        "alice",
        &validator,
    );
    let new_id = result.expect("delegate succeeds");
    let child = store.get(new_id.as_str()).expect("child grant exists");
    assert_eq!(child.grantee, "bob");
    assert_eq!(child.capability, "http");
    assert_eq!(child.status, GrantStatus::Active);
    assert!(matches!(child.provenance, GrantProvenance::Delegated(_)));
    assert!(matches!(child.issuer, GrantIssuer::Parent(_)));

    let evt = bus
        .first_of("grant.delegated")
        .expect("grant.delegated emitted");
    assert_eq!(evt.payload["parent_grant_id"], "static:alice:http");
    assert_eq!(evt.payload["parent_agent"], "alice");
    assert_eq!(evt.payload["child_agent"], "bob");
    assert_eq!(evt.payload["capability"], "http");
}

// T-C6 — caller mismatch (mallory tries to delegate alice's grant).
#[test]
fn delegate_grant_caller_not_grantee_rejected() {
    let (store, bus, _h) = make_store();
    store.insert(alice_http_grant("static:alice:http")).unwrap();
    let validator = SubsetValidatorImpl;
    let err = store
        .delegate_grant(
            "static:alice:http",
            "bob",
            empty_draft("http"),
            "mallory",
            &validator,
        )
        .unwrap_err();
    assert!(
        matches!(err, CapGrantError::PermissionDenied(_)),
        "expected PermissionDenied, got {err:?}"
    );
    assert_eq!(bus.count_of("grant.delegated"), 0);
}

// T-C7 — subset violation (child capability mismatch).
#[test]
fn delegate_grant_subset_violation_rejected() {
    let (store, bus, _h) = make_store();
    store.insert(alice_http_grant("static:alice:http")).unwrap();
    let validator = SubsetValidatorImpl;
    // Draft with a different capability than parent — SubsetValidator rejects.
    let err = store
        .delegate_grant(
            "static:alice:http",
            "bob",
            empty_draft("fs"),
            "alice",
            &validator,
        )
        .unwrap_err();
    assert!(
        matches!(err, CapGrantError::SubsetViolation(_)),
        "expected SubsetViolation, got {err:?}"
    );
    assert_eq!(bus.count_of("grant.delegated"), 0);
}

// T-C8 — parent revoked rejected (Adversarial R14 W1: NotFound collapsed
// to PermissionDenied to eliminate enumeration oracle).
#[test]
fn delegate_grant_parent_revoked_rejected() {
    let (store, bus, _h) = make_store();
    store.insert(alice_http_grant("static:alice:http")).unwrap();
    let _ = store.cascade_revoke("static:alice:http").unwrap();
    let validator = SubsetValidatorImpl;
    let err = store
        .delegate_grant(
            "static:alice:http",
            "bob",
            empty_draft("http"),
            "alice",
            &validator,
        )
        .unwrap_err();
    assert!(
        matches!(err, CapGrantError::PermissionDenied(_)),
        "expected PermissionDenied (collapsed from NotFound to eliminate enumeration oracle), got {err:?}"
    );
    assert_eq!(bus.count_of("grant.delegated"), 0);
}

// T-C9 — 4-quadrant TTL clamp matrix.
#[test]
fn delegate_grant_ttl_4_quadrant_matrix() {
    let validator = SubsetValidatorImpl;

    // Quadrant 1: parent bounded (Until), child bounded (Duration) — child clamped to parent.
    {
        let (store, _bus, _h) = make_store();
        let parent_until = Utc::now() + ChronoDuration::seconds(2);
        let parent = Grant {
            ttl: GrantTtl::Until(parent_until),
            expires_at: Some(parent_until),
            ..alice_http_grant("static:alice:http")
        };
        store.insert(parent).unwrap();
        let draft = GrantDraft {
            capability: "http".to_string(),
            params: vec![],
            ttl: GrantTtl::Duration(5_000),
        };
        let new_id = store
            .delegate_grant("static:alice:http", "bob", draft, "alice", &validator)
            .unwrap();
        let child = store.get(new_id.as_str()).unwrap();
        assert_eq!(child.expires_at, Some(parent_until));
        assert!(matches!(child.ttl, GrantTtl::Duration(5_000)));
    }

    // Quadrant 2: parent bounded (Until), child unbounded (Persistent) — child inherits parent deadline.
    {
        let (store, _bus, _h) = make_store();
        let parent_until = Utc::now() + ChronoDuration::seconds(10);
        let parent = Grant {
            ttl: GrantTtl::Until(parent_until),
            expires_at: Some(parent_until),
            ..alice_http_grant("static:alice:http")
        };
        store.insert(parent).unwrap();
        let draft = GrantDraft {
            capability: "http".to_string(),
            params: vec![],
            ttl: GrantTtl::Persistent,
        };
        let new_id = store
            .delegate_grant("static:alice:http", "bob", draft, "alice", &validator)
            .unwrap();
        let child = store.get(new_id.as_str()).unwrap();
        assert_eq!(child.expires_at, Some(parent_until));
        assert!(matches!(child.ttl, GrantTtl::Persistent));
    }

    // Quadrant 3: parent unbounded (Persistent), child bounded (Duration) — child uses its own.
    // Tolerance-based assertion (delegate_grant uses live Utc::now()).
    {
        let (store, _bus, _h) = make_store();
        store.insert(alice_http_grant("static:alice:http")).unwrap();
        let before = Utc::now();
        let draft = GrantDraft {
            capability: "http".to_string(),
            params: vec![],
            ttl: GrantTtl::Duration(1_000),
        };
        let new_id = store
            .delegate_grant("static:alice:http", "bob", draft, "alice", &validator)
            .unwrap();
        let after = Utc::now();
        let child = store.get(new_id.as_str()).unwrap();
        let exp = child.expires_at.expect("expires_at set");
        assert!(exp >= before + ChronoDuration::milliseconds(999));
        assert!(exp <= after + ChronoDuration::milliseconds(1_001));
        assert!(matches!(child.ttl, GrantTtl::Duration(1_000)));
    }

    // Quadrant 4: parent unbounded (Persistent), child unbounded (Lifecycle) — None.
    {
        let (store, _bus, _h) = make_store();
        store.insert(alice_http_grant("static:alice:http")).unwrap();
        let draft = GrantDraft {
            capability: "http".to_string(),
            params: vec![],
            ttl: GrantTtl::Lifecycle,
        };
        let new_id = store
            .delegate_grant("static:alice:http", "bob", draft, "alice", &validator)
            .unwrap();
        let child = store.get(new_id.as_str()).unwrap();
        assert!(child.expires_at.is_none());
        assert!(matches!(child.ttl, GrantTtl::Lifecycle));
    }
}
