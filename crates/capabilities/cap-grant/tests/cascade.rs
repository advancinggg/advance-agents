//! Cascade tests: T13 (parent-terminate), T14 (recursive cascade).

mod common;

use cap_grant::data::{Grant, GrantId, GrantIssuer, GrantProvenance, GrantStatus, GrantTtl};
use chrono::Utc;

use crate::common::make_store;

fn mk(
    id: &str,
    grantee: &str,
    capability: &str,
    issuer: GrantIssuer,
    prov: GrantProvenance,
) -> Grant {
    Grant {
        id: GrantId::new(id),
        grantee: grantee.to_string(),
        capability: capability.to_string(),
        params: vec![],
        ttl: GrantTtl::Persistent,
        issuer,
        provenance: prov,
        status: GrantStatus::Active,
        created_at: Utc::now(),
        expires_at: None,
    }
}

// MODULE-013-T13 — AC-11 — Parent terminate cascades to child grants.
#[test]
fn parent_terminate_cascades_to_child_grants() {
    let (store, bus, _h) = make_store();
    store
        .insert(mk(
            "g1",
            "child1",
            "fs",
            GrantIssuer::Parent("pX".to_string()),
            GrantProvenance::Requested,
        ))
        .unwrap();
    store
        .insert(mk(
            "g2",
            "child2",
            "http",
            GrantIssuer::Parent("pX".to_string()),
            GrantProvenance::Requested,
        ))
        .unwrap();
    store
        .insert(mk(
            "g3-other",
            "child3",
            "llm",
            GrantIssuer::Parent("pY".to_string()),
            GrantProvenance::Requested,
        ))
        .unwrap();

    let result = store.cascade_by_issuer("pX").unwrap();
    assert_eq!(result.revoked.len(), 2);
    assert_eq!(store.get("g1").unwrap().status, GrantStatus::Revoked);
    assert_eq!(store.get("g2").unwrap().status, GrantStatus::Revoked);
    assert_eq!(store.get("g3-other").unwrap().status, GrantStatus::Active);

    let revoke_events = bus.all_of("grant.revoked");
    assert_eq!(revoke_events.len(), 2);
    for evt in &revoke_events {
        let by = evt.payload["revoked_by"].as_str().unwrap();
        assert_eq!(by, "parent-terminate:pX");
    }
}

// MODULE-013-T14 — AC-12 — Recursive cascade revoke.
#[test]
fn recursive_cascade_revokes_descendants() {
    let (store, bus, _h) = make_store();
    let g1 = mk(
        "G1",
        "alice",
        "fs",
        GrantIssuer::Config,
        GrantProvenance::StaticConfig,
    );
    let g2 = mk(
        "G2",
        "alice",
        "fs",
        GrantIssuer::Resolver("ch1".to_string()),
        GrantProvenance::Delegated(GrantId::new("G1")),
    );
    let g3 = mk(
        "G3",
        "alice",
        "fs",
        GrantIssuer::Resolver("ch1".to_string()),
        GrantProvenance::Delegated(GrantId::new("G2")),
    );
    store.insert(g1).unwrap();
    store.insert(g2).unwrap();
    store.insert(g3).unwrap();

    let result = store.cascade_revoke("G1").unwrap();
    assert_eq!(result.cascade_count, 2);
    assert_eq!(result.revoked.len(), 3);
    assert_eq!(store.get("G1").unwrap().status, GrantStatus::Revoked);
    assert_eq!(store.get("G2").unwrap().status, GrantStatus::Revoked);
    assert_eq!(store.get("G3").unwrap().status, GrantStatus::Revoked);

    let revoke_events = bus.all_of("grant.revoked");
    assert_eq!(revoke_events.len(), 3);
    // Root carries cascade_count=2; descendants carry 0.
    let root_evt = revoke_events
        .iter()
        .find(|e| e.payload["grant_id"].as_str().unwrap() == "G1")
        .unwrap();
    assert_eq!(root_evt.payload["cascade_count"].as_u64().unwrap(), 2);
    let desc_count_total: u64 = revoke_events
        .iter()
        .filter(|e| e.payload["grant_id"].as_str().unwrap() != "G1")
        .map(|e| e.payload["cascade_count"].as_u64().unwrap())
        .sum();
    assert_eq!(desc_count_total, 0);
}
