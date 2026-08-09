//! Store tests: T-A2 (4 issuer types round-trip), T-A3 (by_issuer index).

mod common;

use cap_grant::data::{Grant, GrantId, GrantIssuer, GrantProvenance, GrantStatus, GrantTtl};
use chrono::Utc;

use crate::common::make_store;

fn mk(id: &str, grantee: &str, capability: &str, issuer: GrantIssuer) -> Grant {
    Grant {
        id: GrantId::new(id),
        grantee: grantee.to_string(),
        capability: capability.to_string(),
        params: vec![],
        ttl: GrantTtl::Persistent,
        issuer,
        provenance: GrantProvenance::StaticConfig,
        status: GrantStatus::Active,
        created_at: Utc::now(),
        expires_at: None,
    }
}

// T-A2 — AC-03 + AC-19 — 4 issuer types round-trip.
#[test]
fn four_issuer_types_round_trip() {
    let (store, _bus, handle) = make_store();
    store
        .insert(mk("g-config", "alice", "fs", GrantIssuer::Config))
        .unwrap();
    store
        .insert(mk(
            "g-parent",
            "alice",
            "http",
            GrantIssuer::Parent("p1".to_string()),
        ))
        .unwrap();
    store
        .insert(mk(
            "g-resolver",
            "alice",
            "llm",
            GrantIssuer::Resolver("ch1".to_string()),
        ))
        .unwrap();
    store
        .insert(mk("g-admin", "alice", "secrets", GrantIssuer::Admin))
        .unwrap();

    let listed = store.list_by_grantee("alice");
    assert_eq!(listed.len(), 4);
    let mut issuers: Vec<_> = listed.iter().map(|g| g.issuer.clone()).collect();
    issuers.sort_by(|a, b| format!("{a:?}").cmp(&format!("{b:?}")));
    let admin_count = issuers
        .iter()
        .filter(|i| matches!(i, GrantIssuer::Admin))
        .count();
    let config_count = issuers
        .iter()
        .filter(|i| matches!(i, GrantIssuer::Config))
        .count();
    let parent_count = issuers
        .iter()
        .filter(|i| matches!(i, GrantIssuer::Parent(_)))
        .count();
    let resolver_count = issuers
        .iter()
        .filter(|i| matches!(i, GrantIssuer::Resolver(_)))
        .count();
    assert_eq!(admin_count, 1);
    assert_eq!(config_count, 1);
    assert_eq!(parent_count, 1);
    assert_eq!(resolver_count, 1);

    // by_issuer index returns parent-issued grant only.
    let parent_set = store.list_by_issuer_parent("p1");
    assert_eq!(parent_set.len(), 1);
    assert_eq!(parent_set[0].id.as_str(), "g-parent");

    // SQLite has 4 rows with distinct issuer_type column values.
    let index = cap_grant::GrantSqliteIndex::new(handle);
    assert_eq!(index.count_rows().unwrap(), 4);
}

// T-A3 — AC-19 — by_issuer index lookup.
#[test]
fn by_issuer_index_lookup() {
    let (store, _bus, _h) = make_store();
    store
        .insert(mk(
            "a",
            "alice",
            "fs",
            GrantIssuer::Parent("p1".to_string()),
        ))
        .unwrap();
    store
        .insert(mk(
            "b",
            "alice",
            "http",
            GrantIssuer::Parent("p1".to_string()),
        ))
        .unwrap();
    store
        .insert(mk(
            "c",
            "alice",
            "llm",
            GrantIssuer::Parent("p2".to_string()),
        ))
        .unwrap();

    let p1 = store.list_by_issuer_parent("p1");
    assert_eq!(p1.len(), 2);
    let p2 = store.list_by_issuer_parent("p2");
    assert_eq!(p2.len(), 1);
}
