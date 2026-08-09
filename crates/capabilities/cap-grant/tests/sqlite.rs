//! SQLite tests: T23 (dual-write + recovery), T-A6 (ensure_schema idempotent).

mod common;

use cap_grant::data::{Grant, GrantId, GrantIssuer, GrantProvenance, GrantStatus, GrantTtl};
use cap_grant::{GrantSqliteIndex, GrantStore};
use chrono::Utc;
use std::sync::Arc;

use crate::common::{make_index, make_store, RecordingBus};

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

// MODULE-013-T23 — AC-18 — Dual-write then cold-start recover.
#[test]
fn dual_write_then_recover() {
    let (store, _bus, handle) = make_store();
    store
        .insert(mk("g1", "alice", "fs", GrantIssuer::Config))
        .unwrap();
    store
        .insert(mk(
            "g2",
            "alice",
            "http",
            GrantIssuer::Parent("p1".to_string()),
        ))
        .unwrap();
    store
        .insert(mk(
            "g3",
            "alice",
            "llm",
            GrantIssuer::Resolver("ch1".to_string()),
        ))
        .unwrap();

    let index = GrantSqliteIndex::new(handle.clone());
    assert_eq!(index.count_rows().unwrap(), 3);

    // Revoke 1.
    store.cascade_revoke("g2").unwrap();
    assert_eq!(index.status_of("g2").unwrap().unwrap(), "revoked");

    // Recover only active grants — should be 2 (g1, g3).
    let recovered = index.recover_active_grants().unwrap();
    assert_eq!(recovered.len(), 2);
    let ids: Vec<&str> = recovered.iter().map(|g| g.id.as_str()).collect();
    assert!(ids.contains(&"g1"));
    assert!(ids.contains(&"g3"));

    // Build a fresh store + populate via insert_no_dual_write equivalent
    // (using the cap-grant register flow indirectly by re-inserting):
    let bus2 = RecordingBus::new();
    let bus2_dyn: Arc<dyn advance_shared_types::traits::EventBusEmit> = bus2.clone();
    let new_store = Arc::new(GrantStore::new(index, bus2_dyn));
    // In production this is insert_no_dual_write, but it's pub(crate) —
    // use the recovered grants via re-insert (UPSERT is idempotent).
    for g in recovered {
        new_store.insert(g).unwrap();
    }
    assert_eq!(new_store.list_by_grantee("alice").len(), 2);

    // Round-trip the 4 issuer types.
    let bus3 = RecordingBus::new();
    let bus3_dyn: Arc<dyn advance_shared_types::traits::EventBusEmit> = bus3.clone();
    let (sqlite_idx, _, _h2) = make_index();
    sqlite_idx.ensure_schema().unwrap();
    let store2 = Arc::new(GrantStore::new(sqlite_idx.clone(), bus3_dyn));
    store2
        .insert(mk("a-config", "x", "fs", GrantIssuer::Config))
        .unwrap();
    store2
        .insert(mk(
            "a-parent",
            "x",
            "http",
            GrantIssuer::Parent("p1".to_string()),
        ))
        .unwrap();
    store2
        .insert(mk(
            "a-resolver",
            "x",
            "llm",
            GrantIssuer::Resolver("ch1".to_string()),
        ))
        .unwrap();
    store2
        .insert(mk("a-admin", "x", "secrets", GrantIssuer::Admin))
        .unwrap();
    let recovered2 = sqlite_idx.recover_active_grants().unwrap();
    assert_eq!(recovered2.len(), 4);
    let issuer_kinds: std::collections::HashSet<String> = recovered2
        .iter()
        .map(|g| match &g.issuer {
            GrantIssuer::Config => "config".into(),
            GrantIssuer::Parent(_) => "parent".into(),
            GrantIssuer::Resolver(_) => "resolver".into(),
            GrantIssuer::Admin => "admin".into(),
        })
        .collect();
    assert_eq!(issuer_kinds.len(), 4);
}

// T-A6 — AC-18 — ensure_schema is idempotent.
#[test]
fn ensure_schema_idempotent() {
    let (idx, _bus, _h) = make_index();
    idx.ensure_schema().expect("first call");
    idx.ensure_schema().expect("second call");
    idx.ensure_schema().expect("third call");
    assert_eq!(idx.count_rows().unwrap(), 0);
}
