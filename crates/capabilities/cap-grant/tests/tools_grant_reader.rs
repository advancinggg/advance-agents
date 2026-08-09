//! CONTRACT-183 `ToolsGrantReader` unit coverage (Wave-15 Lane E).
//!
//! Verifies the `tools.ids` allowlist projection: ids→narrow, no-ids→wildcard(None),
//! no-grant→deny(Some([])), expired/revoked/non-tools excluded, CSV de-dup union,
//! and the colon→bare grantee bridge.

mod common;

use advance_shared_types::traits::ToolsGrantReader;
use cap_grant::data::{
    CapParam, Grant, GrantId, GrantIssuer, GrantProvenance, GrantStatus, GrantTtl,
};
use cap_grant::ToolsGrantReaderImpl;
use chrono::Utc;

use common::make_store;

fn tools_grant(id: &str, grantee: &str, ids_csv: Option<&str>, status: GrantStatus) -> Grant {
    Grant {
        id: GrantId::new(id),
        grantee: grantee.to_string(),
        capability: "tools".to_string(),
        params: match ids_csv {
            Some(v) => vec![CapParam {
                key: "ids".to_string(),
                value: v.to_string(),
            }],
            None => vec![],
        },
        ttl: GrantTtl::Persistent,
        issuer: GrantIssuer::Config,
        provenance: GrantProvenance::StaticConfig,
        status,
        created_at: Utc::now(),
        expires_at: None,
    }
}

#[test]
fn tgr_01_ids_grant_narrows_to_allowlist() {
    let (store, _bus, _h) = make_store();
    store
        .insert(tools_grant(
            "g1",
            "alice",
            Some("toola,toolb"),
            GrantStatus::Active,
        ))
        .unwrap();
    let reader = ToolsGrantReaderImpl::new(store);
    assert_eq!(
        reader.tool_allowlist("alice"),
        Some(vec!["toola".to_string(), "toolb".to_string()])
    );
}

#[test]
fn tgr_02_no_ids_grant_is_wildcard_none() {
    let (store, _bus, _h) = make_store();
    store
        .insert(tools_grant("g1", "alice", None, GrantStatus::Active))
        .unwrap();
    let reader = ToolsGrantReaderImpl::new(store);
    assert_eq!(reader.tool_allowlist("alice"), None);
}

#[test]
fn tgr_03_no_tools_grant_denies_all() {
    let (store, _bus, _h) = make_store();
    // A non-"tools" grant must NOT grant tools.
    let mut g = tools_grant("g1", "alice", Some("toola"), GrantStatus::Active);
    g.capability = "fs".to_string();
    store.insert(g).unwrap();
    let reader = ToolsGrantReaderImpl::new(store);
    assert_eq!(reader.tool_allowlist("alice"), Some(Vec::new()));
}

#[test]
fn tgr_04_revoked_grant_excluded() {
    let (store, _bus, _h) = make_store();
    store
        .insert(tools_grant(
            "g1",
            "alice",
            Some("toola"),
            GrantStatus::Revoked,
        ))
        .unwrap();
    let reader = ToolsGrantReaderImpl::new(store);
    // Revoked → not counted → deny all.
    assert_eq!(reader.tool_allowlist("alice"), Some(Vec::new()));
}

#[test]
fn tgr_05_expired_grant_excluded() {
    let (store, _bus, _h) = make_store();
    let mut g = tools_grant("g1", "alice", Some("toola"), GrantStatus::Active);
    g.expires_at = Some(Utc::now() - chrono::Duration::hours(1));
    store.insert(g).unwrap();
    let reader = ToolsGrantReaderImpl::new(store);
    // Active-but-expired → excluded → deny all.
    assert_eq!(reader.tool_allowlist("alice"), Some(Vec::new()));
}

#[test]
fn tgr_06_colon_to_bare_bridge() {
    let (store, _bus, _h) = make_store();
    // Seed under the BARE id (`insert` rejects colon grantees); query with the COLON id.
    store
        .insert(tools_grant(
            "g1",
            "harness",
            Some("toola"),
            GrantStatus::Active,
        ))
        .unwrap();
    let reader = ToolsGrantReaderImpl::new(store);
    assert_eq!(
        reader.tool_allowlist("agent:harness"),
        Some(vec!["toola".to_string()])
    );
}

#[test]
fn tgr_07_union_de_duped_across_grants() {
    let (store, _bus, _h) = make_store();
    store
        .insert(tools_grant(
            "g1",
            "alice",
            Some("toola"),
            GrantStatus::Active,
        ))
        .unwrap();
    store
        .insert(tools_grant(
            "g2",
            "alice",
            Some("toolb, toola"),
            GrantStatus::Active,
        ))
        .unwrap();
    let reader = ToolsGrantReaderImpl::new(store);
    let allow = reader.tool_allowlist("alice").unwrap();
    assert!(allow.contains(&"toola".to_string()));
    assert!(allow.contains(&"toolb".to_string()));
    assert_eq!(
        allow.len(),
        2,
        "ids are de-duped across grants; got {allow:?}"
    );
}
