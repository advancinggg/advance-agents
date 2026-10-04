//! CONTRACT-183 `ToolsGrantReader` unit coverage (Wave-15 Lane E), and its `mcp`
//! counterpart `McpGrantReader`.
//!
//! Verifies the `tools.ids` allowlist projection: ids→narrow, no-ids→wildcard(None),
//! no-grant→deny(Some([])), expired/revoked/non-tools excluded, CSV de-dup union,
//! and the colon→bare grantee bridge. For `mcp`: one scope per active grant, never
//! merged, agreeing with the call-time check, and silent (no `authz.checked`).

mod common;

use advance_shared_types::capability::{CapParams, GrantDecision};
use advance_shared_types::mcp::McpGrantScope;
use advance_shared_types::traits::{GrantCheck, McpGrantReader, ToolsGrantReader};
use cap_grant::data::{
    CapParam, Grant, GrantId, GrantIssuer, GrantProvenance, GrantStatus, GrantTtl,
};
use cap_grant::{GrantCheckImpl, McpGrantReaderImpl, ToolsGrantReaderImpl};
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

// ===== McpGrantReader =====

fn mcp_grant(id: &str, grantee: &str, params: &[(&str, &str)]) -> Grant {
    let mut g = tools_grant(id, grantee, None, GrantStatus::Active);
    g.capability = "mcp".to_string();
    g.params = params
        .iter()
        .map(|(key, value)| CapParam {
            key: key.to_string(),
            value: value.to_string(),
        })
        .collect();
    g
}

fn scope(servers: Option<&[&str]>, patterns: Option<&[&str]>) -> McpGrantScope {
    let owned = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
    McpGrantScope {
        servers: servers.map(owned),
        tool_patterns: patterns.map(owned),
    }
}

#[test]
fn mgr_01_one_scope_per_active_mcp_grant() {
    let (store, _bus, _h) = make_store();
    store
        .insert(mcp_grant(
            "g-a",
            "alice",
            &[("servers", "a"), ("tool-patterns", "x*, y_tool")],
        ))
        .unwrap();
    store
        .insert(mcp_grant("g-b", "alice", &[("servers", "a,b")]))
        .unwrap();
    store
        .insert(mcp_grant("g-c", "alice", &[("tool-patterns", "z*")]))
        .unwrap();
    let mut revoked = mcp_grant("g-d", "alice", &[]);
    revoked.status = GrantStatus::Revoked;
    store.insert(revoked).unwrap();
    let mut expired = mcp_grant("g-e", "alice", &[]);
    expired.expires_at = Some(Utc::now() - chrono::Duration::hours(1));
    store.insert(expired).unwrap();
    // A misspelled key covers nothing, so the grant lists nothing.
    store
        .insert(mcp_grant(
            "g-f",
            "alice",
            &[("servers", "a"), ("tool_patterns", "x*")],
        ))
        .unwrap();
    store
        .insert(tools_grant("g-g", "alice", None, GrantStatus::Active))
        .unwrap();
    store
        .insert(mcp_grant("g-h", "bob", &[("servers", "a")]))
        .unwrap();

    let reader = McpGrantReaderImpl::new(store);
    assert_eq!(
        reader.mcp_grant_scopes("alice"),
        vec![
            scope(Some(&["a"]), Some(&["x*", "y_tool"])),
            scope(Some(&["a", "b"]), None),
            // No `servers`: the grant reaches no server.
            scope(Some(&[]), Some(&["z*"])),
        ]
    );
}

#[test]
fn mgr_02_whole_capability_grant_and_no_grant() {
    let (store, _bus, _h) = make_store();
    store.insert(mcp_grant("g1", "alice", &[])).unwrap();
    let reader = McpGrantReaderImpl::new(store);
    assert_eq!(
        reader.mcp_grant_scopes("alice"),
        vec![McpGrantScope::unrestricted()]
    );
    assert_eq!(reader.mcp_grant_scopes("bob"), Vec::new());
}

#[test]
fn mgr_03_colon_to_bare_bridge() {
    let (store, _bus, _h) = make_store();
    store
        .insert(mcp_grant("g1", "harness", &[("servers", "a")]))
        .unwrap();
    let reader = McpGrantReaderImpl::new(store);
    assert_eq!(
        reader.mcp_grant_scopes("agent:harness"),
        vec![scope(Some(&["a"]), None)]
    );
}

// A listing filtered through the scopes shows exactly what the call-time check allows,
// keeps grants apart, and writes no `authz.checked` event, while the same filter run
// through `GrantCheck` writes one deny event per hidden entry.
#[test]
fn mgr_04_filtered_listing_matches_the_check_and_emits_nothing() {
    let (store, bus, _h) = make_store();
    store
        .insert(mcp_grant(
            "g-a",
            "alice",
            &[("servers", "github"), ("tool-patterns", "get_*")],
        ))
        .unwrap();
    store
        .insert(mcp_grant("g-b", "alice", &[("servers", "notes")]))
        .unwrap();
    let listed = [
        ("github", "get_issue"),
        ("github", "get_pr"),
        ("github", "delete_repo"),
        ("notes", "delete_note"),
        ("slack", "get_channel"),
        ("slack", "post"),
    ];

    let reader = McpGrantReaderImpl::new(store.clone());
    let scopes = reader.mcp_grant_scopes("alice");
    let visible: Vec<(&str, &str)> = listed
        .iter()
        .copied()
        .filter(|(server, tool)| scopes.iter().any(|s| s.covers_tool(server, tool)))
        .collect();
    assert_eq!(
        visible,
        vec![
            ("github", "get_issue"),
            ("github", "get_pr"),
            ("notes", "delete_note")
        ]
    );
    assert_eq!(bus.count_of("authz.checked"), 0);

    let check = GrantCheckImpl::new(store);
    let allowed: Vec<(&str, &str)> = listed
        .iter()
        .copied()
        .filter(|(server, tool)| {
            let request = CapParams::from(serde_json::json!({
                "servers": server,
                "tool-patterns": tool,
            }));
            matches!(
                check.check("alice", "mcp", "list-mcp-tools", &request),
                GrantDecision::Allow
            )
        })
        .collect();
    assert_eq!(allowed, visible);
    assert_eq!(bus.count_of("authz.checked"), listed.len() - visible.len());
}
