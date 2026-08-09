//! Slice D — AC-21 dimension-separation test (CONTRACT-121 enforcement
//! property).
//!
//! Per MODULE-013 §1.5 line 333 + §3.3 T37 (Slice-D reword that drops the
//! events-payload-mismatched `param=tool-x` claim — `authz.checked` payload
//! per §2.3 + events.rs is exactly `agent_id, capability, function,
//! decision, grant_id`). This test exercises the L1 capability-level gate
//! (CONTRACT-121) — it does NOT go through the agent-grant WIT.
//!
//! AC-21 scope per §1.5 line 333: "fails with capability denied because
//! `mcp.servers` is empty" — capability-level dimension separation.
//! Param-level subset enforcement at L1 is L1-V2 (future M001 bootstrap
//! slice that wires `SubsetValidator` into the L1 path).

mod common;

use std::sync::Arc;

use advance_shared_types::capability::{CapParams, GrantDecision};
use advance_shared_types::traits::GrantCheck;
use cap_grant::data::{
    CapParam, Grant, GrantId, GrantIssuer, GrantProvenance, GrantStatus, GrantTtl,
};
use cap_grant::{AuthzLevel, GrantCheckImpl};
use chrono::Utc;

use crate::common::make_store;

const AGENT: &str = "agent-1";

#[test]
fn ac21_capability_dimension_separation_one_allow_three_deny() {
    let (store, bus, _h) = make_store();

    // Issue a `tools` grant ONLY (no mcp.servers / lifecycle / fs grants).
    // Params encode the allowed tool name; the L1 gate authorizes by
    // capability+grantee membership only — param-level subset is L1-V2.
    let grant = Grant {
        id: GrantId::new("g-tools"),
        grantee: AGENT.to_string(),
        capability: "tools".to_string(),
        params: vec![CapParam {
            key: "allowlist".to_string(),
            value: "tool-x".to_string(),
        }],
        ttl: GrantTtl::Lifecycle,
        issuer: GrantIssuer::Resolver("test".to_string()),
        provenance: GrantProvenance::Requested,
        status: GrantStatus::Active,
        created_at: Utc::now(),
        expires_at: None,
    };
    store.insert_dynamic(grant).unwrap();

    // AuthzLevel::All so both Allow + Deny emit (T37 fixture).
    let check: Arc<dyn GrantCheck> = Arc::new(GrantCheckImpl::with_authz_level(
        store.clone(),
        AuthzLevel::All,
    ));

    // 4 checks across 4 distinct capability dimensions × distinct functions.
    let r1 = check.check(AGENT, "tools", "ns-tool::call", &CapParams::empty());
    let r2 = check.check(AGENT, "mcp.servers", "ns-mcp::call", &CapParams::empty());
    let r3 = check.check(
        AGENT,
        "lifecycle",
        "ns-lifecycle::spawn-child",
        &CapParams::empty(),
    );
    let r4 = check.check(AGENT, "fs", "ns-fs::read", &CapParams::empty());

    assert!(matches!(r1, GrantDecision::Allow), "tools → Allow");
    assert!(matches!(r2, GrantDecision::Deny(_)), "mcp.servers → Deny");
    assert!(matches!(r3, GrantDecision::Deny(_)), "lifecycle → Deny");
    assert!(matches!(r4, GrantDecision::Deny(_)), "fs → Deny");

    // Assert the 4 authz.checked events: 1 allowed + 3 denied with correct
    // capability-dimension payload.
    let events = bus.all_of("authz.checked");
    assert_eq!(
        events.len(),
        4,
        "4 authz.checked events, one per check call"
    );
    let by_cap: std::collections::HashMap<String, &advance_shared_types::event::Event> = events
        .iter()
        .map(|e| (e.payload["capability"].as_str().unwrap().to_string(), e))
        .collect();
    assert_eq!(
        by_cap.len(),
        4,
        "4 distinct capability values across events"
    );
    assert_eq!(by_cap["tools"].payload["decision"], "allowed");
    assert_eq!(by_cap["mcp.servers"].payload["decision"], "denied");
    assert_eq!(by_cap["lifecycle"].payload["decision"], "denied");
    assert_eq!(by_cap["fs"].payload["decision"], "denied");

    // Each event's `function` field reflects the per-call function name —
    // proves the events are correctly scoped per capability dimension, not
    // mistakenly conflated.
    assert_eq!(by_cap["tools"].payload["function"], "ns-tool::call");
    assert_eq!(by_cap["mcp.servers"].payload["function"], "ns-mcp::call");
    assert_eq!(
        by_cap["lifecycle"].payload["function"],
        "ns-lifecycle::spawn-child"
    );
    assert_eq!(by_cap["fs"].payload["function"], "ns-fs::read");
}
