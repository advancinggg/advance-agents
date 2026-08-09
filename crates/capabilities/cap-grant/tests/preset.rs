//! Preset tests — AC-08 (3 built-ins) + AC-09 (custom YAML) + AC-20 (apply).

mod common;

use std::io::Write;

use cap_grant::data::{
    CapParam, Grant, GrantId, GrantIssuer, GrantProvenance, GrantStatus, GrantTtl,
};
use cap_grant::error::CapGrantError;
use cap_grant::preset::{PresetRegistry, PRESET_AUTONOMOUS, PRESET_RESTRICT, PRESET_SUPERVISED};
use cap_grant::subset::SubsetValidatorImpl;
use chrono::Utc;
use tempfile::NamedTempFile;

use crate::common::make_store;

#[test]
fn t10_restrict_preset_chain_is_autodeny() {
    let r = PresetRegistry::with_builtins();
    let preset = r.get(PRESET_RESTRICT).expect("restrict exists");
    assert_eq!(preset.resolver_chain_names, vec!["AutoDeny".to_string()]);
}

#[test]
fn t10_supervised_preset_chain_full_5_resolvers() {
    let r = PresetRegistry::with_builtins();
    let preset = r.get(PRESET_SUPERVISED).expect("supervised exists");
    assert_eq!(
        preset.resolver_chain_names,
        vec![
            "SubsetAutoApprove".to_string(),
            "BudgetCheck".to_string(),
            "ParentApproval".to_string(),
            "Channel".to_string(),
            "AutoDeny".to_string(),
        ]
    );
    assert!(
        preset
            .resolver_chain_names
            .contains(&"ParentApproval".to_string()),
        "supervised must include ParentApproval"
    );
}

#[test]
fn t10_autonomous_preset_no_parent_approval() {
    let r = PresetRegistry::with_builtins();
    let preset = r.get(PRESET_AUTONOMOUS).expect("autonomous exists");
    assert_eq!(
        preset.resolver_chain_names,
        vec![
            "SubsetAutoApprove".to_string(),
            "BudgetCheck".to_string(),
            "AutoDeny".to_string(),
        ]
    );
    assert!(
        !preset
            .resolver_chain_names
            .contains(&"ParentApproval".to_string()),
        "autonomous must NOT include ParentApproval"
    );
}

#[test]
fn t11_custom_yaml_load_ok() {
    let mut tmp = NamedTempFile::new().unwrap();
    writeln!(
        tmp,
        r#"
name: research-agent
resolver-chain:
  - SubsetAutoApprove
  - BudgetCheck
  - AutoDeny
default-ttl: lifecycle
grants:
  - capability: http
    params:
      - key: allowlist
        value: "https://api.arxiv.org/*"
    ttl: persistent
"#
    )
    .unwrap();
    let mut r = PresetRegistry::with_builtins();
    let p = r.load_custom_yaml(tmp.path()).expect("load ok");
    assert_eq!(p.name, "research-agent");
    assert_eq!(p.resolver_chain_names.len(), 3);
    assert!(matches!(p.default_ttl, GrantTtl::Lifecycle));
    assert_eq!(p.grants.len(), 1);
    assert_eq!(p.grants[0].capability, "http");
}

#[test]
fn t11_malformed_yaml_charset_violation() {
    let mut tmp = NamedTempFile::new().unwrap();
    writeln!(
        tmp,
        r#"
name: bad:name
resolver-chain: [AutoDeny]
default-ttl: once
"#
    )
    .unwrap();
    let mut r = PresetRegistry::with_builtins();
    let err = r.load_custom_yaml(tmp.path()).unwrap_err();
    assert!(
        matches!(err, CapGrantError::InvalidConfig(_)),
        "got: {err:?}"
    );
}

#[test]
fn t11_oversized_yaml_rejected() {
    let mut tmp = NamedTempFile::new().unwrap();
    let big_value = "x".repeat(2 * 1024 * 1024); // 2 MiB
    writeln!(
        tmp,
        "name: big\nresolver-chain: [AutoDeny]\ndefault-ttl: once\ndata: {big_value}"
    )
    .unwrap();
    let mut r = PresetRegistry::with_builtins();
    let err = r.load_custom_yaml(tmp.path()).unwrap_err();
    assert!(matches!(err, CapGrantError::InvalidConfig(_)));
}

#[test]
fn t11_apply_custom_preset_creates_and_revokes() {
    // Apply a custom preset to a target with one existing dynamic grant;
    // expect: existing dynamic grant revoked, new preset grants created,
    // preset.applied event emitted.
    let mut tmp = NamedTempFile::new().unwrap();
    writeln!(
        tmp,
        r#"
name: test-apply
resolver-chain: [AutoDeny]
default-ttl: once
grants:
  - capability: http
    params:
      - key: allowlist
        value: "https://example.com/*"
    ttl: persistent
"#
    )
    .unwrap();

    let (store, bus, _h) = make_store();
    let mut registry = PresetRegistry::with_builtins();
    registry.load_custom_yaml(tmp.path()).unwrap();

    // Pre-populate target with a dynamic grant that should be revoked.
    let preexisting = Grant {
        id: GrantId::new("dyn-1"),
        grantee: "bob".to_string(),
        capability: "fs".to_string(),
        params: vec![CapParam {
            key: "read-paths".into(),
            value: "/tmp".into(),
        }],
        ttl: GrantTtl::Persistent,
        issuer: GrantIssuer::Resolver("test".into()),
        provenance: GrantProvenance::Requested,
        status: GrantStatus::Active,
        created_at: Utc::now(),
        expires_at: None,
    };
    store.insert_dynamic(preexisting).unwrap();

    // Audit-fix R5 (Adversarial Warning 3): caller_id must equal
    // target_grantee in Slice B (self-apply only). Bob applies the preset
    // to himself; bob already needs a wide http grant in store so the
    // preset's http grant subset-checks against it.
    let bob_http = Grant {
        id: GrantId::new("bob-http"),
        grantee: "bob".to_string(),
        capability: "http".to_string(),
        params: vec![CapParam {
            key: "allowlist".into(),
            value: "https://example.com/*".into(),
        }],
        ttl: GrantTtl::Persistent,
        issuer: GrantIssuer::Config,
        provenance: GrantProvenance::Requested,
        status: GrantStatus::Active,
        created_at: Utc::now(),
        expires_at: None,
    };
    store.insert_dynamic(bob_http).unwrap();

    let validator = SubsetValidatorImpl::new();
    let result = registry
        .apply_preset("test-apply", "bob", &store, &validator, "bob")
        .expect("apply ok");
    // Bob held 2 dynamic grants (preexisting fs grant + the http grant we
    // inserted to satisfy step 2 subset check). Both get revoked in step 3.
    assert_eq!(result.revoked.len(), 2, "should revoke 2 dynamic grants");
    assert_eq!(result.created.len(), 1, "should create 1 preset grant");
    assert_eq!(
        store.get("dyn-1").unwrap().status,
        GrantStatus::Revoked,
        "preexisting dynamic grant is revoked"
    );
    assert_eq!(
        store.get("bob-http").unwrap().status,
        GrantStatus::Revoked,
        "subset-authorizing dynamic grant is revoked with the preset apply"
    );
    let created = store
        .get(result.created[0].as_str())
        .expect("created preset grant is installed");
    assert_eq!(created.status, GrantStatus::Active);
    assert_eq!(created.grantee, "bob");
    assert_eq!(created.capability, "http");
    assert!(matches!(
        created.provenance,
        GrantProvenance::Preset(ref name) if name == "test-apply"
    ));
    let active: Vec<_> = store
        .list_by_grantee("bob")
        .into_iter()
        .filter(|grant| grant.status == GrantStatus::Active)
        .collect();
    assert_eq!(
        active.len(),
        1,
        "active-grants reflects exactly the non-empty preset grant set"
    );
    assert_eq!(active[0].id, result.created[0]);

    let applied_events = bus.all_of("preset.applied");
    assert_eq!(applied_events.len(), 1);
    let p = &applied_events[0].payload;
    assert_eq!(p["target_agent"], "bob");
    assert_eq!(p["preset_name"], "test-apply");
    assert_eq!(p["grants_revoked"], 2);
    assert_eq!(p["grants_created"], 1);
}

#[test]
fn t36_apply_autonomous_no_grants() {
    // autonomous preset has no `grants:` — apply should revoke any existing
    // dynamic grants and emit preset.applied with grants_created=0.
    let (store, bus, _h) = make_store();
    let registry = PresetRegistry::with_builtins();

    let preexisting = Grant {
        id: GrantId::new("dyn-x"),
        grantee: "bob".to_string(),
        capability: "fs".to_string(),
        params: vec![],
        ttl: GrantTtl::Persistent,
        issuer: GrantIssuer::Resolver("test".into()),
        provenance: GrantProvenance::Requested,
        status: GrantStatus::Active,
        created_at: Utc::now(),
        expires_at: None,
    };
    store.insert_dynamic(preexisting).unwrap();

    let validator = SubsetValidatorImpl::new();
    let result = registry
        .apply_preset(PRESET_AUTONOMOUS, "bob", &store, &validator, "bob")
        .expect("apply ok");
    assert_eq!(result.revoked.len(), 1);
    assert_eq!(result.created.len(), 0);

    let applied = bus.all_of("preset.applied");
    assert_eq!(applied.len(), 1);
    assert_eq!(applied[0].payload["grants_created"], 0);
}

#[test]
fn t36_apply_cascades_descendants_audit_fix_r2() {
    // Audit-fix R2 Diff Warning 1 verification: apply_preset's step 3
    // cascades through provenance descendants (matching spec §1.4.4 step 3
    // "Revoke all existing dynamic grants on target agent (cascade)").
    // Setup: target alice has dynamic grant g_a; g_a was delegated to bob
    // as g_b. Apply a preset to alice → both g_a (alice's dynamic) AND
    // g_b (bob's delegated descendant) must end up Revoked.
    let (store, bus, _h) = make_store();
    let registry = PresetRegistry::with_builtins();

    let g_a = Grant {
        id: GrantId::new("g-a"),
        grantee: "alice".to_string(),
        capability: "fs".to_string(),
        params: vec![],
        ttl: GrantTtl::Persistent,
        issuer: GrantIssuer::Resolver("test".into()),
        provenance: GrantProvenance::Requested,
        status: GrantStatus::Active,
        created_at: Utc::now(),
        expires_at: None,
    };
    store.insert_dynamic(g_a.clone()).unwrap();

    let g_b = Grant {
        id: GrantId::new("g-b"),
        grantee: "bob".to_string(),
        capability: "fs".to_string(),
        params: vec![],
        ttl: GrantTtl::Persistent,
        issuer: GrantIssuer::Resolver("test".into()),
        provenance: GrantProvenance::Delegated(GrantId::new("g-a")),
        status: GrantStatus::Active,
        created_at: Utc::now(),
        expires_at: None,
    };
    store.insert_dynamic(g_b.clone()).unwrap();

    let validator = SubsetValidatorImpl::new();
    let result = registry
        .apply_preset(PRESET_AUTONOMOUS, "alice", &store, &validator, "alice")
        .expect("apply ok");

    // alice's g-a should be Revoked.
    assert_eq!(
        store.get(g_a.id.as_str()).unwrap().status,
        GrantStatus::Revoked,
        "alice's dynamic grant must be revoked"
    );
    // bob's g-b (delegated descendant) should ALSO be Revoked.
    assert_eq!(
        store.get(g_b.id.as_str()).unwrap().status,
        GrantStatus::Revoked,
        "bob's delegated descendant must be cascade-revoked"
    );
    // The result.revoked list contains both.
    assert!(result.revoked.iter().any(|i| i.as_str() == "g-a"));
    assert!(result.revoked.iter().any(|i| i.as_str() == "g-b"));

    // Verify preset.applied event has grants_revoked=2 (both root + descendant).
    let applied = bus.all_of("preset.applied");
    assert_eq!(applied.len(), 1);
    assert_eq!(applied[0].payload["grants_revoked"], 2);
}

#[test]
fn t36_apply_subset_violation_errors_no_state_change() {
    // Custom preset wants `tools: [tool-x]` but caller has no tools grant
    // → SubsetViolation; no state change expected.
    let mut tmp = NamedTempFile::new().unwrap();
    writeln!(
        tmp,
        r#"
name: needs-tools
resolver-chain: [AutoDeny]
default-ttl: once
grants:
  - capability: tools
    params:
      - key: ids
        value: tool-x
    ttl: persistent
"#
    )
    .unwrap();

    let (store, bus, _h) = make_store();
    let mut registry = PresetRegistry::with_builtins();
    registry.load_custom_yaml(tmp.path()).unwrap();

    let validator = SubsetValidatorImpl::new();
    let err = registry
        .apply_preset("needs-tools", "bob", &store, &validator, "bob")
        .unwrap_err();
    assert!(
        matches!(err, CapGrantError::SubsetViolation(_)),
        "got: {err:?}"
    );
    // Verify no preset.applied event was emitted.
    assert_eq!(bus.count_of("preset.applied"), 0);
}
