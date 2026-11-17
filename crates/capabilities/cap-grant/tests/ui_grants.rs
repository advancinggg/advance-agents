//! ADR 2026-10-28 D2 — the `browser` / `screen` grant-param families
//! (CONTRACT-122 subsets) and the `UiPolicyReader` projection.
//!
//! - The L1 gate allows a `browser` request whose `origins` param is covered by
//!   a granted origin (exact or `*.` wildcard) and denies one that is not; an
//!   EMPTY granted list denies everything; a whole-capability grant allows any
//!   origin. The same for `screen.targets`.
//! - Unknown knobs are rejected by the fail-closed projection.
//! - The policy reader merges grants as a union and defaults every knob to its
//!   most restrictive value.

mod common;

use advance_shared_types::capability::{CapParams, GrantDecision};
use advance_shared_types::traits::GrantCheck;
use advance_shared_types::ui::{
    AllowRule, ConfirmPolicy, ScreenMode, UiPolicyReader, BROWSER_CAPABILITY, SCREEN_CAPABILITY,
};
use cap_grant::data::{
    CapParam, Grant, GrantId, GrantIssuer, GrantProvenance, GrantStatus, GrantTtl,
};
use cap_grant::{origin_covered, GrantCheckImpl, StaticConfigCompiler, UiPolicyReaderImpl};
use chrono::Utc;
use serde_json::json;
use std::sync::Arc;

use crate::common::make_store;

const AGENT: &str = "agent-ui";
const NAVIGATE: &str = "advance:runtime/ui-browser@0.1.0::navigate";
const DESCRIBE: &str = "advance:runtime/ui-screen@0.1.0::describe";

fn grant(id: &str, capability: &str, params: &[(&str, &str)]) -> Grant {
    Grant {
        id: GrantId::new(id),
        grantee: AGENT.to_string(),
        capability: capability.to_string(),
        params: params
            .iter()
            .map(|(k, v)| CapParam {
                key: (*k).to_string(),
                value: (*v).to_string(),
            })
            .collect(),
        ttl: GrantTtl::Persistent,
        issuer: GrantIssuer::Config,
        provenance: GrantProvenance::StaticConfig,
        status: GrantStatus::Active,
        created_at: Utc::now(),
        expires_at: None,
    }
}

fn check_with(grants: Vec<Grant>) -> (GrantCheckImpl, UiPolicyReaderImpl) {
    let (store, _bus, _handle) = make_store();
    for g in grants {
        store.insert(g).unwrap();
    }
    (
        GrantCheckImpl::new(Arc::clone(&store)),
        UiPolicyReaderImpl::new(store),
    )
}

fn origins(origin: &str) -> CapParams {
    CapParams::new(json!({ "origins": origin }))
}

#[test]
fn origin_covered_exact_and_wildcard_only() {
    assert!(origin_covered("https://example.com", "https://example.com"));
    assert!(origin_covered("HTTPS://Example.com", "https://example.com"));
    assert!(origin_covered(
        "https://*.wikipedia.org",
        "https://en.wikipedia.org"
    ));
    assert!(origin_covered(
        "https://*.wikipedia.org",
        "https://en.m.wikipedia.org"
    ));
    // The wildcard never covers the apex itself, a sibling or another scheme.
    assert!(!origin_covered(
        "https://*.wikipedia.org",
        "https://wikipedia.org"
    ));
    assert!(!origin_covered(
        "https://*.wikipedia.org",
        "https://evilwikipedia.org"
    ));
    assert!(!origin_covered(
        "https://*.wikipedia.org",
        "http://en.wikipedia.org"
    ));
    // Ports are part of the origin.
    assert!(origin_covered(
        "http://localhost:8080",
        "http://localhost:8080"
    ));
    assert!(!origin_covered(
        "http://localhost:8080",
        "http://localhost:9090"
    ));
    assert!(!origin_covered("http://localhost", "http://localhost:8080"));
    // Paths, bare hosts and mid-glob patterns cover nothing.
    assert!(!origin_covered(
        "https://example.com/",
        "https://example.com"
    ));
    assert!(!origin_covered("example.com", "https://example.com"));
    assert!(!origin_covered("https://ex*.com", "https://example.com"));
    assert!(!origin_covered("https://*", "https://example.com"));
}

/// The L1 gate: listed origins allow, others deny, an empty list denies all.
#[test]
fn browser_origins_allowlist_decides_the_navigate_request() {
    let (check, _) = check_with(vec![grant(
        "g-browser",
        BROWSER_CAPABILITY,
        &[("origins", "https://example.com,https://*.wikipedia.org")],
    )]);
    assert_eq!(
        check.check(
            AGENT,
            BROWSER_CAPABILITY,
            NAVIGATE,
            &origins("https://example.com")
        ),
        GrantDecision::Allow
    );
    assert_eq!(
        check.check(
            AGENT,
            BROWSER_CAPABILITY,
            NAVIGATE,
            &origins("https://en.wikipedia.org")
        ),
        GrantDecision::Allow
    );
    assert!(matches!(
        check.check(
            AGENT,
            BROWSER_CAPABILITY,
            NAVIGATE,
            &origins("https://evil.test")
        ),
        GrantDecision::Deny(_)
    ));
    assert!(matches!(
        check.check(
            AGENT,
            BROWSER_CAPABILITY,
            NAVIGATE,
            &origins("http://example.com")
        ),
        GrantDecision::Deny(_)
    ));
    // The capability-level check (no params) still passes: the grant exists.
    assert_eq!(
        check.check(AGENT, BROWSER_CAPABILITY, NAVIGATE, &CapParams::empty()),
        GrantDecision::Allow
    );
}

#[test]
fn empty_origins_list_denies_every_origin() {
    let (check, reader) = check_with(vec![grant(
        "g-browser-empty",
        BROWSER_CAPABILITY,
        &[("origins", "")],
    )]);
    assert!(matches!(
        check.check(
            AGENT,
            BROWSER_CAPABILITY,
            NAVIGATE,
            &origins("https://example.com")
        ),
        GrantDecision::Deny(_)
    ));
    let policy = reader
        .browser_policy(AGENT)
        .expect("a browser grant is held");
    assert!(policy.origins.is_empty_list());
}

#[test]
fn whole_capability_browser_grant_allows_any_origin_with_restrictive_knobs() {
    let (check, reader) = check_with(vec![grant("g-browser-any", BROWSER_CAPABILITY, &[])]);
    assert_eq!(
        check.check(
            AGENT,
            BROWSER_CAPABILITY,
            NAVIGATE,
            &origins("https://anything.test")
        ),
        GrantDecision::Allow
    );
    let policy = reader.browser_policy(AGENT).unwrap();
    assert_eq!(policy.origins, AllowRule::Any);
    assert_eq!(policy.confirm, ConfirmPolicy::Always);
    assert!(!policy.downloads);
    assert_eq!(policy.surfaces, vec!["in-app".to_string()]);
}

#[test]
fn no_browser_grant_denies_and_reads_as_none() {
    let (check, reader) = check_with(vec![grant("g-fs", "fs", &[])]);
    assert!(matches!(
        check.check(
            AGENT,
            BROWSER_CAPABILITY,
            NAVIGATE,
            &origins("https://example.com")
        ),
        GrantDecision::Deny(_)
    ));
    assert!(matches!(
        check.check(AGENT, BROWSER_CAPABILITY, NAVIGATE, &CapParams::empty()),
        GrantDecision::Deny(_)
    ));
    assert!(reader.browser_policy(AGENT).is_none());
    assert!(reader.screen_policy(AGENT).is_none());
}

#[test]
fn unknown_knob_is_rejected_by_the_projection() {
    let (check, _) = check_with(vec![grant("g-browser-any", BROWSER_CAPABILITY, &[])]);
    assert!(matches!(
        check.check(
            AGENT,
            BROWSER_CAPABILITY,
            NAVIGATE,
            &CapParams::new(json!({ "javascript": "true" }))
        ),
        GrantDecision::Deny(_)
    ));
}

#[test]
fn screen_targets_allowlist_decides_and_filters() {
    let (check, reader) = check_with(vec![grant(
        "g-screen",
        SCREEN_CAPABILITY,
        &[
            ("targets", "com.apple.TextEdit,com.apple.Notes"),
            ("mode", "ax"),
            ("confirm", "sensitive"),
        ],
    )]);
    let target = |t: &str| CapParams::new(json!({ "targets": t }));
    assert_eq!(
        check.check(
            AGENT,
            SCREEN_CAPABILITY,
            DESCRIBE,
            &target("com.apple.TextEdit")
        ),
        GrantDecision::Allow
    );
    assert!(matches!(
        check.check(
            AGENT,
            SCREEN_CAPABILITY,
            DESCRIBE,
            &target("com.apple.Safari")
        ),
        GrantDecision::Deny(_)
    ));
    let policy = reader.screen_policy(AGENT).unwrap();
    assert_eq!(
        policy.targets,
        AllowRule::List(vec![
            "com.apple.TextEdit".to_string(),
            "com.apple.Notes".to_string()
        ])
    );
    assert_eq!(policy.mode, ScreenMode::Ax);
    assert_eq!(policy.confirm, ConfirmPolicy::Sensitive);
    assert!(!policy.secure_input);
}

#[test]
fn policy_reader_merges_grants_as_a_union() {
    let (_, reader) = check_with(vec![
        grant(
            "g-a",
            BROWSER_CAPABILITY,
            &[("origins", "https://a.test"), ("confirm", "always")],
        ),
        grant(
            "g-b",
            BROWSER_CAPABILITY,
            &[
                ("origins", "https://b.test"),
                ("confirm", "never"),
                ("downloads", "true"),
                ("surfaces", "external"),
            ],
        ),
    ]);
    let policy = reader.browser_policy(AGENT).unwrap();
    assert_eq!(
        policy.origins,
        AllowRule::List(vec![
            "https://a.test".to_string(),
            "https://b.test".to_string()
        ])
    );
    assert_eq!(policy.confirm, ConfirmPolicy::Never);
    assert!(policy.downloads);
    let mut surfaces = policy.surfaces.clone();
    surfaces.sort();
    assert_eq!(surfaces, vec!["external".to_string(), "in-app".to_string()]);
}

/// The operator's YAML is what reaches the gate: `StaticConfigCompiler` stores a
/// sequence as a comma-separated param and an empty sequence as an empty one; the
/// policy reader and the L1 gate read that encoding back (an empty list denies).
#[test]
fn yaml_config_compiles_into_the_browser_and_screen_policy() {
    let yaml: serde_yml::Value = serde_yml::from_str(
        "capabilities:\n  browser:\n    origins: [\"https://fixture.test\", \"https://*.example.com\"]\n    confirm: always\n  screen:\n    targets: []\n    secure-input: true\n",
    )
    .unwrap();
    let grants = StaticConfigCompiler::compile_from_value(&yaml, AGENT).unwrap();
    let (check, reader) = check_with(grants);

    let browser = reader.browser_policy(AGENT).expect("browser policy");
    assert_eq!(
        browser.origins,
        AllowRule::List(vec![
            "https://fixture.test".to_string(),
            "https://*.example.com".to_string()
        ])
    );
    assert_eq!(browser.confirm, ConfirmPolicy::Always);
    assert!(!browser.downloads);
    for allowed in ["https://fixture.test", "https://app.example.com"] {
        assert_eq!(
            check.check(AGENT, BROWSER_CAPABILITY, NAVIGATE, &origins(allowed)),
            GrantDecision::Allow,
            "{allowed}"
        );
    }
    assert!(matches!(
        check.check(
            AGENT,
            BROWSER_CAPABILITY,
            NAVIGATE,
            &origins("https://denied.test")
        ),
        GrantDecision::Deny(_)
    ));

    let screen = reader.screen_policy(AGENT).expect("screen policy");
    assert_eq!(screen.targets, AllowRule::List(Vec::new()));
    assert!(screen.secure_input);
    assert!(matches!(
        check.check(
            AGENT,
            SCREEN_CAPABILITY,
            DESCRIBE,
            &CapParams::new(json!({ "targets": "com.apple.TextEdit" }))
        ),
        GrantDecision::Deny(_)
    ));
}
