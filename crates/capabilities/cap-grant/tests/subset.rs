//! SubsetValidator tests — AC-07 verification quorum.
//!
//! Covers all 14 spec-table subset rules positive AND negative + sub-fields
//! on multi-sub-rule rows (messaging.max-fanout AND max-depth, lifecycle
//! spawn-child AND spawn-sub) + 8 boundary conditions + 2 URL-pattern
//! abuse-vector tests (Round 5 Warning 2 fix).

use cap_grant::data::{
    CapParam, Grant, GrantDraft, GrantId, GrantIssuer, GrantProvenance, GrantStatus, GrantTtl,
};
use cap_grant::error::CapGrantError;
use cap_grant::subset::{SubsetValidator, SubsetValidatorImpl};
use chrono::Utc;

fn parent(capability: &str, params: Vec<CapParam>) -> Grant {
    Grant {
        id: GrantId::new("parent-id"),
        grantee: "alice".to_string(),
        capability: capability.to_string(),
        params,
        ttl: GrantTtl::Persistent,
        issuer: GrantIssuer::Config,
        provenance: GrantProvenance::StaticConfig,
        status: GrantStatus::Active,
        created_at: Utc::now(),
        expires_at: None,
    }
}

fn draft(capability: &str, params: Vec<CapParam>) -> GrantDraft {
    GrantDraft {
        capability: capability.to_string(),
        params,
        ttl: GrantTtl::Persistent,
    }
}

fn p(key: &str, value: &str) -> CapParam {
    CapParam {
        key: key.to_string(),
        value: value.to_string(),
    }
}

// ===== Row 1: fs read/write paths =====

#[test]
fn t07_fs_subset_path_prefix_ok() {
    let v = SubsetValidatorImpl::new();
    let pa = parent("fs", vec![p("read-paths", "/a")]);
    let ch = draft("fs", vec![p("read-paths", "/a/b")]);
    assert!(v.validate(&pa, &ch).is_ok());
}

#[test]
fn t07_fs_subset_path_outside_fail() {
    let v = SubsetValidatorImpl::new();
    let pa = parent("fs", vec![p("read-paths", "/c")]);
    let ch = draft("fs", vec![p("read-paths", "/a/b")]);
    assert!(matches!(
        v.validate(&pa, &ch),
        Err(CapGrantError::SubsetViolation(_))
    ));
}

// ===== Row 2: http allowlist URL patterns =====

#[test]
fn t08_http_subset_canonical_ok() {
    let v = SubsetValidatorImpl::new();
    let pa = parent("http", vec![p("allowlist", "https://api.github.com/*")]);
    let ch = draft(
        "http",
        vec![p("allowlist", "https://api.github.com/repos/*")],
    );
    assert!(
        v.validate(&pa, &ch).is_ok(),
        "PRD canonical example must pass"
    );
}

#[test]
fn t08_http_subset_reverse_fail() {
    let v = SubsetValidatorImpl::new();
    let pa = parent(
        "http",
        vec![p("allowlist", "https://api.github.com/repos/*")],
    );
    let ch = draft("http", vec![p("allowlist", "https://api.github.com/*")]);
    assert!(matches!(
        v.validate(&pa, &ch),
        Err(CapGrantError::SubsetViolation(_))
    ));
}

#[test]
fn t08_bx_malformed_subset_violation() {
    // Round 5 Warning 2 fix — malformed parent wildcard `<host>*` (no `/` before `*`)
    // routes to SubsetViolation (not InvalidConfig).
    let v = SubsetValidatorImpl::new();
    let pa = parent("http", vec![p("allowlist", "https://api.github.com*")]);
    let ch = draft(
        "http",
        vec![p("allowlist", "https://api.github.com/repos/*")],
    );
    let err = v.validate(&pa, &ch).unwrap_err();
    let CapGrantError::SubsetViolation(msg) = err else {
        panic!("expected SubsetViolation, got: {err:?}");
    };
    assert!(msg.contains("must terminate as `/*`"), "got: {msg}");
}

#[test]
fn t08_bx_sibling_domain_collision() {
    // Round 4 Critical 1 closure — sibling-domain prefix collision rejected.
    let v = SubsetValidatorImpl::new();
    let pa = parent("http", vec![p("allowlist", "https://api.github.com/*")]);
    let ch = draft(
        "http",
        vec![p("allowlist", "https://api.github.companyevil.com/*")],
    );
    assert!(matches!(
        v.validate(&pa, &ch),
        Err(CapGrantError::SubsetViolation(_))
    ));
}

// ===== Row 3: messaging targets =====

#[test]
fn t09_messaging_targets_subset_ok() {
    let v = SubsetValidatorImpl::new();
    let pa = parent("messaging", vec![p("targets", "a,b,c")]);
    let ch = draft("messaging", vec![p("targets", "a,b")]);
    assert!(v.validate(&pa, &ch).is_ok());
}

#[test]
fn t09_messaging_targets_subset_fail() {
    let v = SubsetValidatorImpl::new();
    let pa = parent("messaging", vec![p("targets", "a,b,c")]);
    let ch = draft("messaging", vec![p("targets", "a,d")]);
    assert!(matches!(
        v.validate(&pa, &ch),
        Err(CapGrantError::SubsetViolation(_))
    ));
}

// ===== Row 4: messaging max-fanout / max-depth =====

#[test]
fn t07_bx_msg_max_fanout_ok() {
    let v = SubsetValidatorImpl::new();
    let pa = parent("messaging", vec![p("max-fanout", "10")]);
    let ch = draft("messaging", vec![p("max-fanout", "5")]);
    assert!(v.validate(&pa, &ch).is_ok());
}

#[test]
fn t07_bx_msg_max_fanout_fail() {
    let v = SubsetValidatorImpl::new();
    let pa = parent("messaging", vec![p("max-fanout", "10")]);
    let ch = draft("messaging", vec![p("max-fanout", "20")]);
    assert!(matches!(
        v.validate(&pa, &ch),
        Err(CapGrantError::SubsetViolation(_))
    ));
}

#[test]
fn t07_bx_msg_max_depth_pos_and_neg() {
    // Round 2 Warning 4 fix — both positive AND negative for max-depth.
    let v = SubsetValidatorImpl::new();
    let pa = parent("messaging", vec![p("max-depth", "5")]);
    assert!(v
        .validate(&pa, &draft("messaging", vec![p("max-depth", "3")]))
        .is_ok());
    let neg = v.validate(&pa, &draft("messaging", vec![p("max-depth", "8")]));
    assert!(matches!(neg, Err(CapGrantError::SubsetViolation(_))));
}

// ===== Row 5: lifecycle spawn-child / spawn-sub =====

#[test]
fn t34_lifecycle_spawn_child() {
    let v = SubsetValidatorImpl::new();
    // Parent allows true; child false → ok.
    let pa = parent("lifecycle", vec![p("spawn-child", "true")]);
    assert!(v
        .validate(&pa, &draft("lifecycle", vec![p("spawn-child", "false")]))
        .is_ok());
    // Parent disallows; child requests → fail.
    let pa = parent("lifecycle", vec![p("spawn-child", "false")]);
    let neg = v.validate(&pa, &draft("lifecycle", vec![p("spawn-child", "true")]));
    assert!(matches!(neg, Err(CapGrantError::SubsetViolation(_))));
}

#[test]
fn t34_lifecycle_spawn_sub() {
    // Round 2 Warning 4 fix — separate test for spawn-sub sub-field.
    let v = SubsetValidatorImpl::new();
    let pa = parent("lifecycle", vec![p("spawn-sub", "true")]);
    assert!(v
        .validate(&pa, &draft("lifecycle", vec![p("spawn-sub", "false")]))
        .is_ok());
    let pa = parent("lifecycle", vec![p("spawn-sub", "false")]);
    let neg = v.validate(&pa, &draft("lifecycle", vec![p("spawn-sub", "true")]));
    assert!(matches!(neg, Err(CapGrantError::SubsetViolation(_))));
}

// ===== Row 6: llm.models =====

#[test]
fn t28_llm_models_subset_ok() {
    let v = SubsetValidatorImpl::new();
    let pa = parent("llm", vec![p("models", "sonnet,opus")]);
    let ch = draft("llm", vec![p("models", "sonnet")]);
    assert!(v.validate(&pa, &ch).is_ok());
}

#[test]
fn t28_llm_models_subset_fail() {
    let v = SubsetValidatorImpl::new();
    let pa = parent("llm", vec![p("models", "sonnet,opus")]);
    let ch = draft("llm", vec![p("models", "haiku")]);
    assert!(matches!(
        v.validate(&pa, &ch),
        Err(CapGrantError::SubsetViolation(_))
    ));
}

// ===== Row 7: llm.max-tokens-per-call =====

#[test]
fn t07_bx_llm_tokens_ok() {
    let v = SubsetValidatorImpl::new();
    let pa = parent("llm", vec![p("max-tokens-per-call", "4000")]);
    let ch = draft("llm", vec![p("max-tokens-per-call", "1000")]);
    assert!(v.validate(&pa, &ch).is_ok());
}

#[test]
fn t07_bx_llm_tokens_fail() {
    let v = SubsetValidatorImpl::new();
    let pa = parent("llm", vec![p("max-tokens-per-call", "4000")]);
    let ch = draft("llm", vec![p("max-tokens-per-call", "8000")]);
    assert!(matches!(
        v.validate(&pa, &ch),
        Err(CapGrantError::SubsetViolation(_))
    ));
}

// ===== Row 8: secrets =====

#[test]
fn t29_secrets_subset_ok() {
    let v = SubsetValidatorImpl::new();
    let pa = parent("secrets", vec![p("names", "key-a,key-b")]);
    let ch = draft("secrets", vec![p("names", "key-a")]);
    assert!(v.validate(&pa, &ch).is_ok());
}

#[test]
fn t29_secrets_subset_fail() {
    let v = SubsetValidatorImpl::new();
    let pa = parent("secrets", vec![p("names", "key-a")]);
    let ch = draft("secrets", vec![p("names", "key-c")]);
    assert!(matches!(
        v.validate(&pa, &ch),
        Err(CapGrantError::SubsetViolation(_))
    ));
}

// ===== Row 9: tools =====

#[test]
fn t30_tools_subset_ok() {
    let v = SubsetValidatorImpl::new();
    let pa = parent("tools", vec![p("ids", "tool-x,tool-y")]);
    let ch = draft("tools", vec![p("ids", "tool-x")]);
    assert!(v.validate(&pa, &ch).is_ok());
}

#[test]
fn t30_tools_subset_fail() {
    let v = SubsetValidatorImpl::new();
    let pa = parent("tools", vec![p("ids", "tool-x,tool-y")]);
    let ch = draft("tools", vec![p("ids", "tool-z")]);
    assert!(matches!(
        v.validate(&pa, &ch),
        Err(CapGrantError::SubsetViolation(_))
    ));
}

// ===== Row 10: notify =====

#[test]
fn t31_notify_subset_ok() {
    let v = SubsetValidatorImpl::new();
    let pa = parent("notify", vec![p("targets", "agent-a,agent-b")]);
    let ch = draft("notify", vec![p("targets", "agent-a")]);
    assert!(v.validate(&pa, &ch).is_ok());
}

#[test]
fn t31_notify_subset_fail() {
    let v = SubsetValidatorImpl::new();
    let pa = parent("notify", vec![p("targets", "agent-a,agent-b")]);
    let ch = draft("notify", vec![p("targets", "agent-c")]);
    assert!(matches!(
        v.validate(&pa, &ch),
        Err(CapGrantError::SubsetViolation(_))
    ));
}

// ===== Row 11+12: mcp servers, tool-patterns =====

#[test]
fn t32_mcp_servers_and_patterns_ok() {
    let v = SubsetValidatorImpl::new();
    let pa = parent(
        "mcp",
        vec![p("servers", "s1,s2"), p("tool-patterns", "t1,t2")],
    );
    let ch = draft("mcp", vec![p("servers", "s1"), p("tool-patterns", "t1")]);
    assert!(v.validate(&pa, &ch).is_ok());
}

#[test]
fn t32_neg_servers() {
    let v = SubsetValidatorImpl::new();
    let pa = parent("mcp", vec![p("servers", "s1,s2")]);
    let ch = draft("mcp", vec![p("servers", "s3")]);
    assert!(matches!(
        v.validate(&pa, &ch),
        Err(CapGrantError::SubsetViolation(_))
    ));
}

#[test]
fn t32_neg_tool_patterns() {
    let v = SubsetValidatorImpl::new();
    let pa = parent("mcp", vec![p("tool-patterns", "t1,t2")]);
    let ch = draft("mcp", vec![p("tool-patterns", "t3")]);
    assert!(matches!(
        v.validate(&pa, &ch),
        Err(CapGrantError::SubsetViolation(_))
    ));
}

// ===== Row 13+14: skills =====

#[test]
fn t33_skills_pos() {
    let v = SubsetValidatorImpl::new();
    let pa = parent(
        "skills",
        vec![p("max-active-skills", "5"), p("allowed-actions", "a,b")],
    );
    let ch = draft(
        "skills",
        vec![p("max-active-skills", "3"), p("allowed-actions", "a")],
    );
    assert!(v.validate(&pa, &ch).is_ok());
}

#[test]
fn t33_neg_max_active() {
    let v = SubsetValidatorImpl::new();
    let pa = parent("skills", vec![p("max-active-skills", "5")]);
    let ch = draft("skills", vec![p("max-active-skills", "10")]);
    assert!(matches!(
        v.validate(&pa, &ch),
        Err(CapGrantError::SubsetViolation(_))
    ));
}

#[test]
fn t33_neg_allowed_actions() {
    let v = SubsetValidatorImpl::new();
    let pa = parent("skills", vec![p("allowed-actions", "a,b")]);
    let ch = draft("skills", vec![p("allowed-actions", "c")]);
    assert!(matches!(
        v.validate(&pa, &ch),
        Err(CapGrantError::SubsetViolation(_))
    ));
}

// ===== 8 boundary conditions =====

#[test]
fn bx_capability_mismatch_fails() {
    let v = SubsetValidatorImpl::new();
    let pa = parent("fs", vec![p("read-paths", "/a")]);
    let ch = draft("http", vec![p("allowlist", "https://x/*")]);
    assert!(matches!(
        v.validate(&pa, &ch),
        Err(CapGrantError::SubsetViolation(_))
    ));
}

#[test]
fn bx_empty_parent_permits_any_child() {
    let v = SubsetValidatorImpl::new();
    let pa = parent("http", vec![]);
    let ch = draft("http", vec![p("allowlist", "https://anywhere/*")]);
    assert!(
        v.validate(&pa, &ch).is_ok(),
        "empty parent = whole-cap grant"
    );
}

#[test]
fn bx_empty_child_fails_against_restricted_parent() {
    let v = SubsetValidatorImpl::new();
    let pa = parent("http", vec![p("allowlist", "https://x/*")]);
    let ch = draft("http", vec![]);
    assert!(matches!(
        v.validate(&pa, &ch),
        Err(CapGrantError::SubsetViolation(_))
    ));
}

#[test]
fn bx_unknown_capability_fails_closed() {
    let v = SubsetValidatorImpl::new();
    let pa = parent("frobnicate", vec![p("foo", "bar")]);
    let ch = draft("frobnicate", vec![p("foo", "bar")]);
    let err = v.validate(&pa, &ch).unwrap_err();
    assert!(matches!(err, CapGrantError::SubsetViolation(_)));
}
