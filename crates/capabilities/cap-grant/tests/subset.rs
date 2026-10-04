//! SubsetValidator tests — AC-07 verification quorum.
//!
//! Covers all 14 spec-table subset rules positive AND negative + sub-fields
//! on multi-sub-rule rows (messaging.max-fanout AND max-depth, lifecycle
//! spawn-child AND spawn-sub) + 8 boundary conditions + 2 URL-pattern
//! abuse-vector tests (Round 5 Warning 2 fix).

use advance_shared_types::mcp::SERVER_WIDE_TOOL;
use cap_grant::data::{
    CapParam, Grant, GrantDraft, GrantId, GrantIssuer, GrantProvenance, GrantStatus, GrantTtl,
};
use cap_grant::error::CapGrantError;
use cap_grant::subset::{mcp_param_problems, SubsetValidator, SubsetValidatorImpl};
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

fn violates(v: &SubsetValidatorImpl, pa: &Grant, ch: &GrantDraft) -> bool {
    matches!(v.validate(pa, ch), Err(CapGrantError::SubsetViolation(_)))
}

#[test]
fn mcp_tool_patterns_are_compared_by_subsumption() {
    let v = SubsetValidatorImpl::new();
    let pa = parent(
        "mcp",
        vec![
            p("servers", "github"),
            p("tool-patterns", "get_*,search_code"),
        ],
    );
    let child = |patterns: &str| {
        draft(
            "mcp",
            vec![p("servers", "github"), p("tool-patterns", patterns)],
        )
    };
    for narrower in [
        "get_issue",
        "get_is*",
        "get_*",
        "search_code",
        "get_issue,search_code",
    ] {
        assert!(v.validate(&pa, &child(narrower)).is_ok(), "{narrower}");
    }
    for wider in ["g*", "delete_repo", "search_*", "get_issue,delete_repo"] {
        assert!(violates(&v, &pa, &child(wider)), "{wider}");
    }
    // A literal covers only itself.
    let literal = parent(
        "mcp",
        vec![p("servers", "github"), p("tool-patterns", "get_issue")],
    );
    assert!(violates(&v, &literal, &child("get_*")));
}

#[test]
fn mcp_malformed_patterns_are_violations_on_either_side() {
    let v = SubsetValidatorImpl::new();
    let pa = parent(
        "mcp",
        vec![p("servers", "github"), p("tool-patterns", "get_*")],
    );
    let open = parent("mcp", vec![p("servers", "github")]);
    let covered = draft(
        "mcp",
        vec![p("servers", "github"), p("tool-patterns", "get_issue")],
    );
    for bad in ["*", "get_*_x", "*get", "get?", "a*b", "x[1]", "x{a}"] {
        let ch = draft("mcp", vec![p("servers", "github"), p("tool-patterns", bad)]);
        assert!(violates(&v, &pa, &ch), "child {bad}");
        assert!(violates(&v, &open, &ch), "child {bad} under an open parent");
        // A malformed parent pattern refuses even a child its other patterns cover.
        let bad_parent = parent(
            "mcp",
            vec![
                p("servers", "github"),
                p("tool-patterns", &format!("get_*,{bad}")),
            ],
        );
        assert!(violates(&v, &bad_parent, &covered), "parent {bad}");
    }
}

#[test]
fn mcp_absent_tool_patterns_reach_every_tool() {
    let v = SubsetValidatorImpl::new();
    // A parent without tool-patterns covers any well-formed patterns on its servers.
    let open = parent("mcp", vec![p("servers", "github")]);
    let narrowed = draft(
        "mcp",
        vec![p("servers", "github"), p("tool-patterns", "get_*")],
    );
    assert!(v.validate(&open, &narrowed).is_ok());
    // A child that drops the parent's tool-patterns would reach every tool.
    let restricted = parent(
        "mcp",
        vec![p("servers", "github"), p("tool-patterns", "get_*")],
    );
    let dropped = draft("mcp", vec![p("servers", "github")]);
    assert!(violates(&v, &restricted, &dropped));
}

#[test]
fn mcp_absent_servers_reach_no_server() {
    let v = SubsetValidatorImpl::new();
    let no_servers = parent("mcp", vec![p("tool-patterns", "get_*")]);
    let ch = draft(
        "mcp",
        vec![p("servers", "github"), p("tool-patterns", "get_*")],
    );
    assert!(violates(&v, &no_servers, &ch));
    // A child without servers reaches none, which is narrower than any parent.
    let pa = parent("mcp", vec![p("servers", "github")]);
    let ch = draft("mcp", vec![p("tool-patterns", "get_*")]);
    assert!(v.validate(&pa, &ch).is_ok());
}

#[test]
fn mcp_keys_outside_servers_and_tool_patterns_are_violations() {
    let v = SubsetValidatorImpl::new();
    // A misspelled `tool-patterns` must not read as "every tool".
    let pa = parent("mcp", vec![p("servers", "github")]);
    let typo = draft(
        "mcp",
        vec![p("servers", "github"), p("tool_patterns", "get_*")],
    );
    assert!(violates(&v, &pa, &typo));
    let typo_parent = parent(
        "mcp",
        vec![p("servers", "github"), p("tool_patterns", "get_*")],
    );
    let ch = draft(
        "mcp",
        vec![p("servers", "github"), p("tool-patterns", "get_issue")],
    );
    assert!(violates(&v, &typo_parent, &ch));
}

// ===== covers_request: the call-time check of the L1 gate =====

#[test]
fn covers_request_reads_mcp_tokens_as_literal_names() {
    let v = SubsetValidatorImpl::new();
    let held = parent(
        "mcp",
        vec![p("servers", "github"), p("tool-patterns", "get_*")],
    );
    let call = |tool: &str| {
        draft(
            "mcp",
            vec![p("servers", "github"), p("tool-patterns", tool)],
        )
    };
    assert!(v.covers_request(&held, &call("get_issue")).is_ok());
    assert!(v.covers_request(&held, &call("delete_repo")).is_err());
    // `get_*x` is a tool name here, covered because it starts with `get_`; as a grant
    // draft the same token is a malformed pattern.
    assert!(v.covers_request(&held, &call("get_*x")).is_ok());
    assert!(v.validate(&held, &call("get_*x")).is_err());
    // A name never widens to a pattern: `get*` does not start with `get_`.
    assert!(v.covers_request(&held, &call("get*")).is_err());
    assert!(v.covers_request(&held, &call("get_\u{200B}x")).is_err());
}

#[test]
fn covers_request_without_tool_patterns_asks_for_the_server_only() {
    let v = SubsetValidatorImpl::new();
    let held = parent(
        "mcp",
        vec![p("servers", "github"), p("tool-patterns", "get_*")],
    );
    let server_level = draft("mcp", vec![p("servers", "github")]);
    assert!(v.covers_request(&held, &server_level).is_ok());
    // As a grant draft, the same params would drop the tool restriction.
    assert!(v.validate(&held, &server_level).is_err());
    assert!(v
        .covers_request(&held, &draft("mcp", vec![p("servers", "slack")]))
        .is_err());
    // A request names the server it addresses, whatever the grant.
    let serverless = draft("mcp", vec![p("tool-patterns", "get_issue")]);
    assert!(v.covers_request(&held, &serverless).is_err());
    assert!(v
        .covers_request(&parent("mcp", vec![]), &serverless)
        .is_err());
}

#[test]
fn covers_request_server_wide_needs_an_unrestricted_tool_axis() {
    let v = SubsetValidatorImpl::new();
    let server_wide = draft(
        "mcp",
        vec![p("servers", "github"), p("tool-patterns", SERVER_WIDE_TOOL)],
    );
    assert!(v
        .covers_request(&parent("mcp", vec![]), &server_wide)
        .is_ok());
    assert!(v
        .covers_request(&parent("mcp", vec![p("servers", "github")]), &server_wide)
        .is_ok());
    let restricted = parent(
        "mcp",
        vec![p("servers", "github"), p("tool-patterns", "get_*")],
    );
    assert!(v.covers_request(&restricted, &server_wide).is_err());
}

#[test]
fn covers_request_is_validate_for_other_families() {
    let v = SubsetValidatorImpl::new();
    let held = parent(
        "fs",
        vec![p("read-paths", "/notes"), p("write-paths", "/notes/drafts")],
    );
    for (request, covered) in [
        (vec![p("read-paths", "/notes/a.md")], true),
        (
            vec![
                p("read-paths", "/notes/drafts/b.md"),
                p("write-paths", "/notes/drafts/b.md"),
            ],
            true,
        ),
        (
            vec![
                p("read-paths", "/notes/a.md"),
                p("write-paths", "/notes/a.md"),
            ],
            false,
        ),
        (vec![p("read-paths", "/etc")], false),
        (vec![], false),
    ] {
        let ch = draft("fs", request);
        assert_eq!(v.covers_request(&held, &ch).is_ok(), covered, "{ch:?}");
        assert_eq!(
            v.covers_request(&held, &ch).is_ok(),
            v.validate(&held, &ch).is_ok(),
            "{ch:?}"
        );
    }
    // The retired `data` family keeps its set rule.
    let read_only = parent("data", vec![p("mode", "read")]);
    for (mode, covered) in [("read", true), ("write", false), ("read,write", false)] {
        let ch = draft("data", vec![p("mode", mode)]);
        assert_eq!(v.covers_request(&read_only, &ch).is_ok(), covered, "{mode}");
        assert_eq!(
            v.covers_request(&read_only, &ch).is_ok(),
            v.validate(&read_only, &ch).is_ok(),
            "{mode}"
        );
    }
}

#[test]
fn mcp_param_problems_name_what_covers_nothing() {
    assert!(mcp_param_problems(&[]).is_empty());
    assert!(mcp_param_problems(&[
        p("servers", "github,slack"),
        p("tool-patterns", "get_*,search_code")
    ])
    .is_empty());

    let problems =
        mcp_param_problems(&[p("servers", "github,*"), p("tool-patterns", "get_*,*,a*b")]);
    assert_eq!(problems.len(), 3, "{problems:?}");
    assert!(problems[0].contains("\"*\"") && problems[0].contains("literal id"));
    assert!(problems[1].contains("\"*\"") && problems[1].contains("covers no tool"));
    assert!(problems[2].contains("\"a*b\"") && problems[2].contains("covers no tool"));

    let typo = mcp_param_problems(&[p("server", "github"), p("tool-patterns", "get_*")]);
    assert_eq!(typo.len(), 2, "{typo:?}");
    assert!(typo[0].contains("`server`") && typo[0].contains("covers nothing"));
    assert!(typo[1].contains("reaches no server"));

    let empty = mcp_param_problems(&[p("servers", ""), p("tool-patterns", "")]);
    assert_eq!(empty.len(), 2, "{empty:?}");
    assert!(empty[0].contains("`servers` is empty"));
    assert!(empty[1].contains("`tool-patterns` is empty"));
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

// `data` is a retired family (the data tool is authorized by `fs`). Its rule stays so grants
// persisted by earlier releases can still be narrowed and compared.
#[test]
fn data_mode_is_a_set_subset() {
    let v = SubsetValidatorImpl::new();
    let rw = parent("data", vec![p("mode", "read,write")]);
    let ro = parent("data", vec![p("mode", "read")]);
    assert!(v
        .validate(&rw, &draft("data", vec![p("mode", "read")]))
        .is_ok());
    assert!(v
        .validate(&rw, &draft("data", vec![p("mode", "write")]))
        .is_ok());
    assert!(v
        .validate(&rw, &draft("data", vec![p("mode", "read,write")]))
        .is_ok());
    assert!(matches!(
        v.validate(&ro, &draft("data", vec![p("mode", "write")])),
        Err(CapGrantError::SubsetViolation(_))
    ));
    assert!(matches!(
        v.validate(&ro, &draft("data", vec![])),
        Err(CapGrantError::SubsetViolation(_))
    ));
    // An unrestricted data grant covers any mode.
    assert!(v
        .validate(
            &parent("data", vec![]),
            &draft("data", vec![p("mode", "write")])
        )
        .is_ok());
}
