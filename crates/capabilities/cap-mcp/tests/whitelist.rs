//! Slice D AC-23 — whitelist + tool-patterns + capability split (SD-11..SD-15c).

use std::collections::BTreeMap;
use std::sync::Arc;

use advance_runtime::host_registry::HostRegistry;
use advance_runtime::host_registry::InMemoryHostRegistry;
use advance_shared_types::security_validator::{
    Allowlist, HttpCapability, LeakDetector, ScanContext, ScanResult,
};
use cap_mcp::{
    is_valid_server_id, register_mcp_client, McpClient, McpError, McpErrorKind, McpServerEntry,
    McpServersConfig, McpTransportSpec, ToolPattern,
};

struct NoOpDetector;
impl LeakDetector for NoOpDetector {
    fn scan(&self, _t: &str, _c: ScanContext) -> ScanResult {
        ScanResult::Clean
    }
    fn scan_headers(&self, _h: &[(String, String)]) -> ScanResult {
        ScanResult::Clean
    }
}

fn http_entry(server_id: &str, patterns: Option<Vec<&str>>) -> McpServerEntry {
    let tool_patterns = patterns.map(|raws| {
        raws.into_iter()
            .map(|r| ToolPattern::compile(r).unwrap())
            .collect::<Vec<_>>()
    });
    McpServerEntry {
        server_id: server_id.to_string(),
        description: "test".to_string(),
        transport: McpTransportSpec::Http {
            endpoint_url: format!("https://{server_id}.example.com/mcp"),
            capability: HttpCapability {
                allowlist: Allowlist {
                    patterns: vec!["*.example.com".to_string()],
                },
                credentials: vec![],
                component_id: server_id.into(),
            },
        },
        tool_patterns,
        tool_schemas: BTreeMap::new(),
    }
}

// ─────────────────────────────────────────────────────────────────────────
// SD-11 — list_servers returns whitelisted entries exactly
// ─────────────────────────────────────────────────────────────────────────
#[tokio::test]
async fn sd_11_list_servers_returns_whitelist() {
    let cfg = Arc::new(
        McpServersConfig::builder()
            .add_server(http_entry("alpha", None))
            .unwrap()
            .add_server(http_entry("beta", None))
            .unwrap()
            .build(),
    );
    let client = McpClient::new(cfg, Arc::new(NoOpDetector), None);
    let servers = client.list_servers().await;
    let ids: Vec<_> = servers.iter().map(|s| s.id.as_str()).collect();
    assert_eq!(ids, vec!["alpha", "beta"]);
}

// ─────────────────────────────────────────────────────────────────────────
// SD-12 — server unknown → McpErrorKind::NotFound
// ─────────────────────────────────────────────────────────────────────────
#[tokio::test]
async fn sd_12_unknown_server_blocked() {
    let cfg = Arc::new(
        McpServersConfig::builder()
            .add_server(http_entry("alpha", None))
            .unwrap()
            .build(),
    );
    let client = McpClient::new(cfg, Arc::new(NoOpDetector), None);
    let err = client
        .invoke_tool("gamma", "x", b"{}")
        .await
        .expect_err("not in whitelist");
    assert_eq!(err.kind, McpErrorKind::NotFound);
    assert!(err.message.contains("'gamma'"));
    assert!(err.message.contains("whitelist"));
}

// ─────────────────────────────────────────────────────────────────────────
// SD-13 — list_tools filters via tool_patterns
// (Skipped here — requires a transport mock; covered by tests/client_surface.rs.)
//
// SD-14 — invoke_tool blocked by tool_patterns → ToolNotFound
// ─────────────────────────────────────────────────────────────────────────
#[tokio::test]
async fn sd_14_tool_pattern_blocks_invoke() {
    let cfg = Arc::new(
        McpServersConfig::builder()
            .add_server(http_entry("alpha", Some(vec!["search.*"])))
            .unwrap()
            .build(),
    );
    let client = McpClient::new(cfg, Arc::new(NoOpDetector), None);
    let err = client
        .invoke_tool("alpha", "delete-all", b"{}")
        .await
        .expect_err("blocked by tool-patterns");
    assert_eq!(err.kind, McpErrorKind::ToolNotFound);
    assert!(err.message.contains("delete-all"));
    assert!(err.message.contains("mcp.tool-patterns"));
}

// ─────────────────────────────────────────────────────────────────────────
// SD-15 — tool_patterns absent → no filter (all allowed)
// ─────────────────────────────────────────────────────────────────────────
#[tokio::test]
async fn sd_15_no_patterns_allows_all() {
    let cfg = Arc::new(
        McpServersConfig::builder()
            .add_server(http_entry("alpha", None))
            .unwrap()
            .build(),
    );
    let _client = McpClient::new(cfg, Arc::new(NoOpDetector), None);
    // No filter is structurally true at the entry level.
    let cfg2 = McpServersConfig::builder()
        .add_server(http_entry("alpha", None))
        .unwrap()
        .build();
    assert!(cfg2.get("alpha").unwrap().tool_allowed("anything"));
}

// ─────────────────────────────────────────────────────────────────────────
// SD-15b — interior `*` pattern rejected at compile time
// ─────────────────────────────────────────────────────────────────────────
#[test]
fn sd_15b_interior_star_rejected() {
    let err = ToolPattern::compile("*tool*").expect_err("interior *");
    assert_eq!(err.kind, McpErrorKind::InvalidResponse);
    assert!(err.message.contains("only a single trailing"));
}

// Bare `*` rejected too (Round 2 W4 + Round 5 Codex W3 alignment).
#[test]
fn sd_15b_bare_star_rejected() {
    let err = ToolPattern::compile("*").expect_err("bare *");
    assert!(err.message.contains("bare '*'"));
}

// ─────────────────────────────────────────────────────────────────────────
// SD-15d — adversarial round 1 W2: tool-pattern matcher rejects tool names
// containing zero-width / control / bidi characters even when the byte-
// prefix would match. Prevents visually-spoofed tool name bypass.
// ─────────────────────────────────────────────────────────────────────────
#[test]
fn sd_15d_zero_width_blocked_in_prefix_match() {
    let p = ToolPattern::compile("search.*").unwrap();
    // Operator allowlist "search.*" — naively matches "search.anything".
    // Attacker inserts ZWSP (U+200B) between "search." and "delete-all":
    let attacker_name = "search.\u{200B}delete-all";
    // Byte-prefix would match, BUT is_tool_name_safe rejects on the zero-width.
    assert!(
        !p.matches(attacker_name),
        "ZWSP-injected name should be blocked"
    );
    // Negative control: legitimate name passes.
    assert!(p.matches("search.web"));
}

#[test]
fn sd_15d_control_char_blocked_in_literal_match() {
    let p = ToolPattern::compile("get").unwrap();
    // Even literal match should reject if the candidate name contains a control char.
    let attacker_name = "get\u{0007}"; // BEL after "get"
    assert!(!p.matches(attacker_name));
    assert!(p.matches("get"));
}

#[test]
fn sd_15d_bidi_override_blocked() {
    let p = ToolPattern::compile("safe-tool").unwrap();
    // U+202E RIGHT-TO-LEFT OVERRIDE
    let attacker_name = "safe-tool\u{202E}evil";
    assert!(!p.matches(attacker_name));
}

// Adversarial round 2 W1: U+200E LRM + U+200F RLM + Hangul fillers + invisible
// operators all blocked too.
#[test]
fn sd_15d_lrm_rlm_blocked() {
    let p = ToolPattern::compile("search.*").unwrap();
    // U+200E LRM after the prefix
    assert!(!p.matches("search.\u{200E}delete"));
    // U+200F RLM after the prefix
    assert!(!p.matches("search.\u{200F}delete"));
}

#[test]
fn sd_15d_invisible_operators_blocked() {
    let p = ToolPattern::compile("ns:*").unwrap();
    assert!(!p.matches("ns:\u{2061}func")); // FUNCTION APPLICATION
    assert!(!p.matches("ns:\u{2062}times")); // INVISIBLE TIMES
    assert!(!p.matches("ns:\u{2063}sep")); // INVISIBLE SEPARATOR
    assert!(!p.matches("ns:\u{2064}plus")); // INVISIBLE PLUS
}

#[test]
fn sd_15d_hangul_filler_blocked() {
    let p = ToolPattern::compile("safe").unwrap();
    // U+3164 HANGUL FILLER is visually empty in many renderings; do not allow.
    assert!(!p.matches("safe\u{3164}"));
}

#[test]
fn sd_15d_unsafe_blocked_even_with_no_patterns() {
    // Even when the server entry has tool_patterns: None (no filter),
    // unsafe names must still be rejected (operator intent).
    let cfg = McpServersConfig::builder()
        .add_server(http_entry("alpha", None))
        .unwrap()
        .build();
    let entry = cfg.get("alpha").unwrap();
    assert!(entry.tool_allowed("normal-tool"));
    assert!(!entry.tool_allowed("evil\u{200B}tool"));
    assert!(!entry.tool_allowed("evil\u{0000}null"));
}

// ─────────────────────────────────────────────────────────────────────────
// SD-15c — verify SPLIT capability registration (5 server + 2 tool)
// ─────────────────────────────────────────────────────────────────────────
#[test]
fn sd_15c_split_capability_registration() {
    let cfg = Arc::new(
        McpServersConfig::builder()
            .add_server(http_entry("alpha", None))
            .unwrap()
            .build(),
    );
    let client = Arc::new(McpClient::new(cfg, Arc::new(NoOpDetector), None));
    let registry = InMemoryHostRegistry::new();
    register_mcp_client(&registry, client);

    let servers_specs = registry.lookup("mcp.servers");
    let tools_specs = registry.lookup("mcp.tool-patterns");

    // 5 server-level handlers under mcp.servers
    assert_eq!(servers_specs.len(), 5, "mcp.servers should have 5 specs");
    let server_names: std::collections::BTreeSet<_> =
        servers_specs.iter().map(|s| s.name.as_str()).collect();
    assert_eq!(
        server_names,
        [
            "list-mcp-servers",
            "list-mcp-prompts",
            "get-mcp-prompt",
            "list-mcp-resources",
            "read-mcp-resource"
        ]
        .iter()
        .copied()
        .collect::<std::collections::BTreeSet<_>>()
    );

    // 2 tool-level handlers under mcp.tool-patterns
    assert_eq!(
        tools_specs.len(),
        2,
        "mcp.tool-patterns should have 2 specs"
    );
    let tool_names: std::collections::BTreeSet<_> =
        tools_specs.iter().map(|s| s.name.as_str()).collect();
    assert_eq!(
        tool_names,
        ["list-mcp-tools", "invoke-mcp-tool"]
            .iter()
            .copied()
            .collect::<std::collections::BTreeSet<_>>()
    );

    // All specs share the canonical namespace.
    for spec in servers_specs.iter().chain(tools_specs.iter()) {
        assert_eq!(spec.namespace, "advance:runtime/mcp-client@0.1.0");
    }

    // Idempotent flag: invoke-mcp-tool is the only non-idempotent.
    for spec in tools_specs.iter() {
        let expected = !matches!(spec.name.as_str(), "invoke-mcp-tool");
        assert_eq!(
            spec.idempotent, expected,
            "name={} expected idempotent={}",
            spec.name, expected
        );
    }
    for spec in servers_specs.iter() {
        assert!(
            spec.idempotent,
            "server-level handler {} should be idempotent",
            spec.name
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Server ids: the builder admits only the pack manifest's grammar
// ─────────────────────────────────────────────────────────────────────────
#[test]
fn builder_admits_only_server_ids_from_the_charset() {
    let longest = "a".repeat(128);
    for id in ["a", "srv-1", "alpha.beta_gamma", "A9", longest.as_str()] {
        assert!(is_valid_server_id(id), "{id:?}");
        McpServersConfig::builder()
            .add_server(http_entry(id, None))
            .unwrap_or_else(|e| panic!("{id:?} refused: {e}"));
    }
    let too_long = "a".repeat(129);
    for id in [
        "",
        "a b",
        "a/b",
        "srv:1",
        "ü",
        "a\u{200B}b",
        "a\nb",
        too_long.as_str(),
    ] {
        assert!(!is_valid_server_id(id), "{id:?}");
        let err = McpServersConfig::builder()
            .add_server(http_entry(id, None))
            .expect_err("invalid server id");
        assert_eq!(err.kind, McpErrorKind::InvalidResponse);
        assert!(
            err.message.contains("[A-Za-z0-9._-]"),
            "msg={}",
            err.message
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Debug never prints a resolved secret
// ─────────────────────────────────────────────────────────────────────────
#[test]
fn debug_output_hides_env_values_args_and_endpoint_queries() {
    let stdio = McpServerEntry {
        server_id: "local".to_string(),
        description: "stdio".to_string(),
        transport: McpTransportSpec::Stdio {
            command: "/usr/local/bin/server".to_string(),
            args: vec!["--token=arg-secret-123".to_string()],
            env: BTreeMap::from([("API_TOKEN".to_string(), "env-secret-456".to_string())]),
        },
        tool_patterns: None,
        tool_schemas: BTreeMap::new(),
    };
    let text = format!("{stdio:?}");
    assert!(text.contains("API_TOKEN"), "{text}");
    assert!(text.contains("/usr/local/bin/server"), "{text}");
    assert!(!text.contains("env-secret-456"), "{text}");
    assert!(!text.contains("arg-secret-123"), "{text}");

    let http = McpTransportSpec::Http {
        endpoint_url: "https://mcp.example.com/mcp?key=query-secret-789#frag".to_string(),
        capability: HttpCapability {
            allowlist: Allowlist {
                patterns: vec!["mcp.example.com".to_string()],
            },
            credentials: vec![],
            component_id: "remote".into(),
        },
    };
    let text = format!("{http:?}");
    assert!(text.contains("https://mcp.example.com/mcp"), "{text}");
    assert!(!text.contains("query-secret-789"), "{text}");
    assert!(!text.contains("frag"), "{text}");

    let config = McpServersConfig::builder()
        .add_server(stdio)
        .unwrap()
        .build();
    assert!(!format!("{config:?}").contains("env-secret-456"));
}

fn _unused_mcp_error_type(_e: &McpError) {
    // satisfy "unused import" potential
}
