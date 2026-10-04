//! `McpServersConfig` — MODULE-017 Slice D AC-23 layers 1 + 2.
//!
//! Configures the set of MCP servers reachable via `McpClient` (layer 1 — server
//! whitelist) and, per-server, an optional `tool_patterns` list that restricts
//! which tool names are callable (layer 2 — tool-name filter). Per-tool optional
//! input + output JSON schemas attach here too; they are consumed by `McpClient`
//! through `SchemaValidator` (AC-13).
//!
//! Layer-3 (per-agent grant) is enforced by the framework `CapabilityInjector`
//! via the SPLIT capability dimensions registered in `host_fn::register_mcp_client`
//! — see that module for details. AC-30 architectural intent: server-level methods
//! gate on `mcp.servers`, tool-level methods (`list-mcp-tools`, `invoke-mcp-tool`)
//! gate on `mcp.tool-patterns`.
//!
//! ## `ToolPattern` grammar
//!
//! The grammar, the matcher and the unsafe-name rule are the shared ones in
//! [`advance_shared_types::mcp`], which the `mcp` grant family uses too, so the
//! server filter and the grant check read a pattern the same way:
//!
//! - `Literal("foo")` — exact string match.
//! - `Prefix("foo.")` — derived from raw pattern `"foo.*"` — matches any tool
//!   name starting with `"foo."`.
//!
//! Patterns containing `*`/`?`/`[`/`]`/`{`/`}` anywhere other than a single
//! trailing `*` are REJECTED at config-build time. A bare `*` is also rejected
//! (it would match everything; operators wanting allow-all should set
//! `tool_patterns: None` on the entry).

use std::collections::BTreeMap;

use advance_shared_types::mcp::{self as shared, ToolPatternError};
use advance_shared_types::security_validator::HttpCapability;

use crate::error::McpError;

/// Max patterns per server entry. Bounds per-`list_tools` filter cost.
pub const MAX_PATTERNS_PER_SERVER: usize = 64;

/// Max distinct servers in a single `McpServersConfig`. Bounds the
/// per-client transport pool size.
pub const MAX_SERVERS: usize = 128;

/// Tool name pattern — literal or single-trailing-`*` prefix.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ToolPattern {
    /// Exact-string match (no wildcard).
    Literal(String),
    /// Match anything starting with the given prefix (raw form `"prefix*"`).
    /// The stored value is the prefix without the trailing `*`.
    Prefix(String),
}

impl ToolPattern {
    /// Compile a raw pattern string. See module-level rustdoc for grammar.
    pub fn compile(raw: &str) -> Result<Self, McpError> {
        match shared::ToolPattern::parse(raw) {
            Ok(shared::ToolPattern::Literal(literal)) => {
                Ok(ToolPattern::Literal(literal.to_string()))
            }
            Ok(shared::ToolPattern::Prefix(prefix)) => Ok(ToolPattern::Prefix(prefix.to_string())),
            // The length bound keeps memory and match cost small.
            Err(ToolPatternError::Length) => Err(McpError::invalid_response(format!(
                "tool-pattern: length out of range (1..={} bytes)",
                shared::MAX_TOOL_PATTERN_BYTES
            ))),
            // Bare "*" → empty prefix would match every tool name. Operators wanting
            // "allow all" use `tool_patterns: None` at the McpServerEntry level instead.
            Err(ToolPatternError::BareStar) => Err(McpError::invalid_response(
                "tool-pattern: bare '*' rejected — use `tool_patterns: None` for allow-all",
            )),
            Err(ToolPatternError::Glob) => Err(McpError::invalid_response(
                "tool-pattern: only a single trailing '*' is supported",
            )),
        }
    }

    /// True iff `name` matches this pattern.
    ///
    /// A name that fails [`shared::is_tool_name_safe`] (control, zero-width,
    /// invisible, bidi, variation-selector or tag characters) matches nothing.
    /// Without this, an attacker-controlled MCP server could publish a tool name
    /// like `"search.\u{200B}delete_all"` (zero-width space invisible to the
    /// operator + agent UI) that passes a `"search.*"` prefix pattern but is
    /// semantically a different tool. Confusables (Cyrillic `е` vs Latin `e`)
    /// cannot pass byte-string equality, so the Literal arm is already safe — the
    /// prefix arm + visually-invisible characters were the concrete bypass.
    pub fn matches(&self, name: &str) -> bool {
        let pattern = match self {
            ToolPattern::Literal(literal) => shared::ToolPattern::Literal(literal),
            ToolPattern::Prefix(prefix) => shared::ToolPattern::Prefix(prefix),
        };
        pattern.matches(name)
    }
}

/// Optional per-tool input + output JSON schemas. Consumed by `McpClient`'s
/// `invoke_tool` via `SchemaValidator`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ToolSchemas {
    pub input: Option<serde_json::Value>,
    pub output: Option<serde_json::Value>,
}

/// Per-server transport specification.
///
/// `Debug` never prints what may hold a secret: a stdio `env` shows its keys
/// only (its values are resolved secrets), `args` show only their count, and an
/// http endpoint shows no query or fragment.
#[derive(Clone)]
pub enum McpTransportSpec {
    /// HTTP/SSE transport — reuses MODULE-012 HttpSecurityChain.
    Http {
        endpoint_url: String,
        capability: HttpCapability,
    },
    /// stdio subprocess transport.
    Stdio {
        command: String,
        args: Vec<String>,
        env: BTreeMap<String, String>,
    },
}

impl std::fmt::Debug for McpTransportSpec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            McpTransportSpec::Http {
                endpoint_url,
                capability,
            } => f
                .debug_struct("Http")
                .field("endpoint_url", &RedactedUrl(endpoint_url))
                .field("capability", capability)
                .finish(),
            McpTransportSpec::Stdio { command, args, env } => f
                .debug_struct("Stdio")
                .field("command", command)
                .field("args", &format_args!("<{} redacted>", args.len()))
                .field("env", &RedactedEnv(env))
                .finish(),
        }
    }
}

/// An endpoint URL without its query and fragment, which may carry tokens.
struct RedactedUrl<'a>(&'a str);

impl std::fmt::Debug for RedactedUrl<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Keep the separator (`?` or `#`, one byte) so the shape stays visible.
        match self.0.find(['?', '#']) {
            Some(end) => write!(f, "{:?}", format!("{}<redacted>", &self.0[..=end])),
            None => write!(f, "{:?}", self.0),
        }
    }
}

/// An environment map with every value hidden.
struct RedactedEnv<'a>(&'a BTreeMap<String, String>);

impl std::fmt::Debug for RedactedEnv<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_map()
            .entries(self.0.keys().map(|key| (key, Hidden)))
            .finish()
    }
}

/// Debug-prints as `<redacted>`.
struct Hidden;

impl std::fmt::Debug for Hidden {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("<redacted>")
    }
}

/// Single server entry in the whitelist.
#[derive(Debug)]
pub struct McpServerEntry {
    pub server_id: String,
    pub description: String,
    pub transport: McpTransportSpec,
    /// None → no per-tool filter; Some(patterns) → only tools matching at least
    /// one pattern are visible via `list_tools` and callable via `invoke_tool`.
    pub tool_patterns: Option<Vec<ToolPattern>>,
    pub tool_schemas: BTreeMap<String, ToolSchemas>,
}

impl McpServerEntry {
    /// True iff the given tool name passes the tool-pattern filter (or no
    /// filter is configured) AND contains no forbidden Unicode characters.
    ///
    /// Adversarial round 1 W2: even with `tool_patterns: None`, names
    /// containing control / zero-width / bidi-override characters are
    /// rejected. The operator's intent of "no per-name filter" doesn't
    /// extend to "allow visually-spoofed names" — that's an attacker-side
    /// bypass of any whitelist rationale.
    pub fn tool_allowed(&self, tool_name: &str) -> bool {
        if !shared::is_tool_name_safe(tool_name) {
            return false;
        }
        match &self.tool_patterns {
            None => true,
            Some(patterns) => patterns.iter().any(|p| p.matches(tool_name)),
        }
    }
}

/// Whitelist of MCP servers exposed by an `McpClient`.
#[derive(Debug)]
pub struct McpServersConfig {
    servers: BTreeMap<String, McpServerEntry>,
}

impl McpServersConfig {
    pub fn builder() -> McpServersConfigBuilder {
        McpServersConfigBuilder {
            servers: BTreeMap::new(),
        }
    }

    /// Lookup a server by id. Returns `McpError::not_found(...)` for unknown
    /// ids (AC-23 layer 1).
    pub fn get(&self, server_id: &str) -> Result<&McpServerEntry, McpError> {
        self.servers.get(server_id).ok_or_else(|| {
            McpError::not_found(format!("server '{server_id}' not in mcp.servers whitelist"))
        })
    }

    /// Iterate over the registered servers in stable (sorted-by-id) order.
    pub fn list_servers(&self) -> impl Iterator<Item = &McpServerEntry> + '_ {
        self.servers.values()
    }

    /// Number of registered servers.
    pub fn len(&self) -> usize {
        self.servers.len()
    }

    pub fn is_empty(&self) -> bool {
        self.servers.is_empty()
    }
}

#[derive(Debug)]
pub struct McpServersConfigBuilder {
    servers: BTreeMap<String, McpServerEntry>,
}

impl McpServersConfigBuilder {
    /// Add a server entry. Returns an error if the id is not a valid server id
    /// (the shared grammar, [`shared::is_valid_server_id`], which a pack's
    /// `mcp-servers/*.yaml` follows too), collides with an existing entry, or if
    /// the total would exceed `MAX_SERVERS`.
    pub fn add_server(mut self, entry: McpServerEntry) -> Result<Self, McpError> {
        if !shared::is_valid_server_id(&entry.server_id) {
            return Err(McpError::invalid_response(format!(
                "server_id {:?} must be 1..={} characters from [A-Za-z0-9._-]",
                entry.server_id,
                shared::MAX_SERVER_ID_BYTES
            )));
        }
        if self.servers.contains_key(&entry.server_id) {
            return Err(McpError::invalid_response(format!(
                "duplicate server_id '{}'",
                entry.server_id
            )));
        }
        if self.servers.len() >= MAX_SERVERS {
            return Err(McpError::invalid_response(format!(
                "too many servers (cap: {MAX_SERVERS})"
            )));
        }
        if let Some(patterns) = &entry.tool_patterns {
            if patterns.len() > MAX_PATTERNS_PER_SERVER {
                return Err(McpError::invalid_response(format!(
                    "server '{}' has > {} tool_patterns",
                    entry.server_id, MAX_PATTERNS_PER_SERVER
                )));
            }
        }
        self.servers.insert(entry.server_id.clone(), entry);
        Ok(self)
    }

    pub fn build(self) -> McpServersConfig {
        McpServersConfig {
            servers: self.servers,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pattern_literal_matches_exact() {
        let p = ToolPattern::compile("search").expect("compile");
        assert!(p.matches("search"));
        assert!(!p.matches("search.web"));
        assert!(!p.matches("searchx"));
    }

    #[test]
    fn pattern_prefix_matches_with_dot() {
        let p = ToolPattern::compile("search.*").expect("compile");
        assert!(p.matches("search."));
        assert!(p.matches("search.web"));
        assert!(p.matches("search.code"));
        assert!(!p.matches("search"));
        assert!(!p.matches("delete-all"));
    }

    #[test]
    fn pattern_bare_star_rejected() {
        let err = ToolPattern::compile("*").expect_err("bare *");
        assert!(err.message.contains("bare '*'"));
    }

    #[test]
    fn pattern_interior_star_rejected() {
        let err = ToolPattern::compile("*tool*").expect_err("interior *");
        assert!(err.message.contains("only a single trailing '*'"));
    }

    #[test]
    fn pattern_question_mark_rejected() {
        let err = ToolPattern::compile("tool?").expect_err("?");
        assert!(err.message.contains("only a single trailing '*'"));
    }

    #[test]
    fn pattern_empty_rejected() {
        let err = ToolPattern::compile("").expect_err("empty");
        assert!(err.message.contains("length out of range"));
    }

    #[test]
    fn pattern_oversize_rejected() {
        let raw = "a".repeat(shared::MAX_TOOL_PATTERN_BYTES + 1);
        let err = ToolPattern::compile(&raw).expect_err("oversize");
        assert!(err.message.contains("length out of range"));
    }

    // The server filter and the `mcp` grant family read patterns and names alike.
    #[test]
    fn pattern_grammar_and_matcher_are_the_shared_ones() {
        for raw in [
            "search", "search.*", "ns:*", "*", "", "*tool*", "tool?", "a*b", "x[1]",
        ] {
            assert_eq!(
                ToolPattern::compile(raw).is_ok(),
                shared::ToolPattern::parse(raw).is_ok(),
                "{raw:?}"
            );
        }
        let p = ToolPattern::compile("search.*").expect("compile");
        let entry = dummy_http_entry("alpha", None);
        // A variation selector or a tag character is as invisible as a zero-width space.
        for name in ["search.web\u{FE0F}", "search.\u{E0041}web"] {
            assert!(!p.matches(name), "{name:?}");
            assert!(!entry.tool_allowed(name), "{name:?}");
        }
        assert!(p.matches("search.web"));
    }

    fn dummy_http_entry(server_id: &str, patterns: Option<Vec<&str>>) -> McpServerEntry {
        let tool_patterns = patterns.map(|raws| {
            raws.into_iter()
                .map(|r| ToolPattern::compile(r).expect("test pattern"))
                .collect::<Vec<_>>()
        });
        McpServerEntry {
            server_id: server_id.to_string(),
            description: "test".to_string(),
            transport: McpTransportSpec::Http {
                endpoint_url: "https://example.com".to_string(),
                capability: HttpCapability {
                    allowlist: advance_shared_types::security_validator::Allowlist {
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

    #[test]
    fn config_get_whitelist_hit() {
        let cfg = McpServersConfig::builder()
            .add_server(dummy_http_entry("alpha", None))
            .unwrap()
            .build();
        assert!(cfg.get("alpha").is_ok());
    }

    #[test]
    fn config_get_whitelist_miss() {
        let cfg = McpServersConfig::builder()
            .add_server(dummy_http_entry("alpha", None))
            .unwrap()
            .build();
        let err = cfg.get("gamma").expect_err("miss");
        assert!(err.message.contains("not in mcp.servers whitelist"));
    }

    #[test]
    fn config_list_two_servers() {
        let cfg = McpServersConfig::builder()
            .add_server(dummy_http_entry("alpha", None))
            .unwrap()
            .add_server(dummy_http_entry("beta", None))
            .unwrap()
            .build();
        let ids: Vec<_> = cfg.list_servers().map(|e| e.server_id.as_str()).collect();
        assert_eq!(ids, vec!["alpha", "beta"]);
    }

    #[test]
    fn entry_tool_allowed_with_patterns() {
        let e = dummy_http_entry("alpha", Some(vec!["search.*"]));
        assert!(e.tool_allowed("search.web"));
        assert!(e.tool_allowed("search.code"));
        assert!(!e.tool_allowed("delete-all"));
    }

    #[test]
    fn entry_tool_allowed_no_patterns() {
        let e = dummy_http_entry("alpha", None);
        assert!(e.tool_allowed("anything"));
    }

    #[test]
    fn builder_rejects_duplicate_server_id() {
        let err = McpServersConfig::builder()
            .add_server(dummy_http_entry("alpha", None))
            .unwrap()
            .add_server(dummy_http_entry("alpha", None))
            .expect_err("duplicate");
        assert!(err.message.contains("duplicate server_id"));
    }
}
