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
//! ## In-house `ToolPattern` matcher
//!
//! cap-mcp deliberately ships an in-house matcher rather than pulling `globset`
//! or `glob` into the workspace — neither dep is currently pinned, and adding
//! one would be a cross-cutting supply-chain expansion outside this slice's
//! scope. Supported grammar:
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

use advance_shared_types::security_validator::HttpCapability;

use crate::error::McpError;

/// Max bytes for a single tool-pattern string. Bounds memory + compile cost.
pub const MAX_PATTERN_BYTES: usize = 256;

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
        if raw.is_empty() || raw.len() > MAX_PATTERN_BYTES {
            return Err(McpError::invalid_response(
                "tool-pattern: length out of range (1..=MAX_PATTERN_BYTES)",
            ));
        }
        if let Some(stripped) = raw.strip_suffix('*') {
            // Bare "*" → empty prefix would match every tool name. Reject;
            // operators wanting "allow all" should use `tool_patterns: None`
            // at the McpServerEntry level instead.
            if stripped.is_empty() {
                return Err(McpError::invalid_response(
                    "tool-pattern: bare '*' rejected — use `tool_patterns: None` for allow-all",
                ));
            }
            if stripped.contains(['*', '?', '[', ']', '{', '}']) {
                return Err(McpError::invalid_response(
                    "tool-pattern: only a single trailing '*' is supported",
                ));
            }
            return Ok(ToolPattern::Prefix(stripped.to_string()));
        }
        if raw.contains(['*', '?', '[', ']', '{', '}']) {
            return Err(McpError::invalid_response(
                "tool-pattern: only a single trailing '*' is supported",
            ));
        }
        Ok(ToolPattern::Literal(raw.to_string()))
    }

    /// True iff `name` matches this pattern.
    ///
    /// Adversarial round 1 W2 fix: tool names containing control characters
    /// (U+0000-U+001F, U+007F-U+009F), zero-width / invisible characters
    /// (ZWSP U+200B, ZWNJ U+200C, ZWJ U+200D, BOM U+FEFF, WJ U+2060,
    /// HYPHEN U+00AD), or bidi-override characters (U+202A-U+202E,
    /// U+2066-U+2069) are REJECTED at the matcher boundary. Without this,
    /// an attacker-controlled MCP server could publish a tool name like
    /// `"search.\u{200B}delete_all"` (zero-width space invisible to the
    /// operator + agent UI) that passes a `"search.*"` prefix pattern but
    /// is semantically a different tool. Confusables (Cyrillic `е` vs
    /// Latin `e`) cannot pass byte-string equality, so the Literal arm is
    /// already safe — the prefix arm + visually-invisible characters were
    /// the concrete bypass.
    pub fn matches(&self, name: &str) -> bool {
        if !is_tool_name_safe(name) {
            return false;
        }
        match self {
            ToolPattern::Literal(s) => name == s,
            ToolPattern::Prefix(p) => name.starts_with(p),
        }
    }
}

/// Reject control characters, zero-width / invisible characters, and bidi
/// controls. Returns false (= unsafe / reject) for any character in the
/// forbidden set.
///
/// Adversarial round 2 W1: rejection set expanded to align with cap-skills
/// SecurityScan precedent (U+200E LRM + U+200F RLM bidi marks were missing
/// in round 1; also adding invisible operators, Hangul fillers, and
/// combining grapheme joiner). Set is conservative — any character that
/// renders invisible OR can visually spoof a different code point is
/// rejected.
pub(crate) fn is_tool_name_safe(name: &str) -> bool {
    for c in name.chars() {
        let cp = c as u32;
        // ASCII control chars + DEL + C1 control range
        if cp < 0x20 || (0x7F..=0x9F).contains(&cp) {
            return false;
        }
        // Zero-width / invisible / soft-hyphen / WJ / BOM + bidi marks
        if matches!(
            cp,
            0x00AD       // SOFT HYPHEN
            | 0x034F     // COMBINING GRAPHEME JOINER
            | 0x115F     // HANGUL CHOSEONG FILLER
            | 0x1160     // HANGUL JUNGSEONG FILLER
            | 0x180E     // MONGOLIAN VOWEL SEPARATOR
            | 0x200B     // ZERO WIDTH SPACE
            | 0x200C     // ZERO WIDTH NON-JOINER
            | 0x200D     // ZERO WIDTH JOINER
            | 0x200E     // LEFT-TO-RIGHT MARK
            | 0x200F     // RIGHT-TO-LEFT MARK
            | 0x2060     // WORD JOINER
            | 0x2061     // FUNCTION APPLICATION
            | 0x2062     // INVISIBLE TIMES
            | 0x2063     // INVISIBLE SEPARATOR
            | 0x2064     // INVISIBLE PLUS
            | 0x3164     // HANGUL FILLER
            | 0xFEFF // ZERO WIDTH NO-BREAK SPACE (BOM)
        ) {
            return false;
        }
        // Bidi embedding/overrides + isolates
        if (0x202A..=0x202E).contains(&cp) || (0x2066..=0x2069).contains(&cp) {
            return false;
        }
    }
    true
}

/// Optional per-tool input + output JSON schemas. Consumed by `McpClient`'s
/// `invoke_tool` via `SchemaValidator`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ToolSchemas {
    pub input: Option<serde_json::Value>,
    pub output: Option<serde_json::Value>,
}

/// Per-server transport specification.
#[derive(Clone, Debug)]
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
        if !is_tool_name_safe(tool_name) {
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
    /// Add a server entry. Returns an error if the id collides with an existing
    /// entry, or if the total would exceed `MAX_SERVERS`.
    pub fn add_server(mut self, entry: McpServerEntry) -> Result<Self, McpError> {
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
        let raw = "a".repeat(MAX_PATTERN_BYTES + 1);
        let err = ToolPattern::compile(&raw).expect_err("oversize");
        assert!(err.message.contains("length out of range"));
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
