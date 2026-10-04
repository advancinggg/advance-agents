//! The `mcp` grant family's shared shape: trailing-`*` tool patterns, the scope one grant
//! reaches, and the server-id grammar.
//!
//! One grammar and one matcher serve every place that filters MCP tools by name: the `mcp`
//! grant rules in cap-grant (issuance, the call-time check and the listing reader) and the
//! per-server tool filter in cap-mcp. A listing and a call therefore never disagree about a
//! name.
//!
//! # Server ids
//!
//! A server id is 1..=[`MAX_SERVER_ID_BYTES`] characters from `[A-Za-z0-9._-]` (see
//! [`is_valid_server_id`]). A pack's `mcp-servers/*.yaml` and cap-mcp's server whitelist accept
//! exactly these ids.
//!
//! # Tool patterns
//!
//! A pattern is 1..=[`MAX_TOOL_PATTERN_BYTES`] bytes and is either
//! - a literal (`get_issue`), matching exactly that name, or
//! - a non-empty prefix followed by one trailing `*` (`get_*`), matching every name that starts
//!   with the prefix.
//!
//! No other glob character (`*`, `?`, `[`, `]`, `{`, `}`) may appear, and a bare `*` is
//! malformed: an unrestricted tool axis is written by leaving the patterns out.
//!
//! A tool name is always a literal, never a pattern. A name holding a control, zero-width,
//! invisible or bidi character (see [`is_tool_name_safe`]) matches no pattern, so a server
//! cannot publish a name that reads as one tool and matches as another.
//!
//! # Grant scope
//!
//! [`McpGrantScope`] is what one `mcp` grant reaches: a set of servers (literal ids) and, on
//! those servers, either every tool or the tools its patterns match. Coverage is decided one
//! grant at a time; two grants are never merged axis by axis, so `{servers: [a], tool-patterns:
//! [x*]}` held next to `{servers: [b]}` never covers tool `y` on server `a`.
//!
//! A scope never covers a server id or tool name that a call cannot carry (see
//! [`is_request_token`] and [`is_tool_name_safe`]), so a listing filtered through scopes holds
//! no entry whose call the grant check refuses for its name.

/// Longest tool pattern, in bytes.
pub const MAX_TOOL_PATTERN_BYTES: usize = 256;

/// Longest server id, in bytes.
pub const MAX_SERVER_ID_BYTES: usize = 128;

/// Longest server id or tool name a call can carry, in bytes: the grant check refuses a request
/// string longer than this.
pub const MAX_REQUEST_TOKEN_BYTES: usize = 4096;

/// The `tool-patterns` request token for a server-wide surface (a server's prompts and
/// resources), which no tool pattern describes. Read as a literal name it matches no pattern,
/// so only a grant that leaves the tool axis unrestricted covers it: see
/// [`McpGrantScope::covers_server_wide`].
pub const SERVER_WIDE_TOOL: &str = "*";

/// The glob characters. Outside one trailing `*` they make a pattern malformed.
const GLOB_CHARS: [char; 6] = ['*', '?', '[', ']', '{', '}'];

/// Why a tool pattern is malformed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ToolPatternError {
    /// Empty, or longer than [`MAX_TOOL_PATTERN_BYTES`].
    Length,
    /// A bare `*`. An unrestricted tool axis is written by leaving the patterns out.
    BareStar,
    /// A glob character other than one trailing `*`.
    Glob,
}

impl std::fmt::Display for ToolPatternError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Length => write!(
                f,
                "length out of range (1..={MAX_TOOL_PATTERN_BYTES} bytes)"
            ),
            Self::BareStar => f.write_str(
                "a bare `*` is not a pattern; leave the patterns out to reach every tool",
            ),
            Self::Glob => f.write_str("only a single trailing `*` is supported"),
        }
    }
}

impl std::error::Error for ToolPatternError {}

/// A tool pattern, borrowing its text. Build one from text with [`ToolPattern::parse`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ToolPattern<'a> {
    /// Matches exactly this name.
    Literal(&'a str),
    /// Matches every name that starts with this prefix (the pattern without its trailing `*`).
    /// An empty prefix, which `parse` never produces, matches nothing.
    Prefix(&'a str),
}

impl<'a> ToolPattern<'a> {
    /// Parses `raw` per the grammar in the module docs.
    pub fn parse(raw: &'a str) -> Result<Self, ToolPatternError> {
        if raw.is_empty() || raw.len() > MAX_TOOL_PATTERN_BYTES {
            return Err(ToolPatternError::Length);
        }
        match raw.strip_suffix('*') {
            Some("") => Err(ToolPatternError::BareStar),
            Some(prefix) if prefix.contains(GLOB_CHARS) => Err(ToolPatternError::Glob),
            Some(prefix) => Ok(Self::Prefix(prefix)),
            None if raw.contains(GLOB_CHARS) => Err(ToolPatternError::Glob),
            None => Ok(Self::Literal(raw)),
        }
    }

    /// Whether this pattern matches the tool `name`. A name that fails [`is_tool_name_safe`]
    /// matches nothing.
    pub fn matches(&self, name: &str) -> bool {
        is_tool_name_safe(name)
            && match self {
                Self::Literal(literal) => name == *literal,
                Self::Prefix(prefix) => !prefix.is_empty() && name.starts_with(prefix),
            }
    }

    /// Whether every name `child` matches is also matched by this pattern: a literal covers only
    /// itself, and a prefix covers every literal and prefix that extends it.
    pub fn covers(&self, child: &ToolPattern<'_>) -> bool {
        match (self, child) {
            (Self::Literal(parent), ToolPattern::Literal(child)) => parent == child,
            (Self::Literal(_), ToolPattern::Prefix(_)) => false,
            (Self::Prefix(parent), ToolPattern::Literal(child) | ToolPattern::Prefix(child)) => {
                !parent.is_empty() && child.starts_with(parent)
            }
        }
    }
}

/// The pattern's text: a literal as itself, a prefix followed by its `*`.
impl std::fmt::Display for ToolPattern<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Literal(literal) => f.write_str(literal),
            Self::Prefix(prefix) => write!(f, "{prefix}*"),
        }
    }
}

/// Whether `name` is free of characters that render invisibly or pass for another code point:
/// ASCII and C1 controls, the soft hyphen, zero-width and invisible characters (joiners, fillers,
/// invisible operators, the byte-order mark), bidi marks, embeddings, overrides and isolates,
/// variation selectors and tag characters.
pub fn is_tool_name_safe(name: &str) -> bool {
    !name.chars().any(is_spoofing_char)
}

fn is_spoofing_char(c: char) -> bool {
    matches!(
        c as u32,
        0x00..=0x1F         // ASCII controls
        | 0x7F..=0x9F       // DEL and the C1 controls
        | 0x00AD            // SOFT HYPHEN
        | 0x034F            // COMBINING GRAPHEME JOINER
        | 0x115F | 0x1160   // HANGUL CHOSEONG / JUNGSEONG FILLER
        | 0x180E            // MONGOLIAN VOWEL SEPARATOR
        | 0x200B..=0x200F   // ZWSP, ZWNJ, ZWJ, LRM, RLM
        | 0x202A..=0x202E   // LRE, RLE, PDF, LRO, RLO
        | 0x2060..=0x2064   // WORD JOINER, invisible operators
        | 0x2066..=0x2069   // LRI, RLI, FSI, PDI
        | 0x3164            // HANGUL FILLER
        | 0xFE00..=0xFE0F   // VARIATION SELECTOR-1..16
        | 0xFEFF            // ZERO WIDTH NO-BREAK SPACE (BOM)
        | 0xE0000..=0xE007F // tag characters
    )
}

/// Whether `name` can travel as one call-time request token. The grant check reads a request's
/// params as comma-separated tokens and refuses a token that is empty, holds a `,`, has leading
/// or trailing whitespace or is longer than [`MAX_REQUEST_TOKEN_BYTES`]. A name that passes
/// this and [`is_tool_name_safe`] (which rejects the control and invisible characters the check
/// also refuses) can be named in a call.
pub fn is_request_token(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_REQUEST_TOKEN_BYTES
        && !name.contains(',')
        && name.trim() == name
}

/// Whether `server_id` is 1..=[`MAX_SERVER_ID_BYTES`] characters from `[A-Za-z0-9._-]`. Such an
/// id holds no whitespace, comma, path separator, control or non-ASCII character, so it reads the
/// same in a log line and a call can carry it.
pub fn is_valid_server_id(server_id: &str) -> bool {
    !server_id.is_empty()
        && server_id.len() <= MAX_SERVER_ID_BYTES
        && server_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// A server id or tool name a call can carry: one request token, free of spoofing characters.
fn is_callable_name(name: &str) -> bool {
    is_request_token(name) && is_tool_name_safe(name)
}

/// What one `mcp` grant reaches.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct McpGrantScope {
    /// `None`: every server (a grant without params). `Some(ids)`: exactly these server ids,
    /// compared literally; an empty list reaches no server.
    pub servers: Option<Vec<String>>,
    /// `None`: every tool on the reached servers. `Some(patterns)`: the tools one of these
    /// [`ToolPattern`]s matches. A malformed pattern makes the grant cover no tool.
    pub tool_patterns: Option<Vec<String>>,
}

impl McpGrantScope {
    /// Every server and every tool: the scope of a grant without params.
    pub fn unrestricted() -> Self {
        Self {
            servers: None,
            tool_patterns: None,
        }
    }

    /// Whether the grant reaches `server`. This answers a server-level request, one that names
    /// no tool. A server id no call can carry (see [`is_request_token`] and
    /// [`is_tool_name_safe`]) is never reached.
    pub fn covers_server(&self, server: &str) -> bool {
        is_callable_name(server)
            && self
                .servers
                .as_ref()
                .map_or(true, |ids| ids.iter().any(|id| id == server))
    }

    /// Whether the grant reaches the tool named `tool` on `server`. `tool` is a literal name,
    /// never a pattern. A name no call can carry (see [`is_request_token`] and
    /// [`is_tool_name_safe`]) is never covered, so a listing never shows a tool whose call the
    /// grant check refuses for its name.
    pub fn covers_tool(&self, server: &str, tool: &str) -> bool {
        if !self.covers_server(server) || !is_callable_name(tool) {
            return false;
        }
        let Some(patterns) = &self.tool_patterns else {
            return true;
        };
        let mut matched = false;
        for raw in patterns {
            match ToolPattern::parse(raw) {
                Ok(pattern) => matched |= pattern.matches(tool),
                Err(_) => return false,
            }
        }
        matched
    }

    /// Whether the grant reaches `server` as a whole: its prompts and resources, which no tool
    /// pattern describes. That needs the server and an unrestricted tool axis. Equal to
    /// `covers_tool(server, SERVER_WIDE_TOOL)`.
    pub fn covers_server_wide(&self, server: &str) -> bool {
        self.covers_server(server) && self.tool_patterns.is_none()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scope(servers: Option<&[&str]>, patterns: Option<&[&str]>) -> McpGrantScope {
        let owned = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        McpGrantScope {
            servers: servers.map(owned),
            tool_patterns: patterns.map(owned),
        }
    }

    #[test]
    fn parse_accepts_literals_and_one_trailing_star() {
        assert_eq!(
            ToolPattern::parse("get_issue"),
            Ok(ToolPattern::Literal("get_issue"))
        );
        assert_eq!(ToolPattern::parse("get_*"), Ok(ToolPattern::Prefix("get_")));
        assert_eq!(ToolPattern::parse("ns:*"), Ok(ToolPattern::Prefix("ns:")));
        let longest = "a".repeat(MAX_TOOL_PATTERN_BYTES);
        assert!(ToolPattern::parse(&longest).is_ok());
        for raw in ["get_issue", "get_*"] {
            assert_eq!(ToolPattern::parse(raw).unwrap().to_string(), raw);
        }
    }

    #[test]
    fn parse_rejects_malformed_patterns() {
        assert_eq!(ToolPattern::parse(""), Err(ToolPatternError::Length));
        let too_long = "a".repeat(MAX_TOOL_PATTERN_BYTES + 1);
        assert_eq!(ToolPattern::parse(&too_long), Err(ToolPatternError::Length));
        assert_eq!(ToolPattern::parse("*"), Err(ToolPatternError::BareStar));
        for raw in [
            "*get",
            "get_*_x",
            "a**",
            "*a*",
            "get?",
            "get_[ab]",
            "get_{a,b}",
            "a*b",
        ] {
            assert_eq!(
                ToolPattern::parse(raw),
                Err(ToolPatternError::Glob),
                "{raw:?}"
            );
        }
    }

    #[test]
    fn matches_literal_exactly_and_prefix_by_start() {
        let literal = ToolPattern::parse("get_issue").unwrap();
        assert!(literal.matches("get_issue"));
        assert!(!literal.matches("get_issues"));
        let prefix = ToolPattern::parse("get_*").unwrap();
        assert!(prefix.matches("get_"));
        assert!(prefix.matches("get_issue"));
        assert!(!prefix.matches("get"));
        assert!(!prefix.matches("delete_repo"));
        // A hand-built empty prefix matches nothing rather than everything.
        assert!(!ToolPattern::Prefix("").matches("anything"));
    }

    #[test]
    fn unsafe_names_match_nothing() {
        let prefix = ToolPattern::parse("search.*").unwrap();
        for name in [
            "search.\u{200B}delete",
            "search.\u{0007}",
            "search.\u{0085}x",
            "search.\u{202E}x",
            "search.\u{3164}",
            "search.x\u{FE0F}",
            "search.x\u{E0041}",
        ] {
            assert!(!is_tool_name_safe(name), "{name:?}");
            assert!(!prefix.matches(name), "{name:?}");
        }
        assert!(is_tool_name_safe("search.web"));
        assert!(is_tool_name_safe(SERVER_WIDE_TOOL));
    }

    #[test]
    fn covers_is_pattern_subsumption() {
        let p = |raw| ToolPattern::parse(raw).unwrap();
        assert!(p("get_*").covers(&p("get_issue")));
        assert!(p("get_*").covers(&p("get_is*")));
        assert!(p("get_*").covers(&p("get_*")));
        assert!(p("get_issue").covers(&p("get_issue")));
        assert!(!p("get_issue").covers(&p("get_*")));
        assert!(!p("get_issue").covers(&p("get_issues")));
        assert!(!p("get_*").covers(&p("g*")));
        assert!(!p("get_*").covers(&p("delete_repo")));
        assert!(!ToolPattern::Prefix("").covers(&p("x")));
    }

    #[test]
    fn scope_servers_absent_means_every_server_and_empty_means_none() {
        assert!(McpGrantScope::unrestricted().covers_server("any"));
        assert!(McpGrantScope::unrestricted().covers_tool("any", "anything"));
        assert!(McpGrantScope::unrestricted().covers_server_wide("any"));
        let none = scope(Some(&[]), None);
        assert!(!none.covers_server("github"));
        assert!(!none.covers_tool("github", "get_issue"));
        assert!(!none.covers_server_wide("github"));
    }

    #[test]
    fn scope_restricted_tool_axis_covers_matching_tools_only() {
        let s = scope(Some(&["github"]), Some(&["get_*", "search_code"]));
        assert!(s.covers_server("github"));
        assert!(!s.covers_server("slack"));
        assert!(s.covers_tool("github", "get_issue"));
        assert!(s.covers_tool("github", "search_code"));
        assert!(!s.covers_tool("github", "delete_repo"));
        assert!(!s.covers_tool("slack", "get_issue"));
        // The tool name is a literal: `get_*` as a name is covered only because it starts
        // with `get_`, and a name never widens to a pattern.
        assert!(s.covers_tool("github", "get_*"));
        assert!(!s.covers_tool("github", "search_*"));
        assert!(!s.covers_tool("github", "get_\u{200B}x"));
    }

    #[test]
    fn request_tokens_are_the_names_a_call_can_carry() {
        assert!(is_request_token("get_issue"));
        assert!(is_request_token(SERVER_WIDE_TOOL));
        assert!(is_request_token(&"a".repeat(MAX_REQUEST_TOKEN_BYTES)));
        assert!(!is_request_token(&"a".repeat(MAX_REQUEST_TOKEN_BYTES + 1)));
        // Trimming is Unicode-aware: a no-break or ideographic space counts as whitespace.
        for name in [
            "",
            ",",
            "get_a,get_b",
            " get",
            "get ",
            "get\u{00A0}",
            "\u{3000}get",
        ] {
            assert!(!is_request_token(name), "{name:?}");
        }
    }

    // A listing must not show a name the call-time check refuses: the call reads its tokens as
    // comma-separated values, so a name that would split, trim or vanish is never covered, even
    // by an unrestricted scope.
    #[test]
    fn scope_never_covers_a_name_no_call_can_carry() {
        let open = McpGrantScope::unrestricted();
        let restricted = scope(Some(&["github"]), Some(&["get_*"]));
        let longest = format!("get_{}", "x".repeat(MAX_REQUEST_TOKEN_BYTES - 4));
        assert!(open.covers_tool("github", &longest));
        assert!(restricted.covers_tool("github", &longest));
        let too_long = format!("{longest}x");
        for tool in [
            "",
            "get_a,get_b",
            "get_x ",
            " get_x",
            "get_x\u{00A0}",
            too_long.as_str(),
        ] {
            assert!(!open.covers_tool("github", tool), "{tool:?}");
            assert!(!restricted.covers_tool("github", tool), "{tool:?}");
        }
        for server in ["", "git,hub", " github", "github ", "git\u{200B}hub"] {
            assert!(!open.covers_server(server), "{server:?}");
            assert!(!open.covers_server_wide(server), "{server:?}");
            assert!(!open.covers_tool(server, "get_x"), "{server:?}");
        }
        assert!(!restricted.covers_server("github "));
    }

    #[test]
    fn server_ids_are_short_names_from_the_charset_that_a_call_can_carry() {
        let longest = "a".repeat(MAX_SERVER_ID_BYTES);
        for id in ["a", "srv-1", "alpha.beta_gamma", "A9", longest.as_str()] {
            assert!(is_valid_server_id(id), "{id:?}");
            assert!(McpGrantScope::unrestricted().covers_server(id), "{id:?}");
        }
        let too_long = "a".repeat(MAX_SERVER_ID_BYTES + 1);
        for id in [
            "",
            "a b",
            "a/b",
            "a,b",
            "srv:1",
            "ü",
            "a\u{200B}b",
            "a\nb",
            too_long.as_str(),
        ] {
            assert!(!is_valid_server_id(id), "{id:?}");
        }
    }

    #[test]
    fn scope_malformed_pattern_covers_no_tool_but_keeps_the_server() {
        let s = scope(Some(&["github"]), Some(&["get_*", "*"]));
        assert!(s.covers_server("github"));
        assert!(!s.covers_tool("github", "get_issue"));
        assert!(!s.covers_server_wide("github"));
    }

    #[test]
    fn server_wide_needs_an_unrestricted_tool_axis() {
        let cases = [
            scope(None, None),
            scope(Some(&["github"]), None),
            scope(Some(&["github"]), Some(&["get_*"])),
            scope(Some(&["github"]), Some(&[])),
            scope(Some(&["slack"]), None),
        ];
        let expected = [true, true, false, false, false];
        for (s, want) in cases.iter().zip(expected) {
            assert_eq!(s.covers_server_wide("github"), want, "{s:?}");
            assert_eq!(
                s.covers_tool("github", SERVER_WIDE_TOOL),
                s.covers_server_wide("github"),
                "{s:?}"
            );
        }
    }
}
