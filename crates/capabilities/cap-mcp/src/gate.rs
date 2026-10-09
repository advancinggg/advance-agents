//! [`McpGate`] — what an agent's grants let it do through the mcp-client host
//! functions.
//!
//! Every mcp-client host function is reached through the one capability `mcp`,
//! and the injector lets only an agent holding an `mcp` grant call one. The
//! gate then decides each call on the server and tool it names, against the
//! caller's `mcp` grants:
//!
//! | host function | decided through | needs |
//! |---|---|---|
//! | `invoke-mcp-tool(s, t, …)` | [`GrantCheck`] | a grant covering tool `t` on server `s` |
//! | `get-mcp-prompt(s, …)`, `read-mcp-resource(s, …)` | [`GrantCheck`] | a grant reaching `s` that leaves its tool axis unrestricted |
//! | `list-mcp-servers` | [`McpGrantReader`] | lists the servers a grant reaches |
//! | `list-mcp-tools(s)` | [`McpGrantReader`] | a grant reaching `s`; lists the tools a grant covers |
//! | `list-mcp-prompts(s)`, `list-mcp-resources(s)` | [`McpGrantReader`] | as `get-mcp-prompt` |
//!
//! A server's prompts and resources fall under no tool pattern, so a grant
//! that restricts tools (`tool-patterns`) reaches none of them: it narrows the
//! agent to those tools. Each grant is judged on its own; two grants are never
//! merged axis by axis.
//!
//! A call is decided through [`GrantCheck`], which writes `authz.checked`
//! events by its own policy. A listing is filtered with what the caller's
//! grants reach, read through silent readers ([`McpGrantReader`], and
//! [`WebGrantReader`] for the web family tools), so a listing writes no
//! `authz.checked` event, however many entries it hides. Each reader follows
//! the rules of the check it stands for, so a listing shows exactly what a call
//! may reach.
//!
//! The web family tools (`web.search`, `web.extract`) also need the agent's
//! `web` grant ([`McpWebGrant`]): a call asks its check, a listing its reader.
//! A gate given no web grant withholds them from every agent. A stdio server
//! reaches the network outside the http security chain, with keys of its own,
//! so its web family tools are hidden and refused whatever the agent's grants
//! ([`McpClient::refuses_web_tools`](crate::McpClient::refuses_web_tools)).

use std::sync::Arc;

use advance_shared_types::capability::{CapParams, GrantDecision};
use advance_shared_types::mcp::{McpGrantScope, SERVER_WIDE_TOOL};
use advance_shared_types::traits::{GrantCheck, McpGrantReader, WebGrantReader};
use advance_shared_types::web_search::{is_web_tool_id, WEB_GRANT_CAPABILITY};

use crate::client::McpToolInfo;
use crate::error::McpError;

/// The capability every mcp-client host function is registered under, and the
/// grant family the gate asks.
pub const MCP_CAPABILITY: &str = "mcp";

/// Decides the mcp-client calls of each agent (see the module docs).
#[derive(Clone)]
pub struct McpGate {
    grant: Arc<dyn GrantCheck>,
    reader: Arc<dyn McpGrantReader>,
    web: Option<McpWebGrant>,
}

impl std::fmt::Debug for McpGate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("McpGate")
            .field("reader", &self.reader)
            .field("web", &self.web)
            .finish_non_exhaustive()
    }
}

/// The `web` grant, as the gate asks it about the web family tools: `check`
/// decides a call of one and writes `authz.checked` events by its own policy;
/// `reader` tells a listing, silently, whether to show them.
///
/// The two must agree for every agent: bind them over the same grants, and
/// let neither withhold the web family in a mode where the other offers it. A
/// mode that withholds it from every agent (offline) is expressed by giving
/// the gate no web grant.
#[derive(Clone)]
pub struct McpWebGrant {
    check: Arc<dyn GrantCheck>,
    reader: Arc<dyn WebGrantReader>,
}

impl McpWebGrant {
    /// `check` decides calls and `reader` answers listings (see the type docs).
    pub fn new(check: Arc<dyn GrantCheck>, reader: Arc<dyn WebGrantReader>) -> Self {
        Self { check, reader }
    }
}

impl std::fmt::Debug for McpWebGrant {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("McpWebGrant")
            .field("reader", &self.reader)
            .finish_non_exhaustive()
    }
}

impl McpGate {
    /// `grant` decides calls and `reader` gives listings the scopes of an
    /// agent's `mcp` grants; both must read the same grants. `web` decides
    /// the web family tools; without it they are withheld from every agent.
    pub fn new(
        grant: Arc<dyn GrantCheck>,
        reader: Arc<dyn McpGrantReader>,
        web: Option<McpWebGrant>,
    ) -> Self {
        Self { grant, reader, web }
    }

    /// Decide a call of `tool` on `server` by `agent`: allowed when one of its
    /// `mcp` grants covers that tool on that server. `function` names the
    /// calling host function in the `authz.checked` event.
    pub fn check_tool(
        &self,
        agent: &str,
        function: &str,
        server: &str,
        tool: &str,
    ) -> Result<(), McpError> {
        let request = serde_json::json!({ "servers": server, "tool-patterns": tool });
        self.check(agent, function, request).map_err(|reason| {
            McpError::permission_denied(format!(
                "no mcp grant covers tool {tool:?} on server {server:?} ({reason})"
            ))
        })
    }

    /// Decide a call on the prompts or resources of `server` by `agent`:
    /// allowed when one of its `mcp` grants reaches the server and leaves the
    /// tool axis unrestricted. `function` names the calling host function in
    /// the `authz.checked` event.
    pub fn check_server_wide(
        &self,
        agent: &str,
        function: &str,
        server: &str,
    ) -> Result<(), McpError> {
        let request = serde_json::json!({ "servers": server, "tool-patterns": SERVER_WIDE_TOOL });
        self.check(agent, function, request)
            .map_err(|reason| server_wide_denied(server, Some(&reason)))
    }

    /// Decide a call of a web family tool by `agent`: allowed when the web
    /// grant's check allows its `web` capability. `function` names the calling
    /// host function in the check's `authz.checked` event.
    pub fn check_web(&self, agent: &str, function: &str) -> Result<(), McpError> {
        let Some(web) = &self.web else {
            return Err(McpError::permission_denied(
                "web family tools are withheld: no web grant is bound",
            ));
        };
        match web
            .check
            .check(agent, WEB_GRANT_CAPABILITY, function, &CapParams::empty())
        {
            GrantDecision::Allow => Ok(()),
            GrantDecision::Deny(reason) => Err(McpError::permission_denied(reason)),
        }
    }

    /// The scopes of `agent`'s `mcp` grants, for filtering a listing. Read
    /// through the reader: nothing is decided and no event is written.
    pub fn scopes(&self, agent: &str) -> McpScopes {
        McpScopes(self.reader.mcp_grant_scopes(agent))
    }

    /// The tools of one server's listing that `agent` may see: those one of
    /// its grants covers (`scopes`, read with [`scopes`](Self::scopes)), less
    /// the web family tools when `server_refuses_web` or when the web grant's
    /// reader says `agent` may not use them. Nothing is decided and no event is
    /// written: the reader is asked at most once, and only when a web family
    /// tool would otherwise be shown.
    pub fn visible_tools(
        &self,
        agent: &str,
        scopes: &McpScopes,
        server_refuses_web: bool,
        mut tools: Vec<McpToolInfo>,
    ) -> Vec<McpToolInfo> {
        let mut web_visible: Option<bool> = None;
        tools.retain(|tool| self.shows(agent, scopes, server_refuses_web, &mut web_visible, tool));
        tools
    }

    /// The tools of one server's listing that `agent` may see, as
    /// [`visible_tools`](Self::visible_tools) chooses them, borrowed from
    /// `tools` in listing order: a listing kept elsewhere (the client's tool
    /// cache) is filtered without cloning any tool.
    pub fn visible_tool_refs<'a>(
        &self,
        agent: &str,
        scopes: &McpScopes,
        server_refuses_web: bool,
        tools: &'a [McpToolInfo],
    ) -> Vec<&'a McpToolInfo> {
        let mut web_visible: Option<bool> = None;
        tools
            .iter()
            .filter(|tool| self.shows(agent, scopes, server_refuses_web, &mut web_visible, tool))
            .collect()
    }

    /// Whether `agent` may see `tool` (see [`visible_tools`](Self::visible_tools));
    /// `web_visible` keeps the web grant reader's answer once it was asked.
    fn shows(
        &self,
        agent: &str,
        scopes: &McpScopes,
        server_refuses_web: bool,
        web_visible: &mut Option<bool>,
        tool: &McpToolInfo,
    ) -> bool {
        if !scopes.reaches_tool(&tool.server_id, &tool.name) {
            return false;
        }
        if !is_web_tool_id(&tool.name) {
            return true;
        }
        !server_refuses_web && *web_visible.get_or_insert_with(|| self.web_visible(agent))
    }

    /// Whether a listing may show `agent` the web family tools, read through
    /// the web grant's silent reader; never without a web grant.
    fn web_visible(&self, agent: &str) -> bool {
        self.web
            .as_ref()
            .is_some_and(|web| web.reader.web_grant_held(agent))
    }

    /// Ask the grant check about an `mcp` request; the deny reason on refusal.
    fn check(&self, agent: &str, function: &str, request: serde_json::Value) -> Result<(), String> {
        match self
            .grant
            .check(agent, MCP_CAPABILITY, function, &CapParams::new(request))
        {
            GrantDecision::Allow => Ok(()),
            GrantDecision::Deny(reason) => Err(reason),
        }
    }
}

/// The refusal of a call or listing on the prompts or resources of `server`.
pub(crate) fn server_wide_denied(server: &str, reason: Option<&str>) -> McpError {
    let mut message = format!(
        "the prompts and resources of server {server:?} need an mcp grant that reaches the \
         server without restricting its tools"
    );
    if let Some(reason) = reason {
        message.push_str(&format!(" ({reason})"));
    }
    McpError::permission_denied(message)
}

/// The refusal of a tool listing on `server`.
pub(crate) fn server_denied(server: &str) -> McpError {
    McpError::permission_denied(format!("no mcp grant reaches server {server:?}"))
}

/// What one agent's `mcp` grants reach, read once for a listing
/// ([`McpGate::scopes`]). Each scope is one grant; an entry is reached when one
/// scope reaches it on its own.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct McpScopes(Vec<McpGrantScope>);

impl McpScopes {
    /// Whether a grant reaches `server` (a request naming no tool).
    pub fn reaches_server(&self, server: &str) -> bool {
        self.0.iter().any(|scope| scope.covers_server(server))
    }

    /// Whether a grant covers the tool named `tool` on `server`.
    pub fn reaches_tool(&self, server: &str, tool: &str) -> bool {
        self.0.iter().any(|scope| scope.covers_tool(server, tool))
    }

    /// Whether a grant reaches the prompts and resources of `server`: it
    /// reaches the server and leaves the tool axis unrestricted.
    pub fn reaches_server_wide(&self, server: &str) -> bool {
        self.0.iter().any(|scope| scope.covers_server_wide(server))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;

    fn scope(servers: Option<&[&str]>, patterns: Option<&[&str]>) -> McpGrantScope {
        let owned = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        McpGrantScope {
            servers: servers.map(owned),
            tool_patterns: patterns.map(owned),
        }
    }

    #[derive(Debug)]
    struct Scopes(Vec<McpGrantScope>);
    impl McpGrantReader for Scopes {
        fn mcp_grant_scopes(&self, _agent_id: &str) -> Vec<McpGrantScope> {
            self.0.clone()
        }
    }

    /// Allows or denies every request, recording each one.
    struct Recording {
        allow: bool,
        seen: Mutex<Vec<(String, String, serde_json::Value)>>,
    }
    impl Recording {
        fn new(allow: bool) -> Arc<Self> {
            Arc::new(Self {
                allow,
                seen: Mutex::new(Vec::new()),
            })
        }
        fn seen(&self) -> Vec<(String, String, serde_json::Value)> {
            self.seen.lock().unwrap().clone()
        }
    }
    impl GrantCheck for Recording {
        fn check(
            &self,
            agent_id: &str,
            capability: &str,
            _function: &str,
            params: &CapParams,
        ) -> GrantDecision {
            self.seen.lock().unwrap().push((
                agent_id.to_string(),
                capability.to_string(),
                params.as_value().clone(),
            ));
            if self.allow {
                GrantDecision::Allow
            } else {
                GrantDecision::Deny("denied".into())
            }
        }
    }

    /// A web grant reader answering every agent with `held`, counting reads.
    #[derive(Debug)]
    struct WebHeld {
        held: bool,
        reads: Mutex<usize>,
    }
    impl WebHeld {
        fn new(held: bool) -> Arc<Self> {
            Arc::new(Self {
                held,
                reads: Mutex::new(0),
            })
        }
        fn reads(&self) -> usize {
            *self.reads.lock().unwrap()
        }
    }
    impl WebGrantReader for WebHeld {
        fn web_grant_held(&self, _agent_id: &str) -> bool {
            *self.reads.lock().unwrap() += 1;
            self.held
        }
    }

    /// A gate whose web grant is `check` and `reader`.
    fn web_gate(check: Arc<Recording>, reader: Arc<WebHeld>) -> McpGate {
        McpGate::new(
            Recording::new(true),
            Arc::new(Scopes(vec![])),
            Some(McpWebGrant::new(check, reader)),
        )
    }

    fn tool(server: &str, name: &str) -> McpToolInfo {
        McpToolInfo {
            name: name.into(),
            description: String::new(),
            server_id: server.into(),
            input_schema: None,
        }
    }

    fn names(tools: &[McpToolInfo]) -> Vec<&str> {
        tools.iter().map(|t| t.name.as_str()).collect()
    }

    #[test]
    fn calls_ask_the_mcp_grant_for_the_server_and_the_tool() {
        let grant = Recording::new(true);
        let gate = McpGate::new(grant.clone(), Arc::new(Scopes(vec![])), None);
        gate.check_tool("a", "f", "srv", "echo").unwrap();
        gate.check_server_wide("a", "f", "srv").unwrap();
        assert_eq!(
            grant.seen(),
            vec![
                (
                    "a".to_string(),
                    "mcp".to_string(),
                    serde_json::json!({"servers": "srv", "tool-patterns": "echo"})
                ),
                (
                    "a".to_string(),
                    "mcp".to_string(),
                    serde_json::json!({"servers": "srv", "tool-patterns": SERVER_WIDE_TOOL})
                ),
            ]
        );

        let gate = McpGate::new(Recording::new(false), Arc::new(Scopes(vec![])), None);
        let err = gate.check_tool("a", "f", "srv", "echo").unwrap_err();
        assert_eq!(err.kind, crate::McpErrorKind::PermissionDenied);
        assert!(err.message.contains("\"echo\""), "{}", err.message);
        let err = gate.check_server_wide("a", "f", "srv").unwrap_err();
        assert_eq!(err.kind, crate::McpErrorKind::PermissionDenied);
        assert!(
            err.message.contains("without restricting"),
            "{}",
            err.message
        );
    }

    // A call of a web family tool asks the web grant's check, never its
    // reader; without a web grant it is refused.
    #[test]
    fn web_family_calls_ask_the_web_grant_check() {
        let gate = McpGate::new(Recording::new(true), Arc::new(Scopes(vec![])), None);
        assert!(gate.check_web("a", "f").is_err());

        let check = Recording::new(true);
        let reader = WebHeld::new(false);
        let gate = web_gate(check.clone(), reader.clone());
        assert!(gate.check_web("a", "f").is_ok());
        assert_eq!(check.seen()[0].1, WEB_GRANT_CAPABILITY);
        assert_eq!(reader.reads(), 0, "a call never reads the listing answer");

        let gate = web_gate(Recording::new(false), WebHeld::new(true));
        assert!(gate.check_web("a", "f").is_err());
    }

    #[test]
    fn scopes_are_judged_one_grant_at_a_time() {
        let scopes = McpScopes(vec![
            scope(Some(&["a"]), Some(&["x*"])),
            scope(Some(&["b"]), None),
        ]);
        assert!(scopes.reaches_server("a"));
        assert!(scopes.reaches_server("b"));
        assert!(!scopes.reaches_server("c"));
        assert!(scopes.reaches_tool("a", "x1"));
        assert!(!scopes.reaches_tool("a", "y"));
        assert!(scopes.reaches_tool("b", "y"));
        assert!(!scopes.reaches_server_wide("a"));
        assert!(scopes.reaches_server_wide("b"));
        assert!(!McpScopes::default().reaches_server("a"));
    }

    // The listing filter keeps the covered tools, and shows the web family
    // tools as the web grant's reader says: read once, and only for a covered
    // web family tool on a server that does not refuse them. It never asks a
    // grant check, so it writes no event.
    #[test]
    fn visible_tools_follow_the_scopes_and_the_web_reader() {
        let listing = || {
            vec![
                tool("srv", "get_a"),
                tool("srv", "web.search"),
                tool("srv", "web.extract"),
                tool("srv", "delete"),
            ]
        };
        let scopes = McpScopes(vec![scope(Some(&["srv"]), Some(&["get_*", "web.*"]))]);
        let check = Recording::new(true);
        let reader = WebHeld::new(true);
        let gate = web_gate(check.clone(), reader.clone());
        let shown = gate.visible_tools("a", &scopes, false, listing());
        assert_eq!(names(&shown), ["get_a", "web.search", "web.extract"]);
        assert_eq!(reader.reads(), 1);

        let shown = gate.visible_tools("a", &scopes, true, listing());
        assert_eq!(names(&shown), ["get_a"]);
        assert_eq!(reader.reads(), 1, "a refusing server reads no web grant");

        let no_web = McpScopes(vec![scope(Some(&["srv"]), Some(&["get_*"]))]);
        gate.visible_tools("a", &no_web, false, listing());
        assert_eq!(reader.reads(), 1, "no covered web tool reads no web grant");
        assert!(check.seen().is_empty(), "a listing never asks the check");

        let not_held = web_gate(Recording::new(true), WebHeld::new(false));
        let shown = not_held.visible_tools("a", &scopes, false, listing());
        assert_eq!(names(&shown), ["get_a"]);

        let no_grant = McpGate::new(Recording::new(true), Arc::new(Scopes(vec![])), None);
        let shown = no_grant.visible_tools("a", &scopes, false, listing());
        assert_eq!(names(&shown), ["get_a"]);
    }

    // The borrowing filter chooses what the owning one does, reads the web grant as rarely,
    // and hands back the listing's own tools.
    #[test]
    fn visible_tool_refs_choose_as_visible_tools_does() {
        let listing = vec![
            tool("srv", "get_a"),
            tool("srv", "web.search"),
            tool("srv", "web.extract"),
            tool("srv", "delete"),
        ];
        let scopes = McpScopes(vec![scope(Some(&["srv"]), Some(&["get_*", "web.*"]))]);
        for (held, refuses_web) in [(true, false), (true, true), (false, false)] {
            let reader = WebHeld::new(held);
            let gate = web_gate(Recording::new(true), reader.clone());
            let owned = gate.visible_tools("a", &scopes, refuses_web, listing.clone());
            let reads = reader.reads();
            let borrowed = gate.visible_tool_refs("a", &scopes, refuses_web, &listing);
            assert_eq!(
                borrowed.iter().map(|t| t.name.as_str()).collect::<Vec<_>>(),
                names(&owned),
                "held {held}, refuses {refuses_web}"
            );
            assert_eq!(
                reader.reads(),
                2 * reads,
                "held {held}, refuses {refuses_web}"
            );
            assert!(borrowed
                .iter()
                .all(|t| listing.iter().any(|l| std::ptr::eq(*t, l))));
        }
        let none = McpScopes(vec![scope(Some(&["other"]), None)]);
        let gate = web_gate(Recording::new(true), WebHeld::new(true));
        assert!(gate
            .visible_tool_refs("a", &none, false, &listing)
            .is_empty());
    }
}
