//! `mcp.*` observability events (PRD §15.3.19).
//!
//! The builders return an [`Event`] and never emit it: the mcp-client host
//! functions call `emit` in their own bodies, and the client emits the events
//! about a server's connection.
//!
//! | event | emitted when | payload |
//! |---|---|---|
//! | `mcp.server_started` | the client connected a server (after `initialize`) | `server_id`, `transport` |
//! | `mcp.server_died` | the client found a server's live connection closed | `server_id`, `exit_code` (always `null`: no exit status is collected) |
//! | `mcp.tool_invoked` | `invoke-mcp-tool` returned a result | `server_id`, `tool_name`, `agent_id`, `duration_ms` |
//! | `mcp.tool_error` | `invoke-mcp-tool` failed, refusals included | `server_id`, `tool_name`, `error_type` |
//! | `mcp.prompt_fetched` | `get-mcp-prompt` returned a prompt | `server_id`, `prompt_name` |
//! | `mcp.resource_read` | `read-mcp-resource` returned a resource | `server_id`, `uri`, `size_bytes` |
//!
//! An event never carries params, prompt arguments, results or server-sent
//! text. Server ids, tool and prompt names are cut to
//! [`MAX_EVENT_NAME_BYTES`], with control, invisible and bidi characters
//! replaced by `?`. A resource URI is reduced to its scheme and host
//! ([`redacted_uri`]): its user info, port, path, query and fragment can hold
//! names and tokens.
//!
//! A host function's event carries the caller's agent id, trace id and run id
//! from its call context. The connection events carry the agent id `runtime`:
//! one connection serves every agent.

use advance_runtime::host_registry::HostCallContext;
use advance_shared_types::event::Event;
use serde_json::json;

use crate::stdio_transport::sanitize_log_text;

/// `mcp.server_started`.
pub(crate) const SERVER_STARTED: &str = "mcp.server_started";
/// `mcp.server_died`.
pub(crate) const SERVER_DIED: &str = "mcp.server_died";
/// `mcp.tool_invoked`.
pub(crate) const TOOL_INVOKED: &str = "mcp.tool_invoked";
/// `mcp.tool_error`.
pub(crate) const TOOL_ERROR: &str = "mcp.tool_error";
/// `mcp.prompt_fetched`.
pub(crate) const PROMPT_FETCHED: &str = "mcp.prompt_fetched";
/// `mcp.resource_read`.
pub(crate) const RESOURCE_READ: &str = "mcp.resource_read";

/// Longest server id, tool or prompt name an event carries, in bytes.
pub(crate) const MAX_EVENT_NAME_BYTES: usize = 256;

/// Agent id of the connection events.
const RUNTIME_AGENT: &str = "runtime";

/// `text` made safe for an event (see the module docs).
fn event_text(text: &str) -> String {
    sanitize_log_text(text.as_bytes(), MAX_EVENT_NAME_BYTES)
}

/// An event of a host function call, attributed to its caller.
fn call_event(
    ctx: &HostCallContext,
    event_type: &str,
    payload: serde_json::Value,
    duration_ms: Option<u64>,
) -> Event {
    let mut event = Event::observability(event_type, ctx.agent_id.as_str(), payload, duration_ms);
    event.trace_id = ctx.trace_id.clone();
    event.run_id = ctx.run_id.clone();
    event
}

/// `mcp.tool_invoked`: `tool` on `server_id` returned a result after
/// `duration_ms`, which the envelope carries too.
pub(crate) fn tool_invoked(
    ctx: &HostCallContext,
    server_id: &str,
    tool: &str,
    duration_ms: u64,
) -> Event {
    call_event(
        ctx,
        TOOL_INVOKED,
        json!({
            "server_id": event_text(server_id),
            "tool_name": event_text(tool),
            "agent_id": ctx.agent_id,
            "duration_ms": duration_ms,
        }),
        Some(duration_ms),
    )
}

/// `mcp.tool_error`: the call of `tool` on `server_id` failed with the
/// `mcp-error` arm `error_type` (`permission-denied` for a refusal).
pub(crate) fn tool_error(
    ctx: &HostCallContext,
    server_id: &str,
    tool: &str,
    error_type: &str,
) -> Event {
    call_event(
        ctx,
        TOOL_ERROR,
        json!({
            "server_id": event_text(server_id),
            "tool_name": event_text(tool),
            "error_type": error_type,
        }),
        None,
    )
}

/// `mcp.prompt_fetched`: `prompt` on `server_id` was returned after
/// `duration_ms` (carried by the envelope).
pub(crate) fn prompt_fetched(
    ctx: &HostCallContext,
    server_id: &str,
    prompt: &str,
    duration_ms: u64,
) -> Event {
    call_event(
        ctx,
        PROMPT_FETCHED,
        json!({
            "server_id": event_text(server_id),
            "prompt_name": event_text(prompt),
        }),
        Some(duration_ms),
    )
}

/// `mcp.resource_read`: the resource at `uri` on `server_id` was returned,
/// `size_bytes` long, after `duration_ms` (carried by the envelope). The URI is
/// redacted ([`redacted_uri`]).
pub(crate) fn resource_read(
    ctx: &HostCallContext,
    server_id: &str,
    uri: &str,
    size_bytes: usize,
    duration_ms: u64,
) -> Event {
    call_event(
        ctx,
        RESOURCE_READ,
        json!({
            "server_id": event_text(server_id),
            "uri": redacted_uri(uri),
            "size_bytes": size_bytes,
        }),
        Some(duration_ms),
    )
}

/// `mcp.server_started`: the client connected `server_id` over `transport`
/// (`stdio` or `http`).
pub(crate) fn server_started(server_id: &str, transport: &str) -> Event {
    Event::observability(
        SERVER_STARTED,
        RUNTIME_AGENT,
        json!({
            "server_id": event_text(server_id),
            "transport": transport,
        }),
        None,
    )
}

/// `mcp.server_died`: the client found the live connection of `server_id`
/// closed.
pub(crate) fn server_died(server_id: &str) -> Event {
    Event::observability(
        SERVER_DIED,
        RUNTIME_AGENT,
        json!({
            "server_id": event_text(server_id),
            "exit_code": null,
        }),
        None,
    )
}

/// A resource URI reduced to what an event may carry: `scheme://host` when the
/// URI names a host, `scheme:` when it does not (`file:///…`, `mailto:…`), and
/// `unknown` when it does not parse. User info, port, path, query and fragment
/// are dropped; a host longer than [`MAX_EVENT_NAME_BYTES`] is cut.
pub(crate) fn redacted_uri(uri: &str) -> String {
    match url::Url::parse(uri) {
        Ok(parsed) => match parsed.host_str().filter(|host| !host.is_empty()) {
            Some(host) => format!("{}://{}", parsed.scheme(), event_text(host)),
            None => format!("{}:", parsed.scheme()),
        },
        Err(_) => "unknown".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx() -> HostCallContext {
        HostCallContext {
            agent_id: "agent-1".into(),
            trace_id: "trace-1".into(),
            turn_id: None,
            capability: "mcp".into(),
            function: "advance:runtime/mcp-client@0.1.0::invoke-mcp-tool".into(),
            run_id: Some("run-1".into()),
            iteration: None,
        }
    }

    #[test]
    fn a_uri_keeps_only_its_scheme_and_host() {
        let cases = [
            (
                "https://user:secret@api.example.com:8443/v1/x?token=abc#frag",
                "https://api.example.com",
            ),
            (
                "postgres://admin:pw@db.internal/prod",
                "postgres://db.internal",
            ),
            (
                "github://octo/repo/issues/1?access_token=t",
                "github://octo",
            ),
            ("file:///etc/secret.txt", "file:"),
            ("mailto:someone@example.com", "mailto:"),
            ("data:text/plain,secret", "data:"),
            ("urn:isbn:0451450523", "urn:"),
            ("HTTPS://API.Example.com/a", "https://api.example.com"),
            ("no scheme here", "unknown"),
            ("", "unknown"),
            ("/relative/path", "unknown"),
        ];
        for (uri, expected) in cases {
            assert_eq!(redacted_uri(uri), expected, "{uri:?}");
        }
    }

    #[test]
    fn a_long_host_is_cut() {
        let host = format!("{}.example.com", "a".repeat(400));
        let redacted = redacted_uri(&format!("custom://{host}/x"));
        assert!(redacted.starts_with("custom://aaa"), "{redacted}");
        assert!(redacted.ends_with('…'), "{redacted}");
        assert!(redacted.len() <= "custom://".len() + MAX_EVENT_NAME_BYTES + '…'.len_utf8());
    }

    #[test]
    fn call_events_carry_the_caller_and_safe_names() {
        let event = tool_invoked(&ctx(), "srv", "echo\u{202E}\n", 12);
        assert_eq!(event.event_type, TOOL_INVOKED);
        assert_eq!(event.agent_id, "agent-1");
        assert_eq!(event.trace_id, "trace-1");
        assert_eq!(event.run_id.as_deref(), Some("run-1"));
        assert_eq!(event.duration_ms, Some(12));
        assert_eq!(
            event.payload,
            json!({
                "server_id": "srv",
                "tool_name": "echo??",
                "agent_id": "agent-1",
                "duration_ms": 12,
            })
        );

        let long = "t".repeat(MAX_EVENT_NAME_BYTES + 10);
        let event = tool_error(&ctx(), "srv", &long, "permission-denied");
        assert_eq!(event.event_type, TOOL_ERROR);
        let tool_name = event.payload["tool_name"].as_str().unwrap();
        assert!(tool_name.len() <= MAX_EVENT_NAME_BYTES + '…'.len_utf8());
        assert_eq!(event.payload["error_type"], "permission-denied");
        assert_eq!(event.duration_ms, None);

        let event = prompt_fetched(&ctx(), "srv", "summary", 3);
        assert_eq!(event.event_type, PROMPT_FETCHED);
        assert_eq!(
            event.payload,
            json!({"server_id": "srv", "prompt_name": "summary"})
        );
        assert_eq!(event.duration_ms, Some(3));

        let event = resource_read(&ctx(), "srv", "https://u:p@h.example/a?b=c", 42, 4);
        assert_eq!(event.event_type, RESOURCE_READ);
        assert_eq!(
            event.payload,
            json!({"server_id": "srv", "uri": "https://h.example", "size_bytes": 42})
        );
    }

    #[test]
    fn connection_events_belong_to_the_runtime() {
        let started = server_started("srv", "stdio");
        assert_eq!(started.event_type, SERVER_STARTED);
        assert_eq!(started.agent_id, "runtime");
        assert_eq!(
            started.payload,
            json!({"server_id": "srv", "transport": "stdio"})
        );
        let died = server_died("srv");
        assert_eq!(died.event_type, SERVER_DIED);
        assert_eq!(died.agent_id, "runtime");
        assert_eq!(died.payload, json!({"server_id": "srv", "exit_code": null}));
    }
}
