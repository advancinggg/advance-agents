//! `McpError` — Rust mirror of the WIT `mcp-error` variant declared in
//! `crates/runtime/wit/advance.wit` `interface mcp-client`.
//!
//! Slice B (2026-05-14) ships the 6-arm error surface used by the HTTP/SSE
//! transport. The kebab-case [`McpError::kind`] discriminator matches the
//! WIT variant names so future host_fn-dispatch code (Slice C) can encode
//! these errors as `Val::Variant(kind, msg)` without an extra mapping
//! step.

use thiserror::Error;

/// Variant tags for [`McpError`]. Tag-only enum so error-kind dispatch
/// happens without inspecting the `Display` message.
///
/// Maps to the WIT `mcp-error` variant arms exactly:
/// - `NotFound` ↔ `not-found(string)`
/// - `ToolNotFound` ↔ `tool-not-found(string)`
/// - `TransportError` ↔ `transport-error(string)`
/// - `PermissionDenied` ↔ `permission-denied(string)`
/// - `InvalidResponse` ↔ `invalid-response(string)`
/// - `ServerError` ↔ `server-error(string)`
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum McpErrorKind {
    NotFound,
    ToolNotFound,
    TransportError,
    PermissionDenied,
    InvalidResponse,
    ServerError,
}

impl McpErrorKind {
    /// Kebab-case wire name matching the WIT variant arm.
    pub fn as_kebab(&self) -> &'static str {
        match self {
            McpErrorKind::NotFound => "not-found",
            McpErrorKind::ToolNotFound => "tool-not-found",
            McpErrorKind::TransportError => "transport-error",
            McpErrorKind::PermissionDenied => "permission-denied",
            McpErrorKind::InvalidResponse => "invalid-response",
            McpErrorKind::ServerError => "server-error",
        }
    }
}

/// Error type returned by the MCP transport surfaces.
///
/// Slice B exposes a single `Error`-shaped struct (kind + redacted
/// message). The message is intentionally short and free of upstream
/// content — full error context stays in tracing logs, while the
/// guest-visible payload is a fixed-class string.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
#[error("{}: {message}", kind.as_kebab())]
pub struct McpError {
    pub kind: McpErrorKind,
    pub message: String,
}

impl McpError {
    pub fn new(kind: McpErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }

    pub fn transport(message: impl Into<String>) -> Self {
        Self::new(McpErrorKind::TransportError, message)
    }

    pub fn invalid_response(message: impl Into<String>) -> Self {
        Self::new(McpErrorKind::InvalidResponse, message)
    }

    pub fn server_error(message: impl Into<String>) -> Self {
        Self::new(McpErrorKind::ServerError, message)
    }

    pub fn permission_denied(message: impl Into<String>) -> Self {
        Self::new(McpErrorKind::PermissionDenied, message)
    }

    /// Slice D additive constructor — server unknown / not in whitelist.
    pub fn not_found(message: impl Into<String>) -> Self {
        Self::new(McpErrorKind::NotFound, message)
    }

    /// Slice D additive constructor — tool unknown / blocked by tool-patterns.
    pub fn tool_not_found(message: impl Into<String>) -> Self {
        Self::new(McpErrorKind::ToolNotFound, message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kebab_names_match_wit() {
        assert_eq!(McpErrorKind::NotFound.as_kebab(), "not-found");
        assert_eq!(McpErrorKind::ToolNotFound.as_kebab(), "tool-not-found");
        assert_eq!(McpErrorKind::TransportError.as_kebab(), "transport-error");
        assert_eq!(
            McpErrorKind::PermissionDenied.as_kebab(),
            "permission-denied"
        );
        assert_eq!(McpErrorKind::InvalidResponse.as_kebab(), "invalid-response");
        assert_eq!(McpErrorKind::ServerError.as_kebab(), "server-error");
    }

    #[test]
    fn display_format() {
        let e = McpError::transport("bad");
        assert_eq!(e.to_string(), "transport-error: bad");
    }
}
