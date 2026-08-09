//! CONTRACT-190 — the transport-agnostic client request.
//!
//! Models an HTTP-style request WITHOUT a bound socket: the connection's loopback-ness, the
//! browser `Origin`, the session token, the CSRF token, and the idempotency key are carried as
//! fields so admission/auth/CSRF/idempotency policy is testable in-process. A later serve-loop
//! slice populates these from real HTTP + the peer address.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// HTTP-style method (only what the foundation surface needs).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "UPPERCASE")]
pub enum Method {
    Get,
    Post,
}

/// A client request handed to [`crate::api::ClientApi::handle`].
///
/// `Debug` is hand-written to redact the bearer/CSRF tokens and the body (which may carry a
/// bootstrap code) — no secret leaks via a stray log/`{:?}` (§2.14 secret hygiene).
#[derive(Clone)]
pub struct ClientRequest {
    /// The client-declared API version (checked fail-closed before any handler).
    pub api_version: String,
    pub method: Method,
    /// Logical path, e.g. `/client/session/login`, `/client/health`.
    pub path: String,
    /// Opaque session token (bearer), if the client holds a session.
    pub session_token: Option<String>,
    /// Browser `Origin` header, if the caller is a browser. Absent for native clients.
    pub origin: Option<String>,
    /// CSRF token presented for a browser mutation.
    pub csrf_token: Option<String>,
    /// Idempotency key for a mutating operation.
    pub idempotency_key: Option<String>,
    /// Whether the underlying connection peer is loopback (populated by the transport).
    pub is_loopback_peer: bool,
    /// Request body (already parsed JSON). `Null` for bodyless requests.
    pub body: serde_json::Value,
}

impl std::fmt::Debug for ClientRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientRequest")
            .field("api_version", &self.api_version)
            .field("method", &self.method)
            .field("path", &self.path)
            .field("origin", &self.origin)
            .field("is_loopback_peer", &self.is_loopback_peer)
            .field(
                "session_token",
                &self.session_token.as_ref().map(|_| "<redacted>"),
            )
            .field(
                "csrf_token",
                &self.csrf_token.as_ref().map(|_| "<redacted>"),
            )
            .field(
                "idempotency_key",
                &self.idempotency_key.as_ref().map(|_| "<present>"),
            )
            .field("body", &"<redacted>")
            .finish()
    }
}

impl ClientRequest {
    /// Construct a loopback GET with the current API version (test/ergonomic helper).
    pub fn get(path: impl Into<String>) -> Self {
        Self {
            api_version: crate::envelope::API_VERSION.to_string(),
            method: Method::Get,
            path: path.into(),
            session_token: None,
            origin: None,
            csrf_token: None,
            idempotency_key: None,
            is_loopback_peer: true,
            body: serde_json::Value::Null,
        }
    }

    /// Construct a loopback POST with the current API version.
    pub fn post(path: impl Into<String>, body: serde_json::Value) -> Self {
        Self {
            api_version: crate::envelope::API_VERSION.to_string(),
            method: Method::Post,
            path: path.into(),
            session_token: None,
            origin: None,
            csrf_token: None,
            idempotency_key: None,
            is_loopback_peer: true,
            body,
        }
    }

    pub fn with_session(mut self, token: impl Into<String>) -> Self {
        self.session_token = Some(token.into());
        self
    }

    pub fn with_origin(mut self, origin: impl Into<String>) -> Self {
        self.origin = Some(origin.into());
        self
    }

    pub fn with_csrf(mut self, csrf: impl Into<String>) -> Self {
        self.csrf_token = Some(csrf.into());
        self
    }

    pub fn with_idempotency_key(mut self, key: impl Into<String>) -> Self {
        self.idempotency_key = Some(key.into());
        self
    }

    pub fn with_loopback_peer(mut self, loopback: bool) -> Self {
        self.is_loopback_peer = loopback;
        self
    }

    /// The approximate serialized body size in bytes (for the §2.11 body cap). NOTE: the body
    /// here is already a parsed `Value`, so this is a secondary logical guard — the primary
    /// byte-cap (rejecting an over-sized body BEFORE it is parsed/allocated) is enforced by the
    /// HTTP transport in a later serve-loop slice.
    pub fn body_size(&self) -> usize {
        if self.body.is_null() {
            0
        } else {
            serde_json::to_vec(&self.body).map(|v| v.len()).unwrap_or(0)
        }
    }
}
