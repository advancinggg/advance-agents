//! CONTRACT-190 — the versioned client response envelope, deterministic error codes, and
//! warnings. Every Client API response is a [`ClientEnvelope`]; exactly one of `data`/`error`
//! is non-null (constructors make "both"/"neither" unrepresentable).

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// The canonical Client API version this build speaks (a date string, per §1.4.1).
pub const API_VERSION: &str = "2026-06-30";

/// The versioned response envelope. `data` XOR `error` is non-null; `warnings` may accompany
/// either. Matches MODULE-020 §2.3 / §2.4.
///
/// `Debug` is hand-written to redact the `data` payload: a response envelope's data may carry a
/// secret (e.g. the login response's bearer/CSRF tokens), so `{:?}` on an envelope must never
/// print it (§2.14 — "response body before projection" is a never-log field). `error` (a stable
/// code + message) is shown.
#[derive(Clone, Serialize, Deserialize, JsonSchema)]
pub struct ClientEnvelope<T> {
    pub api_version: String,
    pub request_id: String,
    pub data: Option<T>,
    pub error: Option<ClientError>,
    pub warnings: Vec<ClientWarning>,
}

impl<T> std::fmt::Debug for ClientEnvelope<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientEnvelope")
            .field("api_version", &self.api_version)
            .field("request_id", &self.request_id)
            .field("data", &self.data.as_ref().map(|_| "<redacted>"))
            .field("error", &self.error)
            .field("warnings", &self.warnings)
            .finish()
    }
}

impl<T> ClientEnvelope<T> {
    /// Build a success envelope (`error` is forced to `None`).
    pub fn ok(request_id: impl Into<String>, data: T, warnings: Vec<ClientWarning>) -> Self {
        Self {
            api_version: API_VERSION.to_string(),
            request_id: request_id.into(),
            data: Some(data),
            error: None,
            warnings,
        }
    }

    /// Build an error envelope (`data` is forced to `None`).
    pub fn error(
        request_id: impl Into<String>,
        error: ClientError,
        warnings: Vec<ClientWarning>,
    ) -> Self {
        Self {
            api_version: API_VERSION.to_string(),
            request_id: request_id.into(),
            data: None,
            error: Some(error),
            warnings,
        }
    }

    /// True iff this is a well-formed success envelope (data present, error absent).
    pub fn is_ok(&self) -> bool {
        self.data.is_some() && self.error.is_none()
    }

    /// True iff this is a well-formed error envelope (error present, data absent).
    pub fn is_err(&self) -> bool {
        self.error.is_some() && self.data.is_none()
    }

    /// The stable error code, if this is an error envelope.
    pub fn error_code(&self) -> Option<ClientErrorCode> {
        self.error.as_ref().map(|e| e.code.clone())
    }
}

/// A projected, client-safe error. `code` is the stable compatibility surface; `message` is
/// human-facing; `details` carries structured hints (e.g. the supported version range).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ClientError {
    pub code: ClientErrorCode,
    pub message: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub details: Vec<String>,
}

impl ClientError {
    pub fn new(code: ClientErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            details: Vec::new(),
        }
    }

    pub fn with_details(mut self, details: Vec<String>) -> Self {
        self.details = details;
        self
    }
}

/// The deterministic Client API error codes (MODULE-020 §2.8). Adding codes is
/// backward-compatible per §2.12 (no `api_version` bump). `Unknown` is a forward-compat
/// catch-all so a client built against an older schema tolerates a newer server code on the
/// wire instead of failing to deserialize; the server never *produces* `Unknown`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ClientErrorCode {
    // §2.8 base codes
    UnsupportedApiVersion,
    IdempotencyRequired,
    ModuleUnavailable,
    ProjectionRejected,
    StreamBackpressure,
    // m020-s1 session/auth/routing codes (additive)
    Unauthenticated,
    SessionExpired,
    CsrfRequired,
    CsrfInvalid,
    OriginNotAllowed,
    RemoteBindForbidden,
    InvalidBootstrapCode,
    IdempotencyInProgress,
    IdempotencyConflict,
    IdempotencyCapacity,
    UnknownRoute,
    RequestTooLarge,
    // m020-s2 provider-family codes (additive) — the client-safe projection of MODULE-008/006/017
    // provider errors (raw provider error structs never leak to the client).
    NotFound,
    ReplyNotAuthorized,
    InvalidState,
    Forbidden,
    /// Forward-compat catch-all (deserialization only; never emitted by this server).
    #[serde(other)]
    Unknown,
}

impl ClientErrorCode {
    /// The wire string for this code (the stable identifier clients switch on).
    pub fn as_str(&self) -> &'static str {
        match self {
            ClientErrorCode::UnsupportedApiVersion => "unsupported_api_version",
            ClientErrorCode::IdempotencyRequired => "idempotency_required",
            ClientErrorCode::ModuleUnavailable => "module_unavailable",
            ClientErrorCode::ProjectionRejected => "projection_rejected",
            ClientErrorCode::StreamBackpressure => "stream_backpressure",
            ClientErrorCode::Unauthenticated => "unauthenticated",
            ClientErrorCode::SessionExpired => "session_expired",
            ClientErrorCode::CsrfRequired => "csrf_required",
            ClientErrorCode::CsrfInvalid => "csrf_invalid",
            ClientErrorCode::OriginNotAllowed => "origin_not_allowed",
            ClientErrorCode::RemoteBindForbidden => "remote_bind_forbidden",
            ClientErrorCode::InvalidBootstrapCode => "invalid_bootstrap_code",
            ClientErrorCode::IdempotencyInProgress => "idempotency_in_progress",
            ClientErrorCode::IdempotencyConflict => "idempotency_conflict",
            ClientErrorCode::IdempotencyCapacity => "idempotency_capacity",
            ClientErrorCode::UnknownRoute => "unknown_route",
            ClientErrorCode::RequestTooLarge => "request_too_large",
            ClientErrorCode::NotFound => "not_found",
            ClientErrorCode::ReplyNotAuthorized => "reply_not_authorized",
            ClientErrorCode::InvalidState => "invalid_state",
            ClientErrorCode::Forbidden => "forbidden",
            ClientErrorCode::Unknown => "unknown",
        }
    }

    /// The known (server-producible) codes, in declaration order. Excludes the `Unknown`
    /// forward-compat catch-all. Used by the CONTRACT-192 schema fidelity check.
    pub fn known_codes() -> &'static [&'static str] {
        &[
            "unsupported_api_version",
            "idempotency_required",
            "module_unavailable",
            "projection_rejected",
            "stream_backpressure",
            "unauthenticated",
            "session_expired",
            "csrf_required",
            "csrf_invalid",
            "origin_not_allowed",
            "remote_bind_forbidden",
            "invalid_bootstrap_code",
            "idempotency_in_progress",
            "idempotency_conflict",
            "idempotency_capacity",
            "unknown_route",
            "request_too_large",
            "not_found",
            "reply_not_authorized",
            "invalid_state",
            "forbidden",
        ]
    }
}

/// A non-fatal, client-safe advisory attached to any envelope (e.g. an idempotent-replay note).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ClientWarning {
    pub code: String,
    pub message: String,
}

impl ClientWarning {
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
        }
    }
}
