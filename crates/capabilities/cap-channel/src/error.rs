//! `ChannelError` — the cap-channel error surface.
//!
//! The WIT `channel-error` variant has 4 arms (per MODULE-016 §1.4.1):
//! `not-found`, `connection-failed`, `permission-denied`, `invalid-config`.
//! `ChannelError` also carries internal-only variants for cap-channel-internal
//! failure modes (buffer overflow, HMAC mismatch, missing secret, outbound
//! blocked by security chain) that lower to the 4 WIT-visible variants at the
//! WIT boundary in `wit_impl.rs`.

use thiserror::Error;

/// cap-channel error type.
#[derive(Debug, Error)]
pub enum ChannelError {
    /// WIT `channel-error::not-found` — subscription id unknown.
    #[error("not found: {0}")]
    NotFound(String),

    /// WIT `channel-error::connection-failed` — long poll / WS disconnected, or
    /// outbound `HttpSecurityChain` rejected the request (see [`Self::OutboundBlocked`]).
    #[error("connection failed: {0}")]
    ConnectionFailed(String),

    /// WIT `channel-error::permission-denied` — adapter lacks capability.
    #[error("permission denied: {0}")]
    PermissionDenied(String),

    /// WIT `channel-error::invalid-config` — unknown adapter type, defensive-cap
    /// violation, or `send-raw` method outside the allowed verb set.
    #[error("invalid config: {0}")]
    InvalidConfig(String),

    /// Internal-only — per-subscription buffer at capacity. Lowers to
    /// `ConnectionFailed` at the WIT boundary; surfaces as HTTP 503 at the
    /// webhook-handler boundary.
    #[error("buffer overflow on subscription {0}")]
    BufferOverflow(String),

    /// Internal-only — HMAC tag mismatch on webhook signature verification.
    /// Surfaces as HTTP 401 at the webhook-handler boundary; never reaches the
    /// WIT layer (webhook handler is invoked by the runtime's HTTP server, not
    /// by guest WASM).
    #[error("HMAC mismatch")]
    HmacMismatch,

    /// Internal-only — subscription has no webhook secret configured. Surfaces
    /// as HTTP 401 at the webhook-handler boundary.
    #[error("webhook secret not found for subscription {0}")]
    SecretNotFound(String),

    /// Internal-only — outbound `HttpSecurityChain` returned `HttpError` (allowlist
    /// blocked, SSRF, redirect rejected, transport, …). Lowers to
    /// `ConnectionFailed` at the WIT boundary.
    #[error("outbound blocked: {0}")]
    OutboundBlocked(String),
}

impl ChannelError {
    /// Lower an internal-only variant to its WIT-visible counterpart. Used at
    /// the `wit_impl.rs` boundary before returning to the guest.
    pub fn into_wit(self) -> Self {
        match self {
            Self::BufferOverflow(s) => Self::ConnectionFailed(format!("buffer overflow: {s}")),
            Self::OutboundBlocked(s) => Self::ConnectionFailed(format!("outbound blocked: {s}")),
            Self::HmacMismatch => Self::PermissionDenied("HMAC mismatch".to_string()),
            Self::SecretNotFound(s) => Self::PermissionDenied(format!("secret not found: {s}")),
            other => other,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn into_wit_lowers_internal_variants() {
        assert!(matches!(
            ChannelError::BufferOverflow("s".into()).into_wit(),
            ChannelError::ConnectionFailed(_)
        ));
        assert!(matches!(
            ChannelError::OutboundBlocked("blocked".into()).into_wit(),
            ChannelError::ConnectionFailed(_)
        ));
        assert!(matches!(
            ChannelError::HmacMismatch.into_wit(),
            ChannelError::PermissionDenied(_)
        ));
        assert!(matches!(
            ChannelError::SecretNotFound("s".into()).into_wit(),
            ChannelError::PermissionDenied(_)
        ));
    }

    #[test]
    fn into_wit_passes_through_wit_visible_variants() {
        assert!(matches!(
            ChannelError::NotFound("s".into()).into_wit(),
            ChannelError::NotFound(_)
        ));
        assert!(matches!(
            ChannelError::InvalidConfig("c".into()).into_wit(),
            ChannelError::InvalidConfig(_)
        ));
    }
}
