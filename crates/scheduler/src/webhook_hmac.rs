//! Webhook inbound security core (sched-triggers slice): HMAC-SHA256 signature
//! verification + 401/413 admission decision.
//!
//! This module ships the security-critical *decision* logic for inbound
//! webhooks; the live HTTP listener that wires it into
//! [`crate::hook::WebhookSource`] (axum/hyper transport plumbing) is deferred to
//! the future harness-witness slice (MODULE-014 §3.6).
//!
//! Verification order (mirrors the proven `cap-channel` reference
//! `crates/capabilities/cap-channel/src/webhook.rs`):
//! 1. **size check FIRST** — a body over the cap is rejected with **413**
//!    *before any HMAC is computed* (SYS-AC-107: never spend HMAC work on an
//!    oversized body).
//! 2. **weak-secret fail-closed** — a configured secret shorter than
//!    [`MIN_WEBHOOK_SECRET_BYTES`] cannot authenticate (an empty / short key
//!    makes signatures forgeable); reject with **401**.
//! 3. **signature compare** — missing / malformed / mismatched signature →
//!    **401** (SYS-AC-106); a valid signature → `Ok` (SYS-AC-105).
//!
//! The compare is **encoding-consistent**: both sides are 64-char lowercase hex
//! strings compared as byte slices in constant time via
//! [`subtle::ConstantTimeEq`] (which is implemented for `[u8]`, NOT `str` /
//! `String`). No hex-decode is performed, so there is no mixing of a 32-byte raw
//! tag with a 64-char hex string.

use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

use crate::types::WebhookConfig;

type HmacSha256 = Hmac<Sha256>;

/// Maximum inbound webhook body size (`channels.webhook_max_body_bytes`).
/// Bodies larger than this are rejected with HTTP 413 before HMAC computation.
pub const WEBHOOK_MAX_BODY_BYTES: usize = 1_048_576;

/// Minimum configured webhook secret length (bytes). A secret shorter than this
/// is treated as misconfigured and fails closed (401). Mirrors cap-channel's
/// `MIN_WEBHOOK_SECRET_BYTES` — short/empty keys make signatures forgeable.
pub const MIN_WEBHOOK_SECRET_BYTES: usize = 16;

/// Length (chars) of a valid HMAC-SHA256 signature in lowercase hex: a 32-byte
/// tag → 64 hex chars. Any other length is rejected before normalization/HMAC,
/// bounding the cost of an oversized attacker-supplied signature header.
const SIG_HEX_LEN: usize = 64;

/// Why an inbound webhook was rejected, with its HTTP status.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WebhookRejection {
    /// Body exceeded the configured cap — HTTP 413. Checked before any HMAC.
    PayloadTooLarge { len: usize, cap: usize },
    /// Missing / malformed / mismatched signature, or a weak/empty configured
    /// secret — HTTP 401.
    Unauthorized,
}

impl WebhookRejection {
    /// The HTTP status code this rejection maps to.
    pub fn http_status(&self) -> u16 {
        match self {
            WebhookRejection::PayloadTooLarge { .. } => 413,
            WebhookRejection::Unauthorized => 401,
        }
    }
}

/// Compute the lowercase-hex HMAC-SHA256 signature of `body` under `secret`.
///
/// HMAC accepts a key of any length, so construction never fails. The output is
/// a 64-character lowercase hex string (32 raw tag bytes).
pub fn compute_signature_hex(secret: &[u8], body: &[u8]) -> String {
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC accepts a key of any length");
    mac.update(body);
    let tag = mac.finalize().into_bytes();
    hex::encode(tag)
}

/// Verify an inbound webhook against its config.
///
/// `provided_sig_hex` is the caller-supplied hex signature (e.g. from an
/// `X-Signature` header), if any. `max_body_bytes` is the size cap to enforce
/// (callers pass [`WEBHOOK_MAX_BODY_BYTES`]; parameterized for testability).
///
/// Returns `Ok(())` if the request is admitted, or the [`WebhookRejection`]
/// (carrying its 413/401 status) otherwise. When `cfg.secret` is `None`, no
/// authentication is configured and the request is admitted (documented
/// opt-out) — the size cap still applies.
pub fn verify_webhook(
    cfg: &WebhookConfig,
    body: &[u8],
    provided_sig_hex: Option<&str>,
    max_body_bytes: usize,
) -> Result<(), WebhookRejection> {
    // 1. Size check FIRST — before any HMAC work (SYS-AC-107).
    if body.len() > max_body_bytes {
        return Err(WebhookRejection::PayloadTooLarge {
            len: body.len(),
            cap: max_body_bytes,
        });
    }

    // 2. HMAC gate — only when a secret is configured.
    let secret = match cfg.secret.as_deref() {
        // No auth configured: documented opt-out (size cap already enforced).
        None => return Ok(()),
        Some(s) => s,
    };

    // 2a. Weak/empty secret fails closed (cannot authenticate).
    // `str::len()` is the byte length (UTF-8), which is what MIN_WEBHOOK_SECRET_BYTES bounds.
    if secret.len() < MIN_WEBHOOK_SECRET_BYTES {
        return Err(WebhookRejection::Unauthorized);
    }

    // 2b. A signature must be present.
    let provided = match provided_sig_hex {
        Some(s) => s.trim(),
        None => return Err(WebhookRejection::Unauthorized),
    };

    // 2c. Length gate BEFORE normalization or HMAC: a valid signature is always
    // exactly `SIG_HEX_LEN` chars. Rejecting any other length here bounds the
    // cost of an arbitrarily large attacker-supplied signature header (it is
    // never lowercase-copied, and the HMAC is not computed). The length is not
    // secret-dependent, so this leaks nothing about the key.
    if provided.len() != SIG_HEX_LEN {
        return Err(WebhookRejection::Unauthorized);
    }

    // 3. Encoding-consistent constant-time compare (hex bytes vs hex bytes).
    // `provided` is now bounded to 64 bytes; normalize and compare in constant
    // time against the freshly-computed expected hex. ConstantTimeEq is
    // implemented for `[u8]` (not `str`); both sides are equal-length here.
    let provided = provided.to_ascii_lowercase();
    let expected = compute_signature_hex(secret.as_bytes(), body);
    debug_assert_eq!(expected.len(), SIG_HEX_LEN);
    if bool::from(provided.as_bytes().ct_eq(expected.as_bytes())) {
        Ok(())
    } else {
        Err(WebhookRejection::Unauthorized)
    }
}
