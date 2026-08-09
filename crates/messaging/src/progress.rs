//! Structured-progress boundary helper + key constants (MODULE-006 / REQ-205 share).
//! **Helper/test tripwire only — AC-08 is NOT claimed.**
//!
//! # Scope (SUPERSEDED framing 2026-07-12 keeplosers-2)
//!
//! - **MODULE-016 / cap-channel** owns `parse_progress` / `build_progress_metadata` helpers.
//!   Those helpers have **zero production callers** today; they are not production
//!   "reference adapter honors" evidence for M006-AC-08.
//! - **MODULE-006's share** is this generic namespace tripwire (`validate_metadata_boundary`)
//!   plus a non-interference note that delivery must not strip opaque metadata bags when
//!   a future outbound carrier exists.
//! - The required AC-08 chain is **agent-authored outbound reply/action metadata →
//!   channel egress/delivery → adapter parse/render**. Shipped WIT `action` / `AgentAction` /
//!   `dispatcher.reply` / `ChannelDelivery` / `ChannelEgress` are payload-only; inbound
//!   `MessageOrigin.channel_metadata` is host-owned provenance/routing, not agent progress.
//! - Flexible free-form `message-context` as a progress carrier was **killed** vs PRD §10.6
//!   (identity context must not carry progress). This helper is **not** waiting on that map.
//!
//! [`validate_metadata_boundary`] is signature-compatible with cap-channel's helper so tests
//! can share the tripwire; neither path is a production runtime gate today.

/// Common namespace prefix for structured-progress metadata keys.
pub const PROGRESS_PREFIX: &str = "progress.";

/// Metadata key: progress phase (`ack` / `progress` / `result` / `error`).
pub const PROGRESS_PHASE: &str = "progress.phase";

/// Metadata key: optional `0.0..=1.0` progress value (string-encoded).
pub const PROGRESS_VALUE: &str = "progress.value";

/// Metadata key: human-readable progress summary.
pub const PROGRESS_SUMMARY: &str = "progress.summary";

/// True iff `key` is in the `progress.*` namespace.
pub fn is_progress_key(key: &str) -> bool {
    key.starts_with(PROGRESS_PREFIX)
}

/// A `progress.*` key appeared in a context-key list (generic tripwire only).
///
/// **Not** a production WIT gate and **not** a claim that progress belongs on
/// `MessageOrigin.channel_metadata` (that bag is inbound host provenance/routing).
/// Agent-authored outbound reply metadata is the missing AC-08 carrier; this helper
/// only rejects progress.* when it is mistakenly listed among context keys.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProgressBoundaryError {
    pub leaked_key: String,
}

impl std::fmt::Display for ProgressBoundaryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "progress.* key {:?} leaked into message-context (belongs on message metadata)",
            self.leaked_key
        )
    }
}

impl std::error::Error for ProgressBoundaryError {}

/// Reject any `progress.*` key appearing among the supplied context-key strings.
///
/// Generic namespace tripwire (helper/test only). **Not** a production runtime gate and
/// **not** evidence that AC-08 is honored end-to-end. Signature mirrors cap-channel
/// `progress.rs::validate_metadata_boundary` for shared unit tripwires.
pub fn validate_metadata_boundary(context_keys: &[String]) -> Result<(), ProgressBoundaryError> {
    for key in context_keys {
        if is_progress_key(key) {
            return Err(ProgressBoundaryError {
                leaked_key: key.clone(),
            });
        }
    }
    Ok(())
}
