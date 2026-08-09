//! `SkillError` enum local to `cap-skills`.
//!
//! Slice A (2026-05-11) shipped 4 variants (DraftNotFound / SkillNotFound /
//! VersionNotFound / InvalidTransition). Slice C (2026-05-15) extends to 10
//! variants for richer host-side diagnostics + adds the
//! [`SkillError::to_wit_variant`] projection helper that maps to the canonical
//! 9-arm `skill-error` WIT variant per PRD §9.12 + MODULE-017 §2.8.

use thiserror::Error;

/// Errors emitted by the `cap-skills` state machine.
///
/// Internal 10-variant Rust enum — richer than the 9-arm WIT shape so host-side
/// `tracing` logs preserve the full diagnostic detail. The agent-facing ABI is
/// the 9-arm projection produced by [`SkillError::to_wit_variant`]; payloads
/// across the WASM boundary are fixed safe-class strings (mirrors Slice B's
/// `ToolError` SB-22 redaction discipline).
#[derive(Clone, Debug, PartialEq, Error)]
pub enum SkillError {
    /// Slice C — name fails `^[a-z0-9][a-z0-9_-]{0,63}$` regex per §1.3.2 check 1.
    #[error("invalid skill name: {0}")]
    InvalidName(String),

    /// Slice C — content > 50_000 chars per §1.3.2 check 2. Payload is the
    /// observed byte count (for tracing); WIT projection is payloadless
    /// (PRD §9.12 line 3704).
    #[error("content too large: {0} bytes")]
    ContentTooLarge(usize),

    /// Slice C — YAML frontmatter missing `name` / `description` or unparseable
    /// per §1.3.2 check 3a-c.
    #[error("invalid frontmatter: {0}")]
    InvalidFrontmatter(String),

    /// Slice C — activating a draft whose name collides with an existing Active
    /// skill per §1.3.2 check 4.
    #[error("skill name conflict: {0}")]
    NameConflict(String),

    /// Slice C — hard-fail pattern (Aho-Corasick + regex) or Unicode invisible-
    /// character violation per §1.3.2 checks 5a/6.
    #[error("security violation: {0}")]
    SecurityViolation(String),

    /// Slice C — agent attempted patch/delete/rollback on a Trusted skill, OR
    /// delete/rollback on an Imported+Untrusted skill per PRD §5024-5028.
    #[error("trust violation: {0}")]
    TrustViolation(String),

    /// No draft with the given `draft_id` exists. Emitted by
    /// [`SkillStore::update_draft`] and [`SkillStore::activate`].
    ///
    /// [`SkillStore::update_draft`]: crate::SkillStore::update_draft
    /// [`SkillStore::activate`]: crate::SkillStore::activate
    #[error("draft not found: {0}")]
    DraftNotFound(String),

    /// No active skill (or tombstoned-only chain) with the given
    /// `skill_id` exists.
    #[error("skill not found: {0}")]
    SkillNotFound(String),

    /// `rollback(skill_id, version)` referenced a version not present
    /// in the skill's history.
    #[error("version not found: skill={skill_id} version={version}")]
    VersionNotFound { skill_id: String, version: u32 },

    /// Catch-all for invalid state-machine transitions not covered by the
    /// structured variants above (e.g., u32 version overflow on increment).
    #[error("invalid transition: {0}")]
    InvalidTransition(String),
}

/// 9-arm WIT-shaped projection of [`SkillError`] per PRD §9.12.
///
/// Built by [`SkillError::to_wit_variant`]; consumed by
/// `cap-skills/src/host_fn.rs` to encode `Val::Variant` results.
/// `ContentTooLarge` is payloadless per PRD §9.12 line 3704; all other arms
/// carry a fixed safe-class `String` payload (no skill name, id, or internal
/// state crosses the WASM boundary).
#[derive(Clone, Debug, PartialEq)]
pub enum WitSkillError {
    InvalidName(String),
    /// Payloadless variant arm per PRD §9.12 line 3704.
    ContentTooLarge,
    InvalidFrontmatter(String),
    NameConflict(String),
    SecurityViolation(String),
    TrustViolation(String),
    InvalidTarget(String),
    NotFound(String),
    Internal(String),
}

impl WitSkillError {
    /// The WIT case discriminator (kebab-case, matches PRD §9.12 grammar).
    pub fn case(&self) -> &'static str {
        match self {
            Self::InvalidName(_) => "invalid-name",
            Self::ContentTooLarge => "content-too-large",
            Self::InvalidFrontmatter(_) => "invalid-frontmatter",
            Self::NameConflict(_) => "name-conflict",
            Self::SecurityViolation(_) => "security-violation",
            Self::TrustViolation(_) => "trust-violation",
            Self::InvalidTarget(_) => "invalid-target",
            Self::NotFound(_) => "not-found",
            Self::Internal(_) => "internal",
        }
    }

    /// The WIT payload string (None for `ContentTooLarge`, Some for all others).
    pub fn payload(&self) -> Option<&str> {
        match self {
            Self::ContentTooLarge => None,
            Self::InvalidName(s)
            | Self::InvalidFrontmatter(s)
            | Self::NameConflict(s)
            | Self::SecurityViolation(s)
            | Self::TrustViolation(s)
            | Self::InvalidTarget(s)
            | Self::NotFound(s)
            | Self::Internal(s) => Some(s.as_str()),
        }
    }
}

impl SkillError {
    /// Project the 10-variant Rust enum to the 9-arm WIT shape per
    /// MODULE-017 §2.8 mapping table. The Rust enum is richer for diagnostics;
    /// the WIT shape uses fixed safe-class strings for payloads (redaction
    /// discipline mirrors Slice B SB-22 `ToolError`).
    pub fn to_wit_variant(&self) -> WitSkillError {
        match self {
            Self::InvalidName(_) => WitSkillError::InvalidName("invalid skill name".to_string()),
            Self::ContentTooLarge(_) => WitSkillError::ContentTooLarge,
            Self::InvalidFrontmatter(_) => {
                WitSkillError::InvalidFrontmatter("frontmatter invalid".to_string())
            }
            Self::NameConflict(_) => {
                WitSkillError::NameConflict("skill name already exists".to_string())
            }
            Self::SecurityViolation(_) => {
                WitSkillError::SecurityViolation("security scan failed".to_string())
            }
            Self::TrustViolation(_) => {
                WitSkillError::TrustViolation("trusted skill is immutable".to_string())
            }
            Self::DraftNotFound(_) => WitSkillError::NotFound("draft not found".to_string()),
            Self::SkillNotFound(_) => WitSkillError::NotFound("skill not found".to_string()),
            Self::VersionNotFound { .. } => {
                WitSkillError::InvalidTarget("version not found".to_string())
            }
            Self::InvalidTransition(_) => {
                WitSkillError::Internal("invalid state transition".to_string())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// SC-44 — projection table-driven lock: every Rust variant maps to
    /// the expected WIT case + payload (payloadless for content-too-large).
    #[test]
    fn sc_44_projection_table_lock() {
        let cases: &[(SkillError, &str, Option<&str>)] = &[
            (
                SkillError::InvalidName("foo".into()),
                "invalid-name",
                Some("invalid skill name"),
            ),
            (
                SkillError::ContentTooLarge(99_999),
                "content-too-large",
                None,
            ),
            (
                SkillError::InvalidFrontmatter("missing name".into()),
                "invalid-frontmatter",
                Some("frontmatter invalid"),
            ),
            (
                SkillError::NameConflict("dup".into()),
                "name-conflict",
                Some("skill name already exists"),
            ),
            (
                SkillError::SecurityViolation("curl+POST".into()),
                "security-violation",
                Some("security scan failed"),
            ),
            (
                SkillError::TrustViolation("locked".into()),
                "trust-violation",
                Some("trusted skill is immutable"),
            ),
            (
                SkillError::DraftNotFound("d-1".into()),
                "not-found",
                Some("draft not found"),
            ),
            (
                SkillError::SkillNotFound("skill-x".into()),
                "not-found",
                Some("skill not found"),
            ),
            (
                SkillError::VersionNotFound {
                    skill_id: "x".into(),
                    version: 3,
                },
                "invalid-target",
                Some("version not found"),
            ),
            (
                SkillError::InvalidTransition("u32 overflow".into()),
                "internal",
                Some("invalid state transition"),
            ),
        ];

        for (input, expected_case, expected_payload) in cases {
            let wit = input.to_wit_variant();
            assert_eq!(wit.case(), *expected_case, "case mismatch for {:?}", input);
            assert_eq!(
                wit.payload(),
                *expected_payload,
                "payload mismatch for {:?}",
                input
            );
        }
    }

    /// SC-44 — `ContentTooLarge` is the ONLY payloadless arm per PRD §9.12.
    #[test]
    fn sc_44_content_too_large_is_payloadless() {
        let wit = SkillError::ContentTooLarge(123).to_wit_variant();
        assert_eq!(wit.case(), "content-too-large");
        assert_eq!(wit.payload(), None);
    }

    /// SC-44 — redaction discipline: rich Rust payload does NOT appear in
    /// the WIT projection. A SecurityViolation carrying "VERY SECRET" gets
    /// the fixed string "security scan failed", NOT the original payload.
    #[test]
    fn sc_44_payload_redaction() {
        let rust = SkillError::SecurityViolation("VERY SECRET pattern detected".into());
        let wit = rust.to_wit_variant();
        assert_eq!(wit.payload(), Some("security scan failed"));
        assert!(
            !wit.payload().unwrap().contains("VERY SECRET"),
            "WIT payload must not echo the Rust payload"
        );
    }
}
