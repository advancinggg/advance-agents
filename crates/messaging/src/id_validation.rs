//! Defense-in-depth identifier structural + charset validation.
//!
//! Slice A's broader contract says the WIT host_fn layer (future slice) is
//! authoritative for charset validation. This module is the inner-defense
//! check: even when a caller bypasses the WIT layer (test code, internal
//! callers, slice-B+ code paths), `is_safe_id` ENFORCES the canonical
//! MODULE-006 id grammar:
//!
//!   id := "system" | "agent:" body | "user:" body
//!   body := [A-Za-z0-9_-]+    (no further colons, no whitespace, ASCII only)
//!
//! Length cap: 1..=`MAX_ID_BYTES` (256 bytes — mirrors shared-types
//! bounded-length guidance).
//!
//! This defeats:
//! - JSONL log splice via newline / null / control-char injection.
//! - `user:` empty-prefix bypass (`from = "user:"` granting global route).
//! - `user:` multi-colon bypass (`from = "user:agent:victim"` — R13 Critical
//!   #1) — body must not contain `:`.
//! - Malformed-prefix surface (`:foo`, `bar:`, `foo:bar` with unknown
//!   prefix, lone `:`, etc. — R13 Warning #5) — must match `(agent|user):`
//!   or be exactly `"system"`.
//! - Self-send check bypass via trailing whitespace or Unicode homoglyph
//!   (Cyrillic 'а' vs Latin 'a') — body is ASCII alphanumeric + `_-` only.

/// Bounded id length (bytes) — mirrors shared-types `AgentId` invariant 1.
pub const MAX_ID_BYTES: usize = 256;

/// Returns true iff `s` matches the canonical MODULE-006 id grammar
/// (see module rustdoc).
pub fn is_safe_id(s: &str) -> bool {
    if s.is_empty() || s.len() > MAX_ID_BYTES {
        return false;
    }
    // The literal system sender — exact match, no colon.
    if s == "system" {
        return true;
    }
    let body = if let Some(b) = s.strip_prefix("agent:") {
        b
    } else if let Some(b) = s.strip_prefix("user:") {
        b
    } else {
        return false;
    };
    if body.is_empty() {
        return false;
    }
    body.bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
}

#[cfg(test)]
mod tests {
    use super::is_safe_id;

    #[test]
    fn empty_rejected() {
        assert!(!is_safe_id(""));
    }

    #[test]
    fn null_byte_rejected() {
        assert!(!is_safe_id("agent:a\0b"));
    }

    #[test]
    fn newline_rejected() {
        assert!(!is_safe_id("agent:a\nb"));
    }

    #[test]
    fn whitespace_rejected() {
        assert!(!is_safe_id("agent:a "));
        assert!(!is_safe_id("agent: a"));
    }

    #[test]
    fn user_empty_rejected() {
        assert!(!is_safe_id("user:"));
    }

    #[test]
    fn unicode_rejected() {
        // Cyrillic 'а' (U+0430), not Latin 'a' — non-ASCII byte.
        assert!(!is_safe_id("user:\u{0430}lice"));
    }

    #[test]
    fn oversized_rejected() {
        let s = "a".repeat(257);
        assert!(!is_safe_id(&s));
    }

    #[test]
    fn canonical_accepted() {
        assert!(is_safe_id("agent:root"));
        assert!(is_safe_id("agent:child-1"));
        assert!(is_safe_id("agent:foo_bar"));
        assert!(is_safe_id("user:alice"));
        assert!(is_safe_id("agent:ABC123"));
        assert!(is_safe_id("system"));
    }

    // R13 hardening: multi-colon body rejected (closes user: prefix
    // bypass via "user:agent:victim").
    #[test]
    fn multi_colon_body_rejected() {
        assert!(!is_safe_id("user:agent:victim"));
        assert!(!is_safe_id("agent:a:b"));
        assert!(!is_safe_id("agent::"));
    }

    // R13 hardening: malformed-prefix structure rejected.
    #[test]
    fn malformed_prefix_rejected() {
        assert!(!is_safe_id(":foo"));
        assert!(!is_safe_id("bar:"));
        assert!(!is_safe_id("foo:bar"));
        assert!(!is_safe_id(":"));
        assert!(!is_safe_id("::"));
        assert!(!is_safe_id("admin:alice"));
    }
}
