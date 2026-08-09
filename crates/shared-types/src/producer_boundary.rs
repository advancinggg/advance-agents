//! CONTRACT-214 — `RememberContentPolicy`: the `knowledge.jsonl` producer-boundary
//! guard (MODULE-005-AC-29 / REQ-210 / REQ-211).
//!
//! A dependency-inversion trait declared here (the neutral shared-types surface)
//! and consumed by cap-memory (MODULE-011)'s `RememberHandler`. The concrete
//! `WorkspaceFileResidentPolicy` is PROVIDED by cap-lifecycle (MODULE-005); the two
//! crates join at the cli composition root via `Arc<dyn RememberContentPolicy>` —
//! the exact dependency-inverted topology of [`crate::agent_tree::AgentTreeSnapshot`]
//! (CONTRACT-040): declared in shared-types, implemented by cap-lifecycle, consumed
//! by another crate with no compile-time edge to the provider.
//!
//! # Purpose
//! When an agent calls the WIT `remember(content, tags)` host function, `content` is
//! a free-form string. Data-responsibility single-source (REQ-210) and the
//! non-file-owned-insight rule (REQ-211) require that `knowledge.jsonl` NOT accumulate
//! verbatim copies of workspace files. This policy inspects the `remember()` CONTENT
//! (never `MemorySource` provenance — so L6 synthesis FileRef-sourced entries, which
//! do NOT flow through the `remember()` host path, are unaffected) and rejects content
//! detected as raw file-resident bytes.
//!
//! # Implementer Invariants
//! - **Content only.** Decide solely from the `content` string (and, if scoping to a
//!   specific agent's workspace, the `agent_id`). NEVER inspect memory provenance.
//! - **Bounded.** A `check_content` call MUST do a bounded amount of work regardless of
//!   workspace size (file-count / entry-count / depth / total-bytes caps).
//! - **Fail OPEN.** An implementation MUST NOT return [`RememberDecision::Reject`] as a
//!   result of an I/O error, resource-budget exhaustion, or ambiguity — treat any such
//!   condition as non-matching (skip the failing entry, or stop the scan) and ultimately
//!   `Allow`. A guard that cannot decide must not block a legitimate `remember()`.
//!   Availability of the write path outranks enforcement (this is a best-effort
//!   producer-boundary heuristic, not a security boundary).
//! - **Blocking I/O is permitted** but the consumer runs `check_content` on a blocking
//!   thread; implementations MUST NOT assume they are on an async reactor.

/// The verdict of a [`RememberContentPolicy::check_content`] call.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RememberDecision {
    /// Store the entry (the common case; also the fail-open result).
    Allow,
    /// Refuse the `remember()` — `content` is detected as raw file-resident bytes.
    /// The `String` is a human-readable reason; the cap-memory consumer lowers it to
    /// the WIT `memory-error::storage-error(string)` case (no ABI widen).
    Reject(String),
}

/// CONTRACT-214 — producer-boundary policy on the agent `remember()` write path.
///
/// Canonical source: `crates/shared-types/src/producer_boundary.rs` (re-exported from
/// `crate::traits`). Provider: MODULE-005 (`cap_lifecycle::WorkspaceFileResidentPolicy`).
/// Consumer: MODULE-011 (`cap_memory::RememberHandler`), dependency-inverted.
pub trait RememberContentPolicy: Send + Sync {
    /// Inspect a guest `remember()` CONTENT string. [`RememberDecision::Allow`] stores
    /// it; [`RememberDecision::Reject`] refuses it (content is raw file-resident bytes).
    ///
    /// `agent_id` is the calling agent's identifier — a per-agent implementation may use
    /// it to scope the check to that agent's workspace; a fixed-root implementation may
    /// ignore it.
    ///
    /// See the module-level Implementer Invariants: content-only, bounded, fail-open.
    fn check_content(&self, agent_id: &str, content: &str) -> RememberDecision;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    struct AllowAll;
    impl RememberContentPolicy for AllowAll {
        fn check_content(&self, _agent_id: &str, _content: &str) -> RememberDecision {
            RememberDecision::Allow
        }
    }

    struct RejectFixed(&'static str);
    impl RememberContentPolicy for RejectFixed {
        fn check_content(&self, _agent_id: &str, content: &str) -> RememberDecision {
            if content == self.0 {
                RememberDecision::Reject(format!(
                    "rejected fixed content of {} bytes",
                    content.len()
                ))
            } else {
                RememberDecision::Allow
            }
        }
    }

    #[test]
    fn allow_all_stub_allows() {
        let p: Arc<dyn RememberContentPolicy> = Arc::new(AllowAll);
        assert_eq!(
            p.check_content("agent:a", "anything at all"),
            RememberDecision::Allow
        );
    }

    #[test]
    fn reject_fixed_stub_discriminates() {
        let p: Arc<dyn RememberContentPolicy> = Arc::new(RejectFixed("SECRET-FILE-BYTES"));
        assert_eq!(
            p.check_content("agent:a", "a genuine insight"),
            RememberDecision::Allow
        );
        match p.check_content("agent:a", "SECRET-FILE-BYTES") {
            RememberDecision::Reject(reason) => assert!(reason.contains("17 bytes")),
            other => panic!("expected Reject, got {other:?}"),
        }
    }

    #[test]
    fn decision_equality() {
        assert_eq!(RememberDecision::Allow, RememberDecision::Allow);
        assert_ne!(
            RememberDecision::Allow,
            RememberDecision::Reject("x".into())
        );
        assert_eq!(
            RememberDecision::Reject("same".into()),
            RememberDecision::Reject("same".into())
        );
    }
}
