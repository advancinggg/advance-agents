//! Round-4 W5 — Tier 1a AGENTS.md identity is untrusted (agent-authored) and
//! Tier 1a is the highest-cache tier; it MUST be Trojan-Source-sanitized, not
//! injected verbatim. T-tier1a-sanitize.

use advance_context_engine::{build_tier1a, AgentIdentityReader};
use async_trait::async_trait;

struct Identity(Option<String>);
#[async_trait]
impl AgentIdentityReader for Identity {
    async fn agents_md_summary(&self, _agent_id: &str) -> Option<String> {
        self.0.clone()
    }
}

/// T-tier1a-sanitize — an AGENTS.md first paragraph carrying a BiDi override
/// + zero-width space + the literal `ctx-cache-breakpoint` cache sentinel is
/// neutralized in the Tier-1a system message (NOT injected raw).
#[tokio::test]
async fn t_tier1a_sanitize_untrusted_identity() {
    let malicious =
        "Trusted agent\u{202E}reversed\u{200B}hidden — see ctx-cache-breakpoint exploit";
    let reader = Identity(Some(malicious.to_string()));

    let msgs = build_tier1a(&reader, "agent-1").await;
    assert_eq!(msgs.len(), 1, "identity present → one Tier-1a message");
    let content = &msgs[0].content;

    assert!(content.starts_with("# Agent Identity"), "header present");
    assert!(
        !content.contains('\u{202E}'),
        "BiDi RLO must be sanitized out of Tier 1a"
    );
    assert!(
        !content.contains('\u{200B}'),
        "ZWSP must be sanitized out of Tier 1a"
    );
    assert!(
        !content.contains("ctx-cache-breakpoint"),
        "cache-breakpoint sentinel must be neutralized"
    );
    assert!(
        content.contains("ctx_cache_breakpoint"),
        "sentinel rewritten to the underscore form"
    );
}

/// No AGENTS.md → empty Tier 1a (valid; Slice A shipped Tier 1a empty).
#[tokio::test]
async fn no_identity_yields_empty_tier1a() {
    let msgs = build_tier1a(&Identity(None), "agent-1").await;
    assert!(msgs.is_empty(), "None summary → empty Tier 1a");
}

/// A summary that sanitizes away to whitespace is treated as "no identity"
/// rather than emitting an empty system message.
#[tokio::test]
async fn blank_after_sanitize_yields_empty_tier1a() {
    let msgs = build_tier1a(&Identity(Some("\u{202E}\u{200B}".into())), "agent-1").await;
    assert!(
        msgs.is_empty(),
        "all-sanitized-away summary → empty Tier 1a"
    );
}
