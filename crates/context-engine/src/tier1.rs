//! Tier 1a / Tier 1b builders (Slice B narrow population).
//!
//! Slice A left Tier 1a + Tier 1b as empty placeholders. Slice B fills the
//! two narrow slots this slice owns:
//! - **Tier 1a**: the AGENTS.md identity document (via
//!   [`AgentIdentityReader`]).
//! - **Tier 1b**: the knowledge-map section (AC-16, via
//!   [`KnowledgeMapReader`] + [`crate::knowledge_map`]).
//!
//! Broader Tier 1a/1b population (architecture component usage, security
//! model, capability config, mode state, runtime info, child roster ⑥, …)
//! stays a future-slice concern. AC-05's 4-tier structural property is
//! unaffected — these builders only add content WITHIN Tier 1a/1b; the two
//! cache-breakpoint markers and their positions are unchanged (T06 +
//! `tier_counts_include_cache_breakpoint_marker_tokens` lock that).
//!
//! **Security (MODULE-010 §3.8 Slice-B)**: AGENTS.md is an agent-authored,
//! **untrusted** file and Tier 1a is the highest-cache, per-agent-lifetime
//! tier — the worst place for an unsanitized injection. `build_tier1a`
//! routes the document through the shared `pub(crate)`
//! [`crate::tier2::sanitize_identity_document`] Trojan-Source defense, NOT
//! verbatim (newlines are kept so Markdown structure survives).
//! Knowledge-map topic/synthesis text is likewise untrusted and is sanitized
//! inside [`crate::knowledge_map::build_knowledge_map_section`].

use advance_shared_types::context::LlmMessage;

use crate::knowledge_map::build_knowledge_map_section;
use crate::ports::{AgentIdentityReader, KnowledgeMapReader};
use crate::tier2::sanitize_identity_document;

/// Tier 1a static slot: the sanitized AGENTS.md identity document. Returns an
/// empty `Vec` when the agent has no AGENTS.md (`reader` yields `None`) — an
/// empty Tier 1a is valid (Slice A shipped it empty); AC-05 structural
/// property is preserved either way.
pub async fn build_tier1a(reader: &dyn AgentIdentityReader, agent_id: &str) -> Vec<LlmMessage> {
    match reader.agents_md_summary(agent_id).await {
        Some(document) => {
            let safe = sanitize_identity_document(&document);
            // An all-sanitized-away / blank document is treated as "no
            // identity" rather than emitting an empty system message.
            if safe.trim().is_empty() {
                Vec::new()
            } else {
                vec![LlmMessage {
                    role: "system".into(),
                    content: format!("# Agent Identity\n\n{safe}"),
                }]
            }
        }
        None => Vec::new(),
    }
}

/// Tier 1b dynamic slot: the knowledge-map section (AC-16). Returns an empty
/// `Vec` when there is no knowledge map or it has no topics/syntheses. The
/// section's token estimate is bounded by
/// `min(budget, KNOWLEDGE_MAP_MAX_TOKENS)` (§1.3.3 ⑨ hard cap).
pub async fn build_tier1b(
    km_reader: &dyn KnowledgeMapReader,
    agent_id: &str,
    budget_tokens: usize,
) -> Vec<LlmMessage> {
    let Some(km) = km_reader.read_knowledge_map(agent_id).await else {
        return Vec::new();
    };
    if km.topics.is_empty() && km.task_syntheses.is_empty() {
        return Vec::new();
    }
    let (section, _truncated) = build_knowledge_map_section(&km, budget_tokens);
    vec![LlmMessage {
        role: "system".into(),
        content: section,
    }]
}
