//! MODULE-010 context-engine canonical dependency-inversion surface.
//!
//! Canonical source: `docs/modules/MODULE-010-context-engine.md` §2.3
//! (ContextAssembler + AssemblyContext + AssemblyResult + LlmMessage +
//! TierTokenCounts + AssemblyError).
//!
//! `AgentState` is canonically declared in [`crate::agent_tree`] (MODULE-005
//! owner); this module uses it privately via `use crate::agent_tree::AgentState`
//! (NOT `pub use` — the canonical public path is
//! `advance_shared_types::agent_tree::AgentState`).
//!
//! Verbatim hoist — if the owner module's declaration changes, run
//! `/spec MODULE-010` and re-hoist via a follow-on /dev slice.
//!
//! # Security posture
//!
//! - **`AssemblyContext.prompt: String` bounded-field**: the raw user prompt
//!   before sanitization. Callers at the deserialize boundary MUST cap at
//!   ≤ 64 KiB (recommended) BEFORE materializing to prevent
//!   allocation-based DoS in the assembler.
//! - **`AssemblyResult.messages` attacker-influenced content**: the
//!   assembled `Vec<LlmMessage>` contains attacker-influenced content when
//!   the inbound `Message.payload` originates from an untrusted channel.
//!   The `ContextAssembler::assemble` implementation MUST route untrusted
//!   sections through [`crate::security_validator::PromptInjectionHelpers`]
//!   before emitting — this module's types cannot enforce that structurally.
//! - **Error payload PII policy**: [`AssemblyError`] 3 variants carry
//!   `String` payloads — operator-facing, same PII exclusion rule as
//!   [`crate::mailbox::MsgError`].

use crate::agent_tree::AgentState;
use crate::mailbox::Message;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

/// MODULE-010 §2.3 — minimal LLM message record for assembled Tier-N
/// context. v1 minimal: role/content pair matching industry-standard chat
/// schema. `name` / `tool_calls` / `attachments` deferred additively to
/// MODULE-010 concrete-impl slice.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LlmMessage {
    pub role: String,
    pub content: String,
}

/// The first line of the ⑯ section of the task's recent turns in an assembled context.
pub const RECENT_TURNS_HEADING: &str = "# Recent Turns\n";
/// The first line of the section of the task's recent-turn digests (L2).
pub const RECENT_TURN_DIGESTS_HEADING: &str = "# Recent Turn Digests\n";
/// The first line of the section of the task's epoch summary (L3).
pub const EPOCH_SUMMARY_HEADING: &str = "# Epoch Summary\n";
/// The first line of the ⑯ section of the task's earlier turns the query recalled, loaded whole.
pub const EARLIER_TURNS_HEADING: &str = "# Earlier Turns\n";
/// The first line of the ⑯ section of other tasks' turns the query recalled (PRD §11.3.5
/// "跨 Task 历史").
pub const RELATED_TURNS_HEADING: &str = "# Related Turns\n";

/// The first lines of the Tier 3 history sections of an assembled context: the task's recent
/// turns, their digests, its epoch summary, its earlier turns and other tasks' turns the query
/// recalled. The context engine opens each of these system messages with one of them, and no
/// other; the gateway takes these sections out first when a turn's request outgrows the
/// model's window (MODULE-010 S6), so Tier 1 and Tier 2, the cache prefix, stay as they were
/// sent.
pub const TIER3_HISTORY_HEADINGS: [&str; 5] = [
    RECENT_TURNS_HEADING,
    RECENT_TURN_DIGESTS_HEADING,
    EPOCH_SUMMARY_HEADING,
    EARLIER_TURNS_HEADING,
    RELATED_TURNS_HEADING,
];

/// Whether `content` is one of the Tier 3 history sections ([`TIER3_HISTORY_HEADINGS`]).
pub fn is_tier3_history(content: &str) -> bool {
    TIER3_HISTORY_HEADINGS
        .iter()
        .any(|heading| content.starts_with(heading))
}

/// MODULE-010 §2.3:385-394 — per-tier token accounting. Four fields mirror
/// §1.3 tier model (Tier 1a static / 1b dynamic / Tier 2 session / Tier 3
/// per-call). Tier 4 compression metadata is not materialized here —
/// MODULE-011 L-level compression emits its own events.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TierTokenCounts {
    /// Tier 1a "Static" — per-agent lifetime, aggressively cacheable.
    pub tier1a: u32,
    /// Tier 1b "Dynamic" — per-mode, still high-cacheability.
    pub tier1b: u32,
    /// Tier 2 "Session" — stable between turns within a session.
    pub tier2: u32,
    /// Tier 3 "Per-call" — changes every call; no caching.
    pub tier3: u32,
}

/// MODULE-010 §2.3:398 — ContextAssembler failure modes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AssemblyError {
    BudgetExhausted(String),
    EmbeddingFailed(String),
    MemoryStoreFailure(String),
}

/// MODULE-010 §2.3:324-332 — assembly input context. Passed to
/// [`ContextAssembler::assemble`]. 7 fields matching the owner canonical form.
///
/// **Implementer Invariants**: bounded `turn_buffer` length (recommended
/// ≤ 1024 entries); bounded `prompt` (≤ 64 KiB per module-level security
/// posture above; prompts can legitimately be multi-KiB for
/// retrieval-augmented context, so a 256-byte cap would be too strict
/// for real workloads); bounded `model` (≤ 256 bytes — short identifier).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssemblyContext {
    pub agent_id: String,
    pub task_id: Option<String>,
    /// Canonical shape: MODULE-006 §2.3.
    pub message: Message,
    /// Raw user prompt (pre-sanitization); used for Tier 3 wrapping.
    pub prompt: String,
    pub model: String,
    pub turn_buffer: Vec<LlmMessage>,
    /// Canonical shape: MODULE-005 §2.3.
    pub prior_state: AgentState,
}

/// MODULE-010 §2.3:334-340 — assembly output. Delivered to MODULE-014
/// AgentLoopDriver, which forwards `messages` to MODULE-009 `llm.generate`
/// and consumes `tier_token_counts` for budget telemetry.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssemblyResult {
    pub messages: Vec<LlmMessage>,
    /// "search" | "llm" | "current" (the agent's current task: routing could not settle one).
    pub routing_method: String,
    pub routing_confidence: f32,
    pub is_new_task: bool,
    pub tier_token_counts: TierTokenCounts,
    /// The task the turn runs in (PRD §11.3.1): the one the message names, the one routing
    /// chose, one minted for a new task, or the agent's current task when routing could not
    /// settle one. `None`: the agent's default partition (a control, system or auto message
    /// that names no task, or no current task to fall back to). The agent loop binds it onto
    /// the message, so the turn is logged and post-processed under it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub task_id: Option<String>,
}

/// CONTRACT-090 — context-engine trait. MODULE-010 §2.3:309-322.
/// Mixed-async (async `assemble` + sync `inject_tier3_warning`). Consumed by
/// MODULE-014 agent-loop driver (pre-turn assembly) and MODULE-008
/// RepetitionGuard (Tier 3 repetition-warn inject path).
///
/// # Implementer Invariants
///
/// 1. **Cache-aware**: Tier 1a static content cached across calls; Tier 2
///    session-scoped; Tier 3 per-call. Implementer MUST honor cache
///    breakpoints per MODULE-010 §1.3.
/// 2. **No LLM call inside `inject_tier3_warning`**: this method is a pure
///    buffer append — no network, no LLM generate. Bounded mutation.
/// 3. **Bounded turn-buffer mutation**: `inject_tier3_warning` MUST NOT
///    grow the internal Tier 3 buffer past MODULE-010's cap (recommended
///    ≤ 1024 entries).
/// 4. **Identifier validation**: `agent_id` must be whitelist-validated.
#[async_trait]
pub trait ContextAssembler: Send + Sync {
    async fn assemble(&self, ctx: AssemblyContext) -> Result<AssemblyResult, AssemblyError>;
    fn inject_tier3_warning(&self, agent_id: &str, msg: &str);
}
