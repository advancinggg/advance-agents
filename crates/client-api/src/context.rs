//! CONTRACT-190 context-inspection family.
//!
//! `GET /client/agents/{agent_id}/context` — the latest assembled prompt of an agent, broken
//! down by tier and section, with the budget / progressive-mode decision, routing and recall
//! telemetry, the embedding posture and the size of the agent's turn / task embedding index.
//! Read-only; the provider projects the MODULE-010 `AssemblyReport` the composition root
//! records on every `assemble()` (no prompt TEXT crosses the API — only labels + sizes).
//!
//! Token figures are the assembler's own estimate (bytes / 4, the same rule its
//! `tier_token_counts` use), not a provider tokenizer count — `estimate` says so on the wire.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::agents::validate_agent_id;
use crate::api::{ClientApi, HandlerSpec};
use crate::provider::{provider_or_unavailable, ContextProviderSlot, ProviderError};
use crate::request::Method;
use crate::routes;
use crate::session::Scope;

/// Token estimate rule the figures below use.
pub const CONTEXT_TOKEN_ESTIMATE: &str = "approx-bytes-div-4";

/// Per-tier token totals of one assembled prompt (MODULE-010 `TierTokenCounts`).
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ClientContextTierTokens {
    /// Tier 1a — static (identity, architecture, security model).
    pub tier1a: u32,
    /// Tier 1b — dynamic (runtime state, child roster, knowledge map).
    pub tier1b: u32,
    /// Tier 2 — session (skills, tools, delegates, decomposition, task summary / briefs).
    pub tier2: u32,
    /// Tier 3 — per-call (history, digests, recall, warnings, prompt).
    pub tier3: u32,
}

/// One assembled message, attributed to its tier.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ClientContextSection {
    /// `1a` | `1b` | `2` | `3`.
    pub tier: String,
    /// The section heading (`Agent Identity`, `Available Tools`, …) or a role-derived label
    /// (`history turn`, `warning`, `user prompt`, `cache breakpoint`).
    pub label: String,
    pub role: String,
    pub tokens: u32,
    pub bytes: u32,
}

/// How the turn was routed.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ClientContextRouting {
    /// `search` | `llm`.
    pub method: String,
    /// Top-1 task similarity behind the decision (`0` when no task matched / no routing ran).
    pub confidence: f32,
    pub is_new_task: bool,
}

/// Recall (embedding search) hit counts for the latest assembly.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ClientContextRecall {
    /// A query embedding was requested (non-blank prompt + embedding provider).
    pub attempted: bool,
    pub tasks: u32,
    pub turns: u32,
    pub contents: u32,
    pub memories: u32,
}

/// History / multi-level digest usage for the latest assembly.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ClientContextHistory {
    pub turn_buffer_in: u32,
    pub turn_buffer_kept: u32,
    pub l0_compressed: u32,
    pub l2_digests: u32,
    pub l3_epoch: bool,
    pub l4_task_summary: bool,
    pub l5_related_briefs: u32,
}

/// The latest assembled prompt of an agent.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ClientContextAssembly {
    /// RFC3339.
    pub assembled_at: String,
    /// Monotonic per-agent assembly counter (increments once per assembled turn).
    pub sequence: u64,
    pub message_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trace_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub task_id: Option<String>,
    pub model: String,
    pub model_context_window: u32,
    pub response_reserve: u32,
    pub budget_tokens: u32,
    /// `tier1a + tier1b + tier2 + tier3`.
    pub used_tokens: u32,
    pub remaining_tokens: u32,
    /// `used_tokens / budget_tokens` in `[0, 1]` (`1` when the budget is zero).
    pub used_ratio: f32,
    /// `wide` | `medium` | `compact` | `extreme`.
    pub progressive_mode: String,
    /// The budget-overflow guard produced the degraded (identity + prompt) set.
    pub degraded: bool,
    pub tiers: ClientContextTierTokens,
    pub sections: Vec<ClientContextSection>,
    pub routing: ClientContextRouting,
    pub recall: ClientContextRecall,
    pub history: ClientContextHistory,
    pub prompt_bytes: u32,
    pub warnings: u32,
}

/// The embedding posture behind recall + task routing.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ClientContextEmbedding {
    /// A real embedding provider backs the query + the turn-end index writes.
    pub active: bool,
    /// The embedding model id when active.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
}

/// The agent's turn / task embedding index (rows the turn-end pipeline wrote).
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ClientContextIndex {
    pub turns: u32,
    pub tasks: u32,
}

/// The `GET /client/agents/{agent_id}/context` response payload.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ClientContextSnapshot {
    pub agent_id: String,
    /// Token estimate rule (`approx-bytes-div-4`).
    pub estimate: String,
    /// `null` until the agent has assembled its first turn.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latest: Option<ClientContextAssembly>,
    pub embedding: ClientContextEmbedding,
    pub index: ClientContextIndex,
}

/// Context-inspection provider (MODULE-010 `AssemblyReport` projection). The adapter owns the
/// per-agent latest-report store the composition root feeds, the alias mapping (a client
/// names the bare agent handle; the assembler reports under the colon routing id) and the
/// embedding / index posture. An unknown agent is `NotFound`.
pub trait ContextInspectProvider: Send + Sync {
    fn snapshot(&self, agent_id: &str) -> Result<ClientContextSnapshot, ProviderError>;
}

/// Register the context-inspection route, capturing the shared provider slot in the closure.
pub(crate) fn register(api: &mut ClientApi, slot: ContextProviderSlot) {
    // GET /client/agents/{agent_id}/context — read-only; `ReadRuns` like the other per-agent
    // telemetry reads (runs, agents-md).
    let s = slot.clone();
    api.register_templated(
        Method::Get,
        routes::TPL_AGENT_CONTEXT,
        HandlerSpec::read(true, move |ctx| {
            let agent_id = ctx.path_param("agent_id")?;
            validate_agent_id(&agent_id)?;
            let provider = provider_or_unavailable(&s)?;
            let snapshot = provider
                .snapshot(&agent_id)
                .map_err(ProviderError::into_client_error)?;
            Ok(serde_json::to_value(snapshot).expect("ClientContextSnapshot serializes"))
        })
        .with_scopes(vec![Scope::ReadRuns]),
    );
}
