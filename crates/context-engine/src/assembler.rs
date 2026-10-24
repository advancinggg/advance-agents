//! [`ContextAssemblerImpl`] — CONTRACT-090 implementation.
//!
//! Orchestrates the 4-tier assembly per MODULE-010 §1.3.7:
//! - **Tier 1a (static)**: the AGENTS.md identity document
//!   ([`crate::tier1::build_tier1a`]) followed by the runtime architecture ②
//!   and security model ③ sections ([`crate::tier1_runtime`]) — all three
//!   omit-when-empty.
//! - **Tier 1b (dynamic)**: the runtime state ⑦/⑧ section (mode / model /
//!   window / declared capabilities), the direct-`Child` roster ⑥
//!   ([`crate::tier1_children`]) and the knowledge-map section ⑨ (AC-16;
//!   [`crate::tier1::build_tier1b`]).
//! - **Tier 2 (session)**: ⑩ skills, ⑪/⑫ the AC-18 unified `# Available Tools`
//!   view ([`crate::tier2`]), ⑬ `# Available Delegates`
//!   ([`crate::tier2_delegates`]), ⑭ the active task decomposition
//!   ([`crate::tier2_decomposition`]) + the L4 `# Task Summary` + the L5
//!   `# Task Syntheses` (related task briefs, max 3) — all before the 2→3
//!   cache breakpoint because they are stable within a task.
//! - **Tier 3 (per-call)**: the L0-compressed, progressive-mode-bounded
//!   `ctx.turn_buffer`, the L2 `# Recent Turn Digests` + L3 `# Epoch Summary`,
//!   the query-dependent `# Recalled Context`, the drained warning queue and
//!   the current prompt.
//!
//! Two cache-breakpoint markers (`<!-- ctx-cache-breakpoint:1b->2 -->` and
//! `:2->3 -->`) between Tier 1b/Tier 2 and Tier 2/Tier 3 (AC-05) — positions
//! and token attribution unchanged from Slice A.
//!
//! **One query embedding per turn**: the prompt is embedded at most ONCE per
//! `assemble()` (a per-call memoizing wrapper over the injected
//! [`EmbeddingPort`]) and shared by the L1 vector lookup, the unified-search
//! recall and the [`crate::task_router::TaskRouter`]. A blank prompt embeds
//! nothing (no recall, no routing call).
//!
//! Routing: when `ctx.task_id.is_none()` (new-task entry path) the assembler
//! runs the `TaskRouter` over the prompt to refine `is_new_task`, and reports
//! the real `routing_method` (`search` | `llm`) + `routing_confidence` (top-1
//! similarity). A routing failure degrades gracefully (§2.8 intent: "fall
//! back", not "abort assembly") — assembly still returns a valid result with
//! `is_new_task = true`.
//!
//! Every successful assembly also produces an [`AssemblyReport`] (per-section
//! sizes, mode, budget, recall / history telemetry) delivered to the optional
//! [`AssemblyReportSink`] — the source of the Client API context inspector.

use std::sync::{Arc, Mutex};

use advance_shared_types::chrono::{DateTime, Utc};
use advance_shared_types::context::{
    AssemblyContext, AssemblyError, AssemblyResult, ContextAssembler, LlmMessage, TierTokenCounts,
};
use advance_shared_types::event::Event;
use advance_shared_types::security_validator::{PromptInjectionHelpers, TrustLevel};
use advance_shared_types::traits::{AgentTreeSnapshot, CallableInventoryReader, EventBusEmit};
use async_trait::async_trait;
use uuid::Uuid;

use crate::boundary_marker::layer2_wrap;
use crate::inventory::{HostFnInventoryReader, NativeToolsPort, NeverNativeTools};
use crate::knowledge_map::KNOWLEDGE_MAP_MAX_TOKENS;
use crate::l0_bridge::compress_turn_buffer;
use crate::ports::{
    AgentIdentityReader, AssemblyHistoryReport, AssemblyRecallReport, AssemblyReport,
    AssemblyReportSink, AssemblySection, DecompositionReader, EmbeddingPort, KnowledgeMapReader,
    L2DigestReader, L3EpochReader, L4TaskSummaryReader, L5SynthesisReader, L6ConsolidationReader,
    LightLlmFallbackPort, MultiLevelContextDigest, PortError, RuntimeInfoReader, RuntimeInfoView,
    SkillSummaryReader, TaskIndexPort, UnifiedSearchPort, UnifiedSearchResult, VectorIndexReader,
};
use crate::processing_pipeline::{coordinate_processing, MultiLevelReaders};
use crate::recall_section::format_recall_section;
use crate::task_router::{TaskRouter, TaskRoutingDecision, ROUTING_METHOD_SEARCH};
use crate::tier1::{build_tier1a, build_tier1b};
use crate::tier1_children::format_available_children_section_with_aliases;
use crate::tier1_runtime::{
    format_runtime_architecture_section, format_runtime_state_section,
    format_security_model_section,
};
use crate::tier2::{
    assemble_unified, format_available_tools_section_compact_with_not_shown,
    format_available_tools_section_with_not_shown, neutralize_cache_breakpoint_markers,
    sanitize_description, UnifiedToolRecord,
};
use crate::tier2_decomposition::format_active_decomposition_section;
use crate::tier2_delegates::format_available_delegates_section_with_aliases;
use crate::tier2_skills::{format_available_skills_section, SKILL_BUDGET_TOKENS_DEFAULT};
use crate::tier3::{
    bound_tier3_turns, model_context_window, response_reserve, select_progressive_mode,
    ProgressiveMode,
};
use crate::warning_queue::{is_valid_agent_id, WarningQueue};

/// MODULE-010 internal cache-breakpoint marker between Tier 1b and Tier 2.
pub(crate) const TIER1B_TIER2_BREAKPOINT: &str = "<!-- ctx-cache-breakpoint:1b->2 -->";

/// MODULE-010 internal cache-breakpoint marker between Tier 2 and Tier 3.
pub(crate) const TIER2_TIER3_BREAKPOINT: &str = "<!-- ctx-cache-breakpoint:2->3 -->";

/// Stable, machine-parseable prefix attached to every
/// `AssemblyError::MemoryStoreFailure` payload emitted for input-validation
/// rejection (rather than a genuine M004 store outage). Downstream callers
/// (M009 cap-llm retry classifier, M014 agent-loop driver, observability
/// telemetry) should test `payload.starts_with(INPUT_VALIDATION_PREFIX)` to
/// distinguish the two failure modes without changing the CONTRACT-090
/// `AssemblyError` enum surface. Re-exported via `lib.rs`. See MODULE-010
/// §3.6 + §3.8 for rationale and the long-term `AssemblyError::InvalidInput`
/// variant plan.
pub const INPUT_VALIDATION_PREFIX: &str = "INPUT_VALIDATION";

/// Upper bound on L2 turn digests rendered into `# Recent Turn Digests`. The
/// reader (production: retention-reranked top-K) already bounds its output;
/// this is the render-side ceiling so a misbehaving reader cannot flood Tier 3.
const MAX_L2_RENDERED: usize = 24;

pub struct ContextAssemblerImpl {
    callable_inventory: Arc<dyn CallableInventoryReader>,
    host_fn_inventory: Arc<dyn HostFnInventoryReader>,
    // Slice-B injected ports.
    agent_identity: Arc<dyn AgentIdentityReader>,
    knowledge_map_reader: Arc<dyn KnowledgeMapReader>,
    agent_tree: Arc<dyn AgentTreeSnapshot>,
    embedding: Arc<dyn EmbeddingPort>,
    task_index: Arc<dyn TaskIndexPort>,
    light_llm: Arc<dyn LightLlmFallbackPort>,
    // Slice-B coordinator port (held for `unified_search` callers; the
    // coordinator itself is `crate::unified_search::UnifiedSearchCoordinator`,
    // constructed on demand from this + `embedding`).
    unified_search_port: Arc<dyn UnifiedSearchPort>,
    // Slice-D injected port — canonical CONTRACT-180 EventBusEmit (sync) for
    // the AC-12 `context.assembled` emission.
    event_bus: Arc<dyn EventBusEmit>,
    // Slice-V1-c injected port (11th dep) — visible-skill L0 summaries for the
    // AC-15 Tier-2 ⑩ `# Available Skills` section.
    skill_summary: Arc<dyn SkillSummaryReader>,
    // Stage-C SAT-A injected ports (12th–17th dep) — the 6 L1-L6 reader ports
    // driving the AC-06 `coordinate_processing` digest. The cap-memory-backed
    // adapters live downstream in cli (`context_wiring.rs`, dep-light
    // discipline); these fields are read-only inverted-dependency ports (the
    // AC-01 stateless property the `tests/stateless.rs` size guard defends is
    // preserved).
    l1_vector: Arc<dyn VectorIndexReader>,
    l2_digest: Arc<dyn L2DigestReader>,
    l3_epoch: Arc<dyn L3EpochReader>,
    l4_summary: Arc<dyn L4TaskSummaryReader>,
    l5_synthesis: Arc<dyn L5SynthesisReader>,
    l6_consolidation: Arc<dyn L6ConsolidationReader>,
    // Stage-C SAT-E injected port (18th dep) — canonical CONTRACT-114
    // PromptInjectionHelpers (shared-types). Drives the AC-14 layer-2 boundary
    // marking of the untrusted L4/L5 bodies + the recall section.
    prompt_injection: Arc<dyn PromptInjectionHelpers>,
    // Wave-12 Lane C injected port (19th dep) — the active task's non-orphaned
    // subtasks for the Tier-2 ⑭ "Active Task Decomposition" section.
    decomposition: Arc<dyn DecompositionReader>,
    // Runtime facts for Tier 1a ②/③ + Tier 1b ⑦/⑧. Defaults to a reader that
    // yields `None` (sections omitted) so the 19-arg `new()` callers are
    // byte-identical; the composition root installs the real one via
    // `with_runtime_info`.
    runtime_info: Arc<dyn RuntimeInfoReader>,
    // ADR 2026-10-24 D6 — compact `# Available Tools` when the placement
    // serializes a native `tools` array. Default NeverNativeTools (full form).
    native_tools: Arc<dyn NativeToolsPort>,
    // Optional per-turn inspection sink (`with_report_sink`).
    report_sink: Option<Arc<dyn AssemblyReportSink>>,
    // Optional explicit model window (`with_model_context_window`) — wins over
    // the `model_context_window` table when the composition root knows better.
    model_window_override: Option<usize>,
    // Internally constructed (NOT injected) — Slice-A inject_tier3_warning
    // buffer.
    warnings: Arc<WarningQueue>,
    // Wave-12 — the agent-id alias set {bare cap-id, colon msg-id} used to
    // match the Tier-1b ⑥ child roster + Tier-2 ⑬ delegates `node.parent`
    // AND drain the Tier-3 `WarningQueue`, bridging the colon/bare keying
    // split (production spawns record + the MODULE-008 RepetitionGuard injects
    // under the BARE cap-id, while `assemble()` runs under the COLON msg-id).
    // Empty ⇒ single-id (`ctx.agent_id`-only) behaviour, byte-identical to
    // pre-Wave-12. Set via `with_agent_id_aliases`; defaults empty in `new()`
    // (signature unchanged, so the existing direct `new()` callers are
    // untouched).
    agent_id_aliases: Vec<String>,
}

/// Default [`RuntimeInfoReader`] — no runtime facts → the three runtime
/// sections are omitted.
struct NoRuntimeInfo;
#[async_trait]
impl RuntimeInfoReader for NoRuntimeInfo {
    async fn runtime_info(&self, _agent_id: &str) -> Option<RuntimeInfoView> {
        None
    }
}

/// Per-`assemble()` memoizing [`EmbeddingPort`]: the FIRST `embed(text)`
/// forwards to the inner port; every later call with the SAME text returns the
/// cached result (Ok or Err). The L1 lookup, the recall coordinator and the
/// task router all embed the same prompt, so a real provider is hit once per
/// turn, not three times. `std::sync::Mutex` — never held across an await.
struct MemoEmbedding {
    inner: Arc<dyn EmbeddingPort>,
    cache: Mutex<Option<(String, Result<Vec<f32>, PortError>)>>,
}

impl MemoEmbedding {
    fn new(inner: Arc<dyn EmbeddingPort>) -> Self {
        Self {
            inner,
            cache: Mutex::new(None),
        }
    }
}

#[async_trait]
impl EmbeddingPort for MemoEmbedding {
    async fn embed(&self, text: &str) -> Result<Vec<f32>, PortError> {
        {
            let guard = self.cache.lock().unwrap_or_else(|p| p.into_inner());
            if let Some((cached_text, result)) = guard.as_ref() {
                if cached_text == text {
                    return result.clone();
                }
            }
        }
        let result = self.inner.embed(text).await;
        let mut guard = self.cache.lock().unwrap_or_else(|p| p.into_inner());
        *guard = Some((text.to_string(), result.clone()));
        result
    }
}

impl ContextAssemblerImpl {
    /// Construct with the 19 injected dependency ports. `warnings` is
    /// internally constructed. The callers of `new` are crate-internal test
    /// fixtures + the cli composition root (`context_wiring.rs`) — the
    /// signature growth is confined to this crate's `::new` (CONTRACT-090, the
    /// `ContextAssembler` trait, is UNCHANGED). Slice D added the 10th dep
    /// `event_bus` (canonical CONTRACT-180 `EventBusEmit`) for AC-12; Slice
    /// V1-c added the 11th dep `skill_summary` (`SkillSummaryReader`) for the
    /// AC-15 Tier-2 ⑩ L0 skill-summary section; **Stage-C SAT-A** added the 6
    /// L1-L6 reader ports (12th–17th) so `assemble()` can run
    /// `coordinate_processing` and fold the L0-L6 digest; **Stage-C SAT-E**
    /// adds the 18th dep `prompt_injection` (canonical CONTRACT-114
    /// `PromptInjectionHelpers`); **Wave-12 Lane C** adds the 19th dep
    /// `decomposition` (`DecompositionReader`). The runtime-info reader, the
    /// report sink and the model-window override are opt-in builders
    /// (`with_runtime_info` / `with_report_sink` / `with_model_context_window`).
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        callable_inventory: Arc<dyn CallableInventoryReader>,
        host_fn_inventory: Arc<dyn HostFnInventoryReader>,
        agent_identity: Arc<dyn AgentIdentityReader>,
        knowledge_map_reader: Arc<dyn KnowledgeMapReader>,
        agent_tree: Arc<dyn AgentTreeSnapshot>,
        embedding: Arc<dyn EmbeddingPort>,
        task_index: Arc<dyn TaskIndexPort>,
        light_llm: Arc<dyn LightLlmFallbackPort>,
        unified_search_port: Arc<dyn UnifiedSearchPort>,
        event_bus: Arc<dyn EventBusEmit>,
        skill_summary: Arc<dyn SkillSummaryReader>,
        l1_vector: Arc<dyn VectorIndexReader>,
        l2_digest: Arc<dyn L2DigestReader>,
        l3_epoch: Arc<dyn L3EpochReader>,
        l4_summary: Arc<dyn L4TaskSummaryReader>,
        l5_synthesis: Arc<dyn L5SynthesisReader>,
        l6_consolidation: Arc<dyn L6ConsolidationReader>,
        prompt_injection: Arc<dyn PromptInjectionHelpers>,
        decomposition: Arc<dyn DecompositionReader>,
    ) -> Self {
        Self {
            callable_inventory,
            host_fn_inventory,
            agent_identity,
            knowledge_map_reader,
            agent_tree,
            embedding,
            task_index,
            light_llm,
            unified_search_port,
            event_bus,
            skill_summary,
            l1_vector,
            l2_digest,
            l3_epoch,
            l4_summary,
            l5_synthesis,
            l6_consolidation,
            prompt_injection,
            decomposition,
            runtime_info: Arc::new(NoRuntimeInfo),
            native_tools: Arc::new(NeverNativeTools),
            report_sink: None,
            model_window_override: None,
            warnings: Arc::new(WarningQueue::new()),
            agent_id_aliases: Vec::new(),
        }
    }

    /// Compact `# Available Tools` when the agent's placement supports native
    /// tools (ADR 2026-10-24 D6). Default is full form.
    pub fn with_native_tools_port(mut self, port: Arc<dyn NativeToolsPort>) -> Self {
        self.native_tools = port;
        self
    }

    /// Wave-12 — set the agent-id alias set ({bare cap-id, colon msg-id}) used
    /// by `assemble()` to match the Tier-1b ⑥ child roster and Tier-2 ⑬
    /// delegates `node.parent` AND drain the Tier-3 `WarningQueue` (in ADDITION
    /// to `ctx.agent_id`). The cli composition root passes the production
    /// `query_aliases` (the SAME set already wired to the Tier-1b memory
    /// readers). Empty ⇒ unchanged single-id behaviour. `new()`'s signature is
    /// intentionally left unchanged.
    pub fn with_agent_id_aliases(mut self, aliases: Vec<String>) -> Self {
        self.agent_id_aliases = aliases;
        self
    }

    /// Install the runtime-info source for the Tier 1a `# Runtime Architecture`
    /// / `# Security Model` and Tier 1b `# Runtime State` sections. Without it
    /// (the default) the three sections are omitted.
    pub fn with_runtime_info(mut self, reader: Arc<dyn RuntimeInfoReader>) -> Self {
        self.runtime_info = reader;
        self
    }

    /// Install the per-turn [`AssemblyReport`] sink (the Client API context
    /// inspector's data source). Without it no report is produced.
    pub fn with_report_sink(mut self, sink: Arc<dyn AssemblyReportSink>) -> Self {
        self.report_sink = Some(sink);
        self
    }

    /// Override the model context window used for the budget (wins over the
    /// `model_context_window` table). `None` keeps the table.
    pub fn with_model_context_window(mut self, window: Option<usize>) -> Self {
        self.model_window_override = window;
        self
    }

    /// Swap the residual task-routing tie-break (default: first-candidate
    /// stub). Production installs a gateway-backed light completion.
    pub fn with_light_llm(mut self, port: Arc<dyn LightLlmFallbackPort>) -> Self {
        self.light_llm = port;
        self
    }

    /// Swap the L5 related-brief reader (default: empty). Production reads
    /// L6's `_knowledge_map.yaml` + `syntheses/*.md`.
    pub fn with_l5_synthesis(mut self, reader: Arc<dyn L5SynthesisReader>) -> Self {
        self.l5_synthesis = reader;
        self
    }

    /// Build a [`crate::unified_search::UnifiedSearchCoordinator`] sharing
    /// this assembler's embedding + search ports (AC-02 callable surface).
    /// `assemble()` uses a per-call memoized embedding instead (one embed per
    /// turn) — this accessor keeps the direct-call surface for tests/consumers.
    pub fn unified_search_coordinator(&self) -> crate::unified_search::UnifiedSearchCoordinator {
        crate::unified_search::UnifiedSearchCoordinator::new(
            self.embedding.clone(),
            self.unified_search_port.clone(),
        )
    }

    fn model_limit(&self, model: &str) -> usize {
        self.model_window_override
            .unwrap_or_else(|| model_context_window(model))
    }
}

#[async_trait]
impl ContextAssembler for ContextAssemblerImpl {
    async fn assemble(&self, ctx: AssemblyContext) -> Result<AssemblyResult, AssemblyError> {
        // CONTRACT-090 invariant 4: agent_id MUST be whitelist-validated.
        // Fail-closed here so a malformed `agent_id` cannot be propagated
        // into any reader/port. `AssemblyError` has no "input validation"
        // variant; the chosen workaround is `MemoryStoreFailure` with a
        // stable, machine-parseable prefix [`INPUT_VALIDATION_PREFIX`]. See
        // MODULE-010 §3.6 + §3.8.
        if !is_valid_agent_id(&ctx.agent_id) {
            return Err(AssemblyError::MemoryStoreFailure(format!(
                "{INPUT_VALIDATION_PREFIX}: invalid agent_id"
            )));
        }

        // Model window → budget. Needed by Tier 1b (`# Runtime State`), the
        // Tier-2 ⑩ skills cap and the Tier-3 progressive-load mode-select.
        let model_limit = self.model_limit(&ctx.model);
        let reserve = response_reserve(model_limit);
        let budget = model_limit.saturating_sub(reserve);

        // Runtime facts (one read; feeds Tier 1a ②/③ + Tier 1b ⑦/⑧).
        let runtime_info = self.runtime_info.runtime_info(&ctx.agent_id).await;

        // ── Tier 1a (static): sanitized AGENTS.md identity slot, then the
        // runtime architecture + security model (omit-when-empty).
        let mut tier1a = build_tier1a(self.agent_identity.as_ref(), &ctx.agent_id).await;
        if let Some(info) = &runtime_info {
            if let Some(arch) = format_runtime_architecture_section(info) {
                tier1a.push(system(arch));
            }
            if let Some(sec) = format_security_model_section(info) {
                tier1a.push(system(sec));
            }
        }

        // ── Tier 1b (dynamic): runtime state ⑦/⑧ → child roster ⑥ (direct
        // Child only; omitted when empty) → knowledge-map section ⑨ (AC-16;
        // the §1.3.3 ⑨ 500-token hard cap is enforced inside
        // `build_knowledge_map_section`).
        let mut tier1b = Vec::new();
        if let Some(info) = &runtime_info {
            if let Some(state) = format_runtime_state_section(info, model_limit, budget) {
                tier1b.push(system(state));
            }
        }
        if let Some(roster) = format_available_children_section_with_aliases(
            self.agent_tree.as_ref(),
            self.agent_identity.as_ref(),
            &ctx.agent_id,
            &self.agent_id_aliases,
        )
        .await
        {
            tier1b.push(system(roster));
        }
        tier1b.extend(
            build_tier1b(
                self.knowledge_map_reader.as_ref(),
                &ctx.agent_id,
                KNOWLEDGE_MAP_MAX_TOKENS,
            )
            .await,
        );

        // ── Query embedding (once per turn). A blank prompt embeds nothing:
        // no recall, no L1 lookup, no routing call. An embedding failure is
        // NOT an assembly failure (§2.8 "fall back, not abort").
        let memo: Arc<dyn EmbeddingPort> = Arc::new(MemoEmbedding::new(self.embedding.clone()));
        let prompt_blank = ctx.prompt.trim().is_empty();
        let query_embedding: Option<Vec<f32>> = if prompt_blank {
            None
        } else {
            match memo.embed(&ctx.prompt).await {
                Ok(v) if !v.is_empty() && v.iter().all(|c| c.is_finite()) => Some(v),
                _ => None,
            }
        };

        // ── L0-L6 multi-source digest (AC-06). L0 runs over the mapped
        // `turn_buffer` (the compressed history is rendered below); L1 gets the
        // shared query embedding (empty when none — the reader then yields no
        // hits); L2–L6 read the agent's memory artifacts for `task_id`.
        // `coordinate_processing` is fail-fast; degrade gracefully to an EMPTY
        // digest on any reader error (§2.8) via `unwrap_or_default`.
        let (compressed_history, l0_compressed) = compress_turn_buffer(&ctx.turn_buffer);
        let readers = MultiLevelReaders {
            vector: self.l1_vector.as_ref(),
            l2: self.l2_digest.as_ref(),
            l3: self.l3_epoch.as_ref(),
            l4: self.l4_summary.as_ref(),
            l5: self.l5_synthesis.as_ref(),
            l6: self.l6_consolidation.as_ref(),
        };
        let digest = coordinate_processing(
            &ctx.agent_id,
            ctx.task_id.as_deref().unwrap_or(""),
            &[],
            query_embedding.as_deref().unwrap_or(&[]),
            &readers,
        )
        .await
        .unwrap_or_default();

        // ── Tier 2 ⑩ (Slice V1-c, AC-15): visible skills' L0 summaries, capped
        // at min(skill_budget_tokens, ⌊budget·0.05⌋, 10_000) — AC-15 ceiling +
        // AC-27 default. Omitted entirely (no message) when there are no visible
        // skills.
        let skills = self.skill_summary.list_skill_summaries(&ctx.agent_id).await;
        let skill_cap = SKILL_BUDGET_TOKENS_DEFAULT
            .min((budget / 20) as u32) // ⌊budget·0.05⌋
            .min(10_000);
        let tier2_skills = format_available_skills_section(&skills, skill_cap);

        // ── Tier 2 (session): AC-18 tool view THEN AC-19 delegate section,
        // both before the 1b→2 breakpoint.
        let host_fns = self.host_fn_inventory.list_host_fns(&ctx.agent_id);
        let wasm_tools = self.callable_inventory.list_wasm_tools(&ctx.agent_id);
        // The MCP tools the inventory shows, and how many it leaves out (the section's
        // closing line counts them).
        let mcp = self.callable_inventory.mcp_tools_shown(&ctx.agent_id);
        let mcp_entries = mcp.tools.len();
        let unified = assemble_unified(host_fns, wasm_tools, mcp.tools);
        let tier2_tools = if self.native_tools.supports_native_tools(&ctx.agent_id) {
            format_available_tools_section_compact_with_not_shown(&unified, mcp.not_shown)
        } else {
            format_available_tools_section_with_not_shown(&unified, mcp.not_shown)
        };
        // Wave-12: match the ⑬ delegates `node.parent` against the agent's full
        // id-alias set ({ctx.agent_id} ∪ agent_id_aliases) so a Sub recorded
        // under the BARE cap-id surfaces for this COLON-keyed assemble turn.
        let tier2_delegates = format_available_delegates_section_with_aliases(
            self.agent_tree.as_ref(),
            &ctx.agent_id,
            &self.agent_id_aliases,
        );
        // Tier-2 order matches §1.3.3: ⑩ Skills → ⑪/⑫ (merged `# Available
        // Tools`) → ⑬ Delegates → ⑭ decomposition / task summary / related briefs.
        let mut tier2: Vec<LlmMessage> = Vec::with_capacity(6);
        if let Some(skills_content) = tier2_skills {
            tier2.push(system(skills_content));
        }
        let tools_at = tier2.len();
        tier2.push(system(tier2_tools));
        tier2.push(system(tier2_delegates));
        // ── Tier 2 ⑭ (Wave-12 Lane C): "Active Task Decomposition" — the active
        // task's non-orphaned subtasks. Omitted when empty.
        let decomposition_subtasks = self
            .decomposition
            .read_active_subtasks(&ctx.agent_id, ctx.task_id.as_deref())
            .await;
        if let Some(decomp_content) = format_active_decomposition_section(&decomposition_subtasks) {
            tier2.push(system(decomp_content));
        }
        // ── Tier 2 ⑭ Task Summary (L4) + Related Task Briefs (L5, max 3):
        // task-stable, so they live in the session tier (cacheable across the
        // turns of one task) rather than per-call Tier 3. Untrusted bodies are
        // boundary-wrapped (CONTRACT-114) + cache-marker-neutralized.
        let session_digest = render_session_digest(&digest, self.prompt_injection.as_ref());
        let l5_rendered = session_digest.l5_rendered;
        tier2.extend(session_digest.messages);

        // ── Tier 3 (per-call): progressive-load mode-select (Slice C,
        // AC-09) → bounded history → L2/L3 digest → recall → drained warnings
        // → prompt. Cache-breakpoint marker token sizes are needed for the
        // budget `used` estimate.
        let breakpoint_1_tokens = approx_tokens_str("system", TIER1B_TIER2_BREAKPOINT);
        let breakpoint_2_tokens = approx_tokens_str("system", TIER2_TIER3_BREAKPOINT);

        // Drain the repetition-warning queue ONCE (WarningQueue::drain is
        // destructive — `cache.pop`). Wave-12: drain across the agent's id-alias
        // set so a warning the MODULE-008 RepetitionGuard injected under the
        // BARE cap-id surfaces for this COLON-keyed assemble turn.
        let drained_warnings: Vec<String> = {
            let mut acc = self.warnings.drain(&ctx.agent_id);
            for alias in &self.agent_id_aliases {
                if alias != &ctx.agent_id {
                    acc.extend(self.warnings.drain(alias));
                }
            }
            acc
        };

        let warnings_tokens: u32 = drained_warnings.iter().fold(0u32, |acc, w| {
            acc.saturating_add(approx_tokens_str("system", w))
        });
        // The prompt is appended to Tier 3 ONLY when non-empty; the `used`
        // estimate mirrors that exactly (an empty prompt bills 0, not its
        // role bytes).
        let prompt_tokens = if ctx.prompt.is_empty() {
            0
        } else {
            approx_tokens_str("user", &ctx.prompt)
        };

        // L2 recent turn digests + L3 epoch summary (Tier 3 history layer).
        let recent_digest = render_recent_digest(&digest);
        let digest_tokens = approx_tokens(&recent_digest);

        // ── Tier 3 recall (Wave-13 Lane C, MODULE-010 §3.8): fold the
        // unified_search hits into Tier-3. Query-dependent, so it sits AFTER
        // the 2→3 breakpoint. Degrades gracefully to "no section".
        let recall_attempted = query_embedding.is_some();
        let recall: UnifiedSearchResult = if recall_attempted {
            crate::unified_search::UnifiedSearchCoordinator::new(
                memo.clone(),
                self.unified_search_port.clone(),
            )
            .unified_search(&ctx.agent_id, &ctx.prompt, ctx.task_id.as_deref())
            .await
            .unwrap_or_default()
        } else {
            UnifiedSearchResult::default()
        };
        let recall_messages: Vec<LlmMessage> =
            match format_recall_section(&recall, self.prompt_injection.as_ref()) {
                Some(content) => vec![system(content)],
                None => Vec::new(),
            };
        let recall_tokens = approx_tokens(&recall_messages);

        // Everything `used` counts but Tier-2 (saturating sums of non-negative
        // terms, so the order of the additions does not change the total).
        let used_but_tier2: u32 = approx_tokens(&tier1a)
            .saturating_add(approx_tokens(&tier1b))
            .saturating_add(breakpoint_1_tokens)
            .saturating_add(breakpoint_2_tokens)
            .saturating_add(prompt_tokens)
            .saturating_add(warnings_tokens)
            .saturating_add(digest_tokens)
            .saturating_add(recall_tokens);
        let mut used: u32 = used_but_tier2.saturating_add(approx_tokens(&tier2));

        // MCP tools give way first. When the content does not fit and the tools
        // section lists MCP tools, its last MCP entries (the inventory orders them
        // by priority) are left out, and counted by the section's closing line,
        // until it fits; the host functions, WASM tools, skills, delegates and the
        // decomposition stay. Only content that does not fit without any MCP entry
        // takes the degraded branch below. A section without MCP entries is never
        // re-rendered.
        if (used as usize) > budget && mcp_entries > 0 {
            let rest: usize = tier2
                .iter()
                .enumerate()
                .map(|(at, m)| m.role.len() + if at == tools_at { 0 } else { m.content.len() })
                .sum();
            let used_with = |section: &str| {
                used_but_tier2.saturating_add(chars_to_tokens(rest.saturating_add(section.len())))
            };
            if let Some(section) = fit_mcp_entries(&unified, mcp_entries, mcp.not_shown, |s| {
                (used_with(s) as usize) <= budget
            }) {
                used = used_with(&section);
                tier2[tools_at].content = section;
            }
        }

        // ── Budget-overflow guard (192 / §2.8; aligns with SYS-AC-192). When
        // the non-droppable fixed content `used` (which EXCLUDES the only
        // droppable history, `turn_buffer`) exceeds `budget`, even dropping all
        // history cannot fit — so return a DEGRADED extreme-mode `Ok` prompt
        // rather than a full one or a hard `Err(BudgetExhausted)` (the M014
        // agent-loop drops the turn on ANY assemble `Err`). The degraded set
        // keeps the Tier-1a identity + drained warnings + the current prompt
        // (truncated against the budget remaining after identity + warnings);
        // it DROPS Tier 1b, the Tier-2 session sections, the digest, the recall
        // and all history.
        let degraded = (used as usize) > budget;
        let mode: ProgressiveMode;
        let history_kept: usize;
        let (messages, tier_token_counts) = if degraded {
            mode = ProgressiveMode::Extreme;
            history_kept = 0;
            let identity_tokens = approx_tokens(&tier1a);
            let prompt_budget = budget
                .saturating_sub(identity_tokens as usize)
                .saturating_sub(warnings_tokens as usize);
            let degraded_prompt = truncate_prompt_to_tokens(&ctx.prompt, prompt_budget as u32);
            let mut dmsgs: Vec<LlmMessage> = Vec::with_capacity(
                tier1a
                    .len()
                    .saturating_add(drained_warnings.len())
                    .saturating_add(1),
            );
            dmsgs.extend(tier1a.iter().cloned());
            for w in &drained_warnings {
                dmsgs.push(system(w.clone()));
            }
            if !degraded_prompt.is_empty() {
                dmsgs.push(LlmMessage {
                    role: "user".into(),
                    content: degraded_prompt,
                });
            }
            // Degraded accounting: only Tier-1a + the Tier-3 essentials remain
            // (tier1b / tier2 dropped → 0). tier3 = whatever is NOT tier1a.
            let counts = TierTokenCounts {
                tier1a: identity_tokens,
                tier1b: 0,
                tier2: 0,
                tier3: approx_tokens(&dmsgs).saturating_sub(identity_tokens),
            };
            (dmsgs, counts)
        } else {
            let remaining = budget.saturating_sub(used as usize);
            mode = select_progressive_mode(remaining);

            // Tier-3 order: L0-compressed, mode-bounded history → L2/L3 digest
            // → recall → drained warnings → current prompt. The Slice-A
            // invariant (warning surfaces AFTER prior history but BEFORE the
            // current prompt) is preserved.
            let mut tier3 = bound_tier3_turns(&compressed_history, mode);
            history_kept = tier3.len();
            tier3.extend(recent_digest.iter().cloned());
            tier3.extend(recall_messages.iter().cloned());
            for w in &drained_warnings {
                tier3.push(system(w.clone()));
            }
            if !ctx.prompt.is_empty() {
                tier3.push(LlmMessage {
                    role: "user".into(),
                    content: ctx.prompt.clone(),
                });
            }

            let breakpoint_1 = system(TIER1B_TIER2_BREAKPOINT.to_string());
            let breakpoint_2 = system(TIER2_TIER3_BREAKPOINT.to_string());

            // round-10 ADVERSARIAL Critical 1 / Info 9: saturating arithmetic on
            // the capacity calculation and the tier-token sums.
            let capacity = tier1a
                .len()
                .saturating_add(tier1b.len())
                .saturating_add(1)
                .saturating_add(tier2.len())
                .saturating_add(1)
                .saturating_add(tier3.len());
            let mut messages: Vec<LlmMessage> = Vec::with_capacity(capacity);
            messages.extend(tier1a.iter().cloned());
            messages.extend(tier1b.iter().cloned());
            messages.push(breakpoint_1);
            messages.extend(tier2.iter().cloned());
            messages.push(breakpoint_2);
            messages.extend(tier3.iter().cloned());

            // Tier token accounting: each cache-breakpoint marker is attributed
            // to the tier it terminates (1b→2 → tier1b's count; 2→3 → tier2's
            // count) so `tier1a + tier1b + tier2 + tier3` sums to the assembled
            // prompt size.
            let tier_token_counts = TierTokenCounts {
                tier1a: approx_tokens(&tier1a),
                tier1b: approx_tokens(&tier1b).saturating_add(breakpoint_1_tokens),
                tier2: approx_tokens(&tier2).saturating_add(breakpoint_2_tokens),
                tier3: approx_tokens(&tier3),
            };
            (messages, tier_token_counts)
        };

        // Routing: only the new-task entry path (no task_id) consults the
        // router, and only with a non-blank prompt (nothing to route on
        // otherwise). The router shares the memoized query embedding. A routing
        // failure degrades gracefully (§2.8 "fall back", not "abort") —
        // assembly still succeeds; is_new_task defaults to true (the safe
        // default when no task_id was supplied).
        let (is_new_task, routing_method, routing_confidence) = if ctx.task_id.is_none() {
            if prompt_blank {
                (true, ROUTING_METHOD_SEARCH.to_string(), 0.0_f32)
            } else {
                let router = TaskRouter::new(
                    memo.clone(),
                    self.task_index.clone(),
                    self.light_llm.clone(),
                );
                match router.route_task_detailed(&ctx.agent_id, &ctx.prompt).await {
                    Ok(outcome) => (
                        matches!(outcome.decision, TaskRoutingDecision::NewTask),
                        outcome.method.to_string(),
                        outcome.confidence,
                    ),
                    Err(_) => (true, ROUTING_METHOD_SEARCH.to_string(), 0.0_f32),
                }
            }
        } else {
            // The caller already bound the turn to a task — no search ran.
            (false, ROUTING_METHOD_SEARCH.to_string(), 0.0_f32)
        };

        let result = AssemblyResult {
            messages,
            routing_method,
            routing_confidence,
            is_new_task,
            tier_token_counts,
        };

        // AC-12: emit the `context.assembled` event AFTER the result is built
        // so the payload captures the actual returned values. Uses the
        // CANONICAL CONTRACT-180 `EventBusEmit` (sync; non-blocking per the
        // trait's implementer invariants) + the canonical `Event` STRUCT
        // (`event_type` string discriminator — there is no
        // `Event::ContextAssembled` enum variant). `Event.id` is uuid v4.
        let trace_id = ctx
            .message
            .context
            .as_ref()
            .and_then(|c| c.trace_id.clone());
        let event = Event {
            id: Uuid::new_v4().to_string(),
            // chrono is pinned without the `clock` feature (workspace
            // `features = ["serde", "std"]`), so `Utc::now()` is unavailable;
            // the workspace idiom is `SystemTime::now().into()`.
            timestamp: DateTime::<Utc>::from(std::time::SystemTime::now()),
            agent_id: ctx.agent_id.clone(),
            task_id: ctx.task_id.clone(),
            run_id: None,
            execution_id: None,
            // Stage-F obs SLICE 1: thread the handle-message chain. trace_id reads
            // the chain trace minted at run_turn_once (fallback fresh-v4 when the
            // message carries no context); span_id is the deterministic chain-ROOT
            // span. parent_span_id stays None — this IS the chain root that
            // run.round_completed.parent_span_id links to (SYS-AC-138).
            trace_id: trace_id
                .clone()
                .unwrap_or_else(|| Uuid::new_v4().to_string()),
            span_id: advance_shared_types::event::chain_root_span_id(&ctx.message.id),
            parent_span_id: None,
            event_type: "context.assembled".into(),
            payload: serde_json::json!({
                "tier_token_counts": result.tier_token_counts,
                "routing_method": result.routing_method,
                "routing_confidence": result.routing_confidence,
                "is_new_task": result.is_new_task,
            }),
            duration_ms: None,
        };
        self.event_bus.emit(event);

        // Per-turn inspection report (the Client API context inspector).
        if let Some(sink) = &self.report_sink {
            let counts = &result.tier_token_counts;
            let used_tokens = counts
                .tier1a
                .saturating_add(counts.tier1b)
                .saturating_add(counts.tier2)
                .saturating_add(counts.tier3);
            sink.record(AssemblyReport {
                agent_id: ctx.agent_id.clone(),
                task_id: ctx.task_id.clone(),
                message_id: ctx.message.id.clone(),
                trace_id,
                model: ctx.model.clone(),
                model_context_window: clamp_u32(model_limit),
                response_reserve: clamp_u32(reserve),
                budget_tokens: clamp_u32(budget),
                used_tokens,
                remaining_tokens: clamp_u32(budget.saturating_sub(used_tokens as usize)),
                progressive_mode: mode_label(mode).to_string(),
                degraded,
                tier1a_tokens: counts.tier1a,
                tier1b_tokens: counts.tier1b,
                tier2_tokens: counts.tier2,
                tier3_tokens: counts.tier3,
                sections: label_sections(&result.messages, tier1a.len()),
                routing_method: result.routing_method.clone(),
                routing_confidence: result.routing_confidence,
                is_new_task: result.is_new_task,
                recall: AssemblyRecallReport {
                    attempted: recall_attempted,
                    tasks: clamp_u32(recall.tasks.len()),
                    turns: clamp_u32(recall.turns.len()),
                    contents: clamp_u32(recall.contents.len()),
                    memories: clamp_u32(recall.memories.len()),
                },
                history: AssemblyHistoryReport {
                    turn_buffer_in: clamp_u32(ctx.turn_buffer.len()),
                    turn_buffer_kept: clamp_u32(history_kept),
                    l0_compressed: clamp_u32(l0_compressed),
                    l2_digests: clamp_u32(digest.l2.len()),
                    l3_epoch: digest.l3.is_some(),
                    l4_task_summary: digest
                        .l4
                        .as_ref()
                        .is_some_and(|t| !t.summary.trim().is_empty()),
                    l5_related_briefs: clamp_u32(l5_rendered),
                },
                prompt_bytes: clamp_u32(ctx.prompt.len()),
                warnings: clamp_u32(drained_warnings.len()),
            });
        }

        Ok(result)
    }

    fn inject_tier3_warning(&self, agent_id: &str, msg: &str) {
        self.warnings.push(agent_id, msg);
    }
}

fn system(content: String) -> LlmMessage {
    LlmMessage {
        role: "system".into(),
        content,
    }
}

fn clamp_u32(v: usize) -> u32 {
    u32::try_from(v).unwrap_or(u32::MAX)
}

fn mode_label(mode: ProgressiveMode) -> &'static str {
    match mode {
        ProgressiveMode::Wide => "wide",
        ProgressiveMode::Medium => "medium",
        ProgressiveMode::Compact => "compact",
        ProgressiveMode::Extreme => "extreme",
    }
}

/// Attribute every assembled message to its tier and label it. `tier1a_len`
/// is the number of leading Tier-1a messages (the 1a/1b split is not visible
/// from the messages alone). The two breakpoint markers delimit 1b→2 and 2→3;
/// a degraded set (no markers) is `1a` for the first `tier1a_len` messages and
/// `3` for the rest.
fn label_sections(messages: &[LlmMessage], tier1a_len: usize) -> Vec<AssemblySection> {
    let last_user = messages.iter().rposition(|m| m.role == "user");
    let mut tier = "1a";
    let mut out = Vec::with_capacity(messages.len());
    for (idx, m) in messages.iter().enumerate() {
        if idx >= tier1a_len && tier == "1a" {
            tier = "1b";
        }
        let is_bp1 = m.content == TIER1B_TIER2_BREAKPOINT;
        let is_bp2 = m.content == TIER2_TIER3_BREAKPOINT;
        let label = if is_bp1 || is_bp2 {
            "cache breakpoint".to_string()
        } else if let Some(heading) = m.content.lines().next().filter(|l| l.starts_with("# ")) {
            sanitize_description(heading.trim_start_matches("# ").trim())
        } else if Some(idx) == last_user {
            "user prompt".to_string()
        } else if m.role == "system" && tier == "3" {
            "warning".to_string()
        } else {
            "history turn".to_string()
        };
        out.push(AssemblySection {
            tier: tier.to_string(),
            label,
            role: m.role.clone(),
            tokens: approx_tokens_str(&m.role, &m.content),
            bytes: clamp_u32(m.content.len()),
        });
        if is_bp1 {
            tier = "2";
        } else if is_bp2 {
            tier = "3";
        }
    }
    // A degraded set carries no markers: everything after Tier 1a is Tier 3.
    if !messages
        .iter()
        .any(|m| m.content == TIER1B_TIER2_BREAKPOINT)
    {
        for s in out.iter_mut().skip(tier1a_len) {
            s.tier = "3".to_string();
            if s.role == "system" && s.label == "history turn" {
                s.label = "warning".to_string();
            }
        }
    }
    out
}

/// The `# Available Tools` section of `records` with as many of its MCP entries as `fits`
/// takes, or `None` when it does not take the section even without any of them.
///
/// `records` ends in its `mcp_entries` MCP entries, in the order the inventory gave them,
/// and does not fit with all of them. The last ones are left out first; the section's
/// closing line counts them with the `not_shown` the inventory left out itself. The kept
/// count is found by bisection, a handful of renders.
fn fit_mcp_entries(
    records: &[UnifiedToolRecord],
    mcp_entries: usize,
    not_shown: usize,
    fits: impl Fn(&str) -> bool,
) -> Option<String> {
    let others = records.len() - mcp_entries;
    let render = |kept: usize| {
        format_available_tools_section_with_not_shown(
            &records[..others + kept],
            not_shown.saturating_add(mcp_entries - kept),
        )
    };
    let mut best = render(0);
    if !fits(&best) {
        return None;
    }
    // `fit` MCP entries fit; `over` do not.
    let (mut fit, mut over) = (0, mcp_entries);
    while over - fit > 1 {
        let kept = fit + (over - fit) / 2;
        let section = render(kept);
        if fits(&section) {
            fit = kept;
            best = section;
        } else {
            over = kept;
        }
    }
    Some(best)
}

/// Slice-A placeholder token estimator: chars/4 OpenAI-rule-of-thumb.
/// MODULE-009 tokenizer wiring will replace this in a later slice (AC-12
/// territory). Saturating math: `chars + 3` can only overflow on 32-bit at
/// ~4 GiB strings, which the deserialize boundary's 64 KiB prompt cap
/// prevents in practice.
fn approx_tokens(msgs: &[LlmMessage]) -> u32 {
    let chars: usize = msgs.iter().map(|m| m.role.len() + m.content.len()).sum();
    chars_to_tokens(chars)
}

fn approx_tokens_str(role: &str, content: &str) -> u32 {
    chars_to_tokens(role.len() + content.len())
}

/// `pub(crate)` so `crate::knowledge_map` shares the single token-estimate
/// rule (avoids a divergent `chars/4` copy that could desync the Tier-1b cap
/// math from this Tier-token accounting). Body is the shared leaf
/// (`advance_shared_types::token_estimate::tokens_from_bytes_u32`),
/// byte-identical to Slice A.
pub(crate) fn chars_to_tokens(chars: usize) -> u32 {
    advance_shared_types::token_estimate::tokens_from_bytes_u32(chars)
}

/// Stage-C SAT-E: the §1.4.3 ⑭ render bound for L5 "Related Task Briefs"
/// (`build_related_tasks(&ctx, 3)`, §1.4.7). At most this many non-empty
/// cross-task syntheses render into `# Task Syntheses`, which also bounds the
/// per-body `wrap_with_boundary` allocation independent of how many the L5
/// reader returns.
const MAX_L5_RELATED_TASKS: usize = 3;

/// Stage-C SAT-E adversarial-round hardening: bound the L5 render-time SCAN, not
/// just the wrap. `MAX_L5_RELATED_TASKS` caps how many non-empty syntheses are
/// wrapped, but the empty-skip `filter` runs BEFORE that `take`, so a misbehaving
/// or malicious L5 reader returning a flood of whitespace-only `body` entries
/// would otherwise force a `trim()` scan across the entire `digest.l5` Vec before
/// 3 non-empty are found. `MAX_L5_SCANNED` caps that scan: at most this many raw
/// entries are examined. It is generous headroom over the §2.11 reader contract
/// (max 5 task_syntheses) so a contract-compliant reader is never truncated; it
/// only bounds the pathological all-whitespace flood (CPU-DoS at the render site).
const MAX_L5_SCANNED: usize = 16;

/// The Tier-2 ⑭ rendering of the L4 task summary + L5 related briefs.
struct SessionDigest {
    messages: Vec<LlmMessage>,
    /// Non-empty L5 syntheses actually rendered (≤ `MAX_L5_RELATED_TASKS`).
    l5_rendered: usize,
}

/// Render the task-stable levels of the [`MultiLevelContextDigest`] — L4
/// `# Task Summary` and L5 `# Task Syntheses` (related task briefs) — for the
/// Tier-2 ⑭ slot. Empty levels emit NOTHING.
///
/// Untrusted-content treatment (MODULE-010 §3.8 Stage-C SAT-E, AC-14 live
/// producer path): each body is routed through the canonical CONTRACT-114
/// [`layer2_wrap`] / `wrap_with_boundary` (`TrustLevel::Untrusted`) — the
/// `<data source=".." trust="untrusted">…</data>` boundary envelope +
/// Critical-always / High-when-Untrusted span neutralization — followed by
/// [`neutralize_cache_breakpoint_markers`] to preserve the M009 gateway
/// cache-marker defense `wrap_with_boundary` does not replicate. Each body is
/// wrapped EXACTLY ONCE (CONTRACT-114 invariant 4); the skip-guard runs on the
/// RAW body BEFORE wrapping so an empty body emits nothing.
fn render_session_digest(
    digest: &MultiLevelContextDigest,
    helpers: &dyn PromptInjectionHelpers,
) -> SessionDigest {
    let mut out: Vec<LlmMessage> = Vec::new();

    // L4 — task summary (optional; UNTRUSTED body).
    if let Some(task) = &digest.l4 {
        if !task.summary.trim().is_empty() {
            let wrapped = neutralize_cache_breakpoint_markers(&layer2_wrap(
                &task.summary,
                "memory:l4_task_summary",
                TrustLevel::Untrusted,
                helpers,
            ));
            out.push(system(format!("# Task Summary\n{wrapped}")));
        }
    }

    // L5 — cross-task syntheses (UNTRUSTED bodies), the §1.4.3 ⑭ "Related Task
    // Briefs (L5, max 3)" bound: `take` AFTER the empty-skip so blanks don't
    // consume a slot, and BEFORE `map` so at most 3 bodies are ever wrapped;
    // the leading `take(MAX_L5_SCANNED)` bounds the scan itself.
    let l5_blocks: Vec<String> = digest
        .l5
        .iter()
        .take(MAX_L5_SCANNED)
        .filter(|s| !s.body.trim().is_empty())
        .take(MAX_L5_RELATED_TASKS)
        .map(|s| {
            neutralize_cache_breakpoint_markers(&layer2_wrap(
                &s.body,
                "memory:l5_synthesis",
                TrustLevel::Untrusted,
                helpers,
            ))
        })
        .collect();
    let l5_rendered = l5_blocks.len();
    if !l5_blocks.is_empty() {
        out.push(system(format!(
            "# Task Syntheses\n{}",
            l5_blocks.join("\n")
        )));
    }

    SessionDigest {
        messages: out,
        l5_rendered,
    }
}

/// Render the per-call history levels of the digest — L2 `# Recent Turn
/// Digests` (most recent `MAX_L2_RENDERED`, in reader order) and L3 `# Epoch
/// Summary` — for Tier 3. Empty levels emit NOTHING.
///
/// L2/L3 are char-only [`sanitize_description`]'d (control / BiDi / zero-width
/// / dash-lookalike defense for inline rendered metadata) — not
/// boundary-wrapped (a §3.6 follow-up; wrapping them churns exact-content
/// tests for no L4/L5-injection benefit). L1 (vector hits: id + score, no
/// body) and L6 (consolidation) remain inert / not rendered — the recall
/// section carries the embedding-backed turn hits with their digests.
fn render_recent_digest(digest: &MultiLevelContextDigest) -> Vec<LlmMessage> {
    let mut out: Vec<LlmMessage> = Vec::new();

    // L2 — recent turn digests (each `digest` field is already write-bounded +
    // single-lined at the cap-memory producer; sanitize again for defense-in-depth).
    let l2_lines: Vec<String> = digest
        .l2
        .iter()
        .map(|d| sanitize_description(&d.digest))
        .filter(|s| !s.trim().is_empty())
        .collect();
    if !l2_lines.is_empty() {
        let start = l2_lines.len().saturating_sub(MAX_L2_RENDERED);
        out.push(system(format!(
            "# Recent Turn Digests\n{}",
            l2_lines[start..].join("\n")
        )));
    }

    // L3 — epoch summary (optional).
    if let Some(epoch) = &digest.l3 {
        let summary = sanitize_description(&epoch.summary);
        if !summary.trim().is_empty() {
            out.push(system(format!("# Epoch Summary\n{summary}")));
        }
    }

    out
}

/// Stage-C SAT-A degraded-path helper: truncate `prompt` (char-boundary-safe)
/// so its Tier-3 `role:"user"` message fits within `max_tokens`. The
/// budget-overflow guard drops the droppable content; this bounds the
/// irreducible user prompt against the budget remaining after the kept Tier-1a
/// identity + warnings, so even a pathologically large prompt cannot blow the
/// degraded set's budget. Uses the same chars/4 estimate as [`chars_to_tokens`]:
/// `approx_tokens_str("user", s)` = `(s.len() + 7) / 4`, kept `<= max_tokens` by
/// bounding `s.len() <= 4*max_tokens − 7`. `max_tokens == 0` (or ≤1) → empty.
fn truncate_prompt_to_tokens(prompt: &str, max_tokens: u32) -> String {
    let max_bytes = (max_tokens as usize).saturating_mul(4).saturating_sub(7);
    if prompt.len() <= max_bytes {
        return prompt.to_string();
    }
    let mut end = max_bytes;
    while end > 0 && !prompt.is_char_boundary(end) {
        end -= 1;
    }
    prompt[..end].to_string()
}
