//! [`ContextAssemblerImpl`] — CONTRACT-090 implementation.
//!
//! Orchestrates the 4-tier assembly per MODULE-010 §1.3.7:
//! - **Tier 1a (static)**: Slice B fills the AGENTS.md identity slot
//!   (sanitized; [`crate::tier1::build_tier1a`]). Broader static population
//!   (architecture/security model) still future.
//! - **Tier 1b (dynamic)**: Slice B fills the knowledge-map section (AC-16;
//!   [`crate::tier1::build_tier1b`]). Capability config / mode state / child
//!   roster ⑥ still future.
//! - **Tier 2 (session)**: AC-18 unified `# Available Tools` view
//!   ([`crate::tier2`]) followed by the AC-19 `# Available Delegates` section
//!   ([`crate::tier2_delegates`]) — parallel sections, both before the
//!   1b→2 cache breakpoint.
//! - **Tier 3 (per-call)**: `ctx.turn_buffer` + drained warning queue +
//!   current prompt (unchanged from Slice A).
//!
//! Two cache-breakpoint markers (`<!-- ctx-cache-breakpoint:1b->2 -->` and
//! `:2->3 -->`) between Tier 1b/Tier 2 and Tier 2/Tier 3 (AC-05) — positions
//! and token attribution unchanged from Slice A.
//!
//! Routing: when `ctx.task_id.is_none()` (new-task entry path) the assembler
//! runs [`crate::task_router::TaskRouter`] over the prompt to refine
//! `is_new_task`. A routing failure degrades gracefully (§2.8 intent: "fall
//! back", not "abort assembly") — assembly still returns a valid result with
//! `is_new_task = true` (the safe default when no task_id was supplied); the
//! `EmbeddingFailed` surface itself is exercised by `route_task` /
//! `unified_search` directly (AC-03/02), not by aborting tier assembly.

use std::sync::Arc;

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
use crate::inventory::HostFnInventoryReader;
use crate::knowledge_map::KNOWLEDGE_MAP_MAX_TOKENS;
use crate::ports::{
    AgentIdentityReader, DecompositionReader, EmbeddingPort, KnowledgeMapReader, L2DigestReader,
    L3EpochReader, L4TaskSummaryReader, L5SynthesisReader, L6ConsolidationReader,
    LightLlmFallbackPort, MultiLevelContextDigest, SkillSummaryReader, TaskIndexPort,
    UnifiedSearchPort, VectorIndexReader,
};
use crate::processing_pipeline::{coordinate_processing, MultiLevelReaders};
use crate::recall_section::format_recall_section;
use crate::task_router::{TaskRouter, TaskRoutingDecision};
use crate::tier1::{build_tier1a, build_tier1b};
use crate::tier2::{
    assemble_unified, format_available_tools_section, neutralize_cache_breakpoint_markers,
    sanitize_description,
};
use crate::tier2_decomposition::format_active_decomposition_section;
use crate::tier2_delegates::format_available_delegates_section_with_aliases;
use crate::tier2_skills::{format_available_skills_section, SKILL_BUDGET_TOKENS_DEFAULT};
use crate::tier3::{
    bound_tier3_turns, model_context_window, response_reserve, select_progressive_mode,
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
    // driving the AC-06 `coordinate_processing` digest that `assemble()` now
    // folds into Tier-3. The cap-memory-backed adapters live downstream in
    // cli (`context_wiring.rs`, dep-light discipline); these fields are
    // read-only inverted-dependency ports (the AC-01 stateless property the
    // `tests/stateless.rs` size guard defends is preserved).
    l1_vector: Arc<dyn VectorIndexReader>,
    l2_digest: Arc<dyn L2DigestReader>,
    l3_epoch: Arc<dyn L3EpochReader>,
    l4_summary: Arc<dyn L4TaskSummaryReader>,
    l5_synthesis: Arc<dyn L5SynthesisReader>,
    l6_consolidation: Arc<dyn L6ConsolidationReader>,
    // Stage-C SAT-E injected port (18th dep) — canonical CONTRACT-114
    // PromptInjectionHelpers (shared-types). Drives the AC-14 layer-2 boundary
    // marking of the untrusted L4/L5 digest bodies in `render_multilevel_digest`
    // (the deferred §3.6 Slice-D (c) live producer path). The concrete
    // `DefaultPromptInjectionHelpers` is constructed downstream in cli
    // (`context_wiring.rs`, dep-light); this field is the inverted-dependency
    // trait-object port (AC-01 stateless property preserved).
    prompt_injection: Arc<dyn PromptInjectionHelpers>,
    // Wave-12 Lane C injected port (19th dep) — the active task's non-orphaned
    // subtasks for the Tier-2 ⑭ "Active Task Decomposition" section. The concrete
    // `CapDecompositionReader` (bridging MODULE-005's `DefaultDecompositionStore`)
    // is constructed downstream in cli (`context_wiring.rs`, dep-light); this field
    // is the inverted-dependency trait-object port (the AC-01 stateless property
    // the `tests/stateless.rs` size guard defends is preserved).
    decomposition: Arc<dyn DecompositionReader>,
    // Internally constructed (NOT injected) — Slice-A inject_tier3_warning
    // buffer.
    warnings: Arc<WarningQueue>,
    // Wave-12 — the agent-id alias set {bare cap-id, colon msg-id} used to
    // match the Tier-2 ⑬ delegates `node.parent` AND drain the Tier-3
    // `WarningQueue`, bridging the colon/bare keying split (production spawns
    // record + the MODULE-008 RepetitionGuard injects under the BARE cap-id,
    // while `assemble()` runs under the COLON msg-id). Empty ⇒ single-id
    // (`ctx.agent_id`-only) behaviour, byte-identical to pre-Wave-12. Set via
    // `with_agent_id_aliases`; defaults empty in `new()` (signature unchanged,
    // so the existing direct `new()` callers are untouched).
    agent_id_aliases: Vec<String>,
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
    /// `coordinate_processing` and fold the L0-L6 digest into Tier-3 (the
    /// §3.6 (Slice D,a)/(B1) landing milestone — see §3.8 Stage-C SAT-A);
    /// **Stage-C SAT-E** adds the 18th dep `prompt_injection` (canonical
    /// CONTRACT-114 `PromptInjectionHelpers`) so `render_multilevel_digest`
    /// boundary-wraps the untrusted L4/L5 bodies (AC-14 live producer path —
    /// see §3.8 Stage-C SAT-E); **Wave-12 Lane C** adds the 19th dep
    /// `decomposition` (`DecompositionReader`) so `assemble()` renders the Tier-2 ⑭
    /// "Active Task Decomposition" section from the active task's non-orphaned
    /// subtasks (MODULE-010 §3.7 Wave-12 Lane C).
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
            warnings: Arc::new(WarningQueue::new()),
            agent_id_aliases: Vec::new(),
        }
    }

    /// Wave-12 — set the agent-id alias set ({bare cap-id, colon msg-id}) used
    /// by `assemble()` to match the Tier-2 ⑬ delegates `node.parent` AND drain
    /// the Tier-3 `WarningQueue` (in ADDITION to `ctx.agent_id`). The cli
    /// composition root passes the production `query_aliases` (the SAME set
    /// already wired to the Tier-1b memory readers). Empty ⇒ unchanged single-id
    /// behaviour. `new()`'s signature is intentionally left unchanged.
    pub fn with_agent_id_aliases(mut self, aliases: Vec<String>) -> Self {
        self.agent_id_aliases = aliases;
        self
    }

    /// Build a [`crate::unified_search::UnifiedSearchCoordinator`] sharing
    /// this assembler's embedding + search ports (AC-02 callable surface).
    /// Wave-13 Lane C: `assemble()` now CALLS this and folds an omit-when-empty
    /// `# Recalled Context` section into Tier-3 (MODULE-010 §3.8 Wave-13 Lane C)
    /// — closing the wiring half of the Tier 2 ⑮ assembly-wiring §3.6 deferral.
    /// DORMANT in production (StubEmbedding + empty corpus → no hits → no section).
    pub fn unified_search_coordinator(&self) -> crate::unified_search::UnifiedSearchCoordinator {
        crate::unified_search::UnifiedSearchCoordinator::new(
            self.embedding.clone(),
            self.unified_search_port.clone(),
        )
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

        // ── Tier 1a (static): sanitized AGENTS.md identity slot.
        let tier1a = build_tier1a(self.agent_identity.as_ref(), &ctx.agent_id).await;
        // ── Tier 1b (dynamic): knowledge-map section (AC-16). The §1.3.3 ⑨
        // hard cap is enforced inside `build_knowledge_map_section`; pass the
        // 500-token ceiling as the Slice-B budget (broader budget arithmetic
        // — progressive-load modes — is a future slice).
        let tier1b = build_tier1b(
            self.knowledge_map_reader.as_ref(),
            &ctx.agent_id,
            KNOWLEDGE_MAP_MAX_TOKENS,
        )
        .await;

        // Model window → budget. Hoisted above Tier-2 build because the
        // Tier-2 ⑩ skills section (Slice V1-c) is capped by `budget`; the
        // Slice-C progressive-load mode-select below reuses the same values.
        let model_limit = model_context_window(&ctx.model);
        let budget = model_limit.saturating_sub(response_reserve(model_limit));

        // ── Tier 2 ⑩ (Slice V1-c, AC-15): visible skills' L0 summaries, capped
        // at min(skill_budget_tokens, ⌊budget·0.05⌋, 10_000) — AC-15 ceiling +
        // AC-27 default. Built first so it can be prepended before the AC-18
        // tools section; omitted entirely (no message) when there are no visible
        // skills, so empty-inventory output is byte-identical to pre-V1-c.
        let skills = self.skill_summary.list_skill_summaries(&ctx.agent_id).await;
        let skill_cap = SKILL_BUDGET_TOKENS_DEFAULT
            .min((budget / 20) as u32) // ⌊budget·0.05⌋
            .min(10_000);
        let tier2_skills = format_available_skills_section(&skills, skill_cap);

        // ── Tier 2 (session): AC-18 tool view THEN AC-19 delegate section,
        // both before the 1b→2 breakpoint. (V1-b `# Available Tools` surface
        // unchanged — only a new ⑩ section is prepended.)
        let host_fns = self.host_fn_inventory.list_host_fns(&ctx.agent_id);
        let wasm_tools = self.callable_inventory.list_wasm_tools(&ctx.agent_id);
        let mcp_tools = self.callable_inventory.list_mcp_tools(&ctx.agent_id);
        let unified = assemble_unified(host_fns, wasm_tools, mcp_tools);
        let tier2_tools = format_available_tools_section(&unified);
        // Wave-12: match the ⑬ delegates `node.parent` against the agent's full
        // id-alias set ({ctx.agent_id} ∪ agent_id_aliases) so a Sub recorded
        // under the BARE cap-id surfaces for this COLON-keyed assemble turn.
        let tier2_delegates = format_available_delegates_section_with_aliases(
            self.agent_tree.as_ref(),
            &ctx.agent_id,
            &self.agent_id_aliases,
        );
        // Tier-2 order matches §1.3.3: ⑩ Skills → ⑪/⑫ (merged `# Available
        // Tools`) → ⑬ Delegates. The skills message is present only when
        // `format_available_skills_section` returned `Some`.
        let mut tier2: Vec<LlmMessage> = Vec::with_capacity(4);
        if let Some(skills_content) = tier2_skills {
            tier2.push(LlmMessage {
                role: "system".into(),
                content: skills_content,
            });
        }
        tier2.push(LlmMessage {
            role: "system".into(),
            content: tier2_tools,
        });
        tier2.push(LlmMessage {
            role: "system".into(),
            content: tier2_delegates,
        });
        // ── Tier 2 ⑭ (Wave-12 Lane C): "Active Task Decomposition" — the active
        // task's non-orphaned subtasks (the decomposition sub-part of §1.4.3 ⑭;
        // Task Summary + L5 briefs sub-parts deferred). The reader (cli
        // `CapDecompositionReader`) resolves the owner + filters non-orphaned;
        // `format_active_decomposition_section` returns `None` when there are no
        // active subtasks (no active task ⇒ `ctx.task_id` is `None` ⇒ empty), so the
        // message is OMITTED entirely and empty-state output stays byte-identical
        // (same convention as the ⑩ skills section). Pushed AFTER ⑬ delegates; the
        // existing `used` budget sum counts it via `approx_tokens(&tier2)` below and
        // the degraded branch drops Tier-2 wholesale (so a large decomposition
        // correctly narrows / trips the budget guard and is dropped under overflow).
        let decomposition_subtasks = self
            .decomposition
            .read_active_subtasks(&ctx.agent_id, ctx.task_id.as_deref())
            .await;
        if let Some(decomp_content) = format_active_decomposition_section(&decomposition_subtasks) {
            tier2.push(LlmMessage {
                role: "system".into(),
                content: decomp_content,
            });
        }

        // ── Tier 3 (per-call): progressive-load mode-select (Slice C,
        // AC-09) → bounded turn_buffer → drained warnings → prompt. Ordering
        // unchanged from Slice A (warning surfaces AFTER prior history but
        // BEFORE the current prompt); only the *turn_buffer slice* is now
        // mode-bounded.
        //
        // Cache-breakpoint marker token sizes are needed for the budget
        // `used` estimate below, so compute them here (was previously after
        // message assembly; same values, just hoisted).
        let breakpoint_1_tokens = approx_tokens_str("system", TIER1B_TIER2_BREAKPOINT);
        let breakpoint_2_tokens = approx_tokens_str("system", TIER2_TIER3_BREAKPOINT);

        // Drain the repetition-warning queue ONCE (WarningQueue::drain is
        // destructive — `cache.pop`). The same Vec is reused for both the
        // budget `used` estimate and the Tier-3 append (no double-drain).
        // Wave-12: drain across the agent's id-alias set so a warning the
        // MODULE-008 RepetitionGuard injected under the BARE cap-id surfaces
        // for this COLON-keyed assemble turn. `ctx.agent_id` is drained first;
        // each distinct alias (≠ ctx.agent_id) is drained once — no double-drain
        // (each id keys a separate WarningQueue bucket).
        let drained_warnings: Vec<String> = {
            let mut acc = self.warnings.drain(&ctx.agent_id);
            for alias in &self.agent_id_aliases {
                if alias != &ctx.agent_id {
                    acc.extend(self.warnings.drain(alias));
                }
            }
            acc
        };

        // Progressive-load budget (Slice C, REQ-239/AC-09). `used` = ALL
        // non-droppable assembled content the assembler emits BEFORE the
        // boundable history: the fixed tiers + both cache-breakpoint markers
        // + the current prompt + the drained repetition warnings. The
        // `turn_buffer` is the ONLY droppable history. A large prompt
        // therefore correctly narrows the mode (fail-safe). `model_limit`
        // comes from the fail-safe-small `model_context_window` stand-in
        // (MODULE-010 §3.6 Slice-C (c)/(e)); `select_progressive_mode` owns
        // the §1.3.5 band thresholds.
        let warnings_tokens: u32 = drained_warnings.iter().fold(0u32, |acc, w| {
            acc.saturating_add(approx_tokens_str("system", w))
        });
        // The prompt is appended to Tier 3 ONLY when non-empty (the
        // `if !ctx.prompt.is_empty()` gate below). The `used` estimate must
        // mirror that exactly — otherwise an empty prompt would spuriously
        // bill its `role` bytes (`approx_tokens_str("user", "")` = 1 token),
        // under-estimating `remaining` by 1 and mis-classifying an exact
        // band-edge case (e.g. a true `50_001` → treated as `50_000` →
        // Wide→Medium). Count it iff it is actually emitted.
        let prompt_tokens = if ctx.prompt.is_empty() {
            0
        } else {
            approx_tokens_str("user", &ctx.prompt)
        };

        // ── Stage-C SAT-A: L0-L6 multi-source digest (AC-06). Run the
        // coordinator over the 6 injected reader ports and fold its rendered
        // output into Tier-3 (below). `coordinate_processing` is fail-fast;
        // degrade gracefully to an EMPTY digest on any reader error (§2.8
        // "fall back, not abort") via `unwrap_or_default`. `l0_input` is empty
        // (no `LlmMessage`→`L0Entry` mapping at this layer) and `query_embedding`
        // is empty because the L1 vector reader is inert this slice (no
        // embedding index — MODULE-010 §3.8 Stage-C SAT-A); a future slice
        // wires a real embedding when L1 lands. Null/empty readers → empty
        // digest → no rendered message → Tier-3 byte-identical (protects the
        // existing exact-content tests).
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
            &[],
            &readers,
        )
        .await
        .unwrap_or_default();
        let digest_messages = render_multilevel_digest(&digest, self.prompt_injection.as_ref());
        // The folded digest is non-droppable Tier-3 content (like the prompt +
        // warnings); count it in `used` so a large digest correctly narrows the
        // progressive mode AND can trip the budget-overflow guard below.
        let digest_tokens = approx_tokens(&digest_messages);

        // ── Tier 3 recall (Wave-13 Lane C, MODULE-010 §3.8): fold the
        // unified_search hits into Tier-3. Per-call (query-dependent) retrieved
        // context. Degrade gracefully (§2.8 "fall back, not abort") — any
        // coordinator error → `unwrap_or_default` → empty result → omit-when-empty
        // → byte-identical. In production cli injects StubEmbedding (zero vec) +
        // an empty AgentSearchCorpus → no hits → `format_recall_section` → None →
        // no message (DORMANT; the harvest swaps the embedding + corpus slots to
        // activate). The section is boundary-marked via the existing
        // `prompt_injection` helper (production holds the real one).
        let recall = self
            .unified_search_coordinator()
            .unified_search(&ctx.agent_id, &ctx.prompt, ctx.task_id.as_deref())
            .await
            .unwrap_or_default();
        let recall_messages: Vec<LlmMessage> =
            match format_recall_section(&recall, self.prompt_injection.as_ref()) {
                Some(content) => vec![LlmMessage {
                    role: "system".into(),
                    content,
                }],
                None => Vec::new(),
            };
        // Non-droppable Tier-3 content (like the digest + prompt + warnings);
        // count it in `used` so a large recall narrows the progressive mode AND
        // can trip the budget-overflow guard below (where it is dropped with the
        // digest/Tier-2). 0 tokens when the recall section is omitted.
        let recall_tokens = approx_tokens(&recall_messages);

        let used: u32 = approx_tokens(&tier1a)
            .saturating_add(approx_tokens(&tier1b))
            .saturating_add(breakpoint_1_tokens)
            .saturating_add(approx_tokens(&tier2))
            .saturating_add(breakpoint_2_tokens)
            .saturating_add(prompt_tokens)
            .saturating_add(warnings_tokens)
            .saturating_add(digest_tokens)
            .saturating_add(recall_tokens);
        // `model_limit` / `budget` are computed once above the Tier-2 build
        // (hoisted for the Slice-V1-c skill cap) and reused here.

        // ── Stage-C SAT-A budget-overflow guard (192 / §2.8; aligns with
        // SYS-AC-192). When the non-droppable fixed content `used` (which
        // EXCLUDES the only droppable history, `turn_buffer`, and INCLUDES the
        // folded digest) exceeds `budget`, even dropping all history cannot
        // fit — so return a DEGRADED extreme-mode `Ok` prompt rather than a
        // full one or a hard `Err(BudgetExhausted)` (the M014 agent-loop drops
        // the turn on ANY assemble `Err`, so the in-module degrade is the only
        // path that keeps the turn alive). The degraded set keeps the Tier-1a
        // identity + drained warnings + the current prompt (truncated against
        // the budget remaining after identity + warnings); it DROPS the Tier-2
        // session sections (tools/skills/delegates) + the L0-L6 digest + all
        // history. `messages`/`tier_token_counts` are computed per-branch and
        // shared below (so the AC-12 `context.assembled` event still fires once).
        let (messages, tier_token_counts) = if (used as usize) > budget {
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
                dmsgs.push(LlmMessage {
                    role: "system".into(),
                    content: w.clone(),
                });
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
            let mode = select_progressive_mode(remaining);

            // Tier-3 order: bounded turn_buffer → L0-L6 digest (Stage-C SAT-A,
            // folded here so it lands in the captured prompt) → drained warnings
            // → current prompt. The Slice-A invariant (warning surfaces AFTER
            // prior history but BEFORE the current prompt) is preserved; the
            // digest sits with the history, before warnings/prompt.
            let mut tier3 = bound_tier3_turns(&ctx.turn_buffer, mode);
            tier3.extend(digest_messages.iter().cloned());
            // Wave-13 Lane C: the unified_search recall section sits with the
            // retrieved-context history (after the digest, before warnings/prompt)
            // — in Tier-3, AFTER the 2→3 cache breakpoint, so query-dependent
            // recall never busts the Tier-2 cache. Empty in production (omitted).
            tier3.extend(recall_messages.iter().cloned());
            for w in &drained_warnings {
                tier3.push(LlmMessage {
                    role: "system".into(),
                    content: w.clone(),
                });
            }
            if !ctx.prompt.is_empty() {
                tier3.push(LlmMessage {
                    role: "user".into(),
                    content: ctx.prompt.clone(),
                });
            }

            let breakpoint_1 = LlmMessage {
                role: "system".into(),
                content: TIER1B_TIER2_BREAKPOINT.into(),
            };
            let breakpoint_2 = LlmMessage {
                role: "system".into(),
                content: TIER2_TIER3_BREAKPOINT.into(),
            };

            // round-10 ADVERSARIAL Critical 1 / Info 9: saturating arithmetic on
            // both the `Vec::with_capacity` calculation (usize) and the
            // tier-token sums (u32) — `chars_to_tokens` saturates at u32::MAX,
            // and an adversarial caller filling `turn_buffer` to that ceiling
            // could otherwise wrap or panic on the subsequent addition. The
            // upstream `AssemblyContext.prompt` 64-KiB invariant is documented
            // but not enforced at this layer; defense-in-depth via saturating ops.
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
            // prompt size. Unchanged accounting model from Slice A; saturating
            // adds for the breakpoint-merge sums (round-10 Critical 1).
            // `breakpoint_{1,2}_tokens` are computed once near the top of the
            // Tier-3 block (reused by the progressive-load `used` estimate).
            let tier_token_counts = TierTokenCounts {
                tier1a: approx_tokens(&tier1a),
                tier1b: approx_tokens(&tier1b).saturating_add(breakpoint_1_tokens),
                tier2: approx_tokens(&tier2).saturating_add(breakpoint_2_tokens),
                tier3: approx_tokens(&tier3),
            };
            (messages, tier_token_counts)
        };

        // Routing: only the new-task entry path (no task_id) consults the
        // router. A routing failure degrades gracefully (§2.8 "fall back",
        // not "abort") — assembly still succeeds; is_new_task defaults to
        // true (the safe default when no task_id was supplied). The
        // EmbeddingFailed *surface* is exercised by route_task /
        // unified_search directly (AC-03/02), not by aborting tier assembly.
        let is_new_task = if ctx.task_id.is_none() {
            let router = TaskRouter::new(
                self.embedding.clone(),
                self.task_index.clone(),
                self.light_llm.clone(),
            );
            match router.route_task(&ctx.agent_id, &ctx.prompt).await {
                Ok(TaskRoutingDecision::NewTask) => true,
                Ok(TaskRoutingDecision::Existing(_)) => false,
                Err(_) => true, // degrade to the safe default
            }
        } else {
            false
        };

        let result = AssemblyResult {
            messages,
            routing_method: "search".into(),
            routing_confidence: 0.0,
            is_new_task,
            tier_token_counts,
        };

        // AC-12: emit the `context.assembled` event AFTER the result is built
        // so the payload captures the actual returned values. Uses the
        // CANONICAL CONTRACT-180 `EventBusEmit` (sync; non-blocking per the
        // trait's implementer invariants) + the canonical `Event` STRUCT
        // (`event_type` string discriminator — there is no
        // `Event::ContextAssembled` enum variant). `Event.id` + a fresh
        // per-emit `Event.trace_id` are uuid v4 (canonical `Event.id`
        // invariant forbids sequential / user-controlled ids); `trace_id` is
        // fresh-per-emit because `AssemblyContext` carries no upstream chain id
        // to thread (MODULE-010 §3.6 Slice-D (f)). The routing-field VALUES are
        // Slice-B placeholders ("search"/0.0) read through verbatim — AC-12
        // verifies the emission SCHEMA, content meaningfulness defers to the
        // routing-wiring slice (§3.6 Slice-D (b)).
        let event = Event {
            id: Uuid::new_v4().to_string(),
            // chrono is pinned without the `clock` feature (workspace
            // `features = ["serde", "std"]`), so `Utc::now()` is unavailable;
            // the workspace idiom is `SystemTime::now().into()` (see
            // `crates/database/src/lib.rs`).
            timestamp: DateTime::<Utc>::from(std::time::SystemTime::now()),
            agent_id: ctx.agent_id.clone(),
            task_id: ctx.task_id.clone(),
            run_id: None,
            execution_id: None,
            // Stage-F obs SLICE 1: thread the handle-message chain. trace_id reads
            // the chain trace minted at run_turn_once (fallback fresh-v4 when the
            // message carries no context — preserves the context:None distinctness
            // test); span_id is the deterministic chain-ROOT span (was the fixed
            // "context-assembled" literal). parent_span_id stays None — this IS the
            // chain root that run.round_completed.parent_span_id links to (SYS-AC-138).
            trace_id: ctx
                .message
                .context
                .as_ref()
                .and_then(|c| c.trace_id.clone())
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

        Ok(result)
    }

    fn inject_tier3_warning(&self, agent_id: &str, msg: &str) {
        self.warnings.push(agent_id, msg);
    }
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
/// (`build_related_tasks(&ctx, 3)`, §1.4.7). `render_multilevel_digest` renders
/// at most this many non-empty cross-task syntheses into `# Task Syntheses`,
/// which also bounds the per-body `wrap_with_boundary` allocation independent of
/// how many the (future) L5 reader returns.
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

/// Render the L0-L6 [`MultiLevelContextDigest`] into Tier-3 [`LlmMessage`]s, in
/// spec order (L2 → L3 → L4 → L5). Only the text-bearing levels with content
/// produce a message; empty levels emit NOTHING, so an all-empty / Null-reader
/// digest yields an empty `Vec` and Tier-3 stays byte-identical to pre-slice
/// output (protects the existing exact-content tests).
///
/// Untrusted-content treatment by level (MODULE-010 §3.8 Stage-C SAT-A + SAT-E):
/// - **L2 turn digests + L3 epoch summary**: char-only [`sanitize_description`]
///   (control / BiDi / zero-width / dash-lookalike defense for inline rendered
///   metadata). L4/L5-only scope — L2/L3 are NOT boundary-wrapped (a §3.6
///   follow-up; wrapping them churns exact-content tests for no L4/L5-injection
///   benefit).
/// - **L4 task summary + L5 cross-task syntheses** (Stage-C SAT-E, AC-14 live
///   producer path): routed through the canonical CONTRACT-114
///   [`layer2_wrap`] / `wrap_with_boundary` (`TrustLevel::Untrusted`) — the
///   `<data source=".." trust="untrusted">…</data>` boundary envelope +
///   Critical-always / High-when-Untrusted span neutralization — followed by
///   [`neutralize_cache_breakpoint_markers`] to preserve the M009 gateway
///   cache-marker defense `wrap_with_boundary` does not replicate. Each body is
///   wrapped EXACTLY ONCE (CONTRACT-114 invariant 4); the skip-guard runs on the
///   RAW body BEFORE wrapping so an empty body emits nothing.
///
/// L1 (vector hits: id + score, no body) and L6 (consolidation) remain inert /
/// not rendered.
fn render_multilevel_digest(
    digest: &MultiLevelContextDigest,
    helpers: &dyn PromptInjectionHelpers,
) -> Vec<LlmMessage> {
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
        out.push(LlmMessage {
            role: "system".into(),
            content: format!("# Recent Turn Digests\n{}", l2_lines.join("\n")),
        });
    }

    // L3 — epoch summary (optional).
    if let Some(epoch) = &digest.l3 {
        let summary = sanitize_description(&epoch.summary);
        if !summary.trim().is_empty() {
            out.push(LlmMessage {
                role: "system".into(),
                content: format!("# Epoch Summary\n{summary}"),
            });
        }
    }

    // L4 — task summary (optional; UNTRUSTED body). Stage-C SAT-E: boundary-wrap
    // via the canonical CONTRACT-114 helper (AC-14) THEN preserve the
    // cache-breakpoint defense. Skip-guard on the RAW body BEFORE wrapping keeps
    // the byte-neutral Null-reader invariant (empty body → no message).
    if let Some(task) = &digest.l4 {
        if !task.summary.trim().is_empty() {
            let wrapped = neutralize_cache_breakpoint_markers(&layer2_wrap(
                &task.summary,
                "memory:l4_task_summary",
                TrustLevel::Untrusted,
                helpers,
            ));
            out.push(LlmMessage {
                role: "system".into(),
                content: format!("# Task Summary\n{wrapped}"),
            });
        }
    }

    // L5 — cross-task syntheses (UNTRUSTED bodies). Stage-C SAT-E: rendered for
    // the FIRST time (read into the digest at `coordinate_processing` but never
    // rendered before). Each non-empty body is wrapped EXACTLY ONCE through the
    // same boundary helper + cache-breakpoint neutralization; empty bodies are
    // skipped BEFORE wrapping (byte-neutral invariant). The fold honours the
    // §1.4.3 ⑭ "Related Task Briefs (L5, max 3)" render bound (also §1.4.7
    // `build_related_tasks(&ctx, 3)`): at most `MAX_L5_RELATED_TASKS` non-empty
    // syntheses are rendered — `take` AFTER the empty-skip so blanks don't
    // consume a slot, and BEFORE `map` so at most 3 bodies are ever wrapped.
    // SCOPE OF THE BOUND: this caps only the RENDER/wrap step here (≤3 `layer2_wrap`
    // allocations) AND the render-time SCAN (≤`MAX_L5_SCANNED` raw entries examined,
    // via the leading `take` — so an all-whitespace flood can't drive an unbounded
    // `trim()` scan before 3 non-empty are found). It does NOT bound the upstream
    // `digest.l5` Vec, which `coordinate_processing` materializes from the L5 reader
    // independent of this cap (same as L2/L3/L4/L6 — the reader/coordinator owns the
    // materialization bound, not the renderer). Per-body envelopes are joined under
    // one `# Task Syntheses` section.
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
    if !l5_blocks.is_empty() {
        out.push(LlmMessage {
            role: "system".into(),
            content: format!("# Task Syntheses\n{}", l5_blocks.join("\n")),
        });
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
