//! Slice-C Tier 3 — 4-mode progressive-loading strategy (REQ-239 — AC-09).
//!
//! Implements the §1.3.5 progressive-loading decision matrix's **mode-select +
//! recent-count** dimension. Per the plan's §3.2 reconciliation the 4-mode
//! logic lives here (not a separate `progressive_load.rs`): §1.3.5 makes Tier
//! 3 the natural home since progressive loading governs Tier 3 ⑯ history-turn
//! inclusion.
//!
//! **Scope boundary (honest — MODULE-010 §3.6 Slice-C (f))**: this slice
//! delivers the matrix's *count* dimension (recent-entries cap 5/3/1/0) over
//! the only CONTRACT-090 surface available — `turn_buffer: Vec<LlmMessage>`,
//! which has no per-entry turn/digest typing. The digest-vs-l0_processed-vs-
//! brief *representation* dimension is part of the deferred history-load
//! surface (§3.6 (d)/(f)). AC-09's §1.4 criterion ("4 modes wide/medium/
//! compact/extreme") + T12/T13 are about mode *selection* + count, fully
//! delivered + live-wired into `assemble()`.
//!
//! Pure, no I/O, deterministic. All thresholds/consts exported so tests
//! assert exact boundaries without any production test-only model entry.

use advance_shared_types::context::LlmMessage;

/// §1.3.5 progressive-loading budget mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProgressiveMode {
    /// `> 50_000` remaining tokens — 5 recent L0 turns.
    Wide,
    /// `10_000..=50_000` — 3 recent L0 turns.
    Medium,
    /// `5_000..=10_000` — 1 recent (digest) turn.
    Compact,
    /// `< 5_000` — none (brief only).
    Extreme,
}

// Endpoint-ownership constants (each shared §1.3.5 endpoint is owned by the
// LOWER band — a documented interpretation of the overlapping-inclusive
// matrix notation `>50K / 10-50K / 5-10K / <5K`). `t_mode_boundaries` locks
// every tie point.

/// Minimum remaining tokens for [`ProgressiveMode::Wide`] (strict `>50_000`).
pub const WIDE_MIN: usize = 50_001;
/// Minimum remaining tokens for [`ProgressiveMode::Medium`] (`50_000` is
/// Medium, not Wide).
pub const MEDIUM_MIN: usize = 10_000;
/// Minimum remaining tokens for [`ProgressiveMode::Compact`] (`5_000` is
/// Compact, not Extreme).
pub const COMPACT_MIN: usize = 5_000;

/// §2.10 `context.high_score_threshold` — retention cutoff for l0_processed
/// loading. Exported so the (deferred) earlier-history-loading slice and
/// `retention_rerank` callers share one source of truth.
pub const RETENTION_HIGH_THRESHOLD: f32 = 0.5;
/// §2.10 `context.low_score_threshold` — retention cutoff for digest loading.
pub const RETENTION_LOW_THRESHOLD: f32 = 0.2;

/// Fail-safe-small context window for any model the [`model_context_window`]
/// table does not recognize (the common provider floor). A budget guard MUST
/// under-estimate an unknown window — over-estimating would pack a prompt
/// that overflows a real small provider limit, inverting REQ-239.
pub const SMALL_MODEL_WINDOW: usize = 8_192;

/// Select the progressive-loading mode for `remaining_tokens` per §1.3.5.
///
/// `> 50_000 → Wide`; `10_000..=50_000 → Medium`; `5_000..=10_000 → Compact`;
/// `< 5_000 → Extreme`. Shared endpoints owned by the lower band
/// ([`WIDE_MIN`]/[`MEDIUM_MIN`]/[`COMPACT_MIN`]).
pub fn select_progressive_mode(remaining_tokens: usize) -> ProgressiveMode {
    if remaining_tokens >= WIDE_MIN {
        ProgressiveMode::Wide
    } else if remaining_tokens >= MEDIUM_MIN {
        ProgressiveMode::Medium
    } else if remaining_tokens >= COMPACT_MIN {
        ProgressiveMode::Compact
    } else {
        ProgressiveMode::Extreme
    }
}

/// Recent-L0-turn cap for `mode` (§2.10 `recent_l0_turns_wide/medium/compact`
/// = 5/3/1; Extreme = "none" per the §1.3.5 matrix row 4).
pub fn recent_l0_turns(mode: ProgressiveMode) -> usize {
    match mode {
        ProgressiveMode::Wide => 5,
        ProgressiveMode::Medium => 3,
        ProgressiveMode::Compact => 1,
        ProgressiveMode::Extreme => 0,
    }
}

/// Local deterministic stand-in for the future MODULE-009
/// `context_window()` surface (§1.3.7 `llm_gateway.context_window(&ctx.model)`
/// — no port for it; out of this slice's boundary; MODULE-010 §3.6 Slice-C
/// (c)/(e)).
///
/// The table holds ONLY real model families with documented real windows.
/// Any unrecognized / unknown / spoofed string falls through to the
/// fail-safe-small [`SMALL_MODEL_WINDOW`] (the safe direction for a
/// context-budget guard — never over-estimate an unknown window). There are
/// **no test-only entries** in this production table; tests drive behavior
/// via the exported pure functions + the fail-safe default.
pub fn model_context_window(model: &str) -> usize {
    // Real model families (documented public context windows). Prefix match
    // tolerates dated/suffixed variants (e.g. `gpt-4o-2024-11-20`).
    if model.starts_with("claude-") {
        200_000
    } else if model.starts_with("o1") || model.starts_with("o3") {
        200_000
    } else if model.starts_with("gpt-4o") || model.starts_with("gpt-4.1") {
        128_000
    } else if model.starts_with("gpt-4-turbo") {
        128_000
    } else if model.starts_with("gpt-4-32k") {
        32_768
    } else if model.starts_with("gpt-4") {
        8_192
    } else if model.starts_with("gpt-3.5-turbo") {
        16_385
    } else if model.starts_with("gemini-1.5") || model.starts_with("gemini-2") {
        1_000_000
    } else {
        // Unknown / unrecognized / spoofed → fail-safe-small.
        SMALL_MODEL_WINDOW
    }
}

/// §1.3.7 response reservation: `min(model_limit * 0.15, 30_000)`. Integer
/// math (no float — deterministic): `model_limit * 15 / 100`, saturating mul,
/// capped at 30_000. (8_192 → 1_228; 200_000 → 30_000.)
pub fn response_reserve(model_limit: usize) -> usize {
    (model_limit.saturating_mul(15) / 100).min(30_000)
}

/// Bound `turn_buffer` to the most-recent `recent_l0_turns(mode)` entries
/// (tail), preserving order. `Extreme` (cap 0) → empty. Pure, no I/O. This is
/// the only droppable Tier-3 history; warnings + prompt are appended by the
/// assembler AFTER this bounded slice (Slice-A ordering invariant preserved).
pub fn bound_tier3_turns(turn_buffer: &[LlmMessage], mode: ProgressiveMode) -> Vec<LlmMessage> {
    let cap = recent_l0_turns(mode);
    // `len.saturating_sub(cap)` is `len` when cap == 0 ⇒ empty slice (Extreme),
    // and the start index of the most-recent `cap` entries otherwise.
    let start = turn_buffer.len().saturating_sub(cap);
    turn_buffer[start..].to_vec()
}
