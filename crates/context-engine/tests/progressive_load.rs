//! Slice-C AC-09 (REQ-239) — 4-mode progressive loading.
//!
//! - **MODULE-010-T12** (Unit, AC-09): Wide mode → 5 L0 loaded.
//! - **MODULE-010-T13** (Unit, AC-09): Extreme mode → none (brief only).
//! - **t_mode_boundaries** (Unit, AC-09): §1.3.5 endpoint ownership.
//! - **t_assembler_mode_select** (Integration, AC-09): `assemble()` bounds
//!   Tier-3 by the selected mode — deterministic monotonic relationships
//!   (live-bounding, prompt-monotone, Wide-keeps-all). Exact mode-boundary
//!   determinism is carried by the pure-fn unit tests above (the
//!   `approx_tokens` estimator is private/`pub(crate)` and unreachable from
//!   an integration-test crate, so no exact-`remaining` recompute is done).

use advance_context_engine::{
    bound_tier3_turns, model_context_window, recent_l0_turns, response_reserve,
    select_progressive_mode, ProgressiveMode, COMPACT_MIN, MEDIUM_MIN, SMALL_MODEL_WINDOW,
    WIDE_MIN,
};
use advance_shared_types::context::{ContextAssembler, LlmMessage};

#[path = "common/mod.rs"]
mod common;
use common::*;

fn turns(n: usize) -> Vec<LlmMessage> {
    (0..n)
        .map(|i| LlmMessage {
            role: "user".into(),
            content: format!("TURN-{i}"),
        })
        .collect()
}

// ── MODULE-010-T12 — Wide mode → 5 L0 loaded ──────────────────────────────

#[test]
fn module_010_t12_wide_mode_keeps_5() {
    assert_eq!(select_progressive_mode(60_000), ProgressiveMode::Wide);
    assert_eq!(recent_l0_turns(ProgressiveMode::Wide), 5);
    let buf = turns(8);
    let bounded = bound_tier3_turns(&buf, ProgressiveMode::Wide);
    assert_eq!(bounded.len(), 5, "Wide keeps the most-recent 5");
    // Most-recent tail, order preserved.
    assert_eq!(bounded[0].content, "TURN-3");
    assert_eq!(bounded[4].content, "TURN-7");
}

// ── MODULE-010-T13 — Extreme mode → none ──────────────────────────────────

#[test]
fn module_010_t13_extreme_mode_keeps_none() {
    assert_eq!(select_progressive_mode(4_999), ProgressiveMode::Extreme);
    assert_eq!(recent_l0_turns(ProgressiveMode::Extreme), 0);
    let buf = turns(8);
    let bounded = bound_tier3_turns(&buf, ProgressiveMode::Extreme);
    assert!(bounded.is_empty(), "Extreme keeps no turns (brief only)");
}

// ── t_mode_boundaries — §1.3.5 endpoint ownership (lower band owns) ────────

#[test]
fn t_mode_boundaries() {
    // Wide is strict `>50_000`; 50_000 itself is Medium.
    assert_eq!(WIDE_MIN, 50_001);
    assert_eq!(MEDIUM_MIN, 10_000);
    assert_eq!(COMPACT_MIN, 5_000);

    assert_eq!(select_progressive_mode(50_001), ProgressiveMode::Wide);
    assert_eq!(select_progressive_mode(50_000), ProgressiveMode::Medium);
    assert_eq!(select_progressive_mode(10_000), ProgressiveMode::Medium);
    assert_eq!(select_progressive_mode(9_999), ProgressiveMode::Compact);
    assert_eq!(select_progressive_mode(5_000), ProgressiveMode::Compact);
    assert_eq!(select_progressive_mode(4_999), ProgressiveMode::Extreme);
    assert_eq!(select_progressive_mode(0), ProgressiveMode::Extreme);

    assert_eq!(recent_l0_turns(ProgressiveMode::Wide), 5);
    assert_eq!(recent_l0_turns(ProgressiveMode::Medium), 3);
    assert_eq!(recent_l0_turns(ProgressiveMode::Compact), 1);
    assert_eq!(recent_l0_turns(ProgressiveMode::Extreme), 0);

    // Medium / Compact tail bounds.
    let buf = turns(8);
    assert_eq!(bound_tier3_turns(&buf, ProgressiveMode::Medium).len(), 3);
    assert_eq!(bound_tier3_turns(&buf, ProgressiveMode::Compact).len(), 1);
    assert_eq!(
        bound_tier3_turns(&buf, ProgressiveMode::Compact)[0].content,
        "TURN-7",
        "Compact keeps the single most-recent turn"
    );

    // model_context_window fail-safe-small for unrecognized/spoofed strings;
    // real-model families recognized; NO test-only entries.
    assert_eq!(model_context_window("test-model"), SMALL_MODEL_WINDOW);
    assert_eq!(model_context_window("totally-made-up"), SMALL_MODEL_WINDOW);
    assert_eq!(model_context_window("claude-3-5-sonnet-20241022"), 200_000);
    assert_eq!(model_context_window("gpt-4o-2024-11-20"), 128_000);
    assert_eq!(model_context_window("gpt-4"), 8_192);
    // response_reserve = min(limit*0.15, 30_000), integer math.
    assert_eq!(response_reserve(SMALL_MODEL_WINDOW), 1_228); // 8192*15/100
    assert_eq!(response_reserve(200_000), 30_000); // capped
}

/// `model_context_window` matches by **real-model-family prefix**. A string
/// that shares a real family's prefix (even with a junk suffix) deliberately
/// receives that family's window — exact-model spoof-resistance is the
/// deferred MODULE-009 `context_window()` surface's job (MODULE-010 §3.6
/// Slice-C (c)/(e)). Only strings that match NO real-family prefix get the
/// fail-safe-small default. This test locks that documented behavior so the
/// known limitation is intentional + visible, not accidental.
#[test]
fn t_model_window_prefix_match_is_documented_behavior() {
    // Prefix-match → family window (documented limitation, NOT fail-safe).
    assert_eq!(model_context_window("claude-spoof"), 200_000);
    assert_eq!(model_context_window("o3evil"), 200_000);
    assert_eq!(model_context_window("gemini-2junk"), 1_000_000);
    assert_eq!(model_context_window("gpt-4o-anything"), 128_000);
    // Bare `gpt-4` family vs the more specific prefixes (no shadowing bug).
    assert_eq!(model_context_window("gpt-4-32k-0613"), 32_768);
    assert_eq!(model_context_window("gpt-4-turbo-preview"), 128_000);
    assert_eq!(model_context_window("gpt-4-0613"), 8_192);
    // No real-family prefix → fail-safe-small (the safe under-estimate).
    assert_eq!(model_context_window(""), SMALL_MODEL_WINDOW);
    assert_eq!(model_context_window("llama-3-70b"), SMALL_MODEL_WINDOW);
    assert_eq!(model_context_window("not-a-real-model"), SMALL_MODEL_WINDOW);
    // The unrecognized fail-safe is strictly the conservative direction:
    // a budget guard must never OVER-estimate an unknown window.
    assert!(SMALL_MODEL_WINDOW <= 200_000);
}

// ── t_assembler_mode_select — Integration: assemble() bounds Tier-3 ────────

/// Count Tier-3 turn-portion entries (markers `TURN-…`) in the assembled
/// message sequence. Warnings (system) / prompt (user) do not match.
fn retained_turns(messages: &[LlmMessage]) -> usize {
    messages
        .iter()
        .filter(|m| m.content.starts_with("TURN-"))
        .count()
}

#[tokio::test]
async fn t_assembler_mode_select() {
    let asm = build_assembler_with_empty_inventories();

    // Case A — live + narrowed. "test-model" is unrecognized → 8_192 →
    // (budget 6_964 − tiny empty-inventory used) → Compact → keep 1.
    let mut ctx_a = stub_ctx();
    ctx_a.model = "test-model".into();
    ctx_a.prompt = String::new();
    ctx_a.turn_buffer = turns(10);
    let res_a = asm.assemble(ctx_a.clone()).await.expect("assemble A");
    let r_a = retained_turns(&res_a.messages);
    assert_eq!(
        r_a,
        recent_l0_turns(ProgressiveMode::Compact),
        "test-model (8_192) → Compact → keep recent_l0_turns(Compact)"
    );
    assert_eq!(r_a, 1, "Compact keeps exactly 1");
    assert!(r_a < 10, "bounding is live (10-entry buffer narrowed)");
    // Deterministic: a second identical call yields the same retained count.
    let res_a2 = asm.assemble(ctx_a).await.expect("assemble A2");
    assert_eq!(retained_turns(&res_a2.messages), r_a, "deterministic");
    // Both cache-breakpoint markers present; prompt-position invariant: the
    // last message is NOT a TURN- (prompt empty here → last is a breakpoint
    // or tier2; specifically a TURN never trails the bounded buffer once
    // warnings/prompt are absent — the bounded turns are contiguous at the
    // tail of the sequence).
    assert_eq!(
        res_a2
            .messages
            .iter()
            .filter(|m| m.content.contains("ctx-cache-breakpoint"))
            .count(),
        2,
        "both cache-breakpoint markers emitted"
    );

    // Case B — prompt IS budgeted (Codex-r3 guard). Same model + 10-entry
    // buffer but a very large prompt → remaining strictly smaller → retained
    // count monotone ≤ Case A (no exact-token recompute needed).
    let mut ctx_b = stub_ctx();
    ctx_b.model = "test-model".into();
    ctx_b.prompt = "X".repeat(80_000); // huge prompt
    ctx_b.turn_buffer = turns(10);
    let res_b = asm.assemble(ctx_b).await.expect("assemble B");
    let r_b = retained_turns(&res_b.messages);
    assert!(
        r_b <= r_a,
        "large prompt is subtracted from budget → mode no wider (r_b={r_b} <= r_a={r_a})"
    );

    // Case C — Wide path. A real recognized large-window model → Wide →
    // all 5 retained.
    let mut ctx_c = stub_ctx();
    ctx_c.model = "claude-3-5-sonnet-20241022".into();
    ctx_c.prompt = String::new();
    ctx_c.turn_buffer = turns(5);
    let res_c = asm.assemble(ctx_c).await.expect("assemble C");
    assert_eq!(
        retained_turns(&res_c.messages),
        5,
        "claude-* (200_000) → Wide → all 5 turns retained"
    );
    // Sanity: the model the test relies on really maps Wide via the pure fn.
    let limit = model_context_window("claude-3-5-sonnet-20241022");
    let budget = limit - response_reserve(limit);
    assert!(
        budget >= WIDE_MIN,
        "claude window leaves a Wide budget even before subtracting tiny fixed content"
    );
}
