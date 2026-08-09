//! CONTRACT-141 [`RoundAdvancer`] impl for MODULE-015 Auto mode.
//!
//! Provides [`AutoLoopRoundAdvancer`], the auto-loop crate's production
//! [`RoundAdvancer`] impl — the sole `impl RoundAdvancer for` producer in
//! Auto mode per MODULE-015 §1.4 AC-16.
//!
//! # Crate-boundary note (m015-slice-c)
//!
//! [`AutoLoopRoundAdvancer`] reads per-agent state via an injected
//! `Arc<dyn AutoStateReader>` (NOT `Arc<DefaultAutoLoopDriver>`) so this
//! module does not couple to `driver.rs` (which is outside the slice
//! allowlist). Production wiring (a Reader impl that bridges to
//! [`crate::driver::DefaultAutoLoopDriver`]) is the integrated-loop slice's
//! responsibility — that slice will add `impl AutoStateReader for
//! DefaultAutoLoopDriver` inside `driver.rs` with broader allowlist access.
//!
//! # Run vs Task id discrimination
//!
//! `validate_run_id` (run-manager) forbids `:` in `run_id`, so the
//! `auto:{agent-id}` prefix lives on TASK_ID, not `run_id`.
//! [`AutoLoopRoundAdvancer`] therefore takes a [`AutoStateReader`] that
//! maps `run_id → Option<agent_id>`. Round-4 W2 fix: **None → fail-CLOSED
//! with [`RunError::InvalidState`]** (NOT [`RoundDecision::ContinueAllowed`]).
//! Rationale: `RunManager::complete_round` already gates on
//! `is_auto_mode(task_id)` before invoking the auto-mode advancer, so any
//! `run_id` reaching this impl SHOULD have a registered `agent_id` mapping;
//! `None` indicates a wiring bug worth surfacing loudly.
//!
//! # CONTRACT-141 invariants honored
//!
//! - **Invariant 1 (Stateless across runs)**: no per-run state stored
//!   inside the impl; all reads go through the [`AutoStateReader`].
//! - **Invariant 2 (Reads RunBudget)**:
//!   [`AutoStateReader::budget_decision`] is consulted BEFORE emitting
//!   [`RoundDecision::ContinueAllowed`]; [`BudgetDecision::Deny`]`(reason) →
//!   `[`RoundDecision::Blocked`]`(reason)` per the contract. **Budget gate
//!   ONLY applies to the normal-path `ContinueAllowed` branch — the
//!   complete-cycle terminal path (PRD §4.7.7 priority) wins over budget
//!   denial**: if the agent has recorded a complete-cycle request, the
//!   advancer composes `Blocked("completed: ...")` per §4.7.7 line 934
//!   regardless of `budget_decision`. CONTRACT-141 invariant 2 only
//!   requires the budget check before emitting `ContinueAllowed`, not
//!   before emitting any `Blocked` decision (Round-2 audit C1 fix).
//!   **Mandatory** (no default impl) — production Readers must wire this
//!   to a real `RunBudget` bridge or explicitly opt out via a documented
//!   stub.
//! - **Invariant 3 (No state mutation)**: the impl only reads; never writes.
//! - **Invariant 4 (Bounded execution)**: pure-sync after Reader lookups.

use std::sync::Arc;

use async_trait::async_trait;

use advance_shared_types::capability::BudgetDecision;
use advance_shared_types::run::{RoundAdvancer, RoundDecision, RoundResult, RunError};

use crate::driver::{compose_complete_cycle_decision, CompletionSummary};
use crate::results::IterationStatus;

/// Strip control characters AND Unicode bidirectional-override marks
/// from an agent-emitted string before it flows into operator audit logs
/// (adversarial Round-1 W3 fix + Round-2 bidi-override extension).
/// Each rejected character is replaced with `_` so the result remains
/// analyzable + preserves byte alignment when the upstream length cap
/// kicks in. Defends against:
///
/// - **Log-line injection**: `outcome = "ok\n[fake operator entry]"`.
/// - **ANSI terminal corruption**: `outcome = "\x1b[2Jhidden text"`.
/// - **JSON-structure breakage**: `outcome = "ok\",\"injected\":\"…"`.
/// - **Trojan Source / bidi-override spoofing** (CVE-2021-42574):
///   `outcome = "\u{202E}gnireenigne-laicos"` reverses text rendering
///   in any bidi-aware terminal / log viewer / web UI.
///
/// Rejected character set:
/// - C0 controls (U+0000-U+001F, includes \n \r \t ESC).
/// - DEL (U+007F).
/// - C1 controls (U+0080-U+009F).
/// - Bidi-override marks: U+200E (LRM), U+200F (RLM), U+202A-U+202E
///   (LRE/RLE/PDF/LRO/RLO), U+2066-U+2069 (LRI/RLI/FSI/PDI), U+061C (ALM).
///
/// Not a substitute for PII redaction (per driver.rs `MAX_DECISION_REASON_BYTES`
/// doc-comment, the integrated-loop slice MUST add that pass separately).
/// This helper covers ONLY the structural-injection + bidi-spoofing
/// attack surfaces.
///
/// `pub` (adversarial-r10 W4): reused by
/// [`crate::auto_bootstrap::report_to_event_payloads`] AND by the cli EventBus
/// sink adapters (`auto_wiring`) to sanitize `agent_id` / `run_id` before they
/// flow into `Event` payloads — the same operator-audit-log / EventBus jsonl /
/// WS / `Debug` sink class as `RoundDecision` text. Exposed so the
/// composition-root adapters can apply the SAME control-char/bidi stripping the
/// in-crate paths use, rather than re-implementing it.
pub fn sanitize_for_audit(s: &str) -> String {
    s.chars()
        .map(|c| {
            // C0 controls (0x00-0x1F) including \n \r \t \x1b ESC + DEL (0x7F)
            // + C1 controls (0x80-0x9F).
            if c.is_control() || ('\u{0080}'..='\u{009F}').contains(&c) {
                return '_';
            }
            // Bidi-override marks (Trojan Source — CVE-2021-42574).
            if matches!(
                c,
                '\u{200E}' // LRM
                | '\u{200F}' // RLM
                | '\u{202A}' // LRE
                | '\u{202B}' // RLE
                | '\u{202C}' // PDF
                | '\u{202D}' // LRO
                | '\u{202E}' // RLO
                | '\u{2066}' // LRI
                | '\u{2067}' // RLI
                | '\u{2068}' // FSI
                | '\u{2069}' // PDI
                | '\u{061C}' // ALM (Arabic Letter Mark)
            ) {
                return '_';
            }
            c
        })
        .collect()
}

#[cfg(test)]
mod sanitize_tests {
    use super::sanitize_for_audit;

    #[test]
    fn passes_through_safe_ascii() {
        assert_eq!(
            sanitize_for_audit("research-converged"),
            "research-converged"
        );
        assert_eq!(sanitize_for_audit("abc 123 _-:"), "abc 123 _-:");
    }

    #[test]
    fn replaces_newline_and_cr() {
        assert_eq!(sanitize_for_audit("ok\n\rbad"), "ok__bad");
    }

    #[test]
    fn replaces_ansi_escape() {
        // Only the ESC (0x1B) is a control char; the `[2J` body is plain
        // ASCII and passes through. The key security property is that
        // the ESC is replaced so terminals can't interpret the sequence.
        assert_eq!(sanitize_for_audit("safe\x1b[2Jcleared"), "safe_[2Jcleared");
    }

    #[test]
    fn replaces_tab_and_control_chars() {
        assert_eq!(sanitize_for_audit("ok\tbad\x00null"), "ok_bad_null");
    }

    #[test]
    fn passes_through_non_ascii_text() {
        // Unicode like Chinese / emoji / accented characters are not
        // control codes; they pass through.
        assert_eq!(sanitize_for_audit("研究收敛"), "研究收敛");
        assert_eq!(sanitize_for_audit("café"), "café");
    }

    #[test]
    fn replaces_bidi_override_marks() {
        // Trojan Source attack — CVE-2021-42574. RLO (U+202E) reverses
        // text rendering in any bidi-aware viewer. Sanitizer must strip
        // it.
        assert_eq!(
            sanitize_for_audit("ok\u{202E}gnireenigne-laicos"),
            "ok_gnireenigne-laicos"
        );
        // Cover all marks in the rejected set.
        let marks = "\u{200E}\u{200F}\u{202A}\u{202B}\u{202C}\u{202D}\u{202E}\u{2066}\u{2067}\u{2068}\u{2069}\u{061C}";
        let sanitized = sanitize_for_audit(marks);
        assert_eq!(sanitized, "_".repeat(marks.chars().count()));
        // Ensure none of the bidi chars remain.
        for c in sanitized.chars() {
            assert_eq!(c, '_');
        }
    }
}

/// Read-only view onto auto-loop + run state needed by
/// [`AutoLoopRoundAdvancer`]. The integrated-loop slice will provide a
/// concrete impl bound to [`crate::driver::DefaultAutoLoopDriver`] (requires
/// extending `driver.rs` — out of scope for m015-slice-c). Tests provide
/// an in-memory impl from `tests/common/mod.rs`.
///
/// **Production wiring sketch** (for forward-compat audit):
/// - [`agent_id_for_run`](AutoStateReader::agent_id_for_run): the
///   integrated-loop slice owns this mapping.
///   [`crate::driver::DefaultAutoLoopDriver::start`] only sees `agent_id`
///   (not `run_id`), so the mapping is populated from the **outside** —
///   at the point where `RunManager::create` returns a `run_id` for an
///   Auto-mode task and the integrated-loop coordinator records the
///   `(run_id, agent_id)` pair in either: (a) a new auto-loop-side
///   coordinator struct that owns both `DefaultAutoLoopDriver` and the
///   Reader, OR (b) a slot inside `DefaultAutoLoopDriver` added in that
///   future slice (requires `state.rs` edit). The slice-C
///   `AutoStateReader` trait surface is independent of which option wins.
/// - [`complete_cycle_request`](AutoStateReader::complete_cycle_request):
///   reads `AutoState.complete_cycle_request` (already exists slice-B).
/// - [`last_iteration_status`](AutoStateReader::last_iteration_status):
///   a new per-agent slot set by the integrated loop just before invoking
///   the advancer. **No default fallback** — Round-3 W2 fix: missing
///   status surfaces as
///   `RunError::InvalidState("auto-loop: missing last_iteration_status")`
///   so a forgotten production wiring is loud, not silent.
/// - [`budget_decision`](AutoStateReader::budget_decision): queries the
///   `RunBudget` held by MODULE-008 — the integrated-loop slice composes
///   this via the `RunManager` surface. **No default impl** — Round-3
///   Critical fix: every Reader must provide it.
pub trait AutoStateReader: Send + Sync {
    /// Map a `run_id` to the `agent_id` that owns it.
    ///
    /// `None` → **wiring bug** (Round-4 W2 fix). `RunManager` only calls
    /// the auto-mode advancer for already-detected auto-mode runs
    /// (`is_auto_mode(task_id)` gate at `run-manager/src/run.rs:661`),
    /// so a `None` return indicates the Reader's internal state is stale
    /// or never-populated. The impl returns
    /// `RunError::InvalidState("auto-loop: no agent_id mapping for run_id")`
    /// to surface the wiring bug loudly.
    fn agent_id_for_run(&self, run_id: &str) -> Option<String>;

    /// Read the recorded `complete_cycle_request` for an agent. `None` →
    /// no such request → normal round-advance (the impl returns
    /// [`RoundDecision::ContinueAllowed`]).
    fn complete_cycle_request(&self, agent_id: &str) -> Option<CompletionSummary>;

    /// Read the iteration's keep/discard/crash final_status. The
    /// integrated loop sets this just before invoking the advancer.
    /// **NO DEFAULT** — if the production wiring forgets to populate,
    /// the impl surfaces an `InvalidState` error rather than silently
    /// composing the wrong `final_status: keep` decision string
    /// (Round-3 W2 fix).
    fn last_iteration_status(&self, agent_id: &str) -> Option<IterationStatus>;

    /// CONTRACT-141 invariant 2: consulted before emitting
    /// [`RoundDecision::ContinueAllowed`]. [`BudgetDecision::Deny`]`(reason)
    /// → `[`RoundDecision::Blocked`]`(reason)`. **NO DEFAULT** —
    /// production wiring MUST provide it (Round-3 Critical fix). Tests
    /// pass an in-memory mock that returns either
    /// [`BudgetDecision::Allow`] or [`BudgetDecision::Deny`].
    fn budget_decision(&self, run_id: &str, agent_id: &str) -> BudgetDecision;
}

/// CONTRACT-141 impl for Auto-mode. Stateless across runs — all state
/// reads go through the injected reader. Struct name pinned to MODULE-015
/// AC-16 "AutoLoopDriver is sole round advancer in Auto mode": this is
/// the `auto-loop` crate's [`RoundAdvancer`] impl.
pub struct AutoLoopRoundAdvancer {
    reader: Arc<dyn AutoStateReader>,
}

impl AutoLoopRoundAdvancer {
    /// Construct with the given [`AutoStateReader`] (typically an
    /// `Arc<dyn AutoStateReader>` shared with the integrated-loop
    /// coordinator).
    pub fn new(reader: Arc<dyn AutoStateReader>) -> Self {
        Self { reader }
    }
}

#[async_trait]
impl RoundAdvancer for AutoLoopRoundAdvancer {
    async fn on_complete_round(
        &self,
        run_id: &str,
        _result: RoundResult,
    ) -> Result<RoundDecision, RunError> {
        // Round-4 W2 fix: fail-CLOSED when the Reader can't resolve
        // run_id to an agent_id. Rationale: RunManager::complete_round
        // already gates on `is_auto_mode(task_id)` before invoking the
        // auto-mode advancer (per crates/run-manager/src/run.rs:661), so
        // any run_id reaching this impl SHOULD have a registered
        // agent_id mapping. None means a wiring bug — surface it as
        // InvalidState rather than silently emitting ContinueAllowed
        // (which would bypass budget gating + the complete-cycle
        // terminal path).
        let Some(agent_id) = self.reader.agent_id_for_run(run_id) else {
            return Err(RunError::InvalidState(
                "auto-loop: no agent_id mapping for run_id".to_string(),
            ));
        };

        // Auto-mode complete-cycle terminal path (PRD §4.7.7 line 934 —
        // priority over budget gate per audit Round-2 C1 fix).
        // Rationale: §4.7.7 explicitly prioritizes the complete-cycle
        // termination block ("# 1. Termination path (priority)"). If
        // the agent has already requested complete-cycle and the
        // iteration's final_status is known, the round_completed event
        // is `Blocked("completed: <outcome>, final_status: …")`
        // regardless of budget — the run is ending. CONTRACT-141
        // invariant 2 only requires budget check BEFORE
        // `ContinueAllowed`, not before any `Blocked` decision.
        if let Some(summary) = self.reader.complete_cycle_request(&agent_id) {
            // Round-3 W2 fix: fail-CLOSED if the integrated loop forgot
            // to set last_iteration_status. The advancer would otherwise
            // compose `final_status: keep` regardless of the real
            // terminal status, which silently misrepresents
            // discard/crash outcomes in the round_completed event.
            // Production wiring MUST populate this before invoking.
            let Some(status) = self.reader.last_iteration_status(&agent_id) else {
                return Err(RunError::InvalidState(
                    "auto-loop: missing last_iteration_status".to_string(),
                ));
            };
            // Adversarial Round-1 W3 fix: PRD §4.7.3 `outcome` is
            // agent-emitted. Strip newline / control / ANSI-escape
            // characters before forwarding to compose_complete_cycle_decision,
            // since the composed string flows verbatim into operator
            // audit logs + EventBus round_completed.decision payloads.
            // The length-cap downstream still applies (driver.rs
            // MAX_DECISION_REASON_BYTES). Replacement char `_` keeps the
            // outcome string analyzable while neutralizing log-line
            // injection / ANSI terminal-corruption attempts. The
            // integrated-loop slice MUST add a separate PII redaction
            // pass before emission (per slice-B driver.rs guidance);
            // slice-C only addresses the control-char attack surface.
            let sanitized_outcome = sanitize_for_audit(&summary.outcome);
            let sanitized = CompletionSummary {
                outcome: sanitized_outcome,
                final_metrics: summary.final_metrics,
            };
            return Ok(compose_complete_cycle_decision(&sanitized, status));
        }

        // CONTRACT-141 invariant 2: RunBudget check BEFORE
        // ContinueAllowed (normal path only). Deny → Blocked(reason)
        // per the contract's "Deny → Blocked" rule. Uses canonical
        // advance_shared_types::capability::BudgetDecision (no shadow
        // type).
        if let BudgetDecision::Deny(reason) = self.reader.budget_decision(run_id, &agent_id) {
            return Ok(RoundDecision::Blocked(reason));
        }

        Ok(RoundDecision::ContinueAllowed)
    }
}
