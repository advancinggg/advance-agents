//! AC-16 (sole round advancer in Auto mode) + AC-20 (complete-cycle
//! returns Blocked("completed: …")) + CONTRACT-141 invariant 2 (Reads
//! RunBudget; Deny → Blocked(reason)) + fail-CLOSED None mappings
//! (Round-3 W2 / Round-4 W2 fixes).

mod common;

use std::sync::Arc;

use advance_scheduler_auto_loop::{AutoLoopRoundAdvancer, CompletionSummary, IterationStatus};
use advance_shared_types::capability::BudgetDecision;
use advance_shared_types::run::{RoundAdvancer, RoundDecision, RoundResult, RunError};

use common::MockAutoStateReader;

fn empty_result() -> RoundResult {
    RoundResult {
        summary: None,
        metrics: Vec::new(),
    }
}

fn summary(outcome: &str) -> CompletionSummary {
    CompletionSummary {
        outcome: outcome.to_string(),
        final_metrics: Vec::new(),
    }
}

// MODULE-015-T16-slC.a — unknown run_id (Reader returns None for
// agent_id_for_run) → fail-CLOSED RunError::InvalidState. Round-4 W2 fix.
#[tokio::test]
async fn unknown_run_returns_invalid_state() {
    let reader = MockAutoStateReader::new(); // empty maps
    let advancer = AutoLoopRoundAdvancer::new(Arc::new(reader));
    let err = advancer
        .on_complete_round("run-unknown", empty_result())
        .await
        .expect_err("expected InvalidState");
    match err {
        RunError::InvalidState(reason) => {
            assert!(
                reason.contains("no agent_id mapping"),
                "InvalidState reason should mention missing mapping; got: {reason}"
            );
        }
        other => panic!("expected InvalidState, got {other:?}"),
    }
}

// MODULE-015-T16-slC.b — Reader maps run → agent, budget Allow,
// complete_cycle_request None → ContinueAllowed.
#[tokio::test]
async fn no_complete_cycle_request_returns_continue_allowed() {
    let reader = MockAutoStateReader::new()
        .with_agent_for_run("run-a", "alice")
        .with_budget("run-a", BudgetDecision::Allow);
    let advancer = AutoLoopRoundAdvancer::new(Arc::new(reader));
    let decision = advancer
        .on_complete_round("run-a", empty_result())
        .await
        .expect("ContinueAllowed expected");
    assert_eq!(decision, RoundDecision::ContinueAllowed);
}

// MODULE-015-T16-slC.c — CONTRACT-141 invariant 2: budget Deny on the
// NORMAL path (no complete-cycle request) → Blocked(reason). Audit
// Round-2 C1 fix: budget gate ONLY applies to the ContinueAllowed
// branch; the complete-cycle terminal path (PRD §4.7.7 priority) wins
// over budget denial (see `complete_cycle_wins_over_budget_deny` below).
#[tokio::test]
async fn budget_deny_on_normal_path_returns_blocked_with_reason() {
    let reader = MockAutoStateReader::new()
        .with_agent_for_run("run-a", "alice")
        .with_budget(
            "run-a",
            BudgetDecision::Deny("budget-exceeded-tokens".to_string()),
        );
    // No complete-cycle request configured — normal path applies.
    let advancer = AutoLoopRoundAdvancer::new(Arc::new(reader));
    let decision = advancer
        .on_complete_round("run-a", empty_result())
        .await
        .expect("Blocked expected");
    assert_eq!(
        decision,
        RoundDecision::Blocked("budget-exceeded-tokens".to_string()),
        "budget Deny on normal path must produce Blocked(reason)"
    );
}

// MODULE-015-T16-slC.c2 — Audit Round-2 C1 fix: complete-cycle terminal
// path (PRD §4.7.7 priority) wins over budget Deny. When the agent has
// recorded a complete-cycle request AND budget says Deny, the
// round_completed decision MUST be `Blocked("completed: …")`, not
// `Blocked("budget-exceeded-…")` — the run is ending via the
// complete-cycle path and CONTRACT-141 invariant 2 only gates
// `ContinueAllowed`, not any Blocked decision.
#[tokio::test]
async fn complete_cycle_wins_over_budget_deny() {
    let reader = MockAutoStateReader::new()
        .with_agent_for_run("run-a", "alice")
        .with_budget(
            "run-a",
            BudgetDecision::Deny("budget-exceeded-tokens".to_string()),
        )
        .with_complete_cycle("alice", summary("research-converged"))
        .with_status("alice", IterationStatus::Keep);
    let advancer = AutoLoopRoundAdvancer::new(Arc::new(reader));
    let decision = advancer
        .on_complete_round("run-a", empty_result())
        .await
        .expect("Blocked expected");
    match decision {
        RoundDecision::Blocked(s) => {
            assert_eq!(
                s, "completed: research-converged, final_status: keep",
                "complete-cycle priority path must compose `completed:` decision \
                 regardless of budget denial"
            );
        }
        other => panic!("expected Blocked(completed:…); got {other:?}"),
    }
}

// MODULE-015-T20-slC.a — complete-cycle + Keep → Blocked("completed: <outcome>,
// final_status: keep") verbatim per PRD §4.7.7 line 934.
#[tokio::test]
async fn complete_cycle_returns_blocked_completed_keep() {
    let reader = MockAutoStateReader::new()
        .with_agent_for_run("run-a", "alice")
        .with_budget("run-a", BudgetDecision::Allow)
        .with_complete_cycle("alice", summary("research-converged"))
        .with_status("alice", IterationStatus::Keep);
    let advancer = AutoLoopRoundAdvancer::new(Arc::new(reader));
    let decision = advancer
        .on_complete_round("run-a", empty_result())
        .await
        .expect("Blocked expected");
    match decision {
        RoundDecision::Blocked(s) => {
            assert_eq!(
                s, "completed: research-converged, final_status: keep",
                "decision text must match PRD §4.7.7 line 934 verbatim"
            );
        }
        other => panic!("expected Blocked, got {other:?}"),
    }
}

// MODULE-015-T20-slC.b — complete-cycle + Discard → final_status: discard.
#[tokio::test]
async fn complete_cycle_returns_blocked_completed_discard() {
    let reader = MockAutoStateReader::new()
        .with_agent_for_run("run-a", "alice")
        .with_budget("run-a", BudgetDecision::Allow)
        .with_complete_cycle("alice", summary("primary-regressed"))
        .with_status("alice", IterationStatus::Discard);
    let advancer = AutoLoopRoundAdvancer::new(Arc::new(reader));
    let decision = advancer
        .on_complete_round("run-a", empty_result())
        .await
        .expect("Blocked expected");
    match decision {
        RoundDecision::Blocked(s) => {
            assert_eq!(s, "completed: primary-regressed, final_status: discard");
        }
        other => panic!("expected Blocked, got {other:?}"),
    }
}

// MODULE-015-T20-slC.d — Adversarial Round-1 W3 fix: outcome
// sanitization. Newline, ANSI escape, tab, and other control characters
// in agent-emitted CompletionSummary.outcome are replaced with `_`
// before flowing into the round_completed decision string.
#[tokio::test]
async fn outcome_with_control_chars_sanitized() {
    let reader = MockAutoStateReader::new()
        .with_agent_for_run("run-a", "alice")
        .with_budget("run-a", BudgetDecision::Allow)
        .with_complete_cycle("alice", summary("ok\n\x1b[2Jadmin_secret_leaked=AKIA"))
        .with_status("alice", IterationStatus::Keep);
    let advancer = AutoLoopRoundAdvancer::new(Arc::new(reader));
    let decision = advancer
        .on_complete_round("run-a", empty_result())
        .await
        .expect("Blocked expected");
    match decision {
        RoundDecision::Blocked(s) => {
            // Newline and ESC must be replaced with `_`. The `[2J` ANSI
            // body is non-control text after the ESC is replaced, so it
            // remains visible (but no longer an executable terminal
            // sequence).
            assert!(!s.contains('\n'), "newline must be sanitized: {s:?}");
            assert!(!s.contains('\x1b'), "ESC must be sanitized: {s:?}");
            // The reason still starts with the canonical prefix.
            assert!(s.starts_with("completed: ok"), "unexpected prefix: {s:?}");
            // Replacement character `_` appears where control chars used to be.
            assert!(s.contains('_'), "sanitization marker `_` expected: {s:?}");
        }
        other => panic!("expected Blocked, got {other:?}"),
    }
}

// MODULE-015-T20-slC.c — complete-cycle + Crash → final_status: crash.
#[tokio::test]
async fn complete_cycle_returns_blocked_completed_crash() {
    let reader = MockAutoStateReader::new()
        .with_agent_for_run("run-a", "alice")
        .with_budget("run-a", BudgetDecision::Allow)
        .with_complete_cycle("alice", summary("guardrail-tripped"))
        .with_status("alice", IterationStatus::Crash);
    let advancer = AutoLoopRoundAdvancer::new(Arc::new(reader));
    let decision = advancer
        .on_complete_round("run-a", empty_result())
        .await
        .expect("Blocked expected");
    match decision {
        RoundDecision::Blocked(s) => {
            assert_eq!(s, "completed: guardrail-tripped, final_status: crash");
        }
        other => panic!("expected Blocked, got {other:?}"),
    }
}

// MODULE-015-T16c-slC — Round-3 W2 fail-CLOSED: complete_cycle_request Some
// but last_iteration_status None → RunError::InvalidState. Replaces the
// previous "default to Keep" behavior.
#[tokio::test]
async fn missing_last_iteration_status_errors() {
    let reader = MockAutoStateReader::new()
        .with_agent_for_run("run-a", "alice")
        .with_budget("run-a", BudgetDecision::Allow)
        .with_complete_cycle("alice", summary("stop-please"));
    // NO with_status() — status_for_agent map is empty.
    let advancer = AutoLoopRoundAdvancer::new(Arc::new(reader));
    let err = advancer
        .on_complete_round("run-a", empty_result())
        .await
        .expect_err("expected InvalidState");
    match err {
        RunError::InvalidState(reason) => {
            assert!(
                reason.contains("missing last_iteration_status"),
                "InvalidState reason should mention missing last_iteration_status; got: {reason}"
            );
        }
        other => panic!("expected InvalidState, got {other:?}"),
    }
}

// MODULE-015-T16-slC.d — sanity: a colonless run_id reaches the impl.
// (run-manager's validate_run_id rejects ':' so the auto: prefix never
// reaches our impl; this test just verifies the impl accepts the
// expected run_id grammar without choking.)
#[tokio::test]
async fn colonless_run_id_admitted() {
    let reader = MockAutoStateReader::new()
        .with_agent_for_run("run_with_underscore-and-dash", "alice")
        .with_budget("run_with_underscore-and-dash", BudgetDecision::Allow);
    let advancer = AutoLoopRoundAdvancer::new(Arc::new(reader));
    let decision = advancer
        .on_complete_round("run_with_underscore-and-dash", empty_result())
        .await
        .expect("ContinueAllowed expected");
    assert_eq!(decision, RoundDecision::ContinueAllowed);
}

// MODULE-015-T16-slC.e — AC-16 grep guard: production code MUST have
// exactly one `impl RoundAdvancer for` line, and it MUST be in
// `crates/scheduler/auto-loop/src/round_advancer.rs`. Fail-CLOSED if
// `rg` is unavailable (the test panics with a diagnostic rather than
// silently passing — Round-2/3 W4 fix).
//
// **Scope brittleness note** (audit Round-1 W3): this guard's "exactly
// one" assertion is workspace-wide (any `impl RoundAdvancer for` line
// in `crates/*/src/`, excluding `**/tests/**` and `**/target/**`). The
// AC text says "AutoLoopDriver is sole round advancer **in Auto
// mode**", so a future Normal-mode RoundAdvancer impl in
// `crates/run-manager/src/` would NOT actually violate AC-16's
// intent — but it WOULD break this test. If/when that future impl
// lands, this test should be tightened to either (a) check
// `auto-loop/src/round_advancer.rs` contains exactly one impl AND
// every other production impl is gated on non-Auto-mode dispatch, or
// (b) cooperate with run-manager via a tag/marker comment that the
// audit can grep for. For now the strict assertion is acceptable
// because no other production impl exists.
#[test]
fn sole_round_advancer_grep_guard() {
    use std::process::Command;

    // Resolve workspace root from CARGO_MANIFEST_DIR (this crate is at
    // crates/scheduler/auto-loop/ — 3 levels below workspace root).
    let workspace_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(3)
        .expect("workspace root from CARGO_MANIFEST_DIR ancestor[3]")
        .to_path_buf();

    let output = Command::new("rg")
        .args([
            "-n",
            "^impl RoundAdvancer for", // anchored to line start — excludes docstring mentions
            "--type",
            "rust",
            "--glob",
            "!**/tests/**",
            "--glob",
            "!**/target/**",
        ])
        .arg(workspace_root.join("crates"))
        .output()
        .expect("invoking rg must succeed; install ripgrep");

    // rg exit-code 0 = matches found, 1 = no matches; both acceptable.
    // ≥2 indicates an executable error — panic with diagnostic.
    assert!(
        output.status.success() || output.status.code() == Some(1),
        "rg invocation failed: status={:?}, stderr={}",
        output.status,
        String::from_utf8_lossy(&output.stderr),
    );
    let stdout = String::from_utf8(output.stdout).expect("rg stdout utf8");
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(
        lines.len(),
        1,
        "expected exactly one production `impl RoundAdvancer for` line; \
         got {} lines: {:#?}",
        lines.len(),
        lines
    );
    assert!(
        lines[0].contains("/scheduler/auto-loop/src/round_advancer.rs"),
        "sole `impl RoundAdvancer for` must be in auto-loop/src/round_advancer.rs; \
         got: {}",
        lines[0]
    );
}
