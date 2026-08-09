//! Slice A AC-08, AC-09 integration tests (T37-T46).

use advance_run_manager::{RepetitionAction, RepetitionGuard};
use advance_shared_types::repetition::{OutputHash, RepetitionDecision, ToolCallSignature};
use advance_shared_types::traits::RepetitionGuardCheck;

fn sig(tool_id: &str, method: &str, params_hash: u64) -> ToolCallSignature {
    ToolCallSignature {
        tool_id: tool_id.into(),
        method: method.into(),
        params_hash,
    }
}

fn h(b: u8) -> OutputHash {
    OutputHash([b; 32])
}

/// T37 — AC-08 tool triplet repeat at threshold.
#[test]
fn t37_tool_triplet_repeat_at_threshold() {
    let g = RepetitionGuard::new(5, 3, RepetitionAction::Terminate);
    let s = sig("ns-fs", "read", 0x42);
    assert!(matches!(
        g.record_tool_call("agent-a", s.clone()),
        RepetitionDecision::Pass
    ));
    assert!(matches!(
        g.record_tool_call("agent-a", s.clone()),
        RepetitionDecision::Pass
    ));
    assert!(matches!(
        g.record_tool_call("agent-a", s.clone()),
        RepetitionDecision::Terminate(_)
    ));
    let other = sig("ns-fs", "read", 0x99);
    assert!(matches!(
        g.record_tool_call("agent-a", other),
        RepetitionDecision::Pass
    ));
}

/// T38 — AC-08 window eviction.
#[test]
fn t38_tool_triplet_window_eviction() {
    let g = RepetitionGuard::new(3, 3, RepetitionAction::Terminate);
    let a = sig("ns-fs", "read", 0x42);
    let b = sig("ns-fs", "read", 0x99);
    // A,A,A → Terminate on 3rd.
    assert!(matches!(
        g.record_tool_call("agent-a", a.clone()),
        RepetitionDecision::Pass
    ));
    assert!(matches!(
        g.record_tool_call("agent-a", a.clone()),
        RepetitionDecision::Pass
    ));
    assert!(matches!(
        g.record_tool_call("agent-a", a.clone()),
        RepetitionDecision::Terminate(_)
    ));
    // B pushes oldest A out (window=3 → [A,A,B]).
    assert!(matches!(
        g.record_tool_call("agent-a", b),
        RepetitionDecision::Pass
    ));
    // A again — window becomes [A,B,A], count of A = 2 < threshold → Pass.
    assert!(matches!(
        g.record_tool_call("agent-a", a),
        RepetitionDecision::Pass
    ));
}

/// T39 — AC-08 per-agent isolation.
#[test]
fn t39_tool_triplet_different_agent_independent() {
    let g = RepetitionGuard::new(5, 3, RepetitionAction::Terminate);
    let s = sig("ns-fs", "read", 0x42);
    for _ in 0..2 {
        let _ = g.record_tool_call("agent-a", s.clone());
    }
    assert!(matches!(
        g.record_tool_call("agent-a", s.clone()),
        RepetitionDecision::Terminate(_)
    ));
    assert!(matches!(
        g.record_tool_call("agent-b", s),
        RepetitionDecision::Pass
    ));
}

/// T40 — Identifier validation fail-safe.
#[test]
fn t40_tool_triplet_rejects_invalid_agent_id() {
    let g = RepetitionGuard::new(5, 3, RepetitionAction::Terminate);
    let s = sig("ns-fs", "read", 0x42);
    let bads = [
        "",
        "../etc/passwd",
        "with\0null",
        "with\nnewline",
        "with space",
    ];
    for bad in bads {
        for _ in 0..5 {
            assert!(
                matches!(g.record_tool_call(bad, s.clone()), RepetitionDecision::Pass),
                "invalid agent_id {bad:?} must Pass (fail-safe)"
            );
        }
    }
    let overlong = "a".repeat(129);
    assert!(matches!(
        g.record_tool_call(&overlong, s),
        RepetitionDecision::Pass
    ));
}

/// T41 — AC-09 output hash sequential repeat.
#[test]
fn t41_output_hash_sequential_repeat() {
    let g = RepetitionGuard::new(5, 3, RepetitionAction::Terminate);
    assert!(matches!(
        g.record_output("agent-a", h(0)),
        RepetitionDecision::Pass
    ));
    assert!(matches!(
        g.record_output("agent-a", h(0)),
        RepetitionDecision::Pass
    ));
    assert!(matches!(
        g.record_output("agent-a", h(0)),
        RepetitionDecision::Terminate(_)
    ));
}

/// T42 — AC-09 interrupted run-length resets.
#[test]
fn t42_output_hash_interrupted_resets() {
    let g = RepetitionGuard::new(5, 3, RepetitionAction::Terminate);
    assert!(matches!(
        g.record_output("agent-a", h(0)),
        RepetitionDecision::Pass
    ));
    assert!(matches!(
        g.record_output("agent-a", h(0)),
        RepetitionDecision::Pass
    ));
    assert!(matches!(
        g.record_output("agent-a", h(1)),
        RepetitionDecision::Pass
    )); // different
    assert!(matches!(
        g.record_output("agent-a", h(0)),
        RepetitionDecision::Pass
    )); // run_len of A = 1
}

/// T43 — AC-09 per-agent isolation for output windows.
#[test]
fn t43_output_hash_different_agent_independent() {
    let g = RepetitionGuard::new(5, 3, RepetitionAction::Terminate);
    for _ in 0..2 {
        let _ = g.record_output("agent-a", h(0));
    }
    assert!(matches!(
        g.record_output("agent-a", h(0)),
        RepetitionDecision::Terminate(_)
    ));
    assert!(matches!(
        g.record_output("agent-b", h(0)),
        RepetitionDecision::Pass
    ));
}

/// T44 — Action policy: WarnOnly never returns Terminate.
#[test]
fn t44_warn_only_returns_warn() {
    let g = RepetitionGuard::new(5, 3, RepetitionAction::WarnOnly);
    let s = sig("t", "m", 0xAA);
    for _ in 0..5 {
        let dec = g.record_tool_call("agent-a", s.clone());
        assert!(
            !matches!(dec, RepetitionDecision::Terminate(_)),
            "WarnOnly must never Terminate"
        );
    }
}

/// T45 — Action policy: Terminate returns Terminate on threshold.
#[test]
fn t45_terminate_returns_terminate() {
    let g = RepetitionGuard::new(5, 3, RepetitionAction::Terminate);
    let s = sig("t", "m", 0xAA);
    let _ = g.record_tool_call("agent-a", s.clone());
    let _ = g.record_tool_call("agent-a", s.clone());
    assert!(matches!(
        g.record_tool_call("agent-a", s),
        RepetitionDecision::Terminate(_)
    ));
}

/// T46 — WarnThenTerminate two-stage flag flip (no inject in Slice A).
#[test]
fn t46_warn_then_terminate_two_stage_flag_flips() {
    let g = RepetitionGuard::new(5, 3, RepetitionAction::WarnThenTerminate);
    let s = sig("t", "m", 0xAA);
    // Bring agent-a to threshold for the first time.
    let _ = g.record_tool_call("agent-a", s.clone());
    let _ = g.record_tool_call("agent-a", s.clone());
    let first = g.record_tool_call("agent-a", s.clone());
    assert!(
        matches!(first, RepetitionDecision::Warn(_)),
        "first threshold trip is Warn"
    );
    // Push another matching call — still over threshold.
    let second = g.record_tool_call("agent-a", s);
    assert!(
        matches!(second, RepetitionDecision::Terminate(_)),
        "second threshold trip is Terminate"
    );
}
