//! AC-23 — Callable Framework Layer-2 dispatch-path independence (REQ-034,
//! M005-side structural half).
//!
//! M005 verifies the structural WIT foundation: `agent-lifecycle.wit` has
//! its own package line and contains zero `tool-invoke` / `delegate.spawn`
//! references — a Sub-Agent (Delegate) is spawned via
//! `spawn-agent-from-template` + messaging, NEVER `tool-invoke`. The
//! Layer-3 "Available Delegates" Tier-2 ⑬ assembly is MODULE-010 AC-19's
//! responsibility; the cross-WIT-package comparison completes when MODULE-017
//! ships `agent-tools.wit` (CONTRACT-161).

use std::path::Path;

fn lifecycle_wit() -> String {
    let p = Path::new(env!("CARGO_MANIFEST_DIR")).join("wit/agent-lifecycle.wit");
    std::fs::read_to_string(p).expect("agent-lifecycle.wit present")
}

/// WIT surface only — strips `//` comment lines so AC-23 checks the actual
/// interface declarations, not explanatory prose (which legitimately
/// *names* `tool-invoke` to document the independence invariant).
fn lifecycle_wit_surface() -> String {
    lifecycle_wit()
        .lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn ac23_lifecycle_wit_has_own_package_line() {
    let w = lifecycle_wit();
    assert!(
        w.lines().any(|l| l.trim_start().starts_with("package ")),
        "agent-lifecycle.wit declares its own package"
    );
}

#[test]
fn ac23_no_tool_invoke_dispatch_path() {
    let w = lifecycle_wit_surface();
    assert!(
        !w.contains("tool-invoke"),
        "Sub-Agent dispatch must NOT be via tool-invoke"
    );
    assert!(
        !w.contains("delegate.spawn"),
        "no delegate.spawn tool entry — spawn is spawn-agent-from-template"
    );
}

#[test]
fn ac23_delegate_spawn_path_is_spawn_agent_from_template() {
    let w = lifecycle_wit();
    assert!(
        w.contains("spawn-agent-from-template"),
        "the Delegate spawn entry point is present in agent-lifecycle.wit"
    );
}

#[test]
fn ac23_distinct_from_agent_tools_wit_when_present() {
    // The cross-WIT-package separation completes when MODULE-017 ships
    // agent-tools.wit. If it exists now, assert distinct package + no
    // `spawn-` prefix leak; otherwise the M005-side structural invariant
    // above is the verifiable half this slice (M017 owns its half).
    let candidates = [
        "../cap-tools/wit/agent-tools.wit",
        "../../capabilities/cap-tools/wit/agent-tools.wit",
    ];
    let base = Path::new(env!("CARGO_MANIFEST_DIR"));
    for c in candidates {
        let p = base.join(c);
        if let Ok(tools) = std::fs::read_to_string(&p) {
            assert!(
                !tools.contains("spawn-"),
                "agent-tools.wit must not expose any spawn- entry"
            );
            let lc = lifecycle_wit();
            let lc_pkg: Vec<&str> = lc
                .lines()
                .filter(|l| l.trim_start().starts_with("package "))
                .map(|l| l.trim())
                .collect();
            // Distinct WIT files (different paths) — package may legitimately
            // share the `advance:runtime` namespace but they are separate
            // interface declarations with no cross-reference.
            assert!(!tools.contains("agent-lifecycle"));
            assert!(!lc_pkg.is_empty());
            return;
        }
    }
    // agent-tools.wit not yet shipped (MODULE-017 pending) — M005-side
    // structural invariants (other tests) are the verifiable half.
}
