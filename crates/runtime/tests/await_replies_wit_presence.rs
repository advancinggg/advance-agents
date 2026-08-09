//! MODULE-007-T01 — AC-01 WIT presence verification (slice m007-A).
//!
//! Verifies the slice-A foundation invariant: `await-replies` and its supporting
//! types are declared in the `agent-messaging` interface, in BOTH the host WIT
//! and its byte-identical fixture mirror. Precedent: `mcp_wit_presence.rs`
//! (Slice SB-20).
//!
//! Three sub-tests:
//! 1. String-level presence — both WIT files contain the canonical PRD §9.2
//!    symbols (`await-replies`, `variant await-request`, `variant await-mode`,
//!    `variant timeout-policy`, `variant orchestration-error`, etc.).
//! 2. WIT-parser structural — `wit_parser::Resolve::push_str` parses
//!    successfully; `interface agent-messaging` resolves; the `await-replies`
//!    function is present.
//! 3. No `wait-for` regression — the slice-A "await-replies is the SOLE async
//!    primitive" invariant requires no `wait-for` identifier in the host WIT
//!    file (replaced by await-replies per PRD §4.4).
//!
//! Note: this test deliberately verifies the WIT *signature surface*, not
//! WASM-level invocation behavior — the host-fn handler + call_async fiber
//! suspension wiring (AC-08/14) is slice B. T42 architectural invariant
//! (advance-host world has zero function-bearing imports) stays out of
//! scope here because `agent-messaging` is not imported by `world
//! advance-host`; that's the existing slice-A `agent-messaging` posture and
//! the additive `await-replies` extension does not change it. See
//! `mcp_wit_presence.rs::sb_20_advance_host_world_has_no_mcp_client_import`
//! for the symmetric M017 check pattern; the M007 equivalent ships with the
//! slice-B host-fn handler when that lands.

use wit_parser::Resolve;

const HOST_WIT: &str = include_str!("../wit/advance.wit");
const FIXTURE_WIT: &str = include_str!("fixtures/guest-rust-minimal/wit/advance.wit");

/// String-level presence check across both WIT files (host + fixture).
/// 12 canonical PRD §9.2 symbols.
#[test]
fn m007_a_await_replies_declared_in_both_wit_files() {
    let canonical_symbols = &[
        "await-replies:",
        "variant await-request",
        "agent-request(agent-await-request)",
        "component-finished(component-await-request)",
        "record agent-await-request",
        "record component-await-request",
        "record await-options",
        "variant await-mode",
        "all-of",
        "any-of",
        "variant timeout-policy",
        "return-partial",
        "record await-result",
        "record reply-result",
        "variant reply-status",
        "variant orchestration-error",
    ];
    for sym in canonical_symbols {
        assert!(
            HOST_WIT.contains(sym),
            "host WIT must declare `{sym}` (slice m007-A AC-01)"
        );
        assert!(
            FIXTURE_WIT.contains(sym),
            "fixture WIT must mirror `{sym}` (byte-identical parity)"
        );
    }
}

/// Structural parse via wit_parser::Resolve. Ensures the WIT block is
/// syntactically valid + the `agent-messaging` interface contains
/// `await-replies` as a top-level function.
#[test]
fn m007_a_await_replies_parses_via_wit_parser() {
    let mut resolve = Resolve::default();
    let pkg = resolve
        .push_str("advance.wit", HOST_WIT)
        .expect("host WIT parses");

    // Find `interface agent-messaging` and assert it contains
    // `await-replies` as a function.
    let mut found = false;
    for (_iface_id, iface) in resolve.interfaces.iter() {
        if iface.name.as_deref() == Some("agent-messaging") {
            assert!(
                iface.functions.contains_key("await-replies"),
                "agent-messaging interface must declare `await-replies` function"
            );
            // Also verify the supporting types are present.
            for type_name in &[
                "await-request",
                "agent-await-request",
                "component-await-request",
                "await-options",
                "await-mode",
                "timeout-policy",
                "await-result",
                "reply-result",
                "reply-status",
                "orchestration-error",
            ] {
                assert!(
                    iface.types.contains_key(*type_name),
                    "agent-messaging interface must declare type `{type_name}`"
                );
            }
            found = true;
            break;
        }
    }
    assert!(found, "agent-messaging interface must exist in host WIT");

    // Sanity: fixture WIT also parses (byte-identical to host).
    let mut fixture_resolve = Resolve::default();
    fixture_resolve
        .push_str("fixture/advance.wit", FIXTURE_WIT)
        .expect("fixture WIT parses");

    // Suppress unused warning on `pkg` — kept for future structural checks.
    let _ = pkg;
}

/// AC-01 sole-async-primitive invariant: `wait-for` (the pre-slice
/// async primitive per PRD §4.4) must NOT appear in the host WIT.
#[test]
fn m007_a_no_wait_for_in_host_wit() {
    // Use a word-boundary search to avoid false positives on identifiers
    // that happen to contain the substring (e.g. hypothetical
    // `wait-foreign`).
    for line in HOST_WIT.lines() {
        // Strip leading whitespace + scan tokens.
        let trimmed = line.trim_start();
        // Comments excluded — `wait-for` appearing inside a comment about
        // history would not be a regression.
        if trimmed.starts_with("//") || trimmed.starts_with("/*") {
            continue;
        }
        // Token-ish check: split on punctuation that delimits WIT
        // identifiers.
        let tokens: Vec<&str> = trimmed
            .split(|c: char| !(c.is_ascii_alphanumeric() || c == '-' || c == '_'))
            .collect();
        for tok in tokens {
            assert_ne!(
                tok, "wait-for",
                "host WIT must NOT declare `wait-for` (slice-A AC-01 sole-async-primitive invariant; replaced by await-replies per PRD §4.4)"
            );
        }
    }
}
