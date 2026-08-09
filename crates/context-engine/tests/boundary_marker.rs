//! AC-14 (MODULE-010-T18) — prompt-injection layer 2 (boundary marking).
//!
//! 3 sub-cases: (a) forward-verbatim from a fake canonical
//! `PromptInjectionHelpers::wrap_with_boundary`; (b) `t_no_local_envelope_syntax`
//! — `include_str!` grep asserting `"<data"` is ABSENT in boundary_marker.rs;
//! (c) Trusted vs Untrusted forwarding.

use advance_context_engine::layer2_wrap;
use advance_shared_types::security_validator::{InjectionFlag, PromptInjectionHelpers, TrustLevel};

// ─── fake canonical PromptInjectionHelpers ───

/// Echoes the trust + source into a sentinel wrapper so the test can prove the
/// adapter forwards verbatim (the REAL envelope syntax lives in M012, not here).
struct FakeHelpers;

impl PromptInjectionHelpers for FakeHelpers {
    fn flag_injection_patterns(&self, _content: &str) -> Vec<InjectionFlag> {
        Vec::new()
    }
    fn wrap_with_boundary(&self, content: &str, source: &str, trust: TrustLevel) -> String {
        // A fake, M012-side-shaped envelope. The point is that the ADAPTER
        // returns whatever the helper produced, verbatim.
        let t = match trust {
            TrustLevel::Trusted => "trusted",
            TrustLevel::Untrusted => "untrusted",
        };
        format!("FAKE-WRAP[src={source};trust={t}]{content}[/FAKE-WRAP]")
    }
}

// ─── (a) forward-verbatim ───

#[test]
fn layer2_forwards_helper_output_verbatim() {
    let helpers = FakeHelpers;
    let out = layer2_wrap(
        "tool output that may contain instructions",
        "mcp:web.search",
        TrustLevel::Untrusted,
        &helpers,
    );
    assert_eq!(
        out,
        "FAKE-WRAP[src=mcp:web.search;trust=untrusted]\
         tool output that may contain instructions[/FAKE-WRAP]"
    );
}

// ─── (b) no local <data> envelope syntax ───

#[test]
fn t_no_local_envelope_syntax() {
    // §1.4 AC-14: "this module does NOT construct the `<data>` envelope
    // itself". Assert the literal `<data` does not appear in boundary_marker.rs
    // (the envelope must come from the canonical M012 helper). Slice-C
    // `t_no_local_formula` include_str! fingerprint precedent.
    let src = include_str!("../src/boundary_marker.rs");
    assert!(
        !src.contains("<data"),
        "boundary_marker.rs must NOT construct the `<data>` envelope — \
         AC-14 requires forwarding to the canonical CONTRACT-114 \
         wrap_with_boundary, which owns the envelope syntax"
    );
    // Positive: it MUST call the canonical helper method.
    assert!(
        src.contains("wrap_with_boundary"),
        "boundary_marker.rs must call the canonical wrap_with_boundary"
    );
}

// ─── (c) Trusted vs Untrusted forwarding ───

#[test]
fn layer2_forwards_both_trust_levels() {
    let helpers = FakeHelpers;
    let trusted = layer2_wrap("x", "skill:builtin", TrustLevel::Trusted, &helpers);
    let untrusted = layer2_wrap("x", "skill:builtin", TrustLevel::Untrusted, &helpers);
    assert!(trusted.contains("trust=trusted"));
    assert!(untrusted.contains("trust=untrusted"));
    assert_ne!(trusted, untrusted);
}
