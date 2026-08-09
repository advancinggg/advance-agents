//! AC-14 — prompt-injection layer 2 (boundary marking).
//!
//! §1.4 AC-14: calls `PromptInjectionHelpers::wrap_with_boundary(content,
//! source, trust)` (MODULE-012) to produce the data-block boundary envelope;
//! **this module does NOT construct the boundary envelope itself**.
//!
//! This module is a **thin forwarder** over the CANONICAL CONTRACT-114
//! [`PromptInjectionHelpers`] trait (shared-types `security_validator.rs`).
//! The boundary-envelope markup (and its nonce-based escaping per the
//! CONTRACT-114 implementer invariants) lives entirely in M012; MODULE-010
//! only forwards. [`TrustLevel`] is the CANONICAL shared-types enum.
//!
//! Wiring (Stage-C SAT-E, MODULE-010 §3.8): now wired into the live L4/L5
//! producer — `assembler::render_multilevel_digest` calls [`layer2_wrap`] on the
//! untrusted L4 task-summary + L5 synthesis bodies (TrustLevel::Untrusted) before
//! LLM assembly. The `t_no_local_envelope_syntax` test `include_str!`-greps THIS
//! file for the opening envelope-tag literal and asserts it is ABSENT (the §1.4
//! "does NOT construct the envelope" criterion) — which is why this doc
//! deliberately avoids writing that literal.

use advance_shared_types::security_validator::{PromptInjectionHelpers, TrustLevel};

/// Layer-2 forward: call the canonical CONTRACT-114 `wrap_with_boundary` and
/// return its output verbatim. The envelope construction (and escaping) is
/// M012's responsibility — this function does not build any markup itself.
pub fn layer2_wrap(
    content: &str,
    source: &str,
    trust: TrustLevel,
    helpers: &dyn PromptInjectionHelpers,
) -> String {
    helpers.wrap_with_boundary(content, source, trust)
}
