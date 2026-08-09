//! Structural guardrail test: asserts that `traits.rs` does NOT contain the string
//! `sanitize` as a method reference.
//!
//! Slice A' previously had a bug where the `CallableInventoryReader` rustdoc pointed
//! implementers at a non-existent `PromptInjectionHelpers::sanitize` method. The real
//! API per MODULE-012-security.md lines 515-523 is `flag_injection_patterns` and
//! `wrap_with_boundary`. The Round 3 Codex Adversarial Evaluator caught this
//! invented-API reference.
//!
//! This test guards against that regression class by string-scanning the source file
//! for the banned token. If a future edit reintroduces `sanitize` as a documentation
//! reference, this test fails loudly at `cargo test` time — a load-bearing property,
//! unlike the earlier filesystem-existence check which was tautological (the test
//! binary could not compile unless those files existed).

#[test]
fn traits_rs_does_not_reference_nonexistent_sanitize_method() {
    let src = include_str!("../src/traits.rs");
    assert!(
        !src.contains("sanitize"),
        "traits.rs must not reference PromptInjectionHelpers::sanitize — the canonical \
         API per MODULE-012-security.md:515-523 is flag_injection_patterns + \
         wrap_with_boundary. A prior revision of Slice A' used the wrong method name."
    );
}
