//! `build-agent` library — the production core→component encode step.
//!
//! [`encode_core_to_component`] wraps a `wasm32-unknown-unknown` **core module** (a
//! wit-bindgen guest's `.wasm`, which carries embedded component-type metadata) into a
//! WASM **Component** using `wit_component::ComponentEncoder`. This is exactly the encode
//! that `advance_runtime::ComponentRuntime::load_component` requires: `load_component`
//! accepts a PRE-ENCODED Component, never a bare core module. Until WS-B this encode
//! existed only in test code (`crates/runtime/tests/guest_real_rust.rs`, the
//! `system-acceptance` harness). This fn is the single encode source: the `build-agent`
//! bin calls it to produce `<ws>/.agent/behavior.component.wasm`, and the loopback turn
//! test (`crates/system-acceptance/tests/mode_llm_guest_turn.rs`) reuses it so the SAME
//! encoder that ships the production component is the one proven `load_component`-acceptable.

use anyhow::{Context, Result};
use wit_component::ComponentEncoder;

/// Encode a `wasm32-unknown-unknown` core module into a WASM Component.
///
/// `core_wasm` must be a wit-bindgen guest core module (carrying the embedded
/// component-type custom section). Returns the encoded Component bytes — the form
/// `ComponentRuntime::load_component` accepts. Errors if the bytes are not a valid core
/// module or lack the component-type metadata the encoder needs.
pub fn encode_core_to_component(core_wasm: &[u8]) -> Result<Vec<u8>> {
    let component = ComponentEncoder::default()
        .validate(true)
        .module(core_wasm)
        .context(
            "ComponentEncoder rejected the core module — is it a wit-bindgen \
             wasm32-unknown-unknown guest with embedded component-type metadata?",
        )?
        .encode()
        .context("ComponentEncoder failed to encode the component")?;
    Ok(component)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The committed `hello-llm` reference-guest core module (a real wit-bindgen guest).
    const HELLO_LLM_CORE: &[u8] =
        include_bytes!("../../runtime/tests/fixtures/guest-rust-hello-llm.core.wasm");

    #[test]
    fn encodes_real_guest_core_into_a_component() {
        let component = encode_core_to_component(HELLO_LLM_CORE).expect("encode succeeds");
        assert!(!component.is_empty(), "encoded component must be non-empty");
        // WASM Component-model binary preamble: `\0asm` magic (bytes 0..4) + version
        // low-byte 0x0d (byte 4) — distinguishing a Component from a core module (whose
        // version byte is 0x01). Proves the OUTPUT is a Component, not a passthrough core.
        assert_eq!(&component[0..4], b"\0asm", "missing WASM magic");
        assert_eq!(
            component[4], 0x0d,
            "byte 4 must be the component-model version (0x0d), not core-module 0x01"
        );
        // And it must NOT be the input core module unchanged.
        assert_ne!(
            component, HELLO_LLM_CORE,
            "output must differ from the input core module"
        );
    }

    #[test]
    fn rejects_non_wasm_bytes() {
        let err = encode_core_to_component(b"this is not a wasm module at all");
        assert!(
            err.is_err(),
            "garbage bytes must be rejected, not silently encoded"
        );
    }

    #[test]
    fn rejects_empty_bytes() {
        assert!(
            encode_core_to_component(&[]).is_err(),
            "empty input must be rejected"
        );
    }
}
