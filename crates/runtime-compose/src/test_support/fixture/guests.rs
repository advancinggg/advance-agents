//! Core-module bytes the fixture deploys as `.agent/behavior.wasm`.

pub fn minimal_core() -> &'static [u8] {
    include_bytes!("../../../../runtime/tests/fixtures/guest-rust-minimal.core.wasm")
}

pub fn hello_llm_core() -> &'static [u8] {
    include_bytes!("../../../../runtime/tests/fixtures/guest-rust-hello-llm.core.wasm")
}
