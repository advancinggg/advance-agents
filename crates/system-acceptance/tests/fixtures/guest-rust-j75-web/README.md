# guest-rust-j75-web

SYS-J-75 message-driven guest. World `advance-host-tools-fs-llm` imports
`agent-tools`, `agent-fs`, and `agent-llm`. Inbound payload selects a mode
(`search` / `hostile` / `url` / `forged-ref` / `probe`). Every mode calls
`generate` after the tool sequence.

Regen: `cargo build --target wasm32-unknown-unknown --release --locked` then
copy `target/wasm32-unknown-unknown/release/guest_rust_j75_web.wasm` to
`../guest-rust-j75-web.core.wasm` (must stay under 500 KiB).
