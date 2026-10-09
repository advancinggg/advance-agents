# guest-rust-llm-noerr

Never-`Err` LLM guest. A copy of `guest-rust-hello-llm` (same
`advance-host-llm` world: import `agent-llm`, export `message-driven` and
`runnable`) whose `handle-message` never returns `Err`.

Payload `llm:<p>` uses `<p>` as the prompt; any other payload uses the whole
text; an empty prompt falls back to `hello`. The host call is
`agent-llm::generate`. The action payload is `llm-ok:<text>` on success or
`llm-err:<e:?>` on a host-side LLM error. `run` is a trivial `Completed`.

The committed `../guest-rust-llm-noerr.core.wasm` is wrapped to a Component at
test time via `wit_component::ComponentEncoder` (production wraps through
`build-agent`). The crate is excluded from the workspace.

## WIT note

`wit/advance.wit` is copied from `guest-rust-hello-llm` (canonical host WIT plus
the `advance-host-llm` world). If the canonical WIT changes, copy it again and
keep the appended world block.

## Regen procedure

1. Ensure the wasm32 target: `rustup target add wasm32-unknown-unknown`.
2. If the canonical WIT changed, re-derive `wit/advance.wit` from
   `guest-rust-hello-llm` (or `crates/runtime/wit/advance.wit` plus the
   `advance-host-llm` world). Validate: `wasm-tools component wit wit/advance.wit`.
3. First-time bootstrap (no Cargo.lock): `cargo generate-lockfile`.
4. Build: `cargo build --target wasm32-unknown-unknown --release --locked`, with rustc
   1.91.0 (the crate has no toolchain file of its own, so the workspace's
   `rust-toolchain.toml` applies, as for `guest-rust-hello-llm`). The artifact is stripped
   (`strip = true`) and records no producer, so keep that toolchain.
5. Copy artifact: `cp target/wasm32-unknown-unknown/release/guest_rust_llm_noerr.wasm ../guest-rust-llm-noerr.core.wasm`.
6. Verify size < 500 KiB: `wc -c ../guest-rust-llm-noerr.core.wasm`.
7. `cargo clean`. Do NOT commit `target/`.
8. Commit atomically: the `.wasm` artifact, `Cargo.lock`, and any WIT change.
