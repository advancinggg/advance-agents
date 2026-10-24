# guest-rust-callables

Reference **catalog-driven** guest: a real `wasm32-unknown-unknown` wit-bindgen guest
that imports `advance:runtime/agent-llm@0.1.0` and `advance:runtime/agent-callables@0.1.0`.

Targets the `advance-host-callables` world (imports `agent-llm` + `agent-callables`,
exports `message-driven` + `runnable`). On `handle-message` it:

1. Calls `list-callables` once (keeps that import live).
2. Round 0: `generate(prompt, callables: all, transcript: continue)`.
3. Reads **only** the host envelope `{"tool_calls":[...]}` from `parsed-output`
   (no text parsing, no DSML).
4. For each entry, calls `invoke-callable(id, name, arguments)`.
5. Later rounds: `generate("", callables: all, transcript: continue)`.
6. Stops when the envelope is empty, or after 8 rounds.

Payload is the last assistant text, or the last invoke result when that text is
empty. `run` is a trivial `Completed`.

`guest-rust-hello-llm` stays the one-shot generate fixture used by SYS-AC.
`guest-rust-llm-tools` stays the guest-defined `params.tools` fixture. This guest
is the first-open CREATE_DRIVER (`crates/advance-home/src/fixtures/behavior.core.wasm`).

The committed `../guest-rust-callables.core.wasm` artifact is wrapped to a Component
at test time via `wit_component::ComponentEncoder` / `build_agent::encode_core_to_component`.
It instantiates through the host's `advance-host-with-capabilities` bindgen — only the
EXPORTS must match; the `agent-llm` and `agent-callables` IMPORTS are satisfied
dynamically by the host `CapabilityInjector`.

## WIT note

The guest's `wit/advance.wit` is the canonical host WIT (`crates/runtime/wit/advance.wit`)
plus the appended `advance-host-callables` world. `agent-callables` and
`llm-params.{callables, transcript}` are already on the canonical package. Do not
copy `agent-fs`. `llm-response` is **not** extended; tool calls travel in `parsed-output`.

## Regen procedure

1. Ensure the wasm32 target: `rustup target add wasm32-unknown-unknown`.
2. If the canonical WIT changed, re-derive `wit/advance.wit`:
   ```
   cp ../../wit/advance.wit wit/advance.wit
   # then append:
   # world advance-host-callables {
   #     import agent-llm;
   #     import agent-callables;
   #     export message-driven;
   #     export runnable;
   # }
   ```
   Validate: `wasm-tools component wit wit/advance.wit`.
3. First-time bootstrap (no Cargo.lock): `cargo generate-lockfile`.
4. Build (LINKEDIT workaround on this Darwin toolchain):
   ```
   RUSTFLAGS="-C debuginfo=0 -C split-debuginfo=unpacked" CARGO_INCREMENTAL=0 CARGO_NET_OFFLINE=true \
     cargo build --target wasm32-unknown-unknown --release --locked
   ```
5. Copy artifact:
   `cp target/wasm32-unknown-unknown/release/guest_rust_callables.wasm ../guest-rust-callables.core.wasm`
   and `cp ../guest-rust-callables.core.wasm ../../../advance-home/src/fixtures/behavior.core.wasm`.
6. Verify size < 500 KiB: `wc -c ../guest-rust-callables.core.wasm`.
7. Confirm imports: `wasm-tools print ../guest-rust-callables.core.wasm | grep import`
   — exactly `agent-llm.generate`, `agent-callables.list-callables`,
   `agent-callables.invoke-callable`.
8. `cargo clean`. Do NOT commit `target/`.
9. Commit atomically: the `.wasm` artifact, `Cargo.lock`, WIT, and the CREATE_DRIVER copy.
