# guest-rust-hello-llm

/dev WS-B (2026-06-04) — reference **LLM guest** fixture: the FIRST real `wasm32-unknown-unknown`
guest that calls `agent-llm`.

Targets the `advance-host-llm` world (imports `agent-llm`, exports `message-driven` + `runnable`).
On `handle-message` it reads `msg.payload` as the prompt (falling back to a non-empty default when
the payload is empty — the host `decode_llm_request` rejects empty prompts), calls the imported
`agent-llm` `generate` host fn, and returns the LLM `response.text` as the payload of a single
`action`. `run` is a trivial `Completed`.

The committed `../guest-rust-hello-llm.core.wasm` artifact is wrapped to a Component:
- **in production** via the `build-agent` tool (`crates/build-agent` — the core→component encode +
  deploy step that writes `<ws>/.agent/behavior.component.wasm`);
- **at test time** via `wit_component::ComponentEncoder` (same pattern as `guest-rust-j01-skeleton`).

It instantiates through the host's `advance-host-with-capabilities` bindgen — only the EXPORTS must
match; the `agent-llm` IMPORT is satisfied dynamically by the host `CapabilityInjector` under the
**versioned** namespace `advance:runtime/agent-llm@0.1.0` (host bindgen world ≠ guest world; imports
are linker-validated, not world-validated).

## WIT note (important)

The guest's `wit/advance.wit` is the canonical host WIT (`crates/runtime/wit/advance.wit`) plus an
appended `advance-host-llm` world. Unlike `guest-rust-j01-skeleton` (which had to append the
`agent-fs` interface), `agent-llm` is **already declared at the package level** in the canonical WIT
(`interface agent-llm { generate / %stream / poll-stream }`, with the `%stream` keyword escape), so
this guest appends ONLY the world block — no interface copy.

## Regen procedure

1. Ensure the wasm32 target: `rustup target add wasm32-unknown-unknown`.
2. If the canonical WIT changed, re-derive `wit/advance.wit`:
   ```
   cp ../../wit/advance.wit wit/advance.wit
   # then append the `world advance-host-llm { import agent-llm; export message-driven; export runnable; }` block
   ```
   Validate: `wasm-tools component wit wit/advance.wit`.
3. First-time bootstrap (no Cargo.lock): `cargo generate-lockfile`.
4. Build: `cargo build --target wasm32-unknown-unknown --release --locked`.
5. Copy artifact: `cp target/wasm32-unknown-unknown/release/guest_rust_hello_llm.wasm ../guest-rust-hello-llm.core.wasm`.
6. Verify size < 500 KiB: `wc -c ../guest-rust-hello-llm.core.wasm`.
7. `cargo clean`. Do NOT commit `target/`.
8. Commit atomically: the `.wasm` artifact, `Cargo.lock`, and any WIT change.

The one-shot deploy equivalent (for an operator): from the repo root run
`cargo run -p build-agent -- --guest crates/runtime/tests/fixtures/guest-rust-hello-llm --out <ws>/.agent/behavior.component.wasm`.
