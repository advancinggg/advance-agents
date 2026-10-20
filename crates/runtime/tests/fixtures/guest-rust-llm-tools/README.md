# guest-rust-llm-tools

Reference **LLM + tools** guest: a real `wasm32-unknown-unknown` wit-bindgen guest
that imports `advance:runtime/agent-llm@0.1.0` and `advance:runtime/agent-fs@0.1.0`.

Targets the `advance-host-llm-fs` world (imports `agent-llm` + `agent-fs`, exports
`message-driven` + `runnable`). On `handle-message` it:

1. Reads `msg.payload` as the user prompt (non-empty fallback — the host
   `decode_llm_request` rejects empty prompts).
2. Calls `agent-llm` `generate` with `params.tools` for `write` / `list` / `read` /
   `delete`.
3. If `parsed-output` is the host envelope `{"tool_calls":[...]}` (or the model
   dumped DSML into `text`), dispatches each call through `agent-fs` and folds the
   results into the next prompt.
4. Repeats until the model returns text with no tool calls, or 8 rounds.

`run` is a trivial `Completed`.

`guest-rust-hello-llm` stays the one-shot generate fixture used by SYS-AC. This
guest is the first-open CREATE_DRIVER (`crates/advance-home/src/fixtures/behavior.core.wasm`).

The committed `../guest-rust-llm-tools.core.wasm` artifact is wrapped to a Component
at test time via `wit_component::ComponentEncoder` / `build_agent::encode_core_to_component`.
It instantiates through the host's `advance-host-with-capabilities` bindgen — only the
EXPORTS must match; the `agent-llm` and `agent-fs` IMPORTS are satisfied dynamically
by the host `CapabilityInjector`.

## WIT note

The guest's `wit/advance.wit` is the canonical host WIT (`crates/runtime/wit/advance.wit`)
plus the appended `agent-fs` interface (from `crates/capabilities/cap-fs/wit/agent-fs.wit`,
`%list` / `%type` escapes kept) and the `advance-host-llm-fs` world. `llm-params.tools`
is already on the canonical `agent-llm` interface. `llm-response` is **not** extended
(hello-llm binary compat at `@0.1.0`); tool calls travel in `parsed-output`.

## Regen procedure

1. Ensure the wasm32 target: `rustup target add wasm32-unknown-unknown`.
2. If the canonical WIT changed, re-derive `wit/advance.wit`:
   ```
   cp ../../wit/advance.wit wit/advance.wit
   printf '\n// --- appended for guest-rust-llm-tools: agent-fs + llm-fs world ---\n' >> wit/advance.wit
   sed -n '3,69p' ../../../../capabilities/cap-fs/wit/agent-fs.wit >> wit/advance.wit
   # then append:
   # world advance-host-llm-fs {
   #     import agent-llm;
   #     import agent-fs;
   #     export message-driven;
   #     export runnable;
   # }
   ```
   Validate: `wasm-tools component wit wit/advance.wit`.
3. First-time bootstrap (no Cargo.lock): `cargo generate-lockfile`.
4. Build: `cargo build --target wasm32-unknown-unknown --release --locked`.
5. Copy artifact:
   `cp target/wasm32-unknown-unknown/release/guest_rust_llm_tools.wasm ../guest-rust-llm-tools.core.wasm`
   and `cp ../guest-rust-llm-tools.core.wasm ../../../advance-home/src/fixtures/behavior.core.wasm`.
6. Verify size < 500 KiB: `wc -c ../guest-rust-llm-tools.core.wasm`.
7. `cargo clean`. Do NOT commit `target/`.
8. Commit atomically: the `.wasm` artifact, `Cargo.lock`, WIT, and the CREATE_DRIVER copy.
