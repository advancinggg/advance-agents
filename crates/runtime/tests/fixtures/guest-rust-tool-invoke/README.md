# guest-rust-tool-invoke

Wave-14 Lane C (2026-06-24) — **L2 skill-tool-invoke guest** fixture for the
system-acceptance witness SYS-AC-080 (`sys_j26_progressive_skill.rs`).

The FIRST fixture that actually **CALLS** `tool-invoke` (every other fixture only
DEFINES the `agent-tools` interface for import). Imports BOTH `agent-tools`
(tool-invoke) AND `agent-fs` (write) via the new `advance-host-tools-fs` world.
Both imports are satisfied dynamically by the host `CapabilityInjector` under the
versioned namespaces `advance:runtime/agent-tools@0.1.0` +
`advance:runtime/agent-fs@0.1.0` (imports are linker-validated, not
world-validated — only the `message-driven` + `runnable` EXPORTS must match the
host bindgen `advance-host-with-capabilities`).

`handle-message` UNCONDITIONALLY invokes the skill-bundled tool at the PRD §12.4.4
canonical id `skill::echo-skill`:

```
tool-invoke("skill::echo-skill", "echo", PAYLOAD)
  - Ok(bytes) -> agent-fs::write("tool-result.bin", &bytes); state = STATE_TOOL_OK
  - Err(_)    -> state = STATE_TOOL_ERR (NO write)
```

The witness reads `tool-result.bin` back via the real `fs.read` host-fn and asserts
the bytes == a real `LazyToolRegistry::invoke` of the same tool (the committed
`echo_tool` returns its params verbatim). Discriminators: with no production bridge
(080-b), OR an unregistered/mismatched tool-id (080-c), `tool-invoke` returns
not-found → no file written.

The tool-id is HARDCODED (not parameterized): `handle-message(msg, state)` carries
no `config-data` (that field lives on `component-config`, passed only to
`init`/`run`), so a message-driven guest has no per-turn tool-id selector. The
discriminators vary the input at the HARNESS level (seed name match/mismatch;
bridge run/not-run), never via the guest.

The committed `../guest-rust-tool-invoke.core.wasm` artifact is wrapped to a
Component at test time via `wit_component::ComponentEncoder` (same pattern as
`guest-rust-await-write` / `guest-rust-with-caps`).

## WIT note

`wit/advance.wit` is the canonical host WIT (`crates/runtime/wit/advance.wit`) plus
the appended `agent-fs` interface (from `cap-fs/wit/agent-fs.wit`, `%list` keyword
escaped) plus the `advance-host-fs` / `advance-host-messaging-fs` worlds, identical
to `guest-rust-await-write/wit/advance.wit` with ONE extra world
(`advance-host-tools-fs`, which imports `agent-tools` + `agent-fs`). The canonical
WIT already defines the `agent-tools` interface (`tool-invoke` / `list-tools` /
`tool-error`), so only the new world is appended.

## Regen procedure

1. Ensure the wasm32 target: `rustup target add wasm32-unknown-unknown`.
2. If the canonical WIT changed, re-derive `wit/advance.wit` from
   `guest-rust-await-write/wit/advance.wit` and re-append the `advance-host-tools-fs`
   world. Validate: `wasm-tools component wit wit/advance.wit`.
3. First-time bootstrap (no Cargo.lock): `cargo generate-lockfile`.
4. Build: `cargo build --target wasm32-unknown-unknown --release --locked`.
5. Copy artifact: `cp target/wasm32-unknown-unknown/release/guest_rust_tool_invoke.wasm ../guest-rust-tool-invoke.core.wasm`.
6. Verify size < 500 KiB: `wc -c ../guest-rust-tool-invoke.core.wasm`.
7. `cargo clean`. Do NOT commit `target/`.
8. Commit atomically: the `.wasm` artifact, `Cargo.lock`, and any WIT change.
