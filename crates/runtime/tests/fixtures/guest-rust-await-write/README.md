# guest-rust-await-write

Wave-11 Lane A (2026-06-23) — **await-park + fs-write guest** fixture for the
system-acceptance await-leg witnesses SYS-AC-014 / 018 / 251.

Imports BOTH `agent-messaging` (await-replies) AND `agent-fs` (write) via the new
`advance-host-messaging-fs` world (canonical host WIT — which declares both
interfaces — plus a world that imports both). Both imports are satisfied
dynamically by the host `CapabilityInjector` under the versioned namespaces
`advance:runtime/agent-messaging@0.1.0` + `advance:runtime/agent-fs@0.1.0` (host
bindgen world != guest world; imports are linker-validated, not world-validated —
only the `message-driven` + `runnable` EXPORTS must match). Cannot reuse
`guest-rust-with-caps` (messaging-only world) — adding `agent-fs` to it would
break the messaging-only-caps LinkerTypecheck tests that embed it.

`handle-message` dispatches on the `state` arg (routing intent passed via
`init`'s returned `config_data`, the `guest-rust-with-caps` convention):

- `b"await-write"` (014/018): `await-replies([agent:test-target], AllOf, long
  idle)` PARKS the run. On `Ok` (a child reply resumed it) -> exactly ONE
  `agent-fs::write("await-out.txt", ...)` -> a single `CommitType::Turn` commit
  (014). On `Err` (the await session was closed by pause/cancel) -> return WITHOUT
  writing -> no commit, filesystem unchanged (018).
- `b"await-partial"` (251): `await-replies([agent:test-target], AllOf,
  ReturnPartial, short idle)` PARKS, then the REAL per-session idle monitor
  resolves `Ok(PartialTimeout)` past the idle timeout -> resume. No write.

The committed `../guest-rust-await-write.core.wasm` artifact is wrapped to a
Component at test time via `wit_component::ComponentEncoder` (same pattern as
`guest-rust-with-caps` / `guest-rust-j01-reply-write`).

## WIT note

`wit/advance.wit` is the canonical host WIT (`crates/runtime/wit/advance.wit`)
plus the appended `agent-fs` interface (from `cap-fs/wit/agent-fs.wit`, `%list`
keyword escaped) plus the `advance-host-fs` and `advance-host-messaging-fs`
worlds. Identical to `guest-rust-j01-reply-write/wit/advance.wit` with one extra
world (`advance-host-messaging-fs`).

## Regen procedure

1. Ensure the wasm32 target: `rustup target add wasm32-unknown-unknown`.
2. If the canonical WIT changed, re-derive `wit/advance.wit` from
   `guest-rust-j01-reply-write/wit/advance.wit` and re-append the
   `advance-host-messaging-fs` world. Validate: `wasm-tools component wit wit/advance.wit`.
3. First-time bootstrap (no Cargo.lock): `cargo generate-lockfile`.
4. Build: `cargo build --target wasm32-unknown-unknown --release --locked`.
5. Copy artifact: `cp target/wasm32-unknown-unknown/release/guest_rust_await_write.wasm ../guest-rust-await-write.core.wasm`.
6. Verify size < 500 KiB: `wc -c ../guest-rust-await-write.core.wasm`.
7. `cargo clean`. Do NOT commit `target/`.
8. Commit atomically: the `.wasm` artifact, `Cargo.lock`, and any WIT change.
