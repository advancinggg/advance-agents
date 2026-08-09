# guest-rust-j01-reply-write

Small-witness 2026-06-11 — J-01 system-acceptance **reply+write guest** fixture
(SYS-AC-003), a `guest-rust-j01-skeleton` copy with the reply leg added.

Targets the `advance-host-fs` world (imports `agent-fs`, exports `message-driven` +
`runnable`). On `handle-message` it writes ONE file (`j01.txt`) via the imported
`agent-fs` host fn (real `fs.write` → cap-fs → git `CommitType::Turn` commit) AND
returns one non-empty reply action (payload `j01-reply`), so a single turn witnesses
"after the reply, git log shows exactly one new turn commit whose tree contains the
agent's file writes". `run` is a trivial `Completed`.

The committed `../guest-rust-j01-reply-write.core.wasm` artifact is wrapped to a
Component at test time via `wit_component::ComponentEncoder` (same pattern as
`guest-rust-minimal` / `guest-rust-with-caps`) and instantiated through the host's
`advance-host-with-capabilities` bindgen — only the EXPORTS must match; the
`agent-fs` IMPORT is satisfied dynamically by the host `CapabilityInjector` under the
**versioned** namespace `advance:runtime/agent-fs@0.1.0` (host bindgen world ≠ guest
world; imports are linker-validated, not world-validated).

## WIT note (important)

The guest's `wit/advance.wit` is the canonical host WIT (`crates/runtime/wit/advance.wit`)
plus the appended `agent-fs` interface (from `crates/capabilities/cap-fs/wit/agent-fs.wit`)
and the `advance-host-fs` world. The canonical `agent-fs.wit` escapes the `list` keyword
as `%list` (a WIT requirement for guest import; the component-model name stays `list`).
If you copy a stale `agent-fs.wit`, re-apply that escape or the WIT will fail to parse.

## Regen procedure

1. Ensure the wasm32 target: `rustup target add wasm32-unknown-unknown`.
2. If the canonical WIT changed, re-derive `wit/advance.wit`:
   ```
   cp ../../wit/advance.wit wit/advance.wit
   printf '\n// --- appended for guest-rust-j01-reply-write (BS-3): agent-fs interface + fs-importing world ---\n' >> wit/advance.wit
   sed -n '3,69p' ../../../../capabilities/cap-fs/wit/agent-fs.wit >> wit/advance.wit
   # then append the `world advance-host-fs { import agent-fs; export message-driven; export runnable; }` block
   ```
   Validate: `wasm-tools component wit wit/advance.wit`.
3. First-time bootstrap (no Cargo.lock): `cargo generate-lockfile`.
4. Build: `cargo build --target wasm32-unknown-unknown --release --locked`.
5. Copy artifact: `cp target/wasm32-unknown-unknown/release/guest_rust_j01_reply_write.wasm ../guest-rust-j01-reply-write.core.wasm`.
6. Verify size < 500 KiB: `wc -c ../guest-rust-j01-reply-write.core.wasm`.
7. `cargo clean`. Do NOT commit `target/`.
8. Commit atomically: the `.wasm` artifact, `Cargo.lock`, and any WIT change.
