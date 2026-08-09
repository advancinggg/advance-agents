# guest-rust-mem-skeleton

/dev Slice S2 (2026-06-03) — memory guest fixture for the system-acceptance harness's
`.caps([Cap::Memory])` witness.

Targets the `advance-host-mem` world (imports `agent-memory`, exports `message-driven` +
`runnable`). On `handle-message` it calls `agent-memory::remember(payload, ["insight"])`
then `agent-memory::recall(payload, …)` — the two load-bearing host calls the harness
would witness (`memory.remember` + `memory.recall`). `run` is a trivial `Completed`.

The committed `../guest-rust-mem-skeleton.core.wasm` is wrapped to a Component at test
time via `wit_component::ComponentEncoder` (same pattern as `guest-rust-j01-skeleton`).

## ✅ Resolved (was: blocker — why the full witness was `#[ignore]`d)

The harness smoke `system-acceptance/tests/mode_memory_smoke.rs::memory_remember_recall_through_a_real_turn`
is now ACTIVE (no longer `#[ignore]`d). cap-memory formerly registered its host fns under
the **unversioned** namespace `"advance:runtime/agent-memory"`, but this guest (WIT package
`advance:runtime@0.1.0`) imports the **versioned** `advance:runtime/agent-memory@0.1.0`, and
Wasmtime's component linker requires an exact match (instantiation otherwise failed with
`LinkerTypecheck(... agent-memory@0.1.0 ... not found)`).

**Resolved by /dev Slice N1 (n1-namespaces)**: cap-memory now registers the versioned
`"advance:runtime/agent-memory@0.1.0"` (`src/host_fn.rs:23`) — matching this guest's import,
the same versioned form cap-fs uses for the j01 fs guest. No guest regen was required (this
fixture's committed `.core.wasm` already imports the versioned form).

## Regen procedure

1. `rustup target add wasm32-unknown-unknown`.
2. `wit/advance.wit` = the canonical host WIT (`crates/runtime/wit/advance.wit`, which
   already defines `agent-memory`) + an appended `world advance-host-mem { import
   agent-memory; export message-driven; export runnable; }`.
3. `cargo generate-lockfile`.
4. `cargo build --target wasm32-unknown-unknown --release`.
5. `cp target/wasm32-unknown-unknown/release/guest_rust_mem_skeleton.wasm ../guest-rust-mem-skeleton.core.wasm`.
