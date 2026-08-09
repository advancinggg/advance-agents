# guest-rust-b-mem-seq

/dev Track B (2026-06-04) memory-lifecycle guest fixture for the
`system-acceptance` harness witness of **SYS-J-20** (SYS-AC-060 / SYS-AC-061).

On `handle-message` it drives the full lifecycle through the REAL versioned
`agent-memory` host fns (`advance:runtime/agent-memory@0.1.0`):

```
remember(payload, ["insight"]) -> recall(payload) -> forget(id) -> recall(payload)
```

emitting `memory.remember`, two `memory.recall` (result_count 1 then 0), and
`memory.forget`. `new_state` self-documents the run as `[found1, r1_len, found2, r2_len]`
(healthy run = `[1, 1, 0, 0]`). Targets the `advance-host-mem` world
(imports `agent-memory`, exports `message-driven` + `runnable`),
package `advance:runtime@0.1.0`.

## Regenerate the prebuilt core module

The `.core.wasm` is checked into git (per fixture convention). To rebuild after a
source/WIT change:

```sh
rustup target add wasm32-unknown-unknown          # once
cargo generate-lockfile                            # if Cargo.lock is missing/stale
cargo build --target wasm32-unknown-unknown --release --locked
cp target/wasm32-unknown-unknown/release/guest_rust_b_mem_seq.wasm \
   ../guest-rust-b-mem-seq.core.wasm
cargo clean        # do NOT commit target/
```

The crate is excluded from the parent workspace (empty `[workspace]` table) and is
NOT exercised by `cargo test --workspace`; it is `include_bytes!`'d by
`crates/system-acceptance/tests/sys_j20_memory_lifecycle.rs` and wrapped core->Component
at test time via `wit_component::ComponentEncoder`.
