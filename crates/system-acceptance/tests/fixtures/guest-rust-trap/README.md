# guest-rust-trap

MAINLINE Wave-5 harvest (2026-06-21) — **trapping guest** fixture for SYS-AC-029.

Targets the `advance-host-fs` world (exports `message-driven` + `runnable`). Its
`handle-message` ALWAYS returns `Err`. The production
`AgentLoopDriverImpl::run_turn_once` maps a `handle_message` `Err(HookError::Failure)`
to `TrapError::Crash` and calls `handle_trap` (scheduler `agent_loop.rs:328-330`),
which (1) emits a `component.error` EventBus event via the wired
`with_component_error_emitter` and (2) applies the configured `RestartPolicy`
(`restart_decision`). So this is a REAL guest trap — distinct from the harness mock
`TrappingHandler`. `run` returns `Completed` (unused by the 029 witness).

The committed `../guest-rust-trap.core.wasm` artifact is wrapped to a Component at
test time via `build_agent::encode_core_to_component`. The `agent-fs` IMPORT in the
world is satisfied dynamically by the host `CapabilityInjector` (the guest never
CALLS it — it traps first); it is present only so the component instantiates.

Derived by copying `crates/runtime/tests/fixtures/guest-rust-j01-skeleton` (same WIT
+ world) and replacing the body of `handle_message`.

## Regen procedure

1. Ensure the wasm32 target: `rustup target add wasm32-unknown-unknown`.
2. Build: `cargo build --target wasm32-unknown-unknown --release --locked`.
3. Copy artifact: `cp target/wasm32-unknown-unknown/release/guest_rust_trap.wasm ../guest-rust-trap.core.wasm`.
4. `cargo clean`. Do NOT commit `target/`.
5. Commit atomically: the `.wasm` artifact + `Cargo.lock`.
