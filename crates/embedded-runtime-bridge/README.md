# advance-embedded-runtime-bridge (CONTRACT-210)

Born-OSS **EmbeddedRuntimeBridge** for Wave-27 C210. Native shells and third parties
embed or supervise the **same** M001 runtime core — no product-private Wasmtime host.

## Product Mode B rebind (pin bump)

1. Tag this repo (`vX.Y.Z`) after CI is green.
2. In product `Cargo.toml`, bump all `advance-agents` git deps to the new tag.
3. Rust consumers:

```rust
use advance_core::embedded_runtime_bridge::{
    start, stop, health, BridgeConfig, BridgePlatform, CompositionMode, EngineMode,
    EmbeddedRuntimeBridge,
};
```

4. Native (Apple/Android) link:

```bash
cargo build -p advance-embedded-runtime-bridge --release
# link target/release/libadvance_embedded_runtime_bridge.a
# include crates/embedded-runtime-bridge/include/advance_bridge.h
```

5. Set product `bridgeSurfacePresentOnThisPin = true` only after link succeeds.
6. Wire Mode B router to real `start` / `stop` / `health` (product lane).

MODULE-022’s historical path name `clients/shared-bridge/` maps to **this crate**.

## Platform mode matrix

| Platform | Composition | Engine **policy** | FG max | Storage | Cross-process lock |
|----------|-------------|-------------------|--------|---------|--------------------|
| Mac | Embed or Supervise | Jit (default) or Interpreter | 8 | Persistent | RuntimeLock (`linux`/`macos` host) |
| Windows | Embed or Supervise | Jit or Interpreter | 8 | Persistent | Process-local only |
| iOS | Embed only | **Interpreter required** | 2 | Bounded | Process-local |
| Android | Embed only | **Interpreter required** | 4 | Bounded | Process-local |

**Honesty:** profile reports `engine_mode` (policy class) and `host_backend` (always
`cranelift` this slice). Mobile + Cranelift → `agent_host_available=false`. True no-JIT
Wasmtime host backend is a future runtime feature.

## Lifecycle API

- Rust: `start` / `stop` / `health` / `on_lifecycle` (+ async variants)
- C ABI: `advance_bridge_start` / `_stop` / `_health` / `_on_lifecycle` / `_free_handle`

### Multi-start / double-stop

- Same workspace, same process → `AlreadyRunning`
- Cross-process (linux/macos embed) → `RuntimeLock` (same as `advance start`)
- Double-stop → idempotent `Ok`
- Drop: embed always stops; supervise reaps when `supervise_kill_on_drop` (default true)

### Secrets

FFI carries paths and enums only — no API keys, master keys, or secret env values.

## Tests

```bash
cargo test -p advance-embedded-runtime-bridge --locked
cargo clippy -p advance-embedded-runtime-bridge --all-targets -- -D warnings
```
