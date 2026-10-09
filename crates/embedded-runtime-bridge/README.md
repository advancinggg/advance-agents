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

**Honesty:** profile reports `engine_mode` (policy class) and `host_backend`. v1 health
always reports `host_backend` `cranelift`. v2 health reports `cranelift` or `pulley`
read back from the engines (Pulley on iOS/Android, or when `"engine":"pulley"`). Mobile +
Cranelift → `agent_host_available=false`.

## Lifecycle API

- Rust: `start` / `stop` / `health` / `on_lifecycle` (+ async variants); v2 `start_with_extensions` / `health_v2` / `client_api_base` / `client_api_session`
- C ABI: `advance_bridge_start` / `_stop` / `_health` / `_on_lifecycle` / `_free_handle`; v2 `advance_bridge_start_v2` / `_client_api_base` / `_client_api_session`

### Health JSON (`schema_version` = 1)

`advance_bridge_health` writes a NUL-terminated UTF-8 object. Snake_case enums:

| Key | Meaning |
|-----|---------|
| `schema_version` | `1` |
| `runtime_up` | host/child is live |
| `last_heartbeat_ok` | embed lock heartbeat fresh, or `runtime_up` in supervise |
| `composition_mode` | `embed` \| `supervise` |
| `lock_exclusivity` | `runtime_lock` \| `process_local` |
| `supervise_readiness` | `daemon_ready_line` \| `ready_file` \| `null` |
| `profile.engine_mode` | `jit` \| `interpreter` |
| `profile.host_backend` | `cranelift` \| `pulley` |
| `profile.agent_host_available` | honesty capacity |
| `profile.max_concurrent_runs` | FG class or `0` if not foreground |
| `profile.storage_profile` | `persistent` \| `bounded` \| `ephemeral` |

### Multi-start / double-stop

- Same workspace, same process → `AlreadyRunning`
- Cross-process (linux/macos embed) → `RuntimeLock` (same as `advance start`)
- Double-stop → idempotent `Ok`
- Drop: embed always stops; supervise reaps when `supervise_kill_on_drop` (default true)

### C ABI v2

`advance_bridge_start_v2(workspace, options_json_or_null, out_handle)` starts an embedded
composition. `options_json` is `NULL` (every default) or a JSON object; every key is optional:

| Key | Values | Default |
|-----|--------|---------|
| `platform` | `mac` \| `ios` \| `android` \| `windows` \| `linux` | compiled target (`linux` outside this list) |
| `composition` | `full` \| `host_only` | `full` |
| `engine` | `native` \| `pulley` | `pulley` on ios/android, else `native` |
| `processes` | `allow` \| `forbid` | `forbid` on ios/android, else `allow` |
| `client_api` | `{"port": 0..65535}` \| `null` | `{"port": 0}`; `null` means no Client API |
| `state_root` | absolute path outside the workspace | required by `full` on ios/android |
| `config_path` | path inside the workspace | `.advance/runtime-config.yaml`; `full` accepts only the default |

Codes: 14 `UNSUPPORTED` (platform table, no Client API, non-default `full` config path);
15 `COMPOSE` (every other composition failure; `last_error` is redacted). `host_only` keeps
v1's codes (5 / 7 / 8).

v2 health (`schema_version` 2) adds `composition_profile`, `agent_loop_up`, and
`client_api_base`. Rust `health()` of a v2 handle is the v1-shaped projection
(`schema_version` 1); use `health_v2()`.

`advance_bridge_client_api_base` / `_session` use the health buffer protocol. The session
getter mints an in-process bearer token (size query mints at most once); on a `linux` host
the session's platform is `mac`, since the Client API has no Linux platform value. After
`on_lifecycle(Foreground)`, re-read base and session before any request.

### Secrets

FFI carries paths and enums only — no API keys, master keys, or secret env values. v2
`advance_bridge_client_api_session` returns a bearer token over FFI; keep it in memory,
never write it to disk, a log, or a URL, and wipe the buffer after use.

## Tests

```bash
cargo test -p advance-embedded-runtime-bridge --locked
cargo clippy -p advance-embedded-runtime-bridge --all-targets -- -D warnings
```
