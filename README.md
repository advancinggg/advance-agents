<p align="center">
  <img src="docs/assets/banner.png" alt="Advance Agents" width="640">
</p>

<p align="center">
  <strong>Filesystem-native multi-agent runtime — every agent is a WASM Component.</strong>
</p>

<p align="center">
  <a href="LICENSE-MIT"><img src="https://img.shields.io/badge/License-MIT%20OR%20Apache--2.0-blue.svg?style=for-the-badge" alt="MIT OR Apache-2.0"></a>
  <a href="https://github.com/advancinggg/advance-agents/releases"><img src="https://img.shields.io/github/v/release/advancinggg/advance-agents?include_prereleases&style=for-the-badge" alt="Latest release"></a>
  <a href="https://github.com/advancinggg/advance-agents/stargazers"><img src="https://img.shields.io/github/stars/advancinggg/advance-agents?style=for-the-badge" alt="GitHub stars"></a>
  <a href="https://x.com/Advancinggg"><img src="https://img.shields.io/badge/follow-%40Advancinggg-000000?style=for-the-badge&logo=x&logoColor=white" alt="Follow @Advancinggg on X"></a>
  <img src="https://img.shields.io/badge/MSRV-Rust%201.91.0-orange?style=for-the-badge" alt="MSRV Rust 1.91.0">
</p>

<p align="center">
  <b>English</b> · <a href="README.zh-CN.md">简体中文</a> · <a href="README.es.md">Español</a>
</p>

---

## Overview

**advance-agents** is a Rust runtime framework for building filesystem-native,
message-passing multi-agent systems where **every agent is a WebAssembly Component**.

Each agent runs inside a Wasmtime host. The only way an agent touches the outside world
is through **host functions that must be explicitly injected** — if a capability is not
wired into the instance, the function does not exist inside the guest (L0 hard isolation).
A dynamic grant layer (L1) then decides whether an injected function is currently callable.
State is **filesystem-native**: every agent works inside a virtual, sandboxed projection of
a single Git-versioned workspace. Agents coordinate by **message passing** and an
`await-replies` primitive rather than shared memory. The framework is **extensible by trait
injection** through a single composition root.

This repository is published to **inspire the open-source community** and to give builders a
capability-kernel foundation they can study, embed, and extend. You are welcome to build your
own agent clients, tools, and runtimes on top of it.

## Embed the core

Depend on the single façade crate [`crates/advance-core`](crates/advance-core) — it re-exports
the supported public surface under stable module names:

```toml
advance-core = { git = "https://github.com/advancinggg/advance-agents", tag = "v0.1.0" }
```

## Architecture at a glance

The workspace is 31 crates. Everything is dependency-inverted through `shared-types`.

### Runtime core

| Crate | Role |
|---|---|
| `crates/runtime` | Wasmtime Component Model host: load, L0 capability injection, circuit breakers. |
| `crates/shared-types` | Dependency-inversion home: DTOs + port traits (`Arc<dyn Trait>` seams). |
| `crates/cli` | Binary and composition root (`src/wiring.rs`). |
| `crates/advance-core` | Public façade re-exporting the supported OSS surface. |

### Capabilities (host-function surfaces)

`cap-fs` · `cap-secrets` · `cap-http` · `cap-llm` · `cap-grant` · `cap-memory` ·
`cap-tools` · `cap-skills` · `cap-mcp` · `cap-channel` · `cap-lifecycle`

### Services

`git` · `database` · `event-bus` · `messaging` / `reply-tracker` · `run-manager` ·
`scheduler` / `auto-loop` · `context-engine` · `client-api` ·
`cost-tracker` · `pack-manager` · `system-acceptance`

### Reference client assets (in-crate)

| Path | Role |
|---|---|
| `clients/web-console/` | Embedded reference web console over the client API. |
| `crates/client-api/sdk-artifacts/` | Generated CONTRACT-192 client SDK contract. |

## Build & test

**Prerequisites**

- **Rust 1.91.0** — pinned in [`rust-toolchain.toml`](rust-toolchain.toml)
- Optional: `wasm32-unknown-unknown` target if you rebuild guest WASM fixtures

```bash
cargo build --workspace
cargo test --workspace
```

CI runs `fmt --check`, `clippy`, `build`, `test`, and `cargo deny` on every change.

## Extending

1. Define behavior contracts as traits in `crates/shared-types`.
2. Construct concrete impls in the composition root (`crates/cli/src/wiring.rs`) and pass
   them as `Arc<dyn Trait>`.
3. To change behavior — a new LLM provider, channel adapter, or storage backend — implement
   the port and wire it at the composition root. Do not fork crates.

Community-built agent clients should treat `advance-core` + the client API / shared SDK as the
stable embedding surface, and keep product-specific UI, accounts, and hosting outside this
repository.

## Project status

| Area | Status |
|---|---|
| Runtime core | Shipped in-tree (pre-1.0) |
| Device mesh / local-mesh inference | In progress |
| Public façade (`advance-core`) | Shipped |
| External code contributions | Not accepted yet; issues and discussion welcome |

## Contact

- **Website**: [advance.studio](https://advance.studio)
- **X / Twitter**: [@Advancinggg](https://x.com/Advancinggg)
- **Email**: [admin@advance.studio](mailto:admin@advance.studio)

Bug reports and feature requests are welcome via
[GitHub Issues](https://github.com/advancinggg/advance-agents/issues).

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.

> This project is **not currently accepting external code contributions**; issues and
> discussion are welcome. Copyright is kept consolidated to preserve a future relicensing option.
