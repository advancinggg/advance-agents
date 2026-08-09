<p align="center">
  <img src="docs/assets/banner.png" alt="Advance Agents" width="640">
</p>

<p align="center">
  <strong>文件系统原生的多智能体运行时 —— 每个智能体都是一个 WASM Component。</strong>
</p>

<p align="center">
  <a href="LICENSE-MIT"><img src="https://img.shields.io/badge/License-MIT%20OR%20Apache--2.0-blue.svg?style=for-the-badge" alt="MIT OR Apache-2.0"></a>
  <a href="https://github.com/advancinggg/advance-agents/releases"><img src="https://img.shields.io/github/v/release/advancinggg/advance-agents?include_prereleases&style=for-the-badge" alt="Latest release"></a>
  <a href="https://github.com/advancinggg/advance-agents/stargazers"><img src="https://img.shields.io/github/stars/advancinggg/advance-agents?style=for-the-badge" alt="GitHub stars"></a>
  <a href="https://x.com/Advancinggg"><img src="https://img.shields.io/badge/follow-%40Advancinggg-000000?style=for-the-badge&logo=x&logoColor=white" alt="Follow @Advancinggg on X"></a>
  <img src="https://img.shields.io/badge/MSRV-Rust%201.91.0-orange?style=for-the-badge" alt="MSRV Rust 1.91.0">
</p>

<p align="center">
  <a href="README.md">English</a> · <b>简体中文</b> · <a href="README.es.md">Español</a>
</p>

---

## 概览

**advance-agents** 是一个用 Rust 编写的运行时框架，用于构建文件系统原生、基于消息传递的
多智能体系统 —— **每个智能体都是一个 WebAssembly Component**。

智能体运行在 Wasmtime 宿主中。它接触外部世界的唯一方式是通过**必须显式注入的宿主函数** ——
若某能力未注入到实例中，该函数在 guest 内根本不存在（L0 硬隔离）。动态授权层（L1）再决定
已注入的函数当前是否可调用。状态是**文件系统原生**的：每个智能体工作在单一 Git 版本化工作区
的沙箱投影中。智能体通过**消息传递**与 `await-replies` 原语协调，而非共享内存。框架通过
单一组合根的**特质注入**实现扩展。

本仓库开源的目的是**启发开源社区**，并为构建者提供可学习、可嵌入、可扩展的能力内核基础。
欢迎在此之上构建你自己的 agent 客户端、工具与运行时。

## 嵌入内核

依赖单一门面 crate [`crates/advance-core`](crates/advance-core)：

```toml
advance-core = { git = "https://github.com/advancinggg/advance-agents", tag = "v0.1.0" }
```

## 架构一览

工作区共 31 个 crate，全部通过 `shared-types` 做依赖倒置。

### 运行时核心

| Crate | 职责 |
|---|---|
| `crates/runtime` | Wasmtime Component Model 宿主：加载、L0 能力注入、熔断。 |
| `crates/shared-types` | 依赖倒置中枢：DTO + 端口特质（`Arc<dyn Trait>`）。 |
| `crates/cli` | 二进制与组合根（`src/wiring.rs`）。 |
| `crates/advance-core` | 公开门面，再导出受支持的 OSS 表面。 |

### 能力（宿主函数面）

`cap-fs` · `cap-secrets` · `cap-http` · `cap-llm` · `cap-grant` · `cap-memory` ·
`cap-tools` · `cap-skills` · `cap-mcp` · `cap-channel` · `cap-lifecycle`

### 服务

`git` · `database` · `event-bus` · `messaging` / `reply-tracker` · `run-manager` ·
`scheduler` / `auto-loop` · `context-engine` · `client-api` ·
`cost-tracker` · `pack-manager` · `system-acceptance`

### 参考客户端

| 路径 | 职责 |
|---|---|
| `crates/client-api/assets/console/` | 嵌入的参考 Web 控制台（基于 client API）。 |
| `crates/client-api/sdk-artifacts/` | 生成的 CONTRACT-192 客户端 SDK 契约。 |

## 构建与测试

**前置条件**

- **Rust 1.91.0** —— 见 [`rust-toolchain.toml`](rust-toolchain.toml)
- 可选：重建 guest WASM fixture 时需要 `wasm32-unknown-unknown`

```bash
cargo build --workspace
cargo test --workspace
```

CI 在每次变更上运行 `fmt --check`、`clippy`、`build`、`test` 与 `cargo deny`。

## 扩展方式

1. 在 `crates/shared-types` 中以特质定义行为契约。
2. 在组合根（`crates/cli/src/wiring.rs`）构造具体实现，并以 `Arc<dyn Trait>` 注入。
3. 要更换行为（新 LLM 提供商、通道适配器或存储后端），实现对应端口并在组合根接线 —— 不要 fork crate。

社区构建的 agent 客户端，建议以 `advance-core` 以及 client API / shared SDK 作为稳定嵌入面，
将产品特定的 UI、账户与托管放在本仓库之外。

## 项目状态

| 区域 | 状态 |
|---|---|
| 运行时核心 | 已入库（pre-1.0） |
| 设备网格 / 本地网格推理 | 进行中 |
| 公开门面（`advance-core`） | 已交付 |
| 外部代码贡献 | 暂不接受；欢迎 Issue 与讨论 |

## 联系

- **网站**：[advance.studio](https://advance.studio)
- **X / Twitter**：[@Advancinggg](https://x.com/Advancinggg)
- **Email**：[admin@advance.studio](mailto:admin@advance.studio)

缺陷报告与功能请求请通过
[GitHub Issues](https://github.com/advancinggg/advance-agents/issues) 提交。

## 许可证

任选其一：

- Apache License 2.0（[LICENSE-APACHE](LICENSE-APACHE)）
- MIT（[LICENSE-MIT](LICENSE-MIT)）

> 本项目**目前不接受外部代码贡献**；欢迎 Issue 与讨论。版权保持集中，以便未来保留重新许可的选项。
