<p align="center">
  <img src="docs/assets/banner.png" alt="Advance Agents" width="640">
</p>

<p align="center">
  <strong>Runtime multiagente nativo del sistema de archivos — cada agente es un WASM Component.</strong>
</p>

<p align="center">
  <a href="LICENSE-MIT"><img src="https://img.shields.io/badge/License-MIT%20OR%20Apache--2.0-blue.svg?style=for-the-badge" alt="MIT OR Apache-2.0"></a>
  <a href="https://github.com/advancinggg/advance-agents/releases"><img src="https://img.shields.io/github/v/release/advancinggg/advance-agents?include_prereleases&style=for-the-badge" alt="Latest release"></a>
  <a href="https://github.com/advancinggg/advance-agents/stargazers"><img src="https://img.shields.io/github/stars/advancinggg/advance-agents?style=for-the-badge" alt="GitHub stars"></a>
  <a href="https://x.com/Advancinggg"><img src="https://img.shields.io/badge/follow-%40Advancinggg-000000?style=for-the-badge&logo=x&logoColor=white" alt="Follow @Advancinggg on X"></a>
  <img src="https://img.shields.io/badge/MSRV-Rust%201.91.0-orange?style=for-the-badge" alt="MSRV Rust 1.91.0">
</p>

<p align="center">
  <a href="README.md">English</a> · <a href="README.zh-CN.md">简体中文</a> · <b>Español</b>
</p>

---

## Resumen

**advance-agents** es un framework de runtime en Rust para construir sistemas multiagente
nativos del sistema de archivos y basados en paso de mensajes, donde **cada agente es un
WebAssembly Component**.

Cada agente se ejecuta en un host Wasmtime. La única forma de tocar el mundo exterior es a
través de **funciones host que deben inyectarse explícitamente**: si una capacidad no está
cableada en la instancia, la función no existe dentro del guest (aislamiento duro L0). Una
capa dinámica de grants (L1) decide si una función inyectada es invocable en ese momento. El
estado es **nativo del sistema de archivos**: cada agente trabaja dentro de una proyección
virtual y aislada de un único workspace versionado con Git. Los agentes se coordinan por
**paso de mensajes** y el primitivo `await-replies`, no por memoria compartida. El framework
es **extensible por inyección de traits** desde una sola raíz de composición.

Este repositorio se publica para **inspirar a la comunidad open source** y ofrecer a quienes
construyen una base de núcleo de capacidades que puedan estudiar, embeber y extender. Eres
bienvenido a construir tus propios clientes de agentes, herramientas y runtimes sobre él.

## Embeber el núcleo

Depende del crate fachada [`crates/advance-core`](crates/advance-core):

```toml
advance-core = { git = "https://github.com/advancinggg/advance-agents", tag = "v0.1.0" }
```

## Arquitectura de un vistazo

El workspace tiene 31 crates. Todo está invertido en dependencias a través de `shared-types`.

### Núcleo del runtime

| Crate | Rol |
|---|---|
| `crates/runtime` | Host Wasmtime Component Model: carga, inyección L0, circuit breakers. |
| `crates/shared-types` | Hogar de la inversión de dependencias: DTOs + traits puerto. |
| `crates/cli` | Binario y raíz de composición (`src/wiring.rs`). |
| `crates/advance-core` | Fachada pública del surface OSS soportado. |

### Capacidades (superficies host-function)

`cap-fs` · `cap-secrets` · `cap-http` · `cap-llm` · `cap-grant` · `cap-memory` ·
`cap-tools` · `cap-skills` · `cap-mcp` · `cap-channel` · `cap-lifecycle`

### Servicios

`git` · `database` · `event-bus` · `messaging` / `reply-tracker` · `run-manager` ·
`scheduler` / `auto-loop` · `context-engine` · `client-api` ·
`cost-tracker` · `pack-manager` · `system-acceptance`

### Clientes de referencia

| Ruta | Rol |
|---|---|
| `crates/client-api/assets/console/` | Consola web de referencia embebida sobre la client API. |
| `crates/client-api/sdk-artifacts/` | Contrato SDK cliente CONTRACT-192 generado. |

## Compilar y probar

**Prerrequisitos**

- **Rust 1.91.0** — fijado en [`rust-toolchain.toml`](rust-toolchain.toml)
- Opcional: target `wasm32-unknown-unknown` para reconstruir fixtures WASM guest

```bash
cargo build --workspace
cargo test --workspace
```

CI ejecuta `fmt --check`, `clippy`, `build`, `test` y `cargo deny` en cada cambio.

## Extender

1. Define contratos de comportamiento como traits en `crates/shared-types`.
2. Construye las implementaciones concretas en la raíz de composición
   (`crates/cli/src/wiring.rs`) y pásalas como `Arc<dyn Trait>`.
3. Para cambiar comportamiento — nuevo proveedor LLM, adaptador de canal o backend de
   almacenamiento — implementa el puerto y cablealo en la raíz. No hagas fork de crates.

Los clientes de agentes construidos por la comunidad deberían tratar `advance-core` y la
client API / shared SDK como la superficie estable de embedding, y mantener UI, cuentas y
hosting específicos del producto fuera de este repositorio.

## Estado del proyecto

| Área | Estado |
|---|---|
| Núcleo runtime | En el árbol (pre-1.0) |
| Device mesh / inferencia local-mesh | En progreso |
| Fachada pública (`advance-core`) | Entregada |
| Contribuciones de código externas | Aún no aceptadas; issues y discusión bienvenidos |

## Contacto

- **Sitio web**: [advance.studio](https://advance.studio)
- **X / Twitter**: [@Advancinggg](https://x.com/Advancinggg)
- **Email**: [admin@advance.studio](mailto:admin@advance.studio)

Reportes de bugs y solicitudes de funciones vía
[GitHub Issues](https://github.com/advancinggg/advance-agents/issues).

## Licencia

Bajo una de:

- Apache License 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT ([LICENSE-MIT](LICENSE-MIT))

a tu elección.

> Este proyecto **no acepta actualmente contribuciones de código externas**; issues y
> discusión son bienvenidos. El copyright se mantiene consolidado para preservar una opción
> futura de relicenciamiento.
