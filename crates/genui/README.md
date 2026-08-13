# advance-genui

MODULE-023 GenUI: declarative A2UI document model, vetted component catalog, and
validation gate for the advance-agents runtime.

## Protocol version

Pinned at **A2UI v0.9.1** (v1.0-RC tracked).

## Contracts

- **CONTRACT-220**: A2UI document/update payload types (`document.rs`)
- **CONTRACT-221**: Vetted component catalog + action registry + validation gate (`catalog.rs`)

## Product consumption

Product repos consume this crate through the `advance-core` facade:

```toml
advance-core = { git = "https://github.com/advancinggg/advance-agents", tag = "v0.1.0" }
```

```rust
use advance_core::genui::{GenUiGate, seed_catalog};

let gate = GenUiGate::new(true, 262_144, seed_catalog());
gate.admit(&document)?;
```
