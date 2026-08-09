# guest-rust-minimal

Minimal Rust WASM guest fixture for MODULE-001-AC-03.

Implements `advance:runtime@0.1.0` world exports (`message-driven` and `runnable`)
with trivial function bodies returning sentinel bytes. The committed
`guest-rust-minimal.core.wasm` artifact is wrapped at test-time via `ComponentEncoder`
and loaded by T43/T44/T45
in `crates/runtime/tests/guest_real_rust.rs`.

## Regen procedure

1. Confirm `wasm32-unknown-unknown` target is installed:
   `rustup target list --installed | grep wasm32-unknown-unknown` (add if not: `rustup target add wasm32-unknown-unknown`).
2. If `../../wit/advance.wit` (host WIT at `crates/runtime/wit/advance.wit`) has changed,
   copy it: `cp ../../wit/advance.wit wit/advance.wit`.
3. First-time bootstrap (no Cargo.lock yet): `cargo generate-lockfile`.
4. Build: `cargo build --target wasm32-unknown-unknown --release --locked`.
   Note: uses `wasm32-unknown-unknown` (NOT `wasm32-wasip2`) because `wasip2` adds WASI
   imports that `instantiate_advance_host_async`'s bare linker cannot satisfy.
   The test-time helper wraps the core module with `ComponentEncoder` instead.
5. Copy artifact: `cp target/wasm32-unknown-unknown/release/guest_rust_minimal.wasm ../guest-rust-minimal.core.wasm`.
6. Verify size < 500 KiB with `wc -c`.
7. `cargo clean` in this directory. Do NOT commit `target/`.
8. Commit atomically: the `.wasm` artifact, the `Cargo.lock`, and any WIT change.
