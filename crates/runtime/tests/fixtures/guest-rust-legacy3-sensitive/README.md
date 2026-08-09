# guest-rust-legacy3-sensitive

Real Rust/WASM discriminator for MODULE-012-T10. The exported `runnable.run`
originates the exact `legacy3-raw-secret-7f3a` sentinel and returns nested
canonical named-parameter and CapParam wire containers. Tests wrap the committed
core module with `wit_component::ComponentEncoder` before loading it through the
production runnable hook.

## Regeneration

1. Ensure `wasm32-unknown-unknown` is installed for the pinned toolchain.
2. From this directory run
   `cargo build --release --target wasm32-unknown-unknown --locked`.
3. Copy
   `target/wasm32-unknown-unknown/release/guest_rust_legacy3_sensitive.wasm`
   to `../guest-rust-legacy3-sensitive.core.wasm`.
4. Run the CLI `runnable_factory` and `component_submit_bridge` tests.
5. Do not commit `target/`; commit the core artifact, source, and lockfile together.

The fixture intentionally reuses the sibling `guest-rust-minimal/wit` tree so
its component metadata stays aligned with the runtime test WIT.
