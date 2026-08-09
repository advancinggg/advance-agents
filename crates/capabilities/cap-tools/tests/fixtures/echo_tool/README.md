# echo_tool fixture

Minimal tool exporting `advance:runtime/tool-exports@0.1.0` (CONTRACT-163):

- `describe()` → one `echo` method (idempotent).
- `execute("echo", params)` → `Ok(params)` (echoes input bytes verbatim).
- `execute(other, _)` → `Err("method-not-found: <other>")`.

Used by cap-tools in-WASM integration tests (SC-48/49/53/54/56) and by the
MODULE-017 AC-26 / AC-20 L2 / AC-29 witnessing slices.

## Rebuild

Needs the `wasm32-unknown-unknown` target and `wasm-tools` (the repo's existing
fixture pipeline; cargo-component is NOT required):

```sh
rustup target add wasm32-unknown-unknown   # once
cargo build --release --target wasm32-unknown-unknown
wasm-tools component new \
  target/wasm32-unknown-unknown/release/echo_tool.wasm \
  -o ../echo_tool.component.wasm
wasm-tools validate ../echo_tool.component.wasm
wasm-tools component wit ../echo_tool.component.wasm   # should show: export tool-exports
```

The committed `../echo_tool.component.wasm` lets cap-tools tests load a real
component with no wasm toolchain installed (mirrors `guest-rust-minimal.core.wasm`).
