# clock_tool fixture

Entity-data lane E1: a `tool-exports` component whose method `now` returns the WASI wall
clock as RFC 3339 text. `LazyToolRegistry::invoke_deterministic` freezes that clock, so the
witness asserts the guest sees exactly the injected instant while the ordinary `invoke`
path keeps the system clock.

## Rebuild

Needs the `wasm32-wasip2` target (std's `SystemTime` maps to `wasi:clocks`, which the
host's WASI Preview 2 linker provides; no adapter step):

```sh
rustup target add wasm32-wasip2   # once
cargo build --release --target wasm32-wasip2
cp target/wasm32-wasip2/release/clock_tool.wasm ../clock_tool.component.wasm
wasm-tools validate ../clock_tool.component.wasm
wasm-tools component wit ../clock_tool.component.wasm   # export tool-exports, imports wasi:*
```

The committed `../clock_tool.component.wasm` lets cap-tools tests load a real component
with no wasm toolchain installed (same pattern as `echo_tool.component.wasm`).
