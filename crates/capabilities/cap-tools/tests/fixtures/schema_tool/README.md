# schema_tool fixture

Tool exporting `advance:runtime/tool-exports@0.1.0` (CONTRACT-163) with a
DECLARED input JSON schema on its `check` method
(`{"type":"object","properties":{"x":{"type":"number"}},"required":["x"]}`).

Used by the SYS-AC-084 system-acceptance witness: an input violating the schema
returns `tool-error::input-validation-failed` and `execute` is NOT run (the
input gate fires before `execute_in_wasm`).

## Rebuild

```sh
rustup target add wasm32-unknown-unknown   # once
cargo build --release --target wasm32-unknown-unknown
wasm-tools component new \
  target/wasm32-unknown-unknown/release/schema_tool.wasm \
  -o ../schema_tool.component.wasm
wasm-tools validate ../schema_tool.component.wasm
wasm-tools component wit ../schema_tool.component.wasm   # export tool-exports
```

The committed `../schema_tool.component.wasm` lets tests load a real component
with no wasm toolchain installed (mirrors echo_tool).
