# dual_export fixture

A mutual-exclusion-VIOLATING component: exports BOTH
`advance:runtime/tool-exports@0.1.0` (describe + execute) AND
`advance:runtime/runnable@0.1.0` (run).

Used by the SYS-AC-085 system-acceptance witness: the cap-tools validator rejects
`has_runnable && has_any_tool_export` at cold load, so the tool enters the
failed-set — hidden from `list-tools`, and `tool-invoke` returns
`tool-error::not-found` (the FIRST invoke surfaces the cold-load
`invocation-failed`).

## Rebuild

```sh
rustup target add wasm32-unknown-unknown   # once
cargo build --release --target wasm32-unknown-unknown
wasm-tools component new \
  target/wasm32-unknown-unknown/release/dual_export.wasm \
  -o ../dual_export.component.wasm
wasm-tools validate ../dual_export.component.wasm
wasm-tools component wit ../dual_export.component.wasm   # export tool-exports AND runnable
```

The committed `../dual_export.component.wasm` lets tests load a real component
with no wasm toolchain installed (mirrors echo_tool).
