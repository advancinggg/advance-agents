# big_output fixture

Tool exporting `advance:runtime/tool-exports@0.1.0`. `execute("big")` returns
2 MiB; `execute("small")` returns 2 bytes.

Used by the SYS-AC-219 system-acceptance witness: a `tool-invoke` whose execute
output exceeds `max_result_bytes` is fail-closed with
`tool-error::output-validation-failed`, no truncation. The witness runs with a
REDUCED `max_result_bytes` cap (harness `.with_tools_max_result_bytes`) and a
2 MiB output to exercise the IDENTICAL fail-closed check
(`lazy_registry.rs` `bytes.len() > max_result_bytes`). The literal 16 MiB+
default output is NOT cleanly reachable — a 16 MiB+ result `list<u8>` traps/times
out during the component Val-boundary lift BEFORE the host size check (§3.6(g)
documented limitation; the same boundary deferred the 64 MiB SYS-AC-235). 2 MiB
lifts fast. `small` is the under-cap control.

## Rebuild

```sh
rustup target add wasm32-unknown-unknown   # once
cargo build --release --target wasm32-unknown-unknown
wasm-tools component new \
  target/wasm32-unknown-unknown/release/big_output.wasm \
  -o ../big_output.component.wasm
wasm-tools validate ../big_output.component.wasm
wasm-tools component wit ../big_output.component.wasm   # export tool-exports
```

The committed `../big_output.component.wasm` lets tests load a real component
with no wasm toolchain installed (mirrors echo_tool).
