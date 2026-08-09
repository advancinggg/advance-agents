# guest-tinygo-smoke

Minimal TinyGo smoke fixture for MODULE-001-AC-03's "Go/TinyGo guests load
with experimental flag (smoke test only)" clause.

Does NOT implement the advance-host world exports. Purpose: produce a
Component Model-wrapped .wasm binary loadable by `ComponentRuntime::load_component`.

## Regen procedure

Prerequisites: TinyGo >= 0.34 + Go (version compatible with TinyGo) + `wasm-tools` CLI.

Install examples:
- macOS: `brew tap tinygo-org/tools && brew install tinygo && cargo install wasm-tools`
- Linux: binary release from https://github.com/tinygo-org/tinygo/releases

Steps:
1. `cd crates/runtime/tests/fixtures/guest-tinygo-smoke`
2. `tinygo build -target=wasip2 -o ../guest-tinygo-smoke.component.wasm .`
3. `tinygo version > tinygo-version.txt`
4. Commit atomically: the `.wasm` artifact + `tinygo-version.txt`.
