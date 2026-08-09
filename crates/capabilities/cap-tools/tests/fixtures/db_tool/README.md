# db_tool fixture (MODULE-017-AC-31 / REQ-160)

The agent-facing **DB tool**, shipped as an independent WASM component exporting
`advance:runtime/tool-exports@0.1.0` (CONTRACT-163):

- `describe()` → one `query` method (non-idempotent).
- `execute("query", sql_bytes)` → runs REAL SQL inside this wasm sandbox over a
  fresh in-memory engine and returns the final `SELECT`'s rows as JSON
  (`[[1],[2]]`).
- `execute(other, _)` → `Err("method-not-found: …")`; malformed SQL → `Err(…)`.

## Why this is not a stand-in (anti-fake-green, MODULE-017 §3.6)

The MODULE-017:1998 reconcile recorded that a fixture which merely "proves
ToolRegistry can run a WASM component" (echo_tool already shows that) is
fake-green; AC-31 returns to Verified only once the agent DB tool **ships and
runs real SQL via the L2 tool path**. This component:

- genuinely **tokenizes, parses, and executes** a bounded SQL subset —
  `CREATE TABLE`, `INSERT … VALUES`, and `SELECT` with column projection and a
  `WHERE col = value` filter — entirely in guest wasm (see `src/lib.rs`);
- has **no host SQL/DB import** (zero imports in `wit/world.wit`), so MODULE-004's
  `rusqlite` index stays agent-invisible — the tool is reachable ONLY through the
  L2 `ToolRegistry` (`skill::db`), never a host fn;
- is loaded through the PRODUCTION skill→tool bridge
  (`advance_cli::wiring::register_skill_tools`) as `skill::db`, not a direct
  `register_binary`.

## Self-contained engine (build robustness)

The SQL engine uses **zero external crates** — only `wit-bindgen` for the
component ABI. The plan originally contemplated pinning `sqlparser`; a
self-contained engine is used instead so the artifact builds deterministically
for `wasm32-unknown-unknown` with no network fetch, no transitive `getrandom` /
WASI / C-toolchain, and no AST-version churn. The acceptance property is
identical — real SQL parsed + executed in-sandbox, valid vs. malformed
distinguished — and is independent of the parser's provenance.

## Rebuild

Needs the `wasm32-unknown-unknown` target and `wasm-tools` (the repo's existing
fixture pipeline; cargo-component is NOT required):

```sh
rustup target add wasm32-unknown-unknown   # once
cargo build --release --target wasm32-unknown-unknown
wasm-tools component new \
  target/wasm32-unknown-unknown/release/db_tool.wasm \
  -o ../db_tool.component.wasm
wasm-tools validate ../db_tool.component.wasm
wasm-tools component wit ../db_tool.component.wasm   # should show: export tool-exports
```

The committed `../db_tool.component.wasm` lets cap-tools / cli tests load a real
component with no wasm toolchain installed (mirrors `echo_tool.component.wasm`).
