# guest-rust-ext-probe

Probe guest. Imports `fixture:probe/host@0.1.0` (provided dynamically
by the host `CapabilityInjector` under that versioned namespace) and exports
`message-driven` + `runnable`.

On `handle-message`, payload text `call <arg>` calls `fixture:probe/host::call`
and replies with action payload `ok:<v>` or `err:<e>`. Any other payload replies
`noop`. `handle-message` always returns `Ok` (a guest `Err` would poison the
Store). `init` returns empty state; `run` is a trivial `Completed`.

The committed `../guest-rust-ext-probe.core.wasm` is wrapped to a Component at
test time via `wit_component::ComponentEncoder` (production wraps through
`build-agent`). The crate is excluded from the workspace (own `[workspace]`
table).

## WIT note

`wit/advance.wit` is a verbatim copy of `crates/runtime/wit/advance.wit` plus
the `advance-host-ext-probe` world. `wit/deps/fixture-probe/probe.wit` is the
`fixture:probe@0.1.0` package. If the canonical WIT changes, copy it again and
keep the appended world block.

Validate: `wasm-tools component wit wit/`.

## Regen procedure

1. Ensure the wasm32 target: `rustup target add wasm32-unknown-unknown`.
2. If the canonical WIT changed, re-derive `wit/advance.wit` from
   `crates/runtime/wit/advance.wit` and keep the `advance-host-ext-probe` world.
   Validate: `wasm-tools component wit wit/`.
3. First-time bootstrap (no Cargo.lock): `cargo generate-lockfile`.
4. Build: `cargo build --target wasm32-unknown-unknown --release --locked`.
5. Copy artifact: `cp target/wasm32-unknown-unknown/release/guest_rust_ext_probe.wasm ../guest-rust-ext-probe.core.wasm`.
6. Verify size < 500 KiB: `wc -c ../guest-rust-ext-probe.core.wasm`.
7. `cargo clean`. Do NOT commit `target/`.
8. Commit atomically: the `.wasm` artifact, `Cargo.lock`, and any WIT change.
