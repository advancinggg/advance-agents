# guest-rust-d-grant

/dev Track D (2026-06-04) — grant system-acceptance **guest** fixture.

Targets the `advance-host-grant` world (imports `agent-grant`, exports `message-driven` +
`runnable`). On `handle-message` it parses the inbound payload as a UTF-8 **command line** and
calls the matching `agent-grant` host fn (provided dynamically by the host `CapabilityInjector`
under the **versioned** namespace `advance:runtime/agent-grant@0.1.0`). The WIT `result` is matched
and **swallowed** — the guest returns `Ok(empty ActionResult)` for both Ok and a WIT `result::err`,
because the system-acceptance witnesses assert on emitted events + the grant store, not on the
guest's return value, and the negative scenarios (denied / pending / permission-denied) intentionally
produce a WIT error. (An L1 grant-gate DENY traps the turn, but every grant op runs under capability
`"grant"`, so the harness pre-seeds a `"grant"` self-management grant and no trap occurs.)

Command grammar (space-delimited tokens; params are `key=value`):
- `req <capability> [k=v ...]`               → `request-capability`
- `revoke <target> <grant-id>`               → `revoke-grant`
- `delegate <target> <capability> [k=v ...]` → `delegate-grant`   (deferred-stub use)
- `narrow <target> <grant-id> [k=v ...]`     → `narrow-grant`      (deferred-stub use)
- `apply-preset <target> <preset-name>`      → `apply-preset`      (deferred-stub use)

The committed `../guest-rust-d-grant.core.wasm` artifact is wrapped to a Component at test time via
`wit_component::ComponentEncoder` (same pattern as `guest-rust-j01-skeleton`) and instantiated
through the host's `advance-host-with-capabilities` bindgen — only the EXPORTS must match; the
`agent-grant` IMPORT is satisfied dynamically by the host `CapabilityInjector`.

## WIT note (important)

The guest's `wit/advance.wit` is the canonical host WIT (`crates/runtime/wit/advance.wit`) plus a
**trimmed** `agent-grant` interface and the `advance-host-grant` world. The trim is REQUIRED: the
canonical `crates/capabilities/cap-grant/wit/agent-grant.wit` declares BOTH a `grant-status: func(...)`
AND a `variant grant-status`, which collide in WIT's single per-interface name space (wasm-tools /
wit-bindgen reject it). The host never hits this because it satisfies the namespace via dynamic `Val`
encoding (`cap-grant/src/wit_impl.rs`), not wit-bindgen. This guest imports only the 5
grant-management funcs it drives (signatures IDENTICAL to the canonical ones), omitting
`active-grants` / `grant-status` (and `grant-info` / the `grant-status` variant they need). The host
registers a SUPERSET under the versioned namespace, so this subset import links cleanly.

## Regen procedure

1. Ensure the wasm32 target: `rustup target add wasm32-unknown-unknown`.
2. If the canonical WIT changed, re-derive `wit/advance.wit`:
   ```
   cp ../../wit/advance.wit wit/advance.wit
   # then append the TRIMMED agent-grant interface (5 funcs + their types, signatures matching
   # ../../../capabilities/cap-grant/wit/agent-grant.wit) and:
   #   world advance-host-grant { import agent-grant; export message-driven; export runnable; }
   ```
   Validate: `wasm-tools component wit wit/advance.wit`.
3. First-time bootstrap (no Cargo.lock): `cargo generate-lockfile`.
4. Build: `cargo build --target wasm32-unknown-unknown --release`.
5. Copy artifact: `cp target/wasm32-unknown-unknown/release/guest_rust_d_grant.wasm ../guest-rust-d-grant.core.wasm`.
6. Verify size < 500 KiB: `wc -c ../guest-rust-d-grant.core.wasm`.
7. `cargo clean`. Do NOT commit `target/`.
8. Commit atomically: the `.wasm` artifact, `Cargo.lock`, and any WIT change.
