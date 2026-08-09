# Hand-off — notify-agent host-fn (Satellite S1, 2026-06-13)

Branch `sat/notify-agent-hostfn`. This satellite ships the **data-layer mechanism**
only (handler + registration + crate tests). The mainline H2 harvest owns the wiring
and all ledger flips.

## What was built (all inside `crates/messaging/`)

- **`src/host_fn.rs`** (new) — `NotifyAgentHandler` (`impl HostFunctionHandler`) bridging
  the WIT `notify-agent` call to the existing `MailboxDispatcherImpl::notify_agent`
  (`dispatcher.rs:568-582` → `deliver_notify`). Lifts the 3 WIT params, derives the
  sender from `ctx.agent_id`, lowers `Result<(), NotifyError>` via `encode_notify_error`
  (4 canonical variants). Bounded Val decoders + `sanitize_decode_error` mirror the
  reply-tracker precedent. `register_notify_host_fns(registry, dispatcher)` registers one
  `HostFunctionSpec`.
- **`tests/notify_host_fn.rs`** (new) — TN-01..TN-08 (delivery, unknown-target,
  mailbox-full, breaker-open + PII non-leak, registration, context round-trip, decode-fail
  incl. empty-params arity guard, const pin). TN-09 (encoder variant-spelling drift guard)
  lives in-crate in `src/host_fn.rs`.
- **`src/lib.rs`** — `pub mod host_fn;` + re-exports (`NotifyAgentHandler`,
  `register_notify_host_fns`, `NOTIFY_CAPABILITY`, `NOTIFY_NAMESPACE`); crate-rustdoc note.
- **`Cargo.toml`** — `wasmtime = { workspace = true }` added to `[dependencies]`
  (promoted transitive edge; mirrors `reply-tracker/Cargo.toml`).

## Pinned strings (the cli linker lookup MUST agree — pinned in TN-05/TN-08)

| Field | Value |
|-------|-------|
| capability | `messaging` |
| namespace | `advance:runtime/notify@0.1.0` |
| name | `notify-agent` |
| idempotent | `false` (state-modifying — enqueues a mailbox message) |

`messaging` was chosen for grant-model continuity with the reply-tracker
`agent-messaging` host fns; the distinct namespace keeps the `(namespace, name)` linker
key collision-free.

## Mainline follow-up 1 — cli composition-root wiring

At the composition root, build the configured dispatcher then register:

```rust
let dispatcher = Arc::new(
    MailboxDispatcherImpl::new_full(store, tree, trace, channel_registry)
        .with_circuit_breaker_bus(cb_bus)
        .with_event_bus(event_bus),
);
register_notify_host_fns(&registry, dispatcher.clone() as Arc<dyn MailboxDispatcher>);
```

**Cross-registration**: capability `messaging` is shared with
`register_reply_tracker_host_fns` (await-replies + heartbeat under namespace
`advance:runtime/agent-messaging@0.1.0`). After both run, `lookup("messaging")` returns
**3 specs** — non-colliding because the `(namespace, name)` keys differ. The
`CapabilityInjector::inject` step is the gate for any duplicate `(namespace, name)`;
verify there at inject time.

## Mainline follow-up 2 — `ctx.agent_id` stamping (pitfall 2)

For the SYS-J-55 system→agent bypass, the driver MUST stamp `ctx.agent_id = "system"`
(or a valid `agent:`/`user:` id). The dispatcher re-runs `is_safe_id(from)`; a
`component:`-shaped or unstamped ctx is rejected → the handler returns
`invalid-target("invalid_id")`. This is a mainline-harvest concern, not handled here.

## Ledger flips DEFERRED to this harvest (NOT touched by this satellite)

- **MODULE-006-AC-02** (notify WIT callable) and **MODULE-006-AC-15** (cron notify-agent
  e2e) — both require the wired e2e WIT witness (cli linker + ctx stamping), which this
  single-crate satellite does not build. They stay `untested` in MODULE-006 §3.4.
- **SYS-AC-173 / 174 / 175 / 244** — flipped by the mainline harvest after wiring at the
  cli composition root.
- MODULE-006 §3.2/§3.3/§3.5/§3.6 bookkeeping (record the new file + TN band) — mainline,
  to avoid concurrent divergent doc writes (reply-tracker parallel-safety precedent).

## T42 invariant

No `import notify` was added to any WIT world. Registration is at the `HostRegistry` data
layer only. `notify-channel`'s host-fn is a future slice (not registered here).
