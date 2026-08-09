# system-acceptance — config-driven harness substrate

The shared, journey-agnostic **system-acceptance harness** the parallel e2e tracks
build on. [`SystemUnderTest`] boots a wired in-process runtime in a temp git workspace
and drives an agent turn end-to-end through the **production composition root**
(`advance_cli::agent_loop::build_agent_loop` + `WasmMessageHandler`), reusing the real
`cap-*` providers — **not** the production `advance start` boot path.

> **Contract:** "add a journey = pick a config + supply a guest fixture + write
> assertions — **no edits to `src/lib.rs`**." Every typed witness has a *raw* counterpart
> (`events()`, `events_from_db()`, `workspace_root()`, `event_db_path()`,
> `grant_store()`), so an assertion nobody anticipated never forces a harness change.

## The builder

```rust
use system_acceptance::{Cap, GrantMode, GrantChain, EventSink, LlmMode, SystemUnderTest};

let sut = SystemUnderTest::builder()
    .caps(&[Cap::Fs, Cap::Memory, Cap::Grant, Cap::Llm])   // any subset; default [Fs]
    .grant(GrantMode::Real)                                 // AllowAll (default) | Real
    .grant_chain(GrantChain::Restrict)                      // Supervised (default) | Restrict
    .events(EventSink::RealBus)                             // Capturing (default) | RealBus
    .llm(LlmMode::Loopback(/* LoopbackScript */))           // Off (default) | Loopback | LoopbackScripted
    .budget(run_budget)                                     // loopback-only; default AllowAll (HF-2)
    .repetition(repetition_guard)                           // loopback-only; default NoOp (HF-2)
    .agent_id("agent:harness")                              // default AGENT_ID
    .build(guest_core_wasm)
    .await;
```

`SystemUnderTest::start(guest)` is preserved as the BS-3 back-compat shortcut
(`builder().caps(&[Cap::Fs]).build(guest)`).

### Driving a turn

```rust
sut.inject_message("sender", b"payload").await;  // real dispatcher → emits msg.received
sut.run_turn().await;                             // production run_agent drives the guest
```

### Assertions (typed + raw)

| typed | raw counterpart |
|-------|-----------------|
| `assert_event(type, pred)` / `events_of_types(&[..])` | `events() -> Vec<Event>` |
| `assert_db_event(type, pred)` / `db_event_count(..)` / `assert_no_dropped_events()` | `events_from_db() -> Vec<DbEventRow>`, `event_db_path()` |
| `assert_exactly_one_turn_commit()` | `turn_commits() -> Vec<CommitInfo>` |
| `read_workspace_file(rel)` | `workspace_root()` |
| — | `grant_store()`, `llm_gateway()`, `llm_recorded_authorization()`, `llm_chat_request_count()` (HF-2), `circuit_breaker()` (HF-2) |

## Worked example per mode

**Capability subset** (`Cap::Fs|Memory|Skills|Llm|Grant|Tools`) — registered via the real
`register_agent_*` fns:

```rust
let sut = SystemUnderTest::builder().caps(&[Cap::Fs]).build(j01_guest).await;
sut.inject_message("h", b"hi").await; sut.run_turn().await;
sut.assert_exactly_one_turn_commit();          // fs.write → cap-fs → git Turn commit
```

**Grant `Real`** — the real `GrantCheckImpl` L1 gate + (with `Cap::Grant`) the agent-grant
WIT host fns over a real `ResolverChain`:

```rust
// AllowAll commits; Real with no fs grant DENIES the ungranted fs.write at L1.
let sut = SystemUnderTest::builder().caps(&[Cap::Fs]).grant(GrantMode::Real).build(j01_guest).await;
sut.inject_message("h", b"x").await; sut.run_turn().await;
assert_eq!(sut.turn_commits().iter().filter(|c| c.is_turn).count(), 0); // denied → no commit
```

**Events `RealBus`** — the real synchronous `EventBus` (JSONL under
`<ws>/.runtime/events/jsonl/` + SQLite at `<ws>/.runtime/events.db`) with SQLite
read-back. **Run such tests under
`#[tokio::test(flavor = "multi_thread")]`** (the sync bus writes inline during the turn;
bounded per-turn I/O, deterministic read-back, no drain):

```rust
let sut = SystemUnderTest::builder().events(EventSink::RealBus).build(j01_guest).await;
sut.inject_message("h", b"x").await; sut.run_turn().await;
sut.assert_db_event("msg.received", |r| r.agent_id.as_deref() == Some(sut.agent_id()));
sut.assert_no_dropped_events();
```

**LLM `Loopback`** — a deterministic backend through the **real** cap-llm gateway +
cap-http `DefaultHttpSecurityChain` (all 10 chain steps) reaching a loopback axum mock via
the `dns_overrides` seam, **with zero cap-http edits** and production SSRF intact (the
chain's `DefaultSsrfGuard` sees a public IP for the provider hostname; the executor's DNS
override sends the TCP to `127.0.0.1`). See `src/llm_loopback.rs`:

```rust
use system_acceptance::llm_loopback::LoopbackScript;
use cap_llm::{ChatMessage, ChatParams, ChatRole, LlmGatewayInternal};

let sut = SystemUnderTest::builder()
    .caps(&[Cap::Llm]).llm(LlmMode::Loopback(LoopbackScript::reply("hello"))).build(j01_guest).await;
let resp = sut.llm_gateway().unwrap()
    .chat(vec![ChatMessage { role: ChatRole::User, content: "hi".into() }], ChatParams::default())
    .await.unwrap();
assert_eq!(resp.text, "hello");
```

**Generic host-fn primitive** — drive any registered host fn directly (linker-bypass), e.g. to witness
a channel `send-raw` outbound through the real handler → `OutboundDispatcher` without a guest:

```rust
use wasmtime::component::Val;
// (after .with_channel_capture(); see the channel example below for the capturing seam)
let _ = sut.call_host_fn(
    "channel", "advance:runtime/channel-host@0.1.0", "send-raw",  // or cap_channel::CHANNEL_HOST_NAMESPACE
    vec![Val::String(sut.channel_subscription_id().unwrap().0), Val::List(b"reply".to_vec().into_iter().map(Val::U8).collect())],
).await;
assert!(sut.captured_outbound().iter().any(|o| o.body == b"reply"));
```

**Multi-agent `.agents()`** — seed a tree, witness a real spawn + a real await round-trip:

```rust
use system_acceptance::{AgentSpec, Cap, SystemUnderTest};
use advance_shared_types::agent_tree::AgentKind;

let sut = SystemUnderTest::builder()
    .agents(&[
        AgentSpec { id: "agent:root".into(), kind: AgentKind::Root, parent: None, caps: vec![Cap::Fs] },
        AgentSpec { id: "agent:c1".into(), kind: AgentKind::Child, parent: Some("agent:root".into()), caps: vec![] },
    ])
    .build(j01_guest).await;
assert_eq!(sut.tree_snapshot().nodes.len(), 2);          // seeded root + child (bare-id store)
// spawner() drives the real DefaultSpawner; await_manager()/resolve_await drive a real session.
```

**cap-channel `.with_channel_capture()`** — inbound inject + outbound capture (SYS-J-01 reply leg):

```rust
let sut = SystemUnderTest::builder().with_channel_capture().build(j01_guest).await;
sut.inject_channel_inbound(b"inbound", vec![]).unwrap();
assert_eq!(sut.poll_channel_inbound().unwrap().unwrap().data, b"inbound");   // real SubscriptionManager
sut.drive_channel_send_raw(b"reply").await.unwrap();                          // via the registered SendRawHandler
assert!(sut.captured_outbound().iter().any(|o| o.body == b"reply"));         // captured at the chain seam
```

**cap-mcp `.with_mcp_transports()` + `drive_mcp_tool()`** — an in-process tool call:

```rust
use system_acceptance::McpServerSpec;

let sut = SystemUnderTest::builder()
    .with_mcp_transports(vec![McpServerSpec::scripted("srv", &["echo"]).reply(br#"{"ok":true}"#)])
    .build(j01_guest).await;
let out = sut.drive_mcp_tool("srv", "echo", br#"{"x":1}"#).await.unwrap();
assert_eq!(out, br#"{"ok":true}"#);
```

**`drive_runnable()`** — drive a runnable component's `run` in-process (test `RunnableHook`):

```rust
use advance_scheduler::types::RunStatus;

let res = sut.drive_runnable(Arc::new(MyTestHook), "cron:daily", None, None).await.unwrap();
assert_eq!(res.status, RunStatus::Completed);
```

## Guest fixtures

A guest is a `wasm32-unknown-unknown` core module under
`crates/runtime/tests/fixtures/guest-rust-*/`, `include_bytes!`'d and wrapped to a
Component at test time. The harness ships:
- `guest-rust-j01-skeleton` — imports `agent-fs`, writes one file (fs/grant/events smokes).
- `guest-rust-mem-skeleton` — imports `agent-memory`, remember→recall (see the blocker note in its README).

## Mode smokes (the substrate's own witnesses)

`tests/mode_*_smoke.rs` — one per mode, all green except the `#[ignore]`d full memory
remember→recall witness (blocked upstream; see below). They are NOT the real journeys (the
63 SYS-J journeys are the downstream tracks).

## Fast-follow modes (SHIPPED — HF slice, 2026-06-03)

The four additive builder fast-follows + a generic host-fn primitive. All back-compatible (the
default `caps=[Fs]` / `AllowAll` / `Capturing` path is byte-identical); each is gated behind its own
opt-in builder flag or accessor, so existing journeys are unaffected.

- **Generic host-fn invocation** — `call_host_fn(cap, ns, name, params)` /
  `call_host_fn_as_agent(caller, cap, ns, name, params)` + `host_registry()`. Looks up a registered
  host fn (`HostRegistry::lookup`) and invokes its `HostFunctionHandler::call` **directly**, bypassing
  the WASM component linker — so it drives caps whose `register_*` namespace is UNVERSIONED (channel /
  lifecycle / mcp), which a versioned guest import cannot reach (see the blocker note below). This is the
  workhorse for tracks: it exercises the full `Val-decode → handler → provider` boundary with no guest.
  **Witness-fidelity caveat:** because it calls the handler directly, it bypasses the production
  `CapabilityInjector` grant gate + the host-authoritative `agent_id` stamping. It faithfully witnesses
  properties that live BELOW the handler (e.g. channel owner/method/CRLF checks, `on_reply` source/slot
  match — un-fakeable), but NOT grant-gate authorization or caller-identity attribution — never drive a
  handler as a forged agent id and then assert the runtime *authorized*/*attributed* it (use a real
  guest-driven turn for those).
- **Multi-agent tree + spawn/await substrate** (Track C) — `.agents([AgentSpec…])` seeds a multi-node
  `HarnessAgentTree` (`agent:`-ids, for messaging/await/fs) plus a separate bare-id `AgentTreeStore` owned
  by a real `DefaultSpawner` (two ID conventions — see blocker note). Accessors: `tree_snapshot()`,
  `spawner()`, `await_manager()`, `resolve_await(session, slot, reply)`. Witnesses a real
  `DefaultSpawner.spawn_child` tree mutation (SYS-J-07 shape) and a real `AwaitSessionManagerImpl` oneshot
  resolution (SYS-J-05 shape). `register_agent_lifecycle` (the 10-field bundle) is **deferred**.
- **cap-channel outbound capture + inbound inject** (SYS-J-01 reply leg, Track E channel) —
  `.with_channel_capture()` + `channel_subscription_id()` / `inject_channel_inbound()` /
  `poll_channel_inbound()` / `drive_channel_send_raw()` / `captured_outbound()`. Outbound `send-raw` is
  captured at a test `HttpSecurityChain` seam; inbound via the real `SubscriptionManager`. (There is no
  `notify-channel` host fn — only `subscribe`/`poll-raw`/`send-raw`.)
- **cap-mcp in-process tool call** (Track E-mcp, J-28/58) — `.with_mcp_transports([McpServerSpec…])` +
  `drive_mcp_tool(server, tool, params)` + `mcp_client()`. Drives a real `McpClient::invoke_tool`
  (whitelist → tool-pattern → input-schema → transport → output-schema) over an injected in-process
  scripted transport — no subprocess/network, fully witnessable.
- **In-process runnable driver** (Tracks F/G) — `drive_runnable(hook, id, config_data, trigger)` calls a
  `RunnableHook::run_once(ComponentConfig)` in-process (the trait + `RunResult`/`RunStatus` are shipped).
  Witnessed against a **test** `RunnableHook`; the production WASM runnable path is upstream-blocked
  (below).

## Resilience knobs (SHIPPED — HF-2 slice, 2026-06-04)

The shipped `.llm(Loopback…)` backend used to hard-wire `AllowAllBudget`, a `NoOpRepetitionGuard`,
a single canned HTTP-200, and a **private** event bus — so a journey that needs to witness a
budget block, a repetition terminate, a 429→retry sequence, or an `llm.*` cost event had to
hand-roll its own loopback (`tests/h_loopback/mod.rs`). HF-2 folds those four capabilities into
the shipped harness. All additive + back-compatible (`.llm(LlmMode::Loopback(LoopbackScript::reply(…)))`
+ default `AllowAll`/`NoOp` is byte-identical to BS-3); the resilience journeys (Track H/J round-2)
can migrate onto `SystemUnderTest::builder()` instead of the test-local helper.

- **`.budget(Arc<dyn RunBudget>)`** — supply a real `advance_run_manager::InMemoryRunBudget`
  (caps / scripted deny) instead of the default `AllowAllBudget`. The gateway's `RunBudget::check`
  preflight runs **before** dialing the provider, so a budget-exhausted run errors with
  `LlmError::BudgetExceeded(reason)` and the mock observes zero requests. **The preflight is
  `run_id`-gated:** it fires only on the run-scoped path `LlmGateway::chat_for_run(msgs, params,
  run_id)` (and `generate` with a run id) — plain `LlmGatewayInternal::chat()` passes `run_id =
  None` and **skips the budget check entirely**. Drive a budget witness through `chat_for_run`
  (see `tests/mode_llm_budget_smoke.rs`), not `chat()`.
- **`.repetition(Arc<dyn RepetitionGuardCheck>)`** — supply a real `RepetitionGuard` (triplet /
  output-hash policy) instead of the default `NoOpRepetitionGuard`. Repeated identical output
  trips the guard → `LlmError::RepetitionTerminated`.
- **`LlmMode::LoopbackScripted(Vec<ScriptedResponse>)`** — a FIFO `(status, ScriptedBody)`
  backend (the last response replays once the queue drains) so a journey can script
  `429-then-200` (retry), `401` (non-retryable), or `invalid-then-valid` structured-output
  bodies. The mock returns the **scripted** HTTP status, so the REAL OpenAI adapter does the
  429→RateLimited / 4xx→terminal / 200→parse mapping. Constructors (in
  `system_acceptance::llm_loopback`): `ScriptedResponse::ok_chat(content, prompt_tokens,
  completion_tokens)` and `::err(status, body)` build the historical JSON shape;
  `::sse(status, Vec<SseEvent>)` serves a **verbatim** SSE script (no auto usage frame, no auto
  `[DONE]` — absence is scriptable, for dishonest-SSE fail-closed witnesses); `::raw(status,
  body)` writes bytes as-is; `.with_gate(SseGate)` gates an Sse script per event
  (`release(events + 1)` drains it; `events_emitted()` / `timed_out()` are the out-of-band,
  timing-free assertions — see `tests/llm_loopback_sse_faults.rs`). The replay of a drained
  FIFO never gates. NOTE: `ScriptedResponse.body` is the `ScriptedBody` enum (a recorded
  harness-API break vs the old bare-`String` field; `tests/h_loopback/mod.rs` keeps its own
  independent type).
- **Gateway-event exposure** — the loopback gateway now emits `llm.request` / `llm.retry` /
  `llm.response` / `llm.error` into the harness's normal sink, so they surface through `events()`
  (Capturing) / `events_from_db()` (RealBus). The `llm.response` payload carries
  `cost_usd` / `input_tokens` / `output_tokens` (the event-level cost witness).
- **`circuit_breaker() -> Arc<dyn CircuitBreakerBus>`** — the real, injector-wired breaker bus.
  `open(CircuitBreaker{ scope, target, state: Open, … })` then `is_open_agent`/`is_open_capability`
  drive the breaker; `DefaultCircuitBreakerBus::is_admin_op(&AdminOp::TerminateAgent)` classifies an
  admin bypass. (This exposes the *driver*; the full "new dispatch blocked / messages frozen /
  admin-bypass through the real messaging path" journey is Track J round-2.)

```rust
use system_acceptance::llm_loopback::ScriptedResponse;
use system_acceptance::{Cap, LlmMode, SystemUnderTest};
use cap_llm::{ChatMessage, ChatParams, ChatRole, LlmGatewayInternal};

// A 429-then-200 retry, witnessed through the shipped builder + the harness event sink.
// (For a budget/repetition witness, add the `.budget(rm.budget())` / `.repetition(guard)`
// knobs — see tests/mode_llm_budget_smoke.rs and tests/mode_llm_repetition_smoke.rs.)
let sut = SystemUnderTest::builder()
    .caps(&[Cap::Llm])
    .llm(LlmMode::LoopbackScripted(vec![
        ScriptedResponse::err(429, r#"{"error":{"message":"rate limited"}}"#),
        ScriptedResponse::ok_chat("recovered", 3, 4),
    ]))
    .build(j01_guest).await;
let resp = sut.llm_gateway().unwrap()
    .chat(vec![ChatMessage { role: ChatRole::User, content: "hi".into() }], ChatParams::default())
    .await.unwrap();
assert_eq!(sut.llm_chat_request_count(), 2);                          // 429 then 200
assert!(sut.events().iter().any(|e| e.event_type == "llm.retry"));    // routed to the harness sink
```

> **SSE / streaming — DEFERRED (fast-follow).** A scriptable SSE / `poll-stream` backend
> (ordered deltas, single terminal `llm.response`, budget-checked-once — SYS-J-61 / SYS-AC-188/189)
> is **not** shipped here: cap-llm's `poll-stream` host fn is an unimplemented stub (`stream()` yields
> the whole response as one synthetic chunk) and no `cap-llm-gaps` crate exists in the workspace yet.
> Per the HF-2 plan, the budget / repetition / retry / event-exposure knobs ship now; the SSE leg is a
> fast-follow that lands once cap-llm implements `poll-stream`.

## Witness timing and synchronization conventions

Conventions for every witness in this crate that asserts on ordering, cadence, spacing, or
progress (grok-repass Item 4, ADR 2026-07-30 Decision 1). New tests MUST follow them; existing
tests are brought over opportunistically when a lane already touches them — there is no
repo-wide sweep here.

- **(a) Producer clock only for ordering claims.** Ordering / cadence / spacing assertions read
  the **producer's** timestamp (the one the EventBus event carries), never the harness's
  `Instant::now()`. Harness-side wall time measures the harness plus the scheduler plus the
  machine — a claim about event ordering proven with it is a claim about the test box.
  Explicitly **not applicable** to the ADR D9 p95 SLO ceiling checks, which legitimately
  measure harness-side elapsed time — that is what an SLO is.
- **(b) Synchronize on the Nth expected event, never a fixed sleep.** "Wait then assert" is a
  race with a configurable loss rate; awaiting the Nth event (a counting sink, a gate release,
  a frame count on the wire) is exact. JSONL-reuse paths carry a stale-capture guard so an old
  capture cannot satisfy a new wait. A **bounded watchdog that turns a stuck wait into a
  FAILURE** is not a synchronization primitive and is permitted — the loopback's `SseGate` is
  the worked example: releases gate all progress; the bounded acquire only converts a starved
  script into a deterministic out-of-band `timed_out()` failure signal
  (`tests/llm_loopback_sse_faults.rs`).
- **(c) No xfail/XPass ledgers, no cell-matrix expected-failure runners.** Excluded per the
  2026-07-27 SYS-J-67 v2 ADR's "rejects ignored tests" clause: a witness either passes against
  its stated claim or fails the run. A test that is EXPECTED to fail is a claim the suite does
  not make — delete it or fix it; do not ledger it.

## Resolved upstream blocker (was: guest witnesses importing an UNVERSIONED cap namespace)

A guest can only witness a host fn end-to-end if the cap's `register_*` namespace and
the guest's wit-bindgen import agree on the version. cap-fs registers the **versioned**
`"advance:runtime/agent-fs@0.1.0"`, so the fs guest works. cap-memory and cap-grant
formerly registered **unversioned** namespaces, which the component linker would not match
against a versioned guest import. **Resolved by /dev Slice N1 (n1-namespaces)**: cap-memory
(`"advance:runtime/agent-memory@0.1.0"`, `host_fn.rs:23`), cap-grant
(`"advance:runtime/agent-grant@0.1.0"`, `wit_impl.rs:55`) and the remaining caps
(lifecycle / secrets / channel / tools / skills / mcp) now register **versioned** namespaces,
matching the guest imports.

Consequently:
- **Memory `remember`→`recall`** guest-turn witness is now ACTIVE (no longer `#[ignore]`d)
  (`mode_memory_smoke.rs::memory_remember_recall_through_a_real_turn`) — the ready guest +
  assertions drive a real turn now that cap-memory is versioned. The green
  `memory_cap_registers_and_coexists_with_fs_turn` proves the cap registers + coexists.
- **Grant resolver-walk** (`request-capability` → `resolver.invoked` → `grant.issued`,
  exercising the `ResolverChain` + grant store) is now UNBLOCKED but not yet witnessed here:
  it needs a dedicated grant guest fixture, which **Track D** owns (out of N1's string-only
  scope). The landed grant witness (`mode_grant_smoke.rs`) meanwhile exercises the **real L1
  `GrantCheckImpl`** through the versioned fs guest: `grant(Real)` with no fs grant denies
  the ungranted `fs.write` (no commit), `grant(AllowAll)` commits — a real authorization
  differential. The `grant_store()` + `events_of_types(["resolver.invoked", "grant.issued",
  "authz.checked"])` accessors are provided for Track D to assert the resolver-walk now that
  the cap-grant namespace is versioned.

### HF fast-follow blockers (what the new modes can vs cannot witness end-to-end)

Since Slice N1 versioned every cap namespace (above), the unversioned-namespace *component-linker*
blocker no longer applies to channel / mcp / lifecycle / messaging — a versioned guest CAN now import
them. The **generic host-fn primitive** (`call_host_fn`) remains the harness's convenience driver:
invoking a registered `HostFunctionHandler` directly exercises the real `Val-decode → handler →
provider` path with NO guest component or fixture, so channel / mcp / spawn / await are witnessable at
the harness API level today without authoring a guest. (It resolves the namespace via the exported
`cap_channel::CHANNEL_HOST_NAMESPACE` etc., so it tracks N1's `@0.1.0` versioning automatically.) What
is still NOT witnessable through a single real *guest turn* — genuine product gaps, NOT namespace issues:

- **Multi-agent spawn → child-reply → parent-resume through a guest** is upstream-blocked: there is no
  guest→host *reply* entry-point — `build_agent_loop`'s action dispatcher is **gate-only**
  (`cli/agent_loop.rs` — "Production action delivery … reply leg, deferred") and the `send` host-fn is
  not yet shipped. `.agents()` therefore witnesses spawn via the real `DefaultSpawner` (tree mutation) and
  await via the real `AwaitSessionManagerImpl` (`resolve_await` injects the reply a guest cannot yet send)
  — the substrate the tracks need; the guest-driven end-to-end loop unblocks when the product ships the
  `send` host-fn.
- **Two ID conventions.** cap-lifecycle's `AgentTreeStore` validates **bare** ids (`^[A-Za-z0-9_-]{1,64}$`,
  no colon); messaging/reply-tracker route canonical `agent:<body>` ids. `.agents()` keeps the two views
  separate (a multi-node `HarnessAgentTree` with `agent:` ids for routing/await/fs; a bare-id
  `AgentTreeStore` for the spawn witness) rather than forcing one tree to serve both.
- **cap-channel.** Outbound `send-raw` capture is witnessed by invoking the registered `SendRawHandler`
  via `call_host_fn` (`OutboundDispatcher::dispatch` is `pub(crate)`, reachable only through that handler),
  capturing at a test `HttpSecurityChain` seam — no guest needed. There is **no `notify-channel` host fn**
  — the channel host surface is exactly `subscribe`/`poll-raw`/`send-raw`.
- **`drive_runnable` is test-hook-driven.** The `RunnableHook` trait + `RunResult`/`RunStatus` are shipped,
  but there is **no production WASM `RunnableHook`** (no binding to a WIT `run` export), **no
  `Scheduler::run`** orchestration loop, no cron-expression parsing, and the auto-loop iteration-close is
  unwired. So `drive_runnable` witnesses Tracks F/G against a *test* runnable; a real WASM runnable path is
  the product **`P-runnable`** follow-up.
