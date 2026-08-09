//! CapabilityInjector — Slice T (extended in Slice V with WASI preview2 wiring).
//!
//! The linker-wrapping half of CONTRACT-001 (HostRegistry ships the data
//! registry via Slice H + I; this module ships the actual host-fn injection
//! on a `wasmtime::component::Linker`). Scope:
//!
//! - L0 filter: only capabilities registered in `HostRegistry` can inject
//!   host functions. Unknown capabilities return `HostError::UnknownCapability`.
//! - L1 gate: every invocation calls `GrantCheck::check`; on `Deny(reason)`
//!   the invocation returns `capability-denied: {reason}`.
//! - CircuitBreakerBus query: open capability breakers return
//!   `circuit-breaker: {reason}`.
//! - EventBus integration: **deferred** to the MODULE-019 concrete-impl slice.
//!   Slice T's injector has no `event_bus` field and emits no events.
//! - WASI preview2: Slice V wires `wasmtime_wasi::p2::add_to_linker_async` via
//!   the module-level `add_wasi_to_linker` helper; `ComponentCtx` carries
//!   `WasiCtx` + `ResourceTable` and implements `WasiView`.
//!
//! Namespace grouping: Wasmtime 43's `Linker::instance(name)` errors if called
//! twice with the same name, so we group specs by `namespace` and call
//! `.instance()` exactly once per unique namespace.

use std::collections::HashMap;
use std::sync::Arc;

use advance_shared_types::capability::{CapParams, CapRequest, GrantDecision};
use advance_shared_types::traits::GrantCheck;
use wasmtime::component::{ResourceTable, Val};
use wasmtime::StoreLimits;
use wasmtime_wasi::{WasiCtx, WasiCtxBuilder, WasiCtxView, WasiView};

use crate::circuit_breaker::CircuitBreakerBus;
use crate::component_loader::EpochTickerHandle;
use crate::host_registry::{HostCallContext, HostRegistry};

/// Await-leg slice 1 (2026-06-21) — the bindgen-generated TYPED structs for the
/// imported `agent-messaging` interface (sibling of `…::types`). The dynamic
/// `func_new_async` `&[Val]` lift does NOT produce the `Val::Variant`-in-`list`
/// shape `decode_await_request` expects for `list<await-request>`; the typed
/// `func_wrap_async` path lifts straight into these structs (Wasmtime's own
/// canonical-ABI lift) and we host-build the canonical `Val` the existing
/// reply-tracker decoder consumes — see [`register_typed_await_replies`].
use crate::wit_bindings::with_caps::advance::runtime::agent_messaging as msg;
/// Wave-20 Lane `messagingabi`: the `notify` interface bindgen types (generated
/// from `import notify` on `advance-host-with-capabilities`). `notify` shares
/// `agent-messaging.{message-context}`, so the param lift reuses
/// `msg::MessageContext`; only the result `notify-error` is notify-specific.
use crate::wit_bindings::with_caps::advance::runtime::notify as notify_b;

/// Canonical component-model linker namespace for the `agent-messaging`
/// interface (matches `register_reply_tracker_host_fns`'s spec namespace). The
/// `await-replies` / `heartbeat` host fns under this namespace are registered
/// via the TYPED `func_wrap_async` path; every other namespace (and any other
/// name under this one) stays on the dynamic `func_new_async` path.
const AGENT_MESSAGING_NS: &str = "advance:runtime/agent-messaging@0.1.0";
/// Canonical linker namespace for the `notify` interface (matches
/// `register_notify_host_fns`/`register_notify_channel_host_fn` spec namespace).
/// Wave-20: notify-agent / notify-channel take the TYPED path (the dynamic
/// `option<message-context>` lift is unproven — see the inject() match).
const NOTIFY_NS: &str = "advance:runtime/notify@0.1.0";

/// Per-instance Store data. Slice V extends the Slice T plain struct with
/// `WasiCtx` + `ResourceTable` so the runtime implements `wasmtime_wasi::WasiView`.
/// `ComponentCtx::new` builds an empty default I/O sandbox (no preopens, no env,
/// no stdio, no network); the WASI 0.2 stable subset still installs an OS-CSPRNG
/// via `WasiRandomCtx::default()`, so `wasi:random/random` is reachable from any
/// guest after `add_wasi_to_linker` runs.
///
/// **Security architectural rule** (per §1.7): `wasi` and `table` are `pub(crate)`
/// to prevent external crates from replacing the empty default sandbox with a
/// configuration that grants raw filesystem / network / env access — that would
/// bypass MODULE-002's `VirtualPathResolver` and MODULE-012's SSRF / leak-detector
/// chain (ARCHITECTURE.md §11.2). Filesystem and HTTP egress are owned by
/// MODULE-002 / MODULE-012; this module's WASI surface is sandbox-scaffolding
/// only. In-crate mutation is permitted for the Slice V test surface and for
/// future runtime composition, but expanding the sandbox MUST be reviewed against
/// the §11 threat model.
pub struct ComponentCtx {
    pub agent_id: String,
    pub trace_id: String,
    /// CONTRACT-216 trusted current turn.  Only the host execution loop
    /// stamps/clears this field; WIT parameters have no path to it.
    pub turn_id: Option<String>,
    pub capabilities: Vec<String>,
    /// WASI 0.2 (preview2) host context. `pub(crate)` so external crates cannot
    /// replace the empty default sandbox — see struct rustdoc + §1.7.
    pub(crate) wasi: WasiCtx,
    /// Wasmtime resource table — required by WASI for file/socket/stream handles.
    /// `pub(crate)` for the same reason as `wasi`.
    pub(crate) table: ResourceTable,
    /// Slice AB (2026-04-17) — populated by
    /// `component_loader::apply_host_execution_budget` at instantiate time with a
    /// `StoreLimits` capping linear-memory pages at `WasmConfig.max_memory_pages`.
    /// Empty default (`StoreLimitsBuilder::new().build()`) applies no cap — it is a
    /// placeholder required because `Store::new` consumes `ComponentCtx` by value,
    /// so the real limiter is installed via `store.data_mut().store_limits = limits;`
    /// post-construction.
    pub(crate) store_limits: StoreLimits,
    /// Slice AB (2026-04-17) — Arc to the host-engine epoch ticker. `None` on
    /// default-constructed ctx; `instantiate_advance_host_async` populates with
    /// `Some(Arc::clone(&runtime.host_ticker))` before `Store::new`, ensuring the
    /// ticker outlives `drop(runtime)` as long as the Store survives.
    pub(crate) _ticker_keepalive: Option<Arc<EpochTickerHandle>>,
    /// Slice C (2026-05-09) — business-execution wave id propagated to
    /// `HostCallContext.run_id` on every host-fn invocation. Defaults to `None`
    /// from `ComponentCtx::new`; M008 RunManager populates via
    /// `store.data_mut().run_id = Some(rid)` post-construction (deferred wiring
    /// per MODULE-001 §3.6 "ComponentCtx producer-side wiring of run_id /
    /// iteration"). `pub` so M008 can mutate via `Store::data_mut()`.
    pub run_id: Option<String>,
    /// Slice C (2026-05-09) — per-iteration counter inside a run, propagated
    /// to `HostCallContext.iteration`. Defaults to `None`; M015 AutoMode
    /// populates per loop tick. `pub` for the same reason as `run_id`.
    pub iteration: Option<u32>,
    notify_sender_override: Option<String>,
}

impl ComponentCtx {
    /// Build a fresh per-instance context with an empty WASI sandbox.
    ///
    /// Slice AB (2026-04-17): the new `store_limits` and `_ticker_keepalive` fields
    /// default-initialize to empty / `None`. `instantiate_advance_host_async`
    /// overrides both before the guest runs. External callers that construct raw
    /// Stores via `host_engine_handle()` see the defaults and thereby opt out of
    /// the hardening — see MODULE-001 §3.6 for the future-dispatch-method
    /// discipline.
    pub fn new(agent_id: String, trace_id: String, capabilities: Vec<String>) -> Self {
        Self {
            agent_id,
            trace_id,
            turn_id: None,
            capabilities,
            wasi: WasiCtxBuilder::new().build(),
            table: ResourceTable::new(),
            store_limits: wasmtime::StoreLimitsBuilder::new().build(),
            _ticker_keepalive: None,
            run_id: None,
            iteration: None,
            notify_sender_override: None,
        }
    }

    pub fn with_notify_sender_override(mut self, sender: String) -> Self {
        self.notify_sender_override = Some(sender);
        self
    }

    /// Stamp the exact host-dequeued turn before Store/guest execution.
    pub fn stamp_trusted_turn(&mut self, turn_id: String) {
        self.turn_id = Some(turn_id);
    }

    /// Clear attribution before the Store is reused for a non-message path.
    pub fn clear_trusted_turn(&mut self) {
        self.turn_id = None;
    }

    /// Slice C (2026-05-09): build a `HostCallContext` from this `ComponentCtx`
    /// for the current host-fn invocation. Extracted from the `inject` closure
    /// (capability_injector.rs:221) into a `pub(crate)` helper to provide a
    /// unit-testable seam (T31 / T32 below) without a WAT fixture.
    ///
    /// Behavior is byte-identical to the prior inline 4-field literal except
    /// for the additive `run_id` / `iteration` propagation; existing handler
    /// reads of `ctx.agent_id` / `ctx.trace_id` / `ctx.capability` /
    /// `ctx.function` are unchanged.
    pub(crate) fn to_host_call_context(
        &self,
        capability: String,
        function: String,
    ) -> HostCallContext {
        HostCallContext {
            agent_id: self.agent_id.clone(),
            trace_id: self.trace_id.clone(),
            turn_id: self.turn_id.clone(),
            capability,
            function,
            run_id: self.run_id.clone(),
            iteration: self.iteration,
        }
    }

    pub(crate) fn to_notify_host_call_context(
        &self,
        capability: String,
        function: String,
    ) -> HostCallContext {
        let mut ctx = self.to_host_call_context(capability, function);
        if let Some(sender) = &self.notify_sender_override {
            ctx.agent_id = sender.clone();
        }
        ctx
    }
}

impl WasiView for ComponentCtx {
    fn ctx(&mut self) -> WasiCtxView<'_> {
        WasiCtxView {
            ctx: &mut self.wasi,
            table: &mut self.table,
        }
    }
}

/// Populate `linker` with the WASI 0.2 (preview2) imports surface.
///
/// **Composition rule**: call this BEFORE `CapabilityInjector::inject`. WASI
/// host functions register under the `wasi:*` namespace family
/// (`wasi:random/random`, `wasi:cli/exit`, `wasi:clocks/wall-clock`,
/// `wasi:filesystem/types`, `wasi:io/streams`, `wasi:sockets/...`,
/// `wasi:http/...`); MODULE-001 host functions register under disjoint
/// `ns-*` namespaces by convention. If a future `HostFunctionSpec` ever
/// declares a `namespace` colliding with `wasi:*` (e.g. `"wasi:random/random"`),
/// Wasmtime's `Linker::instance(name)` errors on the second call with the same
/// name — whichever of (this fn) or `inject` runs second will return
/// `Err(wasmtime::Error)`. Callers must propagate the error and not partial-
/// install: a half-wired WASI surface causes behavior divergence between dev
/// and prod. **Do not log-and-continue.**
///
/// WASI policy (preopens / env / stdio / network) defaults to empty per the
/// `ComponentCtx::new` sandbox; expanding it is in-crate only by design — see
/// the `ComponentCtx` rustdoc + §1.7.
pub fn add_wasi_to_linker(
    linker: &mut wasmtime::component::Linker<ComponentCtx>,
) -> wasmtime::Result<()> {
    wasmtime_wasi::p2::add_to_linker_async(linker)
}

/// Errors returned by `CapabilityInjector::inject`.
#[derive(Debug)]
pub enum HostError {
    /// Capability requested but no specs registered under it.
    UnknownCapability(String),
    /// Wasmtime linker rejected a namespace or function registration.
    LinkerError(wasmtime::Error),
}

impl std::fmt::Display for HostError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HostError::UnknownCapability(c) => write!(f, "unknown capability: {c}"),
            HostError::LinkerError(e) => write!(f, "linker error: {e}"),
        }
    }
}

impl std::error::Error for HostError {}

/// The injector. Three `Arc<dyn>` collaborators — no `event_bus` in Slice T.
pub struct CapabilityInjector {
    registry: Arc<dyn HostRegistry>,
    grant_check: Arc<dyn GrantCheck>,
    breaker: Arc<dyn CircuitBreakerBus>,
}

impl CapabilityInjector {
    pub fn new(
        registry: Arc<dyn HostRegistry>,
        grant_check: Arc<dyn GrantCheck>,
        breaker: Arc<dyn CircuitBreakerBus>,
    ) -> Self {
        Self {
            registry,
            grant_check,
            breaker,
        }
    }

    /// Populate `linker` with host functions for every requested capability.
    ///
    /// Each declared capability must resolve to at least one registered spec
    /// in the `HostRegistry`; otherwise `HostError::UnknownCapability` is
    /// returned. Wasmtime-linker errors (e.g. duplicate function name under a
    /// namespace) surface as `HostError::LinkerError`.
    pub fn inject(
        &self,
        linker: &mut wasmtime::component::Linker<ComponentCtx>,
        capabilities: &[CapRequest],
    ) -> Result<(), HostError> {
        // Phase 1: resolve specs + group by namespace. Wasmtime 43's
        // LinkerInstance::instance errors on repeat calls with the same name,
        // so we need one .instance(ns) per unique namespace.
        let mut by_ns: HashMap<String, Vec<crate::host_registry::HostFunctionSpec>> =
            HashMap::new();
        for cap in capabilities {
            let specs = self.registry.lookup(cap.capability.as_str());
            if specs.is_empty() {
                return Err(HostError::UnknownCapability(cap.capability.to_string()));
            }
            for spec in specs {
                by_ns.entry(spec.namespace.clone()).or_default().push(spec);
            }
        }

        // Phase 2: register each function under its namespace. The
        // `agent-messaging` namespace routes `await-replies` / `heartbeat`
        // through the TYPED `func_wrap_async` path (Wasmtime's typed lift
        // produces the correct `list<await-request>` variant shape — see the
        // module rustdoc + [`register_typed_await_replies`]); every other
        // namespace, and any other name under the messaging namespace, stays on
        // the dynamic `func_new_async` path. Both paths apply the SAME L1/CB
        // gates via [`run_capability_gates`] and delegate to the SAME registered
        // `HostFunctionHandler`.
        for (ns, specs) in by_ns {
            let mut instance = linker.instance(&ns).map_err(HostError::LinkerError)?;
            let is_messaging = ns == AGENT_MESSAGING_NS;
            let is_notify = ns == NOTIFY_NS;
            for spec in specs {
                match (is_messaging, is_notify, spec.name.as_str()) {
                    (true, _, "await-replies") => {
                        self.register_typed_await_replies(&mut instance, &spec)?;
                    }
                    (true, _, "heartbeat") => {
                        self.register_typed_heartbeat(&mut instance, &spec)?;
                    }
                    // Wave-20: notify-agent / notify-channel take the typed path
                    // (notify is a separate namespace; the dynamic
                    // `option<message-context>` lift is unproven — same rationale
                    // as `send`). The result lifts `result<_, notify-error>` (the
                    // 4-variant `NotifyError`, distinct from `MsgError`).
                    (_, true, "notify-agent") => {
                        self.register_typed_notify_agent(&mut instance, &spec)?;
                    }
                    (_, true, "notify-channel") => {
                        self.register_typed_notify_channel(&mut instance, &spec)?;
                    }
                    // await-leg B-3 (2026-06-22): `send` shares the agent-messaging
                    // namespace; it takes the typed path too (the dynamic
                    // `func_new_async` lift of an `option<message-context>` guest
                    // call is unproven — `notify-agent`, same shape, is now ALSO
                    // guest-WIT-imported + typed, Wave-20).
                    (true, _, "send") => {
                        self.register_typed_send(&mut instance, &spec)?;
                    }
                    _ => {
                        self.register_dynamic(&mut instance, &spec)?;
                    }
                }
            }
        }
        Ok(())
    }

    /// Dynamic (untyped) `func_new_async` registration — the original Slice T
    /// path used for every capability whose host fn takes simple-enough params
    /// for the raw `&[Val]` canonical-ABI lift. Gate logic factored into
    /// [`run_capability_gates`] so it is byte-identical to the typed path.
    fn register_dynamic(
        &self,
        instance: &mut wasmtime::component::LinkerInstance<'_, ComponentCtx>,
        spec: &crate::host_registry::HostFunctionSpec,
    ) -> Result<(), HostError> {
        let handler = spec.handler.clone();
        let gc = self.grant_check.clone();
        let br = self.breaker.clone();
        let capability = spec.capability.clone();
        let namespace = spec.namespace.clone();
        let name = spec.name.clone();
        instance
            .func_new_async(
                &spec.name,
                move |store_ctx, _component_func, params, results| {
                    let handler = handler.clone();
                    let gc = gc.clone();
                    let br = br.clone();
                    let capability = capability.clone();
                    let function = format!("{namespace}::{name}");
                    let params_owned: Vec<Val> = params.to_vec();
                    let results_len = results.len();
                    // Slice C (2026-05-09): `to_host_call_context` also propagates
                    // `run_id` + `iteration`. Behavior unchanged for the prior 4 fields.
                    let ctx_owned = store_ctx
                        .data()
                        .to_host_call_context(capability.clone(), function);
                    Box::new(async move {
                        run_capability_gates(&*gc, &*br, &ctx_owned, &capability)?;
                        let out = handler
                            .call(ctx_owned, params_owned, results_len)
                            .await
                            .map_err(wasmtime::Error::from)?;
                        if out.len() != results.len() {
                            return Err(wasmtime::Error::msg(format!(
                                "handler returned {} vals, expected {}",
                                out.len(),
                                results.len()
                            )));
                        }
                        for (i, v) in out.into_iter().enumerate() {
                            results[i] = v;
                        }
                        Ok(())
                    })
                },
            )
            .map_err(HostError::LinkerError)
    }

    /// Typed `func_wrap_async` registration for `await-replies`. Wasmtime lifts
    /// the guest's `(list<await-request>, await-options)` straight into the
    /// bindgen structs (the lift the dynamic `&[Val]` path gets wrong for the
    /// nested `list<variant>`), then we host-build the canonical `Val` the
    /// existing `decode_await_replies_params` consumes, run the SAME L1/CB
    /// gates, delegate to the SAME registered handler, and lift the result
    /// `Val` back to the typed `result<await-result, orchestration-error>`.
    /// Manager + decoder + shared-types stay untouched.
    fn register_typed_await_replies(
        &self,
        instance: &mut wasmtime::component::LinkerInstance<'_, ComponentCtx>,
        spec: &crate::host_registry::HostFunctionSpec,
    ) -> Result<(), HostError> {
        let handler = spec.handler.clone();
        let gc = self.grant_check.clone();
        let br = self.breaker.clone();
        let capability = spec.capability.clone();
        let function = format!("{}::{}", spec.namespace, spec.name);
        instance
            .func_wrap_async(
                &spec.name,
                move |store_ctx: wasmtime::StoreContextMut<'_, ComponentCtx>,
                      (requests, options): (Vec<msg::AwaitRequest>, msg::AwaitOptions)| {
                    let handler = handler.clone();
                    let gc = gc.clone();
                    let br = br.clone();
                    let capability = capability.clone();
                    let ctx_owned = store_ctx
                        .data()
                        .to_host_call_context(capability.clone(), function.clone());
                    // Host-build the canonical Val shape the existing decoder expects.
                    let params = vec![
                        lower_await_request_list(&requests),
                        lower_await_options(&options),
                    ];
                    Box::new(async move {
                        run_capability_gates(&*gc, &*br, &ctx_owned, &capability)?;
                        let out = handler
                            .call(ctx_owned, params, 1)
                            .await
                            .map_err(wasmtime::Error::from)?;
                        let v = out.first().ok_or_else(|| {
                            wasmtime::Error::msg("await-replies handler returned no result")
                        })?;
                        let lifted: Result<msg::AwaitResult, msg::OrchestrationError> =
                            lift_await_result_or_error(v).map_err(wasmtime::Error::msg)?;
                        Ok((lifted,))
                    })
                },
            )
            .map_err(HostError::LinkerError)
    }

    /// Typed `func_wrap_async` registration for `heartbeat` (`option<string>`
    /// param). Heartbeat already worked through the dynamic path, but it shares
    /// the `agent-messaging` namespace, so it moves to the typed path too (one
    /// `.instance(ns)` handles the namespace once — both names registered under
    /// it). Same gate + delegate + result-lift discipline as await-replies.
    fn register_typed_heartbeat(
        &self,
        instance: &mut wasmtime::component::LinkerInstance<'_, ComponentCtx>,
        spec: &crate::host_registry::HostFunctionSpec,
    ) -> Result<(), HostError> {
        let handler = spec.handler.clone();
        let gc = self.grant_check.clone();
        let br = self.breaker.clone();
        let capability = spec.capability.clone();
        let function = format!("{}::{}", spec.namespace, spec.name);
        instance
            .func_wrap_async(
                &spec.name,
                move |store_ctx: wasmtime::StoreContextMut<'_, ComponentCtx>,
                      (progress,): (Option<String>,)| {
                    let handler = handler.clone();
                    let gc = gc.clone();
                    let br = br.clone();
                    let capability = capability.clone();
                    let ctx_owned = store_ctx
                        .data()
                        .to_host_call_context(capability.clone(), function.clone());
                    let params = vec![lower_heartbeat_progress(&progress)];
                    Box::new(async move {
                        run_capability_gates(&*gc, &*br, &ctx_owned, &capability)?;
                        let out = handler
                            .call(ctx_owned, params, 1)
                            .await
                            .map_err(wasmtime::Error::from)?;
                        let v = out.first().ok_or_else(|| {
                            wasmtime::Error::msg("heartbeat handler returned no result")
                        })?;
                        let lifted: Result<(), msg::MsgError> =
                            lift_msg_result(v).map_err(wasmtime::Error::msg)?;
                        Ok((lifted,))
                    })
                },
            )
            .map_err(HostError::LinkerError)
    }

    /// Typed `func_wrap_async` registration for `send` (await-leg B-3, 2026-06-22).
    /// `send` shares the `agent-messaging` namespace, so it takes the typed path
    /// alongside `await-replies`/`heartbeat`: Wasmtime lifts `(target: string,
    /// payload: list<u8>, context: option<message-context>)` straight into the
    /// bindgen types, then we host-build the canonical `Val` shape the
    /// reply-tracker `decode_send_params` consumes, run the SAME L1/CB gates,
    /// delegate to the registered `SendHandler`, and lift the
    /// `result<_, msg-error>` back (reusing `lift_msg_result` — same return shape
    /// as `heartbeat`). The dynamic `func_new_async` path is NOT used: the only
    /// same-shape precedent (`notify-agent`) is not imported by any guest WIT
    /// world, so the typed path is the sole guest-call-proven lift for an
    /// agent-messaging `option<message-context>` param. Manager + decoder +
    /// shared-types stay untouched.
    fn register_typed_send(
        &self,
        instance: &mut wasmtime::component::LinkerInstance<'_, ComponentCtx>,
        spec: &crate::host_registry::HostFunctionSpec,
    ) -> Result<(), HostError> {
        let handler = spec.handler.clone();
        let gc = self.grant_check.clone();
        let br = self.breaker.clone();
        let capability = spec.capability.clone();
        let function = format!("{}::{}", spec.namespace, spec.name);
        instance
            .func_wrap_async(
                &spec.name,
                move |store_ctx: wasmtime::StoreContextMut<'_, ComponentCtx>,
                      (target, payload, context): (
                    String,
                    Vec<u8>,
                    Option<msg::MessageContext>,
                )| {
                    let handler = handler.clone();
                    let gc = gc.clone();
                    let br = br.clone();
                    let capability = capability.clone();
                    let ctx_owned = store_ctx
                        .data()
                        .to_host_call_context(capability.clone(), function.clone());
                    // Host-build the canonical Val shape `decode_send_params` expects.
                    let params = vec![
                        Val::String(target),
                        Val::List(payload.into_iter().map(Val::U8).collect()),
                        lower_option_message_context(&context),
                    ];
                    Box::new(async move {
                        run_capability_gates(&*gc, &*br, &ctx_owned, &capability)?;
                        let out = handler
                            .call(ctx_owned, params, 1)
                            .await
                            .map_err(wasmtime::Error::from)?;
                        let v = out.first().ok_or_else(|| {
                            wasmtime::Error::msg("send handler returned no result")
                        })?;
                        let lifted: Result<(), msg::MsgError> =
                            lift_msg_result(v).map_err(wasmtime::Error::msg)?;
                        Ok((lifted,))
                    })
                },
            )
            .map_err(HostError::LinkerError)
    }

    /// Wave-20 — typed registration for `notify-agent`
    /// `func(agent-id: string, payload: list<u8>, context: option<message-context>)
    /// -> result<_, notify-error>`. Mirrors [`register_typed_send`]'s params
    /// (Wasmtime lifts straight into bindgen types), host-builds the canonical
    /// `Val` the `NotifyAgentHandler` decoder consumes, runs the SAME L1/CB gates,
    /// and lifts the `result<_, notify-error>` the handler encodes back into the
    /// bindgen `notify_b::NotifyError` (the 4-variant lift, distinct from
    /// `MsgError`'s 5-variant `lift_msg_result`).
    fn register_typed_notify_agent(
        &self,
        instance: &mut wasmtime::component::LinkerInstance<'_, ComponentCtx>,
        spec: &crate::host_registry::HostFunctionSpec,
    ) -> Result<(), HostError> {
        let handler = spec.handler.clone();
        let gc = self.grant_check.clone();
        let br = self.breaker.clone();
        let capability = spec.capability.clone();
        let function = format!("{}::{}", spec.namespace, spec.name);
        instance
            .func_wrap_async(
                &spec.name,
                move |store_ctx: wasmtime::StoreContextMut<'_, ComponentCtx>,
                      (agent_id, payload, context): (
                    String,
                    Vec<u8>,
                    Option<msg::MessageContext>,
                )| {
                    let handler = handler.clone();
                    let gc = gc.clone();
                    let br = br.clone();
                    let capability = capability.clone();
                    let gate_ctx = store_ctx
                        .data()
                        .to_host_call_context(capability.clone(), function.clone());
                    let handler_ctx = store_ctx
                        .data()
                        .to_notify_host_call_context(capability.clone(), function.clone());
                    let params = vec![
                        Val::String(agent_id),
                        Val::List(payload.into_iter().map(Val::U8).collect()),
                        lower_option_message_context(&context),
                    ];
                    Box::new(async move {
                        run_capability_gates(&*gc, &*br, &gate_ctx, &capability)?;
                        let out = handler
                            .call(handler_ctx, params, 1)
                            .await
                            .map_err(wasmtime::Error::from)?;
                        let v = out.first().ok_or_else(|| {
                            wasmtime::Error::msg("notify-agent handler returned no result")
                        })?;
                        let lifted: Result<(), notify_b::NotifyError> =
                            lift_notify_result(v).map_err(wasmtime::Error::msg)?;
                        Ok((lifted,))
                    })
                },
            )
            .map_err(HostError::LinkerError)
    }

    /// Wave-20 — typed registration for `notify-channel`
    /// `func(channel-id: string, user-id: string, payload: list<u8>,
    /// context: option<message-context>) -> result<_, notify-error>`. Like
    /// [`Self::register_typed_notify_agent`] but with TWO leading string params.
    fn register_typed_notify_channel(
        &self,
        instance: &mut wasmtime::component::LinkerInstance<'_, ComponentCtx>,
        spec: &crate::host_registry::HostFunctionSpec,
    ) -> Result<(), HostError> {
        let handler = spec.handler.clone();
        let gc = self.grant_check.clone();
        let br = self.breaker.clone();
        let capability = spec.capability.clone();
        let function = format!("{}::{}", spec.namespace, spec.name);
        instance
            .func_wrap_async(
                &spec.name,
                move |store_ctx: wasmtime::StoreContextMut<'_, ComponentCtx>,
                      (channel_id, user_id, payload, context): (
                    String,
                    String,
                    Vec<u8>,
                    Option<msg::MessageContext>,
                )| {
                    let handler = handler.clone();
                    let gc = gc.clone();
                    let br = br.clone();
                    let capability = capability.clone();
                    let gate_ctx = store_ctx
                        .data()
                        .to_host_call_context(capability.clone(), function.clone());
                    let handler_ctx = store_ctx
                        .data()
                        .to_notify_host_call_context(capability.clone(), function.clone());
                    let params = vec![
                        Val::String(channel_id),
                        Val::String(user_id),
                        Val::List(payload.into_iter().map(Val::U8).collect()),
                        lower_option_message_context(&context),
                    ];
                    Box::new(async move {
                        run_capability_gates(&*gc, &*br, &gate_ctx, &capability)?;
                        let out = handler
                            .call(handler_ctx, params, 1)
                            .await
                            .map_err(wasmtime::Error::from)?;
                        let v = out.first().ok_or_else(|| {
                            wasmtime::Error::msg("notify-channel handler returned no result")
                        })?;
                        let lifted: Result<(), notify_b::NotifyError> =
                            lift_notify_result(v).map_err(wasmtime::Error::msg)?;
                        Ok((lifted,))
                    })
                },
            )
            .map_err(HostError::LinkerError)
    }
}

// ════════════════════════════════════════════════════════════════════════
// Shared gate helper + bindgen-typed ↔ canonical-Val conversions (await-leg
// slice 1). The `lower_*` builders emit exactly the `Val` shape the
// reply-tracker `decode_*` (host_fn.rs) consumes; the `lift_*` matchers parse
// exactly the `Val` shape the reply-tracker `encode_*` produces. They are a
// second copy of the WIT projection by necessity (Wasmtime exposes no
// Val↔typed bridge) — the unit tests below + the T57/T58 integration witnesses
// pin them against the real decoder/encoder.
// ════════════════════════════════════════════════════════════════════════

/// L1 GrantCheck + CircuitBreaker query, shared by the dynamic and typed
/// registration paths so the gate semantics never drift (the typed path
/// "re-hosts the gates" per the slice plan). A `Deny` or an open capability
/// breaker becomes a guest-visible host trap, matching the original behaviour.
fn run_capability_gates(
    grant_check: &dyn GrantCheck,
    breaker: &dyn CircuitBreakerBus,
    ctx: &HostCallContext,
    capability: &str,
) -> Result<(), wasmtime::Error> {
    let cap_params = CapParams::empty();
    match grant_check.check(&ctx.agent_id, capability, &ctx.function, &cap_params) {
        GrantDecision::Allow => {}
        GrantDecision::Deny(reason) => {
            return Err(wasmtime::Error::msg(format!("capability-denied: {reason}")));
        }
    }
    if let Some(reason) = breaker.is_open_capability(capability) {
        return Err(wasmtime::Error::msg(format!("circuit-breaker: {reason}")));
    }
    Ok(())
}

// ── lower: bindgen-typed → canonical Val (the shape `decode_*` expects) ──

fn lower_opt_string(s: &Option<String>) -> Val {
    match s {
        Some(v) => Val::Option(Some(Box::new(Val::String(v.clone())))),
        None => Val::Option(None),
    }
}

fn lower_message_context(ctx: &msg::MessageContext) -> Val {
    Val::Record(vec![
        ("task-id".into(), lower_opt_string(&ctx.task_id)),
        ("run-id".into(), lower_opt_string(&ctx.run_id)),
        ("execution-id".into(), lower_opt_string(&ctx.execution_id)),
    ])
}

fn lower_option_message_context(ctx: &Option<msg::MessageContext>) -> Val {
    match ctx {
        Some(m) => Val::Option(Some(Box::new(lower_message_context(m)))),
        None => Val::Option(None),
    }
}

fn lower_agent_await_request(req: &msg::AgentAwaitRequest) -> Val {
    Val::Record(vec![
        ("target".into(), Val::String(req.target.clone())),
        (
            "payload".into(),
            Val::List(req.payload.iter().map(|b| Val::U8(*b)).collect()),
        ),
        (
            "correlation-id".into(),
            Val::String(req.correlation_id.clone()),
        ),
        ("context".into(), lower_option_message_context(&req.context)),
    ])
}

fn lower_component_await_request(req: &msg::ComponentAwaitRequest) -> Val {
    Val::Record(vec![
        ("component-id".into(), Val::String(req.component_id.clone())),
        (
            "correlation-id".into(),
            Val::String(req.correlation_id.clone()),
        ),
    ])
}

fn lower_await_request(req: &msg::AwaitRequest) -> Val {
    match req {
        msg::AwaitRequest::AgentRequest(a) => Val::Variant(
            "agent-request".into(),
            Some(Box::new(lower_agent_await_request(a))),
        ),
        msg::AwaitRequest::ComponentFinished(c) => Val::Variant(
            "component-finished".into(),
            Some(Box::new(lower_component_await_request(c))),
        ),
    }
}

fn lower_await_request_list(requests: &[msg::AwaitRequest]) -> Val {
    Val::List(requests.iter().map(lower_await_request).collect())
}

fn lower_await_mode(mode: &msg::AwaitMode) -> Val {
    // Payloadless variant arms — the decoder matches `Val::Variant(case, _)`,
    // NOT `Val::Enum` (the WIT type is a `variant`, not an `enum`).
    let case = match mode {
        msg::AwaitMode::AllOf => "all-of",
        msg::AwaitMode::AnyOf => "any-of",
    };
    Val::Variant(case.into(), None)
}

fn lower_timeout_policy(policy: &msg::TimeoutPolicy) -> Val {
    let case = match policy {
        msg::TimeoutPolicy::ReturnPartial => "return-partial",
        msg::TimeoutPolicy::Fail => "fail",
    };
    Val::Variant(case.into(), None)
}

fn lower_await_options(options: &msg::AwaitOptions) -> Val {
    let idle = match options.idle_timeout_secs {
        Some(n) => Val::Option(Some(Box::new(Val::U32(n)))),
        None => Val::Option(None),
    };
    Val::Record(vec![
        ("mode".into(), lower_await_mode(&options.mode)),
        ("idle-timeout-secs".into(), idle),
        (
            "on-idle-timeout".into(),
            lower_timeout_policy(&options.on_idle_timeout),
        ),
        ("keep-losers".into(), Val::Bool(options.keep_losers)),
    ])
}

fn lower_heartbeat_progress(progress: &Option<String>) -> Val {
    match progress {
        Some(s) => Val::Option(Some(Box::new(Val::String(s.clone())))),
        None => Val::Option(None),
    }
}

// ── lift: canonical Val (the shape `encode_*` produces) → bindgen-typed ──

fn val_record<'a>(v: &'a Val, what: &str) -> Result<&'a [(String, Val)], String> {
    match v {
        Val::Record(f) => Ok(f),
        other => Err(format!("{what}: expected record, got {other:?}")),
    }
}

fn val_field<'a>(fields: &'a [(String, Val)], name: &str) -> Result<&'a Val, String> {
    fields
        .iter()
        .find(|(n, _)| n == name)
        .map(|(_, v)| v)
        .ok_or_else(|| format!("missing field {name:?}"))
}

fn val_string(v: &Val, what: &str) -> Result<String, String> {
    match v {
        Val::String(s) => Ok(s.clone()),
        other => Err(format!("{what}: expected string, got {other:?}")),
    }
}

/// Lift a WIT `option<string>` Val into `Option<String>` (Wave-23 wit-widening — the
/// reply-result `task-id` lift; the inverse of the `lower_opt_string` encoder used at
/// the message-context lowering site).
fn val_opt_string(v: &Val, what: &str) -> Result<Option<String>, String> {
    match v {
        Val::Option(None) => Ok(None),
        Val::Option(Some(inner)) => Ok(Some(val_string(inner, what)?)),
        other => Err(format!("{what}: expected option<string>, got {other:?}")),
    }
}

fn val_bool(v: &Val, what: &str) -> Result<bool, String> {
    match v {
        Val::Bool(b) => Ok(*b),
        other => Err(format!("{what}: expected bool, got {other:?}")),
    }
}

fn val_u8_list(v: &Val, what: &str) -> Result<Vec<u8>, String> {
    match v {
        Val::List(items) => items
            .iter()
            .map(|x| match x {
                Val::U8(b) => Ok(*b),
                o => Err(format!("{what}: expected list<u8>, got {o:?}")),
            })
            .collect(),
        other => Err(format!("{what}: expected list, got {other:?}")),
    }
}

fn lift_reply_status(v: &Val) -> Result<msg::ReplyStatus, String> {
    match v {
        Val::Variant(case, payload) => match case.as_str() {
            "success" => {
                let p = payload
                    .as_ref()
                    .ok_or("reply-status success: missing payload")?;
                Ok(msg::ReplyStatus::Success(val_u8_list(
                    p,
                    "reply-status success",
                )?))
            }
            "completed" => Ok(msg::ReplyStatus::Completed),
            "timed-out" => Ok(msg::ReplyStatus::TimedOut),
            "detached" => Ok(msg::ReplyStatus::Detached),
            "error" => {
                let p = payload
                    .as_ref()
                    .ok_or("reply-status error: missing payload")?;
                Ok(msg::ReplyStatus::Error(val_string(
                    p,
                    "reply-status error",
                )?))
            }
            other => Err(format!("reply-status: unknown case {other:?}")),
        },
        other => Err(format!("reply-status: expected variant, got {other:?}")),
    }
}

fn lift_reply_result(v: &Val) -> Result<msg::ReplyResult, String> {
    let f = val_record(v, "reply-result")?;
    Ok(msg::ReplyResult {
        correlation_id: val_string(val_field(f, "correlation-id")?, "correlation-id")?,
        target: val_string(val_field(f, "target")?, "target")?,
        // Wave-23 wit-widening: read the guest-visible `task-id: option<string>`.
        task_id: val_opt_string(val_field(f, "task-id")?, "task-id")?,
        status: lift_reply_status(val_field(f, "status")?)?,
    })
}

fn lift_await_result(v: &Val) -> Result<msg::AwaitResult, String> {
    let f = val_record(v, "await-result")?;
    let replies = match val_field(f, "replies")? {
        Val::List(items) => items
            .iter()
            .map(lift_reply_result)
            .collect::<Result<Vec<_>, _>>()?,
        other => return Err(format!("replies: expected list, got {other:?}")),
    };
    let completed_all = val_bool(val_field(f, "completed-all")?, "completed-all")?;
    Ok(msg::AwaitResult {
        replies,
        completed_all,
    })
}

fn lift_orchestration_error(v: &Val) -> Result<msg::OrchestrationError, String> {
    match v {
        Val::Variant(case, payload) => {
            let s = || -> Result<String, String> {
                let p = payload
                    .as_ref()
                    .ok_or_else(|| format!("orchestration-error {case}: missing payload"))?;
                val_string(p, "orchestration-error")
            };
            match case.as_str() {
                "capability-denied" => Ok(msg::OrchestrationError::CapabilityDenied(s()?)),
                "invalid-target" => Ok(msg::OrchestrationError::InvalidTarget(s()?)),
                "deadlock-detected" => Ok(msg::OrchestrationError::DeadlockDetected(s()?)),
                "session-limit-exceeded" => Ok(msg::OrchestrationError::SessionLimitExceeded(s()?)),
                "session-closed" => Ok(msg::OrchestrationError::SessionClosed(s()?)),
                "idle-timeout-exceeded" => Ok(msg::OrchestrationError::IdleTimeoutExceeded(s()?)),
                other => Err(format!("orchestration-error: unknown case {other:?}")),
            }
        }
        other => Err(format!(
            "orchestration-error: expected variant, got {other:?}"
        )),
    }
}

fn lift_await_result_or_error(
    v: &Val,
) -> Result<Result<msg::AwaitResult, msg::OrchestrationError>, String> {
    match v {
        Val::Result(Ok(inner)) => {
            let rec = inner
                .as_ref()
                .ok_or("await-replies result: missing Ok payload")?;
            Ok(Ok(lift_await_result(rec)?))
        }
        Val::Result(Err(inner)) => {
            let var = inner
                .as_ref()
                .ok_or("await-replies result: missing Err payload")?;
            Ok(Err(lift_orchestration_error(var)?))
        }
        other => Err(format!(
            "await-replies result: expected result, got {other:?}"
        )),
    }
}

fn lift_msg_error(v: &Val) -> Result<msg::MsgError, String> {
    match v {
        Val::Variant(case, payload) => {
            let s = || -> Result<String, String> {
                let p = payload
                    .as_ref()
                    .ok_or_else(|| format!("msg-error {case}: missing payload"))?;
                val_string(p, "msg-error")
            };
            match case.as_str() {
                "invalid-target" => Ok(msg::MsgError::InvalidTarget(s()?)),
                "mailbox-full" => Ok(msg::MsgError::MailboxFull),
                "circuit-breaker-open" => Ok(msg::MsgError::CircuitBreakerOpen(s()?)),
                "capability-denied" => Ok(msg::MsgError::CapabilityDenied(s()?)),
                "invalid-payload" => Ok(msg::MsgError::InvalidPayload(s()?)),
                other => Err(format!("msg-error: unknown case {other:?}")),
            }
        }
        other => Err(format!("msg-error: expected variant, got {other:?}")),
    }
}

fn lift_msg_result(v: &Val) -> Result<Result<(), msg::MsgError>, String> {
    match v {
        Val::Result(Ok(_)) => Ok(Ok(())),
        Val::Result(Err(inner)) => {
            let var = inner
                .as_ref()
                .ok_or("heartbeat result: missing Err payload")?;
            Ok(Err(lift_msg_error(var)?))
        }
        other => Err(format!("heartbeat result: expected result, got {other:?}")),
    }
}

/// Wave-20 — lift the `notify-error` 4-variant the `encode_notify_error`
/// (messaging/host_fn.rs) produces into the bindgen `notify_b::NotifyError`.
/// Distinct from `lift_msg_error` (5-variant `MsgError` with `circuit-breaker-open`
/// / `invalid-payload`; notify has `identity-unknown` instead).
fn lift_notify_error(v: &Val) -> Result<notify_b::NotifyError, String> {
    match v {
        Val::Variant(case, payload) => {
            let s = || -> Result<String, String> {
                let p = payload
                    .as_ref()
                    .ok_or_else(|| format!("notify-error {case}: missing payload"))?;
                val_string(p, "notify-error")
            };
            match case.as_str() {
                "invalid-target" => Ok(notify_b::NotifyError::InvalidTarget(s()?)),
                "mailbox-full" => Ok(notify_b::NotifyError::MailboxFull),
                "capability-denied" => Ok(notify_b::NotifyError::CapabilityDenied(s()?)),
                "identity-unknown" => Ok(notify_b::NotifyError::IdentityUnknown(s()?)),
                other => Err(format!("notify-error: unknown case {other:?}")),
            }
        }
        other => Err(format!("notify-error: expected variant, got {other:?}")),
    }
}

/// Wave-20 — lift the `result<_, notify-error>` Val the notify handlers encode
/// (`Val::Result(Ok(None))` on success / `encode_notify_error` on failure) into
/// `Result<(), notify_b::NotifyError>`.
fn lift_notify_result(v: &Val) -> Result<Result<(), notify_b::NotifyError>, String> {
    match v {
        Val::Result(Ok(_)) => Ok(Ok(())),
        Val::Result(Err(inner)) => {
            let var = inner.as_ref().ok_or("notify result: missing Err payload")?;
            Ok(Err(lift_notify_error(var)?))
        }
        other => Err(format!("notify result: expected result, got {other:?}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// MODULE-001 sentinel test (supports MODULE-009-AC-01) — Slice C.
    /// `ComponentCtx::to_host_call_context` propagates `run_id` + `iteration`
    /// from `ComponentCtx` into the constructed `HostCallContext`.
    #[test]
    fn t_to_host_call_context_propagates_run_id_iteration() {
        let mut ctx = ComponentCtx::new("agent-1".into(), "trace-1".into(), vec!["llm".into()]);
        ctx.run_id = Some("rid-x".into());
        ctx.iteration = Some(3);

        let hcc =
            ctx.to_host_call_context("llm".into(), "advance:runtime/agent-llm::generate".into());

        assert_eq!(hcc.agent_id, "agent-1");
        assert_eq!(hcc.trace_id, "trace-1");
        assert_eq!(hcc.capability, "llm");
        assert_eq!(hcc.function, "advance:runtime/agent-llm::generate");
        assert_eq!(hcc.run_id, Some("rid-x".to_string()));
        assert_eq!(hcc.iteration, Some(3));
    }

    /// MODULE-001 sentinel test (supports MODULE-009-AC-01) — Slice C.
    /// `ComponentCtx::new(...)` defaults `run_id` and `iteration` to `None`;
    /// `to_host_call_context` preserves the defaults verbatim.
    #[test]
    fn t_to_host_call_context_default_run_id_iteration_none() {
        let ctx = ComponentCtx::new("agent-1".into(), "trace-1".into(), vec!["llm".into()]);

        let hcc =
            ctx.to_host_call_context("llm".into(), "advance:runtime/agent-llm::generate".into());

        assert_eq!(hcc.run_id, None);
        assert_eq!(hcc.iteration, None);
        assert_eq!(hcc.turn_id, None);
    }

    /// MODULE-001-T91 / CONTRACT-216: each host-call context freezes the
    /// current host-owned turn; later Store reuse cannot rewrite an in-flight
    /// handler's already-owned context.
    #[test]
    fn t_trusted_turn_stamp_freezes_per_host_call() {
        let mut ctx = ComponentCtx::new("agent-1".into(), "trace-1".into(), vec!["llm".into()]);
        ctx.stamp_trusted_turn("message-1".into());
        let frozen = ctx.to_host_call_context("llm".into(), "agent-llm::generate".into());

        ctx.stamp_trusted_turn("message-2".into());
        let next = ctx.to_host_call_context("llm".into(), "agent-llm::generate".into());

        assert_eq!(frozen.turn_id.as_deref(), Some("message-1"));
        assert_eq!(next.turn_id.as_deref(), Some("message-2"));
    }

    /// MODULE-001-T94: non-message paths explicitly clear the trusted carrier.
    #[test]
    fn t_trusted_turn_clear_prevents_store_reuse_leakage() {
        let mut ctx = ComponentCtx::new("agent-1".into(), "trace-1".into(), vec!["fs".into()]);
        ctx.stamp_trusted_turn("message-1".into());
        ctx.clear_trusted_turn();

        let call = ctx.to_host_call_context("fs".into(), "fs::read".into());
        assert_eq!(call.turn_id, None);
    }

    /// T5 (Stage-F obs SLICE 1) — the per-turn re-stamp seam: after the cli
    /// `handle_message` overwrites the reused Store's `ComponentCtx.trace_id` (via
    /// `store.data_mut().trace_id = ...`), `to_host_call_context` reflects the NEW
    /// chain trace — overriding the boot constant. This is the propagation seam
    /// that puts cap-llm/tools/fs/memory host-fn events into the chain (137).
    #[test]
    fn t_to_host_call_context_reflects_restamped_trace_id() {
        // Built with the boot constant (as init() does).
        let mut ctx = ComponentCtx::new("agent-1".into(), "trace-boot".into(), vec!["fs".into()]);
        assert_eq!(
            ctx.to_host_call_context("fs".into(), "fs::write".into())
                .trace_id,
            "trace-boot",
            "pre-restamp uses the boot constant"
        );

        // Per-turn re-stamp (what handle_message does on the live Store's ctx).
        ctx.trace_id = "chain-trace-PERTURN".into();

        let hcc = ctx.to_host_call_context("fs".into(), "fs::write".into());
        assert_eq!(
            hcc.trace_id, "chain-trace-PERTURN",
            "re-stamped trace_id must propagate into HostCallContext (cap-event inheritance)"
        );
    }

    #[test]
    fn t_notify_host_call_context_overrides_sender_only_for_notify() {
        let ctx = ComponentCtx::new(
            "component:cron".into(),
            "trace-1".into(),
            vec!["messaging".into()],
        )
        .with_notify_sender_override("system".into());

        let gate_ctx = ctx.to_host_call_context(
            "messaging".into(),
            "advance:runtime/notify@0.1.0::notify-agent".into(),
        );
        let notify_ctx = ctx.to_notify_host_call_context(
            "messaging".into(),
            "advance:runtime/notify@0.1.0::notify-agent".into(),
        );

        assert_eq!(gate_ctx.agent_id, "component:cron");
        assert_eq!(notify_ctx.agent_id, "system");
        assert_eq!(notify_ctx.trace_id, "trace-1");
        assert_eq!(notify_ctx.capability, "messaging");
    }

    // ════════════════════════════════════════════════════════════════════
    // await-leg slice 1 — typed-bindgen ↔ canonical-Val conversion tests.
    // These pin the hand-built Val shapes against the shapes the reply-tracker
    // `decode_*`/`encode_*` (host_fn.rs) consume/produce, for ALL variants/arms
    // (not just the AgentRequest/AllOf/Fail path the guest fixture drives — the
    // typed wasmtime boundary for the rest lands with slice-2 production wiring).
    // ════════════════════════════════════════════════════════════════════

    /// Build-probe (R1): the typed bindgen param/result types carry the
    /// `Lift`/`Lower` derives `func_wrap_async` requires. Compiles iff true.
    #[test]
    fn typed_messaging_types_have_lift_lower() {
        fn _assert_lift<T: wasmtime::component::Lift>() {}
        fn _assert_lower<T: wasmtime::component::Lower>() {}
        _assert_lift::<Vec<msg::AwaitRequest>>();
        _assert_lift::<msg::AwaitOptions>();
        _assert_lift::<Option<String>>();
        _assert_lower::<Result<msg::AwaitResult, msg::OrchestrationError>>();
        _assert_lower::<Result<(), msg::MsgError>>();
    }

    fn sample_agent_request() -> msg::AwaitRequest {
        msg::AwaitRequest::AgentRequest(msg::AgentAwaitRequest {
            target: "agent:t".into(),
            payload: vec![1, 2, 3],
            correlation_id: "corr-1".into(),
            context: None,
        })
    }

    #[test]
    fn lower_agent_request_matches_decoder_shape() {
        assert_eq!(
            lower_await_request(&sample_agent_request()),
            Val::Variant(
                "agent-request".into(),
                Some(Box::new(Val::Record(vec![
                    ("target".into(), Val::String("agent:t".into())),
                    (
                        "payload".into(),
                        Val::List(vec![Val::U8(1), Val::U8(2), Val::U8(3)])
                    ),
                    ("correlation-id".into(), Val::String("corr-1".into())),
                    ("context".into(), Val::Option(None)),
                ]))),
            )
        );
    }

    #[test]
    fn lower_component_finished_matches_decoder_shape() {
        let req = msg::AwaitRequest::ComponentFinished(msg::ComponentAwaitRequest {
            component_id: "comp-9".into(),
            correlation_id: "corr-2".into(),
        });
        assert_eq!(
            lower_await_request(&req),
            Val::Variant(
                "component-finished".into(),
                Some(Box::new(Val::Record(vec![
                    ("component-id".into(), Val::String("comp-9".into())),
                    ("correlation-id".into(), Val::String("corr-2".into())),
                ]))),
            )
        );
    }

    #[test]
    fn lower_message_context_some_matches_decoder_shape() {
        let mc = Some(msg::MessageContext {
            task_id: Some("task-1".into()),
            run_id: None,
            execution_id: Some("exec-1".into()),
        });
        assert_eq!(
            lower_option_message_context(&mc),
            Val::Option(Some(Box::new(Val::Record(vec![
                (
                    "task-id".into(),
                    Val::Option(Some(Box::new(Val::String("task-1".into()))))
                ),
                ("run-id".into(), Val::Option(None)),
                (
                    "execution-id".into(),
                    Val::Option(Some(Box::new(Val::String("exec-1".into()))))
                ),
            ]))))
        );
        assert_eq!(lower_option_message_context(&None), Val::Option(None));
    }

    #[test]
    fn lower_await_options_covers_all_variant_arms() {
        let any_partial = msg::AwaitOptions {
            mode: msg::AwaitMode::AnyOf,
            idle_timeout_secs: Some(42),
            on_idle_timeout: msg::TimeoutPolicy::ReturnPartial,
            keep_losers: true,
        };
        assert_eq!(
            lower_await_options(&any_partial),
            Val::Record(vec![
                ("mode".into(), Val::Variant("any-of".into(), None)),
                (
                    "idle-timeout-secs".into(),
                    Val::Option(Some(Box::new(Val::U32(42))))
                ),
                (
                    "on-idle-timeout".into(),
                    Val::Variant("return-partial".into(), None)
                ),
                ("keep-losers".into(), Val::Bool(true)),
            ])
        );
        let all_fail = msg::AwaitOptions {
            mode: msg::AwaitMode::AllOf,
            idle_timeout_secs: None,
            on_idle_timeout: msg::TimeoutPolicy::Fail,
            keep_losers: false,
        };
        assert_eq!(
            lower_await_options(&all_fail),
            Val::Record(vec![
                ("mode".into(), Val::Variant("all-of".into(), None)),
                ("idle-timeout-secs".into(), Val::Option(None)),
                ("on-idle-timeout".into(), Val::Variant("fail".into(), None)),
                ("keep-losers".into(), Val::Bool(false)),
            ])
        );
    }

    #[test]
    fn lower_heartbeat_and_list_shapes() {
        assert_eq!(lower_heartbeat_progress(&None), Val::Option(None));
        assert_eq!(
            lower_heartbeat_progress(&Some("p".into())),
            Val::Option(Some(Box::new(Val::String("p".into()))))
        );
        match lower_await_request_list(&[sample_agent_request()]) {
            Val::List(items) => assert_eq!(items.len(), 1),
            other => panic!("expected list, got {other:?}"),
        }
    }

    fn reply_record(corr: &str, target: &str, task: Option<&str>, status: Val) -> Val {
        // Wave-23 wit-widening: reply-result now carries `task-id: option<string>`.
        let task_id = match task {
            Some(t) => Val::Option(Some(Box::new(Val::String(t.into())))),
            None => Val::Option(None),
        };
        Val::Record(vec![
            ("correlation-id".into(), Val::String(corr.into())),
            ("target".into(), Val::String(target.into())),
            ("task-id".into(), task_id),
            ("status".into(), status),
        ])
    }

    #[test]
    fn lift_await_result_ok_all_reply_status_arms() {
        let replies = vec![
            reply_record(
                "c1",
                "t1",
                Some("task-1"),
                Val::Variant(
                    "success".into(),
                    Some(Box::new(Val::List(vec![Val::U8(7)]))),
                ),
            ),
            reply_record("c2", "t2", None, Val::Variant("completed".into(), None)),
            reply_record("c3", "t3", None, Val::Variant("timed-out".into(), None)),
            reply_record("c4", "t4", None, Val::Variant("detached".into(), None)),
            reply_record(
                "c5",
                "t5",
                Some("task-5"),
                Val::Variant("error".into(), Some(Box::new(Val::String("boom".into())))),
            ),
        ];
        let ok_val = Val::Result(Ok(Some(Box::new(Val::Record(vec![
            ("replies".into(), Val::List(replies)),
            ("completed-all".into(), Val::Bool(true)),
        ])))));
        let res = lift_await_result_or_error(&ok_val).unwrap().unwrap();
        assert!(res.completed_all);
        assert_eq!(res.replies.len(), 5);
        assert_eq!(res.replies[0].correlation_id, "c1");
        assert_eq!(res.replies[0].target, "t1");
        assert!(matches!(res.replies[0].status, msg::ReplyStatus::Success(ref b) if b == &vec![7]));
        assert!(matches!(res.replies[1].status, msg::ReplyStatus::Completed));
        assert!(matches!(res.replies[2].status, msg::ReplyStatus::TimedOut));
        assert!(matches!(res.replies[3].status, msg::ReplyStatus::Detached));
        assert!(matches!(res.replies[4].status, msg::ReplyStatus::Error(ref s) if s == "boom"));
        // Wave-23 wit-widening (T-N2): the guest-visible `task-id` round-trips (Some + None)
        // through lift_reply_result.
        assert_eq!(res.replies[0].task_id.as_deref(), Some("task-1"));
        assert_eq!(res.replies[1].task_id, None);
        assert_eq!(res.replies[4].task_id.as_deref(), Some("task-5"));
    }

    #[test]
    fn lift_orchestration_error_all_six_arms() {
        use msg::OrchestrationError as Oe;
        let mk = |case: &str| {
            let v = Val::Result(Err(Some(Box::new(Val::Variant(
                case.into(),
                Some(Box::new(Val::String("m".into()))),
            )))));
            lift_await_result_or_error(&v).unwrap().unwrap_err()
        };
        assert!(matches!(mk("capability-denied"), Oe::CapabilityDenied(_)));
        assert!(matches!(mk("invalid-target"), Oe::InvalidTarget(_)));
        assert!(matches!(mk("deadlock-detected"), Oe::DeadlockDetected(_)));
        assert!(matches!(
            mk("session-limit-exceeded"),
            Oe::SessionLimitExceeded(_)
        ));
        assert!(matches!(mk("session-closed"), Oe::SessionClosed(_)));
        assert!(matches!(
            mk("idle-timeout-exceeded"),
            Oe::IdleTimeoutExceeded(_)
        ));
    }

    #[test]
    fn lift_msg_result_ok_and_all_error_arms() {
        use msg::MsgError as Me;
        assert!(matches!(
            lift_msg_result(&Val::Result(Ok(None))).unwrap(),
            Ok(())
        ));
        let mk = |case: &str, payload: Option<Box<Val>>| {
            let v = Val::Result(Err(Some(Box::new(Val::Variant(case.into(), payload)))));
            lift_msg_result(&v).unwrap().unwrap_err()
        };
        let s = || Some(Box::new(Val::String("x".into())));
        assert!(matches!(mk("invalid-target", s()), Me::InvalidTarget(_)));
        assert!(matches!(mk("mailbox-full", None), Me::MailboxFull));
        assert!(matches!(
            mk("circuit-breaker-open", s()),
            Me::CircuitBreakerOpen(_)
        ));
        assert!(matches!(
            mk("capability-denied", s()),
            Me::CapabilityDenied(_)
        ));
        assert!(matches!(mk("invalid-payload", s()), Me::InvalidPayload(_)));
    }

    #[test]
    fn run_capability_gates_denies_and_breaks() {
        use crate::circuit_breaker::DefaultCircuitBreakerBus;
        struct DenyAll;
        impl GrantCheck for DenyAll {
            fn check(&self, _: &str, _: &str, _: &str, _: &CapParams) -> GrantDecision {
                GrantDecision::Deny("nope".into())
            }
        }
        let ctx = ComponentCtx::new("a".into(), "tr".into(), vec!["messaging".into()])
            .to_host_call_context("messaging".into(), "ns::await-replies".into());
        let allow_breaker = DefaultCircuitBreakerBus::new();
        let err = run_capability_gates(&DenyAll, &allow_breaker, &ctx, "messaging")
            .expect_err("deny must trap");
        assert!(err.to_string().contains("capability-denied: nope"));
    }
}
