//! Public component loader for MODULE-001 — Slice T.
//!
//! Resolves the Slice L §2.1:13 boundary deferred_finding via opaque handle
//! newtypes (`HostEngineHandle`, `ToolEngineHandle`) that expose `&wasmtime::Engine`
//! only through a single documented `.engine()` accessor. MODULE-017's future
//! `ToolRegistry` consumes `ToolEngineHandle` for tool-WASM Store creation
//! (Decision 16 Implication (iii)); MODULE-001 remains the sole constructor of
//! `wasmtime::Engine`.
//!
//! Engine construction follows Decision 16's two-Engine architecture verbatim
//! (`host_engine` no-fuel, `tool_engine` fuel-gated on `WasmConfig.fuel_enabled`).
//! Component Model async-proposal prohibition (AC-02 / MODULE-001:529) is
//! enforced by OMITTING the `component-model-async` Cargo feature at the
//! workspace level.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use crate::component_spec::ComponentSpec;
use crate::config::WasmConfig;

/// Slice AB — cooperative-yield cadence expressed in epoch ticks.
///
/// `Store::epoch_deadline_async_yield_and_update(HOST_YIELD_EPOCHS_PER_DEADLINE)` yields
/// to the Tokio executor when the guest's epoch reaches the stored deadline and then
/// resets the deadline to `current_epoch + HOST_YIELD_EPOCHS_PER_DEADLINE`. Paired with
/// the epoch ticker (which calls `Engine::increment_epoch()` every
/// `WasmConfig.epoch_interruption_ms`), this gives a worst-case tokio-starvation bound
/// of `HOST_YIELD_EPOCHS_PER_DEADLINE × epoch_interruption_ms`.
///
/// The value 1 paired with the default 100ms ticker cadence gives ~100ms worst-case
/// yield bound — well below typical request/response timeouts.
pub(crate) const HOST_YIELD_EPOCHS_PER_DEADLINE: u64 = 1;

/// Slice AB — handle to an OS-thread epoch ticker.
///
/// The ticker is an OS thread (via `std::thread::spawn`, NOT `tokio::spawn`) that calls
/// `Engine::increment_epoch()` on a fixed cadence. An OS thread is kernel-scheduled, so
/// a wedged tokio executor (e.g., a tight-loop guest on a `current_thread` runtime)
/// cannot block ticker progress — the ticker always runs, guest yield points always fire.
///
/// The handle is Arc-shared between `ComponentRuntime` (which lazily spawns the ticker
/// on the first `instantiate_advance_host_async`) and every returned `Store`'s
/// `ComponentCtx._ticker_keepalive` — ensuring the ticker outlives `drop(runtime)` as
/// long as any Store survives. When the LAST `Arc<EpochTickerHandle>` drops, `Drop`
/// signals stop via the `AtomicBool` flag and joins the OS thread (bounded by the
/// `interval`, default 100ms).
pub(crate) struct EpochTickerHandle {
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl std::fmt::Debug for EpochTickerHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EpochTickerHandle").finish_non_exhaustive()
    }
}

impl Drop for EpochTickerHandle {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(handle) = self.thread.take() {
            let _ = handle.join();
        }
    }
}

/// Spawn an OS-thread epoch ticker driving `Engine::increment_epoch()` at the given
/// cadence. The ticker runs until the returned `EpochTickerHandle` is dropped.
///
/// # Why `std::thread` not `tokio::spawn`
/// A tokio task sharing the executor with a tight-loop guest would never get scheduled
/// — the guest monopolizes the worker thread. Kernel-scheduled OS threads are immune.
///
/// # Panics
/// `std::thread::Builder::spawn` returns `Err` only under extreme resource pressure
/// (OS thread quota exhausted) — a rare and typically fatal system condition. This
/// function `.expect()`s the result, propagating the failure as a panic to the caller
/// of `instantiate_advance_host_async` (via `OnceLock::get_or_init`). Acceptance
/// rationale: OS thread quota exhaustion at host runtime startup is not actionable via
/// a soft `InstantiateError` variant — the runtime cannot usefully continue without
/// the epoch ticker (guests would run unbounded). A future slice could switch to a
/// `Mutex<Option<Result<Arc<EpochTickerHandle>, io::Error>>>` retry-on-next-call
/// pattern if the panic surface becomes operationally problematic; see MODULE-001
/// §3.6 "Ticker spawn failure on production dispatch path" entry.
pub(crate) fn spawn_epoch_ticker(
    engine: wasmtime::Engine,
    interval: Duration,
) -> EpochTickerHandle {
    // Adversarial R2 fix (symmetric with apply_host_execution_budget W1):
    // WasmConfig.epoch_interruption_ms is validated `> 0` on the file-loaded
    // path in config.rs, but WasmConfig fields are `pub` and
    // `ComponentRuntime::new` does not re-validate. A direct-constructed
    // `WasmConfig { epoch_interruption_ms: 0, .. }` would produce
    // `Duration::ZERO` here, causing `std::thread::sleep(Duration::ZERO)`
    // to be a no-op and the ticker to CPU-burn in a tight loop. Floor the
    // effective interval at 1ms to prevent this degenerate case.
    const MIN_TICKER_INTERVAL: Duration = Duration::from_millis(1);
    let interval = interval.max(MIN_TICKER_INTERVAL);
    let stop = Arc::new(AtomicBool::new(false));
    let stop_clone = Arc::clone(&stop);
    let thread = std::thread::Builder::new()
        .name("advance-host-epoch-ticker".into())
        .spawn(move || {
            // Responsive-shutdown loop: sleep in small chunks so `Drop::drop`'s
            // `join()` returns within ~TICKER_POLL_MAX regardless of the
            // configured interval. Cadence tracking uses `Instant` wall time
            // (R8) — re-anchoring `next_tick_at = now + interval` on each
            // fired tick prevents cumulative drift (a single late wakeup does
            // not push future ticks off-schedule).
            //
            // Cadence precision: ticks fire at the first poll-wakeup past
            // `next_tick_at`, so the effective tick time is quantized to
            // `poll_chunk` granularity. For `interval <= TICKER_POLL_MAX
            // (100ms)`, `poll_chunk == interval`, so cadence matches the
            // configured interval (plus OS sleep jitter, typically sub-ms).
            // For `interval > TICKER_POLL_MAX`, `poll_chunk == 100ms`, so
            // cadence rounds up to the next 100ms boundary past
            // `next_tick_at` (e.g., `interval = 250ms` fires at ~300ms
            // post-last-tick). The default `epoch_interruption_ms = 100`
            // config hits the exact case. Operators tuning large intervals
            // should expect up to TICKER_POLL_MAX-granularity quantization.
            const TICKER_POLL_MAX: Duration = Duration::from_millis(100);
            let poll_chunk = interval.min(TICKER_POLL_MAX);
            let mut next_tick_at = std::time::Instant::now() + interval;
            while !stop_clone.load(Ordering::Acquire) {
                std::thread::sleep(poll_chunk);
                if stop_clone.load(Ordering::Acquire) {
                    break;
                }
                let now = std::time::Instant::now();
                if now >= next_tick_at {
                    engine.increment_epoch();
                    // Anchor the next deadline on `now` (not on the prior
                    // `next_tick_at`) so a single late wakeup doesn't compound
                    // into perpetual lag. Cadence targets interval-from-last-
                    // actual-tick rather than cumulative scheduled anchors.
                    next_tick_at = now + interval;
                }
            }
        })
        .expect("OS thread spawn for epoch ticker");
    EpochTickerHandle {
        stop,
        thread: Some(thread),
    }
}

/// Apply the host-side execution budget (memory cap + cooperative yield) to a freshly
/// constructed Store.
///
/// # Contract
/// - MUST be called immediately after `wasmtime::Store::new(...)`.
/// - MUST be called before any `Linker::instantiate_*` or guest invocation on the store.
/// - Calling it on a store that has already invoked WASM is unsupported (wasmtime does
///   not support re-configuring limiter / yield deadline mid-execution).
/// - The `max_memory_pages` parameter is applied per linear memory
///   (`StoreLimitsBuilder::memory_size`). Equals per-component when the Component uses
///   a single memory — the framework default via `wasm_multi_memory(false)` on both
///   Engines.
/// - **Type coupling**: this helper is specific to `Store<ComponentCtx>`. The limiter
///   closure reads `ctx.store_limits` directly, so other Store data types (e.g., a
///   future tool-WASM ctx with per-call fuel) require their own helper or a generic
///   factoring. Documented here to make the coupling explicit; a future MODULE-017
///   slice will decide whether to reuse, duplicate, or refactor.
pub(crate) fn apply_host_execution_budget(
    store: &mut wasmtime::Store<crate::capability_injector::ComponentCtx>,
    max_memory_pages: u32,
) {
    // Saturating multiplication (R13 adversarial-fix). `WasmConfig` validation
    // caps max_memory_pages at 1_048_576 pages (64 GiB), which fits in `usize`
    // on 64-bit targets; but `WasmConfig` fields are `pub` and
    // `ComponentRuntime::new` does NOT re-validate, so a direct-constructed
    // `WasmConfig { max_memory_pages: u32::MAX, .. }` would overflow
    // `usize * 65536` on 32-bit and wrap on 64-bit overflow-checks=off builds.
    // `saturating_mul` pins the limiter at `usize::MAX` in that degenerate
    // case, which is still a finite cap preventing unbounded growth.
    let memory_size_bytes = (max_memory_pages as usize).saturating_mul(65536);
    let limits = wasmtime::StoreLimitsBuilder::new()
        .memory_size(memory_size_bytes)
        .build();
    store.data_mut().store_limits = limits;
    store.limiter(|ctx: &mut crate::capability_injector::ComponentCtx| &mut ctx.store_limits);
    // Install the yield behavior: when current_epoch reaches the stored
    // epoch_deadline, wasmtime yields to the tokio executor and then updates
    // the deadline to `current_epoch + HOST_YIELD_EPOCHS_PER_DEADLINE`.
    store.epoch_deadline_async_yield_and_update(HOST_YIELD_EPOCHS_PER_DEADLINE);
    // Arm the initial epoch_deadline — default is 0 (already-elapsed), which
    // would force an immediate yield on the guest's first epoch check. Setting
    // it to HOST_YIELD_EPOCHS_PER_DEADLINE means the first yield happens after
    // the ticker has advanced the engine's epoch that many times (~interval_ms
    // real-time at the default cadence). Audit fix R7: removes the "initial
    // yield on guest entry" quirk flagged by R7 Codex Diff finding.
    store.set_epoch_deadline(HOST_YIELD_EPOCHS_PER_DEADLINE);
}

/// Public runtime that owns both Wasmtime Engines.
///
/// Constructs two `wasmtime::Engine` instances per Decision 16 Implication (i)
/// so the "tool-WASM only" fuel-scope lock is structurally enforced.
///
/// Slice AB (2026-04-17): extended with a lazily-spawned OS-thread epoch ticker
/// (`host_ticker`), cached `WasmConfig` values for `instantiate_advance_host_async`
/// wiring (`max_memory_pages`, `epoch_interruption_ms`), and an Arc-shared ticker
/// lifetime that ensures the ticker outlives `drop(runtime)` while any Store it
/// produced is still alive.
///
/// `ComponentRuntime::new` is synchronous and does NOT require a tokio runtime context.
/// The lazy epoch ticker is spawned on the first `instantiate_advance_host_async` call
/// (on an OS thread via `std::thread::spawn`, NOT a tokio task), not at construction.
///
/// Drop releases the local Arc to the ticker. The `EpochTickerHandle::drop` only fires
/// when the LAST Arc drops — which may be held by an outstanding Store. If never
/// instantiated, Drop is a no-op (OnceLock is empty, no `EpochTickerHandle` was
/// created).
pub struct ComponentRuntime {
    host_engine: wasmtime::Engine,
    tool_engine: wasmtime::Engine,
    host_ticker: OnceLock<Arc<EpochTickerHandle>>,
    max_memory_pages: u32,
    epoch_interruption_ms: u64,
}

/// Opaque handle to the `host_engine`. Cheap `Clone` (Engine is Arc-backed).
/// MODULE-001 is the sole constructor; tests that need `&wasmtime::Engine`
/// to build a `Linker<ComponentCtx>` receive one via `.engine()`.
///
/// # Execution-budget hardening boundary (Slice AB)
/// `HostEngineHandle` is the escape hatch for custom Linker / WASI / Store
/// composition. Callers who build a `wasmtime::Store<ComponentCtx>` via
/// `host_engine_handle().engine()` + `Store::new` do NOT automatically get the
/// Slice AB execution budget (memory cap + cooperative yield + epoch ticker):
/// the `apply_host_execution_budget` helper is `pub(crate)` and only runs
/// inside `ComponentRuntime::instantiate_advance_host_async`. This is deliberate
/// — tool-WASM / test-only composition paths may have different budget needs,
/// so the hardening is opt-in via the supported dispatch method, not blanket
/// on every Store constructed on the host engine. If a future in-tree dispatch
/// method needs the hardening, it MUST call `apply_host_execution_budget`
/// directly (see MODULE-001 §3.6 for the discipline). External crates building
/// custom compositions take on the responsibility of applying their own
/// execution budget, consistent with wasmtime's unopinionated `Store::new`
/// posture.
///
/// # Mixed-use warning (R10 + R12 accuracy fix)
/// `Engine::epoch_interruption(true)` is enabled per Decision 16. **Per
/// wasmtime 43.0.1 semantics, the default `Store::epoch_deadline = 0` is
/// already-elapsed on any store built with epoch_interruption enabled — the
/// store traps immediately on its first epoch check regardless of whether
/// the Slice AB ticker has fired.** Raw stores built via
/// `host_engine_handle().engine() + Store::new` therefore MUST arm their
/// epoch deadline to avoid a trap. **Remediation options**: call
/// `store.set_epoch_deadline(delta)` with a non-zero `delta` to push the
/// first deadline out, and separately choose the behavior that fires when
/// the deadline is reached:
/// * `store.epoch_deadline_trap()` (the default — trap when deadline hits)
/// * `store.epoch_deadline_async_yield_and_update(delta2)` (cooperative
///   yield — what Slice AB's `apply_host_execution_budget` installs)
/// * `store.epoch_deadline_callback(fn)` (custom handler)
/// `set_epoch_deadline` alone is insufficient without one of the behavior
/// choices; `epoch_deadline_trap()` alone without `set_epoch_deadline(N>0)`
/// still traps immediately because the default deadline=0 is already
/// elapsed. In-tree tests `wasi_linker.rs` and `capability_injector.rs`
/// (T24/T25) construct raw `Store<ComponentCtx>` but never call
/// `instantiate_advance_host_async` on the same runtime (the ticker is
/// lazy-spawned ONLY from that method), so the ticker never starts and
/// the shared-engine epoch never advances past 0 — those tests work
/// today because their Components don't traverse epoch check points
/// even against a deadline=0 store (minimal Components and trap-body
/// dummies). `callable_framework.rs` uses `host_engine_handle().engine()`
/// to build a raw `Linker` (not a Store), so the trap hazard doesn't
/// apply there. Future in-tree callers that mix must document their
/// epoch policy explicitly.
#[derive(Clone)]
pub struct HostEngineHandle(wasmtime::Engine);

impl HostEngineHandle {
    pub fn engine(&self) -> &wasmtime::Engine {
        &self.0
    }
}

/// Opaque handle to the `tool_engine`. MODULE-017's `ToolRegistry` is the
/// intended consumer (tool-WASM Store creation + per-call `Store::set_fuel`).
#[derive(Clone)]
pub struct ToolEngineHandle(wasmtime::Engine);

impl ToolEngineHandle {
    pub fn engine(&self) -> &wasmtime::Engine {
        &self.0
    }
}

/// Opaque wrapper around a compiled `wasmtime::component::Component`.
/// Kept opaque so downstream callers don't need to depend on `wasmtime` types
/// beyond what `CapabilityInjector::inject()` and `Linker::instantiate_async`
/// already require.
#[derive(Clone)]
pub struct LoadedComponent(wasmtime::component::Component);

impl std::fmt::Debug for LoadedComponent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoadedComponent").finish_non_exhaustive()
    }
}

impl LoadedComponent {
    pub fn component(&self) -> &wasmtime::component::Component {
        &self.0
    }
}

#[derive(Debug)]
pub enum ComponentLoadError {
    /// Failure inside `wasmtime::Engine::new` (Config validation or JIT init).
    EngineInit(wasmtime::Error),
    /// Failure inside `wasmtime::component::Component::from_binary`.
    ComponentParse(wasmtime::Error),
    /// Empty input bytes rejected before invoking `Component::from_binary`.
    EmptyBinary,
}

/// Slice X — failure surfaces for `ComponentRuntime::instantiate_advance_host_async`.
///
/// Three distinct surfaces are mapped to three variants so downstream consumers can
/// surface actionable errors:
///   * `LinkerTypecheck` — `Linker::instantiate_pre` rejected the component because
///     a host fn the guest imports is not registered on the linker. (Slice X's
///     `advance-host` world has no imports, so this variant is unreachable for
///     well-formed test fixtures; future worlds with imports will populate it.)
///   * `BindgenExportLookup` — `AdvanceHostPre::new` rejected the InstancePre
///     because the guest is missing a world-required export
///     (`advance:runtime/message-driven` or `advance:runtime/runnable`).
///   * `Instantiate` — runtime instantiation/start trap from `instantiate_async`.
#[derive(Debug)]
pub enum InstantiateError {
    LinkerTypecheck(wasmtime::Error),
    BindgenExportLookup(wasmtime::Error),
    Instantiate(wasmtime::Error),
}

/// Slice m001-slice-bootstrap (2026-05-28) — map `CapabilityInjector` failures
/// to `InstantiateError`. The mapping preserves callers' ability to
/// programmatically distinguish "capability not registered" (caller forgot
/// to register the cap) from a real linker typecheck failure: the former
/// surfaces a synthetic `wasmtime::Error::msg("unknown capability: {cap}")`
/// whose `Display` prefix is the canonical `"unknown capability: "` tag
/// callers can substring-match. (A typed new InstantiateError variant
/// would be cleaner but would break the existing 3-variant surface
/// documented in CONTRACT-001 §2.3 — see the rustdoc note on
/// LinkerTypecheck for the documented overload semantics.)
impl From<crate::capability_injector::HostError> for InstantiateError {
    fn from(e: crate::capability_injector::HostError) -> Self {
        match e {
            crate::capability_injector::HostError::LinkerError(err) => {
                InstantiateError::LinkerTypecheck(err)
            }
            crate::capability_injector::HostError::UnknownCapability(cap) => {
                // Adversarial R1 W2 fix: sanitize attacker-controllable cap
                // string before baking it into the error chain. CapabilityId
                // is constructed from `&str` with no validation; a hostile
                // caller could supply control chars, BIDI bytes, or oversized
                // text. Strip ASCII control chars (defangs log-injection) and
                // truncate to 64 bytes (defangs oversize) BEFORE format.
                let safe: String = cap
                    .as_str()
                    .chars()
                    .filter(|c| !c.is_ascii_control())
                    .take(64)
                    .collect();
                InstantiateError::LinkerTypecheck(wasmtime::Error::msg(format!(
                    "unknown capability: {safe}"
                )))
            }
        }
    }
}

/// Adversarial fix R1 (round-1 Warning #4): redacted `Display` so consumer
/// surfaces (CLI, telemetry, logs) emit a stable variant tag rather than the
/// raw `wasmtime::Error` chain — the latter can leak host-pointer-aware
/// backtraces and attacker-controlled UTF-8 from component-author-supplied
/// export names. Mirrors `ConfigError`'s redaction posture (config.rs).
/// Callers wanting full diagnostic detail explicitly use `{:?}` (Debug).
impl std::fmt::Display for InstantiateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InstantiateError::LinkerTypecheck(_) => {
                f.write_str("instantiate failed: linker typecheck — required host import not wired")
            }
            InstantiateError::BindgenExportLookup(_) => f.write_str(
                "instantiate failed: guest component is missing a required advance-host export",
            ),
            InstantiateError::Instantiate(_) => {
                f.write_str("instantiate failed: WASM instantiation/start trap")
            }
        }
    }
}

impl std::error::Error for InstantiateError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        // Intentionally returns None — the wrapped wasmtime::Error chain is
        // available via Debug for diagnostics but is NOT exposed via Error::source
        // to prevent accidental leakage through `?` upcasting + downstream
        // formatters that walk the source chain.
        None
    }
}

impl ComponentRuntime {
    /// Construct both Engines per Decision 16.
    ///
    /// Synchronous; does NOT require a tokio runtime context. The lazy epoch ticker
    /// (Slice AB) is spawned on the first `instantiate_advance_host_async` call, not
    /// at construction.
    pub fn new(wasm_cfg: &WasmConfig) -> Result<Self, ComponentLoadError> {
        let base_config = || {
            let mut c = wasmtime::Config::new();
            c.wasm_component_model(true);
            c.epoch_interruption(true);
            c.wasm_memory64(false);
            c.wasm_multi_memory(false);
            c.max_wasm_stack(256 * 1024);
            c
        };

        let mut host_cfg = base_config();
        host_cfg.consume_fuel(false);
        let host_engine =
            wasmtime::Engine::new(&host_cfg).map_err(ComponentLoadError::EngineInit)?;

        let mut tool_cfg = base_config();
        tool_cfg.consume_fuel(wasm_cfg.fuel_enabled);
        let tool_engine =
            wasmtime::Engine::new(&tool_cfg).map_err(ComponentLoadError::EngineInit)?;

        Ok(Self {
            host_engine,
            tool_engine,
            host_ticker: OnceLock::new(),
            max_memory_pages: wasm_cfg.max_memory_pages,
            epoch_interruption_ms: wasm_cfg.epoch_interruption_ms,
        })
    }

    /// Opaque handle to the host engine. Pass the `.engine()` reference into
    /// `wasmtime::component::Linker::new` to build a `Linker<ComponentCtx>`.
    pub fn host_engine_handle(&self) -> HostEngineHandle {
        HostEngineHandle(self.host_engine.clone())
    }

    /// Opaque handle to the tool engine (for MODULE-017 consumption).
    pub fn tool_engine_handle(&self) -> ToolEngineHandle {
        ToolEngineHandle(self.tool_engine.clone())
    }

    /// Compile a WASM Component binary against the host engine.
    pub fn load_component(&self, bytes: &[u8]) -> Result<LoadedComponent, ComponentLoadError> {
        Self::parse_component(&self.host_engine, bytes)
    }

    /// Compile a WASM Component binary against the tool engine.
    pub fn load_tool_component(&self, bytes: &[u8]) -> Result<LoadedComponent, ComponentLoadError> {
        Self::parse_component(&self.tool_engine, bytes)
    }

    /// Compile a `ComponentSpec` (PRD §3.1 Component primitive) into a
    /// `LoadedComponent`, using the spec's `binary` bytes. The framework-level
    /// `id` / `type` / `capabilities` fields are preserved on the spec side
    /// and not consumed by the Wasmtime parser.
    pub fn load_component_spec(
        &self,
        spec: &ComponentSpec,
    ) -> Result<LoadedComponent, ComponentLoadError> {
        self.load_component(&spec.binary)
    }

    fn parse_component(
        engine: &wasmtime::Engine,
        bytes: &[u8],
    ) -> Result<LoadedComponent, ComponentLoadError> {
        if bytes.is_empty() {
            return Err(ComponentLoadError::EmptyBinary);
        }
        wasmtime::component::Component::from_binary(engine, bytes)
            .map(LoadedComponent)
            .map_err(ComponentLoadError::ComponentParse)
    }

    /// Slice X — instantiate a Component implementing the `advance-host` world.
    ///
    /// Returns the bindgen-generated `AdvanceHost` handle plus the owning Store.
    /// `AdvanceHost` exposes both world-exported interfaces via accessors:
    ///   * `bindings.advance_runtime_message_driven()` -> `&exports::advance::runtime::message_driven::Guest`
    ///   * `bindings.advance_runtime_runnable()` -> `&exports::advance::runtime::runnable::Guest`
    ///
    /// The dispatch method does NOT call `add_wasi_to_linker` — the `advance-host`
    /// world declares no WASI imports. Callers needing WASI must wait for a future
    /// slice to ship a parallel `instantiate_advance_host_with_wasi_async` method
    /// (the Linker is constructed inside this method and not exposed, so the
    /// "register WASI on a derived linker" pattern is not available today).
    ///
    /// # Slice AB hardening
    /// This method MUST be called from a tokio runtime context (required by
    /// `instantiate_async` itself). Repeated calls on the same `ComponentRuntime`
    /// share a single ticker (OnceLock idempotency). The first call triggers lazy
    /// ticker spawn; subsequent calls reuse. The returned `Store<ComponentCtx>`
    /// holds an `Arc<EpochTickerHandle>` via `ComponentCtx._ticker_keepalive`,
    /// ensuring the ticker outlives a later `drop(runtime)` as long as any Store
    /// survives.
    pub async fn instantiate_advance_host_async(
        &self,
        loaded: &LoadedComponent,
        mut ctx: crate::capability_injector::ComponentCtx,
    ) -> Result<
        (
            crate::wit_bindings::AdvanceHost,
            wasmtime::Store<crate::capability_injector::ComponentCtx>,
        ),
        InstantiateError,
    > {
        // Slice AB — lazy-start the Arc-shared OS-thread epoch ticker on first call.
        let ticker_arc = self.host_ticker.get_or_init(|| {
            Arc::new(spawn_epoch_ticker(
                self.host_engine.clone(),
                Duration::from_millis(self.epoch_interruption_ms),
            ))
        });
        // Attach a clone of the Arc to ctx before moving ctx into Store::new so the
        // ticker outlives the runtime if the caller holds onto the returned Store.
        ctx._ticker_keepalive = Some(Arc::clone(ticker_arc));

        let linker = wasmtime::component::Linker::<crate::capability_injector::ComponentCtx>::new(
            &self.host_engine,
        );
        let mut store = wasmtime::Store::new(&self.host_engine, ctx);
        // Slice AB — install memory limiter + cooperative-yield epoch deadline. The
        // helper is the single canonical wiring point for the host execution budget
        // (see component_loader.rs::apply_host_execution_budget rustdoc).
        apply_host_execution_budget(&mut store, self.max_memory_pages);
        let pre = linker
            .instantiate_pre(loaded.component())
            .map_err(InstantiateError::LinkerTypecheck)?;
        let bindings_pre = crate::wit_bindings::AdvanceHostPre::new(pre)
            .map_err(InstantiateError::BindgenExportLookup)?;
        let bindings = bindings_pre
            .instantiate_async(&mut store)
            .await
            .map_err(InstantiateError::Instantiate)?;
        Ok((bindings, store))
    }

    /// Slice m001-slice-bootstrap (2026-05-28) — sibling to
    /// [`Self::instantiate_advance_host_async`] that targets the new WIT world
    /// `advance-host-with-capabilities` (imports `agent-messaging`). Wires
    /// the imported host fns via [`CapabilityInjector::inject`] before
    /// `instantiate_pre`, so guest components targeting the new world can
    /// call registered `send` / `heartbeat` / `await-replies` host fns
    /// through the L0/L1/CB gates.
    ///
    /// Replicates the Slice AB ticker lifecycle verbatim:
    /// `host_ticker.get_or_init(spawn_epoch_ticker)` + `ctx._ticker_keepalive
    /// = Some(Arc::clone(...))` BEFORE `Store::new`, then
    /// `apply_host_execution_budget(...)`. The lazy ticker is shared with
    /// the original `instantiate_advance_host_async` path (single OnceLock,
    /// single OS-thread ticker per ComponentRuntime).
    ///
    /// `capabilities: &[CapRequest]` — each request names a capability
    /// (`CapabilityId`) whose registered specs are resolved by
    /// `HostRegistry::lookup`. CapabilityInjector groups by namespace and
    /// registers each spec via `LinkerInstance::func_new_async` with the
    /// L0/L1/CB gate-wrapping closure.
    ///
    /// Failures from `injector.inject` map through the new
    /// `From<HostError> for InstantiateError` impl above —
    /// `HostError::LinkerError` → `InstantiateError::LinkerTypecheck`
    /// (preserving the underlying wasmtime::Error chain);
    /// `HostError::UnknownCapability(c)` → `InstantiateError::LinkerTypecheck`
    /// (wrapping a synthetic message).
    pub async fn instantiate_advance_host_with_capabilities_async(
        &self,
        loaded: &LoadedComponent,
        mut ctx: crate::capability_injector::ComponentCtx,
        capabilities: &[advance_shared_types::capability::CapRequest],
        injector: &crate::capability_injector::CapabilityInjector,
    ) -> Result<
        (
            crate::wit_bindings::AdvanceHostWithCapabilities,
            wasmtime::Store<crate::capability_injector::ComponentCtx>,
        ),
        InstantiateError,
    > {
        // Slice AB ticker lifecycle (verbatim from instantiate_advance_host_async).
        let ticker_arc = self.host_ticker.get_or_init(|| {
            Arc::new(spawn_epoch_ticker(
                self.host_engine.clone(),
                Duration::from_millis(self.epoch_interruption_ms),
            ))
        });
        ctx._ticker_keepalive = Some(Arc::clone(ticker_arc));

        let mut linker =
            wasmtime::component::Linker::<crate::capability_injector::ComponentCtx>::new(
                &self.host_engine,
            );

        // Slice m001-slice-bootstrap — wire registered host fns through L0/L1/CB
        // gates BEFORE instantiate_pre. CapabilityInjector groups by namespace
        // and calls `LinkerInstance::func_new_async` per spec.
        injector.inject(&mut linker, capabilities)?;

        let mut store = wasmtime::Store::new(&self.host_engine, ctx);
        apply_host_execution_budget(&mut store, self.max_memory_pages);

        let pre = linker
            .instantiate_pre(loaded.component())
            .map_err(InstantiateError::LinkerTypecheck)?;
        let bindings_pre = crate::wit_bindings::AdvanceHostWithCapabilitiesPre::new(pre)
            .map_err(InstantiateError::BindgenExportLookup)?;
        let bindings = bindings_pre
            .instantiate_async(&mut store)
            .await
            .map_err(InstantiateError::Instantiate)?;
        Ok((bindings, store))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wasm_cfg(fuel_enabled: bool) -> WasmConfig {
        WasmConfig {
            max_memory_pages: 256,
            epoch_interruption_ms: 100,
            fuel_enabled,
        }
    }

    #[test]
    fn t_s_01_loader_new_with_fuel_disabled() {
        let cfg = wasm_cfg(false);
        let runtime = ComponentRuntime::new(&cfg);
        assert!(runtime.is_ok(), "construction must succeed with fuel off");
    }

    #[test]
    fn t_s_02_loader_new_with_fuel_enabled() {
        let cfg = wasm_cfg(true);
        let runtime = ComponentRuntime::new(&cfg);
        assert!(runtime.is_ok(), "construction must succeed with fuel on");
    }

    #[test]
    fn t_s_03_load_component_empty_bytes_rejected() {
        let cfg = wasm_cfg(false);
        let runtime = ComponentRuntime::new(&cfg).expect("construct runtime");
        let result = runtime.load_component(&[]);
        assert!(matches!(result, Err(ComponentLoadError::EmptyBinary)));
    }

    #[test]
    fn t_s_04_load_component_malformed_bytes_rejected() {
        let cfg = wasm_cfg(false);
        let runtime = ComponentRuntime::new(&cfg).expect("construct runtime");
        let malformed = [0xFFu8; 16];
        let result = runtime.load_component(&malformed);
        assert!(matches!(result, Err(ComponentLoadError::ComponentParse(_))));
    }

    // Slice AB — inline unit tests exercising the lazy OS-thread epoch ticker wiring.
    // These tests need pub(crate) access to `ComponentRuntime::host_ticker`, hence they
    // live inside the component_loader module rather than under `tests/`.

    fn empty_component_bytes() -> Vec<u8> {
        wat::parse_str("(component)").expect("empty component")
    }

    fn ab_ctx() -> crate::capability_injector::ComponentCtx {
        crate::capability_injector::ComponentCtx::new(
            "agent-ab".into(),
            "trace-ab".into(),
            Vec::new(),
        )
    }

    #[tokio::test(flavor = "current_thread")]
    async fn t_ab_01_lazy_ticker_starts_on_first_instantiate() {
        let cfg = wasm_cfg(false);
        let runtime = ComponentRuntime::new(&cfg).expect("runtime");
        assert!(
            runtime.host_ticker.get().is_none(),
            "ticker must not be spawned before first instantiate"
        );

        let bytes = empty_component_bytes();
        let loaded = runtime
            .load_component(&bytes)
            .expect("load empty component");

        // The empty (component) declares no exports, so `instantiate_advance_host_async`
        // returns Err(BindgenExportLookup). We intentionally discard the result — what
        // we care about is that the lazy-spawn branch fired BEFORE bindgen lookup.
        let _ = runtime
            .instantiate_advance_host_async(&loaded, ab_ctx())
            .await;

        assert!(
            runtime.host_ticker.get().is_some(),
            "ticker must be spawned after first instantiate"
        );

        // Second call must reuse the same Arc — OnceLock idempotency.
        let first_arc_ptr = Arc::as_ptr(runtime.host_ticker.get().unwrap());
        let _ = runtime
            .instantiate_advance_host_async(&loaded, ab_ctx())
            .await;
        let second_arc_ptr = Arc::as_ptr(runtime.host_ticker.get().unwrap());
        assert_eq!(
            first_arc_ptr, second_arc_ptr,
            "OnceLock must return the same Arc on subsequent calls"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn t_ab_02_drop_runtime_and_store_cleans_up_ticker() {
        // Scenario C: construct without instantiate, drop — no panic (OnceLock empty).
        {
            let cfg = wasm_cfg(false);
            let runtime = ComponentRuntime::new(&cfg).expect("runtime C");
            assert!(runtime.host_ticker.get().is_none());
            drop(runtime);
        }

        // Scenario A: instantiate fails (empty component has no advance-host exports);
        // the BindgenExportLookup error path drops the Store synchronously before
        // instantiate_async, so ComponentCtx's Arc keepalive drops. Only
        // ComponentRuntime's Arc remains (strong count == 1).
        //
        // Note: this assertion is specific to the BindgenExportLookup error path fired
        // by `AdvanceHostPre::new`. Other error variants (LinkerTypecheck, Instantiate)
        // would drop the Store at different points; the assertion here does not
        // generalize to those.
        {
            let cfg = wasm_cfg(false);
            let runtime = ComponentRuntime::new(&cfg).expect("runtime A");
            let bytes = empty_component_bytes();
            let loaded = runtime.load_component(&bytes).expect("load component A");
            let result = runtime
                .instantiate_advance_host_async(&loaded, ab_ctx())
                .await;
            assert!(
                matches!(result, Err(InstantiateError::BindgenExportLookup(_))),
                "empty component must fail at BindgenExportLookup (scenario A depends on this)"
            );
            let arc = runtime.host_ticker.get().expect("ticker populated");
            assert_eq!(
                Arc::strong_count(arc),
                1,
                "Store's Arc should have dropped when BindgenExportLookup returned Err"
            );
            drop(runtime);
        }

        // Scenario B: successful instantiate retains the Store; drop runtime FIRST,
        // then drop (bindings, store) last. Verifies the Arc-shared ticker lifetime —
        // the ticker OS thread must NOT stop when ComponentRuntime drops while a
        // Store is still alive. Uses the guest-rust-minimal fixture wrapped via
        // ComponentEncoder for a Component that actually satisfies the advance-host
        // world exports.
        {
            use wit_component::ComponentEncoder;
            const CORE_BYTES: &[u8] =
                include_bytes!("../tests/fixtures/guest-rust-minimal.core.wasm");
            let component_bytes = ComponentEncoder::default()
                .validate(true)
                .module(CORE_BYTES)
                .expect("encoder accepts core module")
                .encode()
                .expect("component encoded");

            let cfg = wasm_cfg(false);
            let runtime = ComponentRuntime::new(&cfg).expect("runtime B");
            let loaded = runtime
                .load_component(&component_bytes)
                .expect("load guest component");
            let (_bindings, _store) = runtime
                .instantiate_advance_host_async(&loaded, ab_ctx())
                .await
                .expect("instantiate succeeds");
            // Both the runtime and the Store hold an Arc to the ticker.
            let arc_before_runtime_drop =
                Arc::clone(runtime.host_ticker.get().expect("ticker populated"));
            assert!(
                Arc::strong_count(&arc_before_runtime_drop) >= 3,
                "Arc count should be >= 3 (runtime + store + our local clone); got {}",
                Arc::strong_count(&arc_before_runtime_drop)
            );

            // Drop the runtime FIRST. The ticker must stay alive because the Store
            // still holds an Arc.
            drop(runtime);

            // After runtime drop: our local clone + the Store's Arc remain.
            assert!(
                Arc::strong_count(&arc_before_runtime_drop) >= 2,
                "Arc count should be >= 2 after runtime drop (store + local); got {}",
                Arc::strong_count(&arc_before_runtime_drop)
            );

            // Now drop the Store (and bindings). Our local clone remains.
            drop(_store);
            drop(_bindings);

            // After Store drop: only our local clone remains. The ticker
            // EpochTickerHandle would drop only when this last Arc drops (at scope
            // end). Signal that explicitly by asserting strong_count == 1.
            assert_eq!(
                Arc::strong_count(&arc_before_runtime_drop),
                1,
                "Arc count should be 1 after store drop (only our local clone)"
            );
            // Our local clone drops at scope exit → EpochTickerHandle drops → OS
            // thread stops + joins. No panic expected.
        }
    }
}
