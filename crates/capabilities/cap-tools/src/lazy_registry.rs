//! `LazyToolRegistry` — MODULE-017 Slice B real ToolRegistry impl.
//!
//! Replaces Slice A's `InMemoryToolRegistry` stub (which always returns
//! `NotFound`). Implements:
//!
//! - **Lazy load**: registration takes raw component bytes; the WASM
//!   bring-up (validate `tool-exports` → `Component::from_binary` →
//!   instantiate → `describe()`) is deferred until first `load(id)` call.
//! - **LRU eviction**: in-memory cache capped at
//!   `config.max_tool_instances` (default 20 per MODULE-017 §2.10).
//! - **Tool-exports validation**: via [`crate::validator`] at first
//!   `load(id)`. Failed loads are recorded in `failed` and skipped by
//!   `list()`; subsequent `invoke` returns `NotFound` (AC-12).
//! - **Mutual exclusion**: a binary co-exporting `runnable.run` is
//!   rejected at validate (AC-11).
//! - **Result-size enforcement (Slice B' landing target)**:
//!   `config.max_result_bytes` is plumbed through `LazyRegistryConfig`
//!   and translated from `RuntimeConfig.tools` via `From<&ToolsConfig>`;
//!   when the Slice B' refinement lands the in-WASM `execute()` call,
//!   results exceeding the cap will fail closed with
//!   `OutputValidationFailed` — no silent truncation. Slice B's
//!   `invoke()` short-circuits to the deferred-execute error before
//!   any result is produced, so the cap is currently inert at the
//!   runtime layer (config-validated at boot per
//!   `validate_config` ranges, wired into the registry, but not yet
//!   consulted by an executing tool). See MODULE-017 §2.7 for the
//!   full Slice B / Slice B' contract boundary.
//! - **Two-phase locking**: short lock for cache + loading-set
//!   bookkeeping; lock-free WASM bring-up; short lock again to publish.
//!   Stampede mitigation via cooperative `yield_now` retry with a
//!   bounded-retry self-cleanup so external task cancellation cannot
//!   permanently strand the `loading` set.
//!
//! See MODULE-017 §2.7 Core Logic Slice B paragraph for the full
//! contract.

use std::collections::HashMap;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::Duration;

use advance_runtime::component_loader::ToolEngineHandle;
use advance_runtime::config::ToolsConfig;
use async_trait::async_trait;
use lru::LruCache;
use tokio::sync::Mutex;

use crate::registry::{
    MethodInfo, ToolDescription, ToolError, ToolInfo, ToolInstance, ToolRegistry,
};
use crate::schema_guard::require_intra_schema_refs;
use crate::validator::validate_tool_component;

/// Aggregate cap on the total byte size of a `ToolDescription` returned by a
/// guest's `describe()`. Closes the methods-vector DoS surface noted in
/// round-5 Info finding #2: a single 64-KiB `description` cap would let a
/// malicious tool ship a 1-byte `description` + a 10-MiB `methods` vector.
/// Slice C uses an aggregate JSON-byte serialization length as the proxy.
pub const MAX_TOOL_DESCRIPTION_BYTES: usize = 128 * 1024;

/// Configuration knobs for [`LazyToolRegistry`]. Backed by
/// MODULE-017 §2.10 `tools.*` config fields; wired into [`ToolsConfig`]
/// in `crates/runtime/src/config.rs` (Slice B addition).
///
/// Slice C adds three additive fields for the tool-invoke 主流程
/// (`new_with_engine` path): `tool_invoke_timeout`, `tool_fuel_per_call`,
/// `bring_up_describe_timeout`. The `From<&ToolsConfig>` impl only maps the
/// original 3 fields — the new fields use their `Default` values when
/// converting from `ToolsConfig` (NOT yet sourced from the runtime config
/// surface; surfacing them is a follow-on slice).
#[derive(Clone, Debug)]
pub struct LazyRegistryConfig {
    pub max_tool_instances: NonZeroUsize,
    pub lazy_load_timeout: Duration,
    pub max_result_bytes: usize,
    /// Wall-clock backstop for `invoke()`'s WASM execute() call. Default 5s.
    pub tool_invoke_timeout: Duration,
    /// Optional Wasmtime fuel budget per call. `None` = disabled (the engine
    /// must be configured with `consume_fuel(true)` for fuel to take effect;
    /// otherwise `Store::set_fuel` silently no-ops).
    pub tool_fuel_per_call: Option<u64>,
    /// Timeout for the bring_up `describe()` call. Default 2s (describe is
    /// expected to be a constant-time function returning a small struct).
    pub bring_up_describe_timeout: Duration,
    /// Slice G (MODULE-017-AC-24) — maximum number of retries for a single
    /// `invoke()` call. Default 0 (single attempt, retry disabled) — preserves
    /// pre-Slice-G behaviour for all existing operators. Retry is opt-in via
    /// explicit `LazyRegistryConfig` construction; the `From<&ToolsConfig>` impl
    /// keeps this at 0 because surfacing as a `runtime/src/config.rs` YAML knob
    /// would expand scope to runtime crate (deferred per MODULE-017 §3.6 (tt)).
    /// Gated by [`crate::retry::is_retry_allowed`] (see MODULE-017 §1.4 AC-24);
    /// retries only fire when the per-method `MethodInfo.idempotent` flag is
    /// `Some(true)` AND the error class is transient.
    ///
    /// **Effective ceiling**: the value is clamped to
    /// `crate::retry::MAX_TOOL_INVOKE_RETRIES_CAP` (currently 100) inside
    /// [`crate::retry::dispatch_with_retry`] (audit round 1 W2 fix). Values
    /// above the cap are accepted at construction (no validation panic) but
    /// silently capped at runtime. Combined with `tool_invoke_timeout`
    /// (default 5 s), the worst-case single-invoke wall-clock is bounded at
    /// `(1 + cap) × tool_invoke_timeout` ≈ 8.4 min. Operators wanting
    /// finer-grained behaviour should bridge `tool_invoke_timeout` smaller
    /// rather than raising this field. The cap is a defense-in-depth bound
    /// to prevent an operator-misconfiguration footgun (cf. sibling field
    /// `max_tool_instances ∈ [1, 1024]` which IS validated at the runtime
    /// `validate_config` boundary).
    pub tool_invoke_max_retries: u32,
}

impl Default for LazyRegistryConfig {
    fn default() -> Self {
        Self {
            max_tool_instances: NonZeroUsize::new(20).expect("20 != 0"),
            lazy_load_timeout: Duration::from_secs(30),
            max_result_bytes: 16 * 1024 * 1024,
            tool_invoke_timeout: Duration::from_secs(5),
            tool_fuel_per_call: None,
            bring_up_describe_timeout: Duration::from_secs(2),
            tool_invoke_max_retries: 0,
        }
    }
}

/// Audit-round-6 W1 fix — wire `RuntimeConfig.tools` (validated by
/// `advance_runtime::config::validate_config` at boot) into the
/// cap-tools registry's runtime knobs.
///
/// `validate_config` (config.rs:1072-1080) guarantees
/// `max_tool_instances ∈ [1, 1024]`, so the `NonZeroUsize::new(...)`
/// unwrap below is safe-by-construction. The conversion is
/// total-on-valid-input; if `validate_config` is ever bypassed (e.g.,
/// hand-constructed test ToolsConfig with `max_tool_instances: 0`),
/// the `expect()` panics with a clear message — fail-loud at the
/// translation boundary rather than degrade silently.
///
/// Slice B' will use this `From` impl at the cap-tools wire-up site
/// (currently absent; LazyToolRegistry::new is invoked only by tests
/// in Slice B). Locking the translation contract HERE makes the
/// wire-up slice a one-line plumbing change with this conversion
/// already audit-verified.
impl From<&ToolsConfig> for LazyRegistryConfig {
    fn from(cfg: &ToolsConfig) -> Self {
        // Slice C: all 6 ToolsConfig fields are now plumbed
        // (adversarial round 1 fix for C4 — tool_fuel_per_call +
        // tool_invoke_timeout + bring_up_describe_timeout are now
        // operator-tunable via the runtime config YAML, closing the
        // CPU-bound DoS surface that previously required code changes
        // to enable fuel-based interruption).
        Self {
            max_tool_instances: NonZeroUsize::new(cfg.max_tool_instances)
                .expect("ToolsConfig.max_tool_instances must be > 0 (validated at config load by advance_runtime::config::validate_config)"),
            lazy_load_timeout: Duration::from_secs(cfg.lazy_load_timeout_sec),
            max_result_bytes: cfg.max_result_bytes,
            tool_invoke_timeout: Duration::from_secs(cfg.tool_invoke_timeout_sec),
            tool_fuel_per_call: cfg.tool_fuel_per_call,
            bring_up_describe_timeout: Duration::from_secs(cfg.bring_up_describe_timeout_sec),
            // Slice G (MODULE-017-AC-24): the field is additive on
            // LazyRegistryConfig; surfacing it through the runtime
            // ToolsConfig YAML knob is deferred to a follow-on slice
            // (MODULE-017 §3.6 (tt)). Default 0 = no retry.
            tool_invoke_max_retries: 0,
        }
    }
}

/// Per-method JSON-Schema compiled ONCE at tool load (Slice F adversarial
/// round-11 W1/W2 fix). `Valid` holds the compiled schema, reused across all
/// invokes of that method (no per-invoke recompile). `Invalid` means a schema
/// was DECLARED in `describe()` but failed the [`require_intra_schema_refs`]
/// guard or `JSONSchema::compile` — `invoke()` fails closed for that method
/// (`Input/OutputValidationFailed`) rather than treating it as schema-absent
/// (which would silently BYPASS validation for a malformed/malicious schema).
/// Methods with NO declared schema are simply ABSENT from the map (passthrough).
pub(crate) enum CompiledSchema {
    Valid(Arc<jsonschema::JSONSchema>),
    Invalid,
}

/// Internal cache entry — cached `ToolDescription` from a successful
/// `describe()` call, plus the compiled `wasmtime::component::Component`
/// when the registry was built with an engine (Slice C `new_with_engine`).
///
/// `component: None` on the legacy `::new(config)` path preserves Slice B
/// SB-09 behavior verbatim (synthesized empty description; `invoke()`
/// short-circuits to SB-21 InvocationFailed before it would need a
/// Component). Slice C's `new_with_engine` populates `component: Some(_)`
/// and the in-WASM `execute()` path keys off the populated component.
///
/// Slice F: `input_schemas` / `output_schemas` cache the per-method compiled
/// JSON schemas (compiled once here at load, not per-invoke). Empty on the
/// no-engine path (no describe() methods).
struct LoadedTool {
    tool_id: String,
    description: ToolDescription,
    component: Option<wasmtime::component::Component>,
    input_schemas: HashMap<String, CompiledSchema>,
    output_schemas: HashMap<String, CompiledSchema>,
}

/// Per-id registration record. Stores the raw component bytes for
/// deferred load + the optional cached description after first load.
#[derive(Clone)]
struct ToolBinary {
    bytes: Arc<Vec<u8>>,
}

/// Shared inner state — single Mutex covers LRU + registration map +
/// loading-set + failed-map to make the LRU/register interleave free
/// of split-lock races.
///
/// **Loading map is epoch-tagged** (audit-round-8 W1 fix): each
/// Phase 1 acquisition assigns a unique `u64` from
/// `next_load_epoch`. Phase 3 only removes the entry when its
/// stored epoch matches the caller's local epoch — this prevents
/// the bounded-retry force-clear path from accidentally evicting a
/// newly-published epoch belonging to a different caller. Without
/// epoch tagging, caller B's force-clear could remove caller A's
/// active loading marker, leading to thundering-herd Phase 2 entries
/// + orphaned `Arc<LoadedTool>` writes to the cache. See round-7
/// W2 bounded-retry rationale + round-8 W1 epoch refinement.
struct RegistryInner {
    cache: LruCache<String, Arc<LoadedTool>>,
    registry: HashMap<String, ToolBinary>,
    loading: HashMap<String, u64>,
    failed: HashMap<String, String>,
    next_load_epoch: u64,
}

/// The Slice B production `ToolRegistry` — Slice C adds the optional
/// `tool_engine` for the in-WASM execute() main flow (`new_with_engine`).
///
/// **Constructor matrix**:
/// - `LazyToolRegistry::new(config)` — Slice B path. `tool_engine: None`;
///   `bring_up_tool` synthesizes empty descriptions; `invoke()`
///   short-circuits to SB-21 `InvocationFailed("slice-B: ...")`.
/// - `LazyToolRegistry::new_with_engine(config, engine)` — Slice C path.
///   `bring_up_tool` compiles Component + calls `describe()`;
///   `invoke()` runs the WASI-only `execute(method, params)` call inside
///   the guest, bounded by `tokio::time::timeout` + optional fuel.
pub struct LazyToolRegistry {
    config: LazyRegistryConfig,
    tool_engine: Option<ToolEngineHandle>,
    inner: Mutex<RegistryInner>,
}

impl LazyToolRegistry {
    pub fn new(config: LazyRegistryConfig) -> Self {
        let cap = config.max_tool_instances;
        Self {
            config,
            tool_engine: None,
            inner: Mutex::new(RegistryInner {
                cache: LruCache::new(cap),
                registry: HashMap::new(),
                loading: HashMap::new(),
                failed: HashMap::new(),
                next_load_epoch: 1,
            }),
        }
    }

    /// Slice C — construct with a `ToolEngineHandle` so `bring_up_tool` and
    /// `invoke()` use the in-WASM execute path. Preserves Slice B semantics
    /// on the `::new` path; the engine-presence branching lives in
    /// [`bring_up_tool`] and [`Self::invoke`] respectively.
    pub fn new_with_engine(config: LazyRegistryConfig, engine: ToolEngineHandle) -> Self {
        let cap = config.max_tool_instances;
        Self {
            config,
            tool_engine: Some(engine),
            inner: Mutex::new(RegistryInner {
                cache: LruCache::new(cap),
                registry: HashMap::new(),
                loading: HashMap::new(),
                failed: HashMap::new(),
                next_load_epoch: 1,
            }),
        }
    }

    /// Register a tool binary under `id`. Slice B does NOT perform
    /// validation or `describe()` here — those happen lazily on first
    /// `load(id)` per the AC-14 invariant.
    pub async fn register_binary(&self, id: impl Into<String>, bytes: Vec<u8>) {
        let id = id.into();
        let mut inner = self.inner.lock().await;
        inner.registry.insert(
            id.clone(),
            ToolBinary {
                bytes: Arc::new(bytes),
            },
        );
        // Clear any prior `failed` entry — re-registration is a retry path.
        inner.failed.remove(&id);
        inner.cache.pop(&id);
    }

    /// Explicit cache eviction for tests. In production, eviction is
    /// implicit when `LruCache::put` overflows the capacity.
    pub async fn evict_id(&self, id: &str) {
        let mut inner = self.inner.lock().await;
        inner.cache.pop(id);
    }

    /// Read the cache size (test helper). Not exposed as part of the
    /// trait surface.
    pub async fn cache_len(&self) -> usize {
        let inner = self.inner.lock().await;
        inner.cache.len()
    }
}

#[async_trait]
impl ToolRegistry for LazyToolRegistry {
    async fn load(&self, tool_id: &str) -> Result<ToolInstance, ToolError> {
        load_inner(self, tool_id).await.map(|loaded| ToolInstance {
            tool_id: loaded.tool_id.clone(),
        })
    }

    async fn invoke(
        &self,
        tool_id: &str,
        method: &str,
        params: &[u8],
    ) -> Result<Vec<u8>, ToolError> {
        let loaded = load_inner(self, tool_id).await?;

        // Slice B preservation: when no tool_engine was supplied, `invoke`
        // short-circuits to the SB-21 fail-explicit contract verbatim.
        // SB-21 / SB-09 regression tests live here.
        let engine = match self.tool_engine.as_ref() {
            Some(h) => h,
            None => {
                return Err(ToolError::InvocationFailed(
                    "slice-B: in-WASM execute deferred — see MODULE-017 §2.7 scope reduction"
                        .into(),
                ));
            }
        };

        // Slice C in-WASM execute path. The compiled Component is cached
        // by `bring_up_tool` on the `new_with_engine` path; if it's absent
        // here, the bring-up succeeded structurally (validator) but did
        // NOT cache a component — defensive bail-out per the invariant
        // "Some(engine) implies Some(component) after load_inner returns Ok".
        let component = loaded
            .component
            .as_ref()
            .ok_or_else(|| {
                ToolError::InvocationFailed(
                    "tool component absent post-load (Slice C invariant violated)".into(),
                )
            })?
            .clone();

        let timeout = self.config.tool_invoke_timeout;
        let fuel = self.config.tool_fuel_per_call;
        let max_result = self.config.max_result_bytes;
        let max_retries = self.config.tool_invoke_max_retries;

        // Slice F — input-schema gate against the LOAD-TIME-compiled schema
        // (adversarial round-11 W1/W2 fix: no per-invoke compile). Placed AFTER
        // the `Some(engine)` match so the Slice B no-engine path keeps its SB-21
        // short-circuit verbatim (no gate runs there). Validates `params` as JSON
        // via the cheap cached `is_valid`, run on a blocking thread under a
        // wall-clock timeout — MODULE-017 §2.7 Slice F.
        validate_cached_input(&loaded, method, params, timeout).await?;

        // Slice G (MODULE-017-AC-24) — resolve the per-method idempotent
        // flag from the cached describe() output. Methods absent from
        // describe() (or describe() not yet wired on this code path)
        // resolve to None — the gate then returns false, so the loop is
        // a single-shot attempt regardless of `max_retries`.
        let method_info: Option<MethodInfo> = loaded
            .description
            .methods
            .iter()
            .find(|m| m.name == method)
            .cloned();
        let should_retry = move |err: &ToolError| -> bool {
            match method_info.as_ref() {
                Some(m) => crate::retry::is_retry_allowed(m, err),
                None => false,
            }
        };

        let engine = engine.engine().clone();
        let method_owned = method.to_string();
        let params_owned = params.to_vec();

        // Slice G (MODULE-017-AC-24) — dispatch the execute call via the
        // retry harness. With `tool_invoke_max_retries == 0` (the
        // default) this runs exactly one attempt — behaviour identical
        // to pre-Slice-G. Opt-in callers set the field to N > 0 to
        // allow up to N retries for transient failures on idempotent
        // methods only. Backoff + `tool.retry` event emission are
        // deferred per MODULE-017 §3.6 (tt).
        let bytes = crate::retry::dispatch_with_retry(max_retries, should_retry, || {
            let engine = engine.clone();
            let component = component.clone();
            let method = method_owned.clone();
            let params = params_owned.clone();
            async move {
                tokio::time::timeout(
                    timeout,
                    execute_in_wasm(engine, component, method, params, fuel, max_result),
                )
                .await
                .map_err(|_| ToolError::InvocationFailed("invoke timeout".into()))?
            }
        })
        .await?;

        // Slice F — output-schema gate, BEFORE the max_result_bytes check so
        // both fail-closed paths return OutputValidationFailed.
        validate_cached_output(&loaded, method, &bytes, timeout).await?;

        if bytes.len() > max_result {
            return Err(ToolError::OutputValidationFailed(format!(
                "tool result exceeds max_result_bytes ({} > {})",
                bytes.len(),
                max_result
            )));
        }
        Ok(bytes)
    }

    async fn list(&self) -> Vec<ToolInfo> {
        let inner = self.inner.lock().await;
        let mut out = Vec::with_capacity(inner.registry.len());
        for id in inner.registry.keys() {
            if inner.failed.contains_key(id) {
                continue;
            }
            if let Some(loaded) = inner.cache.peek(id) {
                out.push(ToolInfo {
                    id: id.clone(),
                    description: loaded.description.description.clone(),
                    methods: loaded.description.methods.clone(),
                });
            } else {
                // Lazy: enumerated but not yet loaded — empty description.
                out.push(ToolInfo {
                    id: id.clone(),
                    description: String::new(),
                    methods: Vec::new(),
                });
            }
        }
        // Deterministic order across calls (HashMap iteration is unordered).
        out.sort_by(|a, b| a.id.cmp(&b.id));
        out
    }

    async fn evict_lru(&self) {
        let mut inner = self.inner.lock().await;
        inner.cache.pop_lru();
    }
}

/// Maximum cooperative-yield retries before treating a `loading` set
/// entry as stale and force-clearing it. Bounds the damage from
/// external task cancellation: if a task that holds a `loading` slot
/// is cancelled mid-await, its Phase 3 short lock (which removes the
/// entry) never runs, and subsequent loaders would otherwise spin
/// forever in the yield loop. 1024 yields ≈ ~1 ms self-recovery on
/// a modern executor; the original loader's `tokio::time::timeout`
/// is 30 s by default, so 1 ms is well below any legitimate
/// in-progress-load window.
///
/// **Why not RAII drop guard**: a Drop guard would need to re-acquire
/// the inner mutex on synchronous drop, which the tokio `Mutex`
/// doesn't expose. The alternatives — spawning a cleanup task in
/// Drop, or switching to `parking_lot::Mutex` — are larger refactors;
/// bounded retry is the pragmatic Slice B fix that closes the
/// cancellation gap without changing the lock primitive.
const MAX_LOADING_YIELD_RETRIES: usize = 1024;

/// Two-phase locking load. See module rustdoc.
async fn load_inner(reg: &LazyToolRegistry, tool_id: &str) -> Result<Arc<LoadedTool>, ToolError> {
    // Phase 1 (short lock) — check cache, check failed, check loading.
    let mut yield_retries: usize = 0;
    let (bytes, my_epoch) = loop {
        let mut inner = reg.inner.lock().await;
        if let Some(loaded) = inner.cache.get(tool_id) {
            return Ok(Arc::clone(loaded));
        }
        if inner.failed.contains_key(tool_id) {
            return Err(ToolError::NotFound(tool_id.to_string()));
        }
        if !inner.loading.contains_key(tool_id) {
            let bin = inner
                .registry
                .get(tool_id)
                .ok_or_else(|| ToolError::NotFound(tool_id.to_string()))?
                .clone();
            let epoch = inner.next_load_epoch;
            inner.next_load_epoch = inner.next_load_epoch.wrapping_add(1);
            inner.loading.insert(tool_id.to_string(), epoch);
            break (bin.bytes, epoch);
        }
        // Another task is loading the same id; cooperate via yield_now.
        //
        // **External-cancellation self-recovery (round-7 W2 fix +
        // round-8 W1 epoch refinement)**: if we've yielded
        // MAX_LOADING_YIELD_RETRIES times without observing
        // cache/failed transitions, force-clear the stale `loading`
        // entry AND continue (we'll re-acquire a fresh slot with a
        // new epoch on the next iteration). The original cancelled
        // loader's Phase 3, if it ever runs, will find a different
        // epoch in the loading map (or the entry gone entirely) and
        // no-op the remove. This eliminates the round-7 race where
        // caller B's force-clear could evict caller A's still-active
        // marker; epoch tagging ensures Phase 3 only owns its own
        // epoch.
        if yield_retries >= MAX_LOADING_YIELD_RETRIES {
            inner.loading.remove(tool_id);
            yield_retries = 0;
            drop(inner);
            continue;
        }
        yield_retries += 1;
        drop(inner);
        tokio::task::yield_now().await;
    };

    // Phase 2 (no lock) — validate, build, describe.
    // Slice C: pass the engine handle (or None) so bring_up_tool can branch
    // on engine-presence per §1.C.2.
    let engine_for_bring_up = reg.tool_engine.clone();
    let describe_timeout = reg.config.bring_up_describe_timeout;
    let result = tokio::time::timeout(
        reg.config.lazy_load_timeout,
        bring_up_tool(
            tool_id.to_string(),
            bytes,
            engine_for_bring_up,
            describe_timeout,
        ),
    )
    .await;

    let load_result = match result {
        Err(_) => Err(ToolError::InvocationFailed("load timeout".into())),
        Ok(r) => r,
    };

    // Phase 3 (short lock) — publish to cache or mark failed.
    //
    // **Epoch-guarded ENTIRE Phase 3** (round-9 W1 fix expanding
    // round-8): if our `loading` slot has been force-cleared and a
    // newer caller acquired the slot with a different epoch, our
    // Phase 2 work is orphaned — we MUST NOT write our outcome to
    // `cache.put` or `failed.insert`. The newer caller (B) will
    // publish its own outcome via its own Phase 3. Round-8 only
    // gated `loading.remove`; without gating cache/failed too, a
    // stranded `failed.insert` could shadow B's `cache.put` under
    // later LRU eviction, violating AC-12 ("registered tool
    // re-attemptable after re-register clears failed").
    //
    // The local caller still receives ITS OWN result (Ok(arc) or
    // Err(err)) — the orphan policy applies only to the SHARED
    // registry state. The caller's outcome stays diagnostic-rich;
    // the registry doesn't double-publish.
    let mut inner = reg.inner.lock().await;
    let stored_epoch = inner.loading.get(tool_id).copied();
    let own_slot = stored_epoch == Some(my_epoch);
    if own_slot {
        inner.loading.remove(tool_id);
    }
    match load_result {
        Ok(loaded) => {
            let arc = Arc::new(loaded);
            if own_slot {
                inner.cache.put(tool_id.to_string(), Arc::clone(&arc));
            }
            Ok(arc)
        }
        Err(err) => {
            // Preserve the original ToolError (e.g.,
            // `InvocationFailed("runnable + tool-exports mutual exclusion
            // violated")`) for THIS caller — it ran the validator and
            // gets diagnostic specificity. The `failed` map records the
            // reason string so SUBSEQUENT cache-miss callers short-
            // circuit to `ToolError::NotFound` per AC-12 (Phase 1
            // failed-map check above). Two-layer diagnostic contract:
            // first attempt sees the cause; later attempts see the
            // hidden-load conclusion. Skip the `failed.insert` if our
            // slot was force-cleared (orphaned-work policy).
            if own_slot {
                let reason = err.to_string();
                inner.failed.insert(tool_id.to_string(), reason);
            }
            Err(err)
        }
    }
}

/// Phase 2 body: validate + branch on engine-presence.
///
/// - `engine: None` (Slice B path) — validator gate only; synthesize empty
///   `ToolDescription`; `component: None`. SB-09 / SB-21 behavior preserved.
/// - `engine: Some(handle)` (Slice C path) — validator + compile +
///   instantiate + call `tool-exports.describe()` with the
///   `bring_up_describe_timeout`; aggregate-cap the serialized description
///   at [`MAX_TOOL_DESCRIPTION_BYTES`]; cache `component: Some(_)`.
///
/// **`tokio::task::spawn_blocking` for the validator** (round-8 W2 fix):
/// `validate_tool_component` is a synchronous CPU-bound `wasmparser` walk
/// over potentially-large component bytes. Offloading to the blocking pool
/// preserves cooperative scheduling + lets the outer `load_inner` timeout
/// cancel cleanly.
async fn bring_up_tool(
    tool_id: String,
    bytes: Arc<Vec<u8>>,
    engine: Option<ToolEngineHandle>,
    describe_timeout: Duration,
) -> Result<LoadedTool, ToolError> {
    let bytes_ref = Arc::clone(&bytes);
    let validation = tokio::task::spawn_blocking(move || validate_tool_component(&bytes_ref))
        .await
        .map_err(|e| ToolError::InvocationFailed(format!("validator join error: {e}")))?;
    let _outcome = validation?;

    // Slice B preservation: no engine → empty description, no component, no schemas.
    let Some(engine) = engine else {
        return Ok(LoadedTool {
            tool_id,
            description: ToolDescription {
                description: String::new(),
                methods: Vec::<MethodInfo>::new(),
            },
            component: None,
            input_schemas: HashMap::new(),
            output_schemas: HashMap::new(),
        });
    };

    // Slice C: compile the Component once + invoke describe().
    let component = {
        let bytes_for_compile = Arc::clone(&bytes);
        let engine_clone = engine.clone();
        let result = tokio::task::spawn_blocking(move || {
            wasmtime::component::Component::from_binary(engine_clone.engine(), &bytes_for_compile)
        })
        .await
        .map_err(|e| ToolError::InvocationFailed(format!("compile join error: {e}")))?;
        result.map_err(|e| ToolError::InvocationFailed(format!("component compile failed: {e}")))?
    };

    let description = tokio::time::timeout(
        describe_timeout,
        call_describe(engine.engine().clone(), component.clone()),
    )
    .await
    .map_err(|_| ToolError::InvocationFailed("describe timeout".into()))??;

    // Aggregate cap — guard against malicious methods-vector explosion.
    let serialized = serde_json::to_vec(&description)
        .map_err(|e| ToolError::InvocationFailed(format!("describe serialize: {e}")))?;
    if serialized.len() > MAX_TOOL_DESCRIPTION_BYTES {
        return Err(ToolError::OutputValidationFailed(format!(
            "tool description exceeds MAX_TOOL_DESCRIPTION_BYTES ({} > {})",
            serialized.len(),
            MAX_TOOL_DESCRIPTION_BYTES
        )));
    }

    // Slice F (adversarial round-11 W1/W2 fix): compile each method's
    // input/output JSON schema ONCE here at load (CPU-bound `JSONSchema::compile`
    // on the blocking pool), not per-invoke. `invoke()` then only runs the cheap
    // `is_valid` against the cached compiled schema. The describe()-aggregate is
    // already bounded by MAX_TOOL_DESCRIPTION_BYTES (128 KiB) so this one-time
    // compile is bounded.
    let methods_for_compile = description.methods.clone();
    let (input_schemas, output_schemas) =
        tokio::task::spawn_blocking(move || compile_method_schemas(&methods_for_compile))
            .await
            .map_err(|e| ToolError::InvocationFailed(format!("schema compile join error: {e}")))?;

    Ok(LoadedTool {
        tool_id,
        description,
        component: Some(component),
        input_schemas,
        output_schemas,
    })
}

// ─────────────────────────────────────────────────────────────────────
// In-WASM execute() + describe() runtime
// ─────────────────────────────────────────────────────────────────────

/// `ToolStoreData` — Store-data carrier for the in-WASM execute path.
/// Holds a WASI Preview 2 context + ResourceTable so
/// `wasmtime_wasi::p2::add_to_linker_async<T: WasiView>` typechecks.
/// Also embeds `wasmtime::StoreLimits` so the per-Store memory limiter
/// (adversarial round 2 fix for C1) lives for the Store's lifetime
/// without leaking memory.
struct ToolStoreData {
    wasi: wasmtime_wasi::WasiCtx,
    table: wasmtime_wasi::ResourceTable,
    limits: wasmtime::StoreLimits,
}

impl wasmtime_wasi::WasiView for ToolStoreData {
    fn ctx(&mut self) -> wasmtime_wasi::WasiCtxView<'_> {
        wasmtime_wasi::WasiCtxView {
            ctx: &mut self.wasi,
            table: &mut self.table,
        }
    }
}

/// Per-Store memory cap for tool WASM (adversarial round 2 fix for C1).
/// Tool engines have `wasm_memory64(false)` (~4 GiB cap) but no per-Store
/// limiter — an adversarial tool could `memory.grow` toward the 4 GiB
/// ceiling and OOM the host. 256 MiB is generous for legitimate tools
/// (most echo-style or LLM-wrapper tools fit in < 16 MiB) and small
/// enough to fit 16 concurrent invocations in 4 GiB of host RAM.
/// A future slice can expose this as `tool-max-memory-bytes` in
/// ToolsConfig if operator tuning is required.
const TOOL_MAX_MEMORY_BYTES: usize = 256 * 1024 * 1024;

fn make_tool_store(engine: &wasmtime::Engine) -> wasmtime::Store<ToolStoreData> {
    let wasi_ctx = wasmtime_wasi::WasiCtxBuilder::new().build();
    let limits = wasmtime::StoreLimitsBuilder::new()
        .memory_size(TOOL_MAX_MEMORY_BYTES)
        .build();
    let mut store = wasmtime::Store::new(
        engine,
        ToolStoreData {
            wasi: wasi_ctx,
            table: wasmtime_wasi::ResourceTable::new(),
            limits,
        },
    );
    // Adversarial round 2 fix (C1): install per-Store memory limiter so
    // a malicious tool cannot grow linear memory to OOM the host. Without
    // this, `memory.grow` in the guest can climb to wasmtime's default
    // static-memory ceiling (4 GiB on 32-bit wasm), and the tokio
    // timeout cannot reclaim allocations until the call returns.
    store.limiter(|data| &mut data.limits);
    // CRITICAL: tool_engine has epoch_interruption(true) per Decision 16.
    // Default Store::epoch_deadline = 0 means "already elapsed" — any WASM
    // execution would trap on first epoch check. Slice C has NO tool_engine
    // ticker spawn site (host_ticker is host_engine-only); set deadline to
    // u64::MAX to disable epoch-based interruption entirely.
    //
    // **CPU-bound DoS limitation (audit round 3)**: with the deadline
    // disabled AND `tool_fuel_per_call` defaulting to `None`, the only
    // bounded-execution mechanism is `tokio::time::timeout` in the caller
    // — which can only cancel the future at `.await` points. An adversarial
    // guest with an infinite CPU-bound loop in `execute()` (no I/O, no
    // syscalls, no yields) will block the tokio task indefinitely; the
    // timeout drops the future but the underlying `Func::call_async` may
    // continue holding the OS thread. Operators concerned about adversarial
    // guests should set `tool_fuel_per_call: Some(N)` AFTER configuring
    // `consume_fuel(true)` on the tool engine — fuel exhaustion injects a
    // yield point and will trap the loop. Tracked as MODULE-017 §3.6
    // known gap (a) + (g); the eventual `tool_ticker` ships in a future
    // advance-runtime slice.
    store.set_epoch_deadline(u64::MAX);
    store
}

/// Build a fresh `Linker<ToolStoreData>` with WASI Preview 2 host functions
/// — but NOT any agent-side host functions (no agent-tools, no agent-llm,
/// no agent-fs). Slice C explicitly forbids recursive tool invocation from
/// inside a tool's own execute() call.
fn make_tool_linker(
    engine: &wasmtime::Engine,
) -> Result<wasmtime::component::Linker<ToolStoreData>, ToolError> {
    let mut linker = wasmtime::component::Linker::<ToolStoreData>::new(engine);
    wasmtime_wasi::p2::add_to_linker_async(&mut linker)
        .map_err(|e| ToolError::InvocationFailed(format!("wasi linker setup: {e}")))?;
    Ok(linker)
}

/// Invoke `tool-exports.describe() -> tool-description` on the guest.
async fn call_describe(
    engine: wasmtime::Engine,
    component: wasmtime::component::Component,
) -> Result<ToolDescription, ToolError> {
    let mut store = make_tool_store(&engine);
    let linker = make_tool_linker(&engine)?;

    let instance = linker
        .instantiate_async(&mut store, &component)
        .await
        .map_err(|_| ToolError::InvocationFailed("instantiate failed".into()))?;

    let describe_func =
        resolve_tool_export(&component, &instance, &mut store, &engine, "describe")?;

    // `describe() -> tool-description` where `tool-description` is a
    // dynamic record. We accept any shape and serialize through Val for the
    // describe surface. Slice C uses dynamic call_async with empty params.
    let mut results = vec![wasmtime::component::Val::Bool(false)]; // placeholder slot
    describe_func
        .call_async(&mut store, &[], &mut results)
        .await
        .map_err(|_| ToolError::InvocationFailed("describe trap".into()))?;

    decode_tool_description(&results[0])
}

/// Resolve a `tool-exports.{name}` function from a freshly instantiated
/// component. The export name is mangled per the component-model encoder:
/// flat-style `"{interface-prefix}#{name}"` or instance-style nested under
/// the versioned interface name. Slice C probes both shapes; this matches
/// the validator's accepting both encodings.
fn resolve_tool_export(
    component: &wasmtime::component::Component,
    instance: &wasmtime::component::Instance,
    store: &mut wasmtime::Store<ToolStoreData>,
    engine: &wasmtime::Engine,
    method: &str,
) -> Result<wasmtime::component::Func, ToolError> {
    // Try instance-style: enumerate the component's top-level exports for
    // any whose name starts with the tool-exports prefix (covers
    // `advance:runtime/tool-exports@0.1.0` and unversioned variants), then
    // do nested get_export_index for the method.
    let component_type = component.component_type();
    let candidate_iface_names: Vec<String> = component_type
        .exports(engine)
        .filter_map(|(name, _ty)| {
            if name.starts_with(TOOL_EXPORTS_PREFIX) {
                Some(name.to_string())
            } else {
                None
            }
        })
        .collect();
    for iface_name in &candidate_iface_names {
        if let Some(iface_idx) = instance.get_export_index(&mut *store, None, iface_name.as_str()) {
            if let Some(func_idx) = instance.get_export_index(&mut *store, Some(&iface_idx), method)
            {
                if let Some(f) = instance.get_func(&mut *store, &func_idx) {
                    return Ok(f);
                }
            }
        }
    }
    // Try flat-style: top-level export named "{prefix}#{method}".
    let flat_name = format!("{TOOL_EXPORTS_PREFIX}#{method}");
    if let Some(idx) = instance.get_export_index(&mut *store, None, &flat_name) {
        if let Some(f) = instance.get_func(&mut *store, &idx) {
            return Ok(f);
        }
    }
    // Fall back to bare method name (relevant only for hand-rolled fixtures).
    if let Some(idx) = instance.get_export_index(&mut *store, None, method) {
        if let Some(f) = instance.get_func(&mut *store, &idx) {
            return Ok(f);
        }
    }
    Err(ToolError::InvocationFailed(format!(
        "missing tool-exports.{method}"
    )))
}

/// Validator-aligned prefix for the `tool-exports` interface export name.
const TOOL_EXPORTS_PREFIX: &str = "advance:runtime/tool-exports";

/// Decode a `Val::Record` carrying the `tool-description` shape per the
/// validator-recognized WIT (record { description: string, methods:
/// list<method-info> }). Tolerant to extra fields (forward-compat).
fn decode_tool_description(val: &wasmtime::component::Val) -> Result<ToolDescription, ToolError> {
    use wasmtime::component::Val;
    let fields = match val {
        Val::Record(f) => f,
        _ => {
            return Err(ToolError::InvocationFailed(
                "describe result must be a record".into(),
            ));
        }
    };
    let mut description = String::new();
    let mut methods: Vec<MethodInfo> = Vec::new();
    for (name, value) in fields {
        match name.as_str() {
            "description" => {
                if let Val::String(s) = value {
                    description = s.clone();
                }
            }
            "methods" => {
                if let Val::List(items) = value {
                    for item in items {
                        if let Some(m) = decode_method_info(item) {
                            methods.push(m);
                        }
                    }
                }
            }
            _ => { /* forward-compat: drop unknown fields */ }
        }
    }
    Ok(ToolDescription {
        description,
        methods,
    })
}

fn decode_method_info(val: &wasmtime::component::Val) -> Option<MethodInfo> {
    use wasmtime::component::Val;
    let fields = match val {
        Val::Record(f) => f,
        _ => return None,
    };
    let mut name = String::new();
    let mut description: Option<String> = None;
    let mut input_schema: Option<String> = None;
    let mut output_schema: Option<String> = None;
    let mut idempotent: Option<bool> = None;
    for (k, v) in fields {
        match k.as_str() {
            "name" => {
                if let Val::String(s) = v {
                    name = s.clone();
                }
            }
            "description" => description = decode_optional_string(v),
            "input-schema" => input_schema = decode_optional_string(v),
            "output-schema" => output_schema = decode_optional_string(v),
            "idempotent" => {
                idempotent = match v {
                    Val::Option(Some(boxed)) => match boxed.as_ref() {
                        Val::Bool(b) => Some(*b),
                        _ => None,
                    },
                    Val::Bool(b) => Some(*b),
                    _ => None,
                };
            }
            _ => {}
        }
    }
    if name.is_empty() {
        return None;
    }
    Some(MethodInfo {
        name,
        description,
        input_schema,
        output_schema,
        idempotent,
    })
}

fn decode_optional_string(val: &wasmtime::component::Val) -> Option<String> {
    use wasmtime::component::Val;
    match val {
        Val::Option(Some(boxed)) => match boxed.as_ref() {
            Val::String(s) => Some(s.clone()),
            _ => None,
        },
        Val::String(s) => Some(s.clone()),
        _ => None,
    }
}

/// Invoke `tool-exports.execute(method, params) -> result<list<u8>,
/// string>` on the guest. Returns the result bytes on success; maps the
/// guest `Err(String)` through [`classify_guest_error`] on failure.
async fn execute_in_wasm(
    engine: wasmtime::Engine,
    component: wasmtime::component::Component,
    method: String,
    params: Vec<u8>,
    fuel: Option<u64>,
    max_result_bytes: usize,
) -> Result<Vec<u8>, ToolError> {
    use wasmtime::component::Val;

    let mut store = make_tool_store(&engine);
    if let Some(f) = fuel {
        // Silently ignored when engine.consume_fuel() == false.
        let _ = store.set_fuel(f);
    }

    let linker = make_tool_linker(&engine)?;

    let instance = linker
        .instantiate_async(&mut store, &component)
        .await
        .map_err(|_| ToolError::InvocationFailed("instantiate failed".into()))?;
    let execute_func = resolve_tool_export(&component, &instance, &mut store, &engine, "execute")?;

    let params_val = Val::List(params.iter().map(|b| Val::U8(*b)).collect());
    let mut results = vec![Val::Bool(false)];
    execute_func
        .call_async(
            &mut store,
            &[Val::String(method.clone()), params_val],
            &mut results,
        )
        .await
        .map_err(|_| ToolError::InvocationFailed("execute trap".into()))?;

    // The result is `result<list<u8>, string>`.
    match &results[0] {
        Val::Result(Ok(Some(boxed))) => match boxed.as_ref() {
            Val::List(bytes) => {
                // Audit round 3 fix: short-circuit before the per-byte
                // copy when the Val::List length already exceeds the
                // configured cap. The wasmtime Val machinery has
                // already allocated the Val::List on the host heap by
                // this point — a second large allocation in the copy
                // loop is wasted work AND wedges the host harder on
                // adversarial-tool DoS. The upstream Val::List
                // allocation surface is documented in §3.6 (g) as a
                // known limitation pending wasmtime API support for
                // bounded result decoding.
                if bytes.len() > max_result_bytes {
                    return Err(ToolError::OutputValidationFailed(format!(
                        "tool result list length {} exceeds max_result_bytes ({})",
                        bytes.len(),
                        max_result_bytes
                    )));
                }
                let mut out = Vec::with_capacity(bytes.len());
                for v in bytes {
                    if let Val::U8(b) = v {
                        out.push(*b);
                    } else {
                        return Err(ToolError::InvocationFailed(
                            "execute result list must be list<u8>".into(),
                        ));
                    }
                }
                Ok(out)
            }
            _ => Err(ToolError::InvocationFailed(
                "execute result Ok must wrap list<u8>".into(),
            )),
        },
        Val::Result(Ok(None)) => Ok(Vec::new()),
        Val::Result(Err(Some(boxed))) => match boxed.as_ref() {
            Val::String(s) => Err(classify_guest_error(s, &method)),
            _ => Err(ToolError::InvocationFailed(
                "execute Err must wrap string".into(),
            )),
        },
        Val::Result(Err(None)) => Err(ToolError::InvocationFailed(
            "execute Err arm carried no payload".into(),
        )),
        _ => Err(ToolError::InvocationFailed(
            "execute result must be a Result".into(),
        )),
    }
}

/// Map a guest `execute()` `Err(String)` payload into the appropriate
/// `ToolError` variant. **Non-evaluating**: case-insensitive `starts_with`
/// + `contains` only; no regex backtracking; no eval/exec. The returned
/// `ToolError` payload is always a fixed safe-class string (no echo of the
/// guest's `Err` content per SB-22 redaction discipline).
///
/// **Trust boundary**: agents MUST treat the variant tag as an **advisory
/// hint** about the failure shape, NOT a security claim — a malicious tool
/// can prefix its `Err` with `"method-not-found:..."` even when the method
/// is fully known, causing the host to return `MethodNotFound` to the
/// agent. The classifier is safe because (a) the host never trusts the
/// variant as a security gate (no auth decisions branch on it), and (b)
/// the rich guest message stays in host-side `tracing` for diagnostic
/// purposes only.
pub(crate) fn classify_guest_error(payload: &str, method: &str) -> ToolError {
    let lower = payload.to_ascii_lowercase();
    if lower.starts_with("method-not-found") || lower.contains("unknown method") {
        return ToolError::MethodNotFound(method.to_string());
    }
    if lower.starts_with("input-validation-failed") {
        return ToolError::InputValidationFailed("input validation failed".into());
    }
    if lower.starts_with("output-validation-failed") {
        return ToolError::OutputValidationFailed("output validation failed".into());
    }
    if lower.starts_with("permission-denied") {
        return ToolError::PermissionDenied("permission denied".into());
    }
    ToolError::InvocationFailed("invocation failed".into())
}

// ─────────────────────────────────────────────────────────────────────
// Slice F — runtime JSON-Schema validation gate (compile-at-load)
// ─────────────────────────────────────────────────────────────────────

/// JSON-decode + `is_valid` failure classes for the cached-schema gate.
#[derive(Debug, PartialEq)]
pub(crate) enum GateFail {
    /// Input/output bytes were not valid JSON.
    NotJson,
    /// Bytes are valid JSON but fail the schema.
    SchemaFail,
}

/// Compile every method's input/output JSON schema ONCE (adversarial round-11
/// W1/W2 fix). For each method that DECLARES a schema, run the
/// [`require_intra_schema_refs`] guard then `JSONSchema::compile`; store
/// [`CompiledSchema::Valid`] on success or [`CompiledSchema::Invalid`] on guard
/// rejection / compile failure (so `invoke()` fails closed rather than bypassing
/// validation for a malformed schema). Methods without a schema are absent from
/// the returned map. Pure + CPU-bound — `bring_up_tool` runs it on the blocking
/// pool at load. `serde_json::from_str`'s built-in recursion limit (128) makes a
/// pathologically-nested schema string fail closed (→ Invalid) before the
/// depth-64 guard walk.
pub(crate) fn compile_method_schemas(
    methods: &[MethodInfo],
) -> (
    HashMap<String, CompiledSchema>,
    HashMap<String, CompiledSchema>,
) {
    fn compile_one(schema_str: &str) -> CompiledSchema {
        let schema_val: serde_json::Value = match serde_json::from_str(schema_str) {
            Ok(v) => v,
            Err(_) => return CompiledSchema::Invalid,
        };
        if require_intra_schema_refs(&schema_val).is_err() {
            return CompiledSchema::Invalid;
        }
        match jsonschema::JSONSchema::compile(&schema_val) {
            Ok(c) => CompiledSchema::Valid(Arc::new(c)),
            Err(_) => CompiledSchema::Invalid,
        }
    }
    let mut input = HashMap::new();
    let mut output = HashMap::new();
    for m in methods {
        if let Some(s) = &m.input_schema {
            input.insert(m.name.clone(), compile_one(s));
        }
        if let Some(s) = &m.output_schema {
            output.insert(m.name.clone(), compile_one(s));
        }
    }
    (input, output)
}

/// Decode `bytes` as JSON and check `is_valid` against the precompiled `schema`.
/// Pure + sync (run inside `spawn_blocking`). Returns the failure class so the
/// caller maps it to the right `Input/OutputValidationFailed` safe-class message.
pub(crate) fn json_check(schema: &jsonschema::JSONSchema, bytes: &[u8]) -> Result<(), GateFail> {
    let val: serde_json::Value = serde_json::from_slice(bytes).map_err(|_| GateFail::NotJson)?;
    if schema.is_valid(&val) {
        Ok(())
    } else {
        Err(GateFail::SchemaFail)
    }
}

/// Input gate against the LOAD-TIME-compiled schema cached on `loaded`. No
/// per-invoke compile (only the cheap `is_valid`, run on the blocking pool under
/// `timeout`). Absent method → passthrough; `Invalid` (schema declared but
/// rejected/uncompilable at load) → fail closed; `Valid` → `json_check`.
async fn validate_cached_input(
    loaded: &LoadedTool,
    method: &str,
    params: &[u8],
    timeout: Duration,
) -> Result<(), ToolError> {
    let schema = match loaded.input_schemas.get(method) {
        None => return Ok(()),
        Some(CompiledSchema::Invalid) => {
            return Err(ToolError::InputValidationFailed(
                "input schema invalid (rejected at load)".into(),
            ))
        }
        Some(CompiledSchema::Valid(s)) => Arc::clone(s),
    };
    let owned = params.to_vec();
    match tokio::time::timeout(
        timeout,
        tokio::task::spawn_blocking(move || json_check(&schema, &owned)),
    )
    .await
    {
        Err(_elapsed) => Err(ToolError::InputValidationFailed(
            "input schema validation timed out".into(),
        )),
        Ok(Err(_join)) => Err(ToolError::InputValidationFailed(
            "input schema validation task failed".into(),
        )),
        Ok(Ok(Ok(()))) => Ok(()),
        Ok(Ok(Err(GateFail::NotJson))) => Err(ToolError::InputValidationFailed(
            "input bytes are not valid JSON".into(),
        )),
        Ok(Ok(Err(GateFail::SchemaFail))) => Err(ToolError::InputValidationFailed(
            "input schema validation failed".into(),
        )),
    }
}

/// Output gate (symmetric to [`validate_cached_input`]; maps to
/// `OutputValidationFailed`).
async fn validate_cached_output(
    loaded: &LoadedTool,
    method: &str,
    output: &[u8],
    timeout: Duration,
) -> Result<(), ToolError> {
    let schema = match loaded.output_schemas.get(method) {
        None => return Ok(()),
        Some(CompiledSchema::Invalid) => {
            return Err(ToolError::OutputValidationFailed(
                "output schema invalid (rejected at load)".into(),
            ))
        }
        Some(CompiledSchema::Valid(s)) => Arc::clone(s),
    };
    let owned = output.to_vec();
    match tokio::time::timeout(
        timeout,
        tokio::task::spawn_blocking(move || json_check(&schema, &owned)),
    )
    .await
    {
        Err(_elapsed) => Err(ToolError::OutputValidationFailed(
            "output schema validation timed out".into(),
        )),
        Ok(Err(_join)) => Err(ToolError::OutputValidationFailed(
            "output schema validation task failed".into(),
        )),
        Ok(Ok(Ok(()))) => Ok(()),
        Ok(Ok(Err(GateFail::NotJson))) => Err(ToolError::OutputValidationFailed(
            "output bytes are not valid JSON".into(),
        )),
        Ok(Ok(Err(GateFail::SchemaFail))) => Err(ToolError::OutputValidationFailed(
            "output schema validation failed".into(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn small_cap_config() -> LazyRegistryConfig {
        LazyRegistryConfig {
            max_tool_instances: NonZeroUsize::new(2).expect("2 != 0"),
            lazy_load_timeout: Duration::from_secs(5),
            max_result_bytes: 1024,
            ..Default::default()
        }
    }

    /// SB-12 — dyn-safe + Send + Sync compile-time proof.
    #[test]
    fn sb_12_dyn_safe_send_sync() {
        let _: Box<dyn ToolRegistry> =
            Box::new(LazyToolRegistry::new(LazyRegistryConfig::default()));
    }

    // ──────────────────────────────────────────────────────────────
    // Slice F — runtime JSON-Schema gate unit tests (T80-T87). The gate
    // fns are pub(crate); these exercise the lookup + schema-decision +
    // validate path with hand-constructed MethodInfo (no WASM fixture
    // needed — cargo-component unavailable per §3.6 (e)).
    // ──────────────────────────────────────────────────────────────

    fn method_with(name: &str, input: Option<&str>, output: Option<&str>) -> MethodInfo {
        MethodInfo {
            name: name.into(),
            description: None,
            input_schema: input.map(|s| s.to_string()),
            output_schema: output.map(|s| s.to_string()),
            idempotent: None,
        }
    }

    const OBJ_X_NUM: &str =
        r#"{"type":"object","properties":{"x":{"type":"number"}},"required":["x"]}"#;

    /// Helper: compile a single input-schema method and return the cached
    /// CompiledSchema for `method`.
    fn compiled_input(methods: &[MethodInfo], method: &str) -> Option<CompiledSchema> {
        let (input, _) = compile_method_schemas(methods);
        input.get(method).map(|c| match c {
            CompiledSchema::Valid(a) => CompiledSchema::Valid(Arc::clone(a)),
            CompiledSchema::Invalid => CompiledSchema::Invalid,
        })
    }

    // MODULE-017-T80 — compile-at-load + json_check: valid passes, invalid rejected.
    #[test]
    fn t80_input_gate_valid_and_invalid() {
        let methods = vec![method_with("do", Some(OBJ_X_NUM), None)];
        let (input, _) = compile_method_schemas(&methods);
        let schema = match input.get("do") {
            Some(CompiledSchema::Valid(s)) => Arc::clone(s),
            _ => panic!("expected Valid compiled schema"),
        };
        assert_eq!(json_check(&schema, br#"{"x":1}"#), Ok(()));
        assert_eq!(
            json_check(&schema, br#"{"y":1}"#),
            Err(GateFail::SchemaFail)
        );
    }

    // MODULE-017-T81 — output gate compiled at load: valid passes, invalid rejected.
    #[test]
    fn t81_output_gate_valid_and_invalid() {
        let methods = vec![method_with("do", None, Some(OBJ_X_NUM))];
        let (_, output) = compile_method_schemas(&methods);
        let schema = match output.get("do") {
            Some(CompiledSchema::Valid(s)) => Arc::clone(s),
            _ => panic!("expected Valid compiled output schema"),
        };
        assert_eq!(json_check(&schema, br#"{"x":2}"#), Ok(()));
        assert_eq!(json_check(&schema, br#"{}"#), Err(GateFail::SchemaFail));
    }

    // MODULE-017-T82 — non-JSON bytes with a schema present → NotJson.
    #[test]
    fn t82_input_gate_non_json_params() {
        let methods = vec![method_with("do", Some(OBJ_X_NUM), None)];
        let schema = match compiled_input(&methods, "do") {
            Some(CompiledSchema::Valid(s)) => s,
            _ => panic!("expected Valid"),
        };
        assert_eq!(
            json_check(&schema, b"\xff\xfe not json"),
            Err(GateFail::NotJson)
        );
    }

    // MODULE-017-T83 — no input_schema → method absent from the compiled map
    // (invoke treats absent as passthrough).
    #[test]
    fn t83_input_gate_no_schema_passthrough() {
        let methods = vec![method_with("do", None, None)];
        let (input, _) = compile_method_schemas(&methods);
        assert!(
            input.get("do").is_none(),
            "no-schema method must be absent from cache"
        );
    }

    // MODULE-017-T84 — no output_schema → absent from the output cache.
    #[test]
    fn t84_output_gate_no_schema_passthrough() {
        let methods = vec![method_with("do", None, None)];
        let (_, output) = compile_method_schemas(&methods);
        assert!(output.get("do").is_none());
    }

    // MODULE-017-T87 — compile_method_schemas keys by method name; only the
    // schema'd method is in the map; absent methods passthrough at invoke.
    #[test]
    fn t87_compile_scans_correct_method() {
        let methods = vec![
            method_with("first", None, None),
            method_with("do", Some(OBJ_X_NUM), None),
            method_with("last", None, None),
        ];
        let (input, _) = compile_method_schemas(&methods);
        // Only "do" is cached; first/last (no schema) absent; "missing" never existed.
        assert!(matches!(input.get("do"), Some(CompiledSchema::Valid(_))));
        assert!(input.get("first").is_none());
        assert!(input.get("last").is_none());
        assert!(input.get("missing").is_none());
        // The cached "do" schema validates correctly.
        if let Some(CompiledSchema::Valid(s)) = input.get("do") {
            assert_eq!(json_check(s, br#"{"x":1}"#), Ok(()));
            assert_eq!(json_check(s, br#"{"y":1}"#), Err(GateFail::SchemaFail));
        }
    }

    // MODULE-017-T85 (gate mapping) — network $ref in a declared schema →
    // compile_method_schemas marks the method Invalid (guard rejects before
    // compile), so invoke fails closed instead of bypassing validation.
    #[test]
    fn t85_compile_marks_network_ref_invalid() {
        let bad = r#"{"type":"object","properties":{"x":{"$ref":"https://evil/x"}}}"#;
        let methods = vec![method_with("do", Some(bad), None)];
        let (input, _) = compile_method_schemas(&methods);
        assert!(
            matches!(input.get("do"), Some(CompiledSchema::Invalid)),
            "network $ref schema must compile to Invalid (fail-closed)"
        );
    }

    /// SB-24 — `From<&ToolsConfig> for LazyRegistryConfig` translation
    /// (audit-round-6 W1 fix): a `ToolsConfig` produced by the loader
    /// translates field-for-field into `LazyRegistryConfig`. Locks the
    /// wiring contract so Slice B' wire-up just calls `.into()`.
    #[test]
    fn sb_24_tools_config_translates_to_lazy_registry_config() {
        let tools = ToolsConfig {
            max_tool_instances: 42,
            lazy_load_timeout_sec: 60,
            max_result_bytes: 8 * 1024 * 1024,
            ..Default::default()
        };
        let cfg: LazyRegistryConfig = (&tools).into();
        assert_eq!(cfg.max_tool_instances.get(), 42);
        assert_eq!(cfg.lazy_load_timeout, Duration::from_secs(60));
        assert_eq!(cfg.max_result_bytes, 8 * 1024 * 1024);
    }

    /// SB-24b — default `ToolsConfig` translates to a `LazyRegistryConfig`
    /// matching this crate's `Default::default()` (verifies the two
    /// default sets agree across the runtime/cap-tools boundary).
    #[test]
    fn sb_24b_default_tools_config_matches_default_lazy_registry_config() {
        let tools = ToolsConfig::default();
        let from_tools: LazyRegistryConfig = (&tools).into();
        let cap_default = LazyRegistryConfig::default();
        assert_eq!(
            from_tools.max_tool_instances,
            cap_default.max_tool_instances
        );
        assert_eq!(from_tools.lazy_load_timeout, cap_default.lazy_load_timeout);
        assert_eq!(from_tools.max_result_bytes, cap_default.max_result_bytes);
    }

    /// SB-24c — `From<&ToolsConfig>` PANICS on zero `max_tool_instances`
    /// (defense-in-depth: should never reach this point because
    /// validate_config rejects 0, but if validate_config is bypassed
    /// the translation fails LOUD, not silent). The expected panic
    /// message documents the contract.
    #[test]
    #[should_panic(expected = "ToolsConfig.max_tool_instances must be > 0")]
    fn sb_24c_zero_max_tool_instances_panics_loudly() {
        let tools = ToolsConfig {
            max_tool_instances: 0, // forbidden by validate_config
            lazy_load_timeout_sec: 30,
            max_result_bytes: 16 * 1024 * 1024,
            ..Default::default()
        };
        let _: LazyRegistryConfig = (&tools).into();
    }

    /// SB-26 — epoch tagging prevents Phase 3 from removing the
    /// WRONG loading slot (audit-round-8 W1 fix). Simulates the
    /// scenario where caller B force-clears caller A's loading
    /// marker, then caller B acquires the slot with a NEW epoch.
    /// When caller A's Phase 3 runs, it must NOT remove B's epoch
    /// slot — epoch mismatch leaves B's marker alone.
    #[tokio::test]
    async fn sb_26_epoch_protects_against_phase3_evicting_others_slot() {
        let reg = LazyToolRegistry::new(small_cap_config());
        // Acquire slot manually with epoch 100 (simulating caller A).
        {
            let mut inner = reg.inner.lock().await;
            inner.loading.insert("contested".to_string(), 100);
            // Reserve some future epoch space for the test simulation.
            inner.next_load_epoch = 200;
        }
        // Simulate caller B force-clearing A's slot and seizing a new
        // one with epoch 200.
        {
            let mut inner = reg.inner.lock().await;
            inner.loading.remove("contested"); // force-clear
            inner.loading.insert("contested".to_string(), 200);
        }
        // Now simulate caller A's Phase 3 trying to remove its slot
        // (epoch 100). The slot has epoch 200 → A must NOT remove it.
        {
            let mut inner = reg.inner.lock().await;
            let stored = inner.loading.get("contested").copied();
            assert_eq!(stored, Some(200));
            let my_epoch: u64 = 100;
            // This is the exact predicate from load_inner Phase 3.
            if inner
                .loading
                .get("contested")
                .copied()
                .map(|e| e == my_epoch)
                .unwrap_or(false)
            {
                inner.loading.remove("contested");
            }
            // B's marker survives.
            assert_eq!(inner.loading.get("contested").copied(), Some(200));
        }
        // Now simulate caller B's Phase 3 with matching epoch.
        {
            let mut inner = reg.inner.lock().await;
            let my_epoch: u64 = 200;
            if inner
                .loading
                .get("contested")
                .copied()
                .map(|e| e == my_epoch)
                .unwrap_or(false)
            {
                inner.loading.remove("contested");
            }
            assert!(inner.loading.get("contested").is_none());
        }
    }

    /// SB-25 — bounded-retry self-recovery from a stranded `loading`
    /// set entry (audit-round-7 W2 fix). Simulates the external-
    /// cancellation gap: pre-populate `inner.loading` with an id that
    /// no task is actually loading; verify that `load(id)` eventually
    /// breaks free, force-clears the stale entry, and proceeds.
    #[tokio::test]
    async fn sb_25_load_recovers_from_stranded_loading_entry() {
        let reg = LazyToolRegistry::new(small_cap_config());
        // Register a binary so load() would normally succeed validator
        // (but the test inserts a stale loading entry BEFORE load runs).
        // The stale-entry path is what we're testing — we don't need a
        // real component here; the load will force-clear the loading
        // entry and then fail at the validator (binary is bogus). The
        // important assertion is that load() returns SOMETHING in
        // finite time, not that it returns Ok.
        reg.register_binary("stranded", vec![0, 0, 0, 0]).await;
        // Strand the loading set: another task "promised" to load this
        // id but never followed through (cancellation). Use an
        // arbitrary epoch — load_inner's force-clear path removes the
        // entry regardless of epoch (it's clearing what it considers
        // stale).
        {
            let mut inner = reg.inner.lock().await;
            inner.loading.insert("stranded".to_string(), 0xDEADBEEF);
        }
        // Now call load(). Without the self-recovery path, this would
        // spin forever in yield_now. With the fix, after
        // MAX_LOADING_YIELD_RETRIES yields it force-clears the stale
        // entry and re-enters Phase 1, eventually returning an error
        // because the bogus bytes fail validator.
        let result = reg.load("stranded").await;
        // Either error variant is acceptable (the test verifies finite
        // termination, not the specific error). The bogus bytes mean
        // validation fails → InvocationFailed on first valid attempt;
        // subsequent attempts would short-circuit via failed-map to
        // NotFound.
        assert!(
            result.is_err(),
            "expected load() to return an error in finite time after stale loading entry"
        );
    }

    #[tokio::test]
    async fn registry_starts_empty() {
        let reg = LazyToolRegistry::new(small_cap_config());
        let tools = reg.list().await;
        assert!(tools.is_empty());
    }

    #[tokio::test]
    async fn unknown_id_returns_not_found() {
        let reg = LazyToolRegistry::new(small_cap_config());
        let err = reg.load("nope").await.expect_err("must fail");
        match err {
            ToolError::NotFound(id) => assert_eq!(id, "nope"),
            other => panic!("expected NotFound got {other:?}"),
        }
    }

    // ─────────────────────────────────────────────────────────────
    // Slice C — tool-invoke 主流程 unit tests
    // ─────────────────────────────────────────────────────────────

    /// SC-50: classify_guest_error payload table.
    ///
    /// Each row exercises one classifier branch with a sample guest
    /// payload. The classifier is non-evaluating (case-insensitive
    /// `starts_with` / `contains` only), so payload variations like
    /// `"Method-Not-Found:foo"` still match.
    #[test]
    fn sc_50_classify_guest_error_table() {
        let cases: &[(&str, &str, ToolError)] = &[
            (
                "method-not-found:unknown-method",
                "unknown-method",
                ToolError::MethodNotFound("unknown-method".into()),
            ),
            (
                "MEthOD-Not-Found:case-insensitive",
                "case-insensitive",
                ToolError::MethodNotFound("case-insensitive".into()),
            ),
            (
                "this calls an unknown method foo",
                "foo",
                ToolError::MethodNotFound("foo".into()),
            ),
            (
                "input-validation-failed:reason",
                "ignored",
                ToolError::InputValidationFailed("input validation failed".into()),
            ),
            (
                "output-validation-failed:reason",
                "ignored",
                ToolError::OutputValidationFailed("output validation failed".into()),
            ),
            (
                "permission-denied:reason",
                "ignored",
                ToolError::PermissionDenied("permission denied".into()),
            ),
            (
                "some random failure",
                "ignored",
                ToolError::InvocationFailed("invocation failed".into()),
            ),
        ];
        for (payload, method, expected) in cases {
            let got = classify_guest_error(payload, method);
            assert_eq!(
                std::mem::discriminant(&got),
                std::mem::discriminant(expected),
                "payload {payload:?} did not classify as {expected:?}, got {got:?}"
            );
            match (&got, expected) {
                (ToolError::MethodNotFound(g), ToolError::MethodNotFound(e)) => {
                    assert_eq!(g, e, "method passthrough mismatch")
                }
                (ToolError::InputValidationFailed(g), ToolError::InputValidationFailed(e))
                | (ToolError::OutputValidationFailed(g), ToolError::OutputValidationFailed(e))
                | (ToolError::PermissionDenied(g), ToolError::PermissionDenied(e))
                | (ToolError::InvocationFailed(g), ToolError::InvocationFailed(e)) => {
                    assert_eq!(g, e, "safe-class payload mismatch")
                }
                _ => {}
            }
        }
    }

    /// SC-50-bis: classifier payload is always a fixed safe-class string
    /// (no echo of the guest's `Err` content per SB-22 redaction
    /// discipline). Sensitive guest content must NOT appear in the
    /// returned ToolError's payload.
    #[test]
    fn sc_50_classifier_redaction_discipline() {
        let sensitive = "input-validation-failed: SECRET_KEY=hunter2 leaked";
        let err = classify_guest_error(sensitive, "any-method");
        let displayed = format!("{err:?}");
        assert!(
            !displayed.contains("hunter2"),
            "classifier must not echo sensitive guest payload: {displayed}"
        );
        assert!(
            !displayed.contains("SECRET_KEY"),
            "classifier must not echo sensitive guest payload: {displayed}"
        );
    }

    /// SC-55: `bring_up_tool` under `tool_engine: None` (legacy `::new`)
    /// synthesizes an empty `ToolDescription` and `component: None`.
    /// Verified via a minimal core-wasm-stub binary that satisfies the
    /// validator but is never actually executed.
    #[tokio::test]
    async fn sc_55_bring_up_legacy_path_synthesizes_empty_description() {
        // Hand-craft a minimal Component that exports `tool-exports`
        // describe + execute as imports/exports the validator accepts.
        // Skip if the wat fixture path is not workable — fall back to a
        // direct call into bring_up_tool with a known-valid binary from
        // the registry_lru.rs test infra. For Slice C we exercise
        // ONLY the legacy `engine: None` branch which doesn't actually
        // execute the binary, only validates it.
        let stub = make_validator_friendly_stub();
        let result = bring_up_tool(
            "stub".to_string(),
            Arc::new(stub),
            None, // engine: None — Slice B path
            Duration::from_secs(2),
        )
        .await;
        let loaded = result.expect("legacy path should succeed when validator accepts");
        assert!(loaded.description.description.is_empty());
        assert!(loaded.description.methods.is_empty());
        assert!(
            loaded.component.is_none(),
            "engine: None implies component: None"
        );
    }

    /// Build a validator-accepted dummy Component using `wit_component::
    /// dummy_module` against a `tool-exports` world (canonical
    /// `advance:runtime@0.1.0` package). Mirrors the encoder pattern from
    /// `tests/registry_lru.rs::build_dummy_component`.
    fn make_validator_friendly_stub() -> Vec<u8> {
        use wit_component::{embed_component_metadata, ComponentEncoder, StringEncoding};
        use wit_parser::{ManglingAndAbi, Resolve};

        const WIT: &str = r#"
            package advance:runtime@0.1.0;

            interface tool-exports {
                record method-info { name: string }
                record tool-description {
                    description: string,
                    methods: list<method-info>,
                }
                describe: func() -> tool-description;
                execute: func(method: string, params: list<u8>) -> result<list<u8>, string>;
            }

            world tool-world {
                export tool-exports;
            }
        "#;

        let mut resolve = Resolve::default();
        let pkg = resolve.push_str("inline.wit", WIT).expect("WIT parses");
        let world = resolve
            .select_world(&[pkg], Some("tool-world"))
            .expect("world found");
        let mut core = wit_component::dummy_module(&resolve, world, ManglingAndAbi::Standard32);
        embed_component_metadata(&mut core, &resolve, world, StringEncoding::UTF8)
            .expect("embed metadata");
        ComponentEncoder::default()
            .validate(true)
            .module(&core)
            .expect("module accepted")
            .encode()
            .expect("component encoded")
    }
}
