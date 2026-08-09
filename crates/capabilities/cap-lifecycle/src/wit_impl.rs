//! Slice C — `agent-lifecycle` WIT bindings (CONTRACT-041, MODULE-005
//! AC-01 / REQ-179).
//!
//! 22 `HostFunctionHandler` impls + `register_agent_lifecycle` entry point
//! (mirrors cap-grant's `register_agent_grant` pattern). Every
//! caller-identity handler sources `caller_id` from `HostCallContext.agent_id`
//! (NEVER a guest param — cap-grant wit_impl.rs:229 precedent).
//!
//! Error lowering follows the MODULE-005 §2.8 3-category taxonomy:
//! 1. call-shape / lift / malformed-strategy → `HostCallError::HandlerError`
//!    (host trap, cap-grant call-shape precedent);
//! 2. domain failures → typed WIT variant (`Val::Result(Err(..))`);
//! 3. infra failures → `spawn-error`/`lifecycle-error` neutral bucket +
//!    opaque `"internal-error"`; `decomposition-error` has NO neutral
//!    variant so its infra failures → `HostCallError::HandlerError` host
//!    trap (truthful — never a false `task-not-found` domain lie).
//!
//! AC-06 (subset-enforcement at spawn-child/spawn-sub/submit-component)
//! ships in Slice E (m013-slice-e, 2026-05-23). spawn-child / spawn-sub
//! enforcement flows through `DefaultSpawner.subset_gate` (production
//! callers wire `CapGrantSubsetAdapter` from `cap_grant_adapter.rs`);
//! submit-component enforcement is provided via `SubsetCheckedComponentSubmit`
//! at the cap-lifecycle library layer (Rust-API wrapper). spawn-child /
//! spawn-sub now LIFT the requested `cap-request` capabilities from the call
//! frame into the recorded node (011, Wave-15 Lane E — see `lift_cap_request_list`
//! + `dispatch_spawn`), so the subset gate enforces against real requested caps.
//! CONTRACT-217 v0.2 lifts the complete submit record, including capabilities.
//! The production M014 adapter delegates subset enforcement to the scheduler's
//! injected submitter-grant gate and rejects any parameter carrier that CONTRACT-130
//! cannot represent without authority loss.

use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;

use advance_runtime::host_registry::{
    HostCallContext, HostCallError, HostFunctionHandler, HostFunctionSpec, HostRegistry,
};
use advance_shared_types::traits::EventBusEmit;
use wasmtime::component::Val;

use crate::checkpoint::CheckpointController;
use crate::component_submit::{
    ComponentSubmitConfigV2, ComponentSubmitGate, MAX_SUBMIT_COMPONENT_BYTES,
};
use crate::decomposition::{
    DecompositionPlan, DecompositionState, DecompositionStore, DecompositionStrategy,
    DelegationTarget, SubtaskSpec, SubtaskState, SubtaskStatus,
};
use crate::error::{DecompositionError, LifecycleError, SpawnError};
use crate::spawn::{SpawnChildConfig, SpawnSubConfig, Spawner};
use crate::stats::{AgentStats, StatsController};
use crate::templates::TemplateResolver;
use crate::terminate::TerminateController;
use crate::tree::AgentTreeStore;
use advance_shared_types::agent_tree::{
    AgentId, AgentKind, AgentTreeSnapshot, AgentTreeSnapshotData, Capability,
};
use advance_shared_types::capability::{CapParams, CapabilityId};

pub const AGENT_LIFECYCLE_CAPABILITY: &str = "lifecycle";
pub const AGENT_LIFECYCLE_NAMESPACE: &str = "advance:runtime/agent-lifecycle@0.2.0";

// Defensive WIT-entry caps (defence-in-depth; controllers re-check).
const MAX_AGENT_ID_BYTES: usize = 64;
const MAX_LABEL_BYTES: usize = 128;
const MAX_TARGET_BYTES: usize = 256;
const MAX_CONFIG_BYTES: usize = 256 * 1024;
/// Per-subtask descriptor cap for the test-facing `submit-decomposition` wire
/// shape (`"title|assignee|prompt|deps"`). A maximal LEGIT descriptor is
/// title(≤256) + assignee(≤128) + prompt(≤16 KiB) + up to ~255 dep-titles
/// (≤256 B each) ≈ 82 KiB, so 128 KiB is generous headroom — but it bounds the
/// pathological `…|a,a,a,…` 4th-field that would otherwise amplify into millions
/// of `depends_on` entries (and unbounded assignee clones) BEFORE the store's
/// per-field caps fire (adversarial r7 W1/W2). Oversized descriptor → call-shape
/// `HandlerError` host trap (taxonomy category 1).
const MAX_DESCRIPTOR_BYTES: usize = 128 * 1024;
/// Aggregate cap across ALL `submit-decomposition` descriptors in one call —
/// mirrors the sibling `init_child_workspace_files` aggregate-bytes guard. A
/// maximal legit plan is ≤256 subtasks × ~16.5 KiB (title + assignee + 16 KiB
/// prompt + deps) ≈ 4.2 MiB, so 8 MiB is generous headroom while bounding the
/// host-side lift work to a fixed ceiling regardless of guest linear-memory
/// size (adversarial r8 W1). Exceeding it → call-shape `HandlerError` host trap.
const MAX_DECOMPOSITION_INPUT_BYTES: usize = 8 * 1024 * 1024;

/// Injection bundle for `register_agent_lifecycle`. No `subset_validator`
/// field — subset enforcement flows through `spawner.subset_gate` which
/// production callers wire to `CapGrantSubsetAdapter` (see
/// `cap_grant_adapter.rs`); submit-component subset enforcement is
/// enforced by the production scheduler bridge's injected subset gate. The
/// compatibility `SubsetCheckedComponentSubmit` remains available to Rust-only
/// callers of the legacy mirror.
#[derive(Clone)]
pub struct AgentLifecycleBundle {
    pub tree: AgentTreeStore,
    pub spawner: Arc<dyn Spawner>,
    pub rollback: Arc<dyn crate::rollback::RollbackController>,
    pub checkpoint: Arc<dyn CheckpointController>,
    pub terminate: Arc<dyn TerminateController>,
    pub decomposition: Arc<dyn DecompositionStore>,
    pub stats: Arc<dyn StatsController>,
    pub templates: Arc<dyn TemplateResolver>,
    pub submit_gate: Arc<dyn ComponentSubmitGate>,
    pub event_bus: Arc<dyn EventBusEmit>,
}

/// Register all 22 `agent-lifecycle` host functions.
///
/// 8 read-only methods are `idempotent: true`
/// (component-status, list-components, list-child-checkpoints,
/// list-checkpoints, self-stats, child-stats, list-agent-templates,
/// get-decomposition); the other 14 are `false`.
pub fn register_agent_lifecycle(registry: &dyn HostRegistry, bundle: AgentLifecycleBundle) {
    let cap = AGENT_LIFECYCLE_CAPABILITY.to_string();
    let ns = AGENT_LIFECYCLE_NAMESPACE.to_string();
    let b = Arc::new(bundle);

    let reg = |name: &str, idempotent: bool| {
        registry.register(HostFunctionSpec {
            capability: cap.clone(),
            namespace: ns.clone(),
            name: name.to_string(),
            handler: Arc::new(LifecycleHandler {
                op: name.to_string(),
                b: Arc::clone(&b),
            }),
            idempotent,
        });
    };

    reg("spawn-child", false);
    reg("spawn-sub", false);
    reg("init-child-workspace", false);
    reg("rollback-child", false);
    reg("rollback-child-to-checkpoint", false);
    reg("list-child-checkpoints", true);
    reg("terminate-child", false);
    reg("submit-component", false);
    reg("component-status", true);
    reg("kill-component", false);
    reg("list-components", true);
    reg("checkpoint", false);
    reg("rollback-to-checkpoint", false);
    reg("list-checkpoints", true);
    reg("self-stats", true);
    reg("child-stats", true);
    reg("spawn-agent-from-template", false);
    reg("list-agent-templates", true);
    reg("terminate-agent", false);
    reg("submit-decomposition", false);
    reg("update-subtask-status", false);
    reg("get-decomposition", true);
}

/// Register ONLY the 3 spawn host-fns (`spawn-child` / `spawn-sub` /
/// `spawn-agent-from-template`) over a [`Spawner`], under the agent-lifecycle
/// capability + namespace. The narrow production entry point (011, Wave-11
/// Lane B): `cli::wire_capabilities` calls this over a `DefaultSpawner` sharing
/// the assembler's `AgentTreeStore`, so a sub-agent spawn records a `Sub` node
/// into the SAME store the `# Available Delegates` snapshot reads — WITHOUT the
/// full [`AgentLifecycleBundle`] (terminate / checkpoint / rollback /
/// decomposition / stats / submit need cross-module production controllers that
/// ship only as test stubs; wiring those is mainline). All 3 ops are
/// non-idempotent (they mutate the tree) and reuse the SAME [`dispatch_spawn`]
/// the full [`register_agent_lifecycle`] dispatch uses. Wave-23
/// `perchild-daemon-1` lifted `"lifecycle"` INTO cli `KNOWN_CAPABILITIES`, so a
/// declaring guest links the interface AND the cli `PerChildLoopManager` observer
/// makes the spawned child a LIVE served agent; a build-lane witness also drives
/// the registered handler directly.
///
/// Do NOT call this AND `register_agent_lifecycle` on the same registry — the
/// spawn ops would be registered twice (production wires exactly one path).
pub fn register_agent_spawn(registry: &dyn HostRegistry, spawner: Arc<dyn Spawner>) {
    let cap = AGENT_LIFECYCLE_CAPABILITY.to_string();
    let ns = AGENT_LIFECYCLE_NAMESPACE.to_string();
    for name in ["spawn-child", "spawn-sub", "spawn-agent-from-template"] {
        registry.register(HostFunctionSpec {
            capability: cap.clone(),
            namespace: ns.clone(),
            name: name.to_string(),
            handler: Arc::new(SpawnHandler {
                op: name.to_string(),
                spawner: Arc::clone(&spawner),
            }),
            idempotent: false,
        });
    }
}

/// Narrow spawn-only handler (011): dispatches `spawn-child` / `spawn-sub` /
/// `spawn-agent-from-template` over a [`Spawner`] via the shared
/// [`dispatch_spawn`], running the SAME `check_results_len` + caller `cap_str`
/// preamble that `dispatch` runs. Registered by [`register_agent_spawn`];
/// carries NO full bundle.
struct SpawnHandler {
    op: String,
    spawner: Arc<dyn Spawner>,
}

impl HostFunctionHandler for SpawnHandler {
    fn call(
        &self,
        ctx: HostCallContext,
        params: Vec<Val>,
        results_len: usize,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<Val>, HostCallError>> + Send + 'static>> {
        let op = self.op.clone();
        let spawner = Arc::clone(&self.spawner);
        Box::pin(async move {
            check_results_len(&op, results_len, 1)?;
            // caller identity ALWAYS from the call frame, never a guest param
            // (mirrors `dispatch`'s preamble).
            let caller_id = ctx.agent_id.clone();
            cap_str(&op, &caller_id, MAX_AGENT_ID_BYTES)?;
            let v = dispatch_spawn(&op, spawner.as_ref(), &caller_id, &params)?;
            Ok(vec![v])
        })
    }
}

/// Register ONLY the 3 decomposition host-fns (`submit-decomposition` /
/// `update-subtask-status` / `get-decomposition`) over a [`DecompositionStore`] +
/// an [`EventBusEmit`], under the agent-lifecycle capability + namespace. The narrow
/// production entry point (Wave-12 Lane C): `cli::wire_capabilities` calls this over a
/// `DefaultDecompositionStore` sharing the assembler's `AgentTreeStore` + the shared
/// production `EventBus`, so a `submit-decomposition` / `update-subtask-status` records
/// state the MODULE-010 context-assembler's `# Active Task Decomposition` section reads,
/// and `update-subtask-status` genuinely emits `task.subtask_updated` (submit emits
/// `task.decomposed`) on the registered path — WITHOUT the full [`AgentLifecycleBundle`]
/// (terminate / checkpoint / rollback / spawn / stats need cross-module production
/// controllers that ship only as test stubs; wiring those is mainline). Per-op
/// idempotency matches the full bundle (submit / update = false, get = true), and all 3
/// reuse the SAME [`dispatch_decomposition`] the full [`register_agent_lifecycle`]
/// dispatch uses. Wave-23 `perchild-daemon-1` lifted `"lifecycle"` into cli
/// `KNOWN_CAPABILITIES` (a WHOLE-capability lift — a declaring guest links every
/// registered lifecycle op), but only the SPAWN leg is wired to the per-child
/// serve observer; the decomposition op names stay unexercised by shipped guests,
/// and a build-lane witness drives the registered handler directly.
///
/// Safe to call ALONGSIDE [`register_agent_spawn`] (disjoint op names). Do NOT call
/// this AND `register_agent_lifecycle` on the same registry — the decomposition ops
/// would be registered twice (production wires exactly one path).
pub fn register_agent_decomposition(
    registry: &dyn HostRegistry,
    store: Arc<dyn DecompositionStore>,
    event_bus: Arc<dyn EventBusEmit>,
) {
    let cap = AGENT_LIFECYCLE_CAPABILITY.to_string();
    let ns = AGENT_LIFECYCLE_NAMESPACE.to_string();
    for (name, idempotent) in [
        ("submit-decomposition", false),
        ("update-subtask-status", false),
        ("get-decomposition", true),
    ] {
        registry.register(HostFunctionSpec {
            capability: cap.clone(),
            namespace: ns.clone(),
            name: name.to_string(),
            handler: Arc::new(DecompositionHandler {
                op: name.to_string(),
                store: Arc::clone(&store),
                event_bus: Arc::clone(&event_bus),
            }),
            idempotent,
        });
    }
}

/// Register only CONTRACT-217's four component lifecycle operations. This is
/// safe beside [`register_agent_spawn`] and [`register_agent_decomposition`]
/// because their operation names are disjoint.
pub fn register_agent_component_submit(
    registry: &dyn HostRegistry,
    submit_gate: Arc<dyn ComponentSubmitGate>,
) {
    let cap = AGENT_LIFECYCLE_CAPABILITY.to_string();
    let ns = AGENT_LIFECYCLE_NAMESPACE.to_string();
    for (name, idempotent) in [
        ("submit-component", false),
        ("component-status", true),
        ("kill-component", false),
        ("list-components", true),
    ] {
        registry.register(HostFunctionSpec {
            capability: cap.clone(),
            namespace: ns.clone(),
            name: name.to_owned(),
            handler: Arc::new(ComponentSubmitHandler {
                op: name.to_owned(),
                submit_gate: Arc::clone(&submit_gate),
            }),
            idempotent,
        });
    }
}

struct ComponentSubmitHandler {
    op: String,
    submit_gate: Arc<dyn ComponentSubmitGate>,
}

impl HostFunctionHandler for ComponentSubmitHandler {
    fn call(
        &self,
        ctx: HostCallContext,
        params: Vec<Val>,
        results_len: usize,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<Val>, HostCallError>> + Send + 'static>> {
        let op = self.op.clone();
        let submit_gate = Arc::clone(&self.submit_gate);
        Box::pin(async move {
            check_results_len(&op, results_len, 1)?;
            let caller_id = ctx.agent_id;
            cap_str(&op, &caller_id, MAX_AGENT_ID_BYTES)?;
            let value =
                dispatch_component_submit(&op, submit_gate.as_ref(), &caller_id, &params).await?;
            Ok(vec![value])
        })
    }
}

/// Narrow decomposition-only handler (Wave-12 Lane C): dispatches
/// `submit-decomposition` / `update-subtask-status` / `get-decomposition` over a
/// [`DecompositionStore`] + [`EventBusEmit`] via the shared [`dispatch_decomposition`],
/// running the SAME `check_results_len` + caller `cap_str` preamble that `dispatch`
/// runs. Registered by [`register_agent_decomposition`]; carries NO full bundle.
struct DecompositionHandler {
    op: String,
    store: Arc<dyn DecompositionStore>,
    event_bus: Arc<dyn EventBusEmit>,
}

impl HostFunctionHandler for DecompositionHandler {
    fn call(
        &self,
        ctx: HostCallContext,
        params: Vec<Val>,
        results_len: usize,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<Val>, HostCallError>> + Send + 'static>> {
        let op = self.op.clone();
        let store = Arc::clone(&self.store);
        let event_bus = Arc::clone(&self.event_bus);
        Box::pin(async move {
            check_results_len(&op, results_len, 1)?;
            // caller identity ALWAYS from the call frame, never a guest param
            // (mirrors `dispatch`'s preamble).
            let caller_id = ctx.agent_id.clone();
            cap_str(&op, &caller_id, MAX_AGENT_ID_BYTES)?;
            let v = dispatch_decomposition(
                &op,
                store.as_ref(),
                event_bus.as_ref(),
                &caller_id,
                &params,
            )?;
            Ok(vec![v])
        })
    }
}

struct LifecycleHandler {
    op: String,
    b: Arc<AgentLifecycleBundle>,
}

impl HostFunctionHandler for LifecycleHandler {
    fn call(
        &self,
        ctx: HostCallContext,
        params: Vec<Val>,
        results_len: usize,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<Val>, HostCallError>> + Send + 'static>> {
        let op = self.op.clone();
        let b = Arc::clone(&self.b);
        // sync-in-async-pin: capture owned data, run the synchronous
        // controller call inside `async move` (cap-grant precedent).
        Box::pin(async move { dispatch(&op, &b, &ctx, &params, results_len).await })
    }
}

// ── Val helpers (cap-grant precedent) ──────────────────────────────────────

fn check_results_len(op: &str, got: usize, want: usize) -> Result<(), HostCallError> {
    if got == want {
        Ok(())
    } else {
        Err(HostCallError::HandlerError(format!(
            "{op}: expected results_len == {want}, got {got}"
        )))
    }
}

fn arg_str(params: &[Val], i: usize, op: &str) -> Result<String, HostCallError> {
    match params.get(i) {
        Some(Val::String(s)) => Ok(s.clone()),
        _ => Err(HostCallError::HandlerError(format!(
            "{op}: expected Val::String at param {i}"
        ))),
    }
}

fn arg_str_opt(params: &[Val], i: usize) -> Option<String> {
    match params.get(i) {
        Some(Val::String(s)) => Some(s.clone()),
        Some(Val::Option(Some(b))) => match b.as_ref() {
            Val::String(s) => Some(s.clone()),
            _ => None,
        },
        _ => None,
    }
}

fn ok_unit() -> Val {
    Val::Result(Ok(None))
}

fn ok_string(s: String) -> Val {
    Val::Result(Ok(Some(Box::new(Val::String(s)))))
}

/// Domain error → typed WIT variant `Val::Result(Err(variant(msg)))`.
fn err_variant(case: &str, msg: String) -> Val {
    Val::Result(Err(Some(Box::new(Val::Variant(
        case.to_string(),
        Some(Box::new(Val::String(msg))),
    )))))
}

/// Lower an `AgentStats` to the WIT `agent-stats` record
/// (`result<agent-stats, lifecycle-error>` ok-arm, CONTRACT-041).
/// Field names + order pinned to `wit/agent-lifecycle.wit` `record agent-stats`;
/// the wire-shape test in `tests/wit_impl.rs` locks this against silent reorder.
/// `last_active` is hard-truncated at 256 bytes — defense-in-depth behind the
/// `SqliteAgentStatsReader` 64-byte egress cap, so NO `AgentStatsReader` impl
/// can reflect an unbounded foreign string across the WIT boundary into a
/// guest (adversarial r12; UTF-8-safe boundary).
fn ok_agent_stats(mut s: AgentStats) -> Val {
    const MAX_LOWERED_LAST_ACTIVE_BYTES: usize = 256;
    if s.last_active.len() > MAX_LOWERED_LAST_ACTIVE_BYTES {
        let mut cut = MAX_LOWERED_LAST_ACTIVE_BYTES;
        while cut > 0 && !s.last_active.is_char_boundary(cut) {
            cut -= 1;
        }
        s.last_active.truncate(cut);
    }
    Val::Result(Ok(Some(Box::new(Val::Record(vec![
        ("active-tasks".to_string(), Val::U32(s.active_tasks)),
        ("completed-tasks".to_string(), Val::U32(s.completed_tasks)),
        (
            "avg-turns-per-task".to_string(),
            Val::Float32(s.avg_turns_per_task),
        ),
        (
            "avg-completion-time-hours".to_string(),
            Val::Float32(s.avg_completion_time_hours),
        ),
        ("memory-entries".to_string(), Val::U32(s.memory_entries)),
        ("llm-tokens-24h".to_string(), Val::U64(s.llm_tokens_24h)),
        ("error-count-24h".to_string(), Val::U32(s.error_count_24h)),
        ("last-active".to_string(), Val::String(s.last_active)),
    ])))))
}

fn cap_str(op: &str, s: &str, max: usize) -> Result<(), HostCallError> {
    if s.len() > max {
        return Err(HostCallError::HandlerError(format!(
            "{op}: argument exceeds {max}-byte cap (got {} bytes)",
            s.len()
        )));
    }
    Ok(())
}

// ── Capability lift (011, Wave-15 Lane E) ──────────────────────────────────

/// Lift a `list<cap-request>` (the WIT `child-agent-config.capabilities` /
/// `sub-agent-config.capabilities` field shape) into `Vec<Capability>`. Each item is
/// EITHER a real WIT `cap-request` record `Val::Record { capability: string, params: … }`
/// (a real wit-bindgen guest's shape) OR a bare `Val::String` capability id (the in-repo
/// host/test-harness convention) — mirroring `lift_agent_kind`/`lift_file_entries`'s
/// dual-shape acceptance, so a real guest's record IS faithfully lifted. Only the
/// capability `id` is lifted (cap-level); per-call PARAM narrowing stays L1-V2
/// (MODULE-013-AC-23 / MODULE-017-AC-23) — the recorded cap therefore carries empty
/// (`Null`) params, which the spawner's subset gate treats as a whole/narrower request
/// and bounds against the parent (never exceeding the parent's authority). Unknown shapes
/// are skipped.
fn lift_cap_request_list(v: Option<&Val>) -> Vec<Capability> {
    // Defense-in-depth bound on the lifted list (audit r1): cap allocation/clone work at
    // a fixed ceiling before the downstream `DefaultSpawner` `MAX_CAPABILITIES` /
    // `validate_capability_subset` `MAX_CAPABILITIES_PER_CALL` (64/256) fail-closed
    // rejections run. An over-long list is truncated here; the spawner still rejects it.
    const MAX_LIFTED_CAP_REQUESTS: usize = 256;
    // Defense-in-depth byte cap on each capability id (audit r3): a guest cap-request
    // carrying an over-long capability string is SKIPPED before it is cloned into a
    // `Capability` (and so never reaches the downstream subset-gate error formatter), so a
    // malformed/oversized id cannot drive resource amplification at the lift boundary. A
    // skipped cap fails closed — the spawner gate still validates the surviving caps.
    const MAX_CAP_ID_BYTES: usize = 256;
    let items = match v {
        Some(Val::List(items)) => items,
        _ => return Vec::new(),
    };
    let mut out = Vec::with_capacity(items.len().min(MAX_LIFTED_CAP_REQUESTS));
    for item in items.iter().take(MAX_LIFTED_CAP_REQUESTS) {
        let id: Option<&str> = match item {
            // Real WIT `cap-request` record: read the `capability` field (by reference, so
            // an over-long string is length-checked before any clone).
            Val::Record(fields) => fields.iter().find_map(|(k, val)| match (k.as_str(), val) {
                ("capability", Val::String(s)) => Some(s.as_str()),
                _ => None,
            }),
            // Harness convenience: a bare capability-id string.
            Val::String(s) => Some(s.as_str()),
            _ => None,
        };
        if let Some(id) = id.filter(|s| s.len() <= MAX_CAP_ID_BYTES) {
            out.push(Capability {
                id: CapabilityId::from(id),
                params: CapParams(serde_json::Value::Null),
            });
        }
    }
    out
}

/// Find a named field value in a WIT `Val::Record`'s field list.
fn record_field<'a>(fields: &'a [(String, Val)], name: &str) -> Option<&'a Val> {
    fields.iter().find(|(k, _)| k == name).map(|(_, v)| v)
}

/// Lossless WIT-value projection used only at the CONTRACT-217 boundary. WIT
/// variants use serde's externally-tagged enum shape, records preserve their
/// kebab-case field names, and options become JSON null/value. Unsupported
/// component-model resources/flags fail closed rather than being stringified.
fn val_to_json(value: &Val, depth: usize) -> Result<serde_json::Value, HostCallError> {
    const MAX_DEPTH: usize = 32;
    const MAX_NODES: usize = 16_384;
    if depth > MAX_DEPTH {
        return Err(HostCallError::HandlerError(
            "submit-component: value exceeds depth bound".to_owned(),
        ));
    }
    fn inner(
        value: &Val,
        depth: usize,
        nodes: &mut usize,
    ) -> Result<serde_json::Value, HostCallError> {
        *nodes = nodes.checked_add(1).ok_or_else(|| {
            HostCallError::HandlerError("submit-component: value node overflow".to_owned())
        })?;
        if *nodes > MAX_NODES || depth > MAX_DEPTH {
            return Err(HostCallError::HandlerError(
                "submit-component: value exceeds structural bounds".to_owned(),
            ));
        }
        Ok(match value {
            Val::Bool(value) => serde_json::Value::Bool(*value),
            Val::U8(value) => serde_json::json!(*value),
            Val::U16(value) => serde_json::json!(*value),
            Val::U32(value) => serde_json::json!(*value),
            Val::U64(value) => serde_json::json!(*value),
            Val::S8(value) => serde_json::json!(*value),
            Val::S16(value) => serde_json::json!(*value),
            Val::S32(value) => serde_json::json!(*value),
            Val::S64(value) => serde_json::json!(*value),
            Val::Float32(value) => serde_json::json!(*value),
            Val::Float64(value) => serde_json::json!(*value),
            Val::Char(value) => serde_json::Value::String(value.to_string()),
            Val::String(value) => serde_json::Value::String(value.clone()),
            Val::Option(None) => serde_json::Value::Null,
            Val::Option(Some(value)) => inner(value, depth + 1, nodes)?,
            Val::List(values) | Val::Tuple(values) => serde_json::Value::Array(
                values
                    .iter()
                    .map(|value| inner(value, depth + 1, nodes))
                    .collect::<Result<Vec<_>, _>>()?,
            ),
            Val::Record(fields) => {
                let mut object = serde_json::Map::new();
                for (name, value) in fields {
                    // The top-level `binary` field has its own explicit 256 MiB
                    // admission bound. Counting every byte as a structural node
                    // would accidentally impose the generic 16,384-node limit
                    // on otherwise valid components. Treat the byte vector as
                    // one bounded scalar carrier while still rejecting any
                    // non-u8 element before the canonical projection allocates.
                    let projected = if depth == 0 && name == "binary" {
                        match value {
                            Val::List(values) => {
                                if values.len() > MAX_SUBMIT_COMPONENT_BYTES {
                                    return Err(HostCallError::HandlerError(
                                        "submit-component: binary exceeds the admission bound"
                                            .to_owned(),
                                    ));
                                }
                                serde_json::Value::Array(
                                    values
                                        .iter()
                                        .map(|value| match value {
                                            Val::U8(byte) => Ok(serde_json::json!(*byte)),
                                            _ => Err(HostCallError::HandlerError(
                                                "submit-component: binary must be a list<u8>"
                                                    .to_owned(),
                                            )),
                                        })
                                        .collect::<Result<Vec<_>, _>>()?,
                                )
                            }
                            _ => inner(value, depth + 1, nodes)?,
                        }
                    } else {
                        inner(value, depth + 1, nodes)?
                    };
                    if object.insert(name.clone(), projected).is_some() {
                        return Err(HostCallError::HandlerError(
                            "submit-component: duplicate record field".to_owned(),
                        ));
                    }
                }
                serde_json::Value::Object(object)
            }
            Val::Variant(tag, None) | Val::Enum(tag) => serde_json::Value::String(tag.clone()),
            Val::Variant(tag, Some(payload)) => {
                let mut object = serde_json::Map::new();
                object.insert(tag.clone(), inner(payload, depth + 1, nodes)?);
                serde_json::Value::Object(object)
            }
            _ => {
                return Err(HostCallError::HandlerError(
                    "submit-component: unsupported component value".to_owned(),
                ))
            }
        })
    }
    let mut nodes = 0;
    inner(value, depth, &mut nodes)
}

fn lift_component_submit_v2(params: &[Val]) -> Result<ComponentSubmitConfigV2, HostCallError> {
    if params.len() != 1 {
        return Err(HostCallError::HandlerError(
            "submit-component: expected one component-submit-config record".to_owned(),
        ));
    }
    let canonical = val_to_json(&params[0], 0)?;
    if canonical
        .get("binary")
        .and_then(serde_json::Value::as_array)
        .is_some_and(|bytes| bytes.len() > MAX_SUBMIT_COMPONENT_BYTES)
    {
        return Err(HostCallError::HandlerError(
            "submit-component: binary exceeds the admission bound".to_owned(),
        ));
    }
    ComponentSubmitConfigV2::from_canonical_json(canonical)
        .map_err(|error| HostCallError::HandlerError(format!("submit-component: {error}")))
}

/// Read an `option<string>` field by name from a WIT `Val::Record`'s field list.
/// Accepts both `Val::Option(Some(String))` (real wit-bindgen) and a bare `Val::String`
/// (harness shape); absent / wrong-shape → `None`.
fn record_opt_str(fields: &[(String, Val)], name: &str) -> Option<String> {
    match record_field(fields, name)? {
        Val::String(s) => Some(s.clone()),
        Val::Option(Some(b)) => match b.as_ref() {
            Val::String(s) => Some(s.clone()),
            _ => None,
        },
        _ => None,
    }
}

/// Wave-23 seam (a): read a `list<u8>` field by name from a WIT `Val::Record` as
/// `Vec<u8>` (each element a `Val::U8`). Absent / wrong-shape / empty → `None`
/// (an empty binary is treated as "no driver" by `spawn_child`). Non-U8 elements
/// are skipped (the spawn materializer re-validates wasm magic + size).
fn record_bytes(fields: &[(String, Val)], name: &str) -> Option<Vec<u8>> {
    match record_field(fields, name)? {
        Val::List(items) => {
            let bytes: Vec<u8> = items
                .iter()
                .filter_map(|b| match b {
                    Val::U8(n) => Some(*n),
                    _ => None,
                })
                .collect();
            if bytes.is_empty() {
                None
            } else {
                Some(bytes)
            }
        }
        _ => None,
    }
}

// ── SpawnError / LifecycleError → WIT (§2.8 taxonomy) ──────────────────────

fn lower_spawn_err(e: SpawnError) -> Val {
    match e {
        SpawnError::SubsetViolation(m) => err_variant("subset-violation", m),
        SpawnError::AlreadyExists(m) => err_variant("already-exists", m),
        SpawnError::TreeStateInvalid(m) => {
            // capacity-cap message → resource-limit; else already-exists/
            // invalid-config bucket. Keep it simple + truthful: a
            // tree-state failure that is not a dup is a config-class fault.
            if m.contains("MAX_AGENTS_PER_STORE") {
                err_variant("resource-limit", m)
            } else {
                err_variant("invalid-config", m)
            }
        }
        SpawnError::InvalidConfig(m)
        | SpawnError::ParentNotFound(m)
        | SpawnError::PathTraversal(m) => err_variant("invalid-config", m),
        // infra: spawn-error has a neutral-ish bucket → opaque typed.
        SpawnError::WorkspaceIoFailure(_) => {
            err_variant("invalid-config", "internal-error".to_string())
        }
    }
}

fn lower_lifecycle_err(e: LifecycleError) -> Val {
    match e {
        LifecycleError::NotFound(m) => err_variant("not-found", m),
        LifecycleError::PermissionDenied(m) => err_variant("permission-denied", m),
        LifecycleError::InvalidTarget(m)
        | LifecycleError::RollbackGate(m)
        | LifecycleError::CascadePartial(m) => err_variant("invalid-state", m),
        // infra: lifecycle-error has `invalid-state` neutral bucket.
        LifecycleError::IoFailure(_) => err_variant("invalid-state", "internal-error".to_string()),
    }
}

/// decomposition-error: 7 domain variants → typed. ParseError/IoFailure/
/// InvalidConfig (infra) have NO neutral variant → host trap (truthful;
/// never a false `task-not-found` domain lie). §2.8 R4-C2.
fn lower_decomposition(e: DecompositionError) -> Result<Val, HostCallError> {
    Ok(match e {
        DecompositionError::TaskNotFound(m) => err_variant("task-not-found", m),
        DecompositionError::SubtaskNotFound(m) => err_variant("subtask-not-found", m),
        DecompositionError::DuplicateTitle(m) => err_variant("duplicate-title", m),
        DecompositionError::DuplicateExistingId(m) => err_variant("duplicate-existing-id", m),
        DecompositionError::DependencyCycle(m) => err_variant("dependency-cycle", m),
        DecompositionError::UnresolvedDependency(m) => err_variant("unresolved-dependency", m),
        DecompositionError::PermissionDenied(m) => err_variant("permission-denied", m),
        DecompositionError::ParseError(_)
        | DecompositionError::IoFailure(_)
        | DecompositionError::InvalidConfig(_) => {
            return Err(HostCallError::HandlerError(
                "decomposition: internal-error".to_string(),
            ));
        }
    })
}

/// Lower a `DecompositionState` to the WIT `decomposition-state` record
/// (agent-lifecycle.wit:149-153): `{ goal, strategy, subtasks }`. Kebab field
/// names match the WIT. This is the read-back surface SYS-AC-171 requires — a
/// `update-subtask-status` mutation is observable through `get-decomposition`'s
/// projected `subtasks` (was goal-only). Mirrors the `self-stats`→`agent-stats`
/// record lowering precedent.
fn lower_decomposition_state(st: DecompositionState) -> Val {
    Val::Record(vec![
        ("goal".to_string(), Val::String(st.goal)),
        (
            "strategy".to_string(),
            lower_decomposition_strategy(st.strategy),
        ),
        (
            "subtasks".to_string(),
            Val::List(st.subtasks.into_iter().map(lower_subtask_state).collect()),
        ),
    ])
}

/// Lower a `SubtaskState` to the WIT `subtask-state` record
/// (agent-lifecycle.wit:154-162) — all 7 fields, kebab names; `outcome` is an
/// `option<string>` → `Val::Option`.
fn lower_subtask_state(s: SubtaskState) -> Val {
    Val::Record(vec![
        ("subtask-id".to_string(), Val::String(s.subtask_id)),
        ("title".to_string(), Val::String(s.title)),
        ("assignee".to_string(), Val::String(s.assignee)),
        (
            "depends-on".to_string(),
            Val::List(s.depends_on.into_iter().map(Val::String).collect()),
        ),
        ("status".to_string(), lower_subtask_status(s.status)),
        (
            "outcome".to_string(),
            Val::Option(s.outcome.map(|o| Box::new(Val::String(o)))),
        ),
        ("orphaned".to_string(), Val::Bool(s.orphaned)),
    ])
}

/// Lower a `SubtaskStatus` to the payload-less WIT `subtask-status` variant
/// (agent-lifecycle.wit:148) — kebab tags matching the WIT case names.
fn lower_subtask_status(s: SubtaskStatus) -> Val {
    let tag = match s {
        SubtaskStatus::Pending => "pending",
        SubtaskStatus::InProgress => "in-progress",
        SubtaskStatus::Completed => "completed",
        SubtaskStatus::Failed => "failed",
        SubtaskStatus::Skipped => "skipped",
    };
    Val::Variant(tag.to_string(), None)
}

/// Lower a `DecompositionStrategy` to the WIT `decomposition-strategy` variant
/// (agent-lifecycle.wit:128-137). `delegate-single` is PAYLOAD-BEARING: it
/// carries a nested `delegation-target` record `{assignee, template-ref, prompt}`
/// where `template-ref` is `option<string>` → `Val::Option`. `self-execute` /
/// `decompose` are payload-less. NOTE: distinct from `events.rs::strategy_tag`,
/// which is label-only (drops the payload) for event JSON — this is the WIT-faithful
/// lowering for the `get-decomposition` read-back.
fn lower_decomposition_strategy(s: DecompositionStrategy) -> Val {
    match s {
        DecompositionStrategy::SelfExecute => Val::Variant("self-execute".to_string(), None),
        DecompositionStrategy::Decompose => Val::Variant("decompose".to_string(), None),
        DecompositionStrategy::DelegateSingle(t) => {
            let DelegationTarget {
                assignee,
                template_ref,
                prompt,
            } = t;
            Val::Variant(
                "delegate-single".to_string(),
                Some(Box::new(Val::Record(vec![
                    ("assignee".to_string(), Val::String(assignee)),
                    (
                        "template-ref".to_string(),
                        Val::Option(template_ref.map(|r| Box::new(Val::String(r)))),
                    ),
                    ("prompt".to_string(), Val::String(prompt)),
                ]))),
            )
        }
    }
}

/// MODULE-005-AC-28 — emit `lifecycle.terminate_child` / `terminate_agent`
/// after a successful terminate op. The cascade set is the **target's own
/// pre-snapshot subtree, intersected with the nodes actually removed**: the
/// descendants of `target_id` are computed from the pre-call snapshot's
/// `children_of` (a bounded BFS), then a cascade event is emitted for each
/// descendant absent from the post-call snapshot. Scoping the diff to the
/// target's subtree — rather than diffing the whole tree — keeps a concurrent
/// terminate on a DIFFERENT subtree from polluting this op's event set
/// (no cross-initiator over-attribution, no audit gap from another op's
/// removals). Exact for the quiescent case; the residual concurrent-spawn
/// *under the target* attribution caveat is documented in MODULE-005 §3.6.
/// Target event first (`terminate-child` → `lifecycle.terminate_child`;
/// `terminate-agent` → `lifecycle.terminate_agent`), then one cascade
/// `lifecycle.terminate_agent` per removed descendant, in pre-snapshot
/// (insertion) order. Kinds come from the pre-call snapshot.
fn emit_terminate_events(
    b: &AgentLifecycleBundle,
    initiator: &str,
    target_id: &str,
    pre: &AgentTreeSnapshotData,
    target_reason: &str,
    root_is_child_event: bool,
) {
    let post = b.tree.snapshot();
    let post_ids: std::collections::HashSet<&str> =
        post.nodes.iter().map(|n| n.id.0.as_str()).collect();

    if root_is_child_event {
        b.event_bus
            .emit(crate::events::lifecycle_terminate_child_event(
                initiator,
                target_id,
                target_reason,
            ));
    } else {
        let kind = pre
            .nodes
            .iter()
            .find(|n| n.id.0 == target_id)
            .map(|n| n.kind.clone())
            .unwrap_or(AgentKind::Child);
        b.event_bus
            .emit(crate::events::lifecycle_terminate_agent_event(
                initiator,
                target_id,
                &kind,
                target_reason,
            ));
    }

    // Descendants of target_id from the PRE snapshot (BFS over children_of).
    // The frontier is bounded by the snapshot's node count, so a cycle in a
    // corrupt snapshot cannot loop forever (a visited set guards it anyway).
    let mut descendants: Vec<&AgentId> = Vec::new();
    let mut seen: std::collections::HashSet<&str> = std::collections::HashSet::new();
    let mut frontier: Vec<&str> = pre
        .children_of
        .get(&AgentId(target_id.to_string()))
        .map(|kids| kids.iter().map(|k| k.0.as_str()).collect())
        .unwrap_or_default();
    while let Some(id) = frontier.pop() {
        if !seen.insert(id) {
            continue;
        }
        if let Some(node) = pre.nodes.iter().find(|n| n.id.0 == id) {
            descendants.push(&node.id);
        }
        if let Some(kids) = pre.children_of.get(&AgentId(id.to_string())) {
            frontier.extend(kids.iter().map(|k| k.0.as_str()));
        }
    }

    // Emit cascade events in pre-snapshot (insertion) order, for descendants
    // actually removed by THIS op (absent from post).
    for n in pre.nodes.iter() {
        if descendants.iter().any(|d| d.0 == n.id.0) && !post_ids.contains(n.id.0.as_str()) {
            b.event_bus
                .emit(crate::events::lifecycle_terminate_agent_event(
                    initiator,
                    &n.id.0,
                    &n.kind,
                    crate::events::TERMINATE_REASON_CASCADE,
                ));
        }
    }
}

// ── Dispatch ───────────────────────────────────────────────────────────────

async fn dispatch(
    op: &str,
    b: &AgentLifecycleBundle,
    ctx: &HostCallContext,
    params: &[Val],
    results_len: usize,
) -> Result<Vec<Val>, HostCallError> {
    check_results_len(op, results_len, 1)?;
    // caller identity ALWAYS from the call frame, never a guest param.
    let caller_id = ctx.agent_id.clone();
    cap_str(op, &caller_id, MAX_AGENT_ID_BYTES)?;

    let v: Val = match op {
        // 011 (Wave-11 Lane B): the 3 spawn arms are extracted into the shared
        // `dispatch_spawn` so the narrow production `register_agent_spawn`
        // (spawn-only, no full `AgentLifecycleBundle`) reuses the EXACT same
        // dispatch. Behaviour is byte-identical to the prior inline arms. The
        // preamble (`check_results_len` + caller `cap_str`, above) is NOT re-run
        // inside `dispatch_spawn` — each caller (this `dispatch` and the new
        // `SpawnHandler`) owns it.
        "spawn-child" | "spawn-sub" | "spawn-agent-from-template" => {
            dispatch_spawn(op, b.spawner.as_ref(), &caller_id, params)?
        }
        "list-agent-templates" => {
            let names = b.templates.list();
            Val::Result(Ok(Some(Box::new(Val::List(
                names.into_iter().map(Val::String).collect(),
            )))))
        }
        "init-child-workspace" => {
            let child_id = arg_str(params, 0, op)?;
            cap_str(op, &child_id, MAX_AGENT_ID_BYTES)?;
            // Lift the `list<file-entry>` payload (param 1). Wire shape:
            // a list of Val::Record-shaped `{path, bytes}` OR, for the
            // test/host harness, Val::String "path\0<utf8 bytes>".
            let files = lift_file_entries(params, 1);
            // `caller_id` from `ctx.agent_id` (never a guest param) — the
            // helper enforces parent-of(child)==caller (PRD §1.2; matches
            // the discipline of every other `child-*` operation).
            match crate::workspace::init_child_workspace_files(
                &b.tree, &caller_id, &child_id, &files,
            ) {
                Ok(()) => ok_unit(),
                Err(e) => lower_lifecycle_err(e),
            }
        }
        "rollback-child" => {
            let child_id = arg_str(params, 0, op)?;
            let version = arg_str(params, 1, op)?;
            cap_str(op, &child_id, MAX_AGENT_ID_BYTES)?;
            cap_str(op, &version, MAX_TARGET_BYTES)?;
            match b.rollback.rollback_child(
                &AgentId(caller_id.clone()),
                &AgentId(child_id),
                version,
            ) {
                Ok(_) => ok_unit(),
                Err(e) => lower_lifecycle_err(e),
            }
        }
        "rollback-child-to-checkpoint" => {
            let child_id = arg_str(params, 0, op)?;
            let label = arg_str(params, 1, op)?;
            cap_str(op, &child_id, MAX_AGENT_ID_BYTES)?;
            cap_str(op, &label, MAX_LABEL_BYTES)?;
            match b.rollback.rollback_child_to_checkpoint(
                &AgentId(caller_id.clone()),
                &AgentId(child_id),
                label,
            ) {
                Ok(_) => ok_unit(),
                Err(e) => lower_lifecycle_err(e),
            }
        }
        "terminate-child" => {
            let child_id = arg_str(params, 0, op)?;
            cap_str(op, &child_id, MAX_AGENT_ID_BYTES)?;
            // MODULE-005-AC-28: pre-call snapshot for removed-set attribution
            // (whole-tree diff; exact for the quiescent case — §3.6 caveat).
            let pre = b.tree.snapshot();
            match b.terminate.terminate_child(&caller_id, &child_id) {
                Ok(()) => {
                    emit_terminate_events(
                        &b,
                        &caller_id,
                        &child_id,
                        &pre,
                        crate::events::TERMINATE_REASON_CHILD,
                        /* root_is_child_event */ true,
                    );
                    ok_unit()
                }
                Err(e) => lower_lifecycle_err(e),
            }
        }
        "terminate-agent" => {
            let agent_id = arg_str(params, 0, op)?;
            cap_str(op, &agent_id, MAX_AGENT_ID_BYTES)?;
            let pre = b.tree.snapshot();
            match b.terminate.terminate_agent(&caller_id, &agent_id) {
                Ok(()) => {
                    emit_terminate_events(
                        &b,
                        &caller_id,
                        &agent_id,
                        &pre,
                        crate::events::TERMINATE_REASON_AGENT,
                        /* root_is_child_event */ false,
                    );
                    ok_unit()
                }
                Err(e) => lower_lifecycle_err(e),
            }
        }
        "checkpoint" => {
            let label = arg_str(params, 0, op)?;
            cap_str(op, &label, MAX_LABEL_BYTES)?;
            match b.checkpoint.checkpoint(&caller_id, &label, None) {
                Ok(()) => ok_unit(),
                Err(e) => lower_lifecycle_err(e),
            }
        }
        "rollback-to-checkpoint" => {
            let label = arg_str(params, 0, op)?;
            cap_str(op, &label, MAX_LABEL_BYTES)?;
            match b.checkpoint.rollback_to_checkpoint(&caller_id, &label) {
                Ok(_) => ok_unit(),
                Err(e) => lower_lifecycle_err(e),
            }
        }
        "list-checkpoints" => match b.checkpoint.list_checkpoints(&caller_id) {
            Ok(v) => Val::Result(Ok(Some(Box::new(Val::List(
                v.into_iter().map(|c| Val::String(c.label)).collect(),
            ))))),
            Err(e) => lower_lifecycle_err(e),
        },
        "list-child-checkpoints" => {
            let child_id = arg_str(params, 0, op)?;
            cap_str(op, &child_id, MAX_AGENT_ID_BYTES)?;
            match b.checkpoint.list_child_checkpoints(&caller_id, &child_id) {
                Ok(v) => Val::Result(Ok(Some(Box::new(Val::List(
                    v.into_iter().map(|c| Val::String(c.label)).collect(),
                ))))),
                Err(e) => lower_lifecycle_err(e),
            }
        }
        // self-stats/child-stats lower the FULL `agent-stats` record per the
        // declared `result<agent-stats, lifecycle-error>` (CONTRACT-041).
        // Pre-harvest-obs these arms lowered only `ok_string(last_active)`,
        // dropping 7 computed fields at the WIT boundary (wire-shape bug,
        // fixed 2026-06-10; see MODULE-005 §3.7).
        "self-stats" => match b.stats.self_stats(&caller_id) {
            Ok(s) => ok_agent_stats(s),
            Err(e) => lower_lifecycle_err(e),
        },
        "child-stats" => {
            let child_id = arg_str(params, 0, op)?;
            cap_str(op, &child_id, MAX_AGENT_ID_BYTES)?;
            match b.stats.child_stats(&caller_id, &child_id) {
                Ok(s) => ok_agent_stats(s),
                Err(e) => lower_lifecycle_err(e),
            }
        }
        "submit-component" | "component-status" | "kill-component" | "list-components" => {
            dispatch_component_submit(op, b.submit_gate.as_ref(), &caller_id, params).await?
        }
        // Wave-12 Lane C: the 3 decomposition arms are extracted into the shared
        // `dispatch_decomposition` so the narrow production
        // `register_agent_decomposition` (decomposition-only, no full
        // `AgentLifecycleBundle`) reuses the EXACT same dispatch. Behaviour is
        // byte-identical to the prior inline arms. The preamble
        // (`check_results_len` + caller `cap_str`, above) is NOT re-run inside
        // `dispatch_decomposition` — each caller (this `dispatch` and the new
        // `DecompositionHandler`) owns it. Mirrors the 011 `dispatch_spawn` split.
        "submit-decomposition" | "update-subtask-status" | "get-decomposition" => {
            dispatch_decomposition(
                op,
                b.decomposition.as_ref(),
                b.event_bus.as_ref(),
                &caller_id,
                params,
            )?
        }
        other => {
            return Err(HostCallError::HandlerError(format!(
                "unknown agent-lifecycle op: {other}"
            )));
        }
    };
    Ok(vec![v])
}

async fn dispatch_component_submit(
    op: &str,
    submit_gate: &dyn ComponentSubmitGate,
    caller_id: &str,
    params: &[Val],
) -> Result<Val, HostCallError> {
    Ok(match op {
        "submit-component" => {
            let config = lift_component_submit_v2(params)?;
            match submit_gate.submit_component_v2(caller_id, config).await {
                Ok(cid) => ok_string(cid.0),
                Err(error) => lower_spawn_err(error),
            }
        }
        "component-status" => {
            let id = arg_str(params, 0, op)?;
            cap_str(op, &id, MAX_TARGET_BYTES)?;
            match submit_gate.component_status(&id).await {
                Ok(_) => ok_unit(),
                Err(error) => lower_spawn_err(error),
            }
        }
        "kill-component" => {
            let id = arg_str(params, 0, op)?;
            cap_str(op, &id, MAX_TARGET_BYTES)?;
            match submit_gate.kill_component(&id).await {
                Ok(()) => ok_unit(),
                Err(error) => lower_spawn_err(error),
            }
        }
        "list-components" => {
            let infos = submit_gate.list_components().await;
            Val::Result(Ok(Some(Box::new(Val::List(
                infos
                    .into_iter()
                    .map(|info| Val::String(info.id.0))
                    .collect(),
            )))))
        }
        _ => {
            return Err(HostCallError::HandlerError(format!(
                "unknown component lifecycle op: {op}"
            )))
        }
    })
}

/// Shared decomposition dispatch for `submit-decomposition` /
/// `update-subtask-status` / `get-decomposition` (Wave-12 Lane C). Extracted
/// byte-identically from the prior inline `dispatch` arms so BOTH the full
/// `register_agent_lifecycle` dispatch AND the narrow `register_agent_decomposition`
/// `DecompositionHandler` share ONE code path. Callers run the `check_results_len`
/// + caller `cap_str(MAX_AGENT_ID_BYTES)` preamble themselves (this fn does NOT, to
/// avoid double-application). `caller_id` is the validated `ctx.agent_id`. The emit
/// side-effects (`task.decomposed` on submit / `task.subtask_updated` on update,
/// each gated on `Ok`) go to the injected `event_bus`. A non-decomposition `op` is a
/// handler bug → host trap. Mirrors the 011 `dispatch_spawn` split.
fn dispatch_decomposition(
    op: &str,
    store: &dyn DecompositionStore,
    event_bus: &dyn EventBusEmit,
    caller_id: &str,
    params: &[Val],
) -> Result<Val, HostCallError> {
    let v: Val = match op {
        "submit-decomposition" => {
            let task_id = arg_str(params, 0, op)?;
            cap_str(op, &task_id, MAX_CONFIG_BYTES)?;
            let plan = lift_decomposition_plan(params, op)?;
            // Capture observability fields BEFORE `plan` is moved into submit.
            // `subtask_count` == the receipt length for a fresh plan: every
            // submitted subtask is non-orphaned (orphans are carried over from
            // a PRIOR plan and excluded from the receipt), so the count stays
            // consistent with the returned mapping.
            let subtask_count = plan.subtasks.len();
            let strategy = plan.strategy.clone();
            // First-seen-order dedup of assignees for the event payload, done
            // in O(n) via a HashSet (NOT an O(n²) linear scan) and ONLY when
            // the plan is within the subtask cap. An over-cap plan does no
            // per-element work here — `submit()` rejects it and the emit below
            // (gated on `Ok`) never runs, so the empty placeholder is never
            // emitted. Closes the adversarial-round-6 pre-submit
            // CPU-amplification surface (a huge `Val::List` would otherwise burn
            // O(n²) before the count cap fired).
            let assignees: Vec<String> =
                if subtask_count <= crate::decomposition::MAX_DECOMPOSITION_SUBTASKS {
                    let mut seen = std::collections::HashSet::new();
                    plan.subtasks
                        .iter()
                        .filter(|st| seen.insert(st.assignee.as_str()))
                        .map(|st| st.assignee.clone())
                        .collect()
                } else {
                    Vec::new()
                };
            match store.submit(caller_id, &task_id, plan) {
                Ok(r) => {
                    // task.decomposed emitted ONLY on success.
                    event_bus.emit(crate::events::task_decomposed_event(
                        caller_id,
                        &task_id,
                        &strategy,
                        subtask_count,
                        &assignees,
                    ));
                    Val::Result(Ok(Some(Box::new(Val::List(
                        r.subtask_ids
                            .into_iter()
                            .map(|m| Val::String(format!("{}={}", m.title, m.subtask_id)))
                            .collect(),
                    )))))
                }
                Err(e) => lower_decomposition(e)?,
            }
        }
        "update-subtask-status" => {
            let task_id = arg_str(params, 0, op)?;
            let subtask_id = arg_str(params, 1, op)?;
            let status = lift_subtask_status(params, 2, op)?;
            cap_str(op, &task_id, MAX_CONFIG_BYTES)?;
            cap_str(op, &subtask_id, MAX_TARGET_BYTES)?;
            match store.update_subtask_status(
                caller_id,
                &task_id,
                &subtask_id,
                status,
                arg_str_opt(params, 3),
            ) {
                Ok(old_status) => {
                    // task.subtask_updated emitted ONLY on success; `status`
                    // is `Copy`, so it is still usable as the new status here.
                    event_bus.emit(crate::events::task_subtask_updated_event(
                        caller_id,
                        &task_id,
                        &subtask_id,
                        old_status,
                        status,
                    ));
                    ok_unit()
                }
                Err(e) => lower_decomposition(e)?,
            }
        }
        "get-decomposition" => {
            let task_id = arg_str(params, 0, op)?;
            cap_str(op, &task_id, MAX_CONFIG_BYTES)?;
            match store.get(caller_id, &task_id) {
                // Project the FULL `option<decomposition-state>` per the WIT
                // (agent-lifecycle.wit:149-162) — goal + strategy + subtasks WITH
                // status/outcome — so a `update-subtask-status` mutation is observable
                // through the WIT read-back (SYS-AC-171). Was goal-only `Val::String`.
                Ok(Some(st)) => Val::Result(Ok(Some(Box::new(Val::Option(Some(Box::new(
                    lower_decomposition_state(st),
                ))))))),
                Ok(None) => Val::Result(Ok(Some(Box::new(Val::Option(None))))),
                Err(e) => lower_decomposition(e)?,
            }
        }
        other => {
            return Err(HostCallError::HandlerError(format!(
                "dispatch_decomposition: non-decomposition op {other}"
            )));
        }
    };
    Ok(v)
}

/// Shared spawn dispatch for `spawn-child` / `spawn-sub` /
/// `spawn-agent-from-template` (011, Wave-11 Lane B). Extracted byte-identically
/// from the prior inline `dispatch` arms so BOTH the full `register_agent_lifecycle`
/// dispatch AND the narrow `register_agent_spawn` `SpawnHandler` share ONE code
/// path. Callers run the `check_results_len` + caller `cap_str(MAX_AGENT_ID_BYTES)`
/// preamble themselves (this fn does NOT, to avoid double-application). `caller_id`
/// is the validated `ctx.agent_id`. spawn-child / spawn-sub LIFT the requested
/// `cap-request` capabilities (011, Wave-15 Lane E — spawn-sub decodes the real
/// top-level `sub-agent-config` record, spawn-child reads the positional cap list at
/// param 2), so the spawner's subset gate validates them against the parent's held
/// caps; spawn-agent-from-template keeps empty caps (template-sourced). A non-spawn
/// `op` is a handler bug → host trap.
fn dispatch_spawn(
    op: &str,
    spawner: &dyn Spawner,
    caller_id: &str,
    params: &[Val],
) -> Result<Val, HostCallError> {
    let v: Val = match op {
        "spawn-child" => {
            // AC-06 subset enforcement is performed by `DefaultSpawner.subset_gate`
            // (production callers wire `CapGrantSubsetAdapter` from
            // `cap_grant_adapter.rs`). The requested capabilities are lifted from the
            // `cap-request` list at param 2 (011, Wave-15 Lane E — cap-level; per-call
            // PARAM narrowing stays L1-V2) and threaded into the recorded node; the
            // subset gate validates them against the parent's held caps (a child may
            // not request more than the parent holds). Wave-23 `perchild-daemon-1`:
            // decode the REAL top-level `child-agent-config` `Val::Record` (a
            // wit-bindgen guest's shape) — reading `id` + `capabilities` + `binary`
            // (the child's driver bytes, materialized so the daemon serves it live) —
            // else fall back to the in-repo POSITIONAL convention (param0 = id,
            // param1 = ws?, param2 = caps) so existing callers (spawn_wiring_011) stay
            // unchanged. `child-agent-config` carries no workspace-path field, so the
            // record shape defaults the workspace to the child id (== positional
            // default). CONTRACT-041 WIT is byte-unchanged (the record was already
            // declared); this conforms the host handler to it.
            let (child_id, ws_opt, capabilities, binary) = match params.first() {
                Some(Val::Record(fields)) => (
                    record_opt_str(fields, "id").unwrap_or_default(),
                    None,
                    lift_cap_request_list(record_field(fields, "capabilities")),
                    record_bytes(fields, "binary"),
                ),
                _ => (
                    arg_str(params, 0, op)?,
                    arg_str_opt(params, 1),
                    lift_cap_request_list(params.get(2)),
                    None,
                ),
            };
            cap_str(op, &child_id, MAX_AGENT_ID_BYTES)?;
            let ws = ws_opt.unwrap_or_else(|| child_id.clone());
            match spawner.spawn_child(SpawnChildConfig {
                parent_id: AgentId(caller_id.to_string()),
                child_id: AgentId(child_id),
                child_workspace_path: PathBuf::from(ws),
                capabilities,
                template_ref: None,
                binary,
            }) {
                Ok(id) => ok_string(id.0),
                Err(e) => lower_spawn_err(e),
            }
        }
        "spawn-sub" => {
            // The WIT is `spawn-sub(config: sub-agent-config)` whose `capabilities:
            // list<cap-request>` + `template-ref: option<string>` are RECORD fields.
            // Decode that REAL top-level record when params[0] is a `Val::Record` (a
            // real wit-bindgen guest's shape — faithfully lifts the requested caps),
            // else fall back to the in-repo positional convention (param0 = template-ref,
            // param1 = caps) so existing `vec![]` / positional callers stay unchanged
            // (011, Wave-15 Lane E). The recorded caps must subset the parent's (gate).
            let (capabilities, template_ref) = match params.first() {
                Some(Val::Record(fields)) => (
                    lift_cap_request_list(record_field(fields, "capabilities")),
                    record_opt_str(fields, "template-ref"),
                ),
                _ => (lift_cap_request_list(params.get(1)), arg_str_opt(params, 0)),
            };
            match spawner.spawn_sub(SpawnSubConfig {
                parent_id: AgentId(caller_id.to_string()),
                capabilities,
                template_ref,
            }) {
                Ok(id) => ok_string(id.0),
                Err(e) => lower_spawn_err(e),
            }
        }
        "spawn-agent-from-template" => {
            // Honor the `agent-kind` discriminator: param indices are
            // kind=0, template-ref=1, target-path=2, overrides=3 (CONTRACT-041
            // WIT signature). Resolution flows solely through the spawner's
            // resolver — the single source that also materializes — so an
            // unknown template / unconfigured resolver surfaces as
            // spawn-error::invalid-config via spawn_child/spawn_sub. Param 3
            // (overrides) is not handled this slice. (sat/template-materialization)
            let kind = lift_agent_kind(params, 0, op)?;
            let template_ref = arg_str(params, 1, op)?;
            cap_str(op, &template_ref, MAX_TARGET_BYTES)?;
            let target_path = arg_str_opt(params, 2);
            match kind {
                AgentKind::Child => match target_path {
                    Some(tp) => {
                        cap_str(op, &tp, MAX_TARGET_BYTES)?;
                        // The WIT signature carries no child-id, so derive it
                        // from the target-path leaf. A None leaf (trailing
                        // slash / `.` / `..` / empty) → invalid-config; an
                        // out-of-charset leaf is rejected by spawn_child's own
                        // validate_agent_id; the Sub-cannot-nest + `.sub`/`.agent`
                        // territory guards are inherited from spawn_child.
                        match Path::new(&tp).file_name().and_then(|s| s.to_str()) {
                            Some(child_id) => match spawner.spawn_child(SpawnChildConfig {
                                parent_id: AgentId(caller_id.to_string()),
                                child_id: AgentId(child_id.to_string()),
                                child_workspace_path: PathBuf::from(&tp),
                                capabilities: Vec::new(),
                                template_ref: Some(template_ref),
                                // spawn-agent-from-template materializes the driver
                                // from the resolved template, not an inline binary.
                                binary: None,
                            }) {
                                Ok(id) => ok_string(id.0),
                                Err(e) => lower_spawn_err(e),
                            },
                            None => err_variant(
                                "invalid-config",
                                "spawn-agent-from-template kind=child: target-path has no final component".to_string(),
                            ),
                        }
                    }
                    None => err_variant(
                        "invalid-config",
                        "spawn-agent-from-template kind=child requires target-path".to_string(),
                    ),
                },
                AgentKind::Sub => match spawner.spawn_sub(SpawnSubConfig {
                    parent_id: AgentId(caller_id.to_string()),
                    capabilities: Vec::new(),
                    template_ref: Some(template_ref),
                }) {
                    Ok(id) => ok_string(id.0),
                    Err(e) => lower_spawn_err(e),
                },
                // Unreachable: lift_agent_kind only yields Sub|Child (the WIT
                // agent-kind variant is `{sub, child}`). Defensive host trap,
                // never a panic in the host path.
                AgentKind::Root => {
                    return Err(HostCallError::HandlerError(format!(
                        "{op}: agent-kind cannot be root"
                    )))
                }
            }
        }
        other => {
            return Err(HostCallError::HandlerError(format!(
                "dispatch_spawn: not a spawn op: {other}"
            )))
        }
    };
    Ok(v)
}

/// Lift a `decomposition-plan` record. Malformed shape → call-shape
/// `HandlerError` (taxonomy category 1; this is where the reconciled-away
/// `invalid-strategy` lands).
fn lift_decomposition_plan(params: &[Val], op: &str) -> Result<DecompositionPlan, HostCallError> {
    // Wire shape (test-facing minimal): param1 = goal, param2 = strategy tag
    // ("self-execute"|"decompose"|"delegate-single"), param3 = list of
    // "title|assignee|prompt|dep1,dep2,...|existing-id" subtask descriptors. The
    // 4th `|`-field is OPTIONAL (a comma-separated list of dependency TITLES the
    // store resolves to subtask-ids); the 5th `|`-field is OPTIONAL (the
    // `existing-id` continuity field — a carried `st-<uuid>` preserves the subtask
    // across re-submits, SYS-AC-171; empty/absent → minted fresh). `splitn(5, '|')`
    // is backward-compatible: a legacy 4-field descriptor yields no 5th part → the
    // store mints a fresh id, byte-identical to the prior behavior.
    //
    // DELIMITER CONSTRAINT (this flattened encoding only): `|` and `,` are
    // structural separators here, so a `title` / `assignee` / dep-title that
    // itself contains `|` or `,` is NOT faithfully expressible — it will be
    // split, yielding a different (caller-owned) decomposition than intended. The
    // ONLY behavior delta from the splitn(4)→splitn(5) widening is a malformed
    // 4-field descriptor whose deps field embeds a literal `|`: its post-`|` tail
    // is now read as the existing-id (no real caller does this — deps are `,`-joined).
    // This is a property of the deliberately minimal host-test encoding, NOT of
    // the contract: the production WIT path (once `advance.wit` surfaces the
    // real `decomposition-plan` record with `depends-on: list<string>`) carries
    // titles/deps as typed fields with no in-band delimiters and is unaffected.
    // The mis-encoding is also self-contained — the dependency graph is the
    // caller's OWN task decomposition (no cross-agent trust boundary is
    // crossed); a caller cannot use it to affect another principal.
    let goal = arg_str(params, 1, op)?;
    let strat = arg_str(params, 2, op)?;
    let strategy = match strat.as_str() {
        "self-execute" => DecompositionStrategy::SelfExecute,
        "decompose" => DecompositionStrategy::Decompose,
        "delegate-single" => {
            let assignee = arg_str(params, 4, op).map_err(|_| {
                HostCallError::HandlerError(format!(
                    "{op}: delegate-single requires an assignee (malformed strategy)"
                ))
            })?;
            if assignee.is_empty() {
                return Err(HostCallError::HandlerError(format!(
                    "{op}: delegate-single empty assignee (malformed strategy)"
                )));
            }
            DecompositionStrategy::DelegateSingle(crate::decomposition::DelegationTarget {
                assignee,
                template_ref: None,
                prompt: arg_str_opt(params, 5).unwrap_or_default(),
            })
        }
        bad => {
            return Err(HostCallError::HandlerError(format!(
                "{op}: unknown strategy {bad:?} (malformed strategy → call-shape)"
            )));
        }
    };
    let subtasks = match params.get(3) {
        Some(Val::List(items)) => {
            // Bound the descriptor LIST before iterating — a plan cannot have
            // more than MAX_DECOMPOSITION_SUBTASKS subtasks, so a longer list is
            // definitionally invalid; rejecting here (rather than lifting all of
            // them and letting submit() reject) caps the host-side lift work to a
            // fixed number of iterations regardless of guest linear-memory size
            // (adversarial r8 W1 — mirrors the sibling init_child_workspace_files
            // COUNT + aggregate-bytes guards).
            if items.len() > crate::decomposition::MAX_DECOMPOSITION_SUBTASKS {
                return Err(HostCallError::HandlerError(format!(
                    "{op}: subtask list length {} exceeds {} cap",
                    items.len(),
                    crate::decomposition::MAX_DECOMPOSITION_SUBTASKS
                )));
            }
            let mut total_bytes: usize = 0;
            let mut out: Vec<SubtaskSpec> = Vec::with_capacity(items.len());
            for v in items {
                let Val::String(s) = v else { continue };
                // Bound the descriptor BEFORE splitting — a multi-MB `…|a,a,a,…`
                // 4th-field would otherwise amplify into millions of depends_on
                // entries (and unbounded assignee clones) before the store's
                // per-field caps fire (adversarial r7 W1/W2).
                cap_str(op, s, MAX_DESCRIPTOR_BYTES)?;
                // Aggregate-bytes ceiling across all descriptors (r8 W1).
                total_bytes = total_bytes.saturating_add(s.len());
                if total_bytes > MAX_DECOMPOSITION_INPUT_BYTES {
                    return Err(HostCallError::HandlerError(format!(
                        "{op}: aggregate descriptor bytes exceed {MAX_DECOMPOSITION_INPUT_BYTES} cap"
                    )));
                }
                let mut parts = s.splitn(5, '|');
                let Some(title) = parts.next().map(str::to_string) else {
                    continue;
                };
                let assignee = parts.next().unwrap_or("_self").to_string();
                let prompt = parts.next().unwrap_or("").to_string();
                // 4th field (optional): comma-separated dependency TITLES,
                // trimmed, empties dropped — resolved to subtask-ids by the
                // store. Previously hardcoded `Vec::new()`, which silently
                // dropped dependencies through the WIT path and made
                // dependency-cycle rejection unreachable via the host-fn. The
                // descriptor cap above bounds this list's size; the store
                // additionally caps the resolved depends_on COUNT per subtask.
                let depends_on = parts
                    .next()
                    .map(|d| {
                        d.split(',')
                            .map(str::trim)
                            .filter(|x| !x.is_empty())
                            // Collect at most MAX_DECOMPOSITION_SUBTASKS + 1 dep
                            // titles: a legit subtask in an ≤256-node plan has
                            // ≤256 deps (never truncated), while a pathological
                            // comma-dense field stops at 257 — which the store's
                            // `depends_on.len() > MAX_DECOMPOSITION_SUBTASKS` cap
                            // then rejects. Bounds the per-descriptor transient
                            // to O(256) strings instead of O(field length)
                            // (adversarial r9 Info-1: closes the fixed-ceiling
                            // ~200 MiB transient before submit's count check).
                            .take(crate::decomposition::MAX_DECOMPOSITION_SUBTASKS + 1)
                            .map(str::to_string)
                            .collect()
                    })
                    .unwrap_or_default();
                // 5th field (optional): the `existing-id` continuity carrier
                // (SYS-AC-171). An EMPTY or absent field → `None` (fresh mint) via
                // an explicit trim+empties-filter — a `Some("")` would otherwise be
                // rejected by the store as a non-`st-<uuid>` InvalidConfig. A
                // present value is validated by the store (`is_valid_subtask_id` +
                // prior-plan membership). Already bounded by the descriptor `cap_str`
                // + aggregate-bytes ceiling above.
                let existing_id = parts
                    .next()
                    .map(str::trim)
                    .filter(|x| !x.is_empty())
                    .map(str::to_string);
                out.push(SubtaskSpec {
                    existing_id,
                    title,
                    assignee,
                    template_ref: None,
                    prompt,
                    depends_on,
                });
            }
            out
        }
        _ => Vec::new(),
    };
    Ok(DecompositionPlan {
        goal,
        strategy,
        subtasks,
    })
}

/// Lift `list<file-entry>` where each entry is a `Val::Record` with
/// `path: string` + `bytes: list<u8>` fields. Unknown shapes are skipped
/// (the controller re-validates count/size caps).
fn lift_file_entries(params: &[Val], i: usize) -> Vec<(String, Vec<u8>)> {
    match params.get(i) {
        Some(Val::List(items)) => items
            .iter()
            .filter_map(|v| match v {
                Val::Record(fields) => {
                    let mut path = None;
                    let mut bytes = Vec::new();
                    for (k, val) in fields {
                        match (k.as_str(), val) {
                            ("path", Val::String(s)) => path = Some(s.clone()),
                            ("bytes", Val::List(bs)) => {
                                bytes = bs
                                    .iter()
                                    .filter_map(|b| match b {
                                        Val::U8(n) => Some(*n),
                                        _ => None,
                                    })
                                    .collect();
                            }
                            _ => {}
                        }
                    }
                    path.map(|p| (p, bytes))
                }
                _ => None,
            })
            .collect(),
        _ => Vec::new(),
    }
}

fn lift_subtask_status(params: &[Val], i: usize, op: &str) -> Result<SubtaskStatus, HostCallError> {
    match arg_str(params, i, op)?.as_str() {
        "pending" => Ok(SubtaskStatus::Pending),
        "in-progress" => Ok(SubtaskStatus::InProgress),
        "completed" => Ok(SubtaskStatus::Completed),
        "failed" => Ok(SubtaskStatus::Failed),
        "skipped" => Ok(SubtaskStatus::Skipped),
        bad => Err(HostCallError::HandlerError(format!(
            "{op}: unknown subtask-status {bad:?}"
        ))),
    }
}

/// Lift the `agent-kind` WIT variant (`{sub, child}`) from param `i`.
///
/// Accepts BOTH wire shapes: `Val::Variant("sub"|"child", _)` — the shape a real
/// wit-bindgen runtime lifts a payload-less `variant` case to (the `_` covers the
/// always-`None` payload) — AND `Val::String("sub"|"child")` — the in-repo host/test
/// harness convention (mirrors `lift_subtask_status`, which reads variants via
/// `arg_str`; the harness passes payload-less variants as `Val::String`). `agent-kind`
/// is a WIT `variant`, NOT an `enum`, so `Val::Enum` is intentionally unhandled. Any
/// other shape / unknown case → call-shape `HandlerError` host trap (§2.8 cat-1),
/// never a silent mismap. Returns only `AgentKind::{Sub, Child}` (Root is not an
/// `agent-kind` case). sat/template-materialization 2026-06-13.
fn lift_agent_kind(params: &[Val], i: usize, op: &str) -> Result<AgentKind, HostCallError> {
    let case = match params.get(i) {
        Some(Val::Variant(case, _)) => case.as_str(),
        Some(Val::String(s)) => s.as_str(),
        _ => {
            return Err(HostCallError::HandlerError(format!(
                "{op}: expected agent-kind variant (sub|child) at param {i}"
            )))
        }
    };
    match case {
        "sub" => Ok(AgentKind::Sub),
        "child" => Ok(AgentKind::Child),
        bad => Err(HostCallError::HandlerError(format!(
            "{op}: unknown agent-kind {bad:?} (expected sub|child)"
        ))),
    }
}

#[cfg(test)]
mod cap_lift_tests {
    //! 011 (Wave-15 Lane E) — `lift_cap_request_list` decodes the real WIT
    //! `cap-request` record shape AND the harness bare-string shape.
    use super::*;

    fn cap_record(id: &str) -> Val {
        Val::Record(vec![
            ("capability".to_string(), Val::String(id.to_string())),
            ("params".to_string(), Val::Option(None)),
        ])
    }

    #[test]
    fn lifts_real_cap_request_records() {
        let v = Val::List(vec![cap_record("fs"), cap_record("tools")]);
        let caps = lift_cap_request_list(Some(&v));
        let ids: Vec<&str> = caps.iter().map(|c| c.id.as_str()).collect();
        assert_eq!(ids, vec!["fs", "tools"]);
    }

    #[test]
    fn lifts_bare_string_harness_shape() {
        let v = Val::List(vec![Val::String("fs".into()), Val::String("tools".into())]);
        let caps = lift_cap_request_list(Some(&v));
        let ids: Vec<&str> = caps.iter().map(|c| c.id.as_str()).collect();
        assert_eq!(ids, vec!["fs", "tools"]);
    }

    #[test]
    fn absent_or_non_list_lifts_empty() {
        assert!(lift_cap_request_list(None).is_empty());
        assert!(lift_cap_request_list(Some(&Val::String("x".into()))).is_empty());
    }

    #[test]
    fn record_opt_str_reads_template_ref() {
        let fields = vec![
            ("capabilities".to_string(), Val::List(vec![])),
            ("template-ref".to_string(), Val::Option(None)),
        ];
        assert_eq!(record_opt_str(&fields, "template-ref"), None);
        let fields2 = vec![(
            "template-ref".to_string(),
            Val::Option(Some(Box::new(Val::String("tmpl".into())))),
        )];
        assert_eq!(
            record_opt_str(&fields2, "template-ref"),
            Some("tmpl".to_string())
        );
    }

    #[test]
    fn submit_v2_binary_uses_its_byte_bound_not_the_generic_node_bound() {
        let config = Val::Record(vec![
            ("id".into(), Val::String("large-valid-carrier".into())),
            ("component-type".into(), Val::Variant("task".into(), None)),
            ("binary".into(), Val::List(vec![Val::U8(0); 16_385])),
            ("capabilities".into(), Val::List(Vec::new())),
            ("output-dir".into(), Val::Option(None)),
            ("trigger".into(), Val::Option(None)),
            ("restart-policy".into(), Val::Option(None)),
            ("delay".into(), Val::Option(None)),
            ("initial-grants".into(), Val::Option(None)),
            ("preset".into(), Val::Option(None)),
            ("retry".into(), Val::Option(None)),
            ("sensitive-params".into(), Val::List(Vec::new())),
        ]);

        let lifted = lift_component_submit_v2(&[config])
            .expect("a bounded byte carrier must not consume structural nodes");
        assert_eq!(
            lifted
                .canonical_json()
                .get("binary")
                .and_then(serde_json::Value::as_array)
                .map(Vec::len),
            Some(16_385)
        );
    }
}

#[cfg(test)]
mod decomp_lower_lift_tests {
    //! Wave-17 Lane 4 (SYS-AC-171) — the `get-decomposition` record lowering +
    //! the existing-id descriptor lift. Pins the WIT-faithful shapes (incl. the
    //! `delegate-single` payload and the `option<string>` `template-ref`) and the
    //! backward-compatible `splitn(5)` existing-id parse.
    use super::*;

    #[test]
    fn lower_decomposition_state_projects_full_wit_record() {
        let st = DecompositionState {
            goal: "iterate".into(),
            strategy: DecompositionStrategy::DelegateSingle(DelegationTarget {
                assignee: "worker".into(),
                template_ref: Some("tmpl".into()),
                prompt: "do it".into(),
            }),
            subtasks: vec![SubtaskState {
                subtask_id: "st-abc".into(),
                title: "alpha".into(),
                assignee: "_self".into(),
                depends_on: vec!["st-dep".into()],
                status: SubtaskStatus::InProgress,
                outcome: Some("started".into()),
                orphaned: false,
            }],
        };
        let v = lower_decomposition_state(st);
        let Val::Record(fields) = &v else {
            panic!("expected decomposition-state record, got {v:?}")
        };
        assert!(matches!(record_field(fields, "goal"), Some(Val::String(s)) if s == "iterate"));

        // strategy = delegate-single variant WITH the nested delegation-target
        // record payload {assignee, template-ref:option<string>, prompt}.
        let Some(Val::Variant(tag, Some(payload))) = record_field(fields, "strategy") else {
            panic!("expected delegate-single variant with payload")
        };
        assert_eq!(tag, "delegate-single");
        let Val::Record(dt) = payload.as_ref() else {
            panic!("expected delegation-target record")
        };
        assert!(matches!(record_field(dt, "assignee"), Some(Val::String(s)) if s == "worker"));
        assert!(matches!(
            record_field(dt, "template-ref"),
            Some(Val::Option(Some(b))) if matches!(b.as_ref(), Val::String(s) if s == "tmpl")
        ));
        assert!(matches!(record_field(dt, "prompt"), Some(Val::String(s)) if s == "do it"));

        // subtasks: one subtask-state record with the status variant + outcome option.
        let Some(Val::List(subs)) = record_field(fields, "subtasks") else {
            panic!("expected subtasks list")
        };
        assert_eq!(subs.len(), 1);
        let Val::Record(sf) = &subs[0] else {
            panic!("expected subtask-state record")
        };
        assert!(matches!(record_field(sf, "subtask-id"), Some(Val::String(s)) if s == "st-abc"));
        assert!(matches!(record_field(sf, "title"), Some(Val::String(s)) if s == "alpha"));
        assert!(matches!(
            record_field(sf, "status"),
            Some(Val::Variant(t, None)) if t == "in-progress"
        ));
        assert!(matches!(
            record_field(sf, "outcome"),
            Some(Val::Option(Some(b))) if matches!(b.as_ref(), Val::String(s) if s == "started")
        ));
        assert!(matches!(
            record_field(sf, "orphaned"),
            Some(Val::Bool(false))
        ));
        let Some(Val::List(deps)) = record_field(sf, "depends-on") else {
            panic!("expected depends-on list")
        };
        assert!(matches!(deps.first(), Some(Val::String(s)) if s == "st-dep"));
    }

    #[test]
    fn lower_strategy_and_status_payloadless_variants() {
        assert!(matches!(
            lower_decomposition_strategy(DecompositionStrategy::SelfExecute),
            Val::Variant(t, None) if t == "self-execute"
        ));
        assert!(matches!(
            lower_decomposition_strategy(DecompositionStrategy::Decompose),
            Val::Variant(t, None) if t == "decompose"
        ));
        // delegate-single with a None template-ref → option(none).
        let v =
            lower_decomposition_strategy(DecompositionStrategy::DelegateSingle(DelegationTarget {
                assignee: "w".into(),
                template_ref: None,
                prompt: "p".into(),
            }));
        let Val::Variant(_, Some(b)) = &v else {
            panic!("payload")
        };
        let Val::Record(dt) = b.as_ref() else {
            panic!("record")
        };
        assert!(matches!(
            record_field(dt, "template-ref"),
            Some(Val::Option(None))
        ));
        // every status tag is a payload-less kebab variant.
        for (s, tag) in [
            (SubtaskStatus::Pending, "pending"),
            (SubtaskStatus::InProgress, "in-progress"),
            (SubtaskStatus::Completed, "completed"),
            (SubtaskStatus::Failed, "failed"),
            (SubtaskStatus::Skipped, "skipped"),
        ] {
            assert!(matches!(lower_subtask_status(s), Val::Variant(t, None) if t == tag));
        }
    }

    #[test]
    fn lift_reads_optional_existing_id_5th_field() {
        let params = vec![
            Val::String("task".into()),
            Val::String("goal".into()),
            Val::String("decompose".into()),
            Val::List(vec![
                // 5-field: carries an existing-id.
                Val::String("alpha|_self|do a||st-11111111-1111-4111-8111-111111111111".into()),
                // 4-field (legacy): no 5th part → None.
                Val::String("beta|_self|do b".into()),
                // 5-field with EMPTY existing-id → None (not Some("")).
                Val::String("gamma|_self|do c||".into()),
                // 5-field with deps AND existing-id (deps stay the 4th field).
                Val::String(
                    "delta|_self|do d|alpha,beta|st-22222222-2222-4222-8222-222222222222".into(),
                ),
            ]),
        ];
        let plan = lift_decomposition_plan(&params, "submit-decomposition").expect("lift ok");
        assert_eq!(plan.subtasks.len(), 4);
        assert_eq!(
            plan.subtasks[0].existing_id.as_deref(),
            Some("st-11111111-1111-4111-8111-111111111111")
        );
        assert_eq!(plan.subtasks[1].existing_id, None, "legacy 4-field → None");
        assert_eq!(plan.subtasks[2].existing_id, None, "empty 5th field → None");
        assert_eq!(
            plan.subtasks[3].existing_id.as_deref(),
            Some("st-22222222-2222-4222-8222-222222222222")
        );
        // The deps field (4th) is unaffected by the 5th-field addition.
        assert_eq!(
            plan.subtasks[3].depends_on,
            vec!["alpha".to_string(), "beta".to_string()]
        );
    }
}
