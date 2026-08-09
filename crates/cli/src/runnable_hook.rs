//! Production [`RunnableHook`] — the WASM `runnable.run(config)` bridge
//! (sched-harvest 1B, the "P-runnable" follow-up the trigger-chain §3
//! hand-offs queued).
//!
//! [`WasmRunnableHook`] is the runnable-interface sibling of
//! [`crate::agent_loop::WasmMessageHandler`]: it closes the production
//! `dispatch → runnable run(config)` edge by backing the scheduler's
//! dependency-inverted [`RunnableHook`] trait (`crates/scheduler/src/hook.rs`
//! — "Production: backed by the runtime crate's
//! `wasmtime::component::Instance` holder") with the runtime's
//! `advance_runtime_runnable().call_run` export. The scheduler crate itself
//! must not gain a compile-time `advance-runtime` edge (the MODULE-014 §2.2
//! trait-inversion posture), so this adapter lives at the cli composition
//! root.
//!
//! Per-run instantiation: every `run_once` builds a FRESH instance + Store
//! (the same posture as `WasmMessageHandler::init`'s per-turn instance).
//! Runnable components are stateless across runs by the PRD §3.3 contract —
//! a cron/watcher/task run carries its state in `config-data` /
//! `trigger-context`, not in linear memory — so a fresh Store per run is the
//! correct (and trap-isolating) semantics: a trapped run never poisons the
//! next tick.
//!
//! Type mapping is FULL-FIDELITY, including `trigger-context` (scheduler
//! `TriggerContext` → wit `trigger-context`, field-for-field) — unlike the
//! message-driven path, where the agent skeleton's context is `None` by
//! shape. This is the conversion leg SYS-AC-101's "run(config) executes with
//! a populated trigger-context" rides on.

use std::sync::Arc;

use async_trait::async_trait;

use advance_runtime::wit_bindings::with_caps::advance::runtime::types as wit_types;
use advance_runtime::{CapabilityInjector, ComponentCtx, ComponentRuntime, LoadedComponent};
use advance_scheduler::hook::{HookError, RunnableHook};
use advance_scheduler::types::{ComponentConfig, RunResult, RunStatus};
use advance_shared_types::capability::CapRequest;
use advance_shared_types::event::Event;
use advance_shared_types::traits::EventBusEmit;

/// Production [`RunnableHook`] backed by the runtime's `runnable.run` export.
pub struct WasmRunnableHook {
    runtime: Arc<ComponentRuntime>,
    loaded: LoadedComponent,
    injector: Arc<CapabilityInjector>,
    caps: Vec<CapRequest>,
    /// The id stamped into `ComponentCtx.agent_id` for host-fn calls the
    /// runnable makes (capability attribution). NOTE: this is the COMPONENT
    /// id (cron/watcher/task), not an agent — same `ComponentCtx` shape the
    /// runtime requires for any instantiation.
    component_id: String,
    trace_id: String,
    event_bus: Option<Arc<dyn EventBusEmit>>,
}

impl WasmRunnableHook {
    pub fn new(
        runtime: Arc<ComponentRuntime>,
        loaded: LoadedComponent,
        injector: Arc<CapabilityInjector>,
        caps: Vec<CapRequest>,
        component_id: String,
        trace_id: String,
    ) -> Self {
        Self {
            runtime,
            loaded,
            injector,
            caps,
            component_id,
            trace_id,
            event_bus: None,
        }
    }

    pub fn with_event_bus(mut self, event_bus: Arc<dyn EventBusEmit>) -> Self {
        self.event_bus = Some(event_bus);
        self
    }
}

#[async_trait]
impl RunnableHook for WasmRunnableHook {
    async fn run_once(&self, config: ComponentConfig) -> Result<RunResult, HookError> {
        let ctx = ComponentCtx::new(self.component_id.clone(), self.trace_id.clone(), Vec::new())
            .with_notify_sender_override("system".to_string());
        let (bindings, mut store) = self
            .runtime
            .instantiate_advance_host_with_capabilities_async(
                &self.loaded,
                ctx,
                &self.caps,
                &self.injector,
            )
            .await
            .map_err(|e| HookError::Failure(format!("instantiate: {e:?}")))?;
        // scheduler ComponentConfig -> wit ComponentConfig, FULL fidelity:
        // the trigger-context (event_type / timestamp / payload / chain_id /
        // chain_depth) reaches the guest field-for-field.
        let wit_cfg = wit_types::ComponentConfig {
            id: config.id,
            config_data: config.config_data,
            trigger_context: config.trigger_context.map(|tc| wit_types::TriggerContext {
                event_type: tc.event_type,
                timestamp: tc.timestamp,
                payload: tc.payload,
                trigger_chain_id: tc.trigger_chain_id,
                chain_depth: tc.chain_depth,
            }),
        };
        let wit_result = bindings
            .advance_runtime_runnable()
            .call_run(&mut store, &wit_cfg)
            .await
            .map_err(|e| HookError::Failure(format!("call_run trap: {e:?}")))?
            .map_err(|e| HookError::Failure(format!("run returned err: {e}")))?;
        // Adversarial-round F8 (contested → resolved defensively, 2026-06-13):
        // the guest controls RunResult.output, which the drivers materialize
        // host-side and may write to {output_dir}/result.bin. Guest linear
        // memory bounds it in practice, but that bound is a CONFIG knob
        // (max_memory_pages), not a contract — clamp at the scheduler's wire
        // bound, fail-closed (no truncation of opaque bytes).
        if let Some(out) = &wit_result.output {
            if out.len() > advance_scheduler::types::MAX_WIRE_BYTES_LEN {
                return Err(HookError::Failure(format!(
                    "run output {} bytes exceeds MAX_WIRE_BYTES_LEN ({})",
                    out.len(),
                    advance_scheduler::types::MAX_WIRE_BYTES_LEN
                )));
            }
        }
        let result = RunResult {
            status: match wit_result.status {
                wit_types::RunStatus::Completed => RunStatus::Completed,
                wit_types::RunStatus::Failed(msg) => RunStatus::Failed(msg),
            },
            output: wit_result.output,
        };
        if let Some(event_bus) = &self.event_bus {
            // A valid JSON object/array retains its typed structure for the sensitive-parameter
            // projector.  Arbitrary guest bytes never become a log string; only their length is
            // observable.  Raw output remains available to the scheduler result/output_dir path.
            let output = result.output.as_deref().unwrap_or_default();
            let projected = serde_json::from_slice::<serde_json::Value>(output)
                .unwrap_or_else(|_| serde_json::json!({ "output_bytes": output.len() }));
            let mut event = Event::observability(
                "run.completed",
                self.component_id.clone(),
                serde_json::json!({ "result": projected }),
                None,
            );
            event.task_id = Some(format!("task:{}", self.component_id));
            // This hook invocation is the execution boundary, so give it a
            // real per-execution correlation id. CONTRACT-191 accepts the
            // lowercase hyphenated UUID grammar; the old `run:{component}`
            // synthetic value was not client-projectable because `:` is
            // intentionally forbidden in public run ids.
            event.run_id = Some(uuid::Uuid::new_v4().to_string());
            event.trace_id = self.trace_id.clone();
            event.span_id = uuid::Uuid::new_v4().simple().to_string();
            event_bus.emit(event);
        }
        Ok(result)
    }
}
