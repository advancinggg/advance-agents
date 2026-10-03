//! Production [`RunnableHookFactory`] — the cli composition-root impl of
//! MODULE-014's dependency-inverted factory seam (B3 satellite, 2026-06-15).
//!
//! [`WasmRunnableHookFactory`] is the cli half of the registry→driver
//! materialization layer: the S3 scheduler-half satellite (`scheduler/src/{hook,
//! materializer}.rs`) shipped the [`RunnableHookFactory`] trait + the
//! [`ComponentMaterializer`](advance_scheduler::materializer::ComponentMaterializer)
//! that extracts a component's binary/id/caps FROM an admitted
//! `ComponentRegistryRow`; THIS impl performs the `&[u8] → LoadedComponent →
//! WasmRunnableHook` load step that the materializer drives. The trait takes
//! `binary: &[u8]` (not a runtime `LoadedComponent`) precisely so the
//! `advance-runtime`/`wasmtime` edge never crosses into the scheduler crate —
//! the cli composition root owns it (MODULE-014 §2.2 trait-inversion posture).
//! Keep it that way: this file is the ONLY place the load step lives.
//!
//! **Bytes-binding (anti-fake-green).** `build` loads the EXACT bytes it is
//! handed and binds the produced [`WasmRunnableHook`] to that
//! `LoadedComponent` — never to an id string. A changed/corrupt submit changes
//! the outcome (the bytes either load to a different guest or fail to load),
//! which `tests/runnable_factory.rs` regression-locks with a truncate-mutation
//! discriminator. This is the cli-layer precondition for the mainline
//! SYS-AC-109 kill (the id-string fake-green class), not the kill itself.

use std::sync::Arc;

use async_trait::async_trait;

use advance_runtime::{CapabilityInjector, ComponentRuntime};
use advance_scheduler::hook::{HookError, RunnableHook, RunnableHookFactory};
use advance_shared_types::capability::CapRequest;
use advance_shared_types::traits::EventBusEmit;

use crate::runnable_hook::WasmRunnableHook;

/// Production [`RunnableHookFactory`] backed by the runtime's component loader.
///
/// Holds the two runtime seams a [`WasmRunnableHook`] needs — the
/// [`ComponentRuntime`] (loads + instantiates) and the [`CapabilityInjector`]
/// (wires registered host fns through the L0/L1/CB gates). The composition root
/// constructs it from a `RuntimeHost`:
/// `WasmRunnableHookFactory::new(host.component_runtime(), host.capability_injector())`.
pub struct WasmRunnableHookFactory {
    runtime: Arc<ComponentRuntime>,
    injector: Arc<CapabilityInjector>,
    event_bus: Option<Arc<dyn EventBusEmit>>,
}

impl WasmRunnableHookFactory {
    pub fn new(runtime: Arc<ComponentRuntime>, injector: Arc<CapabilityInjector>) -> Self {
        Self {
            runtime,
            injector,
            event_bus: None,
        }
    }

    /// Attach the daemon's observation bus.  The guest still runs first; only its returned result
    /// is projected into `run.completed`, so a registry-only fake cannot produce this event.
    pub fn with_event_bus(mut self, event_bus: Arc<dyn EventBusEmit>) -> Self {
        self.event_bus = Some(event_bus);
        self
    }
}

#[async_trait]
impl RunnableHookFactory for WasmRunnableHookFactory {
    async fn build(
        &self,
        binary: &[u8],
        component_id: &str,
        caps: &[CapRequest],
    ) -> Result<Arc<dyn RunnableHook>, HookError> {
        // The bytes-binding step: load THESE bytes (corrupt/truncated → Err,
        // mapped to HookError::Failure). load_component is the scheduler-side
        // trait's `&[u8]` boundary made concrete — no runtime type leaks back.
        let loaded = self
            .runtime
            .load_component(binary)
            .map_err(|e| HookError::Failure(format!("load_component: {e:?}")))?;
        // PINNED per-row trace policy (B3): one trace stream per component,
        // deterministic, no global state — mirrors the id WasmRunnableHook
        // already stamps into ComponentCtx.agent_id. The mainline harness must
        // construct this factory identically so its traces line up.
        let trace_id = format!("runnable:{component_id}");
        let hook = WasmRunnableHook::new(
            Arc::clone(&self.runtime),
            loaded,
            Arc::clone(&self.injector),
            caps.to_vec(),
            component_id.to_owned(),
            trace_id,
        );
        Ok(Arc::new(match &self.event_bus {
            Some(event_bus) => hook.with_event_bus(Arc::clone(event_bus)),
            None => hook,
        }))
    }
}
