//! Slice B `Scheduler` router struct.
//!
//! Holds one instance per driver type + the TriggerBus dispatcher.
//! Routes by `ComponentType`. The full submit-component admission +
//! driver-entry-invocation routing is declared in `waived_scope` (see
//! the "Scheduler routing struct" entry in `.dev-state/state.json`);
//! this struct is the surface that admission calls.
//!
//! `driver_name(ComponentType)` returns a stable name string suitable
//! for routing tests — it exercises the dispatcher's
//! component-type-to-driver mapping without requiring the full
//! driver-entry invocation that the waived scope defers.

use std::sync::Arc;

use thiserror::Error;

use advance_shared_types::component::ComponentType;

use crate::agent_loop::AgentLoopDriverImpl;
use crate::contracts::SchedulerExtension;
use crate::cron::CronDriver;
use crate::daemon::DaemonManager;
use crate::hook::RuntimeReadiness;
use crate::task::TaskRunner;
use crate::trigger_bus::TriggerBusDispatchImpl;
use crate::types::{ComponentEvent, SchedulerTick};
use crate::watcher::WatcherDriver;

/// Slice B scheduler-router struct.
pub struct Scheduler {
    pub trigger_bus: Arc<TriggerBusDispatchImpl>,
    pub agent_loop: Option<Arc<AgentLoopDriverImpl>>,
    pub cron: CronDriver,
    pub watcher: WatcherDriver,
    pub daemon: DaemonManager,
    pub task: TaskRunner,
    /// Slice m015-A (CONTRACT-133): registered scheduler extensions
    /// (notably MODULE-015's AutoLoopDriver). **Private** — the public
    /// surface is `register_extension` / `extension_names` /
    /// `dispatch_tick` / `dispatch_component_event` only, so adding this
    /// field cannot break external struct-literal construction or
    /// exhaustive pattern matching (audit round-1 fix: a new `pub` field
    /// would have been public-API drift even though no in-repo call site
    /// uses struct literals). CONTRACT-133 trait shape is unchanged;
    /// the Scheduler change is strictly additive *methods*.
    extensions: Vec<Arc<dyn SchedulerExtension>>,
}

impl Scheduler {
    pub fn new(trigger_bus: Arc<TriggerBusDispatchImpl>) -> Self {
        Self {
            trigger_bus,
            agent_loop: None,
            cron: CronDriver::new(),
            watcher: WatcherDriver::new(),
            daemon: DaemonManager::new(),
            task: TaskRunner::new(),
            extensions: Vec::new(),
        }
    }

    /// Slice m015-A (CONTRACT-133): register a scheduler extension so it
    /// receives ticks/component-events via the fan-out below. This is what
    /// makes MODULE-015's `AutoLoopDriver` a *functional* plug-in (not just
    /// a declared trait impl).
    pub fn register_extension(&mut self, ext: Arc<dyn SchedulerExtension>) {
        self.extensions.push(ext);
    }

    /// Stable names of registered extensions (test-friendly introspection).
    pub fn extension_names(&self) -> Vec<&str> {
        self.extensions.iter().map(|e| e.name()).collect()
    }

    /// Fan a scheduler tick out to EVERY registered extension, in
    /// registration order. Sequential `.await` — slice A has no
    /// concurrency requirement here.
    pub async fn dispatch_tick(&self, tick: SchedulerTick) {
        for ext in &self.extensions {
            ext.on_tick(tick).await;
        }
    }

    /// Fan a component-lifecycle event out to every registered extension.
    /// `ComponentEvent` is `Clone` so each extension gets its own copy.
    pub async fn dispatch_component_event(&self, event: ComponentEvent) {
        for ext in &self.extensions {
            ext.on_component_event(event.clone()).await;
        }
    }

    /// Builder: attach the agent-loop driver. Optional because not every
    /// scheduler instance runs agents (e.g. a worker-only scheduler).
    pub fn with_agent_loop(mut self, agent_loop: Arc<AgentLoopDriverImpl>) -> Self {
        self.agent_loop = Some(agent_loop);
        self
    }

    /// Slice B routing surface: returns the stable driver name for a
    /// given `ComponentType`. The dispatcher invocation
    /// (matching `ComponentType` to `CronDriver::run_periodic` /
    /// `DaemonManager::run_daemon` / etc.) is declared in
    /// `waived_scope` (`.dev-state/state.json`) and tested here only by
    /// its routing-name mapping.
    pub fn driver_name(&self, ct: ComponentType) -> &'static str {
        match ct {
            ComponentType::Agent => "agent_loop",
            ComponentType::Cron => "cron",
            ComponentType::Watcher => "watcher",
            ComponentType::Daemon => "daemon",
            ComponentType::Task => "task",
        }
    }

    /// Slice C readiness gate (AC-20). Consults the `RuntimeReadiness`
    /// trait — when `probe.is_ready().await` returns false, the scheduler
    /// returns `Err(SchedulerStartError::RuntimeNotReady)` without
    /// registering any drivers (fail-fast). When true, returns
    /// `Ok(())` — the post-readiness driver-registration loop is a
    /// follow-up slice's concern (formally declared in `waived_scope`).
    ///
    /// Production callers wire a real `HostRegistry`-backed adapter
    /// (e.g. `HostRegistryReadiness` querying
    /// `HostRegistry::lookup("scheduler.boot")` for a sentinel cap that
    /// M001 registers at end-of-bootstrap). Slice C's adapter lives in a
    /// follow-up wiring slice — preserves the M014-trait-inversion
    /// posture (no compile-time `advance-runtime` dep).
    pub async fn start_with_readiness(
        &self,
        probe: Arc<dyn RuntimeReadiness>,
    ) -> Result<(), SchedulerStartError> {
        if !probe.is_ready().await {
            return Err(SchedulerStartError::RuntimeNotReady);
        }
        Ok(())
    }
}

/// Slice C scheduler-crate-local error enum for `start_with_readiness`.
#[derive(Debug, Error)]
pub enum SchedulerStartError {
    #[error("MODULE-001 runtime reports not ready (HostRegistry probe returned false)")]
    RuntimeNotReady,
}
