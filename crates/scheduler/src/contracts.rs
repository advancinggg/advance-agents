//! MODULE-014 contract traits — Slice A canonical declarations.
//!
//! Signatures come straight from MODULE-014 §2.3:479-506. Object-safety
//! + `Send + Sync` are regression-locked in `tests/object_safety.rs`.

use async_trait::async_trait;

use crate::types::{
    ComponentConfig, ComponentEvent, ComponentInfo, ComponentState, ComponentSubmitConfig,
    SchedulerTick, SpawnError, SubscriptionId, TrapError, TriggerSubscription, WasmInstance,
};
use advance_shared_types::event::Event;

// We do NOT import the `ComponentId` newtype into the trait signature for
// `kill_component` / `component_status` — the canonical MODULE-014 §2.3
// signature takes `&str`, so we keep that here. Slice B may tighten to
// `&ComponentId` once admission is wired up.

/// CONTRACT-130 — admission-and-control API for `submit-component`.
///
/// MODULE-014 §2.3:479-485 verbatim signatures. WIT name → Rust method
/// mapping per the spec:
/// - `submit-component` → `submit_component`
/// - `kill-component` → `kill_component`
/// - `component-status` → `component_status`
/// - `list-components` → `list_components`
///
/// Slice A's `InMemoryComponentSubmitApi` is a stub that returns `Err`
/// on every mutating call and an empty `Vec` on `list_components`.
/// Real admission (SubsetValidator integration, capability-denied path,
/// `max-scheduled-components` quota, daemon-controller-cap rejection,
/// admission-time `component-type: agent` rejection) lands in Slice B.
#[async_trait]
pub trait ComponentSubmitApi: Send + Sync {
    async fn submit_component(
        &self,
        submitter: &str,
        config: ComponentSubmitConfig,
    ) -> Result<crate::types::ComponentId, SpawnError>;
    async fn kill_component(&self, id: &str) -> Result<(), SpawnError>;
    async fn component_status(&self, id: &str) -> Result<ComponentState, SpawnError>;
    /// Canonical signature returns a bare `Vec<ComponentInfo>` — NOT a
    /// `Result`. See MODULE-014 §2.3:484.
    async fn list_components(&self) -> Vec<ComponentInfo>;
}

/// CONTRACT-131 — subscription + fan-out dispatcher for the Trigger
/// Bus. MODULE-014 §2.3:488-492 verbatim signatures.
///
/// `subscribe` returns a fresh `SubscriptionId` directly — no error
/// channel. Slice A enforces whitelist + caps via the pure
/// `validate_subscription` helper called internally; on rejection,
/// `subscribe()` silently no-ops (does not insert) while still
/// returning a fresh ID. Slice B widens the trait to
/// `Result<SubscriptionId, SpawnError>` via /spec.
pub trait TriggerBusDispatch: Send + Sync {
    fn subscribe(&self, subscription: TriggerSubscription) -> SubscriptionId;
    fn unsubscribe(&self, id: SubscriptionId);
    /// Slice A: `unimplemented!()`. Real fan-out (subscription index
    /// scan + visited-set cycle detection + `submit_trigger_run` per
    /// §1.4.3) lands in Slice B.
    fn dispatch(&self, event: Event);
}

/// CONTRACT-132 — drives a single agent message loop, invoking
/// inverted `ContextAssembler` / `MailboxReader` /
/// `AgentActionDispatcher` / `PostProcessorHook` traits. MODULE-014
/// §2.3:494-499 verbatim signatures.
///
/// Slice A's `AgentLoopDriverImpl` holds the inverted-trait
/// `Arc<dyn ...>` fields and stubs both methods. Real loop wired in
/// Slice C (after MODULE-006 mailbox crate lands).
#[async_trait]
pub trait AgentLoopDriver: Send + Sync {
    async fn run_agent(
        &self,
        agent_id: &str,
        component_config: ComponentConfig,
        instance: WasmInstance,
    );
    async fn handle_trap(&self, agent_id: &str, trap: TrapError);
}

/// CONTRACT-133 — extension slot for scheduler-piggyback drivers
/// (notably MODULE-015's AutoLoopDriver). MODULE-014 §2.3:501-506
/// verbatim signatures.
#[async_trait]
pub trait SchedulerExtension: Send + Sync {
    fn name(&self) -> &str;
    async fn on_tick(&self, tick: SchedulerTick);
    async fn on_component_event(&self, event: ComponentEvent);
}
