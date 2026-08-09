//! Slice B `Scheduler` router verification.
//!
//! Verifies that `driver_name(ComponentType)` returns the correct stable
//! string for each of the 5 ComponentType variants.

use std::sync::Arc;

use advance_scheduler::trigger_bus::TriggerBusDispatchImpl;
use advance_scheduler::Scheduler;
use advance_shared_types::component::ComponentType;

#[test]
fn scheduler_routes_all_five_component_types() {
    let tb = Arc::new(TriggerBusDispatchImpl::new());
    let s = Scheduler::new(tb);
    for (ct, expected) in [
        (ComponentType::Agent, "agent_loop"),
        (ComponentType::Cron, "cron"),
        (ComponentType::Watcher, "watcher"),
        (ComponentType::Daemon, "daemon"),
        (ComponentType::Task, "task"),
    ] {
        assert_eq!(
            s.driver_name(ct),
            expected,
            "ComponentType::{ct:?} should route to driver {expected:?}"
        );
    }
}

#[test]
fn scheduler_starts_without_agent_loop_attached() {
    let tb = Arc::new(TriggerBusDispatchImpl::new());
    let s = Scheduler::new(tb);
    assert!(s.agent_loop.is_none());
}
