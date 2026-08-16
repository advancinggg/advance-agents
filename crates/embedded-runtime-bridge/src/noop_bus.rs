//! Minimal EventBusEmit for register_cap_grant (no secrets, no I/O).

use advance_shared_types::event::Event;
use advance_shared_types::traits::EventBusEmit;

#[derive(Debug, Default)]
pub struct NoopEventBus;

impl EventBusEmit for NoopEventBus {
    fn emit(&self, _event: Event) {}
}
