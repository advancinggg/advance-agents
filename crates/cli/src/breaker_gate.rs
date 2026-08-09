//! Stage-F obs SLICE 3 — cli-root adapter bridging the runtime
//! [`CircuitBreakerBus`] to the scheduler's [`ComponentTypeBreakerGate`] seam
//! (SYS-AC-228).
//!
//! Trait inversion: the scheduler declares `ComponentTypeBreakerGate` and consults
//! it in `ComponentMaterializer::materialize` WITHOUT a compile-time
//! `advance-runtime` dependency. This concrete adapter lives at the cli
//! composition root (cli already deps `advance-runtime`) and forwards the gate
//! query to the real `CircuitBreakerBus::is_open_component_type`. The production
//! `DefaultCircuitBreakerBus` is minted in `advance-runtime`'s bootstrap and shared
//! as `Arc<dyn CircuitBreakerBus>`; install via
//! `ComponentMaterializer::with_component_type_breaker_gate`.

use std::sync::Arc;

use advance_runtime::circuit_breaker::CircuitBreakerBus;
use advance_scheduler::hook::ComponentTypeBreakerGate;
use advance_shared_types::component::ComponentType;

/// [`ComponentTypeBreakerGate`] backed by a real [`CircuitBreakerBus`].
pub struct DefaultComponentTypeBreakerGate {
    bus: Arc<dyn CircuitBreakerBus>,
}

impl DefaultComponentTypeBreakerGate {
    pub fn new(bus: Arc<dyn CircuitBreakerBus>) -> Self {
        Self { bus }
    }
}

impl ComponentTypeBreakerGate for DefaultComponentTypeBreakerGate {
    fn is_open_component_type(&self, kind: ComponentType) -> Option<String> {
        self.bus.is_open_component_type(kind)
    }
}
