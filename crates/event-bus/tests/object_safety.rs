//! T_S A9 — compile-time `Box<dyn EventBusEmit>` sentinel for the Slice A impl.

use std::path::PathBuf;

use advance_event_bus::{EventBus, EventBusConfig};
use advance_shared_types::traits::EventBusEmit;

#[test]
fn slice_a_event_bus_is_dyn_constructible() {
    let temp = tempfile::TempDir::new().expect("tempdir");
    let cfg = EventBusConfig::new(temp.path().join("events"), temp.path().join("events.db"));
    let bus = EventBus::new_synchronous_for_tests(cfg).expect("bus");
    let _: Box<dyn EventBusEmit> = Box::new(bus);
    // Compile-time enforcement of object safety (Send + Sync are part of the trait
    // bound). Anchors the same regression lock as
    // crates/shared-types/tests/object_safety.rs but for the concrete impl.
    let _: PathBuf = PathBuf::new(); // touch unused import to keep clippy happy
}
