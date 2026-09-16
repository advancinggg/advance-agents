#![cfg(feature = "gap-p1")]
//! GAP-11 (P1) — `pack.*` events registered in the MODULE-019 taxonomy.
//! They are documented extensions
//! (NOT in PRD §15.3) and must NOT enter the 12-entry Trigger Bus whitelist.

use advance_event_bus::taxonomy::{self, ALL_EVENT_TYPES, TRIGGER_BUS_WHITELIST};

#[test]
fn tx_01_pack_event_constants_are_registered() {
    assert_eq!(taxonomy::pack::INSTALLED, "pack.installed");
    assert_eq!(taxonomy::pack::UNINSTALLED, "pack.uninstalled");
    assert_eq!(taxonomy::pack::REGISTRY_RELOADED, "pack.registry_reloaded");
    for e in [
        taxonomy::pack::INSTALLED,
        taxonomy::pack::UNINSTALLED,
        taxonomy::pack::REGISTRY_RELOADED,
    ] {
        assert!(
            ALL_EVENT_TYPES.contains(&e),
            "{e} must be a fixed-string taxonomy entry"
        );
    }
}

#[test]
fn tx_02_pack_events_stay_out_of_the_trigger_bus_whitelist() {
    assert_eq!(
        TRIGGER_BUS_WHITELIST.len(),
        12,
        "PRD §15.4 pins exactly 12 whitelisted trigger events"
    );
    for e in [
        taxonomy::pack::INSTALLED,
        taxonomy::pack::UNINSTALLED,
        taxonomy::pack::REGISTRY_RELOADED,
    ] {
        assert!(
            !TRIGGER_BUS_WHITELIST.contains(&e),
            "{e} must not trigger components"
        );
    }
}
