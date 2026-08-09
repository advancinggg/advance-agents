//! Round-2 Info 7 + round-3 W2 — clippy `dead_code` guard for `TRIGGER_BUS_WHITELIST`
//! and regression lock on the canonical 12-event count (MODULE-019 §1.3.2a).
//!
//! Slice D adversarial round 1 W3: added `seed_constants_match_submodule_sources`
//! to lock the Slice-A back-compat re-exports against silent divergence between
//! the top-level alias and the sub-module source-of-truth constant.

use advance_event_bus::taxonomy::{
    self, COMPONENT_SPAWNED, FS_READ_ENTRY, LLM_RESPONSE, RUNTIME_STARTED, TASK_CREATED,
    TRIGGER_BUS_WHITELIST,
};

#[test]
fn whitelist_has_12_entries() {
    assert_eq!(TRIGGER_BUS_WHITELIST.len(), 12);
}

#[test]
fn seed_event_type_constants_match_canonical_strings() {
    // Tests reference each constant; clippy `dead_code` lint passes.
    assert_eq!(RUNTIME_STARTED, "runtime.started");
    assert_eq!(FS_READ_ENTRY, "fs.read.entry");
    assert_eq!(LLM_RESPONSE, "llm.response");
    assert_eq!(COMPONENT_SPAWNED, "component.spawned");
    assert_eq!(TASK_CREATED, "task.created");
}

/// Slice D ADVERSARIAL R1 W3 — back-compat re-export equivalence regression lock.
///
/// The Slice-A back-compat aliases at the `taxonomy::*` root are declared as
/// `pub const ALIAS: &str = sub_module::SOURCE;` (taxonomy.rs lines 524-532).
/// Two constant paths to the same string. If a future maintainer updates only
/// one of the two paths (e.g., changes `runtime::STARTED` but forgets to update
/// `RUNTIME_STARTED`, or vice versa), the seed test above catches "alias breaks
/// canonical literal" but does NOT catch "alias and source diverge" — both
/// could be wrong-but-internally-consistent. This test locks the equivalence.
#[test]
fn seed_constants_match_submodule_sources() {
    assert_eq!(RUNTIME_STARTED, taxonomy::runtime::STARTED);
    assert_eq!(LLM_RESPONSE, taxonomy::llm::RESPONSE);
    assert_eq!(COMPONENT_SPAWNED, taxonomy::component::SPAWNED);
    assert_eq!(TASK_CREATED, taxonomy::task::CREATED);
    assert_eq!(FS_READ_ENTRY, taxonomy::extensions::FS_READ_ENTRY);
}
