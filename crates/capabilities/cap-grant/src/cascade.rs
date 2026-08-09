//! Cascade descendant-walking helpers (MODULE-013 §2.7).

use crate::data::GrantId;
use std::collections::{HashMap, HashSet};

/// Maximum number of grants any single cascade may visit.
///
/// Slice-A safety cap mirroring the per-agent ceiling documented in
/// MODULE-013 §2.11 ("Max grants per agent: 10,000"). `walk_descendants`
/// stops collecting once this many ids are visited; the cascade then
/// applies whatever it managed to collect and returns success — this is
/// strictly a DoS-bounding measure and not an error path. Slice B can
/// promote this to a configurable runtime parameter alongside the
/// resolver chain work.
pub const MAX_CASCADE_SIZE: usize = 10_000;

/// Result returned by `GrantStore::cascade_revoke` and
/// `GrantStore::cascade_by_issuer`.
///
/// `cascade_count` records the descendant count at the root only; per-event
/// `cascade_count` semantic (root carries this number; descendants carry 0)
/// is documented at the event-builder layer (`events::grant_revoked_event`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CascadeResult {
    pub root_id: GrantId,
    pub revoked: Vec<GrantId>,
    pub cascade_count: usize,
}

/// DFS-walk descendants of `root` through the `provenance` index
/// (parent grant id → child grant id set), returning descendants in the
/// order they were discovered. The root id itself is NOT included.
///
/// Bounded by the visited set so a malformed cycle (theoretically
/// impossible because every edge `Delegated(parent_id)` points to an
/// older grant, but defended-in-depth) cannot infinite-loop.
pub(crate) fn walk_descendants(
    provenance: &HashMap<GrantId, HashSet<GrantId>>,
    root: &GrantId,
) -> Vec<GrantId> {
    let mut out = Vec::new();
    let mut visited: HashSet<GrantId> = HashSet::new();
    let mut stack: Vec<GrantId> = Vec::new();
    if let Some(children) = provenance.get(root) {
        let mut sorted: Vec<&GrantId> = children.iter().collect();
        sorted.sort();
        for c in sorted {
            stack.push(c.clone());
        }
    }
    while let Some(id) = stack.pop() {
        if out.len() >= MAX_CASCADE_SIZE {
            // DoS bound — stop collecting once the safety cap is hit.
            // Caller (`cascade_revoke` / `cascade_by_issuer`) applies
            // whatever was collected; further descendants are reachable
            // only via a future cascade invocation.
            break;
        }
        if !visited.insert(id.clone()) {
            continue;
        }
        out.push(id.clone());
        if let Some(children) = provenance.get(&id) {
            let mut sorted: Vec<&GrantId> = children.iter().collect();
            sorted.sort();
            for c in sorted {
                stack.push(c.clone());
            }
        }
    }
    out
}
