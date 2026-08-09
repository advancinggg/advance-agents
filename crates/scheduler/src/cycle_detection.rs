//! Pure cycle-detection helper for Trigger Bus dispatch.
//!
//! `check_chain` inspects (does NOT mutate) the visited-set state and
//! returns a verdict. The actual mutation (inserting the component
//! into the visited set + enforcing the 100_000 aggregate cap) happens
//! at the `dispatch()` site, which is `unimplemented!()` in Slice A.
//! Slice B wires that mutation plus the aggregate-cap test.
//!
//! `max_depth` is clamped to `MAX_CHAIN_DEPTH_HARD_CAP` (1 000) before
//! comparison — defense against a caller passing `u32::MAX`.

use std::collections::{HashMap, HashSet};

use crate::types::{ComponentId, TriggerChainId, MAX_CHAIN_DEPTH_HARD_CAP};

/// Slice A cycle-check outcome.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CycleCheckOutcome {
    /// Chain depth within bounds and component not yet visited — safe
    /// to dispatch.
    Allow,
    /// This component already appears in the chain — would cause a
    /// cycle; dispatch must skip it.
    AlreadyVisited,
    /// Depth exceeds the clamped `max_depth` — dispatch must skip.
    MaxDepthExceeded,
}

/// Pure cycle-detection check. Read-only on `visited_sets`.
pub fn check_chain(
    chain_id: &TriggerChainId,
    depth: u32,
    component_id: &ComponentId,
    visited_sets: &HashMap<TriggerChainId, HashSet<ComponentId>>,
    max_depth: u32,
) -> CycleCheckOutcome {
    let effective_max = max_depth.min(MAX_CHAIN_DEPTH_HARD_CAP);
    if depth > effective_max {
        return CycleCheckOutcome::MaxDepthExceeded;
    }
    if let Some(set) = visited_sets.get(chain_id) {
        if set.contains(component_id) {
            return CycleCheckOutcome::AlreadyVisited;
        }
    }
    CycleCheckOutcome::Allow
}

#[cfg(test)]
mod tests {
    use super::*;

    fn chain(s: &str) -> TriggerChainId {
        TriggerChainId(s.into())
    }

    fn cid(s: &str) -> ComponentId {
        ComponentId::new(s.into()).unwrap()
    }

    #[test]
    fn happy_path_allow() {
        let visited = HashMap::new();
        let r = check_chain(&chain("c1"), 1, &cid("comp-a"), &visited, 10);
        assert_eq!(r, CycleCheckOutcome::Allow);
    }

    #[test]
    fn already_visited() {
        let mut visited = HashMap::new();
        let mut set = HashSet::new();
        set.insert(cid("comp-a"));
        visited.insert(chain("c1"), set);
        let r = check_chain(&chain("c1"), 1, &cid("comp-a"), &visited, 10);
        assert_eq!(r, CycleCheckOutcome::AlreadyVisited);
    }

    #[test]
    fn depth_over_max() {
        let visited = HashMap::new();
        let r = check_chain(&chain("c1"), 11, &cid("comp-a"), &visited, 10);
        assert_eq!(r, CycleCheckOutcome::MaxDepthExceeded);
    }

    #[test]
    fn depth_equal_max_is_allow() {
        let visited = HashMap::new();
        let r = check_chain(&chain("c1"), 10, &cid("comp-a"), &visited, 10);
        // Strict `>` boundary: depth == max is still allowed.
        assert_eq!(r, CycleCheckOutcome::Allow);
    }

    #[test]
    fn max_depth_clamped_to_hard_cap() {
        // Caller asks for u32::MAX; the helper clamps to 1_000.
        // Depth 1_001 → MaxDepthExceeded.
        let visited = HashMap::new();
        let r = check_chain(&chain("c1"), 1_001, &cid("comp-a"), &visited, u32::MAX);
        assert_eq!(r, CycleCheckOutcome::MaxDepthExceeded);
        // Depth 1_000 (== clamped max) → Allow.
        let r2 = check_chain(&chain("c1"), 1_000, &cid("comp-a"), &visited, u32::MAX);
        assert_eq!(r2, CycleCheckOutcome::Allow);
    }
}
