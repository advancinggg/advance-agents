//! AC-16 nested AwaitSession tree — in-boundary parent_session linkage seam.
//!
//! [`SessionContextProvider`] is a dependency-inverted seam over MODULE-008's
//! `RunStateSync` (CONTRACT-071 `current_session(caller_run_id)`). Slice-C
//! cannot depend on M008 directly (crate-boundary prompt rule + REQ-293
//! cross-module exclusion); a future slice-D M008+M007 wiring provides a real
//! `RunStateSync`-backed impl. Slice-C tests use mock implementations.
//!
//! **Trait signature scope (slice-C)**: keys on `caller_run_id: &str` per
//! AC-16's RunStateSync mandate. Multi-run-per-caller scenarios are
//! disambiguated by the run_id. CONTRACT-060::start does NOT carry a
//! `caller_run_id` parameter — to keep the trait surface byte-identical,
//! [`crate::AwaitSessionManagerImpl`] exposes a non-trait `start_with_run(caller,
//! caller_run_id, ...)` entry point that the future M006 host-fn handler
//! calls with the actual run_id from Wasmtime store. The trait's `start(...)`
//! delegates to `start_with_run(..., None, ...)` = admission-time root (no
//! parent linkage). Slice-C tests exercise nested linkage via `start_with_run`.

use std::collections::HashMap;

use advance_shared_types::await_session::SessionId;

use crate::manager::SessionEntry;

/// Dependency-inverted seam over M008 `RunStateSync::current_session`.
///
/// Returns the currently-active session id for the given `caller_run_id`, if
/// any. `None` → no in-flight session for that run (the new session is a
/// root). Production wiring (slice-D) backs this with M008 RunStateSync;
/// tests use a `MockSessionContext`-style stub.
pub trait SessionContextProvider: Send + Sync {
    fn current_session(&self, caller_run_id: &str) -> Option<SessionId>;
}

/// Compute the depth of `sid` in the `parent_session` chain inside the
/// `sessions` map.
///
/// Returns `1` if `sid` is absent from the map (a new top-level root) or has
/// `parent_session: None`. For nested entries, walks the chain upward via
/// `session.parent_session`, incrementing depth per resolved ancestor.
/// **Cycle-bounded**: at most `map.len()+1` loop iterations, so any cyclic
/// chain terminates with a finite (possibly inflated) depth — the test suite
/// (T16g) asserts the bound is `≤ map.len()+2`.
///
/// Called under `sessions.read().await` (the manager already holds that lock
/// for the slice-B global-cap check) — purely sync over a borrowed
/// `&HashMap<SessionId, SessionEntry>`.
pub(crate) fn compute_depth_in_map(map: &HashMap<SessionId, SessionEntry>, sid: &SessionId) -> u32 {
    let mut depth: u32 = 1;
    let mut current = sid.clone();
    let max_hops = map.len().saturating_add(1);
    for _ in 0..max_hops {
        match map.get(&current) {
            Some((session, _)) => match &session.parent_session {
                Some(p) => {
                    depth = depth.saturating_add(1);
                    current = p.clone();
                }
                None => return depth,
            },
            None => return depth,
        }
    }
    depth
}

#[cfg(test)]
mod tests {
    use super::*;
    use advance_shared_types::await_session::{AwaitMode, AwaitOptions, SessionId, TimeoutPolicy};
    use tokio::sync::oneshot;

    use crate::session::AwaitSession;

    fn make_session(id: &str, parent: Option<&str>) -> SessionEntry {
        let opts = AwaitOptions {
            mode: AwaitMode::AllOf,
            idle_timeout_secs: None,
            on_idle_timeout: TimeoutPolicy::Fail,
            keep_losers: false,
        };
        let mut session = AwaitSession::new(
            SessionId(id.to_string()),
            "test-caller".to_string(),
            opts,
            vec![],
        );
        session.parent_session = parent.map(|p| SessionId(p.to_string()));
        let (tx, _rx) = oneshot::channel();
        (session, tx)
    }

    #[test]
    fn t16g_compute_depth_in_map_cycle_bounded() {
        // T16g: 3-cycle s1 -> s2 -> s3 -> s1; starting at s1.
        // Walk terminates within max_hops = map.len()+1 = 4 iterations.
        // Returned depth = 1 + max_hops = 5 (no early-exit since no None
        // hits). Bound: returned depth <= map.len()+2 = 5.
        let mut map: HashMap<SessionId, SessionEntry> = HashMap::new();
        map.insert(SessionId("s1".to_string()), make_session("s1", Some("s2")));
        map.insert(SessionId("s2".to_string()), make_session("s2", Some("s3")));
        map.insert(SessionId("s3".to_string()), make_session("s3", Some("s1")));

        let d = compute_depth_in_map(&map, &SessionId("s1".to_string()));
        assert!(
            d <= (map.len() as u32).saturating_add(2),
            "depth {d} exceeded bound map.len()+2 = {}",
            map.len() + 2
        );
        // No panic and finite — the assertion above implicitly verifies that.
    }

    #[test]
    fn t16g_absent_key_is_depth_1() {
        // Absent key → walk terminates immediately → depth 1.
        let map: HashMap<SessionId, SessionEntry> = HashMap::new();
        let d = compute_depth_in_map(&map, &SessionId("missing".to_string()));
        assert_eq!(d, 1);
    }

    #[test]
    fn t16g_no_parent_is_depth_1() {
        // Single-entry map, parent_session = None → depth 1.
        let mut map: HashMap<SessionId, SessionEntry> = HashMap::new();
        map.insert(SessionId("s1".to_string()), make_session("s1", None));
        let d = compute_depth_in_map(&map, &SessionId("s1".to_string()));
        assert_eq!(d, 1);
    }

    #[test]
    fn t16g_three_level_chain_is_depth_3() {
        // s1 (root) -> s2 -> s3; compute_depth_in_map(s3) = 3.
        let mut map: HashMap<SessionId, SessionEntry> = HashMap::new();
        map.insert(SessionId("s1".to_string()), make_session("s1", None));
        map.insert(SessionId("s2".to_string()), make_session("s2", Some("s1")));
        map.insert(SessionId("s3".to_string()), make_session("s3", Some("s2")));
        let d = compute_depth_in_map(&map, &SessionId("s3".to_string()));
        assert_eq!(d, 3);
    }

    #[test]
    fn t16g_ghost_parent_terminates_early() {
        // Child has parent_session=Some(s_x), but s_x absent from map.
        // Walk terminates at first missing key.
        // Starting at s_child: iter1 follows parent to s_x; iter2 lookup
        // misses → return depth=2.
        let mut map: HashMap<SessionId, SessionEntry> = HashMap::new();
        map.insert(
            SessionId("s_child".to_string()),
            make_session("s_child", Some("s_x")),
        );
        let d = compute_depth_in_map(&map, &SessionId("s_child".to_string()));
        // depth starts at 1, hops to parent (depth=2, current=s_x),
        // next lookup misses → return 2.
        assert_eq!(d, 2);
    }
}
