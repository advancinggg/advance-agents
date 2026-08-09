//! Wave-23 `perchild-daemon-1` seam (e) — `DynamicRouting`: a dual-grammar
//! [`AgentTreeReader`] the production daemon composes as the
//! [`crate::dispatcher::MailboxDispatcherImpl`] routing tree so a runtime-spawned
//! child is reachable via `send`/`await-replies` with NO harness-supplied routing
//! entry (the MODULE-001-AC-22 adjudication, SYS-AC-279).
//!
//! ## Why a colon tree is required (not a bare-tree bridge-resolve)
//!
//! `deliver` → [`crate::hierarchy::validate_routing`] gates on
//! [`crate::id_validation::is_safe_id`], whose grammar is
//! `"system" | "agent:"body | "user:"body` — a BARE id (`default-agent`,
//! `child`) is REJECTED. So the send/await path is inherently COLON-space, and
//! its tree must answer `agent_exists` + `parent_of` over COLON keys. The
//! production `AgentTreeStore`, however, is BARE-keyed. `DynamicRouting` bridges
//! the two GRAMMARS in ONE reader:
//! - a **colon** key (`agent:child`) is answered from an interior-mutable colon
//!   adjacency map written at spawn (`seed_root` / `register_child`);
//! - a **bare** key (`default-agent`, `child`) DELEGATES to the wrapped bare
//!   `AgentTreeStore` — so `deliver_notify`'s bridge-resolved BARE membership
//!   check and the assembler's `# Available Delegates` bare queries keep working
//!   byte-identically.
//!
//! The dispatcher's `deliver` core is UNCHANGED — it just holds a `DynamicRouting`
//! as its `tree` instead of the bare store. Discriminator
//! (routing-entry-absent → `unknown_target`): an unregistered colon child yields
//! `agent_exists(colon) == false` → `validate_routing` returns
//! `InvalidTarget("unknown_target")`.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use advance_shared_types::agent_tree::{AgentKind, AgentTreeReader, Capability};

/// A dual-grammar [`AgentTreeReader`]: colon keys from an interior-mutable
/// spawn-written adjacency map, bare keys delegated to the wrapped bare tree.
pub struct DynamicRouting {
    /// The production bare `AgentTreeStore` (as an `AgentTreeReader`). Bare-key
    /// queries delegate here; the colon map never shadows a bare query.
    bare: Arc<dyn AgentTreeReader>,
    /// Colon adjacency: `agent:<id>` → its COLON parent (`None` for the root).
    /// Written by `seed_root` / `register_child` at spawn; read by the colon
    /// branch of every `AgentTreeReader` method.
    colon: RwLock<HashMap<String, Option<String>>>,
}

impl DynamicRouting {
    /// Wrap the production bare `AgentTreeReader`. The colon map starts empty —
    /// call [`DynamicRouting::seed_root`] once for the daemon root, then
    /// [`DynamicRouting::register_child`] per spawn.
    pub fn new(bare: Arc<dyn AgentTreeReader>) -> Self {
        Self {
            bare,
            colon: RwLock::new(HashMap::new()),
        }
    }

    /// Register the daemon root's colon id (no colon parent). Idempotent
    /// (last-wins on the root's parent, which is always `None`).
    pub fn seed_root(&self, colon_root: &str) {
        if let Ok(mut m) = self.colon.write() {
            m.insert(colon_root.to_string(), None);
        }
    }

    /// Register a spawned child's colon adjacency (`colon_child`'s parent is
    /// `colon_parent`) so `validate_routing` admits parent↔child (and
    /// sibling↔sibling). First-wins: a re-register of an existing colon child is
    /// ignored (a spawned id is unique). Returns `true` on insert.
    pub fn register_child(&self, colon_child: &str, colon_parent: &str) -> bool {
        let Ok(mut m) = self.colon.write() else {
            return false;
        };
        if m.contains_key(colon_child) {
            return false;
        }
        m.insert(colon_child.to_string(), Some(colon_parent.to_string()));
        true
    }

    /// Wave-23 seam (e) teardown: drop a spawned child's colon adjacency when its
    /// serve loop has RETURNED (a component that loaded but trapped in
    /// `bootstrap_and_init`, or a guest stop) — so a subsequent parent send
    /// dead-ends cleanly at `validate_routing` (`unknown_target`) instead of
    /// black-holing into a now-unserved mailbox. Only a CHILD (an entry with a
    /// colon parent) is removable; the root seed (parent `None`) is never removed.
    /// Returns `true` iff an entry was removed.
    pub fn unregister_child(&self, colon_child: &str) -> bool {
        let Ok(mut m) = self.colon.write() else {
            return false;
        };
        if matches!(m.get(colon_child), Some(Some(_))) {
            m.remove(colon_child);
            true
        } else {
            false
        }
    }

    /// `true` iff `key` is a colon id (`agent:` prefix) — routed via the colon
    /// map; else it is bare and delegates to the wrapped store. (`user:` /
    /// `system` senders are handled by `validate_routing` itself, never reaching
    /// a tree lookup for `from`.)
    fn is_colon(key: &str) -> bool {
        key.starts_with("agent:")
    }
}

impl AgentTreeReader for DynamicRouting {
    fn parent_of(&self, agent_id: &str) -> Option<String> {
        if Self::is_colon(agent_id) {
            self.colon.read().ok()?.get(agent_id).cloned().flatten()
        } else {
            self.bare.parent_of(agent_id)
        }
    }

    fn children_of(&self, agent_id: &str) -> Vec<String> {
        if Self::is_colon(agent_id) {
            let Ok(m) = self.colon.read() else {
                return Vec::new();
            };
            m.iter()
                .filter(|(_, parent)| parent.as_deref() == Some(agent_id))
                .map(|(child, _)| child.clone())
                .collect()
        } else {
            self.bare.children_of(agent_id)
        }
    }

    fn siblings_of(&self, agent_id: &str) -> Vec<String> {
        if Self::is_colon(agent_id) {
            let Ok(m) = self.colon.read() else {
                return Vec::new();
            };
            let Some(Some(parent)) = m.get(agent_id).cloned() else {
                return Vec::new();
            };
            m.iter()
                .filter(|(id, p)| id.as_str() != agent_id && p.as_deref() == Some(parent.as_str()))
                .map(|(id, _)| id.clone())
                .collect()
        } else {
            self.bare.siblings_of(agent_id)
        }
    }

    fn agent_exists(&self, agent_id: &str) -> bool {
        if Self::is_colon(agent_id) {
            self.colon
                .read()
                .map(|m| m.contains_key(agent_id))
                .unwrap_or(false)
        } else {
            self.bare.agent_exists(agent_id)
        }
    }

    fn agent_kind(&self, agent_id: &str) -> Option<AgentKind> {
        if Self::is_colon(agent_id) {
            let m = self.colon.read().ok()?;
            match m.get(agent_id) {
                // Colon root (no parent) → Root; a registered colon child → Child.
                Some(None) => Some(AgentKind::Root),
                Some(Some(_)) => Some(AgentKind::Child),
                None => None,
            }
        } else {
            self.bare.agent_kind(agent_id)
        }
    }

    fn capabilities(&self, agent_id: &str) -> Vec<Capability> {
        if Self::is_colon(agent_id) {
            // The colon routing map carries no capability data; colon keys are
            // never capability-queried on the routing path (caps are read from
            // the bare tree node by the assembler). Return empty.
            Vec::new()
        } else {
            self.bare.capabilities(agent_id)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use advance_shared_types::agent_tree::{AgentKind, Capability};

    /// A minimal bare `AgentTreeReader` fixture (bare keys only).
    #[derive(Default)]
    struct BareFixture {
        // bare id -> bare parent
        nodes: HashMap<String, Option<String>>,
    }
    impl BareFixture {
        fn with(pairs: &[(&str, Option<&str>)]) -> Self {
            let mut nodes = HashMap::new();
            for (id, p) in pairs {
                nodes.insert(id.to_string(), p.map(|s| s.to_string()));
            }
            Self { nodes }
        }
    }
    impl AgentTreeReader for BareFixture {
        fn parent_of(&self, id: &str) -> Option<String> {
            self.nodes.get(id).cloned().flatten()
        }
        fn children_of(&self, id: &str) -> Vec<String> {
            self.nodes
                .iter()
                .filter(|(_, p)| p.as_deref() == Some(id))
                .map(|(c, _)| c.clone())
                .collect()
        }
        fn siblings_of(&self, _id: &str) -> Vec<String> {
            Vec::new()
        }
        fn agent_exists(&self, id: &str) -> bool {
            self.nodes.contains_key(id)
        }
        fn agent_kind(&self, id: &str) -> Option<AgentKind> {
            self.nodes.get(id).map(|p| {
                if p.is_none() {
                    AgentKind::Root
                } else {
                    AgentKind::Child
                }
            })
        }
        fn capabilities(&self, _id: &str) -> Vec<Capability> {
            Vec::new()
        }
    }

    // T-E1: colon child registration answers agent_exists + parent_of in colon
    // space; bare keys delegate to the wrapped store (notify path preserved).
    #[test]
    fn t_e1_dual_grammar_routing() {
        // Bare tree: root default-agent + a spawned child (bare) under it.
        let bare = Arc::new(BareFixture::with(&[
            ("default-agent", None),
            ("child-1", Some("default-agent")),
        ]));
        let dr = DynamicRouting::new(bare);
        dr.seed_root("agent:default");
        assert!(dr.register_child("agent:child-1", "agent:default"));

        // Colon send-path facts (what validate_routing consumes):
        assert!(dr.agent_exists("agent:child-1"));
        assert_eq!(
            dr.parent_of("agent:child-1"),
            Some("agent:default".to_string())
        );
        assert_eq!(dr.parent_of("agent:default"), None); // root

        // Bare delegation (notify membership path): the wrapped store answers.
        assert!(dr.agent_exists("default-agent"));
        assert!(dr.agent_exists("child-1"));
        assert_eq!(dr.parent_of("child-1"), Some("default-agent".to_string()));

        // Unregistered colon child → false (routing-entry-absent discriminator).
        assert!(!dr.agent_exists("agent:child-2"));

        // children_of / agent_kind in colon space.
        assert_eq!(dr.children_of("agent:default"), vec!["agent:child-1"]);
        assert_eq!(dr.agent_kind("agent:default"), Some(AgentKind::Root));
        assert_eq!(dr.agent_kind("agent:child-1"), Some(AgentKind::Child));

        // register_child is first-wins.
        assert!(!dr.register_child("agent:child-1", "agent:default"));
    }

    // T-E1 (Wave-23 seam e teardown): unregister_child drops a child's colon
    // adjacency (so a subsequent send dead-ends unknown_target) but never the root.
    #[test]
    fn t_e1_unregister_child_drops_child_never_root() {
        let bare = Arc::new(BareFixture::with(&[("default-agent", None)]));
        let dr = DynamicRouting::new(bare);
        dr.seed_root("agent:default");
        assert!(dr.register_child("agent:child-1", "agent:default"));
        assert!(dr.agent_exists("agent:child-1"));

        // Teardown removes the child → agent_exists false (send now unknown_target).
        assert!(dr.unregister_child("agent:child-1"));
        assert!(!dr.agent_exists("agent:child-1"));
        assert_eq!(dr.parent_of("agent:child-1"), None);
        // Idempotent: a second teardown finds nothing.
        assert!(!dr.unregister_child("agent:child-1"));

        // The root (parent None) is NOT a child — teardown refuses it.
        assert!(!dr.unregister_child("agent:default"));
        assert!(dr.agent_exists("agent:default"));

        // After teardown the id can be RE-registered (a fresh spawn).
        assert!(dr.register_child("agent:child-1", "agent:default"));
        assert!(dr.agent_exists("agent:child-1"));
    }

    // T-E1: sibling adjacency in colon space (two children of the same parent).
    #[test]
    fn t_e1_colon_siblings() {
        let bare = Arc::new(BareFixture::with(&[("default-agent", None)]));
        let dr = DynamicRouting::new(bare);
        dr.seed_root("agent:default");
        dr.register_child("agent:a", "agent:default");
        dr.register_child("agent:b", "agent:default");
        let sibs = dr.siblings_of("agent:a");
        assert_eq!(sibs, vec!["agent:b"]);
    }
}
