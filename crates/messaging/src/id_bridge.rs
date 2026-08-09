//! Wave-19 Lane-2 — the colon/bare agent-id bridge (`AgentIdBridge`).
//!
//! ## The residual this closes (MODULE-006 §3.6 AC-02 *membership* leg)
//!
//! Two mutually-incompatible id grammars coexist in the runtime:
//! - **COLON** msg-id (`agent:default`): what [`crate::id_validation::is_safe_id`]
//!   requires (`"system" | agent:<body> | user:<body>`) — the `MailboxStore` key,
//!   the serve-loop poll key, the dispatch / reply-registry id.
//! - **BARE** cap-id (`default-agent`): what `cap-lifecycle`'s `AgentTreeStore` is
//!   keyed on and what its `validate_agent_id` accepts (charset `[A-Za-z0-9_-]`,
//!   ≤64 bytes — a colon is REJECTED).
//!
//! The bodies even differ (`agent:default` ≠ `default-agent`), so a plain
//! `strip_prefix("agent:")` cannot bridge them. The consequence: a production
//! `notify_agent`/`notify_channel` target passes `is_safe_id` (colon) but then
//! fails `tree.agent_exists` against the bare-keyed tree → `target_unknown`, and
//! nothing is ever delivered.
//!
//! ## What this is
//!
//! An immutable, injected resolver of explicit colon/bare **equivalence classes**
//! (the Wave-12 alias-bridge pattern transplanted to the messaging delivery path,
//! cf. `context-engine::tier2_delegates`). Each class pairs a `mailbox_key` (the
//! canonical colon poll-key) with a `bare_tree_key` (the bare tree membership
//! key); BOTH forms are class members. [`AgentIdBridge::resolve`] maps a target
//! to its `(bare_tree_key, mailbox_key)` — used for membership AND mailbox keying
//! via the SAME resolution, so there is no "membership passes / mailbox orphans"
//! split. A non-member resolves to `None` (the caller then uses the target
//! verbatim — today's behavior). **There is deliberately NO strip-prefix
//! fallback**: it would let `agent:default-agent` pass membership via
//! `strip→default-agent` while keying an orphan mailbox `agent:default-agent`.
//!
//! ## Safety
//!
//! `is_safe_id` is still the first admission gate at the dispatcher entry; the
//! class map is closed (only explicitly-registered ids bridge) and every class
//! key is charset-validated at construction. A malformed/unbridged target falls
//! through to the dispatcher's existing `tree.agent_exists` → `target_unknown`.
//! The local bare-id check below is fail-FAST defense-in-depth; the AUTHORITATIVE,
//! always-run gate is the runtime `AgentTreeReader::agent_exists` → real
//! `cap-lifecycle::identifier::validate_agent_id` — a drifted/malformed class just
//! goes silently non-functional (`target_unknown`), never an orphan or a malformed
//! acceptance.
//!
//! ## Wiring
//!
//! Injected opt-in via `MailboxDispatcherImpl::with_id_bridge`; the dispatcher's
//! default is `None` → byte-identical behavior. Wave-23 `perchild-daemon-1` WIRES
//! it into the production cli composition root (`wiring.rs` hoists a shared bridge
//! seeded with the root pair; the `PerChildLoopManager` `register`s each spawned
//! child's colon/bare pair at spawn (seam (e)) and `unregister`s it when the
//! child's serve loop returns). The `notify` membership residual (MODULE-006 §3.6
//! AC-02 row / §3.8 (k)) is a separate slice.

use crate::id_validation::is_safe_id;
use std::collections::HashMap;
use std::sync::RwLock;

/// Maximum length of a bare tree-id. A LOCAL mirror of `cap-lifecycle`'s
/// `identifier::MAX_AGENT_ID_LEN` (= 64): `cap-lifecycle` already depends on
/// `advance-messaging`, so importing its validator back here would be a Cargo
/// cyclic-package build failure, and `shared-types` exposes only a doc-comment
/// invariant (no callable validator). Kept in sync by the `cfg(test)`
/// `local_bare_len_matches_cap_lifecycle` parity marker below; the authoritative
/// gate is the runtime `agent_exists` → real `validate_agent_id`.
const MAX_BARE_ID_LEN: usize = 64;

/// `true` iff `s` matches the bare cap-id grammar `[A-Za-z0-9_-]{1,64}` — the
/// local mirror of `cap-lifecycle::identifier::validate_agent_id`'s charset +
/// length check (colons rejected).
fn is_valid_bare_tree_id(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= MAX_BARE_ID_LEN
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
}

/// The resolved keys for a bridged target (borrows from the [`AgentIdBridge`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Resolved<'a> {
    /// The BARE id to query the (bare-keyed) `AgentTreeReader` membership with.
    pub bare_tree_key: &'a str,
    /// The canonical mailbox key (the colon serve-loop poll key) to deliver to.
    pub mailbox_key: &'a str,
}

/// One colon/bare equivalence class: the canonical keys for a single agent.
struct Class {
    bare_tree_key: String,
    mailbox_key: String,
}

/// An injected colon/bare id resolver (Wave-19 Lane-2). See the module docs. The
/// `from_pairs` seed classes are immutable; Wave-23 `perchild-daemon-1` adds an
/// interior-mutable `registered` overflow map so the per-child daemon can
/// **register a spawned child's colon/bare pair at spawn** (seam (e)) without a
/// rebuild. Empty (`Default`) + no registrations → every `resolve`/`resolve_owned`
/// returns `None` (byte-identical to no bridge).
#[derive(Default)]
pub struct AgentIdBridge {
    /// Every seeded member id-form → its class index. A target is "bridged"
    /// iff it is a member; non-members → `None` (no strip-prefix fallback).
    members: HashMap<String, usize>,
    classes: Vec<Class>,
    /// Wave-23 seam (e): runtime-registered classes (spawned children). Keyed by
    /// BOTH member forms → the `(bare_tree_key, mailbox_key)` pair. Consulted ONLY
    /// by [`AgentIdBridge::resolve_owned`] (the borrowed [`AgentIdBridge::resolve`]
    /// stays seed-only for back-compat — a lock guard cannot outlive a `&str`
    /// borrow). Interior-mutable so the immutable `Arc<AgentIdBridge>` the
    /// dispatcher holds can gain child pairs post-construction.
    registered: RwLock<HashMap<String, (String, String)>>,
}

impl AgentIdBridge {
    /// Build from `(mailbox_key /*colon, is_safe_id*/, bare_tree_key /*bare,
    /// [A-Za-z0-9_-]{1,64}*/)` pairs. Each pair forms one class whose members are
    /// BOTH forms. A pair with a `mailbox_key` failing `is_safe_id` or a
    /// `bare_tree_key` failing the local bare grammar is REJECTED (skipped) — a
    /// malformed class never produces a match. A member already registered (in an
    /// earlier class) is left untouched (first-wins; no silent re-aliasing).
    pub fn from_pairs<I, S>(pairs: I) -> Self
    where
        I: IntoIterator<Item = (S, S)>,
        S: Into<String>,
    {
        let mut bridge = AgentIdBridge::default();
        for (mailbox_key, bare_tree_key) in pairs {
            bridge.insert_class(mailbox_key.into(), bare_tree_key.into());
        }
        bridge
    }

    /// Insert one equivalence class. Validates both keys (fail-fast
    /// defense-in-depth); a malformed key or an already-registered member drops
    /// the class without panicking.
    fn insert_class(&mut self, mailbox_key: String, bare_tree_key: String) {
        if !is_safe_id(&mailbox_key) || !is_valid_bare_tree_id(&bare_tree_key) {
            return;
        }
        if self.members.contains_key(&mailbox_key) || self.members.contains_key(&bare_tree_key) {
            return;
        }
        let idx = self.classes.len();
        self.members.insert(mailbox_key.clone(), idx);
        if bare_tree_key != mailbox_key {
            self.members.insert(bare_tree_key.clone(), idx);
        }
        self.classes.push(Class {
            bare_tree_key,
            mailbox_key,
        });
    }

    /// Resolve `target` to its `(bare_tree_key, mailbox_key)` iff it is a
    /// registered class member; else `None` (the caller uses `target` verbatim).
    pub fn resolve(&self, target: &str) -> Option<Resolved<'_>> {
        let idx = *self.members.get(target)?;
        let class = &self.classes[idx];
        Some(Resolved {
            bare_tree_key: &class.bare_tree_key,
            mailbox_key: &class.mailbox_key,
        })
    }

    /// `true` iff no SEED classes are registered (`resolve` always returns
    /// `None`). Does NOT reflect runtime `register`ed children (see
    /// `resolve_owned`).
    pub fn is_empty(&self) -> bool {
        self.classes.is_empty()
    }

    /// Wave-23 seam (e): register a spawned child's colon/bare equivalence class
    /// at runtime (interior mutability). Validates both keys with the SAME
    /// fail-fast gates as [`AgentIdBridge::from_pairs`] (`is_safe_id(mailbox_key)`
    /// colon + `is_valid_bare_tree_id(bare_tree_key)`); a malformed pair, or a form
    /// already present in a SEED class OR a prior registration, is dropped
    /// (first-wins, no silent re-aliasing) and returns `false`. On success both
    /// member forms map to the `(bare_tree_key, mailbox_key)` pair and the method
    /// returns `true`. Consulted by [`AgentIdBridge::resolve_owned`].
    pub fn register(&self, mailbox_key: &str, bare_tree_key: &str) -> bool {
        if !is_safe_id(mailbox_key) || !is_valid_bare_tree_id(bare_tree_key) {
            return false;
        }
        // A member already claimed by a seed class must not be re-aliased.
        if self.members.contains_key(mailbox_key) || self.members.contains_key(bare_tree_key) {
            return false;
        }
        let mut reg = match self.registered.write() {
            Ok(g) => g,
            Err(_) => return false, // poisoned lock → fail-closed (stay non-functional)
        };
        if reg.contains_key(mailbox_key) || reg.contains_key(bare_tree_key) {
            return false;
        }
        let pair = (bare_tree_key.to_string(), mailbox_key.to_string());
        reg.insert(mailbox_key.to_string(), pair.clone());
        if bare_tree_key != mailbox_key {
            reg.insert(bare_tree_key.to_string(), pair);
        }
        true
    }

    /// Owned-return sibling of [`AgentIdBridge::resolve`] that consults BOTH the
    /// immutable seed classes AND the runtime-`register`ed children. Returns
    /// `(bare_tree_key, mailbox_key)` iff `target` is a member of either; else
    /// `None` (the caller uses `target` verbatim). Owned because the runtime map
    /// lives behind a lock (a borrow cannot outlive the guard). The seed classes
    /// win over registrations (they can never collide — `register` rejects a
    /// seed-claimed member).
    pub fn resolve_owned(&self, target: &str) -> Option<(String, String)> {
        if let Some(&idx) = self.members.get(target) {
            let class = &self.classes[idx];
            return Some((class.bare_tree_key.clone(), class.mailbox_key.clone()));
        }
        self.registered.read().ok()?.get(target).cloned()
    }

    /// Wave-23 seam (e) teardown: drop a runtime-`register`ed child's class (both
    /// member forms) when its serve loop has returned. ONLY the interior-mutable
    /// `registered` overflow map is touched — a SEED class is immutable and is
    /// never removed (a seed-claimed form short-circuits to `false`, so the root
    /// pair can never be torn down). Returns `true` iff a registration was removed.
    pub fn unregister(&self, mailbox_key: &str, bare_tree_key: &str) -> bool {
        if self.members.contains_key(mailbox_key) || self.members.contains_key(bare_tree_key) {
            return false;
        }
        let Ok(mut reg) = self.registered.write() else {
            return false;
        };
        let removed_colon = reg.remove(mailbox_key).is_some();
        let removed_bare = reg.remove(bare_tree_key).is_some();
        removed_colon || removed_bare
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // TB-IDB-01: explicit equivalence-class resolve (both forms → same canonical).
    #[test]
    fn tb_idb_01a_class_resolve_both_forms() {
        let b = AgentIdBridge::from_pairs([("agent:default", "default-agent")]);
        let colon = b.resolve("agent:default").expect("colon form is a member");
        assert_eq!(colon.bare_tree_key, "default-agent");
        assert_eq!(colon.mailbox_key, "agent:default");
        let bare = b.resolve("default-agent").expect("bare form is a member");
        assert_eq!(bare.bare_tree_key, "default-agent");
        assert_eq!(bare.mailbox_key, "agent:default");
        // Both forms resolve to the SAME canonical mailbox key.
        assert_eq!(colon.mailbox_key, bare.mailbox_key);
    }

    // TB-IDB-01 (cont.): non-members → None (NO strip-prefix orphan path).
    #[test]
    fn tb_idb_01b_non_member_none() {
        let b = AgentIdBridge::from_pairs([("agent:default", "default-agent")]);
        // The classic orphan-key trap target: a colon id whose strip (`default-agent`)
        // would match the tree but is NOT a registered member here.
        assert!(b.resolve("agent:default-agent").is_none());
        assert!(b.resolve("agent:other").is_none());
        assert!(b.resolve("default").is_none());
        assert!(b.resolve("user:alice").is_none());
        assert!(b.resolve("").is_none());
    }

    // TB-IDB-01 (cont.): construction rejects a malformed class (charset/length),
    // so a malformed key never produces a match.
    #[test]
    fn tb_idb_01c_malformed_class_rejected() {
        // bad bare_tree_key: contains a colon (fails the bare grammar).
        let b1 = AgentIdBridge::from_pairs([("agent:x", "bad:bare")]);
        assert!(b1.is_empty());
        assert!(b1.resolve("agent:x").is_none());
        // bad bare_tree_key: newline.
        let b2 = AgentIdBridge::from_pairs([("agent:x", "bad\nbare")]);
        assert!(b2.is_empty());
        // bad bare_tree_key: over 64 bytes.
        let long = "a".repeat(65);
        let b3 = AgentIdBridge::from_pairs([("agent:x".to_string(), long)]);
        assert!(b3.is_empty());
        // bad mailbox_key: not is_safe_id (no colon prefix, not "system").
        let b4 = AgentIdBridge::from_pairs([("bare-mailbox", "ok-bare")]);
        assert!(b4.is_empty());
        // bad mailbox_key: multi-colon (is_safe_id rejects).
        let b5 = AgentIdBridge::from_pairs([("agent:a:b", "ok-bare")]);
        assert!(b5.is_empty());
    }

    // Empty/default bridge → resolve always None (byte-identical to no bridge).
    #[test]
    fn tb_idb_01d_empty_default_resolves_none() {
        let b = AgentIdBridge::default();
        assert!(b.is_empty());
        assert!(b.resolve("agent:default").is_none());
        let b2 = AgentIdBridge::from_pairs(Vec::<(String, String)>::new());
        assert!(b2.is_empty());
    }

    // A class whose mailbox_key == bare_tree_key (e.g. an already-colon-free id
    // used identically on both sides) registers once and resolves to itself.
    #[test]
    fn tb_idb_01e_identity_class() {
        // "system" is is_safe_id-valid but NOT a valid bare tree id (it has no
        // colon but IS a reserved word); use a plain bare id that is valid on
        // BOTH sides only if is_safe_id accepts it — it does not (no prefix), so
        // such a degenerate pair is rejected. Confirm a normal distinct pair with
        // matching member bodies is handled (defensive dedup, no double-insert).
        let b = AgentIdBridge::from_pairs([("agent:svc-1", "svc-1")]);
        let r = b.resolve("svc-1").expect("bare member");
        assert_eq!(r.bare_tree_key, "svc-1");
        assert_eq!(r.mailbox_key, "agent:svc-1");
    }

    // TB-IDB-REG (Wave-23 seam e, T-E2): runtime register + resolve_owned.
    #[test]
    fn tb_idb_reg_register_and_resolve_owned() {
        // Seed only the root; register a child at runtime.
        let b = AgentIdBridge::from_pairs([("agent:default", "default-agent")]);
        assert!(b.register("agent:child-1", "child-1"));
        // Both child forms resolve via resolve_owned to the (bare, colon) pair.
        let (bare, mailbox) = b.resolve_owned("agent:child-1").expect("colon child");
        assert_eq!(bare, "child-1");
        assert_eq!(mailbox, "agent:child-1");
        let (bare2, mailbox2) = b.resolve_owned("child-1").expect("bare child");
        assert_eq!(bare2, "child-1");
        assert_eq!(mailbox2, "agent:child-1");
        // The seed root still resolves via resolve_owned (seed wins).
        let (rb, rm) = b.resolve_owned("agent:default").expect("seed root");
        assert_eq!(rb, "default-agent");
        assert_eq!(rm, "agent:default");
        // The borrowed resolve() stays seed-only (does NOT see registrations).
        assert!(b.resolve("agent:child-1").is_none());
        assert!(b.resolve("agent:default").is_some());
        // Unregistered target → None.
        assert!(b.resolve_owned("agent:other").is_none());
    }

    // TB-IDB-REG: register rejects malformed pairs + seed/registration collisions.
    #[test]
    fn tb_idb_reg_rejects_malformed_and_collisions() {
        let b = AgentIdBridge::from_pairs([("agent:default", "default-agent")]);
        // Malformed: colon in the bare key.
        assert!(!b.register("agent:x", "bad:bare"));
        // Malformed: mailbox key not is_safe_id.
        assert!(!b.register("bare-mailbox", "ok-bare"));
        // Collision with a SEED member (mailbox form).
        assert!(!b.register("agent:default", "some-bare"));
        // Collision with a SEED member (bare form).
        assert!(!b.register("agent:zzz", "default-agent"));
        // First registration wins; a second on the same form is dropped.
        assert!(b.register("agent:c1", "c1"));
        assert!(!b.register("agent:c1", "c1-other"));
        assert!(!b.register("agent:c1-other", "c1"));
        // The dropped re-registrations did not perturb the first.
        let (bare, mailbox) = b.resolve_owned("agent:c1").expect("first reg");
        assert_eq!(bare, "c1");
        assert_eq!(mailbox, "agent:c1");
    }

    // TB-IDB-REG (Wave-23 seam e teardown): unregister drops a runtime class (both
    // forms) but never a seed class.
    #[test]
    fn tb_idb_reg_unregister_drops_runtime_never_seed() {
        let b = AgentIdBridge::from_pairs([("agent:default", "default-agent")]);
        assert!(b.register("agent:child-1", "child-1"));
        // Both forms resolve before teardown.
        assert!(b.resolve_owned("agent:child-1").is_some());
        assert!(b.resolve_owned("child-1").is_some());
        // Teardown removes BOTH member forms.
        assert!(b.unregister("agent:child-1", "child-1"));
        assert!(b.resolve_owned("agent:child-1").is_none());
        assert!(b.resolve_owned("child-1").is_none());
        // Idempotent: a second teardown finds nothing to remove.
        assert!(!b.unregister("agent:child-1", "child-1"));
        // A SEED class is immutable — teardown refuses it and the root still resolves.
        assert!(!b.unregister("agent:default", "default-agent"));
        assert!(b.resolve_owned("agent:default").is_some());
        // After teardown the id can be RE-registered (a fresh spawn of the same id).
        assert!(b.register("agent:child-1", "child-1"));
        assert!(b.resolve_owned("agent:child-1").is_some());
    }

    // Parity marker (plan-eval r5/r6): MAX_BARE_ID_LEN MUST equal
    // cap-lifecycle::identifier::MAX_AGENT_ID_LEN (64). Pinned here because the
    // cross-crate import is a cyclic-dependency build failure; if cap-lifecycle
    // changes its cap, update this const + this assert together. The runtime
    // agent_exists → validate_agent_id gate is authoritative either way.
    #[test]
    fn local_bare_len_matches_cap_lifecycle() {
        assert_eq!(MAX_BARE_ID_LEN, 64);
        // 64-byte bare id accepted; 65-byte rejected.
        assert!(is_valid_bare_tree_id(&"a".repeat(64)));
        assert!(!is_valid_bare_tree_id(&"a".repeat(65)));
    }
}
