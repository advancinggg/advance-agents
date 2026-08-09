//! `register_agent_memory` — host-fn registration entry point for the
//! `agent-memory` WIT interface. Mirrors the cap-fs `register_agent_fs`
//! precedent (`crates/capabilities/cap-fs/src/host_fn.rs`).
//!
//! Registers 5 `HostFunctionSpec`s under capability `"memory"` and namespace
//! `"advance:runtime/agent-memory@0.1.0"`. The same `Arc<MemoryStore>` is shared
//! across the 5 handlers, AND should be shared with the post-processor's
//! `Components.store` so the WIT-side reads see the writes the post-processor
//! made (see `Components::register_agent_memory` in `post_processor.rs`).

use std::sync::Arc;

use advance_runtime::host_registry::{HostFunctionSpec, HostRegistry};
use advance_shared_types::traits::{EventBusEmit, RememberContentPolicy};

use crate::l6::cursor::L6CursorStore;
use crate::rollback::MemoryGitRestore;
use crate::store::MemoryStore;
use crate::wit_impl::{
    ForgetHandler, RecallAtHandler, RecallHandler, RememberHandler, RollbackMemoryHandler,
};

pub const CAPABILITY: &str = "memory";
pub const NAMESPACE: &str = "advance:runtime/agent-memory@0.1.0";

pub fn register_agent_memory(
    registry: &dyn HostRegistry,
    store: Arc<MemoryStore>,
    event_bus: Arc<dyn EventBusEmit + Send + Sync>,
    cursor_store: Arc<L6CursorStore>,
) {
    register_agent_memory_with_git(registry, store, event_bus, cursor_store, None)
}

/// rollback-memory slice (2026-06-12): additive sibling threading the
/// [`MemoryGitRestore`] seam into `rollback-memory` (AC-18 git half —
/// `_knowledge_map.yaml` + `syntheses/*.md` restored from history; the store
/// owns knowledge.jsonl in-process). `None` ⇒ identical to
/// [`register_agent_memory`] (the pre-slice surface, byte-compatible).
///
/// Delegates to [`register_agent_memory_with_git_and_policy`] with `policy = None`
/// (byte-identical — no producer-boundary guard).
pub fn register_agent_memory_with_git(
    registry: &dyn HostRegistry,
    store: Arc<MemoryStore>,
    event_bus: Arc<dyn EventBusEmit + Send + Sync>,
    cursor_store: Arc<L6CursorStore>,
    git_restore: Option<Arc<dyn MemoryGitRestore>>,
) {
    register_agent_memory_with_git_and_policy(
        registry,
        store,
        event_bus,
        cursor_store,
        git_restore,
        None,
    )
}

/// Wave-23 m005-knowledge (MODULE-005-AC-29): the superset registration threading
/// the producer-boundary [`RememberContentPolicy`] (CONTRACT-214) into the
/// `remember` handler ONLY. `policy = None` ⇒ byte-identical to
/// [`register_agent_memory_with_git`]; `Some(p)` makes the live `remember()` path
/// reject content detected as raw file-resident bytes. The other 4 handlers are
/// unaffected. Production supplies `Some(WorkspaceFileResidentPolicy)` at the cli
/// composition root (`crates/cli/src/wiring.rs`).
pub fn register_agent_memory_with_git_and_policy(
    registry: &dyn HostRegistry,
    store: Arc<MemoryStore>,
    event_bus: Arc<dyn EventBusEmit + Send + Sync>,
    cursor_store: Arc<L6CursorStore>,
    git_restore: Option<Arc<dyn MemoryGitRestore>>,
    policy: Option<Arc<dyn RememberContentPolicy>>,
) {
    let cap = CAPABILITY.to_string();
    let ns = NAMESPACE.to_string();

    registry.register(HostFunctionSpec {
        capability: cap.clone(),
        namespace: ns.clone(),
        name: "remember".into(),
        idempotent: false,
        handler: Arc::new(RememberHandler::with_policy(
            store.clone(),
            event_bus.clone(),
            policy,
        )),
    });
    registry.register(HostFunctionSpec {
        capability: cap.clone(),
        namespace: ns.clone(),
        name: "recall".into(),
        idempotent: true,
        handler: Arc::new(RecallHandler::new(store.clone(), event_bus.clone())),
    });
    registry.register(HostFunctionSpec {
        capability: cap.clone(),
        namespace: ns.clone(),
        name: "forget".into(),
        idempotent: false,
        handler: Arc::new(ForgetHandler::new(store.clone(), event_bus.clone())),
    });
    registry.register(HostFunctionSpec {
        capability: cap.clone(),
        namespace: ns.clone(),
        name: "recall-at".into(),
        idempotent: true,
        handler: Arc::new(RecallAtHandler::new(store.clone(), event_bus.clone())),
    });
    registry.register(HostFunctionSpec {
        capability: cap,
        namespace: ns,
        name: "rollback-memory".into(),
        idempotent: false,
        handler: Arc::new(RollbackMemoryHandler::new_with_git_restore(
            store,
            event_bus,
            cursor_store,
            git_restore,
        )),
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::NoopEventBus;
    use advance_runtime::host_registry::InMemoryHostRegistry;

    #[test]
    fn register_5_specs() {
        let reg = InMemoryHostRegistry::new();
        let store = Arc::new(MemoryStore::new());
        register_agent_memory(
            &reg,
            store,
            Arc::new(NoopEventBus),
            Arc::new(L6CursorStore::new()),
        );
        let specs = reg.lookup(CAPABILITY);
        assert_eq!(specs.len(), 5);
        let names: std::collections::HashSet<_> = specs.iter().map(|s| s.name.as_str()).collect();
        assert!(names.contains("remember"));
        assert!(names.contains("recall"));
        assert!(names.contains("forget"));
        assert!(names.contains("recall-at"));
        assert!(names.contains("rollback-memory"));
        for s in &specs {
            assert_eq!(s.capability, CAPABILITY);
            assert_eq!(s.namespace, NAMESPACE);
        }
    }

    #[test]
    fn idempotent_flags() {
        let reg = InMemoryHostRegistry::new();
        let store = Arc::new(MemoryStore::new());
        register_agent_memory(
            &reg,
            store,
            Arc::new(NoopEventBus),
            Arc::new(L6CursorStore::new()),
        );
        let specs = reg.lookup(CAPABILITY);
        for s in specs {
            let expected = matches!(s.name.as_str(), "recall" | "recall-at");
            assert_eq!(s.idempotent, expected, "idempotent for {}", s.name);
        }
    }
}
