//! A guard for tests that wire a `messaging` home in-process (`wire_capabilities*`) and then
//! drop the wiring without the composition's teardown.
//!
//! With `messaging` declared, the per-child manager is the spawner's observer in the host
//! registry, and it holds the capability injector (and, once `spawn_test_agent_loop` ran on an
//! `llm` home, the context deps), which hold that registry: the manager and the registry keep
//! each other, and with them the whole wiring graph, alive until `PerChildLoopManager::unbind`.
//! The composition's teardown unbinds; dropping `WiringHandles` and `RuntimeHost` does not.
//! Since the wiring bootstraps a git repository in every initialized workspace (32cff619), the
//! graph of an `fs` home holds a sender of the git commit queue, whose worker waits on the test
//! runtime's blocking pool: without the unbind, the runtime's drop waits for it forever.
//!
//! Create the guard right after the wiring. It is dropped before the handles and the host, and
//! also when an assertion fails (a panic drops the test body's locals before the runtime).
//!
//! Including test: `#[path = "support/unbind_on_drop.rs"] mod unbind_on_drop;`.
#![allow(dead_code)]

use std::sync::Arc;

use advance_cli::perchild_daemon::PerChildLoopManager;

/// Unbinds the per-child manager, when the wiring built one, on drop.
pub struct UnbindOnDrop(Option<Arc<PerChildLoopManager>>);

impl UnbindOnDrop {
    pub fn new(manager: Option<&Arc<PerChildLoopManager>>) -> Self {
        Self(manager.cloned())
    }
}

impl Drop for UnbindOnDrop {
    fn drop(&mut self) {
        if let Some(manager) = self.0.take() {
            manager.unbind();
        }
    }
}
