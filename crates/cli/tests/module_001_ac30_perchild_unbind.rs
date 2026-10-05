//! MODULE-001-AC-30 — `PerChildLoopManager::unbind` breaks the per-child manager ↔ host
//! registry cycle on a home without a git repository (`fs`, `messaging`, `lifecycle`): once
//! the manager is unbound and the wiring's owners let go, the manager and the EventBus die.
//! Non-vacuity: while one strong clone of the EventBus is held, the EventBus is reported
//! alive.
#![cfg(unix)]

#[path = "support/all_caps_home.rs"]
mod all_caps_home;

use std::sync::Arc;
use std::time::{Duration, Instant};

use advance_runtime::bootstrap::RuntimeHostBuilder;
use all_caps_home::{ensure_in_process_master_key, AllCapsHome};

const BUDGET: Duration = Duration::from_secs(2);

fn poll_until(budget: Duration, mut done: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + budget;
    loop {
        if done() {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn module_001_ac30_perchild_unbind_breaks_registry_cycle() {
    ensure_in_process_master_key();
    let home = AllCapsHome::declaring(&["fs", "messaging", "lifecycle"], false);
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("tokio runtime");

    let (manager, bus, held_bus) = runtime.block_on(async {
        let builder = RuntimeHostBuilder::new(&home.config_path(), &home.ws)
            .await
            .expect("RuntimeHostBuilder::new");
        let (host, handles) = advance_cli::wiring::wire_capabilities_with_home_for_test(
            builder,
            &home.ws,
            &home.home_dir(),
        )
        .await
        .expect("wire_capabilities_with_home_for_test");
        let manager = handles
            .perchild_manager
            .as_ref()
            .expect("messaging + lifecycle: the per-child manager exists");
        let weak_manager = Arc::downgrade(manager);
        let weak_bus = Arc::downgrade(&handles.event_bus);
        let held_bus = Arc::clone(&handles.event_bus);
        manager.unbind();
        drop(handles);
        drop(host);
        (weak_manager, weak_bus, held_bus)
    });
    runtime.shutdown_timeout(Duration::from_secs(10));

    // Non-vacuity: the held clone keeps the EventBus alive.
    assert!(
        poll_until(BUDGET, || manager.strong_count() == 0),
        "the unbound per-child manager dies"
    );
    assert!(
        bus.strong_count() > 0,
        "the held clone keeps the EventBus alive"
    );

    drop(held_bus);
    assert!(
        poll_until(BUDGET, || bus.strong_count() == 0),
        "the EventBus dies once its last holder lets go"
    );
}
