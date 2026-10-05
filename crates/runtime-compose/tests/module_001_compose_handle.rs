//! MODULE-001-AC-30 — `ComposedRuntime`: `wait` resolves once a triggered shutdown has
//! completed, dropping the runtime starts its shutdown, `client_api()` is gone as soon as
//! the shutdown is triggered, `health()` reports the root loop and the guard, and
//! `root_agent_id()` is the root identity the home persists.
//!
//! The compositions of this binary run one at a time (`serial`).

#[path = "support/t111.rs"]
mod t111;

use std::sync::Arc;
use std::time::Duration;

use advance_runtime_compose::registry::reserved_homes_for_test;
use advance_runtime_compose::test_support::MemoryComposeLog;
use advance_runtime_compose::{compose, ComposedRuntime, InstanceGuardKind, RuntimePhase};
use t111::{poll_until, serial, T111Home, OBJECTS_BUDGET};

async fn compose_home(home: &T111Home) -> ComposedRuntime {
    compose(home.options(Arc::new(MemoryComposeLog::new())), Vec::new())
        .await
        .expect("compose")
}

#[tokio::test(flavor = "current_thread")]
async fn module_001_ac30_wait_resolves_after_trigger() {
    let _serial = serial();
    let home = T111Home::new(&["fs"], true);
    let runtime = compose_home(&home).await;
    assert_eq!(runtime.health().phase, RuntimePhase::Running);

    assert!(runtime.shutdown_handle().trigger());
    tokio::time::timeout(Duration::from_secs(30), runtime.wait())
        .await
        .expect("wait resolves once the shutdown has completed");
    assert_eq!(runtime.health().phase, RuntimePhase::Stopped);
    assert!(!home.lock_path().exists(), "the guard was released");
    tokio::time::timeout(Duration::from_secs(1), runtime.shutdown())
        .await
        .expect("shutdown returns at once after a completed shutdown")
        .expect("shutdown");
}

#[tokio::test(flavor = "current_thread")]
async fn module_001_ac30_drop_of_composed_runtime_triggers_shutdown() {
    let _serial = serial();
    let home = T111Home::new(&["fs"], true);
    let runtime = compose_home(&home).await;
    let handle = runtime.shutdown_handle();
    assert!(!handle.is_triggered());

    drop(runtime);
    assert!(
        handle.is_triggered(),
        "dropping the runtime triggers its shutdown"
    );
    let released = poll_until(Duration::from_secs(5), || {
        !home.lock_path().exists() && reserved_homes_for_test().is_empty()
    })
    .await;
    assert!(
        released,
        "the shutdown runs to its end: the lock and the reservation are released"
    );
    let again = compose_home(&home).await;
    again.shutdown().await.expect("shutdown");
}

#[tokio::test(flavor = "current_thread")]
async fn module_001_ac30_client_api_none_once_shutdown_started() {
    let _serial = serial();
    let home = T111Home::new(&["fs"], true);
    let runtime = compose_home(&home).await;

    let endpoint = runtime.client_api().expect("the Client API is bound");
    let discovery =
        std::fs::read_to_string(home.home.join(".runtime/client-api")).expect("the discovery file");
    assert!(
        discovery.contains(&format!("client_api_base: \"{}\"", endpoint.base_url)),
        "the endpoint is the discovery file's base: {discovery:?} vs {}",
        endpoint.base_url
    );
    assert_eq!(
        endpoint.base_url,
        format!("http://{}", endpoint.socket_addr)
    );
    assert!(endpoint.api.upgrade().is_some(), "the Client API is alive");

    let handle = runtime.shutdown_handle();
    assert!(handle.trigger());
    assert!(
        runtime.client_api().is_none(),
        "no endpoint once the shutdown is triggered, before it has run"
    );
    runtime.shutdown().await.expect("shutdown");
    assert!(
        poll_until(OBJECTS_BUDGET, || endpoint.api.upgrade().is_none()).await,
        "the Client API is gone after the shutdown"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn module_001_ac30_health_reports_agent_loop_and_guard() {
    let _serial = serial();
    let with_driver = T111Home::new(&["fs"], true);
    let runtime = compose_home(&with_driver).await;
    let health = runtime.health();
    assert_eq!(health.phase, RuntimePhase::Running);
    assert!(health.agent_loop_up, "the root loop serves");
    assert_eq!(health.instance_guard, InstanceGuardKind::PidLockFile);
    assert_eq!(
        health.client_api_base,
        runtime.client_api().map(|endpoint| endpoint.base_url)
    );
    assert!(health.client_api_base.is_some());
    assert!(health.failed_extensions.is_empty());

    runtime.shutdown_handle().trigger();
    runtime.wait().await;
    let health = runtime.health();
    assert_eq!(health.phase, RuntimePhase::Stopped);
    assert!(!health.agent_loop_up);
    assert_eq!(health.client_api_base, None);
    drop(runtime);

    let without_driver = T111Home::new(&["fs"], false);
    let runtime = compose_home(&without_driver).await;
    let health = runtime.health();
    assert_eq!(health.phase, RuntimePhase::Running);
    assert!(!health.agent_loop_up, "no deployed driver, no root loop");
    runtime.shutdown().await.expect("shutdown");
}

#[tokio::test(flavor = "current_thread")]
async fn module_001_ac30_root_agent_id_is_the_persisted_root_identity() {
    let _serial = serial();
    let home = T111Home::new(&["fs"], true);
    let runtime = compose_home(&home).await;
    let persisted =
        cap_lifecycle::identity::read_agent_id(&home.home).expect("the boot persists the root id");
    assert_eq!(runtime.root_agent_id(), persisted);
    runtime.shutdown().await.expect("shutdown");

    let again = compose_home(&home).await;
    assert_eq!(
        again.root_agent_id(),
        persisted,
        "the same root identity on the next composition"
    );
    again.shutdown().await.expect("shutdown");
}
