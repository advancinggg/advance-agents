//! MODULE-001-AC-30 — the process-local instance guard: the home is reserved in the
//! process-local registry only, no `.runtime/runtime.lock` is written, the Client API binds
//! without a discovery file when asked not to write one, the runtime reports the guard in
//! use, and the home composes again after a shutdown.
//!
//! The compositions of this binary run one at a time (`serial`).

#[path = "support/t111.rs"]
mod t111;

use std::sync::Arc;

use advance_runtime_compose::registry::reserved_homes_for_test;
use advance_runtime_compose::test_support::MemoryComposeLog;
use advance_runtime_compose::{
    compose, Admission, ClientApiOptions, ComposeOptions, InstanceGuard, InstanceGuardKind,
    ListenerOptions,
};
use t111::{serial, T111Home};

fn process_local(home: &T111Home) -> ComposeOptions {
    home.options(Arc::new(MemoryComposeLog::new()))
        .with_instance(InstanceGuard::ProcessLocal)
        .with_listeners(ListenerOptions::none())
        .with_client_api(ClientApiOptions::loopback(
            0,
            false,
            Admission::SameUserLoopback,
        ))
}

#[tokio::test(flavor = "current_thread")]
async fn module_001_ac30_process_local_guard_writes_no_lock() {
    let _serial = serial();
    let home = T111Home::new(&["fs"], true);

    let runtime = compose(process_local(&home), Vec::new())
        .await
        .expect("compose under the process-local guard");
    assert!(
        !home.lock_path().exists(),
        "no runtime.lock under the process-local guard"
    );
    assert!(
        !home.home.join(".runtime/client-api").exists(),
        "no Client API discovery file"
    );
    assert!(runtime.client_api().is_some(), "the Client API is bound");
    assert_eq!(
        runtime.health().instance_guard,
        InstanceGuardKind::ProcessLocal
    );
    assert!(
        reserved_homes_for_test().contains(&home.home),
        "the home is reserved in this process"
    );

    runtime.shutdown().await.expect("shutdown");
    assert!(!reserved_homes_for_test().contains(&home.home));
    let again = compose(process_local(&home), Vec::new())
        .await
        .expect("the home composes again");
    assert!(!home.lock_path().exists());
    again.shutdown().await.expect("shutdown");
}
