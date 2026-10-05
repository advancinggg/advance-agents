//! MODULE-001-AC-30 — every composition reserves its home in the process-local registry:
//! while a home is composed in this process a second `compose` of it is refused before any
//! lock is tried (`ComposeError::Lock(LockFailure::HeldInProcess)`, with the text a second
//! in-process runtime lock gives), the first composition is untouched, and once it has shut
//! down the home composes again.
//!
//! The compositions of this binary run one at a time (`serial`).

#[path = "support/t111.rs"]
mod t111;

use std::sync::Arc;

use advance_runtime_compose::registry::reserved_homes_for_test;
use advance_runtime_compose::test_support::MemoryComposeLog;
use advance_runtime_compose::{compose, ComposeError, LockFailure, RuntimePhase};
use t111::{serial, T111Home};

#[tokio::test(flavor = "current_thread")]
async fn module_001_ac30_second_in_process_compose_refused_by_registry() {
    let _serial = serial();
    let home = T111Home::new(&["fs"], true);

    let first = compose(home.options(Arc::new(MemoryComposeLog::new())), Vec::new())
        .await
        .expect("the first composition");
    assert!(reserved_homes_for_test().contains(&home.home));
    let lock = std::fs::read_to_string(home.lock_path()).expect("the first composition's lock");

    let error = compose(home.options(Arc::new(MemoryComposeLog::new())), Vec::new())
        .await
        .expect_err("the home is composed in this process");
    assert!(
        matches!(error, ComposeError::Lock(LockFailure::HeldInProcess)),
        "{error:?}"
    );
    assert_eq!(
        error.to_string(),
        format!(
            "failed to acquire runtime lock: another runtime active (pid={})",
            std::process::id()
        )
    );
    assert_eq!(first.health().phase, RuntimePhase::Running);
    assert_eq!(
        std::fs::read_to_string(home.lock_path()).expect("lock still there"),
        lock,
        "the refused composition never touched the first one's lock"
    );
    assert!(reserved_homes_for_test().contains(&home.home));

    first.shutdown().await.expect("shutdown");
    assert!(!reserved_homes_for_test().contains(&home.home));
    let again = compose(home.options(Arc::new(MemoryComposeLog::new())), Vec::new())
        .await
        .expect("the home composes once the first composition has shut down");
    again.shutdown().await.expect("shutdown");
}
