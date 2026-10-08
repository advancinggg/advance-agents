//! MODULE-001-AC-30 — option values this build does not compose are refused before anything
//! starts: `compose` returns `ComposeError::Unsupported` naming the value, and no runtime
//! lock, reservation, listener or object exists afterwards. One row per refused value (a
//! later step that makes a value composable deletes its row).
//!
//! The compositions of this binary run one at a time (`serial`): it checks process-wide
//! state.

#[path = "support/t111.rs"]
mod t111;

use std::path::PathBuf;
use std::sync::Arc;

use advance_runtime_compose::registry::reserved_homes_for_test;
use advance_runtime_compose::test_support::{ComposeFailpoints, ComposeProbe, MemoryComposeLog};
use advance_runtime_compose::{
    compose, ComposeError, ComposeLog, ComposeOptions, InstanceGuard, Unsupported,
};
use t111::{serial, T111Home};

fn log() -> Arc<dyn ComposeLog> {
    Arc::new(MemoryComposeLog::new())
}

#[tokio::test(flavor = "current_thread")]
async fn module_001_ac30_unsupported_values_refused_before_side_effects() {
    let _serial = serial();
    let home = T111Home::new(&["fs"], true);
    let relative = PathBuf::from("relative/home");
    let not_canonical = home.home.join(".advance").join("..");
    let inside = home.home.join(".runtime");

    let rows: Vec<(&str, ComposeOptions, Unsupported)> = vec![
        (
            "process-local guard with a discovery file",
            home.options(log())
                .with_instance(InstanceGuard::ProcessLocal),
            Unsupported::DiscoveryRequiresPidLock,
        ),
        (
            "relative home",
            ComposeOptions::daemon(&relative, log()).with_state_root(&home.state_root),
            Unsupported::HomeNotCanonical(relative.clone()),
        ),
        (
            "non-canonical home",
            ComposeOptions::daemon(&not_canonical, log()).with_state_root(&home.state_root),
            Unsupported::HomeNotCanonical(not_canonical.clone()),
        ),
        (
            "state root inside the home",
            ComposeOptions::daemon(&home.home, log()).with_state_root(&inside),
            Unsupported::StateRoot {
                path: inside.clone(),
                reason: "lies inside the home",
            },
        ),
    ];

    for (what, options, expected) in rows {
        let probe = Arc::new(ComposeProbe::new());
        let options = options.with_failpoints(ComposeFailpoints {
            probe: Some(Arc::clone(&probe)),
            ..ComposeFailpoints::default()
        });
        match compose(options, Vec::new()).await {
            Err(ComposeError::Unsupported(refused)) => assert_eq!(refused, expected, "{what}"),
            Err(other) => panic!("{what}: expected Unsupported, got {other:?}"),
            Ok(_) => panic!("{what}: composed"),
        }
        assert!(!home.lock_path().exists(), "{what}: no runtime lock");
        assert!(
            reserved_homes_for_test().is_empty(),
            "{what}: no home reserved"
        );
        let record = probe.record();
        assert!(
            record.listeners.is_empty()
                && record.teardown_steps.is_empty()
                && record.client_api.is_none()
                && record.event_bus.is_none(),
            "{what}: nothing was started (listeners {:?}, steps:\n{})",
            record.listeners,
            record.render_steps()
        );
    }

    // Non-vacuity: without the refused value the same home composes.
    let runtime = compose(home.options(log()), Vec::new())
        .await
        .expect("the daemon options compose on this home");
    runtime.shutdown().await.expect("shutdown");
}
