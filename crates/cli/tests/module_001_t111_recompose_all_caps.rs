//! MODULE-001-T111 (6) / MODULE-001-AC-30 on the home declaring every capability on a git
//! repository (messaging, lifecycle and git together: the per-child manager, the
//! CONTRACT-218 custody and the git commit queue all exist): composed in-process, shut
//! down, nothing of it is left — in particular the per-child manager, the EventBus and the
//! git commit queue are dead and the custody paths and git queue registrations are empty —
//! and a second composition of the same home succeeds and stops just as cleanly.
//!
//! The only test of its binary: it checks process-wide state.
#![cfg(unix)]

#[path = "support/all_caps_home.rs"]
mod all_caps_home;

#[path = "../../runtime-compose/tests/support/t111.rs"]
mod t111;

use std::sync::Arc;

use advance_runtime_compose::test_support::{ComposeFailpoints, ComposeProbe, MemoryComposeLog};
use advance_runtime_compose::{compose, ComposeOptions, ComposedRuntime};
use all_caps_home::{ensure_in_process_master_key, AllCapsHome};
use t111::{alive_tasks, assert_composition_gone, assert_steps, serial};

async fn compose_with_probe(home: &AllCapsHome, probe: &Arc<ComposeProbe>) -> ComposedRuntime {
    let options = ComposeOptions::daemon(&home.ws, Arc::new(MemoryComposeLog::new()))
        .with_state_root(home.state_root())
        .with_failpoints(ComposeFailpoints {
            probe: Some(Arc::clone(probe)),
            ..ComposeFailpoints::default()
        });
    compose(options, Vec::new())
        .await
        .expect("compose the all-capabilities git home")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn module_001_ac30_t111_6_recompose_all_capabilities_git_home() {
    let _serial = serial();
    ensure_in_process_master_key();
    let home = AllCapsHome::new();
    let baseline = alive_tasks();

    let probe = Arc::new(ComposeProbe::new());
    let runtime = compose_with_probe(&home, &probe).await;
    let record = probe.record();
    for name in ["perchild_manager", "event_bus", "git_queue"] {
        assert!(
            record.alive().contains(&name),
            "{name} is recorded and alive while composed: {:?}",
            record.alive()
        );
    }
    runtime.shutdown().await.expect("shutdown");
    assert_steps(
        &probe.record(),
        &[
            "loops.perchild",
            "holds.git_queue",
            "holds.event_bus",
            "guard",
        ],
    );
    assert_composition_gone(baseline, &probe, &home.ws).await;

    let probe = Arc::new(ComposeProbe::new());
    let runtime = compose_with_probe(&home, &probe).await;
    runtime.shutdown().await.expect("second shutdown");
    assert_composition_gone(baseline, &probe, &home.ws).await;
}
