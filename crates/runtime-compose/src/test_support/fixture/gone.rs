//! Per-home "nothing survived" check for parallel fixture binaries.

use std::net::TcpListener;
use std::path::Path;
use std::time::{Duration, Instant};

use crate::test_support::{
    active_git_queues, contract218_platform_key, custody_paths, reserved_homes, ComposeProbe,
};

const OBJECTS_BUDGET: Duration = Duration::from_secs(2);
const TASKS_BUDGET: Duration = Duration::from_secs(6);
const POLL: Duration = Duration::from_millis(10);

pub async fn assert_gone_for_home(
    probe: &ComposeProbe,
    home: &Path,
    baseline_tasks: Option<usize>,
) {
    let report = |what: &str| {
        let rec = probe.record();
        format!(
            "{what}\nalive objects: {:?}\nteardown steps:\n{}",
            rec.alive(),
            rec.render_steps()
        )
    };

    assert!(
        poll_until(OBJECTS_BUDGET, || probe.record().alive().is_empty()).await,
        "{}",
        report("objects of the composition are still alive")
    );

    if let Some(baseline) = baseline_tasks {
        assert!(
            poll_until(TASKS_BUDGET, || alive_tasks() == baseline).await,
            "{}",
            report(&format!(
                "tokio alive tasks: {} (baseline {baseline})",
                alive_tasks()
            ))
        );
    }

    let key = contract218_platform_key(home);
    assert!(
        poll_until(OBJECTS_BUDGET, || {
            !reserved_homes().contains(&home.to_path_buf())
                && !custody_paths().iter().any(|path| {
                    path.starts_with(home)
                        || path
                            .components()
                            .any(|c| c.as_os_str() == std::ffi::OsStr::new(&key))
                })
                && !active_git_queues()
                    .iter()
                    .any(|path| path.starts_with(home))
        })
        .await,
        "{}",
        report(&format!(
            "per-home state left: reserved {:?} custody {:?} git {:?}",
            reserved_homes(),
            custody_paths(),
            active_git_queues()
        ))
    );

    let lock = home.join(".runtime/runtime.lock");
    assert!(
        !lock.exists(),
        "{}",
        report(&format!("{} is still there", lock.display()))
    );

    for (name, addr) in probe.record().listeners {
        if let Err(error) = TcpListener::bind(addr) {
            panic!(
                "{}",
                report(&format!(
                    "the {name} port {addr} cannot be bound again: {error}"
                ))
            );
        }
    }
}

fn alive_tasks() -> usize {
    tokio::runtime::Handle::current()
        .metrics()
        .num_alive_tasks()
}

async fn poll_until(budget: Duration, mut done: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + budget;
    loop {
        if done() {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(POLL).await;
    }
}
