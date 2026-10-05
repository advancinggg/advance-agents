//! MODULE-001-AC-30 — the capability wiring graph of a home that declares every capability on a
//! git repository is freed once its owners let go: no reference cycle keeps the event bus, the
//! git commit queue (and with it the queue's blocking worker), the per-child manager or the rest
//! of the graph alive.
//!
//! The per-child manager is the spawner's observer inside the host registry, and it holds the
//! capability injector, which holds that registry: the manager and the registry keep each other
//! alive until `PerChildLoopManager::unbind` releases the injector. The test composes the graph
//! in-process (`wire_capabilities_with_home_for_test`, as `advance start` wires it), records a
//! `Weak` of each big shared object, unbinds the manager, drops the handles and the host, shuts
//! the runtime down (every task dropped, as the binary's runtime drop does, but bounded) and then
//! requires every `Weak` dead and the process-wide sets of active git commit queues and
//! CONTRACT-218 custody objects empty.
//!
//! Non-vacuity: one extra strong clone of the event bus is held across the shutdown; the census
//! must report the bus alive (with only what it holds) until the clone is dropped.
//!
//! The only composing test of its binary: it asserts process-wide sets empty.
#![cfg(unix)]

#[path = "support/all_caps_home.rs"]
mod all_caps_home;

use std::sync::{Arc, Weak};
use std::time::{Duration, Instant};

use advance_runtime::bootstrap::RuntimeHostBuilder;
use all_caps_home::{ensure_in_process_master_key, AllCapsHome};

/// How long the runtime shutdown may wait for blocking tasks (the git commit worker among them).
const RUNTIME_SHUTDOWN_BUDGET: Duration = Duration::from_secs(10);
/// How long each census phase polls for its expected state.
const CENSUS_BUDGET: Duration = Duration::from_secs(5);
/// The recorded objects a held event bus keeps alive: itself, and the CONTRACT-219
/// observation projector its event pipeline holds.
const HELD_BY_BUS: &[&str] = &["event_bus", "contract219_projector"];

/// One recorded object: its name and a probe of whether it is still alive.
struct Tracked {
    name: &'static str,
    alive: Box<dyn Fn() -> bool>,
}

fn track<T: ?Sized + 'static>(name: &'static str, weak: Weak<T>) -> Tracked {
    Tracked {
        name,
        alive: Box::new(move || weak.strong_count() > 0),
    }
}

/// [`track`] an optional handle that this home must have.
fn some<T: ?Sized + 'static>(name: &'static str, handle: &Option<Arc<T>>) -> Tracked {
    let handle = handle
        .as_ref()
        .unwrap_or_else(|| panic!("{name}: every capability is declared, so it is wired"));
    track(name, Arc::downgrade(handle))
}

struct Census(Vec<Tracked>);

impl Census {
    /// Names of the recorded objects still alive.
    fn alive(&self) -> Vec<&'static str> {
        self.0
            .iter()
            .filter(|t| (t.alive)())
            .map(|t| t.name)
            .collect()
    }

    fn report(&self) -> String {
        format!(
            "alive: {:?}; active git commit queues: {:?}; CONTRACT-218 custody: {:?}",
            self.alive(),
            advance_git::commit_queue::active_queue_paths_for_test(),
            advance_cli::contract218_anchor::custody_paths_for_test(),
        )
    }
}

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
fn module_001_ac30_all_capabilities_git_wiring_graph_is_freed_after_unbind() {
    ensure_in_process_master_key();
    let home = AllCapsHome::new();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("tokio runtime");

    let (census, held_bus) = runtime.block_on(async {
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

        let manager = some("perchild_manager", &handles.perchild_manager);
        let census = Census(vec![
            track("event_bus", Arc::downgrade(&handles.event_bus)),
            some("git_queue", &handles.git_queue),
            manager,
            track("run_manager", Arc::downgrade(&handles.run_manager)),
            track("grant_store", Arc::downgrade(&handles.cap_grant.store)),
            some("llm_gateway", &handles.llm_gateway),
            some("llm_stream_reaper", &handles.llm_stream_reaper),
            some("vlm_extractor", &handles.vlm_extractor),
            some("chatgpt_sign_in", &handles.chatgpt_sign_in),
            some("secret_store", &handles.secret_store),
            some("provider_admin", &handles.provider_admin),
            track(
                "client_api",
                Arc::downgrade(
                    &handles
                        .client_api_server
                        .as_ref()
                        .expect("the Client API is bound")
                        .api(),
                ),
            ),
            some("observability_read_api", &handles.observability_read_api),
            some("contract219_projector", &handles.contract219_projector),
            some("await_manager", &handles.await_manager),
            some("messaging_store", &handles.messaging_store),
            track(
                "client_ingress_store",
                Arc::downgrade(&handles.client_ingress_store),
            ),
            track("reply_registry", Arc::downgrade(&handles.reply_registry)),
            some("crash_cascade_sink", &handles.crash_cascade_sink),
            some("grant_approval_intake", &handles.grant_approval_intake),
            some("auto_loop_driver", &handles.auto_loop_driver),
            some("skill_turn_runtime", &handles.skill_turn_runtime),
            some("memory_store", &handles.memory_store),
            some("agent_tree", &handles.agent_tree),
            some("agent_spawner", &handles.agent_spawner),
            some("agent_admin", &handles.agent_admin),
            some("decomposition_store", &handles.decomposition_store),
            some("repetition_guard", &handles.repetition_guard),
            some("tool_registry", &handles.tool_registry),
            track("evidence_ids", Arc::downgrade(&handles.evidence_ids)),
            track("pack_runtime", Arc::downgrade(&handles.pack_runtime)),
            track(
                "component_runtime",
                Arc::downgrade(&host.component_runtime()),
            ),
            track(
                "capability_injector",
                Arc::downgrade(&host.capability_injector()),
            ),
            track("host_registry", Arc::downgrade(&host.host_registry())),
        ]);
        let held_bus = Arc::clone(&handles.event_bus);
        handles
            .perchild_manager
            .as_ref()
            .expect("messaging + lifecycle: the per-child manager exists")
            .unbind();
        drop(handles);
        drop(host);
        (census, held_bus)
    });
    runtime.shutdown_timeout(RUNTIME_SHUTDOWN_BUDGET);

    // Non-vacuity: the census sees the one strong reference this test still holds. Everything
    // the held bus does not reach dies; the bus (and the observation projector its event
    // pipeline holds) stays.
    let settled = poll_until(CENSUS_BUDGET, || {
        census.alive().iter().all(|name| HELD_BY_BUS.contains(name))
    });
    assert!(
        settled && census.alive().contains(&"event_bus"),
        "with one event-bus clone held, the event bus and only what it holds stay alive; {}",
        census.report()
    );

    drop(held_bus);
    let freed = poll_until(CENSUS_BUDGET, || {
        census.alive().is_empty()
            && advance_git::commit_queue::active_queue_paths_for_test().is_empty()
            && advance_cli::contract218_anchor::custody_paths_for_test().is_empty()
    });
    assert!(
        freed,
        "the wiring graph is freed once its owners let go; {}",
        census.report()
    );
}
