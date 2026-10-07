//! Test-only seams of the composition (behind the `test-support` feature): failpoints
//! that make a composition fail part-way, a gate that holds a message turn in flight, a
//! probe that records what the composition built and the steps its teardown ran, and an
//! in-memory log sink.

use std::io;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, Weak};

use advance_client_api::ClientApi;
use advance_event_bus::EventBus;
use advance_git::DefaultGitCommitQueue;
use advance_run_manager::RunManager;
use advance_runtime::capability_injector::{CapabilityInjector, ComponentCtx};
use advance_runtime::ComponentRuntime;
use cap_llm::{LlmGateway, ModelProfileCatalog};
use cap_tools::{LazyToolRegistry, ToolRegistry};
use tokio::sync::Notify;

use crate::agent_config::{active_capabilities_with, read_agent_yaml};
use crate::api::{ComposeLog, ComposeLogLine};
use crate::daemon::is_core_module;
use crate::effective_capabilities::EffectiveCapabilities;
use crate::perchild_daemon::PerChildLoopManager;

pub use crate::composition::TEARDOWN_ORDER;

pub mod fixture;

/// Process-local homes a composition currently holds, for [`fixture::assert_gone_for_home`].
pub fn reserved_homes() -> Vec<PathBuf> {
    crate::registry::reserved_homes_for_test()
}

/// CONTRACT-218 custody paths a composition currently holds.
pub fn custody_paths() -> Vec<PathBuf> {
    crate::contract218_anchor::custody_paths_for_test()
}

/// Git commit-queue paths a composition currently holds.
pub fn active_git_queues() -> Vec<PathBuf> {
    advance_git::commit_queue::active_queue_paths_for_test()
}

/// Platform-directory component under `contract218/<key>/` for this home.
pub fn contract218_platform_key(home: &Path) -> String {
    crate::contract218_bootstrap::workspace_key(home)
}

/// The message of the error a `POST /msg` bind failpoint produces.
pub const POST_MSG_FAILPOINT: &str = "T111 failpoint";
/// The message of the wiring failure the git-queue failpoint produces.
pub const WIRING_FAILPOINT: &str = "T111 wiring failpoint";

/// Failpoints and observers of one composition (a field of `ComposeOptions` in
/// test-support builds; all off by default).
#[derive(Clone, Default)]
pub struct ComposeFailpoints {
    /// The `POST /msg` listener's bind fails with an `io::Error` of this kind (message
    /// [`POST_MSG_FAILPOINT`]), after the agent loop started. The error takes the place
    /// of the bind's result, so the listener reports it as it reports a real one.
    pub post_msg_bind: Option<io::ErrorKind>,
    /// The capability wiring fails right after the git commit queue started (message
    /// [`WIRING_FAILPOINT`]).
    pub wiring_after_git_queue: bool,
    /// Holds every root-loop turn before its context is assembled, until released.
    /// Installed only where the root loop assembles through the LLM gateway (a home
    /// declaring `llm`); [`ProbeRecord::turn_gate_installed`] says whether it was.
    pub turn_gate: Option<TurnGate>,
    /// Records what the composition built and the steps its teardown ran.
    pub probe: Option<Arc<ComposeProbe>>,
}

/// Holds a message turn in flight: the turn signals [`entered`](Self::entered) and then
/// waits for [`release`](Self::release) before its context is assembled.
#[derive(Clone, Default)]
pub struct TurnGate {
    entered: Arc<Notify>,
    release: Arc<Notify>,
}

impl TurnGate {
    pub fn new() -> Self {
        Self::default()
    }

    /// Resolves once a turn has reached the gate (also when it reached it earlier).
    pub async fn entered(&self) {
        self.entered.notified().await;
    }

    /// Let the turn waiting at the gate (or the next one to reach it) go on.
    pub fn release(&self) {
        self.release.notify_one();
    }

    /// Called by the gated turn: signal arrival, then wait to be released.
    pub(crate) async fn pass(&self) {
        self.entered.notify_one();
        self.release.notified().await;
    }
}

/// What a composition recorded, read with [`ComposeProbe::record`].
#[derive(Default)]
pub struct ComposeProbe {
    record: Mutex<ProbeRecord>,
}

impl ComposeProbe {
    pub fn new() -> Self {
        Self::default()
    }

    /// A snapshot of everything recorded so far.
    pub fn record(&self) -> ProbeRecord {
        self.record
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    pub(crate) fn update(&self, update: impl FnOnce(&mut ProbeRecord)) {
        update(
            &mut self
                .record
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()),
        );
    }

    pub(crate) fn set_vlm_catalog(&self, catalog: Weak<ModelProfileCatalog>) {
        self.update(|record| record.vlm_catalog = Some(catalog));
    }

    pub(crate) fn set_gateway_catalog(&self, catalog: Weak<ModelProfileCatalog>) {
        self.update(|record| record.gateway_catalog = Some(catalog));
    }
}

/// The objects a composition built (held weakly, so the record keeps nothing alive),
/// the listeners it bound, and the steps its teardown ran.
#[derive(Clone, Default)]
pub struct ProbeRecord {
    pub client_api: Option<Weak<ClientApi>>,
    pub event_bus: Option<Weak<EventBus>>,
    pub llm_gateway: Option<Weak<LlmGateway>>,
    pub git_queue: Option<Weak<DefaultGitCommitQueue>>,
    pub perchild_manager: Option<Weak<PerChildLoopManager>>,
    pub run_manager: Option<Weak<RunManager>>,
    /// Its last drop joins the epoch ticker thread.
    pub component_runtime: Option<Weak<ComponentRuntime>>,
    /// Only where a sign-in source is configured (a home declaring `llm`).
    pub chatgpt_sign_in: Option<Weak<advance_home::ChatGptSignIn>>,
    /// The VLM extractor's catalog (same `Arc` as the gateway when `llm` is declared).
    pub vlm_catalog: Option<Weak<ModelProfileCatalog>>,
    /// The gateway's catalog (same `Arc` as the VLM extractor when `llm` is declared).
    pub gateway_catalog: Option<Weak<ModelProfileCatalog>>,
    /// `("client_api" | "event_bus" | "post_msg" | "hooks", bound address)`, in bind order.
    pub listeners: Vec<(&'static str, SocketAddr)>,
    /// Whether the turn gate wraps the root loop's context assembler.
    pub turn_gate_installed: bool,
    /// One entry per teardown step that ran, in order: the step's name (one of
    /// [`TEARDOWN_ORDER`]) and tokio's `num_alive_tasks` right after it.
    pub teardown_steps: Vec<(&'static str, usize)>,
    /// The composition's effective capability set (known ∪ extension names).
    pub effective_capabilities: Option<EffectiveCapabilities>,
    /// The root loop's declared capability names (the guest request set).
    pub root_request_set: Option<Vec<String>>,
    /// The injector the host built (dies with the host).
    pub capability_injector: Option<Weak<CapabilityInjector>>,
    /// The concrete host-tool registry (created when the home declares `tools`).
    pub lazy_tool_registry: Option<Weak<LazyToolRegistry>>,
    /// The composite tool registry guests use (created when the home declares `tools`).
    pub tool_registry: Option<Weak<dyn ToolRegistry>>,
}

impl ProbeRecord {
    /// The names of the recorded objects that are still alive.
    pub fn alive(&self) -> Vec<&'static str> {
        fn alive<T: ?Sized>(weak: &Option<Weak<T>>) -> bool {
            weak.as_ref().is_some_and(|weak| weak.strong_count() > 0)
        }
        let mut names = Vec::new();
        for (name, is_alive) in [
            ("client_api", alive(&self.client_api)),
            ("event_bus", alive(&self.event_bus)),
            ("llm_gateway", alive(&self.llm_gateway)),
            ("git_queue", alive(&self.git_queue)),
            ("perchild_manager", alive(&self.perchild_manager)),
            ("run_manager", alive(&self.run_manager)),
            ("component_runtime", alive(&self.component_runtime)),
            ("capability_injector", alive(&self.capability_injector)),
            ("lazy_tool_registry", alive(&self.lazy_tool_registry)),
            ("tool_registry", alive(&self.tool_registry)),
            ("chatgpt_sign_in", alive(&self.chatgpt_sign_in)),
        ] {
            if is_alive {
                names.push(name);
            }
        }
        if alive(&self.vlm_catalog) || alive(&self.gateway_catalog) {
            names.push("model_catalog");
        }
        names
    }

    /// The teardown steps, one line each (`<step> alive_tasks=<n>`), for assertion
    /// messages.
    pub fn render_steps(&self) -> String {
        self.teardown_steps
            .iter()
            .map(|(step, alive)| format!("{step} alive_tasks={alive}"))
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// The names of the teardown steps that ran, in order.
    pub fn step_names(&self) -> Vec<&'static str> {
        self.teardown_steps.iter().map(|(step, _)| *step).collect()
    }

    /// The address a listener of that name was bound to.
    pub fn listener(&self, name: &str) -> Option<SocketAddr> {
        self.listeners
            .iter()
            .find(|(listener, _)| *listener == name)
            .map(|(_, addr)| *addr)
    }
}

/// L0 probe: link `guest` exactly as the root loop links its driver — request set =
/// `active_capabilities_with(read_agent_yaml(agent_workspace), record.effective_capabilities)`,
/// on the composed `ComponentRuntime` and `CapabilityInjector`, in a fresh Store —
/// and return the request set's names, or the instantiate error text. It instantiates
/// (`instantiate_pre` + `instantiate_async`; no export such as `init` or
/// `handle-message` is called).
pub async fn link_guest_for_test(
    record: &ProbeRecord,
    agent_workspace: &Path,
    guest: &[u8],
) -> Result<Vec<String>, String> {
    let runtime = record
        .component_runtime
        .as_ref()
        .and_then(Weak::upgrade)
        .ok_or_else(|| "composition gone".to_string())?;
    let injector = record
        .capability_injector
        .as_ref()
        .and_then(Weak::upgrade)
        .ok_or_else(|| "composition gone".to_string())?;
    let effective = record.effective_capabilities.clone().unwrap_or_default();
    let bytes = if is_core_module(guest) {
        build_agent::encode_core_to_component(guest).map_err(|e| format!("{e:?}"))?
    } else {
        guest.to_vec()
    };
    let loaded = runtime
        .load_component(&bytes)
        .map_err(|e| format!("{e:?}"))?;
    let ctx = ComponentCtx::new("t112c-link-probe".into(), "t112c".into(), Vec::new());
    let caps = active_capabilities_with(read_agent_yaml(agent_workspace).as_deref(), &effective);
    let names: Vec<String> = caps.iter().map(|cap| cap.capability.to_string()).collect();
    let (bindings, store) = runtime
        .instantiate_advance_host_with_capabilities_async(&loaded, ctx, &caps, &injector)
        .await
        .map_err(|e| format!("{e:?}"))?;
    drop(bindings);
    drop(store);
    Ok(names)
}

/// Keeps every line in memory. [`MemoryComposeLog::failing_ready`] makes the readiness
/// line fail (after recording it). Clones share the lines.
#[derive(Clone, Default)]
pub struct MemoryComposeLog {
    lines: Arc<Mutex<Vec<ComposeLogLine>>>,
    fail_ready: Option<io::ErrorKind>,
}

impl MemoryComposeLog {
    pub fn new() -> Self {
        Self::default()
    }

    /// A log whose readiness line fails with an `io::Error` of `kind`.
    pub fn failing_ready(kind: io::ErrorKind) -> Self {
        Self {
            fail_ready: Some(kind),
            ..Self::default()
        }
    }

    pub fn lines(&self) -> Vec<ComposeLogLine> {
        self.lines
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    /// How many lines carry `key`.
    pub fn count(&self, key: &str) -> usize {
        self.lines
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .iter()
            .filter(|line| line.key == key)
            .count()
    }

    fn push(&self, line: &ComposeLogLine) {
        self.lines
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .push(line.clone());
    }
}

impl ComposeLog for MemoryComposeLog {
    fn line(&self, line: &ComposeLogLine) {
        self.push(line);
    }

    fn ready(&self, line: &ComposeLogLine) -> io::Result<()> {
        self.push(line);
        match self.fail_ready {
            Some(kind) => Err(io::Error::from(kind)),
            None => Ok(()),
        }
    }
}

/// How many OS threads the composition started (the Client API adapter workers, the
/// CONTRACT-218 custody threads, the L6 git bridge) are still running.
pub fn live_composition_threads_for_test() -> usize {
    crate::threads::live_threads()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::{log_keys, LogStream};

    #[tokio::test]
    async fn module_001_ac30_turn_gate_holds_until_released_without_losing_a_signal() {
        let gate = TurnGate::new();
        // Released before the turn arrives: the release is kept for it.
        gate.release();
        let passing = tokio::spawn({
            let gate = gate.clone();
            async move { gate.pass().await }
        });
        gate.entered().await;
        passing.await.expect("the turn passes");

        // Arrives first: waits until released.
        let waiting = tokio::spawn({
            let gate = gate.clone();
            async move { gate.pass().await }
        });
        gate.entered().await;
        tokio::task::yield_now().await;
        assert!(!waiting.is_finished(), "held at the gate");
        gate.release();
        waiting.await.expect("released");
    }

    struct NoopBus;
    impl advance_shared_types::traits::EventBusEmit for NoopBus {
        fn emit(&self, _event: advance_shared_types::event::Event) {}
    }

    #[test]
    fn module_001_ac30_probe_reports_live_objects_steps_and_listeners() {
        let probe = ComposeProbe::new();
        let run_manager = RunManager::new_arc(Arc::new(NoopBus));
        let second_holder = Arc::clone(&run_manager);
        probe.update(|record| {
            record.run_manager = Some(Arc::downgrade(&run_manager));
            record
                .listeners
                .push(("post_msg", "127.0.0.1:4242".parse().unwrap()));
            record.teardown_steps.push(("ingress.post_msg", 3));
            record.teardown_steps.push(("guard", 1));
        });
        let record = probe.record();
        assert_eq!(record.alive(), vec!["run_manager"]);
        assert_eq!(record.step_names(), vec!["ingress.post_msg", "guard"]);
        assert_eq!(
            record.render_steps(),
            "ingress.post_msg alive_tasks=3\nguard alive_tasks=1"
        );
        assert_eq!(
            record.listener("post_msg"),
            Some("127.0.0.1:4242".parse().unwrap())
        );
        assert_eq!(record.listener("hooks"), None);
        drop(run_manager);
        assert_eq!(
            probe.record().alive(),
            vec!["run_manager"],
            "one holder is left"
        );
        drop(second_holder);
        assert!(probe.record().alive().is_empty());
    }

    #[test]
    fn module_001_ac30_memory_log_records_and_fails_readiness_on_request() {
        let line = |key: &'static str| ComposeLogLine {
            stream: LogStream::Stdout,
            key,
            text: key.to_owned(),
        };
        let log = MemoryComposeLog::new();
        let shared = log.clone();
        log.line(&line(log_keys::MSG_LISTENER));
        assert!(log.ready(&line(log_keys::READY)).is_ok());
        assert_eq!(shared.count(log_keys::READY), 1);
        assert_eq!(shared.lines().len(), 2);

        let failing = MemoryComposeLog::failing_ready(io::ErrorKind::BrokenPipe);
        let error = failing.ready(&line(log_keys::READY)).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
        assert_eq!(failing.count(log_keys::READY), 1, "recorded, then failed");
    }
}
