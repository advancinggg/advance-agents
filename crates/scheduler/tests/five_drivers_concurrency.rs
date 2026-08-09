//! Slice C AC-01 verification: 5 component execution modes coexist + run
//! **concurrently** under the Tokio multi-thread runtime.
//!
//! Concurrency is deterministically forced via a shared
//! `tokio::sync::Barrier::new(5)` plus per-driver first-action
//! synchronization points (4 `RunnableHook` mocks + 1 `MailboxReader`
//! mock). Barrier requires all 5 first-action points to arrive before
//! any proceeds — by definition all 5 drivers are "in flight"
//! concurrently when the barrier releases.
//!
//! Assertions:
//! - All 5 drivers' records appear within a 2 s wall-clock bound
//!   (liveness + concurrency by barrier-pass).
//! - Pair-overlap sanity check (mathematically guaranteed by barrier
//!   release semantics): exists `(a, b)` with distinct driver_names
//!   such that `a.entry_ns < b.exit_ns AND b.entry_ns < a.exit_ns`.

use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;

use async_trait::async_trait;
use tokio::sync::Barrier;
use tokio_util::sync::CancellationToken;

use advance_scheduler::agent_loop::AgentLoopDriverImpl;
use advance_scheduler::cron::CronDriver;
use advance_scheduler::daemon::DaemonManager;
use advance_scheduler::hook::{
    BootstrapError, HookError, MessageHandler, RunBootstrap, RunnableHook,
};
use advance_scheduler::task::TaskRunner;
use advance_scheduler::trigger_bus::TriggerBusDispatchImpl;
use advance_scheduler::trigger_source::{TriggerEventSource, TriggerSource};
use advance_scheduler::types::{
    ComponentConfig, ComponentId, ComponentSubmitConfig, RestartPolicy, RunResult, RunStatus,
    TriggerSubscription, WasmInstance,
};
use advance_scheduler::watcher::WatcherDriver;
use advance_scheduler::AgentLoopDriver;
use advance_scheduler::TriggerBusDispatch;
use advance_shared_types::component::ComponentType;
use advance_shared_types::context::{
    AssemblyContext, AssemblyError, AssemblyResult, ContextAssembler, TierTokenCounts,
};
use advance_shared_types::event::Event;
use advance_shared_types::mailbox::{
    ActionResult, AgentAction, AgentActionDispatcher, DispatchError, MailboxReader, Message,
    MessageKind,
};
use advance_shared_types::memory::{PostProcessorError, PostProcessorHook};

#[derive(Debug, Clone)]
struct DriverRecord {
    name: &'static str,
    entry_ns: u128,
    exit_ns: u128,
}

type Records = Arc<Mutex<Vec<DriverRecord>>>;

fn elapsed_ns(start: std::time::Instant) -> u128 {
    start.elapsed().as_nanos()
}

/// Barrier-synchronizing RunnableHook used by cron / daemon / task /
/// watcher drivers. Records entry + exit timestamps around the barrier
/// wait so the post-barrier window is observable.
struct BarrierRunnableHook {
    name: &'static str,
    barrier: Arc<Barrier>,
    records: Records,
    start: std::time::Instant,
}

#[async_trait]
impl RunnableHook for BarrierRunnableHook {
    async fn run_once(&self, _config: ComponentConfig) -> Result<RunResult, HookError> {
        let entry_ns = elapsed_ns(self.start);
        self.barrier.wait().await;
        let exit_ns = elapsed_ns(self.start);
        self.records.lock().unwrap().push(DriverRecord {
            name: self.name,
            entry_ns,
            exit_ns,
        });
        Ok(RunResult {
            status: RunStatus::Completed,
            output: None,
        })
    }
}

/// Barrier-synchronizing MailboxReader used by the agent-loop driver.
/// `recv` is the first blocking trait method in the agent-loop's
/// post-bootstrap pipeline, so it's the natural barrier injection point.
struct BarrierMailbox {
    barrier: Arc<Barrier>,
    records: Records,
    start: std::time::Instant,
}

#[async_trait]
impl MailboxReader for BarrierMailbox {
    async fn recv(&self, _agent_id: &str) -> Message {
        let entry_ns = elapsed_ns(self.start);
        self.barrier.wait().await;
        let exit_ns = elapsed_ns(self.start);
        self.records.lock().unwrap().push(DriverRecord {
            name: "agent",
            entry_ns,
            exit_ns,
        });
        Message {
            id: "msg-barrier".into(),
            kind: MessageKind::User,
            from: "user:test".into(),
            to: "agent:test".into(),
            payload: Vec::new(),
            context: None,
            timestamp: std::time::SystemTime::UNIX_EPOCH,
            origin: None,
        }
    }
    fn poll(&self, _agent_id: &str) -> Option<Message> {
        None
    }
    fn depth(&self, _agent_id: &str) -> usize {
        0
    }
    fn freeze(&self, _agent_id: &str) {}
    fn unfreeze(&self, _agent_id: &str) {}
}

// ─────────────────────────────────────────────────────────────────────────
// Cooperative stubs for the rest of the agent-loop pipeline (post-recv).
// ─────────────────────────────────────────────────────────────────────────

struct StubAssembler;

#[async_trait]
impl ContextAssembler for StubAssembler {
    async fn assemble(&self, _ctx: AssemblyContext) -> Result<AssemblyResult, AssemblyError> {
        Ok(AssemblyResult {
            messages: Vec::new(),
            routing_method: "search".into(),
            routing_confidence: 0.0,
            is_new_task: false,
            tier_token_counts: TierTokenCounts {
                tier1a: 0,
                tier1b: 0,
                tier2: 0,
                tier3: 0,
            },
        })
    }
    fn inject_tier3_warning(&self, _agent_id: &str, _msg: &str) {}
}

struct StubPostProcessor;

#[async_trait]
impl PostProcessorHook for StubPostProcessor {
    async fn run(
        &self,
        _agent_id: &str,
        _msg: &Message,
        _result: &ActionResult,
    ) -> Result<(), PostProcessorError> {
        Ok(())
    }
}

struct StubDispatcher;

#[async_trait]
impl AgentActionDispatcher for StubDispatcher {
    async fn dispatch(
        &self,
        _agent_id: &str,
        _source: &advance_shared_types::mailbox::Message,
        _actions: &[AgentAction],
    ) -> Result<advance_shared_types::outbound::DeliveryReport, DispatchError> {
        Ok(advance_shared_types::outbound::DeliveryReport::empty())
    }
}

struct StubBootstrap;

#[async_trait]
impl RunBootstrap for StubBootstrap {
    async fn ensure_run(&self, _controller_agent: &str) -> Result<String, BootstrapError> {
        Ok("run-1".into())
    }
}

struct StubMessageHandler;

#[async_trait]
impl MessageHandler for StubMessageHandler {
    async fn init(&self, _config: ComponentConfig) -> Result<Vec<u8>, HookError> {
        Ok(Vec::new())
    }
    async fn handle_message(
        &self,
        _msg: &Message,
        _state: Vec<u8>,
    ) -> Result<ActionResult, HookError> {
        Ok(ActionResult {
            new_state: Vec::new(),
            actions: Vec::new(),
        })
    }
}

fn canned_event(event_type: &str) -> Event {
    Event {
        id: format!("evt-{event_type}"),
        timestamp: chrono::Utc::now(),
        agent_id: "agent:test".into(),
        task_id: None,
        run_id: None,
        execution_id: None,
        trace_id: "trace-test".into(),
        span_id: "span-test".into(),
        parent_span_id: None,
        event_type: event_type.into(),
        payload: serde_json::Value::Null,
        duration_ms: None,
    }
}

fn dummy_submit_config(id: &str) -> ComponentSubmitConfig {
    ComponentSubmitConfig {
        sensitive_params: Vec::new(),
        id: id.into(),
        component_type: ComponentType::Task,
        binary: Vec::new(),
        capabilities: Vec::new(),
        output_dir: None,
        trigger: None,
        restart_policy: None,
        delay: None,
        initial_grants: None,
        preset: None,
        retry: None,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn five_drivers_run_concurrently() {
    let barrier = Arc::new(Barrier::new(5));
    let records: Records = Arc::new(Mutex::new(Vec::with_capacity(5)));
    let start = std::time::Instant::now();

    // 4 RunnableHook mocks (one per cron / daemon / task / watcher).
    let mk_hook = |name: &'static str| -> Arc<dyn RunnableHook> {
        Arc::new(BarrierRunnableHook {
            name,
            barrier: Arc::clone(&barrier),
            records: Arc::clone(&records),
            start,
        })
    };

    // 1 MailboxReader mock for the agent driver.
    let mailbox = Arc::new(BarrierMailbox {
        barrier: Arc::clone(&barrier),
        records: Arc::clone(&records),
        start,
    });

    // Shared Trigger Bus for the watcher.
    let dispatcher = Arc::new(TriggerBusDispatchImpl::new());
    let dispatcher_for_fire = Arc::clone(&dispatcher);

    // ─── Spawn 5 drivers concurrently ───

    let cancel = CancellationToken::new();

    // Cron driver
    let cron_cancel = cancel.clone();
    let cron_hook = mk_hook("cron");
    let cron_handle = tokio::spawn(async move {
        let _ = CronDriver::run_periodic(
            "cron-conc",
            Duration::from_millis(30),
            cron_hook,
            ComponentConfig {
                id: "cron-conc".into(),
                config_data: None,
                trigger_context: None,
            },
            None,
            cron_cancel,
        )
        .await;
    });

    // Daemon driver
    let daemon_hook = mk_hook("daemon");
    let daemon_handle = tokio::spawn(async move {
        let _ = DaemonManager::run_daemon(
            "daemon-conc",
            RestartPolicy::Never,
            daemon_hook,
            ComponentConfig {
                id: "daemon-conc".into(),
                config_data: None,
                trigger_context: None,
            },
            None,
            CancellationToken::new(),
            None, // backoff (Slice D)
        )
        .await;
    });

    // Task driver (one-shot)
    let task_hook = mk_hook("task");
    let task_handle = tokio::spawn(async move {
        let _ = TaskRunner::run_task(
            "task-conc",
            dummy_submit_config("task-conc"),
            None,
            task_hook,
            None,
        )
        .await;
    });

    // Watcher driver (TriggerEventSource fed a whitelisted event)
    let watcher_cancel = cancel.clone();
    let watcher_hook = mk_hook("watcher");
    let watcher_dispatcher = Arc::clone(&dispatcher);
    let watcher_handle = tokio::spawn(async move {
        let source: Box<dyn TriggerSource> = Box::new(TriggerEventSource {
            sub: TriggerSubscription {
                event_type: "grant.issued".into(),
                filter: None,
                debounce_ms: None,
            },
            dispatcher: watcher_dispatcher,
        });
        let _ = WatcherDriver::run_with_trigger_source(
            "watcher-conc",
            source,
            watcher_hook,
            None,
            watcher_cancel,
        )
        .await;
    });

    // Agent loop driver (single-turn pipeline)
    let agent_handle = tokio::spawn(async move {
        let driver = AgentLoopDriverImpl::new(
            mailbox,
            Arc::new(StubAssembler),
            Arc::new(StubPostProcessor),
            Arc::new(StubDispatcher),
            Arc::new(StubBootstrap),
            Arc::new(StubMessageHandler),
        );
        let config = ComponentConfig {
            id: "agent-conc".into(),
            config_data: None,
            trigger_context: None,
        };
        let instance = WasmInstance::new(ComponentId::new("agent-conc".into()).unwrap());
        driver.run_agent("agent:conc", config, instance).await;
    });

    // Fire a whitelisted event so the watcher's TriggerEventSource queues
    // an entry — the watcher's drain loop will then invoke the hook
    // (hitting the barrier).
    tokio::time::sleep(Duration::from_millis(50)).await;
    dispatcher_for_fire.dispatch(canned_event("grant.issued"));

    // Wall-clock bound: 2 s. All 5 drivers should reach + pass the
    // barrier within this window.
    let timeout = tokio::time::timeout(Duration::from_secs(2), async {
        // Loop until all 5 records are present, then cancel.
        loop {
            if records.lock().unwrap().len() >= 5 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    cancel.cancel();
    // Allow spawned tasks to exit cleanly.
    let _ = tokio::time::timeout(Duration::from_secs(1), async {
        let _ = cron_handle.await;
        let _ = daemon_handle.await;
        let _ = task_handle.await;
        let _ = watcher_handle.await;
        let _ = agent_handle.await;
    })
    .await;

    timeout.expect("all 5 drivers should reach the barrier within 2 s");

    // Assertion 1: liveness — all 5 records present.
    let final_records = records.lock().unwrap().clone();
    assert_eq!(
        final_records.len(),
        5,
        "expected 5 driver records, got {}",
        final_records.len()
    );

    // Check distinct driver names.
    let mut names: Vec<&'static str> = final_records.iter().map(|r| r.name).collect();
    names.sort();
    assert_eq!(names, vec!["agent", "cron", "daemon", "task", "watcher"]);

    // Assertion 2: pair-overlap sanity (mathematically guaranteed by
    // barrier release — all 5 enter the post-barrier code together).
    let mut overlap_found = false;
    'outer: for i in 0..final_records.len() {
        for j in (i + 1)..final_records.len() {
            let a = &final_records[i];
            let b = &final_records[j];
            if a.name == b.name {
                continue;
            }
            // a.entry_ns < b.exit_ns AND b.entry_ns < a.exit_ns
            if a.entry_ns < b.exit_ns && b.entry_ns < a.exit_ns {
                overlap_found = true;
                break 'outer;
            }
        }
    }
    assert!(
        overlap_found,
        "expected at least one pair of drivers with temporally overlapping [entry, exit] windows; records: {:?}",
        final_records
    );
}
