//! SYS-J-70 / MODULE-007-AC-13 — one focused production-chain witness for
//! all four `AnyOf + keep_losers=true` attribution rules.
//!
//! The test begins at the production CLI composition root, consumes protected
//! turns from its real mailbox store, crosses its scheduler execution boundary,
//! drives the production-registered `messaging.send`, and uses the real cap-llm
//! gateway/handler with the activated C216 cost port.  One session proves, in
//! order: loser context substitution/clearing before parent wake; a pre-detach
//! call frozen to the original run; post-detach audit-only calls with no run
//! budget activity; and one-shot `reply_late` disposal before mailbox or a later
//! same-source AwaitSession can observe the old reply.

#[path = "h_loopback/mod.rs"]
mod h_loopback;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use advance_cli::wiring::wire_capabilities;
use advance_event_bus::{EventFilter, ObservabilityReadApi, ReadNext};
use advance_reply_tracker::{AwaitSessionManager, AwaitSessionManagerImpl};
use advance_run_manager::{RepetitionAction, RepetitionGuard, RunConfig};
use advance_runtime::bootstrap::RuntimeHostBuilder;
use advance_runtime::host_registry::{HostCallContext, HostFunctionHandler};
use advance_shared_types::await_session::{
    AgentAwaitRequest, AwaitMode, AwaitOptions, AwaitRequest, AwaitResult, AwaitSessionStatus,
    OrchestrationError, ReplyStatus, SessionId, TimeoutPolicy,
};
use advance_shared_types::capability::BudgetDecision;
use advance_shared_types::event::Event;
use advance_shared_types::mailbox::{MailboxTurnIdentity, MessageContext};
use advance_shared_types::traits::{EventBusEmit, RunBudget};
use advance_shared_types::turn_attribution::{
    CostAttributionLookup, CostTurnState, TurnStartOutcome,
};
use cap_llm::host_fn::AgentLlmGenerateHandler;
use h_loopback::{boot_with_retry_overrides, GatewayDeps, ScriptedResponse};
use wasmtime::component::Val;

const ROOT_BARE: &str = "default-agent";
const ROOT_COLON: &str = "agent:default";
const WINNER: &str = "agent:child-win";
const LOSER_TASK: &str = "agent:child-task";
const LOSER_GLOBAL: &str = "agent:child-global";
const SINK_TASK: &str = "agent:sink-task";
const SINK_GLOBAL: &str = "agent:sink-global";
const PRIMARY_SESSION: &str = "ac13-primary";
const ALIAS_SESSION: &str = "ac13-later-slot";
const REPLACEMENT_TASK: &str = "task-replacement";
const TEST_MASTER_KEY: &str = "4f0be08e7d1746246fe409f30f67df1826848f071d4608f41de29c5c082f9b31";

const RUNTIME_YAML: &str = r#"wasm:
  max_memory_pages: 1024
  epoch_interruption_ms: 100
  fuel_enabled: false

llm-providers: []

cron:
  max_jitter_ratio: 0.1

git:
  gc_interval_hours: 24
  max_tracked_file_mb: 10

secrets:
  master-key-source: env-var
  env-var-name: SYS_J70_MASTER_KEY

post-processor:
  llm-model: sonnet-light
  llm-failure-cooldown-seconds: 600

database:
  db-path: ".runtime/index.db"
  pool-size: 4
"#;

const AGENT_YAML: &str = r#"capabilities:
  messaging: true
agents:
  - alias: child-win
    template: explorer
    target-path: children/win
  - alias: child-task
    template: explorer
    target-path: children/task
  - alias: child-global
    template: explorer
    target-path: children/global
  - alias: sink-task
    template: explorer
    target-path: children/sink-task
  - alias: sink-global
    template: explorer
    target-path: children/sink-global
"#;

struct CountingBudget {
    inner: Arc<dyn RunBudget>,
    checks: AtomicUsize,
    commits: AtomicUsize,
    checked_runs: Mutex<Vec<String>>,
    committed_runs: Mutex<Vec<String>>,
}

impl CountingBudget {
    fn new(inner: Arc<dyn RunBudget>) -> Self {
        Self {
            inner,
            checks: AtomicUsize::new(0),
            commits: AtomicUsize::new(0),
            checked_runs: Mutex::new(Vec::new()),
            committed_runs: Mutex::new(Vec::new()),
        }
    }
}

impl RunBudget for CountingBudget {
    fn check(&self, run_id: &str, tokens: u64, cost: f64) -> BudgetDecision {
        self.checks.fetch_add(1, Ordering::SeqCst);
        self.checked_runs.lock().unwrap().push(run_id.to_string());
        self.inner.check(run_id, tokens, cost)
    }

    fn commit(&self, run_id: &str, tokens: u64, cost: f64) {
        self.commits.fetch_add(1, Ordering::SeqCst);
        self.committed_runs.lock().unwrap().push(run_id.to_string());
        self.inner.commit(run_id, tokens, cost);
    }
}

/// Forwards every gateway event to the production EventBus while retaining no
/// alternate event store.  The witness reads outcomes back through the wired
/// `ObservabilityReadApi`; this adapter only preserves the exact production sink
/// identity expected by `GatewayDeps`.
struct ProductionBus(Arc<dyn EventBusEmit>);

impl EventBusEmit for ProductionBus {
    fn emit(&self, event: Event) {
        self.0.emit(event);
    }
}

fn fresh_workspace() -> (tempfile::TempDir, std::path::PathBuf, std::path::PathBuf) {
    let dir = tempfile::tempdir().expect("tempdir");
    let workspace = std::fs::canonicalize(dir.path()).expect("canonical workspace");
    std::fs::create_dir_all(workspace.join(".advance")).unwrap();
    std::fs::create_dir_all(workspace.join(".runtime/events/jsonl")).unwrap();
    std::fs::create_dir_all(workspace.join(".agent")).unwrap();
    let runtime_config = workspace.join(".advance/runtime-config.yaml");
    std::fs::write(&runtime_config, RUNTIME_YAML).unwrap();
    std::fs::write(workspace.join(".agent/config.yaml"), AGENT_YAML).unwrap();
    (dir, workspace, runtime_config)
}

fn request(target: &str, correlation: &str, task_id: Option<&str>, run_id: &str) -> AwaitRequest {
    AwaitRequest::AgentRequest(AgentAwaitRequest {
        target: target.to_string(),
        payload: format!("work:{target}").into_bytes(),
        correlation_id: correlation.to_string(),
        context: Some(MessageContext {
            task_id: task_id.map(str::to_string),
            run_id: Some(run_id.to_string()),
            execution_id: Some(format!("exec-{correlation}")),
            trace_id: Some(format!("dispatch-{correlation}")),
            in_reply_to: Some(format!("inherited-reply-{correlation}")),
            correlation_id: Some(format!("inherited-correlation-{correlation}")),
        }),
    })
}

fn keep_losers() -> AwaitOptions {
    AwaitOptions {
        mode: AwaitMode::AnyOf,
        idle_timeout_secs: None,
        on_idle_timeout: TimeoutPolicy::ReturnPartial,
        keep_losers: true,
    }
}

fn host_context(agent: &str, turn_id: &str, trace_id: &str, run_id: &str) -> HostCallContext {
    HostCallContext {
        agent_id: agent.to_string(),
        trace_id: trace_id.to_string(),
        turn_id: Some(turn_id.to_string()),
        capability: "llm".to_string(),
        function: "agent-llm::generate".to_string(),
        // Deliberately populated even for post-detach calls: C216 must replace
        // this inherited value with None before the gateway budget boundary.
        run_id: Some(run_id.to_string()),
        iteration: None,
    }
}

fn send_context(agent: &str, turn_id: &str, run_id: &str) -> HostCallContext {
    HostCallContext {
        agent_id: agent.to_string(),
        trace_id: "trace-send".to_string(),
        turn_id: Some(turn_id.to_string()),
        capability: "messaging".to_string(),
        function: "agent-messaging::send".to_string(),
        run_id: Some(run_id.to_string()),
        iteration: None,
    }
}

fn llm_request(prompt: &str, task_id: Option<&str>) -> Vec<Val> {
    vec![Val::Record(vec![
        (
            "task-id".into(),
            Val::Option(task_id.map(|id| Box::new(Val::String(id.to_string())))),
        ),
        ("prompt".into(), Val::String(prompt.to_string())),
        ("params".into(), Val::Option(None)),
        ("output-schema".into(), Val::Option(None)),
    ])]
}

fn message_context(task_id: Option<&str>, run_id: &str) -> Val {
    Val::Option(Some(Box::new(Val::Record(vec![
        (
            "task-id".into(),
            Val::Option(task_id.map(|id| Box::new(Val::String(id.to_string())))),
        ),
        (
            "run-id".into(),
            Val::Option(Some(Box::new(Val::String(run_id.to_string())))),
        ),
        (
            "execution-id".into(),
            Val::Option(Some(Box::new(Val::String("exec-inherited".into())))),
        ),
    ]))))
}

fn send_params(target: &str, payload: &[u8], context: Val) -> Vec<Val> {
    vec![
        Val::String(target.to_string()),
        Val::List(payload.iter().copied().map(Val::U8).collect()),
        context,
    ]
}

fn assert_send_ok(values: &[Val]) {
    assert!(
        matches!(values, [Val::Result(Ok(None))]),
        "send must return result::Ok(unit), got {values:?}"
    );
}

async fn take_running_turn(
    store: &advance_messaging::MailboxStore,
    boundary: &dyn advance_scheduler::hook::ProtectedTurnExecutionBoundary,
    agent: &str,
) -> (advance_shared_types::mailbox::Message, MailboxTurnIdentity) {
    let mailbox = {
        let mut observed = None;
        for _ in 0..200 {
            if let Some(mailbox) = store.get(agent) {
                observed = Some(mailbox);
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        observed.unwrap_or_else(|| panic!("protected mailbox created for {agent}"))
    };
    let envelope = tokio::time::timeout(Duration::from_secs(2), mailbox.recv_turn())
        .await
        .expect("protected turn arrived")
        .expect("protected dequeue succeeds");
    let (message, identity, guard) = envelope.into_parts();
    let identity = identity.expect("protected identity");
    assert_eq!(identity.expected_agent, agent);
    assert_eq!(
        boundary
            .begin(&identity, guard.expect("protected dequeue guard"))
            .expect("start protected turn"),
        TurnStartOutcome::Execute
    );
    (message, identity)
}

async fn query_one_response(read: &dyn ObservabilityReadApi, trace_id: &str) -> Arc<Event> {
    let filter = EventFilter {
        event_type_prefix: Some("llm.response".into()),
        trace_id: Some(trace_id.to_string()),
        ..Default::default()
    };
    for _ in 0..200 {
        let rows = read.query(&filter, 10).await.expect("event query");
        if let Some(row) = rows.into_iter().next() {
            return row.event;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("llm.response for trace {trace_id} was not persisted");
}

fn reply_by_slot(
    result: &AwaitResult,
    slot: u32,
) -> &advance_shared_types::await_session::ReplyResult {
    result
        .replies
        .iter()
        .find(|reply| reply.slot == slot)
        .unwrap_or_else(|| panic!("missing reply slot {slot}"))
}

fn mailbox_depth(store: &advance_messaging::MailboxStore, agent: &str) -> usize {
    store.get(agent).map(|mailbox| mailbox.depth()).unwrap_or(0)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn module_007_ac_13_all_four_keep_losers_rules_share_one_production_turn() {
    // This integration-test binary contains exactly this one test, so a unique
    // environment name and HOME are process-local and cannot race sibling
    // tests.  The dedicated platform home also keeps the external monotonic
    // recovery anchor independent from the disposable workspace journal.
    std::env::set_var("SYS_J70_MASTER_KEY", TEST_MASTER_KEY);
    let platform_home_guard = tempfile::tempdir().expect("platform home");
    let platform_home = std::fs::canonicalize(platform_home_guard.path()).expect("canonical home");
    std::env::set_var("HOME", &platform_home);

    let (_tmp, workspace, config_path) = fresh_workspace();
    let builder = RuntimeHostBuilder::new(&config_path, &workspace)
        .await
        .expect("runtime builder");
    let (host, handles) = wire_capabilities(builder, &workspace)
        .await
        .expect("production wire_capabilities");
    assert_eq!(
        handles
            .perchild_manager
            .as_ref()
            .expect("messaging activation yields per-child manager")
            .register_existing_routes_for_test(),
        5,
        "stand in for advance start's post-wiring serve-existing-children route step"
    );
    let manager: Arc<AwaitSessionManagerImpl> = handles
        .await_manager
        .clone()
        .expect("messaging activation yields await manager");
    let store = handles
        .messaging_store
        .clone()
        .expect("messaging activation yields protected mailbox store");
    let boundary = handles
        .protected_turn_boundary_for_test()
        .expect("joint C215/C216 scheduler boundary");
    let cost_port = handles
        .turn_cost_attribution_for_test()
        .expect("canonical C216 cost projection");
    let read_api = handles
        .observability_read_api
        .clone()
        .expect("production EventBus read surface");

    let original_run = handles
        .run_manager
        .ensure_run("task-parent", ROOT_BARE, RunConfig::default())
        .expect("original run");
    let original_run = original_run.to_string();

    let primary_id = SessionId(PRIMARY_SESSION.to_string());
    let primary_manager = Arc::clone(&manager);
    let primary_run = original_run.clone();
    let primary = tokio::spawn(async move {
        primary_manager
            .start_with_run_and_session(
                SessionId(PRIMARY_SESSION.to_string()),
                ROOT_BARE,
                Some(&primary_run),
                vec![
                    request(WINNER, "winner", Some("task-winner"), &primary_run),
                    request(
                        LOSER_TASK,
                        "loser-task",
                        Some(REPLACEMENT_TASK),
                        &primary_run,
                    ),
                    request(LOSER_GLOBAL, "loser-global", None, &primary_run),
                ],
                keep_losers(),
                None,
            )
            .await
    });

    for _ in 0..40 {
        if primary.is_finished() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    if primary.is_finished() {
        let early = primary.await.expect("early primary task joins");
        panic!("primary await ended before protected dispatch: {early:?}");
    }

    let (winner_message, winner_identity) =
        take_running_turn(&store, boundary.as_ref(), WINNER).await;
    let (loser_task_message, loser_task_identity) =
        take_running_turn(&store, boundary.as_ref(), LOSER_TASK).await;
    let (loser_global_message, loser_global_identity) =
        take_running_turn(&store, boundary.as_ref(), LOSER_GLOBAL).await;

    // The pre-detach trusted contexts carry the original run/reply correlation.
    for message in [&winner_message, &loser_task_message, &loser_global_message] {
        let context = message.context.as_ref().expect("await context");
        assert_eq!(context.run_id.as_deref(), Some(original_run.as_str()));
        assert_eq!(context.in_reply_to.as_deref(), Some(message.id.as_str()));
        assert!(context.correlation_id.is_some());
    }
    assert_eq!(
        loser_task_message
            .context
            .as_ref()
            .and_then(|context| context.task_id.as_deref()),
        Some(REPLACEMENT_TASK)
    );
    assert_eq!(
        loser_global_message
            .context
            .as_ref()
            .and_then(|context| context.task_id.as_deref()),
        None
    );

    let counted_budget = Arc::new(CountingBudget::new(Arc::new(handles.run_manager.budget())));
    let loopback = boot_with_retry_overrides(
        vec![
            ScriptedResponse::err(429, r#"{"error":{"message":"slow down"}}"#),
            ScriptedResponse::ok_chat("pre-detach", 11, 7),
            ScriptedResponse::ok_chat("post-task", 5, 3),
            ScriptedResponse::ok_chat("post-global", 2, 2),
        ],
        GatewayDeps {
            run_budget: counted_budget.clone(),
            repetition_guard: Arc::new(RepetitionGuard::new(64, 100, RepetitionAction::WarnOnly)),
            event_bus: Arc::new(ProductionBus(handles.event_bus_dyn.clone())),
            default_agent_id: LOSER_TASK.to_string(),
        },
        cap_llm::PartialRetry {
            max_retries: Some(2),
            base_delay_ms: Some(1_000),
            max_delay_ms: Some(1_000),
            jitter: Some(false),
        },
    )
    .await;
    let llm = AgentLlmGenerateHandler {
        gateway: loopback.gateway.clone(),
        turn_cost: Some(cost_port.clone()),
    };

    // Rule 2: enter while Active, then hold the call in the real retry loop so
    // the winner can commit the detach transaction before this call completes.
    let pre_detach = tokio::spawn(llm.call(
        host_context(
            LOSER_TASK,
            &loser_task_identity.turn_id,
            "trace-pre-detach",
            "forged-current-run",
        ),
        llm_request("pre-detach call", None),
        1,
    ));
    for _ in 0..200 {
        if loopback.server.recorder().chat_request_count() == 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert_eq!(
        loopback.server.recorder().chat_request_count(),
        1,
        "the pre-detach call must be between its first 429 and retry"
    );

    let send_handler = host
        .host_registry()
        .lookup("messaging")
        .into_iter()
        .find(|spec| spec.name == "send")
        .expect("production-registered messaging.send")
        .handler;
    let winner_send = send_handler
        .call(
            send_context(WINNER, &winner_identity.turn_id, &original_run),
            send_params(ROOT_COLON, b"winner", Val::Option(None)),
            1,
        )
        .await
        .expect("winner send handler");
    assert_send_ok(&winner_send);

    let primary_result: Result<AwaitResult, OrchestrationError> =
        tokio::time::timeout(Duration::from_secs(2), primary)
            .await
            .expect("parent wakes")
            .expect("primary task joins");
    let primary_result = primary_result.expect("AnyOf resolves");
    assert_eq!(primary_result.session_id, primary_id.0);
    assert_eq!(primary_result.status, AwaitSessionStatus::Completed);
    assert_eq!(primary_result.replies.len(), 3);

    // Rule 1: winner is preserved; every pending loser is materialized before
    // parent wake, with explicit task replacement or a cleared task.
    let winner_reply = reply_by_slot(&primary_result, 0);
    assert!(matches!(winner_reply.status, ReplyStatus::Completed));
    assert_eq!(winner_reply.task_id.as_deref(), Some("task-winner"));
    let task_loser_reply = reply_by_slot(&primary_result, 1);
    assert!(matches!(task_loser_reply.status, ReplyStatus::Cancelled));
    assert_eq!(task_loser_reply.task_id.as_deref(), Some(REPLACEMENT_TASK));
    let global_loser_reply = reply_by_slot(&primary_result, 2);
    assert!(matches!(global_loser_reply.status, ReplyStatus::Cancelled));
    assert_eq!(global_loser_reply.task_id, None);

    // The parent result is observable only after batch detach: winner remains
    // Active and both unresolved losers are already Detached at this point.
    assert!(matches!(
        cost_port.cost_attribution(&winner_identity.turn_id, WINNER),
        CostAttributionLookup::Tracked(
            advance_shared_types::turn_attribution::CostAttributionSnapshot {
                state: CostTurnState::Active,
                ..
            }
        )
    ));
    for (identity, agent) in [
        (&loser_task_identity, LOSER_TASK),
        (&loser_global_identity, LOSER_GLOBAL),
    ] {
        assert!(matches!(
            cost_port.cost_attribution(&identity.turn_id, agent),
            CostAttributionLookup::Tracked(
                advance_shared_types::turn_attribution::CostAttributionSnapshot {
                    state: CostTurnState::Detached { .. },
                    ..
                }
            )
        ));
    }

    let pre_out = pre_detach
        .await
        .expect("pre-detach task joins")
        .expect("pre-detach handler succeeds");
    assert!(matches!(pre_out.as_slice(), [Val::Result(Ok(Some(_)))]));
    assert_eq!(counted_budget.checks.load(Ordering::SeqCst), 1);
    assert_eq!(counted_budget.commits.load(Ordering::SeqCst), 1);
    assert_eq!(
        counted_budget.checked_runs.lock().unwrap().as_slice(),
        [original_run.as_str()]
    );
    assert_eq!(
        counted_budget.committed_runs.lock().unwrap().as_slice(),
        [original_run.as_str()]
    );
    let pre_event = query_one_response(read_api.as_ref(), "trace-pre-detach").await;
    assert_eq!(pre_event.run_id.as_deref(), Some(original_run.as_str()));
    assert_eq!(pre_event.task_id.as_deref(), Some(REPLACEMENT_TASK));

    // Rule 3: calls entering after detach still execute and emit, but neither
    // inherited HostCallContext.run_id reaches RunBudget.  The explicit task is
    // audit-only; the no-task loser stays global-only.
    let post_task = llm
        .call(
            host_context(
                LOSER_TASK,
                &loser_task_identity.turn_id,
                "trace-post-task",
                &original_run,
            ),
            llm_request("post detach task", Some(REPLACEMENT_TASK)),
            1,
        )
        .await
        .expect("post-task handler");
    assert!(matches!(post_task.as_slice(), [Val::Result(Ok(Some(_)))]));
    let post_global = llm
        .call(
            host_context(
                LOSER_GLOBAL,
                &loser_global_identity.turn_id,
                "trace-post-global",
                &original_run,
            ),
            llm_request("post detach global", None),
            1,
        )
        .await
        .expect("post-global handler");
    assert!(matches!(post_global.as_slice(), [Val::Result(Ok(Some(_)))]));
    assert_eq!(
        counted_budget.checks.load(Ordering::SeqCst),
        1,
        "post-detach calls perform no budget check"
    );
    assert_eq!(
        counted_budget.commits.load(Ordering::SeqCst),
        1,
        "post-detach calls perform no budget commit"
    );
    let post_task_event = query_one_response(read_api.as_ref(), "trace-post-task").await;
    assert_eq!(post_task_event.run_id, None);
    assert_eq!(post_task_event.task_id.as_deref(), Some(REPLACEMENT_TASK));
    let post_global_event = query_one_response(read_api.as_ref(), "trace-post-global").await;
    assert_eq!(post_global_event.run_id, None);
    assert_eq!(post_global_event.task_id, None);

    // Rule 1's ordinary-routing half: inherited run/execution/await correlation
    // cannot escape a detached turn.  Only the explicit replacement task remains.
    let unrelated_task = send_handler
        .call(
            send_context(LOSER_TASK, &loser_task_identity.turn_id, &original_run),
            send_params(
                SINK_TASK,
                b"detached-task",
                message_context(Some(REPLACEMENT_TASK), &original_run),
            ),
            1,
        )
        .await
        .expect("detached unrelated send");
    assert_send_ok(&unrelated_task);
    let delivered_task = tokio::time::timeout(
        Duration::from_secs(2),
        store.get(SINK_TASK).expect("sink mailbox").recv(),
    )
    .await
    .expect("task sink receives");
    let context = delivered_task.context.expect("sanitized context retained");
    assert_eq!(context.task_id.as_deref(), Some(REPLACEMENT_TASK));
    assert_eq!(context.run_id, None);
    assert_eq!(context.execution_id, None);
    assert_eq!(context.trace_id, None);
    assert_eq!(context.in_reply_to, None);
    assert_eq!(context.correlation_id, None);

    let unrelated_global = send_handler
        .call(
            send_context(LOSER_GLOBAL, &loser_global_identity.turn_id, &original_run),
            send_params(
                SINK_GLOBAL,
                b"detached-global",
                message_context(None, &original_run),
            ),
            1,
        )
        .await
        .expect("detached global send");
    assert_send_ok(&unrelated_global);
    let delivered_global = tokio::time::timeout(
        Duration::from_secs(2),
        store.get(SINK_GLOBAL).expect("global sink mailbox").recv(),
    )
    .await
    .expect("global sink receives");
    let context = delivered_global.context.expect("sanitized empty context");
    assert_eq!(context.task_id, None);
    assert_eq!(context.run_id, None);
    assert_eq!(context.execution_id, None);
    assert_eq!(context.trace_id, None);
    assert_eq!(context.in_reply_to, None);
    assert_eq!(context.correlation_id, None);

    // Arm a later same-source slot.  An implementation that falls back to the
    // old source/target heuristic would incorrectly satisfy this new session.
    let alias_id = SessionId(ALIAS_SESSION.to_string());
    let alias_manager = Arc::clone(&manager);
    let alias_run = original_run.clone();
    let mut alias = tokio::spawn(async move {
        alias_manager
            .start_with_run_and_session(
                SessionId(ALIAS_SESSION.to_string()),
                ROOT_BARE,
                Some(&alias_run),
                vec![request(
                    LOSER_TASK,
                    "later-slot",
                    Some("task-later"),
                    &alias_run,
                )],
                keep_losers(),
                None,
            )
            .await
    });
    for _ in 0..200 {
        if mailbox_depth(&store, LOSER_TASK) == 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert_eq!(mailbox_depth(&store, LOSER_TASK), 1, "later slot armed");

    // Rule 4: exact old-turn reply emits once and is dropped before parent
    // mailbox and before the later same-source AwaitSession.
    let mut late_events = read_api.subscribe(EventFilter {
        event_type_prefix: Some("orchestration.reply_late".into()),
        agent_id: Some(LOSER_TASK.to_string()),
        ..Default::default()
    });
    for payload in [b"late-once".as_slice(), b"late-duplicate".as_slice()] {
        let out = send_handler
            .call(
                send_context(LOSER_TASK, &loser_task_identity.turn_id, &original_run),
                send_params(ROOT_COLON, payload, Val::Option(None)),
                1,
            )
            .await
            .expect("late send handler");
        assert_send_ok(&out);
    }
    let late = match tokio::time::timeout(Duration::from_secs(2), late_events.recv()).await {
        Ok(ReadNext::Event(event)) => event,
        other => panic!("expected one live reply_late event, got {other:?}"),
    };
    assert_eq!(late.event_type, "orchestration.reply_late");
    assert_eq!(late.run_id, None);
    assert_eq!(late.task_id, None);
    assert_eq!(late.payload["turn_id"], loser_task_identity.turn_id);
    assert_eq!(late.payload["outcome"], "dropped");
    assert!(
        tokio::time::timeout(Duration::from_millis(250), late_events.recv())
            .await
            .is_err(),
        "duplicate old-turn reply emits no second reply_late"
    );
    assert_eq!(mailbox_depth(&store, ROOT_COLON), 0);
    assert!(
        tokio::time::timeout(Duration::from_millis(250), &mut alias)
            .await
            .is_err(),
        "old turn must not satisfy a later same-source slot"
    );

    manager
        .close(&alias_id, "witness-cleanup")
        .await
        .expect("close later-slot session");
    let alias_result = alias.await.expect("alias task joins");
    assert!(matches!(
        alias_result,
        Err(OrchestrationError::SessionClosed(reason)) if reason == "witness-cleanup"
    ));

    // Complete the exact three executing Stores so C216 emits source-quiesced
    // receipts and the joint boundary closes their C215 source rows.
    boundary
        .finish_drained(&winner_identity, [0x31; 16], 1)
        .expect("finish winner");
    boundary
        .finish_drained(&loser_task_identity, [0x32; 16], 1)
        .expect("finish task loser");
    boundary
        .finish_drained(&loser_global_identity, [0x33; 16], 1)
        .expect("finish global loser");
}
