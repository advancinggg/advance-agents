//! Focused CONTRACT-216 Store-lifecycle witnesses.
//!
//! These tests intentionally use the real Wasmtime `Store<ComponentCtx>`, the
//! real C216 authority/provider, the protected `MailboxStore` dequeue handoff,
//! and the production scheduler RAII finalizer.  They are not state-bit mocks:
//! a terminal `StoreDestroyed` observation is accepted only after the concrete
//! reusable Store pair has been taken/dropped (or the cancelled guest future's
//! `OwnedWasmInstance` has already dropped it).

use std::num::{NonZeroU32, NonZeroUsize};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use advance_cli::agent_loop::{StoreMailboxReader, WasmMessageHandler};
use advance_messaging::{
    MailboxDispatcher, MailboxStore, NotifyError, ProtectedTurnExecutionBoundary as _,
    TurnExecutionBoundaryImpl, TurnMailboxDelivery,
};
use advance_reply_tracker::manager::ManagerOptions;
use advance_reply_tracker::{
    compose_turn_attribution_facades, register_reply_tracker_host_fns, register_send_host_fn,
    AwaitSessionManagerImpl,
};
use advance_runtime::capability_injector::CapabilityInjector;
use advance_runtime::circuit_breaker::DefaultCircuitBreakerBus;
use advance_runtime::config::WasmConfig;
use advance_runtime::host_registry::{HostRegistry, InMemoryHostRegistry};
use advance_runtime::ComponentRuntime;
use advance_scheduler::agent_loop::AgentLoopDriverImpl;
use advance_scheduler::hook::{
    BootstrapError, HookError, MessageHandler, ProtectedTurnExecutionBoundary, RunBootstrap,
};
use advance_scheduler::types::{ComponentConfig, ComponentId, WasmInstance};
use advance_shared_types::capability::{CapParams, CapRequest, CapabilityId, GrantDecision};
use advance_shared_types::context::{
    AssemblyContext, AssemblyError, AssemblyResult, ContextAssembler, TierTokenCounts,
};
use advance_shared_types::event::Event;
use advance_shared_types::mailbox::{
    AgentAction, AgentActionDispatcher, DequeuedTurnGuard, DispatchError, MailboxReader,
    MailboxTurnIdentity, Message, MessageContext, MessageKind, MsgError,
};
use advance_shared_types::memory::{PostProcessorError, PostProcessorHook};
use advance_shared_types::outbound::DeliveryReport;
use advance_shared_types::progress_lifecycle_recovery::{
    ProgressLifecycleRecoveryJournal, RecoveryJournalConfig,
};
use advance_shared_types::traits::{EventBusEmit, GrantCheck};
use advance_shared_types::turn_attribution::{
    CostAttributionLookup, QueuedTurnSpec, TurnAttributionAuthorityFactory,
    TurnAttributionAuthorityParts, TurnCompletionOwner, TurnCostAttributionReadPort,
    TurnStartOutcome,
};
use advance_shared_types::SessionId;
use tempfile::TempDir;
use zeroize::Zeroizing;

const AGENT: &str = "agent:store-child";
const BARE_AGENT: &str = "store-child";
const COUNTER_CORE: &[u8] =
    include_bytes!("../../runtime/tests/fixtures/guest-rust-counter.core.wasm");
const SEND_CORE: &[u8] = include_bytes!("../../runtime/tests/fixtures/guest-rust-send.core.wasm");
const AWAIT_CORE: &[u8] =
    include_bytes!("../../runtime/tests/fixtures/guest-rust-with-caps.core.wasm");

struct AllowAll;

impl GrantCheck for AllowAll {
    fn check(&self, _: &str, _: &str, _: &str, _: &CapParams) -> GrantDecision {
        GrantDecision::Allow
    }
}

struct NoopBus;

impl EventBusEmit for NoopBus {
    fn emit(&self, _: Event) {}
}

struct NoopDispatcher;

#[async_trait::async_trait]
impl AgentActionDispatcher for NoopDispatcher {
    async fn dispatch(
        &self,
        _: &str,
        _: &Message,
        _: &[AgentAction],
    ) -> Result<DeliveryReport, DispatchError> {
        Ok(DeliveryReport::empty())
    }
}

struct NoopPostProcessor;

#[async_trait::async_trait]
impl PostProcessorHook for NoopPostProcessor {
    async fn run(
        &self,
        _: &str,
        _: &Message,
        _: &advance_shared_types::mailbox::ActionResult,
    ) -> Result<(), PostProcessorError> {
        Ok(())
    }
}

struct NoopRunBootstrap;

#[async_trait::async_trait]
impl RunBootstrap for NoopRunBootstrap {
    async fn ensure_run(&self, controller_agent: &str) -> Result<String, BootstrapError> {
        Ok(format!("run-{controller_agent}"))
    }
}

struct ScriptedAssembler {
    fail: bool,
}

#[async_trait::async_trait]
impl ContextAssembler for ScriptedAssembler {
    async fn assemble(&self, _: AssemblyContext) -> Result<AssemblyResult, AssemblyError> {
        if self.fail {
            return Err(AssemblyError::MemoryStoreFailure(
                "injected-assembly-failure".into(),
            ));
        }
        Ok(AssemblyResult {
            messages: Vec::new(),
            routing_method: "test".into(),
            routing_confidence: 1.0,
            is_new_task: true,
            tier_token_counts: TierTokenCounts {
                tier1a: 0,
                tier1b: 0,
                tier2: 0,
                tier3: 0,
            },
        })
    }

    fn inject_tier3_warning(&self, _: &str, _: &str) {}
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct DrainObservation {
    turn_id: String,
    incarnation: [u8; 16],
    epoch: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct DestroyObservation {
    turn_id: String,
    incarnation: [u8; 16],
}

/// Scheduler-side adapter over the real C216 execution boundary.  The vectors
/// record only after the provider accepts the corresponding terminal proof.
struct RecordingBoundary {
    inner: TurnExecutionBoundaryImpl,
    drained: Mutex<Vec<DrainObservation>>,
    destroyed: Mutex<Vec<DestroyObservation>>,
}

impl RecordingBoundary {
    fn drained(&self) -> Vec<DrainObservation> {
        self.drained.lock().unwrap().clone()
    }

    fn destroyed(&self) -> Vec<DestroyObservation> {
        self.destroyed.lock().unwrap().clone()
    }
}

impl ProtectedTurnExecutionBoundary for RecordingBoundary {
    fn begin(
        &self,
        identity: &MailboxTurnIdentity,
        guard: DequeuedTurnGuard,
    ) -> Result<TurnStartOutcome, HookError> {
        self.inner
            .begin(identity, guard)
            .map_err(|_| HookError::Failure("protected-turn-start-failed".into()))
    }

    fn finish_drained(
        &self,
        identity: &MailboxTurnIdentity,
        store_incarnation: [u8; 16],
        store_epoch: u64,
    ) -> Result<(), HookError> {
        self.inner
            .finish_drained(identity, store_incarnation, store_epoch)
            .map_err(|_| HookError::Failure("protected-turn-finish-failed".into()))?;
        self.drained.lock().unwrap().push(DrainObservation {
            turn_id: identity.turn_id.clone(),
            incarnation: store_incarnation,
            epoch: store_epoch,
        });
        Ok(())
    }

    fn finish_store_destroyed(
        &self,
        identity: &MailboxTurnIdentity,
        store_incarnation: [u8; 16],
    ) -> Result<(), HookError> {
        self.inner
            .finish_store_destroyed(identity, store_incarnation)
            .map_err(|_| HookError::Failure("protected-turn-destroy-failed".into()))?;
        self.destroyed.lock().unwrap().push(DestroyObservation {
            turn_id: identity.turn_id.clone(),
            incarnation: store_incarnation,
        });
        Ok(())
    }
}

struct C216Harness {
    _root: TempDir,
    store: Arc<MailboxStore>,
    cost: Arc<dyn TurnCostAttributionReadPort>,
    boundary: Arc<RecordingBoundary>,
}

impl C216Harness {
    fn new() -> Self {
        let root = tempfile::tempdir().expect("journal root");
        let config = RecoveryJournalConfig::new_at_composition(
            root.path().join("journal"),
            root.path().join("anchor/root.anchor"),
            NonZeroU32::MIN,
            Zeroizing::new([0x61; 32]),
        )
        .expect("recovery config");
        let journal = ProgressLifecycleRecoveryJournal::open_at_composition(config)
            .expect("open recovery journal");
        let (turn_recovery, _progress_recovery) = journal.split_at_composition();
        let TurnAttributionAuthorityParts {
            activation_staging: _,
            registry_issuer,
            mailbox_admission_issuer,
            mailbox_removal_issuer,
            mailbox_dequeue_issuer,
            mailbox_publish_verifier,
            store_quiescence_issuer,
            source_quiescence_recovery_issuer: _,
            source_quiescence_verifier: _,
            verifier,
        } = TurnAttributionAuthorityFactory::new_at_composition(
            &mut rand::rngs::OsRng,
            turn_recovery,
        )
        .expect("C216 authority");
        let (dispatch, execution, _reply, mailbox, cost) =
            compose_turn_attribution_facades(64, registry_issuer, verifier)
                .expect("C216 provider")
                .move_to_composition();
        let store = Arc::new(MailboxStore::new_with_turn_attribution(
            NonZeroUsize::new(16).unwrap(),
            mailbox_admission_issuer,
            mailbox_removal_issuer,
            mailbox_dequeue_issuer,
            mailbox_publish_verifier,
            dispatch,
            mailbox,
            Arc::clone(&execution),
        ));
        let boundary = Arc::new(RecordingBoundary {
            inner: TurnExecutionBoundaryImpl::new(store_quiescence_issuer, execution),
            drained: Mutex::new(Vec::new()),
            destroyed: Mutex::new(Vec::new()),
        });
        Self {
            _root: root,
            store,
            cost,
            boundary,
        }
    }

    fn publish(&self, turn_id: &str) {
        let message = Message {
            id: turn_id.into(),
            kind: MessageKind::User,
            from: "user:test".into(),
            to: AGENT.into(),
            payload: turn_id.as_bytes().to_vec(),
            context: None,
            timestamp: SystemTime::now(),
            origin: None,
        };
        self.store
            .publish_execution_turn(TurnMailboxDelivery {
                target: AGENT.into(),
                message,
                spec: QueuedTurnSpec {
                    turn_id: turn_id.into(),
                    expected_agent: AGENT.into(),
                    parent_agent: "user:test".into(),
                    session_id: SessionId(format!("exec_{turn_id}")),
                    slot: 0,
                    completion_owner: TurnCompletionOwner::ExecutionBoundary,
                    original_task_id: Some(format!("task-{turn_id}")),
                    original_run_id: Some(format!("run-{turn_id}")),
                    original_reply_to: Some("user:test".into()),
                },
            })
            .expect("publish protected execution turn");
    }

    fn assert_untracked(&self, turn_id: &str) {
        assert_eq!(
            self.cost.cost_attribution(turn_id, AGENT),
            CostAttributionLookup::Untracked,
            "terminal execution-boundary turn must leave no tracked/Running row"
        );
    }
}

fn runtime() -> Arc<ComponentRuntime> {
    Arc::new(
        ComponentRuntime::new(&WasmConfig {
            max_memory_pages: 256,
            epoch_interruption_ms: 100,
            fuel_enabled: false,
        })
        .expect("runtime"),
    )
}

fn injector(registry: Arc<dyn HostRegistry>) -> Arc<CapabilityInjector> {
    Arc::new(CapabilityInjector::new(
        registry,
        Arc::new(AllowAll),
        Arc::new(DefaultCircuitBreakerBus::new()),
    ))
}

fn wasm_handler(
    core: &[u8],
    registry: Arc<dyn HostRegistry>,
    caps: Vec<CapRequest>,
) -> Arc<WasmMessageHandler> {
    let runtime = runtime();
    let component = build_agent::encode_core_to_component(core).expect("encode component");
    let loaded = runtime.load_component(&component).expect("load component");
    Arc::new(WasmMessageHandler::new(
        runtime,
        loaded,
        injector(registry),
        caps,
        BARE_AGENT.into(),
        "trace-protected-store".into(),
    ))
}

fn driver(
    harness: &C216Harness,
    handler: Arc<dyn MessageHandler>,
    assembly_fails: bool,
) -> AgentLoopDriverImpl {
    let reader: Arc<dyn MailboxReader> =
        Arc::new(StoreMailboxReader::new(Arc::clone(&harness.store)));
    AgentLoopDriverImpl::new(
        reader,
        Arc::new(ScriptedAssembler {
            fail: assembly_fails,
        }),
        Arc::new(NoopPostProcessor),
        Arc::new(NoopDispatcher),
        Arc::new(NoopRunBootstrap),
        handler,
    )
    .with_protected_turn_boundary(harness.boundary.clone())
}

fn component_config(data: Option<&[u8]>) -> ComponentConfig {
    ComponentConfig {
        id: "protected-store-fixture".into(),
        config_data: data.map(ToOwned::to_owned),
        trigger_context: None,
    }
}

fn instance() -> WasmInstance {
    WasmInstance::new(ComponentId::new("protected-store-instance".into()).unwrap())
}

fn messaging_caps() -> Vec<CapRequest> {
    vec![CapRequest {
        capability: CapabilityId::from("messaging"),
    }]
}

struct ScriptedMailboxDispatcher {
    fail_delivery: AtomicBool,
    deliveries: AtomicUsize,
}

#[async_trait::async_trait]
impl MailboxDispatcher for ScriptedMailboxDispatcher {
    async fn deliver(&self, _: &str, _: Message) -> Result<(), MsgError> {
        self.deliveries.fetch_add(1, Ordering::AcqRel);
        if self.fail_delivery.load(Ordering::Acquire) {
            Err(MsgError::MailboxFull)
        } else {
            Ok(())
        }
    }

    async fn reply(&self, _: &str, _: &str, _: Vec<u8>) -> Result<(), MsgError> {
        Ok(())
    }

    async fn notify_agent(
        &self,
        _: &str,
        _: &str,
        _: Vec<u8>,
        _: Option<MessageContext>,
    ) -> Result<(), NotifyError> {
        Ok(())
    }
}

fn messaging_registry(
    fail_delivery: bool,
) -> (
    Arc<dyn HostRegistry>,
    Arc<AwaitSessionManagerImpl>,
    Arc<ScriptedMailboxDispatcher>,
) {
    let registry: Arc<dyn HostRegistry> = Arc::new(InMemoryHostRegistry::new());
    let dispatcher = Arc::new(ScriptedMailboxDispatcher {
        fail_delivery: AtomicBool::new(fail_delivery),
        deliveries: AtomicUsize::new(0),
    });
    let manager = Arc::new(AwaitSessionManagerImpl::new(
        dispatcher.clone(),
        ManagerOptions::default(),
    ));
    register_send_host_fn(&*registry, manager.clone());
    register_reply_tracker_host_fns(&*registry, manager.clone(), Arc::new(NoopBus));
    (registry, manager, dispatcher)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn c216_real_store_normal_second_turn_drains_epochs_and_leaves_no_running_row() {
    let harness = C216Harness::new();
    let registry: Arc<dyn HostRegistry> = Arc::new(InMemoryHostRegistry::new());
    let concrete = wasm_handler(COUNTER_CORE, registry, Vec::new());
    let incarnation = concrete
        .trusted_store_incarnation()
        .expect("pre-init immutable Store incarnation is available");
    let handler: Arc<dyn MessageHandler> = concrete.clone();
    let driver = driver(&harness, handler, false);
    harness.publish("normal-one");
    harness.publish("normal-two");

    driver
        .serve_n_turns(AGENT, component_config(None), instance(), 2)
        .await;

    let drained = harness.boundary.drained();
    assert_eq!(
        drained,
        vec![
            DrainObservation {
                turn_id: "normal-one".into(),
                incarnation,
                epoch: 1,
            },
            DrainObservation {
                turn_id: "normal-two".into(),
                incarnation,
                epoch: 2,
            },
        ],
        "one concrete Store is safely reused only after the first drain"
    );
    assert!(harness.boundary.destroyed().is_empty());
    assert_eq!(concrete.trusted_store_incarnation(), Some(incarnation));
    harness.assert_untracked("normal-one");
    harness.assert_untracked("normal-two");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn c216_sequential_run_restart_rotates_store_incarnation_and_resets_epoch() {
    let harness = C216Harness::new();
    let registry: Arc<dyn HostRegistry> = Arc::new(InMemoryHostRegistry::new());
    let concrete = wasm_handler(COUNTER_CORE, registry, Vec::new());
    let first_incarnation = concrete.trusted_store_incarnation().unwrap();
    let handler: Arc<dyn MessageHandler> = concrete.clone();
    let driver = driver(&harness, handler, false);

    harness.publish("restart-one");
    driver
        .serve_n_turns(AGENT, component_config(None), instance(), 1)
        .await;
    assert_eq!(
        concrete.trusted_store_incarnation(),
        Some(first_incarnation),
        "normal drain reuses the same concrete Store"
    );

    harness.publish("restart-two");
    driver
        .serve_n_turns(AGENT, component_config(None), instance(), 1)
        .await;
    let second_incarnation = concrete.trusted_store_incarnation().unwrap();
    assert_ne!(
        second_incarnation, first_incarnation,
        "a sequential run restart creates a distinct concrete Store identity"
    );
    assert_eq!(
        harness.boundary.drained(),
        vec![
            DrainObservation {
                turn_id: "restart-one".into(),
                incarnation: first_incarnation,
                epoch: 1,
            },
            DrainObservation {
                turn_id: "restart-two".into(),
                incarnation: second_incarnation,
                epoch: 1,
            },
        ],
        "each Store incarnation owns an independent monotonic drain epoch"
    );
    assert!(harness.boundary.destroyed().is_empty());
    harness.assert_untracked("restart-one");
    harness.assert_untracked("restart-two");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn c216_real_store_assembly_failure_destroys_store_and_leaves_no_running_row() {
    let harness = C216Harness::new();
    let registry: Arc<dyn HostRegistry> = Arc::new(InMemoryHostRegistry::new());
    let concrete = wasm_handler(COUNTER_CORE, registry, Vec::new());
    let incarnation = concrete.trusted_store_incarnation().unwrap();
    let handler: Arc<dyn MessageHandler> = concrete.clone();
    let driver = driver(&harness, handler, true);
    harness.publish("assembly-failure");

    driver
        .serve_n_turns(AGENT, component_config(None), instance(), 1)
        .await;

    assert!(harness.boundary.drained().is_empty());
    assert_eq!(
        harness.boundary.destroyed(),
        vec![DestroyObservation {
            turn_id: "assembly-failure".into(),
            incarnation,
        }],
        "post-start assembly failure must synchronously destroy the idle concrete Store"
    );
    assert_eq!(concrete.trusted_store_incarnation(), None);
    harness.assert_untracked("assembly-failure");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn c216_real_store_guest_failure_destroys_then_next_run_rebuilds_fresh_store() {
    let harness = C216Harness::new();
    let (registry, _manager, dispatcher) = messaging_registry(true);
    let concrete = wasm_handler(SEND_CORE, registry, messaging_caps());
    let incarnation = concrete.trusted_store_incarnation().unwrap();
    let handler: Arc<dyn MessageHandler> = concrete.clone();
    let driver = driver(&harness, handler, false);
    harness.publish("guest-failure");

    driver
        .serve_n_turns(AGENT, component_config(Some(b"send")), instance(), 1)
        .await;

    assert_eq!(dispatcher.deliveries.load(Ordering::Acquire), 1);
    assert!(harness.boundary.drained().is_empty());
    assert_eq!(
        harness.boundary.destroyed(),
        vec![DestroyObservation {
            turn_id: "guest-failure".into(),
            incarnation,
        }],
        "guest Err path must drop the concrete Store before C216 accepts StoreDestroyed"
    );
    assert_eq!(concrete.trusted_store_incarnation(), None);
    harness.assert_untracked("guest-failure");

    dispatcher.fail_delivery.store(false, Ordering::Release);
    harness.publish("guest-recovery");
    driver
        .serve_n_turns(AGENT, component_config(Some(b"send")), instance(), 1)
        .await;

    let recovered_incarnation = concrete
        .trusted_store_incarnation()
        .expect("the next sequential run publishes a fresh Store");
    assert_ne!(
        recovered_incarnation, incarnation,
        "recovery must never reuse the destroyed Store identity"
    );
    assert_eq!(dispatcher.deliveries.load(Ordering::Acquire), 2);
    assert_eq!(
        harness.boundary.drained(),
        vec![DrainObservation {
            turn_id: "guest-recovery".into(),
            incarnation: recovered_incarnation,
            epoch: 1,
        }],
        "the rebuilt Store starts a fresh monotonic drain epoch"
    );
    harness.assert_untracked("guest-recovery");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn c216_real_store_outer_cancellation_drops_owned_store_before_finalizer_and_untracks() {
    let harness = C216Harness::new();
    let (registry, manager, _dispatcher) = messaging_registry(false);
    let concrete = wasm_handler(AWAIT_CORE, registry, messaging_caps());
    let incarnation = concrete.trusted_store_incarnation().unwrap();
    let handler: Arc<dyn MessageHandler> = concrete.clone();
    let driver = driver(&harness, handler, false);
    harness.publish("outer-cancel");

    let task = tokio::spawn(async move {
        driver
            .serve_n_turns(
                AGENT,
                component_config(Some(b"await-replies")),
                instance(),
                1,
            )
            .await;
    });
    let mut parked = false;
    for _ in 0..400 {
        if manager.session_count_for_test().await == 1 {
            parked = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(parked, "guest must be parked inside the real host call");

    task.abort();
    let cancelled = task.await.expect_err("outer serve task is cancelled");
    assert!(cancelled.is_cancelled());

    assert!(harness.boundary.drained().is_empty());
    assert_eq!(
        harness.boundary.destroyed(),
        vec![DestroyObservation {
            turn_id: "outer-cancel".into(),
            incarnation,
        }],
        "cancel drops OwnedWasmInstance first; only then may the RAII owner attest StoreDestroyed"
    );
    assert_eq!(concrete.trusted_store_incarnation(), None);
    harness.assert_untracked("outer-cancel");
}
