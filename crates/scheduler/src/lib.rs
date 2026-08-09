//! MODULE-014 scheduler crate.
//!
//! See `docs/modules/MODULE-014-scheduler.md` §3.7 for the per-slice
//! change-history rows and full scope summaries. Slice A shipped the
//! foundation skeleton (4 contract traits, 5 driver-type skeleton structs,
//! real pure helpers, TriggerBusDispatchImpl subscribe/unsubscribe live
//! with admission-enforced rejection). Slice B adds real driver-loop
//! infrastructure + TriggerBusDispatchImpl `dispatch()` real fan-out +
//! agent-loop RunBootstrap wire.

pub mod agent_loop;
pub mod catchup;
pub mod component_emit;
pub mod contracts;
pub mod cron;
pub mod cycle_detection;
pub mod daemon;
pub mod extension;
pub mod hook;
pub mod materializer;
pub mod observation_anchor;
pub mod output;
pub mod registry;
mod registry_codec;
pub mod scheduler;
pub mod sensitive_params;
pub mod submit;
pub mod task;
pub mod tick_loop;
pub mod trigger_bus;
pub mod trigger_emit;
pub mod trigger_source;
pub mod types;
pub mod watcher;
pub mod webhook_hmac;

pub use catchup::{catch_up_components, CatchupDispatcher, CatchupKind, CatchupOutcome};
pub use component_emit::{
    emit_component_error, emit_component_finished, emit_component_started,
    COMPONENT_ERROR_EVENT_TYPE, COMPONENT_FINISHED_EVENT_TYPE, COMPONENT_STARTED_EVENT_TYPE,
    ERROR_MESSAGE_ECHO_MAX,
};
pub use contracts::{AgentLoopDriver, ComponentSubmitApi, SchedulerExtension, TriggerBusDispatch};
pub use cron::compute_jitter;
pub use cycle_detection::{check_chain, CycleCheckOutcome};
pub use daemon::{
    parse_restart_backoff_config, restart_decision, ParseRestartBackoffError, RestartBackoffConfig,
    RestartDecision, MAX_RESTART_BACKOFF_DELAY_MS, MAX_RESTART_RETRIES,
};
pub use hook::{
    BootstrapError, CrashCascadeSink, FileWatchSource, HookError, MessageHandler, RunBootstrap,
    RunnableHook, RunnableHookFactory, RuntimeReadiness, TurnObserver, WebhookSource,
    WorkspaceRollbackSink,
};
pub use materializer::ComponentMaterializer;
pub use output::write_result_to_dir;
pub use registry::{ComponentRegistry, ComponentRegistryRow, RegistryError};
pub use scheduler::{Scheduler, SchedulerStartError};
pub use submit::{InMemoryComponentSubmitApi, SubmitSubsetGate};
pub use tick_loop::run_scheduler_tick_loop;
pub use trigger_bus::{
    is_event_whitelisted, validate_subscription, CycleRejection, DispatchedEntry,
    SubscriptionRecord, TriggerBusDispatchImpl, VisitedSetState, DEFAULT_MAX_CHAIN_DEPTH,
    VISITED_SET_AGGREGATE_CAP, WHITELIST,
};
pub use trigger_emit::{emit_trigger_fired, TRIGGER_FIRED_EVENT_TYPE};
pub use trigger_source::{
    parse_schedule_string, resolve_trigger, AnyOfTriggerSource, FileWatchTriggerSource,
    ScheduleTriggerSource, TriggerEventSource, TriggerFireEvent, TriggerSource,
    WebhookTriggerSource,
};
pub use types::{
    format_rfc3339_ms, now_unix_ms, ComponentConfig, ComponentEvent, ComponentId, ComponentInfo,
    ComponentState, ComponentSubmitConfig, EventType, GrantDraft, RestartPolicy, RetryConfig,
    RunResult, RunStatus, SchedulerTick, SpawnError, SpawnedKind, SubscriptionId, TrapError,
    TriggerChainId, TriggerConfig, TriggerContext, TriggerFilter, TriggerSubscription,
    WasmInstance, WebhookConfig, MAX_AFFECTED_PATHS, MAX_ANY_OF, MAX_CAPABILITIES,
    MAX_CAPABILITY_ID_LEN, MAX_CHAIN_DEPTH_HARD_CAP, MAX_COMPONENT_ID_LEN, MAX_DEBOUNCE_MS,
    MAX_EVENT_TYPES, MAX_EVENT_TYPE_LEN, MAX_INITIAL_GRANTS, MAX_SUBSCRIPTIONS_PER_EVENT_TYPE,
    MAX_TOTAL_SUBSCRIPTIONS, MAX_TRIGGER_CHAIN_DEPTH, MAX_WIRE_BYTES_LEN, MAX_WIRE_STRING_LEN,
};
pub use webhook_hmac::{
    compute_signature_hex, verify_webhook, WebhookRejection, MIN_WEBHOOK_SECRET_BYTES,
    WEBHOOK_MAX_BODY_BYTES,
};
