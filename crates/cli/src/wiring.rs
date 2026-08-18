//! Production capability wiring for `advance start`.
//!
//! Slice AG (2026-05-11) shipped cap-grant + cap-secrets + EventBus.
//! Slice BS-1 (2026-06-01) extends [`wire_capabilities`] to register the
//! remaining capability providers and load a real master key:
//!   - **cap-fs / cap-skills / cap-memory / cap-grant agent-grant / cap-llm**
//!     host fns, each conditional on `.agent/config.yaml` declaring the
//!     capability active (the same [`yaml_declares_active_capability`] gate
//!     cap-secrets uses).
//!   - **cap-tools** host fns, registered *after* `builder.build()` because
//!     `LazyToolRegistry` needs the `ToolEngineHandle` that only exists once
//!     `ComponentRuntime` is constructed; visible to the already-built
//!     `CapabilityInjector` because `inject()` reads the shared `HostRegistry`
//!     lazily at inject time.
//!   - **Real master key**: `RuntimeConfig.secrets` → `cap_secrets::MasterKeyConfig`
//!     → [`cap_secrets::load_master_key`], replacing the Slice-AG
//!     `Zeroizing::new([0u8; 32])` placeholder. Loaded only when `secrets` or
//!     `llm` is declared (so the Slice-AG graceful-degradation contract —
//!     missing `.agent/config.yaml` → no key read — is preserved).
//!   - **cap-llm**: a real [`cap_llm::LlmGateway`] + cap-http security chain are
//!     constructed and (Slice BS-3) wired to the production
//!     [`cap_http::ReqwestHttpExecutor`]; the `NotWiredHttpExecutor` below remains
//!     only as a fail-closed fallback type. The `NotWired` budget/repetition stubs
//!     persist (unreachable on the BS-1 WIT path). agent-llm host fns are linked at
//!     L0; a full guest→generate→local-mock round-trip is waived_scope (cap-http
//!     SSRF loopback block). See MODULE-009 §3.7 (BS-3) + MODULE-012 §3.6.
//!
//! See MODULE-001 §2.7 / §3.6 for the wiring posture.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;

use advance_event_bus::{EventBus, EventBusConfig, EventBusError, ObservabilityReadApi};
use advance_messaging::{AgentIdBridge, DynamicRouting, MailboxStore};
use advance_run_manager::{RepetitionGuard, RepetitionGuardConfig, RunConfig, RunManager};
// await-leg B-2 (2026-06-22) — the production messaging-chain registration entry +
// the suspend-sink port type, consumed by the `declares_messaging` block below.
use advance_git::{DefaultGitCommitQueue, GitCommitQueue};
use advance_reply_tracker::{
    register_reply_tracker_host_fns_with_suspend_sink,
    register_send_host_fn_with_turn_reply_routing, AwaitSessionManagerImpl,
    ComponentResolutionSink, RunSuspendSink,
};
use advance_runtime::bootstrap::{BootstrapError, RuntimeHost, RuntimeHostBuilder};
use advance_runtime::config::{
    MasterKeySource, RunBudgetConfig, RuntimeConfigProvider, SecretsConfig,
};
use advance_scheduler::{InMemoryComponentSubmitApi, SubmitSubsetGate};
use advance_scheduler_auto_loop::DefaultAutoLoopDriver;
use advance_shared_types::agent_tree::{
    AgentId, AgentKind, AgentNode, AgentStatus, AgentTreeReader, AgentTreeSnapshot, Capability,
};
use advance_shared_types::await_session::AwaitSessionRef;
use advance_shared_types::capability::CapParams;
use advance_shared_types::repetition::{OutputHash, RepetitionDecision, ToolCallSignature};
use advance_shared_types::security_validator::{
    HttpRequest, HttpResponse, RedirectCheck, SsrfGuard,
};
use advance_shared_types::traits::{
    EventBusEmit, HttpStreamingChain, LeakDetector, RepetitionGuardCheck, RunBudget,
};
use cap_fs::{
    register_agent_fs, Adv003GitSync, DefaultAtomicWriter, DefaultVirtualPathResolver, GitSync,
    MetaSchemaLoader, StubFileHistoryProvider, VirtualPathResolver,
};
use cap_grant::{
    register_agent_grant, register_cap_grant, AgentGrantBundle, AutoDenyResolver,
    BudgetCheckResolver, CapGrantError, CapGrantHandles, ChannelApprovalDecision,
    ChannelApprovalError, ChannelApprovalPort, ChannelApprovalRequest, ChannelResolver,
    GrantApprovalIntake, GrantStore, ParentApprovalResolver, PresetRegistry, Resolver,
    ResolverChain, SubsetAutoApproveResolver, SubsetValidator, SubsetValidatorImpl,
};
use cap_http::{
    DefaultHttpSecurityChain, DefaultLeakDetector, DefaultPromptInjectionHelpers, ExecutorError,
    HttpExecutor,
};
use cap_lifecycle::{
    apply_auto_bootstrap, register_agent_component_submit, register_agent_decomposition,
    register_agent_spawn, AgentTreeStore, BootstrapEnsure, BootstrapEntry, BootstrapKind,
    BuiltinTemplateRegistry, CapGrantSubsetAdapter, ComponentSubmitGate, DefaultDecompositionStore,
    DefaultSpawner, SpawnError, SpawnObserver, Spawner, WorkspaceFileResidentPolicy,
};

use crate::component_submit_bridge::{CapGrantSubmitSubsetGate, SchedulerSubmitBridge};
use crate::perchild_daemon::{KeyResolver, PerChildLoopManager};
use crate::progress_lifecycle_activation::{
    activate_progress_lifecycle, ProgressLifecycleActivation,
};
use crate::progress_lifecycle_bootstrap::{
    bootstrap_progress_lifecycle, ProgressLifecycleBootstrapStaging,
};
use crate::reply::ReplyRegistry;
use cap_llm::{register_agent_llm_with_turn_cost, LlmGateway, LlmGatewayVlm, VlmExtractor};
use cap_memory::{
    register_agent_memory_with_git_and_policy, L6CursorStore, MemoryGitRestore, MemoryStore,
    PersistError, DEFAULT_MAX_ACTIVE_PER_AGENT,
};
use cap_secrets::{
    load_master_key, register_agent_secrets, register_agent_secrets_with_policy,
    CallerDependencyPolicy, DeclaredDependencyPolicy, DefaultEntryProvider, FileSecretStorage,
    MasterKeyConfig, SecretError, SecretStorage, SecretStore, DEFAULT_KEYCHAIN_ACCOUNT,
    DEFAULT_KEYCHAIN_SERVICE,
};
use cap_skills::provider::{SingleAgentSkillStoreProvider, SkillStoreProvider};
use cap_tools::{
    register_agent_tools_with_guard, LazyRegistryConfig, LazyToolRegistry, ToolRegistry,
};
use zeroize::Zeroizing;

/// Slice AG placeholder agent id. Future agent-loader slices (BS-2/BS-3) own
/// real agent identities. Shared by cap-grant's grantee, the cap-fs default
/// agent-tree root, the cap-skills single-agent provider, and cap-llm's
/// default agent id so the bootstrap surfaces a single coherent default agent.
const DEFAULT_AGENT_ID: &str = "default-agent";

/// Build the production supervised cap-grant resolver chain.
///
/// The production composition injects the live run budget before parent/channel
/// approval, so exhausted session runs deny at `BudgetCheck` instead of drifting
/// to the terminal `AutoDeny`. Parent approval currently has no backend in the
/// CLI path, so it abstains and leaves Channel as the next decision leg. Until an
/// operator-facing approval backend is wired, the default Channel port fails
/// closed with an explicit channel-approval-unavailable denial.
/// S4 (2026-07-29): install the live-streaming path on the production gateway.
///
/// Extracted so the composition itself is witnessable: `cli`'s composition-root
/// test asserts that the gateway this function returns reports
/// `has_live_streaming()`. Deleting the call (how both earlier S4 attempts were
/// withdrawn) is exactly what that test catches — with the WIT stream path now
/// live-ONLY, an unwired production gateway would fail every `stream()` call.
pub fn install_live_streaming(
    gateway: LlmGateway,
    streaming_chain: Arc<dyn HttpStreamingChain>,
    decoded_detector: Arc<dyn LeakDetector>,
) -> LlmGateway {
    gateway.with_live_streaming(streaming_chain, decoded_detector)
}

/// THE production LLM-gateway constructor (S4, 2026-07-29). The composition root
/// has no other path to a gateway, so a test that calls this with stub
/// collaborators witnesses the real wiring: deleting `install_live_streaming` here
/// fails that test, and deleting the CALL to this function fails to compile.
#[allow(clippy::too_many_arguments)]
pub fn build_llm_gateway(
    config: Arc<dyn RuntimeConfigProvider>,
    chain: Arc<dyn advance_shared_types::security_validator::HttpSecurityChain>,
    streaming_chain: Arc<dyn HttpStreamingChain>,
    decoded_detector: Arc<dyn LeakDetector>,
    budget: Arc<dyn RunBudget>,
    event_bus: Arc<dyn EventBusEmit>,
    repetition: Arc<dyn RepetitionGuardCheck>,
    default_agent_id: String,
    delta_sink: Arc<dyn advance_shared_types::traits::LlmDeltaSink>,
) -> Arc<LlmGateway> {
    Arc::new(install_live_streaming(
        LlmGateway::new(
            config,
            chain,
            budget,
            event_bus,
            repetition,
            default_agent_id,
        )
        .with_delta_sink(delta_sink),
        streaming_chain,
        decoded_detector,
    ))
}

pub fn build_grant_resolver_chain(
    validator: Arc<dyn SubsetValidator>,
    run_budget: Arc<dyn RunBudget>,
    channel_approval: Option<Arc<dyn ChannelApprovalPort>>,
) -> ResolverChain {
    let channel: Box<dyn Resolver> = match channel_approval {
        Some(port) => Box::new(ChannelResolver::with_approval_port(port)),
        None => Box::new(ChannelResolver::new()),
    };
    ResolverChain::new(vec![
        Box::new(SubsetAutoApproveResolver::new(validator)) as Box<dyn Resolver>,
        Box::new(BudgetCheckResolver::with_budget(run_budget)),
        Box::new(ParentApprovalResolver::new_abstain()),
        channel,
        Box::new(AutoDenyResolver::new()),
    ])
}

#[derive(Debug, Default)]
pub struct UnavailableChannelApprovalPort;

impl ChannelApprovalPort for UnavailableChannelApprovalPort {
    fn decision(&self, _request_id: &str) -> ChannelApprovalDecision {
        ChannelApprovalDecision::Pending
    }

    fn request_approval(
        &self,
        _request: ChannelApprovalRequest,
    ) -> Result<(), ChannelApprovalError> {
        Err(ChannelApprovalError::new(
            "CLI channel approval backend unavailable",
        ))
    }
}

pub fn default_channel_approval_port() -> Arc<dyn ChannelApprovalPort> {
    Arc::new(UnavailableChannelApprovalPort)
}

/// Build the production host-side operator approval intake (CONTRACT-123,
/// MODULE-013 AC-24). The returned `Arc` is injected BOTH as the resolver
/// chain's [`ChannelApprovalPort`] (so a parked `grant-decision::pending` routes
/// through it and the requester's retry observes the operator's
/// approve/deny/narrow) AND exposed via [`WiringHandles::grant_approval_intake`]
/// for the MODULE-020 console (and the same-Arc production-composition witness).
/// This replaces the fail-closed [`UnavailableChannelApprovalPort`] in the wired
/// chain; the Channel leg now parks pending (awaiting operator) — the
/// spec-intended supervised "Auto-try → human" flow.
pub fn build_grant_approval_intake(
    store: Arc<GrantStore>,
    validator: Arc<dyn SubsetValidator>,
    presets: Arc<PresetRegistry>,
    event_bus: Arc<dyn EventBusEmit>,
) -> Arc<GrantApprovalIntake> {
    Arc::new(GrantApprovalIntake::new(
        store, validator, presets, event_bus,
    ))
}

/// Preview-read byte cap for cap-fs `read` (truncates large file previews).
const FS_PREVIEW_MAX_BYTES: usize = 4096;

/// Per-`tool.wasm` size cap for the L2 skill-tool bridge (mirrors cap-skills'
/// `MAX_TOOL_WASM_BYTES`). A larger sidecar is skipped so one malformed/huge file
/// never bloats the boot registry.
const MAX_SKILL_TOOL_WASM_BYTES: u64 = 16 * 1024 * 1024;

/// Upper bound on `.agent/skills/` directory ENTRIES SCANNED at boot (and hence on
/// skill tools registered) — bounds the O(N) boot-time stat/read I/O over a
/// pathological skills dir (mirrors context_wiring's `MAX_VISIBLE_SKILLS`). Far above
/// any realistic active-skill count.
const MAX_SKILL_TOOLS: usize = 256;

/// Read a REGULAR file ≤ `max_bytes` as bytes, rejecting symlink / FIFO / dir /
/// socket / device / oversize via a `symlink_metadata` STAT-BEFORE-OPEN (lstat: does
/// NOT follow a symlink and does NOT open — so a planted symlink or named pipe at the
/// sidecar path is rejected without a symlink-follow or a blocking `open`, so boot
/// cannot hang). `None` on any hazard. Mirrors cli `context_wiring::read_regular_capped`
/// (the same disclosed residual: a host-side TOCTOU race-swap to a FIFO between the stat
/// and the open — the cap-skills out-of-scope host-compromise trust level).
fn read_regular_capped_bytes(path: &Path, max_bytes: u64) -> Option<Vec<u8>> {
    use std::io::Read;
    let meta = std::fs::symlink_metadata(path).ok()?;
    if !meta.file_type().is_file() || meta.len() > max_bytes {
        return None;
    }
    let file = std::fs::File::open(path).ok()?;
    let mut buf = Vec::new();
    file.take(max_bytes).read_to_end(&mut buf).ok()?;
    Some(buf)
}

/// Wave-14 (SYS-AC-080) — the L2 skill→tool-registry bridge.
///
/// Registers each materialized skill's `tool.wasm` sidecar into the production
/// [`LazyToolRegistry`] under the PRD §12.4.4 canonical id `skill::{name}`, so a
/// `tools`-declaring agent can invoke a skill-bundled tool at L2 through the wired
/// system. `skills_agent_root` is the cap-skills provider agent root (the same value
/// `wire_capabilities` block 5c computes as `workspace.join(".agent")`); the cap-skills
/// layout appends `.agent/skills` beneath it.
///
/// Uses a BOUNDED, symlink-safe directory walk of `<skills_agent_root>/.agent/skills/`
/// — NOT cap-skills `list_active`, whose `read_active` does unbounded `read_to_string`
/// on `SKILL.md`/`.meta.yaml` (a boot-liveness hazard the cli `DiskSkillSummaryReader`
/// already avoids for exactly this directory). Only real subdirectories (symlink-safe
/// `DirEntry::file_type`) are skill dirs; each `{name}/tool.wasm` is read via a
/// stat-before-open regular-file/size gate ([`read_regular_capped_bytes`]), so a
/// FIFO/device/oversized/symlinked sidecar — or a missing one (a skill with no
/// executable) — is skipped without a blocking read. `register_binary` is lazy
/// (validate/describe deferred to first invoke), so a malformed sidecar never blocks
/// boot; it surfaces as a `tool-error` at invoke time. Bounded at `MAX_SKILL_TOOLS`.
///
/// Boot-time scan over already-materialized skills (the shipped single-agent path; a
/// dynamic first-L2-reference miss-hook is future work, MODULE-017 §3.6 W14). Fail-soft:
/// an absent/unreadable skills dir → 0. Returns the number of skill tools registered.
pub async fn register_skill_tools(registry: &LazyToolRegistry, skills_agent_root: &Path) -> usize {
    let skills_root = skills_agent_root.join(".agent/skills");
    let entries = match std::fs::read_dir(&skills_root) {
        Ok(e) => e,
        // Absent / unreadable skills dir → nothing to register.
        Err(_) => return 0,
    };
    let mut registered = 0usize;
    for (visited, entry) in entries.flatten().enumerate() {
        // Hard bound on directory ENTRIES SCANNED (not just successful registrations):
        // a pathological `.agent/skills/` full of skipped entries (no `tool.wasm`,
        // non-regular, oversized) can't force an unbounded boot-time stat/read sweep.
        if visited >= MAX_SKILL_TOOLS {
            break;
        }
        // Only a real subdirectory is a skill dir. `DirEntry::file_type` does NOT follow
        // symlinks, so a symlink-to-dir planted as a skill entry is skipped.
        if !entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
            continue;
        }
        let Some(skill_id) = entry.file_name().to_str().map(str::to_string) else {
            continue; // non-UTF-8 dir name → not a valid skill id
        };
        // Parity with cap-skills' write-side name discipline (`security_scan::validate_skill_name`,
        // the `^[a-z0-9][a-z0-9_-]{0,63}$` gate EVERY skill-write path enforces): a dir whose name
        // escapes that regex could not have been produced through a validated materialize, so skip
        // it. Defense-in-depth, not a correctness fix — the id is only a registry HashMap key (never
        // a path) — but it keeps the `skill::{name}` namespace consistent with the rest of cap-skills.
        if cap_skills::security_scan::validate_skill_name(&skill_id).is_err() {
            continue;
        }
        // Stat-before-open bounded read of the sidecar: a missing / non-regular (FIFO /
        // device / dir) / symlinked / oversized `tool.wasm` is skipped without a read, so
        // boot can never hang or bloat. A skill carrying no executable simply has no file.
        let Some(bytes) =
            read_regular_capped_bytes(&entry.path().join("tool.wasm"), MAX_SKILL_TOOL_WASM_BYTES)
        else {
            continue;
        };
        registry
            .register_binary(format!("skill::{skill_id}"), bytes)
            .await;
        registered += 1;
    }
    registered
}

/// Errors from [`wire_capabilities`]. Encloses BootstrapError (re-emitted
/// from `RuntimeHostBuilder::build`), EventBusError, CapGrantError, the
/// master-key load failure (BS-1), and the agent-tree construction failure
/// (BS-1 cap-fs) so CLI callers can map each variant to the appropriate exit
/// code.
#[derive(Debug)]
pub enum CliWiringError {
    Bootstrap(BootstrapError),
    EventBus(EventBusError),
    CapGrant(CapGrantError),
    /// BS-1: master-key load failed (env var unset / not 64 hex chars /
    /// keychain error). Replaces the Slice-AG `[0u8; 32]` placeholder, which
    /// never failed.
    MasterKey(SecretError),
    /// CONTRACT-215/216 journal/factory bootstrap failed before EventBus or
    /// runtime visibility. The wrapped error is a fixed, non-sensitive code.
    ProgressLifecycle(&'static str),
    /// The single channel runtime could not be staged before joint activation.
    /// Carries the existing boot-validation diagnostic from channels_boot.
    ChannelRuntime(String),
    /// BS-1: cap-fs agent-tree construction failed (`AgentTreeStore::new` or
    /// `insert_root`).
    AgentTree(SpawnError),
    /// WS-A: opening the on-disk `FileSecretStorage`
    /// (`<ws>/.advance/secrets.json`) failed — unreadable / corrupt / unknown
    /// file version. Wrapped as `SecretError::Storage`.
    SecretStorage(SecretError),
    /// Backbone Step 3: opening the persistent `MemoryStore` rooted at
    /// `<ws>/.agent/memory` failed (unreadable / corrupt knowledge.jsonl line).
    /// Constructed in step 2c BEFORE the EventBus exists, so a failure leaks no
    /// background tasks (same fail-closed discipline as MasterKey/SecretStorage).
    MemoryStore(PersistError),
    /// Wave-7 Lane B (2026-06-22): the `channels.notify` auto-loop notify-sink
    /// install (`build_auto_loop_driver_with_channel_notify`) rejected the config
    /// (unsupported adapter / empty url-template / empty conversation_id). Fires
    /// AFTER the EventBus + cap-grant are constructed but BEFORE `builder.build()`,
    /// so the step-4b error path drops cap-grant (it holds bus clones) then shuts
    /// the EventBus down (no leaked actor tasks). Carries the already-formatted
    /// reason string.
    AutoNotify(String),
    /// Wave-22 (autoloop-integ): the `install_auto_loop_integration` augment
    /// (feeding the auto driver the real CostTrackerQuery + a ResultsWriter via
    /// `Arc::try_unwrap`) failed because the driver `Arc` was already shared —
    /// PROVABLY unreachable here (the augment runs before the round-advancer
    /// clone), but handled fail-CLOSED (drop cap-grant + shut the EventBus)
    /// rather than leaking the actor tasks. Carries the augment's reason string.
    AutoIntegration(String),
    /// Wave-17 Lane 3 (M005-AC-25): the config-declared child-agent hierarchy
    /// (`agents:` block of `.agent/config.yaml`) failed to parse / validate /
    /// materialize at boot. Fires in step 2b AFTER the tree root is inserted but
    /// BEFORE the EventBus exists, so a failure leaks no background tasks (same
    /// fail-closed discipline as AgentTree / MasterKey). Carries the already-formatted
    /// reason (the `AgentConfigError` / `BootstrapError` Display).
    ConfigTree(String),
}

impl std::fmt::Display for CliWiringError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CliWiringError::Bootstrap(e) => write!(f, "bootstrap failure: {e}"),
            CliWiringError::EventBus(e) => write!(f, "event-bus init failure: {e:?}"),
            CliWiringError::CapGrant(e) => write!(f, "cap-grant init failure: {e:?}"),
            CliWiringError::MasterKey(e) => write!(f, "master-key load failure: {e}"),
            CliWiringError::ProgressLifecycle(code) => {
                write!(f, "progress lifecycle bootstrap failure: {code}")
            }
            CliWiringError::ChannelRuntime(reason) => {
                write!(f, "channel runtime bootstrap failure: {reason}")
            }
            CliWiringError::AgentTree(e) => write!(f, "cap-fs agent-tree init failure: {e:?}"),
            CliWiringError::SecretStorage(e) => write!(f, "secret-store init failure: {e}"),
            CliWiringError::MemoryStore(e) => write!(f, "memory-store init failure: {e}"),
            CliWiringError::AutoNotify(m) => write!(f, "auto notify-channel wiring failure: {m}"),
            CliWiringError::AutoIntegration(m) => {
                write!(f, "auto-loop integration wiring failure: {m}")
            }
            CliWiringError::ConfigTree(m) => {
                write!(f, "agent-tree config materialization failure: {m}")
            }
        }
    }
}

impl std::error::Error for CliWiringError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            CliWiringError::Bootstrap(e) => Some(e),
            // EventBusError / CapGrantError / SpawnError do not (yet) implement
            // std::error::Error uniformly; surface the Display form in the
            // parent's message.
            CliWiringError::EventBus(_) => None,
            CliWiringError::CapGrant(_) => None,
            // SecretError implements std::error::Error (cap-secrets error.rs).
            CliWiringError::MasterKey(e) => Some(e),
            CliWiringError::ProgressLifecycle(_) => None,
            CliWiringError::ChannelRuntime(_) => None,
            CliWiringError::AgentTree(_) => None,
            CliWiringError::SecretStorage(e) => Some(e),
            // PersistError implements std::error::Error (cap-memory persistence.rs).
            CliWiringError::MemoryStore(e) => Some(e),
            // String-only reason (already formatted at the call site); no inner source.
            CliWiringError::AutoNotify(_) => None,
            CliWiringError::AutoIntegration(_) => None,
            // String-only reason (AgentConfigError / BootstrapError formatted at the
            // call site); no inner source.
            CliWiringError::ConfigTree(_) => None,
        }
    }
}

/// Aux handles produced by [`wire_capabilities`]. Held by the CLI's
/// `start::run` (or test callers) for the lifetime of the runtime;
/// holding `Arc<EventBus>` (concrete) in addition to
/// `Arc<dyn EventBusEmit>` reserves the option of pre-exit
/// `EventBus::shutdown(self).await` via `Arc::try_unwrap` (deferred
/// to a future lifecycle slice; Slice AG relies on process termination
/// for cleanup — see waived_scope).
///
/// All other provider state (the real `SecretStore`, the cap-fs resolver +
/// `AgentTreeStore`, the cap-memory store, the cap-llm gateway, the cap-tools
/// registry) is owned by the `HostFunctionSpec` handlers held inside the
/// `RuntimeHost`'s `HostRegistry`, so no extra handle fields are needed here.
pub struct WiringHandles {
    pub cap_grant: CapGrantHandles,
    /// Tee slice T3 (ADR 2026-07-22 D5): the turn-end reap handle over cap-llm's
    /// stream registry. `Some` whenever the LLM gateway was registered. `start.rs`
    /// composes it into BOTH turn-observer paths — the root fan-out and the
    /// per-child serve loop — or served child turns silently never reap.
    pub llm_stream_reaper: Option<Arc<cap_llm::AgentStreamReaper>>,
    /// Wave-23 `perchild-daemon-1` seam (d): the per-child serve-loop manager
    /// (attached as the spawner's observer). `Some` when messaging+tree are wired.
    /// `start.rs` binds its runtime post-build and drains its loops at shutdown.
    pub perchild_manager: Option<Arc<PerChildLoopManager>>,
    /// W24 `perchild-daemon-2` seam (f): the shared crash-cascade sink (built when
    /// messaging+tree are wired; resolves the crashing agent's parent dynamically).
    /// Each spawned child loop gets it via `PerChildLoopManager::with_crash_sink`;
    /// `start.rs` attaches it to the ROOT loop. `Some` iff `perchild_manager` is `Some`.
    pub crash_cascade_sink: Option<Arc<dyn advance_scheduler::hook::CrashCascadeSink>>,
    /// W24 seam (f): the per-agent circuit-breaker→mailbox-freeze subscriber over the
    /// shared messaging store (breaker-open freezes a served child's mailbox → pauses
    /// ingress; close unfreezes). Retained for the daemon lifetime — its `Drop` aborts
    /// the task. `Some` iff the messaging store is wired.
    pub breaker_subscriber: Option<advance_messaging::BreakerSubscriber>,
    /// m013-intake (AC-24): the host-side operator approval intake (CONTRACT-123),
    /// wired as the production Channel resolver's `ChannelApprovalPort`. `Some` iff
    /// `.agent/config.yaml` declares `grant` (same gate as the agent-grant WIT
    /// registration). MODULE-020's console drives its operator API
    /// (list_pending / approve / deny / narrow / revoke / apply_preset); a parked
    /// pending decision routes through it and the CONTRACT-120 retry observes the
    /// operator's decision. `None` when `grant` is not declared.
    pub grant_approval_intake: Option<Arc<GrantApprovalIntake>>,
    pub event_bus: Arc<EventBus>,
    pub event_bus_dyn: Arc<dyn EventBusEmit>,
    /// Slice m019-readapi (CONTRACT-185 / MODULE-019-AC-23): the host-side event
    /// READ surface (`ObservabilityReadApi`), derived from the SAME production
    /// `EventBus` registered here. `Some` for the production async bus; would be
    /// `None` only if the bus were synchronous. MODULE-020 (Wave-25) consumes this
    /// to project client-safe live/historical event views. Holds internal clones
    /// (pool/broadcaster/clock), NOT an `Arc<EventBus>`, so it does not perturb the
    /// `event_bus` refcount / shutdown path.
    pub observability_read_api: Option<Arc<dyn ObservabilityReadApi>>,
    /// CONTRACT-218 external-anchor/keyring/role custody. Held for the daemon
    /// lifetime so a second composition cannot acquire the same workspace.
    pub contract218_runtime: Option<crate::contract218_bootstrap::Contract218Runtime>,
    /// Durable, payload-free persisted identity sidecar used to authenticate
    /// public history reconstruction across daemon restarts.
    pub observation_carrier_store:
        Option<Arc<crate::observation_carriers::ObservationCarrierStore>>,
    /// CONTRACT-219 structured EventBus boundary, also shared by component
    /// submission so newly published sources become visible atomically.
    pub contract219_projector:
        Option<Arc<crate::observation_projection::Contract219EventProjector>>,
    /// Loopback-only public Client API + embedded Web Console. The server owns
    /// the exact C219 history/grant adapters and exposes its OS-selected address
    /// for local discovery and acceptance witnesses.
    pub client_api_server: Option<advance_client_api::ClientApiServer>,
    /// Slice BS-3: the cap-fs git commit-queue, held alive for the runtime
    /// lifetime (its `Drop` drains + closes the worker). `None` when the
    /// workspace is not a git repo (cap-fs registered without git_sync → degraded,
    /// no turn commits — same as pre-BS-3).
    pub git_queue: Option<Arc<DefaultGitCommitQueue>>,
    /// Phase-3 kickoff (2026-06-06): the live per-session `RunManager`, wired to
    /// the EventBus's `CostTracker` (`with_cost_tracker(bus.cost_tracker_query())`).
    /// Its `budget()` handle is already inside the cap-llm gateway; this handle is
    /// threaded into the agent loop so the session-run producer + per-turn
    /// `complete_round` run under the same manager. Held for the runtime lifetime.
    pub run_manager: Arc<RunManager>,
    /// Wave-24 `req270-sink`: the composition-root `AwaitSessionManagerImpl` (the
    /// messaging await manager, `Some` iff `declares_messaging`). Exposed so the
    /// composition-root witness (`cli/tests/run_completion_sink_wiring.rs`) can park
    /// a `ComponentFinished` await on the SAME manager the composed CONTRACT-184
    /// `RunCompletionSink` resolves, then drive `complete_run` over `run_manager` —
    /// an anti-fake-green witness that the sink is ATTACHED at the composition root
    /// (NOT a test-constructed `RunManager`).
    pub await_manager: Option<Arc<AwaitSessionManagerImpl>>,
    /// Stage-D (2026-06-19): the MODULE-015 auto-loop driver, shared with the
    /// RunManager's `RoundAdvancer` (as its `AutoStateReader`). `Some` iff the
    /// workspace is a git repo. Held so the Auto-mode start path
    /// (`auto_wiring::start_auto_session`) can `start` sessions + `register_run`;
    /// the harvest additionally registers it as a `SchedulerExtension` + drives
    /// the tick loop. `None` on a non-repo workspace (degraded — no auto mode).
    pub auto_loop_driver: Option<Arc<DefaultAutoLoopDriver>>,
    /// Phase-3 kickoff: the per-run budget caps (from `RuntimeConfig.run-budget`)
    /// the session run is minted with.
    pub run_config: RunConfig,
    /// Backbone Step 2 (2026-06-07): an Arc clone of the cap-llm `LlmGateway`
    /// (the SAME instance the `AgentLlmGenerateHandler` reads — its per-agent
    /// assembled-context store is shared across clones). `Some` iff `.agent/config.yaml`
    /// declares `llm`. The composition root uses it to build the
    /// `PublishingContextAssembler` seam so the assembled layered context feeds the
    /// guest's `generate`. `None` → no LLM, no seam (MinimalContextAssembler default).
    pub llm_gateway: Option<Arc<LlmGateway>>,
    /// Stage-C MAINLINE harvest pass-3 (2026-06-19): the REAL `cap_llm::LlmGatewayVlm`
    /// (Step-3 VLM/image description extractor), sharing the SAME `HttpSecurityChain` +
    /// `RuntimeConfigProvider` as `llm_gateway`. `Some` iff `.agent/config.yaml` declares
    /// `llm` (built alongside the gateway). The composition root threads it into
    /// `build_live_post_processor`, which installs the `VlmDescriptionIndexer` into the
    /// live post-processor's Step-3. `None` → no description indexing (the pre-pass-3
    /// trace-only Step-3 no-op). A non-Bearer provider degrades gracefully at call time.
    pub vlm_extractor: Option<Arc<dyn VlmExtractor>>,
    /// B1 backbone (2026-06-09, ADVERSARIAL-r7 fix): the SAME `Arc<MemoryStore>`
    /// registered for the WIT remember/recall/forget/recall-at handlers, shared
    /// with the context-assembler composition root so the real `KnowledgeMapReader`
    /// reads the SAME store — NOT a second `MemoryStore::open()` (which would
    /// re-hydrate the full active set into a second cache + open a second handle
    /// over the same dir). `Some` iff `.agent/config.yaml` declares `memory`.
    pub memory_store: Option<Arc<MemoryStore>>,
    /// Wave-20 notify production closure: the shared process mailbox store for
    /// messaging-declaring workspaces. `None` iff `messaging` is not declared.
    pub messaging_store: Option<Arc<MailboxStore>>,
    /// The one process reply registry shared by the dispatcher, serving loop,
    /// and POST listener. Constructed in the composition root even when C216 is
    /// inactive so the legacy no-messaging path remains available.
    pub reply_registry: Arc<ReplyRegistry>,
    /// The one configured channel runtime. It is staged before joint C215/C216
    /// activation so the typed progress renderer and legacy channel replies use
    /// the exact same HTTP egress allocation.
    pub channel_runtime: Option<Arc<crate::channels_boot::ChannelRuntime>>,
    /// Jointly activated C215/C216 graph. Kept as one private aggregate so all
    /// recovery/provider handles live for the daemon lifetime; sibling
    /// composition modules clone only its least-privilege consumer ports.
    pub(crate) progress_lifecycle: Option<ProgressLifecycleActivation>,
    /// Stage-C SAT-A: the populated `AgentTreeStore` snapshot (the SAME tree the
    /// cap-fs resolver uses), shared with the context-assembler so the live
    /// `# Available Delegates` section reflects the real tree instead of the
    /// hardcoded `EmptyAgentTree`. `Some` iff `.agent/config.yaml` declares `fs`
    /// (the SNAPSHOT is fs-gated; the shared `AgentTreeStore` itself is built for
    /// `declares_fs || declares_messaging`). 011 (Wave-11 Lane B): the spawn host-fns are
    /// now registered over this SAME tree (`register_agent_spawn`, the 5-spawn block
    /// below), so sub-agent spawns DO record `Sub` nodes here. Wave-12 BRIDGED the
    /// colon/bare keying — `assemble()` matches delegates against the agent-id alias
    /// set `[cap_agent_id (bare), msg_agent_id (colon)]`, so a real product-spawned
    /// Sub now surfaces by NAME (SYS-AC-011 stays DEFERRED only for the empty-caps
    /// WIT spawn cap-lift gap — the "with capability summaries" clause).
    pub agent_tree_snapshot: Option<Arc<dyn AgentTreeSnapshot>>,
    /// Wave-12 Lane C: the `DefaultDecompositionStore` (wrapping the SAME shared
    /// `AgentTreeStore`) the decomposition host-fns record into. `start.rs` wraps it
    /// in a `CapDecompositionReader` (with the agent's bare/colon alias set) and
    /// injects it into the assembler so the Tier-2 ⑭ "Active Task Decomposition"
    /// section reads the live decomposition state. `Some` iff the shared tree exists
    /// (`declares_fs || declares_messaging`, same gate as the spawn host-fns);
    /// `None` ⇒ `start.rs` uses `EmptyDecomposition` (no section). (Wave-23 lifted
    /// `"lifecycle"` into `KNOWN_CAPABILITIES` — the SPAWN host-fns are now live for a
    /// declaring guest; the decomposition host-fns remain unexercised by shipped guests.)
    pub decomposition_store: Option<Arc<DefaultDecompositionStore>>,
    /// Stage-C SAT-A: the cap-memory root dir (`<ws>/.agent/memory`, the dir the
    /// shared `MemoryStore` was opened at) — the base for the L2/L3/L4 history
    /// file readers (`{memory_root}/tasks/{task_id}/{turn-index,summary}.yaml`).
    /// `Some` iff `.agent/config.yaml` declares `memory` (mirrors `memory_store`'s
    /// capability gate, so a no-memory-cap agent never gets the history readers).
    pub memory_root: Option<PathBuf>,
    /// skills-J26 reader satellite (2026-06-20): the cap-skills provider root
    /// (`<ws>/.agent`) — the SAME value passed to the registered
    /// `SingleAgentSkillStoreProvider`, single-sourced so the context-assembler's
    /// `DiskSkillSummaryReader` (read path) and the `activate-skill` host-fn (write
    /// path) can never desync. `Some` iff `.agent/config.yaml` declares `skills`
    /// (the same `declares_skills` gate that registers the provider), so a
    /// no-skills-cap agent gets `None` → the assembler's `StubSkillSummary` → no
    /// `# Available Skills` section.
    pub skills_root: Option<PathBuf>,
    /// MODULE-017-AC-22: live skills turn runtime shared between the scheduler
    /// turn boundary and cap-skills host-fn handlers. `Some` iff skills are
    /// declared and the shared git queue exists.
    pub skill_turn_runtime: Option<Arc<cap_skills::SkillTurnRuntime>>,
    /// Wave-12 (SYS-AC-122): the process-global tool-path `RepetitionGuard`
    /// (concrete `Arc`, so the composition root can LATE-BIND the per-agent
    /// `ContextAssembler` via `set_context_assembler` once it is built — the
    /// guard is constructed at Step 7 BEFORE the per-agent assembler exists).
    /// `Some` iff `.agent/config.yaml` declares `tools` (the same `declares_tools`
    /// gate that registers cap-tools); `None` → no tool-path guard to late-bind.
    pub repetition_guard: Option<Arc<RepetitionGuard>>,
}

#[cfg(feature = "test-support")]
impl WiringHandles {
    /// Narrow production-composition witness seam: clone the already-published
    /// action dispatcher used by root and per-child serve loops.
    pub fn action_dispatcher_for_test(
        &self,
    ) -> Option<Arc<dyn advance_shared_types::mailbox::AgentActionDispatcher>> {
        self.progress_lifecycle
            .as_ref()
            .map(|activation| activation.action_dispatcher.clone())
    }

    /// Narrow production-composition witness seam: clone only the canonical
    /// C216 cost projection from the already-activated graph.
    pub fn turn_cost_attribution_for_test(
        &self,
    ) -> Option<Arc<dyn advance_shared_types::turn_attribution::TurnCostAttributionReadPort>> {
        self.progress_lifecycle
            .as_ref()
            .map(|activation| activation.cost_attribution.clone())
    }

    /// Narrow production-composition witness seam: clone only the scheduler's
    /// protected Store boundary; no issuer/verifier/publication authority leaks.
    pub fn protected_turn_boundary_for_test(
        &self,
    ) -> Option<Arc<dyn advance_scheduler::hook::ProtectedTurnExecutionBoundary>> {
        self.progress_lifecycle
            .as_ref()
            .map(|activation| activation.execution_boundary.clone())
    }
}

/// Phase-3 kickoff (2026-06-06): map the additive `RuntimeConfig.run-budget`
/// block (CONTRACT-003) into the run-manager's `RunConfig` budget caps. `pub`
/// so the `system-acceptance` `sys_budget_session_2turn` witness (and the cli
/// `budget_wiring` tests) can build the SAME `RunConfig` the production session
/// run uses. `None` caps → no limit.
pub fn run_config_from(cfg: &RunBudgetConfig) -> RunConfig {
    RunConfig {
        token_limit: cfg.default_token_limit,
        cost_usd_limit: cfg.default_cost_limit_usd,
        rounds_limit: cfg.default_rounds_limit,
        ..RunConfig::default()
    }
}

/// Production wiring entry point.
///
/// Order (BS-1):
/// 1. Snapshot `.agent/config.yaml` ONCE; derive the per-capability
///    active-gate booleans + `needs_key`.
/// 2. **Before** the EventBus exists (so failure leaks nothing): load the real
///    master key into a shared `Arc<SecretStore>` if `secrets`/`llm` is
///    declared; build the cap-fs agent-tree + resolver if `fs` is declared.
/// 3. EventBus production (4 actor tasks + axum HTTP server).
/// 4. cap-grant production (`register_cap_grant`).
/// 5. Register the pre-build providers (secrets / fs / skills / memory /
///    grant / llm) into `builder.host_registry()`, each behind its gate.
/// 6. `builder.build(grant_check)` — constructs the CapabilityInjector +
///    ComponentRuntime with the real `Arc<dyn GrantCheck>`.
/// 7. Register cap-tools into `host.host_registry()` (post-build — the
///    `ToolEngineHandle` only exists after step 6).
/// rollback-memory slice (2026-06-12): the production [`MemoryGitRestore`]
/// adapter — dispatches cap-memory's dependency-inverted git-restore seam
/// into MODULE-003 CONTRACT-021
/// ([`advance_git::DefaultWorkspaceRollback::rollback_memory_files_at`]).
/// Lives at the composition root so cap-memory keeps zero `advance-git`
/// compile-time edges (the same inversion posture as the scheduler's
/// `WasmRunnableHook`). Public: the system-acceptance harness wires the SAME
/// adapter over its own workspace repo.
pub struct GitMemoryRestore {
    pub inner: Arc<advance_git::DefaultWorkspaceRollback>,
}

impl MemoryGitRestore for GitMemoryRestore {
    fn restore_at(
        &self,
        agent_id: String,
        timestamp_rfc3339: String,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Vec<String>, String>> + Send + 'static>,
    > {
        let inner = Arc::clone(&self.inner);
        Box::pin(async move {
            // `agent:`-prefix duality at the seam boundary (the
            // CapGrantSubsetAdapter precedent): the WIT HostCallContext
            // carries the canonical `agent:<body>` id, but MODULE-003's
            // rollback surface validates agent_id against Git ref-name
            // grammar (colon-free, bare-id convention — `.agent/config.yaml`
            // names the bare body, root falls back to the `root` sentinel).
            let bare = agent_id.strip_prefix("agent:").unwrap_or(&agent_id);
            inner
                .rollback_memory_files_at(bare, &timestamp_rfc3339)
                .await
                .map(|paths| paths.into_iter().map(|p| p.display().to_string()).collect())
                // Adversarial-round F5 fix (2026-06-13): map every git-side
                // failure to a CLOSED set of invariant reason codes — no
                // Debug stringification (RollbackError's Debug carries host
                // absolute paths + unbounded internal detail, which must not
                // cross into the guest-visible WIT storage-error; the
                // ERROR_MESSAGE_ECHO_MAX / sanitize_audit_field discipline).
                // Full detail is logged host-side only.
                .map_err(|e| {
                    eprintln!("advance: rollback-memory git half failed for {bare}: {e:?}");
                    use advance_git::RollbackError as RE;
                    match e {
                        RE::NotFound { .. } => "git-restore:not-found",
                        RE::PermissionDenied { .. } => "git-restore:permission-denied",
                        RE::Libgit2 { .. } => "git-restore:libgit2",
                        RE::Io(_) => "git-restore:io",
                        RE::Checkpoint(_) => "git-restore:invalid-agent-id",
                        RE::InvalidTarget { .. } => "git-restore:invalid-target",
                    }
                    .to_string()
                })
        })
    }
}

/// Wave-17 Lane 3 (MODULE-005-AC-25): materialize the config-declared child-agent
/// hierarchy into `tree` at boot — BEFORE the EventBus exists and BEFORE any message
/// is processed — so a workspace that declares an `agents:` block boots with its root
/// + every declared child already present (each with a workspace territory + identity)
/// rather than only after a runtime `spawn-child`.
///
/// BFS over the declared tree: each node's DIRECT children become one
/// [`apply_auto_bootstrap`] batch under that node's alias as `parent_id` (the root's
/// children use `root_id`). Each decl's `alias` becomes the spawned child's `AgentId`,
/// so a grandchild names its parent by that alias. The spawner is a template-resolving
/// [`DefaultSpawner`] sharing `tree` (Clone shares the interior `Arc<RwLock<_>>`), so
/// spawned children land in the same store every downstream consumer reads (the cap-fs
/// resolver, the assembler's `# Available Delegates` snapshot, the messaging
/// dispatcher).
///
/// Idempotent: re-running over an already-materialized tree is a no-op (apply's
/// alias/path reuse path skips an existing same-template child). Fail-closed: any
/// spawn / template / path error aborts boot with [`CliWiringError::ConfigTree`].
///
/// Requires the agent-tree, which is built only when `fs` or `messaging` is declared
/// (the existing tree-construction gate); a config declaring `agents:` without
/// `fs`/`messaging` has no tree and materializes nothing.
pub fn materialize_config_tree(
    tree: &Arc<AgentTreeStore>,
    root_id: &AgentId,
    decls: &[crate::agent_config::AgentDecl],
) -> Result<(), CliWiringError> {
    if decls.is_empty() {
        return Ok(());
    }
    // One template-resolving spawner sharing THIS tree. Mirrors the
    // `register_agent_spawn` block's spawner construction so config-materialized
    // children are indistinguishable from runtime-spawned ones.
    let spawner = DefaultSpawner::with_template_resolver(
        (**tree).clone(),
        Arc::new(CapGrantSubsetAdapter::new()),
        Arc::new(BuiltinTemplateRegistry::new()),
    );
    let mut queue: std::collections::VecDeque<(AgentId, &[crate::agent_config::AgentDecl])> =
        std::collections::VecDeque::new();
    queue.push_back((root_id.clone(), decls));
    while let Some((parent_id, children)) = queue.pop_front() {
        let entries: Vec<BootstrapEntry> = children
            .iter()
            .map(|d| BootstrapEntry {
                template: d.template.clone(),
                kind: BootstrapKind::Child,
                target_path: d.target_path.clone(),
                alias: d.alias.clone(),
                ensure: BootstrapEnsure::Present,
            })
            .collect();
        let report = apply_auto_bootstrap(&entries, &parent_id, &spawner, tree)
            .map_err(|e| CliWiringError::ConfigTree(format!("{e}")))?;
        // apply_auto_bootstrap returns Ok (NOT Err) when an existing alias at the same
        // target-path declares a DIFFERENT template — it records that as a `conflicts`
        // entry. At a fresh boot the tree holds only the root so no decl can collide;
        // but to keep this materializer fail-closed for any future idempotent re-run
        // against an already-populated tree, surface a conflict as ConfigTree rather
        // than silently keeping the existing (template-mismatched) node.
        if !report.conflicts.is_empty() {
            return Err(CliWiringError::ConfigTree(format!(
                "config-declared agent conflicts with an existing tree node (template mismatch): {:?}",
                report.conflicts
            )));
        }
        for d in children {
            if !d.children.is_empty() {
                queue.push_back((AgentId(d.alias.clone()), &d.children));
            }
        }
    }
    Ok(())
}

pub async fn wire_capabilities(
    builder: RuntimeHostBuilder,
    workspace: &Path,
) -> Result<(RuntimeHost, WiringHandles), CliWiringError> {
    wire_capabilities_inner(builder, workspace, None, None).await
}

/// Test seam: inject a canonical HOME so progress-lifecycle bootstrap does not
/// share the process HOME (which races under `cargo test` parallelism and can
/// trip `progress-lifecycle-path-policy-rejected` on runner temp layouts).
#[cfg(feature = "test-support")]
#[doc(hidden)]
pub async fn wire_capabilities_with_home_for_test(
    builder: RuntimeHostBuilder,
    workspace: &Path,
    home: &Path,
) -> Result<(RuntimeHost, WiringHandles), CliWiringError> {
    wire_capabilities_inner(builder, workspace, None, Some(home)).await
}

/// Production-composition witness entry point.  It preserves the complete
/// `wire_capabilities` graph and substitutes only deterministic DNS plus the
/// external HTTP peer inside the channel security chain.
#[cfg(feature = "test-support")]
#[doc(hidden)]
pub async fn wire_capabilities_with_channel_security_for_test(
    builder: RuntimeHostBuilder,
    workspace: &Path,
    ssrf: Arc<dyn SsrfGuard>,
    executor: Arc<dyn HttpExecutor>,
) -> Result<(RuntimeHost, WiringHandles), CliWiringError> {
    wire_capabilities_inner(
        builder,
        workspace,
        Some(crate::channels_boot::ChannelSecurityTestOverride::new(
            ssrf, executor,
        )),
        None,
    )
    .await
}

async fn wire_capabilities_inner(
    builder: RuntimeHostBuilder,
    workspace: &Path,
    channel_security_override: Option<crate::channels_boot::ChannelSecurityTestOverride>,
    home_override: Option<&Path>,
) -> Result<(RuntimeHost, WiringHandles), CliWiringError> {
    // Step 1 — snapshot the agent config YAML ONCE.
    //
    // Audit-R1 (Slice AG) TOCTOU note: the snapshot lets the L0-active checks
    // here observe the SAME bytes. cap-grant's `register_cap_grant` still does
    // its OWN read via `compile_from_path`; that residual window is documented
    // in the Slice-AG history and is bounded by workspace 0o700 perms.
    let agent_config = workspace.join(".agent/config.yaml");
    // Read the agent config YAML ONCE via the shared helper (bounded 1 MiB read;
    // `None` on absent/oversize/unreadable → graceful degradation). The snapshot
    // lets the L0-active checks here observe the SAME bytes the agent-loop's
    // `agent_config::active_capabilities` uses (WS-A), so L0 registration and
    // guest-linker CapRequest injection cannot drift. (cap-grant's
    // `register_cap_grant` still does its OWN read via `compile_from_path`; that
    // residual window is documented in the Slice-AG history and bounded by the
    // workspace 0o700 perms.)
    let agent_yaml: Option<Vec<u8>> = crate::agent_config::read_agent_yaml(workspace);

    // Per-capability active gate. `None` yaml (no `.agent/config.yaml`) → every
    // capability inactive → graceful degradation (preserves Slice-AG T-AG-04).
    let yaml = agent_yaml.as_deref();
    let declares = |cap: &str| {
        yaml.map(|y| crate::agent_config::yaml_declares_active_capability(y, cap))
            .unwrap_or(false)
    };
    let declares_secrets = declares("secrets");
    let declares_fs = declares("fs");
    let declares_skills = declares("skills");
    let declares_memory = declares("memory");
    let declares_grant = declares("grant");
    let declares_llm = declares("llm");
    let declares_tools = declares("tools");
    // await-leg B-2 (2026-06-22): gate the production messaging chain (await-replies
    // + heartbeat host-fns + the suspend sink). await-leg B-4a (2026-06-22) flipped
    // `"messaging"` INTO `agent_config::KNOWN_CAPABILITIES`, so a `messaging`-declaring
    // agent now ALSO gets a `messaging` CapRequest injected (`start.rs` `caps =
    // active_capabilities(..)`) → the guest LINKS the interface and its `await-replies`
    // parks the Run via the suspend sink. DORMANT only for shipped agents (none declare
    // messaging). This `declares` gate (L0 registration) and `active_capabilities` (the
    // guest CapRequest) read the SAME config, so registration ↔ link stay symmetric.
    let declares_messaging = declares("messaging");
    // Wave-23 `perchild-daemon-1` seam (a): a `lifecycle`-declaring guest links
    // `spawn-child`; the agent tree + spawn host-fns must exist for it, and the
    // per-child daemon observer serves the spawned children.
    let declares_lifecycle = declares("lifecycle");
    // CONTRACT-215/216 uses the existing operator master-key path to derive its
    // journal-only integrity subkey. Messaging therefore needs the key even
    // when neither secrets nor llm is guest-visible.
    let needs_key = declares_secrets || declares_llm || declares_messaging || declares_lifecycle;

    // Step 2a — load the real master key and stage the complete C216→C215
    // journal/factory graph before EventBus, host registration, listeners, or
    // any other externally reachable runtime object exists.
    let mut master_key = if needs_key {
        Some(load_real_master_key(workspace, &builder.config().secrets)?)
    } else {
        None
    };
    let progress_lifecycle_staging: Option<ProgressLifecycleBootstrapStaging> =
        if declares_messaging {
            let key = master_key
                .as_ref()
                .expect("declares_messaging is included in needs_key");
            Some(
                match home_override {
                    Some(home) => {
                        crate::progress_lifecycle_bootstrap::bootstrap_progress_lifecycle_with_home(
                            &*key,
                            workspace,
                            Some(home),
                            None,
                        )
                    }
                    None => bootstrap_progress_lifecycle(&*key, workspace),
                }
                .map_err(|error| CliWiringError::ProgressLifecycle(error.code()))?,
            )
        } else {
            None
        };

    // cap-secrets/cap-llm consume the original operator key after the journal
    // has derived its purpose-separated subkey. A messaging-only boot does not
    // open the secret-value storage backend.
    let secret_store: Option<Arc<SecretStore>> = if declares_secrets || declares_llm {
        let key = master_key
            .take()
            .expect("secrets/llm declaration is included in needs_key");
        // WS-A: persistent on-disk backend so the daemon resolves provider keys
        // (provisioned via `advance secrets set` → `<ws>/.advance/secrets.json`)
        // at request time. Was `InMemorySecretStorage`, which started EMPTY every
        // boot, so a provider `api-key-secret` reference never resolved.
        let storage: Arc<dyn SecretStorage> = Arc::new(
            FileSecretStorage::open(workspace.join(".advance/secrets.json"))
                .map_err(|e| CliWiringError::SecretStorage(SecretError::from(e)))?,
        );
        Some(Arc::new(SecretStore::new(key, storage)))
    } else {
        drop(master_key.take());
        None
    };

    // Step 2b — cap-fs agent-tree + resolver + schema (before EventBus → the
    // fallible `AgentTreeStore::new`/`insert_root` leak nothing on failure).
    // A single `default-agent` root lets the resolver resolve the default
    // agent's territory. 011 (Wave-11 Lane B): the cap-lifecycle spawn host-fns
    // now SHARE this tree (the 5-spawn `register_agent_spawn` block below), so fs
    // resolves real spawned-agent territories as the tree grows.
    // Stage-C SAT-A: build the `AgentTreeStore` as an `Arc` FIRST, then clone it
    // into BOTH the cap-fs resolver AND `agent_tree_snapshot` (exposed via
    // `WiringHandles` for the context-assembler's `# Available Delegates`
    // section). `AgentTreeStore` impls `AgentTreeSnapshot` and uses interior
    // mutability (so `insert_root` takes `&self`).
    // await-leg B-2 (2026-06-22): hoist the single `default-agent`-root
    // `AgentTreeStore` so it is built when EITHER cap-fs OR messaging is declared —
    // the messaging dispatcher (`MailboxDispatcherImpl`) needs an `AgentTreeReader`,
    // and reusing ONE tree keeps the agent hierarchy single-sourced. PRE-EventBus,
    // so a failure leaks nothing (same discipline as the cap-fs block below, whose
    // tree-construction this replaces). The cap-fs resolver + `agent_tree_snapshot`
    // stay gated on `declares_fs`; a messaging-only (no-fs) agent gets the tree (for
    // the dispatcher) but NO resolver/snapshot — `# Available Delegates` behavior
    // unchanged for fs agents, absent for non-fs agents exactly as before.
    let agent_tree: Option<Arc<AgentTreeStore>> =
        if declares_fs || declares_messaging || declares_lifecycle {
            let tree = Arc::new(
                AgentTreeStore::new(workspace.to_path_buf()).map_err(CliWiringError::AgentTree)?,
            );
            // Wave-23 seam (a): seed the root node's capabilities from the root's
            // ACTIVE declared caps (whole-capability, `CapParams::empty()`), so the
            // spawn subset gate (`spawn_child` checks child caps ⊆ parent node caps)
            // admits a child requesting any cap the root holds — e.g. a `messaging`
            // child. Was `Vec::new()`, which rejected every non-empty child request.
            let root_caps: Vec<Capability> = crate::agent_config::active_capabilities(yaml)
                .into_iter()
                .map(|r| Capability {
                    id: r.capability,
                    params: CapParams::empty(),
                })
                .collect();
            tree.insert_root(AgentNode {
                id: AgentId(DEFAULT_AGENT_ID.to_string()),
                kind: AgentKind::Root,
                parent: None,
                workspace_path: workspace.to_path_buf(),
                capabilities: root_caps,
                template_ref: None,
                status: AgentStatus::Active,
            })
            .map_err(CliWiringError::AgentTree)?;
            Some(tree)
        } else {
            None
        };

    // Wave-17 Lane 3 (M005-AC-25): materialize config-declared child agents into the
    // freshly-rooted tree — BEFORE the EventBus / any message. `parse_agents_config`
    // reuses the `yaml` snapshot read above (no second disk read, no TOCTOU window).
    // No `agents:` block ⇒ empty ⇒ no-op (root-only boot byte-identical). Fail-closed
    // on a malformed / over-budget declared hierarchy. Gated on the tree existing
    // (`declares_fs || declares_messaging`): a config without fs/messaging has no tree
    // and so declares no materializable territory.
    if let Some(tree) = agent_tree.as_ref() {
        let decls = crate::agent_config::parse_agents_config(yaml)
            .map_err(|e| CliWiringError::ConfigTree(format!("{e}")))?;
        materialize_config_tree(tree, &AgentId(DEFAULT_AGENT_ID.to_string()), &decls)?;
    }

    let mut agent_tree_snapshot: Option<Arc<dyn AgentTreeSnapshot>> = None;
    let fs_handles: Option<(Arc<dyn VirtualPathResolver>, Arc<MetaSchemaLoader>)> = if declares_fs {
        let tree = agent_tree
            .clone()
            .expect("declares_fs ⇒ agent_tree built (declares_fs || declares_messaging)");
        let snapshot: Arc<dyn AgentTreeSnapshot> = tree.clone();
        agent_tree_snapshot = Some(snapshot);
        let resolver: Arc<dyn VirtualPathResolver> = Arc::new(DefaultVirtualPathResolver::new(
            workspace.to_path_buf(),
            tree,
        ));
        let schema = Arc::new(MetaSchemaLoader::new_with_default(
            workspace.join(".agent/meta-schema.yaml"),
        ));
        Some((resolver, schema))
    } else {
        None
    };

    // Step 2c (Backbone Step 3) — open the PERSISTENT cap-memory store rooted at
    // `<ws>/.agent/memory` (before the EventBus exists → a PersistError leaks no
    // bus tasks, same fail-closed discipline as step 2a/2b). `KnowledgeJsonlStore`
    // (inside `open`) `create_dir_all`s the root (umask-honoring) and re-asserts
    // each per-agent subdir to 0700 (the `.agent` parent + workspace already enforce
    // 0o700 per the Slice-AG trust boundary, and per-agent jsonl files are 0600), so
    // the dir is created safely and coexists with cap-skills' `<ws>/.agent` (distinct
    // subpath). The
    // opened store is registered into the host registry in step 5d below; it is
    // the SAME store the WIT remember/recall/forget/recall-at handlers read+write,
    // so production memory now persists across restarts (MODULE-011-AC-39).
    let memory_store: Option<Arc<MemoryStore>> = if declares_memory {
        Some(Arc::new(
            MemoryStore::open(
                workspace.join(".agent/memory"),
                DEFAULT_MAX_ACTIVE_PER_AGENT,
            )
            .map_err(CliWiringError::MemoryStore)?,
        ))
    } else {
        None
    };

    // Stage-C SAT-A: the cap-memory root dir — the base for the L2/L3/L4 history
    // file readers. Gated on `declares_memory` (same gate as `memory_store`), so a
    // no-memory-cap agent never gets a `memory_root` → no history readers reach
    // its prompt.
    let memory_root: Option<PathBuf> = if declares_memory {
        Some(workspace.join(".agent/memory"))
    } else {
        None
    };

    // CONTRACT-217 production submission opens the exact durable registry
    // before EventBus startup. The shared mutable source is seeded from that
    // registry and updated after each successful submission, so declarations
    // become visible to redaction without a daemon restart.
    let component_registry = if declares_lifecycle {
        Some(
            crate::sensitive_params::open_component_registry(workspace)
                .await
                .map_err(CliWiringError::ConfigTree)?,
        )
    } else {
        None
    };
    let sensitive_params_source = match component_registry.as_ref() {
        Some(registry) => Arc::new(
            crate::sensitive_params::RegistrySensitiveParamsSource::from_registry(registry)
                .await
                .map_err(|error| {
                    CliWiringError::ConfigTree(format!(
                        "read component sensitive declarations: {error}"
                    ))
                })?,
        ),
        None => crate::sensitive_params::build_sensitive_params_source(workspace).await,
    };

    let contract218_runtime = match component_registry.as_ref() {
        Some(registry) => Some(
            crate::contract218_bootstrap::bootstrap_contract218(workspace, Arc::clone(registry))
                .await
                .map_err(CliWiringError::ConfigTree)?,
        ),
        None => None,
    };
    let observation_carrier_store = match contract218_runtime.as_ref() {
        Some(_) => Some(Arc::new(
            crate::observation_carriers::ObservationCarrierStore::open(workspace)
                .map_err(CliWiringError::ConfigTree)?,
        )),
        None => None,
    };
    let contract219_projector = match contract218_runtime.as_ref() {
        Some(runtime) => {
            let projector = crate::observation_projection::Contract219EventProjector::build(
                Arc::clone(&runtime.provider),
                Arc::clone(&runtime.ready_issuer),
                runtime.boot_id,
                Arc::clone(
                    observation_carrier_store
                        .as_ref()
                        .expect("C218 composition creates a carrier store"),
                ),
            )
            .await
            .map_err(CliWiringError::ConfigTree)?;
            projector
                .register_agent(DEFAULT_AGENT_ID)
                .await
                .map_err(CliWiringError::ConfigTree)?;
            Some(projector)
        }
        None => None,
    };

    // Step 3 — EventBus production.
    let event_jsonl_dir = workspace.join(".runtime/events/jsonl");
    let event_db_path = workspace.join(".runtime/events.db");
    let mut event_cfg = EventBusConfig::new(event_jsonl_dir, event_db_path);
    // PRD §15.3.18 default 8081 + operator port discovery deferred to a future
    // MODULE-019 wiring slice; OS-assigned port for both prod and tests here.
    event_cfg.websocket_addr = "127.0.0.1:0".parse().expect("hard-coded literal");
    let public_leak_detector: Arc<dyn LeakDetector> = Arc::new(DefaultLeakDetector::new());
    event_cfg.leak_detector = Some(Arc::clone(&public_leak_detector));
    // CONTRACT-217 activation: this source is seeded from durable declarations
    // and dynamically updated by the scheduler bridge after admission.
    event_cfg.sensitive_params_source = Some(sensitive_params_source.clone());
    event_cfg.observation_projector = contract219_projector
        .as_ref()
        .map(|projector| Arc::clone(projector) as Arc<dyn advance_event_bus::ObservationProjector>);
    let client_event_retention_days = event_cfg.jsonl_retention_days;
    let bus = EventBus::new(event_cfg)
        .await
        .map_err(CliWiringError::EventBus)?;
    let bus_concrete: Arc<EventBus> = Arc::new(bus);
    let event_bus_dyn: Arc<dyn EventBusEmit> = bus_concrete.clone();
    // Slice m019-readapi (CONTRACT-185): derive the host-side read surface from the
    // SAME wired bus. `read_api()` returns a handle over internal clones (pool /
    // broadcaster / clock), NOT an `Arc<EventBus>`, so it does not add a strong ref
    // to `bus_concrete` and the error-path `Arc::try_unwrap(bus_concrete)` below is
    // unaffected. `Some` for the production async bus.
    let observability_read_api = bus_concrete.read_api();

    // Step 4 — cap-grant production. On failure, shut down the EventBus so we
    // don't leak its background tasks.
    let agent_config_arg: Option<&Path> = if agent_yaml.is_some() {
        Some(agent_config.as_path())
    } else {
        None
    };
    let cap_grant = match register_cap_grant(
        builder.sqlite_index_handle(),
        event_bus_dyn.clone(),
        agent_config_arg,
        DEFAULT_AGENT_ID.to_string(),
        Some(Duration::from_secs(60)), // sweeper tick
    ) {
        Ok(h) => h,
        Err(e) => {
            shutdown_event_bus_on_error(bus_concrete, event_bus_dyn).await;
            return Err(CliWiringError::CapGrant(e));
        }
    };

    // Step 4b (Phase-3 kickoff) — construct the live per-session RunManager,
    // wired to the EventBus's baked-in CostTracker so the cost gate reads the
    // accrued per-run cost (CONTRACT-181). Constructed AFTER register_cap_grant
    // so the cap-grant error path above holds no live `run_manager` clone; only
    // the later `builder.build()` error path drops it (it holds an
    // `event_bus_dyn` clone that would otherwise block `Arc::try_unwrap`).
    // Stage-D (2026-06-19) — build the MODULE-015 auto-loop driver (Some iff the
    // workspace is a git repo; auto-mode needs per-iteration git checkpoints,
    // degrading like git_sync otherwise) and thread its CONTRACT-141
    // RoundAdvancer into the RunManager so a `auto:{agent-id}` complete_round
    // routes to the auto advancer (run.rs is_auto_mode gate). The driver holds
    // EventBus sink clones, so it joins the builder.build() error-path drop list
    // below (alongside run_manager) to keep the EventBus shutdown's
    // `Arc::try_unwrap(bus_concrete)` unblocked. Wave-7 Lane B (2026-06-22) wires
    // the production scheduler tick-loop (`advance_scheduler::run_scheduler_tick_loop`
    // + `register_extension`, in `start.rs`); the Auto-mode start SUBCOMMAND that
    // populates the tick caller's session registry remains a harvest install point.
    //
    // SYS-AC-257: when `channels.notify` is configured, install the cap-channel
    // `CapChannelNotifySink` (→ `channel.raw_sent` on degrade/halt) IN PLACE OF the
    // `EventBusNotifySink` default — and it MUST happen HERE, BEFORE the driver is
    // cloned into the round-advancer below, because `install_notify_sink`'s
    // `Arc::try_unwrap` augment-before-share contract rejects an already-shared Arc.
    // The transport is a DEDICATED event-bus-wired `HttpEgress` (the daemon's
    // `ChannelRuntime` is built later in `start.rs`, after this clone — so
    // `cr.transport` is unavailable here; the notify sink is self-contained with its
    // own standalone subscription — MODULE-016 §3.8). On a notify-config `Err`, fail
    // CLOSED: drop `cap_grant` (it holds `event_bus_dyn` clones via its GrantStore +
    // sweeper) THEN shut the EventBus down, mirroring the `builder.build()` error-path
    // drop sequence — else `Arc::try_unwrap(bus_concrete)` fails and the 4 actor tasks
    // + axum server leak. `run_manager`/`auto_loop_driver`/`registry` are not yet
    // built at this point, so cap_grant + the bus are the only live bus-clone holders.
    let runtime_config = builder.config();
    let auto_loop_driver = match runtime_config.channels.notify.as_ref() {
        Some(notify) => {
            // Pass the dedicated transport BY MOVE so its two `event_bus_dyn` clones
            // (chain + egress) are released inside the call on an early `Err`.
            // AC-17: thread the live `security.*` source so the notify egress
            // chain hot-reloads its leak/SSRF/rate tunables + executor DNS timeout
            // (matches the LLM + channel egress chains — no production HTTP chain
            // left on defaults).
            let notify_transport = crate::channels_boot::build_egress_transport_with_security(
                event_bus_dyn.clone(),
                Some(builder.config_watcher() as Arc<dyn RuntimeConfigProvider>),
            );
            match crate::auto_wiring::build_auto_loop_driver_with_channel_notify(
                workspace,
                event_bus_dyn.clone(),
                notify_transport,
                crate::commands::start::DEFAULT_MSG_AGENT_ID,
                notify,
            ) {
                Ok(driver) => driver,
                Err(e) => {
                    drop(cap_grant);
                    shutdown_event_bus_on_error(bus_concrete, event_bus_dyn).await;
                    return Err(CliWiringError::AutoNotify(e));
                }
            }
        }
        None => crate::auto_wiring::build_auto_loop_driver(workspace, event_bus_dyn.clone()),
    };
    // Wave-22 (autoloop-integ): feed the freshly-built auto driver the REAL
    // CostTrackerQuery + a ResultsWriter (production `build_auto_loop_driver`
    // wires NEITHER) via the augment-before-share `Arc::try_unwrap` augment. The
    // driver `Arc` is provably UNIQUE here — nothing clones `auto_loop_driver`
    // between its fresh bind above and its FIRST clone (the round-advancer
    // `auto_loop_driver.clone()` in the `run_manager` build below) — so `try_unwrap`
    // always succeeds; the Err arm is fail-CLOSED (drop cap_grant which holds bus
    // clones, THEN shut the EventBus) rather than leaking the 4 actor tasks + axum
    // server. `bus_concrete.cost_tracker_query()` clones an internal Arc (the same
    // one RunManager consumes below), so calling it here + at the RunManager build
    // is fine.
    let auto_loop_driver = match auto_loop_driver {
        Some(driver) => match crate::auto_wiring::install_auto_loop_integration(
            driver,
            bus_concrete.cost_tracker_query(),
            workspace,
        ) {
            Ok(driver) => Some(driver),
            Err(e) => {
                drop(cap_grant);
                shutdown_event_bus_on_error(bus_concrete, event_bus_dyn).await;
                return Err(CliWiringError::AutoIntegration(e));
            }
        },
        None => None,
    };
    // Stage the one reply registry and one channel runtime at the composition
    // root. The channel runtime must exist before joint activation so C215's
    // typed renderer and legacy channel replies share its exact HttpEgress.
    let reply_registry = Arc::new(ReplyRegistry::new());
    let channel_runtime_result = match channel_security_override {
        #[cfg(feature = "test-support")]
        Some(overrides) => {
            crate::channels_boot::build_channel_runtime_with_security_override_for_test(
                runtime_config.as_ref(),
                crate::commands::start::DEFAULT_MSG_AGENT_ID,
                event_bus_dyn.clone(),
                builder.config_watcher(),
                overrides,
            )
        }
        #[cfg(not(feature = "test-support"))]
        Some(_) => unreachable!("channel security override is test-support only"),
        None => crate::channels_boot::build_channel_runtime_with_config(
            runtime_config.as_ref(),
            crate::commands::start::DEFAULT_MSG_AGENT_ID,
            event_bus_dyn.clone(),
            builder.config_watcher(),
        ),
    };
    let channel_runtime = match channel_runtime_result {
        Ok(runtime) => runtime.map(Arc::new),
        Err(reason) => {
            drop(auto_loop_driver);
            drop(cap_grant);
            shutdown_event_bus_on_error(bus_concrete, event_bus_dyn).await;
            return Err(CliWiringError::ChannelRuntime(reason));
        }
    };

    // Wave-23 seam (e): one bridge + DynamicRouting allocation is shared by
    // protected await dispatch, send/notify, and every per-child loop.
    let (perchild_bridge, perchild_routing): (
        Option<Arc<AgentIdBridge>>,
        Option<Arc<DynamicRouting>>,
    ) = if declares_messaging {
        let bare_tree: Arc<dyn AgentTreeReader> = agent_tree
            .clone()
            .expect("declares_messaging ⇒ agent_tree built (declares_fs || declares_messaging)");
        let bridge = Arc::new(AgentIdBridge::from_pairs([(
            crate::commands::start::DEFAULT_MSG_AGENT_ID.to_string(),
            DEFAULT_AGENT_ID.to_string(),
        )]));
        let routing = Arc::new(DynamicRouting::new(bare_tree));
        routing.seed_root(crate::commands::start::DEFAULT_MSG_AGENT_ID);
        (Some(bridge), Some(routing))
    } else {
        (None, None)
    };

    // Consume the pre-EventBus factories exactly once. Nothing becomes
    // listener/runtime-visible until every C215+C216 provider injection has
    // succeeded and the move-only joint publication authority is consumed as
    // activation's final operation.
    let progress_lifecycle = if declares_messaging {
        let staging = progress_lifecycle_staging
            .expect("declares_messaging stages exactly one progress lifecycle graph");
        let progress_egress = channel_runtime
            .as_ref()
            .map(|runtime| runtime.progress_egress.clone())
            .unwrap_or_else(|| {
                crate::channels_boot::build_progress_egress_with_security(
                    event_bus_dyn.clone(),
                    Some(builder.config_watcher() as Arc<dyn RuntimeConfigProvider>),
                )
            });
        match activate_progress_lifecycle(
            staging,
            progress_egress,
            channel_runtime.as_deref(),
            reply_registry.clone(),
            perchild_bridge
                .as_ref()
                .expect("messaging bridge staged before activation")
                .clone(),
            event_bus_dyn.clone(),
            runtime_config.security.action_validator.max_message_size,
            None,
        ) {
            Ok(activation) => Some(activation),
            Err(error) => {
                drop(channel_runtime);
                drop(auto_loop_driver);
                drop(cap_grant);
                shutdown_event_bus_on_error(bus_concrete, event_bus_dyn).await;
                return Err(CliWiringError::ProgressLifecycle(error.code()));
            }
        }
    } else {
        debug_assert!(progress_lifecycle_staging.is_none());
        None
    };
    let messaging_store = progress_lifecycle
        .as_ref()
        .map(|activation| activation.mailbox_store.clone());

    // Build the await manager only after protected MailboxStore activation.
    // `build_await_messaging_chain` installs its concrete dispatcher as the
    // TurnMailboxDispatchPort, so fan-out uses the same C216 registry/store.
    let (await_manager, await_session_ref, await_dispatcher): (
        Option<Arc<AwaitSessionManagerImpl>>,
        Option<Arc<dyn AwaitSessionRef>>,
        Option<Arc<advance_messaging::MailboxDispatcherImpl>>,
    ) = if declares_messaging {
        let arm_snapshot: Arc<dyn AgentTreeSnapshot> = agent_tree
            .clone()
            .expect("declares_messaging ⇒ agent_tree built");
        let (manager, aref, dispatcher) = crate::await_wiring::build_await_messaging_chain(
            messaging_store
                .as_ref()
                .expect("joint activation yields protected mailbox store")
                .clone(),
            perchild_routing
                .as_ref()
                .expect("messaging routing staged before activation")
                .clone() as Arc<dyn AgentTreeReader>,
            event_bus_dyn.clone(),
            perchild_bridge.clone(),
            Some(arm_snapshot),
        );
        (Some(manager), Some(aref), Some(dispatcher))
    } else {
        (None, None, None)
    };

    let run_manager = {
        let mut rm = RunManager::new(event_bus_dyn.clone())
            .with_cost_tracker(bus_concrete.cost_tracker_query());
        if let Some(driver) = auto_loop_driver.clone() {
            rm = rm.with_round_advancer(crate::auto_wiring::build_auto_round_advancer(driver));
        }
        // await-leg B-2: prod parity for pause/cancel-while-suspended — without the
        // ref, those ops on a Suspended run return
        // PermissionDenied("await-session-ref-not-configured").
        if let Some(aref) = await_session_ref {
            rm = rm.with_await_session_ref(aref);
        }
        if let Some(tree) = agent_tree.as_ref() {
            let snapshot: Arc<dyn AgentTreeSnapshot> = tree.clone();
            rm = rm.with_agent_tree(snapshot);
        }
        // Wave-24 `req270-sink`: compose CONTRACT-184 `RunCompletionSink` at the
        // composition root, gated on messaging (`await_manager` Some). MODULE-008
        // `complete_run` fires the sink on `run.completed`; the MODULE-007
        // `ComponentResolutionSink` resolves the matching `ComponentFinished` await
        // slot status-only. Borrow (`as_ref`) — `await_manager` survives to the
        // step-5 host-fn registration below. HONEST scope: no reachable production
        // driver produces a colon-free component `task_id` yet (a submitted
        // component creates no run; auto-settle's colon `task_id` is short-circuited
        // in the sink), so REQ-270 stays Partial — this composes the sink for a
        // future component-completion driver lane (MODULE-007 §3.6:1099/:1100).
        if let Some(mgr) = await_manager.as_ref() {
            rm = rm
                .with_run_completion_sink(Arc::new(ComponentResolutionSink::new(Arc::clone(mgr))));
        }
        Arc::new(rm)
    };
    let run_config = run_config_from(&builder.config().run_budget);

    // Step 5 — register the pre-build providers into the builder's registry.
    // Each is gated on `.agent/config.yaml` declaring the capability active.
    // None of these calls are fallible (the fallible fs setup ran in step 2b),
    // so no EventBus-shutdown error path is needed in this block.
    let registry = builder.host_registry();

    // 5-spawn — 011 (Wave-11 Lane B, 2026-06-23): register the cap-lifecycle spawn
    // host-fns over the SHARED `agent_tree` so a sub-agent spawn records a `Sub`
    // node into the SAME `AgentTreeStore` consumed downstream. Gated on the tree
    // EXISTING (`declares_fs || declares_messaging`) — recording into the tree keeps
    // it accurate for ALL its consumers: the fs path's `agent_tree_snapshot` (the
    // assembler's `# Available Delegates`, set only under `declares_fs` above) AND the
    // messaging dispatcher's `AgentTreeReader`. For a messaging-ONLY agent the snapshot
    // is `None`, so the registration is dormant-over-the-dispatcher-tree (harmless).
    // `with_template_resolver` (NOT `::new`) so `spawn-agent-from-template` resolves the
    // runtime builtins instead of failing `InvalidConfig` (no-resolver); spawn-sub /
    // spawn-child (`template_ref: None`) bypass the resolver. The full
    // `register_agent_lifecycle` bundle (terminate / checkpoint / rollback / submit) +
    // the pack-tier resolver are mainline. Wave-23 lifted `"lifecycle"` INTO
    // `agent_config::KNOWN_CAPABILITIES`, so a declaring guest links the interface AND
    // the `PerChildLoopManager` observer (attached below) makes the spawned child a
    // LIVE served agent; the build-lane witness (`crates/cli/tests/spawn_wiring_011.rs`)
    // still drives the registered handler directly.
    // Wave-12 Lane C: the decomposition store shares the SAME `AgentTreeStore` (it
    // wraps it), so the assembler's `CapDecompositionReader` reads exactly what the
    // decomposition host-fns record. Declared here so the `WiringHandles`
    // construction below can expose it; assigned inside the same `agent_tree.is_some()`
    // gate as spawn (`declares_fs || declares_messaging`).
    let mut decomposition_store: Option<Arc<DefaultDecompositionStore>> = None;
    // Wave-23 seam (d): retained so `WiringHandles` can expose it (post-build
    // runtime binding + shutdown drain).
    let mut perchild_manager: Option<Arc<PerChildLoopManager>> = None;
    // W24 seam (f): the shared crash-cascade sink, retained so `WiringHandles` can
    // attach it to the ROOT loop in `start.rs` (each spawned CHILD loop already gets
    // it via `PerChildLoopManager::with_crash_sink`).
    let mut perchild_crash_sink: Option<Arc<dyn advance_scheduler::hook::CrashCascadeSink>> = None;

    // CONTRACT-217/041 atomic cutover: only the canonical v0.2 namespace is
    // registered. The real scheduler owns admission, quota, subset validation,
    // and durable ComponentRegistry persistence; the bridge owns only the WIT
    // shape conversion plus post-commit declaration publication.
    if let Some(component_registry) = component_registry.as_ref() {
        let subset_gate: Arc<dyn SubmitSubsetGate> =
            Arc::new(CapGrantSubmitSubsetGate::new(Arc::clone(&cap_grant.store)));
        let api = Arc::new(
            match contract218_runtime.as_ref() {
                Some(runtime) => InMemoryComponentSubmitApi::new().with_observation_provider(
                    Arc::clone(&runtime.provider),
                    Arc::clone(&runtime.ready_issuer),
                ),
                None => {
                    InMemoryComponentSubmitApi::new().with_registry(Arc::clone(component_registry))
                }
            }
            .with_subset_gate(subset_gate),
        );
        let mut bridge = SchedulerSubmitBridge::new(api, Arc::clone(&sensitive_params_source));
        if let Some(projector) = contract219_projector.as_ref() {
            bridge = bridge.with_contract219(Arc::clone(projector));
        }
        let submit_gate: Arc<dyn ComponentSubmitGate> = Arc::new(bridge);
        register_agent_component_submit(&*registry, submit_gate);
    }

    if let Some(tree) = agent_tree.as_ref() {
        let spawner_concrete = DefaultSpawner::with_template_resolver(
            (**tree).clone(),
            Arc::new(CapGrantSubsetAdapter::new()),
            Arc::new(BuiltinTemplateRegistry::new()),
        );
        // Wave-23 seam (d): when messaging is wired (so the shared routing/bridge/
        // store exist), build the PerChildLoopManager and attach it as the spawner's
        // observer — a runtime spawn then delegates the child grant, registers colon
        // routing + the id-bridge pair, and serves a per-agent loop. Its
        // runtime/injector are late-bound after `builder.build()` (below).
        //
        // PRECONDITION — per-child liveness requires `lifecycle` AND `messaging`
        // (audit r9): the child serve loop POLLS A MAILBOX and seams (d)/(e) are the
        // messaging id-chain (store + `DynamicRouting` + `AgentIdBridge`), so a live
        // child is meaningless without the messaging transport (no mailbox to serve,
        // no way for a parent to reach the child). A `lifecycle`-only agent (declares
        // `lifecycle` but not `messaging`) therefore takes the `else` branch below:
        // `spawn-child` still records the tree node, but there is no transport to
        // serve it — the correct, not-silently-dropped outcome (§3.6 gap row).
        let spawner: Arc<dyn Spawner> = if let (Some(store), Some(routing), Some(bridge)) = (
            messaging_store.as_ref(),
            perchild_routing.as_ref(),
            perchild_bridge.as_ref(),
        ) {
            let key_resolver: KeyResolver = Arc::new(|bare: &str| {
                if bare == DEFAULT_AGENT_ID {
                    crate::commands::start::DEFAULT_MSG_AGENT_ID.to_string()
                } else {
                    format!("agent:{bare}")
                }
            });
            // W24 seam (f): one shared crash-cascade sink built from the tree +
            // mailbox store + the SAME bare→colon resolver. It resolves the crashing
            // agent's parent DYNAMICALLY, so one instance serves root + all children.
            let crash_sink = crate::crash_cascade::build_crash_cascade_sink(
                (**tree).clone(),
                store.clone(),
                |bare: &str| {
                    if bare == DEFAULT_AGENT_ID {
                        crate::commands::start::DEFAULT_MSG_AGENT_ID.to_string()
                    } else {
                        format!("agent:{bare}")
                    }
                },
            );
            perchild_crash_sink = Some(crash_sink.clone());
            let mgr = Arc::new(
                PerChildLoopManager::new(
                    store.clone(),
                    event_bus_dyn.clone(),
                    routing.clone(),
                    bridge.clone(),
                    Some(cap_grant.store.clone()),
                    (**tree).clone(),
                    tokio::runtime::Handle::current(),
                    key_resolver,
                )
                .with_progress_lifecycle(
                    progress_lifecycle
                        .as_ref()
                        .expect("per-child messaging requires joint activation")
                        .action_dispatcher
                        .clone(),
                    progress_lifecycle
                        .as_ref()
                        .expect("per-child messaging requires joint activation")
                        .execution_boundary
                        .clone(),
                )
                .with_crash_sink(crash_sink),
            );
            perchild_manager = Some(mgr.clone());
            let observer: Arc<dyn SpawnObserver> = mgr;
            Arc::new(spawner_concrete.with_spawn_observer(observer))
        } else {
            // No messaging chain (a `lifecycle`-only agent, or no agent-tree): the
            // spawner stays observer-less — `spawn-child` records the tree node but
            // no serve loop/routing is attached (there is no mailbox transport to
            // serve). Per-child liveness is a `lifecycle` + `messaging` config.
            Arc::new(spawner_concrete)
        };
        register_agent_spawn(&*registry, spawner);
        // Wave-12 Lane C: register the 3 decomposition host-fns over a
        // `DefaultDecompositionStore` sharing THIS tree + the real `event_bus_dyn`,
        // so `submit-decomposition` / `update-subtask-status` record state the
        // assembler's Tier-2 ⑭ "Active Task Decomposition" section reads, and
        // product-emit `task.decomposed` / `task.subtask_updated`. Wave-23's
        // whole-capability `"lifecycle"` lift makes these op names LINKABLE, but only
        // the spawn leg is served — the decomposition ops stay unexercised by shipped
        // guests; safe ALONGSIDE `register_agent_spawn` (disjoint op names). Witness
        // `crates/cli/tests/decomposition_wiring_172.rs`.
        let decomp_store = Arc::new(DefaultDecompositionStore::new((**tree).clone()));
        register_agent_decomposition(&*registry, decomp_store.clone(), event_bus_dyn.clone());
        decomposition_store = Some(decomp_store);
    }

    // 5-msg — await-leg B-2 (2026-06-22): register the messaging host-fns
    // (await-replies + heartbeat) with the production `RunManagerSuspendSink` so a
    // parked await drives the M008 Run suspend/resume lifecycle. Gated on
    // `declares_messaging` (the chain + ref were built above; `await_manager` is the
    // surviving `Arc::clone`). Closes MODULE-007 §3.6 R9. await-leg B-4a (2026-06-22)
    // added `"messaging"` to `agent_config::KNOWN_CAPABILITIES`, so a `messaging`-
    // declaring guest now LINKS these host fns (this L0 registration ↔ the injected
    // CapRequest read the SAME config). DORMANT only for shipped agents (none declare
    // messaging).
    // Wave-24 `req270-sink`: capture a handle clone BEFORE the `if let Some` below
    // consumes `await_manager`, so `WiringHandles.await_manager` can expose the
    // composition-root manager to the composition-root witness. Cheap `Option<Arc>`
    // clone; `None` on the non-messaging daemon.
    let await_manager_handle = await_manager.clone();
    if let Some(manager) = await_manager {
        let sink: Arc<dyn RunSuspendSink> = Arc::new(
            crate::await_wiring::RunManagerSuspendSink::new(Arc::clone(&run_manager)),
        );
        // await-leg B-3 (2026-06-22): register the WASM `send` host-fn (the
        // child→parent reply ingress → MODULE-007 `on_reply`, else M006 mailbox
        // delivery) alongside await-replies/heartbeat, under the SAME
        // `declares_messaging` gate. `Arc::clone(&manager)` because the
        // `_with_suspend_sink` call below consumes `manager`. As of B-4a the path is
        // guest-linkable (a `send`-importing guest resolves `send` here); DORMANT only
        // for shipped agents (no shipped config/row declares `messaging`).
        register_send_host_fn_with_turn_reply_routing(
            &*registry,
            Arc::clone(&manager),
            progress_lifecycle
                .as_ref()
                .expect("messaging host functions require joint activation")
                .reply_routing
                .clone(),
        );
        register_reply_tracker_host_fns_with_suspend_sink(
            &*registry,
            manager,
            event_bus_dyn.clone(),
            Some(sink),
        );
        // Wave-20 Lane `messagingabi` (M006-AC-02/AC-15): register the guest-
        // callable `notify` host-fns (notify-agent + notify-channel) against the
        // SAME bridge-carrying dispatcher the await chain uses (one store, one
        // tree, one bridge — no orphan store between await and notify). The
        // `import notify` on `world advance-host-with-capabilities` + the injector
        // typed-notify path make a notify-importing guest link + call these. As
        // with `send`, DORMANT for shipped agents (none declare `messaging`).
        if let Some(dispatcher) = await_dispatcher {
            let (notify_leak, _, _) = crate::channels_boot::live_security_components(Some(
                builder.config_watcher() as Arc<dyn RuntimeConfigProvider>,
            ));
            let notify_leak: Arc<dyn LeakDetector> = notify_leak;
            advance_messaging::register_notify_host_fns_with_leak_detector(
                &*registry,
                dispatcher.clone() as Arc<dyn advance_messaging::MailboxDispatcher>,
                Some(notify_leak.clone()),
            );
            advance_messaging::register_notify_channel_host_fn_with_leak_detector(
                &*registry,
                dispatcher as Arc<dyn advance_messaging::ChannelNotifier>,
                Some(notify_leak),
            );
        }
    }

    // 5a — cap-secrets (real store; `needs_key` guarantees `Some`).
    // Wave-18 Lane-3 (MODULE-012-AC-15): `register_secrets_capability` selects the
    // GATED `secret-exists` handler over a `DeclaredDependencyPolicy` when the
    // operator declares `secrets.dependencies` (keyed on the bare cap
    // `ctx.agent_id`, e.g. `default-agent`), else the permissive handler
    // (byte-identical to pre-Wave-18 — the gate is operator-opt-in).
    if declares_secrets {
        let store = secret_store
            .as_ref()
            .expect("needs_key ⇒ Some when secrets declared")
            .clone();
        register_secrets_capability(&*registry, store, &builder.config().secrets);
    }

    // 5b — cap-fs (resolver + schema built in step 2b).
    // Slice BS-3: wire git_sync (so agent writes produce CommitType::Turn commits)
    // IF the workspace is a git repo. `DefaultGitCommitQueue::spawn` OPENS (does not
    // create) the repo; on a non-repo workspace it errors → degrade gracefully
    // (register without git_sync, no commits — identical to pre-BS-3). The queue is
    // held in `WiringHandles` for the runtime lifetime (its Drop drains the worker).
    // The db/workspace/tree trio stays all-None (the slice-C invariant); git_sync is
    // independent (slice-D).
    // Wave-10 Lane C: HOIST the git commit queue. ONE `DefaultGitCommitQueue`
    // per workspace, shared by cap-fs `git_sync` (below) AND the cap-skills
    // lifecycle coordinator (5c) — `commit_queue.rs:31` warns that two queues
    // on the same repo race the shared index. Spawned when fs OR skills is
    // declared (a skills-only agent still needs `turn` commits for skill
    // changes). Bus-wired so every successful commit emits `git.commit`
    // (MODULE-003-AC-25). `Err` (workspace not a bootstrapped git repo) → `None`
    // → degrade (no commits), identical to pre-Wave-10. Built AFTER the earlier
    // auto-notify error path (so only the `builder.build()` error path sees it
    // live + drops it).
    let git_queue_handle: Option<Arc<DefaultGitCommitQueue>> = if declares_fs || declares_skills {
        match DefaultGitCommitQueue::spawn_with_event_bus(
            workspace.to_path_buf(),
            event_bus_dyn.clone(),
        ) {
            Ok(queue) => Some(Arc::new(queue)),
            Err(_) => None, // workspace is not a (bootstrapped) git repo → no commits
        }
    } else {
        None
    };
    if let Some((resolver, schema)) = fs_handles {
        // cap-fs git_sync consumes the SHARED queue handle (clone) when present.
        let git_sync: Option<Arc<dyn GitSync>> = git_queue_handle.clone().map(|queue| {
            let queue_trait: Arc<dyn GitCommitQueue> = queue;
            Arc::new(Adv003GitSync::new(queue_trait)) as Arc<dyn GitSync>
        });
        register_agent_fs(
            &*registry,
            resolver,
            event_bus_dyn.clone(),
            schema,
            Arc::new(StubFileHistoryProvider),
            Arc::new(DefaultAtomicWriter),
            Some(FS_PREVIEW_MAX_BYTES),
            None, // db_sync
            None, // workspace_root
            None, // agent_tree
            git_sync,
        );
    }

    // 5c — cap-skills (single-agent provider rooted at `<workspace>/.agent`).
    // skills-J26 reader satellite: SINGLE-SOURCE the skills root. One
    // `workspace.join(".agent")` literal feeds BOTH the provider (write path) AND
    // the context-assembler's `DiskSkillSummaryReader` (read path, via
    // `WiringHandles.skills_root`), so the two can never desync. Gated on
    // `declares_skills` (the same predicate that registers the provider) → a
    // no-skills-cap agent gets `skills_root: None` → `StubSkillSummary`.
    let mut skill_turn_runtime_handle: Option<Arc<cap_skills::SkillTurnRuntime>> = None;
    let skills_root: Option<PathBuf> = if declares_skills {
        let skills_agent_root = workspace.join(".agent");
        // slice wave6-laneB (leg 3): point the candidate consumer at
        // `<ws>/.agent/memory` — the SAME flat `_skill_candidates.jsonl` the
        // MODULE-011 L6 producer writes (leg 2, via `attach_l6`'s `mem_root`).
        // This is the memory root, NOT the skills `agent_root` (`<ws>/.agent`).
        let candidate_dir = workspace.join(".agent").join("memory");
        let provider = Arc::new(
            SingleAgentSkillStoreProvider::new(DEFAULT_AGENT_ID, skills_agent_root.clone())
                .with_candidate_dir(candidate_dir),
        );
        // Wave-10 Lane C (076/077): when the shared git commit queue exists, wire
        // the persistence coordinator — sharing the provider's resolved store so
        // all 8 skills host-fns serialize on one mutex — so a successful agent
        // activate/rollback emits `skill.activated` / `skill.rolled_back` + a
        // `commit_type: turn` commit. Without a queue (non-git workspace), fall
        // back to the event-less registration (byte-identical to pre-Wave-10).
        match git_queue_handle.clone() {
            Some(queue) => {
                let shared = provider
                    .get(DEFAULT_AGENT_ID)
                    .await
                    .expect("single-agent provider resolves its own id");
                let queue_trait: Arc<dyn GitCommitQueue> = queue;
                // Wave-18 Lane 2 (MODULE-017-AC-06, record side): when an auto-loop
                // driver exists, register the pre-activation observer so an agent
                // `activate-skill` snapshots the prior version into the driver's
                // iteration tracker BEFORE the store mutation — the record half of the
                // discard→rollback bridge. No driver ⇒ byte-identical to pre-Wave-18.
                let mut coord = cap_skills::SkillPersistenceCoordinator::with_shared_store(
                    DEFAULT_AGENT_ID.to_string(),
                    skills_agent_root.clone(),
                    Arc::clone(&shared),
                    queue_trait,
                    event_bus_dyn.clone(),
                );
                if let Some(driver) = &auto_loop_driver {
                    coord = coord.with_pre_activation_observer(
                        crate::skill_rollback_bridge::build_pre_activation_observer(driver),
                    );
                }
                let coordinator = Arc::new(coord);
                // Wave-18 Lane 2 (MODULE-017-AC-07 + MODULE-003-AC-21, write side):
                // late-bind the write-side bridge into the driver so an iteration
                // discard restores the skill via the SAME coordinator on the
                // `Initiator::AutoLoop` (micro) lane — a `[micro]` commit durable BEFORE
                // the `skill.rolled_back` / `skill.deleted` event. OnceLock setter: the
                // driver Arc was already cloned into the round-advancer above, and the
                // late-bind is visible through every clone (Wave-12 ContextAssembler
                // precedent). Closes the Wave-17 strict-hold (no production
                // `impl SkillRollback`).
                if let Some(driver) = &auto_loop_driver {
                    driver.set_skill_rollback(
                        crate::skill_rollback_bridge::build_auto_skill_rollback_bridge(
                            Arc::clone(&coordinator),
                            Arc::clone(&shared),
                        ),
                    );
                }
                let turn_persistence_driver =
                    build_skill_turn_persistence(Arc::clone(&shared), Arc::clone(&coordinator));
                let health_flush: Arc<dyn cap_skills::SkillHealthFlush> =
                    Arc::new(cap_skills::CapMemorySkillHealthFlush::new(
                        workspace.join(".agent").join("memory"),
                    ));
                let turn_runtime = Arc::new(cap_skills::SkillTurnRuntime::new(
                    DEFAULT_AGENT_ID,
                    skills_agent_root.clone(),
                    Arc::clone(&shared),
                    turn_persistence_driver,
                    event_bus_dyn.clone(),
                    health_flush,
                    workspace.join(".agent").join("memory"),
                ));
                skill_turn_runtime_handle = Some(Arc::clone(&turn_runtime));
                cap_skills::register_agent_skills_with_turn_runtime(
                    &*registry,
                    provider,
                    coordinator,
                    turn_runtime,
                );
            }
            None => {
                cap_skills::register_agent_skills(&*registry, provider);
            }
        }
        Some(skills_agent_root)
    } else {
        None
    };

    // 5d — cap-memory. Backbone Step 3: register the PERSISTENT store opened in
    // step 2c (rooted at `<ws>/.agent/memory`) so the WIT remember/recall/forget/
    // recall-at handlers read+write durable per-agent `knowledge.jsonl` across
    // restarts (MODULE-011-AC-39). The fallible `open()` already ran pre-EventBus;
    // this registration is infallible (no teardown path needed). B1 (ADVERSARIAL-r7):
    // clone (not move) so the SAME `Arc<MemoryStore>` is also returned in
    // `WiringHandles.memory_store` for the context-assembler to share (one store,
    // one hydration, one handle — no second `open()`).
    if let Some(store) = &memory_store {
        // rollback-memory slice (2026-06-12): the production AC-18 wiring —
        // (a) the cursor store persists `_knowledge_cursor.yaml` beside each
        // agent's knowledge.jsonl (`with_root`, the SYS-AC-063 file half);
        // (b) the git half restores `_knowledge_map.yaml` + `syntheses/*.md`
        // from history via `GitMemoryRestore` over the real MODULE-003
        // `DefaultWorkspaceRollback` (knowledge.jsonl stays the store's
        // in-process job — the split-brain-avoiding division; see
        // `cap_memory::MemoryGitRestore`).
        let git_restore: Option<Arc<dyn MemoryGitRestore>> =
            match advance_git::DefaultWorkspaceRollback::with_event_bus(
                workspace.to_path_buf(),
                event_bus_dyn.clone(),
            ) {
                // Adversarial-round F2 fix (2026-06-13): `with_event_bus`
                // only canonicalizes — it never opens the repo — so the
                // previous probe wired the git half on NON-repo workspaces
                // too, turning every rollback-memory call into a destructive
                // mutate-then-error (store half lands, git half fails, cursor
                // never reset, no event). Probe with `verify_repo()` (one
                // real repo open) and degrade to None on a non-repo
                // workspace — no history exists there, so skipping the git
                // half IS the correct semantics (the
                // `DefaultGitCommitQueue::spawn` open-probe precedent above).
                Ok(rb) => match rb.verify_repo() {
                    Ok(()) => Some(Arc::new(GitMemoryRestore {
                        inner: Arc::new(rb),
                    })),
                    Err(e) => {
                        eprintln!(
                            "advance: rollback-memory git half not wired (workspace is not a git repository): {e:?}"
                        );
                        None
                    }
                },
                Err(e) => {
                    eprintln!(
                        "advance: rollback-memory git half not wired (workspace rollback unavailable): {e:?}"
                    );
                    None
                }
            };
        // MODULE-005-AC-29 producer-boundary guard (CONTRACT-214): wire the M005-owned
        // `WorkspaceFileResidentPolicy` over the CLI workspace root so live `remember()`
        // rejects whole-file byte copies (≥512 B) — `knowledge.jsonl` stores only
        // non-file-owned insights (REQ-210/211). Best-effort heuristic (fails open under
        // scan-budget exhaustion); the other 4 memory handlers are unaffected.
        let producer_boundary_policy: Arc<dyn advance_shared_types::traits::RememberContentPolicy> =
            Arc::new(WorkspaceFileResidentPolicy::rooted(workspace.to_path_buf()));
        register_agent_memory_with_git_and_policy(
            &*registry,
            store.clone(),
            event_bus_dyn.clone(),
            Arc::new(L6CursorStore::with_root(workspace.join(".agent/memory"))),
            git_restore,
            Some(producer_boundary_policy),
        );
    }

    // 5e — cap-grant agent-grant WIT host fns. The global default resolver
    // chain mirrors the documented "supervised" preset
    // (`PresetRegistry::with_builtins`); it is constructed but not exercised at
    // BS-1 (no agent runs). The bundle's GrantStore is the one already built by
    // `register_cap_grant`.
    // m013-intake (AC-24): declared before the block so the WiringHandles
    // construction (below) can surface it; `None` when `grant` is not declared.
    let mut grant_approval_intake: Option<Arc<GrantApprovalIntake>> = None;
    if declares_grant {
        // Hoist ONE validator + ONE preset registry Arc, shared by the intake,
        // the resolver chain, and the agent-grant bundle.
        let validator: Arc<dyn SubsetValidator> = Arc::new(SubsetValidatorImpl::new());
        let presets = Arc::new(PresetRegistry::with_builtins());
        // Build the operator approval intake (CONTRACT-123) and inject it as the
        // Channel resolver's approval port (replacing the fail-closed default) —
        // a parked `grant-decision::pending` routes THROUGH it and the CONTRACT-120
        // retry observes the operator's approve/deny/narrow.
        let intake = build_grant_approval_intake(
            cap_grant.store.clone(),
            validator.clone(),
            presets.clone(),
            event_bus_dyn.clone(),
        );
        let resolver_chain = Arc::new(build_grant_resolver_chain(
            validator.clone(),
            Arc::new(run_manager.budget()),
            Some(intake.clone() as Arc<dyn ChannelApprovalPort>),
        ));
        register_agent_grant(
            &*registry,
            AgentGrantBundle {
                store: cap_grant.store.clone(),
                validator,
                presets,
                resolver_chain,
                event_bus: event_bus_dyn.clone(),
            },
        );
        grant_approval_intake = Some(intake);
    }

    // 5f — cap-llm. Real gateway + cap-http security chain + REAL per-session
    // budget (Phase-3 kickoff). The reqwest executor is live (BS-3).
    //
    // Backbone Step 2 (2026-06-07): capture an Arc clone of the gateway so the
    // composition root (start.rs) can build the `PublishingContextAssembler`
    // against the SAME gateway the `AgentLlmGenerateHandler` reads (the per-agent
    // assembled-context store is shared across all Arc<LlmGateway> clones). `None`
    // when llm is not declared (no seam, no assembler — the loop keeps the
    // MinimalContextAssembler default).
    let mut llm_gateway: Option<Arc<LlmGateway>> = None;
    let mut llm_delta_hub_opt: Option<Arc<advance_client_api::deltas::LlmDeltaHub>> = None;
    let mut llm_stream_reaper: Option<Arc<cap_llm::AgentStreamReaper>> = None;
    // Stage-C MAINLINE harvest pass-3 (2026-06-19): the REAL Step-3 VLM description
    // extractor, built alongside the gateway (shares its chain + config). `None` when
    // llm is not declared → no Step-3 description indexing.
    let mut vlm_extractor: Option<Arc<dyn VlmExtractor>> = None;
    if declares_llm {
        let store = secret_store
            .as_ref()
            .expect("needs_key ⇒ Some when llm declared")
            .clone();
        // Wave-16 Lane-4 (MODULE-012 AC-17): build the leak/SSRF/rate components
        // with their `security.*` tunables sourced LIVE off the config provider, so
        // a hot-reload takes effect on this LLM-egress chain without restart.
        let (llm_leak, llm_ssrf, llm_rate) = crate::channels_boot::live_security_components(Some(
            builder.config_watcher() as Arc<dyn RuntimeConfigProvider>,
        ));
        // S4: keep a clone of the SAME leak-detector instance for the gateway's
        // decoded layer (single scan authority across wire + decoded scans).
        let llm_leak_gateway: Arc<dyn LeakDetector> = llm_leak.clone();
        // S4: ONE concrete reqwest executor, coerced to both the buffered
        // `HttpExecutor` and the streaming `HttpStreamExecutor` (the comment below
        // claimed this; before 2026-07-29 two separate instances were built).
        let llm_executor = crate::channels_boot::live_executor(Some(
            builder.config_watcher() as Arc<dyn RuntimeConfigProvider>
        ));
        let chain = Arc::new(
            DefaultHttpSecurityChain::new(
                store,
                llm_leak,
                llm_ssrf,
                llm_rate,
                // Slice BS-3 (2026-06-03): real reqwest executor (cap-http "Slice E"
                // shipped it). Dormant until an agent calls agent-llm/generate; a real
                // LLM provider endpoint (https public host) passes the chain's SSRF
                // guard. Replaces the fail-closed NotWiredHttpExecutor.
                // AC-17: connect-time DNS timeout sourced live (matches the chain's
                // SSRF guard), so `security.ssrf.dns_timeout_ms` hot-reload applies here too.
                llm_executor.clone(),
            )
            // Phase-3 kickoff: emit http.*/security.*/secret.injected on the live
            // LLM egress (host-only redacted payloads — MODULE-019-AC-22).
            .with_event_bus(event_bus_dyn.clone())
            // S4: enable the streaming executor on the chain — the SAME concrete
            // reqwest executor, coerced to `HttpStreamExecutor`. This makes
            // `execute_streaming` available for the live path.
            .with_stream_executor(llm_executor),
        );
        // Stage-C MAINLINE harvest pass-3 (2026-06-19): build the REAL VLM extractor
        // BEFORE `chain` is moved into `LlmGateway::new` — it shares the SAME
        // `HttpSecurityChain` + `RuntimeConfigProvider`, so the VLM egress posture is
        // identical to the gateway's (one security chain, one config). Threaded into
        // `build_live_post_processor`, which installs the `VlmDescriptionIndexer` into
        // the live post-processor Step-3.
        let vlm: Arc<dyn VlmExtractor> = Arc::new(LlmGatewayVlm::new(
            builder.config_watcher(),
            chain.clone(),
            event_bus_dyn.clone(),
            DEFAULT_AGENT_ID.to_string(),
        ));
        vlm_extractor = Some(vlm);
        // S4 final (2026-07-29, dev-task-s4-final): live streaming re-wired via
        // `install_live_streaming` below — the chain (with its stream executor
        // above) is coerced to HttpStreamingChain and the decoded layer receives
        // the SAME detector instance as the chain (single scan authority; plan §1).
        // Wired ⇒ the WIT stream path is live ONLY (no buffered fallback).
        let stream_chain: Arc<dyn HttpStreamingChain> = chain.clone();
        let stream_detector: Arc<dyn LeakDetector> = llm_leak_gateway.clone();
        // Tee T2 production wiring (step 1 of 2): construct the shared LlmDeltaHub
        // BEFORE the gateway, so the gateway's delta_sink and the ClientApi's hub
        // slot share the SAME Arc. The hub is the CONTRACT-234 Provider (MODULE-020);
        // the gateway is the Consumer/caller that publishes frames into it.
        let llm_delta_hub: Arc<advance_client_api::deltas::LlmDeltaHub> = {
            let det: Arc<dyn advance_shared_types::traits::LeakDetector> =
                Arc::clone(&public_leak_detector);
            let hold: Arc<dyn Fn(&[u8], usize) -> Result<usize, ()> + Send + Sync> =
                Arc::new(|buf: &[u8], max_canonical: usize| {
                    cap_http::canonical_facade::decoded_hold_split(buf, max_canonical)
                });
            let clock: Arc<dyn advance_client_api::Clock> =
                Arc::new(advance_client_api::SystemClock);
            let observer: Arc<dyn Fn(advance_client_api::deltas::HubEvent) + Send + Sync> =
                Arc::new(|event| {
                    let _ = event; // observer: production would wire tracing here
                });
            Arc::new(advance_client_api::deltas::LlmDeltaHub::new(
                Some(det),
                Some(hold),
                clock,
                Some(observer),
            ))
        };
        llm_delta_hub_opt = Some(Arc::clone(&llm_delta_hub));

        // THE single production path to a gateway (S4): `build_llm_gateway` installs
        // the live streaming path internally, so the composition-root witness in
        // `crates/cli/tests/s4_live_streaming_composition.rs` covers THIS code —
        // deleting the install inside it fails that test, and deleting this call
        // fails to compile.
        let gateway = build_llm_gateway(
            builder.config_watcher(),
            chain,
            stream_chain,
            stream_detector,
            // Phase-3 kickoff: the REAL per-session budget, sharing the manager's
            // RunStore + the EventBus CostTracker. Replaces NotWiredRunBudget so
            // the run_id-gated preflight actually enforces (MODULE-009-AC-19).
            Arc::new(run_manager.budget()),
            event_bus_dyn.clone(),
            // Repetition guard stays NotWired (multi-step agentic run deferred).
            Arc::new(NotWiredRepetitionGuard),
            DEFAULT_AGENT_ID.to_string(),
            // Tee T2 (step 2 of 2): the hub as the gateway's delta sink.
            Arc::clone(&llm_delta_hub) as Arc<dyn advance_shared_types::traits::LlmDeltaSink>,
        );
        // Hold an Arc clone for the composition root before registration
        // moves one into the host-fn handlers (all clones share the one gateway,
        // so its per-agent assembled-context store is the same on both sides).
        llm_gateway = Some(gateway.clone());
        // Tee slice T3: RETAIN the reap handle — the composition root drives
        // turn-end reap through it on both observer paths.
        llm_stream_reaper = Some(register_agent_llm_with_turn_cost(
            &*registry,
            gateway,
            progress_lifecycle
                .as_ref()
                .map(|activation| activation.cost_attribution.clone()),
        ));
    }

    // Step 6 — finalize. On failure, release the registered providers + cap_grant
    // so their `event_bus_dyn` clones drop, THEN shut down the EventBus.
    //
    // Audit-R5 (Codex-Diff W1) fix: the pre-build registrations (fs / memory /
    // grant / llm) live inside the `InMemoryHostRegistry` that `registry` clones,
    // and their handlers hold `event_bus_dyn` clones. `build()` consuming
    // `builder` releases the builder-side registry Arc on its error path, but the
    // LOCAL `registry` clone would otherwise keep the registry (and its handlers'
    // bus clones) alive — making `Arc::try_unwrap(bus_concrete)` fail and silently
    // skipping the EventBus shutdown. (Slice AG never hit this: cap-secrets, its
    // only pre-build registration, holds no bus clone.) `drop(registry)` releases
    // the handlers + their bus clones; `drop(cap_grant)` releases the GrantStore's
    // clone. The spawned sweeper task's transient clone remains the documented
    // best-effort caveat (process exit reaps it).
    let host = match builder.build(cap_grant.grant_check.clone()) {
        Ok(h) => h,
        Err(e) => {
            // Phase-3 kickoff: `run_manager` (and the gateway's `budget()` clone,
            // released via `drop(registry)`) hold `event_bus_dyn` clones; drop the
            // manager too so `Arc::try_unwrap(bus_concrete)` in
            // `shutdown_event_bus_on_error` can succeed and reap the EventBus tasks.
            drop(run_manager);
            // W24 perchild-daemon-2 (Codex audit R9): the `PerChildLoopManager` holds an
            // `event_bus_dyn` clone (SAME allocation as `bus_concrete`, since Wave-23). It
            // is reachable both via this local `Option` AND the spawn observer inside
            // `registry` (released by `drop(registry)` below); drop the local too so
            // `Arc::try_unwrap(bus_concrete)` in `shutdown_event_bus_on_error` can succeed
            // and reap the EventBus tasks — identical invariant to the sibling drops.
            // (`crash_cascade_sink` / `breaker_subscriber` hold NO bus clone — the former
            // takes tree+store+resolver, the latter is spawned only on the success path.)
            drop(perchild_manager);
            // Stage-D: the auto-loop driver holds EventBus event/notify sink
            // clones AND is reachable both via the RunManager's RoundAdvancer
            // (dropped above) and this local Arc. Drop the local Arc too so the
            // driver — and its bus clones — release before the EventBus shutdown.
            drop(auto_loop_driver);
            // Backbone Step 2: the captured gateway clone (if llm declared) holds
            // its own event_bus_dyn + budget clones; drop it too so
            // `Arc::try_unwrap(bus_concrete)` can reap the EventBus tasks.
            drop(llm_gateway);
            // Stage-C harvest pass-3: the `LlmGatewayVlm` (if llm declared) holds its OWN
            // `event_bus_dyn` clone (its `#[allow(dead_code)]` `event_bus` field) — the
            // SAME allocation as `bus_concrete`, so it must drop here too, else
            // `Arc::try_unwrap(bus_concrete)` fails and the EventBus shutdown is skipped
            // (identical invariant to the `drop(llm_gateway)` Audit-R5 fix above).
            drop(vlm_extractor);
            // m013-intake (AC-24): the operator approval intake holds its own
            // `event_bus_dyn` clone (SAME allocation as `bus_concrete`) and is
            // reachable both via this local Arc and the resolver chain held by the
            // registered request-capability handler (released via `drop(registry)`
            // below). Drop the local too so `Arc::try_unwrap(bus_concrete)` can reap
            // the EventBus tasks — identical invariant to the sibling drops above.
            drop(grant_approval_intake);
            drop(cap_grant);
            drop(registry);
            // Wave-10 Lane C: the hoisted git commit queue's worker holds an
            // `event_bus_dyn` clone (in its detached task). Drop the handle so it
            // joins the sibling drops (best-effort EventBus-shutdown drain-signal;
            // the worker's clone is reaped at process exit — same class as
            // cap-grant's spawned sweeper).
            drop(git_queue_handle);
            // W24 perchild-daemon-2 (Codex audit R10): the skills turn-runtime
            // (`SkillTurnRuntime`, if the agent declares skills) holds its OWN
            // `event_bus_dyn` clone — constructed from the `event_bus_dyn.clone()`
            // ctor arg above, the SAME allocation as `bus_concrete`. The
            // `skill_turn_runtime_handle` local is consumed only on the SUCCESS path
            // (moved into the returned `WiringHandles`), so on this Err arm it is
            // still a live holder; drop it too so `Arc::try_unwrap(bus_concrete)` in
            // `shutdown_event_bus_on_error` can succeed and reap the EventBus tasks —
            // identical invariant to the sibling drops. (Pre-existing since the
            // live-skill-turn-persistence wave; completes the drop-list this lane's
            // R9 `drop(perchild_manager)` fix began.)
            drop(skill_turn_runtime_handle);
            // W24 req270-sink (Codex audit R1): the composition-root
            // `await_manager_handle` clone (captured before the `if let Some(manager)
            // = await_manager` consume, for `WiringHandles.await_manager`) retains an
            // `AwaitSessionManagerImpl` Arc, which holds its OWN `event_bus_dyn` clone
            // (SAME allocation as `bus_concrete`, since Wave-15). It is consumed only on
            // the SUCCESS path (moved into `WiringHandles`), so on this Err arm it is
            // still a live holder; drop it too so `Arc::try_unwrap(bus_concrete)` in
            // `shutdown_event_bus_on_error` can succeed and reap the EventBus tasks —
            // identical invariant to the sibling drops. `None` on the non-messaging
            // daemon (drop is a no-op then).
            drop(await_manager_handle);
            // Joint activation and the staged channel runtime each retain the
            // production EventBus through rejection/HTTP sinks. They are not
            // visible until success, so release both before attempting shutdown.
            drop(progress_lifecycle);
            drop(channel_runtime);
            drop(reply_registry);
            shutdown_event_bus_on_error(bus_concrete, event_bus_dyn).await;
            return Err(CliWiringError::Bootstrap(e));
        }
    };

    // Step 7 — cap-tools, POST-build. The `LazyToolRegistry` engine handle only
    // exists once `ComponentRuntime` is built. `host.host_registry()` is the
    // SAME Arc the CapabilityInjector wraps (Arc identity preserved across
    // `build()`, T73); `inject()` reads it lazily, so this post-build
    // registration is visible at L0.
    // Wave-12 (SYS-AC-122): exposed so the composition root can LATE-BIND the
    // per-agent `ContextAssembler` into the guard (the Tier-3 inject sink). `None`
    // when the agent declares no `tools` cap (nothing to late-bind).
    let mut repetition_guard_handle: Option<Arc<RepetitionGuard>> = None;
    if declares_tools {
        let tools_cfg = LazyRegistryConfig::from(&host.config().tools);
        let engine = host.component_runtime().tool_engine_handle();
        // Wave-14 (SYS-AC-080): bind the engine-bearing registry as the CONCRETE
        // `Arc<LazyToolRegistry>` so the L2 skill-tool bridge can `register_binary`
        // skill-bundled `tool.wasm` sidecars BEFORE we coerce to the trait object
        // and register the `tool-invoke` host-fn over it.
        let tools_concrete: Arc<LazyToolRegistry> =
            Arc::new(LazyToolRegistry::new_with_engine(tools_cfg, engine));
        // Wave-14 (SYS-AC-080) — L2 skill→tool-registry bridge. Populate the
        // registry from each materialized skill's `tool.wasm` sidecar under the
        // PRD §12.4.4 canonical id `skill::{name}`. Only when this agent ALSO has a
        // skills root (`skills_root`, computed in block 5c on `declares_skills`); a
        // tools-but-no-skills agent leaves the registry empty (no skill tools).
        // `register_binary` is lazy (validate/describe deferred to first invoke), so
        // a malformed sidecar never blocks boot.
        if let Some(root) = skills_root.as_deref() {
            let _registered = register_skill_tools(&tools_concrete, root).await;
        }
        let tools: Arc<dyn ToolRegistry> = tools_concrete;
        // Wave-11 Lane C — feed the production tool-dispatch repetition guard
        // (closes the orphan `record_tool_call`). One process-global
        // `RepetitionGuard` from the canonical defaults (window 10 / threshold
        // 3 / warn-then-terminate / enabled), pre-wired with the SHARED
        // `event_bus_dyn` + the `RunManager` `AgentRunResolver`, so a runaway
        // identical-tool-call loop emits `run.repetition_detected` (run_id
        // resolved from the agent's live Run) and — on Terminate — fails the
        // call. Per-run `repetition_guard` overrides stay NotWired (mirrors the
        // cap-llm `record_output` path); see MODULE-008 §3.6.
        //
        // Wave-12 (SYS-AC-122 Tier-3 inject conjunct): ALSO wire
        // `PromptInjectionHelpers` here, and keep a CONCRETE `Arc<RepetitionGuard>`
        // so the composition root can `set_context_assembler(inner)` once the
        // per-agent assembler is built (it does not exist at Step 7). The SAME
        // Arc is registered into cap-tools (unsizing-coerced to
        // `Arc<dyn RepetitionGuardCheck>`) AND retained in `WiringHandles`. The
        // `ContextAssembler` stays unset (no inject) until that late-bind.
        let guard: Arc<RepetitionGuard> = Arc::new(
            run_manager
                .build_repetition_guard_from_config(&RepetitionGuardConfig::default())
                .with_prompt_injection_helpers(Arc::new(DefaultPromptInjectionHelpers::default())),
        );
        register_agent_tools_with_guard(
            &*host.host_registry(),
            tools,
            event_bus_dyn.clone(),
            guard.clone(),
        );
        repetition_guard_handle = Some(guard);
    }

    // Wave-23 seam (d): late-bind the post-`build()` runtime + injector into the
    // per-child manager (constructed pre-build when it was attached as the spawner's
    // observer) so a runtime spawn can load + serve the child.
    if let Some(mgr) = &perchild_manager {
        mgr.bind_runtime(host.component_runtime(), host.capability_injector());
    }

    // W24 seam (f): attach the per-agent circuit-breaker→mailbox-freeze subscriber
    // over the shared messaging store (breaker-open for a served child freezes its
    // mailbox → pauses ingress; close unfreezes). ONE subscriber covers all children.
    let breaker_subscriber = messaging_store.as_ref().map(|store| {
        advance_messaging::BreakerSubscriber::spawn(host.circuit_breaker_bus(), store.clone())
    });

    // Final production visibility step: bind only after every fallible runtime
    // capability has composed. An unavailable loopback socket degrades the
    // optional public surface without exposing an unbound/raw fallback.
    // CONTRACT-243: bind whenever EventBus is up, even if C218/projector/carriers
    // are None (fs+llm Landing homes and `advance init` without lifecycle).
    let client_api_server = match observability_read_api.as_ref() {
        Some(read) => {
            let history_events = match (
                contract219_projector.as_ref(),
                observation_carrier_store.as_ref(),
            ) {
                (Some(projector), Some(carriers)) => {
                    let history = crate::client_api_adapters::Contract219HistoryAdapter::new(
                        Arc::clone(read),
                        Arc::clone(projector),
                        Arc::clone(carriers),
                    );
                    let events = crate::client_api_adapters::Contract185EventAdapter::new(
                        Arc::clone(read),
                        client_event_retention_days,
                    );
                    match (history, events) {
                        (Ok(h), Ok(e)) => Some((h, e, Arc::clone(projector))),
                        (Err(error), _) | (_, Err(error)) => {
                            eprintln!("advance: Client API history/events unavailable: {error}");
                            None
                        }
                    }
                }
                _ => None,
            };
            let grant_approval_for_api = grant_approval_intake.clone();
            match advance_client_api::ClientApiServer::bind_local_factory(0, move |address| {
                let mut config = advance_client_api::ClientApiConfig::default();
                config.allowed_origins = vec![format!("http://{address}")];
                let mut api = advance_client_api::ClientApi::new(config);
                if let Some((history, events, projector)) = history_events {
                    let history: Arc<dyn advance_client_api::BoundHistoryReadPort> =
                        Arc::new(history);
                    let events: Arc<dyn advance_client_api::ClientEventProvider> = Arc::new(events);
                    let cursor: Arc<dyn advance_client_api::ClientCursorCodec> =
                        Arc::new(advance_client_api::AeadClientCursorCodec::new(
                            Arc::new(advance_client_api::MemoryCursorKeyCustody::new_local()),
                            Arc::new(advance_client_api::SystemCursorClock),
                            Arc::new(advance_client_api::OsCursorEntropy),
                            client_event_retention_days,
                        ));
                    let grants = grant_approval_for_api.as_ref().map(|intake| {
                        Arc::new(crate::client_api_adapters::Contract219GrantAdapter::new(
                            Arc::clone(intake),
                            Arc::clone(&projector),
                        ))
                            as Arc<dyn advance_client_api::BoundGrantApprovalPort>
                    });
                    api = api
                        .with_bound_history_provider(history)
                        .with_event_provider(events)
                        .with_cursor_codec(cursor)
                        .with_observation_redactor(projector.redactor())
                        .with_leak_detector(Arc::clone(&public_leak_detector));
                    if let Some(grants) = grants {
                        api = api.with_bound_grant_provider(grants);
                    }
                }
                if let Some(hub) = llm_delta_hub_opt.as_ref() {
                    api = api.with_llm_delta_hub(Arc::clone(hub));
                }
                Arc::new(api)
            })
            .await
            {
                Ok(server) => {
                    eprintln!(
                        "advance: Client API and Web Console listening at http://{}",
                        server.local_addr()
                    );
                    let _ = advance_along_home::write_client_api_discovery(
                        workspace,
                        std::process::id(),
                        &format!("http://{}", server.local_addr()),
                    );
                    Some(server)
                }
                Err(error) => {
                    eprintln!("advance: Client API unavailable (loopback bind failed): {error}");
                    None
                }
            }
        }
        None => None,
    };

    Ok((
        host,
        WiringHandles {
            cap_grant,
            grant_approval_intake,
            perchild_manager,
            crash_cascade_sink: perchild_crash_sink,
            breaker_subscriber,
            event_bus: bus_concrete,
            event_bus_dyn,
            observability_read_api,
            contract218_runtime,
            observation_carrier_store,
            contract219_projector,
            client_api_server,
            git_queue: git_queue_handle,
            run_manager,
            await_manager: await_manager_handle,
            auto_loop_driver,
            run_config,
            llm_gateway,
            llm_stream_reaper,
            vlm_extractor,
            memory_store,
            messaging_store,
            reply_registry,
            channel_runtime,
            progress_lifecycle,
            agent_tree_snapshot,
            decomposition_store,
            memory_root,
            skills_root,
            skill_turn_runtime: skill_turn_runtime_handle,
            repetition_guard: repetition_guard_handle,
        },
    ))
}

/// Map `RuntimeConfig.secrets` → [`MasterKeyConfig`] and load the real master
/// key (64 hex chars = 32 bytes). `EnvVar` is the fully-wired + tested source;
/// `Keychain` is best-effort (delegates to the loader's keychain→env fallback
/// using the crate-provided default service/account constants — live OS
/// keychain integration is deferred per MODULE-012 §3.6, so REQ-095 stays
/// Partial).
pub(crate) fn load_real_master_key(
    workspace: &Path,
    secrets: &SecretsConfig,
) -> Result<Zeroizing<[u8; 32]>, CliWiringError> {
    let cfg = match secrets.master_key_source {
        MasterKeySource::EnvVar => MasterKeyConfig::EnvVar(secrets.env_var_name.clone()),
        MasterKeySource::Keychain => MasterKeyConfig::Keychain {
            service: DEFAULT_KEYCHAIN_SERVICE.to_string(),
            account: DEFAULT_KEYCHAIN_ACCOUNT.to_string(),
            fallback_env_var: Some(secrets.env_var_name.clone()),
        },
    };
    // Precedence must mirror cap_secrets::ensure_master_key: an explicitly
    // configured key (env/keychain) wins over the workspace-minted file, so the
    // whole set→resolve chain uses one key (cli/tests/secrets_roundtrip.rs).
    if let Some(key) = cap_secrets::resolve_master_key(workspace, &cfg, &DefaultEntryProvider)
        .map_err(CliWiringError::MasterKey)?
    {
        return Ok(key);
    }
    load_master_key(&cfg, &DefaultEntryProvider).map_err(CliWiringError::MasterKey)
}

/// Build the AC-15 caller-dependency policy from `secrets.dependencies`
/// (Wave-18 Lane-3, MODULE-012-AC-15). Returns `Some(policy)` iff the operator
/// declared at least one `<agent-id> → [secret-name]` mapping; an empty map
/// returns `None` so [`register_secrets_capability`] selects the permissive
/// handler (byte-identical to pre-Wave-18 — the gate is operator-opt-in). The
/// resulting [`DeclaredDependencyPolicy`] keys on the BARE
/// `HostCallContext.agent_id` (e.g. the production-stamped `default-agent`);
/// each agent's `Vec<String>` allowlist becomes a `HashSet` for O(1) membership.
///
/// `pub` so the cli integration test (`tests/secrets_dep_check.rs::T15h`) can
/// pin the config→policy mapping directly.
pub fn build_secrets_dependency_policy(
    secrets: &SecretsConfig,
) -> Option<Arc<dyn CallerDependencyPolicy>> {
    if secrets.dependencies.is_empty() {
        return None;
    }
    let by_agent: std::collections::HashMap<String, std::collections::HashSet<String>> = secrets
        .dependencies
        .iter()
        .map(|(agent, names)| (agent.clone(), names.iter().cloned().collect()))
        .collect();
    Some(Arc::new(DeclaredDependencyPolicy::new(by_agent)))
}

/// Register the `agent-secrets::secret-exists` host function, selecting the
/// GATED handler (over a [`DeclaredDependencyPolicy`] built from
/// `secrets.dependencies`) when the operator configured a caller-dependency
/// allowlist, else the permissive handler. Operator-opt-in: an absent/empty
/// `dependencies` map reproduces pre-Wave-18 behaviour byte-for-byte
/// (MODULE-012-AC-15 / REQ-183).
pub(crate) fn register_secrets_capability(
    registry: &dyn advance_runtime::host_registry::HostRegistry,
    store: Arc<SecretStore>,
    secrets: &SecretsConfig,
) {
    match build_secrets_dependency_policy(secrets) {
        Some(policy) => register_agent_secrets_with_policy(registry, store, policy),
        None => register_agent_secrets(registry, store),
    }
}

// ---------------------------------------------------------------------------
// cap-llm "NotWired" fail-closed execution trio (BS-1)
// ---------------------------------------------------------------------------
//
// cap-llm is REGISTERED in BS-1 (host fns linked at L0) but live LLM execution
// is deferred to BS-3. These cli-local stubs let the `LlmGateway` be
// constructed today without shipping a deceptive mock: any actual
// `agent-llm/generate` call fails closed via the executor. BS-3 replaces the
// whole trio with the production reqwest executor (cap-http "Slice E") + the
// real run-loop budget/repetition guard.
//
// On the BS-1 WIT path the budget/repetition stubs are unreachable
// (`HostCallContext.run_id == None`, so `LlmGateway::generate` skips the budget
// preflight); they exist purely as construction args.

/// Fail-closed `HttpExecutor`: every request errors. Superseded in Slice BS-3 by
/// `cap_http::ReqwestHttpExecutor` (wired above); kept as a documented reference
/// fallback for the no-LLM-provider case.
#[allow(dead_code)]
struct NotWiredHttpExecutor;

#[async_trait]
impl HttpExecutor for NotWiredHttpExecutor {
    async fn execute(
        &self,
        _req: &HttpRequest,
        _redirect_check: Arc<dyn RedirectCheck>,
    ) -> Result<HttpResponse, ExecutorError> {
        // "LLM executor not wired (BS-3)". `Transport` is the closest
        // "could not perform HTTP" variant.
        Err(ExecutorError::Transport)
    }
}

// `NotWiredRunBudget` removed (Phase-3 kickoff): the production gateway is now
// wired with the real `RunManager::budget()` (see step 5f), so the fail-closed
// budget stub is dead. The repetition guard stays NotWired (multi-step deferred).

/// No-op `RepetitionGuardCheck`: passes everything. Unreachable on the BS-1 WIT
/// path; present only as a construction arg for the gateway.
struct NotWiredRepetitionGuard;

impl RepetitionGuardCheck for NotWiredRepetitionGuard {
    fn record_tool_call(&self, _agent_id: &str, _sig: ToolCallSignature) -> RepetitionDecision {
        RepetitionDecision::Pass
    }
    fn record_output(&self, _agent_id: &str, _output_hash: OutputHash) -> RepetitionDecision {
        RepetitionDecision::Pass
    }
}

/// Audit-R1 (Slice AG) Codex-Warning 1 fix: on a post-EventBus-construction
/// error, try to gracefully shut down the bus so we don't leak the 4 actor
/// tasks + axum HTTP server. `EventBus::shutdown(self).await` consumes by
/// value, so we reclaim the concrete EventBus via `Arc::try_unwrap` after
/// dropping the dyn-Arc clone. On failure (an Arc we don't know about is
/// alive), accept the leak; process exit reaps via the cancel_token mechanism.
async fn shutdown_event_bus_on_error(
    bus_concrete: Arc<EventBus>,
    event_bus_dyn: Arc<dyn EventBusEmit>,
) {
    drop(event_bus_dyn);
    match Arc::try_unwrap(bus_concrete) {
        Ok(bus) => bus.shutdown().await,
        Err(_arc_still_shared) => {
            // Defensive — should not happen given the controlled call sites.
        }
    }
}

// `yaml_declares_active_capability` was factored into `crate::agent_config`
// (/dev WS-A) as the single source of truth shared with the agent-loop's
// `active_capabilities`; the `declares` closure above calls it there.

// ─────────────────────────────────────────────────────────────────────────
// Wave-20 (build-only) — MODULE-014 turn-end persistence seam.
// ─────────────────────────────────────────────────────────────────────────

/// Construct the MODULE-014 turn-end persistence driver
/// (`cap_skills::SkillTurnPersistenceDriver`) over a shared `SkillStore` + its
/// per-op coordinator, with the default runtime-private flusher. This realises
/// the MODULE-017-AC-22 legs (b) flush-retry-once + (c) commit-failure
/// in-memory rollback + re-enqueue.
///
/// **LIVE (2026-07-01 skill-persist lane; prose de-staled 2026-07-03)**: the
/// driver built here is wrapped by `SkillTurnRuntime` (below) and driven
/// once-per-turn from the scheduler's turn-persistence boundary (the cli
/// serving-loop builder installs `SkillTurnBoundary`). AC-22 is `passed`; the
/// §3.6 (ccc) flip-blockers are closed (2026-07-03 — crash-atomic lease
/// journals, bounded quarantining reconcile, single-track durable retry;
/// delete runs with a sidecar-aware dir-snapshot restore).
fn build_skill_turn_persistence(
    shared_store: Arc<tokio::sync::Mutex<cap_skills::SkillStore>>,
    coordinator: Arc<cap_skills::SkillPersistenceCoordinator>,
) -> cap_skills::SkillTurnPersistenceDriver {
    let flusher: Arc<dyn cap_skills::RuntimePrivateFlush> =
        Arc::new(cap_skills::StoreDraftFlush::new(Arc::clone(&shared_store)));
    cap_skills::SkillTurnPersistenceDriver::new(shared_store, coordinator, flusher)
}
