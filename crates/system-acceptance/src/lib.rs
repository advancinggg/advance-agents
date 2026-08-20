//! Config-driven system-acceptance harness (Slice S2, 2026-06-03) — the shared
//! substrate the 10 parallel e2e tracks consume.
//!
//! [`SystemUnderTest::builder`] boots a wired in-process runtime in a temp git
//! workspace and drives an agent turn end-to-end through the production
//! composition root (`advance_cli::agent_loop`). The builder lets a journey pick:
//!   - a **capability subset** (`fs / memory / skills / llm / grant / tools`) via the
//!     REAL `register_agent_*` provider fns,
//!   - a **grant mode** — `AllowAll` (test bypass) or `Real` (the real cap-grant
//!     `ResolverChain` + `SubsetValidatorImpl` + `PresetRegistry`, witnessing
//!     approve/deny/narrow/revoke),
//!   - an **event sink** — the in-process [`CapturingBus`] or the **real** synchronous
//!     [`advance_event_bus::EventBus`] (JSONL under `<ws>/.runtime/events/jsonl/` + SQLite
//!     at `<ws>/.runtime/events.db`) with a SQLite read-back assertion path,
//!   - an **LLM loopback** backend reachable through the real cap-llm gateway +
//!     cap-http chain (see [`llm_loopback`]).
//!
//! "Add a journey" = a new test file that builds a `SystemUnderTest` with its own
//! config + guest fixture + assertions — **no edits to this file**. Every typed
//! witness has a RAW counterpart ([`SystemUnderTest::events`],
//! [`SystemUnderTest::events_from_db`], [`SystemUnderTest::workspace_root`],
//! [`SystemUnderTest::event_db_path`]) so an unanticipated assertion never forces a
//! harness-maintainer edit.
//!
//! Construction note: the harness self-wires through the proven full-turn-witness
//! path (raw `InMemoryHostRegistry` + `CapabilityInjector::new` — byte-identical to
//! what `RuntimeHostBuilder::build()` constructs internally) reusing the production
//! `register_agent_*` fns; the cap-grant SQLite handle comes from
//! `advance_database::R2d2SqliteIndexHandle::new_in_memory()`. The driven turn goes
//! through `advance_cli::agent_loop::build_agent_loop`, NOT the production
//! `advance start` boot path.
//!
//! Test-only infrastructure — NOT a registered product requirement (waived scope).

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, SystemTime};

use advance_cli::agent_loop::{
    build_agent_loop, PublishingContextAssembler, RunManagerBootstrap, RunSession, SessionRunCell,
    WasmMessageHandler,
};
use advance_cli::crash_cascade::build_crash_cascade_sink;
use advance_cli::workspace_rollback::build_workspace_rollback_sink;
// Sched-harvest 1B: the PRODUCTION RunnableHook (wasm `runnable.run(config)` bridge).
use advance_cli::runnable_hook::WasmRunnableHook;
// Backbone Step 2 (2026-06-07): the real ContextAssemblerImpl wiring helpers, so
// the harness witnesses layered assembly (SYS-AC-007/010) on a real turn.
use advance_cli::context_wiring::{
    build_context_assembler_for_agent, build_context_assembler_for_agent_with_decomposition,
    build_context_assembler_for_agent_with_history, build_context_assembler_for_agent_with_recall,
    build_context_assembler_for_agent_with_skills, build_dual_recall_unified_search,
    build_recall_unified_search, CapDecompositionReader, CePortError, EmbeddingPort,
    EmptyAgentTree, FixedHostFnInventory, HashingEmbedding,
};
use advance_database::{
    IndexRebuild, R2d2IndexRebuildImpl, R2d2RecallImpl, R2d2SqliteIndexHandle, Recall,
    RecallResult, SqliteIndexHandle, DEFAULT_EMBEDDING_DIM,
};
use advance_run_manager::{RunConfig, RunManager};

/// Wave-20 Lane `search` (SYS-AC-009) — the deterministic 768-dim witness embedder
/// for the dual-path (`.with_dual_recall_corpus()`) recall axis. The cap-llm embed
/// seam (CONTRACT-081/MODULE-009) is stubbed in EVERY recall SYS-AC witness; this one
/// gives CONTROLLED geometry so a content doc can be made provably dense-EXCLUDED
/// while still FTS-matchable — the only way to isolate the dense vs sparse legs:
///   - text containing the marker `SPARSEMARK` → `e_anti = [-1, 0, …, 0]` (cosine -1
///     vs a plain query → recall's dense similarity `(1 + cos)/2 = 0.0 < DENSE_THRESHOLD
///     0.3` → the dense leg EXCLUDES it; it surfaces ONLY via `content_fts MATCH`).
///   - everything else (queries, the dense doc, memory) → `e0 = [1, 0, …, 0]` (cosine 1
///     → similarity 1.0 → dense hit).
/// The SAME embedder backs both the corpus ingest and the assembler's query-embed, so
/// the dense geometry is symmetric. Only the EMBEDDING is fixture-controlled — SQLite,
/// FTS5, vec, the dual-path merge, the adapter, and the assembler are all real.
#[derive(Clone, Debug, Default)]
pub struct FixtureEmbedding;

#[async_trait::async_trait]
impl EmbeddingPort for FixtureEmbedding {
    async fn embed(&self, text: &str) -> Result<Vec<f32>, CePortError> {
        let mut v = vec![0.0_f32; DEFAULT_EMBEDDING_DIM];
        v[0] = if text.contains("SPARSEMARK") {
            -1.0
        } else {
            1.0
        };
        Ok(v)
    }
}
use advance_event_bus::{EventBus, EventBusConfig};
use advance_git::GitCommitQueue;
use advance_runtime::capability_injector::CapabilityInjector;
use advance_runtime::circuit_breaker::{CircuitBreakerBus, DefaultCircuitBreakerBus};
use advance_runtime::config::{RuntimeConfigWatcher, WasmConfig};
use advance_runtime::host_registry::{
    HostCallContext, HostCallError, HostRegistry, InMemoryHostRegistry,
};
use advance_runtime::ComponentRuntime;
use advance_scheduler::agent_loop::AgentLoopDriverImpl;

// CAPSTONE P3: the ADR D5 one-shot BoundClientEnvelope evidence surface.
pub mod client_evidence;
use advance_scheduler::hook::{HookError, MessageHandler, RunnableHook};
use advance_scheduler::types::{
    ComponentConfig, ComponentId, RunResult, RunStatus, TriggerContext, WasmInstance,
};
use advance_scheduler::AgentLoopDriver;
// Harvest-triggers slice (SYS-AC 098-114): the REAL scheduler trigger subsystems wired
// into the harness as an opt-in `.with_triggers()` axis (cron emit / trigger-bus dispatch /
// submit admission / catch-up registry), mirroring the existing `drive_*` seam pattern.
use advance_messaging::{
    BreakerSubscriber, ChannelNotifier, MailboxDispatcher, MailboxDispatcherImpl, MailboxStore,
    MessageTrace, OutboundActionSink, StaticChannelAdapterRegistry,
};
use advance_scheduler::cron::{compute_jitter, CronDriver};
use advance_scheduler::trigger_bus::TriggerBusDispatchImpl;
use advance_scheduler::types::SpawnError as SchedSpawnError;
use advance_scheduler::{
    ComponentRegistry, InMemoryComponentSubmitApi, SubmitSubsetGate, COMPONENT_FINISHED_EVENT_TYPE,
};
use advance_shared_types::agent_tree::{
    AgentId, AgentKind, AgentNode, AgentStatus, AgentTreeReader, AgentTreeSnapshot,
    AgentTreeSnapshotData, Capability,
};
use advance_shared_types::capability::{
    CapParams, CapRequest, CapabilityId, GrantDecision, McpToolEntry, ToolEntry,
};
use advance_shared_types::event::Event;
use advance_shared_types::mailbox::{
    AgentAction, DispatchError, Message, MessageContext, MessageKind,
};
use advance_shared_types::outbound::DeliveryReport;
use advance_shared_types::traits::{EventBusEmit, GrantCheck, RepetitionGuardCheck, RunBudget};
use cap_fs::{
    agent_id_for_m004, register_agent_fs, Adv003GitSync, Db030SqliteSync, DefaultAtomicWriter,
    DefaultVirtualPathResolver, GitSync, MetaMaintainer, MetaSchemaLoader, MetaSchemaWatcher,
    ReconcileReport, SqliteSync, StubFileHistoryProvider, VirtualPathResolver, WorkspaceReconciler,
};
use cap_grant::data::{Grant as CapGrant, GrantStatus};
use cap_grant::{
    register_agent_grant, register_cap_grant, validate_capability_subset, AgentGrantBundle,
    AutoDenyResolver, BudgetCheckResolver, CapGrantError, ChannelApprovalPort, ChannelResolver,
    GrantStore, ParentApprovalResolver, PresetRegistry, Resolver, ResolverChain,
    SubsetAutoApproveResolver, SubsetValidator, SubsetValidatorImpl,
};
use cap_memory::{
    register_agent_memory_with_git, BatchExtractor, Components, FailureCooldown,
    InMemorySimilarityIndex, L6CursorStore, MemoryGitRestore, MemoryStore, PostProcessor,
    Reconciler, RusqliteSqliteIndex, SystemClock, DEFAULT_COOLDOWN_SECS,
    DEFAULT_MAX_ACTIVE_PER_AGENT, DEFAULT_THRESHOLD,
};
use tokio_util::sync::CancellationToken;
// Rollback-memory slice: the production composition-root adapter reused verbatim.
use advance_cli::wiring::GitMemoryRestore;
use wit_component::ComponentEncoder;

// --- HF fast-follow imports (2026-06-03) ---
use advance_reply_tracker::{
    register_reply_tracker_host_fns, AwaitSessionManager, AwaitSessionManagerImpl, ManagerOptions,
};
use advance_shared_types::await_session::{OrchestrationError, ReplyResult, SessionId};
use advance_shared_types::security_validator::{
    HttpCapability, HttpError, HttpRequest, HttpResponse, HttpSecurityChain, LeakDetector,
    ScanContext, ScanResult,
};
use cap_channel::{
    register_channel_host, AdapterType, CapParam, ChannelConfig, ChannelError, ChannelHostBundle,
    HttpMethod as ChannelHttpMethod, OutboundConfig, OutboundDispatcher, RawEvent, SubscriptionId,
    SubscriptionManager,
};
use cap_lifecycle::component_submit::{
    ComponentId as LcComponentId, ComponentInfo as LcComponentInfo,
    ComponentState as LcComponentState, ComponentSubmitConfig as LcComponentSubmitConfig,
    ComponentSubmitGate,
};
use cap_lifecycle::SpawnError as LcSpawnError;
use cap_lifecycle::{
    register_agent_decomposition, AgentTreeStore, CapGrantSubsetAdapter, DefaultDecompositionStore,
    DefaultSpawner, SubsetCheckedComponentSubmit,
};
use cap_mcp::{
    register_mcp_client, McpClient, McpServerEntry, McpServersConfig, McpTransport,
    McpTransportSpec, ToolPattern,
};
use std::collections::BTreeMap;
use wasmtime::component::Val;

pub mod llm_loopback;

/// The harness agent's routing id (`agent:`-prefixed for the messaging layer).
pub const AGENT_ID: &str = "agent:harness";
/// The harness agent's workspace directory name (clean — no colon).
pub const AGENT_DIR: &str = "agent";

/// Wave-7 Lane A (SYS-AC 186/187 + the 069 keystone-dial regression gate): the valid L6
/// classification output the `.with_recording_l6()` gateway returns. An empty
/// `cluster_decisions` map makes the production `LlmL6Classifier` default EVERY input cluster
/// to `Consistent`; the two `skill_health` stale/unhealthy entries drive the runnable Step-5a
/// `append_generated` → two skill candidates + Step-5c `skill.candidate_generated` (186/187).
/// Validated against `L6_SCHEMA` by `cap_llm::try_parse_and_validate` inside `classify()`.
/// NOTE: under the DEFAULT empty-stub path no `syntheses/*.md` is produced even with `Consistent`
/// clusters — `attach_l6` wires an EMPTY `InMemoryStalenessProbe`, so every file-ref entry is
/// orphaned and the synthesis 5-gate never passes (this axis alone witnesses only the 069 keystone
/// DIAL via the regression gate, plus 186/187). EXCEPT under `.with_real_l6_probe()` (Wave-10 Lane
/// A): that opts into the real `ResolverStalenessProbe`, so a real-blob FileRef is judged Valid →
/// the 5-gate passes → a synthesis IS written (the SYS-AC-069 flip).
const L6_RECORDING_OUTPUT: &str = r#"{"cluster_decisions":{},"skill_health":[{"skill":"summarize-pr","status":"stale"},{"skill":"triage-issues","status":"unhealthy"}]}"#;

// ---------------------------------------------------------------------------
// Mode enums — the builder axes (the 10-track contract surface)
// ---------------------------------------------------------------------------

/// A capability the harness can register for the agent (1:1 with a `register_agent_*` fn).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Cap {
    Fs,
    Memory,
    Skills,
    Llm,
    Grant,
    Tools,
    Messaging,
}

impl Cap {
    /// The capability id string the runtime/grant layer uses.
    fn id(self) -> &'static str {
        match self {
            Cap::Fs => "fs",
            Cap::Memory => "memory",
            Cap::Skills => "skills",
            Cap::Llm => "llm",
            Cap::Grant => "grant",
            Cap::Tools => "tools",
            Cap::Messaging => "messaging",
        }
    }
}

/// Grant enforcement mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GrantMode {
    /// Unconditional `Allow` (test bypass; the BS-3 default).
    AllowAll,
    /// The real cap-grant chain (`GrantCheckImpl` at L1 + the agent-grant WIT host
    /// fns), composed per [`GrantChain`].
    Real,
}

/// The resolver-chain composition for [`GrantMode::Real`] (the chain — not the
/// preset — decides auto-approve vs always-deny).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GrantChain {
    /// The 5-resolver production "supervised" chain (auto-approves subset requests).
    Supervised,
    /// `[AutoDeny]` — every `request-capability` is denied (witnesses deny).
    Restrict,
}

/// Event sink mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EventSink {
    /// In-process [`CapturingBus`] (`Mutex<Vec<Event>>`); read via
    /// [`SystemUnderTest::events`]. The default.
    Capturing,
    /// The real synchronous [`advance_event_bus::EventBus`] (JSONL + SQLite, inline
    /// writes); read via [`SystemUnderTest::events_from_db`]. Run such journeys under
    /// `#[tokio::test(flavor = "multi_thread")]`.
    RealBus,
}

/// LLM backend mode.
pub enum LlmMode {
    /// No LLM gateway registered (the default).
    Off,
    /// A deterministic single-200 loopback backend reachable through the real cap-llm
    /// gateway + cap-http chain (see [`llm_loopback`]); the gateway is exposed via
    /// [`SystemUnderTest::llm_gateway`].
    Loopback(llm_loopback::LoopbackScript),
    /// A scriptable FIFO loopback backend (HF-2) — serves a queue of `(status, body)`
    /// responses (the last replays once drained) so a journey can script `429-then-200`
    /// retry, `4xx` non-retryable, or `invalid-then-valid` structured-output sequences.
    /// Combine with [`SystemUnderTestBuilder::budget`] / [`SystemUnderTestBuilder::repetition`]
    /// and witness `llm.*` events through [`SystemUnderTest::events`].
    LoopbackScripted(Vec<llm_loopback::ScriptedResponse>),
}

// ---------------------------------------------------------------------------
// HF fast-follow: public builder axes + types
// ---------------------------------------------------------------------------

/// A node declared for a `.agents([...])` multi-agent tree. `id` is the
/// canonical `agent:<body>` routing id (the messaging/await/fs convention); the
/// harness derives the bare `<body>` id for the cap-lifecycle `AgentTreeStore`
/// spawn witness (the two ID conventions are deliberately kept separate — see
/// the crate README "HF fast-follow blockers").
#[derive(Clone, Debug)]
pub struct AgentSpec {
    pub id: String,
    pub kind: AgentKind,
    pub parent: Option<String>,
    pub caps: Vec<Cap>,
    /// Small-witness 2026-06-11 — param-carrying capabilities seeded onto the
    /// node (e.g. `fs { write-paths: [...] }`). These are what the REAL
    /// `CapGrantSubsetAdapter` reads as the PARENT set when `spawn_child` /
    /// `spawn_sub` subset-checks a child's request. Distinct from `caps`
    /// (which picks the registered host-fn surfaces). Empty (every pre-slice
    /// site) ⇒ the subset gate passes vacuously — byte-compatible behavior.
    pub capabilities: Vec<Capability>,
}

/// A scripted in-process MCP server for `.with_mcp_transports([...])`. The
/// transport is never spawned — an injected `Arc<dyn McpTransport>` keyed by
/// `server_id` bypasses the real stdio/http spawn; `reply` is the canned
/// `tools/call` result [`SystemUnderTest::drive_mcp_tool`] returns.
#[derive(Clone)]
pub struct McpServerSpec {
    server_id: String,
    tools: Vec<String>,
    reply: Vec<u8>,
}

impl McpServerSpec {
    /// A server `server_id` exposing exactly `tools` (Literal tool-patterns).
    /// Chain [`Self::reply`] to script the `tools/call` result.
    pub fn scripted(server_id: &str, tools: &[&str]) -> Self {
        Self {
            server_id: server_id.to_string(),
            tools: tools.iter().map(|t| t.to_string()).collect(),
            reply: Vec::new(),
        }
    }
    /// Set the canned `tools/call` result bytes this server returns.
    pub fn reply(mut self, bytes: &[u8]) -> Self {
        self.reply = bytes.to_vec();
        self
    }
}

/// One captured outbound `send-raw` request, recorded at the test
/// `HttpSecurityChain` seam (`.with_channel_capture()`).
#[derive(Clone, Debug)]
pub struct CapturedOutbound {
    pub agent_id: String,
    pub method: advance_shared_types::security_validator::HttpMethod,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

// --- internal test-only seams (capture / gate-bypass / canned reply) ---

/// Capturing `HttpSecurityChain`: records each outbound request (the capture
/// seam for `send-raw`) and returns a benign 200 so `OutboundDispatcher::dispatch`
/// succeeds. Replaces the production `DefaultHttpSecurityChain` for the harness.
struct CapturingChain {
    captured: Arc<Mutex<Vec<CapturedOutbound>>>,
}

#[async_trait::async_trait]
impl HttpSecurityChain for CapturingChain {
    async fn execute(
        &self,
        agent_id: &str,
        req: HttpRequest,
        _cap: &HttpCapability,
    ) -> Result<HttpResponse, HttpError> {
        self.captured.lock().unwrap().push(CapturedOutbound {
            agent_id: agent_id.to_string(),
            method: req.method.clone(),
            url: req.url.clone(),
            headers: req.headers.clone(),
            body: req.body.clone(),
        });
        Ok(HttpResponse {
            status: 200,
            headers: Vec::new(),
            body: Vec::new(),
        })
    }
}

/// No-op `LeakDetector` for the in-process MCP client (no scanning needed for a
/// scripted transport). cap-mcp's `LeakDetector` has no reusable library no-op.
struct NoOpLeakDetector;
impl LeakDetector for NoOpLeakDetector {
    fn scan(&self, _text: &str, _context: ScanContext) -> ScanResult {
        ScanResult::Clean
    }
    fn scan_headers(&self, _headers: &[(String, String)]) -> ScanResult {
        ScanResult::Clean
    }
}

// Small-witness 2026-06-11: the former `AlwaysOkSubsetGate` stub is GONE — the
// `.agents()` spawner now wires the REAL production `CapGrantSubsetAdapter`
// (cap-lifecycle → cap-grant `validate_capability_subset` → `SubsetValidatorImpl`,
// CONTRACT-122). Existing tests are unaffected: every pre-slice spawn site
// requests EMPTY child capabilities, which the real validator passes vacuously
// (no child cap to check). Non-empty caps now get REAL param-level subset
// enforcement (SYS-AC-046/048).

/// In-process scripted MCP transport — returns canned bytes for any tool call.
struct ScriptedMcpTransport {
    server_id: String,
    reply: Vec<u8>,
}

#[async_trait::async_trait]
impl McpTransport for ScriptedMcpTransport {
    async fn invoke(
        &self,
        _method: &str,
        _params: serde_json::Value,
    ) -> Result<Vec<u8>, cap_mcp::McpError> {
        Ok(self.reply.clone())
    }
    fn server_id(&self) -> &str {
        &self.server_id
    }
}

/// Multi-node agent tree for `.agents([...])` — the messaging/await/fs view
/// (canonical `agent:` ids). [`OneAgentTree`] generalized to N nodes with real
/// parent/children/sibling adjacency for `validate_routing`.
struct HarnessAgentTree {
    nodes: Vec<AgentNode>,
    parent_of: HashMap<String, String>,
    children_of: HashMap<String, Vec<String>>,
}

impl HarnessAgentTree {
    /// GAP-2 (SYS-J-57): assign each node a DISTINCT on-disk territory NESTED
    /// under its parent's, rooted at the RAW `workspace_root` git workdir (NOT
    /// `store.workspace_root()`'s canonicalized form — so a `git.commit`'s
    /// `affected_paths` stay repo-relative as `<bare-id>/…` /
    /// `<parent-bare>/children/<bare-id>/…`, disjoint per node). Mirrors the
    /// `lib.rs::build_agents_handle` LAYOUT, and creates the dirs so the
    /// resolver's territory + Rule-2 lookups resolve to real paths. Replaces the
    /// previous single shared `default_workspace.clone()` per node — without
    /// distinct territories two agents' writes would collide on one path, making
    /// SYS-AC-179's non-overlapping-trees assertion vacuous.
    fn new(specs: &[AgentSpec], workspace_root: &std::path::Path) -> Self {
        let bare = |id: &str| id.strip_prefix("agent:").unwrap_or(id).to_string();
        // Territory-containment + uniqueness guard. The production
        // `AgentTreeStore::insert` canonicalizes each workspace_path and rejects
        // ancestor-escape (the agent_tree.rs producer contract); `HarnessAgentTree`
        // bypasses that, joining `bare(id)` straight into a `create_dir_all` path.
        // Without this guard a spec id whose bare form carries a path separator /
        // `..` (e.g. "agent:../escape") would materialize a dir OUTSIDE
        // workspace_root and set the resolver's workspace_path there; and a
        // duplicate / prefix-colliding id would alias one on-disk territory —
        // silently vacating SYS-AC-179's distinct-territory disjointness invariant.
        // Reject loudly (a test-setup error, not a guest-reachable surface). The
        // `safe` predicate mirrors the production `cap_lifecycle::validate_agent_id`
        // charset (`^[A-Za-z0-9_-]{1,64}$`): a single path-component bare id can't
        // traverse via `Path::join`, and rejecting '.'-prefixed / non-alnum forms
        // also blocks a territory aliasing the repo's own `.git` / `.advance` /
        // `.agent` dirs and caps length (so the downstream ComponentId::new can't
        // overflow). Dedup on the BARE form (not the raw id) so distinct raw ids
        // that collide after prefix-strip (e.g. "agent:a" vs "a") are rejected too —
        // either collision would alias one on-disk territory + drop a node driver,
        // silently vacating SYS-AC-179's distinct-territory disjointness.
        {
            let mut seen = std::collections::HashSet::new();
            let safe = |b: &str| {
                !b.is_empty()
                    && b.len() <= 64
                    && b.chars()
                        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
            };
            for s in specs {
                let bid = bare(&s.id);
                assert!(
                    safe(&bid),
                    "HarnessAgentTree: unsafe agent id {:?} — bare form {:?} must match [A-Za-z0-9_-]{{1,64}} (mirrors cap_lifecycle::validate_agent_id; no path separators, dotfiles, ':', or over-length)",
                    s.id, bid
                );
                if let Some(p) = &s.parent {
                    assert!(
                        safe(&bare(p)),
                        "HarnessAgentTree: unsafe parent id {:?} for node {:?}",
                        p,
                        s.id
                    );
                }
                assert!(
                    seen.insert(bid.clone()),
                    "HarnessAgentTree: agent id {:?} aliases another node's bare territory id {:?} in .agents() (would share one on-disk territory + drop a node driver)",
                    s.id, bid
                );
            }
        }
        let nodes: Vec<AgentNode> = specs
            .iter()
            .map(|s| {
                let bid = bare(&s.id);
                let dir = match &s.parent {
                    Some(p) => workspace_root.join(bare(p)).join("children").join(&bid),
                    None => workspace_root.join(&bid),
                };
                std::fs::create_dir_all(&dir).expect("create harness agent territory");
                AgentNode {
                    id: AgentId(s.id.clone()),
                    kind: s.kind.clone(),
                    parent: s.parent.clone().map(AgentId),
                    workspace_path: dir,
                    capabilities: s.capabilities.clone(),
                    template_ref: None,
                    status: AgentStatus::Active,
                }
            })
            .collect();
        let mut parent_of = HashMap::new();
        let mut children_of: HashMap<String, Vec<String>> = HashMap::new();
        for s in specs {
            if let Some(p) = &s.parent {
                parent_of.insert(s.id.clone(), p.clone());
                children_of.entry(p.clone()).or_default().push(s.id.clone());
            }
        }
        Self {
            nodes,
            parent_of,
            children_of,
        }
    }
}

impl AgentTreeReader for HarnessAgentTree {
    fn parent_of(&self, id: &str) -> Option<String> {
        self.parent_of.get(id).cloned()
    }
    fn children_of(&self, id: &str) -> Vec<String> {
        self.children_of.get(id).cloned().unwrap_or_default()
    }
    fn siblings_of(&self, id: &str) -> Vec<String> {
        match self.parent_of.get(id) {
            Some(p) => self
                .children_of
                .get(p)
                .map(|kids| kids.iter().filter(|k| k.as_str() != id).cloned().collect())
                .unwrap_or_default(),
            None => Vec::new(),
        }
    }
    fn agent_exists(&self, id: &str) -> bool {
        self.nodes.iter().any(|n| n.id.0 == id)
    }
    fn agent_kind(&self, id: &str) -> Option<AgentKind> {
        self.nodes
            .iter()
            .find(|n| n.id.0 == id)
            .map(|n| n.kind.clone())
    }
    fn capabilities(&self, _id: &str) -> Vec<Capability> {
        Vec::new()
    }
}

impl AgentTreeSnapshot for HarnessAgentTree {
    /// GAP-1 (SYS-J-57): a faithful mirror of `AgentTreeStore::snapshot()`
    /// (cap-lifecycle tree.rs:430-457) — populated `parent_of` / `children_of` /
    /// `peer_slug_map` + a non-zero `revision`, keyed by the CANONICAL `agent:`
    /// ids the fs-resolver is invoked with (`HostCallContext.agent_id`). The
    /// previous empty maps silently broke `resolve_child_read` /
    /// `resolve_slug_read` / the Rule-2 child-territory write-block (the resolver
    /// returns NotFound on a miss for anti-fingerprinting, so the break was
    /// silent). NOTE: [`OneAgentTree`] deliberately keeps empty maps — a lone root
    /// has no ancestry — so the single-agent path stays byte-identical.
    fn snapshot(&self) -> AgentTreeSnapshotData {
        let mut parent_of: HashMap<AgentId, Option<AgentId>> = HashMap::new();
        let mut children_of: HashMap<AgentId, Vec<AgentId>> = HashMap::new();
        for n in &self.nodes {
            parent_of.insert(n.id.clone(), n.parent.clone());
            if let Some(p) = &n.parent {
                children_of.entry(p.clone()).or_default().push(n.id.clone());
            }
        }
        // Determinism: sort each child list by id (mirrors tree.rs:442-443).
        for kids in children_of.values_mut() {
            kids.sort_by(|a, b| a.0.cmp(&b.0));
        }
        // peer_slug_map: mirror build_peer_slug_map (tree.rs:460-499) — keyed by a
        // caller AgentId, slug = a template_ref shared with a sibling. Harness
        // nodes carry `template_ref: None` (AgentSpec has no template_ref field),
        // so this is empty today; the loop populates faithfully if template_ref is
        // ever seeded (no slug witness in this slice — SYS-J-56 is out of scope).
        let mut peer_slug_map: HashMap<AgentId, HashMap<String, AgentId>> = HashMap::new();
        for n in &self.nodes {
            let (parent, tmpl) = match (&n.parent, &n.template_ref) {
                (Some(p), Some(t)) => (p, t),
                _ => continue,
            };
            if let Some(sibs) = children_of.get(parent) {
                let mut peer_map: HashMap<String, AgentId> = HashMap::new();
                for s in sibs {
                    if s == &n.id {
                        continue;
                    }
                    if let Some(sn) = self.nodes.iter().find(|x| &x.id == s) {
                        if sn.template_ref.as_deref() == Some(tmpl.as_str()) {
                            peer_map.insert(tmpl.clone(), s.clone());
                        }
                    }
                }
                if !peer_map.is_empty() {
                    peer_slug_map.insert(n.id.clone(), peer_map);
                }
            }
        }
        AgentTreeSnapshotData {
            nodes: self.nodes.clone(),
            parent_of,
            children_of,
            peer_slug_map,
            // Non-zero, immutable post-construction (the harness tree is built
            // once); consumers use revision only for cache invalidation.
            revision: 1,
        }
    }
}

/// Channel-capture handles stored on the SUT when `.with_channel_capture()` is set.
struct ChannelCapture {
    manager: Arc<SubscriptionManager>,
    sub_id: SubscriptionId,
    captured: Arc<Mutex<Vec<CapturedOutbound>>>,
}

/// Multi-agent spawn/await handles stored on the SUT when `.agents()` is set.
struct AgentsHandle {
    tree_store: AgentTreeStore,
    spawner: Arc<DefaultSpawner>,
    await_mgr: Arc<AwaitSessionManagerImpl>,
}

/// Build the bare-id `AgentTreeStore` + `DefaultSpawner` (spawn witness) and the
/// `AwaitSessionManagerImpl` + reply-tracker host fns (await witness) for `.agents()`.
///
/// `deadlock_gate` (sched-harvest 1A, SYS-AC-168): when set, the REAL
/// cap-lifecycle `AgentTreeStore` built here — the production MODULE-005
/// `AgentTreeSnapshot` provider, bare-id keyed with explicit `None` roots,
/// exactly the `forms_cycle` contract — is injected as
/// `ManagerOptions.agent_tree`, activating the reply-tracker AC-09 admission
/// gate. `false` (default) keeps `agent_tree: None` — the gate is skipped
/// entirely and every pre-slice await witness is byte-identical.
/// (Deliberately NOT the harness `HarnessAgentTree`: its `snapshot()` keeps
/// the canonical-id fs-resolver view with empty ancestry maps; the deadlock
/// gate's snapshot source is the bare-id MODULE-005 store, mirroring
/// production.)
fn build_agents_handle(
    specs: &[AgentSpec],
    workspace_root: &std::path::Path,
    dispatcher: Arc<MailboxDispatcherImpl>,
    reply_bus: Arc<dyn EventBusEmit>,
    registry: &dyn HostRegistry,
    deadlock_gate: bool,
) -> AgentsHandle {
    // Bare-id store (cap-lifecycle rejects `agent:` ids). Each node's
    // workspace_path must EXIST + be under the canonical workspace_root (insert
    // canonicalizes), so create the dirs first.
    let store = AgentTreeStore::new(workspace_root.to_path_buf()).expect("agent tree store");
    let canonical_root = store.workspace_root().to_path_buf();
    let bare = |id: &str| id.strip_prefix("agent:").unwrap_or(id).to_string();
    for spec in specs {
        let bid = bare(&spec.id);
        let parent_bare = spec.parent.as_ref().map(|p| bare(p));
        let dir = match &parent_bare {
            Some(p) => canonical_root.join(p).join("children").join(&bid),
            None => canonical_root.join(&bid),
        };
        std::fs::create_dir_all(&dir).expect("create agent workspace dir");
        let node = AgentNode {
            id: AgentId(bid.clone()),
            kind: spec.kind.clone(),
            parent: parent_bare.clone().map(AgentId),
            workspace_path: dir,
            // Small-witness 2026-06-11: seed the param-carrying caps — the
            // spawner's subset gate reads `parent.capabilities` from THIS node.
            capabilities: spec.capabilities.clone(),
            template_ref: None,
            status: AgentStatus::Active,
        };
        match &parent_bare {
            None => store.insert_root(node).expect("insert root"),
            Some(p) => store
                .insert_child(&AgentId(p.clone()), node)
                .expect("insert child"),
        }
    }
    // Small-witness 2026-06-11: the REAL production subset gate (CONTRACT-122).
    let spawner = Arc::new(DefaultSpawner::new(
        store.clone(),
        Arc::new(CapGrantSubsetAdapter::new()),
    ));
    // Deterministic + unique session ids (hf-await-0, hf-await-1, ...): the
    // first session in a smoke is `hf-await-0` (no test-only feature needed).
    let counter = Arc::new(std::sync::atomic::AtomicU64::new(0));
    // Sched-harvest 1A (SYS-AC-168): the AC-09 deadlock gate's snapshot
    // source is the REAL store built above (already populated with the
    // bare-id tree). `None` (default) → gate skipped, slice-A behavior.
    let agent_tree: Option<Arc<dyn AgentTreeSnapshot>> = if deadlock_gate {
        Some(Arc::new(store.clone()) as Arc<dyn AgentTreeSnapshot>)
    } else {
        None
    };
    let await_mgr = Arc::new(AwaitSessionManagerImpl::new(
        dispatcher as Arc<dyn MailboxDispatcher>,
        ManagerOptions {
            session_id_factory: Arc::new(move || {
                SessionId(format!(
                    "hf-await-{}",
                    counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
                ))
            }),
            agent_tree,
            // Wave-15 Lane A: wire the SUT bus into the manager so its
            // in-boundary orchestration.deadlock_rejected (SYS-AC-169) +
            // orchestration.await_idle_timeout (SYS-AC-252) emits land in the
            // same bus `register_reply_tracker_host_fns` registers below (Real
            // → events.db, read back by `assert_db_event`). Cloned because
            // `reply_bus` is moved into the host-fn registration on the next
            // line. Causally gated (no deadlock gate / no idle timeout ⇒ no
            // emit), so existing `.agents()` tests are unaffected.
            event_emitter: Some(reply_bus.clone()),
            ..ManagerOptions::default()
        },
    ));
    register_reply_tracker_host_fns(registry, await_mgr.clone(), reply_bus);
    AgentsHandle {
        tree_store: store,
        spawner,
        await_mgr,
    }
}

// ---------------------------------------------------------------------------
// AllowAll grant bypass + CapturingBus + OneAgentTree (BS-3 building blocks)
// ---------------------------------------------------------------------------

struct AllowAll;
impl GrantCheck for AllowAll {
    fn check(&self, _: &str, _: &str, _: &str, _: &CapParams) -> GrantDecision {
        GrantDecision::Allow
    }
}

/// Captures every emitted `Event` so journeys can witness `msg.received` etc.
pub struct CapturingBus {
    events: Mutex<Vec<Event>>,
}
impl CapturingBus {
    fn new() -> Self {
        Self {
            events: Mutex::new(Vec::new()),
        }
    }
}
impl EventBusEmit for CapturingBus {
    fn emit(&self, event: Event) {
        self.events.lock().unwrap().push(event);
    }
}

struct OneAgentTree {
    nodes: Vec<AgentNode>,
}
impl OneAgentTree {
    fn new(workspace: PathBuf) -> Self {
        Self {
            nodes: vec![AgentNode {
                id: AgentId(AGENT_ID.to_string()),
                kind: AgentKind::Root,
                parent: None,
                workspace_path: workspace,
                capabilities: Vec::new(),
                template_ref: None,
                status: AgentStatus::Active,
            }],
        }
    }
}
impl AgentTreeReader for OneAgentTree {
    fn parent_of(&self, _: &str) -> Option<String> {
        None
    }
    fn children_of(&self, _: &str) -> Vec<String> {
        Vec::new()
    }
    fn siblings_of(&self, _: &str) -> Vec<String> {
        Vec::new()
    }
    fn agent_exists(&self, id: &str) -> bool {
        self.nodes.iter().any(|n| n.id.0 == id)
    }
    fn agent_kind(&self, id: &str) -> Option<AgentKind> {
        self.nodes
            .iter()
            .find(|n| n.id.0 == id)
            .map(|n| n.kind.clone())
    }
    fn capabilities(&self, _: &str) -> Vec<Capability> {
        Vec::new()
    }
}
impl AgentTreeSnapshot for OneAgentTree {
    fn snapshot(&self) -> AgentTreeSnapshotData {
        AgentTreeSnapshotData {
            nodes: self.nodes.clone(),
            parent_of: HashMap::new(),
            children_of: HashMap::new(),
            peer_slug_map: HashMap::new(),
            revision: 0,
        }
    }
}

/// Wave-10 Lane A (SYS-AC-069): the git blob OID (`git hash-object` semantics) of `content`,
/// computed content-only via the production [`advance_git::blob_oid_of_file`] over a temp file.
/// Lets a test compute a FileRef's `blob_id` BEFORE `build()` (when the workspace doesn't exist
/// yet) and seed the SAME bytes via [`SystemUnderTestBuilder::with_seeded_workspace_file`] — the
/// OID is identical because it depends only on content, so the seeded file-ref then resolves to a
/// real, matching blob under the real `.with_real_l6_probe()` staleness probe.
pub fn blob_oid_of_bytes(content: &[u8]) -> String {
    let tmp = tempfile::NamedTempFile::new().expect("temp file for blob hash");
    std::fs::write(tmp.path(), content).expect("write temp blob-hash file");
    advance_git::blob_oid_of_file(tmp.path()).expect("a written temp file always hashes")
}

/// Wave-10 Lane A (SYS-AC-069): write each seeded `(vpath, content)` to `workspace_root/<vpath>`
/// (the territory root the `with_real_l6_probe` resolver tree maps `AGENT_ID` to — NOT `AGENT_DIR`)
/// and commit them in ONE `[seed]` commit (distinct from `[turn]`/`[l6]` so commit-filter assertions
/// are unaffected). Handles the unborn HEAD `bootstrap_repo_at` leaves (the seed is the first commit
/// on `main`). Test-infra only — `system-acceptance` already depends on `git2` + owns the workspace;
/// this never crosses a product module boundary.
fn commit_seeded_workspace_files(workspace_root: &std::path::Path, files: &[(String, Vec<u8>)]) {
    for (vpath, content) in files {
        let physical = workspace_root.join(vpath);
        if let Some(parent) = physical.parent() {
            std::fs::create_dir_all(parent).expect("create seeded-file parent dir");
        }
        std::fs::write(&physical, content).expect("write seeded workspace file");
    }
    let repo = git2::Repository::open(workspace_root).expect("open workspace repo for seed commit");
    let mut index = repo.index().expect("repo index");
    for (vpath, _) in files {
        index
            .add_path(std::path::Path::new(vpath))
            .unwrap_or_else(|e| panic!("git add seeded file {vpath}: {e}"));
    }
    index.write().expect("write seed index");
    let tree_oid = index.write_tree().expect("write seed tree");
    let tree = repo.find_tree(tree_oid).expect("find seed tree");
    let sig =
        git2::Signature::now("harness-seed", "seed@harness.test").expect("git seed signature");
    // Unborn HEAD after `bootstrap_repo_at` → the seed is the FIRST commit (no parent); otherwise
    // chain onto HEAD. `Some("HEAD")` births `refs/heads/main` on the unborn case.
    let head_commit = repo.head().ok().and_then(|h| h.peel_to_commit().ok());
    let parents: Vec<&git2::Commit> = head_commit.iter().collect();
    repo.commit(
        Some("HEAD"),
        &sig,
        &sig,
        "[seed] file-ref blob",
        &tree,
        &parents,
    )
    .expect("seed commit");
}

/// One git commit observed in the workspace repo.
#[derive(Clone, Debug)]
pub struct CommitInfo {
    pub message: String,
    /// `true` when the commit message has the `[turn]` `CommitType::Turn` prefix.
    pub is_turn: bool,
    pub parent_count: usize,
    /// Small-witness 2026-06-11 (SYS-AC-003) — every blob path in this commit's
    /// TREE (recursive walk, workspace-root-relative, e.g. `agent/j01.txt`), so a
    /// test asserts the turn commit's tree CONTAINS the turn's file writes.
    pub tree_paths: Vec<String>,
}

/// A row read back from the real EventBus SQLite `events` table (mirrors
/// `advance_event_bus::query_api::EventRow`).
#[derive(Clone, Debug)]
pub struct DbEventRow {
    pub id: String,
    pub timestamp: String,
    pub agent_id: Option<String>,
    pub trace_id: Option<String>,
    pub event_type: String,
    pub payload: Option<String>,
}

/// The concrete event sink, kept alive for the SUT's lifetime.
enum BusHandle {
    Capturing(Arc<CapturingBus>),
    Real(Arc<EventBus>),
}
impl BusHandle {
    fn as_dyn(&self) -> Arc<dyn EventBusEmit> {
        match self {
            BusHandle::Capturing(b) => b.clone() as Arc<dyn EventBusEmit>,
            BusHandle::Real(b) => b.clone() as Arc<dyn EventBusEmit>,
        }
    }
}

// ---------------------------------------------------------------------------
// Builder
// ---------------------------------------------------------------------------

/// Configures a [`SystemUnderTest`]. Every axis is defaulted so an fs-only message
/// turn stays a one-liner; see [`SystemUnderTest::builder`].
pub struct SystemUnderTestBuilder {
    caps: Vec<Cap>,
    grant: GrantMode,
    grant_chain: GrantChain,
    events: EventSink,
    llm: LlmMode,
    /// SYS-J-72: opt-in CONTRACT-234/235 tee + Client API bind. Default false.
    with_delta_tee: bool,
    /// Optional hub timing override used only when `with_delta_tee` is set.
    delta_tee_timing: Option<advance_client_api::DeltaTiming>,
    agent_id: String,
    // HF-2 resilience knobs (default None → loopback gateway uses AllowAllBudget /
    // NoOpRepetitionGuard; only meaningful when `.llm(Loopback*)` is set).
    budget: Option<Arc<dyn RunBudget>>,
    repetition: Option<Arc<dyn RepetitionGuardCheck>>,
    // MODULE-013 resolver witnesses: default None keeps historical harness
    // behavior; opt-in tests can inject the same seams production uses.
    grant_resolver_budget: Option<Arc<dyn RunBudget>>,
    grant_channel_approval: Option<Arc<dyn ChannelApprovalPort>>,
    grant_presets: Option<Arc<PresetRegistry>>,
    grant_run_session: Option<(Arc<RunManager>, RunConfig)>,
    grant_sweeper_interval: Option<Duration>,
    // HF fast-follow axes (all default to "off" → BS-3 path byte-identical).
    agents: Vec<AgentSpec>,
    channel_capture: bool,
    mcp_servers: Vec<McpServerSpec>,
    // Backbone Step 3: persistent cap-memory store axes. `memory_dir` None →
    // default `<workspace_root>/.agent/memory` (production-mirroring subpath, fresh
    // per build → observably equivalent to the prior in-memory `new()` for the
    // event-only existing tests). Pass a CALLER-owned dir (surviving SUT drop) to
    // witness cross-restart persistence across two SUTs. `memory_cap` None →
    // `DEFAULT_MAX_ACTIVE_PER_AGENT`; set small (e.g. 1) to witness the entry cap.
    memory_dir: Option<PathBuf>,
    memory_cap: Option<usize>,
    // Stage-C harvest pass-1 (SYS-AC 006/008/065/067/213/254): opt-in default-off
    // axis wiring the LIVE memory read+write path SAT-A/SAT-B put in cli — the
    // history-aware assembler (real L2/L3/L4 readers over `<memory_dir>/tasks/{task}/`)
    // + the components-backed PostProcessor (LlmBatchExtractor over the loopback
    // gateway → on-disk summary/turn-index writeback + durable RusqliteSqliteIndex).
    // Default false → no-history assembler + trace-only PostProcessor::new()
    // (byte-identical). Effective ONLY with BOTH `Cap::Memory` and `.llm(Loopback*)`
    // (mirrors production `build_live_post_processor`'s both-present gate;
    // memory-or-LLM-absent ⇒ trace-only, no divergence).
    with_live_memory: bool,
    // Stage-A notify slice (SYS-AC-174): opt-in mailbox capacity override. Default
    // None → the hard-coded 64. Set small (e.g. 1) to provoke `MailboxFull`
    // backpressure on the notify path. Default None → MailboxStore::new(64) →
    // every existing build byte-identical.
    mailbox_cap: Option<usize>,
    // Backbone Step 4: opt-in accumulating outbound-action capture. Default false →
    // `build_agent_loop(.., None)` (gate-only, the existing harness behaviour).
    reply_capture: bool,
    // Wave-18 Lane-3 (MODULE-006-AC-02 infra): opt-in `channel_id → adapter_agent_id`
    // mappings. Default empty → the dispatcher uses `MailboxDispatcherImpl::new`
    // (EmptyChannelAdapterRegistry). notify21 keeps the `notify-channel` host-fn
    // registered even without mappings so guests importing the full notify interface
    // can link; calls then fail at dispatcher resolution (`channel_unknown`). When
    // non-empty, build the dispatcher with `new_full` over a
    // `StaticChannelAdapterRegistry` so `sys_j30_notify_channel` can drive channel
    // delivery end-to-end.
    channel_adapters: Vec<(String, String)>,
    // Harvest-triggers slice (SYS-AC 098-114): opt-in REAL scheduler trigger subsystems
    // (cron / trigger-bus / submit / catch-up registry) sharing the SUT event sink.
    // Default false → existing builds byte-identical (no registry/SQLite open).
    with_triggers: bool,
    // Lifecycle-harvest slice (SYS-AC 152-154/237): opt-in REAL
    // `RuntimeConfigWatcher` over a seeded `<ws>/.advance/runtime-config.yaml`,
    // emitting `runtime.config_reloaded` into the SUT event sink. Default false
    // → existing builds byte-identical. Requires the default Capturing sink
    // (build() panics on RealBus — blocking emitters are forbidden by the
    // watcher's emitter contract).
    runtime_config_watch: bool,
    // Lifecycle-harvest slice (SYS-AC 259-261): opt-in REAL `MetaSchemaWatcher`
    // over a seeded `<ws>/.advance/meta-schema.yaml`; the SAME loader is
    // registered into `register_agent_fs` (replacing the empty-path default),
    // so post-reload `fs_write` auto-populate uses the live schema. Default
    // false → existing builds byte-identical. Requires `Cap::Fs` + the
    // Capturing sink (build() panics otherwise).
    meta_schema_watch: bool,
    // Sched-harvest 1A (SYS-AC-110): opt-in REAL submitter-grant subset gate on
    // the `.with_triggers()` submit admission path — the MODULE-014 §1.7
    // production-adapter recipe (`validate_capability_subset` over
    // `GrantStore::list_by_grantee`, Active-filter + CSV→array re-projection +
    // `agent:`-prefix duality) composed over the SUT's own real `GrantStore`.
    // Default false → submit rule 5 stays `None` (byte-identical pre-seam
    // behavior). Requires `.with_triggers()` + `GrantMode::Real`.
    submit_subset_gate: bool,
    // Sched-harvest 1A (SYS-AC-168): opt-in activation of the reply-tracker
    // AC-09 await-deadlock admission gate — injects the REAL cap-lifecycle
    // `AgentTreeStore` (the same bare-id store the `.agents()` spawner uses)
    // as `ManagerOptions.agent_tree`. Default false → `agent_tree: None`
    // (gate inert; every pre-slice await witness byte-identical). Requires
    // `.agents()`.
    await_deadlock_gate: bool,
    // Wave-18 Lane 4 (SYS-AC-030): opt-in wiring of the production crash-cascade
    // sink (cli `build_crash_cascade_sink`) into every `.agents()` node driver. On a
    // served child's real guest trap, `handle_trap(Crash)` → the sink → cap-lifecycle
    // `handle_crash` → `notify_parent_crash` → the parent's mailbox. Built from the
    // `AgentsHandle.tree_store` (bare) + the shared `MailboxStore` with the symmetric
    // resolver `|b| format!("agent:{b}")`. Default false → drivers keep `crash_sink:
    // None` (byte-identical; every existing `.agents()` test unaffected). Requires
    // `.agents()`.
    with_crash_cascade: bool,
    // Wave-19 (SYS-AC-028): opt-in to wire the production WorkspaceRollbackSink (cli
    // `build_workspace_rollback_sink`) into every `.agents()` node driver, AND to perform the
    // F1a/F1b setup (write each leaf agent's `.agent/config.yaml` with an explicit `agent_id`
    // + commit a baseline so the pre-turn checkpoint has a born HEAD). Default `false` →
    // drivers keep `workspace_rollback_sink: None` (byte-identical). Requires `.agents()` + Fs.
    with_workspace_rollback: bool,
    // Stage-B SQLite/boot-reconcile slice (SYS-AC 146/147/148/233/149/151/260):
    // opt-in REAL cap-fs triple-sync trio — wires `register_agent_fs`'s
    // (db_sync + workspace_root + agent_tree) to a fresh in-memory
    // `R2d2SqliteIndexHandle`, so every fs_write fans out to a real SQLite
    // meta_index/content_index/content_fts, and enables `boot_reconcile()` +
    // `fts_recall()`. Default false → the trio stays None,None,None (byte-identical
    // to every prior build). Requires `Cap::Fs`.
    with_sqlite_index: bool,
    // Harvest-wave slice (SYS-AC-236): opt-in fault-injection on the cap-fs git
    // leg. When true, `register_agent_fs` is wired with a `FailingGitSync`
    // (always `Err`) in place of the production `Adv003GitSync`, so a real
    // `fs.write` exercises the production fail-soft branch (`git_sync_after_write`
    // → `runtime.degraded.git_sync_failed` emit, the fs/.meta.yaml/SQLite legs
    // still commit). Legitimate fault-injection at the designed `Arc<dyn GitSync>`
    // port (mirrors the cap-fs sibling sc_t28 sqlite-leg witness). Default false →
    // `Adv003GitSync` (byte-identical). Requires `Cap::Fs`.
    failing_git_sync: bool,
    // Harvest-wave slice (SYS-AC-219): opt-in override of the LazyToolRegistry
    // `max_result_bytes` cap. Default None → the production default 16 MiB. Set a
    // smaller value to witness the output-validation fail-closed check at a
    // reduced bound — the literal 16 MiB+ output is NOT cleanly reachable (a
    // 16 MiB+ result list<u8> traps/times out during the component Val-boundary
    // lift before the host size check, §3.6(g)). The reduced cap exercises the
    // IDENTICAL `bytes.len() > max_result_bytes` code. Requires `Cap::Tools`.
    tools_max_result_bytes: Option<usize>,
    // Harvest-wave slice (SYS-AC-011): opt-in populated `AgentKind::Sub` delegate
    // nodes (each `(sub_id, capability_ids)`) fed to the turn ContextAssembler's
    // agent_tree port, so the assembled prompt carries a `# Available Delegates`
    // section listing them. Default empty -> `EmptyAgentTree` (byte-identical;
    // the production / pre-slice default). Only meaningful with `.llm(Loopback*)`
    // (the real assembler runs on the turn). Each Sub's parent = the SUT agent_id.
    delegates: Vec<(String, Vec<String>)>,
    // Wave-12 (SYS-AC-011): wire a REAL bare-id `AgentTreeStore` + the production
    // spawn host-fns (`register_agent_spawn`) AND feed that SAME store into the
    // turn assembler's agent_tree port, with `query_aliases = [bare, colon]`. A
    // real `spawn-sub` then records a `Sub` under the BARE id; the COLON assemble
    // turn lists it via the Wave-12 alias bridge. Replaces the synthetic
    // colon-keyed `DelegatesTree` fake-green. Requires `Cap::Llm` + `Cap::Fs`.
    with_real_spawn_tree: bool,
    // Wave-12 (SYS-AC-122): register cap-tools with a REAL `RepetitionGuard`
    // (mirroring production cli `wire_capabilities` Step 7 + `start.rs` late-bind):
    // build_repetition_guard_from_config(default) + PIH, late-bound to the per-turn
    // assembler so a repeated tool-triplet emits `run.repetition_detected` AND
    // injects a Tier-3 warning the next turn drains. Requires `Cap::Tools` +
    // `Cap::Llm`. Default false → the no-op `register_agent_tools` (byte-identical).
    with_tool_repetition_guard: bool,
    // Wave-15 Lane E (SYS-AC-012): wire a populated `cap_tools::CallableInventory`
    // [granted "wasmtool" + ungranted "secrettool"] with a CONTRACT-183
    // `ToolsGrantReader` over a DEDICATED `GrantStore`, so `list_wasm_tools` narrows
    // the `# Available Tools` section to the agent's `tools.ids` allowlist. The
    // dedicated store is exposed via `grant_store()` for the witness to seed. Requires
    // `Cap::Tools` + a loopback LLM; mutually exclusive with `GrantMode::Real`.
    with_tool_grant_filter: bool,
    // Stage-C harvest pass-2 (SYS-AC 070/215/216): opt-in wiring of the LIVE L6
    // consolidation dispatch onto the `.with_live_memory()` post-processor — a
    // faithful call into production `advance_cli::l6_wiring::attach_l6` (the SAME
    // construction cli `start.rs:1198-1205` uses: GitQueueL6Committer over the
    // harness's real git queue + L6Runnable + L6DispatchAdapter sharing the live
    // store/lease/l6_emitter/clock Arcs). Default false → no L6 handler (Step-9 emits
    // `memory.l6_consolidation_due` only, never dispatches), so EVERY existing
    // `.with_live_memory()` build stays byte-identical. Requires `.with_live_memory()`.
    with_live_l6: bool,
    // Stage-C harvest pass-2 (SYS-AC-216): opt-in fault axis — build the L6 dispatch
    // with `cap_memory::l6::FailingCommitter` (always `Err`) in place of the
    // production `GitQueueL6Committer`, so a real consolidation surfaces the
    // mid-run-failure branch (`component.error` + lease cleared + NO `l6_completed` /
    // `[l6]` commit). Mirrors `.with_failing_git_sync()`. Implies the L6 wiring (no
    // separate `.with_live_l6()` needed). Default false. Requires `.with_live_memory()`.
    failing_l6_committer: bool,
    // Wave-7 Lane A (SYS-AC 186/187 + the 069 keystone-dial regression gate): opt-in injection
    // of the REAL production `advance_cli::l6_classifier::LlmL6Classifier` (which dials
    // MODULE-009 CONTRACT-081 `cap_llm::LlmGatewayInternal::chat`) into the live `attach_l6`,
    // dialing a SEPARATE second `LoopbackLlm` (NOT the registered guest/extractor FIFO — so
    // 070/215 stay byte-identical). The separate gateway is scripted with one valid L6 output
    // whose `skill_health` stale/unhealthy entries drive the runnable Step-5a `append_generated`
    // + Step-5c `skill.candidate_generated` (186/187), and whose dial witnesses the 069 keystone
    // ("calls the LLM"). NOTE: under the DEFAULT empty-stub path NO `syntheses/*.md` is produced —
    // `attach_l6` wires an EMPTY staleness probe so the synthesis gate never passes; pair with
    // `.with_real_l6_probe()` (Wave-10 Lane A) to wire the real probe + flip SYS-AC-069's synthesis
    // clause. Default false. Requires `.with_live_memory()` + `Cap::Memory` + a main loopback LLM.
    with_recording_l6: bool,
    // Wave-7 Lane A (SYS-AC-216): opt-in fault axis — inject `LlmL6Classifier` over a SECOND
    // `LoopbackLlm` scripted with a non-retryable HTTP 400, so the REAL `classify()` dial
    // fails (→ `L6Error::LlmFailure`) mid-run: the runnable Step-3 aborts BEFORE the commit,
    // token-checked-releases the lease, and the `L6DispatchAdapter` emits `component.error`
    // (the NAMED 216 "LLM call fails" trigger — distinct from `failing_l6_committer`, whose
    // trigger is a failing COMMITTER, explicitly disclaimed for 216). Default false. Requires
    // `.with_live_memory()` + `Cap::Memory` + a main loopback LLM; mutually exclusive with the
    // other L6 fault/recording axes.
    with_failing_l6_gateway: bool,
    // Stage-C harvest pass-2 (070/215/216): knowledge entries inserted into the shared
    // store immediately after open (BEFORE any turn), so an L6 consolidation sees a
    // pre-seeded synthesis-eligible cluster WITHOUT a caller `.with_memory_dir()`
    // override — which would root the L6 synthesis writes OUTSIDE the git workspace and
    // fail the commit. Default empty → no seeding. Effective only with `Cap::Memory`.
    seeded_knowledge: Vec<cap_memory::MemoryEntry>,
    // Stage-C harvest pass-3 (SYS-AC 071/217/072/066): opt-in install of the cli
    // `VlmDescriptionIndexer` into the `.with_live_memory()` post-processor's Step-3
    // (mirrors production `build_live_post_processor`). A real turn then routes each
    // extraction-listed changed file by MIME (text→gateway.chat, image/pdf→the harness
    // `HarnessVlm`, binary→no-index), writes the description back to `.meta.yaml`, and
    // stores a `FileRef`-sourced (recall-able) entry. Default false → no indexer (Step-3
    // stays the documented no-op), byte-identical. Requires `.with_live_memory()`.
    with_vlm_indexer: bool,
    // Stage-C harvest pass-3 (SYS-AC-068): opt-in isolation of the L6 NewEntries(>=20)
    // trigger leg — freeze the post-processor clock at a fixed `now` and pre-seed
    // `l6_trigger_state{ last_l6_at: now-60s, completed_tasks_delta: 0 }`, silencing the
    // HoursSinceLast(<24h) + CompletedTasks(<3) legs so the ONLY way Step-9 emits
    // `memory.l6_consolidation_due` is >=20 NewEntries-since-last. Makes the named
    // EntryCount leg e2e-attributable. Default false → SystemClock + default state
    // (byte-identical). Requires `.with_live_memory()` (NOT `.with_live_l6()`).
    l6_entrycount_isolation: bool,
    // Wave-6 Lane A (SYS-AC 078/079/081): opt-in install of the REAL production
    // `DiskSkillSummaryReader` (cli `build_context_assembler_for_agent_with_skills`,
    // the SAME fn `start.rs` installs on the production assemble() path) on the
    // per-turn ContextAssembler, rooted at the cap-skills provider root
    // (`agent_workspace` = `<ws>/agent`, canonicalized). A real turn then folds the
    // agent's on-disk activated skills' L0 first-paragraph summaries into the
    // assembled prompt's Tier-2 `# Available Skills` section (capped at
    // `min(skill_budget_tokens, ⌊budget·0.05⌋, 10K)`, lowest-`version` truncated
    // first). Skills ⊥ memory, so this composes with (or without) `.with_live_memory()`.
    // Default false → the no-skills assembler (`StubSkillSummary`, no section), so every
    // existing build is byte-identical. Requires `Cap::Skills` + a loopback LLM (the
    // section reaches the prompt only via the publishing assembler, installed under the
    // `llm` arm); build() panics otherwise (fail-loud, mirrors `await_deadlock_gate`).
    with_skills_summary: bool,
    // Wave-10 Lane A (SYS-AC-069 harvest): opt-in swap of the live `attach_l6` shim for the
    // PRODUCTION `attach_l6_with_stale_resolver(Some(..))` — wiring the REAL
    // `cap_memory::l6::ResolverStalenessProbe` (MODULE-002 git-blob lookup, via the same
    // `advance_cli::l6_wiring::build_l6_stale_resolver` that `start.rs` installs) over a
    // `OneAgentTree::new(workspace_root)` territory. Combined with a real-blob FileRef
    // (`.with_seeded_workspace_file`) the Step-1 staleness probe judges the file-ref Valid →
    // NOT orphaned → the synthesis 5-gate passes → `syntheses/*.md` is written + committed in the
    // `[l6]` `CommitType::L6` commit (069's "writes syntheses" clause, now reachable). Default
    // false → the byte-identical `attach_l6` None-resolver shim (070/215/216 unchanged). Requires
    // `.with_live_memory()` + `Cap::Memory` + a recording/live L6 axis; mutually exclusive with
    // `failing_l6_committer` (that path mirrors `attach_l6`'s body by hand, no resolver seam).
    with_real_l6_probe: bool,
    // Wave-10 Lane A (SYS-AC-069 harvest): files written into the git workspace + committed (one
    // `[seed]` commit) at build time, right after `bootstrap_repo_at`. Each `(vpath, content)`
    // lands at `workspace_root.join(vpath)` — the TERRITORY ROOT the `with_real_l6_probe` resolver
    // tree maps `AGENT_ID` to (NOT `AGENT_DIR`) — so a seeded FileRef carrying
    // `blob_oid_of_bytes(content)` resolves to a real, matching git blob. Default empty → no
    // seeding (byte-identical).
    seeded_workspace_files: Vec<(String, Vec<u8>)>,
    // Wave-11 Lane A (SYS-AC-076/077 harvest): opt-in swap of the event-less
    // `register_agent_skills` for the lifecycle coordinator path
    // `register_agent_skills_with_lifecycle` + `SkillPersistenceCoordinator::with_shared_store`.
    // The later AC-22 cli production path uses `register_agent_skills_with_turn_runtime`;
    // this harness axis remains the narrower lifecycle witness.
    // The coordinator SHARES the provider's resolved store (one mutex across all 8 skills
    // host-fns) + the build's git commit `queue` + `bus_dyn`, rooted at the SAME `agent_workspace`
    // as the provider, so a successful agent `activate-skill`/`rollback-skill` emits the PRODUCT
    // `skill.activated`/`skill.rolled_back` event + a `CommitType::Turn` commit (dual-track) and
    // the committed `affected_paths` match where `DiskSkillStorage` writes. Default false → the
    // event-less registration (074/075/218 byte-identical). Requires `Cap::Skills`.
    with_skills_lifecycle: bool,
    // Wave-13 (SYS-AC-172): wire the cap-lifecycle decomposition host-fns + the
    // context-assembler's `CapDecompositionReader` over ONE shared `DefaultDecompositionStore`,
    // so a real `submit-decomposition` turn's subtasks surface in the next turn's assembled
    // `# Active Task Decomposition` Tier-2 section (the LLM body). Default false → the base
    // assembler keeps `EmptyDecomposition` (no section; byte-identical). Requires a loopback LLM
    // (the section reaches the prompt only via the publishing assembler) and is mutually
    // exclusive with `with_skills_summary`/`with_live_memory` (those assembler branches pass
    // `EmptyDecomposition`, which would silently drop the reader — fail loud below).
    with_decomposition: bool,
    // Wave-16 Lane 2 (SYS-AC-005): opt the per-turn assembler into the REAL cli
    // `build_recall_unified_search` + `build_context_assembler_for_agent_with_recall`
    // production fns — the recall corpus is populated from this SUT's seeded memory +
    // workspace files, so the assembled prompt carries a local `# Recalled Context`.
    // The 5th (mutually-exclusive) assembler-builder branch. Requires Cap::Memory + a
    // loopback LLM (the section reaches the prompt only via the publishing assembler).
    with_recall_corpus: bool,
    /// Wave-20 Lane `search` (SYS-AC-009): the DUAL-PATH (dense + sparse FTS5) recall axis.
    with_dual_recall_corpus: bool,
}

impl Default for SystemUnderTestBuilder {
    fn default() -> Self {
        Self {
            caps: vec![Cap::Fs],
            grant: GrantMode::AllowAll,
            grant_chain: GrantChain::Supervised,
            events: EventSink::Capturing,
            llm: LlmMode::Off,
            with_delta_tee: false,
            delta_tee_timing: None,
            agent_id: AGENT_ID.to_string(),
            budget: None,
            repetition: None,
            grant_resolver_budget: None,
            grant_channel_approval: None,
            grant_presets: None,
            grant_run_session: None,
            grant_sweeper_interval: None,
            agents: Vec::new(),
            channel_capture: false,
            mcp_servers: Vec::new(),
            memory_dir: None,
            memory_cap: None,
            mailbox_cap: None,
            reply_capture: false,
            channel_adapters: Vec::new(),
            with_triggers: false,
            runtime_config_watch: false,
            meta_schema_watch: false,
            submit_subset_gate: false,
            await_deadlock_gate: false,
            with_crash_cascade: false,
            with_workspace_rollback: false,
            with_sqlite_index: false,
            failing_git_sync: false,
            tools_max_result_bytes: None,
            delegates: Vec::new(),
            with_real_spawn_tree: false,
            with_tool_repetition_guard: false,
            with_tool_grant_filter: false,
            with_live_memory: false,
            with_live_l6: false,
            failing_l6_committer: false,
            with_recording_l6: false,
            with_failing_l6_gateway: false,
            seeded_knowledge: Vec::new(),
            with_vlm_indexer: false,
            l6_entrycount_isolation: false,
            with_skills_summary: false,
            with_real_l6_probe: false,
            seeded_workspace_files: Vec::new(),
            with_skills_lifecycle: false,
            with_decomposition: false,
            with_recall_corpus: false,
            with_dual_recall_corpus: false,
        }
    }
}

impl SystemUnderTestBuilder {
    /// Register exactly this capability subset (via the real `register_agent_*` fns).
    pub fn caps(mut self, caps: &[Cap]) -> Self {
        self.caps = caps.to_vec();
        self
    }
    /// Stage-B (SYS-AC 146/147/148/233/149/151/260): wire the REAL cap-fs
    /// triple-sync trio into `register_agent_fs` over a fresh in-memory SQLite
    /// index, so `fs_write` fans out to a real `meta_index`/`content_index`/
    /// `content_fts`, and enable `boot_reconcile()` + `fts_recall()`. Default off
    /// → the trio stays None,None,None (every prior build byte-identical).
    /// Requires `Cap::Fs` (the trio is registered in the fs block; build() panics
    /// otherwise).
    pub fn with_sqlite_index(mut self) -> Self {
        self.with_sqlite_index = true;
        self
    }
    /// Harvest-wave (SYS-AC-236): wire a `FailingGitSync` (always `Err`) into
    /// `register_agent_fs` in place of the production `Adv003GitSync`, so a real
    /// `fs.write` drives the production fail-soft git leg
    /// (`runtime.degraded.git_sync_failed` emitted; the fs/.meta.yaml/SQLite legs
    /// still commit). Default off → `Adv003GitSync` (byte-identical). Requires
    /// `Cap::Fs`.
    pub fn with_failing_git_sync(mut self) -> Self {
        self.failing_git_sync = true;
        self
    }
    /// Harvest-wave (SYS-AC-219): override the LazyToolRegistry `max_result_bytes`
    /// cap (default 16 MiB). Used to witness the output-validation fail-closed
    /// check at a reduced bound (the literal 16 MiB+ output is unreachable through
    /// the component Val boundary, §3.6(g)). Requires `Cap::Tools`.
    pub fn with_tools_max_result_bytes(mut self, n: usize) -> Self {
        self.tools_max_result_bytes = Some(n);
        self
    }
    /// Harvest-wave (SYS-AC-011): feed populated `AgentKind::Sub` delegates (each
    /// `(sub_id, capability_ids)`) to the turn ContextAssembler's agent_tree port,
    /// so the assembled prompt carries a `# Available Delegates` section listing
    /// them. Default off -> `EmptyAgentTree`. Only meaningful with `.llm(Loopback*)`.
    pub fn with_delegates(mut self, delegates: &[(&str, &[&str])]) -> Self {
        self.delegates = delegates
            .iter()
            .map(|(id, caps)| (id.to_string(), caps.iter().map(|c| c.to_string()).collect()))
            .collect();
        self
    }
    /// Wave-12 (SYS-AC-011): wire a REAL bare-id `AgentTreeStore` + the production
    /// spawn host-fns over it, AND feed that SAME store into the turn assembler's
    /// agent_tree port with `query_aliases = [bare "harness", colon AGENT_ID]`. A
    /// witness then drives a real `spawn-sub` host-fn (BARE caller) → records a Sub
    /// under "harness"; the COLON assemble turn lists it via the alias bridge. This
    /// is the FAITHFUL replacement for the synthetic `.with_delegates()` tree (which
    /// keyed the Sub under the colon id, never exercising the bare/colon split).
    /// Requires `Cap::Llm` (assemble turn) + `Cap::Fs` (the bare-id store/spawn).
    pub fn with_real_spawn_tree(mut self) -> Self {
        self.with_real_spawn_tree = true;
        self
    }
    /// Wave-12 (SYS-AC-122): register cap-tools with a REAL `RepetitionGuard`
    /// mirroring production (cli `wire_capabilities` Step 7 + `start.rs` late-bind):
    /// `build_repetition_guard_from_config(default)` (window 10 / threshold 3 /
    /// warn-then-terminate) + `PromptInjectionHelpers`, late-bound to the per-turn
    /// assembler. A repeated identical tool-triplet (×3) then emits
    /// `run.repetition_detected` AND injects a Tier-3 warning the next turn drains.
    /// Sets `query_aliases = [bare, colon]` so the bare-keyed inject drains under the
    /// colon assemble id. Requires `Cap::Tools` + `Cap::Llm`.
    pub fn with_tool_repetition_guard(mut self) -> Self {
        self.with_tool_repetition_guard = true;
        self
    }
    /// Wave-15 Lane E (SYS-AC-012): wire a populated `cap_tools::CallableInventory`
    /// (`[wasmtool, secrettool]`) carrying a CONTRACT-183 `ToolsGrantReader` over a
    /// DEDICATED `GrantStore`, so `# Available Tools` is narrowed to the agent's
    /// effective `tools.ids` allowlist. The dedicated store is exposed via
    /// `grant_store()` for the witness to seed a `"tools"` grant. Requires `Cap::Tools`
    /// + a loopback LLM (the section reaches the prompt only via the publishing
    /// assembler); mutually exclusive with `GrantMode::Real` (the axis owns its store).
    pub fn with_tool_grant_filter(mut self) -> Self {
        self.with_tool_grant_filter = true;
        self
    }
    /// Choose grant enforcement (`AllowAll` default, or the real chain).
    pub fn grant(mut self, mode: GrantMode) -> Self {
        self.grant = mode;
        self
    }
    /// Choose the [`GrantMode::Real`] resolver-chain composition.
    pub fn grant_chain(mut self, chain: GrantChain) -> Self {
        self.grant_chain = chain;
        self
    }
    /// Inject the resolver-chain budget seam for [`GrantChain::Supervised`].
    pub fn grant_resolver_budget(mut self, budget: Arc<dyn RunBudget>) -> Self {
        self.grant_resolver_budget = Some(budget);
        self
    }
    /// Inject the channel-approval port the Channel resolver consults.
    pub fn grant_channel_approval(mut self, approval: Arc<dyn ChannelApprovalPort>) -> Self {
        self.grant_channel_approval = Some(approval);
        self
    }
    /// Inject a preset registry for real cap-grant host-fn wiring.
    pub fn grant_presets(mut self, presets: Arc<PresetRegistry>) -> Self {
        self.grant_presets = Some(presets);
        self
    }
    /// Wire the production run-session bootstrap into the harness message loop.
    pub fn grant_run_session(
        mut self,
        run_manager: Arc<RunManager>,
        run_config: RunConfig,
    ) -> Self {
        self.grant_run_session = Some((run_manager, run_config));
        self
    }
    /// Start the real cap-grant TTL sweeper at the given interval.
    pub fn with_grant_ttl_sweeper(mut self, interval: Duration) -> Self {
        self.grant_sweeper_interval = Some(interval);
        self
    }
    /// Choose the event sink (`Capturing` default, or the real bus + SQLite).
    pub fn events(mut self, sink: EventSink) -> Self {
        self.events = sink;
        self
    }
    /// Configure a deterministic LLM loopback backend (implies the `llm` cap).
    pub fn llm(mut self, mode: LlmMode) -> Self {
        self.llm = mode;
        self
    }
    /// SYS-J-72: inject `LlmDeltaHub` into the loopback gateway, retain the
    /// turn-end reaper, bind a loopback Client API, and attach
    /// `ReapTurnObserver`. Requires `.llm(Loopback*)`. Does **not** add
    /// `Cap::Llm` — callers still set `.caps(&[Cap::Llm, ...])`.
    pub fn with_delta_tee(mut self) -> Self {
        self.with_delta_tee = true;
        self
    }
    /// Like [`Self::with_delta_tee`], with a hub timing override (`LlmDeltaHub::with_timing`).
    /// J72-307a uses default 15 s `reauth_max_age` — do not shrink it for the first-page wait.
    pub fn with_delta_tee_timing(mut self, timing: advance_client_api::DeltaTiming) -> Self {
        self.with_delta_tee = true;
        self.delta_tee_timing = Some(timing);
        self
    }
    /// Override the agent routing id (default [`AGENT_ID`]).
    pub fn agent_id(mut self, id: &str) -> Self {
        self.agent_id = id.to_string();
        self
    }

    /// HF-2: supply the loopback gateway's run-budget (e.g. a real
    /// `advance_run_manager::InMemoryRunBudget`) instead of the default always-allow
    /// budget. Only affects `.llm(Loopback*)` builds; a budget-`Deny` surfaces as
    /// `LlmError::BudgetExceeded` BEFORE the provider is dialed.
    pub fn budget(mut self, budget: Arc<dyn RunBudget>) -> Self {
        self.budget = Some(budget);
        self
    }

    /// HF-2: supply the loopback gateway's repetition guard (e.g. a real
    /// `advance_run_manager::RepetitionGuard`) instead of the default no-op guard. Only
    /// affects `.llm(Loopback*)` builds; a `Terminate` decision surfaces as
    /// `LlmError::RepetitionTerminated`.
    pub fn repetition(mut self, repetition: Arc<dyn RepetitionGuardCheck>) -> Self {
        self.repetition = Some(repetition);
        self
    }

    /// HF: declare a multi-agent tree (root + children, canonical `agent:` ids).
    /// Wires the real `DefaultSpawner` (bare-id `AgentTreeStore` spawn witness) +
    /// `AwaitSessionManagerImpl` + reply-tracker host fns. Empty → single-agent
    /// (BS-3) path.
    pub fn agents(mut self, specs: &[AgentSpec]) -> Self {
        self.agents = specs.to_vec();
        self
    }

    /// HF: register cap-channel with a capturing `HttpSecurityChain` + a
    /// pre-created subscription (owner = this SUT's agent, `Webhook` adapter,
    /// outbound config present) so `send-raw` is captured and inbound can be injected.
    pub fn with_channel_capture(mut self) -> Self {
        self.channel_capture = true;
        self
    }

    /// HF: wire an in-process cap-mcp client over scripted transports (no
    /// subprocess/network). See [`SystemUnderTest::drive_mcp_tool`].
    pub fn with_mcp_transports(mut self, servers: Vec<McpServerSpec>) -> Self {
        self.mcp_servers = servers;
        self
    }

    /// Backbone Step 3: root the persistent cap-memory store at `dir` (which
    /// `MemoryStore::open` creates if absent). Default (unset) → a fresh
    /// `<workspace_root>/.agent/memory` per build. Pass a CALLER-owned `TempDir`
    /// subpath (e.g. `d.path().join(".agent/memory")`) so the dir OUTLIVES the SUT
    /// (whose own workspace tempdir drops on teardown) — required to witness
    /// cross-restart persistence by re-opening the same dir from a second SUT or a
    /// `MemoryStore::open` re-read.
    pub fn with_memory_dir(mut self, dir: PathBuf) -> Self {
        self.memory_dir = Some(dir);
        self
    }

    /// Backbone Step 3: cap the persistent store's active entries per agent
    /// (default `DEFAULT_MAX_ACTIVE_PER_AGENT`). Set small (e.g. 1) to witness the
    /// entry-cap `memory-error::limit-exceeded` path (SYS-AC-212).
    pub fn with_memory_cap(mut self, cap: usize) -> Self {
        self.memory_cap = Some(cap);
        self
    }

    /// Stage-C harvest pass-1 (SYS-AC 006/008/065/067/213/254): wire the LIVE
    /// cap-memory read+write path SAT-A/SAT-B put in cli, so a real guest turn
    /// witnesses (a) the history-aware assembler reading `summary.yaml` /
    /// `turn-index.yaml` from `<memory_dir>/tasks/{task_id}/` (L2/L3/L4) and
    /// (b) the components-backed `PostProcessor` issuing ONE batched
    /// `LlmBatchExtractor` call over the loopback gateway, then writing
    /// `summary.yaml` / `turn-index.yaml` + upserting the durable
    /// `RusqliteSqliteIndex` (`<memory_dir>/index.sqlite`). Mirrors the production
    /// `build_live_post_processor` wiring (cli `start.rs`) from public cap-memory
    /// blocks — TEST-ONLY, no product source change.
    ///
    /// Default OFF → byte-identical (no-history assembler + trace-only
    /// `PostProcessor::new()`). Effective ONLY when BOTH `Cap::Memory` is declared
    /// AND a loopback LLM is set (the same both-present gate production uses); with
    /// either absent the build stays trace-only (no divergence). Drive task-scoped
    /// turns via [`SystemUnderTest::inject_message_with_task`].
    pub fn with_live_memory(mut self) -> Self {
        self.with_live_memory = true;
        self
    }

    /// Stage-C harvest pass-2 (SYS-AC 070/215): wire the LIVE L6 consolidation
    /// dispatch onto the `.with_live_memory()` post-processor via production
    /// `advance_cli::l6_wiring::attach_l6` (GitQueueL6Committer over the harness's
    /// real git queue + L6Runnable + L6DispatchAdapter, sharing the live
    /// store/lease/l6_emitter/clock). With it set, a trigger-firing turn dispatches
    /// the runnable end-to-end → a real `[l6]` `CommitType::L6` commit on disk +
    /// `memory.l6_completed` (delta + KnowledgeHealthSnapshot) on the SUT event sink.
    /// Default OFF → Step-9 emits `memory.l6_consolidation_due` only (no dispatch),
    /// so every existing `.with_live_memory()` test is byte-identical. Requires
    /// `.with_live_memory()` (and thus `Cap::Memory` + a loopback LLM).
    pub fn with_live_l6(mut self) -> Self {
        self.with_live_l6 = true;
        self
    }

    /// Stage-C harvest pass-2 (SYS-AC-216): wire the L6 dispatch with
    /// `cap_memory::l6::FailingCommitter` (always `Err`) instead of the production
    /// `GitQueueL6Committer`, so a real consolidation drives the mid-run-failure
    /// branch — the L6Runnable's Err-arm releases the lease, the adapter emits
    /// `component.error`, and NO `memory.l6_completed` / `[l6]` commit is produced
    /// (the next trigger retries). Mirrors `.with_failing_git_sync()`. Implies the L6
    /// wiring (no separate `.with_live_l6()` needed). Default OFF. Requires
    /// `.with_live_memory()`.
    pub fn with_failing_l6_committer(mut self) -> Self {
        self.failing_l6_committer = true;
        self
    }

    /// Wave-7 Lane A (SYS-AC 186/187 + the 069 keystone-dial regression gate): inject the REAL
    /// production `advance_cli::l6_classifier::LlmL6Classifier` into the live `attach_l6`, dialing
    /// a SEPARATE second `LoopbackLlm` (NOT the registered guest/extractor FIFO — so the
    /// scripted-FIFO loopback is never consumed by L6 and SYS-AC-070/215 stay green). The
    /// separate gateway returns ONE valid L6 output whose `skill_health` stale/unhealthy entries
    /// drive the runnable Step-5a `append_generated` + Step-5c `skill.candidate_generated`
    /// (186/187); its dial witnesses the 069 keystone ("calls the LLM"). Witness the real dial
    /// via [`SystemUnderTest::l6_chat_request_count`] / [`SystemUnderTest::l6_chat_request_bodies`].
    /// Implies the L6 wiring (real `GitQueueL6Committer`). NOTE: ALONE (default empty-stub probe) NO
    /// `syntheses/*.md` is produced — `attach_l6` wires an EMPTY staleness probe (every file-ref
    /// orphaned → the synthesis gate never passes); pair with `.with_real_l6_probe()` (Wave-10 Lane A)
    /// to wire the real `ResolverStalenessProbe` + flip SYS-AC-069's synthesis clause. Default OFF.
    /// Requires `.with_live_memory()` + `Cap::Memory` + a main loopback LLM (build() panics
    /// otherwise); mutually exclusive with `.with_failing_l6_committer()` / `.with_failing_l6_gateway()`.
    pub fn with_recording_l6(mut self) -> Self {
        self.with_recording_l6 = true;
        self
    }

    /// Wave-7 Lane A (SYS-AC-216): inject `LlmL6Classifier` over a SECOND `LoopbackLlm`
    /// scripted with a non-retryable HTTP 400, so the REAL `classify()` dial FAILS mid-run
    /// (`chat()` → `Err` → `L6Error::LlmFailure`). The runnable Step-3 aborts BEFORE the
    /// commit, token-checked-releases the lease, and the `L6DispatchAdapter` emits
    /// `component.error` (the NAMED 216 "LLM call fails" trigger). NOT the same as
    /// `.with_failing_l6_committer()` (which fails the COMMITTER, not the gateway, and is
    /// explicitly disclaimed for 216). Implies the L6 wiring (real `GitQueueL6Committer`; the
    /// failure precedes the commit). Default OFF. Requires `.with_live_memory()` +
    /// `Cap::Memory` + a main loopback LLM (build() panics otherwise); mutually exclusive with
    /// the other L6 fault/recording axes.
    pub fn with_failing_l6_gateway(mut self) -> Self {
        self.with_failing_l6_gateway = true;
        self
    }

    /// Stage-C harvest pass-2 (070/215/216): seed knowledge entries into the shared
    /// store right after open (before any turn) — e.g. a synthesis-eligible cluster
    /// (>=1 FileRef-sourced fact) for an L6 consolidation witness. Lets the L6 tests
    /// use the DEFAULT in-workspace `memory_dir` (so the synthesis commit lands inside
    /// the git workdir) instead of a caller `.with_memory_dir()` override. No-op
    /// without `Cap::Memory` (the store is absent).
    pub fn with_seeded_knowledge(mut self, entries: Vec<cap_memory::MemoryEntry>) -> Self {
        self.seeded_knowledge = entries;
        self
    }

    /// Wave-10 Lane A (SYS-AC-069 harvest): opt into the PRODUCTION real staleness probe on the
    /// live `attach_l6` path — `attach_l6_with_stale_resolver(Some(build_l6_stale_resolver(..)))`
    /// over a `OneAgentTree::new(workspace_root)` territory (the SAME `ResolverStalenessProbe`
    /// `start.rs` always wires). With a real-blob FileRef seeded via `.with_seeded_workspace_file`
    /// the Step-1 probe judges the file-ref Valid → not orphaned → the synthesis 5-gate passes →
    /// `syntheses/*.md` is written + committed in the `[l6]` `CommitType::L6` commit (flips 069).
    /// Default OFF → the byte-identical empty-stub `attach_l6` shim (070/215/216 unchanged).
    /// Requires `.with_live_memory()` + `Cap::Memory` + at least one of `.with_recording_l6()` /
    /// `.with_live_l6()` (a classifier that yields Consistent clusters; if both are set
    /// `with_recording_l6` wins and `with_live_l6` is a no-op); rejected with
    /// `.with_failing_l6_committer()` (build() panics — that path mirrors `attach_l6`'s body by
    /// hand, with no resolver seam).
    pub fn with_real_l6_probe(mut self) -> Self {
        self.with_real_l6_probe = true;
        self
    }

    /// Wave-10 Lane A (SYS-AC-069 harvest): seed a file into the git workspace — written at
    /// `workspace_root.join(vpath)` (the TERRITORY ROOT, NOT `AGENT_DIR`) and committed in one
    /// `[seed]` commit at build time — so a `.with_real_l6_probe()` FileRef carrying
    /// [`blob_oid_of_bytes`]`(content)` resolves to a real, matching git blob. CALLER PRECONDITION
    /// (not validated here): `vpath` must be a clean relative path (no `..`, no hidden/`.advance`
    /// component) — else `resolve_read` rejects it at probe time and the file-ref reads Stale (the
    /// seed/commit still succeed). Default empty → no seeding (byte-identical).
    pub fn with_seeded_workspace_file(mut self, vpath: &str, content: &[u8]) -> Self {
        self.seeded_workspace_files
            .push((vpath.to_string(), content.to_vec()));
        self
    }

    /// Stage-C harvest pass-3 (SYS-AC 071/217/072/066): install the cli
    /// `VlmDescriptionIndexer` into the `.with_live_memory()` post-processor's
    /// Step-3, so a real turn routes each extraction-listed changed file by MIME
    /// (text → CONTRACT-081 `gateway.chat`, image/pdf → CONTRACT-082
    /// `HarnessVlm::extract_description`, binary/unknown → no-index), writes the
    /// description back to `.meta.yaml`, and stores it as a `FileRef`-sourced
    /// (recall-able) entry. Mirrors the production `build_live_post_processor`
    /// install. Default OFF. Requires `.with_live_memory()` (build() panics
    /// otherwise). Inspect the recorded VLM variants via
    /// [`SystemUnderTest::vlm_calls`].
    pub fn with_vlm_indexer(mut self) -> Self {
        self.with_vlm_indexer = true;
        self
    }

    /// Stage-C harvest pass-3 (SYS-AC-068): isolate the L6 NewEntries(>=20)
    /// trigger leg. Swaps the post-processor clock to a frozen
    /// `cap_memory::MutableClock(now)` and pre-seeds `l6_trigger_state` with
    /// `last_l6_at = Some(now-60s)` + `completed_tasks_delta = 0`, so the
    /// HoursSinceLast(<24h) and CompletedTasks(<3) legs are quiet and the ONLY
    /// way Step-9 fires `memory.l6_consolidation_due` is >=20 NewEntries since
    /// last (cap-memory `trigger.rs`). Makes the named EntryCount leg
    /// e2e-attributable (closes the pass-2 deferral). Default OFF. Requires
    /// `.with_live_memory()` (build() panics otherwise); does NOT require
    /// `.with_live_l6()` — the due-event emits independent of the L6 handler
    /// (post_processor.rs Step-9, line ~1331).
    pub fn with_l6_entrycount_isolation(mut self) -> Self {
        self.l6_entrycount_isolation = true;
        self
    }

    /// Wave-6 Lane A (SYS-AC 078/079/081): install the REAL production
    /// `DiskSkillSummaryReader` on the per-turn ContextAssembler (via cli
    /// `build_context_assembler_for_agent_with_skills`, the SAME fn `start.rs`
    /// installs on the production assemble() path), rooted at the cap-skills
    /// provider root (`agent_workspace`, canonicalized to match the canonicalizing
    /// writer). A real turn then surfaces the agent's on-disk activated skills' L0
    /// first-paragraph summaries in the assembled prompt's Tier-2 `# Available
    /// Skills` section (lowest-`version` truncated first under the skill budget).
    /// Default OFF → `StubSkillSummary` (no section, byte-identical). Requires
    /// `Cap::Skills` + a loopback LLM (build() panics otherwise).
    pub fn with_skills_summary(mut self) -> Self {
        self.with_skills_summary = true;
        self
    }

    /// Wave-11 Lane A (SYS-AC-076/077): wire the skill lifecycle
    /// persistence coordinator (`register_agent_skills_with_lifecycle` +
    /// `SkillPersistenceCoordinator::with_shared_store`) so an agent
    /// `activate-skill`/`rollback-skill` emits `skill.activated`/`skill.rolled_back`
    /// + a `CommitType::Turn` commit. Default off → the event-less
    /// `register_agent_skills` (074/075/218 byte-identical). Requires `Cap::Skills`.
    pub fn with_skills_lifecycle(mut self) -> Self {
        self.with_skills_lifecycle = true;
        self
    }

    /// Wave-13 (SYS-AC-172): wire the cap-lifecycle decomposition host-fns
    /// (`register_agent_decomposition`) + the context-assembler's `CapDecompositionReader`
    /// over ONE shared `DefaultDecompositionStore` (rooted at the bare form of this SUT's
    /// agent id — `agent_id().strip_prefix("agent:")`, default `harness`). A real
    /// `submit-decomposition` (driven via the registered host-fn) then surfaces its
    /// non-orphaned subtasks in the next turn's assembled `# Active Task Decomposition`
    /// Tier-2 section (the LLM body). Default
    /// off → the base assembler keeps `EmptyDecomposition` (no section; byte-identical).
    /// Requires a loopback LLM and is mutually exclusive with
    /// `.with_skills_summary()`/`.with_live_memory()` (fail-loud at build).
    pub fn with_decomposition(mut self) -> Self {
        self.with_decomposition = true;
        self
    }

    /// Wave-18 Lane 4 (SYS-AC-030): wire the production crash-cascade sink (cli
    /// `build_crash_cascade_sink`) into every `.agents()` node driver. A served
    /// child's REAL guest trap then drives `handle_trap(Crash)` → the sink →
    /// cap-lifecycle `handle_crash` → `notify_parent_crash` → the parent's mailbox
    /// (`component.terminated` System message). The sink is built from the bare-id
    /// `AgentsHandle.tree_store` + the shared `MailboxStore` with the symmetric
    /// resolver `|b| format!("agent:{b}")` (matching how `.agents()` keys node
    /// mailboxes). Default off → drivers keep `crash_sink: None` (byte-identical).
    /// Requires `.agents()` (fail-loud at build otherwise).
    pub fn with_crash_cascade(mut self) -> Self {
        self.with_crash_cascade = true;
        self
    }

    /// Wave-19 (SYS-AC-028) opt-in — wire the production `WorkspaceRollbackSink` (cli
    /// `build_workspace_rollback_sink`) into every `.agents()` node driver, so a child guest
    /// trap rolls the child territory's committed subtree back to the pre-turn commit
    /// (forward-rollback-commit). At build time the axis ALSO (F1a) writes each LEAF agent's
    /// `.agent/config.yaml` with an explicit `agent_id` (so `WorkspaceRollback`'s
    /// `resolve_agent_root` resolves the territory — NOT for ancestor agents, whose config
    /// would BFS-prune the nested child) and (F1b) commits a `[seed]` baseline (so the
    /// pre-turn `NamedCheckpoint` has a born HEAD + `git status` is clean). Default off →
    /// drivers keep `workspace_rollback_sink: None` (byte-identical). Requires `.agents()` +
    /// `Cap::Fs` (the real per-write `[turn]` commits the rollback compensates).
    pub fn with_workspace_rollback(mut self) -> Self {
        self.with_workspace_rollback = true;
        self
    }

    /// Wave-16 Lane 2 (SYS-AC-005): opt the per-turn assembler into the REAL cli recall
    /// production fns — the recall corpus is populated from THIS SUT's seeded `MemoryStore`
    /// entries (seed via `Cap::Memory` + an active `MemoryEntry` under the colon agent id)
    /// AND its seeded workspace files (`.with_seeded_workspace_file`), so the assembled
    /// prompt carries a local `# Recalled Context` (`## Files` + `## Memory`) the turn answers
    /// from regardless of the configured LLM provider. The 5th (mutually-exclusive) assembler
    /// branch. Requires `Cap::Memory` + a loopback LLM, and is mutually exclusive with
    /// `.with_skills_summary()`/`.with_live_memory()`/`.with_decomposition()` (fail-loud at build).
    pub fn with_recall_corpus(mut self) -> Self {
        self.with_recall_corpus = true;
        self
    }

    /// Wave-20 Lane `search` (SYS-AC-009) — the DUAL-PATH (dense + sparse FTS5) recall
    /// axis. Identical seam to `.with_recall_corpus()` (5th mutually-exclusive assembler
    /// branch; requires `Cap::Memory` + a loopback LLM) EXCEPT the recall is the REAL
    /// MODULE-004 `R2d2UnifiedSearchImpl` over an in-memory SQLite index (dense
    /// `vec_distance_cosine` + sparse `content_fts MATCH`), bridged to the assembler's
    /// `UnifiedSearchPort` by the cli `R2d2UnifiedSearchAdapter`, and the embedder is the
    /// 768-dim [`FixtureEmbedding`] (controlled geometry). This is the SYS-AC-009 witness
    /// axis — a keyword-only sparse hit AND a semantic-only dense hit BOTH reach the
    /// assembled `# Recalled Context`. Mutually exclusive with the other recall/assembler
    /// axes (fail-loud at build).
    pub fn with_dual_recall_corpus(mut self) -> Self {
        self.with_dual_recall_corpus = true;
        self
    }

    /// Stage-A notify slice (SYS-AC-174): override the per-agent mailbox capacity
    /// (default 64, hard-coded at the `MailboxStore::new` site). Set small (e.g. 1)
    /// so a second `notify-agent` to a now-full target surfaces `MailboxFull`
    /// backpressure and delivers nothing. Default (unset) → 64 → byte-identical.
    pub fn with_mailbox_cap(mut self, cap: usize) -> Self {
        self.mailbox_cap = Some(cap);
        self
    }

    /// Wave-18 Lane-3 (MODULE-006-AC-02 infra): register a `channel_id →
    /// adapter_agent_id` mapping AND opt the SUT into building the dispatcher over a
    /// real [`StaticChannelAdapterRegistry`] + registering the `notify-channel`
    /// host-fn. `adapter_agent_id` MUST be a colon-form `agent:`-prefixed id that is
    /// a node in the SUT tree (e.g. the sole [`AGENT_ID`] `agent:harness`) — otherwise
    /// `notify_channel` resolves the channel but `deliver_notify` rejects with
    /// `target_unknown`. Default (axis unset) → `MailboxDispatcherImpl::new`
    /// (EmptyChannelAdapterRegistry) + no `notify-channel` registration → every
    /// existing build byte-identical. Drives
    /// `crates/system-acceptance/tests/sys_j30_notify_channel.rs`.
    pub fn with_channel_adapter(
        mut self,
        channel_id: impl Into<String>,
        adapter_agent_id: impl Into<String>,
    ) -> Self {
        self.channel_adapters
            .push((channel_id.into(), adapter_agent_id.into()));
        self
    }

    /// Backbone Step 4: wire an accumulating `OutboundActionSink` so each turn's
    /// dispatched first-action payload (e.g. a guest's LLM reply) is observable via
    /// [`SystemUnderTest::delivered_replies`]. Off by default → `build_agent_loop`
    /// receives `None` (gate-only) so every existing `run_turn` test is byte-identical.
    /// Mirrors the in-repo `sys_j64_state_roundtrip` `RecordingSink` pattern.
    pub fn with_reply_capture(mut self) -> Self {
        self.reply_capture = true;
        self
    }

    /// Harvest-triggers slice (SYS-AC 098-114): wire the REAL scheduler trigger
    /// subsystems into the SUT — a `TriggerBusDispatchImpl` (max-chain-depth 10), a
    /// registry-backed `InMemoryComponentSubmitApi` (quota 20) over a SQLite
    /// `ComponentRegistry` rooted at `<ws>/.triggers/components.db`, and the SUT's
    /// shared event sink exposed as an `EventBusEmit` so a real `CronDriver` fire's
    /// `trigger.fired` is observable via [`SystemUnderTest::events`]. Drive via
    /// [`SystemUnderTest::drive_cron_fire`] / [`SystemUnderTest::cron_jitter`] /
    /// [`SystemUnderTest::trigger_bus`] / [`SystemUnderTest::submit_api`] /
    /// [`SystemUnderTest::submit_registry`]. Requires the default
    /// [`EventSink::Capturing`] (cron `trigger.fired` is read back through `events()`,
    /// which is empty for `RealBus`). Off by default → every existing build is
    /// byte-identical (no registry/SQLite open).
    pub fn with_triggers(mut self) -> Self {
        self.with_triggers = true;
        self
    }

    /// Lifecycle-harvest (SYS-AC 152-154/237): start a REAL
    /// [`RuntimeConfigWatcher`] over a seeded `<ws>/.advance/runtime-config.yaml`
    /// with the SUT event sink installed as its emitter — edits to the file are
    /// hot-reloaded (validated, fail-closed) and applied reloads emit
    /// `runtime.config_reloaded {sections_changed}` observable via `events()`.
    /// Access via [`SystemUnderTest::runtime_config_watcher`] /
    /// [`SystemUnderTest::runtime_config_path`]. Requires the default
    /// `EventSink::Capturing` (the synchronous RealBus is a blocking emitter,
    /// forbidden by the watcher's emitter contract → build() panics).
    pub fn with_runtime_config_watch(mut self) -> Self {
        self.runtime_config_watch = true;
        self
    }

    /// Lifecycle-harvest (SYS-AC 259-261): start a REAL [`MetaSchemaWatcher`]
    /// over a seeded `<ws>/.advance/meta-schema.yaml`, registering the SAME
    /// loader into `register_agent_fs` (so the live schema drives `fs_write`
    /// auto-populate after a reload) and emitting `runtime.schema_reloaded`
    /// into the SUT event sink. Access via [`SystemUnderTest::schema_watcher`] /
    /// [`SystemUnderTest::schema_loader`] / [`SystemUnderTest::meta_schema_path`].
    /// Requires `Cap::Fs` (the loader lives in the fs registration) and the
    /// default `EventSink::Capturing` (build() panics otherwise).
    pub fn with_meta_schema_watch(mut self) -> Self {
        self.meta_schema_watch = true;
        self
    }

    /// Sched-harvest 1A (SYS-AC-110): enforce the PRD §5.7.4 submitter-grant
    /// subset rule on `submit_component` admission (scheduler rule 5) via the
    /// REAL validator adapter the MODULE-014 §1.7 recipe prescribes —
    /// `cap_grant::validate_capability_subset` over the SUT's own wired
    /// `GrantStore::list_by_grantee` (Active-only filter, CSV→array
    /// re-projection, `agent:`-prefix duality, fail-closed catch-all per the
    /// `CapGrantSubsetAdapter` precedent). Off by default → submit rule 5 is
    /// skipped (`None` gate — byte-identical pre-seam behavior for every
    /// existing test). Requires `.with_triggers()` (the submit seam) and
    /// `GrantMode::Real` (the grant store) — `build()` panics otherwise.
    pub fn with_submit_subset_gate(mut self) -> Self {
        self.submit_subset_gate = true;
        self
    }

    /// Sched-harvest 1A (SYS-AC-168): activate the reply-tracker AC-09
    /// await-deadlock admission gate by injecting the REAL cap-lifecycle
    /// `AgentTreeStore` — the same bare-id store `.agents()` builds and the
    /// `DefaultSpawner` mutates — as `ManagerOptions.agent_tree` (its
    /// `AgentTreeSnapshot` impl is the production MODULE-005 snapshot:
    /// bare-id `parent_of` with explicit `None` roots, exactly the
    /// `forms_cycle` walk contract). Off by default → `agent_tree: None`
    /// (the gate is skipped entirely; every pre-slice await witness is
    /// byte-identical). Requires `.agents()` — `build()` panics otherwise.
    pub fn with_await_deadlock_gate(mut self) -> Self {
        self.await_deadlock_gate = true;
        self
    }

    /// Boot the configured system loading `guest_wasm` (a `wasm32-unknown-unknown`
    /// core module, wrapped to a Component here) as the agent's behavior.
    pub async fn build(self, guest_wasm: &[u8]) -> SystemUnderTest {
        // Lifecycle-harvest axis guards (fail loud at build, not mid-test):
        // (a) both watcher axes install the SUT sink as a watcher emitter, and
        // the watcher emitter contracts forbid blocking emitters — the
        // synchronous RealBus (EventBus::new_synchronous_for_tests) is one.
        // (b) the meta-schema loader is constructed and consumed inside the
        // `Cap::Fs` registration block, so the axis is meaningless without it.
        if (self.runtime_config_watch || self.meta_schema_watch)
            && matches!(self.events, EventSink::RealBus)
        {
            panic!(
                "with_runtime_config_watch()/with_meta_schema_watch() require the default \
                 EventSink::Capturing — the synchronous RealBus is a blocking emitter, \
                 forbidden by the watcher emitter contracts (CONTRACT-180)"
            );
        }
        if self.meta_schema_watch && !self.caps.contains(&Cap::Fs) {
            panic!("with_meta_schema_watch() requires Cap::Fs (the schema loader is wired into register_agent_fs)");
        }
        if self.with_sqlite_index && !self.caps.contains(&Cap::Fs) {
            panic!("with_sqlite_index() requires Cap::Fs (the SQLite triple-sync trio is wired into register_agent_fs)");
        }
        if self.failing_git_sync && !self.caps.contains(&Cap::Fs) {
            panic!("with_failing_git_sync() requires Cap::Fs (the GitSync port is wired into register_agent_fs)");
        }
        if (self.with_live_l6 || self.failing_l6_committer) && !self.with_live_memory {
            panic!("with_live_l6()/with_failing_l6_committer() require with_live_memory() (L6 dispatch attaches to the live post-processor)");
        }
        // Wave-7 Lane A (069/216/186/187): the L6-classifier-injection axes dial a SECOND
        // LoopbackLlm through the real `attach_l6`. FAIL LOUD on every misconfig that would
        // SILENTLY skip the attach (and build a never-driven second gateway): the live-PP
        // install runs only under `if let (Some(store), Some(lp))` below, which needs both a
        // shared store (Cap::Memory) AND a main loopback LLM (not LlmMode::Off); `with_live_l6`
        // is only a flag. Mutually exclusive with each other + the committer-fault axis.
        if self.with_recording_l6 || self.with_failing_l6_gateway {
            if !self.with_live_memory {
                panic!("with_recording_l6()/with_failing_l6_gateway() require with_live_memory() (L6 dispatch attaches to the live post-processor)");
            }
            if !self.caps.contains(&Cap::Memory) {
                panic!("with_recording_l6()/with_failing_l6_gateway() require Cap::Memory (no shared store ⇒ no live post-processor ⇒ no L6 dispatch)");
            }
            if matches!(self.llm, LlmMode::Off) {
                panic!("with_recording_l6()/with_failing_l6_gateway() require a loopback LLM (no main gateway ⇒ the live post-processor is never installed ⇒ the L6 gateway is built but never driven)");
            }
        }
        if [
            self.with_recording_l6,
            self.with_failing_l6_gateway,
            self.failing_l6_committer,
        ]
        .iter()
        .filter(|b| **b)
        .count()
            > 1
        {
            panic!("with_recording_l6() / with_failing_l6_gateway() / with_failing_l6_committer() are mutually exclusive — pick exactly one L6 classifier/committer fault-or-recording axis");
        }
        // Wave-10 Lane A (SYS-AC-069): the real staleness-probe axis swaps `attach_l6`'s None shim
        // for `attach_l6_with_stale_resolver(Some(..))` in the SHARED (non-failing) live-L6 branch.
        // Fail loud on every misconfig that would silently no-op the swap (the live PP installs only
        // under Cap::Memory + with_live_memory) or route to the hand-mirrored failing-committer
        // branch (which has no resolver seam). Needs a Consistent-yielding classifier
        // (recording/live L6) so the synthesis 5-gate's classification gate passes.
        if self.with_real_l6_probe {
            if !self.with_live_memory {
                panic!("with_real_l6_probe() requires with_live_memory() (the real probe is wired into the live post-processor's attach_l6)");
            }
            if !self.caps.contains(&Cap::Memory) {
                panic!("with_real_l6_probe() requires Cap::Memory (no shared store ⇒ no live post-processor ⇒ no L6 dispatch)");
            }
            if self.failing_l6_committer {
                panic!("with_real_l6_probe() is incompatible with with_failing_l6_committer() (that path mirrors attach_l6's body by hand and has no stale-resolver seam)");
            }
            if !(self.with_recording_l6 || self.with_live_l6) {
                panic!("with_real_l6_probe() requires a classifier axis that yields Consistent clusters — .with_recording_l6() or .with_live_l6() (else the synthesis 5-gate classification gate never passes)");
            }
        }

        let tempdir = tempfile::TempDir::new().expect("tempdir");
        let workspace_root = tempdir.path().to_path_buf();
        let agent_workspace = workspace_root.join(AGENT_DIR);
        std::fs::create_dir_all(&agent_workspace).expect("create agent workspace");

        // Event sink. (Constructed BEFORE the git queue since lifecycle-harvest:
        // the queue's worker captures the sink at spawn for `git.commit` events.)
        let (bus, event_db_path) = match self.events {
            EventSink::Capturing => (BusHandle::Capturing(Arc::new(CapturingBus::new())), None),
            EventSink::RealBus => {
                let jsonl_dir = workspace_root.join(".runtime/events/jsonl");
                let db_path = workspace_root.join(".runtime/events.db");
                std::fs::create_dir_all(&jsonl_dir).expect("create events jsonl dir");
                let cfg = EventBusConfig::new(jsonl_dir, db_path.clone());
                let real = EventBus::new_synchronous_for_tests(cfg).expect("real event bus");
                (BusHandle::Real(Arc::new(real)), Some(db_path))
            }
        };
        let bus_dyn = bus.as_dyn();

        // Real git repo (unborn HEAD) + per-write commit queue, bus-wired so
        // every successful commit emits `git.commit` (production cli parity,
        // MODULE-003-AC-25 / SYS-AC-247).
        advance_git::bootstrap_repo_at(&workspace_root).expect("bootstrap_repo_at");
        // Wave-10 Lane A (SYS-AC-069): seed file-ref-backed files into the workspace + commit them
        // (one `[seed]` commit, NOT `[l6]`/`[turn]`) BEFORE any turn — so a `.with_real_l6_probe()`
        // FileRef carrying `blob_oid_of_bytes(content)` resolves to a real, matching git blob. Each
        // lands at `workspace_root.join(vpath)` (the territory root the resolver tree maps AGENT_ID
        // to). Done before the queue spawn (queue is idle until a turn, so no race) and before any
        // turn so the working tree is clean. No-op when no files are seeded (byte-identical).
        if !self.seeded_workspace_files.is_empty() {
            commit_seeded_workspace_files(&workspace_root, &self.seeded_workspace_files);
        }
        let queue = Arc::new(
            advance_git::DefaultGitCommitQueue::spawn_with_event_bus(
                workspace_root.clone(),
                bus_dyn.clone(),
            )
            .expect("git queue spawn"),
        );
        let queue_trait: Arc<dyn GitCommitQueue> = queue.clone();
        // Harvest-wave (SYS-AC-236): inject an always-failing GitSync at the
        // designed `Arc<dyn GitSync>` port to drive the production fail-soft git
        // leg; default → the real `Adv003GitSync`.
        let git_sync: Arc<dyn GitSync> = if self.failing_git_sync {
            Arc::new(FailingGitSync)
        } else {
            Arc::new(Adv003GitSync::new(queue_trait))
        };

        // Lifecycle-harvest (SYS-AC 152-154/237): REAL RuntimeConfigWatcher over
        // a seeded minimal-valid runtime-config.yaml, SUT sink as emitter.
        let runtime_config = if self.runtime_config_watch {
            let advance_dir = workspace_root.join(".advance");
            std::fs::create_dir_all(&advance_dir).expect("create .advance dir");
            let cfg_path = advance_dir.join("runtime-config.yaml");
            std::fs::write(&cfg_path, MINIMAL_RUNTIME_CONFIG_YAML)
                .expect("seed runtime-config.yaml");
            let watcher = RuntimeConfigWatcher::new(&cfg_path)
                .await
                .expect("RuntimeConfigWatcher::new over the seeded config");
            watcher.set_event_emitter(bus_dyn.clone());
            Some(RuntimeConfigHandles {
                watcher: Arc::new(watcher),
                path: cfg_path,
            })
        } else {
            None
        };

        // Lifecycle-harvest (SYS-AC 259-261): REAL MetaSchemaWatcher over a
        // seeded meta-schema.yaml; the loader is ALSO handed to
        // register_agent_fs below so fs_write auto-populate tracks reloads.
        let schema_watch = if self.meta_schema_watch {
            let advance_dir = workspace_root.join(".advance");
            std::fs::create_dir_all(&advance_dir).expect("create .advance dir");
            let schema_path = advance_dir.join("meta-schema.yaml");
            std::fs::write(&schema_path, MINIMAL_META_SCHEMA_YAML).expect("seed meta-schema.yaml");
            let loader = Arc::new(
                MetaSchemaLoader::load_from_disk(&schema_path)
                    .expect("MetaSchemaLoader::load_from_disk over the seeded schema"),
            );
            let watcher = MetaSchemaWatcher::spawn(
                Arc::clone(&loader),
                Some(bus_dyn.clone()),
                std::time::Duration::from_millis(50),
            );
            Some(SchemaWatchHandles {
                watcher,
                loader,
                path: schema_path,
            })
        } else {
            None
        };

        // The messaging/await/fs tree view (canonical `agent:` ids). Default →
        // single-node OneAgentTree (BS-3, byte-identical); `.agents()` → multi-node.
        let (tree_reader, tree_snap): (Arc<dyn AgentTreeReader>, Arc<dyn AgentTreeSnapshot>) =
            if self.agents.is_empty() {
                let t = Arc::new(OneAgentTree::new(agent_workspace.clone()));
                (
                    t.clone() as Arc<dyn AgentTreeReader>,
                    t as Arc<dyn AgentTreeSnapshot>,
                )
            } else {
                // GAP-2: root territories at the RAW workspace_root (the git
                // workdir), NOT agent_workspace (`<ws>/agent`) — each node gets a
                // distinct nested dir so concurrent writes land on disjoint,
                // repo-relative trees.
                let t = Arc::new(HarnessAgentTree::new(&self.agents, &workspace_root));
                (
                    t.clone() as Arc<dyn AgentTreeReader>,
                    t as Arc<dyn AgentTreeSnapshot>,
                )
            };
        // GAP-3 (T57-5/6 non-vacuity witness): retain the canonical
        // HarnessAgentTree snapshot provider so a test can build a
        // DefaultVirtualPathResolver over it and exercise resolve_child_read +
        // the Rule-2 child-territory write-block — an EMPTY children_of would
        // FAIL those, proving GAP-1 populated the maps. `None` in the
        // single-agent (OneAgentTree) path.
        let harness_agent_tree: Option<Arc<dyn AgentTreeSnapshot>> = if self.agents.is_empty() {
            None
        } else {
            Some(tree_snap.clone())
        };
        let registry: Arc<dyn HostRegistry> = Arc::new(InMemoryHostRegistry::new());

        // Wave-12 axis build-time guards (fail loud, mirror the existing axes).
        if self.with_real_spawn_tree {
            assert!(
                self.caps.contains(&Cap::Llm),
                ".with_real_spawn_tree() requires a loopback LLM (the # Available Delegates section reaches the prompt only via the publishing assembler)"
            );
            assert!(
                self.caps.contains(&Cap::Fs),
                ".with_real_spawn_tree() requires Cap::Fs (the bare-id AgentTreeStore + spawn territories)"
            );
        }
        if self.with_tool_repetition_guard {
            assert!(
                self.caps.contains(&Cap::Tools),
                ".with_tool_repetition_guard() requires Cap::Tools (the guarded tool-invoke dispatch)"
            );
            assert!(
                self.caps.contains(&Cap::Llm),
                ".with_tool_repetition_guard() requires a loopback LLM (the next-turn Tier-3 drain runs via the publishing assembler)"
            );
        }
        // Wave-15 Lane E (SYS-AC-012) axis guard (fail loud).
        if self.with_tool_grant_filter {
            assert!(
                self.caps.contains(&Cap::Tools),
                ".with_tool_grant_filter() requires Cap::Tools (the filtered CallableInventory feeds the # Available Tools section)"
            );
            assert!(
                self.caps.contains(&Cap::Llm) && !matches!(self.llm, LlmMode::Off),
                ".with_tool_grant_filter() requires a loopback LLM (Cap::Llm + .llm(Loopback*)) — the filtered CallableInventory + # Available Tools section reach the prompt only via the publishing assembler (installed under `if let Some(lp) = &llm`)"
            );
            assert!(
                matches!(self.grant, GrantMode::AllowAll),
                ".with_tool_grant_filter() is mutually exclusive with GrantMode::Real (the axis owns its dedicated GrantStore for the tools-grant filter)"
            );
        }
        // Wave-13 (SYS-AC-172) axis guards (fail loud).
        if self.with_decomposition {
            assert!(
                self.caps.contains(&Cap::Llm) && !matches!(self.llm, LlmMode::Off),
                ".with_decomposition() requires a loopback LLM (Cap::Llm + .llm(Loopback*)) — the # Active Task Decomposition section reaches the prompt only via the publishing assembler"
            );
            assert!(
                !self.with_skills_summary && !self.with_live_memory,
                ".with_decomposition() cannot combine with .with_skills_summary()/.with_live_memory() — those assembler branches pass EmptyDecomposition and would silently drop the decomposition reader"
            );
        }

        // Wave-12 (SYS-AC-011): the REAL bare-id spawn store, SHARED between the
        // production spawn host-fns (registered here) AND the turn assembler's
        // agent_tree port (selected below). Mirrors production cli wiring.rs: ONE
        // Arc<AgentTreeStore> (bare "harness" root) → register_agent_spawn over a
        // DefaultSpawner::with_template_resolver → store.clone() into the assembler.
        // A real spawn-sub records a Sub under "harness"; the colon assemble turn
        // lists it via the [bare, colon] alias bridge.
        let real_spawn_store: Option<Arc<AgentTreeStore>> = if self.with_real_spawn_tree {
            let store = Arc::new(
                AgentTreeStore::new(workspace_root.clone()).expect("real spawn AgentTreeStore"),
            );
            let bare_id = AGENT_ID
                .strip_prefix("agent:")
                .unwrap_or(AGENT_ID)
                .to_string();
            let root_dir = store.workspace_root().join(&bare_id);
            std::fs::create_dir_all(&root_dir).expect("create bare-root workspace dir");
            store
                .insert_root(AgentNode {
                    id: AgentId(bare_id.clone()),
                    kind: AgentKind::Root,
                    parent: None,
                    workspace_path: root_dir,
                    // Wave-15 Lane E (SYS-AC-011): seed the Root with valid cap-grant
                    // families so a spawn-sub requesting `[fs, tools]` (a subset) passes
                    // the REAL `CapGrantSubsetAdapter` gate (a child's caps must subset
                    // the parent's). The Root is inserted directly (not gated) and is
                    // never rendered (the delegates section lists only `Sub` nodes), so
                    // this is invisible to the name-listing / repetition-guard axes.
                    capabilities: vec![
                        Capability {
                            id: CapabilityId::from("fs"),
                            params: CapParams(serde_json::Value::Null),
                        },
                        Capability {
                            id: CapabilityId::from("tools"),
                            params: CapParams(serde_json::Value::Null),
                        },
                    ],
                    template_ref: None,
                    status: AgentStatus::Active,
                })
                .expect("insert bare root");
            let spawner: Arc<dyn cap_lifecycle::Spawner> =
                Arc::new(DefaultSpawner::with_template_resolver(
                    (*store).clone(),
                    Arc::new(CapGrantSubsetAdapter::new()),
                    Arc::new(cap_lifecycle::BuiltinTemplateRegistry::new()),
                ));
            cap_lifecycle::register_agent_spawn(&*registry, spawner);
            Some(store)
        } else {
            None
        };

        // Wave-13 (SYS-AC-172): ONE shared `DefaultDecompositionStore` over a dedicated
        // AgentTreeStore rooted at the bare form of THIS SUT's agent id (derived from
        // `self.agent_id`, NOT the AGENT_ID const, so the axis respects an `.agent_id()`
        // override — adversarial-r11). Registered into BOTH the cap-lifecycle decomposition
        // host-fns (so a real `submit-decomposition` writes it) AND the assembler's
        // `CapDecompositionReader` below (so the next-turn `# Active Task Decomposition`
        // section reads the SAME live store — mirrors cli `wire_capabilities`). DORMANT for
        // shipped guests (`"lifecycle"` ∉ KNOWN_CAPABILITIES); the witness drives the
        // prod-registered handlers directly (the spawn_wiring_011 / sys_j54 precedent).
        let decomposition_store: Option<Arc<DefaultDecompositionStore>> = if self.with_decomposition
        {
            let tree =
                AgentTreeStore::new(workspace_root.clone()).expect("decomposition AgentTreeStore");
            let bare_id = self
                .agent_id
                .strip_prefix("agent:")
                .unwrap_or(&self.agent_id)
                .to_string();
            let root_dir = tree.workspace_root().join(&bare_id);
            std::fs::create_dir_all(&root_dir).expect("create decomp bare-root workspace dir");
            tree.insert_root(AgentNode {
                id: AgentId(bare_id.clone()),
                kind: AgentKind::Root,
                parent: None,
                workspace_path: root_dir,
                capabilities: Vec::new(),
                template_ref: None,
                status: AgentStatus::Active,
            })
            .expect("insert decomp bare root");
            let store = Arc::new(DefaultDecompositionStore::new(tree));
            register_agent_decomposition(&*registry, store.clone(), bus_dyn.clone());
            Some(store)
        } else {
            None
        };

        // Wave-12 (SYS-AC-122): retained for late-binding the per-turn assembler
        // into the tool-path guard (set after `inner` is built — mirrors start.rs).
        let mut tool_guard: Option<Arc<advance_run_manager::RepetitionGuard>> = None;

        // Stage-B SQLite/boot-reconcile axis: retained for boot_reconcile()/fts_recall()
        // (set inside the Cap::Fs block when `.with_sqlite_index()` is on; None otherwise).
        let mut sqlite_handle_opt: Option<R2d2SqliteIndexHandle> = None;
        let mut fs_schema_opt: Option<Arc<MetaSchemaLoader>> = None;
        // Harvest-wave (SYS-AC-074/075/218): retain the skill provider so a test
        // can reach the SAME `SkillStore` the host-fn handlers resolve (e.g. to
        // call admin `elevate_trust` for the Trusted-collision witness). `None`
        // unless `Cap::Skills`.
        let mut skill_provider_opt: Option<
            Arc<cap_skills::provider::SingleAgentSkillStoreProvider>,
        > = None;
        // Harvest-wave (SYS-AC-082/083/084/085/219): retain the CONCRETE lazy tool
        // registry so a test observes the SAME cache (`cache_len`/`list`) the
        // `tool-invoke` host-fn drives. `None` unless `Cap::Tools`.
        let mut tool_registry_opt: Option<Arc<cap_tools::LazyToolRegistry>> = None;

        // --- pre-runtime capability registrations ---
        if self.caps.contains(&Cap::Fs) {
            let resolver: Arc<dyn VirtualPathResolver> = Arc::new(DefaultVirtualPathResolver::new(
                workspace_root.clone(),
                tree_snap.clone(),
            ));
            // Lifecycle-harvest: when the meta-schema axis is on, register the
            // SAME loader the watcher reloads (live schema drives fs_write
            // auto-populate); otherwise the historic empty-path default.
            let schema = match &schema_watch {
                Some(h) => Arc::clone(&h.loader),
                None => Arc::new(MetaSchemaLoader::new_with_default(PathBuf::new())),
            };
            // Stage-B: wire the cap-fs triple-sync trio (db_sync + workspace_root +
            // agent_tree — all-Some-or-all-None per host_fn.rs:2965) over a fresh
            // in-memory SQLite index, retaining the concrete handle + schema for
            // boot_reconcile()/fts_recall(). Default off → trio stays None,None,None.
            let (db_sync, fs_ws, fs_tree): (
                Option<Arc<dyn SqliteSync>>,
                Option<PathBuf>,
                Option<Arc<dyn AgentTreeSnapshot>>,
            ) = if self.with_sqlite_index {
                let handle =
                    R2d2SqliteIndexHandle::new_in_memory().expect("in-memory sqlite index handle");
                let db: Arc<dyn SqliteSync> = Arc::new(Db030SqliteSync::new(
                    Arc::new(handle.clone()) as Arc<dyn SqliteIndexHandle>,
                ));
                sqlite_handle_opt = Some(handle);
                fs_schema_opt = Some(Arc::clone(&schema));
                (
                    Some(db),
                    Some(workspace_root.clone()),
                    Some(tree_snap.clone()),
                )
            } else {
                (None, None, None)
            };
            register_agent_fs(
                &*registry,
                resolver,
                bus_dyn.clone(),
                schema,
                Arc::new(StubFileHistoryProvider),
                Arc::new(DefaultAtomicWriter),
                None,
                db_sync,
                fs_ws,
                fs_tree,
                Some(git_sync),
            );
        }
        // Backbone Step 3: resolve the persistent cap-memory dir (default a fresh
        // `<workspace_root>/.agent/memory`, mirroring production's `wiring.rs`
        // subpath) + cap, then open a PERSISTENT store (was `MemoryStore::new()`).
        // The SAME store backs the WIT remember/recall/forget/recall-at handlers,
        // so a guest turn's memory persists to `<memory_dir>/<agent-slug>/
        // knowledge.jsonl` and survives a drop+reopen of the dir.
        let memory_dir = self
            .memory_dir
            .clone()
            .unwrap_or_else(|| workspace_root.join(".agent").join("memory"));
        let memory_cap = self.memory_cap.unwrap_or(DEFAULT_MAX_ACTIVE_PER_AGENT);
        // B1 backbone (2026-06-09, ADVERSARIAL-r7 fix): bind the store so the SAME
        // `Arc<MemoryStore>` registered for the WIT handlers is SHARED with the
        // context-assembler below (no second `open()` — mirrors prod
        // `WiringHandles.memory_store`).
        let shared_memory_store: Option<Arc<MemoryStore>> = if self.caps.contains(&Cap::Memory) {
            Some(Arc::new(
                MemoryStore::open(memory_dir.clone(), memory_cap)
                    .expect("open persistent memory store"),
            ))
        } else {
            None
        };
        // Stage-C harvest pass-2 (070/215/216): seed the shared store BEFORE any turn
        // (e.g. an L6 synthesis-eligible cluster) so the consolidation's
        // `store.list(agent)` sees it and the synthesis writes/commit land inside the
        // default in-workspace `memory_dir`.
        if let Some(store) = &shared_memory_store {
            for entry in &self.seeded_knowledge {
                store
                    .insert(&entry.agent_id, entry.clone())
                    .expect("seed knowledge insert");
            }
        }
        // Rollback-memory slice (SYS-AC-062/063/064): the harness mirrors the
        // production wiring — a RETAINED `L6CursorStore::with_root` (the
        // `_knowledge_cursor.yaml` file half + the witness read handle) and
        // the REAL MODULE-003-backed `GitMemoryRestore` over THIS SUT's
        // workspace repo (the same `DefaultWorkspaceRollback` sys_j50/j51
        // witness, `git.rollback` emission included).
        let cursor_store: Option<Arc<L6CursorStore>> = shared_memory_store
            .as_ref()
            .map(|_| Arc::new(L6CursorStore::with_root(memory_dir.clone())));
        if let (Some(store), Some(cursor)) = (&shared_memory_store, &cursor_store) {
            let git_restore: Option<Arc<dyn MemoryGitRestore>> =
                advance_git::DefaultWorkspaceRollback::with_event_bus(
                    workspace_root.clone(),
                    bus_dyn.clone(),
                )
                .ok()
                .map(|rb| {
                    Arc::new(GitMemoryRestore {
                        inner: Arc::new(rb),
                    }) as Arc<dyn MemoryGitRestore>
                });
            register_agent_memory_with_git(
                &*registry,
                store.clone(),
                bus_dyn.clone(),
                cursor.clone(),
                git_restore,
            );
        }
        if self.caps.contains(&Cap::Skills) {
            // Harvest-wave fix: root the provider at the agent workspace dir that
            // CONTAINS `.agent/` (= `agent_workspace` = `<ws>/<AGENT_DIR>`, the same
            // territory the fs VirtualPathResolver roots the default agent at).
            // `DiskSkillStorage` itself appends `.agent/skills/...`, so the prior
            // `.join(".agent")` double-nested to `<ws>/agent/.agent/.agent/skills`,
            // where a guest `fs.read ".agent/skills/..."` (resolving to
            // `<ws>/agent/.agent/skills`) could never observe an activated skill.
            // (Latent: every sys_j25 witness was `#[ignore]`d, so it never fired.)
            // Wave-7 Lane A (186/187): point the candidate consumer at the cap-memory
            // `memory_dir` (`<ws>/.agent/memory`) — the SAME flat `_skill_candidates.jsonl`
            // the L6 producer writes (`attach_l6`'s `mem_root` = `memory_dir`), mirroring
            // production `wiring.rs:574`. NOTE: `candidate_dir` is `memory_dir`, NOT the skills
            // `agent_workspace` (`<ws>/agent`) — wiring it to the skills root would make
            // `list-skill-candidates` read an absent JSONL. Inert for non-L6 Cap::Skills tests
            // (no producer ⇒ absent file ⇒ `list_pending` returns empty, byte-identical).
            let provider = Arc::new(
                cap_skills::provider::SingleAgentSkillStoreProvider::new(
                    &self.agent_id,
                    agent_workspace.clone(),
                )
                .with_candidate_dir(memory_dir.clone()),
            );
            // Wave-11 Lane A (076/077): when opted in via `.with_skills_lifecycle()`, wire the
            // PRODUCTION turn-lane path (mirrors cli/src/wiring.rs:732-757) so an agent
            // activate/rollback emits skill.activated/skill.rolled_back + a CommitType::Turn
            // commit. The coordinator SHARES the provider's resolved store (one mutex across all 8
            // skills host-fns) and is rooted at the SAME `agent_workspace` as the provider, so the
            // committed `affected_paths` match where DiskSkillStorage writes (`agent/.agent/skills/
            // ...`) + where `fs.read .agent/skills/...` resolves. Default-off → the event-less
            // registration (074/075/218 byte-identical).
            if self.with_skills_lifecycle {
                use cap_skills::provider::SkillStoreProvider as _;
                let shared = provider
                    .get(&self.agent_id)
                    .await
                    .expect("single-agent provider resolves its own id");
                let coordinator =
                    Arc::new(cap_skills::SkillPersistenceCoordinator::with_shared_store(
                        self.agent_id.clone(),
                        agent_workspace.clone(),
                        shared,
                        queue.clone() as Arc<dyn GitCommitQueue>,
                        bus_dyn.clone(),
                    ));
                cap_skills::register_agent_skills_with_lifecycle(
                    &*registry,
                    provider.clone(),
                    coordinator,
                );
            } else {
                cap_skills::register_agent_skills(&*registry, provider.clone());
            }
            skill_provider_opt = Some(provider);
        }

        // --- LLM gateway (loopback) ---
        // HF-2: thread the harness bus + the optional budget/repetition knobs into the
        // loopback gateway. `Loopback` is the single-200 back-compat case (converted to a
        // one-element script); `LoopbackScripted` carries the FIFO script directly.
        if self.with_delta_tee && matches!(self.llm, LlmMode::Off) {
            panic!(".with_delta_tee() requires a loopback LLM");
        }
        let mut llm_stream_reaper: Option<Arc<cap_llm::AgentStreamReaper>> = None;
        let llm = match self.llm {
            LlmMode::Off => None,
            LlmMode::Loopback(script) => {
                let responses = vec![llm_loopback::ScriptedResponse::ok_chat(
                    &script.reply_text,
                    script.prompt_tokens,
                    script.completion_tokens,
                )];
                let (lp, reaper) = boot_loopback_for_sut(
                    responses,
                    self.budget.clone(),
                    self.repetition.clone(),
                    bus_dyn.clone(),
                    self.agent_id.clone(),
                    &*registry,
                    self.with_delta_tee,
                    self.delta_tee_timing,
                )
                .await;
                llm_stream_reaper = reaper;
                Some(lp)
            }
            LlmMode::LoopbackScripted(responses) => {
                let (lp, reaper) = boot_loopback_for_sut(
                    responses,
                    self.budget.clone(),
                    self.repetition.clone(),
                    bus_dyn.clone(),
                    self.agent_id.clone(),
                    &*registry,
                    self.with_delta_tee,
                    self.delta_tee_timing,
                )
                .await;
                llm_stream_reaper = reaper;
                Some(lp)
            }
        };

        // --- Wave-7 Lane A: the SEPARATE L6-classifier gateway (069/216/186/187) ---
        // A SECOND LoopbackLlm, deliberately NOT `register_agent_llm`'d, so it never touches
        // the guest/extractor scripted FIFO above — the production
        // `advance_cli::l6_classifier::LlmL6Classifier` dials THIS gateway inside `attach_l6`,
        // leaving 070/215's main-FIFO scripts byte-identical. budget/repetition = None
        // (AllowAllBudget / NoOpRepetitionGuard) so the L6 dial is never gated; event_bus =
        // the SUT sink so the dial's `llm.*` events are faithfully observable. Witness the
        // dial via `l6_chat_request_count()` / `l6_chat_request_bodies()`. (The build()
        // guards above already proved with_live_memory + Cap::Memory + a main loopback, so the
        // live-PP install below will actually drive this classifier.)
        let (l6_llm, l6_classifier): (
            Option<llm_loopback::LoopbackLlm>,
            Option<Arc<dyn cap_memory::l6::L6Classifier + Send + Sync>>,
        ) = if self.with_recording_l6 || self.with_failing_l6_gateway {
            let script = if self.with_failing_l6_gateway {
                // GENERIC non-retryable HTTP 400 → real OpenAI adapter maps to
                // ProviderError("http 400: …") (non-retryable per retry.rs) → exactly ONE
                // upstream attempt → chat() Err → classify() → L6Error::LlmFailure (216).
                vec![llm_loopback::ScriptedResponse::err(
                    400,
                    r#"{"error":{"message":"bad request"}}"#,
                )]
            } else {
                // ONE valid L6 output: drives the 186/187 skill candidates + the 069 keystone dial,
                // and (under `.with_real_l6_probe()`) the Consistent classification that lets the
                // synthesis 5-gate pass. (Without the real probe, attach_l6's empty staleness probe
                // orphans file-refs so the synthesis gate never passes — default empty-stub path.)
                vec![llm_loopback::ScriptedResponse::ok_chat(
                    L6_RECORDING_OUTPUT,
                    7,
                    9,
                )]
            };
            let lp = llm_loopback::LoopbackLlm::start(
                script,
                None,
                None,
                bus_dyn.clone(),
                self.agent_id.clone(),
            )
            .await;
            // Concrete-clone-then-unsize idiom (mirrors build_harness_live_post_processor):
            // Arc<LlmGateway> coerces to the bare dyn trait object at a typed binding.
            let gw: Arc<dyn cap_llm::LlmGatewayInternal + Send + Sync> = lp.gateway.clone();
            let classifier: Arc<dyn cap_memory::l6::L6Classifier + Send + Sync> =
                Arc::new(advance_cli::l6_classifier::LlmL6Classifier::new(gw, None));
            (Some(lp), Some(classifier))
        } else {
            (None, None)
        };

        // --- grant mode ---
        let (grant_check, mut grant_store, grant_sweeper, grant_sweeper_handle): (
            Arc<dyn GrantCheck>,
            Option<Arc<cap_grant::GrantStore>>,
            Option<Arc<cap_grant::TtlSweeper>>,
            Option<tokio::task::JoinHandle<()>>,
        ) = match self.grant {
            GrantMode::AllowAll => (Arc::new(AllowAll), None, None, None),
            GrantMode::Real => {
                let sqlite = Arc::new(R2d2SqliteIndexHandle::new_in_memory().expect("sqlite"));
                let handles = register_cap_grant(
                    sqlite,
                    bus_dyn.clone(),
                    None,
                    self.agent_id.clone(),
                    self.grant_sweeper_interval,
                )
                .expect("register_cap_grant");
                if self.caps.contains(&Cap::Grant) {
                    let validator: Arc<dyn SubsetValidator> = Arc::new(SubsetValidatorImpl::new());
                    let resolver_chain = Arc::new(build_resolver_chain(
                        self.grant_chain,
                        &validator,
                        self.grant_resolver_budget.clone(),
                        self.grant_channel_approval.clone(),
                    ));
                    register_agent_grant(
                        &*registry,
                        AgentGrantBundle {
                            store: handles.store.clone(),
                            validator,
                            presets: self
                                .grant_presets
                                .clone()
                                .unwrap_or_else(|| Arc::new(PresetRegistry::with_builtins())),
                            resolver_chain,
                            event_bus: bus_dyn.clone(),
                        },
                    );
                }
                (
                    handles.grant_check.clone(),
                    Some(handles.store.clone()),
                    handles.sweeper,
                    handles.sweeper_handle,
                )
            }
        };

        // Wave-15 Lane E (SYS-AC-012): the `.with_tool_grant_filter()` axis owns a
        // DEDICATED `GrantStore` (mutually exclusive with GrantMode::Real, asserted at
        // build entry). Build it via the same `register_cap_grant` recipe GrantMode::Real
        // uses (which calls `GrantSqliteIndex::ensure_schema()` — the `grant_index` table
        // is NOT created by `R2d2SqliteIndexHandle::new_in_memory()`'s migrations), then
        // REBIND `grant_store` to it BEFORE the callable-inventory construction below, so
        // the `ToolsGrantReaderImpl` clone and the SUT `grant_store()` accessor share ONE
        // `Arc` (the witness seeds a `"tools"` grant via the latter; the reader observes it).
        if self.with_tool_grant_filter {
            let sqlite =
                Arc::new(R2d2SqliteIndexHandle::new_in_memory().expect("tool-grant-filter sqlite"));
            let handles =
                register_cap_grant(sqlite, bus_dyn.clone(), None, self.agent_id.clone(), None)
                    .expect("register_cap_grant for with_tool_grant_filter");
            grant_store = Some(handles.store.clone());
        }

        // Harvest-triggers slice (SYS-AC 098-114): construct the REAL scheduler trigger
        // subsystems sharing the SUT's event sink. `bus_dyn.clone()` is the SAME
        // `Arc<CapturingBus>` that `events()` reads, so a real `CronDriver` fire's
        // `trigger.fired` (emitted via this sink) is observable. The registry root MUST
        // be created before `ComponentRegistry::open_in` (it canonicalizes the dir);
        // `<ws>/.triggers` is independent of the event-sink `.runtime` path.
        // (Sched-harvest 1A: block sits AFTER the grant-mode block so the opt-in
        // `.with_submit_subset_gate()` can compose the real adapter over the SUT's
        // own wired `GrantStore` — `triggers` is consumed only at SUT construction.)
        let triggers = if self.with_triggers {
            let trig_root = workspace_root.join(".triggers");
            std::fs::create_dir_all(&trig_root).expect("create .triggers registry root");
            let registry = Arc::new(
                ComponentRegistry::open_in(&trig_root, "components.db")
                    .await
                    .expect("open trigger ComponentRegistry"),
            );
            let mut api = InMemoryComponentSubmitApi::new()
                .with_registry(registry.clone())
                .with_quota(20);
            // Sched-harvest 1A (SYS-AC-110): inject the REAL submitter-grant
            // subset gate (MODULE-014 §1.7 adapter recipe) over the SUT's own
            // grant store. Submit admission rule 5 then rejects over-grant
            // requests with `SpawnError::SubsetViolation` BEFORE any side
            // effect (no quota slot, no registry row, no store row).
            if self.submit_subset_gate {
                let store = grant_store.clone().expect(
                    ".with_submit_subset_gate() requires GrantMode::Real (the real GrantStore \
                     is the adapter's grant source)",
                );
                api = api.with_subset_gate(Arc::new(CapGrantSubmitSubsetGate { grants: store }));
            }
            Some(TriggerHandles {
                trigger_bus: Arc::new(TriggerBusDispatchImpl::new().with_max_chain_depth(10)),
                submit_registry: registry,
                submit_api: Arc::new(api),
                emitter: bus_dyn.clone(),
            })
        } else {
            None
        };
        if self.submit_subset_gate && triggers.is_none() {
            panic!(
                ".with_submit_subset_gate() requires .with_triggers() (the submit admission seam)"
            );
        }

        // --- HF: cap-channel outbound capture + inbound inject (.with_channel_capture()) ---
        let channel = if self.channel_capture {
            let captured: Arc<Mutex<Vec<CapturedOutbound>>> = Arc::new(Mutex::new(Vec::new()));
            let chain: Arc<dyn HttpSecurityChain> = Arc::new(CapturingChain {
                captured: captured.clone(),
            });
            let manager = Arc::new(SubscriptionManager::new());
            let outbound = Arc::new(OutboundDispatcher::new(chain, manager.clone()));
            register_channel_host(
                &*registry,
                ChannelHostBundle {
                    manager: manager.clone(),
                    outbound,
                },
            );
            // Pre-create a subscription owned by THIS SUT's agent (so the agent-id
            // `drive_channel_send_raw` threads into the HostCallContext matches the
            // owner — dispatch rejects a mismatch), with an OutboundConfig (else
            // dispatch → InvalidConfig) and a known adapter (Webhook; `Other` rejected).
            let sub_id = manager
                .subscribe(
                    self.agent_id.clone(),
                    ChannelConfig {
                        adapter_type: AdapterType::Webhook,
                        params: Vec::new(),
                        outbound: Some(OutboundConfig {
                            method: ChannelHttpMethod::Post,
                            url_template: "https://hooks.example.com/reply".to_string(),
                            headers: Vec::new(),
                        }),
                    },
                )
                .expect("pre-create channel subscription");
            Some(ChannelCapture {
                manager,
                sub_id,
                captured,
            })
        } else {
            None
        };

        // --- HF: in-process MCP client over scripted transports (.with_mcp_transports()) ---
        let mcp_client = if self.mcp_servers.is_empty() {
            None
        } else {
            let mut builder = McpServersConfig::builder();
            let mut injected: HashMap<String, Arc<dyn McpTransport>> = HashMap::new();
            for spec in &self.mcp_servers {
                let patterns: Vec<ToolPattern> = spec
                    .tools
                    .iter()
                    .map(|t| ToolPattern::compile(t).expect("compile tool pattern"))
                    .collect();
                builder = builder
                    .add_server(McpServerEntry {
                        server_id: spec.server_id.clone(),
                        description: format!("scripted:{}", spec.server_id),
                        // Dummy spec — never spawned (the injected transport keyed
                        // by server_id bypasses the real stdio/http spawn).
                        transport: McpTransportSpec::Stdio {
                            command: "true".to_string(),
                            args: Vec::new(),
                            env: BTreeMap::new(),
                        },
                        tool_patterns: Some(patterns),
                        tool_schemas: BTreeMap::new(),
                    })
                    .expect("add mcp server");
                injected.insert(
                    spec.server_id.clone(),
                    Arc::new(ScriptedMcpTransport {
                        server_id: spec.server_id.clone(),
                        reply: spec.reply.clone(),
                    }) as Arc<dyn McpTransport>,
                );
            }
            let config = Arc::new(builder.build());
            let client = Arc::new(McpClient::new_with_transports(
                config,
                Arc::new(NoOpLeakDetector),
                injected,
            ));
            register_mcp_client(&*registry, client.clone());
            Some(client)
        };

        // HF-2: keep a handle on the real, injector-wired breaker so a journey can drive it
        // (clone the Arc BEFORE it moves into the injector).
        let breaker: Arc<dyn CircuitBreakerBus> = Arc::new(DefaultCircuitBreakerBus::new());
        let injector = Arc::new(CapabilityInjector::new(
            registry.clone(),
            grant_check,
            breaker.clone(),
        ));

        // Runtime + production MessageHandler loading the guest.
        let runtime = Arc::new(
            ComponentRuntime::new(&WasmConfig {
                max_memory_pages: 256,
                epoch_interruption_ms: 100,
                fuel_enabled: false,
            })
            .expect("runtime"),
        );

        // cap-tools registers POST-runtime (LazyToolRegistry needs the ToolEngineHandle).
        if self.caps.contains(&Cap::Tools) {
            let engine = runtime.tool_engine_handle();
            // Harvest-wave: build the CONCRETE registry, retain its Arc for the
            // `tool_registry()` accessor, AND register the SAME Arc (coerced to the
            // trait object) into the host-fn — so `cache_len`/`list`/`register_binary`
            // observe exactly the registry `tool-invoke` drives. Real default config
            // (max_tool_instances=20, max_result_bytes=16 MiB).
            let mut tools_cfg = cap_tools::LazyRegistryConfig::default();
            if let Some(n) = self.tools_max_result_bytes {
                tools_cfg.max_result_bytes = n;
            }
            let tools = Arc::new(cap_tools::LazyToolRegistry::new_with_engine(
                tools_cfg, engine,
            ));
            if self.with_tool_repetition_guard {
                // Wave-12 (SYS-AC-122): mirror production cli Step 7 — a REAL guard
                // from the canonical defaults + PIH, late-bound to the per-turn
                // assembler below. A RunManager over the SUT bus resolves run_id;
                // ensure_run a live Run for the BARE caller the witness drives
                // (the guard's resolver — an Arc::clone of this rm — keeps the run
                // store alive after rm drops).
                let rm = advance_run_manager::RunManager::new_arc(bus_dyn.clone());
                let bare_id = AGENT_ID.strip_prefix("agent:").unwrap_or(AGENT_ID);
                rm.ensure_run(
                    "task-rep-122",
                    bare_id,
                    advance_run_manager::RunConfig::default(),
                )
                .expect("ensure_run for the tool-guard resolver");
                let guard = Arc::new(
                    rm.build_repetition_guard_from_config(
                        &advance_run_manager::RepetitionGuardConfig::default(),
                    )
                    .with_prompt_injection_helpers(Arc::new(
                        cap_http::DefaultPromptInjectionHelpers::default(),
                    )),
                );
                cap_tools::register_agent_tools_with_guard(
                    &*registry,
                    tools.clone() as Arc<dyn cap_tools::ToolRegistry>,
                    bus_dyn.clone(),
                    guard.clone(),
                );
                tool_guard = Some(guard);
            } else {
                cap_tools::register_agent_tools(
                    &*registry,
                    tools.clone() as Arc<dyn cap_tools::ToolRegistry>,
                    bus_dyn.clone(),
                );
            }
            tool_registry_opt = Some(tools);
        }

        let component = ComponentEncoder::default()
            .validate(true)
            .module(guest_wasm)
            .expect("wrap core module")
            .encode()
            .expect("encode component");
        let loaded = runtime.load_component(&component).expect("component loads");
        let cap_requests: Vec<CapRequest> = self
            .caps
            .iter()
            .map(|c| CapRequest {
                capability: CapabilityId::from(c.id()),
            })
            .collect();
        // Sched-harvest 1B: retain the instantiation quadruple on the SUT so
        // [`SystemUnderTest::wasm_runnable_hook`] can mint PRODUCTION
        // `WasmRunnableHook`s over THIS SUT's guest (same runtime / loaded
        // component / injector / caps the message-driven path uses).
        let runnable_parts = (
            runtime.clone(),
            loaded.clone(),
            injector.clone(),
            cap_requests.clone(),
        );
        let grant_run_bootstrap =
            self.grant_run_session
                .as_ref()
                .map(|(run_manager, run_config)| {
                    let cell: SessionRunCell = Arc::new(OnceLock::new());
                    (run_manager.clone(), run_config.clone(), cell)
                });
        let wasm_handler = WasmMessageHandler::new(
            runtime,
            loaded,
            injector,
            cap_requests,
            self.agent_id.clone(),
            "trace-harness".to_string(),
        );
        let wasm_handler = match &grant_run_bootstrap {
            Some((run_manager, _run_config, cell)) => wasm_handler.with_run_session(RunSession {
                run_manager: run_manager.clone(),
                cell: cell.clone(),
            }),
            None => wasm_handler,
        };
        let message_handler: Arc<dyn MessageHandler> = Arc::new(wasm_handler);

        // Shared mailbox + real dispatcher (emits msg.received) + the agent loop.
        // Arc-wrapped (W3) so the await-manager can share it (MailboxDispatcherImpl
        // is not Clone); inject_message still works through Arc Deref.
        // Stage-A notify slice (SYS-AC-174): default 64 (byte-identical) unless
        // `.with_mailbox_cap(n)` overrode it.
        let mailbox_cap = self.mailbox_cap.unwrap_or(64);
        let store = Arc::new(MailboxStore::new(
            std::num::NonZeroUsize::new(mailbox_cap).expect("mailbox cap must be > 0"),
        ));
        let reply_bus = bus_dyn.clone();
        // Capture a bus clone for build_agent_loop. (`bus_dyn` is now CLONED — not
        // moved — at the dispatcher site AND the Stage-C live-memory write-path below,
        // so it stays owned; each of these is an independent handle.) The harness wires
        // the real EventBusRejectionSink (no new event on green paths — rejection only) +
        // `None` outbound (gate-only, unchanged harness behavior).
        let loop_bus = bus_dyn.clone();
        // GAP-3: an extra bus clone for the per-node agent loops (`node_drivers`).
        let node_bus = bus_dyn.clone();
        // Backbone Step 2: a bus clone for the real ContextAssembler's
        // `context.assembled` emit — the CapturingBus captures it so SYS-AC-007 is
        // witnessable via `events()`.
        let assembler_bus = bus_dyn.clone();
        // Small-witness 2026-06-11: wire the SUT's injector-shared breaker into
        // the REAL dispatcher Layer-1 gate (deliver/reply/notify reject while an
        // agent-scope breaker is Open; Control bypasses) and spawn the production
        // Layer-4 `BreakerSubscriber` (freeze on Open, priority/FIFO drain on
        // Close). Breaker starts Closed ⇒ byte-identical behavior for every
        // existing test.
        // Wave-18 Lane-3 (MODULE-006-AC-02 infra): when `.with_channel_adapter(..)`
        // is set, build the dispatcher with `new_full` over a real
        // `StaticChannelAdapterRegistry` so `notify_channel` can resolve a channel id
        // to an adapter agent and DELIVER. Default (no channel adapters) keeps the
        // byte-identical `new` (EmptyChannelAdapterRegistry) path.
        let dispatcher_base = if self.channel_adapters.is_empty() {
            MailboxDispatcherImpl::new(store.clone(), tree_reader)
        } else {
            let mut channel_registry = StaticChannelAdapterRegistry::new();
            for (channel_id, adapter_agent_id) in &self.channel_adapters {
                channel_registry
                    .insert(channel_id.clone(), adapter_agent_id.clone())
                    .expect("with_channel_adapter: invalid channel/adapter id");
            }
            MailboxDispatcherImpl::new_full(
                store.clone(),
                tree_reader,
                Arc::new(MessageTrace::new()),
                Arc::new(channel_registry),
            )
        };
        let dispatcher = Arc::new(
            dispatcher_base
                // Clone (was a move): the Stage-C `.with_live_memory()` write-path
                // block below also needs `bus_dyn` for the components PostProcessor's
                // event sink. Refcount bump only — behaviour-identical.
                .with_event_bus(bus_dyn.clone())
                .with_circuit_breaker_bus(breaker.clone()),
        );
        let breaker_subscriber = BreakerSubscriber::spawn(breaker.clone(), store.clone());
        // Stage-A notify slice (SYS-J-55): register the production `notify-agent`
        // host-fn into the SUT registry, bridging the WIT
        // `advance:runtime/notify@0.1.0` surface to the already-built dispatcher
        // (which emits `msg.received` via its wired `.with_event_bus`). Coerce the
        // concrete dispatcher to the trait object (same unsizing idiom as
        // build_agents_handle). `registry` is still owned here (moved into the SUT
        // at the struct literal below). No new emitter is installed (the dispatcher
        // already holds the bus) → no build guard needed; with no notify call made,
        // behaviour is byte-identical for every existing build.
        advance_messaging::register_notify_host_fns(
            &*registry,
            dispatcher.clone() as Arc<dyn MailboxDispatcher>,
        );
        // Wave-20 production parity: register `notify-channel` over the SAME
        // dispatcher even when no channel adapters are configured. Without adapters,
        // calls fail at dispatcher resolution (`channel_unknown`), but guests that
        // import the full notify interface can still link.
        advance_messaging::register_notify_channel_host_fn(
            &*registry,
            dispatcher.clone() as Arc<dyn ChannelNotifier>,
        );
        // Backbone Step 4: opt-in accumulating outbound capture. When
        // `.with_reply_capture()` is set, wire a real `OutboundActionSink` (the
        // sys_j64 `RecordingSink` pattern) as the post-dispatch delivery seam so each
        // turn's first-action payload is observable; otherwise pass `None` (the
        // existing gate-only behaviour — every prior `run_turn` test is unaffected).
        let captured_replies: Arc<Mutex<Vec<Vec<u8>>>> = Arc::new(Mutex::new(Vec::new()));
        let outbound: Option<Arc<dyn OutboundActionSink>> = if self.reply_capture {
            Some(Arc::new(CapturingOutboundSink {
                replies: captured_replies.clone(),
            }))
        } else {
            None
        };
        let mut driver = build_agent_loop(store.clone(), message_handler, loop_bus, outbound);
        if let Some(reaper) = llm_stream_reaper.clone() {
            driver =
                driver.with_turn_observer(Arc::new(advance_cli::reap::CompositeTurnObserver::new(
                    vec![Arc::new(advance_cli::reap::ReapTurnObserver::for_agent(
                        reaper,
                        self.agent_id.clone(),
                        self.agent_id.clone(),
                    ))],
                )));
        }
        if let Some((run_manager, run_config, cell)) = grant_run_bootstrap {
            driver = driver.with_run_bootstrap(Arc::new(RunManagerBootstrap {
                run_manager,
                run_config,
                session_agent: self.agent_id.clone(),
                cell,
            }));
        }
        // Perf-CI lane (perf_slo harness): retain cheap Arc clones of the live
        // inner ContextAssembler (pre-`PublishingContextAssembler`, so timing it is the
        // bare `assemble()` with no gateway-publish hop) and the live PostProcessor, so
        // the perf witnesses time the named product seam DIRECTLY at a clean seam — never
        // a whole turn. Default `None`; populated only on the `.with_live_memory()` paths
        // below. Additive + default-off; every existing build is byte-identical (the
        // clones are unobserved unless a test calls the new accessors).
        let mut retained_inner_assembler: Option<
            Arc<dyn advance_shared_types::context::ContextAssembler>,
        > = None;
        let mut retained_live_pp: Option<Arc<dyn advance_shared_types::memory::PostProcessorHook>> =
            None;
        // Backbone Step 2: when the loopback LLM is wired, install the REAL
        // ContextAssemblerImpl (via the PublishingContextAssembler seam) so the
        // harness witnesses (a) `context.assembled` per real turn (SYS-AC-007) and
        // (b) the host-assembled `# Available Tools` merge reaching the loopback
        // request body (SYS-AC-010). The harness owns its ports directly: REAL
        // CapturingBus event_bus + a populated CallableInventory (≥1 wasm + ≥1 mcp)
        // + a host-fn inventory (≥1 entry) for the 3-source merge; agent_tree is
        // empty (delegates = SYS-AC-011, §3-deferred). Published under the harness
        // agent_id (= ComponentCtx.agent_id = the generate handler's ctx.agent_id),
        // against the SAME loopback gateway register_agent_llm got.
        if let Some(lp) = &llm {
            let callable: Arc<dyn advance_shared_types::traits::CallableInventoryReader> =
                if self.with_tool_grant_filter {
                    // Wave-15 Lane E (SYS-AC-012): a two-WASM-tool inventory wrapped with a
                    // CONTRACT-183 `ToolsGrantReader` over the dedicated `GrantStore` rebound
                    // above. The witness seeds a `"tools"` grant `ids=wasmtool` → `list_wasm_tools`
                    // surfaces `wasmtool` and FILTERS OUT the ungranted `secrettool`.
                    let store = grant_store.clone().expect(
                        "with_tool_grant_filter rebinds grant_store to the dedicated store",
                    );
                    let reader: Arc<dyn advance_shared_types::traits::ToolsGrantReader> =
                        Arc::new(cap_grant::ToolsGrantReaderImpl::new(store));
                    Arc::new(
                        cap_tools::CallableInventory::new(
                            vec![
                                // Hyphenless names render verbatim through the Tier-2 sanitizer.
                                ToolEntry {
                                    name: "wasmtool".to_string(),
                                    description: "echo tool".to_string(),
                                    params_schema: serde_json::json!({"properties": {"text": {}}}),
                                },
                                ToolEntry {
                                    name: "secrettool".to_string(),
                                    description: "ungranted tool".to_string(),
                                    params_schema: serde_json::json!({"properties": {"text": {}}}),
                                },
                            ],
                            vec![McpToolEntry {
                                name: "mcptool".to_string(),
                                description: "search tool".to_string(),
                                params_schema: serde_json::json!({"properties": {"query": {}}}),
                                server_id: "mcp-server-1".to_string(),
                            }],
                        )
                        .with_tools_grant_reader(reader),
                    )
                } else {
                    Arc::new(cap_tools::CallableInventory::new(
                        vec![ToolEntry {
                            // Hyphenless name: the Tier-2 tool-name sanitizer maps '-' → '_',
                            // so a hyphenless fixture name renders verbatim for a clean witness.
                            name: "wasmtool".to_string(),
                            description: "echo tool".to_string(),
                            params_schema: serde_json::json!({"properties": {"text": {}}}),
                        }],
                        vec![McpToolEntry {
                            name: "mcptool".to_string(),
                            description: "search tool".to_string(),
                            params_schema: serde_json::json!({"properties": {"query": {}}}),
                            server_id: "mcp-server-1".to_string(),
                        }],
                    ))
                };
            // B1 backbone (2026-06-09, ADVERSARIAL-r7 fix): the real KnowledgeMapReader
            // reads the SHARED registered `MemoryStore` (`shared_memory_store` above —
            // the SAME `Arc` the WIT handlers use, NOT a second `open()`). Seeds
            // written to `memory_dir` BEFORE `.build()` are hydrated by that store.
            // Capability-gated: no `Cap::Memory` ⇒ `None` ⇒ all-stub path
            // (byte-identical to pre-B1, preserving SYS-AC-007/010). In the harness the
            // agent WRITES and the assembler QUERIES under the same `self.agent_id`, so
            // write-id == the sole query alias.
            // Harvest-wave (SYS-AC-011): a populated agent_tree when `.with_delegates`
            // was set (Sub nodes parented to this agent → `# Available Delegates`);
            // else the production default EmptyAgentTree (delegates absent).
            let agent_tree: Arc<dyn advance_shared_types::agent_tree::AgentTreeSnapshot> =
                if let Some(store) = &real_spawn_store {
                    // Wave-12 (SYS-AC-011): the REAL bare-id store the spawn host-fns
                    // mutate — the assembler reads the SAME store (production parity,
                    // NOT a synthetic tree). Wins over `.with_delegates()`.
                    store.clone() as Arc<dyn advance_shared_types::agent_tree::AgentTreeSnapshot>
                } else if self.delegates.is_empty() {
                    Arc::new(EmptyAgentTree)
                } else {
                    Arc::new(DelegatesTree::new(&self.agent_id, &self.delegates))
                };
            // Wave-12: the assembler's agent-id alias set. With a bare/colon axis
            // it is [bare "harness", colon AGENT_ID] so the colon assemble matches
            // the bare-keyed delegates AND drains the bare-keyed Tier-3 inject;
            // without either axis it is the single colon id (byte-identical).
            let assembler_aliases: Vec<String> = if self.with_real_spawn_tree
                || self.with_tool_repetition_guard
                || self.with_decomposition
            {
                vec![
                    AGENT_ID
                        .strip_prefix("agent:")
                        .unwrap_or(AGENT_ID)
                        .to_string(),
                    self.agent_id.clone(),
                ]
            } else {
                vec![self.agent_id.clone()]
            };
            // Assembler selection (3-way):
            //   • Wave-6 Lane A `.with_skills_summary()` → the SUPERSET builder
            //     `_with_skills(.., memory_root, skills_agent_root)` installs the REAL
            //     `DiskSkillSummaryReader` (production parity with start.rs). `skills_root`
            //     is the cap-skills provider root (`agent_workspace` = `<ws>/agent`),
            //     CANONICALIZED so the reader path-string matches the canonicalizing
            //     writer EXACTLY (no reliance on /var→/private/var symlink transparency).
            //     skills ⊥ memory: `memory_root` still follows `.with_live_memory()`, so
            //     the skills axis composes with or without live memory.
            //   • `.with_live_memory()` → the history-aware builder (`memory_root =
            //     Some(memory_dir)` → real CapMemoryHistoryReader L2/L3/L4).
            //   • OFF (both) → the frozen no-history builder (delegates to
            //     `_with_history(.., None)`) → byte-identical to every prior build.
            let inner = if self.with_skills_summary {
                let skills_root = std::fs::canonicalize(&agent_workspace)
                    .unwrap_or_else(|_| agent_workspace.clone());
                build_context_assembler_for_agent_with_skills(
                    assembler_bus,
                    callable,
                    Arc::new(FixedHostFnInventory::from_names(&["generate"])),
                    agent_tree,
                    shared_memory_store.clone(),
                    &self.agent_id,
                    &assembler_aliases,
                    if self.with_live_memory {
                        Some(memory_dir.as_path())
                    } else {
                        None
                    },
                    Some(skills_root.as_path()),
                )
            } else if self.with_live_memory {
                build_context_assembler_for_agent_with_history(
                    assembler_bus,
                    callable,
                    Arc::new(FixedHostFnInventory::from_names(&["generate"])),
                    agent_tree,
                    shared_memory_store.clone(),
                    &self.agent_id,
                    &assembler_aliases,
                    Some(memory_dir.as_path()),
                )
            } else if self.with_decomposition {
                // Wave-13 (SYS-AC-172): the REAL `CapDecompositionReader` over the SAME shared
                // `DefaultDecompositionStore` the decomposition host-fns wrote — the assembler's
                // ⑭ `# Active Task Decomposition` section reads the LIVE store, not a seed. The
                // reader resolves the owner from its OWN bare-first `query_aliases` (it ignores
                // ctx.agent_id); the [bare, colon] set bridges the bare-keyed store vs the colon
                // assemble-turn id. (Guarded mutually-exclusive vs skills/live-memory below —
                // those builders pass EmptyDecomposition.)
                let reader = Arc::new(CapDecompositionReader::new(
                    decomposition_store
                        .clone()
                        .expect("with_decomposition ⇒ decomposition_store is Some"),
                    // Derive the [bare, colon] owner aliases from THIS SUT's agent id (NOT the
                    // AGENT_ID const / the shared assembler_aliases), so the reader resolves the
                    // store keyed under the bare form even when `.agent_id()` is overridden
                    // (adversarial-r11): store is bare-keyed; the assemble turn runs under the
                    // colon form; bare-first resolution bridges them.
                    vec![
                        self.agent_id
                            .strip_prefix("agent:")
                            .unwrap_or(&self.agent_id)
                            .to_string(),
                        self.agent_id.clone(),
                    ],
                ));
                build_context_assembler_for_agent_with_decomposition(
                    assembler_bus,
                    callable,
                    Arc::new(FixedHostFnInventory::from_names(&["generate"])),
                    agent_tree,
                    shared_memory_store.clone(),
                    &self.agent_id,
                    &assembler_aliases,
                    None, // memory_root
                    None, // skills_agent_root
                    reader,
                )
            } else if self.with_dual_recall_corpus {
                // Wave-20 Lane `search` (SYS-AC-009): the DUAL-PATH variant of the recall
                // axis. Same wiring as with_recall_corpus EXCEPT the search is the REAL
                // dense+sparse R2d2 SQLite index (build_dual_recall_unified_search →
                // R2d2UnifiedSearchAdapter) and the embedder is the 768-dim FixtureEmbedding
                // (controlled geometry). The SAME embedder backs the corpus ingest AND the
                // assembler's query-embed (symmetric dense ranking). Witnesses BOTH legs
                // (dense + sparse FTS5) reaching `# Recalled Context`.
                let store = shared_memory_store
                    .clone()
                    .expect("with_dual_recall_corpus ⇒ Cap::Memory ⇒ shared_memory_store is Some");
                let embedder: Arc<dyn EmbeddingPort> = Arc::new(FixtureEmbedding);
                let search = build_dual_recall_unified_search(
                    &*store,
                    &workspace_root,
                    &self.agent_id,
                    &assembler_aliases,
                    &*embedder,
                )
                .await;
                build_context_assembler_for_agent_with_recall(
                    assembler_bus,
                    callable,
                    Arc::new(FixedHostFnInventory::from_names(&["generate"])),
                    agent_tree,
                    &assembler_aliases,
                    search,
                    embedder,
                )
            } else if self.with_recall_corpus {
                // Wave-16 Lane 2 (SYS-AC-005): the REAL cli recall production fns over THIS
                // SUT's seeded MemoryStore + workspace files. The populated corpus is keyed
                // under `assembler_aliases` (= [colon self.agent_id], the id `assemble`
                // queries via `unified_search(&ctx.agent_id, …)`); the SAME embedder backs both
                // the corpus build and the assembler's query-embed port (symmetric dense
                // ranking). Only the Tier-3 `# Recalled Context` is memory-derived → the turn
                // answers from LOCAL recall, provider-independent. (Mutually exclusive vs
                // skills/live-memory/decomposition — guarded fail-loud below.)
                let store = shared_memory_store
                    .clone()
                    .expect("with_recall_corpus ⇒ Cap::Memory ⇒ shared_memory_store is Some");
                let embedder: Arc<dyn EmbeddingPort> = Arc::new(HashingEmbedding::default());
                let search = build_recall_unified_search(
                    &*store,
                    &workspace_root,
                    &self.agent_id,
                    &assembler_aliases,
                    &*embedder,
                )
                .await;
                build_context_assembler_for_agent_with_recall(
                    assembler_bus,
                    callable,
                    Arc::new(FixedHostFnInventory::from_names(&["generate"])),
                    agent_tree,
                    &assembler_aliases,
                    search,
                    embedder,
                )
            } else {
                build_context_assembler_for_agent(
                    assembler_bus,
                    callable,
                    Arc::new(FixedHostFnInventory::from_names(&["generate"])),
                    agent_tree,
                    shared_memory_store.clone(),
                    &self.agent_id,
                    &assembler_aliases,
                )
            };
            // Perf-CI lane (SYS-AC-191): retain the INNER assembler (cheap Arc clone)
            // BEFORE it is moved into the Publishing wrapper, so `context_assembler_inner()`
            // hands back the bare `assemble()` seam (no `gateway.publish_assembled` hop).
            retained_inner_assembler = Some(inner.clone());
            // Wave-12 (SYS-AC-122): LATE-BIND the per-turn assembler into the
            // tool-path guard (mirrors start.rs — the guard was built at the
            // cap-tools registration before `inner` existed). The guard injects
            // via `inner.inject_tier3_warning`; the next turn assembles via
            // `publishing` → `inner.assemble` (ONE shared WarningQueue).
            if let Some(guard) = &tool_guard {
                guard.set_context_assembler(inner.clone());
            }
            let publishing = Arc::new(PublishingContextAssembler::new(
                inner,
                lp.gateway.clone(),
                self.agent_id.clone(),
            ));
            driver = driver.with_context_assembler(publishing);
        }

        // Stage-C harvest pass-3 (SYS-AC 071/217/072/066/068): axis guards + the harness
        // VLM extractor. Both new axes operate inside the live-memory post-processor (the
        // Step-3 indexing / Step-9 trigger seams live there); a future caller pairing
        // either flag WITHOUT `.with_live_memory()` would otherwise get a silent no-op, so
        // fail loud (mirrors the `await_deadlock_gate` precedent).
        if self.with_vlm_indexer && !self.with_live_memory {
            panic!(".with_vlm_indexer() requires .with_live_memory()");
        }
        if self.l6_entrycount_isolation && !self.with_live_memory {
            panic!(".with_l6_entrycount_isolation() requires .with_live_memory()");
        }
        // Wave-6 Lane A (SYS-AC 078/079/081): the skills axis needs Cap::Skills (so an
        // activated skill exists on disk for the reader) AND a loopback LLM (the
        // `# Available Skills` section reaches the prompt only via the publishing
        // assembler installed under the `llm` arm above — without it the flag would be a
        // silent no-op). Fail loud (mirrors the `await_deadlock_gate`/vlm/l6 precedent).
        if self.with_skills_summary && !self.caps.contains(&Cap::Skills) {
            panic!(".with_skills_summary() requires Cap::Skills (no activated skill would exist for the reader)");
        }
        if self.with_skills_summary && llm.is_none() {
            panic!(".with_skills_summary() requires a loopback LLM (the # Available Skills section reaches the prompt only via the publishing assembler)");
        }
        // Wave-16 Lane 2 (SYS-AC-005): the recall axis needs Cap::Memory (the corpus reads the
        // shared MemoryStore) AND a loopback LLM (the `# Recalled Context` section reaches the
        // prompt only via the publishing assembler), AND must be the SOLE assembler axis (the
        // `if/else-if` chain places it AFTER skills/live-memory/decomposition, so pairing it with
        // any of those would silently drop the recall corpus). Fail loud (await_deadlock_gate
        // precedent).
        if self.with_recall_corpus && !self.caps.contains(&Cap::Memory) {
            panic!(".with_recall_corpus() requires Cap::Memory (the recall corpus reads the shared MemoryStore)");
        }
        if self.with_recall_corpus && llm.is_none() {
            panic!(".with_recall_corpus() requires a loopback LLM (the # Recalled Context section reaches the prompt only via the publishing assembler)");
        }
        if self.with_recall_corpus
            && (self.with_skills_summary || self.with_live_memory || self.with_decomposition)
        {
            panic!(".with_recall_corpus() is mutually exclusive with .with_skills_summary()/.with_live_memory()/.with_decomposition() (the assembler if/else-if chain would silently drop the recall corpus)");
        }
        // Wave-20 Lane `search` (SYS-AC-009): the same fail-loud gates for the dual-path axis.
        if self.with_dual_recall_corpus && !self.caps.contains(&Cap::Memory) {
            panic!(".with_dual_recall_corpus() requires Cap::Memory (the recall corpus reads the shared MemoryStore)");
        }
        if self.with_dual_recall_corpus && llm.is_none() {
            panic!(".with_dual_recall_corpus() requires a loopback LLM (the # Recalled Context section reaches the prompt only via the publishing assembler)");
        }
        if self.with_dual_recall_corpus
            && (self.with_recall_corpus
                || self.with_skills_summary
                || self.with_live_memory
                || self.with_decomposition)
        {
            panic!(".with_dual_recall_corpus() is mutually exclusive with .with_recall_corpus()/.with_skills_summary()/.with_live_memory()/.with_decomposition() (the assembler if/else-if chain would silently drop it)");
        }
        // Constructed unconditionally (cheap; inert unless installed below). Retained on
        // the SUT so a witness reads the recorded FileContent variants via `vlm_calls()`.
        let harness_vlm = HarnessVlm::new(HARNESS_VLM_DESC);

        // Stage-C harvest pass-1 write-path: when `.with_live_memory()` is set AND
        // both memory + a loopback LLM are present, install the components-backed
        // PostProcessor (mirrors production start.rs build_live_post_processor) so a
        // real turn issues ONE batched extraction call over the loopback gateway,
        // writes summary.yaml/turn-index.yaml under `<memory_dir>/tasks/{task}/`, and
        // upserts the durable RusqliteSqliteIndex (`<memory_dir>/index.sqlite`). Gate
        // truth-table: memory-or-LLM-absent ⇒ this block is skipped ⇒ the driver
        // keeps build_agent_loop's trace-only `PostProcessor::new()` (no divergence —
        // exactly production's memory/LLM-absent branch). Off ⇒ never entered.
        if self.with_live_memory {
            if let (Some(store), Some(lp)) = (&shared_memory_store, &llm) {
                // Stage-C harvest pass-2 (070/215/216): a fresh clone of the harness's
                // REAL commit queue for the L6 committer (production parity with
                // start.rs threading `git_queue` into `attach_l6`). Only consumed when
                // `with_live_l6` (the normal GitQueueL6Committer path); the failing
                // path swaps in FailingCommitter and ignores it.
                let l6_queue: Arc<dyn GitCommitQueue> = queue.clone();
                // Concrete-clone-then-unsize: a bare `Arc::clone(&harness_vlm)` infers
                // `T = HarnessVlm` and does NOT coerce at the arg; a typed binding does.
                let vlm_dyn: Arc<dyn cap_llm::VlmExtractor> = harness_vlm.clone();
                let live_pp = build_harness_live_post_processor(
                    store,
                    &lp.gateway,
                    memory_dir.as_path(),
                    bus_dyn.clone(),
                    &self.agent_id,
                    l6_queue,
                    workspace_root.clone(),
                    // Wave-7 Lane A: widen the live-L6 gate so the real `attach_l6` runs for the
                    // recording / failing-gateway axes too (with the injected classifier below).
                    self.with_live_l6 || self.with_recording_l6 || self.with_failing_l6_gateway,
                    self.failing_l6_committer,
                    self.with_vlm_indexer,
                    vlm_dyn,
                    self.l6_entrycount_isolation,
                    // Wave-7 Lane A: the injected L6 classifier (Some only for the recording /
                    // failing-gateway axes; None ⇒ the real attach_l6 keeps StubL6Classifier).
                    l6_classifier,
                    // Wave-10 Lane A (SYS-AC-069): swap attach_l6's None shim for the production
                    // attach_l6_with_stale_resolver(Some(real ResolverStalenessProbe)) on the
                    // non-failing branch. Default false ⇒ byte-identical empty-stub shim.
                    self.with_real_l6_probe,
                );
                // Perf-CI lane (SYS-AC-214): retain a cheap Arc clone of the SAME live
                // PostProcessor the driver uses, so `live_post_processor()` times the real
                // `PostProcessor::run` seam directly (not a whole turn).
                retained_live_pp = Some(live_pp.clone());
                driver = driver.with_post_processor(live_pp);
            }
        }

        // GAP-3 (SYS-J-57): one production agent-loop driver PER tree node, each
        // baked with the node's CANONICAL id. The fs caller id is the handler's
        // `ComponentCtx.agent_id` (cli/agent_loop.rs:137) AND `run_turn_for` passes
        // the same id as the `run_agent` recv/dispatch argument — so a node's turn
        // recvs from its own mailbox and resolves fs writes to its own distinct
        // territory. All node drivers share the ONE `store` (MailboxStore), the ONE
        // `registry` (→ the single fs resolver over HarnessAgentTree), the ONE
        // `DefaultGitCommitQueue` (via the shared fs host fns — single-in-flight
        // serialization), and the event bus. Built from clones of the shared
        // guest-instantiation quadruple (`runnable_parts`). Empty in the
        // single-agent path → byte-identical to pre-slice builds.
        let node_drivers: HashMap<String, AgentLoopDriverImpl> = self
            .agents
            .iter()
            .map(|spec| {
                let node_id = spec.id.clone(); // canonical `agent:` id
                let handler: Arc<dyn MessageHandler> = Arc::new(WasmMessageHandler::new(
                    runnable_parts.0.clone(),
                    runnable_parts.1.clone(),
                    runnable_parts.2.clone(),
                    runnable_parts.3.clone(),
                    node_id.clone(),
                    "trace-harness".to_string(),
                ));
                let node_driver = build_agent_loop(store.clone(), handler, node_bus.clone(), None);
                (node_id, node_driver)
            })
            .collect();

        // --- HF: multi-agent spawn/await wiring (.agents()) ---
        let agents = if self.agents.is_empty() {
            if self.await_deadlock_gate {
                panic!(".with_await_deadlock_gate() requires .agents() (the await manager + tree)");
            }
            let _ = reply_bus;
            None
        } else {
            Some(build_agents_handle(
                &self.agents,
                &workspace_root,
                dispatcher.clone(),
                reply_bus,
                &*registry,
                self.await_deadlock_gate,
            ))
        };

        // Wave-18 (SYS-AC-030): post-wrap the owned node drivers with the production
        // crash-cascade sink (default-off axis). `node_drivers` is built ABOVE (before
        // `agents`) because the sink needs the `AgentsHandle.tree_store`, so re-bind it
        // here. `AgentLoopDriverImpl` is not `Clone`, hence the consuming `into_iter`
        // re-map. The bare-id tree_store + the symmetric `agent:{b}` resolver pair the
        // bare cap-lifecycle lookup with the colon served-mailbox key.
        let node_drivers = if self.with_crash_cascade {
            let handle = agents
                .as_ref()
                .expect(".with_crash_cascade() requires .agents() (the crash sink needs the tree)");
            let sink =
                build_crash_cascade_sink(handle.tree_store.clone(), store.clone(), |b: &str| {
                    format!("agent:{b}")
                });
            node_drivers
                .into_iter()
                .map(|(k, d)| (k, d.with_crash_cascade(sink.clone())))
                .collect()
        } else {
            node_drivers
        };

        // Wave-19 (SYS-AC-028): post-wrap the node drivers with the production
        // workspace-rollback sink (default-off axis). Requires `.agents()` (the sink needs the
        // bare-id `tree_store` for each child's `workspace_path` + the shared queue for the
        // compensating commit). Before wiring, perform the setup the sink's checkpoint/rollback
        // path needs:
        //  - F1a: write each LEAF agent's `<territory>/.agent/config.yaml` with an explicit
        //    `agent_id` so `WorkspaceRollback::rollback`'s `resolve_agent_root` resolves the
        //    bare child. NOT for ancestor agents — `resolve_agent_root`'s BFS prunes a subtree
        //    at the first `.agent/config.yaml` it meets (regardless of id-match), so an ancestor
        //    config would shadow the nested child. A "leaf" = an agent that is the declared
        //    parent of no other declared agent (the rollback target).
        //  - F1b: commit a `[seed]` baseline (the configs) so the pre-turn `NamedCheckpoint`
        //    has a born HEAD and `git status` is clean (no untracked skeleton files). The
        //    `[seed]` prefix is non-`[turn]` so commit-filter assertions are unaffected.
        let node_drivers = if self.with_workspace_rollback {
            // Requires `.agents()` — the territories (which `build_agents_handle` created) must
            // exist for the leaf config.yaml + baseline. The sink itself needs only the shared
            // queue + repo root (it derives `.meta.yaml` dirs from the rollback's reverted paths).
            assert!(
                agents.is_some(),
                ".with_workspace_rollback() requires .agents() (the child territories)"
            );
            let bare = |id: &str| id.strip_prefix("agent:").unwrap_or(id).to_string();
            let is_leaf = |spec: &AgentSpec| {
                !self
                    .agents
                    .iter()
                    .any(|other| other.parent.as_deref() == Some(spec.id.as_str()))
            };
            let mut seed_files: Vec<(String, Vec<u8>)> = Vec::new();
            for spec in &self.agents {
                if !is_leaf(spec) {
                    continue;
                }
                let bid = bare(&spec.id);
                // Mirror `build_agents_handle`'s territory layout exactly.
                let rel = match &spec.parent {
                    Some(p) => format!("{}/children/{}", bare(p), bid),
                    None => bid.clone(),
                };
                let cfg_vpath = format!("{rel}/.agent/config.yaml");
                let content = format!("agent_id: \"{bid}\"\nkind: \"child\"\n");
                seed_files.push((cfg_vpath, content.into_bytes()));
            }
            if !seed_files.is_empty() {
                commit_seeded_workspace_files(&workspace_root, &seed_files);
            }
            let sink = build_workspace_rollback_sink(queue.clone(), workspace_root.clone());
            node_drivers
                .into_iter()
                .map(|(k, d)| (k, d.with_workspace_rollback(sink.clone())))
                .collect()
        } else {
            node_drivers
        };

        let pump_exits: Arc<Mutex<Vec<advance_client_api::DeltaPumpExit>>> =
            Arc::new(Mutex::new(Vec::new()));
        let client_api_server = if self.with_delta_tee {
            let hub = llm
                .as_ref()
                .and_then(|lp| lp.capturing_sink())
                .expect("with_delta_tee starts capturing sink")
                .inner_hub();
            let exits = pump_exits.clone();
            let observer: advance_client_api::DeltaPumpExitObserver = Arc::new(move |exit| {
                exits.lock().expect("pump exits").push(exit);
            });
            Some(
                advance_client_api::ClientApiServer::bind_local_factory(0, move |address| {
                    let mut config = advance_client_api::ClientApiConfig::default();
                    config.allowed_origins = vec![format!("http://{address}")];
                    let api = advance_client_api::ClientApi::new(config)
                        .with_llm_delta_hub(hub.clone())
                        .with_delta_pump_observer(observer.clone());
                    Arc::new(api)
                })
                .await
                .expect("client api bind"),
            )
        } else {
            None
        };

        SystemUnderTest {
            workspace_root,
            agent_id: self.agent_id,
            bus,
            event_db_path,
            dispatcher,
            driver,
            grant_store,
            _grant_sweeper: grant_sweeper,
            _grant_sweeper_handle: grant_sweeper_handle,
            llm,
            l6_llm,
            registry,
            channel,
            mcp_client,
            agents,
            node_drivers,
            harness_agent_tree,
            real_spawn_store,
            circuit_breaker: breaker,
            mailbox_store: store,
            memory_dir,
            inner_context_assembler: retained_inner_assembler,
            live_post_processor: retained_live_pp,
            vlm: Some(harness_vlm),
            captured_replies,
            triggers,
            runtime_config,
            schema_watch,
            runnable_parts,
            cursor_store,
            sqlite_handle: sqlite_handle_opt,
            fs_schema: fs_schema_opt,
            tool_registry: tool_registry_opt,
            skill_provider: skill_provider_opt,
            decomposition_store,
            _breaker_subscriber: breaker_subscriber,
            _queue: queue,
            _tempdir: tempdir,
            client_api_server,
            pump_exits,
            llm_stream_reaper,
        }
    }
}

async fn boot_loopback_for_sut(
    responses: Vec<llm_loopback::ScriptedResponse>,
    budget: Option<Arc<dyn RunBudget>>,
    repetition: Option<Arc<dyn RepetitionGuardCheck>>,
    bus: Arc<dyn EventBusEmit>,
    agent_id: String,
    registry: &dyn HostRegistry,
    with_delta_tee: bool,
    delta_tee_timing: Option<advance_client_api::DeltaTiming>,
) -> (
    llm_loopback::LoopbackLlm,
    Option<Arc<cap_llm::AgentStreamReaper>>,
) {
    if with_delta_tee {
        let det: Arc<dyn LeakDetector> = Arc::new(cap_http::DefaultLeakDetector::new());
        let hold: advance_client_api::DeltaHoldSplit =
            Arc::new(|buf: &[u8], max_canonical: usize| {
                cap_http::canonical_facade::decoded_hold_split(buf, max_canonical)
            });
        let clock: Arc<dyn advance_client_api::Clock> = Arc::new(advance_client_api::SystemClock);
        let hub = Arc::new(match delta_tee_timing {
            Some(timing) => advance_client_api::LlmDeltaHub::with_timing(
                Some(det),
                Some(hold),
                clock,
                None,
                timing,
            ),
            None => advance_client_api::LlmDeltaHub::new(Some(det), Some(hold), clock, None),
        });
        let lp = llm_loopback::LoopbackLlm::start_with_tee(
            responses, budget, repetition, bus, agent_id, hub,
        )
        .await;
        let reaper = cap_llm::register_agent_llm_with_turn_cost(registry, lp.gateway.clone(), None);
        (lp, Some(reaper))
    } else {
        let lp =
            llm_loopback::LoopbackLlm::start(responses, budget, repetition, bus, agent_id).await;
        cap_llm::register_agent_llm(registry, lp.gateway.clone());
        (lp, None)
    }
}

/// Build the [`GrantMode::Real`] resolver chain for the chosen [`GrantChain`].
fn build_resolver_chain(
    chain: GrantChain,
    validator: &Arc<dyn SubsetValidator>,
    budget: Option<Arc<dyn RunBudget>>,
    channel_approval: Option<Arc<dyn ChannelApprovalPort>>,
) -> ResolverChain {
    match chain {
        GrantChain::Restrict => {
            ResolverChain::new(vec![Box::new(AutoDenyResolver::new()) as Box<dyn Resolver>])
        }
        GrantChain::Supervised => {
            let budget_resolver: Box<dyn Resolver> = match budget {
                Some(budget) => Box::new(BudgetCheckResolver::with_budget(budget)),
                None => Box::new(BudgetCheckResolver::new()),
            };
            let channel_resolver: Box<dyn Resolver> = match channel_approval {
                Some(port) => Box::new(ChannelResolver::with_approval_port(port)),
                None => Box::new(ChannelResolver::new()),
            };
            ResolverChain::new(vec![
                Box::new(SubsetAutoApproveResolver::new(validator.clone())) as Box<dyn Resolver>,
                budget_resolver,
                Box::new(ParentApprovalResolver::new_abstain()),
                channel_resolver,
                Box::new(AutoDenyResolver::new()),
            ])
        }
    }
}

// ---------------------------------------------------------------------------
// Backbone Step 4: accumulating outbound-action capture
// ---------------------------------------------------------------------------

/// An [`OutboundActionSink`] that records each dispatched turn's FIRST action
/// payload into a shared vec — the in-repo `sys_j64_state_roundtrip::RecordingSink`
/// pattern, exposed as the opt-in harness reply-capture seam (`.with_reply_capture()`).
/// This is the REAL post-dispatch delivery seam `build_agent_loop` wires (the daemon
/// wires `ReplyRouterSink` here); the harness substitutes only the recording behaviour,
/// not the dispatch path.
struct CapturingOutboundSink {
    replies: Arc<Mutex<Vec<Vec<u8>>>>,
}

#[async_trait::async_trait]
impl OutboundActionSink for CapturingOutboundSink {
    async fn deliver(
        &self,
        _agent_id: &str,
        _source: &Message,
        actions: &[AgentAction],
    ) -> Result<DeliveryReport, DispatchError> {
        if let Some(a) = actions.first() {
            self.replies.lock().unwrap().push(a.payload.clone());
        }
        Ok(DeliveryReport::empty())
    }
}

// ---------------------------------------------------------------------------
// Harvest-wave (SYS-AC-236): git-leg fault injection
// ---------------------------------------------------------------------------

/// A [`cap_fs::GitSync`] that always fails — the fault-injection seam for the
/// git-leg fail-soft witness (`.with_failing_git_sync()`). When wired into
/// `register_agent_fs` in place of the production `Adv003GitSync`, a real
/// `fs.write` runs the production `git_sync_after_write` Err branch: it emits
/// `runtime.degraded.git_sync_failed` and `fs.write` still returns `Ok` (the
/// file + `.meta.yaml` + SQLite legs already committed). This injects ONLY at the
/// designed `Arc<dyn GitSync>` port — every other leg is the real product path
/// (mirrors the cap-fs sibling `sc_t28` sqlite-leg degraded witness).
struct FailingGitSync;

#[async_trait::async_trait]
impl GitSync for FailingGitSync {
    async fn submit_fs_commit(
        &self,
        _agent_id: &str,
        _op: cap_fs::GitSyncOp,
        _vpath: &str,
        _physical_path: PathBuf,
        _meta_yaml_path: PathBuf,
    ) -> Result<(), cap_fs::GitSyncError> {
        Err(cap_fs::GitSyncError(
            "harness fault-injection: git commit queue unavailable".into(),
        ))
    }
}

// ---------------------------------------------------------------------------
// Stage-C harvest pass-3 (SYS-AC 071/217/072/066): the VLM half of the
// VLM-into-PostProcessor bridge — a harness-owned `cap_llm::VlmExtractor`.
// ---------------------------------------------------------------------------

/// Canned description the harness VLM returns for any non-text file. A distinct,
/// recall-able marker so a witness binds `MemoryStore::recall` / `.meta.yaml` to
/// THIS string (proving the VLM/image leg fired — not a text/LLM reply or a
/// mechanical fallback).
const HARNESS_VLM_DESC: &str = "harness-vlm-described non-text file (canned-071)";

/// A harness-owned [`cap_llm::VlmExtractor`] (mirrors the cli `vlm_indexer.rs`
/// MockVlm): records the `FileContent` variant of each call and returns a canned
/// description, so a witness asserts the VLM was invoked exactly once with the
/// `Image` variant (SYS-AC-217 file-type routing discrimination) WITHOUT any real
/// provider call. Installed only via `.with_vlm_indexer()`; otherwise inert.
struct HarnessVlm {
    reply: String,
    calls: std::sync::Mutex<Vec<String>>,
}

impl HarnessVlm {
    fn new(reply: &str) -> Arc<Self> {
        Arc::new(Self {
            reply: reply.to_string(),
            calls: std::sync::Mutex::new(Vec::new()),
        })
    }

    /// The recorded `FileContent` variant per call, in order (e.g. `["Image"]`).
    fn calls(&self) -> Vec<String> {
        self.calls
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }
}

#[async_trait::async_trait]
impl cap_llm::VlmExtractor for HarnessVlm {
    async fn extract_description(
        &self,
        content: &cap_llm::FileContent,
    ) -> Result<String, cap_llm::LlmError> {
        let variant = match content {
            cap_llm::FileContent::Pdf(_) => "Pdf",
            cap_llm::FileContent::Image { .. } => "Image",
            cap_llm::FileContent::VideoFrame { .. } => "VideoFrame",
            cap_llm::FileContent::Audio { .. } => "Audio",
        };
        self.calls
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(variant.to_string());
        Ok(self.reply.clone())
    }
}

// ---------------------------------------------------------------------------
// Stage-C harvest pass-1 (SYS-AC 065/066/067/213/254): the components-backed
// PostProcessor the `.with_live_memory()` axis installs.
// ---------------------------------------------------------------------------

/// Build the components-backed [`PostProcessor`] the `.with_live_memory()` axis
/// installs — a faithful TEST-ONLY replica of production `build_live_post_processor`
/// (cli `start.rs`) assembled from PUBLIC cap-memory blocks (zero product source
/// change). Differs from production ONLY in that it roots Step-7 writeback + the
/// durable index at the harness's resolved `memory_dir` directly (which may be a
/// caller `.with_memory_dir()` override, not `<ws>/.agent/memory`), so the assembler
/// read-root, the shared [`MemoryStore`] root, and the post-processor write-root all
/// coincide. `write_agent_id` is the harness colon agent id (= the assembler's sole
/// query alias), so the knowledge/index bucket aligns with the read side.
#[allow(clippy::too_many_arguments)]
fn build_harness_live_post_processor(
    store: &Arc<MemoryStore>,
    gateway: &Arc<cap_llm::LlmGateway>,
    mem_root: &std::path::Path,
    event_bus: Arc<dyn EventBusEmit + Send + Sync>,
    write_agent_id: &str,
    // Stage-C harvest pass-2 (070/215/216): the harness's REAL commit queue + git
    // workdir for the L6 committer, and the two opt-in L6 flags. When `with_live_l6`
    // (and not failing) → production `attach_l6` (real GitQueueL6Committer); when
    // `failing_l6_committer` → the same construction with `FailingCommitter` swapped
    // in; when both false → no L6 handler (Step-9 emits consolidation_due only).
    git_queue: Arc<dyn GitCommitQueue>,
    workspace_root: std::path::PathBuf,
    with_live_l6: bool,
    failing_l6_committer: bool,
    // Stage-C harvest pass-3: (071/217/072/066) install the cli VLM description-indexer
    // into Step-3 with `vlm` as the image/pdf leg; (068) `seed_l6_quiet_clock` freezes the
    // clock + seeds the L6 trigger state so NewEntries(>=20) is the sole firing leg.
    with_vlm_indexer: bool,
    vlm: Arc<dyn cap_llm::VlmExtractor>,
    seed_l6_quiet_clock: bool,
    // Wave-7 Lane A (069/216/186/187): the L6 classifier INJECTED into the real `attach_l6`.
    // `Some` for the recording / failing-gateway axes (the production `LlmL6Classifier` over a
    // separate loopback gateway); `None` ⇒ `attach_l6` keeps `StubL6Classifier` (070/215
    // byte-identical). Ignored on the `failing_l6_committer` branch (that path constructs its
    // own runnable with a Stub classifier + FailingCommitter).
    l6_classifier: Option<Arc<dyn cap_memory::l6::L6Classifier + Send + Sync>>,
    // Wave-10 Lane A (SYS-AC-069): when true (and NOT the failing-committer branch), swap
    // `attach_l6`'s None-resolver shim for the PRODUCTION `attach_l6_with_stale_resolver(Some(
    // build_l6_stale_resolver(workspace_root, Some(OneAgentTree::new(workspace_root)))))` — the real
    // MODULE-002-blob-backed `ResolverStalenessProbe`. False ⇒ the byte-identical empty-stub shim.
    with_real_l6_probe: bool,
) -> Arc<dyn advance_shared_types::memory::PostProcessorHook> {
    // Concrete→trait coercion idiom (mirrors start.rs): clone to the concrete Arc
    // first so T infers as LlmGateway, then let the typed binding unsize to dyn.
    let gw_concrete = Arc::clone(gateway);
    let gw: Arc<dyn cap_llm::LlmGatewayInternal + Send + Sync> = gw_concrete;
    let extractor: Arc<dyn BatchExtractor + Send + Sync> = Arc::new(
        advance_cli::memory_extractor::LlmBatchExtractor::new(gw, None),
    );
    let reconciler =
        Reconciler::from_concrete(Arc::new(InMemorySimilarityIndex::new()), DEFAULT_THRESHOLD);
    let cooldown = Arc::new(FailureCooldown::new(DEFAULT_COOLDOWN_SECS));
    // Stage-C harvest pass-3 (SYS-AC-068): freeze the clock at a fixed `now` when the
    // EntryCount-isolation axis is on, so the seeded trigger state below makes the
    // HoursSinceLast + CompletedTasks legs quiet and NewEntries(>=20) is the sole firing
    // lever. Off → the production `SystemClock` (byte-identical).
    let seeded_now = SystemTime::now();
    let clock: Arc<dyn cap_memory::Clock + Send + Sync> = if seed_l6_quiet_clock {
        Arc::new(cap_memory::MutableClock::new(seeded_now))
    } else {
        Arc::new(SystemClock)
    };
    let mut components = Components::wired(
        extractor,
        reconciler,
        Arc::clone(store),
        cooldown,
        clock,
        event_bus,
    )
    .with_fs_root(mem_root.to_path_buf())
    .with_write_agent_id(write_agent_id);
    // Durable 254: swap in the on-disk rusqlite index; degrade to the in-memory
    // default (+ log) on open error — never fail the turn pipeline (mirrors start.rs).
    match RusqliteSqliteIndex::open(mem_root.join("index.sqlite")) {
        Ok(idx) => {
            components = components.with_sqlite_index(Arc::new(idx));
        }
        Err(e) => {
            eprintln!(
                "harness live memory: durable index open failed ({e}); using the in-memory index"
            );
        }
    }
    // Stage-C harvest pass-3 (SYS-AC 071/217/072/066): install the cli VLM
    // description-indexer into Step-3 (default-off; mirrors the production
    // `build_live_post_processor` install). The gateway leg reuses the loopback gateway
    // (CONTRACT-081 text path); the image/pdf leg uses the harness `vlm`. Done BEFORE the
    // L6 block, which consumes `workspace_root`.
    if with_vlm_indexer {
        // Concrete-clone-then-unsize idiom (mirrors gw above): VlmDescriptionIndexer::new
        // wants a bare `Arc<dyn LlmGatewayInternal>`.
        let gw_vlm_concrete = Arc::clone(gateway);
        let gw_vlm: Arc<dyn cap_llm::LlmGatewayInternal> = gw_vlm_concrete;
        components = components.with_description_indexer(Arc::new(
            advance_cli::vlm_indexer::VlmDescriptionIndexer::new(
                gw_vlm,
                vlm,
                workspace_root.clone(),
            ),
        ));
    }
    // Stage-C harvest pass-2 (070/215/216): attach the L6 dispatch onto `components`
    // BEFORE the `with_components` wrap — mirrors production start.rs:1198-1205, which
    // calls `attach_l6(components, git_queue, workspace, mem_root)` on the concrete
    // `Components` then wraps. `with_live_l6` (and not failing) → production attach_l6;
    // `failing_l6_committer` → the SAME construction with FailingCommitter (216).
    if with_live_l6 || failing_l6_committer {
        components = if failing_l6_committer {
            attach_harness_l6_failing(components, mem_root.to_path_buf())
        } else {
            // slice wave6-laneB: attach_l6 takes an INJECTED classifier. Wave-7 Lane A
            // (069/216/186/187): the recording / failing-gateway axes pass the production
            // `LlmL6Classifier` (over a SEPARATE loopback gateway, dialed for real); when
            // `None` the harness keeps `StubL6Classifier` so the scripted-FIFO loopback is
            // NOT consumed by L6 → SYS-AC-070/215 stay byte-identical.
            let classifier: Arc<dyn cap_memory::l6::L6Classifier + Send + Sync> =
                l6_classifier.unwrap_or_else(|| Arc::new(cap_memory::l6::StubL6Classifier::new()));
            if with_real_l6_probe {
                // Wave-10 Lane A (SYS-AC-069): wire the REAL MODULE-002-blob-backed
                // `ResolverStalenessProbe` via the SAME `build_l6_stale_resolver` start.rs:1375
                // installs, over a `OneAgentTree` territory (node id == AGENT_ID == write_agent_id,
                // workspace_path == workspace_root). A real-blob FileRef seeded under workspace_root
                // then resolves Valid → not orphaned → the synthesis 5-gate passes (flips 069). This
                // is the PRODUCTION attach path with a real probe — not a stub-in-the-chain.
                let tree: Arc<dyn AgentTreeSnapshot> =
                    Arc::new(OneAgentTree::new(workspace_root.clone()));
                let resolver = advance_cli::l6_wiring::build_l6_stale_resolver(
                    workspace_root.clone(),
                    Some(tree),
                );
                advance_cli::l6_wiring::attach_l6_with_stale_resolver(
                    components,
                    classifier,
                    git_queue,
                    workspace_root,
                    mem_root.to_path_buf(),
                    Some(resolver),
                )
            } else {
                advance_cli::l6_wiring::attach_l6(
                    components,
                    classifier,
                    git_queue,
                    workspace_root,
                    mem_root.to_path_buf(),
                )
            }
        };
    }
    // Stage-C harvest pass-3 (SYS-AC-068): seed the L6 trigger state so the ONLY way
    // Step-9 fires `memory.l6_consolidation_due` is the NewEntries(>=20) leg — the other
    // two legs are quiet (last_l6_at recent, completed_tasks_delta 0). `last_l6_at` MUST
    // be Some(<=now): a `None` fires HoursSinceLast unconditionally (cap-memory trigger.rs).
    if seed_l6_quiet_clock {
        let mut st = components
            .l6_trigger_state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *st = cap_memory::L6TriggerState {
            new_entries_since_last: 0,
            completed_tasks_delta: 0,
            last_l6_at: Some(
                seeded_now
                    .checked_sub(std::time::Duration::from_secs(60))
                    .unwrap_or(seeded_now),
            ),
        };
    }
    Arc::new(PostProcessor::with_components(components))
}

/// Stage-C harvest pass-2 (SYS-AC-216): attach the L6 dispatch with a
/// `cap_memory::l6::FailingCommitter` swapped in for the production
/// `GitQueueL6Committer`. A faithful in-harness MIRROR of
/// `advance_cli::l6_wiring::attach_l6`'s body (the committer is hard-coded there with
/// no injection seam, l6_wiring.rs:277-278, so the fault axis must replicate the
/// construction — it breaks loudly if `attach_l6`'s wiring drifts). Shares the live
/// `store`/`lease`/`l6_emitter`/`clock` Arcs (HARD REQUIREMENT — a fresh lease would
/// make Step-9's confirm and the runnable's lease gate diverge) and roots the cursor
/// store at `mem_root`. The runnable's commit-failure Err-arm releases the lease and
/// the `L6DispatchAdapter` emits `component.error` (216 shape).
fn attach_harness_l6_failing(
    mut components: Components,
    mem_root: std::path::PathBuf,
) -> Components {
    let store = Arc::clone(&components.store);
    let lease = Arc::clone(&components.lease);
    let emitter = Arc::clone(&components.l6_emitter);
    let clock = Arc::clone(&components.clock);

    let cursor = Arc::new(L6CursorStore::with_root(mem_root.clone()));
    components.cursor_store = Arc::clone(&cursor);

    let committer: Arc<dyn cap_memory::L6Committer + Send + Sync> =
        Arc::new(cap_memory::l6::FailingCommitter::new());

    let runnable = cap_memory::l6::L6Runnable::new(
        "memory.l6",
        Arc::clone(&clock),
        Arc::new(cap_memory::l6::UuidBatchIdSource),
        store,
        lease,
        Arc::new(cap_memory::l6::InMemoryStalenessProbe::new()),
        Arc::new(cap_memory::l6::L6ClusterBuilder::new()),
        Arc::new(cap_memory::l6::StubL6Classifier::new()),
        Arc::new(cap_memory::l6::StubSynthesisGenerator),
        Arc::new(std::sync::Mutex::new(cap_memory::l6::KnowledgeMap::new())),
        Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
        committer,
        emitter,
        cursor,
    )
    .with_fs_root(mem_root);

    let handler: Arc<dyn advance_shared_types::memory::L6Handler + Send + Sync> =
        Arc::new(runnable);
    // `Components.event_bus` is `Arc<dyn EventBusEmit + Send + Sync>`; coerce to the
    // plain `Arc<dyn EventBusEmit>` the adapter consumes (drop the redundant auto-trait
    // annotation at a plain let-binding, mirroring attach_l6).
    let bus_ss = Arc::clone(&components.event_bus);
    let bus: Arc<dyn EventBusEmit> = bus_ss;
    let adapter = advance_cli::l6_wiring::L6DispatchAdapter::new(handler, bus, clock);
    components.with_l6_handler(Arc::new(adapter))
}

// Harvest-wave (SYS-AC-011): a populated AgentTreeSnapshot of Sub delegates
// ---------------------------------------------------------------------------

/// An [`AgentTreeSnapshot`](advance_shared_types::agent_tree::AgentTreeSnapshot)
/// carrying `AgentKind::Sub` delegate nodes parented to one agent — the
/// `.with_delegates()` feed for the turn ContextAssembler's agent_tree port, so
/// `format_available_delegates_section` renders a populated `# Available
/// Delegates` section. Mirrors the production `AgentTreeStore` snapshot shape
/// (the same `AgentTreeSnapshotData` a real multi-agent deployment produces);
/// the assembler reads only `snapshot()`, but the full `AgentTreeReader` surface
/// is implemented for trait completeness.
struct DelegatesTree {
    parent: String,
    /// (sub_id, capability_ids)
    subs: Vec<(String, Vec<String>)>,
}

impl DelegatesTree {
    fn new(parent: &str, subs: &[(String, Vec<String>)]) -> Self {
        Self {
            parent: parent.to_string(),
            subs: subs.to_vec(),
        }
    }

    fn nodes(&self) -> Vec<advance_shared_types::agent_tree::AgentNode> {
        use advance_shared_types::agent_tree::{AgentId, AgentKind, AgentNode, AgentStatus};
        use advance_shared_types::capability::{CapParams, CapabilityId};
        self.subs
            .iter()
            .map(|(id, caps)| AgentNode {
                id: AgentId(id.clone()),
                kind: AgentKind::Sub,
                parent: Some(AgentId(self.parent.clone())),
                workspace_path: std::path::PathBuf::from("/ws"),
                capabilities: caps
                    .iter()
                    .map(|c| advance_shared_types::agent_tree::Capability {
                        id: CapabilityId::new(c),
                        params: CapParams(serde_json::Value::Null),
                    })
                    .collect(),
                template_ref: None,
                status: AgentStatus::Active,
            })
            .collect()
    }
}

impl advance_shared_types::agent_tree::AgentTreeReader for DelegatesTree {
    fn parent_of(&self, agent_id: &str) -> Option<String> {
        self.subs
            .iter()
            .any(|(id, _)| id == agent_id)
            .then(|| self.parent.clone())
    }
    fn children_of(&self, agent_id: &str) -> Vec<String> {
        if agent_id == self.parent {
            self.subs.iter().map(|(id, _)| id.clone()).collect()
        } else {
            Vec::new()
        }
    }
    fn siblings_of(&self, agent_id: &str) -> Vec<String> {
        if self.subs.iter().any(|(id, _)| id == agent_id) {
            self.subs
                .iter()
                .map(|(id, _)| id.clone())
                .filter(|id| id != agent_id)
                .collect()
        } else {
            Vec::new()
        }
    }
    fn agent_exists(&self, agent_id: &str) -> bool {
        agent_id == self.parent || self.subs.iter().any(|(id, _)| id == agent_id)
    }
    fn agent_kind(&self, agent_id: &str) -> Option<advance_shared_types::agent_tree::AgentKind> {
        use advance_shared_types::agent_tree::AgentKind;
        if agent_id == self.parent {
            Some(AgentKind::Root)
        } else if self.subs.iter().any(|(id, _)| id == agent_id) {
            Some(AgentKind::Sub)
        } else {
            None
        }
    }
    fn capabilities(&self, agent_id: &str) -> Vec<advance_shared_types::agent_tree::Capability> {
        use advance_shared_types::capability::{CapParams, CapabilityId};
        self.subs
            .iter()
            .find(|(id, _)| id == agent_id)
            .map(|(_, caps)| {
                caps.iter()
                    .map(|c| advance_shared_types::agent_tree::Capability {
                        id: CapabilityId::new(c),
                        params: CapParams(serde_json::Value::Null),
                    })
                    .collect()
            })
            .unwrap_or_default()
    }
}

impl advance_shared_types::agent_tree::AgentTreeSnapshot for DelegatesTree {
    fn snapshot(&self) -> advance_shared_types::agent_tree::AgentTreeSnapshotData {
        use advance_shared_types::agent_tree::{AgentId, AgentTreeSnapshotData};
        use std::collections::HashMap;
        let nodes = self.nodes();
        let mut parent_of = HashMap::new();
        let mut children: Vec<AgentId> = Vec::new();
        for (id, _) in &self.subs {
            parent_of.insert(AgentId(id.clone()), Some(AgentId(self.parent.clone())));
            children.push(AgentId(id.clone()));
        }
        let mut children_of = HashMap::new();
        children_of.insert(AgentId(self.parent.clone()), children);
        AgentTreeSnapshotData {
            nodes,
            parent_of,
            children_of,
            peer_slug_map: HashMap::new(),
            revision: 1,
        }
    }
}

// ---------------------------------------------------------------------------
// SystemUnderTest
// ---------------------------------------------------------------------------

/// A booted, wired in-process system under test.
pub struct SystemUnderTest {
    workspace_root: PathBuf,
    agent_id: String,
    bus: BusHandle,
    event_db_path: Option<PathBuf>,
    dispatcher: Arc<MailboxDispatcherImpl>,
    driver: AgentLoopDriverImpl,
    grant_store: Option<Arc<cap_grant::GrantStore>>,
    _grant_sweeper: Option<Arc<cap_grant::TtlSweeper>>,
    _grant_sweeper_handle: Option<tokio::task::JoinHandle<()>>,
    llm: Option<llm_loopback::LoopbackLlm>,
    // Wave-7 Lane A (069/216/186/187): the SEPARATE L6-classifier loopback gateway (Some only
    // for `.with_recording_l6()` / `.with_failing_l6_gateway()`). Its own `Drop` aborts the
    // mock task on SUT drop, exactly like `llm`. Read its recorder via `l6_chat_request_count()`.
    l6_llm: Option<llm_loopback::LoopbackLlm>,
    // HF fast-follow handles (None unless the corresponding builder axis is set).
    registry: Arc<dyn HostRegistry>,
    channel: Option<ChannelCapture>,
    mcp_client: Option<Arc<McpClient>>,
    agents: Option<AgentsHandle>,
    // GAP-3 (SYS-J-57): one production `AgentLoopDriverImpl` per `.agents()` tree
    // node, keyed by canonical `agent:` id. Each is baked with its node id and
    // shares the one MailboxStore + registry (fs resolver) + git commit queue.
    // Empty unless `.agents()` was set. Driven via `run_turn_for`/`run_turns_for`.
    node_drivers: HashMap<String, AgentLoopDriverImpl>,
    // GAP-3 (T57-5/6): the canonical HarnessAgentTree snapshot provider (the SAME
    // Arc wired into the fs resolver), retained so a test can build a resolver
    // over it and witness resolve_child_read + the Rule-2 write-block. `None` in
    // the single-agent path.
    harness_agent_tree: Option<Arc<dyn AgentTreeSnapshot>>,
    // Wave-15 Lane E (SYS-AC-011): the REAL bare-id `AgentTreeStore` the
    // `.with_real_spawn_tree()` spawn host-fns mutate (the SAME store fed into the turn
    // assembler). Retained so the witness can assert the COMMITTED Sub node `capabilities`
    // (the recording half) via `real_spawn_tree_snapshot()`. `None` otherwise.
    real_spawn_store: Option<Arc<AgentTreeStore>>,
    // HF-2: the real, injector-wired circuit breaker bus (driven via `circuit_breaker()`).
    circuit_breaker: Arc<dyn CircuitBreakerBus>,
    // Small-witness 2026-06-11: the SAME `Arc<MailboxStore>` the dispatcher +
    // agent loop + BreakerSubscriber share — exposed for freeze/drain witnesses.
    mailbox_store: Arc<MailboxStore>,
    // Backbone Step 3: the resolved persistent cap-memory root (default
    // `<workspace_root>/.agent/memory`, or the caller's `with_memory_dir`). Tests
    // re-open `MemoryStore::open(memory_dir, cap)` to assert on-disk persistence.
    memory_dir: PathBuf,
    // Perf-CI lane (perf_slo harness): the SAME live inner ContextAssembler (191) and
    // live PostProcessor (214) the driver was wired with — retained for direct
    // clean-seam timing. `inner_context_assembler` is `Some` whenever a loopback LLM is
    // configured (the assembler-install block, `if let Some(lp) = &llm`); `live_post_processor`
    // is `Some` only under `.with_live_memory()` (+ Cap::Memory + LLM). Both `None` otherwise.
    inner_context_assembler: Option<Arc<dyn advance_shared_types::context::ContextAssembler>>,
    live_post_processor: Option<Arc<dyn advance_shared_types::memory::PostProcessorHook>>,
    // Stage-C harvest pass-3 (SYS-AC 071/217/072): the harness VLM extractor (always
    // present; inert unless `.with_vlm_indexer()` installed it into Step-3). Exposed via
    // `vlm_calls()` so a witness asserts the recorded FileContent variants (e.g. `["Image"]`).
    vlm: Option<Arc<HarnessVlm>>,
    // Backbone Step 4: per-turn dispatched first-action payloads, accumulated by the
    // opt-in `CapturingOutboundSink` (empty unless `.with_reply_capture()` was set).
    captured_replies: Arc<Mutex<Vec<Vec<u8>>>>,
    // Harvest-triggers slice (SYS-AC 098-114): the REAL scheduler trigger subsystems
    // (None unless `.with_triggers()` was set).
    triggers: Option<TriggerHandles>,
    // Lifecycle-harvest slice (SYS-AC 152-154/237): the REAL runtime-config
    // watcher handles (None unless `.with_runtime_config_watch()` was set).
    runtime_config: Option<RuntimeConfigHandles>,
    // Lifecycle-harvest slice (SYS-AC 259-261): the REAL meta-schema watcher
    // handles (None unless `.with_meta_schema_watch()` was set). The watcher's
    // poll thread stops on SUT drop (MetaSchemaWatcher::Drop → shutdown).
    schema_watch: Option<SchemaWatchHandles>,
    // Rollback-memory slice: the RETAINED cursor store (the same Arc the
    // registered rollback-memory handler resets — the MODULE-011 §3.6
    // "same-Arc" integrator contract) plus its on-disk root. `None` unless
    // `Cap::Memory`.
    cursor_store: Option<Arc<L6CursorStore>>,
    // Stage-B SQLite/boot-reconcile slice: the concrete in-memory SQLite index
    // handle the fs trio writes to (Clone shares the single pooled connection) +
    // the SAME schema loader registered into register_agent_fs. `None` unless
    // `.with_sqlite_index()`. Used by `boot_reconcile()` + `fts_recall()`.
    sqlite_handle: Option<R2d2SqliteIndexHandle>,
    fs_schema: Option<Arc<MetaSchemaLoader>>,
    // Harvest-wave: the CONCRETE lazy tool registry (same Arc the tool-invoke
    // host-fn drives) for cache observation; the skill provider (same store the
    // skill host-fns resolve) for admin elevate_trust. `None` unless the
    // corresponding cap is registered.
    tool_registry: Option<Arc<cap_tools::LazyToolRegistry>>,
    skill_provider: Option<Arc<cap_skills::provider::SingleAgentSkillStoreProvider>>,
    // Wave-13 (SYS-AC-172): the SAME shared `DefaultDecompositionStore` the decomposition
    // host-fns AND the assembler's `CapDecompositionReader` resolve. `Some` only under
    // `.with_decomposition()`.
    decomposition_store: Option<Arc<DefaultDecompositionStore>>,
    // Sched-harvest 1B: the guest-instantiation quadruple (runtime / loaded
    // component / injector / caps) retained so `wasm_runnable_hook()` mints
    // PRODUCTION `WasmRunnableHook`s over THIS SUT's guest.
    runnable_parts: (
        Arc<ComponentRuntime>,
        advance_runtime::LoadedComponent,
        Arc<CapabilityInjector>,
        Vec<CapRequest>,
    ),
    // Small-witness 2026-06-11: the production Layer-4 freeze/drain driver task
    // (aborts on drop via its own Drop impl). Held for the SUT's lifetime.
    _breaker_subscriber: BreakerSubscriber,
    _queue: Arc<advance_git::DefaultGitCommitQueue>,
    _tempdir: tempfile::TempDir,
    client_api_server: Option<advance_client_api::ClientApiServer>,
    pump_exits: Arc<Mutex<Vec<advance_client_api::DeltaPumpExit>>>,
    llm_stream_reaper: Option<Arc<cap_llm::AgentStreamReaper>>,
}

/// Sched-harvest 1A (SYS-AC-110): the REAL submitter-grant subset gate — the
/// MODULE-014 §1.7 "production-adapter obligation" recipe, composed test-side
/// in this harness crate (zero new production edges):
/// `cap_grant::validate_capability_subset` over
/// `GrantStore::list_by_grantee(submitter)`, with
///   - the `agent:`-prefix duality: `GrantStore::insert`'s charset gate
///     colon-rejects `agent:` grantees, so static grants are keyed by the
///     BARE body while `submit_component`'s `submitter` is canonical
///     `agent:<body>` (and `insert_dynamic` grants may carry either) — the
///     adapter unions both grantee views;
///   - the Active-only filter (`list_by_grantee` returns every status;
///     consumed/expired/revoked grants must not authorize);
///   - the CSV→array re-projection (`Grant.params` values are CSV-serialized
///     strings; cap-grant's JSON→CSV projection rejects raw `,`-bearing
///     strings, so multi-token values re-project as JSON arrays);
///   - the fail-closed catch-all: EVERY non-`SubsetViolation` `CapGrantError`
///     also rejects (an unexpected resolver/projection error never approves —
///     the `CapGrantSubsetAdapter` precedent).
struct CapGrantSubmitSubsetGate {
    grants: Arc<GrantStore>,
}

impl SubmitSubsetGate for CapGrantSubmitSubsetGate {
    fn check(&self, submitter: &str, requested: &[Capability]) -> Result<(), SchedSpawnError> {
        let bare = submitter.strip_prefix("agent:").unwrap_or(submitter);
        let mut grants = self.grants.list_by_grantee(submitter);
        if bare != submitter {
            grants.extend(self.grants.list_by_grantee(bare));
        }
        let parent: Vec<Capability> = grants
            .iter()
            .filter(|g| g.status == GrantStatus::Active)
            .map(grant_to_capability)
            .collect();
        match validate_capability_subset(&parent, requested) {
            Ok(()) => Ok(()),
            Err(CapGrantError::SubsetViolation(msg)) => Err(SchedSpawnError::SubsetViolation(msg)),
            Err(other) => Err(SchedSpawnError::SubsetViolation(format!(
                "cap-grant projection error: {other}"
            ))),
        }
    }
}

/// CSV→array re-projection (MODULE-014 §1.7): a `Grant.params` value is a
/// CSV-serialized string (`"a,b"`); shared-types `CapParams` is JSON. A
/// multi-token value re-projects as a JSON array (cap-grant's JSON→CSV
/// projection round-trip rejects raw `,`-bearing top-level strings); a
/// single token stays a JSON string. A grant with no params projects as
/// `CapParams::empty()` (= whole capability).
fn grant_to_capability(g: &CapGrant) -> Capability {
    let mut obj = serde_json::Map::new();
    for p in &g.params {
        let tokens: Vec<&str> = p
            .value
            .split(',')
            .map(str::trim)
            .filter(|t| !t.is_empty())
            .collect();
        let v = if tokens.len() > 1 {
            serde_json::Value::Array(
                tokens
                    .into_iter()
                    .map(|t| serde_json::Value::String(t.to_string()))
                    .collect(),
            )
        } else {
            serde_json::Value::String(tokens.first().copied().unwrap_or("").to_string())
        };
        obj.insert(p.key.clone(), v);
    }
    let params = if obj.is_empty() {
        CapParams::empty()
    } else {
        CapParams::new(serde_json::Value::Object(obj))
    };
    Capability {
        id: CapabilityId::from(g.capability.as_str()),
        params,
    }
}

/// Harvest-triggers slice (SYS-AC 098-114): the real scheduler trigger handles stored
/// on the SUT when `.with_triggers()` is set. All are the production types from
/// `advance-scheduler` (no harness reimplementation) — the witnesses drive these
/// directly so the SYS-AC are exercised against real M014 product.
struct TriggerHandles {
    trigger_bus: Arc<TriggerBusDispatchImpl>,
    submit_registry: Arc<ComponentRegistry>,
    /// Arc since small-witness 2026-06-11 so the `SchedulerSubmitBridge`
    /// (the SYS-AC-047 admission adapter) can hold the SAME api instance.
    submit_api: Arc<InMemoryComponentSubmitApi>,
    /// The SAME `Arc<CapturingBus>` handle `events()` reads (the cron `trigger.fired` sink).
    emitter: Arc<dyn EventBusEmit>,
}

/// Lifecycle-harvest (SYS-AC 152-154/237) — the real M001 runtime-config
/// watcher handles stored on the SUT when `.with_runtime_config_watch()` is
/// set. The watcher is the production `RuntimeConfigWatcher` (notify-backed,
/// validated fail-closed reloads, `runtime.config_reloaded` emission).
struct RuntimeConfigHandles {
    watcher: Arc<RuntimeConfigWatcher>,
    path: PathBuf,
}

/// Lifecycle-harvest (SYS-AC 259-261) — the real cap-fs meta-schema watcher
/// handles stored on the SUT when `.with_meta_schema_watch()` is set. `loader`
/// is the SAME `Arc<MetaSchemaLoader>` registered into `register_agent_fs`.
struct SchemaWatchHandles {
    watcher: MetaSchemaWatcher,
    loader: Arc<MetaSchemaLoader>,
    path: PathBuf,
}

/// Minimal valid `/.advance/runtime-config.yaml` seed for the
/// `.with_runtime_config_watch()` axis (crib: `runtime/tests/config.rs`
/// `minimal_yaml`, plus an explicit `database:` block so SYS-AC-152's
/// dual-section edit has a baseline value to change — `database` is
/// `#[serde(default)]` and would otherwise be absent).
const MINIMAL_RUNTIME_CONFIG_YAML: &str = r#"
wasm:
  max_memory_pages: 512
  epoch_interruption_ms: 50
  fuel_enabled: true
llm-providers: []
cron:
  max_jitter_ratio: 0.05
git:
  gc_interval_hours: 12
  max_tracked_file_mb: 5
circuit-breakers: []
secrets:
  master-key-source: env-var
  env-var-name: MY_KEY
users: []
post-processor:
  llm-model: fast
  llm-failure-cooldown-seconds: 300
database:
  db-path: .runtime/index.db
  pool-size: 4
  recall-max-depth: 2
"#;

/// Minimal valid `/.advance/meta-schema.yaml` seed for the
/// `.with_meta_schema_watch()` axis (crib: cap-fs watcher tests `SCHEMA_A`).
const MINIMAL_META_SCHEMA_YAML: &str = r#"
required:
  name:
    type: string
    auto: filename
optional:
  tags:
    type: list<string>
    default: []
"#;

/// Small-witness 2026-06-11 (SYS-AC-047) — the M005→M014 type bridge: implements
/// cap-lifecycle's `ComponentSubmitGate` (the String-typed opaque seam) over the
/// REAL scheduler `InMemoryComponentSubmitApi` (the enum-typed CONTRACT-130 api).
/// Pure type-conversion glue — every behavioral decision (subset check, binary
/// shape, Rules 1-3 admission, quota, registry persistence) is made by the real
/// production code on either side.
struct SchedulerSubmitBridge {
    api: Arc<InMemoryComponentSubmitApi>,
}

impl SchedulerSubmitBridge {
    fn parse_component_type(
        s: &str,
    ) -> Result<advance_shared_types::component::ComponentType, LcSpawnError> {
        use advance_shared_types::component::ComponentType;
        match s {
            "agent" => Ok(ComponentType::Agent),
            "cron" => Ok(ComponentType::Cron),
            "watcher" => Ok(ComponentType::Watcher),
            "daemon" => Ok(ComponentType::Daemon),
            "task" => Ok(ComponentType::Task),
            other => Err(LcSpawnError::InvalidConfig(format!(
                "unknown component-type: {other}"
            ))),
        }
    }

    fn map_err(e: advance_scheduler::types::SpawnError) -> LcSpawnError {
        use advance_scheduler::types::SpawnError as SchedErr;
        match e {
            SchedErr::SubsetViolation(m) => LcSpawnError::SubsetViolation(m),
            SchedErr::InvalidConfig(m) => LcSpawnError::InvalidConfig(m),
            SchedErr::AlreadyExists(m) => LcSpawnError::AlreadyExists(m),
            SchedErr::CapabilityDenied(m) => {
                LcSpawnError::InvalidConfig(format!("capability denied: {m}"))
            }
            SchedErr::ResourceLimit(m) => {
                LcSpawnError::InvalidConfig(format!("resource limit: {m}"))
            }
        }
    }

    fn map_state(s: advance_scheduler::types::ComponentState) -> LcComponentState {
        use advance_scheduler::types::ComponentState as SchedState;
        match s {
            SchedState::Pending => LcComponentState::Pending,
            SchedState::Running => LcComponentState::Running,
            SchedState::Completed => LcComponentState::Completed,
            SchedState::Failed(m) => LcComponentState::Failed(m),
            SchedState::Killed => LcComponentState::Killed,
        }
    }
}

#[async_trait::async_trait]
impl ComponentSubmitGate for SchedulerSubmitBridge {
    async fn submit_component(
        &self,
        submitter: &str,
        config: LcComponentSubmitConfig,
    ) -> Result<LcComponentId, LcSpawnError> {
        use advance_scheduler::ComponentSubmitApi;
        let sched_config = advance_scheduler::types::ComponentSubmitConfig {
            sensitive_params: Vec::new(),
            id: config.id,
            component_type: Self::parse_component_type(&config.component_type)?,
            binary: config.binary,
            capabilities: config
                .capabilities
                .into_iter()
                .map(|s| CapRequest {
                    capability: CapabilityId::from(s),
                })
                .collect(),
            output_dir: config.output_dir,
            trigger: None,
            restart_policy: None,
            delay: None,
            initial_grants: None,
            preset: None,
            retry: None,
        };
        self.api
            .submit_component(submitter, sched_config)
            .await
            .map(|id| LcComponentId(id.0))
            .map_err(Self::map_err)
    }

    async fn kill_component(&self, id: &str) -> Result<(), LcSpawnError> {
        use advance_scheduler::ComponentSubmitApi;
        self.api.kill_component(id).await.map_err(Self::map_err)
    }

    async fn component_status(&self, id: &str) -> Result<LcComponentState, LcSpawnError> {
        use advance_scheduler::ComponentSubmitApi;
        self.api
            .component_status(id)
            .await
            .map(Self::map_state)
            .map_err(Self::map_err)
    }

    async fn list_components(&self) -> Vec<LcComponentInfo> {
        use advance_scheduler::ComponentSubmitApi;
        self.api
            .list_components()
            .await
            .into_iter()
            .map(|i| LcComponentInfo {
                id: LcComponentId(i.id.0),
                component_type: i.component_type.as_str().to_string(),
                status: Self::map_state(i.status),
                created_at: i.created_at,
            })
            .collect()
    }
}

/// Harvest-triggers slice: a real `RunnableHook` that counts invocations — the fire
/// witness for `drive_cron_fire` (a genuine hook execution, not a stub of the dispatch
/// or emit path). Mirrors `crates/scheduler/tests/cron_trigger_fired_emit.rs`.
struct CronCountingHook(Arc<std::sync::atomic::AtomicUsize>);

#[async_trait::async_trait]
impl RunnableHook for CronCountingHook {
    async fn run_once(&self, _config: ComponentConfig) -> Result<RunResult, HookError> {
        self.0.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Ok(RunResult {
            status: RunStatus::Completed,
            output: None,
        })
    }
}

/// Stage-B harness embedder for the boot-reconcile index rebuild. Returns a
/// fixed-dim (`DEFAULT_EMBEDDING_DIM` = 768) finite zero vector so
/// `R2d2IndexRebuildImpl`'s `embed_or_skip` never aborts the rebuild (it rejects
/// any dim mismatch or non-finite value). `content_vec` is irrelevant to the
/// FTS/keyword recall the witnesses use — this exists only to satisfy the
/// rebuild's `advance_database::Embedder` bound. NOT a semantic embedding.
/// (Distinct from cap-memory's `StubEmbedder`, which impls a cap-memory-INTERNAL
/// `Embedder` trait, not `advance_database::Embedder`.)
#[derive(Clone)]
struct HarnessIndexEmbedder;

#[async_trait::async_trait]
impl advance_database::Embedder for HarnessIndexEmbedder {
    async fn embed(&self, _text: &str) -> Result<Vec<f32>, advance_database::EmbedderError> {
        Ok(vec![0.0_f32; DEFAULT_EMBEDDING_DIM])
    }
}

impl SystemUnderTest {
    /// Start configuring a system under test.
    pub fn builder() -> SystemUnderTestBuilder {
        SystemUnderTestBuilder::default()
    }

    /// Perf-CI lane (SYS-AC-191): the SAME live INNER `ContextAssembler` the driver was
    /// wired with — the bare `assemble()` seam, pre-`PublishingContextAssembler` (so timing
    /// it carries no `gateway.publish_assembled` hop). `Some` on any build that installs a
    /// context assembler — i.e. whenever a loopback LLM is configured (`if let Some(lp) = &llm`);
    /// it is the **history-aware** inner assembler under `.with_live_memory()` and the
    /// no-history inner assembler otherwise. The 191 witness uses `.with_live_memory()` (so it
    /// gets the history-aware variant) and calls `.assemble(ctx)` directly with
    /// `ctx.task_id = Some(..)` to exclude the embedding round-trip.
    pub fn context_assembler_inner(
        &self,
    ) -> Option<Arc<dyn advance_shared_types::context::ContextAssembler>> {
        self.inner_context_assembler.clone()
    }

    /// Perf-CI lane (SYS-AC-214): the SAME live `PostProcessor` the driver was wired with —
    /// the `PostProcessor::run` seam. `Some` only when `.with_live_memory()` (with
    /// `Cap::Memory` + a loopback LLM) was set. The perf witness times one `run(agent_id,
    /// &msg, &result)` over a representative `(Message, ActionResult)`.
    pub fn live_post_processor(
        &self,
    ) -> Option<Arc<dyn advance_shared_types::memory::PostProcessorHook>> {
        self.live_post_processor.clone()
    }

    /// Back-compat (BS-3): an fs-only, AllowAll, Capturing system — equivalent to
    /// `builder().caps(&[Cap::Fs]).build(guest)`.
    pub async fn start(guest_wasm: &[u8]) -> Self {
        Self::builder().caps(&[Cap::Fs]).build(guest_wasm).await
    }

    /// Inject one inbound user message through the REAL dispatcher (emits
    /// `msg.received` and queues the message for the next turn). The sender is
    /// `user:<sender_id>` (bypasses hierarchy adjacency).
    pub async fn inject_message(&self, sender_id: &str, payload: &[u8]) {
        let msg = Message {
            id: format!("msg-{sender_id}"),
            kind: MessageKind::User,
            from: format!("user:{sender_id}"),
            to: self.agent_id.clone(),
            payload: payload.to_vec(),
            context: None,
            timestamp: SystemTime::now(),
            origin: None,
        };
        self.dispatcher
            .deliver(&self.agent_id, msg)
            .await
            .expect("deliver (validate_routing passes)");
    }

    /// Stage-C harvest pass-1 (SYS-AC 006/008): inject one inbound user message
    /// carrying an explicit `MessageContext.task_id`, so the live read+write path
    /// partitions on `tasks/{task_id}/`. The assembler reads `summary.yaml` /
    /// `turn-index.yaml` under `<memory_dir>/tasks/{task_id}/` (`ctx.task_id` →
    /// `CapMemoryHistoryReader`) AND the components `PostProcessor` Step-7 writes the
    /// SAME partition — so a turn-1 write and a turn-2 read align. Pin `task_id` to
    /// the WRITER's stricter charset (plain `[A-Za-z0-9_-]`, single component, NO
    /// leading dot): a value the read gate accepts but the write sanitizer rejects
    /// would skip the write / read empty (silent fake-green).
    pub async fn inject_message_with_task(&self, sender_id: &str, task_id: &str, payload: &[u8]) {
        let msg = Message {
            id: format!("msg-{sender_id}"),
            kind: MessageKind::User,
            from: format!("user:{sender_id}"),
            to: self.agent_id.clone(),
            payload: payload.to_vec(),
            context: Some(MessageContext {
                task_id: Some(task_id.to_string()),
                run_id: None,
                execution_id: None,
                trace_id: None,
                in_reply_to: None,
                correlation_id: None,
            }),
            timestamp: SystemTime::now(),
            origin: None,
        };
        self.dispatcher
            .deliver(&self.agent_id, msg)
            .await
            .expect("deliver (validate_routing passes)");
    }

    /// Drive ONE agent turn: `run_agent` recvs the queued message and runs the guest.
    pub async fn run_turn(&self) {
        let cfg = ComponentConfig {
            id: self.agent_id.clone(),
            config_data: None,
            trigger_context: None,
        };
        let instance =
            WasmInstance::new(ComponentId::new("agent-harness-inst".to_string()).expect("id"));
        self.driver.run_agent(&self.agent_id, cfg, instance).await;
    }

    /// Backbone Step 4 — drive `n` consecutive agent turns on ONE persistent run
    /// loop via the production `AgentLoopDriverImpl::serve_n_turns` (bootstrap+init
    /// ONCE, then `n` turns carrying `new_state` turn→turn). This is the multi-turn
    /// witness path: it reuses the same `serve`/`run_turn_once` machinery the daemon
    /// runs, NOT a bespoke loop.
    ///
    /// Caller contract: enqueue at least `n` messages (via [`Self::inject_message`])
    /// BEFORE calling — each turn's `recv` awaits a queued message, so an under-fed
    /// `run_turns(n)` parks on the missing turn. `run_turns` MUST be the SOLE driver
    /// entry on a SUT: it re-runs `init` (a fresh guest Store), so mixing it with
    /// `run_turn()` (or a second `run_turns`) on the same SUT discards prior state.
    pub async fn run_turns(&self, n: usize) {
        let cfg = ComponentConfig {
            id: self.agent_id.clone(),
            config_data: None,
            trigger_context: None,
        };
        let instance =
            WasmInstance::new(ComponentId::new("agent-harness-inst-n".to_string()).expect("id"));
        self.driver
            .serve_n_turns(&self.agent_id, cfg, instance, n)
            .await;
    }

    /// GAP-3 (SYS-J-57): inject one inbound user message to a SPECIFIC tree
    /// `node` (canonical `agent:` id), the multi-agent analogue of
    /// [`Self::inject_message`]. The sender is `user:<sender_id>` so
    /// `validate_routing` short-circuits Ok to any existing node (no hierarchy
    /// adjacency check). Delivers to `node`'s own mailbox partition; pair with
    /// [`Self::run_turn_for`]/[`Self::run_turns_for`] for the SAME `node`.
    pub async fn inject_message_to(&self, node: &str, sender_id: &str, payload: &[u8]) {
        let msg = Message {
            id: format!("msg-{sender_id}-{node}"),
            kind: MessageKind::User,
            from: format!("user:{sender_id}"),
            to: node.to_string(),
            payload: payload.to_vec(),
            context: None,
            timestamp: SystemTime::now(),
            origin: None,
        };
        self.dispatcher.deliver(node, msg).await.expect(
            "deliver to node (validate_routing passes for a user: sender to an existing node)",
        );
    }

    /// GAP-3 (SYS-J-57): drive ONE turn for a SPECIFIC tree `node` (canonical
    /// `agent:` id) through that node's own production driver. `node` is passed as
    /// BOTH the `run_agent` recv/dispatch argument (so it recvs the message
    /// `inject_message_to(node, …)` queued) AND — because the node's driver was
    /// built with a handler baked with `node` — the fs `HostCallContext.agent_id`
    /// (so the turn's `fs_write` resolves to `node`'s DISTINCT territory). Two
    /// `run_turn_for` futures may be `tokio::join!`ed: they borrow `&self`
    /// immutably and serialize only on the shared single-in-flight commit queue.
    /// Requires `.agents()` (panics on an unknown node).
    pub async fn run_turn_for(&self, node: &str) {
        let driver = self
            .node_drivers
            .get(node)
            .expect("run_turn_for: node has a driver (was it declared in .agents()?)");
        let cfg = ComponentConfig {
            id: node.to_string(),
            config_data: None,
            trigger_context: None,
        };
        let instance = WasmInstance::new(
            ComponentId::new(format!("agent-harness-inst-{}", node.replace(':', "-"))).expect("id"),
        );
        driver.run_agent(node, cfg, instance).await;
    }

    /// GAP-3 (SYS-J-57): drive `n` consecutive turns for a SPECIFIC tree `node`
    /// via its own driver's `serve_n_turns` (bootstrap+init ONCE, then `n` turns
    /// carrying state turn→turn). Same dual-id contract as [`Self::run_turn_for`]
    /// (`node` is both the recv arg and the baked fs caller id). Caller must
    /// enqueue ≥ `n` messages via [`Self::inject_message_to`] for this `node`
    /// first. Requires `.agents()` (panics on an unknown node).
    pub async fn run_turns_for(&self, node: &str, n: usize) {
        let driver = self
            .node_drivers
            .get(node)
            .expect("run_turns_for: node has a driver (was it declared in .agents()?)");
        let cfg = ComponentConfig {
            id: node.to_string(),
            config_data: None,
            trigger_context: None,
        };
        let instance = WasmInstance::new(
            ComponentId::new(format!("agent-harness-inst-n-{}", node.replace(':', "-")))
                .expect("id"),
        );
        driver.serve_n_turns(node, cfg, instance, n).await;
    }

    /// GAP-3 (T57-5/6): the canonical `HarnessAgentTree` snapshot provider wired
    /// into the fs resolver (canonical `agent:`-keyed `parent_of`/`children_of`/
    /// `peer_slug_map`), or `None` in the single-agent path. A test builds a
    /// `DefaultVirtualPathResolver::new(self.workspace_root(), provider)` over it to
    /// witness `resolve_child_read` + the Rule-2 child-territory write-block — an
    /// EMPTY `children_of` (the pre-GAP-1 state) would FAIL those, proving the
    /// snapshot maps are populated. Distinct from [`Self::tree_snapshot`] (the
    /// bare-id cap-lifecycle `AgentTreeStore`).
    pub fn harness_agent_tree(&self) -> Option<Arc<dyn AgentTreeSnapshot>> {
        self.harness_agent_tree.clone()
    }

    /// Wave-15 Lane E (SYS-AC-011): a snapshot of the REAL spawn tree (the bare-id
    /// `AgentTreeStore` the `.with_real_spawn_tree()` spawn host-fns mutate), so a witness
    /// can assert a real-spawned Sub node's COMMITTED `capabilities` (the recording half,
    /// distinct from the assembler render). `None` unless `.with_real_spawn_tree()` was set.
    pub fn real_spawn_tree_snapshot(&self) -> Option<AgentTreeSnapshotData> {
        self.real_spawn_store.as_ref().map(|s| s.snapshot())
    }

    /// Backbone Step 4 — the dispatched first-action payloads, one per turn that
    /// produced an action, in turn order. Populated ONLY when the SUT was built with
    /// `.with_reply_capture()`; empty otherwise. Witnesses that each turn produced a
    /// delivered (coherent) reply through the real action-dispatch outbound seam.
    pub fn delivered_replies(&self) -> Vec<Vec<u8>> {
        self.captured_replies.lock().unwrap().clone()
    }

    /// SYS-J-72: bound Client API, if `.with_delta_tee()` was set.
    pub fn client_api_server(&self) -> Option<&advance_client_api::ClientApiServer> {
        self.client_api_server.as_ref()
    }

    /// SYS-J-72: capturing tee wrapper (Begin keys + recorded Deltas).
    pub fn capturing_sink(&self) -> Option<Arc<llm_loopback::CapturingDeltaSink>> {
        self.llm.as_ref().and_then(|lp| lp.capturing_sink())
    }

    /// SYS-J-72: retained stream reaper.
    pub fn llm_stream_reaper(&self) -> Option<Arc<cap_llm::AgentStreamReaper>> {
        self.llm_stream_reaper.clone()
    }

    /// SYS-J-72: WS pump-exit log (factory-installed observer).
    pub fn pump_exits(&self) -> Vec<advance_client_api::DeltaPumpExit> {
        self.pump_exits.lock().expect("pump exits").clone()
    }

    /// Backbone Step 4 — every outbound `/v1/chat/completions` request body the
    /// loopback mock observed, in arrival order (one per turn that dialed `generate`).
    /// Empty when no loopback was configured. Used by the multi-turn stateless witness
    /// to inspect each turn's request for provider session ids + its own prompt.
    pub fn llm_all_chat_request_bodies(&self) -> Vec<String> {
        self.llm
            .as_ref()
            .map(|l| l.all_chat_request_bodies())
            .unwrap_or_default()
    }

    /// Wave-16 Lane 2 (SYS-AC-005): switch the CONFIGURED LLM provider in-run. Mutates the
    /// loopback gateway's live `InlineConfigProvider` to a genuinely DIFFERENT provider config
    /// ENTRY (distinct `id` + model; OpenAI-wire, same endpoint host + seeded secret) — the
    /// gateway re-reads it on the NEXT `generate`, so a subsequent `run_turn()`'s outbound body
    /// carries `default_model`. Drive turn-1, call this, then drive turn-2 (separate `run_turn()`
    /// calls so the switch lands BETWEEN the two `generate` calls). Panics if no loopback LLM.
    pub fn switch_llm_provider(&self, provider_id: &str, default_model: &str) {
        self.llm
            .as_ref()
            .expect("switch_llm_provider requires a loopback LLM (.llm(LlmMode::Loopback*))")
            .switch_provider(provider_id, default_model);
    }

    // --- raw accessors (the generic assertion escape-hatch) ---

    /// All emitted events captured since boot (Capturing sink only; empty for RealBus
    /// — use [`Self::events_from_db`] there).
    pub fn events(&self) -> Vec<Event> {
        match &self.bus {
            BusHandle::Capturing(b) => b.events.lock().unwrap().clone(),
            BusHandle::Real(_) => Vec::new(),
        }
    }

    /// The agent's workspace root (temp dir, dropped on teardown).
    pub fn workspace_root(&self) -> &std::path::Path {
        &self.workspace_root
    }

    /// Stage-C harvest pass-3 (SYS-AC 071/217): the `FileContent` variants the harness
    /// VLM recorded this build, in order (empty unless `.with_vlm_indexer()` installed it
    /// AND a non-text file was routed to it). A witness asserts e.g. `== ["Image"]` to
    /// prove the VLM fired exactly once with the image variant (not for `.md`/`.bin`).
    pub fn vlm_calls(&self) -> Vec<String> {
        self.vlm.as_ref().map(|v| v.calls()).unwrap_or_default()
    }

    /// Stage-B (SYS-AC 146/147/148/233): run a REAL `WorkspaceReconciler` over the
    /// workspace — repair `.meta.yaml` drift, then `IndexRebuild::rebuild_full`
    /// against the SAME in-memory SQLite index the fs trio writes to — emitting
    /// `fs.reconcile_completed` (always) + `runtime.index_rebuild` (on the
    /// successful-rebuild branch) into the SUT event sink. Returns the aggregate
    /// `ReconcileReport`; inspect `.rebuild_report.as_ref().unwrap().errors` for the
    /// degraded-mode (SYS-AC-233) witness. Requires `.with_sqlite_index()`.
    ///
    /// Single-connection ordering (handle is `Pool::max_size(1)`): callers MUST
    /// `run_turn().await` to completion (draining any in-flight fs upsert) BEFORE
    /// calling this — never overlap a write turn with a reconcile/recall.
    pub async fn boot_reconcile(&self) -> ReconcileReport {
        let handle = self
            .sqlite_handle
            .as_ref()
            .expect("boot_reconcile() requires .with_sqlite_index()");
        let schema = self
            .fs_schema
            .as_ref()
            .expect("boot_reconcile() requires .with_sqlite_index()")
            .clone();
        let maintainer = Arc::new(MetaMaintainer::new(
            Arc::clone(&schema),
            Arc::new(DefaultAtomicWriter),
        ));
        let rebuild: Arc<dyn IndexRebuild> = Arc::new(R2d2IndexRebuildImpl::new(
            handle.clone(),
            HarnessIndexEmbedder,
            self.workspace_root.clone(),
        ));
        let reconciler = WorkspaceReconciler::new(
            self.workspace_root.clone(),
            schema,
            maintainer,
            Some(rebuild),
            self.bus.as_dyn(),
        );
        reconciler
            .reconcile(&self.agent_id, "trace-boot-reconcile")
            .await
            .expect("boot reconcile")
    }

    /// Stage-B (SYS-AC 148/151/260): recall over the in-memory SQLite index via the
    /// FTS/keyword path (`content_vec` is unpopulated on the write path —
    /// `embedding=None` — so the vector branch returns nothing; the non-empty
    /// `query` keywords drive the `content_fts` branch). `agent_id` is the
    /// M004-derived index scope: for a guest write into its own workspace use
    /// [`Self::agent_m004_id`] (`"agent"`). Requires `.with_sqlite_index()`.
    ///
    /// Single-connection ordering: see [`Self::boot_reconcile`] — drain the write
    /// turn before recalling.
    pub async fn fts_recall(&self, agent_id: &str, query: &str) -> Vec<RecallResult> {
        let handle = self
            .sqlite_handle
            .as_ref()
            .expect("fts_recall() requires .with_sqlite_index()");
        let recall = R2d2RecallImpl::new(handle.clone());
        // recall() validates query_embedding (len == embedding_dim AND non-zero
        // magnitude) BEFORE branching, so pass a dim-length UNIT vector even though
        // the FTS/keyword branch ignores its direction entirely.
        let mut q_emb = vec![0.0_f32; recall.current_embedding_dim()];
        if let Some(first) = q_emb.first_mut() {
            *first = 1.0;
        }
        recall
            .recall(agent_id, query, &q_emb, 16)
            .await
            .expect("fts recall")
    }

    /// The M004 index agent_id for the single-agent guest's own workspace
    /// (`<workspace_root>/agent` → `"agent"`) — the scope guest-written files are
    /// indexed under. Pass to [`Self::fts_recall`].
    pub fn agent_m004_id(&self) -> String {
        agent_id_for_m004(&self.workspace_root, &self.workspace_root.join(AGENT_DIR))
            .expect("single-agent m004 id derivable")
    }

    /// Stage-B (SYS-AC-149): direct presence of the SQLite triple-sync rows for a
    /// just-written file (queried against the live `meta_index`/`content_index`
    /// tables — no recall, no rebuild), proving the `fs_write` SQLite leg landed
    /// atomically alongside the file + `.meta.yaml`. Returns
    /// `(meta_index_present, content_index_present)`. Requires `.with_sqlite_index()`.
    pub fn sqlite_file_indexed(
        &self,
        agent_id: &str,
        directory: &str,
        entry_name: &str,
        file_path: &str,
    ) -> (bool, bool) {
        let handle = self
            .sqlite_handle
            .as_ref()
            .expect("sqlite_file_indexed() requires .with_sqlite_index()");
        let conn = handle.get_conn().expect("sqlite conn");
        let meta: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM meta_index WHERE agent_id=?1 AND directory=?2 AND entry_name=?3",
                rusqlite::params![agent_id, directory, entry_name],
                |r| r.get(0),
            )
            .unwrap_or(0);
        let content: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM content_index WHERE agent_id=?1 AND file_path=?2",
                rusqlite::params![agent_id, file_path],
                |r| r.get(0),
            )
            .unwrap_or(0);
        (meta > 0, content > 0)
    }

    /// Backbone Step 3: the resolved persistent cap-memory root (default
    /// `<workspace_root>/.agent/memory`, or the `with_memory_dir` override). A test
    /// re-opens `MemoryStore::open(sut.memory_dir(), cap)` (a fresh instance
    /// hydrates from disk) and `recall(sut.agent_id(), …)` to assert that a guest
    /// turn's memory was persisted to `<memory_dir>/<agent-slug>/knowledge.jsonl`.
    pub fn memory_dir(&self) -> &std::path::Path {
        &self.memory_dir
    }

    /// The real-bus SQLite `events.db` path (RealBus sink only).
    pub fn event_db_path(&self) -> Option<&std::path::Path> {
        self.event_db_path.as_deref()
    }

    /// The SUT's OWN event sink as a CONTRACT-180 [`EventBusEmit`] — under
    /// `EventSink::RealBus` this is the real `advance_event_bus::EventBus` whose SQLite
    /// `events` table [`Self::events_from_db`] reads back.
    ///
    /// DISTINCT from [`Self::event_emitter`], which is the `.with_triggers()`
    /// Capturing-only shared sink and panics without that axis. This accessor is defined
    /// for BOTH sinks and exists so a witness can inject the SUT's real bus into a
    /// FOREIGN subsystem's own emitter (e.g. device-mesh's `EventBusMeshEventSink`) and
    /// then assert on rows READ BACK from the bus — instead of asserting against a
    /// recording double the harness itself controls.
    pub fn event_bus_emitter(&self) -> Arc<dyn EventBusEmit> {
        self.bus.as_dyn()
    }

    /// The cap-grant store for bespoke grant assertions/seeding. `Some` under
    /// `GrantMode::Real` OR `.with_tool_grant_filter()` (Wave-15 Lane E — the latter
    /// rebinds a dedicated, schema-ensured store under `GrantMode::AllowAll`); `None`
    /// otherwise.
    pub fn grant_store(&self) -> Option<&Arc<cap_grant::GrantStore>> {
        self.grant_store.as_ref()
    }

    /// The loopback LLM gateway (when `.llm(Loopback)` was configured).
    pub fn llm_gateway(&self) -> Option<Arc<cap_llm::LlmGateway>> {
        self.llm.as_ref().map(|l| l.gateway.clone())
    }

    /// The `Authorization` header the loopback LLM mock observed on its last request —
    /// witnesses the REAL cap-http chain's credential-injection step (Loopback only).
    pub fn llm_recorded_authorization(&self) -> Option<String> {
        self.llm.as_ref().and_then(|l| l.recorded_authorization())
    }

    /// How many `/v1/chat/completions` requests the loopback mock observed (the retry
    /// witness — e.g. `429-then-200` ⇒ 2). 0 when no loopback was configured. HF-2.
    pub fn llm_chat_request_count(&self) -> usize {
        self.llm
            .as_ref()
            .map(|l| l.chat_request_count())
            .unwrap_or(0)
    }

    /// Backbone Step 2 — the BODY of the loopback's last `/v1/chat/completions`
    /// request (the JSON the real OpenAI adapter put on the wire). Witnesses that
    /// the host-assembled layered context reached the LLM (SYS-AC-010). `None`
    /// when no loopback / no chat request.
    pub fn llm_last_chat_request_body(&self) -> Option<String> {
        self.llm.as_ref().and_then(|l| l.last_chat_request_body())
    }

    /// Wave-7 Lane A (SYS-AC 069/216) — how many `/v1/chat/completions` requests the SEPARATE
    /// L6-classifier loopback gateway observed, i.e. the number of REAL L6 `classify()` dials
    /// (the load-bearing, non-fake-green dial witness: `memory.l6_completed` alone is NOT proof
    /// of a dial, since the Stub path produces it too). 0 when no L6 gateway axis was set.
    pub fn l6_chat_request_count(&self) -> usize {
        self.l6_llm
            .as_ref()
            .map(|l| l.chat_request_count())
            .unwrap_or(0)
    }

    /// Wave-7 Lane A (SYS-AC-069) — EVERY `/v1/chat/completions` request body the SEPARATE
    /// L6-classifier gateway saw, in arrival order, so a witness can confirm the L6 prompt
    /// (e.g. the `"L6 cross-task consolidation"` marker) actually reached the gateway. Empty
    /// when no L6 gateway axis was set.
    pub fn l6_chat_request_bodies(&self) -> Vec<String> {
        self.l6_llm
            .as_ref()
            .map(|l| l.all_chat_request_bodies())
            .unwrap_or_default()
    }

    /// The real, injector-wired circuit breaker bus (HF-2) — `open(CircuitBreaker{..})` then
    /// `is_open_agent`/`is_open_capability` drive it; `DefaultCircuitBreakerBus::is_admin_op`
    /// classifies an admin bypass. Since small-witness 2026-06-11 the SAME bus also gates the
    /// REAL dispatcher (Layer 1: deliver/reply/notify) and drives the production
    /// `BreakerSubscriber` (Layer 4: mailbox freeze/drain) — the full SYS-J-39 journey.
    pub fn circuit_breaker(&self) -> Arc<dyn CircuitBreakerBus> {
        self.circuit_breaker.clone()
    }

    /// Small-witness 2026-06-11 — the SAME `Arc<MailboxStore>` the dispatcher, agent
    /// loop, and `BreakerSubscriber` share. Freeze/drain witnesses poll
    /// `get(agent).poll()/is_frozen()` here (SYS-AC-126/127).
    pub fn mailbox_store(&self) -> Arc<MailboxStore> {
        self.mailbox_store.clone()
    }

    /// Small-witness 2026-06-11 — the REAL `MailboxDispatcherImpl` (raw-accessor
    /// escape hatch). Drive `deliver`/`reply`/`notify_agent` directly to witness
    /// the Layer-1 breaker gate's `Result` values (SYS-AC-125/127).
    pub fn dispatcher(&self) -> &Arc<MailboxDispatcherImpl> {
        &self.dispatcher
    }

    // --- typed witnesses (sugar over the raw accessors) ---

    /// Assert at least one `event_type` event matches `pred`; returns the first match.
    pub fn assert_event(&self, event_type: &str, pred: impl Fn(&Event) -> bool) -> Event {
        self.events()
            .into_iter()
            .find(|e| e.event_type == event_type && pred(e))
            .unwrap_or_else(|| panic!("no `{event_type}` event matched the predicate"))
    }

    /// Events whose type is in `types` (Capturing sink) — e.g. the grant witness set
    /// `["resolver.invoked", "grant.issued", "authz.checked"]`.
    pub fn events_of_types(&self, types: &[&str]) -> Vec<Event> {
        self.events()
            .into_iter()
            .filter(|e| types.contains(&e.event_type.as_str()))
            .collect()
    }

    /// All rows in the real-bus SQLite `events` table (RealBus sink only). Reads via a
    /// fresh read-only connection — valid immediately after a turn (the synchronous
    /// bus writes inline).
    pub fn events_from_db(&self) -> Vec<DbEventRow> {
        let path = self
            .event_db_path
            .as_ref()
            .expect("events_from_db requires EventSink::RealBus");
        let conn = rusqlite::Connection::open(path).expect("open events.db");
        let mut stmt = conn
            .prepare("SELECT id, timestamp, agent_id, trace_id, event_type, payload FROM events ORDER BY timestamp")
            .expect("prepare events query");
        let rows = stmt
            .query_map([], |r| {
                Ok(DbEventRow {
                    id: r.get(0)?,
                    timestamp: r.get(1)?,
                    agent_id: r.get(2)?,
                    trace_id: r.get(3)?,
                    event_type: r.get(4)?,
                    payload: r.get(5)?,
                })
            })
            .expect("query events")
            .map(|r| r.expect("row"))
            .collect();
        rows
    }

    /// Assert at least one SQLite `events` row of `event_type` matches `pred`; returns it.
    pub fn assert_db_event(
        &self,
        event_type: &str,
        pred: impl Fn(&DbEventRow) -> bool,
    ) -> DbEventRow {
        self.events_from_db()
            .into_iter()
            .find(|e| e.event_type == event_type && pred(e))
            .unwrap_or_else(|| panic!("no `{event_type}` row in events.db matched the predicate"))
    }

    /// Count SQLite `events` rows (optionally filtered by type).
    pub fn db_event_count(&self, event_type: Option<&str>) -> usize {
        self.events_from_db()
            .into_iter()
            .filter(|e| event_type.is_none_or(|t| e.event_type == t))
            .count()
    }

    /// Assert the real bus dropped zero events (oversize / duplicate-id / backpressure).
    /// No-op for the Capturing sink.
    pub fn assert_no_dropped_events(&self) {
        if let BusHandle::Real(b) = &self.bus {
            assert_eq!(
                b.dropped_count(),
                0,
                "real EventBus dropped {} event(s)",
                b.dropped_count()
            );
        }
    }

    /// All commits on HEAD (most-recent first). `bootstrap_repo_at` leaves an unborn
    /// HEAD (zero commits), so after N turns there are N commits.
    pub fn turn_commits(&self) -> Vec<CommitInfo> {
        let repo = match git2::Repository::open(&self.workspace_root) {
            Ok(r) => r,
            Err(_) => return Vec::new(),
        };
        let head = match repo.head().and_then(|h| h.peel_to_commit()) {
            Ok(c) => c,
            Err(_) => return Vec::new(),
        };
        let mut out = Vec::new();
        let mut cur = Some(head);
        while let Some(c) = cur {
            let message = c.message().unwrap_or("").to_string();
            // Recursive tree walk → every blob path (workspace-root-relative).
            let mut tree_paths = Vec::new();
            if let Ok(tree) = c.tree() {
                let _ = tree.walk(git2::TreeWalkMode::PreOrder, |dir, entry| {
                    if entry.kind() == Some(git2::ObjectType::Blob) {
                        let name = entry.name().unwrap_or("");
                        tree_paths.push(format!("{dir}{name}"));
                    }
                    git2::TreeWalkResult::Ok
                });
            }
            out.push(CommitInfo {
                is_turn: message.starts_with("[turn]"),
                message,
                parent_count: c.parent_count(),
                tree_paths,
            });
            cur = c.parent(0).ok();
        }
        out
    }

    /// Assert exactly one `[turn]` commit exists; returns it.
    pub fn assert_exactly_one_turn_commit(&self) -> CommitInfo {
        let turns: Vec<CommitInfo> = self
            .turn_commits()
            .into_iter()
            .filter(|c| c.is_turn)
            .collect();
        assert_eq!(
            turns.len(),
            1,
            "expected exactly one turn commit, got {}",
            turns.len()
        );
        turns.into_iter().next().unwrap()
    }

    /// Read a file in the agent's workspace, by path relative to the agent's territory.
    pub fn read_workspace_file(&self, rel: &str) -> Option<Vec<u8>> {
        std::fs::read(self.workspace_root.join(AGENT_DIR).join(rel)).ok()
    }

    /// Read the HEAD-COMMITTED blob whose workspace-root-relative path ENDS WITH
    /// `path_suffix` (e.g. `"skills/myskill/SKILL.md"`); returns its committed bytes
    /// from the git tree (NOT the working tree — proves the dual-track `[turn]` commit
    /// genuinely staged the content). The LC-01/02 `head_skill_md` analogue + the
    /// anti-fake-green reader for the SYS-AC-076/077 turn-commit conjunct. `None` if no
    /// committed blob matches. Suffix-match (not exact) so it is robust to the harness's
    /// `agent/.agent/skills/...` rooting vs production's `.agent/.agent/skills/...`.
    pub fn head_committed_blob(&self, path_suffix: &str) -> Option<Vec<u8>> {
        let repo = git2::Repository::open(&self.workspace_root).ok()?;
        let tree = repo.head().ok()?.peel_to_commit().ok()?.tree().ok()?;
        let mut found: Option<git2::Oid> = None;
        let _ = tree.walk(git2::TreeWalkMode::PreOrder, |dir, entry| {
            if entry.kind() == Some(git2::ObjectType::Blob) {
                let full = format!("{dir}{}", entry.name().unwrap_or(""));
                if full.ends_with(path_suffix) {
                    found = Some(entry.id());
                    return git2::TreeWalkResult::Abort;
                }
            }
            git2::TreeWalkResult::Ok
        });
        let blob = repo.find_blob(found?).ok()?;
        Some(blob.content().to_vec())
    }

    pub fn agent_id(&self) -> &str {
        &self.agent_id
    }

    /// Harvest-wave (SYS-AC-082/083/084/085/219): the CONCRETE `LazyToolRegistry`
    /// the `tool-invoke` host-fn drives — the SAME Arc, so `register_binary` adds
    /// tools the host-fn can invoke and `cache_len`/`list` observe the real cache
    /// state (LRU eviction, failed-set hiding). `None` unless `Cap::Tools`.
    pub fn tool_registry(&self) -> Option<&Arc<cap_tools::LazyToolRegistry>> {
        self.tool_registry.as_ref()
    }

    /// Harvest-wave (SYS-AC-218): the skill provider whose `get(agent_id)` returns
    /// the SAME `Arc<Mutex<SkillStore>>` the skill host-fns resolve — so a test can
    /// call the admin (NOT host-fn) `elevate_trust` on the very store the real
    /// `activate-skill` reads. `None` unless `Cap::Skills`.
    pub fn skill_provider(
        &self,
    ) -> Option<&Arc<cap_skills::provider::SingleAgentSkillStoreProvider>> {
        self.skill_provider.as_ref()
    }

    /// Wave-13 (SYS-AC-172): the SAME shared `DefaultDecompositionStore` the decomposition
    /// host-fns AND the assembler's `CapDecompositionReader` resolve — so a witness can
    /// inspect/seed the very store the next-turn `# Active Task Decomposition` section reads.
    /// `None` unless `.with_decomposition()`.
    pub fn decomposition_store(&self) -> Option<&Arc<DefaultDecompositionStore>> {
        self.decomposition_store.as_ref()
    }

    // --- HF fast-follow: generic host-fn primitive (linker-bypass) ---

    /// The live host registry (for tracks that want bespoke lookup/inspection).
    pub fn host_registry(&self) -> &Arc<dyn HostRegistry> {
        &self.registry
    }

    /// Look up a registered host fn by `(cap, namespace, name)` and invoke its
    /// `HostFunctionHandler::call` DIRECTLY with constructed `Val`s, bypassing the
    /// WASM component linker — so it drives caps whose `register_*` namespace is
    /// unversioned (channel / lifecycle / mcp). Uses this SUT's agent as the caller.
    ///
    /// **Witness-fidelity caveat (READ BEFORE asserting security properties).**
    /// This primitive invokes the handler DIRECTLY, so it bypasses the production
    /// `CapabilityInjector` grant gate + circuit breaker AND the host-authoritative
    /// `agent_id` stamping that the real guest-driven WASM path enforces. It is a
    /// faithful witness ONLY for security properties that live BELOW the handler
    /// boundary (e.g. cap-channel's owner / method / CRLF checks in
    /// `OutboundDispatcher::dispatch`, or reply-tracker's `on_reply`
    /// source/slot match — these run inside the handler and CANNOT be faked here).
    /// It is NOT a faithful witness for **grant-gate authorization** or
    /// **caller-identity attribution** (anything gated only on the injector's
    /// `GrantCheck` or on `HostCallContext.agent_id`): a journey could pass a forged
    /// `caller_agent_id` (see [`Self::call_host_fn_as_agent`]) and record a PASS the
    /// real linker/injector would reject. Witness those via the real guest-driven
    /// turn, never through this primitive.
    pub async fn call_host_fn(
        &self,
        cap: &str,
        namespace: &str,
        name: &str,
        params: Vec<Val>,
    ) -> Result<Vec<Val>, HostCallError> {
        let agent = self.agent_id.clone();
        self.call_host_fn_as_agent(&agent, cap, namespace, name, params)
            .await
    }

    /// As [`Self::call_host_fn`] but with an EXPLICIT caller agent id. The right
    /// value is handler-dependent: cap-channel `send-raw` needs the subscription
    /// OWNER id (`agent:harness`), but reply-tracker `await-replies` needs a BARE
    /// caller (`start_with_run` prepends `agent:`).
    ///
    /// **The forged `caller_agent_id` does NOT pass the production grant gate or
    /// the host-authoritative identity stamping** — see the witness-fidelity caveat
    /// on [`Self::call_host_fn`]. Drive a handler's downstream logic with it, but do
    /// NOT use it to assert that the runtime *authorized* or *attributed* the call to
    /// this id (e.g. do not drive the versioned `await-replies` host fn as a victim
    /// agent and then assert the session was attributed to that victim — the real
    /// linker/injector would never allow that identity).
    pub async fn call_host_fn_as_agent(
        &self,
        caller_agent_id: &str,
        cap: &str,
        namespace: &str,
        name: &str,
        params: Vec<Val>,
    ) -> Result<Vec<Val>, HostCallError> {
        let spec = self
            .registry
            .lookup(cap)
            .into_iter()
            .find(|s| s.namespace == namespace && s.name == name)
            .ok_or_else(|| {
                HostCallError::HandlerError(format!(
                    "no host fn registered for {cap} / {namespace}::{name}"
                ))
            })?;
        let ctx = HostCallContext {
            agent_id: caller_agent_id.to_string(),
            trace_id: "trace-harness".to_string(),
            turn_id: None,
            capability: cap.to_string(),
            function: format!("{namespace}::{name}"),
            run_id: None,
            iteration: None,
        };
        spec.handler.call(ctx, params, 0).await
    }

    /// Wave-12: like [`Self::call_host_fn_as_agent`] but with an EXPLICIT
    /// `results_len` (the WIT result arity the handler validates). Needed to drive
    /// the cap-lifecycle spawn host-fns (`SpawnHandler` guards `results_len == 1`)
    /// AND the cap-tools `tool-invoke` handler with a BARE caller id (cap-lifecycle
    /// `cap_str` rejects a colon, so the SUT's colon `AGENT_ID` cannot be the
    /// spawn caller). Same witness-fidelity caveat as the other `call_host_fn`
    /// accessors: it bypasses the grant gate + identity stamping, so use it only
    /// for properties BELOW the handler boundary (the spawn-store mutation + the
    /// guard's record/inject both qualify — they run inside the handler).
    pub async fn call_host_fn_as_agent_n(
        &self,
        caller_agent_id: &str,
        cap: &str,
        namespace: &str,
        name: &str,
        params: Vec<Val>,
        results_len: usize,
    ) -> Result<Vec<Val>, HostCallError> {
        let spec = self
            .registry
            .lookup(cap)
            .into_iter()
            .find(|s| s.namespace == namespace && s.name == name)
            .ok_or_else(|| {
                HostCallError::HandlerError(format!(
                    "no host fn registered for {cap} / {namespace}::{name}"
                ))
            })?;
        let ctx = HostCallContext {
            agent_id: caller_agent_id.to_string(),
            trace_id: "trace-harness".to_string(),
            turn_id: None,
            capability: cap.to_string(),
            function: format!("{namespace}::{name}"),
            run_id: None,
            iteration: None,
        };
        spec.handler.call(ctx, params, results_len).await
    }

    /// Backbone Step 3: like [`Self::call_host_fn`] but with an EXPLICIT
    /// `results_len` (the WIT result arity the handler validates). The `call_host_fn`
    /// / `_as_agent` convenience pass `0`, which the cap-memory handlers REJECT —
    /// they return `result<.., memory-error>` and guard `results_len == 1`. Use this
    /// (with `results_len = 1`) to drive a memory host fn at the handler boundary and
    /// inspect the returned `Val::Result` (e.g. witness `memory-error::limit-exceeded`
    /// at the WIT boundary over the REAL persistent store). Caller = this SUT's agent.
    /// Same witness-fidelity caveat as [`Self::call_host_fn`]: it bypasses the grant
    /// gate + identity stamping, so use it only for properties BELOW the handler
    /// boundary (the store-cap check here qualifies).
    pub async fn call_host_fn_n(
        &self,
        cap: &str,
        namespace: &str,
        name: &str,
        params: Vec<Val>,
        results_len: usize,
    ) -> Result<Vec<Val>, HostCallError> {
        let spec = self
            .registry
            .lookup(cap)
            .into_iter()
            .find(|s| s.namespace == namespace && s.name == name)
            .ok_or_else(|| {
                HostCallError::HandlerError(format!(
                    "no host fn registered for {cap} / {namespace}::{name}"
                ))
            })?;
        let ctx = HostCallContext {
            agent_id: self.agent_id.clone(),
            trace_id: "trace-harness".to_string(),
            turn_id: None,
            capability: cap.to_string(),
            function: format!("{namespace}::{name}"),
            run_id: None,
            iteration: None,
        };
        spec.handler.call(ctx, params, results_len).await
    }

    /// Small-witness 2026-06-11 — like [`Self::call_host_fn_n`] but with an EXPLICIT
    /// `run_id` on the `HostCallContext` (the SAME field production fills via
    /// `ComponentCtx::to_host_call_context`). The cap-llm budget preflight is
    /// run_id-gated, so this is the drive surface for run-scoped witnesses (e.g.
    /// SYS-AC-189's "RunBudget checked once before the stream starts"). Caller =
    /// this SUT's agent. Same witness-fidelity caveat as [`Self::call_host_fn`]:
    /// bypasses the grant gate + identity stamping — use only for properties BELOW
    /// the handler boundary (the gateway-internal preflight/stream lifecycle here
    /// qualifies); never for authz/identity claims.
    pub async fn call_host_fn_for_run(
        &self,
        run_id: &str,
        cap: &str,
        namespace: &str,
        name: &str,
        params: Vec<Val>,
        results_len: usize,
    ) -> Result<Vec<Val>, HostCallError> {
        let spec = self
            .registry
            .lookup(cap)
            .into_iter()
            .find(|s| s.namespace == namespace && s.name == name)
            .ok_or_else(|| {
                HostCallError::HandlerError(format!(
                    "no host fn registered for {cap} / {namespace}::{name}"
                ))
            })?;
        let ctx = HostCallContext {
            agent_id: self.agent_id.clone(),
            trace_id: "trace-harness".to_string(),
            turn_id: None,
            capability: cap.to_string(),
            function: format!("{namespace}::{name}"),
            run_id: Some(run_id.to_string()),
            iteration: None,
        };
        spec.handler.call(ctx, params, results_len).await
    }

    // --- HF fast-follow: multi-agent (.agents()) ---

    /// Snapshot the bare-id spawn-witness `AgentTreeStore` (empty when `.agents()`
    /// was not set). Assert nodes / parentage after a spawn here.
    pub fn tree_snapshot(&self) -> AgentTreeSnapshotData {
        match &self.agents {
            Some(a) => a.tree_store.snapshot(),
            None => AgentTreeSnapshotData {
                nodes: Vec::new(),
                parent_of: HashMap::new(),
                children_of: HashMap::new(),
                peer_slug_map: HashMap::new(),
                revision: 0,
            },
        }
    }

    /// The real `DefaultSpawner` over the bare-id store (`.agents()` only) — drive
    /// `spawn_child` / `spawn_sub` to witness a real tree mutation.
    pub fn spawner(&self) -> Option<Arc<DefaultSpawner>> {
        self.agents.as_ref().map(|a| a.spawner.clone())
    }

    /// The real `AwaitSessionManagerImpl` (`.agents()` only) — drive `start` (it
    /// blocks on a oneshot; spawn it in a task) and resolve via [`Self::resolve_await`].
    pub fn await_manager(&self) -> Option<Arc<AwaitSessionManagerImpl>> {
        self.agents.as_ref().map(|a| a.await_mgr.clone())
    }

    /// Inject a reply that resolves an open await session (the guest→host reply
    /// entry-point is upstream-missing; this is the test-side stand-in). Retries
    /// on `NotFound` so a just-spawned `start` has time to admit the session.
    pub async fn resolve_await(
        &self,
        session: &SessionId,
        slot: u32,
        reply: ReplyResult,
    ) -> Result<(), OrchestrationError> {
        let mgr = self
            .agents
            .as_ref()
            .expect(".agents() required for resolve_await")
            .await_mgr
            .clone();
        // Short real-time sleeps (not yield_now): on a multi-thread runtime
        // yield_now reschedules THIS task without guaranteeing the spawned
        // `start` task (which admits the session) has run on a sibling worker.
        // ~500 × 2ms = 1s cap; the session normally admits within a few ms.
        for _ in 0..500 {
            match mgr.on_reply(session, slot, reply.clone()).await {
                Err(OrchestrationError::NotFound(_)) => {
                    tokio::time::sleep(std::time::Duration::from_millis(2)).await
                }
                other => return other,
            }
        }
        mgr.on_reply(session, slot, reply).await
    }

    // --- HF fast-follow: cap-channel (.with_channel_capture()) ---

    /// The pre-created subscription id (`.with_channel_capture()` only).
    pub fn channel_subscription_id(&self) -> Option<SubscriptionId> {
        self.channel.as_ref().map(|c| c.sub_id.clone())
    }

    /// Enqueue an inbound channel event onto the subscription (the real
    /// `SubscriptionManager` inbound path). Poll it back via [`Self::poll_channel_inbound`].
    pub fn inject_channel_inbound(
        &self,
        payload: &[u8],
        metadata: Vec<CapParam>,
    ) -> Result<(), ChannelError> {
        let c = self
            .channel
            .as_ref()
            .expect(".with_channel_capture() required");
        c.manager.enqueue_event(
            &c.sub_id,
            RawEvent {
                data: payload.to_vec(),
                metadata,
            },
        )
    }

    /// Poll the next inbound channel event (real `SubscriptionManager::poll_raw`).
    pub fn poll_channel_inbound(&self) -> Result<Option<RawEvent>, ChannelError> {
        let c = self
            .channel
            .as_ref()
            .expect(".with_channel_capture() required");
        c.manager.poll_raw(&self.agent_id, &c.sub_id)
    }

    /// Drive an outbound `send-raw` through the registered `SendRawHandler` →
    /// `OutboundDispatcher` → the capturing chain; assert via [`Self::captured_outbound`].
    pub async fn drive_channel_send_raw(&self, payload: &[u8]) -> Result<(), HostCallError> {
        let sub_id = self
            .channel
            .as_ref()
            .expect(".with_channel_capture() required")
            .sub_id
            .0
            .clone();
        let params = vec![
            Val::String(sub_id),
            Val::List(payload.iter().map(|b| Val::U8(*b)).collect()),
        ];
        let agent = self.agent_id.clone();
        // Use the exported namespace constant so this tracks N1's `@0.1.0`
        // versioning automatically (was a hardcoded unversioned literal).
        self.call_host_fn_as_agent(
            &agent,
            "channel",
            cap_channel::CHANNEL_HOST_NAMESPACE,
            "send-raw",
            params,
        )
        .await
        .map(|_| ())
    }

    /// All captured outbound `send-raw` requests (`.with_channel_capture()` only).
    pub fn captured_outbound(&self) -> Vec<CapturedOutbound> {
        self.channel
            .as_ref()
            .map(|c| c.captured.lock().unwrap().clone())
            .unwrap_or_default()
    }

    // --- HF fast-follow: cap-mcp (.with_mcp_transports()) ---

    /// The in-process MCP client (`.with_mcp_transports()` only).
    pub fn mcp_client(&self) -> Option<Arc<McpClient>> {
        self.mcp_client.clone()
    }

    /// Invoke an MCP tool through the real `McpClient` (whitelist → tool-pattern →
    /// input-schema → transport → output-schema) over the scripted transport.
    pub async fn drive_mcp_tool(
        &self,
        server_id: &str,
        tool: &str,
        params: &[u8],
    ) -> Result<Vec<u8>, cap_mcp::McpError> {
        self.mcp_client
            .as_ref()
            .expect(".with_mcp_transports() required")
            .invoke_tool(server_id, tool, params)
            .await
    }

    // --- HF fast-follow: runnable driver (Tracks F/G) ---

    /// Drive a runnable component's `run(config)` in-process (the same shape
    /// `run_agent` uses for message-turns). Witnessed against a test `RunnableHook`;
    /// the production WASM runnable path is the upstream `P-runnable` follow-up.
    pub async fn drive_runnable(
        &self,
        hook: Arc<dyn RunnableHook>,
        id: &str,
        config_data: Option<Vec<u8>>,
        trigger: Option<TriggerContext>,
    ) -> Result<RunResult, HookError> {
        hook.run_once(ComponentConfig {
            id: id.to_string(),
            config_data,
            trigger_context: trigger,
        })
        .await
    }

    // --- Harvest-triggers slice (SYS-AC 098-114): scheduler trigger-chain drive surface ---

    fn triggers(&self) -> &TriggerHandles {
        self.triggers
            .as_ref()
            .expect(".with_triggers() required for the trigger-chain drive surface")
    }

    /// The real `TriggerBusDispatchImpl` (`.with_triggers()` only). Import
    /// `advance_scheduler::TriggerBusDispatch` for the `subscribe`/`dispatch`/`unsubscribe`
    /// trait methods; `drain_for_subscription` / `cycle_rejected_log` / `rejection_counts` /
    /// `pending_total` / `visited_set_total` are inherent. Witnesses SYS-AC-101/102/103/104.
    pub fn trigger_bus(&self) -> &Arc<TriggerBusDispatchImpl> {
        &self.triggers().trigger_bus
    }

    /// The real registry-backed `InMemoryComponentSubmitApi` (quota 20). Import the
    /// `advance_scheduler::ComponentSubmitApi` trait for `submit_component`/`list_components`;
    /// `list_components_persisted` (durable registry view) is inherent. Witnesses
    /// SYS-AC-108/109/111.
    pub fn submit_api(&self) -> &InMemoryComponentSubmitApi {
        &self.triggers().submit_api
    }

    /// Small-witness 2026-06-11 (SYS-AC-047) — the REAL production submit-admission
    /// composition: `cap_lifecycle::SubsetCheckedComponentSubmit` (capability-subset
    /// gate → `admit_runnable_binary` → inner submit) whose subset gate is the REAL
    /// `CapGrantSubsetAdapter` and whose inner gate bridges to THIS SUT's
    /// registry-backed scheduler `InMemoryComponentSubmitApi` (the same instance
    /// `submit_api()` / `list_components_persisted()` observe). `.with_triggers()`
    /// required. Drive `submit_component_with_subset(submitter, config, parent_caps,
    /// requested_caps)`: a super-parent request → `Err(SpawnError::SubsetViolation)`
    /// BEFORE the inner api is touched; a true subset → admitted into the real
    /// registry-backed api.
    pub fn submit_admission(&self) -> SubsetCheckedComponentSubmit {
        SubsetCheckedComponentSubmit::new(
            Arc::new(SchedulerSubmitBridge {
                api: self.triggers().submit_api.clone(),
            }),
            Arc::new(CapGrantSubsetAdapter::new()),
        )
    }

    /// The real durable SQLite `ComponentRegistry` behind the submit API — also the
    /// catch-up substrate (seed overdue rows via `insert` + `set_expected_next_fire`,
    /// then `TaskRunner::run_expired_catchup`). Witnesses SYS-AC-112/113/114.
    pub fn submit_registry(&self) -> &Arc<ComponentRegistry> {
        &self.triggers().submit_registry
    }

    /// The SUT's shared event sink as an `EventBusEmit` — the SAME `Arc<CapturingBus>`
    /// instance `events()` reads (so cron `trigger.fired` is observable). `.with_triggers()`
    /// only; requires the default `EventSink::Capturing`.
    pub fn event_emitter(&self) -> Arc<dyn EventBusEmit> {
        self.triggers().emitter.clone()
    }

    /// Real `compute_jitter(id, schedule, period_ms, 0.1)` — the EXACT fn the `CronDriver`
    /// calls for its anti-thundering-herd initial offset (cron.rs). Witnesses SYS-AC-100
    /// (two ids on the same schedule → deterministically different bounded offsets).
    pub fn cron_jitter(&self, id: &str, schedule: &str, period_ms: u64) -> std::time::Duration {
        compute_jitter(id, schedule, period_ms, 0.1)
    }

    /// Drive ONE real cron fire: spawn the production `CronDriver::run_periodic_with_emitter`
    /// over the SUT's shared event sink + a real counting `RunnableHook`, wait (bounded) for
    /// the first `trigger.fired` to land in `events()`, then cancel. Returns the observed
    /// `trigger.fired` count. Witnesses SYS-AC-099 (a cron fire emits `trigger.fired` with
    /// `trigger_type=="cron"`). Requires `.with_triggers()` + the default `Capturing` sink.
    ///
    /// The returned quantity is the captured `trigger.fired` count — NOT the hook-invocation
    /// counter. `run_periodic_with_emitter` emits BEFORE the hook (cron.rs) inside a
    /// `select!` that races the hook against the cancel token, so the hook counter has a
    /// (rare) emit-observed-but-hook-cancelled window; the emitted event is exactly the
    /// SYS-AC-099 witness quantity and is race-free (it is what the poll-loop waited for).
    pub async fn drive_cron_fire(&self, id: &str, interval: std::time::Duration) -> usize {
        use std::sync::atomic::AtomicUsize;
        let emitter = self.event_emitter();
        // The hook is a REAL runnable the cron driver actually invokes; its count is not the
        // returned witness (see method doc), only the trigger.fired event count is.
        let counter = Arc::new(AtomicUsize::new(0));
        let hook: Arc<dyn RunnableHook> = Arc::new(CronCountingHook(counter));
        let cancel = CancellationToken::new();
        let cancel_clone = cancel.clone();
        let id_owned = id.to_string();
        let cfg = ComponentConfig {
            id: id.to_string(),
            config_data: None,
            trigger_context: None,
        };
        let handle = tokio::spawn(async move {
            CronDriver::run_periodic_with_emitter(
                &id_owned,
                interval,
                hook,
                cfg,
                None,          // output_dir
                Some(emitter), // shared CapturingBus → trigger.fired observable via events()
                cancel_clone,
            )
            .await
        });
        // Bounded wait (~2s) for the first fire to be captured; the jitter is ≤ interval×0.1.
        for _ in 0..400 {
            if self
                .events()
                .iter()
                .any(|e| e.event_type == "trigger.fired")
            {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        cancel.cancel();
        let _ = handle.await;
        self.events()
            .iter()
            .filter(|e| e.event_type == "trigger.fired")
            .count()
    }

    /// Rollback-memory slice: the RETAINED `L6CursorStore` — the SAME `Arc`
    /// the registered `rollback-memory` handler resets (`None` unless
    /// `Cap::Memory`). `cursor_file_path(agent_id)` on it gives the on-disk
    /// `_knowledge_cursor.yaml` location for file-level witnesses.
    pub fn cursor_store(&self) -> Option<&Arc<L6CursorStore>> {
        self.cursor_store.as_ref()
    }

    /// Sched-harvest 1B: mint a PRODUCTION [`WasmRunnableHook`] over THIS
    /// SUT's guest — the real `runnable.run(config)` bridge (the P-runnable
    /// edge): per-run fresh instantiation of the SAME loaded component /
    /// runtime / `CapabilityInjector` / cap set the message-driven path uses,
    /// with `component_id` stamped as the `ComponentCtx` attribution id.
    /// Witnesses SYS-AC-098/101/109 drive scheduler loops with this hook so
    /// `run(config)` genuinely executes in the real guest.
    pub fn wasm_runnable_hook(&self, component_id: &str) -> Arc<dyn RunnableHook> {
        let (runtime, loaded, injector, caps) = &self.runnable_parts;
        Arc::new(WasmRunnableHook::new(
            runtime.clone(),
            loaded.clone(),
            injector.clone(),
            caps.clone(),
            component_id.to_string(),
            "trace-harness".to_string(),
        ))
    }

    /// SYS-AC-109 run-leg: the `(runtime, injector)` pair needed to construct a
    /// production `cli::WasmRunnableHookFactory` so the readiness-gated registry
    /// walk materializes drivers FROM THE ADMITTED ROW'S BYTES (the factory loads
    /// `row.binary` itself) — the SAME real runtime + `CapabilityInjector` the
    /// message-driven path and [`Self::wasm_runnable_hook`] use. Additive
    /// accessor: existing builds are byte-identical (no field/behaviour change).
    pub fn runnable_factory_parts(&self) -> (Arc<ComponentRuntime>, Arc<CapabilityInjector>) {
        (self.runnable_parts.0.clone(), self.runnable_parts.2.clone())
    }

    /// Sched-harvest 1B (SYS-AC-098/109): drive a REAL `CronDriver` tick loop
    /// with the supplied hook (typically [`Self::wasm_runnable_hook`]) and the
    /// SUT event sink, waiting until at least one `component.finished` for
    /// `id` is captured BEFORE cancelling the driver — the §3 sequencing
    /// contract (an orphan `component.started` is the normal cancel-mid-hook
    /// outcome; ordering is by sink emit order, never `Event.timestamp`).
    /// The cron config carries `trigger_context: None` (the SYS-AC-098
    /// criterion's cron shape). Returns the captured `component.finished`
    /// count for `id`. Requires the default `Capturing` sink.
    pub async fn drive_cron_run(
        &self,
        id: &str,
        interval: std::time::Duration,
        hook: Arc<dyn RunnableHook>,
        output_dir: Option<std::path::PathBuf>,
    ) -> usize {
        let emitter = self.event_emitter();
        let cancel = CancellationToken::new();
        let cancel_clone = cancel.clone();
        let id_owned = id.to_string();
        let cfg = ComponentConfig {
            id: id.to_string(),
            config_data: None,
            trigger_context: None,
        };
        let handle = tokio::spawn(async move {
            CronDriver::run_periodic_with_emitter(
                &id_owned,
                interval,
                hook,
                cfg,
                // Adversarial-round F12 (2026-06-13): output_dir is now
                // caller-supplied so the SYS-AC-098 witness can OBSERVE the
                // guest's None-context echo (no result.bin ⇒ the guest
                // genuinely received trigger_context == None) instead of
                // merely constructing the None input.
                output_dir,
                Some(emitter), // shared CapturingBus → component.* observable via events()
                cancel_clone,
            )
            .await
        });
        // Bounded wait (~10s budget — a real WASM instantiate+run per tick) for the
        // first component.finished of THIS id to be captured, then cancel.
        let finished_for_id = |e: &Event| {
            e.event_type == COMPONENT_FINISHED_EVENT_TYPE
                && e.payload.get("id").and_then(|v| v.as_str()) == Some(id)
        };
        for _ in 0..2000 {
            if self.events().iter().any(|e| finished_for_id(e)) {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        cancel.cancel();
        let _ = handle.await;
        self.events().iter().filter(|e| finished_for_id(e)).count()
    }

    // ── Lifecycle-harvest accessors (SYS-AC 152-154/237 + 259-261) ────────

    /// The real `RuntimeConfigWatcher` started by `.with_runtime_config_watch()`.
    /// Panics if the axis was not enabled (mirrors `triggers()` discipline).
    pub fn runtime_config_watcher(&self) -> &Arc<RuntimeConfigWatcher> {
        &self
            .runtime_config
            .as_ref()
            .expect("runtime_config_watcher(): build with .with_runtime_config_watch()")
            .watcher
    }

    /// The seeded `<ws>/.advance/runtime-config.yaml` path the watcher watches.
    pub fn runtime_config_path(&self) -> &Path {
        &self
            .runtime_config
            .as_ref()
            .expect("runtime_config_path(): build with .with_runtime_config_watch()")
            .path
    }

    /// The real `MetaSchemaWatcher` started by `.with_meta_schema_watch()`
    /// (accessors: `loader()` / `last_error()` / `is_alive()`).
    pub fn schema_watcher(&self) -> &MetaSchemaWatcher {
        &self
            .schema_watch
            .as_ref()
            .expect("schema_watcher(): build with .with_meta_schema_watch()")
            .watcher
    }

    /// The SAME `Arc<MetaSchemaLoader>` registered into `register_agent_fs`
    /// (its `current()` reflects every applied reload).
    pub fn schema_loader(&self) -> Arc<MetaSchemaLoader> {
        Arc::clone(
            &self
                .schema_watch
                .as_ref()
                .expect("schema_loader(): build with .with_meta_schema_watch()")
                .loader,
        )
    }

    /// The seeded `<ws>/.advance/meta-schema.yaml` path the watcher watches.
    pub fn meta_schema_path(&self) -> &Path {
        &self
            .schema_watch
            .as_ref()
            .expect("meta_schema_path(): build with .with_meta_schema_watch()")
            .path
    }
}
