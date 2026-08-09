//! SYS-J-08 — "spawning an agent from a template materializes its behavior.wasm,
//! AGENTS.md, skills, and memory seeds into a new agent workspace ready to run."
//! Chain: MODULE-005 → MODULE-018 → MODULE-002 → MODULE-003.
//!
//! Witness surface (Stage-A harvest): driven through a LOCAL
//! `DefaultSpawner::with_template_resolver` over a real `AgentTreeStore` (the
//! cap-lifecycle `tests/templates.rs::setup_with_resolver` precedent) — the REAL
//! MODULE-005 product spawner running REAL `apply_template`. The resolver is
//! test-supplied template INPUT (a fixture), NOT a module mock; the WIT
//! `spawn-agent-from-template` arm dispatches into the SAME `spawn_child`/`spawn_sub`
//! product path (wit_impl.rs), so this Rust surface is below it, not different
//! behavior. Every load-bearing assertion binds to PRODUCT output: the bytes/files
//! `apply_template` wrote on disk at the path the product spawner set
//! (`tree.get_node(child).workspace_path`), and the real `SpawnError` the product
//! returns. The 4 built-in `BuiltinTemplateRegistry` templates carry
//! `behavior_wasm: None` + empty skills, which would make 022's clauses vacuous —
//! so a CUSTOM resolver supplying behavior_wasm + a skill + a memory seed is used.
//!
//! SYS-AC-024 is now WITNESSED end-to-end (Wave-14 Lane D): a runnable template child is
//! materialized via the REAL spawner, then the PRODUCTION load+encode+run path drives the
//! as-materialized `.agent/behavior.wasm` to handle a message and reply — see
//! `sys_ac_024_materialized_agent_registered_and_runnable` below. The prior deferral reason
//! ("runners load `.agent/behavior.component.wasm`") is stale: production's
//! `resolve_driver_component_bytes` now falls back to `.agent/behavior.wasm` + encodes on the fly.
//!
//! SYS-AC-199 (the <500 ms perf-SLO) is `passed` via the dedicated perf-CI lane
//! (`tests/perf_slo.rs`, 2026-06-19) — NOT this file; the `#[ignore]`d stub below is a stale
//! pointer retained only so its absence is not mistaken for missing coverage.

use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use advance_shared_types::agent_tree::{AgentId, AgentKind, AgentNode, AgentStatus, Capability};
use cap_lifecycle::{
    apply_template, AgentTreeStore, DefaultSpawner, SpawnChildConfig, SpawnError, SpawnSubConfig,
    Spawner, SpawnerSubsetGate, TemplateContent, TemplateError, TemplateResolver,
    TemplateSkillEntry,
};
use tempfile::TempDir;

// --- SYS-AC-024 run-leg: production agent-loop run path (mirrors the passed
// sys_j64_state_roundtrip.rs recipe — REAL encode/load/build_agent_loop/run_agent) ---
use advance_runtime::capability_injector::CapabilityInjector;
use advance_runtime::circuit_breaker::DefaultCircuitBreakerBus;
use advance_runtime::config::WasmConfig;
use advance_runtime::host_registry::{HostRegistry, InMemoryHostRegistry};
use advance_runtime::ComponentRuntime;

use advance_shared_types::capability::{CapParams, GrantDecision};
use advance_shared_types::event::Event;
use advance_shared_types::mailbox::{AgentAction, DispatchError, Message, MessageKind};
use advance_shared_types::outbound::DeliveryReport;
use advance_shared_types::traits::{EventBusEmit, GrantCheck};

use advance_cli::agent_loop::{build_agent_loop, WasmMessageHandler};

use advance_messaging::{MailboxStore, OutboundActionSink};
use advance_scheduler::hook::MessageHandler;
use advance_scheduler::types::{ComponentConfig, ComponentId, WasmInstance};
use advance_scheduler::AgentLoopDriver;

// Template payload that makes 022/023's clauses NON-vacuous (a fake 8-byte WASM
// header is plenty for the materialization assertion — we assert bytes-on-disk, not
// execution). The manifest omits `kind:` so `check_manifest_kind` is a no-op pass for
// BOTH Child and Sub spawns (so 023's Sub seed-skip negative is reached at the gate,
// not aborted early — Claude plan-eval W-b).
const WASM_HEADER: &[u8] = b"\0asm\x01\0\0\0";
// SYS-AC-024 run-leg: a REAL wit-bindgen guest CORE module (version byte 0x01) that, on
// handle-message, replies with the incremented host-passed counter ("1" on the first turn).
// It imports NOTHING (no LLM/caps/grant), so the captured reply is an anti-fake-green oracle:
// it can ONLY come from the materialized bytes actually instantiating + running a real turn.
// Used instead of the 8-byte WASM_HEADER stub above (an empty module that exports no
// message-driven interface, so it cannot produce an observable reply).
const COUNTER_CORE: &[u8] =
    include_bytes!("../../runtime/tests/fixtures/guest-rust-counter.core.wasm");
const SKILL_BYTES: &[u8] = b"# greet skill\n";
const SEED: &str = "{\"insight\":\"seed-knowledge\"}\n";
const AGENTS_MD: &str = "# Self-Improvement Guidelines\n(materialized by template)\n";

fn template_content(manifest_yaml: &str) -> TemplateContent {
    TemplateContent {
        name: "tmpl".to_string(),
        manifest_yaml: manifest_yaml.to_string(),
        agents_md: AGENTS_MD.to_string(),
        skills: vec![TemplateSkillEntry {
            relative_path: PathBuf::from("greet.md"),
            content: SKILL_BYTES.to_vec(),
        }],
        memory_seed_jsonl: Some(SEED.to_string()),
        behavior_wasm: Some(WASM_HEADER.to_vec()),
    }
}

/// Materializing resolver: behavior + skill + seed, manifest WITHOUT `kind:`.
struct MaterializingResolver;
impl TemplateResolver for MaterializingResolver {
    fn resolve(&self, _template_ref: &str) -> Result<TemplateContent, TemplateError> {
        Ok(template_content("name: tmpl\n"))
    }
    fn list(&self) -> Vec<String> {
        vec!["tmpl".to_string()]
    }
}

/// Resolver whose manifest declares `kind: sub` (disagrees with a Child spawn) → 198.
struct KindMismatchResolver;
impl TemplateResolver for KindMismatchResolver {
    fn resolve(&self, _template_ref: &str) -> Result<TemplateContent, TemplateError> {
        Ok(template_content("kind: sub\n"))
    }
    fn list(&self) -> Vec<String> {
        vec!["tmpl".to_string()]
    }
}

/// Resolver that resolves to NO template (unknown ref) → 197.
struct MissingResolver;
impl TemplateResolver for MissingResolver {
    fn resolve(&self, template_ref: &str) -> Result<TemplateContent, TemplateError> {
        Err(TemplateError::NotFound(template_ref.to_string()))
    }
    fn list(&self) -> Vec<String> {
        Vec::new()
    }
}

struct AlwaysOkGate;
impl SpawnerSubsetGate for AlwaysOkGate {
    fn check(&self, _p: &[Capability], _c: &[Capability]) -> Result<(), SpawnError> {
        Ok(())
    }
}

/// SYS-AC-024 resolver: `behavior_wasm` = the REAL `guest-rust-counter.core.wasm` (a runnable
/// wit-bindgen guest), so the materialized child's `.agent/behavior.wasm` is a loadable+runnable
/// core module — NOT the 8-byte `WASM_HEADER` stub (which exports no message-driven interface).
/// No skills / no memory seed: the run-leg only needs a runnable behavior; 022/023 already
/// witness the skill/seed materialization.
struct RunnableResolver;
impl TemplateResolver for RunnableResolver {
    fn resolve(&self, _template_ref: &str) -> Result<TemplateContent, TemplateError> {
        Ok(TemplateContent {
            name: "tmpl".to_string(),
            manifest_yaml: "name: tmpl\n".to_string(),
            agents_md: AGENTS_MD.to_string(),
            skills: Vec::new(),
            memory_seed_jsonl: None,
            behavior_wasm: Some(COUNTER_CORE.to_vec()),
        })
    }
    fn list(&self) -> Vec<String> {
        vec!["tmpl".to_string()]
    }
}

// ── SYS-AC-024 run-leg helpers (mirror the passed sys_j64_state_roundtrip.rs) ──

struct NullBus;
impl EventBusEmit for NullBus {
    fn emit(&self, _event: Event) {}
}

/// Always-allow grant gate — the counter guest requests NO capabilities, so this is never
/// consulted; present only to construct the production `CapabilityInjector`.
struct AllowAllGrant;
impl GrantCheck for AllowAllGrant {
    fn check(&self, _a: &str, _c: &str, _f: &str, _p: &CapParams) -> GrantDecision {
        GrantDecision::Allow
    }
}

/// Captures each turn's first-action reply payload through the PRODUCTION outbound seam.
struct RecordingSink {
    replies: Arc<Mutex<Vec<Vec<u8>>>>,
}
#[async_trait::async_trait]
impl OutboundActionSink for RecordingSink {
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

fn run_runtime() -> Arc<ComponentRuntime> {
    Arc::new(
        ComponentRuntime::new(&WasmConfig {
            max_memory_pages: 256,
            epoch_interruption_ms: 100,
            fuel_enabled: false,
        })
        .expect("runtime"),
    )
}

fn run_injector() -> Arc<CapabilityInjector> {
    let registry: Arc<dyn HostRegistry> = Arc::new(InMemoryHostRegistry::new());
    Arc::new(CapabilityInjector::new(
        registry,
        Arc::new(AllowAllGrant),
        Arc::new(DefaultCircuitBreakerBus::new()),
    ))
}

fn user_msg(id: &str, agent: &str) -> Message {
    Message {
        id: id.into(),
        kind: MessageKind::User,
        from: "user:test".into(),
        to: agent.into(),
        payload: b"tick".to_vec(),
        context: None,
        timestamp: SystemTime::now(),
        origin: None,
    }
}

/// Mirror cap-lifecycle `tests/templates.rs::setup_with_resolver`, also returning the
/// root workspace dir so rollback/atomicity assertions can target the would-be child.
fn setup(
    resolver: Arc<dyn TemplateResolver>,
) -> (TempDir, AgentTreeStore, DefaultSpawner, PathBuf) {
    let tmp = TempDir::new().unwrap();
    let workspace_root = tmp.path().canonicalize().expect("canonicalize");
    let tree = AgentTreeStore::new(workspace_root.clone()).unwrap();
    let root_ws = workspace_root.join("root_ws");
    std::fs::create_dir_all(&root_ws).unwrap();
    tree.insert_root(AgentNode {
        id: AgentId("root".to_string()),
        kind: AgentKind::Root,
        parent: None,
        workspace_path: root_ws.clone(),
        capabilities: Vec::new(),
        template_ref: None,
        status: AgentStatus::Active,
    })
    .unwrap();
    let spawner =
        DefaultSpawner::with_template_resolver(tree.clone(), Arc::new(AlwaysOkGate), resolver);
    (tmp, tree, spawner, root_ws)
}

fn agent_dir(ws: &Path) -> PathBuf {
    ws.join(".agent")
}

/// SYS-AC-022 — spawn-agent-from-template materializes behavior.wasm, AGENTS.md, and
/// the template's skills into the new agent workspace.
#[test]
fn sys_ac_022_template_materializes_behavior_agents_md_and_skills() {
    let (_tmp, tree, spawner, _root_ws) = setup(Arc::new(MaterializingResolver));
    let child = spawner
        .spawn_child(SpawnChildConfig {
            parent_id: AgentId("root".to_string()),
            child_id: AgentId("mat022".to_string()),
            child_workspace_path: PathBuf::from("agents/mat022"),
            capabilities: Vec::new(),
            template_ref: Some("tmpl".to_string()),
            binary: None,
        })
        .expect("spawn_child from template");

    let node = tree.get_node(&child).expect("child node registered");
    let ad = agent_dir(&node.workspace_path);

    // behavior.wasm bytes == template bytes (PRODUCT wrote these).
    assert_eq!(
        std::fs::read(ad.join("behavior.wasm")).expect("behavior.wasm materialized"),
        WASM_HEADER,
        "behavior.wasm content matches the template"
    );
    // AGENTS.md present (the agents_md field, materialized to .agent/AGENTS.md).
    let agents_md = std::fs::read_to_string(ad.join("AGENTS.md")).expect("AGENTS.md materialized");
    assert!(
        agents_md.contains("Self-Improvement Guidelines"),
        "AGENTS.md carries the template's guidelines"
    );
    // The template's skill landed under .agent/skills/<rel>.
    assert_eq!(
        std::fs::read(ad.join("skills").join("greet.md")).expect("skill materialized"),
        SKILL_BYTES,
        "skill content matches the template"
    );
}

/// SYS-AC-023 — for kind in {child, root} the template's memory-seed is written; for
/// kind=sub it is never written. (behavior.wasm is written for ALL kinds incl Sub, so
/// the Sub leg asserts behavior present + memory ABSENT — a non-vacuous negative.)
#[test]
fn sys_ac_023_memory_seed_written_for_child_root_not_sub() {
    // --- Child: seed written ---
    let (_tmp, tree, spawner, _root_ws) = setup(Arc::new(MaterializingResolver));
    let child = spawner
        .spawn_child(SpawnChildConfig {
            parent_id: AgentId("root".to_string()),
            child_id: AgentId("seed023".to_string()),
            child_workspace_path: PathBuf::from("agents/seed023"),
            capabilities: Vec::new(),
            template_ref: Some("tmpl".to_string()),
            binary: None,
        })
        .expect("spawn child from template");
    let child_ad = agent_dir(&tree.get_node(&child).expect("child node").workspace_path);
    assert_eq!(
        std::fs::read_to_string(child_ad.join("memory").join("knowledge.jsonl"))
            .expect("child memory seed written"),
        SEED,
        "Child kind writes the template memory seed"
    );

    // --- Sub: seed NOT written (load-bearing negative), but behavior IS (non-vacuity) ---
    let sub = spawner
        .spawn_sub(SpawnSubConfig {
            parent_id: AgentId("root".to_string()),
            capabilities: Vec::new(),
            template_ref: Some("tmpl".to_string()),
        })
        .expect("spawn sub from template");
    let sub_ad = agent_dir(&tree.get_node(&sub).expect("sub node").workspace_path);
    assert!(
        sub_ad.join("behavior.wasm").exists(),
        "Sub still materializes behavior.wasm (so the spawn succeeded — the negative is non-vacuous)"
    );
    assert!(
        !sub_ad.join("memory").exists(),
        "Sub kind NEVER writes the memory seed (.agent/memory absent)"
    );

    // --- Root: seed written (same Child|Root gated branch), via direct apply_template ---
    // (Root is the tree root, not spawnable-from-template — the WIT arm traps on Root
    //  and DefaultSpawner has no spawn_root — so the Root token is witnessed at the pub
    //  `apply_template` product surface, the same fn the spawner calls. Plan-eval C3.)
    let rtmp = TempDir::new().unwrap();
    let ws_root = rtmp.path().canonicalize().unwrap();
    let root_target = ws_root.join("root_target");
    // apply_template's precondition: the .agent/ workspace scaffold already exists
    // (the spawner's init_child_workspace establishes .agent/{,memory/,skills/} before
    // calling apply_template; mirror that minimal scaffold here).
    std::fs::create_dir_all(root_target.join(".agent").join("memory")).unwrap();
    std::fs::create_dir_all(root_target.join(".agent").join("skills")).unwrap();
    apply_template(
        &root_target,
        &template_content("name: tmpl\n"),
        AgentKind::Root,
        &ws_root,
    )
    .expect("apply_template Root");
    assert_eq!(
        std::fs::read_to_string(
            agent_dir(&root_target)
                .join("memory")
                .join("knowledge.jsonl")
        )
        .expect("root memory seed written"),
        SEED,
        "Root kind writes the template memory seed (Child|Root shared branch)"
    );
}

/// SYS-AC-197 — a template-ref that resolves to no template aborts before any
/// workspace materialization: SpawnError::InvalidConfig, no child node, and no
/// `.agent/` workspace left on disk (rollback/atomicity).
#[test]
fn sys_ac_197_unresolved_template_ref_aborts_before_materialization() {
    let (_tmp, tree, spawner, root_ws) = setup(Arc::new(MissingResolver));
    let err = spawner
        .spawn_child(SpawnChildConfig {
            parent_id: AgentId("root".to_string()),
            child_id: AgentId("orphan197".to_string()),
            child_workspace_path: PathBuf::from("agents/orphan197"),
            capabilities: Vec::new(),
            template_ref: Some("ghost".to_string()),
            binary: None,
        })
        .expect_err("unresolved template_ref must fail");
    assert!(
        matches!(err, SpawnError::InvalidConfig(_)),
        "unresolved template_ref → SpawnError::InvalidConfig, got {err:?}"
    );
    assert!(
        tree.get_node(&AgentId("orphan197".to_string())).is_none(),
        "no child node registered after the failed spawn"
    );
    assert!(
        !agent_dir(&root_ws.join("agents").join("orphan197")).exists(),
        "no .agent/ workspace materialized (rollback/atomicity)"
    );
}

/// SYS-AC-198 — a template whose manifest `kind:` disagrees with the requested spawn
/// kind is rejected with SpawnError::InvalidConfig and no agent is materialized.
#[test]
fn sys_ac_198_template_kind_mismatch_rejected() {
    let (_tmp, tree, spawner, root_ws) = setup(Arc::new(KindMismatchResolver));
    // Manifest declares `kind: sub`; we request a Child spawn → mismatch.
    let err = spawner
        .spawn_child(SpawnChildConfig {
            parent_id: AgentId("root".to_string()),
            child_id: AgentId("mm198".to_string()),
            child_workspace_path: PathBuf::from("agents/mm198"),
            capabilities: Vec::new(),
            template_ref: Some("tmpl".to_string()),
            binary: None,
        })
        .expect_err("kind mismatch must fail");
    assert!(
        matches!(err, SpawnError::InvalidConfig(_)),
        "manifest kind mismatch → SpawnError::InvalidConfig, got {err:?}"
    );
    assert!(
        tree.get_node(&AgentId("mm198".to_string())).is_none(),
        "no child node registered after the kind-mismatch rejection"
    );
    assert!(
        !agent_dir(&root_ws.join("agents").join("mm198")).exists(),
        "no agent materialized on a kind mismatch"
    );
}

/// SYS-AC-024 — the newly materialized agent is registered in the tree and can run
/// (receives/handles a message) without further setup.
///
/// END-TO-END over the SYS-J-08 Module Chain (MODULE-005→MODULE-018→MODULE-002→MODULE-003),
/// every load-bearing surface PRODUCTION (the prior `#[ignore]` deferral reason is now STALE):
/// - MODULE-005 spawn: the REAL `DefaultSpawner::spawn_child` (the `setup()` helper).
/// - MODULE-018 template: a test-supplied `TemplateResolver` (template INPUT fixture, the same
///   posture as the passed 022/023) whose `behavior_wasm` = the REAL `guest-rust-counter.core.wasm`
///   (a wit-bindgen guest core module, version byte 0x01) → REAL `apply_template`.
/// - MODULE-002 fs: REAL `apply_template` writes `<child_ws>/.agent/behavior.wasm` verbatim +
///   registers the child node.
/// - MODULE-003 run: read the EXACT bytes back from the as-materialized `.agent/behavior.wasm`
///   (NO manual edit) → encode via the PRODUCTION `build_agent::encode_core_to_component` (the
///   fn cli start.rs:660 calls) → load via the PRODUCTION `ComponentRuntime::load_component` (cli
///   start.rs:763) → run via the PRODUCTION `build_agent_loop` + `WasmMessageHandler` +
///   `run_agent` (single turn) → the child handles a message and replies "1".
///
/// Why this is now witnessable (the deferral reason was stale): the production loader
/// `resolve_driver_component_bytes` (cli start.rs:637) now PREFERS `.agent/behavior.component.wasm`
/// ELSE FALLS BACK to `.agent/behavior.wasm`, discriminates a `wasm32` core module (`0x01`) from an
/// encoded Component (`0x0d`), and encodes a core module ON THE FLY before `load_component` — so a
/// template-materialized `.agent/behavior.wasm` is loadable with no extra build step.
///
/// Anti-fake-green / witness-floor:
/// - The bytes that run come from the SPAWNER-materialized file (round-tripped through real
///   `apply_template`), NOT the SUT's build-time-baked `node_drivers` (which key on `.agents()`
///   ids; a template-materialized child is absent from that map).
/// - The counter guest imports NOTHING and its reply derives ONLY from the host-passed `state`
///   (its SYS-AC-264 witness-floor), so the captured reply "1" can only mean the materialized
///   bytes instantiated + ran a real turn. ZERO mocked surfaces.
/// - Honesty split: the private `resolve_driver_component_bytes` SELECTOR is unreachable from this
///   crate; THIS witness pins the e2e RUNNABLE claim over the real materialized artifact, asserting
///   the file INPUTS (`.component.wasm` absent; `.behavior.wasm` present + core module 0x01) that
///   deterministically select production's encode branch. The SELECTOR itself is pinned by the cli
///   unit tests `tests_024` (start.rs:1704-1798). A regression in the selector would be caught
///   there, not here — do not over-read this e2e as covering the selector.
/// - Witness-fidelity disclosure (run-leg floor): like EVERY run-leg SYS-AC witness in this suite
///   (e.g. the passed `sys_j64` 263/264, `reply_delivery` 001), the run is driven through the
///   harness-constructed production `build_agent_loop` composition — NOT the `advance start`
///   daemon-boot path, and NOT a product seam that auto-registers a dynamically-spawned child's
///   serve-loop (the daemon boots ONE deployed agent; `spawn-agent-from-template` returns an id with
///   no serve-loop — dynamic per-child driver registration is a separate, unbuilt seam OUT OF
///   SYS-AC-024's scope). What THIS witnesses is exactly SYS-AC-024's criterion: the as-materialized
///   `.agent/` is loadable + runnable (a real turn executes + a message is handled) with NO manual
///   setup — the exact gap the product loader closed. The drive-prod-fn-no-caller precedent
///   (098/101/109/202): the harness composes + drives the real product fns; the product provides the
///   load-bearing load+encode+run.
/// - Agent-id grammar: the cap-lifecycle `child_id` is BARE (its `AgentId` grammar rejects a
///   colon); the RUN leg (mailbox key / `run_agent` / dispatch) uses the canonical colon messaging
///   id `agent:<child_id>`. The colon on the RUN/dispatch id is LOAD-BEARING:
///   `build_agent_loop`'s `AgentActionDispatcherImpl::dispatch` calls `is_safe_id(agent_id)`
///   DIRECTLY (messaging action_dispatcher.rs:173) BEFORE the `DefaultActionValidator` and BEFORE
///   the outbound sink, and `is_safe_id` REJECTS a bare id (`system`/`agent:body`/`user:body`
///   only) → a bare run id errors in dispatch (`invalid_agent_id`) and the reply never reaches the
///   sink. (`DefaultActionValidator`'s own id whitelist would ACCEPT a bare id — the load-bearing
///   gate is the dispatcher's direct `is_safe_id` check, not the validator.) The passed `sys_j64`
///   uses `agent:counter`.
///   NOTE (not fully production-faithful, by design): production `try_spawn_agent_loop`
///   (start.rs:770-781) builds the `WasmMessageHandler` with a BARE `cap_agent_id` (the
///   capability-context id for fs/grant resolution) and runs the mailbox under the colon
///   `msg_agent_id`. THIS witness uses the colon id for the handler too — sound ONLY because the
///   counter guest requests NO capabilities, so the handler's cap-context id is never consulted.
///   The materialized child's capability-identity bridging (bare `cap_agent_id`) is therefore NOT
///   exercised here; it is witnessed by the fs/grant SYS-J journeys, not by this run-leg witness.
#[tokio::test(flavor = "multi_thread")]
async fn sys_ac_024_materialized_agent_registered_and_runnable() {
    // --- MODULE-005/018/002: materialize a RUNNABLE child via the REAL spawner ---
    let (_tmp, tree, spawner, _root_ws) = setup(Arc::new(RunnableResolver));
    let child = spawner
        .spawn_child(SpawnChildConfig {
            parent_id: AgentId("root".to_string()),
            child_id: AgentId("mat024run".to_string()), // BARE (cap-lifecycle rejects a colon)
            child_workspace_path: PathBuf::from("agents/mat024run"),
            capabilities: Vec::new(),
            template_ref: Some("tmpl".to_string()),
            binary: None,
        })
        .expect("spawn_child from a runnable template");

    // Criterion clause 1 — REGISTERED IN THE TREE.
    let node = tree
        .get_node(&child)
        .expect("the materialized child is registered in the tree");
    let ad = agent_dir(&node.workspace_path);

    // Pin production's resolution branch via the as-materialized file INPUTS (NO manual setup):
    //  - no pre-encoded .component.wasm → production falls back to .agent/behavior.wasm
    //  - .agent/behavior.wasm present, == the template core bytes, and a wasm32 core module
    //    (version byte 0x01) → production's encode-on-the-fly branch.
    assert!(
        !ad.join("behavior.component.wasm").exists(),
        "no pre-encoded .component.wasm — production resolution falls back to .agent/behavior.wasm"
    );
    let materialized = std::fs::read(ad.join("behavior.wasm"))
        .expect("apply_template materialized .agent/behavior.wasm");
    assert_eq!(
        materialized, COUNTER_CORE,
        "the materialized .agent/behavior.wasm equals the template's core bytes (verbatim)"
    );
    assert!(
        materialized.len() >= 8 && &materialized[0..4] == b"\0asm" && materialized[4] == 0x01,
        "the materialized behavior.wasm is a wasm32 core module (version byte 0x01) — \
         production's encode branch"
    );

    // --- MODULE-003: drive the PRODUCTION load+encode+run over the MATERIALIZED bytes ---
    // Encode the EXACT materialized bytes via the production encoder (cli start.rs:660 calls this).
    let component = build_agent::encode_core_to_component(&materialized)
        .expect("production encode_core_to_component encodes the materialized core module");
    assert_eq!(
        component[4], 0x0d,
        "the core module was encoded to a WASM Component (version byte 0x0d)"
    );
    let runtime = run_runtime();
    // Load via the production loader (cli start.rs:763 calls this).
    let loaded = runtime
        .load_component(&component)
        .expect("the materialized child's encoded component loads");

    // Two-grammar split: BARE tree id → canonical colon messaging id for the run/dispatch leg.
    let run_id = format!("agent:{}", child.0);

    let handler: Arc<dyn MessageHandler> = Arc::new(WasmMessageHandler::new(
        runtime,
        loaded,
        run_injector(),
        vec![],
        run_id.clone(),
        "trace-sys-ac-024".to_string(),
    ));

    let store = Arc::new(MailboxStore::new(NonZeroUsize::new(8).unwrap()));
    let replies = Arc::new(Mutex::new(Vec::new()));
    let sink: Arc<dyn OutboundActionSink> = Arc::new(RecordingSink {
        replies: replies.clone(),
    });
    let driver = build_agent_loop(store.clone(), handler, Arc::new(NullBus), Some(sink));

    // Deliver one message to the MATERIALIZED child's mailbox + drive ONE production turn.
    store
        .get_or_create(&run_id)
        .expect("mailbox")
        .deliver(user_msg("m1", &run_id))
        .expect("deliver");
    let cfg = ComponentConfig {
        id: run_id.clone(),
        config_data: None,
        trigger_context: None,
    };
    let instance =
        WasmInstance::new(ComponentId::new("mat024-inst".to_string()).expect("component id"));
    driver.run_agent(&run_id, cfg, instance).await;

    // Criterion clause 2 — CAN RUN (receives/handles a message) WITHOUT FURTHER SETUP.
    // The materialized child handled the inbound message and replied "1" through the production
    // outbound seam — proving it ran from the as-materialized `.agent/` with NO manual setup.
    let got = replies.lock().unwrap().clone();
    assert_eq!(
        got,
        vec![b"1".to_vec()],
        "the materialized child handled the message and replied '1' via the production run path \
         (run_agent over encode_core_to_component(materialized-bytes) + load_component) — not a \
         build-time-baked node_driver"
    );
}

/// SYS-AC-199 — the pure `<500 ms` template-materialization perf-SLO is `passed` via the
/// dedicated perf-CI lane (`crates/system-acceptance/tests/perf_slo.rs`, median-of-N /
/// `--release` / `--test-threads=1`, harvested 2026-06-19), NOT this file. This `#[ignore]`d
/// stub is retained only as a pointer so the perf-SLO row is not mistaken for missing coverage
/// here. (Earlier this stub claimed a §3 deferral — stale; 199 is no longer deferred.)
#[test]
#[ignore = "perf-SLO passed via tests/perf_slo.rs (perf-CI lane, 2026-06-19), not this file — pointer stub only"]
fn sys_ac_199_typical_template_materializes_under_500ms() {}
