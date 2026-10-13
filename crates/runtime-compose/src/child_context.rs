//! Per-child context assembly + turn-end memory wiring.
//!
//! The root loop is built in `daemon::try_spawn_agent_loop`. Child serve loops
//! used to keep the walking-skeleton [`MinimalContextAssembler`] + trace-only
//! post-processor, so a child's `generate` never saw a layered prompt and its
//! turns never wrote embeddings. This module is the same production path,
//! keyed on the child's bare/colon pair and workspace.

use std::path::Path;
use std::sync::Arc;

use advance_context_engine::DecompositionReader;
use advance_runtime::host_registry::HostRegistry;
use advance_scheduler::agent_loop::AgentLoopDriverImpl;
use advance_shared_types::agent_tree::AgentTreeSnapshot;
use advance_shared_types::context::ContextAssembler;
use advance_shared_types::traits::{
    CallableInventoryReader, EventBusEmit, GrantCheck, ToolsGrantReader,
};
use cap_lifecycle::DefaultDecompositionStore;
use cap_llm::{resolve_provider_and_model, LlmGateway, VlmExtractor};
use cap_memory::MemoryStore;
use cap_tools::ToolRegistry;

use crate::agent_loop::PublishingContextAssembler;
use crate::api::log_keys;
use crate::compose_log::LogHandle;
use crate::context_inspect::{ContextSnapshotStore, EmbeddingPosture};
use crate::context_wiring::{
    host_fns_from_registry, FixedHostFnInventory, GatewayEmbedding, GatewayLightLlm,
    PackSkillSummaryReader,
};

/// Shared production deps late-bound onto [`crate::perchild_daemon::PerChildLoopManager`]
/// after the LLM gateway exists and before any child loop is served.
pub struct ChildContextDeps {
    pub context_store: Arc<ContextSnapshotStore>,
    pub gateway: Arc<LlmGateway>,
    pub memory_store: Option<Arc<MemoryStore>>,
    pub memory_index: Option<Arc<dyn cap_memory::SqliteIndex + Send + Sync>>,
    pub agent_tree: Option<Arc<dyn AgentTreeSnapshot>>,
    pub decomposition: Option<Arc<DefaultDecompositionStore>>,
    pub pack_runtime: Option<Arc<crate::pack_runtime::PackRuntime>>,
    pub tool_registry: Option<Arc<dyn ToolRegistry>>,
    pub tools_grant_reader: Option<Arc<dyn ToolsGrantReader>>,
    pub web_grant: Option<Arc<dyn GrantCheck>>,
    pub mcp: Option<Arc<crate::mcp_wiring::McpRuntime>>,
    pub event_bus: Arc<dyn EventBusEmit>,
    pub event_bus_ss: Arc<dyn EventBusEmit + Send + Sync>,
    pub git_queue: Option<Arc<dyn advance_git::GitCommitQueue>>,
    pub vlm: Option<Arc<dyn VlmExtractor>>,
    pub host_registry: Arc<dyn HostRegistry>,
    pub embedding_posture: EmbeddingPosture,
    pub assembler_model: String,
    pub llm_provider: Option<String>,
    pub runtime_version: String,
    pub runtime_handle: tokio::runtime::Handle,
    pub log: LogHandle,
}

fn has_cap(caps: &[String], name: &str) -> bool {
    caps.iter().any(|c| c == name)
}

/// Attach the production assembler + (when the child declared `memory`) the
/// live post-processor to a child serve loop. No-ops only if construction
/// cannot proceed; the driver is always returned.
pub fn attach_child_context(
    mut driver: AgentLoopDriverImpl,
    deps: &ChildContextDeps,
    cap_agent_id: &str,
    msg_agent_id: &str,
    workspace: &Path,
    declared_caps: &[String],
) -> AgentLoopDriverImpl {
    let child_memory = has_cap(declared_caps, "memory")
        .then(|| deps.memory_store.clone())
        .flatten();
    let (post_processor, child_index) = crate::daemon::build_live_post_processor(
        child_memory.as_ref(),
        Some(&deps.gateway),
        workspace,
        deps.event_bus_ss.clone(),
        cap_agent_id,
        deps.git_queue.clone(),
        deps.vlm.clone(),
        deps.agent_tree.clone(),
        &deps.log,
        deps.memory_index.clone(),
    );
    driver = driver.with_post_processor(post_processor);

    deps.context_store
        .register_aliases(&[cap_agent_id.to_string(), msg_agent_id.to_string()]);

    let agent_tree: Arc<dyn AgentTreeSnapshot> = match deps.agent_tree.clone() {
        Some(t) => t,
        None => Arc::new(crate::context_wiring::EmptyAgentTree),
    };
    let decomposition: Arc<dyn DecompositionReader> = match deps.decomposition.clone() {
        Some(store) => Arc::new(crate::context_wiring::CapDecompositionReader::new(
            store,
            vec![cap_agent_id.to_string(), msg_agent_id.to_string()],
        )),
        None => Arc::new(crate::context_wiring::EmptyDecomposition),
    };

    let declared_refs: Vec<&str> = declared_caps.iter().map(|s| s.as_str()).collect();
    let wasm_entries = if let Some(reg) = deps.tool_registry.as_ref() {
        let listed = list_tools_blocking(reg, &deps.runtime_handle);
        let allow = deps
            .tools_grant_reader
            .as_ref()
            .and_then(|r| r.tool_allowlist(cap_agent_id));
        cap_tools::web::project_callable_tool_entries(
            listed,
            allow.as_deref(),
            deps.web_grant.as_deref(),
            cap_agent_id,
        )
    } else {
        Vec::new()
    };
    let callable: Arc<dyn CallableInventoryReader> = match (
        deps.mcp.clone(),
        has_cap(declared_caps, "mcp") || has_cap(declared_caps, "tools"),
    ) {
        (Some(mcp), true) => Arc::new(crate::mcp_wiring::LiveCallableInventory::for_agent(
            wasm_entries,
            mcp,
            cap_agent_id,
            &[cap_agent_id.to_string(), msg_agent_id.to_string()],
        )),
        _ if deps.tool_registry.is_some() && has_cap(declared_caps, "tools") => {
            Arc::new(cap_tools::CallableInventory::new(wasm_entries, vec![]))
        }
        _ => Arc::new(crate::context_wiring::EmptyCallableInventory),
    };

    let identity_root = workspace.join(".agent");
    let child_memory_root = child_memory
        .is_some()
        .then(|| workspace.join(".agent").join("memory"));
    let child_skills_root = has_cap(declared_caps, "skills").then(|| workspace.join(".agent"));
    let embedding_live = deps.embedding_posture.active;
    let embedding: Option<Arc<dyn advance_context_engine::EmbeddingPort>> =
        embedding_live.then(|| {
            Arc::new(GatewayEmbedding::new(deps.gateway.clone()))
                as Arc<dyn advance_context_engine::EmbeddingPort>
        });

    let runtime_info = advance_context_engine::RuntimeInfoView {
        runtime_version: deps.runtime_version.clone(),
        agent_kind: Some("child".to_string()),
        parent_agent: agent_tree.parent_of(cap_agent_id),
        workspace: Some(workspace.display().to_string()),
        capabilities: declared_caps.to_vec(),
        mode: Some("child-serve".to_string()),
        llm_provider: deps.llm_provider.clone(),
        llm_model: (!deps.assembler_model.is_empty()).then(|| deps.assembler_model.clone()),
        memory_enabled: child_memory.is_some(),
        skills_enabled: child_skills_root.is_some(),
        embedding_enabled: embedding_live,
    };

    let sqlite_index = child_index.or_else(|| deps.memory_index.clone());
    let inner = crate::context_wiring::build_context_assembler_for_agent_production(
        crate::context_wiring::ProductionAssemblerParts {
            event_bus: deps.event_bus.clone(),
            callable_inventory: callable,
            host_fn_inventory: Arc::new(FixedHostFnInventory::new(host_fns_from_registry(
                deps.host_registry.as_ref(),
                &declared_refs,
            ))),
            agent_tree,
            memory: child_memory,
            write_agent_id: cap_agent_id,
            query_aliases: &[cap_agent_id.to_string(), msg_agent_id.to_string()],
            memory_root: child_memory_root.as_deref(),
            skills_agent_root: child_skills_root.as_deref(),
            decomposition,
            pack_skills: deps
                .pack_runtime
                .clone()
                .filter(|_| has_cap(declared_caps, "tools"))
                .map(|runtime| {
                    Arc::new(PackSkillSummaryReader::new(runtime))
                        as Arc<dyn advance_context_engine::ports::SkillSummaryReader>
                }),
            identity_agent_root: Some(&identity_root),
            embedding,
            sqlite_index,
            runtime_info: Some(runtime_info),
            report_sink: Some(deps.context_store.clone()),
            light_llm: Some(Arc::new(GatewayLightLlm::new(deps.gateway.clone()))),
        },
    );

    if !deps.assembler_model.is_empty() {
        driver = driver.with_model(deps.assembler_model.clone());
    }
    let publishing: Arc<dyn ContextAssembler> = Arc::new(PublishingContextAssembler::new(
        inner,
        deps.gateway.clone(),
        cap_agent_id.to_string(),
    ));
    driver.with_context_assembler(publishing)
}

/// Open the durable cap-memory SQLite index if `memory_root` is present.
/// Fail-soft: a missing / unreadable file is logged and returns `None`.
pub fn open_shared_memory_index(
    memory_root: Option<&Path>,
    log: &LogHandle,
) -> Option<Arc<dyn cap_memory::SqliteIndex + Send + Sync>> {
    let root = memory_root?;
    match cap_memory::RusqliteSqliteIndex::open(root.join("index.sqlite")) {
        Ok(idx) => Some(Arc::new(idx)),
        Err(e) => {
            log.err(
                log_keys::MEMORY_INDEX_FALLBACK,
                format!(
                    "advance start: durable memory index open failed ({e}); using the in-memory index"
                ),
            );
            None
        }
    }
}

/// Resolve the default chat model / provider id the assemblers stamp on reports.
pub fn resolve_assembler_model(
    providers: &[advance_runtime::config::LlmProviderConfig],
) -> (String, Option<String>) {
    match resolve_provider_and_model(providers, None) {
        Ok(r) => (r.model, Some(r.id)),
        Err(_) => (String::new(), None),
    }
}

/// `ToolRegistry::list` is async; child spawn is sync. Hop off the current
/// worker so we never `block_on` a runtime from inside itself.
fn list_tools_blocking(
    reg: &Arc<dyn ToolRegistry>,
    handle: &tokio::runtime::Handle,
) -> Vec<cap_tools::ToolInfo> {
    let reg = Arc::clone(reg);
    let handle = handle.clone();
    std::thread::Builder::new()
        .name("child-tools-list".into())
        .spawn(move || handle.block_on(cap_tools::ToolRegistry::list(reg.as_ref())))
        .and_then(|join| {
            join.join()
                .map_err(|_| std::io::Error::new(std::io::ErrorKind::Other, "tools list thread"))
        })
        .unwrap_or_default()
}
