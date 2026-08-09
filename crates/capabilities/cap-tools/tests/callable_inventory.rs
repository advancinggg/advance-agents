//! Slice J (V1-b) — MODULE-017-AC-30 architectural test (materializes §3.3 T32,
//! the M017-owned sub-criteria) + an e2e that feeds the production
//! `CallableInventoryReader` into the REAL `ContextAssemblerImpl::assemble()` and
//! asserts the Layer-3 `# Available Tools` view lists the WASM + MCP tools while
//! `# Available Delegates` stays a separate section.
//!
//! Lives in `cap-tools/tests` (NOT `context-engine/tests`) so context-engine's
//! manifest stays free of cap-mcp/cap-http — preserving its AC-01 dep-light
//! posture (`context-engine/tests/stateless.rs` greps that manifest).
//!
//! cargo-component is NOT required: the WASM half is built from synthetic
//! `ToolInfo` (via `cap_tools::tool_entries_from_infos`) and the MCP half from
//! synthetic `McpToolInfo` (via `cap_mcp::mcp_tool_entries_from_infos`).

#![allow(dead_code)]

use std::any::TypeId;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::SystemTime;

use advance_context_engine::{
    assemble_unified, format_available_tools_section, AgentIdentityReader, ContextAssemblerImpl,
    DecompositionReader, EmbeddingPort, EpochSummary, GlobalMemoryRecord, HostFnEntry,
    HostFnInventoryReader, KnowledgeMap, KnowledgeMapReader, L2DigestReader, L3EpochReader,
    L4TaskSummaryReader, L5SynthesisReader, L6ConsolidationReader, LightLlmFallbackPort, PortError,
    SkillSummaryEntry, SkillSummaryReader, SubtaskView, SynthesisView, TaskHit, TaskIndexPort,
    TaskSummaryView, TurnDigestForEmbed, UnifiedSearchPort, UnifiedSearchResult, VectorHit,
    VectorIndexReader,
};
use advance_shared_types::agent_tree::{
    AgentKind, AgentState, AgentStatus, AgentTreeSnapshotData, Capability,
};
use advance_shared_types::capability::{McpToolEntry, ToolEntry};
use advance_shared_types::context::{AssemblyContext, ContextAssembler, LlmMessage};
use advance_shared_types::event::Event;
use advance_shared_types::mailbox::{Message, MessageKind};
use advance_shared_types::security_validator::{InjectionFlag, PromptInjectionHelpers, TrustLevel};
use advance_shared_types::traits::{
    AgentTreeReader, AgentTreeSnapshot, CallableInventoryReader, EventBusEmit,
};
use async_trait::async_trait;
use cap_mcp::{mcp_tool_entries_from_infos, McpToolInfo};
use cap_tools::{tool_entries_from_infos, CallableInventory, MethodInfo, ToolInfo};

// ─── synthetic inventory snapshots (no WASM build, no real MCP server) ───

// Sanitization-stable identifiers: M010's `tier2::sanitize_tool_name` rewrites
// `-` (and other delimiter/Unicode-spoof chars) to `_` in the rendered line, so
// we use underscore names whose raw form == rendered form. This keeps the e2e
// assertions about "the tool appears in the section" decoupled from M010's
// substitution rule (which has its own M010 sanitizer tests).
const WASM_TOOL: &str = "fs_read";
const MCP_TOOL: &str = "web_search";

/// WASM half: synthetic `ToolInfo` → `ToolEntry` via the production mapping.
fn wasm_snapshot() -> Vec<ToolEntry> {
    tool_entries_from_infos(vec![ToolInfo {
        id: WASM_TOOL.into(),
        description: "Read a file".into(),
        methods: vec![MethodInfo {
            name: "read".into(),
            description: None,
            input_schema: None,
            output_schema: None,
            idempotent: None,
        }],
    }])
}

/// MCP half: synthetic `McpToolInfo` → `McpToolEntry` via the production mapping.
fn mcp_snapshot() -> Vec<McpToolEntry> {
    mcp_tool_entries_from_infos(vec![McpToolInfo {
        name: MCP_TOOL.into(),
        description: "Search the web".into(),
        server_id: "srv-1".into(),
    }])
}

fn production_reader() -> Arc<dyn CallableInventoryReader> {
    Arc::new(CallableInventory::new(wasm_snapshot(), mcp_snapshot()))
}

// ════════════════════════════════════════════════════════════════════════
// MODULE-017-T32 — architectural (the sub-criteria owned by M017's reader).
// ════════════════════════════════════════════════════════════════════════

/// T32 sub-(4)+(5): the two methods return DISTINCT types and ONLY their own
/// kind; no combined `Vec` is produced inside M017. The explicit type
/// annotations are a compile-time pin (a `pub type McpToolEntry = ToolEntry`
/// alias collapse would fail to compile here); the `TypeId` assert is the
/// nominal-distinctness tripwire (mirrors runtime T49 for the production impl).
#[test]
fn module_017_t32_two_methods_distinct_types_never_combined() {
    let reader = production_reader();

    let wasm: Vec<ToolEntry> = reader.list_wasm_tools("agent-default");
    let mcp: Vec<McpToolEntry> = reader.list_mcp_tools("agent-default");

    // distinct nominal types (anti-alias tripwire).
    assert_ne!(
        TypeId::of::<ToolEntry>(),
        TypeId::of::<McpToolEntry>(),
        "CONTRACT-165: ToolEntry and McpToolEntry must remain distinct nominal types",
    );

    // each method returns ONLY its own kind — no crossover, no pre-merge.
    assert_eq!(wasm.len(), 1);
    assert_eq!(wasm[0].name, WASM_TOOL);
    assert!(
        !wasm.iter().any(|t| t.name == MCP_TOOL),
        "list_wasm_tools leaked an MCP entry — the two inventories were combined",
    );

    assert_eq!(mcp.len(), 1);
    assert_eq!(mcp[0].name, MCP_TOOL);
    assert_eq!(mcp[0].server_id, "srv-1");
    assert!(
        !mcp.iter().any(|t| t.name == WASM_TOOL),
        "list_mcp_tools leaked a WASM entry — the two inventories were combined",
    );
}

/// T32 sub-(4): `params_schema` is the empty object for both halves (V1-b
/// mapping); the Tier-2 line renders `- name() — desc` (no args).
#[test]
fn module_017_t32_params_schema_is_empty_object() {
    let reader = production_reader();
    assert_eq!(
        reader.list_wasm_tools("agent-default")[0].params_schema,
        serde_json::json!({})
    );
    assert_eq!(
        reader.list_mcp_tools("agent-default")[0].params_schema,
        serde_json::json!({})
    );
}

// ════════════════════════════════════════════════════════════════════════
// e2e — production reader feeds M010's Layer-3 view.
// ════════════════════════════════════════════════════════════════════════

/// e2e (direct Layer-3 path): the production reader's two lists feed M010's
/// `assemble_unified` → `format_available_tools_section` (the exact code
/// `ContextAssemblerImpl::assemble` runs at the Tier-2 step) and the rendered
/// `# Available Tools` section lists BOTH the WASM and MCP tools.
#[test]
fn v1b_available_tools_direct_lists_wasm_and_mcp() {
    let reader = production_reader();
    let host_fns: Vec<HostFnEntry> = Vec::new();
    let unified = assemble_unified(
        host_fns,
        reader.list_wasm_tools("agent-default"),
        reader.list_mcp_tools("agent-default"),
    );
    let section = format_available_tools_section(&unified);

    assert!(section.starts_with("# Available Tools"));
    assert!(
        section.contains(WASM_TOOL),
        "rendered section missing the WASM tool: {section}"
    );
    assert!(
        section.contains(MCP_TOOL),
        "rendered section missing the MCP tool: {section}"
    );
}

/// e2e (full assemble): inject the production reader into the REAL
/// `ContextAssemblerImpl` (no more stub `MockCallableInventory`) and run
/// `assemble()`. Assert the `# Available Tools` message lists the WASM + MCP
/// tools, and a SEPARATE `# Available Delegates` message exists that does NOT
/// contain the tool names (PRD §3.9/§3.10 dual positioning). `task_id = Some`
/// short-circuits the task router, so the embedding/task-index/light-llm doubles
/// are constructed but never invoked.
#[tokio::test]
async fn v1b_available_tools_e2e_through_real_assembler() {
    let assembler = ContextAssemblerImpl::new(
        production_reader(),
        Arc::new(NullHostFnInventory),
        Arc::new(NullAgentIdentity),
        Arc::new(NullKnowledgeMap),
        Arc::new(NullAgentTree),
        Arc::new(NullEmbedding),
        Arc::new(NullTaskIndex),
        Arc::new(NullLightLlm),
        Arc::new(NullUnifiedSearch),
        Arc::new(NullEventBus),
        Arc::new(NullSkillSummary),
        Arc::new(NullVectorIndex),
        Arc::new(NullL2Digest),
        Arc::new(NullL3Epoch),
        Arc::new(NullL4TaskSummary),
        Arc::new(NullL5Synthesis),
        Arc::new(NullL6Consolidation),
        Arc::new(NullPromptInjectionHelpers),
        // Wave-12 Lane C: 19th port — DecompositionReader (empty double → no
        // Tier-2 ⑭ section → this test's # Available Tools/Delegates assertions
        // are unaffected).
        Arc::new(NullDecomposition),
    );

    let result = assembler
        .assemble(stub_ctx())
        .await
        .expect("assemble must succeed");

    let tools = result
        .messages
        .iter()
        .find(|m| m.content.starts_with("# Available Tools"))
        .map(|m| m.content.clone())
        .expect("assembled output missing the `# Available Tools` section");
    assert!(
        tools.contains(WASM_TOOL),
        "tools section missing WASM tool: {tools}"
    );
    assert!(
        tools.contains(MCP_TOOL),
        "tools section missing MCP tool: {tools}"
    );

    // Delegates stay a SEPARATE section — and the tool names must not bleed into it.
    let delegates = result
        .messages
        .iter()
        .find(|m| m.content.starts_with("# Available Delegates"))
        .map(|m| m.content.clone())
        .expect("assembled output missing the separate `# Available Delegates` section");
    assert!(
        !delegates.contains(WASM_TOOL) && !delegates.contains(MCP_TOOL),
        "tool entries leaked into the Delegates section: {delegates}"
    );
}

/// Registry-gather path: `wasm_tool_entries` over a REAL `LazyToolRegistry`.
/// `register_binary` takes raw bytes and `LazyToolRegistry::list()` enumerates
/// registered-but-unloaded tools WITHOUT loading/validating them, so non-WASM
/// bytes are fine and no cargo-component is needed (§3.6 (e)). The gathered
/// `ToolEntry` carries `name == id` and an OPPORTUNISTIC empty description
/// (no force-load — §2.7 "descriptions opportunistic"), with `params_schema={}`.
#[tokio::test]
async fn v1b_wasm_tool_entries_gathers_from_real_registry() {
    use cap_tools::{wasm_tool_entries, LazyRegistryConfig, LazyToolRegistry};

    let registry = LazyToolRegistry::new(LazyRegistryConfig::default());
    registry
        .register_binary("fs_read", vec![0xde, 0xad, 0xbe, 0xef])
        .await;

    let entries = wasm_tool_entries(&registry).await;
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].name, "fs_read");
    assert!(
        entries[0].description.is_empty(),
        "unloaded tool should map to an opportunistic empty description",
    );
    assert_eq!(entries[0].params_schema, serde_json::json!({}));
}

// ─── stub AssemblyContext (task_id = Some → skip the router) ───

fn stub_ctx() -> AssemblyContext {
    AssemblyContext {
        agent_id: "agent-default".into(),
        task_id: Some("task-1".into()),
        message: Message {
            id: "msg-stub".into(),
            kind: MessageKind::User,
            from: "agent-default".into(),
            to: "agent-default".into(),
            payload: Vec::new(),
            context: None,
            timestamp: SystemTime::UNIX_EPOCH,
            origin: None,
        },
        prompt: String::new(),
        model: "test-model".into(),
        turn_buffer: Vec::<LlmMessage>::new(),
        prior_state: AgentState {
            agent_id: "agent-default".into(),
            status: AgentStatus::Active,
            current_task_id: None,
            current_run_id: None,
            iteration: 0,
            turn_counter: 0,
            last_handle_message_at: None,
        },
    }
}

// ─── local dependency doubles for ContextAssemblerImpl::new (18 ports) ───
// (context-engine/tests/common is a private test module, not importable.)

struct NullHostFnInventory;
impl HostFnInventoryReader for NullHostFnInventory {
    fn list_host_fns(&self, _agent_id: &str) -> Vec<HostFnEntry> {
        Vec::new()
    }
}

struct NullAgentIdentity;
#[async_trait]
impl AgentIdentityReader for NullAgentIdentity {
    async fn agents_md_summary(&self, _agent_id: &str) -> Option<String> {
        None
    }
}

struct NullKnowledgeMap;
#[async_trait]
impl KnowledgeMapReader for NullKnowledgeMap {
    async fn read_knowledge_map(&self, _agent_id: &str) -> Option<KnowledgeMap> {
        None
    }
}

/// Empty agent tree — satisfies `AgentTreeReader` + the `AgentTreeSnapshot`
/// supertrait. With no `Sub` nodes, the Delegates section is header-only.
struct NullAgentTree;
impl AgentTreeReader for NullAgentTree {
    fn parent_of(&self, _agent_id: &str) -> Option<String> {
        None
    }
    fn children_of(&self, _agent_id: &str) -> Vec<String> {
        Vec::new()
    }
    fn siblings_of(&self, _agent_id: &str) -> Vec<String> {
        Vec::new()
    }
    fn agent_exists(&self, _agent_id: &str) -> bool {
        false
    }
    fn agent_kind(&self, _agent_id: &str) -> Option<AgentKind> {
        None
    }
    fn capabilities(&self, _agent_id: &str) -> Vec<Capability> {
        Vec::new()
    }
}
impl AgentTreeSnapshot for NullAgentTree {
    fn snapshot(&self) -> AgentTreeSnapshotData {
        AgentTreeSnapshotData {
            nodes: Vec::new(),
            parent_of: HashMap::new(),
            children_of: HashMap::new(),
            peer_slug_map: HashMap::new(),
            revision: 0,
        }
    }
}

struct NullEmbedding;
#[async_trait]
impl EmbeddingPort for NullEmbedding {
    async fn embed(&self, _text: &str) -> Result<Vec<f32>, PortError> {
        Ok(vec![0.0_f32, 1.0, 0.0])
    }
}

struct NullTaskIndex;
#[async_trait]
impl TaskIndexPort for NullTaskIndex {
    async fn top_n_by_similarity(
        &self,
        _agent_id: &str,
        _q: &[f32],
        _n: usize,
    ) -> Result<Vec<TaskHit>, PortError> {
        Ok(Vec::new())
    }
}

struct NullLightLlm;
#[async_trait]
impl LightLlmFallbackPort for NullLightLlm {
    async fn pick_one(&self, _query: &str, candidates: &[String]) -> Result<String, PortError> {
        candidates
            .first()
            .cloned()
            .ok_or_else(|| PortError("no candidates".into()))
    }
}

struct NullUnifiedSearch;
#[async_trait]
impl UnifiedSearchPort for NullUnifiedSearch {
    async fn search(
        &self,
        _agent_id: &str,
        _query: &str,
        _q: &[f32],
    ) -> Result<UnifiedSearchResult, PortError> {
        Ok(UnifiedSearchResult::default())
    }
}

struct NullEventBus;
impl EventBusEmit for NullEventBus {
    fn emit(&self, _event: Event) {}
}

/// Slice-V1-c 11th dep — empty skill reader (no `# Available Skills` section,
/// so the V1-b `# Available Tools` assertions below are unaffected).
struct NullSkillSummary;
#[async_trait]
impl SkillSummaryReader for NullSkillSummary {
    async fn list_skill_summaries(&self, _agent_id: &str) -> Vec<SkillSummaryEntry> {
        Vec::new()
    }
}

// ─── Stage-C SAT-A 12th–17th deps — empty L1-L6 reader doubles (empty digest
//     → no fold message → the `# Available Tools` assertions are unaffected). ───

struct NullVectorIndex;
#[async_trait]
impl VectorIndexReader for NullVectorIndex {
    async fn lookup(&self, _agent_id: &str, _q: &[f32]) -> Result<Vec<VectorHit>, PortError> {
        Ok(Vec::new())
    }
}

struct NullL2Digest;
#[async_trait]
impl L2DigestReader for NullL2Digest {
    async fn read_digests(
        &self,
        _agent_id: &str,
        _task_id: &str,
    ) -> Result<Vec<TurnDigestForEmbed>, PortError> {
        Ok(Vec::new())
    }
}

struct NullL3Epoch;
#[async_trait]
impl L3EpochReader for NullL3Epoch {
    async fn read_epoch(
        &self,
        _agent_id: &str,
        _task_id: &str,
    ) -> Result<Option<EpochSummary>, PortError> {
        Ok(None)
    }
}

struct NullL4TaskSummary;
#[async_trait]
impl L4TaskSummaryReader for NullL4TaskSummary {
    async fn read_task_summary(
        &self,
        _agent_id: &str,
        _task_id: &str,
    ) -> Result<Option<TaskSummaryView>, PortError> {
        Ok(None)
    }
}

struct NullL5Synthesis;
#[async_trait]
impl L5SynthesisReader for NullL5Synthesis {
    async fn read_syntheses(
        &self,
        _agent_id: &str,
        _task_id: &str,
    ) -> Result<Vec<SynthesisView>, PortError> {
        Ok(Vec::new())
    }
}

struct NullL6Consolidation;
#[async_trait]
impl L6ConsolidationReader for NullL6Consolidation {
    async fn read_global_memory(
        &self,
        _agent_id: &str,
    ) -> Result<Vec<GlobalMemoryRecord>, PortError> {
        Ok(Vec::new())
    }
}

// Stage-C SAT-E: local passthrough double for the 18th port (cap-tools deps
// shared-types, not cap-http — the trait lives in shared-types).
struct NullPromptInjectionHelpers;
impl PromptInjectionHelpers for NullPromptInjectionHelpers {
    fn flag_injection_patterns(&self, _content: &str) -> Vec<InjectionFlag> {
        Vec::new()
    }
    fn wrap_with_boundary(&self, content: &str, _source: &str, _trust: TrustLevel) -> String {
        content.to_string()
    }
}

// Wave-12 Lane C: empty DecompositionReader double for the 19th port.
struct NullDecomposition;
#[async_trait]
impl DecompositionReader for NullDecomposition {
    async fn read_active_subtasks(
        &self,
        _agent_id: &str,
        _task_id: Option<&str>,
    ) -> Vec<SubtaskView> {
        Vec::new()
    }
}
