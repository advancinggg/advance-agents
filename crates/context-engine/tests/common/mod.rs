//! Shared helpers for context-engine integration tests.
//!
//! Each test file pulls these via:
//! ```ignore
//! #[path = "common/mod.rs"]
//! mod common;
//! use common::*;
//! ```
//! The `tests/common/mod.rs` layout (directory + `mod.rs`) is the canonical
//! Rust idiom — Cargo does NOT compile `common` as its own test binary.
//!
//! `ContextAssemblerImpl::new` has grown across slices to 19 injected deps
//! (Slice B 2→9; Slice D +6 L-readers → 17; Stage-C SAT-E +1
//! `PromptInjectionHelpers` → 18; Wave-12 Lane C +1 `DecompositionReader` → 19).
//! The public helper signatures
//! (`build_assembler_with`, `build_assembler_with_empty_inventories`) are
//! UNCHANGED so the earlier test files (`tier_structure.rs`,
//! `tier2_unified_tools.rs`, `inject_tier3_warning.rs`) keep compiling without
//! edits — the newer ports are filled with `Null*` doubles here.

#![allow(dead_code)]

use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use advance_context_engine::{
    AgentIdentityReader, ContextAssemblerImpl, DecompositionReader, EmbeddingPort, EpochSummary,
    GlobalMemoryRecord, HostFnEntry, HostFnInventoryReader, KnowledgeMap, KnowledgeMapReader,
    L2DigestReader, L3EpochReader, L4TaskSummaryReader, L5SynthesisReader, L6ConsolidationReader,
    LightLlmFallbackPort, PortError, SkillSummaryEntry, SkillSummaryReader, SubtaskView,
    SynthesisView, TaskHit, TaskIndexPort, TaskSummaryView, TurnDigestForEmbed, UnifiedSearchPort,
    UnifiedSearchResult, VectorHit, VectorIndexReader,
};
use advance_shared_types::agent_tree::{
    AgentId, AgentKind, AgentState, AgentStatus, AgentTreeSnapshotData,
};
use advance_shared_types::capability::{McpToolEntry, ToolEntry};
use advance_shared_types::context::{AssemblyContext, LlmMessage};
use advance_shared_types::event::Event;
use advance_shared_types::mailbox::{Message, MessageKind};
use advance_shared_types::security_validator::{InjectionFlag, PromptInjectionHelpers, TrustLevel};
use advance_shared_types::traits::{
    AgentTreeReader, AgentTreeSnapshot, CallableInventoryReader, EventBusEmit,
};
use async_trait::async_trait;

// ─── Inventory factory helpers ───

pub fn host(name: &str, description: &str, params_schema: serde_json::Value) -> HostFnEntry {
    HostFnEntry {
        name: name.into(),
        description: description.into(),
        params_schema,
    }
}

pub fn tool(name: &str, description: &str, params_schema: serde_json::Value) -> ToolEntry {
    ToolEntry {
        name: name.into(),
        description: description.into(),
        params_schema,
    }
}

pub fn mcp(
    name: &str,
    description: &str,
    params_schema: serde_json::Value,
    server_id: &str,
) -> McpToolEntry {
    McpToolEntry {
        name: name.into(),
        description: description.into(),
        params_schema,
        server_id: server_id.into(),
    }
}

// ─── Slice-A mock inventory readers (unchanged) ───

#[derive(Default)]
pub struct MockCallableInventory {
    pub wasm: Mutex<Vec<ToolEntry>>,
    pub mcp: Mutex<Vec<McpToolEntry>>,
}

impl CallableInventoryReader for MockCallableInventory {
    fn list_wasm_tools(&self, _agent_id: &str) -> Vec<ToolEntry> {
        self.wasm.lock().unwrap().clone()
    }
    fn list_mcp_tools(&self, _agent_id: &str) -> Vec<McpToolEntry> {
        self.mcp.lock().unwrap().clone()
    }
}

#[derive(Default)]
pub struct MockHostFnInventory {
    pub host: Mutex<Vec<HostFnEntry>>,
}

impl HostFnInventoryReader for MockHostFnInventory {
    fn list_host_fns(&self, _agent_id: &str) -> Vec<HostFnEntry> {
        self.host.lock().unwrap().clone()
    }
}

// ─── Slice-B Null port doubles ───

pub struct NullAgentIdentity;
#[async_trait]
impl AgentIdentityReader for NullAgentIdentity {
    async fn agents_md_summary(&self, _agent_id: &str) -> Option<String> {
        None
    }
}

pub struct NullKnowledgeMap;
#[async_trait]
impl KnowledgeMapReader for NullKnowledgeMap {
    async fn read_knowledge_map(&self, _agent_id: &str) -> Option<KnowledgeMap> {
        None
    }
}

/// Empty agent tree (no nodes). Satisfies both `AgentTreeReader` and the
/// `AgentTreeSnapshot` supertrait.
pub struct NullAgentTreeSnapshot;

impl AgentTreeReader for NullAgentTreeSnapshot {
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
    fn capabilities(&self, _agent_id: &str) -> Vec<advance_shared_types::agent_tree::Capability> {
        Vec::new()
    }
}

impl AgentTreeSnapshot for NullAgentTreeSnapshot {
    fn snapshot(&self) -> AgentTreeSnapshotData {
        AgentTreeSnapshotData {
            nodes: Vec::new(),
            parent_of: std::collections::HashMap::new(),
            children_of: std::collections::HashMap::new(),
            peer_slug_map: std::collections::HashMap::new(),
            revision: 0,
        }
    }
}

/// Returns a fixed finite non-empty embedding (passes finite-value
/// hardening; the actual values are irrelevant when paired with
/// [`NullTaskIndex`], which returns no hits → `NewTask`).
pub struct NullEmbedding;
#[async_trait]
impl EmbeddingPort for NullEmbedding {
    async fn embed(&self, _text: &str) -> Result<Vec<f32>, PortError> {
        Ok(vec![0.0_f32, 1.0, 0.0])
    }
}

pub struct NullTaskIndex;
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

pub struct NullLightLlm;
#[async_trait]
impl LightLlmFallbackPort for NullLightLlm {
    async fn pick_one(&self, _query: &str, candidates: &[String]) -> Result<String, PortError> {
        candidates
            .first()
            .cloned()
            .ok_or_else(|| PortError("no candidates".into()))
    }
}

pub struct NullUnifiedSearch;
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

/// Slice-D no-op `EventBusEmit` double (canonical CONTRACT-180). Lets the
/// existing Slice-A/B/C tests construct the assembler through the unchanged
/// `build_assembler_with` signature — the AC-12 emission just drops on the
/// floor in those tests. T16 uses its own capturing spy instead.
pub struct NullEventBus;
impl EventBusEmit for NullEventBus {
    fn emit(&self, _event: Event) {}
}

/// Slice-V1-c no-op `SkillSummaryReader` double — returns no visible skills, so
/// the Tier-2 ⑩ `# Available Skills` section is omitted and the assembled output
/// stays byte-identical to pre-V1-c for the existing Slice-A/B/C/D test files.
/// Tests that exercise the section (`skill_l0_inject.rs`) use their own scored
/// fixture reader instead.
pub struct NullSkillSummary;
#[async_trait]
impl SkillSummaryReader for NullSkillSummary {
    async fn list_skill_summaries(&self, _agent_id: &str) -> Vec<SkillSummaryEntry> {
        Vec::new()
    }
}

// ─── Stage-C SAT-A Null L1-L6 reader doubles ───
//
// Empty doubles for the 6 L-reader ports the assembler injects (12th–17th
// dep). They return no content, so `coordinate_processing` yields an all-empty
// `MultiLevelContextDigest` → `render_multilevel_digest` emits no message →
// Tier-3 is byte-identical to pre-Stage-C output. The existing Slice-A/B/C/D
// test files keep compiling through the unchanged `build_assembler_with`
// signature; tests that exercise the fold (`processing_pipeline.rs` /
// the new assembler fold test) supply their own content-bearing fakes.

pub struct NullVectorIndex;
#[async_trait]
impl VectorIndexReader for NullVectorIndex {
    async fn lookup(&self, _agent_id: &str, _q: &[f32]) -> Result<Vec<VectorHit>, PortError> {
        Ok(Vec::new())
    }
}

pub struct NullL2Digest;
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

pub struct NullL3Epoch;
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

pub struct NullL4TaskSummary;
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

pub struct NullL5Synthesis;
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

pub struct NullL6Consolidation;
#[async_trait]
impl L6ConsolidationReader for NullL6Consolidation {
    async fn read_global_memory(
        &self,
        _agent_id: &str,
    ) -> Result<Vec<GlobalMemoryRecord>, PortError> {
        Ok(Vec::new())
    }
}

// ─── Stage-C SAT-E Null PromptInjectionHelpers double ───
//
// Empty/passthrough double for the 18th injected port (the canonical CONTRACT-114
// `PromptInjectionHelpers`). `flag_injection_patterns` → empty Vec;
// `wrap_with_boundary` → passthrough (returns `content` verbatim, NO `<data>`
// envelope), so the existing exact-content tests (e.g. multilevel_fold) stay
// byte-identical. Tests that exercise the live boundary-wrap ingress
// (`injection_ingress.rs`) supply their own content-bearing fake helper.
pub struct NullPromptInjectionHelpers;
impl PromptInjectionHelpers for NullPromptInjectionHelpers {
    fn flag_injection_patterns(&self, _content: &str) -> Vec<InjectionFlag> {
        Vec::new()
    }
    fn wrap_with_boundary(&self, content: &str, _source: &str, _trust: TrustLevel) -> String {
        content.to_string()
    }
}

// ─── Wave-12 Lane C Null DecompositionReader double ───
//
// Empty double for the 19th injected dep. Returns no subtasks, so
// `format_active_decomposition_section` returns `None` → no Tier-2 ⑭ message →
// the assembled output is byte-identical to pre-Wave-12. Existing test files keep
// compiling through the unchanged `build_assembler_with` signature.
pub struct NullDecomposition;
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

// ─── Assembler builders (PUBLIC SIGNATURES UNCHANGED) ───

/// Build an assembler with the given Slice-A inventories and `Null*` doubles
/// for every Slice-B port. Signature unchanged from Slice A so existing test
/// files compile without edits.
pub fn build_assembler_with(
    host_fns: Vec<HostFnEntry>,
    wasm: Vec<ToolEntry>,
    mcp: Vec<McpToolEntry>,
) -> ContextAssemblerImpl {
    let callable = MockCallableInventory {
        wasm: Mutex::new(wasm),
        mcp: Mutex::new(mcp),
    };
    let hostfn = MockHostFnInventory {
        host: Mutex::new(host_fns),
    };
    ContextAssemblerImpl::new(
        Arc::new(callable),
        Arc::new(hostfn),
        Arc::new(NullAgentIdentity),
        Arc::new(NullKnowledgeMap),
        Arc::new(NullAgentTreeSnapshot),
        Arc::new(NullEmbedding),
        Arc::new(NullTaskIndex),
        Arc::new(NullLightLlm),
        Arc::new(NullUnifiedSearch),
        // Slice D: 10th injected dep — canonical EventBusEmit (no-op double).
        Arc::new(NullEventBus),
        // Slice V1-c: 11th injected dep — SkillSummaryReader (empty double).
        Arc::new(NullSkillSummary),
        // Stage-C SAT-A: 12th–17th injected deps — the 6 L1-L6 reader ports
        // (empty doubles → empty digest → Tier-3 byte-identical).
        Arc::new(NullVectorIndex),
        Arc::new(NullL2Digest),
        Arc::new(NullL3Epoch),
        Arc::new(NullL4TaskSummary),
        Arc::new(NullL5Synthesis),
        Arc::new(NullL6Consolidation),
        // Stage-C SAT-E: 18th injected dep — PromptInjectionHelpers (passthrough
        // double → no `<data>` envelope → byte-identical exact-content tests).
        Arc::new(NullPromptInjectionHelpers),
        // Wave-12 Lane C: 19th injected dep — DecompositionReader (empty double →
        // no Tier-2 ⑭ section → byte-identical existing tests).
        Arc::new(NullDecomposition),
    )
}

pub fn build_assembler_with_empty_inventories() -> ContextAssemblerImpl {
    build_assembler_with(Vec::new(), Vec::new(), Vec::new())
}

/// Build an assembler with empty inventories + Null doubles for every port
/// EXCEPT the Wave-12 Lane C `DecompositionReader`, which is the caller-supplied
/// double. Lets a test drive the Tier-2 ⑭ "Active Task Decomposition" section from
/// a fixture without changing the FROZEN `build_assembler_with` signature.
pub fn build_assembler_with_decomposition(
    decomposition: Arc<dyn DecompositionReader>,
) -> ContextAssemblerImpl {
    ContextAssemblerImpl::new(
        Arc::new(MockCallableInventory {
            wasm: Mutex::new(Vec::new()),
            mcp: Mutex::new(Vec::new()),
        }),
        Arc::new(MockHostFnInventory {
            host: Mutex::new(Vec::new()),
        }),
        Arc::new(NullAgentIdentity),
        Arc::new(NullKnowledgeMap),
        Arc::new(NullAgentTreeSnapshot),
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
        decomposition,
    )
}

/// Configurable `DecompositionReader` test double — returns the given subtasks
/// for ANY (agent_id, task_id), so a test can drive the assembled Tier-2 ⑭
/// section deterministically. (The task_id-scoping + non-orphaned filtering live
/// in the cli `CapDecompositionReader` adapter, exercised by its own witness.)
pub struct FixtureDecomposition(pub Vec<SubtaskView>);
#[async_trait]
impl DecompositionReader for FixtureDecomposition {
    async fn read_active_subtasks(
        &self,
        _agent_id: &str,
        _task_id: Option<&str>,
    ) -> Vec<SubtaskView> {
        self.0.clone()
    }
}

// ─── Stub AssemblyContext ───

pub fn stub_ctx() -> AssemblyContext {
    AssemblyContext {
        agent_id: "agent-default".into(),
        task_id: None,
        message: stub_message(),
        prompt: String::new(),
        model: "test-model".into(),
        turn_buffer: Vec::<LlmMessage>::new(),
        prior_state: stub_agent_state(),
    }
}

fn stub_message() -> Message {
    Message {
        id: "msg-stub".into(),
        kind: MessageKind::User,
        from: "agent-default".into(),
        to: "agent-default".into(),
        payload: Vec::new(),
        context: None,
        timestamp: SystemTime::UNIX_EPOCH,
        origin: None,
    }
}

fn stub_agent_state() -> AgentState {
    AgentState {
        agent_id: "agent-default".into(),
        status: AgentStatus::Active,
        current_task_id: None,
        current_run_id: None,
        iteration: 0,
        turn_counter: 0,
        last_handle_message_at: None,
    }
}

// ─── Assembled-output helpers ───

pub fn find_tier2_section(messages: &[LlmMessage]) -> String {
    messages
        .iter()
        .find(|m| m.content.starts_with("# Available Tools"))
        .map(|m| m.content.clone())
        .expect("Tier 2 `# Available Tools` section missing from assembled output")
}

// ─── Slice-B agent-tree fixture builder (for tier2_delegates tests) ───

/// A `AgentTreeSnapshot` backed by a fixed node list (for AC-19 / T23).
pub struct FixtureTree {
    pub nodes: Vec<advance_shared_types::agent_tree::AgentNode>,
}

impl AgentTreeReader for FixtureTree {
    fn parent_of(&self, agent_id: &str) -> Option<String> {
        self.nodes
            .iter()
            .find(|n| n.id.0 == agent_id)
            .and_then(|n| n.parent.as_ref().map(|p| p.0.clone()))
    }
    fn children_of(&self, agent_id: &str) -> Vec<String> {
        let key = AgentId(agent_id.to_string());
        self.nodes
            .iter()
            .filter(|n| n.parent.as_ref() == Some(&key))
            .map(|n| n.id.0.clone())
            .collect()
    }
    fn siblings_of(&self, _agent_id: &str) -> Vec<String> {
        Vec::new()
    }
    fn agent_exists(&self, agent_id: &str) -> bool {
        self.nodes.iter().any(|n| n.id.0 == agent_id)
    }
    fn agent_kind(&self, agent_id: &str) -> Option<AgentKind> {
        self.nodes
            .iter()
            .find(|n| n.id.0 == agent_id)
            .map(|n| n.kind.clone())
    }
    fn capabilities(&self, agent_id: &str) -> Vec<advance_shared_types::agent_tree::Capability> {
        self.nodes
            .iter()
            .find(|n| n.id.0 == agent_id)
            .map(|n| n.capabilities.clone())
            .unwrap_or_default()
    }
}

impl AgentTreeSnapshot for FixtureTree {
    fn snapshot(&self) -> AgentTreeSnapshotData {
        AgentTreeSnapshotData {
            nodes: self.nodes.clone(),
            parent_of: std::collections::HashMap::new(),
            children_of: std::collections::HashMap::new(),
            peer_slug_map: std::collections::HashMap::new(),
            revision: 1,
        }
    }
}
