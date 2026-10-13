//! Runtime-info sections (Tier 1a ②/③ + Tier 1b ⑦/⑧), the Tier-2 ⑭ L4/L5
//! placement, the one-embedding-per-turn memo, recall snippets, real routing
//! telemetry and the per-turn `AssemblyReport` sink.

#[path = "common/mod.rs"]
mod common;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use advance_context_engine::{
    AssemblyReport, AssemblyReportSink, ContextAssemblerImpl, EmbeddingPort, L4TaskSummaryReader,
    L5SynthesisReader, PortError, RuntimeInfoReader, RuntimeInfoView, SynthesisView, TaskHit,
    TaskIndexPort, TaskSummaryView, TurnHit, UnifiedSearchPort, UnifiedSearchResult,
    ROUTING_METHOD_SEARCH,
};
use advance_shared_types::context::{ContextAssembler, LlmMessage};
use async_trait::async_trait;
use common::*;

struct FixtureRuntimeInfo(RuntimeInfoView);
#[async_trait]
impl RuntimeInfoReader for FixtureRuntimeInfo {
    async fn runtime_info(&self, _agent_id: &str) -> Option<RuntimeInfoView> {
        Some(self.0.clone())
    }
}

#[derive(Default)]
struct CapturingSink(Mutex<Vec<AssemblyReport>>);
impl AssemblyReportSink for CapturingSink {
    fn record(&self, report: AssemblyReport) {
        self.0.lock().unwrap().push(report);
    }
}

/// Counts `embed` calls and returns a fixed finite vector.
struct CountingEmbedding(Arc<AtomicUsize>);
#[async_trait]
impl EmbeddingPort for CountingEmbedding {
    async fn embed(&self, _text: &str) -> Result<Vec<f32>, PortError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(vec![1.0, 0.0])
    }
}

struct FixtureSearch;
#[async_trait]
impl UnifiedSearchPort for FixtureSearch {
    async fn search(
        &self,
        _agent_id: &str,
        _query: &str,
        _q: &[f32],
    ) -> Result<UnifiedSearchResult, PortError> {
        Ok(UnifiedSearchResult {
            turns: vec![TurnHit {
                id: "turn-3".into(),
                task_id: "old-task".into(),
                similarity: 0.81,
                timestamp: SystemTime::UNIX_EPOCH,
                snippet: Some("User asked to deploy\nthe service".into()),
            }],
            ..Default::default()
        })
    }
}

struct FixtureTaskIndex(Vec<TaskHit>);
#[async_trait]
impl TaskIndexPort for FixtureTaskIndex {
    async fn top_n_by_similarity(
        &self,
        _agent_id: &str,
        _q: &[f32],
        _n: usize,
    ) -> Result<Vec<TaskHit>, PortError> {
        Ok(self.0.clone())
    }
}

struct FixtureL4(Option<TaskSummaryView>);
#[async_trait]
impl L4TaskSummaryReader for FixtureL4 {
    async fn read_task_summary(
        &self,
        _a: &str,
        _t: &str,
    ) -> Result<Option<TaskSummaryView>, PortError> {
        Ok(self.0.clone())
    }
}

struct FixtureL5(Vec<SynthesisView>);
#[async_trait]
impl L5SynthesisReader for FixtureL5 {
    async fn read_syntheses(&self, _a: &str, _t: &str) -> Result<Vec<SynthesisView>, PortError> {
        Ok(self.0.clone())
    }
}

fn runtime_view() -> RuntimeInfoView {
    RuntimeInfoView {
        runtime_version: "0.1.40".into(),
        agent_kind: Some("root".into()),
        parent_agent: None,
        workspace: Some("ws".into()),
        capabilities: vec!["llm".into(), "memory".into()],
        mode: Some("serve".into()),
        llm_provider: Some("openai".into()),
        llm_model: Some("gpt-4o".into()),
        memory_enabled: true,
        skills_enabled: false,
        embedding_enabled: true,
    }
}

#[allow(clippy::too_many_arguments)]
fn assembler(
    embedding: Arc<dyn EmbeddingPort>,
    task_index: Arc<dyn TaskIndexPort>,
    search: Arc<dyn UnifiedSearchPort>,
    l4: Arc<dyn L4TaskSummaryReader>,
    l5: Arc<dyn L5SynthesisReader>,
) -> ContextAssemblerImpl {
    ContextAssemblerImpl::new(
        Arc::new(MockCallableInventory::default()),
        Arc::new(MockHostFnInventory::default()),
        Arc::new(NullAgentIdentity),
        Arc::new(NullKnowledgeMap),
        Arc::new(NullAgentTreeSnapshot),
        embedding,
        task_index,
        Arc::new(NullLightLlm),
        search,
        Arc::new(NullEventBus),
        Arc::new(NullSkillSummary),
        Arc::new(NullVectorIndex),
        Arc::new(NullL2Digest),
        Arc::new(NullL3Epoch),
        l4,
        l5,
        Arc::new(NullL6Consolidation),
        Arc::new(NullPromptInjectionHelpers),
        Arc::new(NullDecomposition),
    )
}

fn idx_of(msgs: &[LlmMessage], prefix: &str) -> usize {
    msgs.iter()
        .position(|m| m.content.starts_with(prefix))
        .unwrap_or_else(|| panic!("section {prefix:?} missing"))
}

#[tokio::test]
async fn runtime_sections_land_in_tier1a_and_tier1b() {
    let sink = Arc::new(CapturingSink::default());
    let asm = assembler(
        Arc::new(NullEmbedding),
        Arc::new(NullTaskIndex),
        Arc::new(NullUnifiedSearch),
        Arc::new(NullL4TaskSummary),
        Arc::new(NullL5Synthesis),
    )
    .with_runtime_info(Arc::new(FixtureRuntimeInfo(runtime_view())))
    .with_report_sink(sink.clone());
    let mut ctx = stub_ctx();
    ctx.model = "gpt-4o".into();
    ctx.prompt = "hello".into();

    let res = asm.assemble(ctx).await.unwrap();
    let m = &res.messages;
    let arch = idx_of(m, "# Runtime Architecture");
    let sec = idx_of(m, "# Security Model");
    let state = idx_of(m, "# Runtime State");
    let bp1 = idx_of(m, "<!-- ctx-cache-breakpoint:1b->2 -->");
    assert!(
        arch < sec && sec < state && state < bp1,
        "1a → 1b → breakpoint"
    );
    assert!(m[state].content.contains("- context window: 128000 tokens"));

    let reports = sink.0.lock().unwrap();
    let r = &reports[0];
    assert_eq!(r.model_context_window, 128_000);
    assert_eq!(r.progressive_mode, "wide");
    assert!(!r.degraded);
    let tier_of = |label: &str| {
        r.sections
            .iter()
            .find(|s| s.label == label)
            .map(|s| s.tier.clone())
            .unwrap_or_else(|| panic!("section {label} missing from report"))
    };
    assert_eq!(tier_of("Runtime Architecture"), "1a");
    assert_eq!(tier_of("Security Model"), "1a");
    assert_eq!(tier_of("Runtime State"), "1b");
    assert_eq!(tier_of("Available Tools"), "2");
    assert_eq!(tier_of("user prompt"), "3");
    // Per-section tokens round per message; the tier totals round once per
    // tier — so the section sum is within one token per section of the total.
    let sum: u32 = r.sections.iter().map(|s| s.tokens).sum();
    let total = r.tier1a_tokens + r.tier1b_tokens + r.tier2_tokens + r.tier3_tokens;
    assert!(
        sum >= total && sum - total <= r.sections.len() as u32,
        "per-section tokens ({sum}) track the tier totals ({total})"
    );
    assert_eq!(r.used_tokens + r.remaining_tokens, r.budget_tokens);
}

#[tokio::test]
async fn no_runtime_info_omits_all_three_sections() {
    let asm = build_assembler_with_empty_inventories();
    let res = asm.assemble(stub_ctx()).await.unwrap();
    assert!(!res.messages.iter().any(|m| {
        m.content.starts_with("# Runtime Architecture")
            || m.content.starts_with("# Security Model")
            || m.content.starts_with("# Runtime State")
    }));
}

#[tokio::test]
async fn l4_summary_and_l5_briefs_render_in_tier2() {
    let asm = assembler(
        Arc::new(NullEmbedding),
        Arc::new(NullTaskIndex),
        Arc::new(NullUnifiedSearch),
        Arc::new(FixtureL4(Some(TaskSummaryView {
            task_id: "t".into(),
            summary: "the task brief".into(),
        }))),
        Arc::new(FixtureL5(vec![
            SynthesisView {
                task_id: "a".into(),
                body: "brief a".into(),
            },
            SynthesisView {
                task_id: "b".into(),
                body: "   ".into(),
            },
            SynthesisView {
                task_id: "c".into(),
                body: "brief c".into(),
            },
        ])),
    );
    let mut ctx = stub_ctx();
    ctx.task_id = Some("t".into());
    ctx.prompt = "go".into();
    let res = asm.assemble(ctx).await.unwrap();
    let m = &res.messages;
    let bp1 = idx_of(m, "<!-- ctx-cache-breakpoint:1b->2 -->");
    let bp2 = idx_of(m, "<!-- ctx-cache-breakpoint:2->3 -->");
    let ts = idx_of(m, "# Task Summary");
    let syn = idx_of(m, "# Task Syntheses");
    assert!(bp1 < ts && ts < syn && syn < bp2, "L4/L5 sit in Tier 2");
    assert!(m[syn].content.contains("brief a") && m[syn].content.contains("brief c"));
    assert!(res.tier_token_counts.tier2 > 0);
}

#[tokio::test]
async fn prompt_is_embedded_once_and_recall_carries_snippets() {
    let calls = Arc::new(AtomicUsize::new(0));
    let sink = Arc::new(CapturingSink::default());
    let asm = assembler(
        Arc::new(CountingEmbedding(calls.clone())),
        Arc::new(FixtureTaskIndex(vec![TaskHit {
            task_id: "old-task".into(),
            similarity: 0.9,
            last_turn_at: None,
            snippet: None,
        }])),
        Arc::new(FixtureSearch),
        Arc::new(NullL4TaskSummary),
        Arc::new(NullL5Synthesis),
    )
    .with_report_sink(sink.clone());
    let mut ctx = stub_ctx();
    ctx.prompt = "deploy it again".into();

    let res = asm.assemble(ctx).await.unwrap();
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "L1 + recall + routing share ONE query embedding"
    );
    let recall = &res.messages[idx_of(&res.messages, "# Recalled Context")];
    assert!(
        recall
            .content
            .contains("- turn-3 (0.810) — User asked to deploy the service"),
        "snippet rendered single-line: {}",
        recall.content
    );
    // Routing: the task index matched above threshold → existing task, real
    // confidence + method.
    assert!(!res.is_new_task);
    assert_eq!(res.routing_method, ROUTING_METHOD_SEARCH);
    assert!((res.routing_confidence - 0.9).abs() < 1e-6);

    let reports = sink.0.lock().unwrap();
    assert!(reports[0].recall.attempted);
    assert_eq!(reports[0].recall.turns, 1);
    assert!((reports[0].routing_confidence - 0.9).abs() < 1e-6);
}

#[tokio::test]
async fn blank_prompt_skips_embedding_and_routing() {
    let calls = Arc::new(AtomicUsize::new(0));
    let asm = assembler(
        Arc::new(CountingEmbedding(calls.clone())),
        Arc::new(NullTaskIndex),
        Arc::new(FixtureSearch),
        Arc::new(NullL4TaskSummary),
        Arc::new(NullL5Synthesis),
    );
    let mut ctx = stub_ctx();
    ctx.prompt = "   ".into();
    let res = asm.assemble(ctx).await.unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert!(res.is_new_task);
    assert_eq!(res.routing_confidence, 0.0);
    assert!(!res
        .messages
        .iter()
        .any(|m| m.content.starts_with("# Recalled Context")));
}

#[tokio::test]
async fn l0_compression_applies_to_turn_buffer_history() {
    let sink = Arc::new(CapturingSink::default());
    let asm = assembler(
        Arc::new(NullEmbedding),
        Arc::new(NullTaskIndex),
        Arc::new(NullUnifiedSearch),
        Arc::new(NullL4TaskSummary),
        Arc::new(NullL5Synthesis),
    )
    .with_report_sink(sink.clone());
    let mut ctx = stub_ctx();
    ctx.model = "claude-3-5-sonnet".into();
    ctx.prompt = "next".into();
    ctx.turn_buffer = vec![
        LlmMessage {
            role: "user".into(),
            content: "q".into(),
        },
        LlmMessage {
            role: "tool".into(),
            content: "fs.read a.rs".into(),
        },
        LlmMessage {
            role: "tool".into(),
            content: "fs.read a.rs".into(),
        },
        LlmMessage {
            role: "assistant".into(),
            content: "Read it.".into(),
        },
    ];
    let res = asm.assemble(ctx).await.unwrap();
    let reads = res
        .messages
        .iter()
        .filter(|m| m.content == "fs.read a.rs")
        .count();
    assert_eq!(reads, 1, "the superseded duplicate read is dropped");
    let r = &sink.0.lock().unwrap()[0];
    assert_eq!(r.history.turn_buffer_in, 4);
    assert_eq!(r.history.l0_compressed, 1);
    assert_eq!(r.history.turn_buffer_kept, 3);
}

#[tokio::test]
async fn model_window_override_wins_over_table() {
    let sink = Arc::new(CapturingSink::default());
    let asm = assembler(
        Arc::new(NullEmbedding),
        Arc::new(NullTaskIndex),
        Arc::new(NullUnifiedSearch),
        Arc::new(NullL4TaskSummary),
        Arc::new(NullL5Synthesis),
    )
    .with_model_context_window(Some(32_000))
    .with_report_sink(sink.clone());
    let mut ctx = stub_ctx();
    ctx.model = "gpt-4o".into();
    asm.assemble(ctx).await.unwrap();
    assert_eq!(sink.0.lock().unwrap()[0].model_context_window, 32_000);
}
