//! Wave-13 Lane C build-lane witness (MODULE-010 §3.8 Wave-13 Lane C).
//!
//! Proves the read-path mechanism: `assemble()` runs `unified_search` over a
//! POPULATED `AgentSearchCorpus` with a REAL deterministic `HashingEmbedding`
//! and folds an omit-when-empty, boundary-marked recall section into Tier-3
//! (after the 2→3 cache breakpoint). This is NOT a SYS-AC flip (satellite) —
//! production stays byte-identical (empty corpus → no section), proven by the
//! `empty_corpus_yields_no_recall_section` discriminator.

use std::collections::HashMap;
use std::sync::Arc;

use advance_context_engine::{
    build_agent_search_corpus, AgentSearchCorpus, ContextAssemblerImpl, CorpusDoc,
    HashingEmbedding, RankingUnifiedSearch,
};
use advance_shared_types::context::{AssemblyContext, ContextAssembler, LlmMessage};
use advance_shared_types::security_validator::{InjectionFlag, PromptInjectionHelpers, TrustLevel};

#[path = "common/mod.rs"]
mod common;
use common::*;

// Content-bearing CONTRACT-114 helper (mirrors `injection_ingress::FakeWrapHelper`):
// `NullPromptInjectionHelpers` is passthrough, so the `[[WRAP …]]` envelope is
// only observable with a content-bearing helper.
struct FakeWrapHelper;
impl PromptInjectionHelpers for FakeWrapHelper {
    fn flag_injection_patterns(&self, _content: &str) -> Vec<InjectionFlag> {
        Vec::new()
    }
    fn wrap_with_boundary(&self, content: &str, source: &str, trust: TrustLevel) -> String {
        let t = match trust {
            TrustLevel::Trusted => "trusted",
            TrustLevel::Untrusted => "untrusted",
        };
        format!("[[WRAP src={source} trust={t}]]{content}[[/WRAP]]")
    }
}

/// = `stub_ctx().agent_id`. `RankingUnifiedSearch::search` does a literal
/// `corpora.get(agent_id)` (no alias fallback), so the corpus MUST be keyed here.
const AGENT: &str = "agent-default";

/// The exact `TIER2_TIER3_BREAKPOINT` marker literal (the constant is
/// `pub(crate)` / not re-exported, so an integration test matches the literal).
const BREAKPOINT_2: &str = "<!-- ctx-cache-breakpoint:2->3 -->";

/// Wide-budget ctx with a NON-EMPTY query prompt. The recall path embeds
/// `ctx.prompt`; an empty/whitespace prompt → `HashingEmbedding` all-zero vector
/// → cosine `None` for every row → no hit (a false negative). The Wide model
/// keeps the recall out of the budget-overflow degraded branch.
fn wide_ctx(prompt: &str) -> AssemblyContext {
    let mut c = stub_ctx();
    c.model = "claude-3-5-sonnet-20241022".into();
    c.prompt = prompt.into();
    c
}

/// An assembler with a REAL embedder (6th), the given corpus-backed
/// `unified_search` port (9th, keyed under exactly `AGENT`), and a
/// content-bearing `FakeWrapHelper` (18th); all other 16 ports are Null doubles.
fn assembler_with_corpus(corpus: AgentSearchCorpus) -> ContextAssemblerImpl {
    let mut map: HashMap<String, AgentSearchCorpus> = HashMap::new();
    map.insert(AGENT.to_string(), corpus);
    ContextAssemblerImpl::new(
        Arc::new(MockCallableInventory::default()),
        Arc::new(MockHostFnInventory::default()),
        Arc::new(NullAgentIdentity),
        Arc::new(NullKnowledgeMap),
        Arc::new(NullAgentTreeSnapshot),
        Arc::new(HashingEmbedding::default()), // 6th — REAL deterministic embedder
        Arc::new(NullTaskIndex),
        Arc::new(NullLightLlm),
        Arc::new(RankingUnifiedSearch::new(map)), // 9th — corpus-backed real search
        Arc::new(NullEventBus),
        Arc::new(NullSkillSummary),
        Arc::new(NullVectorIndex),
        Arc::new(NullL2Digest),
        Arc::new(NullL3Epoch),
        Arc::new(NullL4TaskSummary),
        Arc::new(NullL5Synthesis),
        Arc::new(NullL6Consolidation),
        Arc::new(FakeWrapHelper), // 18th — content-bearing → wrap envelope visible
        Arc::new(NullDecomposition),
    )
}

fn recall_msg_index(messages: &[LlmMessage]) -> Option<usize> {
    messages
        .iter()
        .position(|m| m.content.contains("# Recalled Context"))
}

fn breakpoint2_index(messages: &[LlmMessage]) -> usize {
    messages
        .iter()
        .position(|m| m.content == BREAKPOINT_2)
        .expect("the 2->3 cache breakpoint marker must be present")
}

#[tokio::test]
async fn recall_reaches_prompt_over_populated_corpus() {
    let embedder = HashingEmbedding::default();
    let docs = vec![
        CorpusDoc::content(
            "deploy-doc",
            "the deploy script runs cargo build then rsync to prod",
        ),
        CorpusDoc::memory(
            "pref-dark",
            "the user prefers dark mode and concise answers",
        ),
    ];
    let corpus = build_agent_search_corpus(&docs, &embedder).await;
    // The corpus is genuinely populated (both sources, real embeddings invoked).
    assert_eq!(corpus.contents.len(), 1, "files corpus populated");
    assert_eq!(corpus.memories.len(), 1, "memory corpus populated");

    let asm = assembler_with_corpus(corpus);
    let res = asm
        .assemble(wide_ctx(
            "how does the deploy script work and what are the user's preferences?",
        ))
        .await
        .expect("assemble succeeds");

    // POSITIVE assertions — a miss (empty prompt / mis-key / non-overlap) fails loudly.
    let recall_idx = recall_msg_index(&res.messages).expect("# Recalled Context section present");
    let recall = &res.messages[recall_idx].content;
    assert!(
        recall.contains("[[WRAP src=memory:recall trust=untrusted]]"),
        "recall body is boundary-marked (CONTRACT-114 untrusted): {recall}"
    );
    assert!(
        recall.contains("## Files") && recall.contains("deploy-doc"),
        "files hit: {recall}"
    );
    assert!(
        recall.contains("## Memory") && recall.contains("pref-dark"),
        "memory hit: {recall}"
    );

    // POSITIONAL Tier-3 placement: recall sits AFTER the 2->3 cache breakpoint
    // (query-dependent recall must never bust the Tier-2 cache).
    assert!(
        recall_idx > breakpoint2_index(&res.messages),
        "recall must land in Tier-3 (after the 2->3 breakpoint)"
    );
}

#[tokio::test]
async fn empty_corpus_yields_no_recall_section() {
    // Discriminator: SAME real embedder + SAME non-empty prompt, vary ONLY the
    // corpus (empty) → `RankingUnifiedSearch` finds the bucket but ranks zero
    // rows → empty result → `format_recall_section` None → no section. Holding
    // embed + prompt fixed ensures the empty-state arises from the empty corpus
    // (the production mechanism), NOT an EmbeddingFailed/empty-prompt route.
    let asm = assembler_with_corpus(AgentSearchCorpus::default());
    let res = asm
        .assemble(wide_ctx(
            "how does the deploy script work and what are the user's preferences?",
        ))
        .await
        .expect("assemble succeeds");
    assert!(
        recall_msg_index(&res.messages).is_none(),
        "empty corpus must yield NO recall section (byte-identical empty-state)"
    );
    // No stray recall envelope leaked anywhere.
    assert!(!res
        .messages
        .iter()
        .any(|m| m.content.contains("memory:recall")));
}

#[tokio::test]
async fn recall_is_local_not_provider() {
    // SYS-AC-005 angle (build-lane): recall is sourced ENTIRELY from the local
    // corpus + local `EmbeddingPort` — no LLM/provider participates in the recall
    // path. Context is rebuilt locally each call, independent of provider state.
    let embedder = HashingEmbedding::default();
    let docs = vec![CorpusDoc::memory(
        "pref-dark",
        "the user prefers dark mode and concise replies",
    )];
    let corpus = build_agent_search_corpus(&docs, &embedder).await;
    let asm = assembler_with_corpus(corpus);
    let res = asm
        .assemble(wide_ctx("what are the user's preferences?"))
        .await
        .unwrap();
    let recall = recall_msg_index(&res.messages).map(|i| res.messages[i].content.clone());
    assert!(
        recall
            .as_deref()
            .map(|r| r.contains("pref-dark"))
            .unwrap_or(false),
        "recall is rebuilt from the LOCAL unified_search corpus, not provider state"
    );
}
