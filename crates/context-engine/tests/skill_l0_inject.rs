//! MODULE-010-T19 (AC-15 / REQ-264) — Skill L0 summaries injected in Tier 2 ⑩
//! `# Available Skills`, capped at `min(skill_budget_tokens, ⌊budget·0.05⌋, 10K)`.
//!
//! The cap is witnessed in BOTH regimes so the AC-15 ceiling holds generally,
//! not at a single hand-picked model:
//!   - small-model (test-model, window 8192): cap == ⌊budget·0.05⌋ (the AC-15
//!     dynamic term dominates — exact-formula witness);
//!   - large-model (claude, window 200000): cap == skill_budget_tokens (2000)
//!     AND ≤ ⌊budget·0.05⌋ (ceiling-not-equality witness).
//! Plus: over-cap drops lowest-score; zero-skills omits the section; untrusted
//! content is sanitized; the AC-18 tools section is still present and follows ⑩.

use std::sync::Arc;

use advance_context_engine::{
    model_context_window, response_reserve, ContextAssemblerImpl, SkillSummaryEntry,
    SkillSummaryReader, SKILL_BUDGET_TOKENS_DEFAULT,
};
use advance_shared_types::context::{AssemblyContext, ContextAssembler, LlmMessage};
use advance_shared_types::token_estimate::tokens_from_bytes;
use async_trait::async_trait;

#[path = "common/mod.rs"]
mod common;
use common::*;

/// Fixture reader returning a fixed scored skill list.
struct FixtureSkills(Vec<SkillSummaryEntry>);
#[async_trait]
impl SkillSummaryReader for FixtureSkills {
    async fn list_skill_summaries(&self, _agent_id: &str) -> Vec<SkillSummaryEntry> {
        self.0.clone()
    }
}

fn skill(name: &str, summary: &str, score: f32) -> SkillSummaryEntry {
    SkillSummaryEntry {
        name: name.into(),
        summary: summary.into(),
        score,
    }
}

/// Build an assembler whose only non-Null dep is the skill-summary reader.
fn assembler_with_skills(skills: Vec<SkillSummaryEntry>) -> ContextAssemblerImpl {
    ContextAssemblerImpl::new(
        Arc::new(MockCallableInventory::default()),
        Arc::new(MockHostFnInventory::default()),
        Arc::new(NullAgentIdentity),
        Arc::new(NullKnowledgeMap),
        Arc::new(NullAgentTreeSnapshot),
        Arc::new(NullEmbedding),
        Arc::new(NullTaskIndex),
        Arc::new(NullLightLlm),
        Arc::new(NullUnifiedSearch),
        Arc::new(NullEventBus),
        Arc::new(FixtureSkills(skills)),
        Arc::new(NullVectorIndex),
        Arc::new(NullL2Digest),
        Arc::new(NullL3Epoch),
        Arc::new(NullL4TaskSummary),
        Arc::new(NullL5Synthesis),
        Arc::new(NullL6Consolidation),
        Arc::new(NullPromptInjectionHelpers),
        Arc::new(NullDecomposition),
    )
}

fn ctx_for_model(model: &str) -> AssemblyContext {
    let mut c = stub_ctx();
    c.model = model.into();
    c
}

/// Workspace `chars/4` byte-length token estimate (matches the assembler).
fn approx_tokens(byte_len: usize) -> usize {
    tokens_from_bytes(byte_len)
}

fn skills_section(messages: &[LlmMessage]) -> Option<String> {
    messages
        .iter()
        .find(|m| m.content.starts_with("# Available Skills"))
        .map(|m| m.content.clone())
}

/// Re-derive the effective cap from the exported budget primitives — keeps the
/// assertions tied to the real formula, not a hardcoded value.
fn expected_cap(model: &str) -> u32 {
    let limit = model_context_window(model);
    let budget = limit - response_reserve(limit);
    SKILL_BUDGET_TOKENS_DEFAULT
        .min((budget / 20) as u32)
        .min(10_000)
}

const SMALL_MODEL: &str = "test-model";
const LARGE_MODEL: &str = "claude-3-5-sonnet-20241022";

#[tokio::test]
async fn injects_all_summaries_when_under_cap() {
    let asm = assembler_with_skills(vec![
        skill("alpha", "first skill summary", 0.9),
        skill("beta", "second skill summary", 0.5),
    ]);
    let res = asm.assemble(ctx_for_model(LARGE_MODEL)).await.unwrap();
    let sec = skills_section(&res.messages).expect("# Available Skills present");
    assert!(sec.contains("- alpha: first skill summary"));
    assert!(sec.contains("- beta: second skill summary"));
    // Higher score injected first.
    assert!(sec.find("- alpha:").unwrap() < sec.find("- beta:").unwrap());
}

#[tokio::test]
async fn small_model_cap_is_floor_budget_times_005_and_truncates_lowest_score() {
    // test-model → window 8192 → budget 6964 → ⌊6964·0.05⌋ = 348; the dynamic
    // term dominates (< 2000) → this IS the AC-15 `min(budget·0.05, 10K)` value.
    let cap = expected_cap(SMALL_MODEL);
    assert_eq!(cap, 348, "AC-15 dynamic term ⌊(8192-1228)·0.05⌋");

    // 10 skills of ~95-token summaries (far over 348). score increases with i.
    let many: Vec<_> = (0..10)
        .map(|i| skill(&format!("s{i:02}"), &"x".repeat(380), i as f32))
        .collect();
    let asm = assembler_with_skills(many);
    let res = asm.assemble(ctx_for_model(SMALL_MODEL)).await.unwrap();
    let sec = skills_section(&res.messages).expect("section present");

    // Section honors the cap.
    assert!(
        approx_tokens(sec.len()) <= cap as usize,
        "section {} tok exceeds cap {cap}",
        approx_tokens(sec.len())
    );
    // Truncated to the highest-score prefix: top kept, bottom dropped.
    assert!(sec.contains("- s09:"), "highest-score skill kept");
    assert!(!sec.contains("- s00:"), "lowest-score skill dropped");
    let present = (0..10)
        .filter(|i| sec.contains(&format!("- s{i:02}:")))
        .count();
    assert!(
        (1..10).contains(&present),
        "expected partial truncation, got {present}/10"
    );
}

#[tokio::test]
async fn large_model_cap_is_skill_budget_default_under_ceiling() {
    // claude → window 200000 → budget 170000 → ⌊·0.05⌋ = 8500; the 2000 default
    // dominates and is strictly below the ceiling (ceiling-not-equality).
    let limit = model_context_window(LARGE_MODEL);
    let budget = limit - response_reserve(limit);
    let dynamic = (budget / 20) as u32;
    let cap = expected_cap(LARGE_MODEL);
    assert_eq!(cap, SKILL_BUDGET_TOKENS_DEFAULT, "default 2000 dominates");
    assert!(
        cap < dynamic,
        "2000 < ceiling {dynamic} (capped-at = ceiling, not equality)"
    );

    // Same 10 skills as the small-model case → more fit under 2000 than 348.
    let many: Vec<_> = (0..10)
        .map(|i| skill(&format!("s{i:02}"), &"x".repeat(380), i as f32))
        .collect();
    let asm = assembler_with_skills(many);
    let res = asm.assemble(ctx_for_model(LARGE_MODEL)).await.unwrap();
    let sec = skills_section(&res.messages).expect("section present");
    assert!(approx_tokens(sec.len()) <= cap as usize);
    // 10 × ~97 tok + header ≈ 975 tok ≤ 2000 → all fit.
    let present = (0..10)
        .filter(|i| sec.contains(&format!("- s{i:02}:")))
        .count();
    assert_eq!(present, 10, "all 10 skills fit under the 2000-token cap");
}

#[tokio::test]
async fn zero_skills_omits_section_but_tools_section_remains() {
    let asm = assembler_with_skills(vec![]);
    let res = asm.assemble(ctx_for_model(LARGE_MODEL)).await.unwrap();
    assert!(
        skills_section(&res.messages).is_none(),
        "no visible skills → no `# Available Skills` section"
    );
    // V1-b AC-18 surface intact.
    assert!(
        res.messages
            .iter()
            .any(|m| m.content.starts_with("# Available Tools")),
        "`# Available Tools` still present"
    );
}

#[tokio::test]
async fn untrusted_summary_is_sanitized() {
    let asm = assembler_with_skills(vec![skill(
        "nm",
        "danger\u{202E}reversed and\nnewline",
        1.0,
    )]);
    let res = asm.assemble(ctx_for_model(LARGE_MODEL)).await.unwrap();
    let sec = skills_section(&res.messages).expect("section");
    assert!(!sec.contains('\u{202E}'), "BiDi override neutralized");
    assert!(
        sec.contains("- nm: danger"),
        "line present + name preserved"
    );
}

#[tokio::test]
async fn skills_section_precedes_tools_section() {
    let asm = assembler_with_skills(vec![skill("a", "sum", 1.0)]);
    let res = asm.assemble(ctx_for_model(LARGE_MODEL)).await.unwrap();
    let skill_pos = res
        .messages
        .iter()
        .position(|m| m.content.starts_with("# Available Skills"))
        .expect("skills section");
    let tools_pos = res
        .messages
        .iter()
        .position(|m| m.content.starts_with("# Available Tools"))
        .expect("tools section");
    assert!(skill_pos < tools_pos, "Tier-2 ⑩ Skills precede ⑪/⑫ Tools");
}
