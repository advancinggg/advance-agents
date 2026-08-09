//! Stage-C SAT-E (MODULE-010 §3.8) — the live L4/L5 untrusted-content injection
//! ingress: `assemble()` → `render_multilevel_digest` routes the untrusted L4
//! task-summary AND L5 cross-task synthesis bodies through the injected
//! canonical CONTRACT-114 `PromptInjectionHelpers` (AC-14 layer-2 boundary
//! marking), wrapped EXACTLY ONCE, then preserves the cache-breakpoint defense.
//!
//! These are WIRING witnesses: a content-bearing fake helper proves the
//! assembler ROUTES L4/L5 bodies through the 18th port + folds L5 (rendered for
//! the first time) + preserves the cache-breakpoint sentinel. The REAL
//! `<data … trust="untrusted">…[NEUTRALIZED]` strip/neutralize behavior is
//! covered by cap-http's own `tests/prompt_injection.rs` (dep-light: this crate
//! cannot dep cap-http, so the live envelope is witnessed there + at the
//! mainline SYS-AC-056/057 e2e).

use std::sync::Arc;

use advance_context_engine::{
    ContextAssemblerImpl, L4TaskSummaryReader, L5SynthesisReader, PortError, SynthesisView,
    TaskSummaryView,
};
use advance_shared_types::context::ContextAssembler;
use advance_shared_types::security_validator::{InjectionFlag, PromptInjectionHelpers, TrustLevel};
use async_trait::async_trait;

#[path = "common/mod.rs"]
mod common;
use common::*;

// ── content-bearing fake CONTRACT-114 helper ──
//
// A sentinel-envelope formatter (the REAL `<data>` envelope lives in M012). The
// point is to prove the ADAPTER routes each body through `wrap_with_boundary`
// exactly once, with the right `source` + `trust`. It does NOT neutralize the
// cache-breakpoint sentinel — that is the ASSEMBLER's post-wrap step (T-E6).
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

// ── content-bearing L4 / L5 readers ──

struct FakeL4(Option<TaskSummaryView>);
#[async_trait]
impl L4TaskSummaryReader for FakeL4 {
    async fn read_task_summary(
        &self,
        _a: &str,
        _t: &str,
    ) -> Result<Option<TaskSummaryView>, PortError> {
        Ok(self.0.clone())
    }
}

struct FakeL5(Vec<SynthesisView>);
#[async_trait]
impl L5SynthesisReader for FakeL5 {
    async fn read_syntheses(&self, _a: &str, _t: &str) -> Result<Vec<SynthesisView>, PortError> {
        Ok(self.0.clone())
    }
}

/// Build an assembler with custom L4/L5 readers + the content-bearing
/// `FakeWrapHelper` as the 18th port; every other port is a Null double.
fn assembler(l4: Option<TaskSummaryView>, l5: Vec<SynthesisView>) -> ContextAssemblerImpl {
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
        Arc::new(NullSkillSummary),
        Arc::new(NullVectorIndex),
        Arc::new(NullL2Digest),
        Arc::new(NullL3Epoch),
        Arc::new(FakeL4(l4)),
        Arc::new(FakeL5(l5)),
        Arc::new(NullL6Consolidation),
        Arc::new(FakeWrapHelper),
        Arc::new(NullDecomposition),
    )
}

fn l4(summary: &str) -> Option<TaskSummaryView> {
    Some(TaskSummaryView {
        task_id: "task-1".into(),
        summary: summary.into(),
    })
}

fn l5(bodies: &[&str]) -> Vec<SynthesisView> {
    bodies
        .iter()
        .enumerate()
        .map(|(i, b)| SynthesisView {
            task_id: format!("syn-{i}"),
            body: (*b).into(),
        })
        .collect()
}

/// A ctx on the NORMAL (non-degraded) path: wide-budget model + a task_id so the
/// L-readers are driven and the digest folds in full.
fn ctx() -> advance_shared_types::context::AssemblyContext {
    let mut c = stub_ctx();
    c.task_id = Some("task-1".into());
    c.model = "claude-3-5-sonnet-20241022".into();
    c.prompt = "the user prompt".into();
    c
}

fn section<'a>(
    messages: &'a [advance_shared_types::context::LlmMessage],
    prefix: &str,
) -> Option<&'a str> {
    messages
        .iter()
        .find(|m| m.content.starts_with(prefix))
        .map(|m| m.content.as_str())
}

// ── T-E1: L4 task summary is routed through the injected helper ──
#[tokio::test]
async fn t_e1_l4_routed_through_boundary_helper() {
    let asm = assembler(l4("do the task carefully"), vec![]);
    let res = asm.assemble(ctx()).await.unwrap();
    let ts = section(&res.messages, "# Task Summary").expect("L4 task summary rendered");
    assert!(
        ts.contains("[[WRAP src=memory:l4_task_summary trust=untrusted]]do the task carefully[[/WRAP]]"),
        "L4 body must be routed through wrap_with_boundary with the memory:l4_task_summary source: {ts}"
    );
}

// ── T-E2: L5 synthesis body is FOLDED (first time) + routed through the helper ──
#[tokio::test]
async fn t_e2_l5_folded_and_routed() {
    let asm = assembler(None, l5(&["prior task synthesis insight"]));
    let res = asm.assemble(ctx()).await.unwrap();
    let syn =
        section(&res.messages, "# Task Syntheses").expect("L5 syntheses rendered (first time)");
    assert!(
        syn.contains("[[WRAP src=memory:l5_synthesis trust=untrusted]]prior task synthesis insight[[/WRAP]]"),
        "L5 body must be folded into `# Task Syntheses` and routed through wrap_with_boundary: {syn}"
    );
}

// ── T-E3: each body wrapped EXACTLY ONCE (CONTRACT-114 inv. 4) ──
#[tokio::test]
async fn t_e3_wrapped_exactly_once() {
    let asm = assembler(l4("alpha"), l5(&["beta"]));
    let res = asm.assemble(ctx()).await.unwrap();
    let ts = section(&res.messages, "# Task Summary").unwrap();
    let syn = section(&res.messages, "# Task Syntheses").unwrap();
    assert_eq!(
        ts.matches("[[WRAP").count(),
        1,
        "L4 wrapped exactly once: {ts}"
    );
    assert_eq!(
        syn.matches("[[WRAP").count(),
        1,
        "L5 (one body) wrapped exactly once: {syn}"
    );
    // No nested envelope (wrap output never re-fed to wrap).
    assert!(!ts.contains("[[WRAP src=memory:l4_task_summary trust=untrusted]][[WRAP"));
}

// ── T-E4: empty L4/L5 bodies are skipped BEFORE wrapping (byte-neutral) ──
#[tokio::test]
async fn t_e4_empty_bodies_skipped() {
    // L4 None + one whitespace-only L5 body → neither section emitted.
    let asm = assembler(None, l5(&["   "]));
    let res = asm.assemble(ctx()).await.unwrap();
    assert!(
        section(&res.messages, "# Task Summary").is_none(),
        "empty L4 → no section"
    );
    assert!(
        section(&res.messages, "# Task Syntheses").is_none(),
        "blank L5 body → no section"
    );
    // And no stray envelope leaked anywhere.
    assert!(!res.messages.iter().any(|m| m.content.contains("[[WRAP")));
}

// ── T-E5: TrustLevel::Untrusted is passed for BOTH L4 and L5 ──
#[tokio::test]
async fn t_e5_untrusted_trust_on_both_legs() {
    let asm = assembler(l4("a"), l5(&["b"]));
    let res = asm.assemble(ctx()).await.unwrap();
    assert!(section(&res.messages, "# Task Summary")
        .unwrap()
        .contains("trust=untrusted"));
    assert!(section(&res.messages, "# Task Syntheses")
        .unwrap()
        .contains("trust=untrusted"));
}

// ── T-E6: cache-breakpoint sentinel neutralized POST-wrap on BOTH legs ──
#[tokio::test]
async fn t_e6_cache_breakpoint_preserved_both_legs() {
    let asm = assembler(
        l4("see ctx-cache-breakpoint:fake in L4"),
        l5(&["embed ctx-cache-breakpoint:evil in L5"]),
    );
    let res = asm.assemble(ctx()).await.unwrap();
    let ts = section(&res.messages, "# Task Summary").unwrap();
    let syn = section(&res.messages, "# Task Syntheses").unwrap();
    // The raw sentinel must NOT survive; the neutralized form must be present.
    assert!(
        !ts.contains("ctx-cache-breakpoint"),
        "L4: raw cache-breakpoint sentinel survived: {ts}"
    );
    assert!(
        ts.contains("ctx_cache_breakpoint"),
        "L4: neutralized form missing: {ts}"
    );
    assert!(
        !syn.contains("ctx-cache-breakpoint"),
        "L5: raw cache-breakpoint sentinel survived: {syn}"
    );
    assert!(
        syn.contains("ctx_cache_breakpoint"),
        "L5: neutralized form missing: {syn}"
    );
}

// ── T-E7: L5 fold honours the §1.4.3⑭ max-3 related-task render bound ──
#[tokio::test]
async fn t_e7_l5_render_capped_at_three() {
    // 5 non-empty syntheses → only the first 3 are rendered (the §1.4.3⑭ /
    // §1.4.7 `build_related_tasks(&ctx, 3)` bound; also caps per-body wrap alloc).
    let asm = assembler(
        None,
        l5(&["syn-AA", "syn-BB", "syn-CC", "syn-DD", "syn-EE"]),
    );
    let res = asm.assemble(ctx()).await.unwrap();
    let syn = section(&res.messages, "# Task Syntheses").expect("L5 syntheses rendered");
    assert_eq!(
        syn.matches("[[WRAP").count(),
        3,
        "exactly 3 L5 syntheses wrapped (max-3 render bound): {syn}"
    );
    assert!(syn.contains("syn-AA") && syn.contains("syn-BB") && syn.contains("syn-CC"));
    assert!(
        !syn.contains("syn-DD") && !syn.contains("syn-EE"),
        "syntheses beyond the max-3 bound must be dropped: {syn}"
    );
}

// ── T-E8: the L5 render-time SCAN is bounded (whitespace-flood DoS guard) ──
#[tokio::test]
async fn t_e8_l5_scan_bounded_against_whitespace_flood() {
    // A malicious/misbehaving L5 reader floods digest.l5 with 20 whitespace-only
    // bodies (> MAX_L5_SCANNED=16), then 3 real syntheses BEHIND the flood. The
    // render examines at most MAX_L5_SCANNED raw entries, so the empty-skip filter
    // never reaches the trailing reals → the scan is bounded (no unbounded trim()
    // pass) and (intentionally, for a flood) the behind-the-window reals are dropped
    // → no `# Task Syntheses` section. Witnesses the leading `.take(MAX_L5_SCANNED)`.
    let mut bodies: Vec<&str> = vec!["   "; 20];
    bodies.extend_from_slice(&["flood-real-A", "flood-real-B", "flood-real-C"]);
    let asm = assembler(None, l5(&bodies));
    let res = asm.assemble(ctx()).await.unwrap();
    assert!(
        section(&res.messages, "# Task Syntheses").is_none(),
        "an all-whitespace flood within the scan window yields no section; reals \
         behind MAX_L5_SCANNED are not scanned (bounded): {:?}",
        res.messages
            .iter()
            .map(|m| m.content.as_str())
            .collect::<Vec<_>>()
    );
    // And no stray envelope leaked from the flood.
    assert!(!res.messages.iter().any(|m| m.content.contains("[[WRAP")));
}
