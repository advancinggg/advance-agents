//! Stage-C SAT-A (MODULE-010 §3.8) — `assemble()` folds the L0-L6
//! `coordinate_processing` digest into Tier-3, and the budget-overflow guard
//! returns a DEGRADED extreme-mode `Ok` prompt (192 / §2.8 / SYS-AC-192).
//!
//! Exercises AC-06 (L0-L6 coordination) + AC-09/192 at the NEW live-fold
//! integration point. The module ACs are already `passed` at unit level; these
//! strengthen them where `assemble()` now drives the coordinator.

use std::sync::Arc;

use advance_context_engine::{
    ContextAssemblerImpl, L2DigestReader, L4TaskSummaryReader, PortError, TaskSummaryView,
    TurnDigestForEmbed,
};
use advance_shared_types::context::ContextAssembler;
use async_trait::async_trait;

#[path = "common/mod.rs"]
mod common;
use common::*;

// ── content-bearing L-reader fakes ──

struct FakeL2(Vec<TurnDigestForEmbed>);
#[async_trait]
impl L2DigestReader for FakeL2 {
    async fn read_digests(&self, _a: &str, _t: &str) -> Result<Vec<TurnDigestForEmbed>, PortError> {
        Ok(self.0.clone())
    }
}

struct FakeL2Err;
#[async_trait]
impl L2DigestReader for FakeL2Err {
    async fn read_digests(&self, _a: &str, _t: &str) -> Result<Vec<TurnDigestForEmbed>, PortError> {
        Err(PortError("L2 boom".into()))
    }
}

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

/// Build an assembler with custom L2/L4 readers; every other port is a Null
/// double (incl. L1/L3/L5/L6). Mirrors `common::build_assembler_with` but lets
/// the test supply content-bearing history readers.
fn assembler_with_l2_l4(
    l2: Arc<dyn L2DigestReader>,
    l4: Arc<dyn L4TaskSummaryReader>,
) -> ContextAssemblerImpl {
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
        l2,
        Arc::new(NullL3Epoch),
        l4,
        Arc::new(NullL5Synthesis),
        Arc::new(NullL6Consolidation),
        Arc::new(NullPromptInjectionHelpers),
        Arc::new(NullDecomposition),
    )
}

// ── T1: non-empty L2/L4 → folded into Tier-3, before the current prompt ──
#[tokio::test]
async fn folds_l2_l4_digest_into_tier3_before_prompt() {
    let l2 = Arc::new(FakeL2(vec![TurnDigestForEmbed {
        turn_id: 1,
        digest: "did the thing".into(),
        collapsed_view: "cv".into(),
    }]));
    let l4 = Arc::new(FakeL4(Some(TaskSummaryView {
        task_id: "task-1".into(),
        summary: "overall task summary".into(),
    })));
    let asm = assembler_with_l2_l4(l2, l4);

    let mut ctx = stub_ctx();
    ctx.task_id = Some("task-1".into());
    ctx.model = "claude-3-5-sonnet-20241022".into(); // Wide budget → no overflow
    ctx.prompt = "the user prompt".into();

    let res = asm.assemble(ctx).await.unwrap();
    let contents: Vec<&str> = res.messages.iter().map(|m| m.content.as_str()).collect();

    let task_idx = contents
        .iter()
        .position(|c| c.starts_with("# Task Summary"))
        .expect("L4 task summary folded into the prompt");
    let turn_idx = contents
        .iter()
        .position(|c| c.starts_with("# Recent Turn Digests"))
        .expect("L2 turn digests folded into the prompt");
    assert!(contents[task_idx].contains("overall task summary"));
    assert!(contents[turn_idx].contains("did the thing"));

    // The digest folds BEFORE the current user prompt (and the tools section is
    // present → this is the NORMAL path, not the degraded one).
    let prompt_idx = contents
        .iter()
        .position(|c| *c == "the user prompt")
        .expect("current prompt present as a Tier-3 message");
    assert!(
        task_idx < prompt_idx && turn_idx < prompt_idx,
        "digest folds before the current prompt (task_idx={task_idx}, turn_idx={turn_idx}, prompt_idx={prompt_idx})"
    );
    assert!(
        contents.iter().any(|c| c.starts_with("# Available Tools")),
        "normal (non-degraded) path keeps the Tier-2 tools section"
    );
}

// ── T2: Null/empty readers → no digest message (byte-neutral fold) ──
#[tokio::test]
async fn null_readers_emit_no_digest_message() {
    let asm = build_assembler_with_empty_inventories();
    let mut ctx = stub_ctx();
    ctx.model = "claude-3-5-sonnet-20241022".into();
    ctx.prompt = "hi".into();

    let res = asm.assemble(ctx).await.unwrap();
    assert!(
        !res.messages.iter().any(|m| {
            m.content.starts_with("# Task Summary")
                || m.content.starts_with("# Recent Turn Digests")
                || m.content.starts_with("# Epoch Summary")
        }),
        "Null readers → empty digest → no fold message (Tier-3 byte-neutral)"
    );
}

// ── T3: a reader Err → empty digest, assemble() still Ok (§2.8 graceful) ──
#[tokio::test]
async fn reader_error_degrades_to_empty_digest_but_ok() {
    let asm = assembler_with_l2_l4(Arc::new(FakeL2Err), Arc::new(FakeL4(None)));
    let mut ctx = stub_ctx();
    ctx.task_id = Some("task-1".into());
    ctx.model = "claude-3-5-sonnet-20241022".into();

    let res = asm
        .assemble(ctx)
        .await
        .expect("a reader error degrades to an empty digest, assembly still Ok");
    assert!(
        !res.messages
            .iter()
            .any(|m| m.content.starts_with("# Recent Turn Digests")),
        "a fail-fast coordinator error yields no digest message"
    );
}

// ── T4: fixed content > budget → DEGRADED Ok (192 / §2.8) ──
#[tokio::test]
async fn budget_overflow_returns_degraded_ok_not_err() {
    let l2 = Arc::new(FakeL2(vec![TurnDigestForEmbed {
        turn_id: 1,
        digest: "d".into(),
        collapsed_view: "c".into(),
    }]));
    let l4 = Arc::new(FakeL4(Some(TaskSummaryView {
        task_id: "t".into(),
        summary: "s".into(),
    })));
    let asm = assembler_with_l2_l4(l2, l4);

    let mut ctx = stub_ctx();
    ctx.task_id = Some("t".into());
    ctx.model = "test-model".into(); // unrecognized → SMALL_MODEL_WINDOW (8192)
    ctx.prompt = "X".repeat(80_000); // ~20k tokens >> budget → overflow

    let res = asm
        .assemble(ctx)
        .await
        .expect("budget overflow returns a degraded Ok, NEVER Err");

    // Degraded extreme-mode set: the Tier-2 session tools section + the L0-L6
    // digest are dropped.
    assert!(
        !res.messages
            .iter()
            .any(|m| m.content.starts_with("# Available Tools")),
        "degraded path drops the Tier-2 tools section"
    );
    assert!(
        !res.messages.iter().any(|m| {
            m.content.starts_with("# Recent Turn Digests")
                || m.content.starts_with("# Task Summary")
        }),
        "degraded path drops the L0-L6 digest"
    );

    // The current prompt survives (best-effort) but is truncated to fit budget.
    let user = res
        .messages
        .iter()
        .find(|m| m.role == "user")
        .expect("degraded set keeps the (truncated) user prompt");
    assert!(
        user.content.len() < 80_000,
        "the oversize prompt is truncated against the remaining budget (len={})",
        user.content.len()
    );
}
