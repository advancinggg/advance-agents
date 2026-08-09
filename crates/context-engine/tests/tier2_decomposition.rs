//! Wave-12 Lane C — Tier-2 ⑭ "Active Task Decomposition" assembled-output tests.
//!
//! Mirrors `tier2_delegates.rs`: drives the REAL `ContextAssemblerImpl` over a
//! fixture `DecompositionReader` and asserts the `# Active Task Decomposition`
//! section appears in the assembled prompt (or is OMITTED when there are no active
//! subtasks — the byte-identical-when-empty invariant). The `format_*` unit cases
//! (empty→None, sanitization, truncation) live in `src/tier2_decomposition.rs`.

mod common;
use common::*;

use std::sync::Arc;

use advance_context_engine::SubtaskView;
use advance_shared_types::context::ContextAssembler;

fn view(id: &str, title: &str, status: &str) -> SubtaskView {
    SubtaskView {
        subtask_id: id.into(),
        title: title.into(),
        status: status.into(),
    }
}

#[tokio::test]
async fn decomposition_section_omitted_when_no_active_subtasks() {
    // Null DecompositionReader (empty) ⇒ `format_active_decomposition_section`
    // returns None ⇒ NO Tier-2 message ⇒ the assembled output is byte-identical
    // to pre-Wave-12 (the omit-when-empty invariant the satellite relies on).
    let asm = build_assembler_with_empty_inventories();
    let result = asm.assemble(stub_ctx()).await.expect("assemble ok");
    let count = result
        .messages
        .iter()
        .filter(|m| m.content.starts_with("# Active Task Decomposition"))
        .count();
    assert_eq!(
        count, 0,
        "no active subtasks ⇒ no decomposition section emitted"
    );
}

#[tokio::test]
async fn decomposition_section_lists_subtasks_through_real_assembler() {
    let asm = build_assembler_with_decomposition(Arc::new(FixtureDecomposition(vec![
        view("st-1", "Design schema", "in-progress"),
        view("st-2", "Write tests", "pending"),
    ])));
    let result = asm.assemble(stub_ctx()).await.expect("assemble ok");

    let section = result
        .messages
        .iter()
        .find(|m| m.content.starts_with("# Active Task Decomposition"))
        .expect("a # Active Task Decomposition section is present");
    assert!(
        section
            .content
            .contains("- st-1 — Design schema [in-progress]"),
        "section must list subtask 1 with id/title/status; got:\n{}",
        section.content
    );
    assert!(
        section.content.contains("- st-2 — Write tests [pending]"),
        "section must list subtask 2 with id/title/status; got:\n{}",
        section.content
    );

    let count = result
        .messages
        .iter()
        .filter(|m| m.content.starts_with("# Active Task Decomposition"))
        .count();
    assert_eq!(count, 1, "exactly one # Active Task Decomposition section");
}
