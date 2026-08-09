//! AC-01 — Stateless per-call reconstruction; no provider session id retained.
//!
//! Two mechanical witnesses:
//! 1. The crate's `Cargo.toml` is greped for the absence of any provider /
//!    HTTP / TLS crate; presence of any would imply provider session lifecycle.
//!    (Unchanged from Slice A — the STRONGER witness.)
//! 2. `ContextAssemblerImpl`'s field-set is verified by `size_of_val` to be
//!    exactly N pointer-shaped fields and nothing else (no `HashMap<String,
//!    ProviderHandle>` / session map / connection pool). Slice B grew the
//!    struct from 3 fields (Slice A) to 10; Slice D → 11 (`event_bus`);
//!    Slice V1-c → 12 (`skill_summary`); Stage-C SAT-A → 18 fields (the 6
//!    L1-L6 reader ports); Stage-C SAT-E → 19 fields; **Wave-12 Lane C grows it
//!    to 20 fields**: 19
//!    `Arc<dyn …>` trait-object pointers (`callable_inventory`,
//!    `host_fn_inventory`, `agent_identity`, `knowledge_map_reader`,
//!    `agent_tree`, `embedding`, `task_index`, `light_llm`,
//!    `unified_search_port`, `event_bus` — the canonical CONTRACT-180
//!    `EventBusEmit` for AC-12, `skill_summary`, the 6 Stage-C SAT-A
//!    L1-L6 reader ports `l1_vector`/`l2_digest`/`l3_epoch`/`l4_summary`/
//!    `l5_synthesis`/`l6_consolidation` driving the AC-06 digest fold, and the
//!    Stage-C SAT-E `prompt_injection` canonical CONTRACT-114
//!    `PromptInjectionHelpers` for the AC-14 L4/L5 boundary-wrap, and the
//!    Wave-12 Lane C `decomposition` `DecompositionReader` for the Tier-2 ⑭
//!    "Active Task Decomposition" section) + 1
//!    `Arc<WarningQueue>` thin pointer. The AC-01 property the test defends is
//!    PRESERVED and RE-EXPRESSED: every field is still a `Send + Sync` `Arc`
//!    to a read-only inverted-dependency port, the canonical event-bus emit
//!    hook, or the bounded warning buffer — zero provider-session-shaped
//!    state. Any future non-pointer / session-map addition changes the size
//!    and trips this test. (This field-count assertion is rewritten in-scope
//!    each time the constructor grows — the Slice-A→B→D→V1-c→SAT-A precedent.)
//!
//! `include_str!("../Cargo.toml")` resolves to the *crate* manifest
//! (`crates/context-engine/Cargo.toml`), NOT the workspace manifest at the
//! repo root — the workspace manifest deliberately lists every provider
//! crate in the workspace and would always false-positive.

use std::mem::size_of;
use std::sync::Arc;

use advance_context_engine::WarningQueue;
use advance_shared_types::traits::CallableInventoryReader;

#[path = "common/mod.rs"]
mod common;

const CRATE_CARGO_TOML: &str = include_str!("../Cargo.toml");

#[test]
fn cargo_manifest_excludes_provider_crates() {
    let manifest = CRATE_CARGO_TOML;
    for forbidden in &[
        // Provider SDK / wrapper crates that imply LLM-provider session state.
        "cap-llm",
        "advance-cap-llm",
        "anthropic",
        "openai",
        "cohere",
        "bedrock",
        "mistral",
        "replicate",
        // HTTP / TLS stacks — outbound network = provider session lifecycle.
        "reqwest",
        "ureq",
        "isahc",
        "hyper",
        "hyper-tls",
        "rustls",
        "native-tls",
        "tonic",
    ] {
        assert!(
            !manifest.contains(forbidden),
            "advance-context-engine must not depend on `{forbidden}` — \
             AC-01 stateless requires no provider session storage; provider \
             deps would imply session lifecycle"
        );
    }
}

#[test]
fn assembler_has_no_session_id_shaped_fields() {
    // Construct via the common builder (Null doubles for all 19 injected
    // ports; `warnings` is internally constructed). We assert ONLY the
    // struct's byte size — the builder choice is irrelevant to the field-set
    // invariant.
    let asm = common::build_assembler_with_empty_inventories();

    // 19 fat `Arc<dyn _>` trait-object pointers + 1 thin `Arc<WarningQueue>`
    // + 1 `Vec<String>` agent-id alias config = 21 fields. All `Arc<dyn _>` are
    // the same width regardless of the trait, so one representative `size_of`
    // covers the 19 (Slice D added `event_bus`; Slice V1-c added `skill_summary:
    // Arc<dyn SkillSummaryReader>`; Stage-C SAT-A added the 6 L1-L6 reader ports
    // `l1_vector`/`l2_digest`/`l3_epoch`/`l4_summary`/`l5_synthesis`/
    // `l6_consolidation`; Stage-C SAT-E added `prompt_injection: Arc<dyn
    // PromptInjectionHelpers>`; Wave-12 Lane C added `decomposition: Arc<dyn
    // DecompositionReader>` (the 19th injected port); Wave-12 Lane A added
    // `agent_id_aliases: Vec<String>` — an IMMUTABLE construction-time alias set
    // ({bare cap-id, colon msg-id}) read by `assemble()` for the ⑬ delegate-match
    // + Tier-3 warning-drain. Every `Arc<dyn _>` is a read-only
    // inverted-dependency port; the `Vec<String>` is construction config, NOT
    // per-call/session/provider state — the AC-01 stateless invariant (no
    // mutation across `assemble()` calls) is preserved).
    let fat = size_of::<Arc<dyn CallableInventoryReader>>();
    let thin = size_of::<Arc<WarningQueue>>();
    let expected_size = 19 * fat + thin + size_of::<Vec<String>>();

    assert_eq!(
        size_of_val(&asm),
        expected_size,
        "ContextAssemblerImpl field-set changed — possible provider-state \
         addition. AC-01 requires the struct hold ONLY 19 Arc<dyn _> \
         inverted-dependency ports (incl. the canonical EventBusEmit, the \
         Slice-V1-c SkillSummaryReader, the Stage-C SAT-A 6 L1-L6 reader \
         ports, the Stage-C SAT-E PromptInjectionHelpers, and the Wave-12 \
         Lane C DecompositionReader) + 1 Arc<WarningQueue> + 1 Vec<String> \
         agent-id alias config (Wave-12 Lane A, immutable construction config — \
         not session/provider state); no session map, connection pool, or \
         provider handle."
    );
}
