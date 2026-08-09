//! Repetition-guard data types shipped by Slice K.
//!
//! Canonical source: `docs/modules/MODULE-008-run-manager.md` §1.3.5
//! (lines 198-304 after Slice K DOCS-first amendment).
//!
//! Used by:
//! - [`crate::traits::RepetitionGuardCheck`] (CONTRACT-072), consumed by
//!   MODULE-009 cap-llm (`record_output` after each LLM generate/stream)
//!   and MODULE-017 cap-tools (`record_tool_call` after each WASM tool /
//!   MCP tool returns).
//! - MODULE-008 `RepetitionGuard` concrete impl (future slice).

use serde::{Deserialize, Serialize};

/// Per-tool-call fingerprint compared inside the window VecDeque.
///
/// Canonical source: MODULE-008:210-214.
///
/// # Fields
///
/// - `tool_id`, `method`: attacker-influenced — originate from WASM
///   component manifests / MCP server responses. Same surface as
///   `ToolEntry`/`McpToolEntry`; `#[serde(deny_unknown_fields)]` provides
///   the structural defense. Producers (MODULE-017 cap-tools) MUST reject
///   or sanitize these strings to strip newlines / `\r` / `\0` / ASCII
///   control chars before constructing a [`ToolCallSignature`] — this
///   keeps the canonical [`Display`] impl infallible and prevents log
///   injection via `sig.to_string()` at MODULE-008:229. If the rendered
///   string is further routed into model-facing context by a concrete
///   `RepetitionGuardCheck` implementer, control-char stripping alone
///   is insufficient — see MODULE-008 §3.6 for the tracked
///   prompt-injection mitigation follow-up.
/// - `params_hash`: implementer-computed (cap-tools) digest of the
///   invocation parameters; not deserialized from an untrusted wire format
///   in the hot path.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolCallSignature {
    pub tool_id: String,
    pub method: String,
    pub params_hash: u64,
}

/// Canonical operator-facing rendering required by MODULE-008:229
/// (`self.decide(&agent_id_owned, &sig.to_string())`). Format is pinned
/// in MODULE-008 §1.3.5 DOCS-first canonical declaration; changing it
/// breaks the operator-log contract.
impl std::fmt::Display for ToolCallSignature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}::{}#{:016x}",
            self.tool_id, self.method, self.params_hash
        )
    }
}

/// 256-bit hash of the LLM output text, newtype-wrapped so the type
/// system prevents mixing with other hashes.
///
/// **Algorithm-opaque at the shared-types layer.** The concrete hash
/// algorithm (BLAKE3 / SHA-256 / etc.) and LLM-output text-normalization
/// rules (whitespace trimming, Unicode NFC, tokenizer boundaries) are the
/// concrete implementer's responsibility — both the producer (cap-llm)
/// and the consumer (MODULE-008 `RepetitionGuard`) MUST agree on the
/// same algorithm + normalization, pinned in the owner module with a
/// cross-crate integration test. Two correct-looking implementations
/// that disagree would silently break repetition detection. Tracked in
/// MODULE-008 §3.6.
///
/// # Wire format
///
/// `#[serde(transparent)]` over `[u8; 32]` → JSON array of 32 u8 numbers
/// (locked by `wire_output_hash`). The wire-format is not human-readable;
/// if MODULE-019 observability wants hex display in events, it wraps
/// with its own serializer.
///
/// The tuple field is `pub` so MODULE-009 cap-llm can construct values
/// directly after computing the hash (MODULE-008:497 consumer surface).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct OutputHash(pub [u8; 32]);

/// Outcome of a single repetition-guard observation.
///
/// Canonical source: MODULE-008:231/256-257/267/276 usage sites.
///
/// **Intentionally NOT `#[non_exhaustive]`** — cross-references
/// [`crate::capability::BudgetDecision`]'s rationale (closed 2/3-state
/// fail-closed gate; wildcard arms tend to be fail-open risk). The
/// reason-`String` payloads are implementer-chosen stable identifiers
/// (e.g. `"output-repeat"`, `"tool-repeat:<tool_id>::<method>"`) — they
/// MUST NOT carry user PII, budget values, or agent-private context.
/// Reason strings are operator-facing, not user-facing.
///
/// `#[serde(deny_unknown_fields)]` is forward-looking hardening (inert
/// for tuple-form variants today, load-bearing the moment a struct-form
/// variant is added) — matches `BudgetDecision`/`GrantDecision` posture.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum RepetitionDecision {
    Pass,
    Warn(String),
    Terminate(String),
}

/// Stable wire-format identifier for the M009 `llm-error::repetition-terminated`
/// non-retryable error variant per PRD §4.2.3 + §4.6 retry classification table.
///
/// Co-located with [`RepetitionDecision`] (not in `advance-run-manager`) to
/// avoid introducing a compile-time edge `MODULE-009 → MODULE-008`. Consumers
/// (MODULE-009 cap-llm retry classifier; MODULE-017 cap-tools) reach for this
/// constant from `shared-types`, which is already in their dep set.
///
/// The retry classifier in M009 MUST NOT match this tag against any
/// retryable error variant (rate-limited, provider-error). M008's
/// `RepetitionGuard::Terminate(_)` decision lifts to this WIT-side
/// identifier at the M009 boundary.
pub const REPETITION_TERMINATED_TAG: &str = "repetition-terminated";
