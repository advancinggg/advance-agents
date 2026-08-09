//! AC-17 — L1 vector-retrieval turn-end embedding pipeline (§1.3.3 / §11.3.3
//! L1 / REQ-226).
//!
//! §1.4 AC-17: "after each turn completes, generate embedding from
//! `digest + collapsed_view` via CONTRACT-081, write to `turn-index.yaml` L1
//! layer **AND** to `turn_index` SQLite virtual table via CONTRACT-030;
//! consumed by subsequent `unified_search` calls".
//!
//! [`index_turn_end`] is the pipeline:
//! 1. Compute `embed_source` byte-matching `crates/database/src/rebuild.rs`:
//!    `if collapsed_view.is_empty() { digest } else { format!("{} {}", digest,
//!    collapsed_view) }` — so a turn embedded live at turn-end yields the SAME
//!    vector as the same turn re-embedded by a rebuild (no drift).
//! 2. Embed via [`EmbeddingPort`] (CONTRACT-081 stand-in); `Err` / non-finite
//!    → [`AssemblyError::EmbeddingFailed`].
//! 3. Write to BOTH [`TurnIndexSqliteWriter`] (CONTRACT-030) AND
//!    [`TurnIndexYamlWriter`] (CONTRACT-101) — once each per call, so the §1.4
//!    "AND" conjunction is verifiable at the M010 caller boundary. Either
//!    writer `Err` → [`AssemblyError::MemoryStoreFailure`] (writer-tag
//!    prefixed).
//!
//! Non-wired scope (MODULE-010 §3.6 Slice-D (d)): exported + integration-tested
//! but not wired into the live M014 turn-end hook (turn-end indexing fires
//! after the LLM call — MODULE-014's agent-loop-driver territory, not the
//! pre-turn `assemble()`).

use advance_shared_types::context::AssemblyError;

use crate::ports::{EmbeddingPort, TurnIndexEntry, TurnIndexSqliteWriter, TurnIndexYamlWriter};

/// Writer-tag prefixes so a caller reading `MemoryStoreFailure` can tell which
/// write side failed (parallels the Slice-A `INPUT_VALIDATION_PREFIX`
/// machine-parseable-prefix pattern).
pub const SQLITE_WRITER_PREFIX: &str = "TURN_INDEX_SQLITE";
/// See [`SQLITE_WRITER_PREFIX`].
pub const YAML_WRITER_PREFIX: &str = "TURN_INDEX_YAML";

/// Defense-in-depth upper bound on the embed-source byte length
/// (`digest` + `collapsed_view`). Mirrors the canonical CONTRACT-114
/// `MAX_INJECTION_BYTES` = 1 MiB fail-closed discipline (and the Slice-A
/// `WarningQueue` `MAX_WARNING_MSG_LEN` bound). **The PRIMARY bound is upstream**
/// — MODULE-011 builds turn-index digests + collapsed-views at bounded size
/// (a digest is a one-sentence summary; the collapsed_view is a bounded
/// L0-collapse of one turn). This is a consumer-side guard so a poisoned /
/// oversized turn cannot amplify into a giant `embed()` payload + dual
/// oversized writes (the round-9 adversarial DoS-amplification finding).
/// In-bound inputs are unaffected — the embed-source format + `rebuild.rs`
/// parity are preserved; only an anomalous `> 1 MiB` source is rejected
/// (fail-CLOSED, not silently truncated — a truncated embedding would be a
/// semantically wrong vector that silently diverges from the rebuild path).
pub const MAX_EMBED_SOURCE_BYTES: usize = 1_048_576;

/// Machine-parseable prefix on the oversize-rejection `MemoryStoreFailure`
/// payload (same pattern as the writer-tag prefixes above).
pub const OVERSIZE_PREFIX: &str = "TURN_EMBED_OVERSIZE";

/// Compute the embed-source text. Byte-matches `crates/database/src/rebuild.rs`
/// so live + rebuild embeddings agree for the same turn.
fn embed_source(digest: &str, collapsed_view: &str) -> String {
    if collapsed_view.is_empty() {
        digest.to_string()
    } else {
        format!("{digest} {collapsed_view}")
    }
}

/// Run the AC-17 turn-end embedding pipeline. Returns the written
/// [`TurnIndexEntry`] on success.
///
/// `id` is the caller-supplied turn-index entry id (e.g.
/// `{task_id}{US}turn-{n}` per the rebuild convention); MODULE-010 does not
/// mint it (the turn identity is owned by the caller / M004).
pub async fn index_turn_end(
    id: &str,
    turn_id: u64,
    digest: &str,
    collapsed_view: &str,
    embed_port: &dyn EmbeddingPort,
    sqlite_writer: &dyn TurnIndexSqliteWriter,
    yaml_writer: &dyn TurnIndexYamlWriter,
) -> Result<TurnIndexEntry, AssemblyError> {
    let source = embed_source(digest, collapsed_view);

    // Defense-in-depth (round-9 adversarial): reject an anomalous oversized
    // embed source BEFORE the `embed()` call + dual writes, so a poisoned turn
    // cannot amplify a multi-MiB payload across the embedding port + SQLite +
    // YAML. Fail-CLOSED (reject, do not truncate — see MAX_EMBED_SOURCE_BYTES).
    if source.len() > MAX_EMBED_SOURCE_BYTES {
        return Err(AssemblyError::MemoryStoreFailure(format!(
            "{OVERSIZE_PREFIX}: embed source {} bytes exceeds {MAX_EMBED_SOURCE_BYTES}",
            source.len()
        )));
    }

    // Step 2: embed. `Err` OR a non-finite/empty vector → EmbeddingFailed
    // (mirrors the Slice-B route_task / unified_search finite-value hardening:
    // a NaN/Inf embedding is not a usable embedding).
    let embedding = match embed_port.embed(&source).await {
        Ok(v) if !v.is_empty() && v.iter().all(|x| x.is_finite()) => v,
        Ok(_) => {
            return Err(AssemblyError::EmbeddingFailed(
                "embed() returned an empty or non-finite vector".to_string(),
            ));
        }
        Err(e) => return Err(AssemblyError::EmbeddingFailed(e.0)),
    };

    let entry = TurnIndexEntry {
        id: id.to_string(),
        turn_id,
        digest: digest.to_string(),
        collapsed_view: collapsed_view.to_string(),
        embedding,
    };

    // Step 3: write to BOTH targets, once each. SQLite first, then YAML; either
    // failure is surfaced (writer-tag-prefixed) — NOT swallowed. A partial
    // write (sqlite ok, yaml fail) returns the YAML error so the caller knows
    // the YAML layer is out of sync and can reconcile / retry.
    sqlite_writer
        .write_turn_index_sqlite(&entry)
        .await
        .map_err(|e| {
            AssemblyError::MemoryStoreFailure(format!("{SQLITE_WRITER_PREFIX}: {}", e.0))
        })?;
    yaml_writer
        .write_turn_index_yaml(&entry)
        .await
        .map_err(|e| AssemblyError::MemoryStoreFailure(format!("{YAML_WRITER_PREFIX}: {}", e.0)))?;

    Ok(entry)
}
