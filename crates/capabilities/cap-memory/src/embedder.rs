//! Embedder seam (slice F) — cap-memory-internal trait for L1 vector embedding
//! (AC-19, REQ-226).
//!
//! `StubEmbedder` ships a deterministic 8-dim per-byte-folded sketch for tests
//! (same posture as slice-B `InMemorySimilarityIndex` token-Jaccard deterministic
//! stub). Production wiring to MODULE-009 CONTRACT-081 `embed()` (§2.2
//! dependencies row pairs CONTRACT-081 with "LLM batch extraction, embed(),
//! VLM") is deferred to a future M009 wiring slice — see MODULE-011 §3.6 row
//! "Production `embed()` adapter for `Embedder` seam".
//!
//! NOT promoted to `crates/shared-types`, NOT registered in
//! ARCHITECTURE.md §6.1 — same posture as slice B/C/D internal seams (per
//! MODULE-011 §2.7 explicit guidance).

use async_trait::async_trait;

/// Fixed embedding dimensionality for the slice-F `StubEmbedder`.
///
/// 8 is a deliberately small, debuggable stub vector — the production adapter
/// (MODULE-009 CONTRACT-081 `embed()`) will return whatever dimensionality
/// the configured embedding model produces (typically 768 or 1536). Consumers
/// MUST NOT assume the slice-F dimensionality is the production one.
pub const STUB_EMBEDDING_DIM: usize = 8;

/// Error returned by [`Embedder::embed`]. Slice F's only variant is
/// `Upstream(String)` — production wiring will likely add network /
/// rate-limit / token-budget variants.
///
/// **Sanitization contract for `Upstream(String)`** (adversarial round 5
/// finding): the `String` payload is propagated verbatim through the
/// `#[error("upstream embedding failure: {0}")]` Display impl and will
/// surface in `tracing::error!` / forensic log paths once any seam method
/// (`Components::sync_turn_index` / `sync_task_index`) returns it via `?`.
/// Implementations of [`Embedder`] that wrap an HTTP / SDK error MUST
/// redact:
/// - bearer tokens / `Authorization` headers
/// - request/response bodies that may echo user content (PII) or API keys
/// - URLs containing secret query-string parameters
///
/// A reasonable default for the deferred MODULE-009 production adapter is
/// to map upstream errors to a coarse status string (e.g., "rate-limit
/// exceeded", "upstream 5xx", "model unavailable") rather than verbatim
/// reqwest/hyper error chains.
#[derive(Debug, thiserror::Error)]
pub enum EmbedderError {
    /// Upstream embedding service failed (transport / rate-limit / 5xx / etc.)
    #[error("upstream embedding failure: {0}")]
    Upstream(String),
}

/// Cap-memory-internal embedder seam (AC-19). Compute an L1 vector embedding
/// for `text` (typically `digest + "\n" + collapsed_view` per `sync_turn_index`,
/// or `summary.brief` per `sync_task_index`).
///
/// `Send + Sync` super-bound matches the `Arc<dyn Embedder + Send + Sync>`
/// trait-object form stored in `Components.embedder` — see the
/// `post_processor.rs` "Send + Sync auto-trait note" rustdoc.
#[async_trait]
pub trait Embedder: Send + Sync {
    async fn embed(&self, text: &str) -> Result<Vec<f32>, EmbedderError>;
}

/// Deterministic 8-dim per-byte-folded sketch (L2-normalized).
///
/// Per-byte folding: for each input byte at position `i`, accumulate into
/// bucket `i % 8`; then L2-normalize. This is deterministic across the Rust
/// toolchain (no floating-point arch dependency since accumulation is `u32`),
/// reproducible across re-runs, and trivially non-zero for any non-empty
/// input. NOT a semantic embedding — never substitute for the production
/// MODULE-009 adapter.
#[derive(Default, Clone, Debug)]
pub struct StubEmbedder;

#[async_trait]
impl Embedder for StubEmbedder {
    async fn embed(&self, text: &str) -> Result<Vec<f32>, EmbedderError> {
        let mut sketch = [0u32; STUB_EMBEDDING_DIM];
        for (i, b) in text.as_bytes().iter().enumerate() {
            sketch[i % STUB_EMBEDDING_DIM] = sketch[i % STUB_EMBEDDING_DIM].wrapping_add(*b as u32);
        }
        let norm: f32 = (sketch.iter().map(|x| (*x as f32).powi(2)).sum::<f32>())
            .sqrt()
            .max(1.0);
        Ok(sketch.iter().map(|x| (*x as f32) / norm).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn stub_embedder_returns_fixed_8_dim_vector() {
        let e = StubEmbedder;
        let v = e.embed("hello").await.unwrap();
        assert_eq!(v.len(), STUB_EMBEDDING_DIM);
    }

    #[tokio::test]
    async fn stub_embedder_is_deterministic_across_runs() {
        let e = StubEmbedder;
        let v1 = e.embed("the quick brown fox").await.unwrap();
        let v2 = e.embed("the quick brown fox").await.unwrap();
        assert_eq!(v1, v2, "identical input → identical bytes");
    }

    #[tokio::test]
    async fn stub_embedder_distinct_inputs_yield_distinct_vectors() {
        let e = StubEmbedder;
        let v1 = e.embed("alpha").await.unwrap();
        let v2 = e.embed("beta").await.unwrap();
        assert_ne!(v1, v2);
    }

    #[tokio::test]
    async fn stub_embedder_empty_input_l2_norm_is_zero_vector_with_unit_clamp() {
        // Empty input → sketch all zeros → norm = max(0.0, 1.0) = 1.0;
        // every element becomes 0.0 / 1.0 = 0.0. Length is still
        // STUB_EMBEDDING_DIM (no panic on zero-norm division).
        let e = StubEmbedder;
        let v = e.embed("").await.unwrap();
        assert_eq!(v.len(), STUB_EMBEDDING_DIM);
        assert!(v.iter().all(|x| *x == 0.0));
    }

    #[tokio::test]
    async fn stub_embedder_l2_norm_is_at_most_one_for_nonempty_input() {
        // After L2 normalization the vector lies on the unit sphere (norm == 1.0)
        // for any non-zero sketch.
        let e = StubEmbedder;
        let v = e.embed("hello world").await.unwrap();
        let norm: f32 = v.iter().map(|x| x.powi(2)).sum::<f32>().sqrt();
        assert!((norm - 1.0).abs() < 1e-5, "unit norm; got {norm}");
    }
}
