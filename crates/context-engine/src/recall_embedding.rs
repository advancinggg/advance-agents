//! Wave-13 Lane C — `HashingEmbedding`: a real deterministic hermetic
//! `EmbeddingPort` for the read-path recall wiring (MODULE-010 §3.8 Wave-13
//! Lane C). The legitimate IN-CRATE embedder the §3.6 "Real EmbeddingPort
//! (`/v1/embeddings`) cannot live in context-engine" row said the GATEWAY
//! adapter could not be — its embedding logic uses only `std` (+ the
//! already-present `async-trait` for the `EmbeddingPort` impl; no NEW / provider
//! crate), so the AC-01 `tests/stateless.rs::cargo_manifest_excludes_provider_crates`
//! guard is preserved.
//!
//! Deterministic + content-sensitive + hermetic (NOT semantic): folds each
//! input byte into bucket `i % dim` (`wrapping_add`, u32 — toolchain-independent),
//! then L2-normalizes to a unit vector. Non-empty text → a non-zero finite unit
//! vector; empty/whitespace (or all-zero-byte) text → the all-zero vector
//! (intentionally un-rankable: `cosine_similarity` skips zero-norm). Reuses the
//! *technique* (not the dimensionality) of cap-memory's 8-dim `StubEmbedder`.

use async_trait::async_trait;

use crate::ports::{EmbeddingPort, PortError};

/// Default embedding dimensionality. Matches the cli `StubEmbedding` slot
/// (`vec![0.0; 16]`) so `HashingEmbedding` is a drop-in for the harvest swap,
/// and matches the existing 16-dim corpora.
pub const RECALL_EMBEDDING_DIM_DEFAULT: usize = 16;

/// A deterministic, hermetic, content-sensitive `EmbeddingPort`.
#[derive(Clone, Debug)]
pub struct HashingEmbedding {
    dim: usize,
}

impl HashingEmbedding {
    /// Construct with an explicit dimensionality. `dim == 0` is clamped to 1 to
    /// avoid a zero-length / div-by-zero vector.
    pub fn new(dim: usize) -> Self {
        Self { dim: dim.max(1) }
    }

    /// The pure embedding function (sync) — exposed for corpus-build reuse and
    /// unit testing. Deterministic: same `text` → same vector.
    pub fn embed_text(&self, text: &str) -> Vec<f32> {
        // Empty / whitespace-only input → the all-zero vector (intentionally
        // un-rankable: `cosine_similarity` skips zero-norm). Without this guard,
        // folding raw whitespace bytes (e.g. `" "` → 0x20) would yield a spurious
        // non-zero unit vector. Non-blank text is folded verbatim (the trim is
        // ONLY for the blank-check, so content + trailing/leading spaces still
        // contribute, preserving determinism + content-sensitivity).
        if text.trim().is_empty() {
            return vec![0.0; self.dim];
        }
        let mut sketch = vec![0u32; self.dim];
        for (i, b) in text.as_bytes().iter().enumerate() {
            let bucket = i % self.dim;
            sketch[bucket] = sketch[bucket].wrapping_add(*b as u32);
        }
        // L2 norm. `max(1.0)` guards the all-zero (empty-text) case → returns
        // the all-zero vector (finite, intentionally un-rankable), never a NaN
        // from 0/0. For any ordinary non-empty text the true norm is ≫ 1, so
        // the clamp does not alter the unit-normalization.
        let norm: f32 = sketch
            .iter()
            .map(|x| (*x as f32) * (*x as f32))
            .sum::<f32>()
            .sqrt()
            .max(1.0);
        sketch.iter().map(|x| (*x as f32) / norm).collect()
    }
}

impl Default for HashingEmbedding {
    fn default() -> Self {
        Self::new(RECALL_EMBEDDING_DIM_DEFAULT)
    }
}

#[async_trait]
impl EmbeddingPort for HashingEmbedding {
    async fn embed(&self, text: &str) -> Result<Vec<f32>, PortError> {
        Ok(self.embed_text(text))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_same_text_same_vector() {
        let e = HashingEmbedding::default();
        assert_eq!(e.embed_text("hello world"), e.embed_text("hello world"));
    }

    #[test]
    fn non_empty_text_is_non_zero_finite_unit_vector() {
        let e = HashingEmbedding::default();
        let v = e.embed_text("the deploy script runs cargo build then rsync");
        assert_eq!(v.len(), RECALL_EMBEDDING_DIM_DEFAULT);
        assert!(
            v.iter().any(|x| *x != 0.0),
            "non-empty text must embed non-zero"
        );
        assert!(v.iter().all(|x| x.is_finite()), "all components finite");
        let norm: f32 = v.iter().map(|x| x * x).sum::<f32>().sqrt();
        assert!((norm - 1.0).abs() < 1e-5, "expected unit norm, got {norm}");
    }

    #[test]
    fn distinct_text_distinct_vectors() {
        let e = HashingEmbedding::default();
        assert_ne!(
            e.embed_text("alpha beta gamma delta"),
            e.embed_text("zulu yankee xray whiskey")
        );
    }

    #[test]
    fn empty_or_whitespace_text_is_all_zero() {
        let e = HashingEmbedding::default();
        for t in ["", "   ", "\t\n "] {
            let v = e.embed_text(t);
            assert_eq!(v.len(), RECALL_EMBEDDING_DIM_DEFAULT);
            assert!(
                v.iter().all(|x| *x == 0.0),
                "{t:?} must embed all-zero (un-rankable)"
            );
        }
    }

    #[test]
    fn dim_respected_and_min_one() {
        assert_eq!(HashingEmbedding::new(8).embed_text("abc").len(), 8);
        assert_eq!(HashingEmbedding::new(0).embed_text("abc").len(), 1);
    }

    #[tokio::test]
    async fn embed_port_matches_embed_text() {
        let e = HashingEmbedding::default();
        let via_port = e.embed("hello").await.unwrap();
        assert_eq!(via_port, e.embed_text("hello"));
    }
}
