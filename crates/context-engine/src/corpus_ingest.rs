//! Wave-13 Lane C — corpus-populate primitive (MODULE-010 §3.8 Wave-13 Lane C).
//!
//! `build_agent_search_corpus(docs, embedder)` embeds a list of plain
//! [`CorpusDoc`]s (id + text + kind) and buckets them into the pre-built
//! [`crate::vector_search::AgentSearchCorpus`] (Content→`contents`,
//! Memory→`memories`), ready for `RankingUnifiedSearch`. This is the in-crate
//! ingest primitive the cli harvest calls (with cap-memory + file content); the
//! witness calls it directly. `tasks`/`turns` (which need task-id / timestamp
//! metadata the plain doc does not carry) are out of this slice's scope and
//! stay empty.

use crate::ports::EmbeddingPort;
use crate::vector_search::{AgentSearchCorpus, IndexedVector};

/// The corpus bucket a [`CorpusDoc`] indexes into.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CorpusDocKind {
    /// File / document content → `AgentSearchCorpus.contents`.
    Content,
    /// Memory-entry content → `AgentSearchCorpus.memories`.
    Memory,
}

/// A plain (un-embedded) corpus document: an identity + its text + which source
/// bucket it belongs to. Embedding happens in [`build_agent_search_corpus`].
#[derive(Clone, Debug, PartialEq)]
pub struct CorpusDoc {
    pub id: String,
    pub text: String,
    pub kind: CorpusDocKind,
}

impl CorpusDoc {
    /// A file/document-content doc → `contents` bucket.
    pub fn content(id: impl Into<String>, text: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            text: text.into(),
            kind: CorpusDocKind::Content,
        }
    }

    /// A memory-entry-content doc → `memories` bucket.
    pub fn memory(id: impl Into<String>, text: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            text: text.into(),
            kind: CorpusDocKind::Memory,
        }
    }
}

/// Build a populated [`AgentSearchCorpus`] by embedding each doc's text via
/// `embedder` and bucketing by [`CorpusDocKind`]. Defensive: a doc whose text
/// is empty/whitespace, or whose embedding errors / is empty / non-finite, is
/// SKIPPED — it never poisons the corpus (`cosine_similarity` would skip it
/// anyway; dropping it keeps the corpus clean). `tasks`/`turns` stay empty.
pub async fn build_agent_search_corpus(
    docs: &[CorpusDoc],
    embedder: &dyn EmbeddingPort,
) -> AgentSearchCorpus {
    let mut corpus = AgentSearchCorpus::default();
    for doc in docs {
        if doc.text.trim().is_empty() {
            continue;
        }
        let embedding = match embedder.embed(&doc.text).await {
            Ok(v) if !v.is_empty() && v.iter().all(|x| x.is_finite()) => v,
            _ => continue, // Err / empty / non-finite → skip (defensive)
        };
        let row = IndexedVector {
            id: doc.id.clone(),
            embedding,
        };
        match doc.kind {
            CorpusDocKind::Content => corpus.contents.push(row),
            CorpusDocKind::Memory => corpus.memories.push(row),
        }
    }
    corpus
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ports::PortError;
    use crate::recall_embedding::HashingEmbedding;
    use async_trait::async_trait;

    #[tokio::test]
    async fn buckets_content_and_memory_with_real_embedding() {
        let e = HashingEmbedding::default();
        let docs = vec![
            CorpusDoc::content("file-1", "the deploy script runs cargo build"),
            CorpusDoc::memory("mem-1", "the user prefers dark mode"),
        ];
        let c = build_agent_search_corpus(&docs, &e).await;
        assert_eq!(c.contents.len(), 1);
        assert_eq!(c.memories.len(), 1);
        assert_eq!(c.contents[0].id, "file-1");
        assert_eq!(c.memories[0].id, "mem-1");
        assert!(c.tasks.is_empty() && c.turns.is_empty());
        // the embedder was actually invoked (a non-zero vector got indexed)
        assert!(c.contents[0].embedding.iter().any(|x| *x != 0.0));
    }

    #[tokio::test]
    async fn skips_empty_or_whitespace_text() {
        let e = HashingEmbedding::default();
        let docs = vec![CorpusDoc::memory("mem-empty", "   ")];
        let c = build_agent_search_corpus(&docs, &e).await;
        assert!(c.memories.is_empty());
    }

    #[tokio::test]
    async fn skips_embed_error() {
        struct FailEmbed;
        #[async_trait]
        impl EmbeddingPort for FailEmbed {
            async fn embed(&self, _t: &str) -> Result<Vec<f32>, PortError> {
                Err(PortError("boom".into()))
            }
        }
        let docs = vec![CorpusDoc::content("file-1", "deploy script")];
        let c = build_agent_search_corpus(&docs, &FailEmbed).await;
        assert!(c.contents.is_empty());
    }
}
