//! AC-17 (MODULE-010-T21) — L1 turn-end embedding pipeline.
//!
//! 5 sub-cases: (a) embed-source = `format!("{} {}", digest, collapsed_view)`;
//! (b) empty collapsed_view → embed-source = digest alone (matches
//! `crates/database/src/rebuild.rs`); (c) BOTH writers called once each;
//! (d) embed failure → EmbeddingFailed; (e) writer failure → MemoryStoreFailure.

use std::sync::Mutex;

use advance_context_engine::{
    index_turn_end, EmbeddingPort, PortError, TurnIndexEntry, TurnIndexSqliteWriter,
    TurnIndexYamlWriter, MAX_EMBED_SOURCE_BYTES, OVERSIZE_PREFIX, SQLITE_WRITER_PREFIX,
    YAML_WRITER_PREFIX,
};
use advance_shared_types::context::AssemblyError;
use async_trait::async_trait;

// ─── fakes ───

/// Records the exact text passed to `embed`, returns a fixed finite vector
/// (or a forced error / non-finite vector).
struct FakeEmbedding {
    seen: Mutex<Vec<String>>,
    mode: EmbedMode,
}
enum EmbedMode {
    Ok,
    Err,
    NonFinite,
}
#[async_trait]
impl EmbeddingPort for FakeEmbedding {
    async fn embed(&self, text: &str) -> Result<Vec<f32>, PortError> {
        self.seen.lock().unwrap().push(text.to_string());
        match self.mode {
            EmbedMode::Ok => Ok(vec![0.1, 0.2, 0.3]),
            EmbedMode::Err => Err(PortError("embed service down".into())),
            EmbedMode::NonFinite => Ok(vec![0.1, f32::NAN, 0.3]),
        }
    }
}

#[derive(Default)]
struct FakeSqliteWriter {
    writes: Mutex<Vec<TurnIndexEntry>>,
    err: bool,
}
#[async_trait]
impl TurnIndexSqliteWriter for FakeSqliteWriter {
    async fn write_turn_index_sqlite(&self, entry: &TurnIndexEntry) -> Result<(), PortError> {
        if self.err {
            return Err(PortError("sqlite locked".into()));
        }
        self.writes.lock().unwrap().push(entry.clone());
        Ok(())
    }
}

#[derive(Default)]
struct FakeYamlWriter {
    writes: Mutex<Vec<TurnIndexEntry>>,
    err: bool,
}
#[async_trait]
impl TurnIndexYamlWriter for FakeYamlWriter {
    async fn write_turn_index_yaml(&self, entry: &TurnIndexEntry) -> Result<(), PortError> {
        if self.err {
            return Err(PortError("yaml fsync failed".into()));
        }
        self.writes.lock().unwrap().push(entry.clone());
        Ok(())
    }
}

// ─── (a) embed-source format match (non-empty collapsed_view) ───

#[tokio::test]
async fn embed_source_concatenates_digest_and_collapsed_view() {
    let embed = FakeEmbedding {
        seen: Mutex::new(Vec::new()),
        mode: EmbedMode::Ok,
    };
    let sqlite = FakeSqliteWriter::default();
    let yaml = FakeYamlWriter::default();

    index_turn_end(
        "task-1\u{1f}turn-3",
        3,
        "the digest",
        "the collapsed view",
        &embed,
        &sqlite,
        &yaml,
    )
    .await
    .unwrap();

    let seen = embed.seen.lock().unwrap();
    assert_eq!(seen.len(), 1);
    // Matches crates/database/src/rebuild.rs: format!("{} {}", digest, collapsed_view).
    assert_eq!(seen[0], "the digest the collapsed view");
}

// ─── (b) empty collapsed_view → digest alone ───

#[tokio::test]
async fn embed_source_is_digest_alone_when_collapsed_view_empty() {
    let embed = FakeEmbedding {
        seen: Mutex::new(Vec::new()),
        mode: EmbedMode::Ok,
    };
    let sqlite = FakeSqliteWriter::default();
    let yaml = FakeYamlWriter::default();

    index_turn_end(
        "task-1\u{1f}turn-4",
        4,
        "digest only",
        "",
        &embed,
        &sqlite,
        &yaml,
    )
    .await
    .unwrap();

    let seen = embed.seen.lock().unwrap();
    assert_eq!(seen[0], "digest only"); // NOT "digest only " (no trailing space)
}

// ─── (c) BOTH writers called once each ───

#[tokio::test]
async fn both_writers_receive_one_write_each() {
    let embed = FakeEmbedding {
        seen: Mutex::new(Vec::new()),
        mode: EmbedMode::Ok,
    };
    let sqlite = FakeSqliteWriter::default();
    let yaml = FakeYamlWriter::default();

    let entry = index_turn_end("id-5", 5, "d", "c", &embed, &sqlite, &yaml)
        .await
        .unwrap();

    let sqlite_writes = sqlite.writes.lock().unwrap();
    let yaml_writes = yaml.writes.lock().unwrap();
    assert_eq!(
        sqlite_writes.len(),
        1,
        "sqlite turn_index written exactly once"
    );
    assert_eq!(yaml_writes.len(), 1, "turn-index.yaml written exactly once");
    // Both sides got the same entry (same embedding + digest).
    assert_eq!(sqlite_writes[0], entry);
    assert_eq!(yaml_writes[0], entry);
    assert_eq!(entry.embedding, vec![0.1, 0.2, 0.3]);
    assert_eq!(entry.turn_id, 5);
}

// ─── (d) embed failure → EmbeddingFailed ───

#[tokio::test]
async fn embed_error_yields_embedding_failed() {
    let embed = FakeEmbedding {
        seen: Mutex::new(Vec::new()),
        mode: EmbedMode::Err,
    };
    let sqlite = FakeSqliteWriter::default();
    let yaml = FakeYamlWriter::default();

    let err = index_turn_end("id", 1, "d", "c", &embed, &sqlite, &yaml)
        .await
        .unwrap_err();
    assert!(matches!(err, AssemblyError::EmbeddingFailed(_)));
    // No writes happened on the embed-failure path.
    assert!(sqlite.writes.lock().unwrap().is_empty());
    assert!(yaml.writes.lock().unwrap().is_empty());
}

#[tokio::test]
async fn non_finite_embedding_yields_embedding_failed() {
    let embed = FakeEmbedding {
        seen: Mutex::new(Vec::new()),
        mode: EmbedMode::NonFinite,
    };
    let sqlite = FakeSqliteWriter::default();
    let yaml = FakeYamlWriter::default();

    let err = index_turn_end("id", 1, "d", "c", &embed, &sqlite, &yaml)
        .await
        .unwrap_err();
    assert!(matches!(err, AssemblyError::EmbeddingFailed(_)));
}

// ─── (e) writer failure → MemoryStoreFailure (writer-tag prefixed) ───

#[tokio::test]
async fn sqlite_writer_error_yields_memory_store_failure() {
    let embed = FakeEmbedding {
        seen: Mutex::new(Vec::new()),
        mode: EmbedMode::Ok,
    };
    let sqlite = FakeSqliteWriter {
        writes: Mutex::new(Vec::new()),
        err: true,
    };
    let yaml = FakeYamlWriter::default();

    let err = index_turn_end("id", 1, "d", "c", &embed, &sqlite, &yaml)
        .await
        .unwrap_err();
    match err {
        AssemblyError::MemoryStoreFailure(m) => assert!(m.starts_with(SQLITE_WRITER_PREFIX)),
        other => panic!("expected MemoryStoreFailure, got {other:?}"),
    }
}

// ─── round-9 adversarial: oversized embed source rejected fail-CLOSED ───

#[tokio::test]
async fn oversized_embed_source_is_rejected_before_embed_and_writes() {
    let embed = FakeEmbedding {
        seen: Mutex::new(Vec::new()),
        mode: EmbedMode::Ok,
    };
    let sqlite = FakeSqliteWriter::default();
    let yaml = FakeYamlWriter::default();

    // collapsed_view just over the 1 MiB cap → rejected before any I/O.
    let huge = "x".repeat(MAX_EMBED_SOURCE_BYTES + 1);
    let err = index_turn_end("id", 1, "d", &huge, &embed, &sqlite, &yaml)
        .await
        .unwrap_err();
    match err {
        AssemblyError::MemoryStoreFailure(m) => assert!(m.starts_with(OVERSIZE_PREFIX)),
        other => panic!("expected oversize MemoryStoreFailure, got {other:?}"),
    }
    // No embed call, no writes — rejected before the amplification point.
    assert!(
        embed.seen.lock().unwrap().is_empty(),
        "embed must not be called"
    );
    assert!(sqlite.writes.lock().unwrap().is_empty());
    assert!(yaml.writes.lock().unwrap().is_empty());
}

#[tokio::test]
async fn at_cap_embed_source_is_accepted() {
    let embed = FakeEmbedding {
        seen: Mutex::new(Vec::new()),
        mode: EmbedMode::Ok,
    };
    let sqlite = FakeSqliteWriter::default();
    let yaml = FakeYamlWriter::default();

    // digest "d" + " " + collapsed_view sized so the total == cap exactly.
    let cv = "x".repeat(MAX_EMBED_SOURCE_BYTES - 2); // "d" + " " + cv == cap
    let entry = index_turn_end("id", 1, "d", &cv, &embed, &sqlite, &yaml)
        .await
        .expect("exactly-at-cap source must be accepted");
    assert_eq!(entry.embedding, vec![0.1, 0.2, 0.3]);
}

#[tokio::test]
async fn yaml_writer_error_yields_memory_store_failure() {
    let embed = FakeEmbedding {
        seen: Mutex::new(Vec::new()),
        mode: EmbedMode::Ok,
    };
    let sqlite = FakeSqliteWriter::default();
    let yaml = FakeYamlWriter {
        writes: Mutex::new(Vec::new()),
        err: true,
    };

    let err = index_turn_end("id", 1, "d", "c", &embed, &sqlite, &yaml)
        .await
        .unwrap_err();
    match err {
        AssemblyError::MemoryStoreFailure(m) => assert!(m.starts_with(YAML_WRITER_PREFIX)),
        other => panic!("expected MemoryStoreFailure, got {other:?}"),
    }
}
