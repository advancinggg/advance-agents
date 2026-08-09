//! Slice G (2026-05-09) — `Tunables` / `TunablesProvider` unit tests.
//!
//! Verifies:
//! 1. `StaticTunablesProvider::default()` returns 768/3/true.
//! 2. `R2d2SqliteIndexHandle::with_tunables(...)` plumbs custom dim into
//!    upsert validation: with embedding_dim=1024, a 768-dim embedding
//!    upsert fails with InvalidConfig.
//! 3. `R2d2RecallImpl::with_tunables(...)` exposes `current_embedding_dim()`
//!    that mirrors the provider's snapshot.
//!
//! No `set_tunables` test — Slice G dropped that API to keep
//! R2d2SqliteIndexHandle Clone-able (a `Mutex<Arc<dyn ...>>` field would
//! break `derive(Clone)`).

use std::sync::Arc;

use advance_database::{
    DbError, R2d2RecallImpl, R2d2SqliteIndexHandle, R2d2UnifiedSearchImpl, SqliteIndexHandle,
    StaticTunablesProvider, Tunables, DEFAULT_EMBEDDING_DIM, DEFAULT_RECALL_MAX_DEPTH,
    DEFAULT_WAL_MODE,
};

#[test]
fn static_tunables_provider_default_returns_canonical_values() {
    let p = StaticTunablesProvider::default();
    let t = advance_database::TunablesProvider::current(&p);
    assert_eq!(t.embedding_dim, 768);
    assert_eq!(t.embedding_dim, DEFAULT_EMBEDDING_DIM);
    assert_eq!(t.recall_max_depth, 3);
    assert_eq!(t.recall_max_depth, DEFAULT_RECALL_MAX_DEPTH);
    assert!(t.wal_mode);
    assert_eq!(t.wal_mode, DEFAULT_WAL_MODE);
}

#[test]
fn r2d2_handle_with_tunables_threads_custom_dim_into_upsert_validation() {
    let custom = StaticTunablesProvider::new(Tunables {
        embedding_dim: 1024,
        recall_max_depth: 5,
        wal_mode: true,
    });
    let tunables: Arc<dyn advance_database::TunablesProvider> = Arc::new(custom);

    // Use new_in_memory's path-equivalent: we want an in-memory file. The
    // public surface lacks `with_tunables_in_memory`; build via a tempdir
    // file instead so we exercise the actual `with_tunables` constructor.
    let dir = tempfile::tempdir().expect("tempdir");
    let db_path = dir.path().join("tunables_smoke.db");
    let handle =
        R2d2SqliteIndexHandle::with_tunables(&db_path, 1, tunables.clone()).expect("with_tunables");

    assert_eq!(handle.current_tunables().embedding_dim, 1024);
    assert_eq!(handle.current_tunables().recall_max_depth, 5);
    assert!(handle.current_tunables().wal_mode);

    // 768-dim embedding should be rejected because tunables say 1024.
    let one_hot_768: Vec<f32> = (0..768).map(|i| if i == 0 { 1.0 } else { 0.0 }).collect();
    let result = handle.upsert_content_index(
        "/",
        "/notes.md",
        "test",
        Some(&one_hot_768),
        Some("2026-01-01T00:00:00.000Z"),
    );
    let err = result.expect_err("768-dim upsert should fail with custom dim=1024");
    match err {
        DbError::InvalidConfig(msg) => {
            assert!(
                msg.contains("1024"),
                "error message should name the expected dim 1024: {msg}"
            );
        }
        other => panic!("expected InvalidConfig, got {other:?}"),
    }

    // Note: a 1024-dim embedding CANNOT actually succeed against this
    // handle's vec0 schema (created with `embedding float[768]` per
    // schema.rs). The application-level validator catches the dim
    // mismatch before SQL — that's the failure case asserted above. A
    // genuine "rebuild with new dim" requires the vector-index rebuild
    // slice (per MODULE-004 §2.10's operator note); out of scope here.
    //
    // What this test pins is exactly: the application-level validator
    // consults `tunables.current().embedding_dim`, NOT a compile-time
    // constant. That's the AC-19 behavioral half.
}

#[test]
fn r2d2_recall_impl_with_tunables_exposes_current_embedding_dim() {
    let custom = StaticTunablesProvider::new(Tunables {
        embedding_dim: 2048,
        recall_max_depth: 7,
        wal_mode: false,
    });
    let tunables: Arc<dyn advance_database::TunablesProvider> = Arc::new(custom);

    let dir = tempfile::tempdir().expect("tempdir");
    let db_path = dir.path().join("recall_tunables.db");
    let handle =
        R2d2SqliteIndexHandle::with_tunables(&db_path, 1, tunables.clone()).expect("handle");

    let recall = R2d2RecallImpl::with_tunables(handle, tunables.clone());
    assert_eq!(
        recall.current_embedding_dim(),
        2048,
        "current_embedding_dim mirrors the provider's snapshot"
    );
    assert_eq!(recall.current_tunables().recall_max_depth, 7);
}

#[test]
fn r2d2_unified_search_with_tunables_delegates_through_inner_recall() {
    // Slice G C3 fix: R2d2UnifiedSearchImpl is single-owner via the inner
    // recall — no dual tunables field. This test pins the contract by
    // constructing with custom tunables and verifying that unified_search
    // behavior follows the provider snapshot. Negative test: a 768-dim
    // search would be rejected by validate_query_embedding when
    // tunables.embedding_dim == 1024.
    let custom = StaticTunablesProvider::new(Tunables {
        embedding_dim: 1024,
        recall_max_depth: 3,
        wal_mode: true,
    });
    let tunables: Arc<dyn advance_database::TunablesProvider> = Arc::new(custom);

    let dir = tempfile::tempdir().expect("tempdir");
    let db_path = dir.path().join("unified_tunables.db");
    let handle =
        R2d2SqliteIndexHandle::with_tunables(&db_path, 1, tunables.clone()).expect("handle");

    let unified = R2d2UnifiedSearchImpl::with_tunables(handle, 10, tunables);

    // Use a runtime to drive the async search.
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");

    let one_hot_768: Vec<f32> = (0..768).map(|i| if i == 0 { 1.0 } else { 0.0 }).collect();
    let result = rt.block_on(async {
        advance_database::UnifiedSearch::search(&unified, "/", "q", &one_hot_768).await
    });
    let err = result.expect_err("768-dim query should fail with tunables.embedding_dim=1024");
    match err {
        DbError::InvalidConfig(msg) => {
            assert!(msg.contains("1024"), "error names new dim: {msg}");
        }
        other => panic!("expected InvalidConfig, got {other:?}"),
    }
}
