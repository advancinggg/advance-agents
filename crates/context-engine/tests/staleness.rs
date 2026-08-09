//! AC-08 (MODULE-010-T11) — cross-turn staleness via git blob_id.
//!
//! 6 sub-cases: all-match → Fresh; one-diverges → DemotedToDigest; missing-path
//! → DemotedToDigest; reader-Err → ReaderFailure (fail-CLOSED); pure-fn
//! determinism; reader-once-per-tracked-path.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Mutex;

use advance_context_engine::{
    check_and_demote, is_turn_stale, BlobId, CheckedTurn, GitBlobReader, PortError,
    StalenessCheckError, StalenessVerdict, TurnReadFileVersions, TurnView, MAX_TRACKED_PATHS,
};
use async_trait::async_trait;

// ─── fake GitBlobReader ───

/// Configured per-path responses + a call counter (for the once-per-path
/// assertion).
struct FakeGitBlob {
    /// path → the reader's response.
    responses: BTreeMap<PathBuf, Result<Option<BlobId>, PortError>>,
    calls: Mutex<Vec<PathBuf>>,
}

impl FakeGitBlob {
    fn new(responses: BTreeMap<PathBuf, Result<Option<BlobId>, PortError>>) -> Self {
        Self {
            responses,
            calls: Mutex::new(Vec::new()),
        }
    }
}

#[async_trait]
impl GitBlobReader for FakeGitBlob {
    async fn current_blob(&self, path: &std::path::Path) -> Result<Option<BlobId>, PortError> {
        self.calls.lock().unwrap().push(path.to_path_buf());
        self.responses.get(path).cloned().unwrap_or(Ok(None)) // unconfigured path == absent
    }
}

fn turn_with(paths: &[(&str, &str)]) -> TurnView {
    let mut entries = BTreeMap::new();
    for (p, b) in paths {
        entries.insert(PathBuf::from(p), BlobId(b.to_string()));
    }
    TurnView {
        turn_id: 7,
        digest: "turn 7 digest".into(),
        collapsed_view: "turn 7 collapsed view".into(),
        read_file_versions: TurnReadFileVersions { entries },
    }
}

// ─── (a) all blobs match → Fresh ───

#[tokio::test]
async fn all_blobs_match_is_fresh() {
    let turn = turn_with(&[("src/a.rs", "blob-a"), ("src/b.rs", "blob-b")]);
    let mut responses = BTreeMap::new();
    responses.insert(PathBuf::from("src/a.rs"), Ok(Some(BlobId("blob-a".into()))));
    responses.insert(PathBuf::from("src/b.rs"), Ok(Some(BlobId("blob-b".into()))));
    let reader = FakeGitBlob::new(responses);

    let checked = check_and_demote(turn.clone(), &reader).await.unwrap();
    match checked {
        CheckedTurn::Fresh(t) => assert_eq!(t, turn),
        other => panic!("expected Fresh, got {other:?}"),
    }
}

// ─── (b) one blob diverges → DemotedToDigest ───

#[tokio::test]
async fn one_blob_diverges_is_demoted() {
    let turn = turn_with(&[("src/a.rs", "blob-a"), ("src/b.rs", "blob-b")]);
    let mut responses = BTreeMap::new();
    responses.insert(PathBuf::from("src/a.rs"), Ok(Some(BlobId("blob-a".into()))));
    // b.rs now has a DIFFERENT blob → diverged.
    responses.insert(
        PathBuf::from("src/b.rs"),
        Ok(Some(BlobId("blob-b-CHANGED".into()))),
    );
    let reader = FakeGitBlob::new(responses);

    let checked = check_and_demote(turn, &reader).await.unwrap();
    match checked {
        CheckedTurn::DemotedToDigest(d) => {
            assert_eq!(d.turn_id, 7);
            assert_eq!(d.digest, "turn 7 digest");
        }
        other => panic!("expected DemotedToDigest, got {other:?}"),
    }
}

// ─── (c) missing path (reader Ok(None)) → DemotedToDigest ───

#[tokio::test]
async fn missing_path_is_demoted() {
    let turn = turn_with(&[("src/a.rs", "blob-a"), ("src/gone.rs", "blob-gone")]);
    let mut responses = BTreeMap::new();
    responses.insert(PathBuf::from("src/a.rs"), Ok(Some(BlobId("blob-a".into()))));
    // gone.rs no longer exists in the working tree → Ok(None).
    responses.insert(PathBuf::from("src/gone.rs"), Ok(None));
    let reader = FakeGitBlob::new(responses);

    let checked = check_and_demote(turn, &reader).await.unwrap();
    assert!(matches!(checked, CheckedTurn::DemotedToDigest(_)));
}

// ─── (d) reader Err → ReaderFailure (fail-CLOSED, NOT demoted) ───

#[tokio::test]
async fn reader_error_propagates_fail_closed() {
    let turn = turn_with(&[("src/a.rs", "blob-a")]);
    let mut responses = BTreeMap::new();
    responses.insert(
        PathBuf::from("src/a.rs"),
        Err(PortError("git index lock contention".into())),
    );
    let reader = FakeGitBlob::new(responses);

    let err = check_and_demote(turn, &reader).await.unwrap_err();
    match err {
        StalenessCheckError::ReaderFailure { path, reason } => {
            assert_eq!(path, PathBuf::from("src/a.rs"));
            assert_eq!(reason, "git index lock contention");
        }
        other => panic!("expected ReaderFailure, got {other:?}"),
    }
}

// ─── (e) pure-fn determinism ───

#[test]
fn is_turn_stale_is_deterministic() {
    let turn = turn_with(&[("src/a.rs", "blob-a"), ("src/b.rs", "blob-b")]);
    let mut current = BTreeMap::new();
    current.insert(PathBuf::from("src/a.rs"), BlobId("blob-a".into()));
    current.insert(PathBuf::from("src/b.rs"), BlobId("blob-b-CHANGED".into()));

    let v1 = is_turn_stale(&turn.read_file_versions, &current);
    let v2 = is_turn_stale(&turn.read_file_versions, &current);
    assert_eq!(v1, v2);
    match v1 {
        StalenessVerdict::Stale { diverged } => {
            assert_eq!(diverged, vec![PathBuf::from("src/b.rs")]);
        }
        StalenessVerdict::Fresh => panic!("expected Stale"),
    }
}

// ─── round-9 adversarial: oversized read_file_versions map rejected ───

#[tokio::test]
async fn too_many_tracked_paths_rejected_before_fanout() {
    // A turn tracking MAX_TRACKED_PATHS+1 distinct paths must be rejected
    // BEFORE any GitBlobReader call (fan-out DoS defense).
    let mut entries = std::collections::BTreeMap::new();
    for i in 0..=MAX_TRACKED_PATHS {
        entries.insert(
            PathBuf::from(format!("src/f{i}.rs")),
            BlobId(format!("b{i}")),
        );
    }
    let turn = TurnView {
        turn_id: 9,
        digest: "big turn".into(),
        collapsed_view: "cv".into(),
        read_file_versions: TurnReadFileVersions { entries },
    };
    // Reader that PANICS if ever called — proves rejection happens before fan-out.
    struct PanicReader;
    #[async_trait]
    impl GitBlobReader for PanicReader {
        async fn current_blob(&self, _path: &std::path::Path) -> Result<Option<BlobId>, PortError> {
            panic!("reader must NOT be called when the path cap is exceeded");
        }
    }

    let err = check_and_demote(turn, &PanicReader).await.unwrap_err();
    match err {
        StalenessCheckError::TooManyTrackedPaths { count, max } => {
            assert_eq!(count, MAX_TRACKED_PATHS + 1);
            assert_eq!(max, MAX_TRACKED_PATHS);
        }
        other => panic!("expected TooManyTrackedPaths, got {other:?}"),
    }
}

// ─── (f) reader called exactly once per tracked path ───

#[tokio::test]
async fn reader_called_once_per_tracked_path() {
    let turn = turn_with(&[("src/a.rs", "blob-a"), ("src/b.rs", "blob-b")]);
    let mut responses = BTreeMap::new();
    responses.insert(PathBuf::from("src/a.rs"), Ok(Some(BlobId("blob-a".into()))));
    responses.insert(PathBuf::from("src/b.rs"), Ok(Some(BlobId("blob-b".into()))));
    let reader = FakeGitBlob::new(responses);

    let _ = check_and_demote(turn, &reader).await.unwrap();

    let mut calls = reader.calls.lock().unwrap().clone();
    calls.sort();
    assert_eq!(
        calls,
        vec![PathBuf::from("src/a.rs"), PathBuf::from("src/b.rs")]
    );
}
