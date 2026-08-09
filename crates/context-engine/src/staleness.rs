//! AC-08 — cross-turn staleness via git blob_id (§1.3.4 / REQ-225).
//!
//! §1.3.4: "turn-index.yaml records `read_file_versions[*].blob_id`. On load,
//! `is_turn_stale()` checks current git blob; **stale turns demoted to digest
//! only**."
//!
//! Two surfaces:
//! - [`is_turn_stale`] — pure function comparing a turn's recorded blob map
//!   against a current-blob map. No I/O; deterministic.
//! - [`check_and_demote`] — async wrapper that pulls the current blobs via a
//!   [`GitBlobReader`] and applies the §1.3.4 demotion.
//!
//! **Fail-CLOSED reader-error policy** (plan round-2 Claude W3): a
//! [`GitBlobReader`] `Err` is propagated as
//! [`StalenessCheckError::ReaderFailure`], NOT silently treated as `Stale`.
//! A silent-swallow would let an attacker who induces transient FS / git
//! errors force every turn to demote — a data-integrity DoS. A reader
//! `Ok(None)` (the tracked path is gone from the current tree) IS genuine
//! staleness → demote.
//!
//! `GitBlobReader` is a category-(B1) stand-in: ARCHITECTURE.md §6.1 has no
//! git-blob-by-path CONTRACT (CONTRACT-051 is MailboxDispatcher M006; M003
//! git-version owns commit-queue / rollback / checkpoint, none blob-by-path).
//! See MODULE-010 §3.6 Slice-D (e).

use std::collections::BTreeMap;
use std::path::PathBuf;

use crate::ports::{
    BlobId, CheckedTurn, DigestOnlyView, GitBlobReader, StalenessVerdict, TurnView,
};

/// Defense-in-depth upper bound on the number of tracked paths a single turn's
/// staleness check fans out over. Each tracked path triggers one
/// [`GitBlobReader`] call; without a cap, a poisoned turn-index entry with a
/// huge `read_file_versions` map would amplify into that many sequential
/// git-blob I/O calls (the round-9 adversarial fan-out finding). **The PRIMARY
/// bound is upstream** — MODULE-011 records `read_file_versions` from the files
/// a turn actually read; a turn legitimately reading more than this many
/// distinct files is anomalous. Fail-CLOSED: a turn exceeding the cap returns
/// [`StalenessCheckError::TooManyTrackedPaths`] rather than silently iterating.
pub const MAX_TRACKED_PATHS: usize = 4096;

/// Error from [`check_and_demote`]. The local control-flow error enum owned by
/// this module (NOT a `ports.rs` data carrier — MODULE-010 §4.1 carrier rule).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StalenessCheckError {
    /// A [`GitBlobReader`] lookup failed for a tracked path. Propagated up the
    /// stack (fail-CLOSED) so the caller can retry / surface to operator
    /// rather than mis-classifying the turn as stale.
    ReaderFailure { path: PathBuf, reason: String },
    /// The turn's `read_file_versions` map exceeds [`MAX_TRACKED_PATHS`].
    /// Returned BEFORE any reader fan-out, so a poisoned oversized map cannot
    /// amplify into an unbounded I/O burst (round-9 adversarial defense).
    TooManyTrackedPaths { count: usize, max: usize },
}

impl std::fmt::Display for StalenessCheckError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StalenessCheckError::ReaderFailure { path, reason } => {
                write!(f, "git blob reader failed for {}: {reason}", path.display())
            }
            StalenessCheckError::TooManyTrackedPaths { count, max } => {
                write!(f, "turn tracks {count} paths, exceeds the {max} cap")
            }
        }
    }
}

impl std::error::Error for StalenessCheckError {}

/// Pure staleness verdict: compare the turn's recorded `(path, blob_id)` map
/// against the current-tree blob map. `Fresh` iff every recorded path is
/// present in `current_blobs` with an identical blob id; otherwise `Stale`
/// with the diverged (or missing) paths (sorted, deterministic).
///
/// Only the recorded paths are checked — extra paths in `current_blobs` that
/// the turn never read do not affect staleness (the turn's observations are
/// what can go stale).
pub fn is_turn_stale(
    turn_blobs: &TurnReadFileVersions,
    current_blobs: &BTreeMap<PathBuf, BlobId>,
) -> StalenessVerdict {
    let mut diverged: Vec<PathBuf> = Vec::new();
    for (path, recorded) in &turn_blobs.entries {
        match current_blobs.get(path) {
            Some(current) if current == recorded => {} // unchanged
            _ => diverged.push(path.clone()),          // changed OR missing
        }
    }
    if diverged.is_empty() {
        StalenessVerdict::Fresh
    } else {
        // `BTreeMap` iteration is already sorted, so `diverged` is sorted.
        StalenessVerdict::Stale { diverged }
    }
}

/// Async staleness check + §1.3.4 demotion. Reads the current blob for each
/// tracked path via `reader`, builds the current-blob map, runs
/// [`is_turn_stale`], and on `Stale` demotes the turn to digest-only.
///
/// Reader semantics:
/// - `Ok(Some(blob))` → contributes to the current-blob map.
/// - `Ok(None)` → the path is gone; recorded as "absent" so the comparison
///   treats it as diverged (genuine staleness).
/// - `Err(e)` → propagated as [`StalenessCheckError::ReaderFailure`]
///   (fail-CLOSED; the check does NOT continue and does NOT demote).
pub async fn check_and_demote(
    turn: TurnView,
    reader: &dyn GitBlobReader,
) -> Result<CheckedTurn, StalenessCheckError> {
    // Defense-in-depth (round-9 adversarial): cap the reader fan-out BEFORE
    // issuing any I/O, so a poisoned turn with a huge read_file_versions map
    // cannot amplify into an unbounded sequential git-blob burst.
    let n = turn.read_file_versions.entries.len();
    if n > MAX_TRACKED_PATHS {
        return Err(StalenessCheckError::TooManyTrackedPaths {
            count: n,
            max: MAX_TRACKED_PATHS,
        });
    }

    let mut current_blobs: BTreeMap<PathBuf, BlobId> = BTreeMap::new();
    for path in turn.read_file_versions.entries.keys() {
        match reader.current_blob(path).await {
            Ok(Some(blob)) => {
                current_blobs.insert(path.clone(), blob);
            }
            // Missing path: leave it OUT of current_blobs so is_turn_stale's
            // `current_blobs.get(path)` → None → diverged (stale). This is the
            // intended §1.3.4 behavior (a tracked path that vanished is stale).
            Ok(None) => {}
            Err(e) => {
                return Err(StalenessCheckError::ReaderFailure {
                    path: path.clone(),
                    reason: e.0,
                });
            }
        }
    }

    match is_turn_stale(&turn.read_file_versions, &current_blobs) {
        StalenessVerdict::Fresh => Ok(CheckedTurn::Fresh(turn)),
        StalenessVerdict::Stale { .. } => Ok(CheckedTurn::DemotedToDigest(DigestOnlyView {
            turn_id: turn.turn_id,
            digest: turn.digest,
        })),
    }
}

// Re-export the carrier used in the pure-fn signature so call sites can
// `use crate::staleness::TurnReadFileVersions` without reaching into ports.
pub use crate::ports::TurnReadFileVersions;
