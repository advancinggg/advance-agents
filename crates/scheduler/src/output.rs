//! Slice C `write_result_to_dir` POSIX-atomic-rename helper for the
//! `output-dir/result.bin` auto-write described in AC-19.
//!
//! Atomicity: `tokio::fs::rename` provides directory-entry atomic
//! replacement on POSIX (the result.bin.tmp → result.bin swap is atomic
//! at the inode pointer level; no torn-half-file state during normal
//! process kill).
//!
//! fsync/fdatasync durability discipline is **deliberately omitted** —
//! formally declared in `waived_scope`. Slice C's failure model is
//! process-kill during write, not power-loss; durability is a follow-up
//! concern. AC-19 verification text does not require durability.
//!
//! `RunResult.output == None` short-circuits without creating any
//! file — Slice C drivers pass through whatever the hook returns; the
//! "no output → no result.bin" semantics is observable in
//! `tests/runnable_run_abi.rs` T39.
//!
//! **Path-confinement trust boundary** (Slice C adversarial round 1
//! Warning 2): the `dir` parameter is taken at face value but a defensive
//! `..` component rejection runs at every call (the symlink / TOCTOU /
//! absolute-path-into-shared-namespace concerns require admission-time
//! context that the future `submit-component` admission pipeline owns —
//! see MODULE-014 §3.8 (c) for the trust-boundary rationale). Slice C's
//! tempdir-rooted tests are not vulnerable to the deferred concerns.

use std::path::{Component, Path};
use std::sync::atomic::{AtomicU64, Ordering};

use crate::types::RunResult;

/// Slice C adversarial round 2 fix (W6): monotonic per-process counter
/// so concurrent `write_result_to_dir` calls (possibly from different
/// driver instances configured with the same `output_dir`) produce
/// distinct tmp filenames. Eliminates the cross-tenant tmp-clobber
/// torn-write race that the fixed-name `result.bin.tmp` had.
static TMP_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Atomic write of `result.output` (if Some) to `{dir}/result.bin`.
/// No-op when `result.output` is None.
///
/// **Defensive `..` rejection** (Slice C): if any component of `dir`
/// (after `Path::components()` normalization) is `Component::ParentDir`
/// (`..`), the function fails with `std::io::ErrorKind::InvalidInput`
/// without creating any file. This catches the easy class of
/// path-traversal attacks at the helper layer; symlink-follow,
/// TOCTOU-on-rename, and absolute-path-into-shared-namespace concerns
/// remain caller-layer concerns (the production caller — future
/// `submit-component` admission — applies its own path-confinement
/// logic with admission-time context). See `output.rs` module-level
/// rustdoc for the full trust-boundary delineation.
///
/// Errors propagate as `std::io::Error`. Callers in the 4 non-agent
/// drivers log errors via `eprintln!` (best-effort: the run itself
/// succeeded; the side-effect write failure is observable but
/// non-fatal).
pub async fn write_result_to_dir(dir: &Path, result: &RunResult) -> std::io::Result<()> {
    let Some(bytes) = result.output.as_ref() else {
        return Ok(());
    };
    // Defense-in-depth: reject `..` components at the helper layer.
    // Note: this does NOT defend against symlinks (a `dir` like
    // `/tmp/foo/symlink_to_../etc` would canonicalize to outside the
    // intended namespace). Symlink-follow protection requires
    // platform-specific OpenOptions (e.g. O_NOFOLLOW on Linux) and is
    // deferred to a future slice's submit-component admission path.
    if dir.components().any(|c| matches!(c, Component::ParentDir)) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "write_result_to_dir: rejected path with `..` component: {}",
                dir.display()
            ),
        ));
    }
    tokio::fs::create_dir_all(dir).await?;
    // Slice C adversarial round 2 (W6): use a per-process monotonic
    // counter + PID for the tmp filename so concurrent writers to the
    // same `dir` don't race on a fixed name. The final rename is still
    // atomic on POSIX; the rename order observed by readers is
    // implementation-defined (last-writer-wins), but no torn bytes
    // appear in the published `result.bin`.
    let counter = TMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id();
    let tmp_name = format!("result.bin.tmp.{pid}.{counter}");
    let tmp = dir.join(tmp_name);
    tokio::fs::write(&tmp, bytes).await?;
    tokio::fs::rename(&tmp, dir.join("result.bin")).await?;
    Ok(())
}
