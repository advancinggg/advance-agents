//! Slice A fetch dispatch — local-path copy. Slice D extends to all 4 source
//! types: git+ via subprocess `git clone --depth 1` (M017 env hardening), tarball
//! via sync `tar`+`flate2` in `spawn_blocking`, registry via `RegistryClient`
//! async seam (chained into tarball untar).
//!
//! `copy_dir_no_symlinks` (free fn) is the security gate for step ② (local
//! source → tmp) and step ⑥ (tmp → install path). It rejects ALL symlinks
//! (regardless of target) to eliminate TOCTOU + privilege-escalation vectors.
//!
//! Pack lane P3:
//! - §4.2 (#13): a `@<40-hex>` ref pins a commit — fetched with `git init` /
//!   `remote add` / `fetch --depth 1 origin <sha>` / `checkout FETCH_HEAD`
//!   under the same env hardening as the clone path (the server must allow
//!   `uploadpack.allowAnySHA1InWant` / `allowReachableSHA1InWant`; GitHub does).
//! - §4.3 (#15): the copy is fd-relative on unix — see
//!   [`copy_dir_no_symlinks_observed`] — so the classify→open window the old
//!   path-based walk left open is closed (`openat2` `RESOLVE_NO_SYMLINKS |
//!   RESOLVE_BENEATH` on Linux; `openat` + `O_NOFOLLOW` elsewhere).
//!
//! Slice D introduces `FetchContext<'a>` as the entry surface for step ② so
//! that the dispatcher has access to per-install seams (`registry_client`) and
//! the wall-clock fetch timeout. The previous free `fetch_to_temp` function is
//! replaced with `FetchContext::fetch_to_temp(&SourceRef)`.

use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::{error::PackError, registry_client::RegistryClient, source::SourceRef};

const MAX_COPY_DEPTH: usize = 256;

/// Slice D constants for tarball extract — defense against gzip-bomb / tar-bomb
/// classes.
const TARBALL_TOTAL_CAP: u64 = 256 * 1024 * 1024; // 256 MiB
const TARBALL_PER_ENTRY_CAP: u64 = 64 * 1024 * 1024; // 64 MiB
const TARBALL_ENTRY_COUNT_CAP: usize = 65_536;

/// Slice D — step ② fetch dispatch context. Carries per-install seams
/// (`registry_client` for `SourceRef::Registry` dispatch) and the wall-clock
/// `fetch_timeout` honored by git subprocess + registry async fetch.
pub struct FetchContext<'a> {
    pub registry_client: Option<&'a dyn RegistryClient>,
    pub fetch_timeout: Duration,
}

impl<'a> FetchContext<'a> {
    /// Slice D — step ② fetch dispatch. Branches on `SourceRef` variant; all
    /// 4 source types produce a `TempPackDir` whose `path()` contains the
    /// extracted pack source tree (mirrors Local shape post-extract).
    pub async fn fetch_to_temp(&self, src: &SourceRef) -> Result<TempPackDir, PackError> {
        match src {
            SourceRef::Local(path) => fetch_local_to_temp(path),
            SourceRef::GitUrl { url, git_ref } => {
                fetch_git_to_temp(url, git_ref.as_deref(), self.fetch_timeout).await
            }
            SourceRef::Tarball(path) => fetch_tarball_to_temp(path).await,
            SourceRef::Registry { name, version } => {
                let client = self.registry_client.ok_or_else(|| {
                    PackError::InvalidManifest(
                        "registry source declared but no RegistryClient configured".into(),
                    )
                })?;
                // Allocate a temp dir for the blob; the client copies the
                // tarball into it; we then untar that into a separate
                // sibling subpath under the same tempdir.
                let tmp = tempfile::TempDir::new().map_err(|e| PackError::Io {
                    path: PathBuf::from(format!("registry:{name}@{version}")),
                    source: e,
                })?;
                let blob_dir = tmp.path().join("registry_blob");
                std::fs::create_dir_all(&blob_dir).map_err(|e| PackError::Io {
                    path: blob_dir.clone(),
                    source: e,
                })?;
                let tarball_path = match tokio::time::timeout(
                    self.fetch_timeout,
                    client.fetch_tarball(name, version, &blob_dir),
                )
                .await
                {
                    Ok(Ok(p)) => p,
                    Ok(Err(e)) => return Err(e),
                    Err(_) => {
                        return Err(PackError::RegistryFetchFailed {
                            name: name.clone(),
                            version: version.clone(),
                            reason: "fetch_tarball wall-clock timeout".into(),
                        })
                    }
                };
                // AUDIT round-1 fix (Codex Diff W2): validate the path returned
                // by RegistryClient is CONFINED under blob_dir. A buggy or
                // hostile client could otherwise return an arbitrary path
                // (e.g. /etc/passwd) and we'd dutifully try to untar it.
                let blob_dir_canon =
                    std::fs::canonicalize(&blob_dir).map_err(|e| PackError::Io {
                        path: blob_dir.clone(),
                        source: e,
                    })?;
                let tarball_canon =
                    std::fs::canonicalize(&tarball_path).map_err(|e| PackError::Io {
                        path: tarball_path.clone(),
                        source: e,
                    })?;
                if !tarball_canon.starts_with(&blob_dir_canon) {
                    return Err(PackError::RegistryFetchFailed {
                        name: name.clone(),
                        version: version.clone(),
                        reason: format!(
                            "client returned tarball path outside blob_dir: {} not under {}",
                            tarball_canon.display(),
                            blob_dir_canon.display()
                        ),
                    });
                }
                // Chain to tarball untar — produces TempPackDir holding both the
                // original blob and the extracted tree under tmp.path()/untar.
                // fetch_tarball_into_existing_tmp ALSO performs the
                // symlink_metadata + is_file probe (shared with the direct-
                // tarball path).
                fetch_tarball_into_existing_tmp(&tarball_path, tmp).await
            }
        }
    }
}

fn fetch_local_to_temp(path: &Path) -> Result<TempPackDir, PackError> {
    if !path.exists() {
        return Err(PackError::Io {
            path: path.to_path_buf(),
            source: std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "local pack source not found",
            ),
        });
    }
    let tmp = tempfile::TempDir::new().map_err(|e| PackError::Io {
        path: path.to_path_buf(),
        source: e,
    })?;
    let target = tmp.path().join("pack");
    copy_dir_no_symlinks(path, &target)?;
    Ok(TempPackDir { tmp, target })
}

/// A `git` invocation with the M017 cap-skills slice-E env hardening
/// (import.rs:230-328): cleared environment with only `PATH`; `HOME` /
/// `XDG_CONFIG_HOME` / `GIT_CONFIG_GLOBAL` / `GIT_CONFIG_SYSTEM` pointed at
/// `/dev/null` (ADVERSARIAL round-1 Claude Critical fix — git's libcurl
/// fallback recovers `$HOME` via `getpwuid` for `~/.netrc`, and a poisoned
/// `insteadOf` redirect in any config file must be invisible); no terminal
/// prompt; command-level `-c` overrides that forbid the `ext::` remote helper
/// (`protocol.ext.allow=never`), keep the default `protocol.allow=user`
/// policy, and neutralise checkout hooks (`core.hooksPath=/dev/null`) for the
/// P3 SHA-pin path's separate `checkout` step.
fn hardened_git(host_path: &str) -> std::process::Command {
    let mut cmd = std::process::Command::new("git");
    cmd.env_clear()
        .env("PATH", host_path)
        .env("HOME", "/dev/null")
        .env("XDG_CONFIG_HOME", "/dev/null")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_SYSTEM", "/dev/null")
        .env("GIT_TERMINAL_PROMPT", "0")
        .args([
            "-c",
            "protocol.ext.allow=never",
            "-c",
            "protocol.allow=user",
            "-c",
            "core.hooksPath=/dev/null",
        ]);
    cmd
}

/// Run a hardened git command to completion; the error is the diagnostic
/// `GitCloneFailed::reason` (git's first stderr line, or the spawn failure).
fn run_git(mut cmd: std::process::Command) -> Result<(), String> {
    match cmd.output() {
        Ok(out) if out.status.success() => Ok(()),
        Ok(out) => {
            let stderr = String::from_utf8_lossy(&out.stderr);
            Err(stderr
                .lines()
                .next()
                .unwrap_or("git non-zero exit")
                .to_string())
        }
        Err(e) => Err(format!("git spawn failed: {e}")),
    }
}

/// `git clone --depth 1 [--branch <ref>] -- <url> <dest>` (tag / branch refs).
fn git_clone(host_path: &str, url: &str, git_ref: Option<&str>, dest: &Path) -> Result<(), String> {
    let mut cmd = hardened_git(host_path);
    cmd.args(["clone", "--depth", "1"]);
    if let Some(r) = git_ref {
        cmd.arg("--branch").arg(r);
    }
    cmd.arg("--").arg(url).arg(dest);
    run_git(cmd)
}

/// Pack lane P3: commit-SHA pin — `git init <dest>`, `remote add
/// origin <url>`, `fetch --depth 1 origin <sha>`, `checkout --detach FETCH_HEAD`.
/// Installs EXACTLY `sha` regardless of where any branch points. Requires
/// `uploadpack.allowAnySHA1InWant` (or `allowReachableSHA1InWant`) on the
/// server; the first stderr line of a refusing server surfaces as the reason.
fn git_fetch_commit(host_path: &str, url: &str, sha: &str, dest: &Path) -> Result<(), String> {
    let mut init = hardened_git(host_path);
    init.arg("init").arg("--quiet").arg(dest);
    run_git(init)?;
    let mut remote = hardened_git(host_path);
    remote
        .arg("-C")
        .arg(dest)
        .args(["remote", "add", "origin", "--"])
        .arg(url);
    run_git(remote)?;
    let mut fetch = hardened_git(host_path);
    fetch
        .arg("-C")
        .arg(dest)
        .args(["fetch", "--quiet", "--depth", "1", "origin"])
        .arg(sha);
    run_git(fetch)?;
    let mut checkout = hardened_git(host_path);
    checkout
        .arg("-C")
        .arg(dest)
        .args(["checkout", "--quiet", "--detach", "FETCH_HEAD"]);
    run_git(checkout)
}

/// Slice D — subprocess `git clone --depth 1 [--branch <ref>] -- <url> <dest>`
/// (or, P3, the SHA-pin fetch sequence) with M017 cap-skills slice-E env
/// hardening. On Unix and Windows. Wraps `std::process::Command` in
/// `tokio::task::spawn_blocking` + `tokio::time::timeout`. Post-clone `.git/`
/// strip so `validate_pack_layout` at step ⑥ doesn't reject the metadata
/// directory.
async fn fetch_git_to_temp(
    url: &str,
    git_ref: Option<&str>,
    timeout: Duration,
) -> Result<TempPackDir, PackError> {
    // Preflight: verify git is in PATH. Surfaces a clean diagnostic before the
    // clone attempt.
    let preflight = tokio::task::spawn_blocking(|| {
        std::process::Command::new("git")
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    })
    .await
    .map_err(|e| PackError::GitCloneFailed {
        url: url.to_string(),
        reason: format!("spawn_blocking join: {e}"),
    })?;
    if !preflight {
        return Err(PackError::GitCloneFailed {
            url: url.to_string(),
            reason: "git binary not found in PATH".into(),
        });
    }

    let tmp = tempfile::TempDir::new().map_err(|e| PackError::Io {
        path: PathBuf::from(url),
        source: e,
    })?;
    let dest = tmp.path().join("git_clone");

    let host_path = std::env::var("PATH").unwrap_or_default();
    let url_owned = url.to_string();
    let git_ref_owned = git_ref.map(|s| s.to_string());
    let dest_owned = dest.clone();

    let outcome = tokio::time::timeout(
        timeout,
        tokio::task::spawn_blocking(move || match git_ref_owned.as_deref() {
            Some(sha) if crate::source::is_commit_sha(sha) => {
                git_fetch_commit(&host_path, &url_owned, sha, &dest_owned)
            }
            other => git_clone(&host_path, &url_owned, other, &dest_owned),
        }),
    )
    .await;

    match outcome {
        Ok(Ok(Ok(()))) => {}
        Ok(Ok(Err(reason))) => {
            return Err(PackError::GitCloneFailed {
                url: url.to_string(),
                reason,
            })
        }
        Ok(Err(e)) => {
            return Err(PackError::GitCloneFailed {
                url: url.to_string(),
                reason: format!("spawn_blocking join: {e}"),
            })
        }
        Err(_) => {
            return Err(PackError::GitCloneFailed {
                url: url.to_string(),
                reason: "wall-clock timeout".into(),
            })
        }
    }

    // Post-clone .git strip so step ⑥ validate_pack_layout doesn't reject the
    // metadata dir as an unknown top-level entry.
    let dot_git = dest.join(".git");
    if dot_git.exists() {
        std::fs::remove_dir_all(&dot_git).map_err(|e| PackError::Io {
            path: dot_git.clone(),
            source: e,
        })?;
    }

    Ok(TempPackDir { tmp, target: dest })
}

/// Slice D — extract a `.tar.gz` / `.tgz` archive into a temp directory with
/// per-entry security validation + size caps. Sync `tar`+`flate2` wrapped in
/// `tokio::task::spawn_blocking`. The symlink_metadata + is_file probe runs
/// inside `fetch_tarball_into_existing_tmp` so direct-tarball and registry-
/// chained paths share the same boundary check.
async fn fetch_tarball_to_temp(path: &Path) -> Result<TempPackDir, PackError> {
    let tmp = tempfile::TempDir::new().map_err(|e| PackError::Io {
        path: path.to_path_buf(),
        source: e,
    })?;
    fetch_tarball_into_existing_tmp(path, tmp).await
}

/// Inner tarball untar — accepts a pre-allocated TempDir so the registry-source
/// path can share the same RAII tempdir that holds the downloaded blob.
///
/// AUDIT round-1 fix (both Diff evaluators W3/W2): performs the same
/// symlink_metadata + is_file probe as `fetch_tarball_to_temp` so the registry
/// path doesn't bypass the leaf-symlink gate. A `RegistryClient::fetch_tarball`
/// impl that returns a symlink (or a non-regular file) is now rejected at the
/// same boundary as a direct-tarball install.
async fn fetch_tarball_into_existing_tmp(
    tarball: &Path,
    tmp: tempfile::TempDir,
) -> Result<TempPackDir, PackError> {
    let md = std::fs::symlink_metadata(tarball).map_err(|e| PackError::Io {
        path: tarball.to_path_buf(),
        source: e,
    })?;
    if md.file_type().is_symlink() {
        return Err(PackError::TarballExtractFailed {
            path: tarball.to_path_buf(),
            reason: "tarball source is a symlink".into(),
        });
    }
    if !md.is_file() {
        return Err(PackError::TarballExtractFailed {
            path: tarball.to_path_buf(),
            reason: "tarball source is not a regular file".into(),
        });
    }
    let dest = tmp.path().join("untar");
    std::fs::create_dir(&dest).map_err(|e| PackError::Io {
        path: dest.clone(),
        source: e,
    })?;
    let tarball_owned = tarball.to_path_buf();
    let dest_owned = dest.clone();

    tokio::task::spawn_blocking(move || untar_with_validation(&tarball_owned, &dest_owned))
        .await
        .map_err(|e| PackError::TarballExtractFailed {
            path: tarball.to_path_buf(),
            reason: format!("spawn_blocking join: {e}"),
        })??;

    Ok(TempPackDir { tmp, target: dest })
}

fn untar_with_validation(tarball: &Path, dest_root: &Path) -> Result<(), PackError> {
    let file = std::fs::File::open(tarball).map_err(|e| PackError::Io {
        path: tarball.to_path_buf(),
        source: e,
    })?;
    let gz = flate2::read::GzDecoder::new(file);
    let mut archive = tar::Archive::new(gz);

    let mut total_size: u64 = 0;
    let mut entry_count: usize = 0;
    let canonical_dest = std::fs::canonicalize(dest_root).map_err(|e| PackError::Io {
        path: dest_root.to_path_buf(),
        source: e,
    })?;

    for entry_result in archive
        .entries()
        .map_err(|e| PackError::TarballExtractFailed {
            path: tarball.to_path_buf(),
            reason: format!("tar header read: {e}"),
        })?
    {
        entry_count += 1;
        if entry_count > TARBALL_ENTRY_COUNT_CAP {
            return Err(PackError::TarballExtractFailed {
                path: tarball.to_path_buf(),
                reason: format!("entry count cap {TARBALL_ENTRY_COUNT_CAP} exceeded"),
            });
        }
        let mut entry = entry_result.map_err(|e| PackError::TarballExtractFailed {
            path: tarball.to_path_buf(),
            reason: format!("tar entry read: {e}"),
        })?;
        let header = entry.header();
        let entry_type = header.entry_type();
        // Type validation: only Regular + Directory allowed. Rejects Symlink,
        // Link (hardlink), Char, Block, Fifo, GNUSparse, GNULongName,
        // GNULongLink, XGlobalHeader, XHeader.
        if !(entry_type.is_file() || entry_type.is_dir()) {
            let kind = if entry_type.is_symlink() {
                "symlink"
            } else if matches!(entry_type, tar::EntryType::Link) {
                "hardlink"
            } else {
                "non-regular"
            };
            return Err(PackError::TarballExtractFailed {
                path: tarball.to_path_buf(),
                reason: format!("entry type {kind} rejected ({entry_type:?})"),
            });
        }
        // Size cap (per-entry + total).
        let entry_size = header.size().map_err(|e| PackError::TarballExtractFailed {
            path: tarball.to_path_buf(),
            reason: format!("tar header size read: {e}"),
        })?;
        if entry_size > TARBALL_PER_ENTRY_CAP {
            return Err(PackError::TarballExtractFailed {
                path: tarball.to_path_buf(),
                reason: format!(
                    "per-entry size cap {TARBALL_PER_ENTRY_CAP} exceeded ({entry_size} bytes)"
                ),
            });
        }
        total_size = total_size.saturating_add(entry_size);
        if total_size > TARBALL_TOTAL_CAP {
            return Err(PackError::TarballExtractFailed {
                path: tarball.to_path_buf(),
                reason: format!("total size cap {TARBALL_TOTAL_CAP} exceeded ({total_size} bytes)"),
            });
        }
        // Path validation: UTF-8, no null, no backslash, no absolute, no `..`,
        // no leading `/`. Clone the path into an owned PathBuf so the borrow
        // doesn't extend to the later `unpack_in` mutable borrow.
        let entry_path: PathBuf = entry
            .path()
            .map_err(|e| PackError::TarballExtractFailed {
                path: tarball.to_path_buf(),
                reason: format!("tar entry path read: {e}"),
            })?
            .into_owned();
        let path_str = entry_path
            .to_str()
            .ok_or_else(|| PackError::TarballExtractFailed {
                path: tarball.to_path_buf(),
                reason: format!("non-UTF-8 entry path: {entry_path:?}"),
            })?
            .to_string();
        if path_str.contains('\0') {
            return Err(PackError::TarballExtractFailed {
                path: tarball.to_path_buf(),
                reason: format!("null byte in entry path: {path_str}"),
            });
        }
        if path_str.contains('\\') {
            return Err(PackError::TarballExtractFailed {
                path: tarball.to_path_buf(),
                reason: format!("backslash in entry path (Windows path-shape attack): {path_str}"),
            });
        }
        if path_str.starts_with('/') {
            return Err(PackError::TarballExtractFailed {
                path: tarball.to_path_buf(),
                reason: format!("absolute path entry rejected: {path_str}"),
            });
        }
        for component in entry_path.components() {
            if matches!(component, std::path::Component::ParentDir) {
                return Err(PackError::TarballExtractFailed {
                    path: tarball.to_path_buf(),
                    reason: format!("parent-directory traversal in entry path: {path_str}"),
                });
            }
            if matches!(component, std::path::Component::RootDir) {
                return Err(PackError::TarballExtractFailed {
                    path: tarball.to_path_buf(),
                    reason: format!("absolute path component in entry: {path_str}"),
                });
            }
        }
        // Write the entry. `tar::Entry::unpack_in` performs join + extract.
        entry
            .unpack_in(&canonical_dest)
            .map_err(|e| PackError::TarballExtractFailed {
                path: tarball.to_path_buf(),
                reason: format!("tar entry unpack failed for {path_str}: {e}"),
            })?;
        // Post-write canonicalize+ancestor check (defense-in-depth against
        // intermediate-parent symlink races).
        // ADVERSARIAL round-2 Claude W4 fix: propagate canonicalize errors
        // explicitly via `?` instead of silently swallowing via
        // `if let Ok(canon)`. Without this, a file-disappearance race
        // between unpack_in write and the post-write canonicalize bypasses
        // the symlink-escape gate. NotFound is the one legitimate
        // exception (entry could be a directory entry that canonicalize
        // resolves to the dest root itself, which is fine — we keep the
        // ancestor check on Ok and treat NotFound as expected for
        // directory entries).
        let written = canonical_dest.join(&entry_path);
        match std::fs::canonicalize(&written) {
            Ok(canon) => {
                if !canon.starts_with(&canonical_dest) {
                    return Err(PackError::TarballExtractFailed {
                        path: tarball.to_path_buf(),
                        reason: format!(
                            "entry {path_str} escapes dest root via intermediate symlink"
                        ),
                    });
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // Directory entry or transient race; treat as not-escape since
                // tar::unpack_in already passed and we can't validate what
                // we can't see. Documented residual.
            }
            Err(e) => {
                return Err(PackError::TarballExtractFailed {
                    path: tarball.to_path_buf(),
                    reason: format!("post-write canonicalize failed for entry {path_str}: {e}"),
                });
            }
        }
    }
    Ok(())
}

pub struct TempPackDir {
    #[allow(dead_code)] // RAII handle — guards lifetime; not read directly.
    tmp: tempfile::TempDir,
    target: PathBuf,
}

impl TempPackDir {
    pub fn path(&self) -> &Path {
        &self.target
    }
}

/// Recursive directory copy that rejects ALL symlinks on BOTH sides of the
/// copy. Equivalent to [`copy_dir_no_symlinks_observed`] with a no-op
/// observer — see there for the fd-relative discipline.
///
/// - **Source side**: every entry is classified with a non-following stat and
///   then opened relative to its parent directory fd with `O_NOFOLLOW`
///   (Linux: `openat2` + `RESOLVE_NO_SYMLINKS | RESOLVE_BENEATH`), so a
///   symlink anywhere in the tree — including one swapped in between the
///   classification and the open — is refused, never followed.
/// - **Destination side**: `dst` MUST NOT pre-exist (fresh install required).
///   The top-level pre-check rejects ANY pre-existing `dst` (symlink, regular
///   dir, or regular file) and is the realistic-attack defense — tests
///   t39/t40/t43 exercise these three branches. Every nested entry is created
///   relative to its parent fd with `O_CREAT | O_EXCL` / `mkdirat`, so a
///   pre-existing child (concurrent attacker activity or stale state) is
///   rejected before any write.
///
/// The destination `dst` is created with `std::fs::create_dir` (not
/// `create_dir_all`) precisely so a pre-existing `dst` surfaces as
/// `Io::AlreadyExists` rather than being silently followed if it happens to
/// be a symlink. The caller is responsible for clearing a stale partial
/// install before retry — see MODULE-018 §3.6 "Step ⑥ rollback safety".
pub fn copy_dir_no_symlinks(src: &Path, dst: &Path) -> Result<(), PackError> {
    copy_dir_no_symlinks_observed(src, dst, &mut |_| {})
}

/// [`copy_dir_no_symlinks`] with a test hook (Pack lane P3).
///
/// `on_descend` fires once per directory entry AFTER it was classified as a
/// directory and IMMEDIATELY BEFORE it is opened for descent — i.e. inside the
/// classify→open window an attacker with write access to the source tree
/// would race. Production callers pass a no-op closure; the witness swaps the
/// entry for a symlink inside the callback and must observe a clean error
/// with nothing behind the link copied.
///
/// # Platform discipline
///
/// - **Linux**: children are opened with `openat2(dirfd, name,
///   O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC, RESOLVE_NO_SYMLINKS|RESOLVE_BENEATH)`
///   (files: `O_RDONLY|O_NOFOLLOW|O_NONBLOCK`); on a pre-5.6 kernel
///   (`ENOSYS`) the same single-component open falls back to `openat` +
///   `O_NOFOLLOW`, which is equivalent for a one-segment name.
/// - **Other unix (macOS)**: `openat` + `O_NOFOLLOW` per component. Every
///   descent and every file open is relative to the parent directory fd, so
///   the whole walk is fd-relative once the two roots are open.
/// - **Residual window (documented per §4.3)**: the two ROOT opens are
///   path-based (`open(src, O_DIRECTORY|O_NOFOLLOW)` after the `symlink_metadata`
///   probe; likewise for the freshly created `dst`). `O_NOFOLLOW` guards only
///   the last component, so a parent component of `src` / `dst` swapped for a
///   symlink in that instant would be followed. Both roots live in directories
///   this process owns (its own `TempDir`, the admin-owned `packs_dir`), which
///   bounds the residual to the caller's own trust domain.
/// - **Non-unix**: the pre-P3 path-based walk (per-entry `symlink_metadata`
///   probes, `on_descend` fired at the same point) — no fd-relative
///   primitives.
///
/// File mode bits (`0o777` mask) are preserved like `std::fs::copy`; the tree
/// depth is capped at 256 levels (`InvalidManifest`), and open handles stay
/// proportional to the depth, not the tree size.
pub fn copy_dir_no_symlinks_observed(
    src: &Path,
    dst: &Path,
    on_descend: &mut dyn FnMut(&Path),
) -> Result<(), PackError> {
    // Check `src` itself for symlink-ness BEFORE recursion.
    let md = std::fs::symlink_metadata(src).map_err(|e| PackError::Io {
        path: src.to_path_buf(),
        source: e,
    })?;
    if md.file_type().is_symlink() {
        return Err(PackError::InvalidManifest(format!(
            "symlink rejected at pack source root: {}",
            src.display()
        )));
    }
    if !md.is_dir() {
        return Err(PackError::InvalidManifest(format!(
            "pack source must be a directory, got: {}",
            src.display()
        )));
    }
    // Destination must NOT pre-exist — close TOCTOU at the top-level. A
    // pre-existing `dst` (whether symlink, file, or dir) is rejected; the
    // caller must clear stale state explicitly before retrying.
    match std::fs::symlink_metadata(dst) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => { /* OK — fresh */ }
        Ok(dst_md) => {
            let kind = if dst_md.file_type().is_symlink() {
                "symlink"
            } else if dst_md.is_dir() {
                "directory"
            } else {
                "non-directory entry"
            };
            return Err(PackError::InvalidManifest(format!(
                "copy destination must not pre-exist (rejected pre-existing {kind}): {}",
                dst.display()
            )));
        }
        Err(e) => {
            return Err(PackError::Io {
                path: dst.to_path_buf(),
                source: e,
            });
        }
    }
    std::fs::create_dir(dst).map_err(|e| PackError::Io {
        path: dst.to_path_buf(),
        source: e,
    })?;
    tree_copy::copy_tree(src, dst, on_descend)
}

/// fd-relative walk (unix). See [`copy_dir_no_symlinks_observed`].
#[cfg(unix)]
mod tree_copy {
    use std::ffi::{CStr, CString, OsStr};
    use std::fs::File;
    use std::os::fd::OwnedFd;
    use std::os::unix::ffi::OsStrExt;
    use std::path::Path;

    use rustix::fs::{
        fchmod, fstat, mkdirat, open, openat, statat, AtFlags, Dir, FileType, Mode, OFlags,
    };
    use rustix::io::Errno;

    use super::MAX_COPY_DEPTH;
    use crate::error::PackError;

    fn dir_flags() -> OFlags {
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC
    }

    /// `O_NONBLOCK` so a FIFO swapped in for a regular file cannot park the
    /// installer on `open`; the `fstat` after the open rejects it.
    fn file_read_flags() -> OFlags {
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK
    }

    fn file_create_flags() -> OFlags {
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC
    }

    fn io(path: &Path, e: Errno) -> PackError {
        PackError::Io {
            path: path.to_path_buf(),
            source: e.into(),
        }
    }

    fn pre_existed(path: &Path) -> PackError {
        PackError::InvalidManifest(format!(
            "destination entry pre-existed (symlink or stale state, rejected): {}",
            path.display()
        ))
    }

    /// `ELOOP` (a symlink where a plain entry was just classified) and `EXDEV`
    /// (Linux `RESOLVE_BENEATH` violation) on a single-component open mean the
    /// entry was replaced inside the classify→open window — report the symlink
    /// rejection rather than an opaque I/O error.
    fn swapped_or_io(path: &Path, e: Errno) -> PackError {
        match e {
            Errno::LOOP | Errno::XDEV => PackError::InvalidManifest(format!(
                "symlink rejected in pack content (entry replaced during copy): {}",
                path.display()
            )),
            other => io(path, other),
        }
    }

    /// Open the single path component `name` relative to `dirfd`, never
    /// following a symlink and never leaving `dirfd`.
    #[cfg(target_os = "linux")]
    fn open_beneath(
        dirfd: &OwnedFd,
        name: &CStr,
        flags: OFlags,
        mode: Mode,
    ) -> Result<OwnedFd, Errno> {
        use rustix::fs::{openat2, ResolveFlags};
        match openat2(
            dirfd,
            name,
            flags,
            mode,
            ResolveFlags::NO_SYMLINKS | ResolveFlags::BENEATH,
        ) {
            // Pre-5.6 kernel: `openat` + `O_NOFOLLOW` is equivalent for a
            // single component (there is no intermediate to resolve).
            Err(Errno::NOSYS) => openat(dirfd, name, flags, mode),
            other => other,
        }
    }

    #[cfg(not(target_os = "linux"))]
    fn open_beneath(
        dirfd: &OwnedFd,
        name: &CStr,
        flags: OFlags,
        mode: Mode,
    ) -> Result<OwnedFd, Errno> {
        openat(dirfd, name, flags, mode)
    }

    pub(super) fn copy_tree(
        src: &Path,
        dst: &Path,
        on_descend: &mut dyn FnMut(&Path),
    ) -> Result<(), PackError> {
        let src_fd = open(src, dir_flags(), Mode::empty()).map_err(|e| io(src, e))?;
        let dst_fd = open(dst, dir_flags(), Mode::empty()).map_err(|e| io(dst, e))?;
        copy_dir_fd(&src_fd, &dst_fd, src, dst, 0, on_descend)
    }

    fn copy_dir_fd(
        src_fd: &OwnedFd,
        dst_fd: &OwnedFd,
        src_path: &Path,
        dst_path: &Path,
        depth: usize,
        on_descend: &mut dyn FnMut(&Path),
    ) -> Result<(), PackError> {
        if depth > MAX_COPY_DEPTH {
            return Err(PackError::InvalidManifest(format!(
                "pack source exceeds max copy depth {MAX_COPY_DEPTH}: {}",
                src_path.display()
            )));
        }
        // Snapshot the entry names, then release the directory stream (and the
        // fd it holds) before descending, so open handles stay O(depth).
        let names: Vec<CString> = {
            let dir = Dir::read_from(src_fd).map_err(|e| io(src_path, e))?;
            let mut names = Vec::new();
            for entry in dir {
                let entry = entry.map_err(|e| io(src_path, e))?;
                let name = entry.file_name();
                if name.to_bytes() == b"." || name.to_bytes() == b".." {
                    continue;
                }
                names.push(name.to_owned());
            }
            names
        };
        for name in names {
            let os_name = OsStr::from_bytes(name.to_bytes());
            let entry_src = src_path.join(os_name);
            let entry_dst = dst_path.join(os_name);
            // Classify WITHOUT following (the same probe the path-based walk
            // used) — the open below re-checks against the same parent fd.
            let st = statat(src_fd, name.as_c_str(), AtFlags::SYMLINK_NOFOLLOW)
                .map_err(|e| io(&entry_src, e))?;
            match FileType::from_raw_mode(st.st_mode as _) {
                FileType::Symlink => {
                    return Err(PackError::InvalidManifest(format!(
                        "symlink rejected in pack content: {}",
                        entry_src.display()
                    )));
                }
                FileType::Directory => {
                    // The TOCTOU window the witness races (§4.3).
                    on_descend(&entry_src);
                    let child_src =
                        open_beneath(src_fd, name.as_c_str(), dir_flags(), Mode::empty())
                            .map_err(|e| swapped_or_io(&entry_src, e))?;
                    match mkdirat(dst_fd, name.as_c_str(), Mode::from_raw_mode(0o755)) {
                        Ok(()) => {}
                        Err(Errno::EXIST) => return Err(pre_existed(&entry_dst)),
                        Err(e) => return Err(io(&entry_dst, e)),
                    }
                    let child_dst =
                        open_beneath(dst_fd, name.as_c_str(), dir_flags(), Mode::empty())
                            .map_err(|e| io(&entry_dst, e))?;
                    copy_dir_fd(
                        &child_src,
                        &child_dst,
                        &entry_src,
                        &entry_dst,
                        depth + 1,
                        on_descend,
                    )?;
                }
                FileType::RegularFile => {
                    let in_fd =
                        open_beneath(src_fd, name.as_c_str(), file_read_flags(), Mode::empty())
                            .map_err(|e| swapped_or_io(&entry_src, e))?;
                    // fstat the OPEN handle: the type + mode come from the same
                    // inode the copy reads.
                    let in_st = fstat(&in_fd).map_err(|e| io(&entry_src, e))?;
                    if FileType::from_raw_mode(in_st.st_mode as _) != FileType::RegularFile {
                        return Err(PackError::InvalidManifest(format!(
                            "unsupported file type in pack (entry replaced during copy): {}",
                            entry_src.display()
                        )));
                    }
                    let mode = Mode::from_raw_mode(in_st.st_mode as _) & Mode::from_raw_mode(0o777);
                    let out_fd =
                        match open_beneath(dst_fd, name.as_c_str(), file_create_flags(), mode) {
                            Ok(fd) => fd,
                            Err(Errno::EXIST) => return Err(pre_existed(&entry_dst)),
                            Err(e) => return Err(io(&entry_dst, e)),
                        };
                    let mut reader = File::from(in_fd);
                    let mut writer = File::from(out_fd);
                    std::io::copy(&mut reader, &mut writer).map_err(|e| PackError::Io {
                        path: entry_dst.clone(),
                        source: e,
                    })?;
                    // Exact mode bits regardless of the umask applied at create.
                    fchmod(&writer, mode).map_err(|e| io(&entry_dst, e))?;
                }
                _ => {
                    return Err(PackError::InvalidManifest(format!(
                        "unsupported file type in pack: {}",
                        entry_src.display()
                    )));
                }
            }
        }
        Ok(())
    }
}

/// Path-based walk (non-unix): per-entry `symlink_metadata` probes; the
/// observer fires at the same classify→descend point.
#[cfg(not(unix))]
mod tree_copy {
    use std::path::{Path, PathBuf};

    use super::MAX_COPY_DEPTH;
    use crate::error::PackError;

    pub(super) fn copy_tree(
        src: &Path,
        dst: &Path,
        on_descend: &mut dyn FnMut(&Path),
    ) -> Result<(), PackError> {
        let mut stack: Vec<(PathBuf, PathBuf, usize)> = Vec::new();
        stack.push((src.to_path_buf(), dst.to_path_buf(), 0));

        while let Some((s, d, depth)) = stack.pop() {
            if depth > MAX_COPY_DEPTH {
                return Err(PackError::InvalidManifest(format!(
                    "pack source exceeds max copy depth {MAX_COPY_DEPTH}: {}",
                    s.display()
                )));
            }
            let read_dir = std::fs::read_dir(&s).map_err(|e| PackError::Io {
                path: s.clone(),
                source: e,
            })?;
            for entry in read_dir {
                let entry = entry.map_err(|e| PackError::Io {
                    path: s.clone(),
                    source: e,
                })?;
                let entry_path = entry.path();
                let entry_md =
                    std::fs::symlink_metadata(&entry_path).map_err(|e| PackError::Io {
                        path: entry_path.clone(),
                        source: e,
                    })?;
                let entry_dst = d.join(entry.file_name());

                if entry_md.file_type().is_symlink() {
                    return Err(PackError::InvalidManifest(format!(
                        "symlink rejected in pack content: {}",
                        entry_path.display()
                    )));
                }
                match std::fs::symlink_metadata(&entry_dst) {
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => { /* OK */ }
                    Ok(_) => {
                        return Err(PackError::InvalidManifest(format!(
                            "destination entry pre-existed (symlink or stale state, rejected): {}",
                            entry_dst.display()
                        )));
                    }
                    Err(e) => {
                        return Err(PackError::Io {
                            path: entry_dst.clone(),
                            source: e,
                        });
                    }
                }
                if entry_md.is_dir() {
                    on_descend(&entry_path);
                    std::fs::create_dir(&entry_dst).map_err(|e| PackError::Io {
                        path: entry_dst.clone(),
                        source: e,
                    })?;
                    stack.push((entry_path, entry_dst, depth + 1));
                } else if entry_md.is_file() {
                    std::fs::copy(&entry_path, &entry_dst).map_err(|e| PackError::Io {
                        path: entry_dst.clone(),
                        source: e,
                    })?;
                } else {
                    return Err(PackError::InvalidManifest(format!(
                        "unsupported file type in pack: {}",
                        entry_path.display()
                    )));
                }
            }
        }
        Ok(())
    }
}
