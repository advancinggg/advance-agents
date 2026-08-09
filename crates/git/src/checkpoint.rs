//! CONTRACT-022 `NamedCheckpoint` — Git annotated tag checkpoint primitive.
//!
//! Matches MODULE-003 §1.4.3 + §2.3 byte-for-byte:
//! - Tag name: `refs/tags/checkpoint/{agent_id}/{label}`.
//! - Tag message: strict JSON — `{}` for full-directory, `{"paths":[...]}`
//!   for path-scoped. Any deviation (non-object, extra keys, null/non-array
//!   `paths`, non-string member, BOM-prefix) → `valid: false` at
//!   `parse_tag_message` boundary. Rollback surfaces invalid entries as
//!   `CheckpointError::InvalidState` per §1.4.3 line 411-413.
//! - Path normalization (PRD §7.2 line 1987): trailing-slash → dedupe →
//!   parent-child fold → dictionary sort. Applied at `create()` before the
//!   JSON message is written; `list()` returns paths verbatim from the
//!   stored message.
//!
//! # Concurrency
//!
//! Each of `create`/`list`/`delete` acquires the per-repo-path
//! `crate::coord::git_repo_lock` at method entry, serializing with
//! [`crate::commit_queue::DefaultGitCommitQueue`] workers and
//! [`crate::rollback::DefaultWorkspaceRollback`] invocations on the same
//! repo. The lock is `std::sync::Mutex` — the critical section is entirely
//! synchronous libgit2 work; using `tokio::sync::Mutex::blocking_lock` would
//! panic on the blocking-pool thread that carries a tokio runtime handle.

use crate::coord::git_repo_lock;
use crate::error::{CheckpointError, DeniedReason};
use crate::repo::open_repo_internal;
use git2::{Repository, Signature};
use serde_json::Value;
use std::path::{Component, Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// Public per-entry view returned by `list()`. Shape matches MODULE-003 §1.4.3
/// line 365-371 (label, agent, timestamp, paths, valid).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckpointEntry {
    pub label: String,
    pub agent: String,
    /// Unix seconds as a decimal string (matches §1.4.3's `timestamp: String`).
    pub timestamp: String,
    /// `None` = full-directory checkpoint; `Some(list)` = path-scoped.
    pub paths: Option<Vec<PathBuf>>,
    /// `false` for corrupt tag messages (AC-10); `true` otherwise including
    /// legacy empty-message tags normalized to `{}` (AC-11).
    pub valid: bool,
}

/// CONTRACT-022 trait.
pub trait NamedCheckpoint: Send + Sync {
    fn create(
        &self,
        agent_id: &str,
        label: &str,
        paths: Option<Vec<PathBuf>>,
    ) -> Result<(), CheckpointError>;
    fn list(&self, agent_id: &str) -> Result<Vec<CheckpointEntry>, CheckpointError>;
    fn delete(&self, agent_id: &str, label: &str) -> Result<(), CheckpointError>;
}

/// Default impl — canonicalized repo path is cached for coord mutex keying.
pub struct DefaultNamedCheckpoint {
    canonical_repo: PathBuf,
}

impl DefaultNamedCheckpoint {
    /// `repo_path` must point at a repository already bootstrapped via
    /// [`crate::repo::bootstrap_repo_at`]. Canonicalization is required so the
    /// coord mutex key matches the commit queue's registration.
    pub fn new(repo_path: PathBuf) -> Result<Self, CheckpointError> {
        let canonical_repo = std::fs::canonicalize(&repo_path).map_err(|e| {
            CheckpointError::Io(std::io::Error::new(
                e.kind(),
                format!(
                    "cannot canonicalize repo path for checkpoint impl: {} ({e})",
                    repo_path.display()
                ),
            ))
        })?;
        Ok(Self { canonical_repo })
    }
}

impl NamedCheckpoint for DefaultNamedCheckpoint {
    fn create(
        &self,
        agent_id: &str,
        label: &str,
        paths: Option<Vec<PathBuf>>,
    ) -> Result<(), CheckpointError> {
        let coord = git_repo_lock(&self.canonical_repo);
        let _guard = coord
            .lock()
            .expect("git coord mutex poisoned in checkpoint::create");
        let repo = open_repo_internal(&self.canonical_repo)?;
        validate_ref_component(agent_id, "agent_id")?;
        validate_ref_component(label, "label")?;
        let tag_name = format!("checkpoint/{agent_id}/{label}");
        // Composed-name grammar probe — catches anything the per-component
        // check missed (e.g., combined sequences that libgit2 rejects).
        if !probe_tag_name_valid(&tag_name) {
            return Err(CheckpointError::InvalidLabel {
                label: label.to_string(),
                reason: "composed ref name fails Git grammar".to_string(),
            });
        }

        // Normalize paths + input validation. `None` OR `Some(empty)` → `{}`.
        let normalized: Option<Vec<PathBuf>> = match paths {
            None => None,
            Some(v) if v.is_empty() => None,
            Some(v) => {
                // First reject any invalid path. `create()` rejects any `.agent/`
                // path (writable-domain rule — see §3.8).
                for p in &v {
                    validate_create_path(p)?;
                }
                Some(normalize_paths(&repo, v))
            }
        };

        let json_value = match &normalized {
            None => serde_json::json!({}),
            Some(ps) => {
                let s: Vec<String> = ps
                    .iter()
                    .map(|p| p.to_string_lossy().into_owned())
                    .collect();
                serde_json::json!({ "paths": s })
            }
        };
        let message = serde_json::to_string(&json_value)
            .map_err(|e| CheckpointError::Io(std::io::Error::other(e.to_string())))?;

        // Check for existing tag → Conflict.
        let full_ref = format!("refs/tags/{tag_name}");
        if repo.find_reference(&full_ref).is_ok() {
            return Err(CheckpointError::Conflict {
                label: label.to_string(),
            });
        }

        // Target HEAD commit. Unborn HEAD → no target; checkpoint against an
        // unborn branch is meaningless (the repo has no commits yet). Fail
        // with a clear error rather than silently producing a tag pointing at
        // a missing object.
        let head = match repo.head() {
            Ok(h) => h,
            Err(e) if e.code() == git2::ErrorCode::UnbornBranch => {
                return Err(CheckpointError::InvalidState {
                    label: label.to_string(),
                    reason: "cannot create checkpoint on unborn branch (no commits yet)"
                        .to_string(),
                });
            }
            Err(e) => return Err(CheckpointError::from(e)),
        };
        let target = head.peel_to_commit()?;

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        let when = git2::Time::new(now, 0);
        let sig = Signature::new("runtime", "runtime@advance-agents", &when)?;
        // `force=false` — we already checked for existence above, so any
        // collision from a concurrent writer races only against the coord
        // mutex (impossible) or a manual tag operation outside the runtime
        // (out of scope).
        repo.tag(&tag_name, target.as_object(), &sig, &message, false)?;
        Ok(())
    }

    fn list(&self, agent_id: &str) -> Result<Vec<CheckpointEntry>, CheckpointError> {
        let coord = git_repo_lock(&self.canonical_repo);
        let _guard = coord
            .lock()
            .expect("git coord mutex poisoned in checkpoint::list");
        let repo = open_repo_internal(&self.canonical_repo)?;
        validate_ref_component(agent_id, "agent_id")?;

        let glob = format!("refs/tags/checkpoint/{agent_id}/*");
        let mut entries: Vec<CheckpointEntry> = Vec::new();
        // `references_glob` returns refs matching the pattern; for each tag
        // ref we peel to a tag object (annotated) and extract message + tagger.
        for r in repo.references_glob(&glob)? {
            let r = r?;
            let name = r.name().unwrap_or("");
            let label = match name.strip_prefix(&format!("refs/tags/checkpoint/{agent_id}/")) {
                Some(s) => s.to_string(),
                None => continue,
            };
            // Per §1.4.3 the tag grammar is `checkpoint/{agent-id}/{label}`
            // with a flat label. An imported/malformed ref like
            // `refs/tags/checkpoint/alice/a/b/c` strips to `a/b/c` — surface
            // that as valid=false rather than exposing it verbatim; the
            // label is not round-trippable through `delete()` in any case
            // because `validate_ref_component` rejects `/` in a component.
            if label.contains('/') {
                entries.push(CheckpointEntry {
                    label,
                    agent: agent_id.to_string(),
                    timestamp: "0".to_string(),
                    paths: None,
                    valid: false,
                });
                continue;
            }
            // Peel to annotated tag. A lightweight tag (no tag object) has
            // no message, no tagger — treat as legacy tag with empty message
            // → `(valid=true, paths=None)` per AC-11 fallback, and use the
            // pointed commit's time as `timestamp`.
            let entry = match r.peel_to_tag() {
                Ok(tag) => {
                    let msg_bytes = tag.message_bytes().unwrap_or(&[]);
                    let (valid, paths) = parse_tag_message(msg_bytes);
                    let ts = tag.tagger().map(|t| t.when().seconds()).unwrap_or_else(|| {
                        // Fallback: commit time if tagger is absent (shouldn't
                        // happen on a proper annotated tag, but safe default).
                        tag.target()
                            .ok()
                            .and_then(|o| o.peel_to_commit().ok())
                            .map(|c| c.time().seconds())
                            .unwrap_or(0)
                    });
                    CheckpointEntry {
                        label,
                        agent: agent_id.to_string(),
                        timestamp: ts.to_string(),
                        paths,
                        valid,
                    }
                }
                Err(_) => {
                    // Lightweight tag: peel to commit for the timestamp.
                    let commit_time = r
                        .peel_to_commit()
                        .ok()
                        .map(|c| c.time().seconds())
                        .unwrap_or(0);
                    CheckpointEntry {
                        label,
                        agent: agent_id.to_string(),
                        timestamp: commit_time.to_string(),
                        paths: None,
                        valid: true,
                    }
                }
            };
            entries.push(entry);
        }
        // Stable order for callers and tests — alphabetical by label.
        entries.sort_by(|a, b| a.label.cmp(&b.label));
        Ok(entries)
    }

    fn delete(&self, agent_id: &str, label: &str) -> Result<(), CheckpointError> {
        let coord = git_repo_lock(&self.canonical_repo);
        let _guard = coord
            .lock()
            .expect("git coord mutex poisoned in checkpoint::delete");
        let repo = open_repo_internal(&self.canonical_repo)?;
        validate_ref_component(agent_id, "agent_id")?;
        validate_ref_component(label, "label")?;
        let tag_name = format!("checkpoint/{agent_id}/{label}");
        match repo.tag_delete(&tag_name) {
            Ok(()) => Ok(()),
            Err(e) if e.code() == git2::ErrorCode::NotFound => Err(CheckpointError::NotFound {
                label: label.to_string(),
            }),
            Err(e) => Err(CheckpointError::from(e)),
        }
    }
}

/// Parse a tag message byte slice, returning `(valid, paths)` per §1.4.3.
///
/// Rules (fail-closed per PRD §7.2):
/// - Empty OR whitespace-only → `(true, None)` (legacy empty-message
///   normalization per AC-11).
/// - BOM-prefixed → `(false, None)` — strict schema.
/// - Not valid JSON → `(false, None)`.
/// - Not a JSON object → `(false, None)`.
/// - Any key other than `paths` → `(false, None)`.
/// - `paths` is absent → `(true, None)` (`{}` = full-directory).
/// - `paths` is null / not an array / contains a non-string → `(false, None)`.
/// - `paths` is an array of strings (possibly empty) → `(true, Some(list))`.
pub(crate) fn parse_tag_message(msg: &[u8]) -> (bool, Option<Vec<PathBuf>>) {
    // UTF-8 boundary — tag messages are byte blobs, but our schema is JSON
    // (UTF-8). Non-UTF8 → invalid.
    let s = match std::str::from_utf8(msg) {
        Ok(s) => s,
        Err(_) => return (false, None),
    };
    let trimmed = s.trim();
    if trimmed.is_empty() {
        return (true, None);
    }
    // BOM rejection — the UTF-8 BOM `\u{FEFF}` is not stripped by `str::trim`
    // (it's not whitespace), so a BOM-only tag would fall through to JSON
    // parse, where `serde_json` rejects it as invalid. Make the rejection
    // explicit so the test matrix passes independently of serde_json's
    // precise error set.
    if trimmed.starts_with('\u{FEFF}') {
        return (false, None);
    }
    let v: Value = match serde_json::from_str(trimmed) {
        Ok(v) => v,
        Err(_) => return (false, None),
    };
    let obj = match v.as_object() {
        Some(o) => o,
        None => return (false, None),
    };
    // Any key other than `paths` → invalid. This correctly rejects
    // `{"paths": [], "extra": 1}` since the `extra` key is not `paths`.
    if obj.keys().any(|k| k.as_str() != "paths") {
        return (false, None);
    }
    let paths = match obj.get("paths") {
        None => return (true, None),
        Some(Value::Array(arr)) => {
            let mut out = Vec::with_capacity(arr.len());
            for item in arr {
                match item.as_str() {
                    Some(s) => out.push(PathBuf::from(s)),
                    None => return (false, None),
                }
            }
            out
        }
        // null / non-array → invalid.
        Some(_) => return (false, None),
    };
    (true, Some(paths))
}

/// Stage order: trailing-slash → dedupe → parent-child fold → dictionary sort
/// (PRD §7.2 line 1987). Operates on pre-validated paths — callers must have
/// rejected `..` / hidden / `.agent/` / encoding issues BEFORE calling.
pub(crate) fn normalize_paths(repo: &Repository, inputs: Vec<PathBuf>) -> Vec<PathBuf> {
    // Stage 1: append trailing `/` to directories known to HEAD's tree.
    // An unborn HEAD has no tree — in that case, trailing-slash behavior
    // honors caller's explicit signal only.
    let head_tree = repo
        .head()
        .ok()
        .and_then(|h| h.peel_to_commit().ok())
        .and_then(|c| c.tree().ok());
    let mut staged: Vec<String> = Vec::with_capacity(inputs.len());
    for p in inputs {
        let s = p.to_string_lossy().into_owned();
        if s.ends_with('/') {
            staged.push(s);
            continue;
        }
        let is_dir = head_tree
            .as_ref()
            .map(|t| {
                matches!(
                    t.get_path(Path::new(&s)).ok().and_then(|e| e.kind()),
                    Some(git2::ObjectType::Tree)
                )
            })
            .unwrap_or(false);
        if is_dir {
            staged.push(format!("{s}/"));
        } else {
            staged.push(s);
        }
    }

    // Stage 2: dedupe (exact-equal after trailing-slash normalization).
    // `sort` + `dedup` is O(n log n) and stable; dedup keeps the first.
    staged.sort();
    staged.dedup();

    // Stage 3: parent-child fold. If `a/` is present, drop every entry
    // starting with `a/`. Because the list is sorted and every directory
    // entry ends with `/`, a prefix check (`candidate.starts_with(parent)`
    // AND `parent.ends_with('/')`) is sufficient.
    let mut folded: Vec<String> = Vec::with_capacity(staged.len());
    for c in staged {
        let covered = folded.iter().any(|kept| {
            kept.ends_with('/') && c.starts_with(kept.as_str()) && c.as_str() != kept.as_str()
        });
        if !covered {
            folded.push(c);
        }
    }

    // Stage 4: dictionary sort (byte-lexicographic; ASCII paths in practice
    // per PRD §6 — see §3.8 Implementation Notes). Stable re-sort because
    // stage 3 may have reduced but not re-ordered.
    folded.sort();
    folded.into_iter().map(PathBuf::from).collect()
}

/// Rejects per-path input to `NamedCheckpoint::create`. Maps to
/// `CheckpointError::InvalidPath` with the appropriate `DeniedReason`.
pub(crate) fn validate_create_path(p: &Path) -> Result<(), CheckpointError> {
    let raw = p.to_string_lossy();
    // Strip leading `./` before any rejection so `./a` and `a` agree.
    let stripped = raw.strip_prefix("./").unwrap_or(&raw);

    // Encoding: non-UTF8 (not representable in to_string_lossy without
    // replacement chars) or ASCII control chars.
    if raw.contains(char::REPLACEMENT_CHARACTER) {
        return Err(CheckpointError::InvalidPath {
            path: p.to_path_buf(),
            reason: DeniedReason::Encoding,
        });
    }
    if stripped.chars().any(|c| c.is_control() || c == '\0') {
        return Err(CheckpointError::InvalidPath {
            path: p.to_path_buf(),
            reason: DeniedReason::Encoding,
        });
    }
    // Absolute path.
    if Path::new(stripped).is_absolute() {
        return Err(CheckpointError::InvalidPath {
            path: p.to_path_buf(),
            reason: DeniedReason::NotWritableDomain,
        });
    }
    // Windows backslash separator.
    if stripped.contains('\\') {
        return Err(CheckpointError::InvalidPath {
            path: p.to_path_buf(),
            reason: DeniedReason::NotWritableDomain,
        });
    }
    // `..` component.
    for c in Path::new(stripped).components() {
        if matches!(c, Component::ParentDir) {
            return Err(CheckpointError::InvalidPath {
                path: p.to_path_buf(),
                reason: DeniedReason::ParentDirTraversal,
            });
        }
    }
    // `.agent/` at any level — always rejected at create (checkpoints never
    // capture `.agent/`; see §3.8 Implementation Notes).
    for c in Path::new(stripped).components() {
        if let Component::Normal(name) = c {
            if name.to_string_lossy().eq_ignore_ascii_case(".agent") {
                return Err(CheckpointError::InvalidPath {
                    path: p.to_path_buf(),
                    reason: DeniedReason::DotAgentOutsideMemoryRollback,
                });
            }
        }
    }
    // Hidden runtime path (`.git`, `.meta.yaml`, `*.sqlite*`, `.runtime/*`,
    // `.advance/*`, `.sub/*`). Any component matching one of these is
    // rejected.
    for c in Path::new(stripped).components() {
        if let Component::Normal(name) = c {
            let n = name.to_string_lossy();
            let nl = n.to_lowercase();
            if nl == ".git"
                || nl == ".meta.yaml"
                || nl == ".runtime"
                || nl == ".advance"
                || nl == ".sub"
                || nl.ends_with(".sqlite")
                || nl.ends_with(".sqlite-wal")
                || nl.ends_with(".sqlite-shm")
            {
                return Err(CheckpointError::InvalidPath {
                    path: p.to_path_buf(),
                    reason: DeniedReason::HiddenRuntimePath,
                });
            }
        }
    }
    Ok(())
}

/// Validate a single ref-path component (label / agent_id). Two-step: NUL +
/// control pre-filter (to avoid `CString::new(..).unwrap()` panic in git2
/// 0.20.4 internals), then composed-name probe against Git ref-name grammar.
/// Reject Unicode characters in General Category Cf (Format). Covers the
/// BMP Cf range (U+00AD, U+0600..U+0605, U+061C, U+06DD, U+070F, U+08E2,
/// U+180E, U+200B..U+200F, U+202A..U+202E, U+2060..U+2064, U+2066..U+206F,
/// U+FEFF, U+FFF9..U+FFFB) plus the astral Tags/Variation-selector-supplement
/// blocks (U+E0000..U+E007F, U+E0100..U+E01EF). Hand-enumerated for
/// dependency-free operation; precision over completeness — the BMP
/// coverage handles the practical bidi / log-injection surface that
/// motivates this filter.
fn is_unicode_format_char(c: char) -> bool {
    let code = c as u32;
    matches!(
        code,
        0x00AD
            | 0x0600..=0x0605
            | 0x061C
            | 0x06DD
            | 0x070F
            | 0x08E2
            | 0x180E
            | 0x200B..=0x200F
            | 0x202A..=0x202E
            | 0x2060..=0x2064
            | 0x2066..=0x206F
            | 0xFEFF
            | 0xFFF9..=0xFFFB
            | 0xE0000..=0xE007F
            | 0xE0100..=0xE01EF
    )
}

pub(crate) fn validate_ref_component(s: &str, field: &str) -> Result<(), CheckpointError> {
    if s.is_empty() {
        return Err(CheckpointError::InvalidLabel {
            label: s.to_string(),
            reason: format!("{field} is empty"),
        });
    }
    if s.chars().any(|c| c == '\0' || c.is_control()) {
        return Err(CheckpointError::InvalidLabel {
            label: s.to_string(),
            reason: format!("{field} contains NUL or control char"),
        });
    }
    // Slice E adversarial fix R2: reject Unicode format characters
    // (General Category Cf). Rust's `char::is_control()` only covers Cc
    // (Unicode control); it does NOT include bidi overrides (U+202A..U+202E,
    // U+2066..U+2069), directional marks (U+200E, U+200F), zero-width
    // joiners (U+200D), byte-order mark (U+FEFF), etc. Those characters
    // are legal in Git refs (`Tag::is_valid_name` accepts them) but
    // enable log-injection and bidi-override attacks against downstream
    // consumers (JSONL/SQLite/WebSocket) when the label/agent_id flows
    // into `git.rollback` event payload.target_ref/agent_id. The Cf
    // rejection closes that attack surface at the validation boundary,
    // preserving the invariant that only "safe" strings reach audit
    // sinks. Hand-enumerated against a whitelist of Cf code points in
    // the BMP; astral-plane Cf (e.g., U+E0001..E0FFF Tags block) is
    // also rejected via the range check.
    if s.chars().any(is_unicode_format_char) {
        return Err(CheckpointError::InvalidLabel {
            label: s.to_string(),
            reason: format!(
                "{field} contains Unicode format char (bidi override / LRM / ZWJ / BOM)"
            ),
        });
    }
    // No `/` — the separator in the composed tag name is inserted by the
    // caller; a `/` inside the component would produce an ambiguous ref.
    if s.contains('/') {
        return Err(CheckpointError::InvalidLabel {
            label: s.to_string(),
            reason: format!("{field} contains '/'"),
        });
    }
    // Compose a probe tag name and let libgit2 decide — `Tag::is_valid_name`
    // accepts the short form and internally prepends `refs/tags/` for the
    // libgit2 validation call (git2 0.20.4 tag.rs:22-30). This catches
    // `..`, `@{`, trailing `.`, space, and other Git-ref grammar violations
    // that the prefilter above misses.
    let probe = format!("checkpoint/{}/__probe__", s);
    if !probe_tag_name_valid(&probe) {
        return Err(CheckpointError::InvalidLabel {
            label: s.to_string(),
            reason: format!("{field} fails Git ref-name grammar"),
        });
    }
    Ok(())
}

/// Thin wrapper around `git2::Tag::is_valid_name` that first filters for NUL
/// and control chars — the underlying libgit2 binding uses `CString::new(..)
/// .unwrap()` (tag.rs:24 in git2 0.20.4) which panics on interior NUL bytes.
/// Returning `false` for any control-char-tainted input matches the
/// "rejected" semantics without the panic surface.
pub(crate) fn probe_tag_name_valid(short_name: &str) -> bool {
    if short_name.chars().any(|c| c == '\0' || c.is_control()) {
        return false;
    }
    git2::Tag::is_valid_name(short_name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_empty_message_is_valid_none() {
        let (valid, paths) = parse_tag_message(b"");
        assert!(valid);
        assert!(paths.is_none());
    }

    #[test]
    fn parse_whitespace_only_is_valid_none() {
        let (valid, paths) = parse_tag_message(b"   \n\t   ");
        assert!(valid);
        assert!(paths.is_none());
    }

    #[test]
    fn parse_empty_object_is_valid_none() {
        let (valid, paths) = parse_tag_message(b"{}");
        assert!(valid);
        assert!(paths.is_none());
    }

    #[test]
    fn parse_paths_array_is_valid() {
        let (valid, paths) = parse_tag_message(br#"{"paths":["a/","b.md"]}"#);
        assert!(valid);
        assert_eq!(
            paths,
            Some(vec![PathBuf::from("a/"), PathBuf::from("b.md")])
        );
    }

    #[test]
    fn parse_empty_paths_array_is_valid_with_empty_vec() {
        let (valid, paths) = parse_tag_message(br#"{"paths":[]}"#);
        assert!(valid);
        assert_eq!(paths, Some(vec![]));
    }

    #[test]
    fn parse_extra_key_alone_invalid() {
        let (valid, _) = parse_tag_message(br#"{"x":1}"#);
        assert!(!valid);
    }

    #[test]
    fn parse_paths_plus_extra_key_invalid() {
        let (valid, _) = parse_tag_message(br#"{"paths":[],"extra":1}"#);
        assert!(!valid, "paths-plus-extra must be invalid");
    }

    #[test]
    fn parse_non_object_invalid() {
        assert!(!parse_tag_message(b"[]").0);
        assert!(!parse_tag_message(b"null").0);
        assert!(!parse_tag_message(b"\"str\"").0);
        assert!(!parse_tag_message(b"123").0);
    }

    #[test]
    fn parse_null_paths_invalid() {
        assert!(!parse_tag_message(br#"{"paths":null}"#).0);
    }

    #[test]
    fn parse_non_array_paths_invalid() {
        assert!(!parse_tag_message(br#"{"paths":"foo"}"#).0);
    }

    #[test]
    fn parse_non_string_member_invalid() {
        assert!(!parse_tag_message(br#"{"paths":[1,2]}"#).0);
    }

    #[test]
    fn parse_bom_prefixed_invalid() {
        let (valid, _) = parse_tag_message("\u{FEFF}{}".as_bytes());
        assert!(!valid, "BOM-prefixed input must be valid=false");
    }

    #[test]
    fn probe_rejects_nul_byte_without_panic() {
        assert!(!probe_tag_name_valid("checkpoint/has\0nul/label"));
    }

    #[test]
    fn probe_rejects_control_char_without_panic() {
        assert!(!probe_tag_name_valid("checkpoint/has\nctl/label"));
    }

    #[test]
    fn probe_accepts_normal_name() {
        assert!(probe_tag_name_valid("checkpoint/agent-x/v1"));
    }

    #[test]
    fn probe_rejects_dotdot_component() {
        assert!(!probe_tag_name_valid("checkpoint/../evil"));
    }

    #[test]
    fn validate_ref_component_accepts_normal() {
        assert!(validate_ref_component("agent-x", "agent_id").is_ok());
    }

    #[test]
    fn validate_ref_component_rejects_empty() {
        assert!(matches!(
            validate_ref_component("", "label"),
            Err(CheckpointError::InvalidLabel { .. })
        ));
    }

    #[test]
    fn validate_ref_component_rejects_slash() {
        assert!(matches!(
            validate_ref_component("has/slash", "label"),
            Err(CheckpointError::InvalidLabel { .. })
        ));
    }

    #[test]
    fn validate_ref_component_rejects_dotdot() {
        assert!(matches!(
            validate_ref_component("..", "label"),
            Err(CheckpointError::InvalidLabel { .. })
        ));
    }

    #[test]
    fn validate_create_path_rejects_parent_dir() {
        let err = validate_create_path(Path::new("../evil")).unwrap_err();
        assert!(matches!(
            err,
            CheckpointError::InvalidPath {
                reason: DeniedReason::ParentDirTraversal,
                ..
            }
        ));
    }

    #[test]
    fn validate_create_path_rejects_absolute() {
        let err = validate_create_path(Path::new("/abs/path")).unwrap_err();
        assert!(matches!(
            err,
            CheckpointError::InvalidPath {
                reason: DeniedReason::NotWritableDomain,
                ..
            }
        ));
    }

    #[test]
    fn validate_create_path_rejects_dotagent() {
        let err = validate_create_path(Path::new(".agent/memory/knowledge.jsonl")).unwrap_err();
        assert!(matches!(
            err,
            CheckpointError::InvalidPath {
                reason: DeniedReason::DotAgentOutsideMemoryRollback,
                ..
            }
        ));
    }

    #[test]
    fn validate_create_path_rejects_hidden_git() {
        let err = validate_create_path(Path::new(".git/config")).unwrap_err();
        assert!(matches!(
            err,
            CheckpointError::InvalidPath {
                reason: DeniedReason::HiddenRuntimePath,
                ..
            }
        ));
    }

    #[test]
    fn validate_create_path_rejects_sqlite() {
        let err = validate_create_path(Path::new("index.sqlite")).unwrap_err();
        assert!(matches!(
            err,
            CheckpointError::InvalidPath {
                reason: DeniedReason::HiddenRuntimePath,
                ..
            }
        ));
    }

    #[test]
    fn validate_create_path_rejects_backslash() {
        let err = validate_create_path(Path::new("win\\path")).unwrap_err();
        assert!(matches!(
            err,
            CheckpointError::InvalidPath {
                reason: DeniedReason::NotWritableDomain,
                ..
            }
        ));
    }

    #[test]
    fn validate_create_path_rejects_control_char() {
        let err = validate_create_path(Path::new("a\nb")).unwrap_err();
        assert!(matches!(
            err,
            CheckpointError::InvalidPath {
                reason: DeniedReason::Encoding,
                ..
            }
        ));
    }

    #[test]
    fn validate_create_path_accepts_normal() {
        assert!(validate_create_path(Path::new("data/report.md")).is_ok());
    }

    #[test]
    fn validate_create_path_accepts_stripped_dotslash() {
        assert!(validate_create_path(Path::new("./data/report.md")).is_ok());
    }
}
