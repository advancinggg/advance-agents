//! `.meta.yaml` reader/writer with atomic rename per MODULE-018 §2.5.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::{error::PackError, manifest::TrustLevel};

/// Maximum permitted `.meta.yaml` size in bytes — 10 MiB. Bounds memory
/// allocation at read time and prevents adversarial pack hosts from feeding
/// a multi-GiB YAML document that causes serde_yml to OOM. Sized to
/// accommodate thousands of installed-pack entries with descriptions; far
/// beyond any realistic workload. (Round-9 adversarial W4.)
const MAX_META_YAML_BYTES: u64 = 10 * 1024 * 1024;

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct MetaIndex {
    /// MODULE-018 §2.5: the `_scope:` block describing this directory's role.
    #[serde(rename = "_scope")]
    pub scope: MetaScope,
    /// `{name}@{version}` keys → entry data.
    #[serde(flatten)]
    pub packs: BTreeMap<String, MetaPackEntry>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct MetaScope {
    pub description: String,
    pub tags: Vec<String>,
}

impl Default for MetaScope {
    fn default() -> Self {
        Self {
            description: "Installed packs".into(),
            tags: vec!["admin".into(), "pack-registry".into()],
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct MetaPackEntry {
    #[serde(default)]
    pub description: Option<String>,
    pub installed_at: String,
    // `skip_serializing_if` + `default` (adversarial round 20): `.meta.yaml` is a
    // manager-generated INDEX whose cardinality scales with the installed-pack count
    // (the §2.5 target is "thousands of entries"). `serde_yml` serializes an EMPTY `Vec`
    // as the flow token `[]` (one `[` per entry) but a non-empty one as BLOCK style
    // (`- cap`, zero flow tokens); omitting empties keeps the whole index at ~0 flow-opens
    // regardless of N, so it never trips the crate-wide `yaml_nesting_within_bound` opens
    // cap (which is sized for BOUNDED pack manifests, not this unbounded index). Without
    // this, ≥1001 empty-capability packs produced ≥1001 `[]` opens and the reader rejected
    // the tool's OWN index — bricking rescan/install.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub required_capabilities: Vec<String>,
    pub trust_level: TrustLevel,
}

/// Read `<packs_dir>/.meta.yaml`. Returns `Default` if the file is absent.
///
/// Round-9 adversarial C2 defense: probe via `symlink_metadata` (which does
/// NOT follow symlinks) before reading. A symlinked `.meta.yaml` is rejected
/// outright — without this check, an attacker with `packs_dir` write access
/// could plant `.meta.yaml -> /etc/shadow` and the subsequent
/// `read_to_string` would follow the link and try to parse the target,
/// leaking sensitive content into the `serde_yml::from_str` error message
/// (which embeds source-text excerpts on parse failure).
///
/// Round-9 adversarial W4 defense: cap file size at `MAX_META_YAML_BYTES`
/// before allocating; a multi-GiB file would otherwise force
/// `read_to_string` to OOM.
///
/// **Residual TOCTOU window** (Codex r2 W1, bounded by trust model): between
/// the `symlink_metadata` probe and the `read_to_string` open, an attacker
/// with concurrent write access to `packs_dir` can replace the file with a
/// symlink. The Slice A threat model bounds this by trusting the admin-
/// owned `packs_dir` (same trust boundary as the §2.9 copy_dir_no_symlinks
/// residual TOCTOU); Slice B closes the window via `rustix::openat2 +
/// RESOLVE_NO_SYMLINKS` on Linux 5.6+ — see §2.9.
pub fn read_meta_index(packs_dir: &Path) -> Result<MetaIndex, PackError> {
    let path = packs_dir.join(".meta.yaml");
    let md = match std::fs::symlink_metadata(&path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(MetaIndex::default());
        }
        Err(e) => return Err(PackError::Io { path, source: e }),
        Ok(md) => md,
    };
    if md.file_type().is_symlink() {
        return Err(PackError::InvalidManifest(format!(
            ".meta.yaml rejected (is a symlink): {}",
            path.display()
        )));
    }
    if !md.is_file() {
        return Err(PackError::InvalidManifest(format!(
            ".meta.yaml is not a regular file: {}",
            path.display()
        )));
    }
    if md.len() > MAX_META_YAML_BYTES {
        return Err(PackError::InvalidManifest(format!(
            ".meta.yaml exceeds max size {MAX_META_YAML_BYTES} bytes: {} bytes",
            md.len()
        )));
    }
    let text = std::fs::read_to_string(&path).map_err(|e| PackError::Io {
        path: path.clone(),
        source: e,
    })?;
    // Delegate the TEXT-level acceptance gates to the shared `parse_meta_text` — the SAME gate
    // `write_meta_index_atomic`'s verify-before-persist runs, so the writer can NEVER commit an
    // index the reader would reject (adversarial round 26).
    parse_meta_text(&text)
}

/// TEXT-level acceptance gate for `.meta.yaml`, shared by `read_meta_index` (the reader) and
/// `write_meta_index_atomic`'s verify-before-persist step so the two can NEVER disagree.
///
/// Runs, in order, every gate the reader applies to the file text:
///  - **size cap** (`MAX_META_YAML_BYTES`) — bounds allocation;
///  - **alias-bomb guard** (`yaml_has_alias_refs`, round-9) — a byte-scan that rejects any `*`
///    followed by an identifier char BEFORE `serde_yml` can expand aliases (billion-laughs);
///  - **panic-safe parse** (`catch_unwind` around `serde_yml::from_str`) — any residual libyml
///    parse panic (hand-planted poison, or the workspace-wide literal-block libyml bug — round-22
///    Finding 2) becomes a clean `Err` rather than unwinding the caller.
///
/// Adversarial round 26: a prior verify checked ONLY `from_str(...).is_ok()`, so a pack
/// `description` containing `*`+identifier (e.g. via a `\x2a` escape that slips past the pack.yaml
/// byte-scan) parsed fine, PASSED verify, persisted — and then the reader's `yaml_has_alias_refs`
/// rejected the serialized `*name` on EVERY read, persistently bricking install/rescan. Sharing
/// this exact gate between reader and writer closes that verify≠read asymmetry: whatever the
/// writer commits, the reader is guaranteed to accept. (`.meta.yaml` is deliberately NOT
/// flow-opens-guarded — see the round-20 rationale: it is a manager-generated index the opens cap
/// wrongly rejects at scale.)
fn parse_meta_text(text: &str) -> Result<MetaIndex, PackError> {
    if text.len() as u64 > MAX_META_YAML_BYTES {
        return Err(PackError::InvalidManifest(format!(
            ".meta.yaml exceeds max size {MAX_META_YAML_BYTES} bytes: {} bytes",
            text.len()
        )));
    }
    if crate::manifest::yaml_has_alias_refs(text) {
        return Err(PackError::InvalidManifest(
            ".meta.yaml contains YAML alias references (`*name`) — rejected to prevent billion-laughs amplification".into(),
        ));
    }
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| serde_yml::from_str::<MetaIndex>(text)))
        .map_err(|_| {
            PackError::InvalidManifest(
                ".meta.yaml parse panicked (hostile/corrupt YAML — e.g. a libyml literal-block break-run) — rejected".into(),
            )
        })?
        .map_err(|e| PackError::InvalidManifest(format!(".meta.yaml parse: {e}")))
}

#[cfg(test)]
mod meta_index_scale_tests {
    use super::*;

    fn entry() -> MetaPackEntry {
        MetaPackEntry {
            description: Some("A test pack".into()),
            installed_at: "2026-07-06T00:00:00Z".into(),
            required_capabilities: vec![],
            trust_level: TrustLevel::Trusted,
        }
    }

    #[test]
    fn meta_index_with_thousands_of_empty_cap_packs_round_trips() {
        // Adversarial round 20 regression: `.meta.yaml` is a manager-generated index whose
        // cardinality scales with the installed-pack count (§2.5 target = "thousands of
        // entries"). serde_yml serialized an empty `required_capabilities` Vec as `[]` (one
        // flow-open per entry); at ≥1001 empty-cap packs the round-16 opens cap rejected the
        // tool's OWN index → bricked rescan/install. Fix: skip-empty serialization + drop the
        // opens cap on `.meta.yaml`. This 2000-entry index MUST round-trip cleanly.
        let dir = tempfile::TempDir::new().unwrap();
        let mut idx = MetaIndex::default();
        for i in 0..2_000 {
            idx.packs.insert(format!("pack-{i}@1.0.0"), entry());
        }
        write_meta_index_atomic(dir.path(), &idx).expect("write 2000-entry index");
        let read = read_meta_index(dir.path()).expect("read 2000-entry index (must NOT brick)");
        assert_eq!(read.packs.len(), 2_000);
        // skip-empty: an empty required_capabilities is omitted on write and defaults back to
        // empty on read.
        assert!(read
            .packs
            .values()
            .all(|e| e.required_capabilities.is_empty()));
    }

    #[test]
    fn meta_index_sanitizes_trailing_newline_description() {
        // Adversarial round 22 Finding 1: a pack description with trailing newlines is emitted
        // by serde_yml as a `|+` literal block that libyml 0.0.5 PANICS re-parsing — a single
        // pack would poison the index and brick every future rescan/install. Sanitization on
        // write strips control chars, so the index round-trips cleanly (no panic, no brick).
        let dir = tempfile::TempDir::new().unwrap();
        let mut idx = MetaIndex::default();
        let mut e = entry();
        e.description = Some(format!("evil{}", "\n".repeat(64)));
        idx.packs.insert("evil@1.0.0".into(), e);
        write_meta_index_atomic(dir.path(), &idx).expect("write");
        let read = read_meta_index(dir.path()).expect("re-read must NOT panic/brick");
        let desc = read.packs["evil@1.0.0"].description.as_deref().unwrap();
        assert!(
            !desc.contains('\n'),
            "newlines must be stripped, got {desc:?}"
        );
        assert_eq!(desc, "evil");
    }

    #[test]
    fn meta_index_sanitizes_interior_whitespace_runs() {
        // Adversarial round 24: libyml 0.0.5 panics on ANY interior run of ≥16 whitespace-class
        // chars (≥6 for U+2028/U+2029). The round-22 `is_control`→space map (a) missed
        // U+2028/U+2029 and (b) MANUFACTURED a poison run from interior tabs. Collapsing every
        // whitespace run to ≤1 space defuses all of these — each MUST round-trip (no panic/brick).
        let cases: [(String, &str); 5] = [
            ("Col1".to_string() + &" ".repeat(16) + "Col2", "Col1 Col2"), // 16 literal spaces (BENIGN column-align)
            ("a".to_string() + &"\t".repeat(16) + "b", "a b"), // 16 tabs (round-22 control→run manufacture)
            ("a".to_string() + &"\u{2028}".repeat(8) + "b", "a b"), // U+2028 (is_control=false)
            ("a".to_string() + &"\u{2029}".repeat(8) + "b", "a b"), // U+2029
            ("x".to_string() + &" \t\u{2028}".repeat(20) + "y", "x y"), // mixed whitespace run
        ];
        for (i, (payload, expected)) in cases.iter().enumerate() {
            let dir = tempfile::TempDir::new().unwrap();
            let mut idx = MetaIndex::default();
            let mut e = entry();
            e.description = Some(payload.clone());
            let key = format!("pack-{i}@1.0.0");
            idx.packs.insert(key.clone(), e);
            write_meta_index_atomic(dir.path(), &idx)
                .unwrap_or_else(|err| panic!("case {i} write: {err:?}"));
            let read = read_meta_index(dir.path())
                .unwrap_or_else(|err| panic!("case {i} re-read (BRICK!): {err:?}"));
            assert_eq!(
                read.packs[&key].description.as_deref(),
                Some(*expected),
                "case {i}"
            );
        }
    }

    #[test]
    fn read_meta_index_catches_libyml_literal_block_panic() {
        // Adversarial round 22: a hand-planted `.meta.yaml` carrying the libyml `|+`-block
        // poison (as a direct-packs_dir-write attacker could, or a pre-fix poisoned index) must
        // surface as a clean Err via catch_unwind, NOT unwind the caller. Build the exact poison
        // by serializing a trailing-newline description directly (bypassing the write-path sanitize).
        let dir = tempfile::TempDir::new().unwrap();
        let mut idx = MetaIndex::default();
        let mut e = entry();
        e.description = Some("d".to_string() + &"\n".repeat(32));
        idx.packs.insert("evil@1.0.0".into(), e);
        let poison = serde_yml::to_string(&idx).unwrap(); // `|+` literal block, un-sanitized
        std::fs::write(dir.path().join(".meta.yaml"), &poison).unwrap();
        // Suppress the caught-panic backtrace so a PASSING test doesn't look alarming.
        let prev = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        let r = read_meta_index(dir.path());
        std::panic::set_hook(prev);
        assert!(
            matches!(r, Err(PackError::InvalidManifest(_))),
            "poisoned index must Err (caught panic), got {r:?}"
        );
    }

    #[test]
    fn write_refuses_alias_bearing_description_no_brick() {
        // Adversarial round 26: a description containing `*`+identifier (reachable via a `\x2a`
        // escape past the pack.yaml byte-scan) survives whitespace-collapse and PARSES fine, but
        // the reader's alias-bomb guard rejects the serialized `*name`. Verify-before-persist now
        // shares the reader's gate (`parse_meta_text`), so the write is REFUSED — the poison never
        // reaches disk, and a pre-existing valid index is NOT bricked.
        let dir = tempfile::TempDir::new().unwrap();
        let mut good = MetaIndex::default();
        good.packs.insert("ok@1.0.0".into(), entry());
        write_meta_index_atomic(dir.path(), &good).expect("seed valid index");

        let mut bad = MetaIndex::default();
        let mut e = entry();
        e.description = Some("x*foo".into()); // serializes to `x*foo` → trips the read alias guard
        bad.packs.insert("evil@1.0.0".into(), e);
        let r = write_meta_index_atomic(dir.path(), &bad);
        assert!(
            matches!(r, Err(PackError::InvalidManifest(_))),
            "write must refuse an alias-bearing serialization (verify == read), got {r:?}"
        );

        // The pre-existing valid index is intact + readable — the refused write left it untouched.
        let read = read_meta_index(dir.path()).expect("existing index still readable (NO brick)");
        assert_eq!(read.packs.len(), 1);
        assert!(read.packs.contains_key("ok@1.0.0"));
    }

    #[test]
    fn meta_index_with_bracket_heavy_description_round_trips() {
        // A pack-controlled description full of `[` flows into `.meta.yaml` as a string SCALAR
        // (re-serialized, quoted), so it must NOT brick the reader — round 20: the opens cap
        // would have counted those `[` (quote-blind) and rejected the whole index off a single
        // pack. Since `.meta.yaml` is no longer opens-capped, it round-trips.
        let dir = tempfile::TempDir::new().unwrap();
        let mut idx = MetaIndex::default();
        let mut e = entry();
        e.description = Some("[".repeat(5_000));
        idx.packs.insert("evil@1.0.0".into(), e);
        write_meta_index_atomic(dir.path(), &idx).expect("write bracket-heavy index");
        let read = read_meta_index(dir.path()).expect("read bracket-heavy index (must NOT brick)");
        assert_eq!(read.packs.len(), 1);
        // `[` is not a control char so it survives sanitization, but the round-22 write-path
        // sanitizer caps the `.meta` description at 512 chars — the index round-trips with no brick.
        assert_eq!(
            read.packs["evil@1.0.0"].description.as_deref(),
            Some("[".repeat(512).as_str())
        );
    }
}

/// RAII tempfile cleanup guard. If the consumer calls [`Self::commit`] the
/// tempfile path is dropped from the guard so `Drop` becomes a no-op. If
/// the consumer falls out of scope (panic, error return, etc.) without
/// committing, `Drop` removes the tempfile. Closes the round-9 adversarial
/// W7 cleanup leak in `write_meta_index_atomic`.
struct TempFileGuard {
    path: Option<PathBuf>,
}

impl TempFileGuard {
    fn new(path: PathBuf) -> Self {
        Self { path: Some(path) }
    }
    fn commit(mut self) {
        self.path = None;
    }
}

impl Drop for TempFileGuard {
    fn drop(&mut self) {
        if let Some(path) = self.path.take() {
            // Best-effort cleanup; if rm fails (e.g. already moved), silently ignore.
            let _ = std::fs::remove_file(path);
        }
    }
}

/// Sanitize a pack-controlled `description` before it is serialized into `.meta.yaml`.
/// COLLAPSES every maximal run of whitespace-class characters — ASCII control (`\n`/`\r`/`\t`/
/// C0-C1) AND all Unicode whitespace, crucially including the line/paragraph separators
/// U+2028/U+2029 — down to a SINGLE ASCII space, then caps the length and trims.
///
/// Rationale (adversarial rounds 22 + 24): libyml 0.0.5 PANICS while scanning any INTERIOR run
/// of ≥16 whitespace-class chars (≥6 for U+2028/U+2029) — `serde_yml::to_string` emits such a
/// description, and `serde_yml::from_str` then panics on it, poisoning this index. The round-22
/// version only mapped `is_control()`→space, which (a) missed U+2028/U+2029 (`is_control` is
/// false for them) and (b) MANUFACTURED a poison run by mapping 16 interior tabs to 16 spaces.
/// Collapsing every whitespace run to ≤1 space means no run of length ≥2 can ever survive, so the
/// panic class is defused for ANY whitespace char — no per-character allow/deny list to maintain.
/// (The `write_meta_index_atomic` verify-before-persist step is the belt-and-suspenders net for
/// any residual non-whitespace libyml quirk.) `.meta.yaml` descriptions are display-only, so
/// lossy whitespace normalization is acceptable.
fn sanitize_meta_description(s: &str) -> String {
    const MAX_META_DESCRIPTION_CHARS: usize = 512;
    let mut out = String::new();
    let mut n = 0usize;
    let mut prev_ws = false;
    for c in s.chars() {
        if n >= MAX_META_DESCRIPTION_CHARS {
            break;
        }
        if c.is_whitespace() || c.is_control() {
            if !prev_ws {
                out.push(' ');
                prev_ws = true;
                n += 1;
            }
        } else {
            out.push(c);
            prev_ws = false;
            n += 1;
        }
    }
    out.trim().to_string()
}

/// Atomic-rename write: tempfile in same dir → fsync(file) → rename.
///
/// What's atomic: the visible content of `.meta.yaml` flips from "old" to "new"
/// in a single `rename(2)` syscall — readers never see a partially-written file.
///
/// What's NOT atomic (Slice A scope): durability across power loss. We do NOT
/// `fsync` the parent directory after `rename`, so a crash between the rename
/// and the next filesystem sync may revert the directory entry. Acceptable for
/// Slice A's admin-CLI single-process invariant; durability-fence lands in a
/// later slice if needed (post-OS-crash recovery is admin's `advance pack
/// re-install` step).
///
/// `create_new(true)` (O_EXCL) defends against in-process tempfile-suffix
/// collisions (Round-2 fix).
pub fn write_meta_index_atomic(packs_dir: &Path, idx: &MetaIndex) -> Result<(), PackError> {
    use std::io::Write;
    let target = packs_dir.join(".meta.yaml");
    let nanos = chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0);
    let tmp = packs_dir.join(format!(".meta.yaml.tmp.{}.{}", std::process::id(), nanos));
    // Adversarial round 22: SANITIZE every pack-controlled string (`description`) before
    // serialization. A pack ships its `description` verbatim into `MetaPackEntry` (install.rs);
    // `serde_yml::to_string` emits a string with TRAILING NEWLINES as a `|+` literal block that
    // libyml 0.0.5 PANICS re-parsing (scanner.rs:2235) — a single malicious pack would poison
    // this index and brick every subsequent `read_meta_index` (rescan/install). Stripping
    // control characters makes the round-trip provably safe. `write_meta_index_atomic` is the
    // SOLE writer of `packs_dir/.meta.yaml`, so this one chokepoint covers all callers; the
    // clone is cheap relative to the filesystem write.
    let mut idx = idx.clone();
    idx.scope.description = sanitize_meta_description(&idx.scope.description);
    for entry in idx.packs.values_mut() {
        let d = entry.description.take();
        entry.description = d.map(|s| sanitize_meta_description(&s));
    }
    let yaml = serde_yml::to_string(&idx)
        .map_err(|e| PackError::InvalidManifest(format!(".meta.yaml serialize: {e}")))?;
    // VERIFY-BEFORE-PERSIST (adversarial rounds 24 + 26): re-run the EXACT reader gate
    // (`parse_meta_text`: size cap + alias-bomb guard + panic-safe parse) on the serialized bytes
    // BEFORE the atomic rename. If the serialized index would NOT be accepted by
    // `read_meta_index` — for ANY reason (a libyml scalar-emission quirk, an alias-guard trip on a
    // `*`-bearing description, an over-size index) — REFUSE to persist it: fail THIS write cleanly,
    // leaving the existing on-disk index untouched, rather than commit a file that bricks every
    // future read. Because verify and read share `parse_meta_text`, nothing the writer commits can
    // be rejected by the reader (the round-24/26 persistent-brick class is closed by construction).
    if parse_meta_text(&yaml).is_err() {
        return Err(PackError::InvalidManifest(
            ".meta.yaml serialization would be rejected by the reader (alias/size/parse gate) — refusing to persist".into(),
        ));
    }
    // RAII guard removes `tmp` if any subsequent step errors. The `commit()`
    // call right before returning Ok prevents removal of the now-renamed
    // `.meta.yaml`. Closes round-9 adversarial W7 (mid-write leaks left
    // tempfiles behind for `write_all` / `sync_all` / `rename` failures).
    let guard = TempFileGuard::new(tmp.clone());
    {
        let mut f = std::fs::File::options()
            .write(true)
            .create_new(true)
            .open(&tmp)
            .map_err(|e| PackError::Io {
                path: tmp.clone(),
                source: e,
            })?;
        f.write_all(yaml.as_bytes()).map_err(|e| PackError::Io {
            path: tmp.clone(),
            source: e,
        })?;
        f.sync_all().map_err(|e| PackError::Io {
            path: tmp.clone(),
            source: e,
        })?;
    }
    std::fs::rename(&tmp, &target).map_err(|e| PackError::Io {
        path: target.clone(),
        source: e,
    })?;
    guard.commit();
    Ok(())
}
