//! Memory-seed bridge (§3.1 row 5): an installed pack's
//! `memory-seeds/{name}.jsonl` → an agent's flat
//! `<agent-root>/.agent/memory/knowledge.jsonl`, the file
//! `advance_database::rebuild`'s `scan_knowledge_jsonl` indexes into SQLite.
//!
//! Every seed line is validated the way that scanner validates (`id` / `type` /
//! `content` / `created_at` non-empty strings, `id` free of C0 controls, one
//! JSON object per line, 1 MiB per line), de-duplicated by `id` against the
//! lines already in the target, and appended with pack provenance recorded in
//! `sources` as `{"pack": "{name}@{version}"}` (the scanner stores `sources`
//! as opaque JSON).
//!
//! Layout guard: cap-memory's `KnowledgeJsonlStore` hydrates the PER-AGENT
//! buckets `<ws>/.agent/memory/<agent>/knowledge.jsonl` with a strict
//! `MemoryEntry` parser that fails the whole store on a line it cannot parse
//! (a seed line carries a `pack` source it does not know). Seeding such a
//! bucket would brick the next boot, so a target of that shape is refused
//! (`ConstraintViolation`) — seeds belong in the flat scanner layout above.

use std::collections::HashSet;
use std::io::Write;
use std::path::Path;
use std::sync::Arc;

use advance_pack_manager::{ComponentKind, PackError, PackRegistry};
use serde_json::{Map, Value};

use super::{pack_id, resolve_kind, PackBridgeError};

/// Cap on a pack's seed file.
pub const MAX_SEED_FILE_BYTES: u64 = 64 * 1024 * 1024;
/// Cap on a single JSONL line (mirrors the rebuild scanner's `MAX_JSONL_LINE_BYTES`).
pub const MAX_SEED_LINE_BYTES: usize = 1024 * 1024;
/// Cap on the target file we read back for de-duplication.
pub const MAX_TARGET_FILE_BYTES: u64 = 256 * 1024 * 1024;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SeedReport {
    pub appended: usize,
    pub skipped_duplicates: usize,
}

pub struct PackMemorySeedBridge {
    registry: Arc<dyn PackRegistry>,
}

impl PackMemorySeedBridge {
    pub fn new(registry: Arc<dyn PackRegistry>) -> Self {
        Self { registry }
    }

    /// Append the seeds of `{pack}@{ver}/memory-seeds/{name}` to `knowledge_jsonl`
    /// (created 0600 when absent), skipping ids already present. Idempotent.
    pub fn seed(
        &self,
        pack_ref: &str,
        knowledge_jsonl: &Path,
    ) -> Result<SeedReport, PackBridgeError> {
        let resolution = resolve_kind(&*self.registry, pack_ref, ComponentKind::MemorySeed)?;
        let pack = pack_id(&resolution);
        refuse_cap_memory_bucket(knowledge_jsonl)?;

        let source = read_regular_file_bounded(&resolution.local_path, MAX_SEED_FILE_BYTES)?;
        let source_text = std::str::from_utf8(&source).map_err(|_| {
            PackError::InvalidManifest(format!(
                "memory seed is not valid UTF-8: {}",
                resolution.local_path.display()
            ))
        })?;
        let seeds = parse_seed_lines(source_text, &resolution.local_path)?;

        let existing_ids = read_existing_ids(knowledge_jsonl)?;

        let mut report = SeedReport::default();
        let mut out: Vec<u8> = Vec::new();
        for (id, mut obj) in seeds {
            if existing_ids.contains(&id) {
                report.skipped_duplicates += 1;
                continue;
            }
            let mut sources = match obj.remove("sources") {
                Some(Value::Array(a)) => a,
                Some(_) => {
                    return Err(PackBridgeError::Pack(PackError::InvalidManifest(format!(
                        "memory seed {id:?}: `sources` must be an array"
                    ))))
                }
                None => Vec::new(),
            };
            sources.push(serde_json::json!({ "pack": pack }));
            obj.insert("sources".into(), Value::Array(sources));
            let line = serde_json::to_string(&Value::Object(obj))
                .map_err(|e| PackBridgeError::Io(format!("serialize seed {id:?}: {e}")))?;
            out.extend_from_slice(line.as_bytes());
            out.push(b'\n');
            report.appended += 1;
        }
        if !out.is_empty() {
            append_owner_only(knowledge_jsonl, &out)?;
        }
        Ok(report)
    }
}

/// Parse + validate every line → `(id, object)`; a duplicate `id` INSIDE the
/// seed file is refused (the file is pack-authored and must be self-consistent).
fn parse_seed_lines(
    text: &str,
    path: &Path,
) -> Result<Vec<(String, Map<String, Value>)>, PackBridgeError> {
    let mut out = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    for (idx, raw) in text.lines().enumerate() {
        let line_no = idx + 1;
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        let invalid = |msg: String| {
            PackBridgeError::Pack(PackError::InvalidManifest(format!(
                "memory seed {} line {line_no}: {msg}",
                path.display()
            )))
        };
        if line.len() > MAX_SEED_LINE_BYTES {
            return Err(invalid(format!(
                "line too large ({} bytes; cap {MAX_SEED_LINE_BYTES})",
                line.len()
            )));
        }
        let value: Value =
            serde_json::from_str(line).map_err(|e| invalid(format!("parse error: {e}")))?;
        let obj = match value {
            Value::Object(m) => m,
            _ => return Err(invalid("not a JSON object".into())),
        };
        for field in ["id", "type", "content", "created_at"] {
            match obj.get(field) {
                Some(Value::String(s)) if !s.is_empty() => {}
                _ => return Err(invalid(format!("`{field}` must be a non-empty string"))),
            }
        }
        let id = obj["id"].as_str().unwrap_or_default().to_string();
        if id.chars().any(|c| (c as u32) < 0x20 || c == '\u{7F}') {
            return Err(invalid("`id` contains C0 control characters".into()));
        }
        if !seen.insert(id.clone()) {
            return Err(invalid(format!("duplicate id {id:?} within the seed file")));
        }
        out.push((id, obj));
    }
    Ok(out)
}

/// `id`s already in the target (absent target → empty). Lines that are not a
/// JSON object with a string `id` are ignored for de-duplication — the scanner
/// skips them too.
fn read_existing_ids(target: &Path) -> Result<HashSet<String>, PackBridgeError> {
    match std::fs::symlink_metadata(target) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(HashSet::new()),
        Err(e) => {
            return Err(PackBridgeError::Io(format!(
                "stat {}: {e}",
                target.display()
            )))
        }
        Ok(md) if md.file_type().is_symlink() => {
            return Err(PackBridgeError::Pack(PackError::InvalidManifest(format!(
                "knowledge.jsonl target is a symlink (rejected): {}",
                target.display()
            ))))
        }
        Ok(md) if !md.is_file() => {
            return Err(PackBridgeError::Pack(PackError::InvalidManifest(format!(
                "knowledge.jsonl target is not a regular file: {}",
                target.display()
            ))))
        }
        Ok(_) => {}
    }
    let bytes = read_regular_file_bounded(target, MAX_TARGET_FILE_BYTES)?;
    let text = String::from_utf8_lossy(&bytes);
    let mut ids = HashSet::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.len() > MAX_SEED_LINE_BYTES {
            continue;
        }
        if let Ok(Value::Object(m)) = serde_json::from_str::<Value>(line) {
            if let Some(Value::String(id)) = m.get("id") {
                ids.insert(id.clone());
            }
        }
    }
    Ok(ids)
}

/// Refuse a cap-memory per-agent bucket (`…/.agent/memory/<agent>/knowledge.jsonl`).
fn refuse_cap_memory_bucket(target: &Path) -> Result<(), PackBridgeError> {
    fn name(p: Option<&Path>) -> Option<&str> {
        p.and_then(Path::file_name).and_then(|s| s.to_str())
    }
    let parent = target.parent();
    let grandparent = parent.and_then(Path::parent);
    let great = grandparent.and_then(Path::parent);
    if name(Some(target)) == Some("knowledge.jsonl")
        && name(grandparent) == Some("memory")
        && name(great) == Some(".agent")
    {
        return Err(PackBridgeError::Pack(PackError::ConstraintViolation {
            reason: format!(
                "refusing to seed {}: it is a cap-memory per-agent store bucket \
                 (`.agent/memory/<agent>/knowledge.jsonl`) whose strict loader would reject \
                 pack-seeded lines at the next boot; seed the flat \
                 `<agent-root>/.agent/memory/knowledge.jsonl` the SQLite index rebuild scans",
                target.display()
            ),
        }));
    }
    Ok(())
}

/// `O_NOFOLLOW` (unix) open + fstat regular-file + size check + bounded read.
fn read_regular_file_bounded(path: &Path, max: u64) -> Result<Vec<u8>, PackBridgeError> {
    use std::io::Read;
    let mut opts = std::fs::OpenOptions::new();
    opts.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.custom_flags(libc::O_NOFOLLOW);
    }
    let mut file = opts.open(path).map_err(|e| {
        #[cfg(unix)]
        if e.raw_os_error() == Some(libc::ELOOP) {
            return PackBridgeError::Pack(PackError::InvalidManifest(format!(
                "{} is a symlink (rejected by O_NOFOLLOW)",
                path.display()
            )));
        }
        PackBridgeError::Io(format!("open {}: {e}", path.display()))
    })?;
    let md = file
        .metadata()
        .map_err(|e| PackBridgeError::Io(format!("stat {}: {e}", path.display())))?;
    if !md.is_file() {
        return Err(PackBridgeError::Pack(PackError::InvalidManifest(format!(
            "{} must be a regular file",
            path.display()
        ))));
    }
    if md.len() > max {
        return Err(PackBridgeError::Pack(PackError::InvalidManifest(format!(
            "{} exceeds max size {max} bytes ({} bytes)",
            path.display(),
            md.len()
        ))));
    }
    let mut buf = Vec::with_capacity(md.len() as usize);
    (&mut file)
        .take(max)
        .read_to_end(&mut buf)
        .map_err(|e| PackBridgeError::Io(format!("read {}: {e}", path.display())))?;
    Ok(buf)
}

/// Append `bytes` in one write (create 0600 when absent; never through a symlink).
fn append_owner_only(target: &Path, bytes: &[u8]) -> Result<(), PackBridgeError> {
    let mut opts = std::fs::OpenOptions::new();
    opts.append(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let mut file = opts
        .open(target)
        .map_err(|e| PackBridgeError::Io(format!("open {} for append: {e}", target.display())))?;
    file.write_all(bytes)
        .map_err(|e| PackBridgeError::Io(format!("append {}: {e}", target.display())))?;
    file.sync_all()
        .map_err(|e| PackBridgeError::Io(format!("fsync {}: {e}", target.display())))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cap_memory_bucket_shape_is_refused_flat_layout_is_not() {
        assert!(
            refuse_cap_memory_bucket(Path::new("/ws/.agent/memory/root/knowledge.jsonl")).is_err()
        );
        assert!(refuse_cap_memory_bucket(Path::new("/ws/.agent/memory/knowledge.jsonl")).is_ok());
        assert!(
            refuse_cap_memory_bucket(Path::new("/ws/child/.agent/memory/knowledge.jsonl")).is_ok()
        );
        assert!(refuse_cap_memory_bucket(Path::new("/tmp/seeds.jsonl")).is_ok());
    }

    #[test]
    fn seed_lines_are_validated_like_the_rebuild_scanner() {
        let p = Path::new("x.jsonl");
        let ok = "{\"id\":\"a\",\"type\":\"fact\",\"content\":\"c\",\"created_at\":\"t\"}\n\n";
        assert_eq!(parse_seed_lines(ok, p).unwrap().len(), 1);
        for bad in [
            "{\"id\":\"\",\"type\":\"fact\",\"content\":\"c\",\"created_at\":\"t\"}\n",
            "{\"id\":\"a\",\"content\":\"c\",\"created_at\":\"t\"}\n",
            "[1,2]\n",
            "not json\n",
            "{\"id\":\"a\\u0001\",\"type\":\"fact\",\"content\":\"c\",\"created_at\":\"t\"}\n",
            "{\"id\":\"a\",\"type\":\"fact\",\"content\":\"c\",\"created_at\":\"t\"}\n{\"id\":\"a\",\"type\":\"fact\",\"content\":\"d\",\"created_at\":\"t\"}\n",
        ] {
            assert!(parse_seed_lines(bad, p).is_err(), "should reject {bad:?}");
        }
    }
}
