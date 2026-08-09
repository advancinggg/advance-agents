//! `Entry` — slice A representation of the WIT `record entry`.
//!
//! WIT shape (per MODULE-002 §1.4.1):
//!   record entry { name: string, is-dir: bool, size: option<u64>, modified: option<string> }
//!
//! `from_metadata` is the production constructor; `from_metadata_with_mtime` exposes
//! a closure-based test seam so SA-T11c can deterministically force the
//! `modified == None` graceful-degradation branch without depending on a platform
//! whose `Metadata::modified()` actually returns `Err`.

use std::fs::Metadata;
use std::time::SystemTime;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use wasmtime::component::Val;

/// Filesystem directory entry — matches the WIT `record entry`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    pub name: String,
    pub is_dir: bool,
    pub size: Option<u64>,
    pub modified: Option<String>,
}

impl Entry {
    /// Build an `Entry` from a real `Metadata` reading mtime via `meta.modified()`.
    /// Production code path. On platforms / filesystems where `modified()` returns
    /// `Err`, this gracefully sets `modified: None`.
    pub fn from_metadata(name: String, meta: &Metadata) -> Self {
        Self::from_metadata_with_mtime(name, meta, |m| m.modified())
    }

    /// Test seam: same construction logic but the mtime is supplied by a closure,
    /// so SA-T11c can pass `|_| Err(...)` to force `modified: None` deterministically.
    pub fn from_metadata_with_mtime<F>(name: String, meta: &Metadata, mtime_fn: F) -> Self
    where
        F: Fn(&Metadata) -> std::io::Result<SystemTime>,
    {
        let size = if meta.is_file() {
            Some(meta.len())
        } else {
            None
        };
        let modified = mtime_fn(meta)
            .ok()
            .map(|t| DateTime::<Utc>::from(t).to_rfc3339());
        Entry {
            name,
            is_dir: meta.is_dir(),
            size,
            modified,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Slice B record additions: ScopeMeta / ChildMeta / ScanResult / VersionEntry.
// ─────────────────────────────────────────────────────────────────────────────

/// serde default for [`ScopeMeta::r#type`] — matches [`ScopeMeta::default`] so
/// the serde-deserialize path and the Rust `Default` agree (a scope always
/// represents a directory = a `collection`; ADR 2026-06-29 Decision 1).
fn default_scope_type() -> Option<String> {
    Some("collection".to_string())
}

/// `_scope` block of a `.meta.yaml` — slice B WIT `record scope-meta`.
///
/// `type` (ADR 2026-06-29 Decision 1) is the scope-level entity discriminator,
/// auto-populated to `collection` (a scope is a directory) via `Default`. It is
/// exposed through the CONTRACT-010 L0 `scope-meta` scan record but is NOT a
/// schema-required field (the `_scope.type`-requiredness ADR Open Follow-up
/// stays undecided) — so a `.meta.yaml` lacking `_scope.type` still validates.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScopeMeta {
    pub slug: Option<String>,
    pub description: String,
    pub tags: Vec<String>,
    pub status: Option<String>,
    #[serde(rename = "type", default = "default_scope_type")]
    pub r#type: Option<String>,
}

impl Default for ScopeMeta {
    fn default() -> Self {
        Self {
            slug: None,
            description: String::new(),
            tags: Vec::new(),
            status: None,
            // A scope always represents a directory → `collection` (ADR Decision 1).
            r#type: Some("collection".to_string()),
        }
    }
}

/// Per-child entry in a `scan-result` — slice B WIT `record child-meta`.
///
/// `type` (ADR 2026-06-29 Decision 1) is the entity discriminator for the child;
/// always non-empty (resolved via the defaults table / the scan `[pending]`
/// fallback). Exposed through the CONTRACT-010 L0 `child-meta` scan record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChildMeta {
    pub name: String,
    pub description: String,
    pub tags: Vec<String>,
    pub is_dir: bool,
    pub has_agent: bool,
    #[serde(rename = "type", default)]
    pub r#type: String,
}

/// Slice B WIT `record scan-result`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanResult {
    pub scope: ScopeMeta,
    pub children: Vec<ChildMeta>,
}

/// Slice B WIT `record version-entry`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VersionEntry {
    pub version: String,
    pub timestamp: String,
    pub message: Option<String>,
}

/// Encode `ScopeMeta` into Wasmtime `Val::Record`.
pub fn scope_meta_to_val(s: &ScopeMeta) -> Val {
    Val::Record(vec![
        (
            "slug".to_string(),
            match &s.slug {
                Some(v) => Val::Option(Some(Box::new(Val::String(v.clone())))),
                None => Val::Option(None),
            },
        ),
        (
            "description".to_string(),
            Val::String(s.description.clone()),
        ),
        (
            "tags".to_string(),
            Val::List(s.tags.iter().map(|t| Val::String(t.clone())).collect()),
        ),
        (
            "status".to_string(),
            match &s.status {
                Some(v) => Val::Option(Some(Box::new(Val::String(v.clone())))),
                None => Val::Option(None),
            },
        ),
        // `type` appended LAST (ADR 2026-06-29 Decision 1 / CONTRACT-010) so the
        // pre-existing positional field indices are unchanged.
        (
            "type".to_string(),
            match &s.r#type {
                Some(v) => Val::Option(Some(Box::new(Val::String(v.clone())))),
                None => Val::Option(None),
            },
        ),
    ])
}

/// Encode `ChildMeta` into Wasmtime `Val::Record`.
pub fn child_meta_to_val(c: &ChildMeta) -> Val {
    Val::Record(vec![
        ("name".to_string(), Val::String(c.name.clone())),
        (
            "description".to_string(),
            Val::String(c.description.clone()),
        ),
        (
            "tags".to_string(),
            Val::List(c.tags.iter().map(|t| Val::String(t.clone())).collect()),
        ),
        ("is-dir".to_string(), Val::Bool(c.is_dir)),
        ("has-agent".to_string(), Val::Bool(c.has_agent)),
        // `type` appended LAST (ADR 2026-06-29 Decision 1 / CONTRACT-010) so the
        // positional `fields[4]` = has-agent decoder contract is preserved.
        ("type".to_string(), Val::String(c.r#type.clone())),
    ])
}

/// Encode `ScanResult` into Wasmtime `Val::Record`.
pub fn scan_result_to_val(r: &ScanResult) -> Val {
    Val::Record(vec![
        ("scope".to_string(), scope_meta_to_val(&r.scope)),
        (
            "children".to_string(),
            Val::List(r.children.iter().map(child_meta_to_val).collect()),
        ),
    ])
}

/// Encode `VersionEntry` into Wasmtime `Val::Record`.
pub fn version_entry_to_val(v: &VersionEntry) -> Val {
    Val::Record(vec![
        ("version".to_string(), Val::String(v.version.clone())),
        ("timestamp".to_string(), Val::String(v.timestamp.clone())),
        (
            "message".to_string(),
            match &v.message {
                Some(m) => Val::Option(Some(Box::new(Val::String(m.clone())))),
                None => Val::Option(None),
            },
        ),
    ])
}

/// Encode an `Entry` into the Wasmtime `Val::Record` shape for the WIT
/// `record entry` value-type.
///
/// Wasmtime 43 expects `Val::Record(Vec<(String, Val)>)`; option fields use
/// `Val::Option(Some(Box::new(_)))` for present and `Val::Option(None)` for absent.
pub fn entry_to_val(e: &Entry) -> Val {
    Val::Record(vec![
        ("name".to_string(), Val::String(e.name.clone())),
        ("is-dir".to_string(), Val::Bool(e.is_dir)),
        (
            "size".to_string(),
            match e.size {
                Some(n) => Val::Option(Some(Box::new(Val::U64(n)))),
                None => Val::Option(None),
            },
        ),
        (
            "modified".to_string(),
            match &e.modified {
                Some(s) => Val::Option(Some(Box::new(Val::String(s.clone())))),
                None => Val::Option(None),
            },
        ),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_metadata_with_mtime_err_returns_none_modified() {
        let tempdir = tempfile::TempDir::new().unwrap();
        let path = tempdir.path().join("f.txt");
        std::fs::write(&path, b"x").unwrap();
        let meta = std::fs::metadata(&path).unwrap();
        let entry = Entry::from_metadata_with_mtime("f.txt".into(), &meta, |_| {
            Err(std::io::Error::new(std::io::ErrorKind::Other, "stub"))
        });
        assert_eq!(entry.modified, None);
        assert_eq!(entry.is_dir, false);
        assert_eq!(entry.size, Some(1));
    }

    #[test]
    fn from_metadata_with_mtime_ok_returns_rfc3339_string() {
        let tempdir = tempfile::TempDir::new().unwrap();
        let path = tempdir.path().join("f.txt");
        std::fs::write(&path, b"hi").unwrap();
        let meta = std::fs::metadata(&path).unwrap();
        let fixed = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000);
        let entry = Entry::from_metadata_with_mtime("f.txt".into(), &meta, move |_| Ok(fixed));
        assert!(entry.modified.is_some(), "expected Some(rfc3339), got None");
        let s = entry.modified.unwrap();
        assert!(s.contains('T'), "expected RFC3339 string, got {s}");
    }

    #[test]
    fn entry_to_val_shape() {
        let entry = Entry {
            name: "f.txt".into(),
            is_dir: false,
            size: Some(42),
            modified: Some("2026-05-03T13:30:00Z".into()),
        };
        let val = entry_to_val(&entry);
        match val {
            Val::Record(fields) => {
                assert_eq!(fields.len(), 4);
                assert_eq!(fields[0].0, "name");
                match &fields[0].1 {
                    Val::String(s) => assert_eq!(s, "f.txt"),
                    _ => panic!("name not a String"),
                }
                assert_eq!(fields[1].0, "is-dir");
                match &fields[1].1 {
                    Val::Bool(b) => assert_eq!(*b, false),
                    _ => panic!("is-dir not a Bool"),
                }
                assert_eq!(fields[2].0, "size");
                match &fields[2].1 {
                    Val::Option(Some(inner)) => match inner.as_ref() {
                        Val::U64(n) => assert_eq!(*n, 42),
                        _ => panic!("size inner not U64"),
                    },
                    _ => panic!("size not Option(Some)"),
                }
                assert_eq!(fields[3].0, "modified");
                match &fields[3].1 {
                    Val::Option(Some(inner)) => match inner.as_ref() {
                        Val::String(s) => assert!(s.contains('T')),
                        _ => panic!("modified inner not String"),
                    },
                    _ => panic!("modified not Option(Some)"),
                }
            }
            _ => panic!("expected Val::Record"),
        }
    }

    #[test]
    fn entry_to_val_size_none_lowers_to_option_none() {
        let entry = Entry {
            name: "dir".into(),
            is_dir: true,
            size: None,
            modified: None,
        };
        let val = entry_to_val(&entry);
        match val {
            Val::Record(fields) => {
                match &fields[2].1 {
                    Val::Option(None) => {}
                    _ => panic!("size should be Val::Option(None) for is_dir"),
                }
                match &fields[3].1 {
                    Val::Option(None) => {}
                    _ => panic!("modified None should be Val::Option(None)"),
                }
            }
            _ => panic!("expected Val::Record"),
        }
    }

    #[test]
    fn child_meta_to_val_appends_type_last_preserving_has_agent_index() {
        // AC-18 leg c: `type` is appended LAST so the positional decoder contract
        // (fields[4] = has-agent) is preserved and fields[5] = type.
        let c = ChildMeta {
            name: "notes.md".into(),
            description: "d".into(),
            tags: vec![],
            is_dir: false,
            has_agent: true,
            r#type: "document".into(),
        };
        match child_meta_to_val(&c) {
            Val::Record(fields) => {
                assert_eq!(fields.len(), 6);
                assert_eq!(fields[4].0, "has-agent");
                assert!(matches!(fields[4].1, Val::Bool(true)));
                assert_eq!(fields[5].0, "type");
                match &fields[5].1 {
                    Val::String(s) => assert_eq!(s, "document"),
                    _ => panic!("type not a String"),
                }
            }
            _ => panic!("expected Val::Record"),
        }
    }

    #[test]
    fn scope_meta_to_val_appends_type_last_and_default_is_collection() {
        let s = ScopeMeta::default();
        assert_eq!(s.r#type.as_deref(), Some("collection"));
        match scope_meta_to_val(&s) {
            Val::Record(fields) => {
                assert_eq!(fields.len(), 5);
                assert_eq!(fields[4].0, "type");
                match &fields[4].1 {
                    Val::Option(Some(inner)) => match inner.as_ref() {
                        Val::String(v) => assert_eq!(v, "collection"),
                        _ => panic!("scope type inner not String"),
                    },
                    _ => panic!("scope type should be Option(Some) for default"),
                }
            }
            _ => panic!("expected Val::Record"),
        }
    }
}
