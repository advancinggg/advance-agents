//! Pure `.meta.yaml` transforms for the operator core (oss-fs-core §6.7, §7.2).
//!
//! Re-key on rename, take/put an entry, never persist `_scope` as an entry,
//! and plan quarantine-and-rebuild when the sidecar is unreadable.

#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::unimplemented)]
#![deny(clippy::todo)]

use std::path::{Path, PathBuf};

use advance_shared_types::workspace_path::{classify_component, policy_skeleton, ComponentClass};
use sha2::{Digest, Sha256};

use crate::error::FsError;
use crate::meta_maintainer::{EntryMetaValues, MetaFile, MetaMaintainer};

use super::{FilesError, LIST_SCAN_CAP};

const QUARANTINE_DIR: &str = "quarantine";
const META_SIDECAR: &str = ".meta.yaml";

/// Where unreadable sidecar bytes will be moved (oss-fs-core §6.7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QuarantineDest {
    /// `<files-state>/quarantine/<op_id>-<hex8(dir)>.yaml` (same device).
    FilesState { path: PathBuf },
    /// `.~advance-quarantine-<op_id>` next to the sidecar (cross-device).
    InPlace { name: String },
}

/// One directory child that survives a quarantine rebuild (no content extract).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SurvivingChild {
    pub name: String,
    pub is_dir: bool,
}

/// Quarantine destination plus a rebuilt [`MetaFile`].
#[derive(Debug, Clone)]
pub struct QuarantineRebuildPlan {
    pub dest: QuarantineDest,
    pub rebuilt: MetaFile,
}

/// True for `_scope` and look-alikes (policy skeleton).
pub fn is_scope_key(name: &str) -> bool {
    name == "_scope" || policy_skeleton(name) == "_scope"
}

/// Parse sidecar bytes through [`MetaMaintainer::parse_meta_bytes`].
pub fn parse_meta_bytes(bytes: &[u8]) -> Result<MetaFile, FsError> {
    MetaMaintainer::parse_meta_bytes(bytes)
}

/// Remove `name` from `meta.entries`.
pub fn take_entry(meta: &mut MetaFile, name: &str) -> Option<EntryMetaValues> {
    meta.entries.remove(name)
}

/// Insert `entry` under `name`. Refuses `_scope` (never an entry).
pub fn put_entry(meta: &mut MetaFile, name: &str, entry: EntryMetaValues) -> bool {
    if is_scope_key(name) {
        return false;
    }
    meta.entries.insert(name.to_string(), entry);
    true
}

/// Rename an entry key, preserving user values. Refuses a `_scope` destination.
pub fn rekey_entry(meta: &mut MetaFile, from: &str, to: &str) -> bool {
    if is_scope_key(to) {
        return false;
    }
    match take_entry(meta, from) {
        Some(entry) => put_entry(meta, to, entry),
        None => false,
    }
}

/// Same-device → files-state quarantine path; otherwise in-place private name.
pub fn quarantine_dest(
    files_state: &Path,
    op_id: &str,
    dir_rel: &str,
    same_device: bool,
) -> QuarantineDest {
    if same_device {
        let mut file = String::new();
        file.push_str(op_id);
        file.push('-');
        file.push_str(&hex8(dir_rel.as_bytes()));
        file.push_str(".yaml");
        QuarantineDest::FilesState {
            path: files_state.join(QUARANTINE_DIR).join(file),
        }
    } else {
        let mut name = String::from(".~advance-quarantine-");
        name.push_str(op_id);
        QuarantineDest::InPlace { name }
    }
}

/// Rebuild `build_default_meta(dir_name)` plus a fresh auto-populated entry
/// (empty body: no content extraction) for each surviving child. `_scope` and
/// hidden/junk names never become entries. Larger than [`LIST_SCAN_CAP`] → error.
pub fn rebuild_meta(
    maintainer: &MetaMaintainer,
    dir_name: &str,
    surviving: &[SurvivingChild],
) -> Result<MetaFile, FilesError> {
    if surviving.len() > LIST_SCAN_CAP {
        return Err(FilesError::Io("meta_unsafe".into()));
    }
    let mut meta = maintainer.build_default_meta(dir_name);
    for child in surviving {
        if !surviving_name_ok(&child.name) {
            continue;
        }
        let (next, _changed) = maintainer
            .add_entry_for_write(Some(meta), &child.name, b"")
            .map_err(|e| FilesError::Io(e.to_string()))?;
        meta = next;
        if child.is_dir {
            if let Some(entry) = meta.entries.get_mut(&child.name) {
                entry.r#type = "collection".to_string();
                entry
                    .extra
                    .insert("is_dir".to_string(), serde_yml::Value::Bool(true));
            }
        }
    }
    Ok(meta)
}

/// Plan: destination for the unreadable bytes plus the rebuilt sidecar.
pub fn plan_quarantine_and_rebuild(
    maintainer: &MetaMaintainer,
    files_state: &Path,
    op_id: &str,
    dir_rel: &str,
    dir_name: &str,
    same_device: bool,
    surviving: &[SurvivingChild],
) -> Result<QuarantineRebuildPlan, FilesError> {
    let dest = quarantine_dest(files_state, op_id, dir_rel, same_device);
    let rebuilt = rebuild_meta(maintainer, dir_name, surviving)?;
    Ok(QuarantineRebuildPlan { dest, rebuilt })
}

fn surviving_name_ok(name: &str) -> bool {
    if name.is_empty() || name == "." || name == ".." || name == META_SIDECAR || is_scope_key(name)
    {
        return false;
    }
    !matches!(
        classify_component(name, false),
        ComponentClass::Private | ComponentClass::Junk
    )
}

fn hex8(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(8);
    for &b in digest.iter().take(4) {
        out.push(char::from(HEX[usize::from(b >> 4)]));
        out.push(char::from(HEX[usize::from(b & 0x0f)]));
    }
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::atomic::DefaultAtomicWriter;
    use crate::meta_schema::MetaSchemaLoader;
    use std::sync::Arc;

    fn maintainer() -> Arc<MetaMaintainer> {
        let schema_path = std::env::temp_dir().join("schema-meta-ops-test.yaml");
        let loader = Arc::new(MetaSchemaLoader::new_with_default(schema_path));
        Arc::new(MetaMaintainer::new(loader, Arc::new(DefaultAtomicWriter)))
    }

    fn dummy_entry(name: &str) -> EntryMetaValues {
        EntryMetaValues {
            name: name.to_string(),
            slug: name.to_string(),
            description: format!("desc {name}"),
            r#type: "document".into(),
            tags: vec!["kept".into()],
            lifecycle: None,
            extra: Default::default(),
        }
    }

    #[test]
    fn scope_named_entry_never_written() {
        let mm = maintainer();
        let mut meta = MetaFile::default();
        assert!(
            !put_entry(&mut meta, "_scope", dummy_entry("stolen")),
            "put must refuse _scope"
        );
        assert!(!meta.entries.contains_key("_scope"));

        meta.entries
            .insert("notes.md".into(), dummy_entry("notes.md"));
        assert!(
            !rekey_entry(&mut meta, "notes.md", "_scope"),
            "re-key must refuse _scope destination"
        );
        assert!(!meta.entries.contains_key("_scope"));
        assert!(meta.entries.contains_key("notes.md"));

        let plan = plan_quarantine_and_rebuild(
            mm.as_ref(),
            Path::new("/tmp/files-state"),
            "01ARZ3NDEKTSV4RRFFQ69G5FAV",
            "notes",
            "notes",
            true,
            &[
                SurvivingChild {
                    name: "_scope".into(),
                    is_dir: false,
                },
                SurvivingChild {
                    name: "a.md".into(),
                    is_dir: false,
                },
            ],
        )
        .unwrap();
        assert!(
            !plan.rebuilt.entries.contains_key("_scope"),
            "_scope must not become an entry in a rebuild"
        );
        assert!(plan.rebuilt.entries.contains_key("a.md"));
        assert!(
            matches!(plan.dest, QuarantineDest::FilesState { .. }),
            "same-device uses files-state dest: {:?}",
            plan.dest
        );
        let QuarantineDest::FilesState { path } = &plan.dest else {
            return;
        };
        let name = path.file_name().and_then(|s| s.to_str()).unwrap();
        assert!(
            name.starts_with("01ARZ3NDEKTSV4RRFFQ69G5FAV-"),
            "quarantine name {name}"
        );
        assert!(name.ends_with(".yaml"));

        let parsed = parse_meta_bytes(
            b"_scope:\n  description: notes with & and *\na.md:\n  name: a\n  slug: a\n  description: ok\n",
        )
        .unwrap();
        assert!(!parsed.entries.contains_key("_scope"));
        assert!(parsed.entries.contains_key("a.md"));
    }

    #[test]
    fn rekey_preserves_user_values() {
        let mut meta = MetaFile::default();
        put_entry(&mut meta, "old.md", dummy_entry("old.md"));
        assert!(rekey_entry(&mut meta, "old.md", "new.md"));
        assert!(!meta.entries.contains_key("old.md"));
        let got = meta.entries.get("new.md").unwrap();
        assert_eq!(got.description, "desc old.md");
        assert_eq!(got.tags, vec!["kept".to_string()]);
    }

    #[test]
    fn cross_device_quarantine_is_in_place() {
        let dest = quarantine_dest(Path::new("/state/files"), "opid", "dir", false);
        assert_eq!(
            dest,
            QuarantineDest::InPlace {
                name: ".~advance-quarantine-opid".into()
            }
        );
    }
}
