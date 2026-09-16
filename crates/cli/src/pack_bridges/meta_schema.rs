//! Meta-schema bridge (§3.1 row 4): an installed pack's
//! `meta-schema-extensions/{name}.yaml` → the workspace `meta-schema.yaml` the
//! live `cap_fs::MetaSchemaLoader` was constructed over, then a reload so the
//! running schema (and the polling watcher's baseline) sees the new fields.
//!
//! The merge itself is pack-manager's structured single-document merge
//! (`meta_schema_merge`): identical redeclaration is idempotent, a differing
//! spec is a [`PackBridgeError::SchemaConflict`]. Before anything is written
//! the merged document is dry-run parsed by cap-fs's OWN schema parser
//! (`MetaSchemaLoader::from_yaml`), so a merge that cap-fs would reject leaves
//! the file untouched and the post-write `reload_from_disk` can only fail on
//! I/O — the on-disk file and the live schema never diverge.

use std::path::PathBuf;
use std::sync::Arc;

use advance_pack_manager::meta_schema_merge::{
    merge_meta_schema_extension_file_with, MetaSchemaMergeError,
};
use advance_pack_manager::{ComponentKind, PackRegistry};
use cap_fs::meta_schema::MetaSchemaLoader;

use super::{resolve_kind, PackBridgeError};

/// Fields the merge added / found already present with an identical spec.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MergeReport {
    pub added: Vec<String>,
    pub unchanged: Vec<String>,
}

pub struct PackMetaSchemaBridge {
    registry: Arc<dyn PackRegistry>,
}

impl PackMetaSchemaBridge {
    pub fn new(registry: Arc<dyn PackRegistry>) -> Self {
        Self { registry }
    }

    /// Merge `{pack}@{ver}/meta-schema-extensions/{name}` into `loader`'s
    /// schema file and reload the live schema.
    pub fn merge(
        &self,
        pack_ref: &str,
        loader: &MetaSchemaLoader,
    ) -> Result<MergeReport, PackBridgeError> {
        let resolution = resolve_kind(
            &*self.registry,
            pack_ref,
            ComponentKind::MetaSchemaExtension,
        )?;
        let target = loader.schema_path().to_path_buf();
        let report =
            merge_meta_schema_extension_file_with(&resolution.local_path, &target, |merged| {
                // Dry-run through cap-fs's parser BEFORE the write.
                MetaSchemaLoader::from_yaml(PathBuf::new(), merged)
                    .map(|_| ())
                    .map_err(|e| format!("merged schema rejected by cap-fs: {e}"))
            })
            .map_err(|e| match e {
                MetaSchemaMergeError::Conflict {
                    field,
                    existing,
                    incoming,
                } => PackBridgeError::SchemaConflict {
                    field,
                    existing,
                    incoming,
                },
                other => PackBridgeError::Pack(other.into()),
            })?;
        loader
            .reload_from_disk()
            .map_err(|e| PackBridgeError::Io(format!("meta-schema reload after merge: {e}")))?;
        Ok(MergeReport {
            added: report.added,
            unchanged: report.unchanged,
        })
    }
}
