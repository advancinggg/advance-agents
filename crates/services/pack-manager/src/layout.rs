//! Pack directory layout validation (AC-03, REQ-342).
//!
//! Strict top-level allow-list per PRD §19.3 / MODULE-018 §2.5: `pack.yaml`
//! MUST exist, optional `.meta.yaml`, top-level entries restricted to the
//! 11 canonical subdirectory names (the 10 §19.3 kinds + the AC-17
//! `resource-capabilities` category; sparse subset OK — pack ships only the
//! subdirs it populates). Unknown top-level entries (`README.md`, `LICENSE`,
//! `extra/`, `.DS_Store`, etc.) → `InvalidManifest`.
//!
//! Insertion site: called inline inside `Installer::install_with_context`'s
//! step ⑥ window, AFTER `copy_dir_no_symlinks` and BEFORE
//! `verify_provides_on_disk`. No new `InstallStep` enum variant, no new
//! trace event — preserves the Slice A/B verbatim PRD §19.5 8-step trace
//! order. AC-03 verification is observable via the install-time error
//! path (a malformed layout fails install with `InvalidManifest`).

use std::path::Path;

use crate::error::PackError;

/// Canonical PRD §19.3 / MODULE-018 §2.5 top-level allow-list.
/// `.meta.yaml` is optional; `pack.yaml` is required (separately checked).
const CANONICAL_TOP_LEVEL: &[&str] = &[
    "pack.yaml",
    ".meta.yaml",
    "behavior-binaries",
    "agent-templates",
    "skills",
    "components",
    "channel-adapters",
    "mcp-servers",
    "presets",
    "workflows",
    "memory-seeds",
    "meta-schema-extensions",
    "resource-capabilities",
];

/// Validate the top-level shape of a pack install directory per AC-03.
///
/// - `pack.yaml` MUST exist (re-asserted here for explicit AC-03 coverage
///   beyond step ③'s manifest parse).
/// - Every other top-level entry MUST appear in the canonical allow-list.
/// - Subdirectory contents are NOT recursed; admin owns sub-tree shape.
/// - Declared `provides[*]` existence is enforced separately by step ⑥a
///   `verify_provides_on_disk` (Slice A) — orthogonal concerns.
pub(crate) fn validate_pack_layout(install_path: &Path) -> Result<(), PackError> {
    // Require pack.yaml at the pack root.
    let pack_yaml = install_path.join("pack.yaml");
    match std::fs::symlink_metadata(&pack_yaml) {
        Ok(md) if md.is_file() && !md.file_type().is_symlink() => {}
        Ok(_) => {
            return Err(PackError::InvalidManifest(format!(
                "pack layout: pack.yaml must be a regular file: {}",
                pack_yaml.display()
            )));
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(PackError::InvalidManifest(
                "pack layout: missing required pack.yaml at pack root".into(),
            ));
        }
        Err(e) => {
            return Err(PackError::Io {
                path: pack_yaml,
                source: e,
            });
        }
    }

    // Top-level entry scan — strict allow-list + file-type enforcement.
    // Slice C adversarial round 11 Info 1 fix: don't just allow-list by
    // name — verify each entry has the canonical TYPE for its name.
    // `pack.yaml` and `.meta.yaml` must be regular files; the 11 subdirs
    // must be directories. Symlinks are rejected outright at the top
    // level (defense-in-depth on top of `copy_dir_no_symlinks`).
    let read_dir = std::fs::read_dir(install_path).map_err(|e| PackError::Io {
        path: install_path.to_path_buf(),
        source: e,
    })?;
    for entry in read_dir {
        let entry = entry.map_err(|e| PackError::Io {
            path: install_path.to_path_buf(),
            source: e,
        })?;
        let name_os = entry.file_name();
        let name = name_os.to_str().ok_or_else(|| {
            PackError::InvalidManifest(format!(
                "pack layout: top-level entry has non-UTF-8 name: {name_os:?}"
            ))
        })?;
        if !CANONICAL_TOP_LEVEL.contains(&name) {
            return Err(PackError::InvalidManifest(format!(
                "pack layout: unknown top-level entry: {name:?}"
            )));
        }
        // Type enforcement: symlinks at top level are always rejected.
        let md = std::fs::symlink_metadata(entry.path()).map_err(|e| PackError::Io {
            path: entry.path(),
            source: e,
        })?;
        if md.file_type().is_symlink() {
            return Err(PackError::InvalidManifest(format!(
                "pack layout: top-level entry {name:?} is a symlink (rejected): {}",
                entry.path().display()
            )));
        }
        // File-type expectation per name.
        let expected_dir = matches!(
            name,
            "behavior-binaries"
                | "agent-templates"
                | "skills"
                | "components"
                | "channel-adapters"
                | "mcp-servers"
                | "presets"
                | "workflows"
                | "memory-seeds"
                | "meta-schema-extensions"
                | "resource-capabilities"
        );
        if expected_dir && !md.is_dir() {
            return Err(PackError::InvalidManifest(format!(
                "pack layout: top-level {name:?} must be a directory (got {:?})",
                md.file_type()
            )));
        }
        if !expected_dir && !md.is_file() {
            // `name` is `pack.yaml` or `.meta.yaml` (the only non-dir
            // canonical names).
            return Err(PackError::InvalidManifest(format!(
                "pack layout: top-level {name:?} must be a regular file (got {:?})",
                md.file_type()
            )));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_pack_dir(extras: &[(&str, bool)]) -> tempfile::TempDir {
        // `extras` items: (name, is_dir). Pack root always has pack.yaml.
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::write(dir.path().join("pack.yaml"), b"name: x\n").unwrap();
        for (name, is_dir) in extras {
            let p = dir.path().join(name);
            if *is_dir {
                std::fs::create_dir_all(&p).unwrap();
            } else {
                std::fs::write(&p, b"").unwrap();
            }
        }
        dir
    }

    #[test]
    fn pack_layout_accepts_pack_yaml_only() {
        let dir = make_pack_dir(&[]);
        validate_pack_layout(dir.path()).unwrap();
    }

    #[test]
    fn pack_layout_accepts_full_canonical_layout() {
        let extras: Vec<(&str, bool)> = vec![
            (".meta.yaml", false),
            ("behavior-binaries", true),
            ("agent-templates", true),
            ("skills", true),
            ("components", true),
            ("channel-adapters", true),
            ("mcp-servers", true),
            ("presets", true),
            ("workflows", true),
            ("memory-seeds", true),
            ("meta-schema-extensions", true),
        ];
        let dir = make_pack_dir(&extras);
        validate_pack_layout(dir.path()).unwrap();
    }

    #[test]
    fn pack_layout_accepts_sparse_subset() {
        let dir = make_pack_dir(&[("behavior-binaries", true), ("skills", true)]);
        validate_pack_layout(dir.path()).unwrap();
    }

    #[test]
    fn pack_layout_rejects_readme() {
        let dir = make_pack_dir(&[("README.md", false)]);
        match validate_pack_layout(dir.path()) {
            Err(PackError::InvalidManifest(msg)) => assert!(msg.contains("README.md")),
            other => panic!("expected InvalidManifest, got {other:?}"),
        }
    }

    #[test]
    fn pack_layout_rejects_extra_subdir() {
        let dir = make_pack_dir(&[("extra", true)]);
        match validate_pack_layout(dir.path()) {
            Err(PackError::InvalidManifest(msg)) => assert!(msg.contains("extra")),
            other => panic!("expected InvalidManifest, got {other:?}"),
        }
    }

    #[test]
    fn pack_layout_rejects_root_wasm() {
        let dir = make_pack_dir(&[("tool.wasm", false)]);
        match validate_pack_layout(dir.path()) {
            Err(PackError::InvalidManifest(msg)) => assert!(msg.contains("tool.wasm")),
            other => panic!("expected InvalidManifest, got {other:?}"),
        }
    }

    #[test]
    fn pack_layout_rejects_missing_pack_yaml() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::create_dir_all(dir.path().join("behavior-binaries")).unwrap();
        match validate_pack_layout(dir.path()) {
            Err(PackError::InvalidManifest(msg)) => {
                assert!(msg.contains("missing required pack.yaml"))
            }
            other => panic!("expected InvalidManifest, got {other:?}"),
        }
    }

    // ── MODULE-018-T91 (AC-17): resource-capabilities/ layout parity ──

    #[test]
    fn t91_pack_layout_accepts_resource_capabilities_dir() {
        // AC-17: the top-level allow-list widened by exactly `resource-capabilities/`.
        let dir = make_pack_dir(&[("resource-capabilities", true)]);
        validate_pack_layout(dir.path()).unwrap();
    }

    #[test]
    fn t91_pack_layout_still_rejects_unknown_dir_alongside_resource_capabilities() {
        // Widening is EXACTLY `resource-capabilities/` — an unknown sibling still fails.
        let dir = make_pack_dir(&[("resource-capabilities", true), ("extra", true)]);
        match validate_pack_layout(dir.path()) {
            Err(PackError::InvalidManifest(msg)) => assert!(msg.contains("extra")),
            other => panic!("expected InvalidManifest, got {other:?}"),
        }
    }

    #[test]
    fn t91_pack_layout_rejects_resource_capabilities_as_file() {
        // Directory-backed kind: a regular file named `resource-capabilities` is rejected.
        let dir = make_pack_dir(&[("resource-capabilities", false)]);
        match validate_pack_layout(dir.path()) {
            Err(PackError::InvalidManifest(msg)) => {
                assert!(msg.contains("resource-capabilities"))
            }
            other => panic!("expected InvalidManifest, got {other:?}"),
        }
    }
}
