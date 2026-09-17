//! Pack bundling for a static registry (entity-data lane E4, `advance pack bundle`).
//!
//! A registry is a directory of static files in the layout [`RegistryClient`] consumers read:
//!
//! ```text
//! <registry>/<name>-<version>.tar.gz          the pack (flat: pack.yaml at the archive root)
//! <registry>/index/<name>.json                { "name", "versions": { "<v>": { tarball, sha256, size } } }
//! ```
//!
//! `bundle_pack` archives a validated pack directory (the install-layout allow-list; `pack.sig`
//! rides along when present), records its sha256 + size, and merges the version into the
//! index (other versions are kept). The tarball is reproducible: entries sorted by path,
//! mtime 0, uid/gid 0, modes 0644, ustar headers only (the installer refuses GNU long-name
//! extension entries), gzip header without a timestamp — the same source tree bundles to the
//! same bytes on any machine, so a CI rebuild can compare digests.
//!
//! The `tarball` field is the bare file name unless a `base_url` is given (then
//! `<base_url>/<file>`); [`RegistryClient`] implementations resolve a bare name against the
//! registry base, so one static tree can be served from any host.
//!
//! [`RegistryClient`]: crate::RegistryClient

use std::io::Write;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::error::PackError;
use crate::manifest::PackManifest;

/// Bound on one bundled file (matches the installer's per-entry cap order of magnitude).
const MAX_BUNDLE_FILE_BYTES: u64 = 64 * 1024 * 1024;
/// Bound on the number of files in one bundle.
const MAX_BUNDLE_FILES: usize = 4096;

/// What `bundle_pack` produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BundleReport {
    pub name: String,
    pub version: String,
    /// `<registry>/<name>-<version>.tar.gz`.
    pub tarball: PathBuf,
    pub size: u64,
    /// Lower-case hex sha256 of the tarball bytes.
    pub sha256: String,
    /// `<registry>/index/<name>.json`.
    pub index: PathBuf,
}

fn violation(reason: impl Into<String>) -> PackError {
    PackError::ConstraintViolation {
        reason: reason.into(),
    }
}

fn io(path: &Path, source: std::io::Error) -> PackError {
    PackError::Io {
        path: path.to_path_buf(),
        source,
    }
}

/// Every regular file under `root`, as sorted `(relative path, absolute path)` pairs. Symlinks
/// are refused (the installer refuses them too).
fn collect_files(root: &Path) -> Result<Vec<(String, PathBuf)>, PackError> {
    fn walk(root: &Path, dir: &Path, out: &mut Vec<(String, PathBuf)>) -> Result<(), PackError> {
        for entry in std::fs::read_dir(dir).map_err(|e| io(dir, e))? {
            let entry = entry.map_err(|e| io(dir, e))?;
            let path = entry.path();
            let md = std::fs::symlink_metadata(&path).map_err(|e| io(&path, e))?;
            if md.file_type().is_symlink() {
                return Err(violation(format!(
                    "symlink in pack source: {}",
                    path.display()
                )));
            }
            if md.is_dir() {
                walk(root, &path, out)?;
            } else if md.is_file() {
                if md.len() > MAX_BUNDLE_FILE_BYTES {
                    return Err(violation(format!(
                        "{} exceeds the {MAX_BUNDLE_FILE_BYTES}-byte bundle file cap",
                        path.display()
                    )));
                }
                let rel = path
                    .strip_prefix(root)
                    .map_err(|e| violation(e.to_string()))?
                    .to_str()
                    .ok_or_else(|| violation(format!("non-UTF-8 path: {}", path.display())))?
                    .replace('\\', "/");
                out.push((rel, path));
                if out.len() > MAX_BUNDLE_FILES {
                    return Err(violation(format!(
                        "more than {MAX_BUNDLE_FILES} files in the pack"
                    )));
                }
            } else {
                return Err(violation(format!(
                    "non-regular file in pack source: {}",
                    path.display()
                )));
            }
        }
        Ok(())
    }
    let mut out = Vec::new();
    walk(root, root, &mut out)?;
    out.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(out)
}

/// A deterministic gzip'd ustar archive of `files` (see module docs).
fn build_archive(files: &[(String, PathBuf)]) -> Result<Vec<u8>, PackError> {
    let mut builder = tar::Builder::new(Vec::new());
    for (rel, abs) in files {
        let bytes = std::fs::read(abs).map_err(|e| io(abs, e))?;
        let mut header = tar::Header::new_ustar();
        header.set_path(rel).map_err(|e| {
            violation(format!(
                "{rel}: path does not fit a ustar header (rename it shorter): {e}"
            ))
        })?;
        header.set_entry_type(tar::EntryType::Regular);
        header.set_mode(0o644);
        header.set_uid(0);
        header.set_gid(0);
        header.set_mtime(0);
        header.set_size(bytes.len() as u64);
        header.set_cksum();
        builder
            .append(&header, bytes.as_slice())
            .map_err(|e| violation(format!("tar append {rel}: {e}")))?;
    }
    let tar_bytes = builder
        .into_inner()
        .map_err(|e| violation(format!("tar finish: {e}")))?;
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best());
    gz.write_all(&tar_bytes)
        .map_err(|e| violation(format!("gzip: {e}")))?;
    gz.finish()
        .map_err(|e| violation(format!("gzip finish: {e}")))
}

/// Archive `pack_dir` into `registry_dir` and merge the version into the registry index.
pub fn bundle_pack(
    pack_dir: &Path,
    registry_dir: &Path,
    base_url: Option<&str>,
) -> Result<BundleReport, PackError> {
    let manifest_path = pack_dir.join("pack.yaml");
    let manifest_text =
        std::fs::read_to_string(&manifest_path).map_err(|e| io(&manifest_path, e))?;
    let manifest = PackManifest::from_yaml(&manifest_text)?;
    crate::layout::validate_pack_layout(pack_dir)?;
    let files = collect_files(pack_dir)?;
    let archive = build_archive(&files)?;
    let size = archive.len() as u64;
    let sha256 = hex::encode(Sha256::digest(&archive));

    let file_name = format!("{}-{}.tar.gz", manifest.name, manifest.version);
    let index_dir = registry_dir.join("index");
    std::fs::create_dir_all(&index_dir).map_err(|e| io(&index_dir, e))?;
    let tarball = registry_dir.join(&file_name);
    if tarball.exists() {
        let existing = std::fs::read(&tarball).map_err(|e| io(&tarball, e))?;
        if hex::encode(Sha256::digest(&existing)) != sha256 {
            return Err(violation(format!(
                "{} already exists with different content — a published version is immutable; \
                 bump the pack version",
                tarball.display()
            )));
        }
    } else {
        std::fs::write(&tarball, &archive).map_err(|e| io(&tarball, e))?;
    }

    // Merge the index document (other versions are kept; the name must match).
    let index_path = index_dir.join(format!("{}.json", manifest.name));
    let mut doc: serde_json::Value = if index_path.is_file() {
        let text = std::fs::read_to_string(&index_path).map_err(|e| io(&index_path, e))?;
        serde_json::from_str(&text).map_err(|e| violation(format!("index JSON: {e}")))?
    } else {
        serde_json::json!({ "name": manifest.name, "versions": {} })
    };
    let obj = doc
        .as_object_mut()
        .ok_or_else(|| violation("index document is not an object"))?;
    match obj.get("name").and_then(serde_json::Value::as_str) {
        Some(n) if n == manifest.name => {}
        Some(n) => {
            return Err(violation(format!(
                "index {} names pack {n:?}, not {:?}",
                index_path.display(),
                manifest.name
            )))
        }
        None => {
            obj.insert(
                "name".into(),
                serde_json::Value::String(manifest.name.clone()),
            );
        }
    }
    let tarball_ref = match base_url {
        Some(base) => format!("{}/{file_name}", base.trim_end_matches('/')),
        None => file_name.clone(),
    };
    let versions = obj
        .entry("versions")
        .or_insert_with(|| serde_json::json!({}))
        .as_object_mut()
        .ok_or_else(|| violation("index `versions` is not an object"))?;
    versions.insert(
        manifest.version.clone(),
        serde_json::json!({ "tarball": tarball_ref, "sha256": sha256, "size": size }),
    );
    let mut text = serde_json::to_string_pretty(&doc).map_err(|e| violation(e.to_string()))?;
    text.push('\n');
    std::fs::write(&index_path, text).map_err(|e| io(&index_path, e))?;

    Ok(BundleReport {
        name: manifest.name,
        version: manifest.version,
        tarball,
        size,
        sha256,
        index: index_path,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pack(dir: &Path) {
        std::fs::create_dir_all(dir.join("skills/demo")).unwrap();
        std::fs::write(dir.join("skills/demo/SKILL.md"), "# demo\n").unwrap();
        std::fs::write(
            dir.join("pack.yaml"),
            "name: demo\nversion: 1.0.0\nauthor: a\ndescription: d\nlicense: MIT\n\
             runtime-version: \">=0.1.0\"\ntrust-level: untrusted\nprovides:\n  skills:\n    - demo\n\
             checksums:\n  algo: sha256\n  files:\n    skills/demo/SKILL.md: \
             8b5f2e5b7e4dc2f0c18cd5a4d27cf4b3d61b1c1a8fdd0ed1a0b7d8a0b4a3d5e6\n",
        )
        .unwrap();
    }

    #[test]
    fn archive_bytes_are_reproducible_and_flat() {
        let tmp = tempfile::TempDir::new().unwrap();
        let a = tmp.path().join("a");
        let b = tmp.path().join("b");
        pack(&a);
        pack(&b);
        let fa = collect_files(&a).unwrap();
        let fb = collect_files(&b).unwrap();
        assert_eq!(
            fa.iter().map(|(r, _)| r.as_str()).collect::<Vec<_>>(),
            vec!["pack.yaml", "skills/demo/SKILL.md"]
        );
        let ba = build_archive(&fa).unwrap();
        let bb = build_archive(&fb).unwrap();
        assert_eq!(ba, bb, "same tree → same bytes");
        // Every entry is a regular file with a relative ustar path and mtime 0.
        let gz = flate2::read::GzDecoder::new(ba.as_slice());
        let mut archive = tar::Archive::new(gz);
        let mut names = Vec::new();
        for entry in archive.entries().unwrap() {
            let entry = entry.unwrap();
            assert!(entry.header().entry_type().is_file());
            assert_eq!(entry.header().mtime().unwrap(), 0);
            names.push(entry.path().unwrap().to_string_lossy().to_string());
        }
        assert_eq!(names, vec!["pack.yaml", "skills/demo/SKILL.md"]);
    }

    #[test]
    fn symlinks_and_long_paths_are_refused() {
        let tmp = tempfile::TempDir::new().unwrap();
        let dir = tmp.path().join("p");
        pack(&dir);
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(dir.join("pack.yaml"), dir.join("skills/demo/link"))
                .unwrap();
            assert!(collect_files(&dir).is_err());
            std::fs::remove_file(dir.join("skills/demo/link")).unwrap();
        }
        let long = "x".repeat(300);
        let files = vec![(long, dir.join("pack.yaml"))];
        assert!(build_archive(&files).is_err(), "no GNU long-name entries");
    }
}
