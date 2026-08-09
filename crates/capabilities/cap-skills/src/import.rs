//! Slice E — `SkillImporter` library API for PRD §12.4 Path A.
//!
//! Strictly knowledge-only: the importer NEVER ingests `tool_wasm` —
//! that's admin Path B's job (offline WASM-ization writes
//! `tool_wasm: Some(...)` directly into the admin pool via
//! `AdminPoolStorage::write_bundle`). Path A walks the source via
//! `tokio::fs::read_to_string` (UTF-8); binary files at the source root
//! (incl. a pre-existing `tool.wasm`) FAIL UTF-8 decode and reject the
//! import with `InvalidTransition("source-scripts entry not valid UTF-8:
//! ...")`. Tests SE-22d locks this property.
//!
//! Three ingestion methods:
//! - `import_from_local_path` — Path A canonical walk.
//! - `import_from_git_url` — `git clone --depth 1` via
//!   `std::process::Command` + `tokio::task::spawn_blocking` (so no tokio
//!   `process` feature needed; Cargo.toml stays out of slice boundary).
//!   URL scheme whitelist + env hardening; uses caller-supplied
//!   `work_dir` for clone destination (no `tempfile` production dep).
//! - `import_from_mcp_source` — synthesizes SKILL.md from a JSON
//!   `McpImportSpec` descriptor.

use std::path::{Path, PathBuf};
use std::time::Duration;

use advance_shared_types::skills::{Provenance, TrustLevel};

use crate::admin_pool::AdminPoolStorage;
use crate::error::SkillError;
use crate::security_scan::{validate_skill_filename, validate_skill_name};
use crate::skill_bundle::{McpImportSpec, SkillBundle, MAX_SKILL_MD_BYTES};

/// 30s wall-clock cap on git clone subprocess.
const GIT_CLONE_TIMEOUT: Duration = Duration::from_secs(30);

/// `SkillImporter` provides Path A ingestion for skill bundles.
pub struct SkillImporter {
    /// Parent directory under which `import_from_git_url` creates a
    /// uniquely-timestamped clone destination subdir. Caller manages the
    /// `work_dir` lifecycle (typically a tempdir at higher level).
    work_dir: PathBuf,
}

impl SkillImporter {
    pub fn new(work_dir: PathBuf) -> Self {
        Self { work_dir }
    }

    /// Path A canonical import: walks a local directory tree and writes
    /// the resulting `SkillBundle` to the admin pool.
    ///
    /// Walk:
    /// - `<source>/SKILL.md` (required, ≤ 50_000 bytes)
    /// - `<source>/.meta.yaml` (optional; informational only — bundle's
    ///   own meta is built from source-tree structure)
    /// - `<source>/templates/*` (optional; per-DIR + per-FILE symlink
    ///   reject + filename + UTF-8 + size cap)
    /// - `<source>/source-scripts/*` (optional; same guards)
    /// - Any OTHER file at source root → `source_scripts` vector via
    ///   `tokio::fs::read_to_string`; BINARY files fail UTF-8 decode →
    ///   InvalidTransition.
    ///
    /// Imports default `provenance: Imported`, `trust_level: Untrusted`.
    pub async fn import_from_local_path(
        &self,
        source: &Path,
        target_name: &str,
        admin: &AdminPoolStorage,
    ) -> Result<(), SkillError> {
        validate_skill_name(target_name)?;

        // Reject if source itself is a symlink (root-level defense).
        let source_meta = tokio::fs::symlink_metadata(source)
            .await
            .map_err(|e| SkillError::InvalidTransition(format!("source symlink_metadata: {e}")))?;
        if source_meta.file_type().is_symlink() {
            return Err(SkillError::InvalidTransition(format!(
                "source root is a symlink: {source:?}"
            )));
        }
        if !source_meta.is_dir() {
            return Err(SkillError::InvalidTransition(format!(
                "source is not a directory: {source:?}"
            )));
        }
        let source = source.to_path_buf();

        // SKILL.md is required. Size pre-check via metadata avoids loading
        // a multi-gigabyte attacker-controlled file before the cap fires
        // (closes adversarial round-1 W2 DoS).
        let skill_md_path = source.join("SKILL.md");
        let skill_md =
            match read_file_no_symlink_capped(&skill_md_path, MAX_SKILL_MD_BYTES as u64).await? {
                Some(s) => s,
                None => {
                    return Err(SkillError::InvalidTransition(format!(
                        "source missing required SKILL.md: {source:?}"
                    )))
                }
            };

        // templates/ directory (per-DIR symlink check; per-FILE size +
        // count caps via *_capped helper — closes round-1 W4 walk DoS).
        let templates = read_text_dir_no_symlink_capped(
            &source.join("templates"),
            crate::skill_bundle::MAX_TEMPLATES,
            MAX_SKILL_MD_BYTES as u64,
        )
        .await?;

        // source-scripts/ directory (same caps).
        let mut source_scripts = read_text_dir_no_symlink_capped(
            &source.join("source-scripts"),
            crate::skill_bundle::MAX_SOURCE_SCRIPTS,
            MAX_SKILL_MD_BYTES as u64,
        )
        .await?;

        // Collect top-level non-knowledge files into source_scripts. The
        // canonical Path A "first-class file set" is
        // {SKILL.md, .meta.yaml, templates/, source-scripts/}; anything
        // else (scripts like .sh / .py, also pre-existing tool.wasm and
        // tool.capabilities.json) gets moved into source_scripts as text.
        // Binary files fail UTF-8 decode here.
        let known_first_class: &[&str] = &["SKILL.md", ".meta.yaml"];
        let known_dirs: &[&str] = &["templates", "source-scripts"];

        let mut entries = tokio::fs::read_dir(&source)
            .await
            .map_err(|e| SkillError::InvalidTransition(format!("read_dir source: {e}")))?;
        while let Some(entry) = entries
            .next_entry()
            .await
            .map_err(|e| SkillError::InvalidTransition(format!("read_dir next: {e}")))?
        {
            let filename = match entry.file_name().into_string() {
                Ok(s) => s,
                Err(_) => continue,
            };
            if known_first_class.contains(&filename.as_str())
                || known_dirs.contains(&filename.as_str())
            {
                continue;
            }
            let path = entry.path();
            let meta = tokio::fs::symlink_metadata(&path)
                .await
                .map_err(|e| SkillError::InvalidTransition(format!("symlink_metadata: {e}")))?;
            if meta.file_type().is_symlink() {
                return Err(SkillError::InvalidTransition(format!(
                    "refusing symlink at {path:?}"
                )));
            }
            if !meta.is_file() {
                continue;
            }
            validate_skill_filename(&filename)?;
            // Count cap: source_scripts entries combined (from
            // <source>/source-scripts/ + top-level non-knowledge files)
            // must stay under MAX_SOURCE_SCRIPTS. Reject BEFORE
            // read_to_string — closes round-1 W3/W4 walk DoS.
            if source_scripts.len() >= crate::skill_bundle::MAX_SOURCE_SCRIPTS {
                return Err(SkillError::InvalidTransition(format!(
                    "source_scripts count exceeds {}",
                    crate::skill_bundle::MAX_SOURCE_SCRIPTS
                )));
            }
            // Per-entry size pre-check via metadata — closes round-1
            // W2 DoS surface.
            if meta.len() > MAX_SKILL_MD_BYTES as u64 {
                return Err(SkillError::ContentTooLarge(meta.len() as usize));
            }
            // Collision policy: if `<source>/source-scripts/{filename}`
            // already provided an entry with the same name, reject.
            if source_scripts.iter().any(|(f, _)| f == &filename) {
                return Err(SkillError::InvalidTransition(format!(
                    "source_scripts filename collision: {filename}"
                )));
            }
            // Read as UTF-8; binary files fail here.
            let body = tokio::fs::read_to_string(&path).await.map_err(|e| {
                if e.kind() == std::io::ErrorKind::InvalidData {
                    SkillError::InvalidTransition(format!(
                        "source-scripts entry not valid UTF-8: {filename}"
                    ))
                } else {
                    SkillError::InvalidTransition(format!("read_to_string {filename}: {e}"))
                }
            })?;
            source_scripts.push((filename, body));
        }
        source_scripts.sort_by(|a, b| a.0.cmp(&b.0));

        let bundle = SkillBundle::new(
            target_name.to_string(),
            skill_md,
            None, // Path A NEVER populates tool_wasm
            None, // Path A NEVER populates tool_capabilities
            templates,
            source_scripts,
            Provenance::Imported,
            TrustLevel::Untrusted,
        )?;
        admin.write_bundle(&bundle).await
    }

    /// Path A git-URL import. Spawns `git clone --depth 1` via
    /// `std::process::Command` wrapped in `tokio::task::spawn_blocking`
    /// (uses workspace tokio's `rt` + `time` features only; no
    /// `process` feature needed).
    ///
    /// URL scheme whitelist: `file://`, `https://` (see `check_git_url_scheme`).
    /// Rejects `http://`, `ssh://`, `git://`, `ext::`, scp-style
    /// (`user@host:`), bare paths, etc. with
    /// `InvalidTransition("unsupported URL scheme")`.
    ///
    /// Env hardened: `env_clear()` + PATH-only pass-through (HOME
    /// dropped to defeat `~/.gitconfig` `url.*.insteadOf` redirects) +
    /// `GIT_CONFIG_GLOBAL=/dev/null` + `GIT_CONFIG_SYSTEM=/dev/null` +
    /// `GIT_TERMINAL_PROMPT=0` + `-c protocol.ext.allow=never` +
    /// `-c protocol.allow=user`.
    ///
    /// Clone destination is a uniquely-timestamped subdir under
    /// `self.work_dir`; no `tempfile` production dep needed. On
    /// completion (success or error) the clone-dest is removed via
    /// `safe_remove_dir_all`-equivalent walking with symlink reject.
    pub async fn import_from_git_url(
        &self,
        url: &str,
        target_name: &str,
        admin: &AdminPoolStorage,
    ) -> Result<(), SkillError> {
        validate_skill_name(target_name)?;
        check_git_url_scheme(url)?;

        // Verify git binary present early.
        let git_check = tokio::task::spawn_blocking(|| {
            std::process::Command::new("git")
                .arg("--version")
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false)
        })
        .await
        .map_err(|e| SkillError::InvalidTransition(format!("spawn_blocking join: {e}")))?;
        if !git_check {
            return Err(SkillError::InvalidTransition(
                "git binary not found in PATH".to_string(),
            ));
        }

        // Build the clone destination under work_dir.
        let stamp = chrono::Utc::now()
            .timestamp_nanos_opt()
            .unwrap_or_else(|| chrono::Utc::now().timestamp());
        let dest = self.work_dir.join(format!("clone-{stamp}"));
        tokio::fs::create_dir_all(&dest)
            .await
            .map_err(|e| SkillError::InvalidTransition(format!("create clone dir: {e}")))?;

        let host_path = std::env::var("PATH").unwrap_or_default();
        let url_owned = url.to_string();
        let dest_owned = dest.clone();

        let clone_outcome = tokio::time::timeout(
            GIT_CLONE_TIMEOUT,
            tokio::task::spawn_blocking(move || {
                std::process::Command::new("git")
                    .env_clear()
                    .env("PATH", host_path)
                    .env("GIT_CONFIG_GLOBAL", "/dev/null")
                    .env("GIT_CONFIG_SYSTEM", "/dev/null")
                    .env("GIT_TERMINAL_PROMPT", "0")
                    .args([
                        "clone",
                        "--depth",
                        "1",
                        "-c",
                        "protocol.ext.allow=never",
                        "-c",
                        "protocol.allow=user",
                    ])
                    .arg(&url_owned)
                    .arg(&dest_owned)
                    .output()
            }),
        )
        .await;

        let cleanup = |_: &Path| async {
            // Best-effort cleanup; ignore errors.
            let _ = safe_remove(&dest).await;
        };

        let clone_result = match clone_outcome {
            Ok(Ok(Ok(output))) => {
                if output.status.success() {
                    Ok(())
                } else {
                    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
                    Err(SkillError::InvalidTransition(format!(
                        "git clone failed: {stderr}"
                    )))
                }
            }
            Ok(Ok(Err(e))) => Err(SkillError::InvalidTransition(format!(
                "git spawn failed: {e}"
            ))),
            Ok(Err(e)) => Err(SkillError::InvalidTransition(format!(
                "spawn_blocking join: {e}"
            ))),
            Err(_) => Err(SkillError::InvalidTransition(
                "git clone wall-clock timeout".to_string(),
            )),
        };

        if let Err(e) = clone_result {
            cleanup(&dest).await;
            return Err(e);
        }

        let import_result = self.import_from_local_path(&dest, target_name, admin).await;
        cleanup(&dest).await;
        import_result
    }

    /// Path A MCP-source import: synthesizes SKILL.md from a JSON
    /// `McpImportSpec` descriptor. Knowledge-only — no tool_wasm.
    ///
    /// The synthesized SKILL.md's frontmatter is built via
    /// `serde_yml::to_string` so caller-supplied `description` / `tags` are
    /// properly quoted and escaped (closes the round-2 YAML-metacharacter
    /// audit gap where plain-scalar hazards like `foo: bar` or `[x, y]` in
    /// `description` would otherwise mangle the frontmatter). `prompt_text`
    /// (which lives BELOW the frontmatter boundary) is allowed to contain
    /// anything UTF-8; the SKILL.md size cap (50_000) and the `SecurityScan`
    /// 6 checks at activate time still apply at later lifecycle points.
    ///
    /// Additional defenses:
    /// - `source_name` validated via `validate_skill_name` (rejects path
    ///   traversal / control chars / dots).
    /// - Control bytes (other than `\t`) rejected in `description` /
    ///   `prompt_text` / each `tag` — defense-in-depth even though serde_yml
    ///   would escape them.
    pub async fn import_from_mcp_source(
        &self,
        spec: &McpImportSpec,
        admin: &AdminPoolStorage,
    ) -> Result<(), SkillError> {
        validate_skill_name(&spec.source_name)?;
        // Defense-in-depth size pre-checks (round-3 adversarial fix):
        // bound caller-supplied strings BEFORE iterating chars + format!.
        // SkillBundle::new would eventually reject via ContentTooLarge,
        // but pre-checking saves O(n) iteration + O(n) allocation on a
        // multi-gigabyte attacker-controlled prompt_text.
        if spec.prompt_text.len() > crate::skill_bundle::MAX_SKILL_MD_BYTES {
            return Err(SkillError::ContentTooLarge(spec.prompt_text.len()));
        }
        if spec.description.len() > 4096 {
            return Err(SkillError::ContentTooLarge(spec.description.len()));
        }
        if spec.tags.len() > 64 {
            return Err(SkillError::InvalidTransition(format!(
                "McpImportSpec.tags count {} exceeds 64",
                spec.tags.len()
            )));
        }
        for tag in &spec.tags {
            if tag.len() > 128 {
                return Err(SkillError::ContentTooLarge(tag.len()));
            }
        }
        check_no_control_chars(&spec.description, "description")?;
        check_no_control_chars(&spec.prompt_text, "prompt_text")?;
        for (i, tag) in spec.tags.iter().enumerate() {
            check_no_control_chars(tag, &format!("tags[{i}]"))?;
        }

        // Build the frontmatter via serde_yml so values are properly
        // quoted/escaped (closes plain-scalar YAML-metacharacter hazards).
        #[derive(serde::Serialize)]
        struct Frontmatter<'a> {
            name: &'a str,
            description: &'a str,
            #[serde(skip_serializing_if = "<[String]>::is_empty")]
            tags: &'a [String],
        }
        let fm = Frontmatter {
            name: &spec.source_name,
            description: &spec.description,
            tags: &spec.tags,
        };
        let frontmatter_yaml = serde_yml::to_string(&fm)
            .map_err(|e| SkillError::InvalidTransition(format!("frontmatter yaml: {e}")))?;
        // Defense-in-depth: assert that serde_yml didn't emit a stray
        // `\n---\n` inside our frontmatter (it shouldn't for safe values,
        // but we surface the case loudly rather than silently mangling).
        if frontmatter_yaml.contains("\n---") {
            return Err(SkillError::InvalidTransition(
                "synthesized frontmatter contains '---' separator".to_string(),
            ));
        }

        let skill_md = format!("---\n{frontmatter_yaml}---\n\n{}\n", spec.prompt_text);

        let bundle = SkillBundle::new(
            spec.source_name.clone(),
            skill_md,
            None,
            None,
            Vec::new(),
            Vec::new(),
            Provenance::Imported,
            TrustLevel::Untrusted,
        )?;
        admin.write_bundle(&bundle).await
    }
}

/// Reject control bytes (other than `\t`) in caller-supplied input.
/// Defense-in-depth — `serde_yml` would escape these properly inside a
/// double-quoted YAML string, but rejecting at the input boundary surfaces
/// operator typos / malicious input loudly.
fn check_no_control_chars(value: &str, field: &str) -> Result<(), SkillError> {
    for c in value.chars() {
        if c.is_control() && c != '\t' && c != '\n' && c != '\r' {
            return Err(SkillError::InvalidTransition(format!(
                "McpImportSpec.{field} contains control character — refusing"
            )));
        }
    }
    Ok(())
}

/// URL scheme whitelist for `import_from_git_url`. Accepts ONLY
/// `file://` and `https://`. Rejects `http://` (on-path spoofing surface
/// per adversarial round-1; transport must be authenticated or local),
/// `ssh://`, `git://`, `ext::`, scp-style (`user@host:`), bare paths,
/// etc.
fn check_git_url_scheme(url: &str) -> Result<(), SkillError> {
    const ALLOWED: &[&str] = &["file://", "https://"];
    let lower = url.to_ascii_lowercase();
    if ALLOWED.iter().any(|p| lower.starts_with(p)) {
        return Ok(());
    }
    Err(SkillError::InvalidTransition(format!(
        "unsupported URL scheme: {url}"
    )))
}

/// Read a file as UTF-8 text after a size pre-check via `symlink_metadata`.
/// Returns `Ok(None)` if the path is absent or not a regular file. Errors
/// on symlink, oversize (> `cap`), or UTF-8 decode failure. The size
/// pre-check closes the round-1 adversarial DoS surface where
/// `tokio::fs::read_to_string` would otherwise load a multi-gigabyte
/// attacker-controlled file into memory before any cap fired.
async fn read_file_no_symlink_capped(path: &Path, cap: u64) -> Result<Option<String>, SkillError> {
    let meta = match tokio::fs::symlink_metadata(path).await {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => {
            return Err(SkillError::InvalidTransition(format!(
                "symlink_metadata: {e}"
            )))
        }
    };
    if meta.file_type().is_symlink() {
        return Err(SkillError::InvalidTransition(format!(
            "refusing symlink at {path:?}"
        )));
    }
    if !meta.is_file() {
        return Ok(None);
    }
    if meta.len() > cap {
        return Err(SkillError::ContentTooLarge(meta.len() as usize));
    }
    tokio::fs::read_to_string(path)
        .await
        .map(Some)
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::InvalidData {
                SkillError::InvalidTransition(format!("source file not valid UTF-8: {path:?}"))
            } else {
                SkillError::InvalidTransition(format!("read_to_string: {e}"))
            }
        })
}

/// Legacy non-capped variant retained for unconditional callers; gated by
/// a generous `u64::MAX` cap that disables size enforcement. Existing
/// callers should migrate to `read_file_no_symlink_capped` with an
/// explicit size cap (see `MAX_SKILL_MD_BYTES` etc.).
#[allow(dead_code)] // migration complete — zero callers remain; delete in a cleanup slice
async fn read_file_no_symlink(path: &Path) -> Result<Option<String>, SkillError> {
    read_file_no_symlink_capped(path, u64::MAX).await
}

/// Walk a directory, reading text entries up to a count + per-entry size
/// cap. Each leaf is symlink_metadata-checked and then size-prechecked
/// BEFORE the `read_to_string` call — closes the round-1 adversarial DoS
/// surface where unbounded walks loaded gigabytes before SkillBundle::new
/// rejected.
async fn read_text_dir_no_symlink_capped(
    dir: &Path,
    max_entries: usize,
    max_bytes_per_entry: u64,
) -> Result<Vec<(String, String)>, SkillError> {
    match tokio::fs::symlink_metadata(dir).await {
        Ok(meta) => {
            if meta.file_type().is_symlink() {
                return Err(SkillError::InvalidTransition(format!(
                    "refusing symlinked dir at {dir:?}"
                )));
            }
            if !meta.is_dir() {
                return Ok(Vec::new());
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => {
            return Err(SkillError::InvalidTransition(format!(
                "symlink_metadata: {e}"
            )))
        }
    }
    let mut entries = tokio::fs::read_dir(dir)
        .await
        .map_err(|e| SkillError::InvalidTransition(format!("read_dir: {e}")))?;
    let mut out = Vec::new();
    while let Some(entry) = entries
        .next_entry()
        .await
        .map_err(|e| SkillError::InvalidTransition(format!("read_dir next: {e}")))?
    {
        let filename = match entry.file_name().into_string() {
            Ok(s) => s,
            Err(_) => continue,
        };
        let path = entry.path();
        let meta = tokio::fs::symlink_metadata(&path)
            .await
            .map_err(|e| SkillError::InvalidTransition(format!("symlink_metadata: {e}")))?;
        if meta.file_type().is_symlink() {
            return Err(SkillError::InvalidTransition(format!(
                "refusing symlinked entry at {path:?}"
            )));
        }
        if !meta.is_file() {
            continue;
        }
        // Pre-allocation count cap — rejects unbounded entry counts
        // BEFORE allocating bodies (closes round-1 W4 walk DoS).
        if out.len() >= max_entries {
            return Err(SkillError::InvalidTransition(format!(
                "directory entry count exceeds {max_entries}: {dir:?}"
            )));
        }
        validate_skill_filename(&filename)?;
        // Per-entry size pre-check — rejects oversized entries BEFORE
        // read_to_string loads them into memory.
        if meta.len() > max_bytes_per_entry {
            return Err(SkillError::ContentTooLarge(meta.len() as usize));
        }
        let body = tokio::fs::read_to_string(&path).await.map_err(|e| {
            if e.kind() == std::io::ErrorKind::InvalidData {
                SkillError::InvalidTransition(format!(
                    "template/script entry not valid UTF-8: {filename}"
                ))
            } else {
                SkillError::InvalidTransition(format!("read_to_string {filename}: {e}"))
            }
        })?;
        out.push((filename, body));
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(out)
}

/// Legacy uncapped wrapper retained for callers that don't pass size
/// limits. New callers should always use `read_text_dir_no_symlink_capped`.
#[allow(dead_code)] // migration complete — zero callers remain; delete in a cleanup slice
async fn read_text_dir_no_symlink(dir: &Path) -> Result<Vec<(String, String)>, SkillError> {
    read_text_dir_no_symlink_capped(dir, usize::MAX, u64::MAX).await
}

/// Local helper to remove a directory tree leaf-up, refusing symlinks.
/// Reuses the admin_pool pattern but lives here so import.rs is
/// self-contained.
fn safe_remove(
    path: &Path,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), SkillError>> + Send + '_>> {
    Box::pin(async move {
        let meta = match tokio::fs::symlink_metadata(path).await {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => {
                return Err(SkillError::InvalidTransition(format!(
                    "symlink_metadata: {e}"
                )))
            }
        };
        if meta.file_type().is_symlink() {
            // Don't follow; just remove the link itself if possible.
            let _ = tokio::fs::remove_file(path).await;
            return Ok(());
        }
        if meta.is_dir() {
            let mut entries = tokio::fs::read_dir(path)
                .await
                .map_err(|e| SkillError::InvalidTransition(format!("read_dir: {e}")))?;
            while let Some(entry) = entries
                .next_entry()
                .await
                .map_err(|e| SkillError::InvalidTransition(format!("read_dir next: {e}")))?
            {
                safe_remove(&entry.path()).await?;
            }
            tokio::fs::remove_dir(path)
                .await
                .map_err(|e| SkillError::InvalidTransition(format!("remove_dir: {e}")))?;
        } else {
            tokio::fs::remove_file(path)
                .await
                .map_err(|e| SkillError::InvalidTransition(format!("remove_file: {e}")))?;
        }
        Ok(())
    })
}
