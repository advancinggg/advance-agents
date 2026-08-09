//! `advance skill import` / `advance skill materialize` — Slice I (m017-slice-i).
//!
//! Admin/operator surface (MODULE-017 §1.3.6, §2.7, §3.2) wired to the Slice-E
//! `cap_skills` Path-A importer + admin-pool + materialize library API:
//!   - `import` writes a skill bundle into the admin pool `<pool>/{name}/`.
//!   - `materialize` projects a pool bundle into `<agent-root>/.agent/skills/{name}/`.
//!
//! This module registers NO host function — it is invoked from a shell by an
//! operator, never callable by an agent (see the §2.7 AC-28 route-absence audit
//! memo). Async library calls run on a current-thread Tokio runtime, mirroring
//! `start.rs`.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use cap_skills::persistence::DiskSkillStorage;
use cap_skills::{materialize_skill, AdminPoolStorage, McpImportSpec, SkillImporter};

/// Render a `Path` for safe stderr/stdout emission. A path sourced from CLI
/// args / `$ADVANCE_WORKSPACE` may carry ANSI escapes, control bytes, or
/// newlines; `Path::display()` does NOT escape these, whereas `{:?}` routes
/// through Debug → `escape_debug` and DOES. Mirrors `start.rs::safe_path`.
fn safe_path(p: &Path) -> String {
    format!("{p:?}")
}

/// Neutralize terminal-control / ANSI / newline bytes in a message destined for
/// stderr/stdout (adversarial R1 W2/W3 fix). `safe_path` only guards `Path`
/// args; error Display strings (`SkillError`) and the raw `<source>` arg can
/// carry caller- or remote-git-controlled control bytes (e.g. a malicious
/// `https://` server's clone stderr, or a crafted `--name`/URL echoed back in
/// the rejection message). Escapes ASCII/Unicode control chars (incl. ESC
/// 0x1b and newlines) via `escape_default`; leaves printable chars + tab
/// readable.
fn safe_msg(s: &str) -> String {
    s.chars()
        .flat_map(|c| {
            if c.is_control() && c != '\t' {
                c.escape_default().collect::<Vec<char>>()
            } else {
                vec![c]
            }
        })
        .collect()
}

/// Resolve the admin pool root: explicit `--pool` → `$ADVANCE_WORKSPACE/.advance/skills`
/// → `./.advance/skills`.
fn resolve_pool(pool: Option<PathBuf>) -> PathBuf {
    if let Some(p) = pool {
        return p;
    }
    if let Some(ws) = std::env::var_os("ADVANCE_WORKSPACE") {
        return PathBuf::from(ws).join(".advance").join("skills");
    }
    PathBuf::from(".advance").join("skills")
}

/// Derive a default skill name from a source string: the last path/URL segment
/// with a trailing `.git` stripped (`https://h/foo/bar.git` → `bar`,
/// `/tmp/my-skill/` → `my-skill`). Returns `None` if nothing usable remains —
/// the caller then asks for an explicit `--name`. The library re-validates the
/// name via `validate_skill_name`, so this need not enforce the grammar.
fn derive_name(source: &str) -> Option<String> {
    let trimmed = source.trim_end_matches('/');
    let seg = trimmed.rsplit(['/', ':']).next().unwrap_or("");
    let seg = seg.strip_suffix(".git").unwrap_or(seg);
    if seg.is_empty() {
        None
    } else {
        Some(seg.to_string())
    }
}

/// Sync entry point for `advance skill import`. Validates argument shape, then
/// drives the async import on a current-thread Tokio runtime.
pub fn run_import(
    source: Option<String>,
    mcp_descriptor: Option<PathBuf>,
    name: Option<String>,
    pool: Option<PathBuf>,
    trust: Option<String>,
) -> ExitCode {
    // `--trust` accepts only `untrusted`: Path A always produces
    // Imported/Untrusted bundles (admin Path B handles trusted bundles via a
    // direct AdminPoolStorage::write_bundle, not this CLI). Reject any other
    // value rather than silently ignore it.
    if let Some(t) = trust.as_deref() {
        if t != "untrusted" {
            eprintln!(
                "advance skill import: --trust only accepts 'untrusted' \
                 (Path A imports are always Untrusted; admin Path B handles trusted bundles)"
            );
            return ExitCode::from(2);
        }
    }

    // `<source>` and `--mcp-descriptor` are mutually exclusive; exactly one is required.
    match (source.is_some(), mcp_descriptor.is_some()) {
        (true, true) => {
            eprintln!(
                "advance skill import: provide either <source> or --mcp-descriptor, not both"
            );
            return ExitCode::from(2);
        }
        (false, false) => {
            eprintln!(
                "advance skill import: missing <source> (git URL or local directory) \
                 or --mcp-descriptor <spec.json>"
            );
            return ExitCode::from(2);
        }
        _ => {}
    }

    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!(
                "advance skill import: failed to build tokio runtime: {}",
                safe_msg(&e.to_string())
            );
            return ExitCode::from(1);
        }
    };
    rt.block_on(run_import_async(source, mcp_descriptor, name, pool))
}

async fn run_import_async(
    source: Option<String>,
    mcp_descriptor: Option<PathBuf>,
    name: Option<String>,
    pool: Option<PathBuf>,
) -> ExitCode {
    let admin = AdminPoolStorage::with_default_writer(resolve_pool(pool));
    // `work_dir` is the parent under which `import_from_git_url` creates its own
    // uniquely-timestamped clone subdir (and cleans it up). Only the git path
    // uses it; local-path and MCP imports ignore it.
    let importer = SkillImporter::new(std::env::temp_dir());

    let outcome: Result<String, cap_skills::SkillError> = if let Some(desc_path) = mcp_descriptor {
        // --mcp-descriptor: read an McpImportSpec JSON file → synthesize a
        // knowledge-only SKILL.md (no cap-mcp involvement).
        //
        // DoS + symlink hardening (adversarial R1 W1): stat FIRST — reject a
        // symlink (defeats a `/dev/zero`/attacker-target symlink), reject a
        // non-regular file (defeats a blocking FIFO), and cap the size BEFORE
        // loading the whole file. The library bounds the parsed FIELDS, but
        // only after the String + serde allocations; this is the one import
        // read that would otherwise be uncapped. 256 KiB is generous vs the
        // field caps (SKILL.md ≤ 50 KiB + description ≤ 4 KiB + 64 tags × 128 B
        // + JSON syntax).
        const MAX_MCP_DESCRIPTOR_BYTES: u64 = 256 * 1024;
        match tokio::fs::symlink_metadata(&desc_path).await {
            Ok(meta) if meta.file_type().is_symlink() => {
                eprintln!(
                    "advance skill import: --mcp-descriptor {} is a symlink (refused)",
                    safe_path(&desc_path)
                );
                return ExitCode::from(1);
            }
            Ok(meta) if !meta.is_file() => {
                eprintln!(
                    "advance skill import: --mcp-descriptor {} is not a regular file",
                    safe_path(&desc_path)
                );
                return ExitCode::from(1);
            }
            Ok(meta) if meta.len() > MAX_MCP_DESCRIPTOR_BYTES => {
                eprintln!(
                    "advance skill import: --mcp-descriptor {} is {} bytes (max {MAX_MCP_DESCRIPTOR_BYTES})",
                    safe_path(&desc_path),
                    meta.len()
                );
                return ExitCode::from(1);
            }
            Ok(_) => {}
            Err(e) => {
                eprintln!(
                    "advance skill import: cannot stat --mcp-descriptor {}: {}",
                    safe_path(&desc_path),
                    safe_msg(&e.to_string())
                );
                return ExitCode::from(1);
            }
        }
        let text = match tokio::fs::read_to_string(&desc_path).await {
            Ok(t) => t,
            Err(e) => {
                eprintln!(
                    "advance skill import: cannot read --mcp-descriptor {}: {}",
                    safe_path(&desc_path),
                    safe_msg(&e.to_string())
                );
                return ExitCode::from(1);
            }
        };
        let mut spec: McpImportSpec = match serde_json::from_str(&text) {
            Ok(s) => s,
            Err(e) => {
                eprintln!(
                    "advance skill import: invalid --mcp-descriptor JSON {}: {}",
                    safe_path(&desc_path),
                    safe_msg(&e.to_string())
                );
                return ExitCode::from(1);
            }
        };
        if let Some(n) = name {
            spec.source_name = n;
        }
        importer
            .import_from_mcp_source(&spec, &admin)
            .await
            .map(|()| spec.source_name.clone())
    } else {
        let source = source.expect("source presence validated in run_import");
        let target = match name.or_else(|| derive_name(&source)) {
            Some(n) => n,
            None => {
                eprintln!(
                    "advance skill import: could not derive a skill name from '{}'; \
                     pass --name <name>",
                    safe_msg(&source)
                );
                return ExitCode::from(2);
            }
        };
        // Local-vs-git detection by filesystem existence. `symlink_metadata`
        // does NOT follow symlinks, so only a REAL existing directory routes to
        // the local-path importer; a symlink-to-dir, a file, or a non-existent
        // path routes to the git importer, which validates the URL scheme
        // (file:// + https:// only). This avoids mis-routing a POSIX local path
        // that happens to contain "://".
        let is_local_dir = matches!(
            tokio::fs::symlink_metadata(&source).await,
            Ok(meta) if meta.file_type().is_dir()
        );
        if is_local_dir {
            importer
                .import_from_local_path(Path::new(&source), &target, &admin)
                .await
                .map(|()| target.clone())
        } else {
            importer
                .import_from_git_url(&source, &target, &admin)
                .await
                .map(|()| target.clone())
        }
    };

    match outcome {
        Ok(skill_name) => {
            println!(
                "Imported skill '{skill_name}' into admin pool {}",
                safe_path(&admin.root().join(&skill_name))
            );
            ExitCode::SUCCESS
        }
        Err(e) => {
            // safe_msg: SkillError Display embeds raw --name / URL / remote git
            // clone stderr (adversarial R1 W3) — escape control bytes.
            eprintln!("advance skill import: {}", safe_msg(&e.to_string()));
            ExitCode::from(1)
        }
    }
}

/// Sync entry point for `advance skill materialize`.
pub fn run_materialize(name: String, to: PathBuf, pool: Option<PathBuf>) -> ExitCode {
    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!(
                "advance skill materialize: failed to build tokio runtime: {}",
                safe_msg(&e.to_string())
            );
            return ExitCode::from(1);
        }
    };
    rt.block_on(run_materialize_async(name, to, pool))
}

async fn run_materialize_async(name: String, to: PathBuf, pool: Option<PathBuf>) -> ExitCode {
    let admin = AdminPoolStorage::with_default_writer(resolve_pool(pool));
    let storage = DiskSkillStorage::with_default_writer(to.clone());
    match materialize_skill(&name, &admin, &storage).await {
        Ok(()) => {
            println!(
                "Materialized skill '{name}' into {}",
                safe_path(&to.join(".agent").join("skills").join(&name))
            );
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("advance skill materialize: {}", safe_msg(&e.to_string()));
            ExitCode::from(1)
        }
    }
}
