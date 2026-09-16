//! `advance pack install | list | uninstall` — PACK-GAP-CLOSURE P1 (§2.7).
//!
//! Admin/operator surface (MODULE-018 §1.3.2) over the production
//! `advance_pack_manager::Installer` — the same 8-step orchestrator the
//! SYS-J-29 witnesses drive and the daemon's boot-time registry
//! (`pack_wiring.rs`) reads. Registers NO host function (never agent-callable).
//! Async library calls run on a current-thread Tokio runtime, mirroring
//! `skill.rs`.
//!
//! - `<source>`: local directory / `git+<url>[@<ref>]` / `<path>.tar.gz` /
//!   `registry:<name>@<version>` (the `parse_source` grammar). A registry
//!   source needs a `RegistryClient`, which is lane P3 (#3) — until then it is
//!   surfaced as an install error, never silently skipped.
//! - packs dir: `--packs-dir` → `pack.packs-dir` of the workspace
//!   `runtime-config.yaml` (when present) joined onto the workspace root →
//!   `<ws>/.advance/packs`, where `<ws>` = `$ADVANCE_WORKSPACE` → `.`. A
//!   present-but-invalid runtime config is a hard error (fail-closed, matching
//!   `advance start`); an absent one means defaults.
//! - approval: `InteractiveApproval` on stdin/stdout by default; `--no-input`
//!   (or `pack.approval: auto-reject`) → `RejectUnlessTrivial`. Both approve a
//!   pack with an empty `required-capabilities` without any decision (AC-07);
//!   a pack that would need one is prompted for / rejected. The strategy is
//!   wrapped in `CatalogCheckedApproval` over `agent_config::KNOWN_CAPABILITIES`
//!   ∪ the ids of every installed pack's resource-capabilities, so an unknown
//!   requirement is refused BEFORE any prompt.
//! - output: `installed {name}@{version} -> {path}` / one `name@version\ttrust\t
//!   installed_at` line per pack / `uninstalled {name}@{version}`; failures go
//!   to stderr with the error's Display and exit 1 (usage errors exit 2). Every
//!   byte of pack-controlled text passes through `safe_msg` / `safe_path`.

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use advance_pack_manager::meta::read_meta_index;
use advance_pack_manager::{
    resource_capability_id, ApprovalStrategy, AutoReject, CatalogCheckedApproval, ComponentKind,
    InMemoryPackRegistry, Installer, InteractiveApproval, PackError, PackRegistry,
    RejectUnlessTrivial, StaticCapabilityCatalog,
};
use advance_runtime::config::{load_config, PackApprovalPolicy, PackConfig};

use super::skill::{safe_msg, safe_path};
use crate::agent_config::KNOWN_CAPABILITIES;

/// Runtime version the installer checks `runtime-version:` ranges against.
const CURRENT_RUNTIME_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Resolved per-invocation settings (see module docs for the precedence).
struct PackCliSettings {
    packs_dir: PathBuf,
    fetch_timeout: Duration,
    auto_reject: bool,
}

/// `$ADVANCE_WORKSPACE` (non-empty) → `.` — mirrors `start.rs::resolve_workspace`
/// minus the explicit flag (this family takes `--packs-dir` instead).
fn workspace_root() -> PathBuf {
    match std::env::var_os("ADVANCE_WORKSPACE") {
        Some(ws) if !ws.is_empty() => PathBuf::from(ws),
        _ => PathBuf::from("."),
    }
}

fn resolve_settings(packs_dir: Option<PathBuf>) -> Result<PackCliSettings, String> {
    let ws = workspace_root();
    let cfg_path = ws.join(".advance").join("runtime-config.yaml");
    // Present ⇒ it MUST load (a broken config is never silently ignored); absent
    // ⇒ `PackConfig::default()`. `load_config` is a pure parse+validate.
    let pack_cfg: PackConfig = if std::fs::symlink_metadata(&cfg_path).is_ok() {
        load_config(&cfg_path)
            .map_err(|e| format!("cannot load {}: {e}", safe_path(&cfg_path)))?
            .pack
    } else {
        PackConfig::default()
    };
    Ok(PackCliSettings {
        packs_dir: packs_dir.unwrap_or_else(|| ws.join(&pack_cfg.packs_dir)),
        fetch_timeout: Duration::from_secs(pack_cfg.fetch_timeout_sec),
        auto_reject: pack_cfg.approval == PackApprovalPolicy::AutoReject,
    })
}

/// A rescanned registry over `packs_dir` (disk truth BEFORE any decision: the
/// installer's step-⑤ dependency dedup, the capability catalog and `list` all
/// read the in-memory registry).
async fn rescanned_registry(
    verb: &str,
    packs_dir: &Path,
) -> Result<Arc<InMemoryPackRegistry>, ExitCode> {
    let registry = Arc::new(InMemoryPackRegistry::new(packs_dir.to_path_buf()));
    if let Err(e) = registry.rescan().await {
        eprintln!(
            "advance pack {verb}: cannot read installed packs at {}: {}",
            safe_path(packs_dir),
            safe_msg(&e.to_string())
        );
        return Err(ExitCode::from(1));
    }
    Ok(registry)
}

/// `KNOWN_CAPABILITIES` ∪ every installed pack's resource-capability ids (read
/// through the registry's validated `resolve` + the bounded manifest parser).
fn build_capability_catalog(
    registry: &InMemoryPackRegistry,
) -> Result<StaticCapabilityCatalog, PackError> {
    let mut names: Vec<String> = KNOWN_CAPABILITIES.iter().map(|s| s.to_string()).collect();
    for pack in registry.list_installed() {
        let Some(provides) = registry.provides(&pack.name, &pack.version) else {
            continue;
        };
        for entry in provides
            .iter()
            .filter(|p| p.kind == ComponentKind::ResourceCapability)
        {
            let resolution = registry.resolve(&format!(
                "{}@{}/resource-capabilities/{}",
                pack.name, pack.version, entry.name
            ))?;
            names.push(resource_capability_id(&resolution.local_path)?);
        }
    }
    Ok(StaticCapabilityCatalog::new(names))
}

/// Operator-facing rendering of a `PackError` (plan §2.7: `PackNotFound` reads
/// "not installed"; everything else is the error's Display).
fn render_error(e: &PackError) -> String {
    match e {
        PackError::PackNotFound(name, version) => format!("{name}@{version} is not installed"),
        other => other.to_string(),
    }
}

fn build_runtime(verb: &str) -> Result<tokio::runtime::Runtime, ExitCode> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| {
            eprintln!(
                "advance pack {verb}: failed to build tokio runtime: {}",
                safe_msg(&e.to_string())
            );
            ExitCode::from(1)
        })
}

/// Sync entry point for `advance pack install`.
pub fn run_install(source: String, packs_dir: Option<PathBuf>, no_input: bool) -> ExitCode {
    let rt = match build_runtime("install") {
        Ok(rt) => rt,
        Err(code) => return code,
    };
    rt.block_on(run_install_async(source, packs_dir, no_input))
}

async fn run_install_async(source: String, packs_dir: Option<PathBuf>, no_input: bool) -> ExitCode {
    let settings = match resolve_settings(packs_dir) {
        Ok(s) => s,
        Err(msg) => {
            eprintln!("advance pack install: {}", safe_msg(&msg));
            return ExitCode::from(1);
        }
    };
    let registry = match rescanned_registry("install", &settings.packs_dir).await {
        Ok(r) => r,
        Err(code) => return code,
    };
    let catalog = match build_capability_catalog(&registry) {
        Ok(c) => c,
        Err(e) => {
            eprintln!(
                "advance pack install: cannot build the capability catalog: {}",
                safe_msg(&e.to_string())
            );
            return ExitCode::from(1);
        }
    };
    // `--no-input` / `pack.approval: auto-reject` ⇒ a pack that needs an admin
    // decision is refused; otherwise the operator answers on stdin. Both approve
    // a pack with an empty `required-capabilities` without any decision (AC-07).
    let inner: Arc<dyn ApprovalStrategy> = if no_input || settings.auto_reject {
        Arc::new(RejectUnlessTrivial)
    } else {
        Arc::new(InteractiveApproval::new_stdin())
    };
    let approval = Arc::new(CatalogCheckedApproval::new(inner, Arc::new(catalog)));
    let installer = Installer::new(
        settings.packs_dir.clone(),
        registry,
        CURRENT_RUNTIME_VERSION,
        approval,
    )
    .with_fetch_timeout(settings.fetch_timeout);

    match installer.install(&source).await {
        Ok(report) => {
            println!(
                "installed {}@{} -> {}",
                safe_msg(&report.name),
                safe_msg(&report.version),
                safe_path(&report.install_path)
            );
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("advance pack install: {}", safe_msg(&render_error(&e)));
            ExitCode::from(1)
        }
    }
}

/// Sync entry point for `advance pack list`.
pub fn run_list(packs_dir: Option<PathBuf>) -> ExitCode {
    let rt = match build_runtime("list") {
        Ok(rt) => rt,
        Err(code) => return code,
    };
    rt.block_on(run_list_async(packs_dir))
}

async fn run_list_async(packs_dir: Option<PathBuf>) -> ExitCode {
    let settings = match resolve_settings(packs_dir) {
        Ok(s) => s,
        Err(msg) => {
            eprintln!("advance pack list: {}", safe_msg(&msg));
            return ExitCode::from(1);
        }
    };
    let registry = match rescanned_registry("list", &settings.packs_dir).await {
        Ok(r) => r,
        Err(code) => return code,
    };
    // `installed_at` lives only in the `.meta.yaml` index (the registry keeps the
    // pack.yaml-authoritative fields); the rescan above already validated it.
    let index = match read_meta_index(&settings.packs_dir) {
        Ok(idx) => idx,
        Err(e) => {
            eprintln!(
                "advance pack list: cannot read {}: {}",
                safe_path(&settings.packs_dir.join(".meta.yaml")),
                safe_msg(&e.to_string())
            );
            return ExitCode::from(1);
        }
    };
    for pack in registry.list_installed() {
        let key = format!("{}@{}", pack.name, pack.version);
        let installed_at = index
            .packs
            .get(&key)
            .map(|e| e.installed_at.as_str())
            .unwrap_or("-");
        let trust = format!("{:?}", pack.trust_level).to_lowercase();
        println!("{}\t{trust}\t{}", safe_msg(&key), safe_msg(installed_at));
    }
    ExitCode::SUCCESS
}

/// Sync entry point for `advance pack uninstall`. `spec` is `<name>@<version>`.
pub fn run_uninstall(spec: String, packs_dir: Option<PathBuf>) -> ExitCode {
    let (name, version) = match spec.split_once('@') {
        Some((n, v)) if !n.is_empty() && !v.is_empty() && !v.contains('@') => {
            (n.to_string(), v.to_string())
        }
        _ => {
            eprintln!(
                "advance pack uninstall: expected <name>@<version>, got '{}'",
                safe_msg(&spec)
            );
            return ExitCode::from(2);
        }
    };
    let rt = match build_runtime("uninstall") {
        Ok(rt) => rt,
        Err(code) => return code,
    };
    rt.block_on(run_uninstall_async(name, version, packs_dir))
}

async fn run_uninstall_async(
    name: String,
    version: String,
    packs_dir: Option<PathBuf>,
) -> ExitCode {
    let settings = match resolve_settings(packs_dir) {
        Ok(s) => s,
        Err(msg) => {
            eprintln!("advance pack uninstall: {}", safe_msg(&msg));
            return ExitCode::from(1);
        }
    };
    // `uninstall` rescans under the install lock itself; no approval is involved
    // (AutoReject is inert here).
    let registry = Arc::new(InMemoryPackRegistry::new(settings.packs_dir.clone()));
    let installer = Installer::new(
        settings.packs_dir.clone(),
        registry,
        CURRENT_RUNTIME_VERSION,
        Arc::new(AutoReject),
    );
    match installer.uninstall(&name, &version).await {
        Ok(report) => {
            println!(
                "uninstalled {}@{} ({})",
                safe_msg(&report.name),
                safe_msg(&report.version),
                safe_path(&report.removed_path)
            );
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("advance pack uninstall: {}", safe_msg(&render_error(&e)));
            ExitCode::from(1)
        }
    }
}
