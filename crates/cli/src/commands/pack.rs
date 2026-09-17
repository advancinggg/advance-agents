//! `advance pack install | list | uninstall` — Pack lane P1.
//!
//! Admin/operator surface (MODULE-018 §1.3.2) over the production
//! `advance_pack_manager::Installer` — the same 8-step orchestrator the
//! SYS-J-29 witnesses drive and the daemon's boot-time registry
//! (`pack_wiring.rs`) reads. Registers NO host function (never agent-callable).
//! Async library calls run on a current-thread Tokio runtime, mirroring
//! `skill.rs`.
//!
//! - `<source>`: local directory / `git+<url>[@<ref>]` / `<path>.tar.gz` /
//!   `registry:<name>@<version>` (the `parse_source` grammar; P3 §4.2 accepts
//!   `@<40-hex>` commit pins and slash refs). A registry source is served by
//!   the `HttpsRegistryClient` built from `pack.registry-url` (P3 §4.4); with no
//!   URL configured it is surfaced as an install error, never silently skipped.
//! - packs dir: `--packs-dir` → `pack.packs-dir` of the workspace
//!   `runtime-config.yaml` (when present) joined onto the workspace root →
//!   `<ws>/.advance/packs`, where `<ws>` = `$ADVANCE_WORKSPACE` → `.`. A
//!   present-but-invalid runtime config is a hard error (fail-closed, matching
//!   `advance start`); an absent one means defaults. `pack.trust-roots` become
//!   the installer's signing roots (P3 §4.1): an unsigned `trusted` claim is
//!   downgraded and shown as such in the approval prompt.
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
    InMemoryPackRegistry, Installer, InteractiveApproval, PackError, PackManifest, PackRegistry,
    RejectUnlessTrivial, StaticCapabilityCatalog,
};
use advance_runtime::config::{load_config, PackApprovalPolicy, PackConfig};

use super::skill::{safe_msg, safe_path};
use crate::agent_config::KNOWN_CAPABILITIES;
use crate::pack_registry_client::HttpsRegistryClient;

/// Runtime version the installer checks `runtime-version:` ranges against.
const CURRENT_RUNTIME_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Resolved per-invocation settings (see module docs for the precedence).
struct PackCliSettings {
    packs_dir: PathBuf,
    fetch_timeout: Duration,
    auto_reject: bool,
    /// P3 §4.1 — `pack.trust-roots` (hex ed25519 public keys).
    trust_roots: Vec<String>,
    /// P3 §4.4 — `pack.registry-url`; `None` ⇒ no `RegistryClient` is wired.
    registry_url: Option<String>,
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
        trust_roots: pack_cfg.trust_roots,
        registry_url: pack_cfg.registry_url,
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
pub(crate) fn build_capability_catalog(
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
    let mut installer = Installer::new(
        settings.packs_dir.clone(),
        registry,
        CURRENT_RUNTIME_VERSION,
        approval,
    )
    .with_fetch_timeout(settings.fetch_timeout)
    .with_trust_roots(settings.trust_roots);
    // P3 §4.4: the production registry client, only when the operator
    // configured `pack.registry-url` (the config loader already shape-checked
    // it; the client re-applies the https / loopback-http policy).
    if let Some(url) = &settings.registry_url {
        match HttpsRegistryClient::new(url, settings.fetch_timeout) {
            Ok(client) => installer = installer.with_registry_client(Arc::new(client)),
            Err(e) => {
                eprintln!(
                    "advance pack install: cannot build the registry client: {}",
                    safe_msg(&e.to_string())
                );
                return ExitCode::from(1);
            }
        }
    }

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

// ── `advance pack build` (entity-data lane E2, plan §3.4) ───────────────────────────────────

/// Source pack directories stay text-only; `packs/<name>.build.yaml` beside the pack names
/// the guest crates whose `tool.wasm` a build produces.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackBuildManifest {
    #[serde(default)]
    pub tools: Vec<PackBuildTool>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackBuildTool {
    /// The skill (`skills/<skill>/`) that receives `tool.wasm`.
    pub skill: String,
    /// The guest crate, relative to the repository root (the manifest's grandparent).
    #[serde(rename = "crate")]
    pub crate_dir: PathBuf,
    /// Cargo target; `wasm32-unknown-unknown` (core module, encoded here) by default,
    /// `wasm32-wasip2` (already a component) also accepted.
    #[serde(default = "default_target")]
    pub target: String,
}

fn default_target() -> String {
    "wasm32-unknown-unknown".to_string()
}

#[derive(Debug)]
pub enum PackBuildError {
    Manifest(String),
    Io(String),
    Cargo(String),
    Encode(String),
    Checksum(String),
    /// A pack-manager failure while signing / bundling.
    Pack(String),
}

impl std::fmt::Display for PackBuildError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Manifest(m) => write!(f, "build manifest: {m}"),
            Self::Io(m) => write!(f, "io: {m}"),
            Self::Cargo(m) => write!(f, "cargo: {m}"),
            Self::Encode(m) => write!(f, "component encode: {m}"),
            Self::Checksum(m) => write!(f, "checksums: {m}"),
            Self::Pack(m) => write!(f, "pack: {m}"),
        }
    }
}

impl std::error::Error for PackBuildError {}

/// What a build produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuiltPack {
    /// `<out>/<pack name>` — installable with `advance pack install`.
    pub dir: PathBuf,
    /// Every `tool.wasm` written, in manifest order.
    pub tools: Vec<PathBuf>,
}

const PACK_LAYOUT_DIRS: &[&str] = &[
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

impl PackBuildManifest {
    pub fn load(path: &Path) -> Result<Self, PackBuildError> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| PackBuildError::Manifest(format!("{}: {e}", path.display())))?;
        let m: PackBuildManifest = serde_yml::from_str(&text)
            .map_err(|e| PackBuildError::Manifest(format!("{}: {e}", path.display())))?;
        for t in &m.tools {
            let ok = |s: &str| {
                !s.is_empty()
                    && s.bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
            };
            if !ok(&t.skill) {
                return Err(PackBuildError::Manifest(format!(
                    "bad skill name {:?}",
                    t.skill
                )));
            }
            if t.crate_dir.is_absolute()
                || t.crate_dir
                    .components()
                    .any(|c| matches!(c, std::path::Component::ParentDir))
            {
                return Err(PackBuildError::Manifest(format!(
                    "crate path must be relative without `..`: {}",
                    t.crate_dir.display()
                )));
            }
            if !matches!(
                t.target.as_str(),
                "wasm32-unknown-unknown" | "wasm32-wasip2"
            ) {
                return Err(PackBuildError::Manifest(format!(
                    "unsupported target {:?}",
                    t.target
                )));
            }
        }
        Ok(m)
    }

    /// `packs/<name>.build.yaml` beside `pack_dir`, if any.
    pub fn for_pack(pack_dir: &Path) -> Result<Option<Self>, PackBuildError> {
        let name = pack_dir
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| PackBuildError::Manifest("pack dir has no name".into()))?;
        let path = pack_dir
            .parent()
            .map(|p| p.join(format!("{name}.build.yaml")))
            .ok_or_else(|| PackBuildError::Manifest("pack dir has no parent".into()))?;
        if !path.is_file() {
            return Ok(None);
        }
        Self::load(&path).map(Some)
    }
}

fn copy_layout(src: &Path, dst: &Path) -> Result<(), PackBuildError> {
    std::fs::create_dir_all(dst).map_err(|e| PackBuildError::Io(e.to_string()))?;
    for entry in std::fs::read_dir(src).map_err(|e| PackBuildError::Io(e.to_string()))? {
        let entry = entry.map_err(|e| PackBuildError::Io(e.to_string()))?;
        let name = entry.file_name();
        let name_s = name.to_string_lossy().to_string();
        let ft = entry
            .file_type()
            .map_err(|e| PackBuildError::Io(e.to_string()))?;
        if ft.is_symlink() {
            return Err(PackBuildError::Io(format!(
                "symlink in pack source: {name_s}"
            )));
        }
        let keep = name_s == "pack.yaml"
            || name_s == "pack.sig"
            || PACK_LAYOUT_DIRS.contains(&name_s.as_str());
        if !keep {
            continue;
        }
        copy_tree(&entry.path(), &dst.join(&name))?;
    }
    Ok(())
}

fn copy_tree(src: &Path, dst: &Path) -> Result<(), PackBuildError> {
    let md = std::fs::symlink_metadata(src).map_err(|e| PackBuildError::Io(e.to_string()))?;
    if md.file_type().is_symlink() {
        return Err(PackBuildError::Io(format!(
            "symlink in pack source: {}",
            src.display()
        )));
    }
    if md.is_dir() {
        std::fs::create_dir_all(dst).map_err(|e| PackBuildError::Io(e.to_string()))?;
        for entry in std::fs::read_dir(src).map_err(|e| PackBuildError::Io(e.to_string()))? {
            let entry = entry.map_err(|e| PackBuildError::Io(e.to_string()))?;
            copy_tree(&entry.path(), &dst.join(entry.file_name()))?;
        }
    } else {
        std::fs::copy(src, dst).map_err(|e| PackBuildError::Io(e.to_string()))?;
    }
    Ok(())
}

/// `true` for a WASM component (`\0asm` + layer 0x01), `false` for a core module.
fn is_component(bytes: &[u8]) -> bool {
    bytes.len() >= 8 && &bytes[0..4] == b"\0asm" && bytes[6] == 0x01
}

fn build_tool(repo_root: &Path, tool: &PackBuildTool) -> Result<Vec<u8>, PackBuildError> {
    let crate_dir = repo_root.join(&tool.crate_dir);
    let manifest = crate_dir.join("Cargo.toml");
    if !manifest.is_file() {
        return Err(PackBuildError::Cargo(format!(
            "no Cargo.toml at {}",
            manifest.display()
        )));
    }
    // An explicit target dir inside the guest crate: never the workspace's (a `cargo test`
    // that drives this build holds the workspace build-dir lock, and `CARGO_TARGET_DIR`
    // must not redirect the guest build into it).
    let target_dir = crate_dir.join("target");
    let status = std::process::Command::new("cargo")
        .args([
            "build",
            "--release",
            "--target",
            &tool.target,
            "--manifest-path",
        ])
        .arg(&manifest)
        .arg("--target-dir")
        .arg(&target_dir)
        .env_remove("CARGO_TARGET_DIR")
        .status()
        .map_err(|e| PackBuildError::Cargo(format!("spawn cargo: {e}")))?;
    if !status.success() {
        return Err(PackBuildError::Cargo(format!(
            "cargo build failed for {} ({status})",
            tool.crate_dir.display()
        )));
    }
    let release = crate_dir.join("target").join(&tool.target).join("release");
    let mut wasms: Vec<PathBuf> = std::fs::read_dir(&release)
        .map_err(|e| PackBuildError::Cargo(format!("{}: {e}", release.display())))?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.extension().and_then(|x| x.to_str()) == Some("wasm"))
        .collect();
    wasms.sort();
    let wasm = wasms
        .first()
        .ok_or_else(|| PackBuildError::Cargo(format!("no .wasm in {}", release.display())))?;
    let bytes = std::fs::read(wasm).map_err(|e| PackBuildError::Io(e.to_string()))?;
    if is_component(&bytes) {
        Ok(bytes)
    } else {
        build_agent::encode_core_to_component(&bytes)
            .map_err(|e| PackBuildError::Encode(e.to_string()))
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::Digest;
    let d = sha2::Sha256::digest(bytes);
    d.iter().map(|b| format!("{b:02x}")).collect()
}

/// Fill `checksums.files` of `<dir>/pack.yaml` with the digest of every other file.
fn write_checksums(dir: &Path) -> Result<(), PackBuildError> {
    let manifest_path = dir.join("pack.yaml");
    let text =
        std::fs::read_to_string(&manifest_path).map_err(|e| PackBuildError::Io(e.to_string()))?;
    let mut doc: serde_yml::Value = serde_yml::from_str(&text)
        .map_err(|e| PackBuildError::Checksum(format!("pack.yaml: {e}")))?;
    let mut files = serde_yml::Mapping::new();
    for entry in walkdir::WalkDir::new(dir)
        .follow_links(false)
        .sort_by_file_name()
    {
        let entry = entry.map_err(|e| PackBuildError::Io(e.to_string()))?;
        if !entry.file_type().is_file() {
            continue;
        }
        let rel = entry
            .path()
            .strip_prefix(dir)
            .map_err(|e| PackBuildError::Io(e.to_string()))?
            .to_string_lossy()
            .replace('\\', "/");
        if rel == "pack.yaml" || rel == "pack.sig" {
            continue;
        }
        let bytes = std::fs::read(entry.path()).map_err(|e| PackBuildError::Io(e.to_string()))?;
        files.insert(
            serde_yml::Value::String(rel),
            serde_yml::Value::String(sha256_hex(&bytes)),
        );
    }
    let checksums = doc
        .as_mapping_mut()
        .and_then(|m| m.get_mut(serde_yml::Value::String("checksums".into())))
        .and_then(serde_yml::Value::as_mapping_mut)
        .ok_or_else(|| PackBuildError::Checksum("pack.yaml has no `checksums` mapping".into()))?;
    checksums.insert(
        serde_yml::Value::String("files".into()),
        serde_yml::Value::Mapping(files),
    );
    let out = serde_yml::to_string(&doc).map_err(|e| PackBuildError::Checksum(e.to_string()))?;
    std::fs::write(&manifest_path, out).map_err(|e| PackBuildError::Io(e.to_string()))?;
    // Self-check with the installer's own verifier.
    let manifest = PackManifest::from_yaml(
        &std::fs::read_to_string(&manifest_path).map_err(|e| PackBuildError::Io(e.to_string()))?,
    )
    .map_err(|e| PackBuildError::Checksum(e.to_string()))?;
    advance_pack_manager::verify_checksums(dir, &manifest.checksums)
        .map_err(|e| PackBuildError::Checksum(e.to_string()))
}

/// Build the source pack at `src` into `<out_root>/<name>`: copy the allow-listed layout,
/// build + encode every tool the sibling build manifest names, fill the output manifest's
/// checksums. The source directory is never modified.
pub fn build_pack(src: &Path, out_root: &Path) -> Result<BuiltPack, PackBuildError> {
    let src = src
        .canonicalize()
        .map_err(|e| PackBuildError::Io(format!("{}: {e}", src.display())))?;
    if !src.join("pack.yaml").is_file() {
        return Err(PackBuildError::Manifest(format!(
            "{} has no pack.yaml",
            src.display()
        )));
    }
    let name = src
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| PackBuildError::Manifest("pack dir has no name".into()))?
        .to_string();
    let out = out_root.join(&name);
    if out.exists() {
        std::fs::remove_dir_all(&out).map_err(|e| PackBuildError::Io(e.to_string()))?;
    }
    copy_layout(&src, &out)?;
    let manifest = PackBuildManifest::for_pack(&src)?;
    let repo_root = src
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .ok_or_else(|| PackBuildError::Manifest("pack dir is not under <repo>/packs/".into()))?;
    let mut tools = Vec::new();
    if let Some(m) = manifest {
        for tool in &m.tools {
            let skill_dir = out.join("skills").join(&tool.skill);
            if !skill_dir.is_dir() {
                return Err(PackBuildError::Manifest(format!(
                    "skill {:?} is not part of the pack (no skills/{}/ directory)",
                    tool.skill, tool.skill
                )));
            }
            let bytes = build_tool(&repo_root, tool)?;
            let dest = skill_dir.join("tool.wasm");
            std::fs::write(&dest, bytes).map_err(|e| PackBuildError::Io(e.to_string()))?;
            tools.push(dest);
        }
    }
    write_checksums(&out)?;
    Ok(BuiltPack { dir: out, tools })
}

// ── `advance pack keygen` / `sign` / `bundle` (entity-data lane E4, plan §5) ────────────────

/// Sign `<dir>/pack.yaml` with `secret` (an ed25519 seed), write `<dir>/pack.sig`, and return
/// the lower-case hex public key (the trust root operators list in `pack.trust-roots`).
/// Re-signing overwrites an existing `pack.sig` — the normal flow after editing the manifest.
/// The written signature is verified with the installer's own verifier before returning.
pub fn sign_pack(dir: &Path, secret: &[u8; 32]) -> Result<String, PackBuildError> {
    let manifest_path = dir.join("pack.yaml");
    let bytes = std::fs::read(&manifest_path)
        .map_err(|e| PackBuildError::Io(format!("{}: {e}", manifest_path.display())))?;
    let text = std::str::from_utf8(&bytes)
        .map_err(|e| PackBuildError::Manifest(format!("pack.yaml is not UTF-8: {e}")))?;
    let manifest =
        PackManifest::from_yaml(text).map_err(|e| PackBuildError::Manifest(e.to_string()))?;
    let (sig_text, public_hex) = advance_pack_manager::sign_pack_yaml(&bytes, secret);
    let sig_path = dir.join(advance_pack_manager::PACK_SIG_FILENAME);
    std::fs::write(&sig_path, sig_text)
        .map_err(|e| PackBuildError::Io(format!("{}: {e}", sig_path.display())))?;
    match advance_pack_manager::verify_pack_signature(
        dir,
        &bytes,
        &manifest.name,
        std::slice::from_ref(&public_hex),
    ) {
        Ok(Some(signer)) if signer == public_hex => Ok(public_hex),
        other => Err(PackBuildError::Pack(format!(
            "signature self-check failed: {other:?}"
        ))),
    }
}

/// Archive `dir` into the static registry at `out` (see `advance_pack_manager::bundle`); the
/// index's `tarball` entry is the bare file name (resolved against the registry base URL).
pub fn bundle_pack(
    dir: &Path,
    out: &Path,
) -> Result<advance_pack_manager::BundleReport, PackBuildError> {
    bundle_pack_with(dir, out, None)
}

/// [`bundle_pack`] with an absolute `base_url` written into the index's `tarball` entries.
pub fn bundle_pack_with(
    dir: &Path,
    out: &Path,
    base_url: Option<&str>,
) -> Result<advance_pack_manager::BundleReport, PackBuildError> {
    if let Some(base) = base_url {
        if !(base.starts_with("https://") || base.starts_with("http://")) {
            return Err(PackBuildError::Manifest(
                "--base-url must be an http(s) URL".into(),
            ));
        }
    }
    advance_pack_manager::bundle_pack(dir, out, base_url)
        .map_err(|e| PackBuildError::Pack(e.to_string()))
}

/// Read a signing key file: 64 hex chars (what `keygen` writes; surrounding whitespace
/// ignored) or exactly 32 raw bytes.
pub fn read_signing_key(path: &Path) -> Result<[u8; 32], PackBuildError> {
    let raw =
        std::fs::read(path).map_err(|e| PackBuildError::Io(format!("{}: {e}", path.display())))?;
    if raw.len() == 32 {
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&raw);
        return Ok(seed);
    }
    let text = std::str::from_utf8(&raw)
        .map_err(|_| {
            PackBuildError::Manifest("signing key must be 64 hex chars or 32 raw bytes".into())
        })?
        .trim();
    if text.len() != 64 || !text.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(PackBuildError::Manifest(
            "signing key must be 64 hex chars or 32 raw bytes".into(),
        ));
    }
    let bytes = hex::decode(text).map_err(|e| PackBuildError::Manifest(e.to_string()))?;
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&bytes);
    Ok(seed)
}

/// Generate an ed25519 signing key from OS randomness, write it to `out` as 64 hex chars
/// (created exclusively, mode 0600 on Unix), and return the public key hex.
pub fn generate_signing_key(out: &Path) -> Result<String, PackBuildError> {
    use rand::RngCore;
    use std::io::Write;
    let mut seed = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut seed);
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(out)
        .map_err(|e| PackBuildError::Io(format!("{}: {e}", out.display())))?;
    file.write_all(format!("{}\n", hex::encode(seed)).as_bytes())
        .map_err(|e| PackBuildError::Io(format!("{}: {e}", out.display())))?;
    Ok(advance_pack_manager::public_key_hex(&seed))
}

/// Sync entry point for `advance pack keygen`.
pub fn run_keygen(out: PathBuf) -> ExitCode {
    match generate_signing_key(&out) {
        Ok(public_hex) => {
            println!("wrote signing key to {}", safe_path(&out));
            println!("public key (add to pack.trust-roots): {public_hex}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("advance pack keygen: {}", safe_msg(&e.to_string()));
            ExitCode::from(1)
        }
    }
}

/// Sync entry point for `advance pack sign`.
pub fn run_sign(dir: PathBuf, key: PathBuf) -> ExitCode {
    let secret = match read_signing_key(&key) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("advance pack sign: {}", safe_msg(&e.to_string()));
            return ExitCode::from(1);
        }
    };
    match sign_pack(&dir, &secret) {
        Ok(public_hex) => {
            println!("signed {} (public key {public_hex})", safe_path(&dir));
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("advance pack sign: {}", safe_msg(&e.to_string()));
            ExitCode::from(1)
        }
    }
}

/// Sync entry point for `advance pack bundle`.
pub fn run_bundle(dir: PathBuf, out: PathBuf, base_url: Option<String>) -> ExitCode {
    match bundle_pack_with(&dir, &out, base_url.as_deref()) {
        Ok(report) => {
            println!(
                "bundled {}@{} -> {} ({} bytes, sha256 {})",
                report.name,
                report.version,
                safe_path(&report.tarball),
                report.size,
                report.sha256
            );
            println!("index {}", safe_path(&report.index));
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("advance pack bundle: {}", safe_msg(&e.to_string()));
            ExitCode::from(1)
        }
    }
}

/// Sync entry point for `advance pack build`.
pub fn run_build(source: PathBuf, out: PathBuf) -> ExitCode {
    match build_pack(&source, &out) {
        Ok(built) => {
            println!(
                "built {} ({} tool wasm)",
                safe_path(&built.dir),
                built.tools.len()
            );
            for t in &built.tools {
                println!("  {}", safe_path(t));
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("advance pack build: {}", safe_msg(&e.to_string()));
            ExitCode::from(1)
        }
    }
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
