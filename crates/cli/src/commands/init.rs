//! `advance init <path>` — create a workspace skeleton with `.advance/`,
//! `.runtime/`, `.agent/` and a MINIMAL_STARTER `runtime-config.yaml`.
//!
//! Linux 5.6+ takes an fd-pinned openat2(RESOLVE_NO_SYMLINKS) path that
//! closes the symlink-swap subset of the Slice F deferred findings (§1.7).
//! Linux <5.6 and macOS fall back to the Slice F pathname-based flow.

use std::fs;
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

/// Minimal `runtime-config.yaml` template that passes every Slice D validator
/// rule with zero free-parameter failures. Carries BOTH an `anthropic` and an
/// `openai` `llm-providers[]` entry (/dev WS-A) — each validator-compliant:
/// `https` endpoint, distinct `id`, non-empty `api-key-secret` (a secret
/// *reference* name, provisioned via `advance secrets set`, never inlined),
/// `cost-per-mtoken-*` > 0, and the REQUIRED non-zero `rate-limit`. (MODULE-001
/// §1.4.2's example notoriously omitted `rate-limit` on its OpenAI block, which
/// the validator rejects — this template does not.)
pub(crate) const MINIMAL_STARTER: &str = "\
wasm:
  max_memory_pages: 1024
  epoch_interruption_ms: 100
  fuel_enabled: false

llm-providers:
  - id: anthropic
    endpoint: https://api.anthropic.com
    api-key-secret: anthropic-api-key
    model-aliases:
      sonnet: claude-sonnet-4-5
    cost-per-mtoken-in: 3.00
    cost-per-mtoken-out: 15.00
    rate-limit:
      requests-per-minute: 1000
      tokens-per-minute: 400000
  - id: openai
    endpoint: https://api.openai.com
    api-key-secret: openai-api-key
    model-aliases:
      gpt: gpt-4o
    cost-per-mtoken-in: 2.50
    cost-per-mtoken-out: 10.00
    rate-limit:
      requests-per-minute: 1000
      tokens-per-minute: 400000

cron:
  max_jitter_ratio: 0.1

git:
  gc_interval_hours: 24
  max_tracked_file_mb: 10

secrets:
  master-key-source: keychain
  env-var-name: SECRETS_MASTER_KEY

post-processor:
  llm-model: sonnet-light
  llm-failure-cooldown-seconds: 600

# Slice AE (2026-05-09): per-workspace SQLite index handle. The block has
# `#[serde(default)]` on the parent struct, so omitting it produces the same
# values; explicit form here keeps `advance config check` output canonical.
# Slice G (2026-05-09): adds wal-mode + embedding-dim + recall-max-depth for
# AC-19 hot-reload coverage. Each subfield has its own `#[serde(default)]`
# so omitting an individual line within a present `database:` block also
# yields the canonical default.
#
# IMPORTANT: `wal-mode: false` issues `PRAGMA journal_mode = MEMORY` —
# committed transactions are NOT crash-durable. Keep `true` in production.
# The runtime emits a stderr warning at startup if you flip this to false.
database:
  db-path: \".runtime/index.db\"
  pool-size: 4
  wal-mode: true
  embedding-dim: 768
  recall-max-depth: 3
";

/// Starter `<workspace>/.agent/config.yaml` (/dev WS-A). Declares the agent's
/// L0-active capability set under the top-level `capabilities:` mapping that
/// both `cli::wiring::wire_capabilities` (which host fns to register) and
/// `agent_config::active_capabilities` (which CapRequests the agent loop injects
/// into the guest) read. `fs` + `llm` are the spine's minimum: `fs` so the agent
/// can write its workspace, `llm` so the agent-llm host fns are linked into the
/// guest's linker. A `true` value is L0-active; cap-grant emits a Grant per
/// active entry. NOTE: because `llm: true` activates the secrets/llm chain,
/// `advance start` will require a master key (`SECRETS_MASTER_KEY` env or OS
/// keychain) — provision one and `advance secrets set <name>` before starting.
pub(crate) const AGENT_CONFIG_STARTER: &str = "\
capabilities:
  fs: true
  llm: true
";

pub fn run(path: PathBuf) -> ExitCode {
    match run_outer(&path) {
        Ok(display) => {
            println!("Initialized advance workspace at {display}");
            ExitCode::SUCCESS
        }
        Err(msg) => {
            eprintln!("advance init: {msg}");
            ExitCode::from(1)
        }
    }
}

fn run_outer(path: &Path) -> Result<String, String> {
    // Common pre-phase: leaf stat + create_dir_all on NotFound. Protects the
    // leaf symlink case on both Linux and macOS — subsequent Linux-hardened
    // openat2 or macOS-fallback canonicalize handles the ancestor chain.
    match fs::symlink_metadata(path) {
        Ok(meta) => {
            let ft = meta.file_type();
            if ft.is_symlink() {
                return Err("refuses to init into a symlink target path".into());
            }
            if !ft.is_dir() {
                return Err("target exists and is not a directory".into());
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir_all(path)
                .map_err(|e| format!("failed to create target dir {}: {e}", path.display()))?;
            let meta = fs::symlink_metadata(path)
                .map_err(|e| format!("failed to stat {} after create: {e}", path.display()))?;
            if meta.file_type().is_symlink() {
                return Err(
                    "refuses to init into a symlink target path (post-create check)".into(),
                );
            }
        }
        Err(e) => return Err(format!("stat {} failed: {e}", path.display())),
    }

    #[cfg(target_os = "linux")]
    {
        match try_linux_hardened(path) {
            Ok(s) => return Ok(s),
            Err(TryLinuxErr::Unsupported) => { /* fall through to fallback */ }
            Err(TryLinuxErr::Failed(msg)) => return Err(msg),
        }
    }

    fallback_init(path).map(|p| p.display().to_string())
}

fn fallback_init(path: &Path) -> Result<PathBuf, String> {
    let canonical = fs::canonicalize(path)
        .map_err(|e| format!("canonicalize {} failed: {e}", path.display()))?;

    advance_runtime::config::check_no_ancestor_symlinks_parents(&canonical)
        .map_err(|e| e.to_string())?;

    for sub in [".advance", ".runtime", ".agent"] {
        let p = canonical.join(sub);
        if fs::symlink_metadata(&p).is_ok() {
            return Err(format!(
                "{} already exists — refusing to re-init",
                p.display()
            ));
        }
    }
    let cfg_path = canonical.join(".advance").join("runtime-config.yaml");
    if fs::symlink_metadata(&cfg_path).is_ok() {
        return Err(format!(
            "{} already exists — refusing to overwrite",
            cfg_path.display()
        ));
    }

    let mut dir_opts = fs::DirBuilder::new();
    dir_opts.mode(0o700);
    for sub in [".advance", ".runtime", ".agent"] {
        let p = canonical.join(sub);
        dir_opts
            .create(&p)
            .map_err(|e| format!("failed to create {}: {e}", p.display()))?;
    }

    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&cfg_path)
        .map_err(|e| format!("failed to create {}: {e}", cfg_path.display()))?;
    file.write_all(MINIMAL_STARTER.as_bytes())
        .map_err(|e| format!("failed to write {}: {e}", cfg_path.display()))?;

    // /dev WS-A: scaffold `<ws>/.agent/config.yaml` (capabilities: {fs, llm}).
    // `.agent/` was just created above (and the leaf-exists guards refuse a
    // re-init), so `create_new` + O_NOFOLLOW cannot collide with a pre-existing
    // file or follow a symlink.
    let agent_cfg_path = canonical.join(".agent").join("config.yaml");
    let mut agent_file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&agent_cfg_path)
        .map_err(|e| format!("failed to create {}: {e}", agent_cfg_path.display()))?;
    agent_file
        .write_all(AGENT_CONFIG_STARTER.as_bytes())
        .map_err(|e| format!("failed to write {}: {e}", agent_cfg_path.display()))?;

    Ok(canonical)
}

// ============================================================================
// Linux-only fd-pinned hardened path (Slice G)
// ============================================================================

#[cfg(target_os = "linux")]
enum TryLinuxErr {
    Unsupported,
    Failed(String),
}

#[cfg(target_os = "linux")]
fn try_linux_hardened(path: &Path) -> Result<String, TryLinuxErr> {
    use advance_runtime::config::open_dir_hardened;
    use rustix::fd::AsFd;
    use rustix::fs::{mkdirat, openat2, statat, AtFlags, Mode, OFlags, ResolveFlags};

    // Absolute-ize WITHOUT canonicalize so openat2 sees ancestor symlinks.
    let abs = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|e| TryLinuxErr::Failed(format!("getcwd: {e}")))?
            .join(path)
    };

    let root_fd = match open_dir_hardened(&abs) {
        Ok(fd) => fd,
        Err(e) if e.kind() == std::io::ErrorKind::Unsupported => {
            return Err(TryLinuxErr::Unsupported);
        }
        Err(e) => {
            return Err(TryLinuxErr::Failed(format!(
                "open workspace root {} failed (ancestor symlink or permission?): {e}",
                abs.display()
            )));
        }
    };

    for sub in [".advance", ".runtime", ".agent"] {
        match statat(root_fd.as_fd(), sub, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(_) => {
                return Err(TryLinuxErr::Failed(format!(
                    "{}/{sub} already exists — refusing to re-init",
                    abs.display()
                )));
            }
            Err(e) if e.raw_os_error() == libc::ENOENT => (),
            Err(e) => return Err(TryLinuxErr::Failed(format!("statat {sub}: {e}"))),
        }
    }

    for sub in [".advance", ".runtime", ".agent"] {
        mkdirat(root_fd.as_fd(), sub, Mode::from_bits_truncate(0o700))
            .map_err(|e| TryLinuxErr::Failed(format!("mkdir {sub}: {e}")))?;
    }

    let advance_fd = openat2(
        root_fd.as_fd(),
        ".advance",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::NO_SYMLINKS,
    )
    .map_err(|e| TryLinuxErr::Failed(format!("reopen .advance: {e}")))?;
    let advance_file = std::fs::File::from(advance_fd);

    let cfg_fd = openat2(
        advance_file.as_fd(),
        "runtime-config.yaml",
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_bits_truncate(0o600),
        ResolveFlags::NO_SYMLINKS,
    )
    .map_err(|e| TryLinuxErr::Failed(format!("create runtime-config.yaml: {e}")))?;
    let mut cfg_file = std::fs::File::from(cfg_fd);

    cfg_file
        .write_all(MINIMAL_STARTER.as_bytes())
        .map_err(|e| TryLinuxErr::Failed(format!("write runtime-config.yaml: {e}")))?;

    // /dev WS-A: scaffold `.agent/config.yaml` via the same fd-pinned,
    // RESOLVE_NO_SYMLINKS path used for runtime-config.yaml above. `.agent/` was
    // created by the `mkdirat` loop; reopen it NOFOLLOW, then create config.yaml
    // O_EXCL|O_NOFOLLOW (0600).
    let agent_fd = openat2(
        root_fd.as_fd(),
        ".agent",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::NO_SYMLINKS,
    )
    .map_err(|e| TryLinuxErr::Failed(format!("reopen .agent: {e}")))?;
    let agent_dir_file = std::fs::File::from(agent_fd);

    let agent_cfg_fd = openat2(
        agent_dir_file.as_fd(),
        "config.yaml",
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_bits_truncate(0o600),
        ResolveFlags::NO_SYMLINKS,
    )
    .map_err(|e| TryLinuxErr::Failed(format!("create .agent/config.yaml: {e}")))?;
    let mut agent_cfg_file = std::fs::File::from(agent_cfg_fd);
    agent_cfg_file
        .write_all(AGENT_CONFIG_STARTER.as_bytes())
        .map_err(|e| TryLinuxErr::Failed(format!("write .agent/config.yaml: {e}")))?;

    Ok(abs.display().to_string())
}
