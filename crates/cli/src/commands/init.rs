//! `advance init <path>` — create a workspace skeleton with `.advance/`,
//! `.runtime/`, `.agent/` and a MINIMAL_STARTER `runtime-config.yaml`.
//!
//! Linux 5.6+ takes an fd-pinned openat2(RESOLVE_NO_SYMLINKS) path that
//! closes the symlink-swap subset of the Slice F deferred findings (§1.7).
//! Linux <5.6 and macOS fall back to the Slice F pathname-based flow.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

#[cfg(target_os = "linux")]
use std::io::Write;

/// Starter YAML lives in `advance-along-home` so create + `advance init` share it.
#[cfg(target_os = "linux")]
pub(crate) use advance_along_home::{AGENT_CONFIG_STARTER, MINIMAL_STARTER};

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

    advance_along_home::write_recognizable_home(&canonical)
        .map_err(|e| format!("failed to scaffold recognizable home: {e}"))?;

    let mk = cap_secrets::MasterKeyConfig::Keychain {
        service: cap_secrets::DEFAULT_KEYCHAIN_SERVICE.into(),
        account: cap_secrets::DEFAULT_KEYCHAIN_ACCOUNT.into(),
        fallback_env_var: Some("SECRETS_MASTER_KEY".into()),
    };
    let _ = cap_secrets::ensure_master_key(&canonical, &mk, &cap_secrets::DefaultEntryProvider);

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

    let mk = cap_secrets::MasterKeyConfig::Keychain {
        service: cap_secrets::DEFAULT_KEYCHAIN_SERVICE.into(),
        account: cap_secrets::DEFAULT_KEYCHAIN_ACCOUNT.into(),
        fallback_env_var: Some("SECRETS_MASTER_KEY".into()),
    };
    let _ = cap_secrets::ensure_master_key(&abs, &mk, &cap_secrets::DefaultEntryProvider);

    Ok(abs.display().to_string())
}
