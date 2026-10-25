//! Shared recognizable-home writer used by CONTRACT-243 create and `advance init`.

use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};

/// Same validator-compliant starter `advance init` wrote before this crate.
pub const MINIMAL_STARTER: &str = "\
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

database:
  db-path: \".runtime/index.db\"
  pool-size: 4
  wal-mode: true
  embedding-dim: 768
  recall-max-depth: 3
";

pub const AGENT_CONFIG_STARTER: &str = "\
capabilities:
  fs: true
  llm: true
";

/// Where a home keeps its master key + provider-key ciphertext.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SecretsMode {
    /// `secrets.master-key-source: keychain` (the `keyring` OS store with the env var as
    /// fallback) + `<home>/.advance/master.key` + `<home>/.advance/secrets.json`. The
    /// pre-existing scaffold.
    File,
    /// `secrets.master-key-source: keychain-sync`: master key and ciphertext are
    /// synchronizable data-protection keychain items; the home carries only names and no
    /// `master.key` is minted at create.
    KeychainSync,
}

impl SecretsMode {
    /// The YAML `secrets:` block of a starter config in this mode.
    pub fn starter_secrets_block(self) -> &'static str {
        match self {
            SecretsMode::File => {
                "secrets:\n  master-key-source: keychain\n  env-var-name: SECRETS_MASTER_KEY\n"
            }
            SecretsMode::KeychainSync => {
                "secrets:\n  master-key-source: keychain-sync\n  env-var-name: SECRETS_MASTER_KEY\n  keychain:\n    namespace: default\n    synchronizable: true\n"
            }
        }
    }
}

/// The File-mode `secrets:` block exactly as [`MINIMAL_STARTER`] carries it.
const STARTER_SECRETS_FILE_BLOCK: &str =
    "secrets:\n  master-key-source: keychain\n  env-var-name: SECRETS_MASTER_KEY\n";

/// [`MINIMAL_STARTER`] rendered for `mode` (File = the constant itself).
pub fn starter_for_mode(mode: SecretsMode) -> String {
    match mode {
        SecretsMode::File => MINIMAL_STARTER.to_string(),
        SecretsMode::KeychainSync => {
            MINIMAL_STARTER.replacen(STARTER_SECRETS_FILE_BLOCK, mode.starter_secrets_block(), 1)
        }
    }
}

/// Write `.advance/` / `.runtime/` / `.agent/` (+ `.advance/packs/`, the
/// default MODULE-018 `pack.packs-dir` — Pack lane P1) + starter
/// files. Parent dirs may already exist (Linux `mkdirat` / create path).
/// File secrets mode (the pre-existing behaviour, including the `master.key` mint).
pub fn write_recognizable_home(path: &Path) -> Result<(), std::io::Error> {
    write_recognizable_home_with_mode(path, SecretsMode::File)
}

/// [`write_recognizable_home`] for an explicit [`SecretsMode`]: the starter's `secrets:`
/// block follows the mode and `master.key` is minted only in File mode.
pub fn write_recognizable_home_with_mode(
    path: &Path,
    mode: SecretsMode,
) -> Result<(), std::io::Error> {
    match fs::symlink_metadata(path) {
        Ok(m) if m.file_type().is_symlink() => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                "home path is a symlink",
            ));
        }
        Ok(m) if !m.file_type().is_dir() => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                "home path is not a directory",
            ));
        }
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir_all(path)?;
        }
        Err(e) => return Err(e),
    }
    let mut dir_opts = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        dir_opts.mode(0o700);
    }
    // Order matters: `.advance` is created before its `packs` child.
    for sub in [".advance", ".runtime", ".agent", ".advance/packs"] {
        let p = path.join(sub);
        match fs::symlink_metadata(&p) {
            Ok(m) if m.file_type().is_dir() => {}
            Ok(_) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::AlreadyExists,
                    "marker is not a real directory",
                ));
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                dir_opts.create(&p)?;
            }
            Err(e) => return Err(e),
        }
    }
    write_new_0600(
        &path.join(".advance").join("runtime-config.yaml"),
        starter_for_mode(mode).as_bytes(),
    )?;
    write_new_0600(
        &path.join(".agent").join("config.yaml"),
        AGENT_CONFIG_STARTER.as_bytes(),
    )?;
    if mode == SecretsMode::KeychainSync {
        // The master key is a keychain item, minted on first use; never a workspace file.
        return Ok(());
    }
    let master_path = path.join(".advance").join("master.key");
    if fs::symlink_metadata(&master_path).is_err() {
        let mut bytes = zeroize::Zeroizing::new([0u8; 32]);
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut *bytes);
        let hex = zeroize::Zeroizing::new(hex::encode(*bytes));
        write_new_0600(&master_path, hex.as_bytes())?;
    } else if !crate::recognize::is_real_file(&master_path) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "master.key is not a regular file",
        ));
    }
    Ok(())
}

pub(crate) fn read_small_regular(path: &Path, max: u64) -> Option<String> {
    let meta = fs::symlink_metadata(path).ok()?;
    if !meta.file_type().is_file() || meta.len() > max {
        return None;
    }
    let mut opts = fs::OpenOptions::new();
    opts.read(true);
    #[cfg(unix)]
    {
        opts.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let mut file = opts.open(path).ok()?;
    let mut buf = vec![0u8; max as usize];
    let n = std::io::Read::read(&mut file, &mut buf).ok()?;
    String::from_utf8(buf[..n].to_vec()).ok()
}

pub(crate) fn write_0600_nofollow(path: &Path, bytes: &[u8]) -> Result<(), std::io::Error> {
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        opts.mode(0o600);
        opts.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let mut file = opts.open(path)?;
    file.write_all(bytes)?;
    Ok(())
}

/// CONTRACT-243 create-only driver bytes. Copied from
/// `crates/runtime/tests/fixtures/guest-rust-callables.core.wasm` (wasm32 core).
/// hello-llm stays the SYS-AC one-shot generate fixture; guest-rust-llm-tools
/// stays the guest-defined `tools` fixture. This driver runs generate →
/// invoke-callable → generate against the host catalog.
const CREATE_DRIVER: &[u8] = include_bytes!("fixtures/behavior.core.wasm");

/// Sha256 of every CREATE_DRIVER ever shipped (ADR 2026-10-24 D8).
///
/// Full 64-char hex, or an 8-char prefix when the original blob is gone
/// (`d431c8bf` is the ADR hello-llm CREATE_DRIVER; on-disk hello-llm is
/// `7cc5eaf7…`). A `.agent/behavior.wasm` whose hash matches an entry (or
/// the current driver) and is not current is replaced at start/compose; any
/// other hash is a custom driver and is never touched.
pub const DEFAULT_DRIVER_LINEAGE: &[&str] = &[
    "d431c8bf",
    "7cc5eaf7467258f6ca4f832dd32018bc8edd83c6d179565cdd83862e6d9162be",
    "0b0a3cceedaa2e00926e910727f7373af9d2860ef8db5d759ebf2c8a0c9664de",
    "88a90243514df75ff2045d79b8f4a49e1f2c3d97e2294aa67b23a94b0a1809b4",
    "81ea832ec7215dd47b68facdfc3a41651aa25aa6c87a739752d6853d9882c697",
];

/// Outcome of [`maybe_upgrade_default_driver`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DriverUpgrade {
    /// No `.agent/behavior.wasm` — create still owns first materialization.
    Missing,
    /// Hash equals the current CREATE_DRIVER; left in place.
    Current,
    /// Hash was in [`DEFAULT_DRIVER_LINEAGE`] and was replaced.
    Upgraded { from: String },
    /// Hash is not in the lineage; never touched.
    Custom { sha256: String },
    /// Read or atomic replace failed; the existing file is left in place.
    Failed { error: String },
}

/// Materialize `<home>/.agent/behavior.wasm` for a new-home `create`.
/// Not used by `write_recognizable_home` / `advance init`.
pub(crate) fn write_create_driver(home: &Path) -> Result<(), std::io::Error> {
    if !crate::recognize::is_real_dir(home) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "home is not a real directory",
        ));
    }
    let agent = home.join(".agent");
    if !crate::recognize::is_real_dir(&agent) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "agent dir is not a real directory",
        ));
    }
    write_new_0600(&agent.join("behavior.wasm"), CREATE_DRIVER)?;
    if !crate::recognize::is_real_dir(home) || !crate::recognize::is_real_dir(&agent) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "home or agent dir was replaced during driver write",
        ));
    }
    Ok(())
}

fn write_new_0600(path: &Path, bytes: &[u8]) -> Result<(), std::io::Error> {
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        opts.mode(0o600);
        opts.custom_flags(libc::O_NOFOLLOW);
    }
    let mut file = opts.open(path)?;
    file.write_all(bytes)?;
    Ok(())
}

/// Sha256 hex of the CREATE_DRIVER bytes this build embeds.
pub fn current_create_driver_sha256() -> String {
    sha256_hex(CREATE_DRIVER)
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn in_lineage(hex: &str) -> bool {
    DEFAULT_DRIVER_LINEAGE.iter().any(|entry| {
        if entry.len() == 64 {
            hex.eq_ignore_ascii_case(entry)
        } else {
            hex.len() == 64
                && hex
                    .get(..entry.len())
                    .is_some_and(|p| p.eq_ignore_ascii_case(entry))
        }
    })
}

fn sha256_file_nofollow(path: &Path) -> Result<String, std::io::Error> {
    let mut opts = fs::OpenOptions::new();
    opts.read(true);
    #[cfg(unix)]
    {
        opts.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let mut file = opts.open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 8192];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hex::encode(hasher.finalize()))
}

fn replace_driver_atomic(dest: &Path) -> Result<(), std::io::Error> {
    let dir = dest.parent().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "driver path has no parent",
        )
    })?;
    let tmp = dir.join(format!(".behavior.wasm.{}.tmp", std::process::id()));
    if crate::recognize::is_real_file(&tmp) {
        let _ = fs::remove_file(&tmp);
    }
    write_0600_nofollow(&tmp, CREATE_DRIVER)?;
    fs::rename(&tmp, dest).map_err(|e| {
        let _ = fs::remove_file(&tmp);
        e
    })?;
    Ok(())
}

/// Replace `<workspace>/.agent/behavior.wasm` when its hash is a previous
/// CREATE_DRIVER and is not current. Missing files and custom hashes are left
/// alone. Fail-open: IO errors return [`DriverUpgrade::Failed`] and do not
/// change the file.
pub fn maybe_upgrade_default_driver(workspace: &Path) -> DriverUpgrade {
    let dest = workspace.join(".agent").join("behavior.wasm");
    if !crate::recognize::is_real_file(&dest) {
        return if fs::symlink_metadata(&dest).is_ok() {
            DriverUpgrade::Custom {
                sha256: "not-regular".into(),
            }
        } else {
            DriverUpgrade::Missing
        };
    }
    let hex = match sha256_file_nofollow(&dest) {
        Ok(h) => h,
        Err(e) => {
            return DriverUpgrade::Failed {
                error: e.to_string(),
            }
        }
    };
    if hex.eq_ignore_ascii_case(&current_create_driver_sha256()) {
        return DriverUpgrade::Current;
    }
    if !in_lineage(&hex) {
        return DriverUpgrade::Custom { sha256: hex };
    }
    match replace_driver_atomic(&dest) {
        Ok(()) => DriverUpgrade::Upgraded { from: hex },
        Err(e) => DriverUpgrade::Failed {
            error: e.to_string(),
        },
    }
}

const UPGRADE_WALK_MAX_DEPTH: usize = 8;
const UPGRADE_WALK_MAX_FILES: usize = 64;

/// Upgrade the root workspace driver and every child `*/.agent/behavior.wasm`
/// under `home` with the same lineage rule.
pub fn upgrade_default_drivers_under(home: &Path) -> Vec<(PathBuf, DriverUpgrade)> {
    let mut workspaces = Vec::new();
    collect_agent_workspaces(home, 0, &mut workspaces);
    workspaces
        .into_iter()
        .map(|ws| {
            let outcome = maybe_upgrade_default_driver(&ws);
            (ws, outcome)
        })
        .collect()
}

fn collect_agent_workspaces(dir: &Path, depth: usize, out: &mut Vec<PathBuf>) {
    if depth > UPGRADE_WALK_MAX_DEPTH || out.len() >= UPGRADE_WALK_MAX_FILES {
        return;
    }
    if !crate::recognize::is_real_dir(dir) {
        return;
    }
    if dir.join(".agent").join("behavior.wasm").exists() {
        out.push(dir.to_path_buf());
        if out.len() >= UPGRADE_WALK_MAX_FILES {
            return;
        }
    }
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        if out.len() >= UPGRADE_WALK_MAX_FILES {
            return;
        }
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name.starts_with('.') || name == "target" || name == "node_modules" {
            continue;
        }
        let path = entry.path();
        if crate::recognize::is_real_dir(&path) {
            collect_agent_workspaces(&path, depth + 1, out);
        }
    }
}
