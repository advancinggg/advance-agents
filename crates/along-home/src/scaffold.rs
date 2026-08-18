//! Shared recognizable-home writer used by CONTRACT-243 create and `advance init`.

use std::fs;
use std::io::Write;
use std::path::Path;

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

/// Write `.advance/` / `.runtime/` / `.agent/` + starter files.
/// Parent dirs may already exist (Linux `mkdirat` / create path).
pub fn write_recognizable_home(path: &Path) -> Result<(), std::io::Error> {
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
    for sub in [".advance", ".runtime", ".agent"] {
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
        MINIMAL_STARTER.as_bytes(),
    )?;
    write_new_0600(
        &path.join(".agent").join("config.yaml"),
        AGENT_CONFIG_STARTER.as_bytes(),
    )?;
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
