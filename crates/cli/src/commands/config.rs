//! `advance config check [<file-path>]` — validate a runtime-config.yaml.
//!
//! Path resolution: explicit arg → `$ADVANCE_WORKSPACE/.advance/runtime-config.yaml`
//! → `./.advance/runtime-config.yaml`. Does NOT canonicalize — Slice D's
//! `load_config` intentionally inspects the raw path via `symlink_metadata`
//! and `O_NOFOLLOW`/`openat2(RESOLVE_NO_SYMLINKS)`, rejecting symlinks;
//! canonicalizing would follow symlinks before that check.

use std::path::PathBuf;
use std::process::ExitCode;

pub fn check(path: Option<PathBuf>) -> ExitCode {
    let resolved = resolve_path(path);
    match advance_runtime::config::load_config(&resolved) {
        Ok(cfg) => {
            println!(
                "{}: valid ({} llm providers)",
                resolved.display(),
                cfg.llm_providers.len()
            );
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("{e}");
            ExitCode::from(1)
        }
    }
}

fn resolve_path(explicit: Option<PathBuf>) -> PathBuf {
    if let Some(p) = explicit {
        return p;
    }
    if let Some(ws) = std::env::var_os("ADVANCE_WORKSPACE") {
        if !ws.is_empty() {
            return PathBuf::from(ws)
                .join(".advance")
                .join("runtime-config.yaml");
        }
    }
    PathBuf::from("./.advance/runtime-config.yaml")
}
