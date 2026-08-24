//! Integration tests for `advance init`.

use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;
use std::os::unix::fs::symlink;
use tempfile::TempDir;

fn advance() -> Command {
    Command::cargo_bin("advance").unwrap()
}

#[test]
fn init_creates_workspace_skeleton() {
    let tmp = TempDir::new().unwrap();
    let ws = tmp.path().join("ws");
    advance()
        .args(["init"])
        .arg(&ws)
        .assert()
        .success()
        .stdout(predicate::str::contains("Initialized"));
    assert!(ws.join(".advance").is_dir());
    assert!(ws.join(".runtime").is_dir());
    assert!(ws.join(".agent").is_dir());
    assert!(ws.join(".advance/runtime-config.yaml").is_file());
    assert!(
        !ws.join(".agent/behavior.wasm").exists(),
        "advance init does not write a create-only driver"
    );
}

#[test]
fn init_accepts_relative_path() {
    let tmp = TempDir::new().unwrap();
    advance()
        .current_dir(tmp.path())
        .args(["init", "relative/ws"])
        .assert()
        .success();
    assert!(tmp.path().join("relative/ws/.advance").is_dir());
}

#[test]
fn init_refuses_when_advance_exists() {
    let tmp = TempDir::new().unwrap();
    let ws = tmp.path().join("ws");
    fs::create_dir_all(ws.join(".advance")).unwrap();
    advance()
        .args(["init"])
        .arg(&ws)
        .assert()
        .failure()
        .code(1)
        .stderr(predicate::str::contains("already exists"));
}

#[test]
fn init_refuses_when_runtime_exists() {
    let tmp = TempDir::new().unwrap();
    let ws = tmp.path().join("ws");
    fs::create_dir_all(ws.join(".runtime")).unwrap();
    advance().args(["init"]).arg(&ws).assert().failure().code(1);
}

#[test]
fn init_refuses_when_agent_exists() {
    let tmp = TempDir::new().unwrap();
    let ws = tmp.path().join("ws");
    fs::create_dir_all(ws.join(".agent")).unwrap();
    advance().args(["init"]).arg(&ws).assert().failure().code(1);
}

#[test]
fn init_written_yaml_passes_config_check() {
    let tmp = TempDir::new().unwrap();
    let ws = tmp.path().join("ws");
    advance().args(["init"]).arg(&ws).assert().success();
    advance()
        .args(["config", "check"])
        .arg(ws.join(".advance/runtime-config.yaml"))
        .assert()
        .success()
        .stdout(predicate::str::contains("valid"));
}

#[test]
fn init_rejects_symlink_target() {
    let tmp = TempDir::new().unwrap();
    let real = tmp.path().join("real");
    fs::create_dir(&real).unwrap();
    let link = tmp.path().join("ws");
    symlink(&real, &link).unwrap();
    advance()
        .args(["init"])
        .arg(&link)
        .assert()
        .failure()
        .code(1)
        .stderr(predicate::str::contains("symlink"));
}

#[test]
fn init_written_files_have_hardened_modes() {
    use std::os::unix::fs::PermissionsExt;
    let tmp = TempDir::new().unwrap();
    let ws = tmp.path().join("ws");
    advance().args(["init"]).arg(&ws).assert().success();
    for sub in [".advance", ".runtime", ".agent"] {
        let meta = fs::metadata(ws.join(sub)).unwrap();
        assert_eq!(
            meta.permissions().mode() & 0o777,
            0o700,
            "{sub} must be 0o700"
        );
    }
    let cfg_meta = fs::metadata(ws.join(".advance/runtime-config.yaml")).unwrap();
    assert_eq!(
        cfg_meta.permissions().mode() & 0o777,
        0o600,
        "runtime-config.yaml must be 0o600"
    );
}

#[test]
fn init_rejects_regular_file_target() {
    let tmp = TempDir::new().unwrap();
    let ws = tmp.path().join("ws");
    fs::write(&ws, "stuff").unwrap();
    advance()
        .args(["init"])
        .arg(&ws)
        .assert()
        .failure()
        .code(1)
        .stderr(predicate::str::contains("not a directory"));
}

#[test]
fn init_scaffolds_agent_config_with_fs_llm_and_both_providers() {
    use std::os::unix::fs::PermissionsExt;
    let tmp = TempDir::new().unwrap();
    let ws = tmp.path().join("ws");
    advance().args(["init"]).arg(&ws).assert().success();

    // /dev WS-A: `.agent/config.yaml` is scaffolded, mode 0600, and parses to
    // exactly [fs, llm] via the SAME helper the daemon uses to derive the
    // agent's CapRequest set — so init + agent-loop wiring agree.
    let agent_cfg = ws.join(".agent/config.yaml");
    assert!(
        agent_cfg.is_file(),
        ".agent/config.yaml must be scaffolded by `advance init`"
    );
    assert_eq!(
        fs::metadata(&agent_cfg).unwrap().permissions().mode() & 0o777,
        0o600,
        ".agent/config.yaml must be 0o600"
    );
    let bytes = fs::read(&agent_cfg).unwrap();
    let caps = advance_cli::agent_config::active_capabilities(Some(&bytes));
    let names: Vec<&str> = caps.iter().map(|c| c.capability.as_str()).collect();
    assert_eq!(
        names,
        vec!["fs", "llm"],
        "scaffold should declare fs + llm active"
    );

    // runtime-config.yaml carries BOTH openai and anthropic providers, and the
    // validator accepts them (config check prints the provider count → 2).
    let rt_cfg = fs::read_to_string(ws.join(".advance/runtime-config.yaml")).unwrap();
    assert!(
        rt_cfg.contains("id: anthropic"),
        "anthropic provider must be present"
    );
    assert!(
        rt_cfg.contains("id: openai"),
        "openai provider must be present"
    );
    advance()
        .args(["config", "check"])
        .arg(ws.join(".advance/runtime-config.yaml"))
        .assert()
        .success()
        .stdout(predicate::str::contains("2 llm providers"));
}

// ============================================================================
// Linux-only Slice G tests — openat2 fd-pinned init hardening
// ============================================================================

#[cfg(target_os = "linux")]
fn openat2_supported() -> bool {
    use rustix::fs::{openat2, Mode, OFlags, ResolveFlags, CWD};
    match openat2(
        CWD,
        ".",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::empty(),
    ) {
        Ok(_) => true,
        Err(e) if e.raw_os_error() == libc::ENOSYS => false,
        Err(_) => true,
    }
}

#[cfg(target_os = "linux")]
#[test]
fn init_rejects_linux_ancestor_symlink() {
    if !openat2_supported() {
        eprintln!("skipping — kernel <5.6, no openat2");
        return;
    }
    let tmp = TempDir::new().unwrap();
    let base = tmp.path().canonicalize().unwrap();
    fs::create_dir_all(base.join("real/ws")).unwrap();
    symlink(base.join("real"), base.join("link")).unwrap();
    advance()
        .args(["init"])
        .arg(base.join("link/ws"))
        .assert()
        .failure()
        .code(1)
        .stderr(
            predicate::str::contains("ancestor symlink")
                .or(predicate::str::contains("too many levels"))
                .or(predicate::str::contains("ELOOP")),
        );
}

#[cfg(target_os = "linux")]
#[test]
fn init_linux_mkdirat_pins_advance() {
    if !openat2_supported() {
        eprintln!("skipping — kernel <5.6, no openat2");
        return;
    }
    use std::os::unix::fs::PermissionsExt;
    let tmp = TempDir::new().unwrap();
    let base = tmp.path().canonicalize().unwrap();
    let ws = base.join("ws");
    advance().args(["init"]).arg(&ws).assert().success();
    for sub in [".advance", ".runtime", ".agent"] {
        let meta = fs::metadata(ws.join(sub)).unwrap();
        assert_eq!(
            meta.permissions().mode() & 0o777,
            0o700,
            "{sub} must be 0o700"
        );
    }
    let cfg = ws.join(".advance/runtime-config.yaml");
    assert_eq!(
        fs::metadata(&cfg).unwrap().permissions().mode() & 0o777,
        0o600,
        "runtime-config.yaml must be 0o600"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn init_linux_refuses_when_advance_exists_statat() {
    if !openat2_supported() {
        eprintln!("skipping — kernel <5.6, no openat2");
        return;
    }
    let tmp = TempDir::new().unwrap();
    let base = tmp.path().canonicalize().unwrap();
    let ws = base.join("ws");
    fs::create_dir_all(ws.join(".advance")).unwrap();
    advance()
        .args(["init"])
        .arg(&ws)
        .assert()
        .failure()
        .code(1)
        .stderr(predicate::str::contains("already exists"));
}

#[cfg(target_os = "linux")]
#[test]
fn init_linux_rejects_advance_pre_symlinked() {
    if !openat2_supported() {
        eprintln!("skipping — kernel <5.6, no openat2");
        return;
    }
    let tmp = TempDir::new().unwrap();
    let base = tmp.path().canonicalize().unwrap();
    let ws = base.join("ws");
    fs::create_dir_all(&ws).unwrap();
    let sibling = base.join("sibling");
    fs::create_dir(&sibling).unwrap();
    symlink(&sibling, ws.join(".advance")).unwrap();
    advance()
        .args(["init"])
        .arg(&ws)
        .assert()
        .failure()
        .code(1)
        .stderr(predicate::str::contains("already exists"));
}
