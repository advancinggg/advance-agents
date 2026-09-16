#![cfg(feature = "gap-p1")]
//! GAP-01 (P1) — `advance pack install | list | uninstall`.
//! Mirrors the skill_import.rs assert_cmd style.

use std::path::{Path, PathBuf};

use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::TempDir;

fn advance() -> Command {
    Command::cargo_bin("advance").unwrap()
}

fn write_pack(root: &Path, name: &str, required: &[&str]) -> PathBuf {
    let dir = root.join(format!("{name}-src"));
    std::fs::create_dir_all(dir.join("behavior-binaries")).unwrap();
    std::fs::write(dir.join("behavior-binaries/dummy.wasm"), b"\0asm\x01\0\0\0").unwrap();
    let mut yaml = format!(
        "name: {name}\nversion: 1.0.0\nruntime-version: \">=0.1.0\"\nprovides:\n  behavior-binaries:\n    - dummy\nchecksums:\n  algo: sha256\n  files: {{}}\n"
    );
    if !required.is_empty() {
        yaml.push_str("required-capabilities:\n");
        for r in required {
            yaml.push_str(&format!("  - {r}\n"));
        }
    }
    std::fs::write(dir.join("pack.yaml"), yaml).unwrap();
    dir
}

#[test]
fn pc_01_install_list_uninstall_roundtrip() {
    let tmp = TempDir::new().unwrap();
    let packs = tmp.path().join("packs");
    let src = write_pack(tmp.path(), "foo", &[]);

    advance()
        .args(["pack", "install"])
        .arg(&src)
        .arg("--packs-dir")
        .arg(&packs)
        .arg("--no-input")
        .assert()
        .success()
        .stdout(predicate::str::contains("installed foo@1.0.0"));
    assert!(packs.join("foo@1.0.0/pack.yaml").is_file());

    advance()
        .args(["pack", "list", "--packs-dir"])
        .arg(&packs)
        .assert()
        .success()
        .stdout(predicate::str::contains("foo@1.0.0"))
        .stdout(predicate::str::contains("untrusted"));

    advance()
        .args(["pack", "uninstall", "foo@1.0.0", "--packs-dir"])
        .arg(&packs)
        .assert()
        .success();
    assert!(!packs.join("foo@1.0.0").exists());

    advance()
        .args(["pack", "list", "--packs-dir"])
        .arg(&packs)
        .assert()
        .success()
        .stdout(predicate::str::contains("foo@1.0.0").not());
}

#[test]
fn pc_02_reinstall_is_refused_with_already_installed() {
    let tmp = TempDir::new().unwrap();
    let packs = tmp.path().join("packs");
    let src = write_pack(tmp.path(), "foo", &[]);
    advance()
        .args(["pack", "install"])
        .arg(&src)
        .args(["--no-input", "--packs-dir"])
        .arg(&packs)
        .assert()
        .success();
    advance()
        .args(["pack", "install"])
        .arg(&src)
        .args(["--no-input", "--packs-dir"])
        .arg(&packs)
        .assert()
        .failure()
        .stderr(predicate::str::contains("already installed"));
}

#[test]
fn pc_03_required_capabilities_prompt_reads_stdin_and_no_input_rejects() {
    let tmp = TempDir::new().unwrap();
    let packs = tmp.path().join("packs");
    let src = write_pack(tmp.path(), "needy", &["fs"]);

    // --no-input → AutoReject: a pack WITH requirements cannot be installed unattended.
    advance()
        .args(["pack", "install"])
        .arg(&src)
        .args(["--no-input", "--packs-dir"])
        .arg(&packs)
        .assert()
        .failure()
        .stderr(predicate::str::contains("rejected"));

    // Interactive "n".
    advance()
        .args(["pack", "install"])
        .arg(&src)
        .arg("--packs-dir")
        .arg(&packs)
        .write_stdin("n\n")
        .assert()
        .failure()
        .stdout(predicate::str::contains("fs"))
        .stdout(predicate::str::contains("untrusted"));
    assert!(!packs.join("needy@1.0.0").exists());

    // Interactive "y".
    advance()
        .args(["pack", "install"])
        .arg(&src)
        .arg("--packs-dir")
        .arg(&packs)
        .write_stdin("y\n")
        .assert()
        .success();
    assert!(packs.join("needy@1.0.0").exists());
}

#[test]
fn pc_04_unknown_required_capability_is_refused_before_prompt() {
    let tmp = TempDir::new().unwrap();
    let packs = tmp.path().join("packs");
    let src = write_pack(tmp.path(), "weird", &["teleport"]);
    advance()
        .args(["pack", "install"])
        .arg(&src)
        .arg("--packs-dir")
        .arg(&packs)
        .write_stdin("y\n")
        .assert()
        .failure()
        .stderr(predicate::str::contains("teleport"));
    assert!(!packs.join("weird@1.0.0").exists());
}

#[test]
fn pc_05_uninstall_missing_and_bad_spec() {
    let tmp = TempDir::new().unwrap();
    let packs = tmp.path().join("packs");
    std::fs::create_dir_all(&packs).unwrap();
    advance()
        .args(["pack", "uninstall", "ghost@1.0.0", "--packs-dir"])
        .arg(&packs)
        .assert()
        .failure()
        .stderr(predicate::str::contains("not installed"));
    advance()
        .args(["pack", "uninstall", "no-version-here", "--packs-dir"])
        .arg(&packs)
        .assert()
        .failure();
}

#[test]
fn pc_06_packs_dir_defaults_to_workspace_env() {
    let tmp = TempDir::new().unwrap();
    let ws = tmp.path().join("ws");
    std::fs::create_dir_all(ws.join(".advance")).unwrap();
    let src = write_pack(tmp.path(), "foo", &[]);
    advance()
        .args(["pack", "install"])
        .arg(&src)
        .arg("--no-input")
        .env("ADVANCE_WORKSPACE", &ws)
        .assert()
        .success();
    assert!(ws.join(".advance/packs/foo@1.0.0/pack.yaml").is_file());
}
