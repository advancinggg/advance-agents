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

// `provides: resource-capabilities` is a retired content kind: `advance pack install` refuses a
// manifest that declares it, and a pack that an older runtime installed with it still lists and
// uninstalls (rescan ignores the key instead of failing every pack command).
#[test]
fn pc_07_retired_resource_capabilities_key() {
    let tmp = TempDir::new().unwrap();
    let packs = tmp.path().join("packs");
    let src = write_pack(tmp.path(), "foo", &[]);
    let manifest = src.join("pack.yaml");
    let plain = std::fs::read_to_string(&manifest).unwrap();
    let with_key = plain.replacen("provides:\n", "provides:\n  resource-capabilities: []\n", 1);
    assert_ne!(with_key, plain);

    std::fs::write(&manifest, &with_key).unwrap();
    advance()
        .args(["pack", "install"])
        .arg(&src)
        .args(["--no-input", "--packs-dir"])
        .arg(&packs)
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "foo@1.0.0 declares `provides: resource-capabilities`",
        ));
    assert!(!packs.join("foo@1.0.0").exists());

    std::fs::write(&manifest, &plain).unwrap();
    advance()
        .args(["pack", "install"])
        .arg(&src)
        .args(["--no-input", "--packs-dir"])
        .arg(&packs)
        .assert()
        .success();
    std::fs::write(packs.join("foo@1.0.0/pack.yaml"), &with_key).unwrap();
    advance()
        .args(["pack", "list", "--packs-dir"])
        .arg(&packs)
        .assert()
        .success()
        .stdout(predicate::str::contains("foo@1.0.0"));
    advance()
        .args(["pack", "uninstall", "foo@1.0.0", "--packs-dir"])
        .arg(&packs)
        .assert()
        .success();
    assert!(!packs.join("foo@1.0.0").exists());
}

// The catalog `required-capabilities` are checked against is exactly the runtime's capability
// names (no installed pack widens it), and the install note never names the retired kind.
#[test]
fn pc_08_capability_catalog_is_exactly_the_known_capabilities() {
    use advance_pack_manager::{ComponentKind, PackProvideEntry};
    let mut known = advance_cli::agent_config::KNOWN_CAPABILITIES.to_vec();
    known.sort_unstable();
    known.dedup();
    let catalog = advance_cli::commands::pack::capability_catalog();
    assert_eq!(catalog.names().collect::<Vec<_>>(), known);

    let every_kind: Vec<PackProvideEntry> = [
        ComponentKind::Binary,
        ComponentKind::AgentTemplate,
        ComponentKind::Skill,
        ComponentKind::RunnableComponent,
        ComponentKind::ChannelAdapter,
        ComponentKind::McpServer,
        ComponentKind::Preset,
        ComponentKind::Workflow,
        ComponentKind::MemorySeed,
        ComponentKind::MetaSchemaExtension,
    ]
    .into_iter()
    .map(|kind| PackProvideEntry {
        kind,
        name: "x".into(),
    })
    .collect();
    let inert = advance_cli::pack_runtime::inert_kinds(&every_kind);
    assert!(!inert.contains(&"resource-capabilities"), "{inert:?}");
}
