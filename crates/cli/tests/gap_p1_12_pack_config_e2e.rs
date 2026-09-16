#![cfg(feature = "gap-p1")]
//! GAP-12 (P1, e2e half) — `pack:` section round-trips through `advance init` +
//! `load_config`. The unit half lives in
//! crates/runtime/tests/gap_p1_12_pack_config.rs.

use advance_runtime::config::{load_config, PackApprovalPolicy, PackConfig};
use assert_cmd::Command;
use tempfile::TempDir;

#[test]
fn pcfg_01_init_produces_defaults_and_packs_dir() {
    let tmp = TempDir::new().unwrap();
    let ws = tmp.path().join("ws");
    Command::cargo_bin("advance")
        .unwrap()
        .arg("init")
        .arg(&ws)
        .assert()
        .success();
    let cfg = load_config(&ws.join(".advance/runtime-config.yaml")).expect("starter config loads");
    assert_eq!(cfg.pack, PackConfig::default());
    assert_eq!(cfg.pack.packs_dir, ".advance/packs");
    assert_eq!(cfg.pack.fetch_timeout_sec, 120);
    assert_eq!(cfg.pack.approval, PackApprovalPolicy::Interactive);
    assert!(
        ws.join(".advance/packs").is_dir(),
        "init scaffolds the packs dir"
    );
}

#[test]
fn pcfg_02_explicit_section_is_honoured_and_validated() {
    let tmp = TempDir::new().unwrap();
    let ws = tmp.path().join("ws");
    Command::cargo_bin("advance")
        .unwrap()
        .arg("init")
        .arg(&ws)
        .assert()
        .success();
    let path = ws.join(".advance/runtime-config.yaml");
    let base = std::fs::read_to_string(&path).unwrap();

    std::fs::write(
        &path,
        format!(
            "{base}\npack:\n  packs-dir: .advance/packs\n  fetch-timeout-sec: 30\n  approval: auto-reject\n  trust-roots:\n    - {}\n",
            "ab".repeat(32)
        ),
    )
    .unwrap();
    let cfg = load_config(&path).expect("valid pack section");
    assert_eq!(cfg.pack.fetch_timeout_sec, 30);
    assert_eq!(cfg.pack.approval, PackApprovalPolicy::AutoReject);
    assert_eq!(cfg.pack.trust_roots.len(), 1);

    std::fs::write(&path, format!("{base}\npack:\n  fetch-timeout-sec: 0\n")).unwrap();
    assert!(
        load_config(&path).is_err(),
        "zero timeout must be rejected by validate_config"
    );

    std::fs::write(&path, format!("{base}\npack:\n  packs-dir: ../outside\n")).unwrap();
    assert!(
        load_config(&path).is_err(),
        "`..` in packs-dir must be rejected"
    );

    std::fs::write(&path, format!("{base}\npack:\n  approval: auto-approve\n")).unwrap();
    assert!(
        load_config(&path).is_err(),
        "there is deliberately no auto-approve policy"
    );
}
