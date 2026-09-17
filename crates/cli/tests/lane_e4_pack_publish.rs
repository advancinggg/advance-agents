#![cfg(feature = "lane-e4")]
//! Lane E4 — signing and bundling a pack for the registry (the internal entity-data lane plan §5):
//! `sign` writes a `pack.sig` a trust root accepts, `bundle` produces an installable tarball
//! and merges the registry index the production `HttpsRegistryClient` reads.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use advance_cli::commands::pack::{bundle_pack, sign_pack};
use advance_pack_manager::signature::verify_pack_signature;
use advance_pack_manager::{AutoApprove, InMemoryPackRegistry, Installer, PackRegistry};
use sha2::{Digest, Sha256};

fn agenda_copy(tmp: &Path) -> PathBuf {
    let src = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../packs/agenda")
        .canonicalize()
        .unwrap();
    let dst = tmp.join("agenda");
    copy_tree(&src, &dst);
    dst
}

fn copy_tree(src: &Path, dst: &Path) {
    std::fs::create_dir_all(dst).unwrap();
    for entry in std::fs::read_dir(src).unwrap() {
        let entry = entry.unwrap();
        let to = dst.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_tree(&entry.path(), &to);
        } else {
            std::fs::copy(entry.path(), to).unwrap();
        }
    }
}

const SECRET: [u8; 32] = [7u8; 32];

#[test]
fn e4_sign_writes_a_pack_sig_that_a_trust_root_accepts() {
    let tmp = tempfile::TempDir::new().unwrap();
    let dir = agenda_copy(tmp.path());
    let public_hex = sign_pack(&dir, &SECRET).expect("sign");
    assert_eq!(public_hex.len(), 64);
    let sig = std::fs::read_to_string(dir.join("pack.sig")).unwrap();
    assert!(sig.contains("alg: ed25519") && sig.contains(&public_hex), "{sig}");

    let manifest = std::fs::read(dir.join("pack.yaml")).unwrap();
    assert_eq!(
        verify_pack_signature(&dir, &manifest, "agenda", &[public_hex.clone()]).unwrap(),
        Some(public_hex.clone()),
        "signed by a configured root"
    );
    assert_eq!(
        verify_pack_signature(&dir, &manifest, "agenda", &["ab".repeat(32)]).unwrap(),
        None,
        "an unknown signer proves nothing"
    );
    let tampered = [manifest.as_slice(), &b"\n# tampered\n"[..]].concat();
    assert!(
        verify_pack_signature(&dir, &tampered, "agenda", &[public_hex]).is_err(),
        "the signature covers the exact manifest bytes"
    );
}

#[tokio::test]
async fn e4_bundle_produces_an_installable_tarball_and_merges_the_index() {
    let tmp = tempfile::TempDir::new().unwrap();
    let dir = agenda_copy(tmp.path());
    sign_pack(&dir, &SECRET).unwrap();
    let out = tmp.path().join("registry");

    let report = bundle_pack(&dir, &out).expect("bundle");
    assert_eq!(report.tarball, out.join("agenda-0.1.0.tar.gz"));
    let bytes = std::fs::read(&report.tarball).unwrap();
    assert_eq!(report.size, bytes.len() as u64);
    assert_eq!(report.sha256, format!("{:x}", Sha256::digest(&bytes)));

    let index: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(out.join("index/agenda.json")).unwrap())
            .unwrap();
    assert_eq!(index["name"], "agenda");
    let v = &index["versions"]["0.1.0"];
    assert_eq!(v["sha256"], serde_json::json!(report.sha256));
    assert_eq!(v["size"], serde_json::json!(report.size));
    assert!(
        v["tarball"].as_str().unwrap().ends_with("agenda-0.1.0.tar.gz"),
        "{index}"
    );

    // The tarball installs through the real installer (tarball source) and keeps pack.sig.
    let packs = tmp.path().join("packs");
    let registry = Arc::new(InMemoryPackRegistry::new(packs.clone()));
    let installer = Installer::new(
        &packs,
        registry.clone(),
        env!("CARGO_PKG_VERSION"),
        Arc::new(AutoApprove),
    );
    let installed = installer
        .install(report.tarball.to_str().unwrap())
        .await
        .expect("install from tarball");
    assert!(registry.has(&installed.name, &installed.version));
    assert!(installed.install_path.join("pack.sig").is_file());

    // A second version merges into the same index without dropping the first.
    let bumped = tmp.path().join("agenda-0.2.0");
    copy_tree(&dir, &bumped);
    let manifest = std::fs::read_to_string(bumped.join("pack.yaml")).unwrap();
    std::fs::write(bumped.join("pack.yaml"), manifest.replace("version: 0.1.0", "version: 0.2.0")).unwrap();
    let _ = std::fs::remove_file(bumped.join("pack.sig"));
    sign_pack(&bumped, &SECRET).unwrap();
    bundle_pack(&bumped, &out).expect("bundle 0.2.0");
    let index: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(out.join("index/agenda.json")).unwrap())
            .unwrap();
    assert!(index["versions"]["0.1.0"].is_object() && index["versions"]["0.2.0"].is_object());
}
