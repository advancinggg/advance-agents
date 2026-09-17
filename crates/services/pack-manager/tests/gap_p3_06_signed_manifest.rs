//! GAP-06 (P3) — signed manifests (`pack.sig` over `pack.yaml` bytes, ed25519).
//! See the internal pack gap-closure plan §4.1.
//! Requires `ed25519-dalek` (pinned workspace-wide) — deterministic keys, no RNG.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use advance_pack_manager::{
    AutoApprove, InMemoryPackRegistry, InstallStep, Installer, PackError, PackRegistry,
    RecordingTraceSink, TrustLevel,
};
use ed25519_dalek::{Signer, SigningKey};

const PACK_YAML: &str = "name: foo\nversion: 1.0.0\nruntime-version: \">=0.1.0\"\ntrust-level: trusted\nprovides:\n  behavior-binaries:\n    - dummy\nchecksums:\n  algo: sha256\n  files: {}\n";

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn pubkey_hex(k: &SigningKey) -> String {
    hex::encode(k.verifying_key().to_bytes())
}

fn write_pack(root: &Path, signer: Option<&SigningKey>) -> PathBuf {
    let dir = root.join("foo-src");
    std::fs::create_dir_all(dir.join("behavior-binaries")).unwrap();
    std::fs::write(dir.join("behavior-binaries/dummy.wasm"), b"\0asm\x01\0\0\0").unwrap();
    std::fs::write(dir.join("pack.yaml"), PACK_YAML).unwrap();
    if let Some(k) = signer {
        let sig = k.sign(PACK_YAML.as_bytes());
        std::fs::write(
            dir.join("pack.sig"),
            format!(
                "alg: ed25519\npublic-key: {}\nsignature: {}\n",
                pubkey_hex(k),
                hex::encode(sig.to_bytes())
            ),
        )
        .unwrap();
    }
    dir
}

fn installer(packs: &Path, roots: Vec<String>, trace: Arc<RecordingTraceSink>) -> Installer {
    Installer::new(
        packs,
        Arc::new(InMemoryPackRegistry::new(packs.to_path_buf())),
        "0.1.0",
        Arc::new(AutoApprove),
    )
    .with_trace_sink(trace)
    .with_trust_roots(roots)
}

fn step4_payload(trace: &RecordingTraceSink) -> serde_json::Value {
    trace
        .events
        .lock()
        .unwrap()
        .iter()
        .find(|(s, _)| *s == InstallStep::Step4AdminApproval)
        .map(|(_, p)| p.clone())
        .expect("step 4 traced")
}

#[tokio::test]
async fn g06_valid_signature_under_trust_root_keeps_trusted_and_records_signer() {
    let work = tempfile::TempDir::new().unwrap();
    let packs = tempfile::TempDir::new().unwrap();
    let k = key(7);
    let src = write_pack(work.path(), Some(&k));
    let trace = Arc::new(RecordingTraceSink::new());
    let inst = installer(packs.path(), vec![pubkey_hex(&k)], trace.clone());
    inst.install(src.to_str().unwrap())
        .await
        .expect("signed install");

    let meta = inst.registry.list_installed();
    assert_eq!(meta.len(), 1);
    assert_eq!(meta[0].trust_level, TrustLevel::Trusted);
    let index = std::fs::read_to_string(packs.path().join(".meta.yaml")).unwrap();
    assert!(
        index.contains(&pubkey_hex(&k)),
        "signed-by must be recorded: {index}"
    );
    assert_eq!(step4_payload(&trace).get("trust_downgraded"), None);
    // pack.sig is a legitimate top-level entry (layout allow-list).
    assert!(packs.path().join("foo@1.0.0/pack.sig").is_file());
}

#[tokio::test]
async fn g06_tampered_manifest_fails_signature_verification() {
    let work = tempfile::TempDir::new().unwrap();
    let packs = tempfile::TempDir::new().unwrap();
    let k = key(7);
    let src = write_pack(work.path(), Some(&k));
    // Tamper AFTER signing: append a harmless comment → bytes differ → signature invalid.
    let mut tampered = std::fs::read_to_string(src.join("pack.yaml")).unwrap();
    tampered.push_str("# tampered\n");
    std::fs::write(src.join("pack.yaml"), tampered).unwrap();

    let inst = installer(
        packs.path(),
        vec![pubkey_hex(&k)],
        Arc::new(RecordingTraceSink::new()),
    );
    let err = inst
        .install(src.to_str().unwrap())
        .await
        .expect_err("tamper detected");
    assert!(
        matches!(err, PackError::SignatureInvalid { .. }),
        "got {err:?}"
    );
    assert!(!packs.path().join("foo@1.0.0").exists());
}

#[tokio::test]
async fn g06_unsigned_trusted_claim_is_downgraded_to_untrusted() {
    let work = tempfile::TempDir::new().unwrap();
    let packs = tempfile::TempDir::new().unwrap();
    let src = write_pack(work.path(), None);
    let trace = Arc::new(RecordingTraceSink::new());
    let inst = installer(packs.path(), vec![pubkey_hex(&key(7))], trace.clone());
    inst.install(src.to_str().unwrap())
        .await
        .expect("unsigned packs still install");
    assert_eq!(
        inst.registry.list_installed()[0].trust_level,
        TrustLevel::Untrusted
    );
    assert_eq!(
        step4_payload(&trace).get("trust_downgraded"),
        Some(&serde_json::Value::Bool(true)),
        "admin must see the downgrade at approval time"
    );
}

#[tokio::test]
async fn g06_signature_from_unknown_key_counts_as_unsigned() {
    let work = tempfile::TempDir::new().unwrap();
    let packs = tempfile::TempDir::new().unwrap();
    let src = write_pack(work.path(), Some(&key(9)));
    // Roots contain a DIFFERENT key (and, in the second installer, none at all).
    let inst = installer(
        packs.path(),
        vec![pubkey_hex(&key(7))],
        Arc::new(RecordingTraceSink::new()),
    );
    inst.install(src.to_str().unwrap())
        .await
        .expect("unknown signer ≠ invalid signature");
    assert_eq!(
        inst.registry.list_installed()[0].trust_level,
        TrustLevel::Untrusted
    );

    let packs2 = tempfile::TempDir::new().unwrap();
    let inst2 = installer(packs2.path(), vec![], Arc::new(RecordingTraceSink::new()));
    inst2
        .install(src.to_str().unwrap())
        .await
        .expect("no roots configured → unsigned semantics");
    assert_eq!(
        inst2.registry.list_installed()[0].trust_level,
        TrustLevel::Untrusted
    );
}
