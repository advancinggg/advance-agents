//! Pack lane P3 — composition-root wiring witnesses for `advance pack
//! install` (the internal pack gap-closure plan §4.1 + §4.4): the `pack:` block of
//! the workspace `runtime-config.yaml` drives the real binary.
//!
//! - `pack.trust-roots` → `Installer::with_trust_roots`: a `pack.sig` signed by
//!   a configured root keeps `trust-level: trusted` (and `advance pack list`
//!   shows it); the same signed pack without the root installs as `untrusted`.
//! - `pack.registry-url` → `HttpsRegistryClient`: `registry:foo@1.0.0` is fetched
//!   from a loopback registry served in-process; with no URL configured the
//!   registry source is an install error, never a silent skip.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use assert_cmd::Command;
use axum::{extract::State, routing::get, Router};
use ed25519_dalek::{Signer, SigningKey};
use predicates::prelude::*;
use sha2::{Digest, Sha256};
use tempfile::TempDir;

const PACK_YAML: &str = "name: foo\nversion: 1.0.0\nruntime-version: \">=0.1.0\"\ntrust-level: trusted\nprovides:\n  behavior-binaries:\n    - dummy\nchecksums:\n  algo: sha256\n  files: {}\n";

fn advance() -> Command {
    Command::cargo_bin("advance").unwrap()
}

/// `advance init <ws>` then append `extra` to the starter runtime config.
fn init_workspace(root: &Path, extra_pack_yaml: &str) -> PathBuf {
    let ws = root.join("ws");
    advance().arg("init").arg(&ws).assert().success();
    let cfg = ws.join(".advance/runtime-config.yaml");
    let base = std::fs::read_to_string(&cfg).unwrap();
    std::fs::write(&cfg, format!("{base}\npack:\n{extra_pack_yaml}")).unwrap();
    ws
}

fn write_signed_pack(root: &Path, key: &SigningKey) -> PathBuf {
    let dir = root.join("foo-src");
    std::fs::create_dir_all(dir.join("behavior-binaries")).unwrap();
    std::fs::write(dir.join("behavior-binaries/dummy.wasm"), b"\0asm\x01\0\0\0").unwrap();
    std::fs::write(dir.join("pack.yaml"), PACK_YAML).unwrap();
    let sig = key.sign(PACK_YAML.as_bytes());
    std::fs::write(
        dir.join("pack.sig"),
        format!(
            "alg: ed25519\npublic-key: {}\nsignature: {}\n",
            hex::encode(key.verifying_key().to_bytes()),
            hex::encode(sig.to_bytes())
        ),
    )
    .unwrap();
    dir
}

fn hex_of(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn cw_01_trust_roots_from_config_keep_a_root_signed_pack_trusted() {
    let tmp = TempDir::new().unwrap();
    let key = SigningKey::from_bytes(&[7u8; 32]);
    let pk = hex::encode(key.verifying_key().to_bytes());
    let src = write_signed_pack(tmp.path(), &key);

    // Root configured → trusted survives.
    let ws = init_workspace(tmp.path(), &format!("  trust-roots:\n    - {pk}\n"));
    let packs = tmp.path().join("packs-trusted");
    advance()
        .env("ADVANCE_WORKSPACE", &ws)
        .args(["pack", "install"])
        .arg(&src)
        .arg("--packs-dir")
        .arg(&packs)
        .arg("--no-input")
        .assert()
        .success()
        .stdout(predicate::str::contains("installed foo@1.0.0"));
    advance()
        .env("ADVANCE_WORKSPACE", &ws)
        .args(["pack", "list", "--packs-dir"])
        .arg(&packs)
        .assert()
        .success()
        .stdout(predicate::str::contains("foo@1.0.0\ttrusted"));
    let index = std::fs::read_to_string(packs.join(".meta.yaml")).unwrap();
    assert!(index.contains(&pk), "signed_by recorded: {index}");
    assert!(packs.join("foo@1.0.0/pack.sig").is_file());

    // No root configured (fresh workspace) → the same signed pack is downgraded.
    let tmp2 = TempDir::new().unwrap();
    let ws2 = init_workspace(tmp2.path(), "  fetch-timeout-sec: 30\n");
    let packs2 = tmp2.path().join("packs-unsigned");
    advance()
        .env("ADVANCE_WORKSPACE", &ws2)
        .args(["pack", "install"])
        .arg(&src)
        .arg("--packs-dir")
        .arg(&packs2)
        .arg("--no-input")
        .assert()
        .success();
    advance()
        .env("ADVANCE_WORKSPACE", &ws2)
        .args(["pack", "list", "--packs-dir"])
        .arg(&packs2)
        .assert()
        .success()
        .stdout(predicate::str::contains("foo@1.0.0\tuntrusted"));

    // A tampered manifest fails the install outright (regardless of roots).
    let mut tampered = std::fs::read_to_string(src.join("pack.yaml")).unwrap();
    tampered.push_str("# tampered\n");
    std::fs::write(src.join("pack.yaml"), tampered).unwrap();
    let packs3 = tmp.path().join("packs-tampered");
    advance()
        .env("ADVANCE_WORKSPACE", &ws)
        .args(["pack", "install"])
        .arg(&src)
        .arg("--packs-dir")
        .arg(&packs3)
        .arg("--no-input")
        .assert()
        .failure()
        .stderr(predicate::str::contains("signature verification failed"));
    assert!(!packs3.join("foo@1.0.0").exists());
}

#[derive(Clone)]
struct Served {
    index: Arc<str>,
    tarball: Arc<Vec<u8>>,
}

fn build_tarball() -> Vec<u8> {
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    {
        let mut b = tar::Builder::new(&mut gz);
        let yaml = "name: foo\nversion: 1.0.0\nruntime-version: \">=0.1.0\"\nchecksums:\n  algo: sha256\n  files: {}\n";
        let mut h = tar::Header::new_gnu();
        h.set_path("pack.yaml").unwrap();
        h.set_size(yaml.len() as u64);
        h.set_mode(0o644);
        h.set_cksum();
        b.append(&h, yaml.as_bytes()).unwrap();
        b.finish().unwrap();
    }
    gz.finish().unwrap()
}

/// One loopback server for both the index and the blob (single base URL).
async fn serve_registry(tarball: Vec<u8>) -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let sha = hex_of(&Sha256::digest(&tarball));
    let index = format!(
        "{{\"name\":\"foo\",\"versions\":{{\"1.0.0\":{{\"tarball\":\"http://{addr}/blobs/foo-1.0.0.tar.gz\",\"sha256\":\"{sha}\",\"size\":{}}}}}}}",
        tarball.len()
    );
    let state = Served {
        index: index.into(),
        tarball: Arc::new(tarball),
    };
    let app = Router::new()
        .route(
            "/index/foo.json",
            get(|State(s): State<Served>| async move { s.index.to_string() }),
        )
        .route(
            "/blobs/foo-1.0.0.tar.gz",
            get(|State(s): State<Served>| async move { (*s.tarball).clone() }),
        )
        .with_state(state);
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    addr
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cw_02_registry_url_from_config_serves_registry_sources() {
    let tmp = TempDir::new().unwrap();
    let registry = serve_registry(build_tarball()).await;

    // Configured → the registry source installs through HttpsRegistryClient.
    let ws = init_workspace(tmp.path(), &format!("  registry-url: http://{registry}\n"));
    let packs = tmp.path().join("packs");
    let (ws_c, packs_c) = (ws.clone(), packs.clone());
    tokio::task::spawn_blocking(move || {
        advance()
            .env("ADVANCE_WORKSPACE", &ws_c)
            .args(["pack", "install", "registry:foo@1.0.0", "--packs-dir"])
            .arg(&packs_c)
            .arg("--no-input")
            .assert()
            .success()
            .stdout(predicate::str::contains("installed foo@1.0.0"));
    })
    .await
    .unwrap();
    assert!(packs.join("foo@1.0.0/pack.yaml").is_file());

    // Not configured → surfaced as an install error, never silently skipped.
    let tmp2 = TempDir::new().unwrap();
    let ws2 = init_workspace(tmp2.path(), "  fetch-timeout-sec: 30\n");
    let packs2 = tmp2.path().join("packs");
    tokio::task::spawn_blocking(move || {
        advance()
            .env("ADVANCE_WORKSPACE", &ws2)
            .args(["pack", "install", "registry:foo@1.0.0", "--packs-dir"])
            .arg(&packs2)
            .arg("--no-input")
            .assert()
            .failure()
            .stderr(predicate::str::contains("no RegistryClient configured"));
    })
    .await
    .unwrap();
}
