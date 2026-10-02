//! GAP-03 (P3) — `HttpsRegistryClient` against a local axum registry.
//! Needs cli dev-deps `tar`, `flate2`, `sha2`
//! (workspace-pinned) to build and hash the tarball fixture.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use advance_cli::pack_registry_client::HttpsRegistryClient;
use advance_pack_manager::{PackError, RegistryClient};
use axum::{extract::State, routing::get, Router};
use sha2::{Digest, Sha256};

#[derive(Clone)]
struct Served {
    index: Arc<str>,
    tarball: Arc<Vec<u8>>,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
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

/// Serve `index` at /index/foo.json and `tarball` at /blobs/foo-1.0.0.tar.gz.
async fn serve(index: String, tarball: Vec<u8>) -> SocketAddr {
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
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    addr
}

fn index(blob_host: SocketAddr, sha: &str, size: usize) -> String {
    format!(
        "{{\"name\":\"foo\",\"versions\":{{\"1.0.0\":{{\"tarball\":\"http://{blob_host}/blobs/foo-1.0.0.tar.gz\",\"sha256\":\"{sha}\",\"size\":{size}}}}}}}"
    )
}

#[tokio::test]
async fn rc_01_fetch_verifies_sha256_and_lists_versions() {
    let tarball = build_tarball();
    let sha = hex(&Sha256::digest(&tarball));
    let size = tarball.len();
    let blob_host = serve(String::new(), tarball.clone()).await;
    let registry = serve(index(blob_host, &sha, size), tarball).await;
    let client = HttpsRegistryClient::new(&format!("http://{registry}"), Duration::from_secs(5))
        .expect("loopback http allowed");
    let dest = tempfile::TempDir::new().unwrap();
    let path = client
        .fetch_tarball("foo", "1.0.0", dest.path())
        .await
        .expect("fetch");
    assert!(path.starts_with(dest.path()));
    assert_eq!(hex(&Sha256::digest(std::fs::read(&path).unwrap())), sha);
    let versions = client.list_versions("foo").await.unwrap();
    assert_eq!(versions, vec![semver::Version::parse("1.0.0").unwrap()]);
}

#[tokio::test]
async fn rc_02_sha_mismatch_and_oversize_are_refused() {
    let tarball = build_tarball();
    let size = tarball.len();
    let blob_host = serve(String::new(), tarball.clone()).await;
    let bad_sha = serve(index(blob_host, &"0".repeat(64), size), tarball.clone()).await;
    let client =
        HttpsRegistryClient::new(&format!("http://{bad_sha}"), Duration::from_secs(5)).unwrap();
    let dest = tempfile::TempDir::new().unwrap();
    let err = client
        .fetch_tarball("foo", "1.0.0", dest.path())
        .await
        .unwrap_err();
    assert!(
        matches!(err, PackError::RegistryFetchFailed { .. }),
        "{err:?}"
    );
    assert!(
        std::fs::read_dir(dest.path()).unwrap().next().is_none(),
        "no unverified blob left behind"
    );

    let huge = serve(
        index(blob_host, &"0".repeat(64), 300 * 1024 * 1024),
        tarball,
    )
    .await;
    let client =
        HttpsRegistryClient::new(&format!("http://{huge}"), Duration::from_secs(5)).unwrap();
    let err = client
        .fetch_tarball("foo", "1.0.0", dest.path())
        .await
        .unwrap_err();
    assert!(
        matches!(err, PackError::RegistryFetchFailed { .. }),
        "declared size over cap: {err:?}"
    );
}

#[test]
fn rc_03_plain_http_is_loopback_only() {
    let t = Duration::from_secs(1);
    assert!(HttpsRegistryClient::new("https://registry.example.com", t).is_ok());
    assert!(HttpsRegistryClient::new("http://127.0.0.1:8080", t).is_ok());
    assert!(HttpsRegistryClient::new("http://localhost:8080", t).is_ok());
    assert!(HttpsRegistryClient::new("http://registry.example.com", t).is_err());
    assert!(HttpsRegistryClient::new("ftp://x", t).is_err());
}
