//! Pack lane P3 — `HttpsRegistryClient`, the production
//! `advance_pack_manager::RegistryClient` behind `registry:<name>@<version>`
//! sources and (lane P2) the `RegistryDependencyResolver`.
//!
//! Registry protocol (static files; any HTTPS host can serve it):
//!
//! ```text
//! GET {base}/index/{name}.json
//! { "name": "foo",
//!   "versions": { "1.0.0": { "tarball": "https://…/foo-1.0.0.tar.gz",
//!                            "sha256": "<64 hex>", "size": 12345 } } }
//! ```
//!
//! Security posture:
//! - `base_url` and every `tarball` URL the index hands back must be `https://`
//!   (any host) or `http://` on a LOOPBACK host only (`127.0.0.0/8`, `::1`,
//!   `localhost`) — the same rule `runtime-config.yaml`'s `pack.registry-url`
//!   enforces. Userinfo is refused. Redirects are NOT followed (a 3xx is a
//!   fetch failure), so a compromised index cannot bounce the download to an
//!   internal address.
//! - the index body is bounded (1 MiB); the declared `size` and the actual
//!   stream are both bounded by the installer's 256 MiB tarball cap (declared
//!   over-size is refused before any byte is downloaded; an under-declared
//!   stream is cut off at the declared size);
//! - the tarball is hashed while streaming into `dest_dir/<name>-<version>.tar.gz.part`
//!   (`O_EXCL`), renamed into place only after the sha256 matches; on any
//!   failure the partial file is removed so nothing unverified stays behind.
//! - `name` / `version` segments are shape-checked before they are spliced
//!   into a URL (no `/`, `..`, `@`, NUL, leading `.`).
//!
//! `list_versions` returns the index's versions in ascending SemVer order;
//! a non-SemVer key fails the call (fail-closed) rather than being skipped.

use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;

use advance_pack_manager::{PackError, RegistryClient};
use async_trait::async_trait;
use reqwest::Url;
use sha2::{Digest, Sha256};

/// Hard cap on a pack tarball (matches `fetch.rs::TARBALL_TOTAL_CAP`).
pub const MAX_TARBALL_BYTES: u64 = 256 * 1024 * 1024;
/// Hard cap on an index document.
const MAX_INDEX_BYTES: usize = 1024 * 1024;

#[derive(Debug, serde::Deserialize)]
struct IndexDoc {
    name: String,
    #[serde(default)]
    versions: BTreeMap<String, IndexVersion>,
}

#[derive(Debug, serde::Deserialize)]
struct IndexVersion {
    tarball: String,
    sha256: String,
    size: u64,
}

/// Production `RegistryClient` over HTTPS (see module docs).
pub struct HttpsRegistryClient {
    base: Url,
    client: reqwest::Client,
}

impl HttpsRegistryClient {
    /// `base_url`: `https://…` (any host) or `http://` on a loopback host.
    /// `timeout` bounds each HTTP request end to end (the installer's own
    /// `fetch_timeout` additionally bounds the whole `fetch_tarball`).
    pub fn new(base_url: &str, timeout: Duration) -> Result<Self, PackError> {
        let base = parse_registry_url(base_url, "registry base URL")?;
        let client = reqwest::Client::builder()
            .timeout(timeout)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| PackError::ConstraintViolation {
                reason: format!("registry HTTP client: {e}"),
            })?;
        Ok(Self { base, client })
    }

    /// `{base}/index/{name}.json` — the base's path is joined, never replaced.
    fn index_url(&self, name: &str) -> Result<Url, PackError> {
        validate_segment(name, "name")?;
        let mut url = self.base.clone();
        {
            let mut segs = url
                .path_segments_mut()
                .map_err(|_| PackError::ConstraintViolation {
                    reason: "registry base URL cannot be a base".into(),
                })?;
            segs.pop_if_empty();
            segs.push("index");
            segs.push(&format!("{name}.json"));
        }
        Ok(url)
    }

    async fn fetch_index(&self, name: &str) -> Result<IndexDoc, PackError> {
        let url = self.index_url(name)?;
        let fail = |reason: String| PackError::RegistryFetchFailed {
            name: name.to_string(),
            version: "*".into(),
            reason,
        };
        let resp = self
            .client
            .get(url.clone())
            .send()
            .await
            .map_err(|e| fail(format!("index request: {e}")))?;
        if !resp.status().is_success() {
            return Err(fail(format!("index HTTP {}", resp.status())));
        }
        if let Some(len) = resp.content_length() {
            if len > MAX_INDEX_BYTES as u64 {
                return Err(fail(format!("index exceeds {MAX_INDEX_BYTES} bytes")));
            }
        }
        let body = read_bounded(resp, MAX_INDEX_BYTES)
            .await
            .map_err(|e| fail(format!("index body: {e}")))?;
        let doc: IndexDoc =
            serde_json::from_slice(&body).map_err(|e| fail(format!("index JSON: {e}")))?;
        if doc.name != name {
            return Err(fail(format!(
                "index name mismatch: requested {name}, document says {}",
                doc.name
            )));
        }
        Ok(doc)
    }
}

#[async_trait]
impl RegistryClient for HttpsRegistryClient {
    async fn fetch_tarball(
        &self,
        name: &str,
        version: &str,
        dest_dir: &Path,
    ) -> Result<PathBuf, PackError> {
        let fail = |reason: String| PackError::RegistryFetchFailed {
            name: name.to_string(),
            version: version.to_string(),
            reason,
        };
        validate_segment(name, "name")?;
        validate_segment(version, "version")?;
        let doc = self.fetch_index(name).await?;
        let entry = doc
            .versions
            .get(version)
            .ok_or_else(|| fail("version not in registry index".into()))?;
        if entry.size > MAX_TARBALL_BYTES {
            return Err(fail(format!(
                "declared size {} exceeds the {MAX_TARBALL_BYTES}-byte tarball cap",
                entry.size
            )));
        }
        let expected = decode_sha256(&entry.sha256).map_err(fail)?;
        let tarball_url = parse_registry_url(&entry.tarball, "tarball URL")?;

        std::fs::create_dir_all(dest_dir).map_err(|e| PackError::Io {
            path: dest_dir.to_path_buf(),
            source: e,
        })?;
        let final_path = dest_dir.join(format!("{name}-{version}.tar.gz"));
        let part_path = dest_dir.join(format!("{name}-{version}.tar.gz.part"));
        let outcome =
            download_verified(&self.client, tarball_url, &part_path, entry.size, &expected).await;
        match outcome {
            Ok(()) => {
                std::fs::rename(&part_path, &final_path).map_err(|e| {
                    let _ = std::fs::remove_file(&part_path);
                    PackError::Io {
                        path: final_path.clone(),
                        source: e,
                    }
                })?;
                Ok(final_path)
            }
            Err(reason) => {
                // Nothing unverified stays behind.
                let _ = std::fs::remove_file(&part_path);
                Err(fail(reason))
            }
        }
    }

    async fn list_versions(&self, name: &str) -> Result<Vec<semver::Version>, PackError> {
        let doc = self.fetch_index(name).await?;
        let mut out = Vec::with_capacity(doc.versions.len());
        for key in doc.versions.keys() {
            let v = semver::Version::parse(key).map_err(|e| PackError::RegistryFetchFailed {
                name: name.to_string(),
                version: key.clone(),
                reason: format!("index version key is not SemVer: {e}"),
            })?;
            out.push(v);
        }
        out.sort();
        Ok(out)
    }
}

/// Stream `url` into `part_path` (created `O_EXCL`), hashing as it goes.
/// Errors are the human-readable reason; the caller removes the partial file.
async fn download_verified(
    client: &reqwest::Client,
    url: Url,
    part_path: &Path,
    declared_size: u64,
    expected_sha256: &[u8; 32],
) -> Result<(), String> {
    let resp = client
        .get(url)
        .send()
        .await
        .map_err(|e| format!("tarball request: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("tarball HTTP {}", resp.status()));
    }
    if let Some(len) = resp.content_length() {
        if len > declared_size {
            return Err(format!(
                "tarball Content-Length {len} exceeds the index's declared size {declared_size}"
            ));
        }
    }
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(part_path)
        .map_err(|e| format!("create {}: {e}", part_path.display()))?;
    let mut hasher = Sha256::new();
    let mut received: u64 = 0;
    let mut resp = resp;
    while let Some(chunk) = resp
        .chunk()
        .await
        .map_err(|e| format!("tarball stream: {e}"))?
    {
        received = received.saturating_add(chunk.len() as u64);
        if received > declared_size {
            return Err(format!(
                "tarball stream exceeds the index's declared size {declared_size} bytes"
            ));
        }
        hasher.update(&chunk);
        file.write_all(&chunk)
            .map_err(|e| format!("write {}: {e}", part_path.display()))?;
    }
    file.flush()
        .map_err(|e| format!("flush {}: {e}", part_path.display()))?;
    drop(file);
    let actual: [u8; 32] = hasher.finalize().into();
    if !constant_time_eq(&actual, expected_sha256) {
        return Err(format!(
            "sha256 mismatch: index says {}, downloaded {}",
            hex::encode(expected_sha256),
            hex::encode(actual)
        ));
    }
    Ok(())
}

/// Read a response body with a hard byte cap (the index document).
async fn read_bounded(mut resp: reqwest::Response, cap: usize) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    while let Some(chunk) = resp.chunk().await.map_err(|e| format!("stream: {e}"))? {
        if out.len() + chunk.len() > cap {
            return Err(format!("body exceeds {cap} bytes"));
        }
        out.extend_from_slice(&chunk);
    }
    Ok(out)
}

fn constant_time_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    use subtle::ConstantTimeEq;
    a.ct_eq(b).into()
}

fn decode_sha256(hex_digest: &str) -> Result<[u8; 32], String> {
    if hex_digest.len() != 64 || !hex_digest.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("index sha256 must be 64 hex chars".into());
    }
    let bytes = hex::decode(hex_digest).map_err(|e| format!("index sha256: {e}"))?;
    bytes
        .try_into()
        .map_err(|_| "index sha256 must decode to 32 bytes".to_string())
}

/// `https://` on any host; `http://` on a loopback host only; no userinfo.
fn parse_registry_url(raw: &str, what: &str) -> Result<Url, PackError> {
    let reject = |reason: String| PackError::ConstraintViolation {
        reason: format!("{what}: {reason}"),
    };
    let url = Url::parse(raw).map_err(|e| reject(format!("{e}")))?;
    if !url.username().is_empty() || url.password().is_some() {
        return Err(reject("userinfo (user:pass@) is not allowed".into()));
    }
    let host = url
        .host_str()
        .ok_or_else(|| reject("URL has no host".into()))?
        .to_string();
    match url.scheme() {
        "https" => Ok(url),
        "http" => {
            if is_loopback_host(&host) {
                Ok(url)
            } else {
                Err(reject(
                    "plain http is allowed only for loopback hosts (127.0.0.0/8, ::1, localhost)"
                        .into(),
                ))
            }
        }
        other => Err(reject(format!(
            "unsupported scheme {other}:// (https://, or http:// on a loopback host)"
        ))),
    }
}

/// `localhost`, or a literal IP in `127.0.0.0/8` / `::1` (the `url` crate hands
/// IPv6 hosts back bracketed).
fn is_loopback_host(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost")
        || host
            .trim_start_matches('[')
            .trim_end_matches(']')
            .parse::<std::net::IpAddr>()
            .map(|ip| ip.is_loopback())
            .unwrap_or(false)
}

/// The `registry:name@version` segment shape (mirrors pack-manager's
/// `validate_registry_segments`) — these are spliced into URL paths.
fn validate_segment(segment: &str, label: &str) -> Result<(), PackError> {
    if segment.is_empty()
        || segment.contains('\0')
        || segment.contains('/')
        || segment.contains('\\')
        || segment.contains('@')
        || segment.starts_with('.')
        || segment.contains("..")
        || segment
            .chars()
            .any(|c| !c.is_ascii() || c.is_ascii_control() || c.is_ascii_whitespace())
    {
        return Err(PackError::InvalidManifest(format!(
            "registry {label} has a forbidden shape (empty/null/separator/@/traversal/leading-dot/non-ASCII): {segment:?}"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_policy_https_any_host_http_loopback_only_no_userinfo() {
        let t = Duration::from_secs(1);
        assert!(HttpsRegistryClient::new("https://registry.example.com/packs", t).is_ok());
        assert!(HttpsRegistryClient::new("http://127.0.0.1:8080", t).is_ok());
        assert!(HttpsRegistryClient::new("http://127.9.9.9", t).is_ok());
        assert!(HttpsRegistryClient::new("http://[::1]:8080", t).is_ok());
        assert!(HttpsRegistryClient::new("http://LOCALHOST", t).is_ok());
        assert!(HttpsRegistryClient::new("http://registry.example.com", t).is_err());
        assert!(HttpsRegistryClient::new("http://10.0.0.1", t).is_err());
        assert!(HttpsRegistryClient::new("http://localhost@evil.example", t).is_err());
        assert!(HttpsRegistryClient::new("https://user:pw@registry.example.com", t).is_err());
        assert!(HttpsRegistryClient::new("ftp://x", t).is_err());
        assert!(HttpsRegistryClient::new("not a url", t).is_err());
    }

    #[test]
    fn index_url_joins_under_the_base_path() {
        let c = HttpsRegistryClient::new("https://r.example.com/base/", Duration::from_secs(1))
            .unwrap();
        assert_eq!(
            c.index_url("foo").unwrap().as_str(),
            "https://r.example.com/base/index/foo.json"
        );
        let c = HttpsRegistryClient::new("https://r.example.com", Duration::from_secs(1)).unwrap();
        assert_eq!(
            c.index_url("foo").unwrap().as_str(),
            "https://r.example.com/index/foo.json"
        );
        for bad in ["../etc", "a/b", "", ".hidden", "a@b", "sp ace"] {
            assert!(c.index_url(bad).is_err(), "must reject {bad:?}");
        }
    }

    #[test]
    fn sha256_shape_and_segments() {
        assert!(decode_sha256(&"0".repeat(64)).is_ok());
        assert!(decode_sha256(&"0".repeat(63)).is_err());
        assert!(decode_sha256(&"g".repeat(64)).is_err());
        assert!(validate_segment("1.0.0", "version").is_ok());
        assert!(validate_segment("1.0.0/../x", "version").is_err());
    }
}
