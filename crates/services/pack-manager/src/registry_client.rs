//! Slice D — `RegistryClient` async seam for the `registry:name@version`
//! install source type (AC-05 / REQ-344). M018-internal seam (NOT promoted to
//! ARCH §6.1 contract registry — matches the `DependencyResolver` /
//! `WorkflowExecutor` / `SecretStore` precedent).
//!
//! Slice D ships the seam + a `MockRegistryClient` test helper. Production
//! HTTPS registry endpoint implementation (URL parsing, TLS, retry policy) is
//! a Slice D+ concern; PRD §19.5 lists registry as "future".
//!
//! Visibility model: both `RegistryClient` and `MockRegistryClient` are
//! unconditionally `pub` (NOT `#[cfg(test)]`-gated) so integration tests under
//! `tests/` can construct the mock. Matches the `RecordingTraceSink` precedent
//! at `install.rs:99` — a test-oriented impl that's `pub`-exported because Rust
//! integration tests compile as a separate crate consuming only the public API.
//! Doc comment on `MockRegistryClient` marks it as "Test/integration helper
//! — not production code".

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use async_trait::async_trait;

use crate::error::PackError;

/// Slice D — M018-internal seam for registry source-type fetch dispatch.
/// `Installer.registry_client: Option<Arc<dyn RegistryClient>>` carries the
/// optional production impl; when `None` and a registry source is requested,
/// `FetchContext::fetch_to_temp` surfaces `InvalidManifest("registry source
/// declared but no RegistryClient configured")` (matches `DependencyResolver`
/// Option-None pattern).
#[async_trait]
pub trait RegistryClient: Send + Sync {
    /// Fetch the pack tarball for `name@version` into `dest_dir` (caller-
    /// managed parent directory; typically a `tempfile::TempDir` child path).
    /// Returns the absolute path to the resulting `.tar.gz` blob, which the
    /// installer's tarball fetcher then untars.
    async fn fetch_tarball(
        &self,
        name: &str,
        version: &str,
        dest_dir: &Path,
    ) -> Result<PathBuf, PackError>;
}

/// Test/integration helper — NOT production code. Maps `(name, version)` →
/// pre-built fixture tarball path. `fetch_tarball` copies the fixture to
/// `dest_dir`. Override entries via the `set_*` helpers below to inject
/// failure modes (delay-then-fail for timeout tests; explicit-error for
/// client-error-propagation tests).
pub struct MockRegistryClient {
    /// `(name, version)` → fixture tarball path on disk.
    fixtures: Mutex<HashMap<(String, String), PathBuf>>,
    /// Optional injected behavior for failure-mode coverage (T80b).
    behavior: Mutex<MockBehavior>,
}

enum MockBehavior {
    /// Normal mode: look up fixture, copy to dest_dir, return path.
    CopyFixture,
    /// Sleep for the given duration before responding. Combined with
    /// `Installer.fetch_timeout` shorter than this duration, exercises the
    /// timeout-bounded RegistryFetchFailed path.
    SleepThenCopy(std::time::Duration),
    /// Always return the given error verbatim (cloned per call). Exercises
    /// client-side error-propagation surface.
    ErrFn(fn(&str, &str) -> PackError),
}

impl Default for MockRegistryClient {
    fn default() -> Self {
        Self::new()
    }
}

impl MockRegistryClient {
    pub fn new() -> Self {
        Self {
            fixtures: Mutex::new(HashMap::new()),
            behavior: Mutex::new(MockBehavior::CopyFixture),
        }
    }

    /// Register a fixture mapping. Subsequent `fetch_tarball(name, version,
    /// dest_dir)` calls will copy this fixture into `dest_dir`.
    pub fn insert_fixture(&self, name: &str, version: &str, fixture: PathBuf) {
        self.fixtures
            .lock()
            .unwrap()
            .insert((name.to_string(), version.to_string()), fixture);
    }

    /// Inject sleep-then-copy behavior — combined with a short
    /// `Installer.fetch_timeout` triggers the registry timeout path (AC-05
    /// T80b case 1).
    pub fn set_sleep(&self, duration: std::time::Duration) {
        *self.behavior.lock().unwrap() = MockBehavior::SleepThenCopy(duration);
    }

    /// Inject error-returning behavior — `f` is called with `(name, version)`
    /// and the returned `PackError` is propagated via `??` to exercise the
    /// client-returned error surface (AC-05 T80b cases 2-3).
    pub fn set_err_fn(&self, f: fn(&str, &str) -> PackError) {
        *self.behavior.lock().unwrap() = MockBehavior::ErrFn(f);
    }
}

#[async_trait]
impl RegistryClient for MockRegistryClient {
    async fn fetch_tarball(
        &self,
        name: &str,
        version: &str,
        dest_dir: &Path,
    ) -> Result<PathBuf, PackError> {
        // Snapshot the behavior so the async path doesn't hold the lock across
        // an `.await`.
        let behavior = {
            let guard = self.behavior.lock().unwrap();
            match &*guard {
                MockBehavior::CopyFixture => MockBehaviorRun::CopyFixture,
                MockBehavior::SleepThenCopy(d) => MockBehaviorRun::SleepThenCopy(*d),
                MockBehavior::ErrFn(f) => MockBehaviorRun::ErrFn(*f),
            }
        };
        match behavior {
            MockBehaviorRun::CopyFixture => self.copy_fixture(name, version, dest_dir).await,
            MockBehaviorRun::SleepThenCopy(d) => {
                tokio::time::sleep(d).await;
                self.copy_fixture(name, version, dest_dir).await
            }
            MockBehaviorRun::ErrFn(f) => Err(f(name, version)),
        }
    }
}

enum MockBehaviorRun {
    CopyFixture,
    SleepThenCopy(std::time::Duration),
    ErrFn(fn(&str, &str) -> PackError),
}

impl MockRegistryClient {
    async fn copy_fixture(
        &self,
        name: &str,
        version: &str,
        dest_dir: &Path,
    ) -> Result<PathBuf, PackError> {
        let fixture = {
            let guard = self.fixtures.lock().unwrap();
            guard
                .get(&(name.to_string(), version.to_string()))
                .cloned()
                .ok_or_else(|| PackError::RegistryFetchFailed {
                    name: name.to_string(),
                    version: version.to_string(),
                    reason: "no fixture registered for this name@version".into(),
                })?
        };
        let dest = dest_dir.join(format!("{name}-{version}.tar.gz"));
        std::fs::create_dir_all(dest_dir).map_err(|e| PackError::Io {
            path: dest_dir.to_path_buf(),
            source: e,
        })?;
        std::fs::copy(&fixture, &dest).map_err(|e| PackError::Io {
            path: dest.clone(),
            source: e,
        })?;
        Ok(dest)
    }
}
