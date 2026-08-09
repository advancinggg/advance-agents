//! Recursive dependency install helper (Slice B, AC-08; extended Slice D
//! AC-05 for cross-source recursion).
//!
//! Exposes `DependencyResolver` seam trait and `install_deps_recursive` helper
//! invoked from step ⑤ of `Installer::install_with_context`. Algorithm:
//!
//! 1. Depth cap FIRST: if `depth + 1 > 32` → `DependencyDepthExceeded`.
//! 2. Parse `dep.version` as `semver::VersionReq`.
//! 3. Dedup check via registry: `find_installed_satisfying(name, &req)` Some(_) →
//!    skip.
//! 4. Cycle check: if `(name, version_req_str)` is in `in_flight` Vec → render
//!    cycle path (DFS-stack order; root NOT included).
//! 5. Push `(name, version_req_str)` to `in_flight` BEFORE recursion.
//! 6. Resolver returns `SourceRef` → re-enter `installer.install_with_context`
//!    for ALL 4 source variants (Slice D: was Local-only in Slice B; now
//!    git+https/file + tarball + registry + Local all dispatch uniformly via
//!    direct `&SourceRef` recursion, no stringify/reparse).
//! 7. Post-install version validation: `find_installed_satisfying` confirms the
//!    resolver delivered a satisfying concrete version → `DependencyVersionMismatch`
//!    on miss.
//! 8. Pop `in_flight` after success (DFS discipline).

use std::future::Future;
use std::pin::Pin;

use async_trait::async_trait;

use crate::error::PackError;
use crate::install::Installer;
use crate::manifest::PackDependency;
use crate::source::SourceRef;

const MAX_DEP_DEPTH: usize = 32;

#[async_trait]
pub trait DependencyResolver: Send + Sync {
    async fn resolve(&self, name: &str, req: &semver::VersionReq) -> Result<SourceRef, PackError>;
}

/// Recursive install helper. Returns `Pin<Box<dyn Future>>` to allow async
/// recursion (Rust async fn can't directly recurse without boxing).
pub(crate) fn install_deps_recursive<'a>(
    installer: &'a Installer,
    resolver: &'a dyn DependencyResolver,
    deps: &'a [PackDependency],
    depth: usize,
    in_flight: &'a mut Vec<(String, String)>,
) -> Pin<Box<dyn Future<Output = Result<(), PackError>> + Send + 'a>> {
    Box::pin(async move {
        for dep in deps {
            // ① Depth cap FIRST.
            if depth + 1 > MAX_DEP_DEPTH {
                return Err(PackError::DependencyDepthExceeded {
                    max_depth: MAX_DEP_DEPTH,
                    name: dep.name.clone(),
                });
            }

            // ② Parse version_req.
            let req = semver::VersionReq::parse(&dep.version).map_err(|e| {
                PackError::InvalidManifest(format!(
                    "dependency {:?} version {:?} not a valid SemVer range: {e}",
                    dep.name, dep.version
                ))
            })?;

            // ③ Registry dedup check.
            if installer
                .registry
                .find_installed_satisfying(&dep.name, &req)
                .is_some()
            {
                continue;
            }

            // ④ Cycle check.
            let key = (dep.name.clone(), dep.version.clone());
            if in_flight.iter().any(|k| k == &key) {
                let mut cycle_names: Vec<String> =
                    in_flight.iter().map(|(n, _)| n.clone()).collect();
                cycle_names.push(dep.name.clone());
                return Err(PackError::DependencyCycle { path: cycle_names });
            }

            // ⑤ Push BEFORE recursion (DFS discipline).
            in_flight.push(key);

            // ⑥ Resolve via seam.
            let source_ref = resolver.resolve(&dep.name, &req).await?;

            // ⑦ Re-enter install — Slice D: all 4 source types via direct
            //    &SourceRef recursion (no stringify/reparse round-trip).
            //    install_with_context takes &SourceRef and applies validate()
            //    invariant gate before fetch.
            //
            //    ADVERSARIAL round-1 Codex W7 fix: bind the resolved pack's
            //    name+version identity back to the requested dep selector.
            //    Without this, a hostile resolver could return a `wrapper`
            //    SourceRef whose pack.yaml declares a different name but
            //    transitively installs a `foo` dep that satisfies the
            //    request — then `find_installed_satisfying` below succeeds
            //    while the unauthorized wrapper pack remains installed.
            let report = installer
                .install_with_context(&source_ref, in_flight, depth + 1)
                .await?;
            if report.name != dep.name {
                return Err(PackError::DependencyVersionMismatch {
                    name: dep.name.clone(),
                    required: dep.version.clone(),
                    found: format!(
                        "resolver returned pack with manifest name {:?} (expected {:?}); \
                         possible substitution-attack rejected",
                        report.name, dep.name
                    ),
                });
            }
            if !req.matches(&semver::Version::parse(&report.version).map_err(|e| {
                PackError::InvalidManifest(format!(
                    "resolver-installed pack {:?} has non-SemVer version {:?}: {e}",
                    report.name, report.version
                ))
            })?) {
                return Err(PackError::DependencyVersionMismatch {
                    name: dep.name.clone(),
                    required: dep.version.clone(),
                    found: report.version,
                });
            }

            // ⑧ Post-install version validation.
            let installed = installer
                .registry
                .find_installed_satisfying(&dep.name, &req);
            match installed {
                Some(_) => {
                    // ⑨ Pop AFTER successful recursion.
                    in_flight.pop();
                }
                None => {
                    return Err(PackError::DependencyVersionMismatch {
                        name: dep.name.clone(),
                        required: dep.version.clone(),
                        found: "<no installed version satisfies req after resolver returned>"
                            .to_string(),
                    });
                }
            }
        }
        Ok(())
    })
}
