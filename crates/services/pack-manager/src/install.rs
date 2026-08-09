//! 8-step Installer per MODULE-018 §1.3.2 / PRD §19.5.
//!
//! Slice A scope: Local source only; non-empty `dependencies:` surfaced
//! `NotImplemented` at step ⑤. Slice B adds recursive dependency install for
//! Local-source deps (DFS with cycle detection + 32-level depth cap + diamond
//! dedup via registry). Non-Local sources still surface `NotImplemented` at step
//! ②. AC-05 still partial (full 8-step verbatim awaits non-Local fetchers).

use std::path::{Path, PathBuf};
use std::sync::Arc;

use advance_shared_types::event::Event;
use advance_shared_types::traits::EventBusEmit;
use async_trait::async_trait;
use serde_json::json;

/// Maximum permitted `pack.yaml` size in bytes — 1 MiB. Generously sized
/// for any realistic manifest (the spec example fits in ~2 KiB); rejecting
/// larger inputs at read time bounds parser/allocator cost during step ③
/// and prevents adversarial sources from supplying multi-GiB documents.
/// (Round-9 adversarial W4.)
const MAX_PACK_YAML_BYTES: u64 = 1024 * 1024;

use crate::{
    deps::DependencyResolver,
    error::PackError,
    fetch::{copy_dir_no_symlinks, FetchContext},
    manifest::{PackManifest, PackProvides},
    meta::{read_meta_index, write_meta_index_atomic, MetaPackEntry},
    registry::{path_for_kind, ComponentKind, InMemoryPackRegistry, PackRegistry},
    registry_client::RegistryClient,
    source::{parse_source, SourceRef},
    verify::verify_checksums,
};

pub struct Installer {
    pub packs_dir: PathBuf,
    pub registry: Arc<InMemoryPackRegistry>,
    pub current_runtime_version: String,
    pub approval: Arc<dyn ApprovalStrategy>,
    pub trace_sink: Arc<dyn InstallTraceSink>,
    /// Slice B: optional dependency resolver. When `None` and a pack declares
    /// non-empty `dependencies:`, step ⑤ returns
    /// `InvalidManifest("dependencies declared but no DependencyResolver configured")`.
    pub dep_resolver: Option<Arc<dyn DependencyResolver>>,
    /// Slice C: optional EventBus emit hook (CONTRACT-180). When `Some`,
    /// the public `install` method emits **exactly one**
    /// `pack.registry_reloaded` event per top-level install call (AC-15,
    /// REQ-344). Recursive sub-installs invoked through
    /// `install_with_context` from `deps::install_deps_recursive` do NOT
    /// fire their own event — one top-level install action = one event.
    /// When `None`, install path is observably silent.
    ///
    /// Cross-module note: M019 taxonomy registration of
    /// `pack.registry_reloaded` as a documented extension is a Slice C+
    /// follow-up (§3.6 Known Gaps row). MockBus tests in pack-manager do
    /// NOT enforce taxonomy validation, so the emit contract holds
    /// regardless of M019's current registration state.
    pub event_bus: Option<Arc<dyn EventBusEmit>>,
    /// Slice D: optional `RegistryClient` seam for `registry:name@version`
    /// source-type dispatch (AC-05). When `None` and the source is
    /// `SourceRef::Registry`, step ② fetch_to_temp surfaces
    /// `InvalidManifest("registry source declared but no RegistryClient
    /// configured")` — matches the `DependencyResolver` Option-None pattern
    /// for the resolver-missing case.
    pub registry_client: Option<Arc<dyn RegistryClient>>,
    /// Slice D: optional fetch wall-clock timeout. Honored by `fetch_git_to_temp`
    /// (subprocess `git clone` via `tokio::time::timeout`) and by
    /// `RegistryClient::fetch_tarball` (async timeout). Defaults to 120 seconds
    /// when `None` (matches §2.10 `pack.fetch_timeout_sec` documented default).
    /// Runtime-config plumbing from `runtime-config.yaml` is Slice D+.
    pub fetch_timeout: Option<std::time::Duration>,
}

#[async_trait]
pub trait ApprovalStrategy: Send + Sync {
    async fn approve(&self, manifest: &PackManifest) -> Result<bool, PackError>;
}

pub struct AutoApprove;

#[async_trait]
impl ApprovalStrategy for AutoApprove {
    async fn approve(&self, _: &PackManifest) -> Result<bool, PackError> {
        Ok(true)
    }
}

pub struct AutoReject;

#[async_trait]
impl ApprovalStrategy for AutoReject {
    async fn approve(&self, _: &PackManifest) -> Result<bool, PackError> {
        Ok(false)
    }
}

pub trait InstallTraceSink: Send + Sync {
    fn trace(&self, step: InstallStep, payload: serde_json::Value);
}

/// Test/integration helper — captures the full trace sequence for AC-05/AC-06
/// ordering assertions.
///
/// `events` is wrapped in a `std::sync::Mutex` so the sink is `Sync` for the
/// async `Installer::install` path. `.unwrap()` on `.lock()` is the canonical
/// poison-handling pattern: a poisoned mutex means another thread panicked
/// mid-push, in which case the captured trace is ambiguous and the test
/// harness should crash rather than observe partial data. The Slice A
/// single-process admin-CLI invariant guarantees no real contention; if
/// multi-thread test fixtures grow up in Slice B+, switch to `parking_lot`
/// (no poison) or explicit `PoisonError` handling.
pub struct RecordingTraceSink {
    pub events: std::sync::Mutex<Vec<(InstallStep, serde_json::Value)>>,
}

impl Default for RecordingTraceSink {
    fn default() -> Self {
        Self {
            events: std::sync::Mutex::new(Vec::new()),
        }
    }
}

impl RecordingTraceSink {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn steps(&self) -> Vec<InstallStep> {
        self.events
            .lock()
            .unwrap()
            .iter()
            .map(|(s, _)| *s)
            .collect()
    }
}

impl InstallTraceSink for RecordingTraceSink {
    fn trace(&self, step: InstallStep, payload: serde_json::Value) {
        self.events.lock().unwrap().push((step, payload));
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum InstallStep {
    Step1ParseSource,
    Step2DownloadToTemp,
    Step3VerifyChecksums,
    Step4AdminApproval,
    Step5RecursiveDeps,
    Step6CopyToInstallDir,
    Step7UpdateMetaIndex,
    Step8RegistryRescan,
}

#[derive(Debug, Clone)]
pub struct PackInstallReport {
    pub name: String,
    pub version: String,
    pub install_path: PathBuf,
    pub trace_steps: Vec<InstallStep>,
}

impl Installer {
    /// Public entry — allocates a fresh `in_flight` Vec for cycle detection,
    /// delegates to `install_with_context`, and emits a single AC-15
    /// `pack.registry_reloaded` event on the top-level install boundary
    /// (NOT per recursive sub-install).
    pub async fn install(&self, source: &str) -> Result<PackInstallReport, PackError> {
        // Slice D: parse_source ONCE at public entry. On error, emit
        // Step1ParseSource trace BEFORE returning so AC-05 "each step emits a
        // trace event" holds even for parse-error path. On success, forward
        // &src to install_with_context (owns happy-path Step1 emission).
        let src = match parse_source(source) {
            Ok(src) => src,
            Err(e) => {
                self.trace_sink.trace(
                    InstallStep::Step1ParseSource,
                    json!({"source": source, "parse_error": format!("{e}")}),
                );
                return Err(e);
            }
        };
        let mut in_flight: Vec<(String, String)> = Vec::new();
        let report = self.install_with_context(&src, &mut in_flight, 0).await?;

        // Slice C: AC-15 single `pack.registry_reloaded` event per
        // top-level install. Emitted here (not inside install_with_context)
        // so recursive dep installs do NOT each fire their own event —
        // one install action, one event. Per CONTRACT-180 Event invariants:
        // UUID v4 for id / trace_id / span_id; all five Option fields None;
        // agent_id = "pack-manager" (admin-side service, not an agent).
        if let Some(bus) = &self.event_bus {
            let pack_count = self.registry.list_installed().len();
            let installed_pack = format!("{}@{}", report.name, report.version);
            let event = Event {
                id: uuid::Uuid::new_v4().to_string(),
                timestamp: chrono::Utc::now(),
                agent_id: "pack-manager".to_string(),
                task_id: None,
                run_id: None,
                execution_id: None,
                trace_id: uuid::Uuid::new_v4().to_string(),
                span_id: uuid::Uuid::new_v4().to_string(),
                parent_span_id: None,
                event_type: "pack.registry_reloaded".to_string(),
                payload: json!({
                    "pack_count": pack_count,
                    "installed_pack": installed_pack,
                }),
                duration_ms: None,
            };
            bus.emit(event);
        }

        Ok(report)
    }

    /// Recursive entry — threads `in_flight` (DFS stack of `(name, version_req)`)
    /// and `depth` through nested install calls. Used by step ⑤ recursive deps.
    /// Slice D: signature changed from `(&str)` to `(&SourceRef)` — eliminates
    /// the stringify/reparse round-trip on the recursive path. Body order:
    /// (1) emit Step1ParseSource trace with `src.source_form()` payload;
    /// (2) call `src.validate()?` invariant gate;
    /// (3) continue with Step2DownloadToTemp via FetchContext dispatch;
    /// (4) remaining steps ③-⑧ unchanged.
    pub(crate) async fn install_with_context(
        &self,
        src: &SourceRef,
        in_flight: &mut Vec<(String, String)>,
        depth: usize,
    ) -> Result<PackInstallReport, PackError> {
        let mut trace: Vec<InstallStep> = Vec::new();

        // ① Step1 trace fires FIRST (with src.source_form() payload), then
        // validate runs — so trace fires even when validate() rejects a
        // resolver-injected invalid SourceRef (AC-05 "each step emits a trace
        // event" preserved).
        self.trace_sink.trace(
            InstallStep::Step1ParseSource,
            json!({"source": src.source_form()}),
        );
        trace.push(InstallStep::Step1ParseSource);
        src.validate()?;

        // ② download / clone to temp — Slice D: FetchContext dispatch to all 4
        // source types (Local / git+ / tarball / registry).
        self.trace_sink.trace(
            InstallStep::Step2DownloadToTemp,
            json!({"src_kind": src.kind_str()}),
        );
        trace.push(InstallStep::Step2DownloadToTemp);
        let ctx = FetchContext {
            registry_client: self.registry_client.as_deref(),
            fetch_timeout: self
                .fetch_timeout
                .unwrap_or(std::time::Duration::from_secs(120)),
        };
        let tmp = ctx.fetch_to_temp(src).await?;

        // ③ verify pack.yaml + checksums (parse, runtime-version, checksums)
        self.trace_sink
            .trace(InstallStep::Step3VerifyChecksums, json!({}));
        trace.push(InstallStep::Step3VerifyChecksums);
        let pack_yaml_path = tmp.path().join("pack.yaml");
        // Round-9 adversarial W4: bound pack.yaml size before reading.
        // symlink_metadata also rejects a pack.yaml that's a symlink — the
        // step ② source-side walk should have caught this, but defense-in-
        // depth here is cheap (one syscall).
        let pack_yaml_md =
            std::fs::symlink_metadata(&pack_yaml_path).map_err(|e| PackError::Io {
                path: pack_yaml_path.clone(),
                source: e,
            })?;
        if pack_yaml_md.file_type().is_symlink() {
            return Err(PackError::InvalidManifest(format!(
                "pack.yaml is a symlink (rejected): {}",
                pack_yaml_path.display()
            )));
        }
        if pack_yaml_md.len() > MAX_PACK_YAML_BYTES {
            return Err(PackError::InvalidManifest(format!(
                "pack.yaml exceeds max size {MAX_PACK_YAML_BYTES} bytes ({} bytes)",
                pack_yaml_md.len()
            )));
        }
        let yaml = std::fs::read_to_string(&pack_yaml_path).map_err(|e| PackError::Io {
            path: pack_yaml_path.clone(),
            source: e,
        })?;
        let manifest = PackManifest::from_yaml(&yaml)?;
        manifest.check_runtime_compat(&self.current_runtime_version)?;
        verify_checksums(tmp.path(), &manifest.checksums)?;

        // Slice D AUDIT round-1 Codex Diff W1 fix — registry source identity
        // binding: when the source is `registry:<name>@<version>`, the
        // downloaded archive's manifest MUST match the requested selector.
        // Without this gate, a buggy or hostile RegistryClient could return
        // an archive for a DIFFERENT pack (e.g. `bar@9.0.0`) when asked for
        // `foo@1.0.0`, and pack-manager would silently install it under the
        // wrong name. Manifest-internal checksums don't detect this — they
        // only verify the manifest's claimed files match SHA, not that the
        // manifest itself matches the request.
        if let SourceRef::Registry {
            name: req_name,
            version: req_version,
        } = src
        {
            if manifest.name != *req_name {
                return Err(PackError::InvalidManifest(format!(
                    "registry identity mismatch: requested name {req_name}, \
                     archive manifest says {}",
                    manifest.name
                )));
            }
            // ADVERSARIAL round-2 Claude Warning fix: use SemVer match (not
            // byte equality) for the version binding so equivalent versions
            // like `1.0.0` and `1.0.0+build.1` are accepted as the same
            // release per SemVer §10. Consistent with deps.rs:121 which uses
            // VersionReq::matches via semver. The byte-equality fallback
            // would have rejected legitimate registry-stamp variants.
            let manifest_ver = semver::Version::parse(&manifest.version).map_err(|e| {
                PackError::InvalidManifest(format!(
                    "archive manifest version {:?} is not valid SemVer: {e}",
                    manifest.version
                ))
            })?;
            let req_ver = semver::Version::parse(req_version).map_err(|e| {
                PackError::InvalidManifest(format!(
                    "registry source version {:?} is not valid SemVer: {e}",
                    req_version
                ))
            })?;
            if manifest_ver != req_ver {
                return Err(PackError::InvalidManifest(format!(
                    "registry identity mismatch: requested {req_name}@{req_version}, \
                     archive manifest says {}@{}",
                    manifest.name, manifest.version
                )));
            }
        }

        // ④ admin approval — AC-06 invariant: runs AFTER ③.
        // ADVERSARIAL round-2 Claude Critical fix: include manifest.name +
        // manifest.version in the approval-step trace payload so the admin
        // can verify pack identity before approving. Without this, an admin
        // approving `git+https://attacker.example/looks-innocent.git` could
        // unknowingly install a pack whose manifest claims a high-trust
        // identity (e.g. `claude-code@99.0.0`) — a top-level analogue of the
        // resolver-substitution attack closed in deps.rs (commit 8d11e78).
        // The admin-side approval UI (`ApprovalStrategy::approve`) receives
        // the full `&PackManifest` already, so InteractiveApproval can
        // display name + version; this trace addition surfaces the binding
        // in the audit log too.
        self.trace_sink.trace(
            InstallStep::Step4AdminApproval,
            json!({
                "pack_name": &manifest.name,
                "pack_version": &manifest.version,
                "required_capabilities": &manifest.required_capabilities,
                "trust_level": &manifest.trust_level,
            }),
        );
        trace.push(InstallStep::Step4AdminApproval);
        if !self.approval.approve(&manifest).await? {
            return Err(PackError::AdminRejected);
        }

        // ⑤ recursive deps — Slice B: DFS install via DependencyResolver seam.
        self.trace_sink.trace(
            InstallStep::Step5RecursiveDeps,
            json!({"deps_count": manifest.dependencies.len(), "depth": depth}),
        );
        trace.push(InstallStep::Step5RecursiveDeps);
        if !manifest.dependencies.is_empty() {
            let resolver = self.dep_resolver.as_ref().ok_or_else(|| {
                PackError::InvalidManifest(
                    "dependencies declared but no DependencyResolver configured".into(),
                )
            })?;
            crate::deps::install_deps_recursive(
                self,
                resolver.as_ref(),
                &manifest.dependencies,
                depth,
                in_flight,
            )
            .await?;
        }

        // ⑥ copy to /.advance/packs/{name}@{version}/
        let install_path = self
            .packs_dir
            .join(format!("{}@{}", manifest.name, manifest.version));
        self.trace_sink.trace(
            InstallStep::Step6CopyToInstallDir,
            json!({"install_path": install_path.display().to_string()}),
        );
        trace.push(InstallStep::Step6CopyToInstallDir);
        std::fs::create_dir_all(&self.packs_dir).map_err(|e| PackError::Io {
            path: self.packs_dir.clone(),
            source: e,
        })?;
        copy_dir_no_symlinks(tmp.path(), &install_path)?;

        // Slice C: AC-03 layout discipline. Inline inside the step ⑥ window
        // (no new InstallStep enum variant, no new trace event — preserves
        // verbatim 8-step PRD §19.5 order). A non-conformant layout fails
        // install with InvalidManifest before ⑥a fires.
        crate::layout::validate_pack_layout(&install_path)?;

        // ⑥a verify every `provides[*]` entry has the matching on-disk artifact
        //     at its canonical §19.3 path — closes the gap where a manifest can
        //     declare components that don't exist on disk, leaving `resolve()`
        //     to return dead paths at runtime. Symlinks at the declared path
        //     are also rejected (consistent with copy_dir_no_symlinks).
        verify_provides_on_disk(&install_path, &manifest.provides)?;

        // ⑥b AC-29 point 1 (m017-slice-l): validate each installed skill bundle's
        //     OPTIONAL `skills/<name>/tool.wasm` exports the `tool-exports` contract
        //     (via the cap-tools validator, CONTRACT-163). Runs AFTER ⑥a so each
        //     skill's directory-shape is already validated; a skill without a
        //     tool.wasm is a knowledge-only skill and is skipped. No new InstallStep
        //     / trace event — preserves the verbatim 8-step PRD §19.5 order, same
        //     discipline as ⑥ layout / ⑥a provides checks.
        verify_skill_tool_exports(&install_path, &manifest.provides.skills)?;

        // ⑥c AC-17 (m018-rescap): validate each declared resource-capability's
        //     `capability.yaml` shape (ADR Decision 3). Runs after ⑥a existence + ⑥b
        //     skill exports; a malformed manifest fails install with
        //     InvalidManifest/ConstraintViolation. Same no-new-InstallStep / no-new-trace
        //     discipline as ⑥ layout / ⑥a provides / ⑥b skill-exports. INSTALL-ONLY (matching
        //     `verify_skill_tool_exports`): rescan (registry.rs) re-checks existence via
        //     `verify_provides_on_disk`, and a post-install shape tamper is caught on-demand at
        //     `register_resource_capability` — see this fn's doc + the round-12 rescan-fan-out note.
        verify_resource_capabilities(&install_path, &manifest.provides.resource_capabilities)?;

        // ⑦ update /.advance/packs/.meta.yaml (atomic rename)
        self.trace_sink
            .trace(InstallStep::Step7UpdateMetaIndex, json!({}));
        trace.push(InstallStep::Step7UpdateMetaIndex);
        let mut idx = read_meta_index(&self.packs_dir)?;
        idx.packs.insert(
            format!("{}@{}", manifest.name, manifest.version),
            MetaPackEntry {
                description: manifest.description.clone(),
                installed_at: chrono::Utc::now().to_rfc3339(),
                required_capabilities: manifest.required_capabilities.clone(),
                trust_level: manifest.trust_level,
            },
        );
        write_meta_index_atomic(&self.packs_dir, &idx)?;

        // ⑧ runtime pack-registry rescan — async no-arg per §1.3.2 line 124
        self.trace_sink
            .trace(InstallStep::Step8RegistryRescan, json!({}));
        trace.push(InstallStep::Step8RegistryRescan);
        self.registry.rescan().await?;

        // Slice C: AC-15 `pack.registry_reloaded` event is emitted ONCE
        // per TOP-LEVEL `Installer::install` call, from the public `install`
        // method above — NOT here. Recursive sub-installs share their
        // parent's install action and must NOT each fire their own event.

        Ok(PackInstallReport {
            name: manifest.name,
            version: manifest.version,
            install_path,
            trace_steps: trace,
        })
    }
}

/// Walk `manifest.provides` and verify every declared component has a
/// matching on-disk artifact at its canonical §19.3 path. File-backed kinds
/// (binary/mcp-server/preset/workflow/memory-seed/meta-schema-extension)
/// require a regular file; directory-backed kinds (agent-template/skill/
/// runnable-component/channel-adapter) require a directory. Symlinks are
/// rejected at the artifact path (consistent with the no-symlink invariant
/// enforced by `copy_dir_no_symlinks`). Catches manifest drift at install
/// time rather than as a runtime `resolve()` dead-path.
///
/// `pub(crate)` so that `registry::rescan` can re-run this check on every
/// rescan — closes Codex r3 W1 (rescan trusts on-disk pack contents
/// without re-running install-time integrity checks). Re-checksumming on
/// rescan remains a Slice B concern (potentially expensive); per-artifact
/// stat is cheap and catches deletion / wrong-type / symlink-swap tampers.
pub(crate) fn verify_provides_on_disk(
    install_path: &Path,
    provides: &PackProvides,
) -> Result<(), PackError> {
    // Round-9 adversarial Codex W2: canonicalize the install_path ONCE
    // and ancestor-check every artifact's canonical path against it.
    // Without this an attacker who races between step ⑥ and step ⑥a (e.g.
    // by swapping `install_path/behavior-binaries/` for a symlink to
    // `/etc/`) can satisfy the leaf `symlink_metadata` check (since the
    // leaf is a regular file at the target) while still pointing
    // `path_for_kind` outside the pack root.
    let install_canon = std::fs::canonicalize(install_path).map_err(|e| PackError::Io {
        path: install_path.to_path_buf(),
        source: e,
    })?;
    let file_groups: &[(ComponentKind, &Vec<String>)] = &[
        (ComponentKind::Binary, &provides.behavior_binaries),
        (ComponentKind::McpServer, &provides.mcp_servers),
        (ComponentKind::Preset, &provides.presets),
        (ComponentKind::Workflow, &provides.workflows),
        (ComponentKind::MemorySeed, &provides.memory_seeds),
        (
            ComponentKind::MetaSchemaExtension,
            &provides.meta_schema_extensions,
        ),
    ];
    let dir_groups: &[(ComponentKind, &Vec<String>)] = &[
        (ComponentKind::AgentTemplate, &provides.agent_templates),
        (ComponentKind::Skill, &provides.skills),
        (ComponentKind::RunnableComponent, &provides.components),
        (ComponentKind::ChannelAdapter, &provides.channel_adapters),
    ];
    for (kind, names) in file_groups {
        for name in *names {
            let p = path_for_kind(install_path, *kind, name);
            let md = std::fs::symlink_metadata(&p).map_err(|e| match e.kind() {
                std::io::ErrorKind::NotFound => PackError::InvalidManifest(format!(
                    "provides[{kind:?}] declares '{name}' but missing on disk: {}",
                    p.display()
                )),
                _ => PackError::Io {
                    path: p.clone(),
                    source: e,
                },
            })?;
            if md.file_type().is_symlink() {
                return Err(PackError::InvalidManifest(format!(
                    "provides[{kind:?}] '{name}' is a symlink (rejected): {}",
                    p.display()
                )));
            }
            if !md.is_file() {
                return Err(PackError::InvalidManifest(format!(
                    "provides[{kind:?}] '{name}' must be a regular file: {}",
                    p.display()
                )));
            }
            // Defense-in-depth: canonicalize and confirm the resolved path
            // stays inside install_canon. Catches an intermediate symlink
            // swap on a parent directory between step ⑥ and step ⑥a.
            let canon = std::fs::canonicalize(&p).map_err(|e| PackError::Io {
                path: p.clone(),
                source: e,
            })?;
            if !canon.starts_with(&install_canon) {
                return Err(PackError::InvalidManifest(format!(
                    "provides[{kind:?}] '{name}' escapes install_path via intermediate symlink: {}",
                    p.display()
                )));
            }
        }
    }
    for (kind, names) in dir_groups {
        for name in *names {
            let p = path_for_kind(install_path, *kind, name);
            let md = std::fs::symlink_metadata(&p).map_err(|e| match e.kind() {
                std::io::ErrorKind::NotFound => PackError::InvalidManifest(format!(
                    "provides[{kind:?}] declares '{name}' but missing on disk: {}",
                    p.display()
                )),
                _ => PackError::Io {
                    path: p.clone(),
                    source: e,
                },
            })?;
            if md.file_type().is_symlink() {
                return Err(PackError::InvalidManifest(format!(
                    "provides[{kind:?}] '{name}' is a symlink (rejected): {}",
                    p.display()
                )));
            }
            if !md.is_dir() {
                return Err(PackError::InvalidManifest(format!(
                    "provides[{kind:?}] '{name}' must be a directory: {}",
                    p.display()
                )));
            }
            // Defense-in-depth canonicalize+ancestor check (see file-kind
            // branch above for rationale).
            let canon = std::fs::canonicalize(&p).map_err(|e| PackError::Io {
                path: p.clone(),
                source: e,
            })?;
            if !canon.starts_with(&install_canon) {
                return Err(PackError::InvalidManifest(format!(
                    "provides[{kind:?}] '{name}' escapes install_path via intermediate symlink: {}",
                    p.display()
                )));
            }
        }
    }
    // AC-17: resource-capabilities are directory-backed WITH a required inner
    // `capability.yaml`. verify_provides_on_disk enforces EXISTENCE (dir + manifest
    // file) at install AND on rescan (both call this fn); shape validation is the
    // separate `verify_resource_capabilities` pass. Same symlink-reject + canonicalize
    // ancestor discipline as the dir_groups loop above, plus the inner-file check.
    for name in &provides.resource_capabilities {
        let dir = path_for_kind(install_path, ComponentKind::ResourceCapability, name);
        let md = std::fs::symlink_metadata(&dir).map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => PackError::InvalidManifest(format!(
                "provides[ResourceCapability] declares '{name}' but missing on disk: {}",
                dir.display()
            )),
            _ => PackError::Io {
                path: dir.clone(),
                source: e,
            },
        })?;
        if md.file_type().is_symlink() {
            return Err(PackError::InvalidManifest(format!(
                "provides[ResourceCapability] '{name}' is a symlink (rejected): {}",
                dir.display()
            )));
        }
        if !md.is_dir() {
            return Err(PackError::InvalidManifest(format!(
                "provides[ResourceCapability] '{name}' must be a directory: {}",
                dir.display()
            )));
        }
        let canon = std::fs::canonicalize(&dir).map_err(|e| PackError::Io {
            path: dir.clone(),
            source: e,
        })?;
        if !canon.starts_with(&install_canon) {
            return Err(PackError::InvalidManifest(format!(
                "provides[ResourceCapability] '{name}' escapes install_path via intermediate symlink: {}",
                dir.display()
            )));
        }
        // Required inner manifest.
        let manifest = dir.join("capability.yaml");
        let mmd = std::fs::symlink_metadata(&manifest).map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => PackError::InvalidManifest(format!(
                "provides[ResourceCapability] '{name}' missing required capability.yaml: {}",
                manifest.display()
            )),
            _ => PackError::Io {
                path: manifest.clone(),
                source: e,
            },
        })?;
        if mmd.file_type().is_symlink() {
            return Err(PackError::InvalidManifest(format!(
                "provides[ResourceCapability] '{name}' capability.yaml is a symlink (rejected): {}",
                manifest.display()
            )));
        }
        if !mmd.is_file() {
            return Err(PackError::InvalidManifest(format!(
                "provides[ResourceCapability] '{name}' capability.yaml must be a regular file: {}",
                manifest.display()
            )));
        }
        let mcanon = std::fs::canonicalize(&manifest).map_err(|e| PackError::Io {
            path: manifest.clone(),
            source: e,
        })?;
        if !mcanon.starts_with(&install_canon) {
            return Err(PackError::InvalidManifest(format!(
                "provides[ResourceCapability] '{name}' capability.yaml escapes install_path: {}",
                manifest.display()
            )));
        }
    }
    Ok(())
}

/// AC-17 (m018-rescap) — validate the ADR Decision-3 shape of each declared
/// `resource-capabilities/{name}/capability.yaml`. Runs at INSTALL (step ⑥c) ONLY —
/// matching the `verify_skill_tool_exports` precedent (deep validation at install; cheap
/// existence re-check at rescan). Rescan re-checks EXISTENCE (dir + inner manifest) via
/// `verify_provides_on_disk`; a post-install shape tamper is caught on-demand by
/// `register_resource_capability`. Running this per-capability 1-MiB parse on every rescan
/// was an availability regression (adversarial round 12: rescan re-parse fan-out +
/// deep-nesting parse-DoS amplifier), so it is deliberately install-only. This pass PARSES
/// + validates via the same bounded / symlink-safe / alias-guarded / nesting-bounded read
/// gates. Registered-not-copied: read + validate only, nothing written.
///
/// `pub(crate)` so the §3.3 integration suite can exercise it directly.
pub(crate) fn verify_resource_capabilities(
    install_path: &Path,
    resource_capabilities: &[String],
) -> Result<(), PackError> {
    for name in resource_capabilities {
        let cap_dir = path_for_kind(install_path, ComponentKind::ResourceCapability, name);
        // Parse + validate; discard the manifest (this is the validation half). A
        // malformed manifest fails install/rescan with InvalidManifest/ConstraintViolation.
        let _ = crate::component_manifest::parse_resource_capability_manifest(&cap_dir)?;
    }
    Ok(())
}

/// AC-29 point 1 (m017-slice-l) — validate every installed skill bundle's
/// OPTIONAL `skills/<name>/tool.wasm` against the `tool-exports` contract via
/// the cap-tools validator (CONTRACT-163). A skill without a `tool.wasm` is a
/// knowledge-only skill (MODULE-017 AC-26) and is skipped. The read is
/// symlink-rejecting + size-bounded, matching the hardened install invariants
/// (`copy_dir_no_symlinks` already rejected symlinks at copy; the
/// `symlink_metadata` probe here is defense-in-depth on a post-copy swap).
///
/// `pub(crate)` so the inline test module + the §3.3 install-flow integration
/// suite can exercise it directly.
pub(crate) fn verify_skill_tool_exports(
    install_path: &Path,
    skills: &[String],
) -> Result<(), PackError> {
    /// Cap on a single `tool.wasm` read — matches the 256 MiB per-artifact bound
    /// used elsewhere in the installer (verify.rs / materialize_impl.rs).
    const MAX_TOOL_WASM_BYTES: u64 = 256 * 1024 * 1024;
    use std::io::Read;
    for name in skills {
        // Canonical layout: `skills/<name>/tool.wasm` (directory-backed kind).
        let tool_wasm = path_for_kind(install_path, ComponentKind::Skill, name).join("tool.wasm");
        // Open with O_NOFOLLOW (Unix) so a symlink-swap of the leaf is rejected
        // at open, and fstat the OPEN handle so the size bound is enforced
        // against the SAME inode the bounded read consumes — closing the
        // stat/read TOCTOU that a bare `std::fs::read` after a path-stat would
        // leave open (adversarial round 4 W1). Mirrors
        // `materialize_impl.rs::read_bytes_nofollow_bounded` + `verify.rs`'s
        // streaming discipline (both name-cited on MAX_TOOL_WASM_BYTES above).
        #[cfg(unix)]
        let mut file = {
            use std::os::unix::fs::OpenOptionsExt;
            match std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW)
                .open(&tool_wasm)
            {
                Ok(f) => f,
                // Absent tool.wasm → knowledge-only skill; nothing to validate.
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                // O_NOFOLLOW returns ELOOP when the final component is a symlink.
                Err(e) if e.raw_os_error() == Some(libc::ELOOP) => {
                    return Err(PackError::InvalidManifest(format!(
                        "skill '{name}' tool.wasm is a symlink (rejected by O_NOFOLLOW): {}",
                        tool_wasm.display()
                    )));
                }
                Err(e) => {
                    return Err(PackError::Io {
                        path: tool_wasm,
                        source: e,
                    })
                }
            }
        };
        #[cfg(not(unix))]
        let mut file = match std::fs::OpenOptions::new().read(true).open(&tool_wasm) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => {
                return Err(PackError::Io {
                    path: tool_wasm,
                    source: e,
                })
            }
        };
        // fstat on the OPEN handle (not the path) — same inode the read consumes.
        let md = file.metadata().map_err(|e| PackError::Io {
            path: tool_wasm.clone(),
            source: e,
        })?;
        if !md.is_file() {
            return Err(PackError::InvalidManifest(format!(
                "skill '{name}' tool.wasm must be a regular file: {}",
                tool_wasm.display()
            )));
        }
        if md.len() > MAX_TOOL_WASM_BYTES {
            return Err(PackError::InvalidManifest(format!(
                "skill '{name}' tool.wasm exceeds max size {MAX_TOOL_WASM_BYTES} bytes ({} bytes)",
                md.len()
            )));
        }
        // Bounded read: `.take(MAX)` hard-caps the bytes pulled even if the inode
        // somehow grows between fstat and read (defense-in-depth on the fstat bound).
        let mut bytes = Vec::with_capacity(md.len() as usize);
        (&mut file)
            .take(MAX_TOOL_WASM_BYTES)
            .read_to_end(&mut bytes)
            .map_err(|e| PackError::Io {
                path: tool_wasm.clone(),
                source: e,
            })?;
        cap_tools::validate_tool_component(&bytes).map_err(|e| {
            PackError::InvalidManifest(format!(
                "skill '{name}' tool.wasm does not export tool-exports (AC-29): {e}"
            ))
        })?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    //! Round-6 W3: directly exercise the `verify_provides_on_disk` symlink
    //! rejection branch. The full install path can't reach this branch
    //! (step ② copy_dir_no_symlinks rejects symlinks in source before step ⑥a
    //! sees them), so the inner check is genuinely defense-in-depth — testable
    //! only by calling the helper directly with a pre-populated install_path.
    use super::*;
    use crate::manifest::PackProvides;

    #[test]
    fn verify_provides_rejects_symlink_at_file_artifact() {
        #[cfg(not(unix))]
        {
            eprintln!("symlink unit test skipped on non-Unix");
            return;
        }
        #[cfg(unix)]
        {
            let dir = tempfile::TempDir::new().unwrap();
            let install_path = dir.path().to_path_buf();
            std::fs::create_dir_all(install_path.join("behavior-binaries")).unwrap();
            // Create the artifact AS a symlink so the step ⑥a symlink branch
            // fires (bypasses step ② which would reject in normal install).
            let target = dir.path().join("real_tool.wasm");
            std::fs::write(&target, b"\x00").unwrap();
            std::os::unix::fs::symlink(
                &target,
                install_path.join("behavior-binaries").join("tool.wasm"),
            )
            .unwrap();

            let mut provides = PackProvides::default();
            provides.behavior_binaries.push("tool".into());

            match verify_provides_on_disk(&install_path, &provides) {
                Err(PackError::InvalidManifest(msg)) => assert!(
                    msg.contains("symlink") && msg.contains("Binary"),
                    "expected file-kind symlink rejection, got: {msg}"
                ),
                other => panic!("expected InvalidManifest(symlink), got {other:?}"),
            }
        }
    }

    #[test]
    fn verify_provides_rejects_symlink_at_directory_artifact() {
        #[cfg(not(unix))]
        {
            eprintln!("symlink unit test skipped on non-Unix");
            return;
        }
        #[cfg(unix)]
        {
            let dir = tempfile::TempDir::new().unwrap();
            let install_path = dir.path().to_path_buf();
            std::fs::create_dir_all(install_path.join("skills")).unwrap();
            // skill artifact AS a symlink → directory-backed kind path.
            let real_skill = dir.path().join("real_skill_dir");
            std::fs::create_dir_all(&real_skill).unwrap();
            std::os::unix::fs::symlink(&real_skill, install_path.join("skills").join("my-skill"))
                .unwrap();

            let mut provides = PackProvides::default();
            provides.skills.push("my-skill".into());

            match verify_provides_on_disk(&install_path, &provides) {
                Err(PackError::InvalidManifest(msg)) => assert!(
                    msg.contains("symlink") && msg.contains("Skill"),
                    "expected dir-kind symlink rejection, got: {msg}"
                ),
                other => panic!("expected InvalidManifest(symlink), got {other:?}"),
            }
        }
    }

    // AC-29 point 1 (m017-slice-l) — structural rejections of the skill
    // `tool.wasm` gate. The tool-exports validation accept/reject paths (which
    // need real Component bytes) are witnessed end-to-end through the installer
    // in `tests/skill_tool_exports.rs`.
    #[test]
    fn verify_skill_tool_exports_skips_absent_tool_wasm() {
        let dir = tempfile::TempDir::new().unwrap();
        let install_path = dir.path().to_path_buf();
        // Knowledge-only skill: directory exists, no tool.wasm → Ok (skipped).
        std::fs::create_dir_all(install_path.join("skills").join("knowledge-only")).unwrap();
        verify_skill_tool_exports(&install_path, &["knowledge-only".to_string()]).unwrap();
    }

    #[test]
    fn verify_skill_tool_exports_rejects_symlink_tool_wasm() {
        #[cfg(not(unix))]
        {
            eprintln!("symlink unit test skipped on non-Unix");
        }
        #[cfg(unix)]
        {
            let dir = tempfile::TempDir::new().unwrap();
            let install_path = dir.path().to_path_buf();
            std::fs::create_dir_all(install_path.join("skills").join("s")).unwrap();
            let target = dir.path().join("real_tool.wasm");
            std::fs::write(&target, b"\x00").unwrap();
            std::os::unix::fs::symlink(
                &target,
                install_path.join("skills").join("s").join("tool.wasm"),
            )
            .unwrap();
            match verify_skill_tool_exports(&install_path, &["s".to_string()]) {
                Err(PackError::InvalidManifest(msg)) => assert!(
                    msg.contains("symlink") && msg.contains("tool.wasm"),
                    "expected tool.wasm symlink rejection, got: {msg}"
                ),
                other => panic!("expected InvalidManifest(symlink), got {other:?}"),
            }
        }
    }

    #[test]
    fn verify_skill_tool_exports_rejects_non_regular_file() {
        let dir = tempfile::TempDir::new().unwrap();
        let install_path = dir.path().to_path_buf();
        // `skills/d/tool.wasm` is a DIRECTORY, not a regular file → rejected.
        std::fs::create_dir_all(install_path.join("skills").join("d").join("tool.wasm")).unwrap();
        match verify_skill_tool_exports(&install_path, &["d".to_string()]) {
            Err(PackError::InvalidManifest(msg)) => assert!(
                msg.contains("regular file") && msg.contains("tool.wasm"),
                "expected not-a-regular-file rejection, got: {msg}"
            ),
            other => panic!("expected InvalidManifest(not-a-file), got {other:?}"),
        }
    }
}
