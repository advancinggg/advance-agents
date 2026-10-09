//! The inference contribution phase: record, validate, commit.

use std::collections::BTreeSet;
use std::fmt;
use std::sync::Arc;

use advance_runtime::config::InferenceBackendClass;
use advance_runtime::config::RuntimeConfig;
use advance_shared_types::inference::{InferenceBackendPort, MeshInferenceDispatch};
use cap_llm::catalog::ModelProfile;
use cap_llm::error::LlmError;

use super::contained::{ContainedInferencePort, ContainedMeshDispatch};
use super::validate::classify_claim;
use super::ExtensionHold;
use crate::api::{
    ComposeCx, ComposeError, ComposeExtension, ExtensionPhase, InferenceContribution,
    InferenceRefusal, InferenceSubject, ProcessPolicy,
};
use crate::compose_log::LogHandle;
use crate::extension::guard;
use crate::extension::set::ExtensionSet;

/// What the inference phase hands the gateway builder.
pub(crate) struct InferenceOutcome {
    pub claims: std::collections::BTreeMap<String, Arc<dyn InferenceBackendPort>>,
    pub mesh_dispatch: Option<Arc<dyn MeshInferenceDispatch>>,
    pub catalog: Arc<cap_llm::ModelProfileCatalog>,
    pub snapshot: Option<Arc<RuntimeConfig>>,
    pub claimed: BTreeSet<String>,
    pub marks_claimable: bool,
}

impl fmt::Debug for InferenceOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InferenceOutcome")
            .field("claims", &self.claims.keys().collect::<Vec<_>>())
            .field("has_mesh_dispatch", &self.mesh_dispatch.is_some())
            .field("claimed", &self.claimed)
            .field("marks_claimable", &self.marks_claimable)
            .finish_non_exhaustive()
    }
}

pub(crate) fn run_inference_phase(
    exts: &ExtensionSet,
    boot: Arc<RuntimeConfig>,
    log: &LogHandle,
    holds: &mut Vec<ExtensionHold>,
) -> Result<InferenceOutcome, ComposeError> {
    run_inference_over(exts.iter_with_cx()?, boot, log, holds)
}

/// The loop over any (id, extension, context) sequence; unit tests drive it with
/// [`ComposeCx::detached_for_test`] contexts.
pub(crate) fn run_inference_over<'a>(
    items: impl Iterator<Item = (&'static str, &'a Arc<dyn ComposeExtension>, &'a ComposeCx)>,
    boot: Arc<RuntimeConfig>,
    log: &LogHandle,
    holds: &mut Vec<ExtensionHold>,
) -> Result<InferenceOutcome, ComposeError> {
    let mut out = InferenceContribution::new(boot, log.clone());
    for (id, ext, cx) in items {
        out.begin_extension(id, cx.processes());
        let r = guard::run_sync_callback(id, ExtensionPhase::Inference, || {
            ext.inference(cx, &mut out)
        });
        let refusal = out.end_extension(matches!(r, Ok(Ok(()))));
        holds.append(&mut out.take_holds());
        let r = r?;
        if let Some(error) = refusal {
            return Err(error);
        }
        if let Err(error) = r {
            return Err(guard::failed(id, ExtensionPhase::Inference, &error));
        }
    }
    Ok(out.finish())
}

impl InferenceContribution {
    pub(crate) fn new(boot: Arc<RuntimeConfig>, log: LogHandle) -> Self {
        Self {
            boot,
            log,
            current: None,
            claimable: Vec::new(),
            staged: Default::default(),
            committed: Default::default(),
            holds: Vec::new(),
        }
    }

    /// The extension whose callback is running.
    pub fn extension_id(&self) -> &'static str {
        self.current.map(|(id, _)| id).unwrap_or("")
    }

    /// The extension a record belongs to. The composer hands `&mut self` to one extension's
    /// `inference` callback at a time, so a record made with no callback running is a composer
    /// bug: a debug build panics, a release build records nothing.
    fn recording(&self) -> Option<(&'static str, ProcessPolicy)> {
        debug_assert!(
            self.current.is_some(),
            "InferenceContribution recorded outside an extension's inference callback"
        );
        self.current
    }

    /// Entries this extension may claim now: backend class `local`, no sidecar,
    /// present in the home's boot config, not claimed by an earlier extension.
    /// Declaration order.
    pub fn claimable(&self) -> impl Iterator<Item = &str> + '_ {
        self.claimable.iter().map(String::as_str)
    }

    /// Serve the claimable entry `entry_id` with `port`.
    pub fn claim(
        &mut self,
        entry_id: impl Into<String>,
        port: Arc<dyn InferenceBackendPort>,
    ) -> &mut Self {
        let Some((id, processes)) = self.recording() else {
            return self;
        };
        let entry = entry_id.into();
        let contained: Arc<dyn InferenceBackendPort> = Arc::new(ContainedInferencePort::new(
            id,
            &entry,
            port,
            self.log.clone(),
        ));
        let refusal = if let Some((by, _)) = self.committed.claims.get(&entry) {
            Some(InferenceRefusal::AlreadyClaimed { by: *by })
        } else if self.staged.claims.iter().any(|(e, _)| e == &entry) {
            Some(InferenceRefusal::AlreadyClaimed { by: id })
        } else {
            classify_claim(
                self.boot.llm_providers.iter().find(|p| p.id == entry),
                processes,
            )
            .err()
        };
        if let Some(reason) = refusal {
            self.keep_first(InferenceSubject::Entry(entry.clone()), reason);
        }
        self.staged.claims.push((entry, contained));
        self
    }

    /// Add a catalog profile under `profile_id`.
    pub fn add_profile(
        &mut self,
        profile_id: impl Into<String>,
        profile: ModelProfile,
    ) -> &mut Self {
        let Some((id, _)) = self.recording() else {
            return self;
        };
        let profile_id = profile_id.into();
        let refusal = if let Some(by) = self.committed.profile_owner.get(&profile_id) {
            Some(InferenceRefusal::DuplicateProfile { by: *by })
        } else if self.staged.profiles.iter().any(|p| p == &profile_id) {
            Some(InferenceRefusal::DuplicateProfile { by: id })
        } else {
            let catalog = self
                .staged
                .catalog
                .get_or_insert_with(|| self.committed.catalog.clone());
            match catalog.insert(profile_id.clone(), profile) {
                Ok(()) => None,
                Err(LlmError::ModelNotAvailable(message)) => {
                    Some(InferenceRefusal::InvalidProfile(message))
                }
                Err(other) => Some(InferenceRefusal::InvalidProfile(other.to_string())),
            }
        };
        if let Some(reason) = refusal {
            self.keep_first(InferenceSubject::Profile(profile_id.clone()), reason);
        }
        self.staged.profiles.push(profile_id);
        self
    }

    /// Attach a hold. Never refused. Kept even when this callback fails.
    pub fn hold<H: Send + 'static>(&mut self, hold: H) -> &mut Self {
        let Some((id, _)) = self.recording() else {
            return self;
        };
        self.holds
            .push(ExtensionHold::new(id, hold, self.log.clone()));
        self.staged.holds += 1;
        self
    }

    /// Supply THE dispatch every `mesh-remote` entry uses. At most one per composition.
    pub fn mesh_dispatch(&mut self, dispatch: Arc<dyn MeshInferenceDispatch>) -> &mut Self {
        let Some((id, _)) = self.recording() else {
            return self;
        };
        let contained: Arc<dyn MeshInferenceDispatch> =
            Arc::new(ContainedMeshDispatch::new(id, dispatch, self.log.clone()));
        let refusal = if let Some((first, _)) = self.committed.mesh {
            Some(InferenceRefusal::SecondMeshDispatch { first })
        } else if !self.staged.dispatches.is_empty() {
            Some(InferenceRefusal::SecondMeshDispatch { first: id })
        } else {
            None
        };
        if let Some(reason) = refusal {
            self.keep_first(InferenceSubject::MeshDispatch, reason);
        }
        self.staged.dispatches.push(contained);
        self
    }

    /// Declare that this extension serves `local` entries without a sidecar even
    /// when it claims none at this boot.
    pub fn serves_local_entries(&mut self) -> &mut Self {
        if self.recording().is_some() {
            self.staged.serves_local = true;
        }
        self
    }

    pub(crate) fn begin_extension(&mut self, extension: &'static str, processes: ProcessPolicy) {
        self.current = Some((extension, processes));
        self.staged = Default::default();
        self.claimable = self
            .boot
            .llm_providers
            .iter()
            .filter(|p| {
                p.backend_class == InferenceBackendClass::Local
                    && p.sidecar.is_none()
                    && !self.committed.claims.contains_key(&p.id)
            })
            .map(|p| p.id.clone())
            .collect();
    }

    pub(crate) fn end_extension(&mut self, callback_ok: bool) -> Option<ComposeError> {
        let staged = std::mem::take(&mut self.staged);
        let Some((id, _)) = self.current.take() else {
            return None;
        };
        if let Some((subject, reason)) = staged.first_refusal {
            return Some(ComposeError::InferenceClaim {
                extension: id,
                subject,
                reason,
            });
        }
        if callback_ok {
            let contributed = !staged.claims.is_empty()
                || !staged.profiles.is_empty()
                || staged.holds > 0
                || !staged.dispatches.is_empty()
                || staged.serves_local;
            for (entry, port) in staged.claims {
                self.committed.claims.insert(entry, (id, port));
            }
            for profile in staged.profiles {
                self.committed.profile_owner.insert(profile, id);
            }
            if let Some(catalog) = staged.catalog {
                self.committed.catalog = catalog;
            }
            if let Some(dispatch) = staged.dispatches.into_iter().next() {
                self.committed.mesh = Some((id, dispatch));
            }
            self.committed.contributed |= contributed;
        }
        None
    }

    pub(crate) fn take_holds(&mut self) -> Vec<ExtensionHold> {
        std::mem::take(&mut self.holds)
    }

    pub(crate) fn finish(self) -> InferenceOutcome {
        let claimed: BTreeSet<String> = self.committed.claims.keys().cloned().collect();
        InferenceOutcome {
            claims: self
                .committed
                .claims
                .into_iter()
                .map(|(entry, (_, port))| (entry, port))
                .collect(),
            mesh_dispatch: self.committed.mesh.map(|(_, dispatch)| dispatch),
            catalog: Arc::new(self.committed.catalog),
            snapshot: Some(self.boot),
            claimed,
            marks_claimable: self.committed.contributed,
        }
    }

    fn keep_first(&mut self, subject: InferenceSubject, reason: InferenceRefusal) {
        if self.staged.first_refusal.is_none() {
            self.staged.first_refusal = Some((subject, reason));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::{BoxFuture, ComposeError, ExtensionError, ExtensionFailure, OssBinding};
    use crate::test_support::MemoryComposeLog;
    use advance_shared_types::inference::{
        InferenceBackendError, InferenceChatRequest, InferenceChatResponse, InferenceEmbedRequest,
        InferenceEmbedResponse, InferenceStream, InferenceStreamHead,
    };
    use async_trait::async_trait;
    use cap_llm::capability::CapabilityDescriptor;
    use cap_llm::catalog::{CatalogTier, ModelProfileCatalog, ProfileKey};
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    const BOOT: &str = r#"
wasm:
  max_memory_pages: 1024
  epoch_interruption_ms: 100
  fuel_enabled: false
llm-providers:
  - id: local-stub
    backend-class: local
    endpoint: ""
    api-key-secret: local-stub-key
    model-aliases: { default: stub-model }
    cost-per-mtoken-in: 2.0
    cost-per-mtoken-out: 4.0
  - id: local-free
    backend-class: local
    endpoint: ""
    api-key-secret: local-free-key
    model-aliases: { default: free-model }
    cost-per-mtoken-in: 0.01
    cost-per-mtoken-out: 0.01
  - id: side
    backend-class: local
    endpoint: ""
    api-key-secret: side-key
    model-aliases: { default: side-model }
    cost-per-mtoken-in: 0.01
    cost-per-mtoken-out: 0.01
    sidecar: { command: /bin/true }
  - id: cloud-a
    endpoint: "http://127.0.0.1:9/v1"
    api-key-secret: cloud-a-key
    model-aliases: { default: cloud-model }
    cost-per-mtoken-in: 0.01
    cost-per-mtoken-out: 0.01
  - id: mesh-stub
    backend-class: mesh-remote
    device-id: dev-1
    api-key-secret: mesh-stub-key
    model-aliases: { default: mesh-model }
    cost-per-mtoken-in: 0.01
    cost-per-mtoken-out: 0.01
  - id: cli
    backend-class: agent-cli
    api-key-secret: cli-key
    model-aliases: { default: cli-model }
    cost-per-mtoken-in: 0.01
    cost-per-mtoken-out: 0.01
    agent-cli: { vendor: claude, command: /nonexistent/claude }
cron:
  max_jitter_ratio: 0.1
git:
  gc_interval_hours: 24
  max_tracked_file_mb: 10
secrets:
  master-key-source: keychain
  env-var-name: SECRETS_MASTER_KEY
post-processor:
  llm-model: sonnet-light
  llm-failure-cooldown-seconds: 600
"#;

    fn boot() -> Arc<RuntimeConfig> {
        Arc::new(serde_yml::from_str(BOOT).expect("fixture RuntimeConfig parses"))
    }

    fn text_profile(model_version: &str) -> ModelProfile {
        ModelProfile {
            key: ProfileKey {
                model_version: model_version.into(),
                quantization: "none".into(),
                backend: "fixture".into(),
                chat_template: "chatml".into(),
                tool_parser: "none".into(),
            },
            tier: CatalogTier::Evaluation,
            licence: "fixture-licence".into(),
            benchmark_provenance: None,
            quirks: cap_llm::catalog::ProfileQuirks::default(),
            capabilities: CapabilityDescriptor::unbound_local(false),
        }
    }

    struct NopPort {
        drops: Arc<AtomicUsize>,
    }

    impl Drop for NopPort {
        fn drop(&mut self) {
            self.drops.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[async_trait]
    impl InferenceBackendPort for NopPort {
        async fn chat(
            &self,
            _req: InferenceChatRequest,
        ) -> Result<InferenceChatResponse, InferenceBackendError> {
            Err(InferenceBackendError::Unwired)
        }
        async fn embed(
            &self,
            _req: InferenceEmbedRequest,
        ) -> Result<InferenceEmbedResponse, InferenceBackendError> {
            Err(InferenceBackendError::Unwired)
        }
        async fn start_stream(
            &self,
            _req: InferenceChatRequest,
        ) -> Result<(InferenceStreamHead, Box<dyn InferenceStream>), InferenceBackendError>
        {
            Err(InferenceBackendError::Unwired)
        }
        fn is_wired(&self) -> bool {
            false
        }
    }

    struct NopDispatch;

    #[async_trait]
    impl MeshInferenceDispatch for NopDispatch {
        async fn dispatch_chat(
            &self,
            _req: InferenceChatRequest,
            _invocation_id: &str,
            _target_device_id: &str,
        ) -> Result<
            InferenceChatResponse,
            advance_shared_types::inference::MeshInferenceDispatchError,
        > {
            Err(advance_shared_types::inference::MeshInferenceDispatchError::Unwired)
        }
        async fn dispatch_embed(
            &self,
            _req: InferenceEmbedRequest,
            _invocation_id: &str,
            _target_device_id: &str,
        ) -> Result<
            InferenceEmbedResponse,
            advance_shared_types::inference::MeshInferenceDispatchError,
        > {
            Err(advance_shared_types::inference::MeshInferenceDispatchError::Unwired)
        }
        async fn start_stream(
            &self,
            _req: InferenceChatRequest,
            _invocation_id: &str,
            _target_device_id: &str,
        ) -> Result<
            (
                InferenceStreamHead,
                Box<dyn InferenceStream>,
                advance_shared_types::inference::MeshCarrier,
            ),
            advance_shared_types::inference::MeshInferenceDispatchError,
        > {
            Err(advance_shared_types::inference::MeshInferenceDispatchError::Unwired)
        }
        fn is_wired(&self) -> bool {
            false
        }
    }

    struct FnExt<F> {
        id: &'static str,
        f: F,
    }

    impl<F> ComposeExtension for FnExt<F>
    where
        F: Fn(&ComposeCx, &mut InferenceContribution) -> Result<(), ExtensionError>
            + Send
            + Sync
            + 'static,
    {
        fn id(&self) -> &'static str {
            self.id
        }
        fn inference(
            &self,
            cx: &ComposeCx,
            out: &mut InferenceContribution,
        ) -> Result<(), ExtensionError> {
            (self.f)(cx, out)
        }
        fn shutdown<'a>(&'a self) -> BoxFuture<'a, ()> {
            Box::pin(async {})
        }
    }

    fn ext(
        id: &'static str,
        f: impl Fn(&ComposeCx, &mut InferenceContribution) -> Result<(), ExtensionError>
            + Send
            + Sync
            + 'static,
    ) -> Arc<dyn ComposeExtension> {
        Arc::new(FnExt { id, f })
    }

    fn run(
        exts: &[Arc<dyn ComposeExtension>],
    ) -> (
        Result<InferenceOutcome, ComposeError>,
        Vec<ExtensionHold>,
        MemoryComposeLog,
    ) {
        let cxs: Vec<ComposeCx> = exts
            .iter()
            .map(|e| ComposeCx::detached_for_test(e.id(), PathBuf::from("/")))
            .collect();
        let items = exts.iter().zip(cxs.iter()).map(|(e, cx)| (e.id(), e, cx));
        let mut holds = Vec::new();
        let sink = MemoryComposeLog::new();
        let log = LogHandle::new(Arc::new(sink.clone()));
        let result = run_inference_over(items, boot(), &log, &mut holds);
        (result, holds, sink)
    }

    fn port(drops: &Arc<AtomicUsize>) -> Arc<dyn InferenceBackendPort> {
        Arc::new(NopPort {
            drops: Arc::clone(drops),
        })
    }

    #[test]
    fn module_001_ac31_validate_refuses_second_claim_within_and_across_extensions() {
        let drops = Arc::new(AtomicUsize::new(0));
        let d = Arc::clone(&drops);
        let (err, _, _) = run(&[ext("fixture", move |_, out| {
            out.claim("local-stub", port(&d))
                .claim("local-stub", port(&d));
            Ok(())
        })]);
        match err {
            Err(ComposeError::InferenceClaim {
                extension: "fixture",
                subject: InferenceSubject::Entry(entry),
                reason: InferenceRefusal::AlreadyClaimed { by: "fixture" },
            }) => assert_eq!(entry, "local-stub"),
            other => panic!("{other:?}"),
        }

        let d1 = Arc::new(AtomicUsize::new(0));
        let d2 = Arc::new(AtomicUsize::new(0));
        let a = Arc::clone(&d1);
        let b = Arc::clone(&d2);
        let (err, _, _) = run(&[
            ext("fixture", move |_, out| {
                out.claim("local-stub", port(&a));
                Ok(())
            }),
            ext("fixture-two", move |_, out| {
                out.claim("local-stub", port(&b));
                Ok(())
            }),
        ]);
        match err {
            Err(ComposeError::InferenceClaim {
                extension: "fixture-two",
                subject: InferenceSubject::Entry(entry),
                reason: InferenceRefusal::AlreadyClaimed { by: "fixture" },
            }) => assert_eq!(entry, "local-stub"),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn module_001_ac31_validate_profiles_unique_and_catalog_refusals_typed() {
        let (err, _, _) = run(&[ext("fixture", |_, out| {
            out.add_profile("p1", text_profile("v1"))
                .add_profile("p1", text_profile("v2"));
            Ok(())
        })]);
        match err {
            Err(ComposeError::InferenceClaim {
                extension: "fixture",
                subject: InferenceSubject::Profile(id),
                reason: InferenceRefusal::DuplicateProfile { by: "fixture" },
            }) => assert_eq!(id, "p1"),
            other => panic!("{other:?}"),
        }

        let (err, _, _) = run(&[
            ext("fixture", |_, out| {
                out.add_profile("p1", text_profile("v1"));
                Ok(())
            }),
            ext("fixture-two", |_, out| {
                out.add_profile("p1", text_profile("v2"));
                Ok(())
            }),
        ]);
        match err {
            Err(ComposeError::InferenceClaim {
                extension: "fixture-two",
                subject: InferenceSubject::Profile(id),
                reason: InferenceRefusal::DuplicateProfile { by: "fixture" },
            }) => assert_eq!(id, "p1"),
            other => panic!("{other:?}"),
        }

        let mut empty = text_profile("empty");
        empty.licence.clear();
        let (err, _, _) = run(&[ext("fixture", move |_, out| {
            out.add_profile("p2", empty.clone());
            Ok(())
        })]);
        match err {
            Err(ComposeError::InferenceClaim {
                extension: "fixture",
                subject: InferenceSubject::Profile(id),
                reason: InferenceRefusal::InvalidProfile(message),
            }) => {
                assert_eq!(id, "p2");
                assert_eq!(message, "catalog profile missing licence");
            }
            other => panic!("{other:?}"),
        }

        let (err, _, _) = run(&[ext("fixture", |_, out| {
            out.add_profile("a", text_profile("same"))
                .add_profile("b", text_profile("same"));
            Ok(())
        })]);
        match err {
            Err(ComposeError::InferenceClaim {
                reason: InferenceRefusal::InvalidProfile(message),
                ..
            }) => assert_eq!(message, "catalog registration unit already exists"),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn module_001_ac31_validate_second_mesh_dispatch_refused() {
        let (err, _, _) = run(&[ext("fixture", |_, out| {
            out.mesh_dispatch(Arc::new(NopDispatch))
                .mesh_dispatch(Arc::new(NopDispatch));
            Ok(())
        })]);
        match err {
            Err(ComposeError::InferenceClaim {
                extension: "fixture",
                subject: InferenceSubject::MeshDispatch,
                reason: InferenceRefusal::SecondMeshDispatch { first: "fixture" },
            }) => {}
            other => panic!("{other:?}"),
        }

        let (err, _, _) = run(&[
            ext("fixture", |_, out| {
                out.mesh_dispatch(Arc::new(NopDispatch));
                Ok(())
            }),
            ext("fixture-two", |_, out| {
                out.mesh_dispatch(Arc::new(NopDispatch));
                Ok(())
            }),
        ]);
        match err {
            Err(ComposeError::InferenceClaim {
                extension: "fixture-two",
                subject: InferenceSubject::MeshDispatch,
                reason: InferenceRefusal::SecondMeshDispatch { first: "fixture" },
            }) => {}
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn module_001_ac31_first_refusal_in_recording_order_wins() {
        let drops = Arc::new(AtomicUsize::new(0));
        let d = Arc::clone(&drops);
        let (err, _, _) = run(&[ext("fixture", move |_, out| {
            out.add_profile("p1", text_profile("v1"))
                .add_profile("p1", text_profile("v2"))
                .claim("ghost", port(&d));
            Ok(())
        })]);
        match err {
            Err(ComposeError::InferenceClaim {
                subject: InferenceSubject::Profile(id),
                reason: InferenceRefusal::DuplicateProfile { .. },
                ..
            }) => assert_eq!(id, "p1"),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn module_001_ac31_phase_precedence_panic_then_refusal_then_err() {
        let drops = Arc::new(AtomicUsize::new(0));
        let d = Arc::clone(&drops);
        let (err, _, _) = run(&[ext("fixture", move |_, out| {
            out.claim("ghost", port(&d));
            panic!("fixture panic in inference");
        })]);
        match err {
            Err(ComposeError::Extension {
                extension: "fixture",
                phase: ExtensionPhase::Inference,
                failure: ExtensionFailure::Panicked(message),
            }) => assert!(message.contains("fixture panic in inference"), "{message}"),
            other => panic!("{other:?}"),
        }

        let d = Arc::new(AtomicUsize::new(0));
        let (err, _, _) = run(&[ext("fixture", move |_, out| {
            out.claim("ghost", port(&d));
            Err(ExtensionError::new("fixture failure in inference"))
        })]);
        match err {
            Err(ComposeError::InferenceClaim {
                subject: InferenceSubject::Entry(entry),
                reason: InferenceRefusal::AbsentEntry,
                ..
            }) => assert_eq!(entry, "ghost"),
            other => panic!("{other:?}"),
        }

        let d = Arc::new(AtomicUsize::new(0));
        let (err, _, _) = run(&[ext("fixture", move |_, out| {
            out.claim("local-stub", port(&d));
            Err(ExtensionError::new("fixture failure in inference"))
        })]);
        match err {
            Err(ComposeError::Extension {
                extension: "fixture",
                phase: ExtensionPhase::Inference,
                failure: ExtensionFailure::Failed(message),
            }) => assert_eq!(message, "fixture failure in inference"),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn module_001_ac31_refused_or_failed_extension_commits_nothing_and_keeps_holds() {
        let drops = Arc::new(AtomicUsize::new(0));
        let log = LogHandle::null();
        let mut out = InferenceContribution::new(boot(), log);
        let mut holds = Vec::new();

        out.begin_extension("a", ProcessPolicy::Allow);
        out.claim("ghost", port(&drops)).hold(());
        assert!(out.end_extension(true).is_some());
        holds.append(&mut out.take_holds());

        out.begin_extension("b", ProcessPolicy::Allow);
        out.claim("local-stub", port(&drops)).hold(());
        assert!(out.end_extension(false).is_none());
        holds.append(&mut out.take_holds());

        out.begin_extension("c", ProcessPolicy::Allow);
        out.claim("local-free", port(&drops)).hold(());
        assert!(out.end_extension(false).is_none());
        holds.append(&mut out.take_holds());

        assert_eq!(holds.len(), 3);
        let outcome = out.finish();
        assert!(outcome.claims.is_empty());
        assert!(outcome.mesh_dispatch.is_none());
        assert!(outcome.claimed.is_empty());
        drop(holds);
        assert_eq!(drops.load(Ordering::SeqCst), 3);
    }

    #[test]
    fn module_001_ac31_marks_claimable_only_when_something_was_contributed() {
        let (ok, _, _) = run(&[ext("fixture", |_, _| Ok(()))]);
        assert!(!ok.expect("ok").marks_claimable);

        let (ok, _, _) = run(&[ext("fixture", |_, out| {
            out.add_profile("p", text_profile("v"));
            Ok(())
        })]);
        assert!(ok.expect("ok").marks_claimable);

        let (ok, holds, _) = run(&[ext("fixture", |_, out| {
            out.hold(1u8);
            Ok(())
        })]);
        assert!(ok.expect("ok").marks_claimable);
        assert_eq!(holds.len(), 1);

        let (ok, _, _) = run(&[ext("fixture", |_, out| {
            out.serves_local_entries();
            Ok(())
        })]);
        assert!(ok.expect("ok").marks_claimable);

        let d = Arc::new(AtomicUsize::new(0));
        let mut out = InferenceContribution::new(boot(), LogHandle::null());
        out.begin_extension("fixture", ProcessPolicy::Allow);
        out.claim("local-stub", port(&d));
        assert!(out.end_extension(false).is_none());
        assert!(!out.finish().marks_claimable);
    }

    #[test]
    #[cfg(debug_assertions)]
    fn module_001_ac31_contribution_recorded_outside_a_callback_is_a_composer_bug() {
        let drops = Arc::new(AtomicUsize::new(0));
        let records: Vec<(&str, Box<dyn Fn(&mut InferenceContribution)>)> = vec![
            (
                "claim",
                Box::new(move |out| {
                    out.claim("local-stub", port(&drops));
                }),
            ),
            (
                "add_profile",
                Box::new(|out| {
                    out.add_profile("p", text_profile("v"));
                }),
            ),
            (
                "hold",
                Box::new(|out| {
                    out.hold(1u8);
                }),
            ),
            (
                "mesh_dispatch",
                Box::new(|out| {
                    out.mesh_dispatch(Arc::new(NopDispatch));
                }),
            ),
            (
                "serves_local_entries",
                Box::new(|out| {
                    out.serves_local_entries();
                }),
            ),
        ];
        for (name, record) in records {
            let mut out = InferenceContribution::new(boot(), LogHandle::null());
            let outcome =
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| record(&mut out)));
            let message = outcome
                .expect_err(name)
                .downcast::<&str>()
                .map(|m| (*m).to_owned())
                .unwrap_or_default();
            assert_eq!(
                message, "InferenceContribution recorded outside an extension's inference callback",
                "{name}"
            );
            assert!(out.take_holds().is_empty(), "{name}");
            let outcome = out.finish();
            assert!(
                outcome.claims.is_empty() && outcome.mesh_dispatch.is_none(),
                "{name}"
            );
            assert!(!outcome.marks_claimable, "{name}");
        }
    }

    #[test]
    fn module_001_ac31_claimable_view_excludes_sidecar_absent_and_already_claimed() {
        let seen = Arc::new(Mutex::new(Vec::<Vec<String>>::new()));
        let s1 = Arc::clone(&seen);
        let s2 = Arc::clone(&seen);
        let d = Arc::new(AtomicUsize::new(0));
        let (ok, _, _) = run(&[
            ext("fixture", move |_, out| {
                s1.lock()
                    .unwrap()
                    .push(out.claimable().map(str::to_owned).collect());
                out.claim("local-stub", port(&d));
                Ok(())
            }),
            ext("fixture-two", move |_, out| {
                s2.lock()
                    .unwrap()
                    .push(out.claimable().map(str::to_owned).collect());
                Ok(())
            }),
        ]);
        assert!(ok.is_ok());
        let views = seen.lock().unwrap();
        assert_eq!(
            views[0],
            vec!["local-stub".to_owned(), "local-free".to_owned()]
        );
        assert_eq!(views[1], vec!["local-free".to_owned()]);
    }

    #[test]
    fn module_001_ac31_inference_claim_display_texts() {
        let rows = [
            (
                ComposeError::InferenceClaim {
                    extension: "fixture",
                    subject: InferenceSubject::Entry("ghost".into()),
                    reason: InferenceRefusal::AbsentEntry,
                },
                "extension fixture: inference claim on entry \"ghost\" refused: no such entry in the home's llm-providers",
            ),
            (
                ComposeError::InferenceClaim {
                    extension: "fixture-two",
                    subject: InferenceSubject::Entry("local-stub".into()),
                    reason: InferenceRefusal::AlreadyClaimed { by: "fixture" },
                },
                "extension fixture-two: inference claim on entry \"local-stub\" refused: already claimed by extension fixture",
            ),
            (
                ComposeError::InferenceClaim {
                    extension: "fixture",
                    subject: InferenceSubject::Entry("side".into()),
                    reason: InferenceRefusal::BoundByOss(OssBinding::LocalSidecar),
                },
                "extension fixture: inference claim on entry \"side\" refused: bound by OSS (local sidecar)",
            ),
            (
                ComposeError::InferenceClaim {
                    extension: "fixture",
                    subject: InferenceSubject::Entry("cli".into()),
                    reason: InferenceRefusal::BoundByOss(OssBinding::AgentCli),
                },
                "extension fixture: inference claim on entry \"cli\" refused: bound by OSS (agent-cli)",
            ),
            (
                ComposeError::InferenceClaim {
                    extension: "fixture",
                    subject: InferenceSubject::Entry("cloud-a".into()),
                    reason: InferenceRefusal::BoundByOss(OssBinding::CloudWireAdapter),
                },
                "extension fixture: inference claim on entry \"cloud-a\" refused: bound by OSS (cloud wire adapter)",
            ),
            (
                ComposeError::InferenceClaim {
                    extension: "fixture",
                    subject: InferenceSubject::Entry("side".into()),
                    reason: InferenceRefusal::SidecarUnderForbid,
                },
                "extension fixture: inference claim on entry \"side\" refused: a local entry with a sidecar is bound to a typed refusal under ProcessPolicy::Forbid",
            ),
            (
                ComposeError::InferenceClaim {
                    extension: "fixture",
                    subject: InferenceSubject::Entry("mesh-stub".into()),
                    reason: InferenceRefusal::MeshRemoteEntry,
                },
                "extension fixture: inference claim on entry \"mesh-stub\" refused: mesh-remote entries are served by the mesh dispatch",
            ),
            (
                ComposeError::InferenceClaim {
                    extension: "fixture-two",
                    subject: InferenceSubject::Profile("p1".into()),
                    reason: InferenceRefusal::DuplicateProfile { by: "fixture" },
                },
                "extension fixture-two: inference claim on profile \"p1\" refused: profile id already added by extension fixture",
            ),
            (
                ComposeError::InferenceClaim {
                    extension: "fixture",
                    subject: InferenceSubject::Profile("p2".into()),
                    reason: InferenceRefusal::InvalidProfile(
                        "catalog profile missing licence".into(),
                    ),
                },
                "extension fixture: inference claim on profile \"p2\" refused: the catalog refused the profile: catalog profile missing licence",
            ),
            (
                ComposeError::InferenceClaim {
                    extension: "fixture-two",
                    subject: InferenceSubject::MeshDispatch,
                    reason: InferenceRefusal::SecondMeshDispatch { first: "fixture" },
                },
                "extension fixture-two: inference claim on mesh dispatch refused: a mesh dispatch is already supplied by extension fixture",
            ),
        ];
        for (error, text) in rows {
            assert_eq!(error.to_string(), text);
        }
    }

    #[test]
    fn finish_empty_catalog_is_shared_shape() {
        let (ok, holds, _) = run(&[]);
        let outcome = ok.expect("empty phase");
        assert!(outcome.claims.is_empty());
        assert!(outcome.mesh_dispatch.is_none());
        assert!(outcome.claimed.is_empty());
        assert!(!outcome.marks_claimable);
        assert!(holds.is_empty());
        assert!(ModelProfileCatalog::new().default_id().is_err());
        assert!(outcome.catalog.default_id().is_err());
    }
}
