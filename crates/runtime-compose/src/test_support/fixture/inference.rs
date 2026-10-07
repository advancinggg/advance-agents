//! The fixture's (b) inference part: a plan applied verbatim to the contribution.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use advance_shared_types::inference::{
    InferenceBackendError, InferenceBackendPort, InferenceChatRequest, InferenceChatResponse,
    InferenceEmbedRequest, InferenceEmbedResponse, InferenceStream, InferenceStreamClass,
    InferenceStreamHead, InferenceTextDelta, MeshCarrier, MeshInferenceDispatch,
    MeshInferenceDispatchError, NormalizedUsage,
};
use cap_llm::capability::CapabilityDescriptor;
use cap_llm::catalog::{CatalogTier, ModelProfile, ProfileKey, ProfileQuirks};

use crate::api::async_trait;
use crate::api::InferenceContribution;

/// Entry id claimed by [`FixtureInference::standard`].
pub const LOCAL_STUB_ID: &str = "local-stub";
pub const STUB_PROFILE_ID: &str = "fixture.stub-profile";
pub const STUB_REPLY: &str = "stub-pong";
pub const STUB_PORT_PANIC: &str = "fixture inference port panic";
pub const STUB_MESH_PANIC: &str = "fixture mesh dispatch panic";

/// The fixture's (b) part: a plan applied verbatim to the contribution (no
/// checks of its own, so a test can record any refused claim).
#[derive(Clone, Default)]
pub struct FixtureInference {
    claims: Vec<(String, Arc<dyn InferenceBackendPort>)>,
    profiles: Vec<(String, ModelProfile)>,
    holds: Vec<DropFlag>,
    dispatches: Vec<Arc<dyn MeshInferenceDispatch>>,
    serves_local: bool,
}

impl FixtureInference {
    pub fn new() -> Self {
        Self::default()
    }

    /// Claim [`LOCAL_STUB_ID`] with `port`, add [`STUB_PROFILE_ID`] =
    /// [`stub_profile`], and [`Self::serves_local_entries`].
    pub fn standard(port: Arc<StubInferencePort>) -> Self {
        Self::new()
            .claim(LOCAL_STUB_ID, port)
            .profile(STUB_PROFILE_ID, stub_profile())
            .serves_local_entries()
    }

    pub fn claim(mut self, entry: &str, port: Arc<dyn InferenceBackendPort>) -> Self {
        self.claims.push((entry.to_string(), port));
        self
    }

    pub fn profile(mut self, id: &str, profile: ModelProfile) -> Self {
        self.profiles.push((id.to_string(), profile));
        self
    }

    /// The [`DropToken`] is created inside [`Self::apply`].
    pub fn hold(mut self, flag: &DropFlag) -> Self {
        self.holds.push(flag.clone());
        self
    }

    pub fn mesh_dispatch(mut self, dispatch: Arc<dyn MeshInferenceDispatch>) -> Self {
        self.dispatches.push(dispatch);
        self
    }

    pub fn serves_local_entries(mut self) -> Self {
        self.serves_local = true;
        self
    }

    /// Claims, then profiles, then holds, then dispatches, then serves_local,
    /// each in insertion order.
    pub fn apply(&self, out: &mut InferenceContribution) {
        for (entry, port) in &self.claims {
            out.claim(entry.clone(), Arc::clone(port));
        }
        for (id, profile) in &self.profiles {
            out.add_profile(id.clone(), profile.clone());
        }
        for flag in &self.holds {
            out.hold(flag.token());
        }
        for dispatch in &self.dispatches {
            out.mesh_dispatch(Arc::clone(dispatch));
        }
        if self.serves_local {
            out.serves_local_entries();
        }
    }
}

/// A text-only profile: licence `"fixture-licence"`, tier Evaluation, key
/// `{ model_version, quantization "none", backend "fixture", chat_template
/// "chatml", tool_parser "none" }`, quirks Default, benchmark_provenance None,
/// capabilities `CapabilityDescriptor::unbound_local(false)`.
pub fn text_profile(model_version: &str) -> ModelProfile {
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
        quirks: ProfileQuirks::default(),
        capabilities: CapabilityDescriptor::unbound_local(false),
    }
}

pub fn stub_profile() -> ModelProfile {
    text_profile("stub-1")
}

pub struct StubInferencePort {
    reply: String,
    input_tokens: u64,
    output_tokens: u64,
    calls: AtomicUsize,
    requests: Mutex<Vec<RecordedChat>>,
    panic_next: AtomicBool,
    gate: Mutex<Option<StubGate>>,
}

impl StubInferencePort {
    pub fn new(reply: &str, input_tokens: u64, output_tokens: u64) -> Arc<Self> {
        Arc::new(Self {
            reply: reply.to_string(),
            input_tokens,
            output_tokens,
            calls: AtomicUsize::new(0),
            requests: Mutex::new(Vec::new()),
            panic_next: AtomicBool::new(false),
            gate: Mutex::new(None),
        })
    }

    pub fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }

    pub fn requests(&self) -> Vec<RecordedChat> {
        self.requests
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    pub fn panic_next_call(&self) {
        self.panic_next.store(true, Ordering::SeqCst);
    }

    pub fn hold_next_call(&self) -> StubGate {
        let gate = StubGate {
            entered: Arc::new(tokio::sync::Notify::new()),
            release: Arc::new(tokio::sync::Notify::new()),
        };
        *self
            .gate
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(gate.clone());
        gate
    }

    fn note_call(&self) {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.panic_next.swap(false, Ordering::SeqCst) {
            panic!("{STUB_PORT_PANIC}");
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecordedChat {
    pub provider_id: String,
    pub model: String,
    pub messages: Vec<(String, String)>,
    pub max_tokens: Option<u32>,
}

#[derive(Clone)]
pub struct StubGate {
    entered: Arc<tokio::sync::Notify>,
    release: Arc<tokio::sync::Notify>,
}

impl StubGate {
    pub async fn entered(&self) {
        self.entered.notified().await;
    }

    pub fn release(&self) {
        self.release.notify_one();
    }
}

struct OneShotStream {
    delta: Option<InferenceTextDelta>,
}

#[async_trait]
impl InferenceStream for OneShotStream {
    async fn next_chunk(&mut self) -> Option<Result<InferenceTextDelta, InferenceBackendError>> {
        self.delta.take().map(Ok)
    }

    fn cancel(&mut self) {}
}

fn terminal_delta(reply: &str, input_tokens: u64, output_tokens: u64) -> InferenceTextDelta {
    InferenceTextDelta {
        text: reply.to_string(),
        usage: Some(NormalizedUsage {
            input_tokens,
            output_tokens,
            cached_tokens: 0,
        }),
        terminal: true,
        finish_reason: Some("stop".into()),
    }
}

fn success_head() -> InferenceStreamHead {
    InferenceStreamHead {
        class: InferenceStreamClass::Success,
        snapshot_only: true,
    }
}

#[async_trait]
impl InferenceBackendPort for StubInferencePort {
    async fn chat(
        &self,
        req: InferenceChatRequest,
    ) -> Result<InferenceChatResponse, InferenceBackendError> {
        self.requests
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .push(RecordedChat {
                provider_id: req.provider_id.clone(),
                model: req.model.clone(),
                messages: req
                    .messages
                    .iter()
                    .map(|m| (m.role.clone(), m.content.clone()))
                    .collect(),
                max_tokens: req.max_tokens,
            });
        self.note_call();
        let gate = self
            .gate
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take();
        if let Some(gate) = gate {
            gate.entered.notify_one();
            gate.release.notified().await;
        }
        Ok(InferenceChatResponse {
            text: self.reply.clone(),
            model: req.model,
            input_tokens: self.input_tokens,
            output_tokens: self.output_tokens,
            finish_reason: "stop".into(),
        })
    }

    async fn embed(
        &self,
        req: InferenceEmbedRequest,
    ) -> Result<InferenceEmbedResponse, InferenceBackendError> {
        self.note_call();
        Ok(InferenceEmbedResponse {
            vector: vec![0.0; 4],
            model: req.model,
        })
    }

    async fn start_stream(
        &self,
        _req: InferenceChatRequest,
    ) -> Result<(InferenceStreamHead, Box<dyn InferenceStream>), InferenceBackendError> {
        self.note_call();
        let stream: Box<dyn InferenceStream> = Box::new(OneShotStream {
            delta: Some(terminal_delta(
                &self.reply,
                self.input_tokens,
                self.output_tokens,
            )),
        });
        Ok((success_head(), stream))
    }

    fn is_wired(&self) -> bool {
        true
    }
}

pub struct StubMeshDispatch {
    reply: String,
    calls: AtomicUsize,
    targets: Mutex<Vec<String>>,
    panic_next: AtomicBool,
}

impl StubMeshDispatch {
    pub fn new(reply: &str) -> Arc<Self> {
        Arc::new(Self {
            reply: reply.to_string(),
            calls: AtomicUsize::new(0),
            targets: Mutex::new(Vec::new()),
            panic_next: AtomicBool::new(false),
        })
    }

    pub fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }

    pub fn targets(&self) -> Vec<String> {
        self.targets
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    pub fn panic_next_call(&self) {
        self.panic_next.store(true, Ordering::SeqCst);
    }

    fn note_call(&self, target_device_id: &str) {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.targets
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .push(target_device_id.to_string());
        if self.panic_next.swap(false, Ordering::SeqCst) {
            panic!("{STUB_MESH_PANIC}");
        }
    }
}

#[async_trait]
impl MeshInferenceDispatch for StubMeshDispatch {
    async fn dispatch_chat(
        &self,
        req: InferenceChatRequest,
        _invocation_id: &str,
        target_device_id: &str,
    ) -> Result<InferenceChatResponse, MeshInferenceDispatchError> {
        self.note_call(target_device_id);
        Ok(InferenceChatResponse {
            text: self.reply.clone(),
            model: req.model,
            input_tokens: 3,
            output_tokens: 3,
            finish_reason: "stop".into(),
        })
    }

    async fn dispatch_embed(
        &self,
        req: InferenceEmbedRequest,
        _invocation_id: &str,
        target_device_id: &str,
    ) -> Result<InferenceEmbedResponse, MeshInferenceDispatchError> {
        self.note_call(target_device_id);
        Ok(InferenceEmbedResponse {
            vector: vec![0.0; 4],
            model: req.model,
        })
    }

    async fn start_stream(
        &self,
        _req: InferenceChatRequest,
        _invocation_id: &str,
        target_device_id: &str,
    ) -> Result<
        (InferenceStreamHead, Box<dyn InferenceStream>, MeshCarrier),
        MeshInferenceDispatchError,
    > {
        self.note_call(target_device_id);
        let stream: Box<dyn InferenceStream> = Box::new(OneShotStream {
            delta: Some(terminal_delta(&self.reply, 3, 3)),
        });
        Ok((success_head(), stream, MeshCarrier::Snapshot))
    }

    fn is_wired(&self) -> bool {
        true
    }
}

#[derive(Clone, Default)]
pub struct DropFlag(Arc<AtomicBool>);

impl DropFlag {
    pub fn token(&self) -> DropToken {
        DropToken(Arc::clone(&self.0))
    }

    pub fn dropped(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }
}

pub struct DropToken(Arc<AtomicBool>);

impl Drop for DropToken {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

/// An executable `#!/bin/sh` script in its own tempdir that touches a marker
/// file. OSS spawns it; it writes the marker and exits without a handshake.
#[cfg(unix)]
pub struct SidecarMarker {
    _dir: tempfile::TempDir,
    script: PathBuf,
    marker: PathBuf,
}

#[cfg(unix)]
impl SidecarMarker {
    pub fn new() -> std::io::Result<Self> {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir()?;
        let script = dir.path().join("side.sh");
        let marker = dir.path().join("ran");
        let quoted = marker.display().to_string().replace('\'', "'\\''");
        std::fs::write(&script, format!("#!/bin/sh\ntouch '{quoted}'\n"))?;
        let mut perms = std::fs::metadata(&script)?.permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&script, perms)?;
        Ok(Self {
            _dir: dir,
            script,
            marker,
        })
    }

    pub fn command(&self) -> &Path {
        &self.script
    }

    pub fn ran(&self) -> bool {
        self.marker.exists()
    }
}

/// Provider entries (each passes `runtime/src/config.rs` validation).
pub mod provider_yaml {
    use std::path::Path;

    pub const LOCAL_STUB: &str = concat!(
        "  - id: local-stub\n",
        "    backend-class: local\n",
        "    endpoint: \"\"\n",
        "    api-key-secret: local-stub-key\n",
        "    model-aliases: { default: stub-model }\n",
        "    cost-per-mtoken-in: 2.0\n",
        "    cost-per-mtoken-out: 4.0\n",
        "    rate-limit: { requests-per-minute: 100, tokens-per-minute: 100000 }\n",
        "    profile-id: fixture.stub-profile\n",
    );

    pub const LOCAL_STUB_PLAIN: &str = concat!(
        "  - id: local-stub\n",
        "    backend-class: local\n",
        "    endpoint: \"\"\n",
        "    api-key-secret: local-stub-key\n",
        "    model-aliases: { default: stub-model }\n",
        "    cost-per-mtoken-in: 2.0\n",
        "    cost-per-mtoken-out: 4.0\n",
        "    rate-limit: { requests-per-minute: 100, tokens-per-minute: 100000 }\n",
    );

    pub const LOCAL_FREE: &str = concat!(
        "  - id: local-free\n",
        "    backend-class: local\n",
        "    endpoint: \"\"\n",
        "    api-key-secret: local-free-key\n",
        "    model-aliases: { default: free-model }\n",
        "    cost-per-mtoken-in: 0.01\n",
        "    cost-per-mtoken-out: 0.01\n",
        "    rate-limit: { requests-per-minute: 100, tokens-per-minute: 100000 }\n",
    );

    pub const CLOUD_A: &str = concat!(
        "  - id: cloud-a\n",
        "    endpoint: \"http://127.0.0.1:9/v1\"\n",
        "    api-key-secret: cloud-a-key\n",
        "    model-aliases: { default: cloud-model }\n",
        "    cost-per-mtoken-in: 0.01\n",
        "    cost-per-mtoken-out: 0.01\n",
        "    rate-limit: { requests-per-minute: 100, tokens-per-minute: 100000 }\n",
    );

    pub const MESH_STUB: &str = concat!(
        "  - id: mesh-stub\n",
        "    backend-class: mesh-remote\n",
        "    device-id: dev-1\n",
        "    api-key-secret: mesh-stub-key\n",
        "    model-aliases: { default: mesh-model }\n",
        "    cost-per-mtoken-in: 0.01\n",
        "    cost-per-mtoken-out: 0.01\n",
        "    rate-limit: { requests-per-minute: 100, tokens-per-minute: 100000 }\n",
    );

    pub const CLI: &str = concat!(
        "  - id: cli\n",
        "    backend-class: agent-cli\n",
        "    api-key-secret: cli-key\n",
        "    model-aliases: { default: cli-model }\n",
        "    cost-per-mtoken-in: 0.01\n",
        "    cost-per-mtoken-out: 0.01\n",
        "    rate-limit: { requests-per-minute: 100, tokens-per-minute: 100000 }\n",
        "    agent-cli: { vendor: claude, command: /nonexistent/claude }\n",
    );

    pub fn side(command: &Path) -> String {
        let quoted = command.display().to_string().replace('\'', "''");
        format!(
            "  - id: side\n    backend-class: local\n    endpoint: \"\"\n    api-key-secret: side-key\n    model-aliases: {{ default: side-model }}\n    cost-per-mtoken-in: 0.01\n    cost-per-mtoken-out: 0.01\n    rate-limit: {{ requests-per-minute: 100, tokens-per-minute: 100000 }}\n    sidecar: {{ command: '{quoted}' }}\n"
        )
    }

    /// The complete `llm-providers:` key and list (`FixtureHomeSpec.providers_yaml`).
    pub fn llm_providers_block(entries: &[&str]) -> String {
        let mut out = String::from("llm-providers:\n");
        for entry in entries {
            out.push_str(entry.trim_end());
            out.push('\n');
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::fixture::{CapDecl, FixtureDriver, FixtureHome, FixtureHomeSpec};
    use advance_shared_types::inference::InferenceMessage;
    use std::sync::atomic::AtomicBool;
    use std::time::{Duration, Instant};

    #[test]
    fn drop_flag_sets_on_token_drop() {
        let flag = DropFlag::default();
        assert!(!flag.dropped());
        drop(flag.token());
        assert!(flag.dropped());
    }

    #[test]
    fn provider_yaml_loads_through_fixture_home() {
        let side = provider_yaml::side(Path::new("/bin/true"));
        let home = FixtureHome::new(FixtureHomeSpec {
            capabilities: vec![CapDecl::Granted("llm")],
            driver: FixtureDriver::None,
            git: false,
            providers_yaml: Some(provider_yaml::llm_providers_block(&[
                provider_yaml::LOCAL_STUB,
                provider_yaml::LOCAL_FREE,
                provider_yaml::CLOUD_A,
                provider_yaml::MESH_STUB,
                provider_yaml::CLI,
                side.as_str(),
            ])),
        })
        .expect("home");
        advance_runtime::config::load_config(&home.home().join(".advance/runtime-config.yaml"))
            .expect("provider yaml");
    }

    #[tokio::test]
    async fn stub_port_chat_embed_and_stream() {
        let port = StubInferencePort::new("pong", 2, 3);
        let req = InferenceChatRequest {
            provider_id: LOCAL_STUB_ID.into(),
            model: "stub-model".into(),
            messages: vec![InferenceMessage {
                role: "user".into(),
                content: "hi".into(),
            }],
            temperature: None,
            max_tokens: Some(16),
            stop_sequences: None,
            tools: None,
            output_schema: None,
            deadline: Instant::now() + Duration::from_secs(5),
            cancel: Arc::new(AtomicBool::new(false)),
        };
        let chat = port.chat(req.clone()).await.expect("chat");
        assert_eq!(chat.text, "pong");
        assert_eq!(chat.input_tokens, 2);
        assert_eq!(chat.output_tokens, 3);
        assert_eq!(port.calls(), 1);
        assert_eq!(
            port.requests(),
            vec![RecordedChat {
                provider_id: LOCAL_STUB_ID.into(),
                model: "stub-model".into(),
                messages: vec![("user".into(), "hi".into())],
                max_tokens: Some(16),
            }]
        );
        let embed = port
            .embed(InferenceEmbedRequest {
                provider_id: LOCAL_STUB_ID.into(),
                model: "stub-model".into(),
                text: "x".into(),
                deadline: Instant::now() + Duration::from_secs(5),
                cancel: Arc::new(AtomicBool::new(false)),
            })
            .await
            .expect("embed");
        assert_eq!(embed.vector, vec![0.0; 4]);
        let (head, mut stream) = port.start_stream(req).await.expect("stream");
        assert_eq!(head.class, InferenceStreamClass::Success);
        assert!(head.snapshot_only);
        let delta = stream.next_chunk().await.expect("delta").expect("ok");
        assert_eq!(delta.text, "pong");
        assert!(delta.terminal);
        assert!(stream.next_chunk().await.is_none());
        assert_eq!(port.calls(), 3);
    }
}
