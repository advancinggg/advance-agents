//! Neutral fixture shell: lifecycle knobs, home, guests, client helpers, gone-check.

use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::api::{
    BoxFuture, ComposeCx, ComposeExtension, ExtensionError, ExtensionPhase, GatewayHandle,
    HostFunctionDef, HostFunctionRegistrar, StartedCx, ToolRegistrar,
};

mod capabilities;
mod client;
mod gone;
mod guests;
mod home;
mod lifecycle;

pub use capabilities::{
    EchoTool, FixtureHostFn, FixtureSpec, FixtureTool, ProbeHandler, ECHO_TOOL, PROBE_CAPABILITY,
    PROBE_FUNCTION, PROBE_NAMESPACE,
};
pub use client::{mint_browser_session, mint_session, post_msg, Http, HttpResponse};
pub use gone::assert_gone_for_home;
pub use guests::{ext_probe_core, hello_llm_core, llm_noerr_core, minimal_core};
pub use home::{CapDecl, FixtureDriver, FixtureHome, FixtureHomeSpec, FIXTURE_MASTER_KEY};
pub use lifecycle::{FixtureLifecycle, OnStartedMode, ShutdownMode};

pub const FIXTURE_ID: &str = "fixture";
pub const FIXTURE_TWO_ID: &str = "fixture-two";

pub struct FixtureExtension {
    id: &'static str,
    lifecycle: FixtureLifecycle,
    secret_need: bool,
    breaks: FixtureBreaks,
    record: Arc<FixtureRecord>,
    spec: Option<FixtureSpec>,
}

#[derive(Clone, Copy, Default)]
pub struct FixtureBreaks {
    pub panic_in: Option<ExtensionPhase>,
    pub fail_in: Option<ExtensionPhase>,
    pub id_panics: bool,
    pub secret_need_panics: bool,
}

impl FixtureExtension {
    pub fn new(id: &'static str) -> Self {
        Self {
            id,
            lifecycle: FixtureLifecycle::default(),
            secret_need: false,
            breaks: FixtureBreaks::default(),
            record: Arc::new(FixtureRecord::default()),
            spec: None,
        }
    }

    pub fn with_spec(mut self, spec: FixtureSpec) -> Self {
        self.spec = Some(spec);
        self
    }

    pub fn standard() -> Self {
        Self::new(FIXTURE_ID).with_spec(FixtureSpec::standard())
    }

    pub fn with_lifecycle(mut self, lifecycle: FixtureLifecycle) -> Self {
        self.lifecycle = lifecycle;
        self
    }

    pub fn needing_secret_store(mut self) -> Self {
        self.secret_need = true;
        self
    }

    pub fn with_breaks(mut self, breaks: FixtureBreaks) -> Self {
        debug_assert!(breaks.fail_in != Some(ExtensionPhase::Capabilities));
        self.breaks = breaks;
        self
    }

    pub fn sharing(mut self, record: &Arc<FixtureRecord>) -> Self {
        self.record = Arc::clone(record);
        self
    }

    pub fn record(&self) -> Arc<FixtureRecord> {
        Arc::clone(&self.record)
    }

    pub fn arc(self) -> Arc<dyn ComposeExtension> {
        Arc::new(self)
    }

    pub(crate) fn enter_phase(
        &self,
        phase: ExtensionPhase,
        cx: Option<&ComposeCx>,
    ) -> Result<(), ExtensionError> {
        self.record
            .order
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .push(FixtureCall {
                extension: self.id,
                phase: phase_name(phase),
                at: Instant::now(),
                discovery_present: cx
                    .map(|cx| cx.home().join(".runtime/client-api").exists())
                    .unwrap_or(false),
                client_api_base: None,
            });
        if self.breaks.panic_in == Some(phase) {
            panic!("fixture panic in {}", phase_name(phase));
        }
        if self.breaks.fail_in == Some(phase) {
            return Err(ExtensionError::new(format!(
                "fixture failure in {}",
                phase_name(phase)
            )));
        }
        Ok(())
    }
}

pub(crate) fn phase_name(phase: ExtensionPhase) -> &'static str {
    match phase {
        ExtensionPhase::Capabilities => "capabilities",
        ExtensionPhase::Inference => "inference",
        ExtensionPhase::HostFunctions => "host_functions",
        ExtensionPhase::Tools => "tools",
        ExtensionPhase::ClientFamilies => "client_families",
    }
}

impl ComposeExtension for FixtureExtension {
    fn id(&self) -> &'static str {
        if self.breaks.id_panics {
            panic!("fixture id panic");
        }
        self.id
    }

    fn capabilities(&self) -> &'static [&'static str] {
        let _ = self.enter_phase(ExtensionPhase::Capabilities, None);
        self.spec
            .as_ref()
            .map(|spec| spec.capabilities)
            .unwrap_or(&[])
    }

    fn host_functions(
        &self,
        cx: &ComposeCx,
        reg: &mut HostFunctionRegistrar,
    ) -> Result<(), ExtensionError> {
        self.enter_phase(ExtensionPhase::HostFunctions, Some(cx))?;
        if let Some(spec) = &self.spec {
            for host_fn in &spec.host_functions {
                let handler = Arc::new(ProbeHandler {
                    record: Arc::clone(&self.record),
                });
                reg.register(HostFunctionDef::new(
                    host_fn.capability,
                    host_fn.namespace,
                    host_fn.name,
                    handler,
                ))?;
            }
        }
        Ok(())
    }

    fn tools<'a>(
        &'a self,
        cx: &'a ComposeCx,
        reg: &'a mut ToolRegistrar,
    ) -> BoxFuture<'a, Result<(), ExtensionError>> {
        Box::pin(async move {
            self.enter_phase(ExtensionPhase::Tools, Some(cx))?;
            if let Some(spec) = &self.spec {
                for tool in &spec.tools {
                    let echo = Arc::new(EchoTool {
                        record: Arc::clone(&self.record),
                    });
                    reg.register(tool.id, echo).await?;
                }
            }
            Ok(())
        })
    }

    fn needs_secret_store(&self) -> bool {
        if self.breaks.secret_need_panics {
            panic!("fixture secret-need panic");
        }
        self.secret_need
    }

    fn on_started<'a>(&'a self, cx: &'a StartedCx) -> BoxFuture<'a, Result<(), ExtensionError>> {
        self.run_on_started(cx)
    }

    fn shutdown<'a>(&'a self) -> BoxFuture<'a, ()> {
        self.run_shutdown()
    }
}

#[derive(Default)]
pub struct FixtureRecord {
    pub order: Mutex<Vec<FixtureCall>>,
    pub started: Mutex<Option<StartedSnapshot>>,
    pub on_started_dropped: AtomicBool,
    pub on_started_returned: AtomicBool,
    pub hooks: Mutex<Vec<&'static str>>,
    pub ticks: AtomicU64,
    pub ticker_dropped: AtomicBool,
    pub host_calls: AtomicUsize,
    pub tool_calls: AtomicUsize,
    gate: tokio::sync::Notify,
    panic_ticker: AtomicBool,
}

impl FixtureRecord {
    pub fn phases(&self) -> Vec<&'static str> {
        self.calls().into_iter().map(|call| call.phase).collect()
    }

    pub fn calls(&self) -> Vec<FixtureCall> {
        self.order
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    pub async fn started(&self, within: Duration) -> Option<StartedSnapshot> {
        let deadline = Instant::now() + within;
        loop {
            if let Some(snapshot) = self
                .started
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .clone()
            {
                return Some(snapshot);
            }
            if Instant::now() >= deadline {
                return None;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    pub fn release_on_started(&self) {
        self.gate.notify_one();
    }

    pub fn panic_ticker(&self) {
        self.panic_ticker.store(true, Ordering::SeqCst);
    }
}

#[derive(Clone, Debug)]
pub struct FixtureCall {
    pub extension: &'static str,
    pub phase: &'static str,
    pub at: Instant,
    pub discovery_present: bool,
    pub client_api_base: Option<String>,
}

#[derive(Clone)]
pub struct StartedSnapshot {
    pub cx: ComposeCx,
    pub client_api_base: Option<String>,
    pub gateway: Option<GatewayHandle>,
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;

    #[test]
    fn module_001_ac31_fixture_uses_only_public_api() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/test_support/fixture");
        let mut files = Vec::new();
        visit(&root, &mut files);
        files.sort();
        assert!(!files.is_empty(), "fixture sources");
        for path in files {
            let text = fs::read_to_string(&path).expect("read fixture source");
            let mut in_tests = false;
            for (index, line) in text.lines().enumerate() {
                let trimmed = line.trim_start();
                if trimmed.starts_with("#[cfg(test)]") {
                    in_tests = true;
                    continue;
                }
                if in_tests {
                    continue;
                }
                let code = strip_comments_and_strings(trimmed);
                if let Some(rest) = code.trim_start().strip_prefix("use crate::") {
                    let ok = rest.starts_with("api::") || rest.starts_with("test_support::");
                    assert!(
                        ok,
                        "{}:{}: fixture code may only `use crate::api::` or `use crate::test_support::`",
                        path.display(),
                        index + 1
                    );
                }
                assert!(
                    !code.contains("println!")
                        && !code.contains("eprintln!")
                        && !code.contains("std::io::stdout")
                        && !code.contains("std::io::stderr")
                        && !code.contains("std::process"),
                    "{}:{}: fixture code must not print or spawn processes",
                    path.display(),
                    index + 1
                );
            }
        }
    }

    fn strip_comments_and_strings(line: &str) -> String {
        let mut out = String::new();
        let mut chars = line.chars().peekable();
        let mut in_string = false;
        while let Some(c) = chars.next() {
            if in_string {
                if c == '\\' {
                    let _ = chars.next();
                } else if c == '"' {
                    in_string = false;
                }
                continue;
            }
            if c == '"' {
                in_string = true;
                continue;
            }
            if c == '/' && chars.peek() == Some(&'/') {
                break;
            }
            out.push(c);
        }
        out
    }

    fn visit(dir: &std::path::Path, files: &mut Vec<PathBuf>) {
        for entry in fs::read_dir(dir).expect("read fixture dir") {
            let entry = entry.expect("dirent");
            let path = entry.path();
            if path.is_dir() {
                visit(&path, files);
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                files.push(path);
            }
        }
    }
}
