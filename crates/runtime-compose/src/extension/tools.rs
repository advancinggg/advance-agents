//! Native-tool registrar containment and the tools site.

use std::panic::AssertUnwindSafe;
use std::sync::Arc;

use async_trait::async_trait;
use cap_tools::{HostTool, LazyToolRegistry, ToolDescription, ToolError};
use futures::FutureExt;

use crate::api::log_keys;
use crate::api::{ComposeError, ExtensionPhase, ToolRefusal, ToolRegistrar};
use crate::compose_log::LogHandle;
use crate::extension::call::{scope, CallIdentity};
use crate::extension::guard;
use crate::extension::set::ExtensionSet;

const MAX_TOOL_ID_LEN: usize = 128;

/// Call every extension's `tools` and register accepted tools immediately.
pub(crate) async fn run_tools(
    exts: &ExtensionSet,
    tools: &Arc<LazyToolRegistry>,
    log: &LogHandle,
) -> Result<usize, ComposeError> {
    let mut n = 0;
    for (id, ext, cx) in exts.iter_with_cx()? {
        let mut reg = ToolRegistrar::new(id, Arc::clone(tools), log);
        let result =
            guard::run_async_callback(id, ExtensionPhase::Tools, || ext.tools(cx, &mut reg))
                .await?;
        if let Some(refusal) = reg.first_refusal() {
            return Err(ComposeError::Tool {
                extension: id,
                refusal: refusal.clone(),
            });
        }
        if let Err(error) = result {
            return Err(guard::failed(id, ExtensionPhase::Tools, &error));
        }
        n += reg.registered;
    }
    Ok(n)
}

impl ToolRegistrar {
    pub(crate) fn new(
        extension: &'static str,
        tools: Arc<LazyToolRegistry>,
        log: &LogHandle,
    ) -> Self {
        Self {
            extension,
            tools,
            refusals: Vec::new(),
            registered: 0,
            log: log.sink(),
        }
    }

    pub(crate) fn first_refusal(&self) -> Option<&ToolRefusal> {
        self.refusals.first()
    }

    /// Wraps `tool` in the containment adapter and registers it through
    /// [`LazyToolRegistry::register_host`]. Every refusal is also recorded
    /// (`compose` fails with the first one).
    pub async fn register(
        &mut self,
        id: impl Into<String> + Send,
        tool: Arc<dyn HostTool>,
    ) -> Result<(), ToolRefusal> {
        let id = id.into();
        if let Err(refusal) = self.check_id(&id).await {
            self.refusals.push(refusal.clone());
            return Err(refusal);
        }
        let description = match std::panic::catch_unwind(AssertUnwindSafe(|| tool.describe())) {
            Ok(description) => description,
            Err(_) => {
                let refusal = ToolRefusal::DescribePanicked { id };
                self.refusals.push(refusal.clone());
                return Err(refusal);
            }
        };
        let contained = Arc::new(ContainedHostTool {
            extension: self.extension,
            id: id.clone(),
            inner: Some(tool),
            description,
            log: LogHandle::new(Arc::clone(&self.log)),
        });
        match self.tools.register_host(id.clone(), contained).await {
            Ok(()) => {
                self.registered += 1;
                Ok(())
            }
            Err(error) => {
                let refusal = ToolRefusal::Invalid {
                    id,
                    reason: error.to_string(),
                };
                self.refusals.push(refusal.clone());
                Err(refusal)
            }
        }
    }

    async fn check_id(&self, id: &str) -> Result<(), ToolRefusal> {
        if let Some(reason) = invalid_id_reason(id) {
            return Err(ToolRefusal::Invalid {
                id: id.to_owned(),
                reason: reason.to_owned(),
            });
        }
        if is_reserved_tool_id(id) {
            return Err(ToolRefusal::Reserved { id: id.to_owned() });
        }
        if self.tools.is_registered(id).await {
            return Err(ToolRefusal::Duplicate { id: id.to_owned() });
        }
        Ok(())
    }
}

fn invalid_id_reason(id: &str) -> Option<&'static str> {
    if id.is_empty() {
        return Some("empty");
    }
    if id.len() > MAX_TOOL_ID_LEN {
        return Some("longer than 128 bytes");
    }
    if id.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Some("contains whitespace or control characters");
    }
    None
}

fn is_reserved_tool_id(id: &str) -> bool {
    id == advance_shared_types::entity::DATA_TOOL_ID
        || id.starts_with("skill::")
        || advance_shared_types::web_search::is_web_tool_id(id)
}

pub(crate) struct ContainedHostTool {
    extension: &'static str,
    id: String,
    inner: Option<Arc<dyn HostTool>>,
    description: ToolDescription,
    log: LogHandle,
}

#[async_trait]
impl HostTool for ContainedHostTool {
    fn describe(&self) -> ToolDescription {
        self.description.clone()
    }

    async fn execute(&self, method: &str, params: &[u8]) -> Result<Vec<u8>, ToolError> {
        let Some(inner) = self.inner.as_ref() else {
            return Err(self.failure());
        };
        let built =
            match std::panic::catch_unwind(AssertUnwindSafe(|| inner.execute(method, params))) {
                Ok(fut) => fut,
                Err(_) => return self.on_panic(method),
            };
        match AssertUnwindSafe(built).catch_unwind().await {
            Ok(result) => result,
            Err(_) => self.on_panic(method),
        }
    }

    async fn execute_as(
        &self,
        agent_id: &str,
        method: &str,
        params: &[u8],
    ) -> Result<Vec<u8>, ToolError> {
        let Some(inner) = self.inner.as_ref() else {
            return Err(self.failure());
        };
        let id = CallIdentity::tool(self.extension, agent_id, &self.id, method);
        let built = match std::panic::catch_unwind(AssertUnwindSafe(|| {
            inner.execute_as(agent_id, method, params)
        })) {
            Ok(fut) => fut,
            Err(_) => return self.on_panic(method),
        };
        match AssertUnwindSafe(scope(id, built)).catch_unwind().await {
            Ok(result) => result,
            Err(_) => self.on_panic(method),
        }
    }
}

impl ContainedHostTool {
    fn failure(&self) -> ToolError {
        ToolError::InvocationFailed(format!(
            "extension {}: tool {} failed",
            self.extension, self.id
        ))
    }

    fn on_panic(&self, method: &str) -> Result<Vec<u8>, ToolError> {
        self.log.err(
            log_keys::EXT_TOOL_PANICKED,
            format!(
                "advance: WARN extension {} tool {} panicked in {}; the call failed",
                self.extension,
                self.id,
                guard::sanitize_text(method)
            ),
        );
        Err(self.failure())
    }
}

impl Drop for ContainedHostTool {
    fn drop(&mut self) {
        let inner = self.inner.take();
        if std::panic::catch_unwind(AssertUnwindSafe(move || drop(inner))).is_err() {
            self.log.err(
                log_keys::EXT_TOOL_PANICKED,
                format!(
                    "advance: WARN extension {} tool {} panicked in drop; ignored",
                    self.extension, self.id
                ),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::{HostTool, MethodInfo};
    use crate::extension::call;
    use crate::test_support::MemoryComposeLog;
    use cap_tools::LazyRegistryConfig;
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    fn echo_desc() -> ToolDescription {
        desc(&["echo"])
    }

    fn desc(methods: &[&str]) -> ToolDescription {
        ToolDescription {
            description: String::new(),
            methods: methods
                .iter()
                .map(|name| MethodInfo {
                    name: (*name).to_owned(),
                    description: None,
                    input_schema: None,
                    output_schema: None,
                    idempotent: None,
                })
                .collect(),
        }
    }

    struct Nop;

    #[async_trait]
    impl HostTool for Nop {
        fn describe(&self) -> ToolDescription {
            echo_desc()
        }

        async fn execute(&self, _method: &str, _params: &[u8]) -> Result<Vec<u8>, ToolError> {
            Ok(Vec::new())
        }
    }

    fn nop() -> Arc<dyn HostTool> {
        Arc::new(Nop)
    }

    fn registry() -> Arc<LazyToolRegistry> {
        Arc::new(LazyToolRegistry::new(LazyRegistryConfig::default()))
    }

    fn registrar() -> (ToolRegistrar, MemoryComposeLog) {
        let sink = MemoryComposeLog::new();
        let log = LogHandle::new(Arc::new(sink.clone()));
        (ToolRegistrar::new("fixture", registry(), &log), sink)
    }

    fn wrap(inner: Arc<dyn HostTool>) -> (ContainedHostTool, MemoryComposeLog) {
        let sink = MemoryComposeLog::new();
        let description = inner.describe();
        (
            ContainedHostTool {
                extension: "fixture",
                id: "fixture.echo".into(),
                inner: Some(inner),
                description,
                log: LogHandle::new(Arc::new(sink.clone())),
            },
            sink,
        )
    }

    fn texts(sink: &MemoryComposeLog) -> Vec<(String, String)> {
        sink.lines()
            .into_iter()
            .map(|line| (line.key.to_owned(), line.text))
            .collect()
    }

    fn assert_no_payload(sink: &MemoryComposeLog, payload: &str) {
        for line in sink.lines() {
            assert!(
                !line.text.contains(payload),
                "payload {payload:?} leaked into {}",
                line.text
            );
        }
    }

    #[tokio::test]
    async fn module_001_ac31_tool_registrar_refusals() {
        // Reserved ×3.
        for id in ["data", "skill::agenda", "web.search"] {
            let mut reg = registrar().0;
            let err = reg.register(id, nop()).await.expect_err("reserved");
            assert_eq!(err, ToolRefusal::Reserved { id: id.into() });
            assert_eq!(reg.first_refusal(), Some(&err));
            assert_eq!(err.to_string(), format!("tool {id:?}: reserved for OSS"));
        }
        let mut ignored = registrar().0;
        let _ = ignored.register("web.extract", nop()).await;
        assert_eq!(
            ignored.first_refusal(),
            Some(&ToolRefusal::Reserved {
                id: "web.extract".into()
            })
        );

        // Duplicate.
        let (mut reg, _) = registrar();
        reg.register("fixture.echo", nop())
            .await
            .expect("first register");
        let err = reg
            .register("fixture.echo", nop())
            .await
            .expect_err("duplicate");
        assert_eq!(
            err,
            ToolRefusal::Duplicate {
                id: "fixture.echo".into()
            }
        );
        assert_eq!(reg.first_refusal(), Some(&err));
        assert_eq!(err.to_string(), "tool \"fixture.echo\": already registered");

        // Invalid: empty, whitespace, 129 bytes, duplicate method from register_host.
        let mut reg = registrar().0;
        let err = reg.register("", nop()).await.expect_err("empty");
        assert_eq!(
            err,
            ToolRefusal::Invalid {
                id: String::new(),
                reason: "empty".into(),
            }
        );
        assert_eq!(reg.first_refusal(), Some(&err));
        assert_eq!(err.to_string(), "tool \"\": empty");

        for id in [" ", "a b", "echo\n"] {
            let mut reg = registrar().0;
            let _ = reg.register(id, nop()).await;
            assert_eq!(
                reg.first_refusal(),
                Some(&ToolRefusal::Invalid {
                    id: id.into(),
                    reason: "contains whitespace or control characters".into(),
                }),
                "{id:?}"
            );
        }

        let too_long = "a".repeat(MAX_TOOL_ID_LEN + 1);
        let mut reg = registrar().0;
        let err = reg
            .register(too_long.clone(), nop())
            .await
            .expect_err("129");
        assert_eq!(
            err,
            ToolRefusal::Invalid {
                id: too_long,
                reason: "longer than 128 bytes".into(),
            }
        );
        registrar()
            .0
            .register("a".repeat(MAX_TOOL_ID_LEN), nop())
            .await
            .expect("128-byte id");

        struct DupMethods;
        #[async_trait]
        impl HostTool for DupMethods {
            fn describe(&self) -> ToolDescription {
                desc(&["echo", "echo"])
            }
            async fn execute(&self, _method: &str, _params: &[u8]) -> Result<Vec<u8>, ToolError> {
                Ok(Vec::new())
            }
        }
        let mut reg = registrar().0;
        let err = reg
            .register("fixture.echo", Arc::new(DupMethods))
            .await
            .expect_err("dup method");
        match &err {
            ToolRefusal::Invalid { id, reason } => {
                assert_eq!(id, "fixture.echo");
                assert!(
                    reason.contains("declares method \"echo\" twice"),
                    "{reason}"
                );
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(reg.first_refusal(), Some(&err));

        // DescribePanicked.
        struct Boom;
        #[async_trait]
        impl HostTool for Boom {
            fn describe(&self) -> ToolDescription {
                panic!("describe-payload");
            }
            async fn execute(&self, _method: &str, _params: &[u8]) -> Result<Vec<u8>, ToolError> {
                Ok(Vec::new())
            }
        }
        let mut reg = registrar().0;
        let err = reg
            .register("fixture.echo", Arc::new(Boom))
            .await
            .expect_err("describe panic");
        assert_eq!(
            err,
            ToolRefusal::DescribePanicked {
                id: "fixture.echo".into()
            }
        );
        assert_eq!(reg.first_refusal(), Some(&err));
        assert_eq!(
            err.to_string(),
            "tool \"fixture.echo\": describe() panicked"
        );
    }

    #[derive(Default)]
    struct Counting {
        describe: AtomicUsize,
        execute: AtomicUsize,
        as_agent: Mutex<Option<String>>,
        identity: Mutex<Option<(String, String, String)>>,
    }

    #[async_trait]
    impl HostTool for Counting {
        fn describe(&self) -> ToolDescription {
            self.describe.fetch_add(1, Ordering::SeqCst);
            echo_desc()
        }

        async fn execute(&self, _method: &str, params: &[u8]) -> Result<Vec<u8>, ToolError> {
            self.execute.fetch_add(1, Ordering::SeqCst);
            *self.identity.lock().expect("id") = current_identity();
            Ok(params.to_vec())
        }

        async fn execute_as(
            &self,
            agent_id: &str,
            method: &str,
            params: &[u8],
        ) -> Result<Vec<u8>, ToolError> {
            *self.as_agent.lock().expect("agent") = Some(agent_id.to_owned());
            self.execute(method, params).await
        }
    }

    fn current_identity() -> Option<(String, String, String)> {
        call::current().map(|id| {
            (
                id.extension().to_owned(),
                id.agent_id().to_owned(),
                id.function().to_owned(),
            )
        })
    }

    struct SyncPanic;
    impl HostTool for SyncPanic {
        fn describe(&self) -> ToolDescription {
            echo_desc()
        }

        fn execute<'a, 'b, 'c, 'async_trait>(
            &'a self,
            _method: &'b str,
            _params: &'c [u8],
        ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, ToolError>> + Send + 'async_trait>>
        where
            'a: 'async_trait,
            'b: 'async_trait,
            'c: 'async_trait,
            Self: 'async_trait,
        {
            panic!("sync-payload");
        }
    }

    struct AsyncPanic;
    #[async_trait]
    impl HostTool for AsyncPanic {
        fn describe(&self) -> ToolDescription {
            echo_desc()
        }

        async fn execute(&self, _method: &str, _params: &[u8]) -> Result<Vec<u8>, ToolError> {
            panic!("async-payload");
        }
    }

    struct DropPanic;
    #[async_trait]
    impl HostTool for DropPanic {
        fn describe(&self) -> ToolDescription {
            echo_desc()
        }

        async fn execute(&self, _method: &str, _params: &[u8]) -> Result<Vec<u8>, ToolError> {
            Ok(Vec::new())
        }
    }
    impl Drop for DropPanic {
        fn drop(&mut self) {
            panic!("drop-payload");
        }
    }

    #[tokio::test]
    async fn module_001_ac31_contained_host_tool() {
        let inner = Arc::new(Counting::default());
        let (contained, sink) = wrap(Arc::clone(&inner) as Arc<dyn HostTool>);
        assert_eq!(inner.describe.load(Ordering::SeqCst), 1);
        let _ = contained.describe();
        let _ = contained.describe();
        assert_eq!(inner.describe.load(Ordering::SeqCst), 1);
        assert!(sink.lines().is_empty());

        let out = contained.execute("echo", b"hi").await.expect("execute ok");
        assert_eq!(out, b"hi");
        assert_eq!(inner.execute.load(Ordering::SeqCst), 1);
        assert_eq!(*inner.identity.lock().expect("id"), None);

        let out = contained
            .execute_as("root", "echo", b"as")
            .await
            .expect("execute_as ok");
        assert_eq!(out, b"as");
        assert_eq!(
            inner.as_agent.lock().expect("agent").as_deref(),
            Some("root")
        );
        assert_eq!(
            *inner.identity.lock().expect("id"),
            Some((
                "fixture".into(),
                "root".into(),
                "tool::fixture.echo/echo".into()
            ))
        );

        let (contained, sink) = wrap(Arc::new(SyncPanic));
        let err = contained
            .execute("echo", b"")
            .await
            .expect_err("sync panic");
        match err {
            ToolError::InvocationFailed(message) => {
                assert_eq!(message, "extension fixture: tool fixture.echo failed");
            }
            other => panic!("{other}"),
        }
        let lines = texts(&sink);
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0].0, log_keys::EXT_TOOL_PANICKED);
        assert_eq!(
            lines[0].1,
            "advance: WARN extension fixture tool fixture.echo panicked in echo; the call failed"
        );
        assert_no_payload(&sink, "sync-payload");

        let (contained, sink) = wrap(Arc::new(AsyncPanic));
        let err = contained
            .execute("echo", b"")
            .await
            .expect_err("async panic");
        match err {
            ToolError::InvocationFailed(message) => {
                assert_eq!(message, "extension fixture: tool fixture.echo failed");
            }
            other => panic!("{other}"),
        }
        assert_eq!(sink.count(log_keys::EXT_TOOL_PANICKED), 1);
        assert_no_payload(&sink, "async-payload");

        let (contained, sink) = wrap(Arc::new(AsyncPanic));
        let err = contained
            .execute("echo\npanic", b"")
            .await
            .expect_err("newline method");
        match err {
            ToolError::InvocationFailed(_) => {}
            other => panic!("{other}"),
        }
        let lines = texts(&sink);
        assert_eq!(lines.len(), 1);
        assert!(
            lines[0]
                .1
                .contains("panicked in echo panic; the call failed"),
            "{}",
            lines[0].1
        );
        assert!(!lines[0].1.contains('\n'));

        let sink = MemoryComposeLog::new();
        let contained = ContainedHostTool {
            extension: "fixture",
            id: "fixture.echo".into(),
            inner: Some(Arc::new(DropPanic)),
            description: echo_desc(),
            log: LogHandle::new(Arc::new(sink.clone())),
        };
        drop(contained);
        let lines = texts(&sink);
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0].0, log_keys::EXT_TOOL_PANICKED);
        assert_eq!(
            lines[0].1,
            "advance: WARN extension fixture tool fixture.echo panicked in drop; ignored"
        );
        assert_no_payload(&sink, "drop-payload");
    }
}
