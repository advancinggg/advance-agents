//! Containment adapters for extension inference ports, streams, and mesh dispatch.

use std::future::Future;
use std::panic::AssertUnwindSafe;
use std::sync::Arc;

use advance_shared_types::inference::{
    InferenceBackendError, InferenceBackendPort, InferenceChatRequest, InferenceChatResponse,
    InferenceEmbedRequest, InferenceEmbedResponse, InferenceStream, InferenceStreamHead,
    InferenceTextDelta, MeshCarrier, MeshInferenceDispatch, MeshInferenceDispatchError,
};
use async_trait::async_trait;
use futures::FutureExt;

use crate::api::log_keys;
use crate::compose_log::LogHandle;

async fn guarded<T, F>(make: impl FnOnce() -> F) -> Result<T, ()>
where
    F: Future<Output = T> + Send,
{
    let fut = std::panic::catch_unwind(AssertUnwindSafe(make)).map_err(|_| ())?;
    AssertUnwindSafe(fut).catch_unwind().await.map_err(|_| ())
}

pub(crate) struct ContainedInferencePort {
    ext: &'static str,
    entry: String,
    log: LogHandle,
    inner: Option<Arc<dyn InferenceBackendPort>>,
}

pub(crate) struct ContainedMeshDispatch {
    ext: &'static str,
    log: LogHandle,
    inner: Option<Arc<dyn MeshInferenceDispatch>>,
}

pub(crate) struct ContainedStream {
    ext: &'static str,
    owner: StreamOwner,
    log: LogHandle,
    inner: Option<Box<dyn InferenceStream>>,
}

pub(crate) enum StreamOwner {
    Port(String),
    Mesh,
}

impl ContainedInferencePort {
    pub(crate) fn new(
        ext: &'static str,
        entry: &str,
        inner: Arc<dyn InferenceBackendPort>,
        log: LogHandle,
    ) -> Self {
        Self {
            ext,
            entry: entry.to_owned(),
            log,
            inner: Some(inner),
        }
    }

    fn port_panic(&self) -> InferenceBackendError {
        InferenceBackendError::LocalTransport(format!(
            "extension {}: inference port panicked",
            self.ext
        ))
    }

    fn log_op(&self, op: &str) {
        let text = match op {
            "is_wired" => format!(
                "advance: WARN extension {} inference port {} panicked in is_wired; answered wired",
                self.ext, self.entry
            ),
            "drop" => format!(
                "advance: WARN extension {} inference port {} panicked in drop; continuing",
                self.ext, self.entry
            ),
            _ => format!(
                "advance: WARN extension {} inference port {} panicked in {op}; the call answered a typed error",
                self.ext, self.entry
            ),
        };
        self.log.err(log_keys::EXT_INFERENCE_PORT_PANICKED, text);
    }
}

impl ContainedMeshDispatch {
    pub(crate) fn new(
        ext: &'static str,
        inner: Arc<dyn MeshInferenceDispatch>,
        log: LogHandle,
    ) -> Self {
        Self {
            ext,
            log,
            inner: Some(inner),
        }
    }

    fn dispatch_panic(&self) -> MeshInferenceDispatchError {
        MeshInferenceDispatchError::Provider(format!(
            "extension {}: mesh dispatch panicked",
            self.ext
        ))
    }

    fn log_op(&self, op: &str) {
        let text = match op {
            "is_wired" => format!(
                "advance: WARN extension {} mesh dispatch panicked in is_wired; answered wired",
                self.ext
            ),
            "drop" => format!(
                "advance: WARN extension {} mesh dispatch panicked in drop; continuing",
                self.ext
            ),
            _ => format!(
                "advance: WARN extension {} mesh dispatch panicked in {op}; the call answered a typed error",
                self.ext
            ),
        };
        self.log.err(log_keys::EXT_MESH_DISPATCH_PANICKED, text);
    }
}

impl ContainedStream {
    fn stream_panic(&self) -> InferenceBackendError {
        InferenceBackendError::LocalTransport(format!(
            "extension {}: inference stream panicked",
            self.ext
        ))
    }

    fn log_stream(&self, op: &str, end: &str) {
        match &self.owner {
            StreamOwner::Port(entry) => {
                self.log.err(
                    log_keys::EXT_INFERENCE_PORT_PANICKED,
                    format!(
                        "advance: WARN extension {} inference port {entry} stream panicked in {op}; {end}",
                        self.ext
                    ),
                );
            }
            StreamOwner::Mesh => {
                self.log.err(
                    log_keys::EXT_MESH_DISPATCH_PANICKED,
                    format!(
                        "advance: WARN extension {} mesh dispatch stream panicked in {op}; {end}",
                        self.ext
                    ),
                );
            }
        }
    }
}

#[async_trait]
impl InferenceBackendPort for ContainedInferencePort {
    async fn chat(
        &self,
        req: InferenceChatRequest,
    ) -> Result<InferenceChatResponse, InferenceBackendError> {
        let Some(inner) = self.inner.clone() else {
            return Err(self.port_panic());
        };
        match guarded(move || async move { inner.chat(req).await }).await {
            Ok(result) => result,
            Err(()) => {
                self.log_op("chat");
                Err(self.port_panic())
            }
        }
    }

    async fn embed(
        &self,
        req: InferenceEmbedRequest,
    ) -> Result<InferenceEmbedResponse, InferenceBackendError> {
        let Some(inner) = self.inner.clone() else {
            return Err(self.port_panic());
        };
        match guarded(move || async move { inner.embed(req).await }).await {
            Ok(result) => result,
            Err(()) => {
                self.log_op("embed");
                Err(self.port_panic())
            }
        }
    }

    async fn start_stream(
        &self,
        req: InferenceChatRequest,
    ) -> Result<(InferenceStreamHead, Box<dyn InferenceStream>), InferenceBackendError> {
        let Some(inner) = self.inner.clone() else {
            return Err(self.port_panic());
        };
        match guarded(move || async move { inner.start_stream(req).await }).await {
            Ok(Ok((head, stream))) => Ok((
                head,
                Box::new(ContainedStream {
                    ext: self.ext,
                    owner: StreamOwner::Port(self.entry.clone()),
                    log: self.log.clone(),
                    inner: Some(stream),
                }),
            )),
            Ok(Err(error)) => Err(error),
            Err(()) => {
                self.log_op("start_stream");
                Err(self.port_panic())
            }
        }
    }

    fn is_wired(&self) -> bool {
        let Some(inner) = self.inner.as_ref() else {
            return true;
        };
        match std::panic::catch_unwind(AssertUnwindSafe(|| inner.is_wired())) {
            Ok(wired) => wired,
            Err(_) => {
                self.log_op("is_wired");
                true
            }
        }
    }
}

#[async_trait]
impl MeshInferenceDispatch for ContainedMeshDispatch {
    async fn dispatch_chat(
        &self,
        req: InferenceChatRequest,
        invocation_id: &str,
        target_device_id: &str,
    ) -> Result<InferenceChatResponse, MeshInferenceDispatchError> {
        let Some(inner) = self.inner.clone() else {
            return Err(self.dispatch_panic());
        };
        let invocation_id = invocation_id.to_owned();
        let target_device_id = target_device_id.to_owned();
        match guarded(move || async move {
            inner
                .dispatch_chat(req, &invocation_id, &target_device_id)
                .await
        })
        .await
        {
            Ok(result) => result,
            Err(()) => {
                self.log_op("dispatch_chat");
                Err(self.dispatch_panic())
            }
        }
    }

    async fn dispatch_embed(
        &self,
        req: InferenceEmbedRequest,
        invocation_id: &str,
        target_device_id: &str,
    ) -> Result<InferenceEmbedResponse, MeshInferenceDispatchError> {
        let Some(inner) = self.inner.clone() else {
            return Err(self.dispatch_panic());
        };
        let invocation_id = invocation_id.to_owned();
        let target_device_id = target_device_id.to_owned();
        match guarded(move || async move {
            inner
                .dispatch_embed(req, &invocation_id, &target_device_id)
                .await
        })
        .await
        {
            Ok(result) => result,
            Err(()) => {
                self.log_op("dispatch_embed");
                Err(self.dispatch_panic())
            }
        }
    }

    async fn start_stream(
        &self,
        req: InferenceChatRequest,
        invocation_id: &str,
        target_device_id: &str,
    ) -> Result<
        (InferenceStreamHead, Box<dyn InferenceStream>, MeshCarrier),
        MeshInferenceDispatchError,
    > {
        let Some(inner) = self.inner.clone() else {
            return Err(self.dispatch_panic());
        };
        let invocation_id = invocation_id.to_owned();
        let target_device_id = target_device_id.to_owned();
        match guarded(move || async move {
            inner
                .start_stream(req, &invocation_id, &target_device_id)
                .await
        })
        .await
        {
            Ok(Ok((head, stream, carrier))) => Ok((
                head,
                Box::new(ContainedStream {
                    ext: self.ext,
                    owner: StreamOwner::Mesh,
                    log: self.log.clone(),
                    inner: Some(stream),
                }),
                carrier,
            )),
            Ok(Err(error)) => Err(error),
            Err(()) => {
                self.log_op("start_stream");
                Err(self.dispatch_panic())
            }
        }
    }

    fn is_wired(&self) -> bool {
        let Some(inner) = self.inner.as_ref() else {
            return true;
        };
        match std::panic::catch_unwind(AssertUnwindSafe(|| inner.is_wired())) {
            Ok(wired) => wired,
            Err(_) => {
                self.log_op("is_wired");
                true
            }
        }
    }
}

#[async_trait]
impl InferenceStream for ContainedStream {
    async fn next_chunk(&mut self) -> Option<Result<InferenceTextDelta, InferenceBackendError>> {
        let mut inner = match self.inner.take() {
            Some(inner) => inner,
            None => return None,
        };
        let result = AssertUnwindSafe(async { inner.next_chunk().await })
            .catch_unwind()
            .await;
        match result {
            Ok(chunk) => {
                self.inner = Some(inner);
                chunk
            }
            Err(_) => {
                let _ = std::panic::catch_unwind(AssertUnwindSafe(move || drop(inner)));
                self.log_stream("next_chunk", "the stream ended with a typed error");
                Some(Err(self.stream_panic()))
            }
        }
    }

    fn cancel(&mut self) {
        let Some(inner) = self.inner.as_mut() else {
            return;
        };
        if std::panic::catch_unwind(AssertUnwindSafe(|| inner.cancel())).is_err() {
            self.log_stream("cancel", "continuing");
        }
    }
}

impl Drop for ContainedInferencePort {
    fn drop(&mut self) {
        let inner = self.inner.take();
        if std::panic::catch_unwind(AssertUnwindSafe(move || drop(inner))).is_err() {
            self.log_op("drop");
        }
    }
}

impl Drop for ContainedMeshDispatch {
    fn drop(&mut self) {
        let inner = self.inner.take();
        if std::panic::catch_unwind(AssertUnwindSafe(move || drop(inner))).is_err() {
            self.log_op("drop");
        }
    }
}

impl Drop for ContainedStream {
    fn drop(&mut self) {
        let inner = self.inner.take();
        if std::panic::catch_unwind(AssertUnwindSafe(move || drop(inner))).is_err() {
            match &self.owner {
                StreamOwner::Port(entry) => {
                    self.log.err(
                        log_keys::EXT_INFERENCE_PORT_PANICKED,
                        format!(
                            "advance: WARN extension {} inference port {entry} panicked in drop; continuing",
                            self.ext
                        ),
                    );
                }
                StreamOwner::Mesh => {
                    self.log.err(
                        log_keys::EXT_MESH_DISPATCH_PANICKED,
                        format!(
                            "advance: WARN extension {} mesh dispatch panicked in drop; continuing",
                            self.ext
                        ),
                    );
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::MemoryComposeLog;
    use advance_shared_types::inference::InferenceStreamClass;
    use cap_llm::error::LlmError;
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::{Duration, Instant};

    const PAYLOAD: &str = "port panic";
    const MESH_PAYLOAD: &str = "mesh panic";
    const STREAM_PAYLOAD: &str = "stream-payload";
    const DROP_PAYLOAD: &str = "drop panic";

    fn chat_req() -> InferenceChatRequest {
        InferenceChatRequest {
            provider_id: "e".into(),
            model: "m".into(),
            messages: Vec::new(),
            temperature: None,
            max_tokens: None,
            stop_sequences: None,
            tools: None,
            output_schema: None,
            deadline: Instant::now() + Duration::from_secs(5),
            cancel: Arc::new(AtomicBool::new(false)),
        }
    }

    fn embed_req() -> InferenceEmbedRequest {
        InferenceEmbedRequest {
            provider_id: "e".into(),
            model: "m".into(),
            text: "t".into(),
            deadline: Instant::now() + Duration::from_secs(5),
            cancel: Arc::new(AtomicBool::new(false)),
        }
    }

    fn ok_chat() -> InferenceChatResponse {
        InferenceChatResponse {
            text: "ok".into(),
            model: "m".into(),
            input_tokens: 1,
            output_tokens: 1,
            finish_reason: "stop".into(),
        }
    }

    fn ok_embed() -> InferenceEmbedResponse {
        InferenceEmbedResponse {
            vector: vec![0.0; 4],
            model: "m".into(),
        }
    }

    fn ok_head() -> InferenceStreamHead {
        InferenceStreamHead {
            class: InferenceStreamClass::Success,
            snapshot_only: true,
        }
    }

    struct EmptyStream;

    #[async_trait]
    impl InferenceStream for EmptyStream {
        async fn next_chunk(
            &mut self,
        ) -> Option<Result<InferenceTextDelta, InferenceBackendError>> {
            None
        }
        fn cancel(&mut self) {}
    }

    struct PollPanicPort {
        armed: AtomicBool,
    }

    #[async_trait]
    impl InferenceBackendPort for PollPanicPort {
        async fn chat(
            &self,
            _req: InferenceChatRequest,
        ) -> Result<InferenceChatResponse, InferenceBackendError> {
            if self.armed.swap(false, Ordering::SeqCst) {
                panic!("{PAYLOAD}");
            }
            Ok(ok_chat())
        }
        async fn embed(
            &self,
            _req: InferenceEmbedRequest,
        ) -> Result<InferenceEmbedResponse, InferenceBackendError> {
            if self.armed.swap(false, Ordering::SeqCst) {
                panic!("{PAYLOAD}");
            }
            Ok(ok_embed())
        }
        async fn start_stream(
            &self,
            _req: InferenceChatRequest,
        ) -> Result<(InferenceStreamHead, Box<dyn InferenceStream>), InferenceBackendError>
        {
            if self.armed.swap(false, Ordering::SeqCst) {
                panic!("{PAYLOAD}");
            }
            Ok((ok_head(), Box::new(EmptyStream)))
        }
        fn is_wired(&self) -> bool {
            true
        }
    }

    struct BuildPanicPort;

    impl InferenceBackendPort for BuildPanicPort {
        fn chat<'life0, 'async_trait>(
            &'life0 self,
            _req: InferenceChatRequest,
        ) -> Pin<
            Box<
                dyn Future<Output = Result<InferenceChatResponse, InferenceBackendError>>
                    + Send
                    + 'async_trait,
            >,
        >
        where
            'life0: 'async_trait,
            Self: 'async_trait,
        {
            panic!("{PAYLOAD}");
        }
        fn embed<'life0, 'async_trait>(
            &'life0 self,
            _req: InferenceEmbedRequest,
        ) -> Pin<
            Box<
                dyn Future<Output = Result<InferenceEmbedResponse, InferenceBackendError>>
                    + Send
                    + 'async_trait,
            >,
        >
        where
            'life0: 'async_trait,
            Self: 'async_trait,
        {
            panic!("{PAYLOAD}");
        }
        fn start_stream<'life0, 'async_trait>(
            &'life0 self,
            _req: InferenceChatRequest,
        ) -> Pin<
            Box<
                dyn Future<
                        Output = Result<
                            (InferenceStreamHead, Box<dyn InferenceStream>),
                            InferenceBackendError,
                        >,
                    > + Send
                    + 'async_trait,
            >,
        >
        where
            'life0: 'async_trait,
            Self: 'async_trait,
        {
            panic!("{PAYLOAD}");
        }
        fn is_wired(&self) -> bool {
            true
        }
    }

    struct WiredPanicPort;

    #[async_trait]
    impl InferenceBackendPort for WiredPanicPort {
        async fn chat(
            &self,
            _req: InferenceChatRequest,
        ) -> Result<InferenceChatResponse, InferenceBackendError> {
            Ok(ok_chat())
        }
        async fn embed(
            &self,
            _req: InferenceEmbedRequest,
        ) -> Result<InferenceEmbedResponse, InferenceBackendError> {
            Ok(ok_embed())
        }
        async fn start_stream(
            &self,
            _req: InferenceChatRequest,
        ) -> Result<(InferenceStreamHead, Box<dyn InferenceStream>), InferenceBackendError>
        {
            Ok((ok_head(), Box::new(EmptyStream)))
        }
        fn is_wired(&self) -> bool {
            panic!("{PAYLOAD}");
        }
    }

    struct DropPanicPort;

    #[async_trait]
    impl InferenceBackendPort for DropPanicPort {
        async fn chat(
            &self,
            _req: InferenceChatRequest,
        ) -> Result<InferenceChatResponse, InferenceBackendError> {
            Ok(ok_chat())
        }
        async fn embed(
            &self,
            _req: InferenceEmbedRequest,
        ) -> Result<InferenceEmbedResponse, InferenceBackendError> {
            Ok(ok_embed())
        }
        async fn start_stream(
            &self,
            _req: InferenceChatRequest,
        ) -> Result<(InferenceStreamHead, Box<dyn InferenceStream>), InferenceBackendError>
        {
            Ok((ok_head(), Box::new(EmptyStream)))
        }
        fn is_wired(&self) -> bool {
            true
        }
    }

    impl Drop for DropPanicPort {
        fn drop(&mut self) {
            panic!("{DROP_PAYLOAD}");
        }
    }

    struct PollPanicStream {
        armed: AtomicBool,
        cancel_armed: AtomicBool,
    }

    #[async_trait]
    impl InferenceStream for PollPanicStream {
        async fn next_chunk(
            &mut self,
        ) -> Option<Result<InferenceTextDelta, InferenceBackendError>> {
            if self.armed.swap(false, Ordering::SeqCst) {
                panic!("{STREAM_PAYLOAD}");
            }
            None
        }
        fn cancel(&mut self) {
            if self.cancel_armed.swap(false, Ordering::SeqCst) {
                panic!("{STREAM_PAYLOAD}");
            }
        }
    }

    struct PollPanicDispatch {
        armed: AtomicBool,
    }

    #[async_trait]
    impl MeshInferenceDispatch for PollPanicDispatch {
        async fn dispatch_chat(
            &self,
            _req: InferenceChatRequest,
            _invocation_id: &str,
            _target_device_id: &str,
        ) -> Result<InferenceChatResponse, MeshInferenceDispatchError> {
            if self.armed.swap(false, Ordering::SeqCst) {
                panic!("{MESH_PAYLOAD}");
            }
            Ok(ok_chat())
        }
        async fn dispatch_embed(
            &self,
            _req: InferenceEmbedRequest,
            _invocation_id: &str,
            _target_device_id: &str,
        ) -> Result<InferenceEmbedResponse, MeshInferenceDispatchError> {
            if self.armed.swap(false, Ordering::SeqCst) {
                panic!("{MESH_PAYLOAD}");
            }
            Ok(ok_embed())
        }
        async fn start_stream(
            &self,
            _req: InferenceChatRequest,
            _invocation_id: &str,
            _target_device_id: &str,
        ) -> Result<
            (InferenceStreamHead, Box<dyn InferenceStream>, MeshCarrier),
            MeshInferenceDispatchError,
        > {
            if self.armed.swap(false, Ordering::SeqCst) {
                panic!("{MESH_PAYLOAD}");
            }
            Ok((ok_head(), Box::new(EmptyStream), MeshCarrier::Snapshot))
        }
        fn is_wired(&self) -> bool {
            true
        }
    }

    struct BuildPanicDispatch;

    impl MeshInferenceDispatch for BuildPanicDispatch {
        fn dispatch_chat<'life0, 'life1, 'life2, 'async_trait>(
            &'life0 self,
            _req: InferenceChatRequest,
            _invocation_id: &'life1 str,
            _target_device_id: &'life2 str,
        ) -> Pin<
            Box<
                dyn Future<Output = Result<InferenceChatResponse, MeshInferenceDispatchError>>
                    + Send
                    + 'async_trait,
            >,
        >
        where
            'life0: 'async_trait,
            'life1: 'async_trait,
            'life2: 'async_trait,
            Self: 'async_trait,
        {
            panic!("{MESH_PAYLOAD}");
        }
        fn dispatch_embed<'life0, 'life1, 'life2, 'async_trait>(
            &'life0 self,
            _req: InferenceEmbedRequest,
            _invocation_id: &'life1 str,
            _target_device_id: &'life2 str,
        ) -> Pin<
            Box<
                dyn Future<Output = Result<InferenceEmbedResponse, MeshInferenceDispatchError>>
                    + Send
                    + 'async_trait,
            >,
        >
        where
            'life0: 'async_trait,
            'life1: 'async_trait,
            'life2: 'async_trait,
            Self: 'async_trait,
        {
            panic!("{MESH_PAYLOAD}");
        }
        fn start_stream<'life0, 'life1, 'life2, 'async_trait>(
            &'life0 self,
            _req: InferenceChatRequest,
            _invocation_id: &'life1 str,
            _target_device_id: &'life2 str,
        ) -> Pin<
            Box<
                dyn Future<
                        Output = Result<
                            (InferenceStreamHead, Box<dyn InferenceStream>, MeshCarrier),
                            MeshInferenceDispatchError,
                        >,
                    > + Send
                    + 'async_trait,
            >,
        >
        where
            'life0: 'async_trait,
            'life1: 'async_trait,
            'life2: 'async_trait,
            Self: 'async_trait,
        {
            panic!("{MESH_PAYLOAD}");
        }
        fn is_wired(&self) -> bool {
            true
        }
    }

    struct WiredPanicDispatch;

    #[async_trait]
    impl MeshInferenceDispatch for WiredPanicDispatch {
        async fn dispatch_chat(
            &self,
            _req: InferenceChatRequest,
            _invocation_id: &str,
            _target_device_id: &str,
        ) -> Result<InferenceChatResponse, MeshInferenceDispatchError> {
            Ok(ok_chat())
        }
        async fn dispatch_embed(
            &self,
            _req: InferenceEmbedRequest,
            _invocation_id: &str,
            _target_device_id: &str,
        ) -> Result<InferenceEmbedResponse, MeshInferenceDispatchError> {
            Ok(ok_embed())
        }
        async fn start_stream(
            &self,
            _req: InferenceChatRequest,
            _invocation_id: &str,
            _target_device_id: &str,
        ) -> Result<
            (InferenceStreamHead, Box<dyn InferenceStream>, MeshCarrier),
            MeshInferenceDispatchError,
        > {
            Ok((ok_head(), Box::new(EmptyStream), MeshCarrier::Snapshot))
        }
        fn is_wired(&self) -> bool {
            panic!("{MESH_PAYLOAD}");
        }
    }

    struct DropPanicDispatch;

    #[async_trait]
    impl MeshInferenceDispatch for DropPanicDispatch {
        async fn dispatch_chat(
            &self,
            _req: InferenceChatRequest,
            _invocation_id: &str,
            _target_device_id: &str,
        ) -> Result<InferenceChatResponse, MeshInferenceDispatchError> {
            Ok(ok_chat())
        }
        async fn dispatch_embed(
            &self,
            _req: InferenceEmbedRequest,
            _invocation_id: &str,
            _target_device_id: &str,
        ) -> Result<InferenceEmbedResponse, MeshInferenceDispatchError> {
            Ok(ok_embed())
        }
        async fn start_stream(
            &self,
            _req: InferenceChatRequest,
            _invocation_id: &str,
            _target_device_id: &str,
        ) -> Result<
            (InferenceStreamHead, Box<dyn InferenceStream>, MeshCarrier),
            MeshInferenceDispatchError,
        > {
            Ok((ok_head(), Box::new(EmptyStream), MeshCarrier::Snapshot))
        }
        fn is_wired(&self) -> bool {
            true
        }
    }

    impl Drop for DropPanicDispatch {
        fn drop(&mut self) {
            panic!("{DROP_PAYLOAD}");
        }
    }

    fn wrap_port(
        inner: Arc<dyn InferenceBackendPort>,
    ) -> (ContainedInferencePort, MemoryComposeLog) {
        let sink = MemoryComposeLog::new();
        let log = LogHandle::new(Arc::new(sink.clone()));
        (
            ContainedInferencePort::new("fx", "local-stub", inner, log),
            sink,
        )
    }

    fn wrap_mesh(
        inner: Arc<dyn MeshInferenceDispatch>,
    ) -> (ContainedMeshDispatch, MemoryComposeLog) {
        let sink = MemoryComposeLog::new();
        let log = LogHandle::new(Arc::new(sink.clone()));
        (ContainedMeshDispatch::new("fx", inner, log), sink)
    }

    fn assert_no_payload(sink: &MemoryComposeLog, payload: &str) {
        for line in sink.lines() {
            assert!(
                !line.text.contains(payload),
                "log must not carry the panic payload: {}",
                line.text
            );
        }
    }

    #[tokio::test]
    async fn module_001_ac31_contained_port_panic_typed_logged_without_payload_next_call_ok() {
        let expected =
            InferenceBackendError::LocalTransport("extension fx: inference port panicked".into());
        let poll = Arc::new(PollPanicPort {
            armed: AtomicBool::new(true),
        });
        let (port, sink) = wrap_port(poll);
        assert_eq!(port.chat(chat_req()).await, Err(expected.clone()));
        assert_eq!(port.chat(chat_req()).await, Ok(ok_chat()));
        assert_eq!(sink.count(log_keys::EXT_INFERENCE_PORT_PANICKED), 1);
        assert_no_payload(&sink, PAYLOAD);

        let poll = Arc::new(PollPanicPort {
            armed: AtomicBool::new(true),
        });
        let (port, sink) = wrap_port(poll);
        assert_eq!(port.embed(embed_req()).await, Err(expected.clone()));
        assert_eq!(port.embed(embed_req()).await, Ok(ok_embed()));
        assert_eq!(sink.count(log_keys::EXT_INFERENCE_PORT_PANICKED), 1);

        let poll = Arc::new(PollPanicPort {
            armed: AtomicBool::new(true),
        });
        let (port, sink) = wrap_port(poll);
        assert_eq!(
            port.start_stream(chat_req()).await.err(),
            Some(expected.clone())
        );
        assert!(port.start_stream(chat_req()).await.is_ok());
        assert_eq!(sink.count(log_keys::EXT_INFERENCE_PORT_PANICKED), 1);

        let (port, sink) = wrap_port(Arc::new(BuildPanicPort));
        assert_eq!(port.chat(chat_req()).await, Err(expected.clone()));
        assert_eq!(sink.count(log_keys::EXT_INFERENCE_PORT_PANICKED), 1);
        assert_no_payload(&sink, PAYLOAD);

        let (port, sink) = wrap_port(Arc::new(BuildPanicPort));
        assert_eq!(port.embed(embed_req()).await, Err(expected.clone()));
        assert_eq!(sink.count(log_keys::EXT_INFERENCE_PORT_PANICKED), 1);

        let (port, sink) = wrap_port(Arc::new(BuildPanicPort));
        assert_eq!(port.start_stream(chat_req()).await.err(), Some(expected));
        assert_eq!(sink.count(log_keys::EXT_INFERENCE_PORT_PANICKED), 1);
    }

    #[tokio::test]
    async fn module_001_ac31_contained_stream_panic_ends_stream_typed() {
        let sink = MemoryComposeLog::new();
        let log = LogHandle::new(Arc::new(sink.clone()));
        let mut stream = ContainedStream {
            ext: "fx",
            owner: StreamOwner::Port("local-stub".into()),
            log: log.clone(),
            inner: Some(Box::new(PollPanicStream {
                armed: AtomicBool::new(true),
                cancel_armed: AtomicBool::new(false),
            })),
        };
        let err = stream.next_chunk().await;
        assert_eq!(
            err,
            Some(Err(InferenceBackendError::LocalTransport(
                "extension fx: inference stream panicked".into()
            )))
        );
        assert_eq!(stream.next_chunk().await, None);
        stream.cancel();
        assert_eq!(sink.count(log_keys::EXT_INFERENCE_PORT_PANICKED), 1);
        assert!(sink.lines()[0].text.contains("next_chunk"));
        assert_no_payload(&sink, STREAM_PAYLOAD);

        let mut stream = ContainedStream {
            ext: "fx",
            owner: StreamOwner::Port("local-stub".into()),
            log,
            inner: Some(Box::new(PollPanicStream {
                armed: AtomicBool::new(false),
                cancel_armed: AtomicBool::new(true),
            })),
        };
        stream.cancel();
        assert_eq!(sink.count(log_keys::EXT_INFERENCE_PORT_PANICKED), 2);
        let texts: Vec<String> = sink.lines().into_iter().map(|l| l.text).collect();
        assert!(texts.iter().any(|t| t.contains("cancel")));
        assert_no_payload(&sink, STREAM_PAYLOAD);
    }

    #[tokio::test]
    async fn module_001_ac31_contained_mesh_dispatch_panic_typed_next_call_ok() {
        let expected =
            MeshInferenceDispatchError::Provider("extension fx: mesh dispatch panicked".into());
        let poll = Arc::new(PollPanicDispatch {
            armed: AtomicBool::new(true),
        });
        let (dispatch, sink) = wrap_mesh(poll);
        assert_eq!(
            dispatch.dispatch_chat(chat_req(), "i", "d").await,
            Err(expected.clone())
        );
        assert_eq!(
            dispatch.dispatch_chat(chat_req(), "i", "d").await,
            Ok(ok_chat())
        );
        assert_eq!(sink.count(log_keys::EXT_MESH_DISPATCH_PANICKED), 1);
        assert_no_payload(&sink, MESH_PAYLOAD);

        let poll = Arc::new(PollPanicDispatch {
            armed: AtomicBool::new(true),
        });
        let (dispatch, sink) = wrap_mesh(poll);
        assert_eq!(
            dispatch.dispatch_embed(embed_req(), "i", "d").await,
            Err(expected.clone())
        );
        assert_eq!(
            dispatch.dispatch_embed(embed_req(), "i", "d").await,
            Ok(ok_embed())
        );
        assert_eq!(sink.count(log_keys::EXT_MESH_DISPATCH_PANICKED), 1);

        let poll = Arc::new(PollPanicDispatch {
            armed: AtomicBool::new(true),
        });
        let (dispatch, sink) = wrap_mesh(poll);
        assert_eq!(
            dispatch.start_stream(chat_req(), "i", "d").await.err(),
            Some(expected.clone())
        );
        assert!(dispatch.start_stream(chat_req(), "i", "d").await.is_ok());
        assert_eq!(sink.count(log_keys::EXT_MESH_DISPATCH_PANICKED), 1);

        let (dispatch, sink) = wrap_mesh(Arc::new(BuildPanicDispatch));
        assert_eq!(
            dispatch.dispatch_chat(chat_req(), "i", "d").await,
            Err(expected)
        );
        assert_eq!(sink.count(log_keys::EXT_MESH_DISPATCH_PANICKED), 1);
        assert_no_payload(&sink, MESH_PAYLOAD);
    }

    #[test]
    fn module_001_ac31_contained_is_wired_panic_answers_wired() {
        let (port, sink) = wrap_port(Arc::new(WiredPanicPort));
        assert!(port.is_wired());
        assert_eq!(sink.count(log_keys::EXT_INFERENCE_PORT_PANICKED), 1);
        assert!(sink.lines()[0].text.contains("is_wired"));
        assert_no_payload(&sink, PAYLOAD);

        let (dispatch, sink) = wrap_mesh(Arc::new(WiredPanicDispatch));
        assert!(dispatch.is_wired());
        assert_eq!(sink.count(log_keys::EXT_MESH_DISPATCH_PANICKED), 1);
        assert!(sink.lines()[0].text.contains("is_wired"));
        assert_no_payload(&sink, MESH_PAYLOAD);
    }

    #[test]
    fn module_001_ac31_contained_drop_panic_is_caught_and_logged() {
        let (port, sink) = wrap_port(Arc::new(DropPanicPort));
        drop(port);
        assert_eq!(sink.count(log_keys::EXT_INFERENCE_PORT_PANICKED), 1);
        assert!(sink.lines()[0].text.contains("drop"));
        assert_no_payload(&sink, DROP_PAYLOAD);

        let (dispatch, sink) = wrap_mesh(Arc::new(DropPanicDispatch));
        drop(dispatch);
        assert_eq!(sink.count(log_keys::EXT_MESH_DISPATCH_PANICKED), 1);
        assert!(sink.lines()[0].text.contains("drop"));
        assert_no_payload(&sink, DROP_PAYLOAD);
    }

    #[test]
    fn module_001_ac31_containment_panic_answers_are_never_pre_token_failover() {
        let port =
            InferenceBackendError::LocalTransport("extension fx: inference port panicked".into());
        let stream =
            InferenceBackendError::LocalTransport("extension fx: inference stream panicked".into());
        let mesh = InferenceBackendError::from(MeshInferenceDispatchError::Provider(
            "extension fx: mesh dispatch panicked".into(),
        ));
        for err in [&port, &stream, &mesh] {
            let llm = LlmError::ProviderError(err.as_llm_message());
            assert!(
                !cap_llm::placement::is_pre_token_failover(&llm),
                "{}",
                err.as_llm_message()
            );
            assert!(!cap_llm::retry::classify_retryable(&llm));
        }
        assert!(cap_llm::placement::is_pre_token_failover(
            &LlmError::ProviderError("mesh-remote: not wired".into())
        ));
    }
}
