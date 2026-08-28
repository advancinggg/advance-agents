//! `mesh-remote` InferenceBackendPort wrapping [`MeshInferenceDispatch`].

use std::sync::Arc;

use advance_shared_types::inference::{
    InferenceBackendError, InferenceBackendPort, InferenceChatRequest, InferenceChatResponse,
    InferenceEmbedRequest, InferenceEmbedResponse, InferenceStream, InferenceStreamHead,
    MeshCarrier, MeshInferenceDispatch,
};
use async_trait::async_trait;
use uuid::Uuid;

pub struct MeshRemoteAdapter {
    pub dispatch: Arc<dyn MeshInferenceDispatch>,
    pub provider_id: String,
    pub embedding_model: Option<String>,
    pub target_device_id: String,
}

impl MeshRemoteAdapter {
    fn invocation_id() -> String {
        Uuid::new_v4().to_string()
    }
}

#[async_trait]
impl InferenceBackendPort for MeshRemoteAdapter {
    async fn chat(
        &self,
        req: InferenceChatRequest,
    ) -> Result<InferenceChatResponse, InferenceBackendError> {
        self.dispatch
            .dispatch_chat(req, &Self::invocation_id(), &self.target_device_id)
            .await
            .map_err(InferenceBackendError::from)
    }

    async fn embed(
        &self,
        req: InferenceEmbedRequest,
    ) -> Result<InferenceEmbedResponse, InferenceBackendError> {
        self.dispatch
            .dispatch_embed(req, &Self::invocation_id(), &self.target_device_id)
            .await
            .map_err(InferenceBackendError::from)
    }

    async fn start_stream(
        &self,
        req: InferenceChatRequest,
    ) -> Result<(InferenceStreamHead, Box<dyn InferenceStream>), InferenceBackendError> {
        let (head, stream, carrier) = self
            .dispatch
            .start_stream(req, &Self::invocation_id(), &self.target_device_id)
            .await
            .map_err(InferenceBackendError::from)?;
        Ok((
            InferenceStreamHead {
                class: head.class,
                snapshot_only: matches!(carrier, MeshCarrier::Snapshot),
            },
            stream,
        ))
    }

    fn is_wired(&self) -> bool {
        self.dispatch.is_wired()
    }
}
