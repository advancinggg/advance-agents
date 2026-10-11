//! CONTRACT-190 messaging family (m020-s2, AC-08).
//!
//! `POST /client/messages` (send a user message to an agent) + `GET /client/messages/{message_id}`
//! (read delivery/reply state). The raw MODULE-006 `MsgError` is never projected to the client — the
//! adapter maps it operation-scoped to a [`ProviderError`](crate::provider::ProviderError).

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::api::{ClientApi, HandlerSpec};
use crate::envelope::{ClientError, ClientErrorCode};
use crate::provider::{provider_or_unavailable, MessagingProviderSlot, ProviderError};
use crate::request::Method;
use crate::routes;
use crate::session::Scope;

/// The body of `POST /client/messages`. The idempotency key is envelope-level
/// (`ClientRequest.idempotency_key`), NOT in the body.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ClientSendMessageRequest {
    /// Target agent id (agent-style; must exist in the tree).
    pub to: String,
    /// UTF-8 text payload delivered to the target's mailbox.
    pub payload: String,
}

/// The acknowledgement returned by `POST /client/messages`.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ClientMessageAck {
    pub message_id: String,
    pub to: String,
    /// `delivered | pending`.
    pub delivery_state: String,
}

/// The delivery/reply state returned by `GET /client/messages/{message_id}`.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ClientMessageStatus {
    pub message_id: String,
    pub to: String,
    pub from: String,
    /// `delivered | pending`.
    pub delivery_state: String,
    /// `none | replied`. This vocabulary is unchanged. Subscription usage exhaustion
    /// is not a third `reply_state`; it is [`Self::failure_class`].
    pub reply_state: String,
    /// Opaque C235 subscribe pointer (`st_<hex>`). Never assistant body.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stream_key: Option<String>,
    /// Redacted failure class for this message, independent of `reply_state`.
    ///
    /// Omitted when unset. Older clients that only branch on `reply_state`
    /// (`none` | `replied`) keep working: this field is optional and is left out
    /// of the JSON when absent.
    ///
    /// `subscription-usage-limit` means the agent's model call stopped because the
    /// subscription usage window is exhausted. The value is that fixed token. It
    /// does not include vendor stderr, account identifiers, reset times, or tokens.
    /// The WIT `provider-error` payload the guest reads is the same token (the WIT
    /// case stays `provider-error`). Other provider failures stay `"provider error"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure_class: Option<String>,
}

/// Register the messaging routes, capturing the shared provider slot in each closure.
pub(crate) fn register(api: &mut ClientApi, slot: MessagingProviderSlot) {
    // POST /client/messages — send a user message to an agent (mutation: idempotent). The pipeline
    // enforces SendMessages before the idempotency gate.
    let s = slot.clone();
    api.register(
        Method::Post,
        routes::PATH_MESSAGES,
        HandlerSpec::mutation(true, move |ctx| {
            let req: ClientSendMessageRequest =
                serde_json::from_value(ctx.body.clone()).map_err(|_| {
                    ClientError::new(ClientErrorCode::ProjectionRejected, "invalid message body")
                })?;
            if req.to.is_empty() {
                return Err(ClientError::new(ClientErrorCode::NotFound, "empty target"));
            }
            let provider = provider_or_unavailable(&s)?;
            let ack = provider
                .send(&req.to, req.payload.as_bytes())
                .map_err(ProviderError::into_client_error)?;
            Ok(serde_json::to_value(ack).expect("ClientMessageAck serializes"))
        })
        .with_scopes(vec![Scope::SendMessages]),
    );

    // GET /client/messages/{message_id} — read delivery/reply state (templated read).
    let s = slot.clone();
    api.register_templated(
        Method::Get,
        routes::TPL_MESSAGE_GET,
        HandlerSpec::read(true, move |ctx| {
            let message_id = ctx.path_param("message_id")?;
            let provider = provider_or_unavailable(&s)?;
            let status = provider
                .message_status(&message_id)
                .map_err(ProviderError::into_client_error)?;
            Ok(serde_json::to_value(status).expect("ClientMessageStatus serializes"))
        })
        .with_scopes(vec![Scope::ReadMessages]),
    );
}
