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
    /// `none | replied`. This vocabulary is unchanged. A turn that will not answer
    /// (subscription usage exhaustion, a failed turn) is not a third `reply_state`;
    /// it is [`Self::failure_class`]. The value is the agent's, not the message's:
    /// it reflects the last turn the agent ran, so an older message of the agent
    /// reads `replied` once a later message was answered, while
    /// [`Self::failure_class`] stays that older message's own.
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
    /// Every value is one fixed token. None carries vendor stderr, account
    /// identifiers, reset times, or tokens:
    ///
    /// - `subscription-usage-limit`: the agent's model call stopped because the
    ///   subscription usage window is exhausted. Recorded when that call returns
    ///   to the guest, while the turn is still running: a later model call of the
    ///   same turn that succeeds withdraws it, and the turn may still reply (the
    ///   token then stays beside `reply_state: replied`). The WIT `provider-error`
    ///   payload the guest reads is the same token (the WIT case stays
    ///   `provider-error`). It takes precedence: the two tokens below never
    ///   replace it, so a usage-limited turn that ends without a reply keeps it.
    /// - `provider-error` ([`FAILURE_CLASS_PROVIDER_ERROR`]): the turn ended in an
    ///   error or trap without a reply after its last model call returned any
    ///   other model error (the guest itself still reads `"provider error"`).
    /// - `agent-error` ([`FAILURE_CLASS_AGENT_ERROR`]): the turn ended in an error
    ///   or trap without a reply and no model failure was observed; a message
    ///   whose turn could not be started at all ends this way too.
    ///
    /// Client rule: `provider-error` and `agent-error` are final — this message
    /// will get no reply; stop waiting. They are recorded once the turn has ended,
    /// never while it is in flight, so a client that stops on them cannot miss a
    /// later reply. `subscription-usage-limit` is recorded in flight and is not by
    /// itself proof that no reply will come: a client that stops on it trades
    /// that certainty for an immediate usage signal. A turn that produced a reply,
    /// or that ended normally without one, carries neither generic token.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure_class: Option<String>,
}

/// [`ClientMessageStatus::failure_class`] of a message whose turn ended in an error
/// or trap without a reply after its last model call failed.
pub const FAILURE_CLASS_PROVIDER_ERROR: &str = "provider-error";

/// [`ClientMessageStatus::failure_class`] of a message whose turn ended in an error
/// or trap without a reply and no model failure was observed.
pub const FAILURE_CLASS_AGENT_ERROR: &str = "agent-error";

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
