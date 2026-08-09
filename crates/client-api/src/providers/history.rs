//! Public task/run history over opaque CONTRACT-185 bound documents.

use std::sync::Arc;

use advance_shared_types::sensitive_observation::{BoundObservationDocument, ObservationNode};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::api::{ClientApi, HandlerResponse, HandlerSpec};
use crate::envelope::{ClientError, ClientErrorCode};
use crate::provider::{
    provider_or_unavailable, BoundHistoryProviderSlot, LeakDetectorSlot, ObservationRedactorSlot,
    ProviderError,
};
use crate::providers::grants::{scan_text, ClientCapParam};
use crate::providers::Projectable;
use crate::request::Method;
use crate::routes;
use crate::session::Scope;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ClientHistoryEntry {
    pub event_id: String,
    pub occurred_at: String,
    pub kind: String,
    pub summary: String,
    pub params: Vec<ClientCapParam>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ClientHistoryResponse {
    pub entries: Vec<ClientHistoryEntry>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct HistoryRequest {
    #[serde(default)]
    cursor: Option<String>,
}

pub struct BoundHistoryPage {
    documents: Vec<BoundObservationDocument>,
    next_cursor: Option<String>,
}

impl BoundHistoryPage {
    pub fn from_bound_documents(
        documents: Vec<BoundObservationDocument>,
        next_cursor: Option<String>,
    ) -> Self {
        Self {
            documents,
            next_cursor,
        }
    }

    fn into_parts(self) -> (Vec<BoundObservationDocument>, Option<String>) {
        (self.documents, self.next_cursor)
    }
}

pub trait BoundHistoryReadPort: Send + Sync {
    fn task_history_bound(
        &self,
        task_id: &str,
        cursor: Option<&str>,
    ) -> Result<BoundHistoryPage, ProviderError>;

    fn run_history_bound(
        &self,
        run_id: &str,
        cursor: Option<&str>,
    ) -> Result<BoundHistoryPage, ProviderError>;
}

struct HistorySlots {
    provider: BoundHistoryProviderSlot,
    redactor: ObservationRedactorSlot,
    detector: LeakDetectorSlot,
}

pub(crate) fn register(
    api: &mut ClientApi,
    provider: BoundHistoryProviderSlot,
    redactor: ObservationRedactorSlot,
    detector: LeakDetectorSlot,
) {
    let slots = Arc::new(HistorySlots {
        provider,
        redactor,
        detector,
    });
    let task = Arc::clone(&slots);
    api.register_templated(
        Method::Get,
        routes::TPL_TASK_HISTORY,
        HandlerSpec::read_with_warnings(true, move |ctx| {
            let id = ctx.path_param("task_id")?;
            handle(&task, &id, &ctx.body, true)
        })
        .with_scopes(vec![Scope::ReadRuns]),
    );
    let run = Arc::clone(&slots);
    api.register_templated(
        Method::Get,
        routes::TPL_RUN_HISTORY,
        HandlerSpec::read_with_warnings(true, move |ctx| {
            let id = ctx.path_param("run_id")?;
            handle(&run, &id, &ctx.body, false)
        })
        .with_scopes(vec![Scope::ReadRuns]),
    );
}

fn handle(
    slots: &HistorySlots,
    id: &str,
    body: &Value,
    task: bool,
) -> Result<HandlerResponse, ClientError> {
    let request = if body.is_null() {
        HistoryRequest::default()
    } else {
        serde_json::from_value(body.clone()).map_err(|_| {
            ClientError::new(
                ClientErrorCode::ProjectionRejected,
                "invalid history request",
            )
        })?
    };
    let provider = provider_or_unavailable(&slots.provider)?;
    let redactor = provider_or_unavailable(&slots.redactor)?;
    let detector = provider_or_unavailable(&slots.detector)?;
    let page = if task {
        provider.task_history_bound(id, request.cursor.as_deref())
    } else {
        provider.run_history_bound(id, request.cursor.as_deref())
    }
    .map_err(ProviderError::into_client_error)?;
    let (documents, next_cursor) = page.into_parts();
    let mut entries = Vec::with_capacity(documents.len());
    let mut warnings = Vec::new();
    for bound in documents {
        let document = Projectable::<ClientHistoryEntry>::from_bound(bound).redact(&redactor)?;
        let (_, payload) = document.event_parts().ok_or_else(projection_error)?;
        let mut entry = decode_entry(payload)?;
        scan_text(
            &mut entry.summary,
            detector.as_ref(),
            "summary",
            true,
            &mut warnings,
        )?;
        for (index, param) in entry.params.iter_mut().enumerate() {
            scan_text(
                &mut param.value,
                detector.as_ref(),
                &format!("params[{index}].value"),
                false,
                &mut warnings,
            )?;
        }
        entries.push(entry);
    }
    Ok(HandlerResponse::with_warnings(
        serde_json::to_value(ClientHistoryResponse {
            entries,
            next_cursor,
        })
        .expect("history serializes"),
        warnings,
    ))
}

fn decode_entry(node: &ObservationNode) -> Result<ClientHistoryEntry, ClientError> {
    let ObservationNode::Object(fields) = node else {
        return Err(projection_error());
    };
    let expected = ["event_id", "occurred_at", "kind", "summary", "params"];
    if fields.len() != expected.len()
        || fields
            .iter()
            .zip(expected)
            .any(|((actual, _), expected)| actual != expected)
    {
        return Err(projection_error());
    }
    let value = |index: usize| match &fields[index].1 {
        ObservationNode::String(value) => Ok(value.clone()),
        _ => Err(projection_error()),
    };
    let params = match &fields[4].1 {
        ObservationNode::CanonicalCapParams(values) => values
            .iter()
            .map(|param| match &param.value {
                ObservationNode::String(value) => Ok(ClientCapParam {
                    key: param.key.clone(),
                    value: value.clone(),
                }),
                _ => Err(projection_error()),
            })
            .collect::<Result<_, _>>()?,
        _ => return Err(projection_error()),
    };
    let occurred_at = value(1)?;
    chrono::DateTime::parse_from_rfc3339(&occurred_at).map_err(|_| projection_error())?;
    Ok(ClientHistoryEntry {
        event_id: value(0)?,
        occurred_at,
        kind: value(2)?,
        summary: value(3)?,
        params,
    })
}

fn projection_error() -> ClientError {
    ClientError::new(
        ClientErrorCode::ProjectionRejected,
        "history document schema rejected",
    )
}
