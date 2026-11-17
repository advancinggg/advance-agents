//! `ui.*` events (MODULE-019 taxonomy `ui::ACTION`, `ui::OBSERVATION`, `ui::REFUSED`).

use advance_runtime::host_registry::HostCallContext;
use advance_shared_types::event::Event;
use advance_shared_types::traits::EventBusEmit;
use advance_shared_types::ui::UiSurface;
use chrono::Utc;
use serde_json::{json, Value};
use uuid::Uuid;

pub const UI_ACTION: &str = "ui.action";
pub const UI_OBSERVATION: &str = "ui.observation";
pub const UI_REFUSED: &str = "ui.refused";

fn event(
    ctx: &HostCallContext,
    event_type: &str,
    payload: Value,
    duration_ms: Option<u64>,
) -> Event {
    Event {
        id: Uuid::new_v4().to_string(),
        timestamp: Utc::now(),
        agent_id: ctx.agent_id.clone(),
        task_id: None,
        run_id: ctx.run_id.clone(),
        execution_id: None,
        trace_id: ctx.trace_id.clone(),
        span_id: Uuid::new_v4().to_string(),
        parent_span_id: None,
        event_type: event_type.into(),
        payload,
        duration_ms,
    }
}

#[allow(clippy::too_many_arguments)]
pub fn action(
    bus: &dyn EventBusEmit,
    ctx: &HostCallContext,
    surface: UiSurface,
    verb: &str,
    target: Option<&str>,
    sensitive: bool,
    duration_ms: u64,
    is_error: bool,
) {
    bus.emit(event(
        ctx,
        UI_ACTION,
        json!({
            "surface": surface.as_str(),
            "verb": verb,
            "target": target,
            "sensitive": sensitive,
            "duration_ms": duration_ms,
            "is_error": is_error,
        }),
        Some(duration_ms),
    ));
}

pub fn observation(
    bus: &dyn EventBusEmit,
    ctx: &HostCallContext,
    surface: UiSurface,
    kind: &str,
    bytes: usize,
    elements: usize,
    scan: &str,
) {
    bus.emit(event(
        ctx,
        UI_OBSERVATION,
        json!({
            "surface": surface.as_str(),
            "kind": kind,
            "bytes": bytes,
            "elements": elements,
            "scan": scan,
        }),
        None,
    ));
}

pub fn refused(
    bus: &dyn EventBusEmit,
    ctx: &HostCallContext,
    surface: UiSurface,
    verb: &str,
    reason: &str,
) {
    // The reason is a fixed class or the gate's text, never page content.
    let reason: String = reason.chars().take(256).collect();
    bus.emit(event(
        ctx,
        UI_REFUSED,
        json!({
            "surface": surface.as_str(),
            "verb": verb,
            "reason": reason,
        }),
        None,
    ));
}
