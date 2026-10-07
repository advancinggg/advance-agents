//! Client API families phase: record, validate, wrap, replay inside the bind factory.

use std::sync::Arc;

use advance_client_api::families::{
    method_label, ExtensionFamilies, ExtensionRouteEvent, ExtensionRouteGate, ExtensionRouteHooks,
    ExtensionServiceParts, RouteBook, RouteRefusal,
};
use advance_client_api::ClientApiConfig;

use crate::api::{log_keys, ComposeError, ExtensionPhase};
use crate::compose_log::LogHandle;
use crate::extension::guard;
use crate::extension::ExtensionSet;

pub(crate) struct ComposeRouteHooks {
    log: LogHandle,
}

impl ExtensionRouteHooks for ComposeRouteHooks {
    fn event(&self, event: &ExtensionRouteEvent) {
        match event {
            ExtensionRouteEvent::HandlerPanicked {
                extension,
                method,
                route,
            } => self.log.err(
                log_keys::EXT_ROUTE_PANICKED,
                format!(
                    "advance: WARN extension {extension} route {} {route} panicked; answered module_unavailable",
                    method_label(*method)
                ),
            ),
            ExtensionRouteEvent::DetailsDropped {
                extension,
                method,
                route,
                count,
            } => self.log.err(
                log_keys::EXT_ROUTE_DETAILS_DROPPED,
                format!(
                    "advance: WARN extension {extension} route {} {route} returned {count} error detail(s) that are not stable tokens; dropped",
                    method_label(*method)
                ),
            ),
            ExtensionRouteEvent::WarningsDropped {
                extension,
                method,
                route,
                count,
            } => self.log.err(
                log_keys::EXT_ROUTE_WARNINGS_DROPPED,
                format!(
                    "advance: WARN extension {extension} route {} {route} returned {count} warning(s) with a non-token code or a blocked message; dropped",
                    method_label(*method)
                ),
            ),
            ExtensionRouteEvent::UnknownCodeRemapped {
                extension,
                method,
                route,
            } => self.log.err(
                log_keys::EXT_ROUTE_CODE_REMAPPED,
                format!(
                    "advance: WARN extension {extension} route {} {route} returned error code unknown; answered module_unavailable",
                    method_label(*method)
                ),
            ),
            ExtensionRouteEvent::ScanOptOut {
                extension,
                method,
                route,
                reason,
            } => self.log.err(
                log_keys::EXT_ROUTE_SCAN_OPT_OUT,
                format!(
                    "advance: extension {extension} route {} {route} skips the response leak scan: {reason}",
                    method_label(*method)
                ),
            ),
            _ => {}
        }
    }
}

pub(crate) fn run_client_families(
    exts: &ExtensionSet,
    config: &ClientApiConfig,
    parts: ExtensionServiceParts,
    gate: ExtensionRouteGate,
    log: &LogHandle,
) -> Result<ExtensionFamilies, ComposeError> {
    if exts.is_empty() {
        return Ok(ExtensionFamilies::empty());
    }
    let hooks: Arc<dyn ExtensionRouteHooks> = Arc::new(ComposeRouteHooks { log: log.clone() });
    let mut book = RouteBook::new(config, parts, gate, hooks);
    for (id, ext, cx) in exts.iter_with_cx()? {
        let r = {
            let mut reg = book.registrar(id);
            guard::run_sync_callback(id, ExtensionPhase::ClientFamilies, || {
                ext.client_families(cx, &mut reg)
            })?
        };
        if let Some(refusal) = book.refusal(id) {
            return Err(to_compose_error(refusal.clone()));
        }
        if let Err(error) = r {
            return Err(guard::failed(id, ExtensionPhase::ClientFamilies, &error));
        }
    }
    book.finish().map_err(to_compose_error)
}

pub(crate) fn to_compose_error(r: RouteRefusal) -> ComposeError {
    ComposeError::Registration {
        extension: r.extension,
        route: r.route,
        reason: r.reason,
    }
}
