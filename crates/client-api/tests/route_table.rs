//! `ClientApi::route_table` — read-only introspection of the registered routes.
//!
//! The accessor must report exactly what `handle()` routes: every listed (method, path) is
//! dispatched to a registered handler (never `unknown_route`), with the session / scope /
//! mutation gates the entry reports, and the listing is deterministic.

use advance_client_api::routes::{RoutePattern, PATH_HEALTH, TPL_RUN_PAUSE};
use advance_client_api::{
    ClientApi, ClientApiConfig, ClientErrorCode, ClientRequest, ClientSession, Method, Platform,
    Principal, RouteTableEntry, Scope,
};

const TOKEN: &str = "route-table-token";
const SCOPELESS_TOKEN: &str = "route-table-scopeless";

fn api_with_sessions() -> ClientApi {
    let api = ClientApi::new(ClientApiConfig::default());
    for (token, scopes) in [
        (TOKEN, Scope::operator_default()),
        (SCOPELESS_TOKEN, Vec::new()),
    ] {
        api.sessions().insert(
            token.to_string(),
            ClientSession {
                session_id: format!("sess-{token}"),
                principal: Principal::operator("operator"),
                platform: Platform::Mac,
                scopes,
                csrf_token: None,
                expires_at: u64::MAX,
            },
            0,
        );
    }
    api
}

/// Substitute every `{name}` parameter of a template with a concrete segment value.
fn concrete(path: &str) -> String {
    let mut out = String::new();
    let mut rest = path;
    while let Some(open) = rest.find('{') {
        out.push_str(&rest[..open]);
        let close = rest[open..].find('}').expect("closed parameter") + open;
        out.push_str("probe-value");
        rest = &rest[close + 1..];
    }
    out.push_str(rest);
    out
}

fn request(entry: &RouteTableEntry, token: Option<&str>) -> ClientRequest {
    let path = concrete(&entry.path);
    let mut req = match entry.method {
        Method::Get => ClientRequest::get(path),
        Method::Post => ClientRequest::post(path, serde_json::json!({})),
    };
    if let Some(token) = token {
        req = req.with_session(token);
    }
    if entry.is_mutation {
        req = req.with_idempotency_key(format!("route-table-{}", entry.path));
    }
    req
}

#[test]
fn route_table_is_sorted_unique_and_deterministic() {
    let api = ClientApi::new(ClientApiConfig::default());
    let table = api.route_table();
    assert!(!table.is_empty());
    assert_eq!(table, api.route_table(), "two reads of one instance");
    assert_eq!(
        table,
        ClientApi::new(ClientApiConfig::default()).route_table(),
        "two instances report the same table"
    );
    let rank = |m: Method| match m {
        Method::Get => 0,
        Method::Post => 1,
    };
    for pair in table.windows(2) {
        let a = (
            pair[0].path.as_str(),
            rank(pair[0].method),
            pair[0].templated,
        );
        let b = (
            pair[1].path.as_str(),
            rank(pair[1].method),
            pair[1].templated,
        );
        assert!(a < b, "sorted and unique: {a:?} then {b:?}");
    }
}

#[test]
fn route_table_reports_exact_and_templated_gates() {
    let table = ClientApi::new(ClientApiConfig::default()).route_table();
    let health = table
        .iter()
        .find(|e| e.path == PATH_HEALTH)
        .expect("health listed");
    assert_eq!(
        health,
        &RouteTableEntry {
            method: Method::Get,
            path: PATH_HEALTH.to_string(),
            templated: false,
            requires_session: false,
            is_mutation: false,
            required_scopes: Vec::new(),
        }
    );
    let pause = table
        .iter()
        .find(|e| e.path == TPL_RUN_PAUSE)
        .expect("templated pause listed with its template text");
    assert_eq!(
        pause,
        &RouteTableEntry {
            method: Method::Post,
            path: TPL_RUN_PAUSE.to_string(),
            templated: true,
            requires_session: true,
            is_mutation: true,
            required_scopes: vec![Scope::ControlRuns],
        }
    );
    // Session operations are dispatched before route lookup and are not registered routes.
    assert!(table
        .iter()
        .all(|e| !e.path.starts_with("/client/session/")));
}

#[test]
fn every_listed_route_is_routed_with_the_listed_gates() {
    let api = api_with_sessions();
    for entry in api.route_table() {
        let ok = api.handle(request(&entry, Some(TOKEN)));
        assert_ne!(
            ok.error.as_ref().map(|e| e.code.clone()),
            Some(ClientErrorCode::UnknownRoute),
            "{entry:?} is listed but not routed"
        );
        if entry.requires_session {
            let anonymous = api.handle(request(&entry, None));
            assert_eq!(
                anonymous.error.map(|e| e.code),
                Some(ClientErrorCode::Unauthenticated),
                "{entry:?} reports requires_session"
            );
        }
        if !entry.required_scopes.is_empty() {
            let scopeless = api.handle(request(&entry, Some(SCOPELESS_TOKEN)));
            assert_eq!(
                scopeless.error.map(|e| e.code),
                Some(ClientErrorCode::Forbidden),
                "{entry:?} reports required scopes"
            );
        }
        if entry.is_mutation {
            let mut keyless = request(&entry, Some(TOKEN));
            keyless.idempotency_key = None;
            assert_eq!(
                api.handle(keyless).error.map(|e| e.code),
                Some(ClientErrorCode::IdempotencyRequired),
                "{entry:?} reports is_mutation"
            );
        }
    }
}

#[test]
fn route_pattern_template_round_trips() {
    for template in [
        "/client/runs/{run_id}:pause",
        "/client/messages/{message_id}",
        "/client/entities/{agent_id}/{entity_id}",
        "/client/health",
        "/client/{unclosed",
        "/client/{a}b}",
        "",
    ] {
        assert_eq!(RoutePattern::parse(template).template(), template);
    }
}
