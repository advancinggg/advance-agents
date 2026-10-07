//! MODULE-020-AC-18: unbound history and list-only pending-grant fallbacks on a bare ClientApi.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use cap_http::DefaultLeakDetector;
use rand::{rngs::OsRng, RngCore};
use serde_json::{json, Value};
use zeroize::Zeroizing;

use advance_shared_types::security_validator::{LeakDetector, ScanContext, ScanResult};
use advance_shared_types::sensitive_observation::{
    BoundObservationDocument, ObservationAssociationRoleFactory, RedactionBlockReason,
    RedactionDisposition, SensitiveObservationRedactor,
};

use crate::api::ClientApi;
use crate::config::ClientApiConfig;
use crate::envelope::{ClientEnvelope, ClientErrorCode};
use crate::provider::ProviderError;
use crate::providers::grants::{
    BoundGrantApprovalPort, BoundGrantMutation, BoundMutationOutcome, PendingGrantListPort,
    ProviderClientDoneReceipt, ProviderMutationRecovery, ProviderPrepareOutcome,
};
use crate::providers::history::{
    BoundHistoryPage, BoundHistoryReadPort, UnboundHistoryEntry, UnboundHistoryReadPort,
};
use crate::request::ClientRequest;
use crate::session::{ClientSession, Platform, Principal, Scope};

const TOKEN: &str = "tok";
const OCCURRED_AT: &str = "2026-10-03T12:00:00+00:00";

fn insert_session(api: &ClientApi) {
    api.sessions().insert(
        TOKEN.to_owned(),
        ClientSession {
            session_id: "session".to_owned(),
            principal: Principal::operator("operator"),
            platform: Platform::Mac,
            scopes: Scope::operator_default(),
            csrf_token: None,
            expires_at: u64::MAX,
        },
        0,
    );
}

fn get(api: &ClientApi, path: &str) -> ClientEnvelope<Value> {
    api.handle(ClientRequest::get(path).with_session(TOKEN))
}

fn get_cursor(api: &ClientApi, path: &str, cursor: &str) -> ClientEnvelope<Value> {
    let mut req = ClientRequest::get(path).with_session(TOKEN);
    req.body = json!({ "cursor": cursor });
    api.handle(req)
}

fn post(api: &ClientApi, path: &str, body: Value, key: &str) -> ClientEnvelope<Value> {
    api.handle(
        ClientRequest::post(path, body)
            .with_session(TOKEN)
            .with_idempotency_key(key),
    )
}

fn assert_unwired(env: &ClientEnvelope<Value>) {
    assert_eq!(env.error_code(), Some(ClientErrorCode::ModuleUnavailable));
    assert_eq!(
        env.error.as_ref().expect("error").message,
        "provider not wired"
    );
}

fn revision() -> String {
    URL_SAFE_NO_PAD.encode([0x5a; 185])
}

fn fail_closed_redactor() -> Arc<SensitiveObservationRedactor> {
    let mut key = Zeroizing::new([0u8; 32]);
    OsRng.fill_bytes(key.as_mut());
    key[0] |= 1;
    let mut boot = [0u8; 16];
    OsRng.fill_bytes(&mut boot);
    boot[0] |= 1;
    let parts = ObservationAssociationRoleFactory::new_at_composition(key, boot, Vec::new())
        .and_then(ObservationAssociationRoleFactory::split_once)
        .expect("nonzero key and boot id; structural schemas only");
    Arc::new(
        parts
            .provider
            .bind_once(parts.verifier, |_| RedactionDisposition::Blocked {
                reason: RedactionBlockReason::AuthorityUnavailable,
            })
            .expect("provider and verifier come from one factory"),
    )
}

fn sample_entries() -> Vec<UnboundHistoryEntry> {
    vec![
        UnboundHistoryEntry {
            event_id: "e1".into(),
            occurred_at: OCCURRED_AT.into(),
            kind: "run.round_completed".into(),
            summary: "observability event".into(),
        },
        UnboundHistoryEntry {
            event_id: "e2".into(),
            occurred_at: OCCURRED_AT.into(),
            kind: "run.started".into(),
            summary: "observability event".into(),
        },
    ]
}

fn expected_entries() -> Value {
    json!({
        "entries": [
            {
                "event_id": "e1",
                "occurred_at": OCCURRED_AT,
                "kind": "run.round_completed",
                "summary": "observability event",
                "params": []
            },
            {
                "event_id": "e2",
                "occurred_at": OCCURRED_AT,
                "kind": "run.started",
                "summary": "observability event",
                "params": []
            }
        ]
    })
}

struct UnboundFake {
    calls: Mutex<Vec<(bool, String, Option<String>)>>,
    page: Mutex<Result<Vec<UnboundHistoryEntry>, ProviderError>>,
}

impl UnboundFake {
    fn ok(entries: Vec<UnboundHistoryEntry>) -> Arc<Self> {
        Arc::new(Self {
            calls: Mutex::new(Vec::new()),
            page: Mutex::new(Ok(entries)),
        })
    }

    fn err(error: ProviderError) -> Arc<Self> {
        Arc::new(Self {
            calls: Mutex::new(Vec::new()),
            page: Mutex::new(Err(error)),
        })
    }

    fn serve(
        &self,
        task: bool,
        id: &str,
        cursor: Option<&str>,
    ) -> Result<Vec<UnboundHistoryEntry>, ProviderError> {
        self.calls
            .lock()
            .unwrap()
            .push((task, id.to_owned(), cursor.map(str::to_owned)));
        self.page.lock().unwrap().clone()
    }
}

impl UnboundHistoryReadPort for UnboundFake {
    fn task_history_unbound(
        &self,
        task_id: &str,
        cursor: Option<&str>,
    ) -> Result<Vec<UnboundHistoryEntry>, ProviderError> {
        self.serve(true, task_id, cursor)
    }

    fn run_history_unbound(
        &self,
        run_id: &str,
        cursor: Option<&str>,
    ) -> Result<Vec<UnboundHistoryEntry>, ProviderError> {
        self.serve(false, run_id, cursor)
    }
}

struct BoundHistoryFake;

impl BoundHistoryReadPort for BoundHistoryFake {
    fn task_history_bound(
        &self,
        _task_id: &str,
        _cursor: Option<&str>,
    ) -> Result<BoundHistoryPage, ProviderError> {
        Ok(BoundHistoryPage::from_bound_documents(Vec::new(), None))
    }

    fn run_history_bound(
        &self,
        _run_id: &str,
        _cursor: Option<&str>,
    ) -> Result<BoundHistoryPage, ProviderError> {
        Ok(BoundHistoryPage::from_bound_documents(Vec::new(), None))
    }
}

struct ListFake {
    lists: AtomicUsize,
    redactor: Arc<SensitiveObservationRedactor>,
}

impl ListFake {
    fn empty() -> Arc<Self> {
        Arc::new(Self {
            lists: AtomicUsize::new(0),
            redactor: fail_closed_redactor(),
        })
    }
}

impl PendingGrantListPort for ListFake {
    fn list_pending_bound(&self) -> Result<Vec<BoundObservationDocument>, ProviderError> {
        self.lists.fetch_add(1, Ordering::SeqCst);
        Ok(Vec::new())
    }

    fn redactor(&self) -> Arc<SensitiveObservationRedactor> {
        Arc::clone(&self.redactor)
    }
}

struct BoundGrantFake;

impl BoundGrantApprovalPort for BoundGrantFake {
    fn list_pending_bound(&self) -> Result<Vec<BoundObservationDocument>, ProviderError> {
        Ok(Vec::new())
    }

    fn prepare_mutation_bound(
        &self,
        _mutation_id: [u8; 32],
        _request_fingerprint: [u8; 32],
        _mutation: BoundGrantMutation,
    ) -> ProviderPrepareOutcome {
        unreachable!()
    }

    fn verify_recovery_ticket_bound(
        &self,
        _mutation_id: [u8; 32],
        _request_fingerprint: [u8; 32],
        _operation_tag: u8,
        _recovery: &ProviderMutationRecovery,
    ) -> Result<(), ProviderError> {
        unreachable!()
    }

    fn execute_prepared_bound(&self, _recovery: &ProviderMutationRecovery) -> BoundMutationOutcome {
        unreachable!()
    }

    fn recover_mutation_bound(&self, _recovery: &ProviderMutationRecovery) -> BoundMutationOutcome {
        unreachable!()
    }

    fn acknowledge_client_done_bound(
        &self,
        _done: &ProviderClientDoneReceipt,
    ) -> Result<(), ProviderError> {
        unreachable!()
    }
}

struct ScriptedDetector {
    result: ScanResult,
}

impl LeakDetector for ScriptedDetector {
    fn scan(&self, _text: &str, _context: ScanContext) -> ScanResult {
        self.result.clone()
    }

    fn scan_headers(&self, _headers: &[(String, String)]) -> ScanResult {
        ScanResult::Clean
    }
}

#[test]
fn module_020_ac18_unbound_history_answers_entries_with_empty_params_and_no_next_cursor() {
    let port = UnboundFake::ok(sample_entries());
    let api = ClientApi::new(ClientApiConfig::default())
        .with_unbound_history_provider(Arc::clone(&port) as Arc<dyn UnboundHistoryReadPort>)
        .with_leak_detector(Arc::new(DefaultLeakDetector::new()));
    insert_session(&api);

    for (path, task, id) in [
        ("/client/tasks/task-a/history", true, "task-a"),
        ("/client/runs/run-a/history", false, "run-a"),
    ] {
        let env = get_cursor(&api, path, "c1");
        assert!(env.is_ok(), "{path}: {:?}", env.error);
        let data = env.data.as_ref().expect("data");
        assert_eq!(data, &expected_entries());
        assert!(data.get("next_cursor").is_none());
        let last = port.calls.lock().unwrap().last().cloned();
        assert_eq!(last, Some((task, id.to_owned(), Some("c1".into()))));
    }
}

#[test]
fn module_020_ac18_unbound_history_needs_the_detector_not_the_redactor() {
    let port = UnboundFake::ok(sample_entries());
    let api = ClientApi::new(ClientApiConfig::default())
        .with_unbound_history_provider(Arc::clone(&port) as Arc<dyn UnboundHistoryReadPort>);
    insert_session(&api);
    assert_unwired(&get(&api, "/client/runs/run-a/history"));

    let api = ClientApi::new(ClientApiConfig::default())
        .with_unbound_history_provider(port as Arc<dyn UnboundHistoryReadPort>)
        .with_leak_detector(Arc::new(DefaultLeakDetector::new()));
    insert_session(&api);
    let env = get(&api, "/client/runs/run-a/history");
    assert!(env.is_ok(), "{:?}", env.error);
    assert_eq!(env.data.as_ref().unwrap(), &expected_entries());
}

#[test]
fn module_020_ac18_history_with_no_port_answers_as_at_v0_1_26() {
    let api = ClientApi::new(ClientApiConfig::default())
        .with_leak_detector(Arc::new(DefaultLeakDetector::new()));
    insert_session(&api);
    assert_unwired(&get(&api, "/client/runs/run-a/history"));
    assert_unwired(&get(&api, "/client/tasks/task-a/history"));
}

#[test]
fn module_020_ac18_bound_history_wins_over_the_unbound_port() {
    let unbound = UnboundFake::ok(sample_entries());
    let api = ClientApi::new(ClientApiConfig::default())
        .with_bound_history_provider(Arc::new(BoundHistoryFake))
        .with_unbound_history_provider(Arc::clone(&unbound) as Arc<dyn UnboundHistoryReadPort>)
        .with_leak_detector(Arc::new(DefaultLeakDetector::new()));
    insert_session(&api);
    assert_unwired(&get(&api, "/client/runs/run-a/history"));
    assert!(unbound.calls.lock().unwrap().is_empty());
}

#[test]
fn module_020_ac18_unbound_history_maps_errors_and_gates_the_time() {
    let missing = UnboundFake::err(ProviderError::NotFound("gone".into()));
    let api = ClientApi::new(ClientApiConfig::default())
        .with_unbound_history_provider(missing as Arc<dyn UnboundHistoryReadPort>)
        .with_leak_detector(Arc::new(DefaultLeakDetector::new()));
    insert_session(&api);
    let env = get(&api, "/client/runs/run-a/history");
    assert_eq!(env.error_code(), Some(ClientErrorCode::NotFound));
    assert_eq!(
        env.error.as_ref().expect("error").message,
        "resource not found"
    );

    let bad_time = UnboundFake::ok(vec![UnboundHistoryEntry {
        event_id: "e1".into(),
        occurred_at: "yesterday".into(),
        kind: "run.started".into(),
        summary: "observability event".into(),
    }]);
    let api = ClientApi::new(ClientApiConfig::default())
        .with_unbound_history_provider(bad_time as Arc<dyn UnboundHistoryReadPort>)
        .with_leak_detector(Arc::new(DefaultLeakDetector::new()));
    insert_session(&api);
    let env = get(&api, "/client/runs/run-a/history");
    assert_eq!(env.error_code(), Some(ClientErrorCode::ProjectionRejected));
    assert_eq!(
        env.error.as_ref().expect("error").message,
        "history document schema rejected"
    );
}

#[test]
fn module_020_ac18_unbound_history_summary_passes_the_contract112_scan() {
    let port = UnboundFake::ok(sample_entries());
    let redacted = ClientApi::new(ClientApiConfig::default())
        .with_unbound_history_provider(Arc::clone(&port) as Arc<dyn UnboundHistoryReadPort>)
        .with_leak_detector(Arc::new(ScriptedDetector {
            result: ScanResult::Redacted {
                redacted: "[REDACTED]".into(),
                findings: Vec::new(),
            },
        }));
    insert_session(&redacted);
    let env = get(&redacted, "/client/runs/run-a/history");
    assert!(env.is_ok(), "{:?}", env.error);
    let entries = env.data.as_ref().unwrap()["entries"].as_array().unwrap();
    assert_eq!(entries[0]["summary"], "[REDACTED]");
    assert!(env
        .warnings
        .iter()
        .any(|w| w.code == "sensitive_value_redacted"));

    let blocked = ClientApi::new(ClientApiConfig::default())
        .with_unbound_history_provider(port as Arc<dyn UnboundHistoryReadPort>)
        .with_leak_detector(Arc::new(ScriptedDetector {
            result: ScanResult::Blocked {
                findings: Vec::new(),
            },
        }));
    insert_session(&blocked);
    let env = get(&blocked, "/client/runs/run-a/history");
    assert_eq!(env.error_code(), Some(ClientErrorCode::ProjectionRejected));
    assert_eq!(
        env.error.as_ref().expect("error").message,
        "client projection rejected"
    );
}

#[test]
fn module_020_ac18_list_only_port_answers_without_the_shared_redactor_slot() {
    let list = ListFake::empty();
    let api = ClientApi::new(ClientApiConfig::default())
        .with_pending_grant_list_provider(Arc::clone(&list) as Arc<dyn PendingGrantListPort>);
    insert_session(&api);
    assert_unwired(&get(&api, "/client/grants/pending"));

    let api = ClientApi::new(ClientApiConfig::default())
        .with_pending_grant_list_provider(Arc::clone(&list) as Arc<dyn PendingGrantListPort>)
        .with_leak_detector(Arc::new(DefaultLeakDetector::new()));
    insert_session(&api);
    let env = get(&api, "/client/grants/pending");
    assert!(env.is_ok(), "{:?}", env.error);
    assert_eq!(env.data.as_ref().unwrap(), &json!({ "requests": [] }));
}

#[test]
fn module_020_ac18_grant_mutations_never_reach_the_list_only_port() {
    let list = ListFake::empty();
    let api = ClientApi::new(ClientApiConfig::default())
        .with_pending_grant_list_provider(Arc::clone(&list) as Arc<dyn PendingGrantListPort>)
        .with_leak_detector(Arc::new(DefaultLeakDetector::new()));
    insert_session(&api);

    let rev = revision();
    let mutations: [(&str, Value, &str); 5] = [
        (
            "/client/grants/pending/t29-req:approve",
            json!({ "decision_revision": rev.clone() }),
            "t29-1",
        ),
        (
            "/client/grants/pending/t29-req:deny",
            json!({ "decision_revision": rev.clone(), "reason": "t29" }),
            "t29-2",
        ),
        (
            "/client/grants/pending/t29-req:narrow",
            json!({
                "decision_revision": rev,
                "params": [{ "key": "k", "value": "v" }]
            }),
            "t29-3",
        ),
        ("/client/grants/g1:revoke", json!({}), "t29-4"),
        (
            "/client/presets/supervised:apply",
            json!({ "target_agent_id": "agent:root" }),
            "t29-5",
        ),
    ];
    for (path, body, key) in mutations {
        let first = post(&api, path, body.clone(), key);
        assert_unwired(&first);
        assert!(
            first.warnings.iter().all(|w| w.code != "idempotent_replay"),
            "{path}"
        );
        let replay = post(&api, path, body, key);
        assert_unwired(&replay);
        assert!(
            replay
                .warnings
                .iter()
                .all(|w| w.code != "idempotent_replay"),
            "replay {path}"
        );
    }
    assert_eq!(list.lists.load(Ordering::SeqCst), 0);
}

#[test]
fn module_020_ac18_bound_grants_win_over_the_list_only_port() {
    let list = ListFake::empty();
    let api = ClientApi::new(ClientApiConfig::default())
        .with_bound_grant_provider(Arc::new(BoundGrantFake))
        .with_pending_grant_list_provider(Arc::clone(&list) as Arc<dyn PendingGrantListPort>)
        .with_leak_detector(Arc::new(DefaultLeakDetector::new()));
    insert_session(&api);
    assert_unwired(&get(&api, "/client/grants/pending"));
    assert_eq!(list.lists.load(Ordering::SeqCst), 0);
}

#[test]
fn module_020_ac18_clear_providers_empties_the_new_slots() {
    let unbound = UnboundFake::ok(sample_entries());
    let list = ListFake::empty();
    let unbound_weak = Arc::downgrade(&unbound);
    let list_weak = Arc::downgrade(&list);
    let api = ClientApi::new(ClientApiConfig::default())
        .with_unbound_history_provider(unbound as Arc<dyn UnboundHistoryReadPort>)
        .with_pending_grant_list_provider(list as Arc<dyn PendingGrantListPort>)
        .with_leak_detector(Arc::new(DefaultLeakDetector::new()));
    insert_session(&api);
    assert!(get(&api, "/client/runs/run-a/history").is_ok());
    assert!(get(&api, "/client/grants/pending").is_ok());

    api.clear_providers();
    assert!(unbound_weak.upgrade().is_none());
    assert!(list_weak.upgrade().is_none());
    assert_unwired(&get(&api, "/client/runs/run-a/history"));
    assert_unwired(&get(&api, "/client/grants/pending"));
}
