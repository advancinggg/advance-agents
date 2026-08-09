//! Stage-D cli auto_wiring: the 201 PackRegistry→EvaluatorResolver bridge, the
//! EventBus sink adapters, and the driver/advancer/start-path constructors.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use advance_cli::auto_wiring::{
    build_auto_loop_driver, build_auto_round_advancer, start_auto_session, to_evaluator_manifest,
    EventBusAutoIterationSink, EventBusNotifySink, PackEvaluatorResolver, AUTO_NOTIFY_EVENT,
};
use advance_pack_manager::error::PackError;
use advance_pack_manager::registry::{
    ComponentManifest, PackComponentResolution, PackMetadata, PackRegistry, PackResolution,
};
use advance_scheduler_auto_loop::{
    config::{MetricSource, Objective, Op, Predicate, Role, SuccessCriteria},
    event_sink::event_type,
    AutoIterationEventPayload, AutoIterationEventSink, AutoStateReader, ConstraintViolation,
    EvaluatorResolveError, EvaluatorResolver, NotifySink,
};
use advance_shared_types::event::Event;
use advance_shared_types::traits::EventBusEmit;

// ── A mock PackRegistry returning a canned component resolution ───────────────
struct MockPackRegistry {
    component_type: String,
    binary: Vec<u8>,
    raw_yaml: String,
    not_found: bool,
}

impl PackRegistry for MockPackRegistry {
    fn list_installed(&self) -> Vec<PackMetadata> {
        Vec::new()
    }
    fn resolve(&self, fq_ref: &str) -> Result<PackResolution, PackError> {
        Err(PackError::PackNotFound(fq_ref.to_string(), "0".to_string()))
    }
    fn has(&self, _name: &str, _version: &str) -> bool {
        false
    }
    fn resolve_pack_component(&self, fq_ref: &str) -> Result<PackComponentResolution, PackError> {
        if self.not_found {
            return Err(PackError::PackNotFound(
                fq_ref.to_string(),
                "1.0.0".to_string(),
            ));
        }
        Ok(PackComponentResolution {
            binary: self.binary.clone(),
            capabilities: Vec::new(),
            output_dir: PathBuf::from("/tmp/out"),
            manifest: ComponentManifest {
                component_type: self.component_type.clone(),
                raw_yaml: self.raw_yaml.clone(),
            },
        })
    }
}

#[test]
fn to_evaluator_manifest_derives_has_binary_and_trigger() {
    // binary present, no trigger key → has_binary true, trigger_present false.
    let res = PackComponentResolution {
        binary: vec![0u8, 1, 2],
        capabilities: Vec::new(),
        output_dir: PathBuf::from("/tmp"),
        manifest: ComponentManifest {
            component_type: "task".to_string(),
            raw_yaml: "component_type: task\nbinary: e.wasm\n".to_string(),
        },
    };
    let m = to_evaluator_manifest(&res);
    assert_eq!(m.component_type, "task");
    assert!(m.has_binary);
    assert!(!m.trigger_present);

    // empty binary + a non-null trigger key → has_binary false, trigger_present true.
    let res2 = PackComponentResolution {
        binary: Vec::new(),
        capabilities: Vec::new(),
        output_dir: PathBuf::from("/tmp"),
        manifest: ComponentManifest {
            component_type: "task".to_string(),
            raw_yaml: "component_type: task\ntrigger:\n  after-each-turn: true\n".to_string(),
        },
    };
    let m2 = to_evaluator_manifest(&res2);
    assert!(!m2.has_binary);
    assert!(m2.trigger_present);
}

#[tokio::test]
async fn pack_evaluator_resolver_valid_admits() {
    let reg = Arc::new(MockPackRegistry {
        component_type: "task".to_string(),
        binary: vec![1, 2, 3],
        raw_yaml: "component_type: task\nbinary: e.wasm\n".to_string(),
        not_found: false,
    });
    let resolver = PackEvaluatorResolver::new(reg);
    let spec = resolver
        .resolve_evaluator("research-pack@1.2.0/evaluator-bpb")
        .await
        .expect("valid task component admits");
    assert_eq!(spec.binary, vec![1, 2, 3]);
    assert_eq!(spec.manifest.component_type, "task");
}

#[tokio::test]
async fn pack_evaluator_resolver_wrong_type_violates() {
    let reg = Arc::new(MockPackRegistry {
        component_type: "agent".to_string(), // NOT task → constraint violation
        binary: vec![1],
        raw_yaml: "component_type: agent\n".to_string(),
        not_found: false,
    });
    let resolver = PackEvaluatorResolver::new(reg);
    let err = resolver
        .resolve_evaluator("p@1/c")
        .await
        .expect_err("non-task component must be rejected");
    assert!(matches!(
        err,
        EvaluatorResolveError::ConstraintViolated(ConstraintViolation::WrongComponentType(t)) if t == "agent"
    ));
}

#[tokio::test]
async fn pack_evaluator_resolver_not_found_maps() {
    let reg = Arc::new(MockPackRegistry {
        component_type: "task".to_string(),
        binary: vec![1],
        raw_yaml: String::new(),
        not_found: true,
    });
    let resolver = PackEvaluatorResolver::new(reg);
    let err = resolver.resolve_evaluator("missing@1/c").await.unwrap_err();
    assert!(matches!(err, EvaluatorResolveError::NotFound(_)));
}

// ── Recording EventBusEmit for the sink-adapter tests ────────────────────────
#[derive(Default)]
struct RecordingBus {
    events: Mutex<Vec<Event>>,
}
impl EventBusEmit for RecordingBus {
    fn emit(&self, event: Event) {
        self.events.lock().unwrap().push(event);
    }
}

#[tokio::test]
async fn event_bus_iteration_sink_emits_typed_event() {
    let bus = Arc::new(RecordingBus::default());
    let sink = EventBusAutoIterationSink::new(bus.clone());
    sink.emit(AutoIterationEventPayload::Kept {
        agent_id: "alice".to_string(),
        run_id: Some("run-a".to_string()),
        iteration: 3,
        metric: Some(0.42),
    })
    .await
    .unwrap();

    let evs = bus.events.lock().unwrap();
    assert_eq!(evs.len(), 1);
    assert_eq!(evs[0].event_type, event_type::ITERATION_KEPT);
    assert_eq!(evs[0].agent_id, "alice");
    assert_eq!(evs[0].payload["iter"], 3);
}

// Adversarial-r10 W4: the EventBus sink sanitizes agent_id + run_id (control /
// bidi-override chars) before they enter the Event envelope.
#[tokio::test]
async fn event_bus_sink_sanitizes_agent_id_and_run_id() {
    let bus = Arc::new(RecordingBus::default());
    let sink = EventBusAutoIterationSink::new(bus.clone());
    sink.emit(AutoIterationEventPayload::Started {
        agent_id: "ok\u{202E}evil".to_string(), // Trojan-Source bidi override
        run_id: Some("r\nINJECT".to_string()),  // newline log-injection
        iteration: 1,
    })
    .await
    .unwrap();
    let evs = bus.events.lock().unwrap();
    assert!(
        !evs[0].agent_id.contains('\u{202E}'),
        "bidi-override must be stripped from agent_id"
    );
    let run = evs[0].payload["run_id"].as_str().unwrap();
    assert!(!run.contains('\n'), "newline must be stripped from run_id");
}

#[tokio::test]
async fn event_bus_notify_sink_emits_notify_event() {
    let bus = Arc::new(RecordingBus::default());
    let sink = EventBusNotifySink::new(bus.clone());
    sink.notify("alice", "auto-loop degraded: ...")
        .await
        .unwrap();
    let evs = bus.events.lock().unwrap();
    assert_eq!(evs.len(), 1);
    assert_eq!(evs[0].event_type, AUTO_NOTIFY_EVENT);
    assert_eq!(evs[0].agent_id, "alice");
}

// ── Driver construction + Auto-mode start path (git workspace) ───────────────
fn init_repo(dir: &Path) {
    let repo = git2::Repository::init(dir).unwrap();
    let mut cfg = repo.config().unwrap();
    cfg.set_str("user.name", "t").unwrap();
    cfg.set_str("user.email", "t@example.com").unwrap();
    let sig = git2::Signature::now("t", "t@example.com").unwrap();
    let tree_id = repo.index().unwrap().write_tree().unwrap();
    let tree = repo.find_tree(tree_id).unwrap();
    repo.commit(Some("HEAD"), &sig, &sig, "init", &tree, &[])
        .unwrap();
}

fn primary_criteria() -> SuccessCriteria {
    SuccessCriteria {
        evaluator: None,
        objectives: vec![Objective {
            name: "val-bpb".to_string(),
            role: Role::Primary,
            metric_source: MetricSource::File {
                path: "m.json".to_string(),
                key: "v".to_string(),
            },
            predicate: Predicate {
                op: Op::Lt,
                threshold: None,
            },
        }],
        per_iteration_budget: None,
        fail_fast: None,
        safety_valve: None,
    }
}

#[test]
fn build_auto_loop_driver_none_on_non_repo() {
    let tmp = tempfile::tempdir().unwrap();
    let bus: Arc<dyn EventBusEmit> = Arc::new(RecordingBus::default());
    // A plain (non-git) dir → no checkpoints possible → degrade to None.
    assert!(build_auto_loop_driver(tmp.path(), bus).is_none());
}

#[tokio::test]
async fn build_driver_and_start_auto_session_over_git_repo() {
    let tmp = tempfile::tempdir().unwrap();
    init_repo(tmp.path());
    let bus: Arc<dyn EventBusEmit> = Arc::new(RecordingBus::default());
    let driver = build_auto_loop_driver(tmp.path(), bus).expect("git workspace → Some(driver)");

    // The driver is constructible as the RoundAdvancer's reader.
    let _advancer = build_auto_round_advancer(driver.clone());

    // Auto-mode start path: claim the session + register the run mapping.
    start_auto_session(&driver, "alice", "auto:alice:run-1", primary_criteria())
        .await
        .expect("start_auto_session");
    assert_eq!(
        driver.agent_id_for_run("auto:alice:run-1").as_deref(),
        Some("alice")
    );
    // Double-start of the same agent is rejected (AlreadyStarted).
    assert!(
        start_auto_session(&driver, "alice", "auto:alice:run-2", primary_criteria())
            .await
            .is_err()
    );
}
