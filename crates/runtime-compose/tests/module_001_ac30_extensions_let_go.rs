//! MODULE-001-AC-30 (ADR 2026-10-03 D1) — the shutdown lets go of the extensions at the end
//! of step 3. An extension that added a Client API family route, a host function (called by
//! the root guest), a native tool and an inference claim with a hold, and whose spawned
//! tasks are running (one of them holding the extension itself), is dropped right after its
//! shutdown hook ran and its tasks were joined: before any hold of step 4 is released, while
//! the runtime lock and the home's process-local reservation are still held. Its inference
//! hold goes later, in step 4. The same holds for the teardown of a start that failed after
//! the extension's registrations.

#[path = "support/t111.rs"]
mod t111;

use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError, Weak};
use std::time::{Duration, Instant};

use advance_runtime_compose::test_support::fixture::inference::{
    provider_yaml, DropFlag, FixtureInference, StubInferencePort, LOCAL_STUB_ID,
};
use advance_runtime_compose::test_support::fixture::{
    assert_gone_for_home, ext_probe_core, mint_session, post_msg, CapDecl, FixtureDriver,
    FixtureExtension, FixtureFamilies, FixtureHome, FixtureHomeSpec, FixtureLifecycle,
    FixtureRecord, FixtureSpec, Http,
};
use advance_runtime_compose::test_support::{
    reserved_homes, ComposeFailpoints, ComposeProbe, MemoryComposeLog,
};
use advance_runtime_compose::{
    compose, BoxFuture, ClientFamilyRegistrar, ComposeCx, ComposeError, ComposeExtension,
    ExtensionError, HostFunctionRegistrar, InferenceContribution, StartedCx, ToolRegistrar,
};

const WAIT: Duration = Duration::from_secs(5);
const POLL: Duration = Duration::from_millis(10);

/// What the extension saw when it was dropped.
#[derive(Debug)]
struct AtDrop {
    /// The teardown steps that had run.
    steps: Vec<&'static str>,
    /// Whether the home's runtime lock file still existed.
    lock_held: bool,
    /// Whether the home was still reserved in the process-local registry.
    reserved: bool,
    /// Whether its inference hold was still held.
    hold_held: bool,
}

/// The neutral fixture extension, plus a task it spawns from `on_started` that holds the
/// extension itself until the shutdown cancels it. When dropped, it records what had
/// happened by then.
struct LetGoWitness {
    inner: FixtureExtension,
    me: Weak<LetGoWitness>,
    probe: Arc<ComposeProbe>,
    home: PathBuf,
    hold: DropFlag,
    holder_spawned: Arc<AtomicBool>,
    at_drop: Arc<Mutex<Option<AtDrop>>>,
}

impl ComposeExtension for LetGoWitness {
    fn id(&self) -> &'static str {
        self.inner.id()
    }

    fn capabilities(&self) -> &'static [&'static str] {
        self.inner.capabilities()
    }

    fn inference(
        &self,
        cx: &ComposeCx,
        out: &mut InferenceContribution,
    ) -> Result<(), ExtensionError> {
        self.inner.inference(cx, out)
    }

    fn host_functions(
        &self,
        cx: &ComposeCx,
        reg: &mut HostFunctionRegistrar,
    ) -> Result<(), ExtensionError> {
        self.inner.host_functions(cx, reg)
    }

    fn tools<'a>(
        &'a self,
        cx: &'a ComposeCx,
        reg: &'a mut ToolRegistrar,
    ) -> BoxFuture<'a, Result<(), ExtensionError>> {
        self.inner.tools(cx, reg)
    }

    fn client_families(
        &self,
        cx: &ComposeCx,
        reg: &mut ClientFamilyRegistrar<'_>,
    ) -> Result<(), ExtensionError> {
        self.inner.client_families(cx, reg)
    }

    fn needs_secret_store(&self) -> bool {
        self.inner.needs_secret_store()
    }

    fn on_started<'a>(&'a self, cx: &'a StartedCx) -> BoxFuture<'a, Result<(), ExtensionError>> {
        Box::pin(async move {
            self.inner.on_started(cx).await?;
            let me = self
                .me
                .upgrade()
                .ok_or_else(|| ExtensionError::new("the extension is gone"))?;
            cx.tasks().spawn(async move {
                let _held = me;
                std::future::pending::<()>().await
            })?;
            self.holder_spawned.store(true, Ordering::SeqCst);
            Ok(())
        })
    }

    fn shutdown<'a>(&'a self) -> BoxFuture<'a, ()> {
        self.inner.shutdown()
    }
}

impl Drop for LetGoWitness {
    fn drop(&mut self) {
        let seen = AtDrop {
            steps: self.probe.record().step_names(),
            lock_held: self.home.join(".runtime/runtime.lock").exists(),
            reserved: reserved_homes().contains(&self.home),
            hold_held: !self.hold.dropped(),
        };
        *self.at_drop.lock().unwrap_or_else(PoisonError::into_inner) = Some(seen);
    }
}

/// One witness composition: the extension (the caller hands its only reference to
/// `compose`) and what the test keeps to observe it.
struct Witness {
    extension: Arc<dyn ComposeExtension>,
    record: Arc<FixtureRecord>,
    stub: Arc<StubInferencePort>,
    hold: DropFlag,
    holder_spawned: Arc<AtomicBool>,
    at_drop: Arc<Mutex<Option<AtDrop>>>,
}

impl Witness {
    /// The fixture with its standard client families, its `fixture.probe` capability with
    /// a host function and the `fixture.echo` tool, a claim of `local-stub` with a profile
    /// and a hold, and a ticker task.
    fn new(probe: &Arc<ComposeProbe>, home: &Path) -> Self {
        let stub = StubInferencePort::new("stub-pong", 1, 1);
        let hold = DropFlag::default();
        let inner = FixtureExtension::new("fixture")
            .with_spec(FixtureSpec::standard())
            .with_families(FixtureFamilies::standard())
            .with_inference(FixtureInference::standard(Arc::clone(&stub)).hold(&hold))
            .with_lifecycle(FixtureLifecycle {
                spawn_ticker: true,
                ..FixtureLifecycle::default()
            });
        let record = inner.record();
        let holder_spawned = Arc::new(AtomicBool::new(false));
        let at_drop = Arc::new(Mutex::new(None));
        let extension: Arc<LetGoWitness> = Arc::new_cyclic(|me| LetGoWitness {
            inner,
            me: me.clone(),
            probe: Arc::clone(probe),
            home: home.to_path_buf(),
            hold: hold.clone(),
            holder_spawned: Arc::clone(&holder_spawned),
            at_drop: Arc::clone(&at_drop),
        });
        Self {
            extension,
            record,
            stub,
            hold,
            holder_spawned,
            at_drop,
        }
    }

    /// What the extension recorded when it was dropped.
    fn at_drop(at_drop: &Mutex<Option<AtDrop>>) -> AtDrop {
        at_drop
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
            .expect("the extension was dropped by the teardown")
    }
}

/// `fs`, `llm` (one claimable `local` entry, `local-stub`), `tools` and the fixture's
/// `fixture.probe`, granted; the probe guest deployed as the root driver; a git repo.
fn home() -> FixtureHome {
    FixtureHome::new(FixtureHomeSpec {
        capabilities: vec![
            CapDecl::Granted("fs"),
            CapDecl::Granted("llm"),
            CapDecl::Granted("tools"),
            CapDecl::Granted("fixture.probe"),
        ],
        driver: FixtureDriver::Core(ext_probe_core()),
        git: true,
        providers_yaml: Some(provider_yaml::llm_providers_block(&[
            provider_yaml::LOCAL_STUB,
        ])),
    })
    .expect("home")
}

fn alive_tasks() -> usize {
    tokio::runtime::Handle::current()
        .metrics()
        .num_alive_tasks()
}

async fn wait_for(what: &str, mut done: impl FnMut() -> bool) {
    let deadline = Instant::now() + WAIT;
    while !done() {
        assert!(Instant::now() < deadline, "{what} within {WAIT:?}");
        tokio::time::sleep(POLL).await;
    }
}

/// A requested shutdown of a running composition.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn module_001_ac30_extensions_are_let_go_after_their_hooks_on_shutdown() {
    let home = home();
    let log = MemoryComposeLog::new();
    let probe = Arc::new(ComposeProbe::new());
    let Witness {
        extension,
        record,
        stub,
        hold,
        holder_spawned,
        at_drop,
    } = Witness::new(&probe, home.home());
    let baseline = alive_tasks();
    let rt = compose(
        home.options(Arc::new(log), Arc::clone(&probe)),
        vec![extension],
    )
    .await
    .expect("compose");

    // Everything the extension added is live.
    let endpoint = rt.client_api().expect("the Client API is bound");
    let token = mint_session(&endpoint);
    let status = Http::get(endpoint.socket_addr, "/client/fixture/status")
        .session(&token)
        .send()
        .await;
    assert_eq!(status.status, 200, "{:?}", status.body);
    assert_eq!(status.body["data"]["status"], "ok", "{:?}", status.body);
    let preflight = Http::post(
        endpoint.socket_addr,
        format!("/client/providers/{LOCAL_STUB_ID}:preflight"),
    )
    .session(&token)
    .idempotency_key("k-preflight")
    .send()
    .await;
    assert_eq!(preflight.body["data"]["ok"], true, "{:?}", preflight.body);
    assert!(stub.calls() >= 1, "the claimed port answered the preflight");
    let post_msg_addr = probe
        .record()
        .listener("post_msg")
        .expect("POST /msg is bound");
    let (code, reply) = post_msg(post_msg_addr, "call a").await;
    assert_eq!(
        (code, reply.as_str()),
        (200, "ok:probe:a"),
        "the root guest called the extension's host function"
    );
    assert!(record.host_calls.load(Ordering::SeqCst) >= 1);
    wait_for("the ticker ticks", || {
        record.ticks.load(Ordering::SeqCst) >= 1
    })
    .await;
    wait_for("the task holding the extension is spawned", || {
        holder_spawned.load(Ordering::SeqCst)
    })
    .await;
    assert!(!hold.dropped(), "the hold is held while the runtime runs");

    rt.shutdown().await.expect("shutdown");

    let teardown = probe.record();
    let names = teardown.step_names();
    let seen = Witness::at_drop(&at_drop);
    let tasks = names
        .iter()
        .position(|step| *step == "extensions.tasks")
        .unwrap_or_else(|| panic!("no extensions.tasks step:\n{}", teardown.render_steps()));
    assert_eq!(
        seen.steps,
        names[..=tasks],
        "the extension is let go right after its hooks ran and its tasks were joined:\n{}",
        teardown.render_steps()
    );
    assert!(
        seen.lock_held,
        "dropped while the runtime lock was still held"
    );
    assert!(
        seen.reserved,
        "dropped while the home was still reserved in the process-local registry"
    );
    assert!(
        seen.hold_held,
        "dropped before its inference hold was released"
    );
    assert!(record.ticker_dropped.load(Ordering::SeqCst));
    assert!(hold.dropped(), "the shutdown released the hold");
    t111::assert_steps(
        &teardown,
        &[
            "ingress.client_api",
            "ingress.post_msg",
            "loops.root",
            "extensions.hooks",
            "extensions.tasks",
            "holds.git_queue",
            "holds.client_api_slots",
            "holds.event_bus",
            "holds.drop_graph",
            "holds.extension_holds",
            "guard",
        ],
    );
    assert_eq!(
        Arc::strong_count(&stub),
        1,
        "nothing of the composition keeps the claimed port"
    );
    assert_gone_for_home(&probe, home.home(), Some(baseline)).await;
}

/// The teardown of a start that failed after the extension's registrations (the
/// `POST /msg` listener cannot bind once the Client API and the root loop are up; no
/// `on_started` ran).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn module_001_ac30_extensions_are_let_go_after_their_hooks_on_a_failed_start() {
    let home = home();
    let probe = Arc::new(ComposeProbe::new());
    let Witness {
        extension,
        record,
        stub,
        hold,
        holder_spawned,
        at_drop,
    } = Witness::new(&probe, home.home());
    let baseline = alive_tasks();
    let error = compose(
        home.options(Arc::new(MemoryComposeLog::new()), Arc::clone(&probe))
            .with_failpoints(ComposeFailpoints {
                post_msg_bind: Some(io::ErrorKind::AddrInUse),
                probe: Some(Arc::clone(&probe)),
                ..ComposeFailpoints::default()
            }),
        vec![extension],
    )
    .await
    .expect_err("the POST /msg listener cannot bind");
    assert!(matches!(error, ComposeError::Listener(_)), "{error:?}");
    let phases = record.phases();
    for phase in ["inference", "host_functions", "tools", "client_families"] {
        assert!(phases.contains(&phase), "{phase} ran: {phases:?}");
    }
    assert!(!phases.contains(&"on_started"), "{phases:?}");
    assert!(!holder_spawned.load(Ordering::SeqCst));

    let teardown = probe.record();
    let names = teardown.step_names();
    let seen = Witness::at_drop(&at_drop);
    let hooks = names
        .iter()
        .position(|step| *step == "extensions.hooks")
        .unwrap_or_else(|| panic!("no extensions.hooks step:\n{}", teardown.render_steps()));
    assert_eq!(
        seen.steps,
        names[..=hooks],
        "the extension is let go right after its hook ran:\n{}",
        teardown.render_steps()
    );
    assert!(
        seen.lock_held,
        "dropped while the runtime lock was still held"
    );
    assert!(
        seen.reserved,
        "dropped while the home was still reserved in the process-local registry"
    );
    assert!(
        seen.hold_held,
        "dropped before its inference hold was released"
    );
    assert!(hold.dropped(), "the teardown released the hold");
    t111::assert_steps(
        &teardown,
        &[
            "ingress.client_api",
            "loops.root",
            "extensions.hooks",
            "holds.client_api_slots",
            "holds.drop_graph",
            "holds.extension_holds",
            "guard",
        ],
    );
    assert_eq!(
        Arc::strong_count(&stub),
        1,
        "nothing of the composition keeps the claimed port"
    );
    assert_gone_for_home(&probe, home.home(), Some(baseline)).await;
}
