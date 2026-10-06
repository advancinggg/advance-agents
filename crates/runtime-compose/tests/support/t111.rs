//! Shared fixtures of the MODULE-001-T111 / MODULE-001-AC-30 in-process witnesses: a home
//! (runtime config, agent config, optionally a deployed driver, a git repository) with a
//! state root beside it, the clients a witness drives a composition with (raw `POST /msg`
//! on a std thread, an operator session, the `/client/events/stream` WebSocket polled
//! inline, so a witness spawns no tokio task of its own), and the checks that nothing of a
//! stopped composition is left.
//!
//! Included by each witness binary: `#[path = "support/t111.rs"] mod t111;`.
#![allow(dead_code)]

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, Once};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use advance_client_api::{ClientSession, Platform, Principal, Scope, CLIENT_WS_PROTOCOL};
use advance_runtime_compose::test_support::{
    live_composition_threads_for_test, ComposeProbe, ProbeRecord, TEARDOWN_ORDER,
};
use advance_runtime_compose::{ClientApiEndpoint, ComposeLog, ComposeOptions};
use futures::{SinkExt, StreamExt};
use tempfile::TempDir;
use tokio_tungstenite::tungstenite::Message;
use wit_component::ComponentEncoder;

/// The deployed driver: on `handle-message` it writes the message payload to `j01.txt`
/// through `agent-fs` (one turn commit) and replies `j01-reply`. It never calls the LLM.
const J01_CORE: &[u8] =
    include_bytes!("../../../runtime/tests/fixtures/guest-rust-j01-reply-write.core.wasm");
/// What the driver replies to every message.
pub const J01_REPLY: &[u8] = b"j01-reply";
/// The name of the file the driver writes (in the root agent's territory).
pub const J01_FILE: &str = "j01.txt";

/// The environment variable the homes' runtime config names for the master key.
pub const MASTER_KEY_ENV: &str = "ADVANCE_T111_MASTER_KEY";
const MASTER_KEY_HEX: &str = "7111711171117111711171117111711171117111711171117111711171117111";

/// Budget of the objects a stopped composition built to die.
pub const OBJECTS_BUDGET: Duration = Duration::from_secs(2);
/// Budget of the tasks to end: the per-operation library tasks a composition cannot own
/// (axum per-connection tasks, client pool tasks, session idle monitors that tick every
/// 5 s) end on their own once their owners are gone.
pub const TASKS_BUDGET: Duration = Duration::from_secs(6);
/// Budget of the composition's own threads to end.
pub const THREADS_BUDGET: Duration = Duration::from_secs(5);
/// Budget of the config watcher's threads to end: the teardown waits a bounded time for
/// the release of the OS watcher, which on macOS waits for the FSEvents run loop (its
/// latency is the platform's, seconds under load), and past that bound the release ends
/// on its own thread.
pub const OS_WATCHER_RELEASE_BUDGET: Duration = Duration::from_secs(60);
/// Budget of one HTTP exchange with a composition.
const HTTP_TIMEOUT: Duration = Duration::from_secs(60);
const POLL: Duration = Duration::from_millis(10);

/// Compositions of one test binary run one at a time: the witnesses check process-wide
/// state (the CONTRACT-218 custody paths, the git commit queues, the process-local
/// registry, the composition's thread count), which a concurrent composition would
/// disturb. Every composing test holds this for its whole body.
pub fn serial() -> MutexGuard<'static, ()> {
    static SERIAL: Mutex<()> = Mutex::new(());
    SERIAL
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Set the master key in this process's environment once, before any composition reads
/// it.
pub fn ensure_master_key() {
    static INIT: Once = Once::new();
    INIT.call_once(|| std::env::set_var(MASTER_KEY_ENV, MASTER_KEY_HEX));
}

/// A home under a fresh temp root: `<root>/home` (canonical, the composed home, a git
/// repository) and `<root>/state` (the state root every witness passes, so nothing is
/// written under the process `HOME`).
pub struct T111Home {
    _dir: TempDir,
    pub root: PathBuf,
    pub home: PathBuf,
    pub state_root: PathBuf,
}

impl T111Home {
    /// A home declaring `caps`, with the `j01` driver deployed when `driver` is set.
    pub fn new(caps: &[&str], driver: bool) -> T111Home {
        ensure_master_key();
        let dir = tempfile::tempdir().expect("tempdir");
        let root = std::fs::canonicalize(dir.path()).expect("canonical temp root");
        let home = root.join("home");
        let state_root = root.join("state");
        for path in [
            home.join(".advance"),
            home.join(".runtime/events/jsonl"),
            home.join(".agent"),
            state_root.clone(),
        ] {
            std::fs::create_dir_all(&path)
                .unwrap_or_else(|e| panic!("create {}: {e}", path.display()));
        }
        std::fs::write(home.join(".advance/runtime-config.yaml"), runtime_yaml())
            .expect("write runtime config");
        std::fs::write(home.join(".agent/config.yaml"), agent_yaml(caps))
            .expect("write agent config");
        if driver {
            std::fs::write(
                home.join(".agent/behavior.component.wasm"),
                encode_component(J01_CORE),
            )
            .expect("deploy driver");
        }
        advance_git::bootstrap_repo_at(&home).expect("git repository");
        T111Home {
            _dir: dir,
            root,
            home,
            state_root,
        }
    }

    /// `ComposeOptions::daemon` on this home, with platform state under the state root.
    pub fn options(&self, log: Arc<dyn ComposeLog>) -> ComposeOptions {
        ComposeOptions::daemon(&self.home, log).with_state_root(&self.state_root)
    }

    /// `<home>/.runtime/runtime.lock`.
    pub fn lock_path(&self) -> PathBuf {
        self.home.join(".runtime/runtime.lock")
    }

    /// Replace the deployed driver's bytes.
    pub fn deploy_driver_bytes(&self, bytes: &[u8]) {
        std::fs::write(self.home.join(".agent/behavior.component.wasm"), bytes)
            .expect("deploy driver bytes");
    }

    /// `<home>/.advance/runtime-config.yaml`.
    pub fn config_path(&self) -> PathBuf {
        self.home.join(".advance/runtime-config.yaml")
    }

    /// Rewrite the runtime config through `edit`.
    pub fn edit_runtime_config(&self, edit: impl FnOnce(String) -> String) {
        let yaml = std::fs::read_to_string(self.config_path()).expect("read runtime config");
        std::fs::write(self.config_path(), edit(yaml)).expect("write runtime config");
    }
}

/// One OpenAI provider (never called: the driver makes no LLM call) and the master key
/// from [`MASTER_KEY_ENV`].
pub fn runtime_yaml() -> String {
    format!(
        r#"wasm:
  max_memory_pages: 1024
  epoch_interruption_ms: 100
  fuel_enabled: false

llm-providers:
  - id: openai
    endpoint: https://api.openai.com
    api-key-secret: openai-api-key
    model-aliases:
      gpt: gpt-4o
    cost-per-mtoken-in: 2.50
    cost-per-mtoken-out: 10.00
    rate-limit:
      requests-per-minute: 1000
      tokens-per-minute: 400000

cron:
  max_jitter_ratio: 0.1

git:
  gc_interval_hours: 24
  max_tracked_file_mb: 10

secrets:
  master-key-source: env-var
  env-var-name: {MASTER_KEY_ENV}

post-processor:
  llm-model: sonnet-light
  llm-failure-cooldown-seconds: 600

database:
  db-path: ".runtime/index.db"
  pool-size: 4
"#
    )
}

fn agent_yaml(caps: &[&str]) -> String {
    if caps.is_empty() {
        return "capabilities: {}\n".to_owned();
    }
    let mut yaml = String::from("capabilities:\n");
    for cap in caps {
        yaml.push_str(&format!("  {cap}: true\n"));
    }
    yaml
}

fn encode_component(core: &[u8]) -> Vec<u8> {
    ComponentEncoder::default()
        .validate(true)
        .module(core)
        .expect("wrap core module")
        .encode()
        .expect("encode component")
}

/// tokio's alive tasks on the current runtime.
pub fn alive_tasks() -> usize {
    tokio::runtime::Handle::current()
        .metrics()
        .num_alive_tasks()
}

/// Poll `done` (yielding to the runtime between polls) until it holds or `budget` ends.
pub async fn poll_until(budget: Duration, mut done: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + budget;
    loop {
        if done() {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(POLL).await;
    }
}

/// Wait for a std thread without blocking the runtime the composition runs on.
pub async fn join_thread<T>(thread: JoinHandle<T>, budget: Duration) -> T {
    assert!(
        poll_until(budget, || thread.is_finished()).await,
        "the client thread did not finish within {budget:?}"
    );
    thread.join().expect("client thread")
}

/// `POST /msg` with `{"payload": payload}` over a blocking socket: the status and the
/// body.
pub fn post_msg(addr: SocketAddr, payload: &str) -> (u16, Vec<u8>) {
    let body = serde_json::json!({ "payload": payload }).to_string();
    let request = format!(
        "POST /msg HTTP/1.1\r\nHost: {addr}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let mut stream = TcpStream::connect(addr).expect("connect POST /msg");
    stream
        .set_read_timeout(Some(HTTP_TIMEOUT))
        .expect("read timeout");
    stream
        .write_all(request.as_bytes())
        .expect("write POST /msg");
    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .expect("read POST /msg response");
    parse_http_response(&response)
}

/// [`post_msg`] on a std thread of its own.
pub fn spawn_post_msg(addr: SocketAddr, payload: &str) -> JoinHandle<(u16, Vec<u8>)> {
    let payload = payload.to_owned();
    std::thread::Builder::new()
        .name("t111-post-msg".into())
        .spawn(move || post_msg(addr, &payload))
        .expect("spawn POST /msg client")
}

/// The status code and the body of a `Content-Length` HTTP/1.1 response.
fn parse_http_response(response: &[u8]) -> (u16, Vec<u8>) {
    let split = response
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .unwrap_or_else(|| panic!("no HTTP head in {:?}", String::from_utf8_lossy(response)));
    let head = String::from_utf8_lossy(&response[..split]);
    let status = head
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse().ok())
        .unwrap_or_else(|| panic!("no status line in {head:?}"));
    (status, response[split + 4..].to_vec())
}

/// Insert an operator session into the composition's Client API and return its token.
/// The strong reference is dropped before this returns.
pub fn mint_session(endpoint: &ClientApiEndpoint) -> String {
    let token = "t111-operator".to_owned();
    let api = endpoint.api.upgrade().expect("the Client API is alive");
    api.sessions().insert(
        token.clone(),
        ClientSession {
            session_id: "t111-session".into(),
            principal: Principal::operator("t111"),
            platform: Platform::Mac,
            scopes: Scope::operator_default(),
            csrf_token: None,
            expires_at: u64::MAX,
        },
        0,
    );
    token
}

/// A Client API WebSocket, polled inline by the witness.
pub type ClientWs = tokio_tungstenite::WebSocketStream<tokio::net::TcpStream>;

/// Open `/client/events/stream` as `token` and return the socket with its seed frame.
pub async fn open_events_ws(endpoint: &ClientApiEndpoint, token: &str) -> (ClientWs, String) {
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;
    use tokio_tungstenite::tungstenite::http::header::{ORIGIN, SEC_WEBSOCKET_PROTOCOL};

    let addr = endpoint.socket_addr;
    let mut request = format!("ws://{addr}/client/events/stream")
        .into_client_request()
        .expect("WebSocket request");
    request.headers_mut().insert(
        SEC_WEBSOCKET_PROTOCOL,
        format!("{CLIENT_WS_PROTOCOL}, advance.bearer.{token}")
            .parse()
            .expect("protocol header"),
    );
    request.headers_mut().insert(
        ORIGIN,
        format!("http://{addr}").parse().expect("origin header"),
    );
    let tcp = tokio::net::TcpStream::connect(addr)
        .await
        .expect("connect the Client API");
    let (mut ws, _) = tokio_tungstenite::client_async(request, tcp)
        .await
        .expect("WebSocket handshake");
    let seed = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            match ws.next().await {
                Some(Ok(Message::Text(text))) => return text.to_string(),
                Some(Ok(Message::Ping(payload))) => {
                    let _ = ws.send(Message::Pong(payload)).await;
                }
                other => panic!("unexpected frame before the seed: {other:?}"),
            }
        }
    })
    .await
    .expect("the seed frame arrives");
    (ws, seed)
}

/// The socket is closed by the server (a Close frame, or the end of the stream) within
/// `budget`.
pub async fn assert_ws_closed(ws: &mut ClientWs, budget: Duration) {
    let closed = tokio::time::timeout(budget, async {
        loop {
            match ws.next().await {
                None | Some(Ok(Message::Close(_))) | Some(Err(_)) => return,
                Some(Ok(_)) => continue,
            }
        }
    })
    .await;
    assert!(
        closed.is_ok(),
        "the events WebSocket is still open {budget:?} after the shutdown"
    );
}

/// The order the shutdown runs its steps in, written out here rather than read from the
/// implementation: ingress, loops, extension hooks, holds, and the instance guard last;
/// the loops in the order the daemon has always stopped them, then the LLM stream reaper;
/// the holds in dependency order: the selected-provider writer, the watchers, the packs
/// poll, the cap-grant sweeper, the breaker, the ChatGPT sign-in, the git commit queue
/// (closed and its worker joined), the Client API provider slots, the EventBus, the
/// extensions' holds, then the rest of the graph (whose drop releases the CONTRACT-218
/// custody).
pub const D1_ORDER: &[&str] = &[
    "ingress.client_api",
    "ingress.post_msg",
    "ingress.hooks",
    "loops.root",
    "loops.host_pump",
    "loops.perchild",
    "loops.mcp",
    "loops.auto_tick",
    "loops.readiness_walk",
    "loops.llm_stream_reaper",
    "extensions.hooks",
    "extensions.tasks",
    "holds.selected_provider",
    "holds.watchers",
    "holds.packs_poll",
    "holds.cap_grant_sweeper",
    "holds.breaker",
    "holds.chatgpt_sign_in",
    "holds.git_queue",
    "holds.client_api_slots",
    "holds.event_bus",
    "holds.extension_holds",
    "holds.drop_graph",
    "guard",
];

/// The steps the teardown ran follow [`D1_ORDER`] (each at most once), and the
/// `mandatory` ones all ran, in the order `mandatory` lists them. The teardown's own step
/// catalogue ([`TEARDOWN_ORDER`]) is [`D1_ORDER`].
pub fn assert_steps(rec: &ProbeRecord, mandatory: &[&str]) {
    assert_eq!(
        TEARDOWN_ORDER, D1_ORDER,
        "the teardown's step catalogue is the shutdown order"
    );
    let names = rec.step_names();
    let positions: Vec<usize> = names
        .iter()
        .map(|name| {
            D1_ORDER
                .iter()
                .position(|step| step == name)
                .unwrap_or_else(|| panic!("unknown teardown step {name}"))
        })
        .collect();
    assert!(
        positions.windows(2).all(|pair| pair[0] < pair[1]),
        "the teardown steps are out of order:\n{}",
        rec.render_steps()
    );
    let ran: Vec<&str> = names
        .iter()
        .copied()
        .filter(|name| mandatory.contains(name))
        .collect();
    assert_eq!(
        ran,
        mandatory,
        "the mandatory teardown steps, in this order:\n{}",
        rec.render_steps()
    );
}

/// Nothing of the composition `probe` recorded is left: every object it built is dead,
/// tokio's alive tasks are back to `baseline_tasks`, no thread the composition started
/// runs (counted, and on Linux and macOS also found by name, the config watcher's threads
/// included), the process-wide CONTRACT-218 custody paths, git commit queues and reserved
/// homes are empty, `home`'s runtime lock is gone and every port it bound can be bound
/// again. Each failure names what is left and the teardown's step table (each step with
/// the alive tasks right after it).
pub async fn assert_composition_gone(baseline_tasks: usize, probe: &ComposeProbe, home: &Path) {
    let report = |what: &str| {
        let rec = probe.record();
        format!(
            "{what}\nalive objects: {:?}\nteardown steps:\n{}",
            rec.alive(),
            rec.render_steps()
        )
    };

    assert!(
        poll_until(OBJECTS_BUDGET, || probe.record().alive().is_empty()).await,
        "{}",
        report("objects of the composition are still alive")
    );
    assert!(
        poll_until(TASKS_BUDGET, || alive_tasks() == baseline_tasks).await,
        "{}",
        report(&format!(
            "tokio alive tasks: {} (baseline {baseline_tasks})",
            alive_tasks()
        ))
    );
    assert!(
        poll_until(THREADS_BUDGET, || live_composition_threads_for_test() == 0).await,
        "{}",
        report(&format!(
            "threads of the composition still running: {}",
            live_composition_threads_for_test()
        ))
    );
    assert!(
        poll_until(THREADS_BUDGET, || {
            named_threads(COMPOSITION_THREADS).is_empty()
        })
        .await,
        "{}",
        report(&format!(
            "threads still running: {:?}",
            named_threads(COMPOSITION_THREADS)
        ))
    );
    assert!(
        poll_until(OS_WATCHER_RELEASE_BUDGET, || {
            config_watcher_threads().is_empty()
        })
        .await,
        "{}",
        report(&format!(
            "config watcher threads still running: {:?}",
            config_watcher_threads()
        ))
    );
    assert!(
        poll_until(THREADS_BUDGET, || {
            advance_runtime_compose::contract218_anchor::custody_paths_for_test().is_empty()
                && advance_git::commit_queue::active_queue_paths_for_test().is_empty()
                && advance_runtime_compose::registry::reserved_homes_for_test().is_empty()
        })
        .await,
        "{}",
        report(&format!(
            "process-wide state left: CONTRACT-218 custody {:?}, git commit queues {:?}, \
             reserved homes {:?}",
            advance_runtime_compose::contract218_anchor::custody_paths_for_test(),
            advance_git::commit_queue::active_queue_paths_for_test(),
            advance_runtime_compose::registry::reserved_homes_for_test(),
        ))
    );
    let lock = home.join(".runtime/runtime.lock");
    assert!(
        !lock.exists(),
        "{}",
        report(&format!("{} is still there", lock.display()))
    );
    for (name, addr) in probe.record().listeners {
        if let Err(error) = TcpListener::bind(addr) {
            panic!(
                "{}",
                report(&format!(
                    "the {name} port {addr} cannot be bound again: {error}"
                ))
            );
        }
    }
}

/// Name prefixes of the threads a composition starts, itself or through the crates it
/// composes, each at most 15 bytes long (Linux truncates a thread's name to that).
const COMPOSITION_THREADS: &[&str] = &[
    "advance-client-",
    "contract218-anc",
    "advance-host-ep",
    "chatgpt-renewal",
    "chatgpt-sign-in",
    "cap-grant-chann",
    "l6-git-bridge",
];

/// Name prefixes of the config watcher's threads: the OS watcher's own (`notify-rs inotify
/// loop` on Linux, `notify-rs fsevents loop` on macOS) and the one that releases it at
/// shutdown (`advance-config-watch-release`).
const CONFIG_WATCHER_THREADS: &[&str] = &["notify-rs ", "advance-config-"];

/// The config watcher's threads running now, by name.
pub fn config_watcher_threads() -> Vec<String> {
    named_threads(CONFIG_WATCHER_THREADS)
}

/// The names of this process's threads that start with one of `prefixes` (none where
/// this process's thread names are not read: other than Linux and macOS).
fn named_threads(prefixes: &[&str]) -> Vec<String> {
    thread_names()
        .into_iter()
        .filter(|name| prefixes.iter().any(|prefix| name.starts_with(prefix)))
        .collect()
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn thread_names() -> Vec<String> {
    Vec::new()
}

/// The name of every thread of this process (`/proc/self/task/*/comm`).
#[cfg(target_os = "linux")]
fn thread_names() -> Vec<String> {
    let mut names = Vec::new();
    if let Ok(tasks) = std::fs::read_dir("/proc/self/task") {
        for task in tasks.flatten() {
            if let Ok(comm) = std::fs::read_to_string(task.path().join("comm")) {
                names.push(comm.trim().to_owned());
            }
        }
    }
    names
}

/// The name of every thread of this process: `proc_pidinfo` lists the process's threads,
/// then gives each one's info, its name included.
#[cfg(target_os = "macos")]
fn thread_names() -> Vec<String> {
    /// `PROC_PIDLISTTHREADS` of `<sys/proc_info.h>`, which `libc` does not export.
    const PROC_PIDLISTTHREADS: libc::c_int = 6;
    let pid = std::process::id() as libc::c_int;
    let mut handles = vec![0u64; 256];
    let listed = loop {
        let capacity = std::mem::size_of_val(handles.as_slice()) as libc::c_int;
        // SAFETY: `handles` is valid for writes of `capacity` bytes.
        let bytes = unsafe {
            libc::proc_pidinfo(
                pid,
                PROC_PIDLISTTHREADS,
                0,
                handles.as_mut_ptr().cast(),
                capacity,
            )
        };
        if bytes <= 0 {
            return Vec::new();
        }
        if bytes < capacity {
            break bytes as usize / std::mem::size_of::<u64>();
        }
        // The list may have been cut short: retry with room to spare.
        let grown = handles.len() * 2;
        handles.resize(grown, 0);
    };
    handles.truncate(listed);
    handles
        .into_iter()
        .filter_map(|handle| {
            // SAFETY: `proc_threadinfo` is plain data, valid when zeroed.
            let mut info: libc::proc_threadinfo = unsafe { std::mem::zeroed() };
            let size = std::mem::size_of::<libc::proc_threadinfo>() as libc::c_int;
            // SAFETY: `info` is valid for writes of `size` bytes.
            let got = unsafe {
                libc::proc_pidinfo(
                    pid,
                    libc::PROC_PIDTHREADINFO,
                    handle,
                    std::ptr::addr_of_mut!(info).cast(),
                    size,
                )
            };
            // A thread that ended after the list was taken has no info any more.
            (got == size).then(|| {
                let name: Vec<u8> = info.pth_name.iter().map(|&c| c as u8).collect();
                let end = name.iter().position(|&b| b == 0).unwrap_or(name.len());
                String::from_utf8_lossy(&name[..end]).into_owned()
            })
        })
        .collect()
}

/// The commits reachable from the home repository's `HEAD` (none on an unborn branch).
pub fn head_commits(home: &Path) -> usize {
    let repo = git2::Repository::open(home).expect("open the home repository");
    let Ok(head) = repo.head() else {
        return 0;
    };
    let mut walk = repo.revwalk().expect("revwalk");
    walk.push(head.target().expect("HEAD names a commit"))
        .expect("walk from HEAD");
    walk.count()
}

/// Every file path in the tree of the home repository's `HEAD` commit (for failure
/// messages).
pub fn head_paths(home: &Path) -> Vec<String> {
    let repo = git2::Repository::open(home).expect("open the home repository");
    let Ok(tree) = repo.head().and_then(|head| head.peel_to_tree()) else {
        return Vec::new();
    };
    let mut paths = Vec::new();
    let _ = tree.walk(git2::TreeWalkMode::PreOrder, |dir, entry| {
        if entry.kind() == Some(git2::ObjectType::Blob) {
            paths.push(format!("{dir}{}", entry.name().unwrap_or("<non-utf8>")));
        }
        git2::TreeWalkResult::Ok
    });
    paths
}

/// The path and the bytes of the first file named `name` (at any depth) in the tree of
/// the home repository's `HEAD` commit.
pub fn head_file(home: &Path, name: &str) -> Option<(String, Vec<u8>)> {
    let repo = git2::Repository::open(home).expect("open the home repository");
    let head = repo.head().ok()?;
    let tree = head.peel_to_commit().ok()?.tree().ok()?;
    let mut found = None;
    tree.walk(git2::TreeWalkMode::PreOrder, |dir, entry| {
        if found.is_none()
            && entry.name() == Some(name)
            && entry.kind() == Some(git2::ObjectType::Blob)
        {
            found = Some((format!("{dir}{name}"), entry.id()));
        }
        git2::TreeWalkResult::Ok
    })
    .ok()?;
    let (path, id) = found?;
    let blob = repo.find_blob(id).ok()?;
    Some((path, blob.content().to_vec()))
}
