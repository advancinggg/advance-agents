//! The Client API listener the composition owns: probe, retire, rebind on the same
//! `ClientApi`, and shutdown step 1.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::RwLock;
use std::time::Duration;

use advance_client_api::{ClientApi, ClientApiServer, ShutdownIngress};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::{timeout_at, Instant};

use crate::api::{log_keys, Admission, ClientApiCheck, ClientApiEndpoint, ClientApiRebindError};
use crate::compose_log::LogHandle;

const PROBE_BUDGET: Duration = Duration::from_millis(300);
const PROBE_ATTEMPTS: u32 = 2;
const PROBE_PAUSE: Duration = Duration::from_millis(100);
const RETIRE_BUDGET: Duration = Duration::from_secs(1);

pub(crate) struct ClientIngress {
    state: tokio::sync::Mutex<IngressState>,
    endpoint: RwLock<Option<ClientApiEndpoint>>,
    admission: Admission,
    write_discovery: bool,
    home: PathBuf,
    log: LogHandle,
    runtime: tokio::runtime::Handle,
    #[cfg(feature = "test-support")]
    probe: Option<std::sync::Arc<crate::test_support::ComposeProbe>>,
    #[cfg(feature = "test-support")]
    fail_next_probe: std::sync::atomic::AtomicBool,
    #[cfg(feature = "test-support")]
    fail_next_rebind: std::sync::atomic::AtomicBool,
    #[cfg(feature = "test-support")]
    pause: std::sync::Mutex<Option<crate::test_support::ReverifyPause>>,
    #[cfg(test)]
    probes_sent: std::sync::atomic::AtomicU32,
}

struct IngressState {
    api: Option<std::sync::Arc<ClientApi>>,
    server: Option<ClientApiServer>,
    last_addr: SocketAddr,
    closed: bool,
}

#[derive(Clone)]
pub(crate) struct IngressFromGraph {
    pub admission: Admission,
    pub write_discovery: bool,
    pub home: PathBuf,
    #[cfg(feature = "test-support")]
    pub probe: Option<std::sync::Arc<crate::test_support::ComposeProbe>>,
}

impl ClientIngress {
    pub(crate) fn new(
        server: ClientApiServer,
        params: IngressFromGraph,
        log: LogHandle,
        runtime: tokio::runtime::Handle,
    ) -> std::sync::Arc<Self> {
        let addr = server.local_addr();
        let api = server.api();
        let endpoint = endpoint_of(addr, &api);
        std::sync::Arc::new(Self {
            state: tokio::sync::Mutex::new(IngressState {
                api: Some(api),
                server: Some(server),
                last_addr: addr,
                closed: false,
            }),
            endpoint: RwLock::new(Some(endpoint)),
            admission: params.admission,
            write_discovery: params.write_discovery,
            home: params.home,
            log,
            runtime,
            #[cfg(feature = "test-support")]
            probe: params.probe,
            #[cfg(feature = "test-support")]
            fail_next_probe: std::sync::atomic::AtomicBool::new(false),
            #[cfg(feature = "test-support")]
            fail_next_rebind: std::sync::atomic::AtomicBool::new(false),
            #[cfg(feature = "test-support")]
            pause: std::sync::Mutex::new(None),
            #[cfg(test)]
            probes_sent: std::sync::atomic::AtomicU32::new(0),
        })
    }

    pub(crate) fn admission(&self) -> Admission {
        self.admission
    }

    pub(crate) fn runtime(&self) -> tokio::runtime::Handle {
        self.runtime.clone()
    }

    pub(crate) fn endpoint(&self) -> Option<ClientApiEndpoint> {
        self.endpoint
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    fn set_endpoint(&self, endpoint: Option<ClientApiEndpoint>) {
        *self
            .endpoint
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = endpoint;
    }

    pub(crate) async fn shutdown(&self, budget: Duration) -> ShutdownIngress {
        let deadline = Instant::now() + budget;
        let mut st = self.state.lock().await;
        st.closed = true;
        self.set_endpoint(None);
        let api = st.api.take().expect("Client API ingress shuts down once");
        let remaining = deadline.saturating_duration_since(Instant::now());
        if let Some(server) = st.server.take() {
            server.shutdown_ingress(remaining).await
        } else {
            ClientApiServer::shutdown_unbound(api, remaining).await
        }
    }

    #[cfg(test)]
    pub(crate) async fn reverify(
        self: std::sync::Arc<Self>,
    ) -> Result<ClientApiCheck, ClientApiRebindError> {
        if self.admission != Admission::InProcessOnly {
            return Err(ClientApiRebindError::NotInProcessAdmission);
        }
        self.reverify_body().await
    }

    pub(crate) async fn reverify_body(
        self: std::sync::Arc<Self>,
    ) -> Result<ClientApiCheck, ClientApiRebindError> {
        #[cfg(feature = "test-support")]
        {
            let pause = self
                .pause
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .take();
            if let Some(pause) = pause {
                pause.reached.notify_one();
                pause.resume.notified().await;
            }
        }
        let mut st = self.state.lock().await;
        if st.closed {
            return Err(ClientApiRebindError::ShuttingDown);
        }
        let api = st.api.clone().ok_or(ClientApiRebindError::ShuttingDown)?;
        if let Some(server) = st.server.as_ref() {
            let addr = server.local_addr();
            let fail_probe = {
                #[cfg(feature = "test-support")]
                {
                    self.fail_next_probe
                        .swap(false, std::sync::atomic::Ordering::SeqCst)
                }
                #[cfg(not(feature = "test-support"))]
                {
                    false
                }
            };
            if !fail_probe && self.listener_answers(addr).await {
                return Ok(ClientApiCheck::Healthy);
            }
            let retired = st
                .server
                .take()
                .expect("listener")
                .retire(RETIRE_BUDGET)
                .await;
            st.last_addr = retired.local_addr;
        }
        let previous = st.last_addr;
        #[cfg(feature = "test-support")]
        if self
            .fail_next_rebind
            .swap(false, std::sync::atomic::Ordering::SeqCst)
        {
            self.set_endpoint(None);
            self.log.err(
                log_keys::CLIENT_API_REBIND_FAILED,
                format!(
                    "advance: WARN Client API listener could not be bound again (previous port {}): test-support rebind failpoint",
                    previous.port()
                ),
            );
            return Err(ClientApiRebindError::Bind {
                previous,
                error: std::io::Error::other("test-support rebind failpoint"),
            });
        }
        match ClientApiServer::bind(std::sync::Arc::clone(&api), previous.port()).await {
            Ok(server) => {
                st.server = Some(server);
                self.set_endpoint(Some(endpoint_of(previous, &api)));
                self.record_listener(previous);
                self.log.err(
                    log_keys::CLIENT_API_REBOUND,
                    format!("advance: Client API listener rebound at http://{previous}"),
                );
                Ok(ClientApiCheck::Rebound { addr: previous })
            }
            Err(_) => match ClientApiServer::bind(std::sync::Arc::clone(&api), 0).await {
                Ok(server) => {
                    let current = server.local_addr();
                    st.server = Some(server);
                    st.last_addr = current;
                    self.set_endpoint(Some(endpoint_of(current, &api)));
                    if self.write_discovery {
                        let _ = advance_home::write_client_api_discovery(
                            &self.home,
                            std::process::id(),
                            &format!("http://{current}"),
                        );
                    }
                    self.record_listener(current);
                    self.log.err(
                        log_keys::CLIENT_API_MOVED,
                        format!(
                            "advance: Client API listener moved from http://{previous} to http://{current}"
                        ),
                    );
                    Ok(ClientApiCheck::Moved { previous, current })
                }
                Err(error) => {
                    self.set_endpoint(None);
                    self.log.err(
                        log_keys::CLIENT_API_REBIND_FAILED,
                        format!(
                            "advance: WARN Client API listener could not be bound again (previous port {}): {error}",
                            previous.port()
                        ),
                    );
                    Err(ClientApiRebindError::Bind { previous, error })
                }
            },
        }
    }

    fn record_listener(&self, addr: SocketAddr) {
        #[cfg(feature = "test-support")]
        probe_record!(self.probe, |record| record
            .listeners
            .push(("client_api", addr)));
        #[cfg(not(feature = "test-support"))]
        let _ = addr;
    }

    async fn listener_answers(&self, addr: SocketAddr) -> bool {
        for attempt in 0..PROBE_ATTEMPTS {
            if attempt > 0 {
                tokio::time::sleep(PROBE_PAUSE).await;
            }
            #[cfg(test)]
            {
                self.probes_sent
                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }
            let deadline = Instant::now() + PROBE_BUDGET;
            let answered = timeout_at(deadline, probe_once(addr)).await;
            if matches!(answered, Ok(true)) {
                return true;
            }
        }
        false
    }

    #[cfg(feature = "test-support")]
    pub(crate) async fn sever_for_test(&self) -> Option<SocketAddr> {
        let mut st = self.state.lock().await;
        if st.closed {
            return None;
        }
        let server = st.server.take()?;
        let addr = server.local_addr();
        let retired = server.retire(RETIRE_BUDGET).await;
        st.last_addr = retired.local_addr;
        Some(addr)
    }

    #[cfg(feature = "test-support")]
    pub(crate) fn fail_next_probe(&self) {
        self.fail_next_probe
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }

    #[cfg(feature = "test-support")]
    pub(crate) fn fail_next_rebind(&self) {
        self.fail_next_rebind
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }

    #[cfg(feature = "test-support")]
    pub(crate) fn arm_pause(&self) -> crate::test_support::ReverifyPause {
        let pause = crate::test_support::ReverifyPause {
            reached: std::sync::Arc::new(tokio::sync::Notify::new()),
            resume: std::sync::Arc::new(tokio::sync::Notify::new()),
        };
        *self
            .pause
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(pause.clone());
        pause
    }

    #[cfg(test)]
    fn probes_sent(&self) -> u32 {
        self.probes_sent.load(std::sync::atomic::Ordering::SeqCst)
    }
}

fn endpoint_of(addr: SocketAddr, api: &std::sync::Arc<ClientApi>) -> ClientApiEndpoint {
    ClientApiEndpoint {
        base_url: format!("http://{addr}"),
        socket_addr: addr,
        api: std::sync::Arc::downgrade(api),
    }
}

async fn probe_once(addr: SocketAddr) -> bool {
    let Ok(mut stream) = tokio::net::TcpStream::connect(addr).await else {
        return false;
    };
    let request =
        format!("GET /client/health HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n");
    if stream.write_all(request.as_bytes()).await.is_err() {
        return false;
    }
    let mut buf = [0u8; 64];
    let Ok(n) = stream.read(&mut buf).await else {
        return false;
    };
    buf[..n].starts_with(b"HTTP/1.")
}

#[cfg(test)]
mod tests {
    use super::*;
    use advance_client_api::{ClientApi, ClientApiConfig};
    use std::sync::Arc;

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn module_001_ac32_reverify_is_refused_for_same_user_admission_without_probing() {
        let api = Arc::new(ClientApi::new(ClientApiConfig::default()));
        let server = ClientApiServer::bind(api, 0)
            .await
            .expect("bind a same-user listener");
        let dir = tempfile::tempdir().expect("home");
        let home = std::fs::canonicalize(dir.path()).expect("canonical home");
        let ing = ClientIngress::new(
            server,
            IngressFromGraph {
                admission: Admission::SameUserLoopback,
                write_discovery: false,
                home,
                #[cfg(feature = "test-support")]
                probe: None,
            },
            LogHandle::null(),
            tokio::runtime::Handle::current(),
        );
        let error = Arc::clone(&ing)
            .reverify()
            .await
            .expect_err("same-user admission is not rebound");
        assert!(
            matches!(error, ClientApiRebindError::NotInProcessAdmission),
            "{error:?}"
        );
        assert_eq!(ing.probes_sent(), 0);
        let _ = ing.shutdown(Duration::from_secs(1)).await;
    }
}
