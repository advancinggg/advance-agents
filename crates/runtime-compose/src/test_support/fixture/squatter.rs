//! Another app's server on a loopback port the composition's Client API listener no longer
//! owns (the OS reclaimed its socket while the host app was suspended).

use std::io::{ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use advance_client_api::transport::{LISTENER_CHALLENGE_HEADER, LISTENER_PROOF_HEADER};

const ACCEPT_POLL: Duration = Duration::from_millis(5);
const READ_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_REQUEST_HEAD: usize = 64 * 1024;

/// A server bound to a port the composition gave up. It answers every request the way the
/// Client API transport answers a listener challenge (`204 No Content` with a proof header),
/// except that its "proof" can only echo the challenge: it does not hold the listener's key.
/// It records the head of every request it receives, so a test can tell what reached it.
pub struct PortSquatter {
    addr: SocketAddr,
    stop: Arc<AtomicBool>,
    received: Arc<Mutex<Vec<String>>>,
    thread: Option<JoinHandle<()>>,
}

impl PortSquatter {
    /// Bind `addr` (its port must be free) and start answering.
    pub fn bind(addr: SocketAddr) -> std::io::Result<Self> {
        let listener = TcpListener::bind(addr)?;
        listener.set_nonblocking(true)?;
        let addr = listener.local_addr()?;
        let stop = Arc::new(AtomicBool::new(false));
        let received = Arc::new(Mutex::new(Vec::new()));
        let thread = {
            let stop = Arc::clone(&stop);
            let received = Arc::clone(&received);
            std::thread::Builder::new()
                .name("port-squatter".to_owned())
                .spawn(move || {
                    while !stop.load(Ordering::SeqCst) {
                        match listener.accept() {
                            Ok((stream, _)) => answer(stream, &received),
                            Err(error) if error.kind() == ErrorKind::WouldBlock => {
                                std::thread::sleep(ACCEPT_POLL)
                            }
                            Err(_) => std::thread::sleep(ACCEPT_POLL),
                        }
                    }
                })?
        };
        Ok(Self {
            addr,
            stop,
            received,
            thread: Some(thread),
        })
    }

    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// The head of every request received so far, in arrival order.
    pub fn received(&self) -> Vec<String> {
        self.received
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    /// Stop answering, release the port, and return the head of every request received.
    pub fn stop(mut self) -> Vec<String> {
        self.halt();
        self.received()
    }

    fn halt(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

impl Drop for PortSquatter {
    fn drop(&mut self) {
        self.halt();
    }
}

fn answer(mut stream: TcpStream, received: &Mutex<Vec<String>>) {
    // An accepted socket inherits the listener's non-blocking mode on some platforms.
    let _ = stream.set_nonblocking(false);
    let _ = stream.set_read_timeout(Some(READ_TIMEOUT));
    let mut head = Vec::new();
    let mut chunk = [0u8; 1024];
    while !head.windows(4).any(|window| window == b"\r\n\r\n") && head.len() < MAX_REQUEST_HEAD {
        match stream.read(&mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(n) => head.extend_from_slice(&chunk[..n]),
        }
    }
    let head = String::from_utf8_lossy(&head).into_owned();
    let echo = header_value(&head, LISTENER_CHALLENGE_HEADER).unwrap_or_default();
    received
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .push(head);
    let response = format!(
        "HTTP/1.1 204 No Content\r\n{LISTENER_PROOF_HEADER}: {echo}\r\ncache-control: no-store\r\nconnection: close\r\n\r\n"
    );
    let _ = stream.write_all(response.as_bytes());
    let _ = stream.flush();
}

/// The value of header `name` in a request head (names compare case-insensitively).
pub fn header_value(head: &str, name: &str) -> Option<String> {
    head.split("\r\n").skip(1).find_map(|line| {
        let (key, value) = line.split_once(':')?;
        key.trim()
            .eq_ignore_ascii_case(name)
            .then(|| value.trim().to_owned())
    })
}
