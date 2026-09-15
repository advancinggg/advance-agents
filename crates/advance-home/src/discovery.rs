//! `{home}/.runtime/client-api` attach discovery.

use std::fs;
use std::net::ToSocketAddrs;
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientApiDiscovery {
    pub pid: u32,
    pub client_api_base: String,
}

pub fn discovery_path(home: &Path) -> std::path::PathBuf {
    home.join(".runtime").join("client-api")
}

pub fn write_client_api_discovery(
    home: &Path,
    pid: u32,
    client_api_base: &str,
) -> Result<(), std::io::Error> {
    let dir = home.join(".runtime");
    fs::create_dir_all(&dir)?;
    let path = discovery_path(home);
    if client_api_base
        .bytes()
        .any(|b| b < 0x21 || b == b'"' || b > 0x7e)
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "client_api_base must be a single-line token",
        ));
    }
    let body = format!("pid: {pid}\nclient_api_base: \"{client_api_base}\"\n");
    crate::scaffold::write_0600_nofollow(&path, body.as_bytes())
}

pub fn read_client_api_discovery(home: &Path) -> Option<ClientApiDiscovery> {
    let raw = crate::scaffold::read_small_regular(&discovery_path(home), 512)?;
    parse_discovery(&raw)
}

fn parse_discovery(raw: &str) -> Option<ClientApiDiscovery> {
    let mut pid = None;
    let mut base = None;
    for line in raw.lines() {
        if let Some(rest) = line.strip_prefix("pid:") {
            pid = rest.trim().parse().ok();
        } else if let Some(rest) = line.strip_prefix("client_api_base:") {
            let v = rest.trim().trim_matches('"');
            if loopback_http_base(v) {
                base = Some(v.to_string());
            }
        }
    }
    Some(ClientApiDiscovery {
        pid: pid?,
        client_api_base: base?,
    })
}

fn loopback_http_base(v: &str) -> bool {
    parse_loopback_endpoint(v).is_some()
}

fn parse_loopback_endpoint(v: &str) -> Option<(String, u16)> {
    let v = v.trim().trim_matches('"');
    if v.bytes().any(|b| b < 0x21 || b > 0x7e) {
        return None;
    }
    let rest = v
        .strip_prefix("http://")
        .or_else(|| v.strip_prefix("https://"))?;
    let authority = rest.split('/').next().unwrap_or("");
    if authority.is_empty() || authority.contains('@') {
        return None;
    }
    let (host, port) = if let Some(h) = authority.strip_prefix("[::1]") {
        let p = if h.is_empty() {
            80
        } else {
            h.strip_prefix(':')?.parse().ok()?
        };
        ("::1", p)
    } else {
        let mut parts = authority.rsplitn(2, ':');
        let maybe_port = parts.next()?;
        match parts.next() {
            Some(h) => (h, maybe_port.parse().ok()?),
            None => (maybe_port, 80),
        }
    };
    if !matches!(host, "127.0.0.1" | "localhost" | "::1") {
        return None;
    }
    Some((host.to_string(), port))
}

fn loopback_connect_addr(host: &str, port: u16) -> Option<std::net::SocketAddr> {
    match host {
        "127.0.0.1" => Some(std::net::SocketAddr::from(([127, 0, 0, 1], port))),
        "::1" => Some(std::net::SocketAddr::from((
            std::net::Ipv6Addr::LOCALHOST,
            port,
        ))),
        "localhost" => (host, port)
            .to_socket_addrs()
            .ok()?
            .find(|a| a.ip().is_loopback()),
        _ => None,
    }
}

/// Probe CONTRACT-190 liveness. Prefer `/client/health`.
pub fn client_api_accepts(base: &str) -> bool {
    let Some((host, port)) = parse_loopback_endpoint(base) else {
        return false;
    };
    let Some(addr) = loopback_connect_addr(&host, port) else {
        return false;
    };
    block_on_io(async move {
        match tokio::time::timeout(
            std::time::Duration::from_millis(150),
            tokio::net::TcpStream::connect(addr),
        )
        .await
        {
            Ok(Ok(stream)) => http_get_health(stream, addr).await,
            _ => false,
        }
    })
}

async fn http_get_health(mut stream: tokio::net::TcpStream, addr: std::net::SocketAddr) -> bool {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let req = format!("GET /client/health HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n");
    if tokio::time::timeout(
        std::time::Duration::from_millis(150),
        stream.write_all(req.as_bytes()),
    )
    .await
    .ok()
    .and_then(|r| r.ok())
    .is_none()
    {
        return false;
    }
    let mut buf = [0u8; 64];
    match tokio::time::timeout(std::time::Duration::from_millis(150), stream.read(&mut buf)).await {
        Ok(Ok(n)) if n > 0 => {
            let s = String::from_utf8_lossy(&buf[..n]);
            s.contains(" 200 ") || s.starts_with("HTTP/1.1 200") || s.starts_with("HTTP/1.0 200")
        }
        _ => false,
    }
}

pub(crate) fn block_on_io<F, T>(fut: F) -> T
where
    F: std::future::Future<Output = T> + Send + 'static,
    T: Send + 'static,
{
    if let Ok(handle) = tokio::runtime::Handle::try_current() {
        // Never Handle::block_on on the caller's runtime. Fresh thread.
        let _ = handle;
    }
    std::thread::Builder::new()
        .name("c243-io".into())
        .spawn(move || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("c243 tokio runtime")
                .block_on(fut)
        })
        .expect("c243 io thread")
        .join()
        .expect("c243 io thread join")
}
