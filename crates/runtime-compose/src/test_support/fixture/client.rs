//! Raw HTTP/1.1 helpers for fixture tests (std sockets inside `spawn_blocking`).

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

use advance_client_api::{ClientSession, Platform, Principal, Scope, API_VERSION};
use serde_json::Value;

use crate::api::ClientApiEndpoint;

const HTTP_TIMEOUT: Duration = Duration::from_secs(60);

pub struct Http {
    addr: SocketAddr,
    method: &'static str,
    path: String,
    session: Option<String>,
    idempotency_key: Option<String>,
    origin: Option<String>,
    csrf: Option<String>,
    body: Option<String>,
}

pub struct HttpResponse {
    pub status: u16,
    pub body: Value,
}

impl Http {
    pub fn get(addr: SocketAddr, path: impl Into<String>) -> Self {
        Self::new(addr, "GET", path)
    }

    pub fn post(addr: SocketAddr, path: impl Into<String>) -> Self {
        Self::new(addr, "POST", path)
    }

    fn new(addr: SocketAddr, method: &'static str, path: impl Into<String>) -> Self {
        Self {
            addr,
            method,
            path: path.into(),
            session: None,
            idempotency_key: None,
            origin: None,
            csrf: None,
            body: None,
        }
    }

    pub fn session(mut self, tok: impl Into<String>) -> Self {
        self.session = Some(tok.into());
        self
    }

    pub fn idempotency_key(mut self, key: impl Into<String>) -> Self {
        self.idempotency_key = Some(key.into());
        self
    }

    pub fn origin(mut self, origin: impl Into<String>) -> Self {
        self.origin = Some(origin.into());
        self
    }

    pub fn csrf(mut self, token: impl Into<String>) -> Self {
        self.csrf = Some(token.into());
        self
    }

    pub async fn json(mut self, body: Value) -> HttpResponse {
        self.body = Some(body.to_string());
        self.send().await
    }

    pub async fn send(self) -> HttpResponse {
        tokio::task::spawn_blocking(move || self.send_blocking())
            .await
            .expect("http worker")
    }

    fn send_blocking(&self) -> HttpResponse {
        let mut headers = format!(
            "{} {} HTTP/1.1\r\nHost: {}\r\nx-advance-api-version: {API_VERSION}\r\nConnection: close\r\n",
            self.method, self.path, self.addr
        );
        if let Some(token) = &self.session {
            headers.push_str(&format!("Authorization: Bearer {token}\r\n"));
        }
        if let Some(key) = &self.idempotency_key {
            headers.push_str(&format!("idempotency-key: {key}\r\n"));
        }
        if let Some(origin) = &self.origin {
            headers.push_str(&format!("Origin: {origin}\r\n"));
        }
        if let Some(csrf) = &self.csrf {
            headers.push_str(&format!("x-csrf-token: {csrf}\r\n"));
        }
        let request = if let Some(body) = &self.body {
            format!(
                "{headers}Content-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
                body.len()
            )
        } else {
            format!("{headers}\r\n")
        };
        let mut stream = TcpStream::connect(self.addr).expect("connect client api");
        stream
            .set_read_timeout(Some(HTTP_TIMEOUT))
            .expect("read timeout");
        stream.write_all(request.as_bytes()).expect("write request");
        let mut response = Vec::new();
        stream.read_to_end(&mut response).expect("read response");
        let (status, body) = parse_http_response(&response);
        let body = if body.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&body)
                .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&body).into_owned()))
        };
        HttpResponse { status, body }
    }
}

pub async fn post_msg(addr: SocketAddr, payload: &str) -> (u16, String) {
    let payload = payload.to_owned();
    tokio::task::spawn_blocking(move || {
        let body = serde_json::json!({ "payload": payload }).to_string();
        let request = format!(
            "POST /msg HTTP/1.1\r\nHost: {addr}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        let mut stream = TcpStream::connect(addr).expect("connect POST /msg");
        stream
            .set_read_timeout(Some(HTTP_TIMEOUT))
            .expect("read timeout");
        stream.write_all(request.as_bytes()).expect("write POST /msg");
        let mut response = Vec::new();
        stream.read_to_end(&mut response).expect("read POST /msg");
        let (status, body) = parse_http_response(&response);
        (status, String::from_utf8_lossy(&body).into_owned())
    })
    .await
    .expect("post_msg worker")
}

pub fn mint_session(endpoint: &ClientApiEndpoint) -> String {
    mint_session_inner(endpoint, None)
}

pub fn mint_browser_session(endpoint: &ClientApiEndpoint) -> (String, String) {
    let csrf = "fixture-csrf".to_owned();
    let token = mint_session_inner(endpoint, Some(csrf.clone()));
    (token, csrf)
}

fn mint_session_inner(endpoint: &ClientApiEndpoint, csrf: Option<String>) -> String {
    let token = "fixture-operator".to_owned();
    let api = endpoint.api.upgrade().expect("the Client API is alive");
    api.sessions().insert(
        token.clone(),
        ClientSession {
            session_id: "fixture-session".into(),
            principal: Principal::operator("operator"),
            platform: Platform::Mac,
            scopes: Scope::operator_default(),
            csrf_token: csrf,
            expires_at: u64::MAX,
        },
        0,
    );
    token
}

fn parse_http_response(response: &[u8]) -> (u16, Vec<u8>) {
    let split = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
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
