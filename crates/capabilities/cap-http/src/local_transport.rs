//! CONTRACT-238 local-inference transport (MODULE-012-AC-22).
//!
//! Connects ONLY to a supervision hand-off loopback address. No credential
//! injection, no redirects, no HttpSecurityChain / SsrfDnsResolver.

use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use advance_shared_types::inference::{
    is_credential_header, remaining_until, LocalBodyStream, LocalHttpRequest, LocalHttpResponse,
    LocalHttpResponseHead, LocalInferenceTransportPolicy, LocalTransportError, SidecarHandoff,
};
use async_trait::async_trait;
use reqwest::redirect::Policy;

use crate::executor::{DEFAULT_MAX_RESPONSE_BYTES, MAX_STREAM_DURATION};

#[derive(Clone, Debug, Default)]
pub struct DefaultLocalInferenceTransport;

fn validate(
    handoff: &SidecarHandoff,
    request: &LocalHttpRequest,
) -> Result<(), LocalTransportError> {
    if request.cancel.load(Ordering::SeqCst) {
        return Err(LocalTransportError::new("cancelled"));
    }
    if !handoff.is_loopback() {
        return Err(LocalTransportError::new("handoff target is not loopback"));
    }
    if remaining_until(request.deadline).is_zero() {
        return Err(LocalTransportError::new("deadline exceeded"));
    }
    Ok(())
}

fn url_for(handoff: &SidecarHandoff, path: &str) -> Result<String, LocalTransportError> {
    if path.contains('@') || path.contains('\\') || path.contains("://") {
        return Err(LocalTransportError::new("path must not rewrite the host"));
    }
    let path = if path.starts_with('/') {
        path.to_string()
    } else {
        format!("/{path}")
    };
    let raw = format!("http://{}{path}", handoff.loopback);
    let parsed =
        url::Url::parse(&raw).map_err(|e| LocalTransportError::new(format!("url: {e}")))?;
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(LocalTransportError::new("path must not rewrite the host"));
    }
    let expect = handoff.loopback.ip().to_string();
    if parsed.host_str() != Some(expect.as_str()) {
        return Err(LocalTransportError::new(
            "url host is not the hand-off target",
        ));
    }
    let port = parsed
        .port()
        .or_else(|| parsed.port_or_known_default())
        .unwrap_or(80);
    if port != handoff.loopback.port() {
        return Err(LocalTransportError::new(
            "url port is not the hand-off target",
        ));
    }
    Ok(raw)
}

fn timeout_for(deadline: Instant) -> Duration {
    // Cap at MAX_STREAM_DURATION (300s, same as S4) — never the 30s buffered
    // DEFAULT_TIMEOUT, which would be a second clock on live streams.
    remaining_until(deadline).min(MAX_STREAM_DURATION)
}

fn build_client(timeout: Duration) -> Result<reqwest::Client, LocalTransportError> {
    reqwest::Client::builder()
        .redirect(Policy::none())
        .timeout(timeout)
        .connect_timeout(timeout.min(Duration::from_secs(10)))
        .no_proxy()
        .build()
        .map_err(|e| LocalTransportError::new(format!("client build: {e}")))
}

fn apply_headers(
    mut builder: reqwest::RequestBuilder,
    headers: &[(String, String)],
) -> reqwest::RequestBuilder {
    for (k, v) in headers {
        if is_credential_header(k) {
            continue;
        }
        builder = builder.header(k, v);
    }
    builder
}

struct ReqwestBodyStream {
    resp: Option<reqwest::Response>,
    cancel: std::sync::Arc<std::sync::atomic::AtomicBool>,
    deadline: Instant,
    seen: usize,
}

#[async_trait]
impl LocalBodyStream for ReqwestBodyStream {
    async fn next_chunk(&mut self) -> Option<Result<Vec<u8>, LocalTransportError>> {
        if self.cancel.load(Ordering::SeqCst) {
            self.resp.take();
            return Some(Err(LocalTransportError::new("cancelled")));
        }
        if remaining_until(self.deadline).is_zero() {
            self.resp.take();
            return Some(Err(LocalTransportError::new("deadline exceeded")));
        }
        let resp = match self.resp.as_mut() {
            Some(r) => r,
            None => return Some(Err(LocalTransportError::new("cancelled"))),
        };
        match resp.chunk().await {
            Ok(Some(bytes)) => {
                self.seen = self.seen.saturating_add(bytes.len());
                if self.seen > DEFAULT_MAX_RESPONSE_BYTES {
                    self.resp.take();
                    return Some(Err(LocalTransportError::new("response over size cap")));
                }
                Some(Ok(bytes.to_vec()))
            }
            Ok(None) => None,
            Err(e) => Some(Err(LocalTransportError::new(format!("stream: {e}")))),
        }
    }

    fn cancel(&mut self) {
        self.cancel.store(true, Ordering::SeqCst);
        self.resp.take();
    }
}

#[async_trait]
impl LocalInferenceTransportPolicy for DefaultLocalInferenceTransport {
    async fn execute(
        &self,
        handoff: &SidecarHandoff,
        request: LocalHttpRequest,
    ) -> Result<LocalHttpResponse, LocalTransportError> {
        validate(handoff, &request)?;
        let timeout = timeout_for(request.deadline);
        let client = build_client(timeout)?;
        let url = url_for(handoff, &request.path)?;
        let builder = apply_headers(client.post(&url), &request.headers).body(request.body);
        let resp = builder
            .send()
            .await
            .map_err(|e| LocalTransportError::new(format!("send: {e}")))?;
        let status = resp.status().as_u16();
        if (300..400).contains(&status) {
            return Err(LocalTransportError::new("redirect forbidden"));
        }
        if let Some(len) = resp.content_length() {
            if len as usize > DEFAULT_MAX_RESPONSE_BYTES {
                return Err(LocalTransportError::new("response over size cap"));
            }
        }
        let headers = resp
            .headers()
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
            .collect();
        let mut body = Vec::new();
        let mut stream = resp;
        loop {
            match stream.chunk().await {
                Ok(Some(chunk)) => {
                    let next = body.len().saturating_add(chunk.len());
                    if next > DEFAULT_MAX_RESPONSE_BYTES {
                        return Err(LocalTransportError::new("response over size cap"));
                    }
                    body.extend_from_slice(&chunk);
                }
                Ok(None) => break,
                Err(e) => return Err(LocalTransportError::new(format!("body: {e}"))),
            }
        }
        Ok(LocalHttpResponse {
            status,
            headers,
            body,
        })
    }

    async fn execute_streaming(
        &self,
        handoff: &SidecarHandoff,
        request: LocalHttpRequest,
    ) -> Result<(LocalHttpResponseHead, Box<dyn LocalBodyStream>), LocalTransportError> {
        validate(handoff, &request)?;
        let timeout = timeout_for(request.deadline);
        let client = build_client(timeout)?;
        let url = url_for(handoff, &request.path)?;
        let cancel = request.cancel.clone();
        let deadline = request.deadline;
        let builder = apply_headers(client.post(&url), &request.headers).body(request.body);
        let resp = builder
            .send()
            .await
            .map_err(|e| LocalTransportError::new(format!("send: {e}")))?;
        let status = resp.status().as_u16();
        if (300..400).contains(&status) {
            return Err(LocalTransportError::new("redirect forbidden"));
        }
        let headers = resp
            .headers()
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
            .collect();
        let boxed: Box<dyn LocalBodyStream> = Box::new(ReqwestBodyStream {
            resp: Some(resp),
            cancel,
            deadline,
            seen: 0,
        });
        Ok((LocalHttpResponseHead { status, headers }, boxed))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::atomic::AtomicBool;
    use std::sync::Arc;

    fn handoff(ip: IpAddr, port: u16) -> SidecarHandoff {
        SidecarHandoff {
            pid: 1,
            loopback: SocketAddr::new(ip, port),
        }
    }

    fn req() -> LocalHttpRequest {
        LocalHttpRequest {
            path: "/v1/chat/completions".into(),
            headers: vec![("Authorization".into(), "Bearer secret".into())],
            body: b"{}".to_vec(),
            deadline: Instant::now() + Duration::from_secs(5),
            cancel: Arc::new(AtomicBool::new(false)),
        }
    }

    #[tokio::test]
    async fn t30_rfc1918_refused() {
        let policy = DefaultLocalInferenceTransport;
        let h = handoff(IpAddr::V4(Ipv4Addr::new(192, 168, 0, 10)), 80);
        let err = policy.execute(&h, req()).await.unwrap_err();
        assert!(err.0.contains("loopback"), "{err:?}");
    }

    #[tokio::test]
    async fn t30_no_handoff_loopback_required() {
        let policy = DefaultLocalInferenceTransport;
        let h = handoff(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 80);
        assert!(policy.execute(&h, req()).await.is_err());
    }

    #[test]
    fn t30_path_cannot_rewrite_host() {
        let h = handoff(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080);
        let err = url_for(&h, "@169.254.169.254/latest/meta-data/").unwrap_err();
        assert!(err.0.contains("host") || err.0.contains("path"), "{err:?}");
    }
}
