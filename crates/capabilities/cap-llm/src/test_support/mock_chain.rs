//! Scripted `MockHttpSecurityChain` for cap-llm's `#[cfg(test)]` modules.

#![cfg(test)]

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use advance_shared_types::security_validator::{
    HttpBodyStream, HttpCapability, HttpError, HttpRequest, HttpResponse, HttpResponseHead,
    HttpSecurityChain, HttpStreamingChain,
};
use async_trait::async_trait;

#[derive(Default)]
pub(crate) struct MockHttpSecurityChain {
    /// Scripted responses keyed by URL path suffix (`/v1/chat/completions`,
    /// `/v1/messages`, `/v1/embeddings`). Entry value is a Vec to support
    /// multi-attempt scripts (RateLimited then Ok). When the call
    /// exhausts the script, the chain returns the last entry repeatedly.
    pub responses: Mutex<HashMap<String, Vec<Result<HttpResponse, HttpError>>>>,
    pub step_tracer: Mutex<Option<Arc<dyn Fn(&'static str) + Send + Sync>>>,
    pub call_log: Mutex<Vec<HttpRequest>>,
    /// Cursor per path suffix, recording how many responses have been popped.
    pub cursors: Mutex<HashMap<String, usize>>,
    /// grok-repass Item 2e: raw per-pull `Result` scripts for
    /// `execute_streaming`, keyed by path suffix. When present for a URL they
    /// take precedence over the buffered-response-derived `SimpleStream`
    /// synthesis, so a test can script a mid-stream or terminal `HttpError`.
    pub stream_results: Mutex<HashMap<String, Vec<Result<Vec<u8>, HttpError>>>>,
}

impl MockHttpSecurityChain {
    /// Push a scripted response for the path suffix matching the URL.
    pub fn push_response(&self, path_suffix: &str, response: Result<HttpResponse, HttpError>) {
        self.responses
            .lock()
            .unwrap()
            .entry(path_suffix.to_string())
            .or_default()
            .push(response);
    }

    pub fn set_step_tracer(&self, tracer: Arc<dyn Fn(&'static str) + Send + Sync>) {
        *self.step_tracer.lock().unwrap() = Some(tracer);
    }

    /// grok-repass Item 2e: script `execute_streaming` for `path_suffix` with
    /// raw per-pull results (see `stream_results`).
    #[allow(dead_code)]
    pub fn set_stream_results(&self, path_suffix: &str, results: Vec<Result<Vec<u8>, HttpError>>) {
        self.stream_results
            .lock()
            .unwrap()
            .insert(path_suffix.to_string(), results);
    }

    fn lookup_response(&self, url: &str) -> Result<HttpResponse, HttpError> {
        let responses = self.responses.lock().unwrap();
        let mut cursors = self.cursors.lock().unwrap();
        for (path, list) in responses.iter() {
            if url.ends_with(path) || url.contains(path) {
                let idx = cursors.entry(path.clone()).or_insert(0);
                let response = if *idx < list.len() {
                    let r = list[*idx].clone();
                    *idx += 1;
                    r
                } else {
                    list.last().cloned().unwrap_or_else(|| {
                        Err(HttpError::Transport(
                            advance_shared_types::security_validator::TransportErrorKind::Other,
                        ))
                    })
                };
                return response;
            }
        }
        Err(HttpError::Transport(
            advance_shared_types::security_validator::TransportErrorKind::Other,
        ))
    }

    /// Pop the next scripted entry for `url`, mirroring how the buffered `execute`
    /// consumes the script.
    ///
    /// Selection is by LONGEST matching key, not by first hit while iterating the
    /// map. `HashMap` iteration order depends on a per-process-random SipHash seed,
    /// so when two scripted keys are both substrings of the same request URL, a
    /// first-hit scan consumes a different script from run to run — a flake that
    /// would surface as an unrelated assertion failure. Audit round 10 flagged the
    /// hazard; making the choice deterministic and most-specific-wins removes it.
    fn take_scripted_for(
        &self,
        url: &str,
    ) -> Option<Result<advance_shared_types::security_validator::HttpResponse, HttpError>> {
        let mut responses = self.responses.lock().unwrap();
        let best = responses
            .iter()
            .filter(|(key, list)| url.contains(key.as_str()) && !list.is_empty())
            .map(|(key, _)| key.clone())
            .max_by_key(|key| key.len())?;
        let list = responses.get_mut(&best)?;
        Some(if list.len() == 1 {
            list[0].clone()
        } else {
            list.remove(0)
        })
    }
}

#[async_trait]
impl HttpSecurityChain for MockHttpSecurityChain {
    async fn execute(
        &self,
        _agent_id: &str,
        req: HttpRequest,
        _cap: &HttpCapability,
    ) -> Result<HttpResponse, HttpError> {
        // Step tracer mimics the canonical 10-step trace shape using the
        // SAME lowercase snake_case strings emitted by the real
        // `DefaultHttpSecurityChain` (cap-http/security_chain.rs:29-38). The
        // mock and the real chain MUST agree on tracer output so unit-test
        // assertions stay valid against the real chain in
        // tests/integration_chain.rs T90 (round-AUDIT-2 W1 fix).
        if let Some(t) = self.step_tracer.lock().unwrap().as_ref() {
            t("allowlist");
            t("outbound_leak_scan");
            t("substitute_placeholders");
            t("inject_credentials");
            t("ssrf_check");
            t("rate_limit");
            t("execute");
            t("inbound_leak_scan");
            t("redact_error_message");
            t("return");
        }
        self.call_log.lock().unwrap().push(req.clone());
        self.lookup_response(&req.url)
    }
}

pub(crate) struct SimpleStream {
    chunks: std::vec::IntoIter<Result<Vec<u8>, HttpError>>,
    /// Absorbing terminal: after the first scripted `Err` (or exhaustion),
    /// every subsequent pull returns `None` — mirrors the wire seam's
    /// post-error contract so a consumer that keeps pulling past an error
    /// cannot observe resurrected chunks.
    done: bool,
}

impl SimpleStream {
    /// grok-repass Item 2d: byte-exact deltas — `split_inclusive(' ')`
    /// segments carry their trailing space so `concat(deltas) == text`
    /// byte-for-byte (the old `split_whitespace` + space-re-prefix synthesis
    /// collapsed whitespace runs). Deliberate pinned consequence:
    /// newline-separated spaceless text yields ONE delta, not two.
    fn from_content(text: &str) -> Self {
        let mut frames: Vec<Result<Vec<u8>, HttpError>> = Vec::new();
        for part in text.split_inclusive(' ') {
            let frame = serde_json::json!({
                "choices": [ { "delta": { "content": part } } ]
            });
            frames.push(Ok(format!("data: {}\n\n", frame).into_bytes()));
        }
        // Terminal with usage + finish
        frames.push(Ok(b"data: {\"choices\":[{\"delta\":{},\"finish_reason\":\"stop\"}],\"usage\":{\"prompt_tokens\":3,\"completion_tokens\":4}}\n\n".to_vec()));
        frames.push(Ok(b"data: [DONE]\n\n".to_vec()));
        Self {
            chunks: frames.into_iter(),
            done: false,
        }
    }

    /// grok-repass Item 2e (chain seam): an error-capable script. NOTE the
    /// error type is `HttpError` — this mock sits on the `HttpBodyStream`
    /// chain seam; `ExecutorError` stays inside cap-http's executor seam.
    pub(crate) fn from_results(results: Vec<Result<Vec<u8>, HttpError>>) -> Self {
        Self {
            chunks: results.into_iter(),
            done: false,
        }
    }
}

#[async_trait]
impl HttpBodyStream for SimpleStream {
    async fn next_chunk(&mut self) -> Option<Result<Vec<u8>, HttpError>> {
        if self.done {
            return None;
        }
        match self.chunks.next() {
            Some(Ok(chunk)) => Some(Ok(chunk)),
            Some(Err(e)) => {
                self.done = true;
                Some(Err(e))
            }
            None => {
                self.done = true;
                None
            }
        }
    }
}

/// grok-repass Item 2d (L2-T5, cap-llm site): byte-exactness pins for
/// `SimpleStream::from_content` — same obligation and same red half as the
/// loopback's `build_openai_sse` pins (multi-line / multi-space /
/// whitespace-only fail under the historical `split_whitespace`).
#[cfg(test)]
mod delta_pins {
    use super::*;

    async fn deltas_of(text: &str) -> Vec<String> {
        let mut s = SimpleStream::from_content(text);
        let mut out = Vec::new();
        while let Some(chunk) = s.next_chunk().await {
            let bytes = chunk.expect("from_content scripts no errors");
            let line = String::from_utf8(bytes).expect("utf8 frame");
            let Some(data) = line.strip_prefix("data: ") else {
                continue;
            };
            let data = data.trim_end();
            if data == "[DONE]" {
                continue;
            }
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(data) {
                if let Some(content) = v["choices"][0]["delta"]["content"].as_str() {
                    out.push(content.to_string());
                }
            }
        }
        out
    }

    async fn concat_of(text: &str) -> (String, usize) {
        let deltas = deltas_of(text).await;
        (deltas.concat(), deltas.len())
    }

    #[tokio::test]
    async fn t_l2t5_single_space_prose_concat_exact() {
        let (concat, n) = concat_of("alpha beta gamma delta").await;
        assert_eq!(concat, "alpha beta gamma delta");
        assert!(n >= 2);
    }

    #[tokio::test]
    async fn t_l2t5_consecutive_spaces_concat_exact() {
        let (concat, _) = concat_of("a  b").await;
        assert_eq!(concat, "a  b");
    }

    #[tokio::test]
    async fn t_l2t5_multiline_concat_exact() {
        let text = "line one\nline two";
        let (concat, _) = concat_of(text).await;
        assert_eq!(concat, text);
    }

    #[tokio::test]
    async fn t_l2t5_fenced_code_block_concat_exact() {
        let text = "```rust\nfn main() {\n    println!(\"hi\");\n}\n```";
        let (concat, _) = concat_of(text).await;
        assert_eq!(concat, text);
    }

    #[tokio::test]
    async fn t_l2t5_whitespace_only_input_yields_nonempty_deltas() {
        let (concat, n) = concat_of(" ").await;
        assert_eq!(concat, " ");
        assert!(n > 0);
    }

    /// The deliberate, pinned 2→1 delta-count change for newline-separated
    /// content — the real regression surface, since `from_content` is fed
    /// arbitrary scripted assistant content that can be newline-separated.
    #[tokio::test]
    async fn t_l2t5_newline_separated_no_space_is_one_delta() {
        let text = "a\nb";
        let (concat, n) = concat_of(text).await;
        assert_eq!(concat, text);
        assert_eq!(n, 1);
    }

    #[tokio::test]
    async fn t_l2t5_trailing_space_concat_exact() {
        let (concat, _) = concat_of("alpha beta ").await;
        assert_eq!(concat, "alpha beta ");
    }

    /// CONTROL: empty content (the `.unwrap_or_default()` feed when a script
    /// has no content field) yields zero deltas under both splitters.
    #[tokio::test]
    async fn t_l2t5_empty_input_yields_no_deltas() {
        let (concat, n) = concat_of("").await;
        assert_eq!(concat, "");
        assert_eq!(n, 0);
    }

    /// L2-T8 — `from_results` surfaces the scripted terminal `HttpError`
    /// from `next_chunk`, and the stream is ABSORBING afterwards (a consumer
    /// pulling past the error cannot observe resurrected chunks).
    #[tokio::test]
    async fn t_l2t8_from_results_surfaces_scripted_err_and_absorbs() {
        use advance_shared_types::security_validator::TransportErrorKind;
        let mut s = SimpleStream::from_results(vec![
            Ok(b"data: x\n\n".to_vec()),
            Err(HttpError::Transport(TransportErrorKind::Other)),
            Ok(b"data: never\n\n".to_vec()),
        ]);
        assert!(matches!(s.next_chunk().await, Some(Ok(chunk)) if chunk == b"data: x\n\n"));
        assert!(matches!(
            s.next_chunk().await,
            Some(Err(HttpError::Transport(_)))
        ));
        assert!(s.next_chunk().await.is_none(), "absorbing after first Err");
        assert!(s.next_chunk().await.is_none());
    }

    /// L2-T8 (chain seam) — `set_stream_results` feeds `execute_streaming`
    /// the raw script, so a scripted stream error is reachable through the
    /// `HttpStreamingChain` surface cap-llm actually consumes.
    #[tokio::test]
    async fn t_l2t8_chain_scripting_seam_serves_raw_results() {
        use advance_shared_types::security_validator::{Allowlist, HttpMethod, TransportErrorKind};
        let chain = MockHttpSecurityChain::default();
        chain.set_stream_results(
            "/v1/chat/completions",
            vec![
                Ok(b"data: a\n\n".to_vec()),
                Err(HttpError::Transport(TransportErrorKind::Other)),
            ],
        );
        let req = HttpRequest {
            method: HttpMethod::Post,
            url: "https://api.openai.com/v1/chat/completions".into(),
            headers: vec![],
            body: vec![],
        };
        let cap = HttpCapability {
            allowlist: Allowlist {
                patterns: vec!["api.openai.com".into()],
            },
            credentials: vec![],
            component_id: "l2t8".into(),
        };
        let (head, mut body) = chain
            .execute_streaming("agent-x", req, &cap)
            .await
            .expect("scripted head ok");
        assert_eq!(head.status, 200);
        assert!(matches!(body.next_chunk().await, Some(Ok(chunk)) if chunk == b"data: a\n\n"));
        assert!(matches!(
            body.next_chunk().await,
            Some(Err(HttpError::Transport(_)))
        ));
        assert!(body.next_chunk().await.is_none());
    }
}

#[async_trait]
impl HttpStreamingChain for MockHttpSecurityChain {
    async fn execute_streaming(
        &self,
        _agent_id: &str,
        req: HttpRequest,
        _cap: &HttpCapability,
    ) -> Result<(HttpResponseHead, Box<dyn HttpBodyStream>), HttpError> {
        self.call_log.lock().unwrap().push(req.clone());
        // grok-repass Item 2e: a raw stream-results script takes precedence —
        // it is the only way to script a mid-stream/terminal HttpError.
        let raw_script = {
            let mut scripts = self.stream_results.lock().unwrap();
            let key = scripts
                .keys()
                .filter(|k| req.url.contains(k.as_str()))
                .max_by_key(|k| k.len())
                .cloned();
            key.and_then(|k| scripts.remove(&k))
        };
        if let Some(results) = raw_script {
            let head = HttpResponseHead {
                status: 200,
                headers: vec![("content-type".into(), "text/event-stream".into())],
            };
            let body: Box<dyn HttpBodyStream> = Box::new(SimpleStream::from_results(results));
            return Ok((head, body));
        }
        // Honor the SCRIPT for this URL: status and content come from the pushed
        // response, never from a fallback constant (a fabricating mock cannot
        // witness anything — merge-gate finding, 2026-07-29). A script entry with a
        // non-200 status is served as such so head classification is exercisable.
        let scripted = self.take_scripted_for(&req.url);
        let (status, content) = match scripted {
            Some(Ok(resp)) => {
                let content = serde_json::from_slice::<serde_json::Value>(&resp.body)
                    .ok()
                    .and_then(|v| {
                        v.get("choices")?
                            .as_array()?
                            .first()?
                            .get("message")?
                            .get("content")?
                            .as_str()
                            .map(str::to_string)
                    })
                    .unwrap_or_default();
                (resp.status, content)
            }
            Some(Err(e)) => return Err(e),
            None => {
                return Err(HttpError::Transport(
                    advance_shared_types::security_validator::TransportErrorKind::Other,
                ))
            }
        };
        let head = HttpResponseHead {
            status,
            headers: vec![("content-type".into(), "text/event-stream".into())],
        };
        let body: Box<dyn HttpBodyStream> = Box::new(SimpleStream::from_content(&content));
        Ok((head, body))
    }
}
