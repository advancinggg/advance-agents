//! The egress chain of the Sign in with ChatGPT client ([`crate::chatgpt_sign_in`]).
//!
//! Like every egress path of the daemon it is a [`DefaultHttpSecurityChain`]: a request must
//! match the capability it is sent under (the sign-in client allows exactly the issuer origin and
//! the API origin), passes the SSRF guard and the rate limiter, never carries its body across a
//! redirect, and its answer is size-capped by the executor. Unlike the other paths it does not
//! scan request and answer content for credential-shaped text. Everything this chain carries is
//! credential material by definition (authorization codes, token answers, refresh tokens), and
//! the scan's block patterns also match random base64url text: a scanned token answer would now
//! and then be refused after the identity provider had already rotated the refresh token it
//! replaces, ending the user's session. Nothing an agent controls travels on this chain and
//! nothing it returns reaches an agent; no other egress path may be built with it.

use std::sync::Arc;

use advance_shared_types::security_validator::{
    Action, Finding, LeakDetector, ScanContext, ScanResult, SsrfGuard,
};
use cap_http::leak_detector::MAX_SCAN_BYTES;
use cap_http::{DefaultHttpSecurityChain, HttpExecutor, RateLimiter};
use cap_secrets::SecretStore;

/// The chain the sign-in client sends every request through. `store` is the daemon's live
/// secret store (the model listing injects the access token from it); `ssrf`, `rate_limiter` and
/// `executor` are the same kinds the LLM egress chain is built with.
pub fn sign_in_egress_chain(
    store: Arc<SecretStore>,
    ssrf: Arc<dyn SsrfGuard>,
    rate_limiter: Arc<dyn RateLimiter>,
    executor: Arc<dyn HttpExecutor>,
) -> DefaultHttpSecurityChain {
    DefaultHttpSecurityChain::new(
        store,
        Arc::new(SignInTrafficDetector),
        ssrf,
        rate_limiter,
        executor,
    )
}

/// Reports content of ordinary size clean and refuses oversize input, as every detector must.
struct SignInTrafficDetector;

impl SignInTrafficDetector {
    fn verdict(len: usize) -> ScanResult {
        if len > MAX_SCAN_BYTES {
            ScanResult::Blocked {
                findings: vec![Finding {
                    pattern_name: "scan_overflow".to_string(),
                    offset: 0,
                    length: 0,
                    action: Action::Block,
                }],
            }
        } else {
            ScanResult::Clean
        }
    }
}

impl LeakDetector for SignInTrafficDetector {
    fn scan(&self, text: &str, _context: ScanContext) -> ScanResult {
        Self::verdict(text.len())
    }

    fn scan_headers(&self, headers: &[(String, String)]) -> ScanResult {
        Self::verdict(headers.iter().map(|(k, v)| k.len() + v.len()).sum())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use advance_shared_types::security_validator::{
        Allowlist, HttpCapability, HttpError, HttpMethod, HttpRequest, HttpResponse,
        HttpSecurityChain,
    };
    use cap_http::{DefaultLeakDetector, DefaultSsrfGuard, MockHttpExecutor, MockResolver};
    use cap_secrets::InMemorySecretStorage;
    use zeroize::Zeroizing;

    const TOKEN_URL: &str = "https://auth.example.test/oauth/token";
    /// Resolvable and answered like the allowed origin, so only the allowlist can refuse it.
    const OFF_LIST_URL: &str = "https://elsewhere.example.test/oauth/token";

    /// Random base64url that happens to contain the shapes of an AWS access key id and of a
    /// GitHub token, as a signature segment occasionally does.
    fn credential_shaped_answer() -> Vec<u8> {
        format!(
            "{{\"access_token\":\"eyJh.eyJz.xAkIa0b1c2d3e4f5g6h7Q9\",\"refresh_token\":\"rt_ghp_{}\",\
             \"token_type\":\"Bearer\",\"expires_in\":3600}}",
            "aB3".repeat(13)
        )
        .into_bytes()
    }

    fn chain_with(detector: Option<Arc<dyn LeakDetector>>) -> DefaultHttpSecurityChain {
        let store = Arc::new(SecretStore::new(
            Zeroizing::new([7u8; 32]),
            Arc::new(InMemorySecretStorage::default()),
        ));
        let public = vec!["93.184.216.34".parse().unwrap()];
        let resolver = MockResolver::new()
            .with("auth.example.test", public.clone())
            .with("elsewhere.example.test", public);
        let ssrf: Arc<dyn SsrfGuard> =
            Arc::new(DefaultSsrfGuard::with_resolver(Box::new(resolver)));
        let answer = HttpResponse {
            status: 200,
            headers: vec![("content-type".into(), "application/json".into())],
            body: credential_shaped_answer(),
        };
        let executor: Arc<dyn HttpExecutor> = Arc::new(
            MockHttpExecutor::new()
                .with_response(TOKEN_URL, answer.clone())
                .with_response(OFF_LIST_URL, answer),
        );
        let rate: Arc<dyn RateLimiter> = Arc::new(cap_http::DefaultRateLimiter::new());
        match detector {
            None => sign_in_egress_chain(store, ssrf, rate, executor),
            Some(d) => DefaultHttpSecurityChain::new(store, d, ssrf, rate, executor),
        }
    }

    fn token_request() -> (HttpRequest, HttpCapability) {
        let req = HttpRequest {
            method: HttpMethod::Post,
            url: TOKEN_URL.into(),
            headers: vec![(
                "Content-Type".into(),
                "application/x-www-form-urlencoded".into(),
            )],
            body: b"grant_type=refresh_token&refresh_token=rt_xAkIa0b1c2d3e4f5g6h7Q9".to_vec(),
        };
        let cap = HttpCapability {
            allowlist: Allowlist {
                patterns: vec!["https://auth.example.test/".into()],
            },
            credentials: Vec::new(),
            component_id: "advance-home/chatgpt-sign-in".into(),
        };
        (req, cap)
    }

    #[test]
    fn credential_shaped_text_is_clean_and_oversize_input_is_refused() {
        let detector = SignInTrafficDetector;
        let github_shaped = format!("ghp_{}", "aB3".repeat(13));
        for text in [
            "xAkIa0b1c2d3e4f5g6h7Q9",
            github_shaped.as_str(),
            "Authorization: Bearer eyJhbGciOiJSUzI1NiJ9",
        ] {
            assert_eq!(
                detector.scan(text, ScanContext::HttpInbound),
                ScanResult::Clean
            );
            // The default detector acts on the same text: that is what this chain avoids.
            assert_ne!(
                DefaultLeakDetector::new().scan(text, ScanContext::HttpInbound),
                ScanResult::Clean,
                "{text}"
            );
        }
        let oversize = "a".repeat(MAX_SCAN_BYTES + 1);
        match detector.scan(&oversize, ScanContext::HttpOutbound) {
            ScanResult::Blocked { findings } => {
                assert_eq!(findings[0].pattern_name, "scan_overflow")
            }
            other => panic!("oversize input must be refused, got {other:?}"),
        }
        let headers = vec![("x".to_string(), oversize)];
        assert!(matches!(
            detector.scan_headers(&headers),
            ScanResult::Blocked { .. }
        ));
    }

    #[tokio::test]
    async fn a_credential_shaped_token_answer_passes_this_chain_verbatim() {
        let (req, cap) = token_request();
        let answer = chain_with(None)
            .execute("advance-home/chatgpt-sign-in", req.clone(), &cap)
            .await
            .expect("the sign-in chain returns the token answer");
        assert_eq!(answer.status, 200);
        assert_eq!(answer.body, credential_shaped_answer());

        // The scanning chain refuses the same exchange.
        let scanned = chain_with(Some(Arc::new(DefaultLeakDetector::new())))
            .execute("advance-home/chatgpt-sign-in", req, &cap)
            .await;
        assert!(
            matches!(
                scanned,
                Err(HttpError::LeakBlocked(_)) | Err(HttpError::InboundLeakBlocked(_))
            ),
            "the scanning chain must refuse it: {scanned:?}"
        );
    }

    #[tokio::test]
    async fn the_capability_allowlist_still_applies() {
        let (mut req, cap) = token_request();
        req.url = OFF_LIST_URL.into();
        // The host resolves to a public address and the executor would answer it: only the
        // allowlist stands between the request and the network.
        let mut open = cap.clone();
        open.allowlist
            .patterns
            .push("https://elsewhere.example.test/".into());
        let reachable = chain_with(None)
            .execute("advance-home/chatgpt-sign-in", req.clone(), &open)
            .await;
        assert!(reachable.is_ok(), "{reachable:?}");

        let refused = chain_with(None)
            .execute("advance-home/chatgpt-sign-in", req, &cap)
            .await;
        assert!(
            matches!(refused, Err(HttpError::AllowlistBlocked(_))),
            "an off-allowlist request must be refused by the allowlist: {refused:?}"
        );
    }
}
