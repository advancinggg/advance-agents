//! Witnesses for the Sign in with ChatGPT client (`chatgpt_sign_in`): the browser flow over a
//! real loopback listener on an OS-assigned port, ID-token validation, renewal, sign-out and
//! custody. The identity provider and the API are a scripted executor behind the production
//! sign-in egress chain (`sign_in_egress_chain`: allowlist, placeholder rule, bearer injection,
//! SSRF guard over a mock resolver, no content scan), with a fault-injecting wrapper in front of
//! it; nothing leaves the process. ID tokens are signed with fixed test-only RSA keys.

use std::collections::{HashMap, HashSet, VecDeque};
use std::io::{Read as _, Write as _};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use advance_shared_types::security_validator::{
    HttpCapability, HttpError, HttpRequest, HttpResponse, HttpSecurityChain, RedirectCheck,
    TransportErrorKind,
};
use async_trait::async_trait;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use cap_http::{
    DefaultHttpSecurityChain, DefaultSsrfGuard, ExecutorError, HttpExecutor, MockResolver,
    RateLimiter,
};
use cap_llm::{CredentialFailure, ProviderCredentialSource};
use cap_secrets::{InMemorySecretStorage, SecretStorage, SecretStore, StorageError, StoredSecret};
use rsa::pkcs1v15::SigningKey;
use rsa::signature::{SignatureEncoding as _, Signer as _};
use rsa::traits::PublicKeyParts as _;
use rsa::{BigUint, RsaPrivateKey};
use secrecy::ExposeSecret;
use serde_json::{json, Value};
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

use crate::chatgpt_sign_in::*;
use crate::sign_in_egress::sign_in_egress_chain;

const ISSUER: &str = "https://auth.example.test";
const API: &str = "https://api.example.test";
const RESOURCE: &str = "https://api.example.test/v1";
const NAME: &str = "openai-plan";
const RECORD: &str = "openai-plan.chatgpt-oauth";
const APP: &str = "Advance Agents Test";
const ISSUED: &str = "oaiapp_issued_0001";
const SUB: &str = "user-sub-0001";
const EMAIL: &str = "person@example.test";
const FULL_SCOPE: &str =
    "openid profile email offline_access resource.invoke chatgpt.tokens.use.direct";
const NO_PLAN_SCOPE: &str = "openid profile email offline_access resource.invoke";
const T0_MS: u64 = 1_800_000_000_000;

fn token_endpoint() -> String {
    format!("{ISSUER}/api/accounts/oauth/token")
}

fn models_endpoint() -> String {
    format!("{API}/v1/models")
}

fn test_config() -> ChatGptSignInConfig {
    ChatGptSignInConfig {
        issuer: ISSUER.into(),
        authorize_endpoint: format!("{ISSUER}/api/accounts/authorize"),
        token_endpoint: token_endpoint(),
        discovery_endpoint: format!("{ISSUER}/.well-known/openid-configuration"),
        fallback_jwks_uri: format!("{ISSUER}/fallback/jwks"),
        fallback_revocation_endpoint: format!("{ISSUER}/fallback/revoke"),
        resource: RESOURCE.into(),
        models_endpoint: models_endpoint(),
        callback_port: 0,
        sign_in_window: Duration::from_secs(30),
        retry_backoff: Duration::from_millis(1),
        callback_read_timeout: Duration::from_secs(5),
        ..ChatGptSignInConfig::default()
    }
}

// ── test-only RSA keys (fixed primes; signing happens only here) ─────────────────────────────

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Which {
    A,
    B,
    Small,
}

struct Keys {
    a: RsaPrivateKey,
    b: RsaPrivateKey,
    small: RsaPrivateKey,
}

fn key(which: Which) -> &'static RsaPrivateKey {
    static KEYS: OnceLock<Keys> = OnceLock::new();
    let keys = KEYS.get_or_init(|| {
        let from = |p: &str, q: &str| {
            let prime = |h: &str| BigUint::from_bytes_be(&hex::decode(h).expect("hex prime"));
            RsaPrivateKey::from_p_q(prime(p), prime(q), BigUint::from(65_537u64)).expect("key")
        };
        Keys {
            a: from(
                "e6394cb9058bcebe5f91f09aa3b820b1fd87ec16f1af34527dc0fbddd66dd61fdd1cd79eb297916d00ecf99911dd3bec58b816e0ec56cb63b99213fd132eca738b91a13f3ed2e0c7da3f4313be50b7b1520de433bb6d1425972b980c0b03e046228bb4c8c5b96d0fb4c2a75c1abbbe302bf253d34dfd3b61872483b9133469b7",
                "dbc020158b915f12744b5a14d90f4ec00e7da0b5e6a47d939910fc2ba334a75d96aa83ec58585d5cb5eda30a76cbc944f2b63d05740758436a3416be0ce6494ee36206feb4c7c16fd6cadfea1dc4bd1673f146ddc1547312b6d9673ed890cedd2f3fe8b7e1af385b4bef6577feac439894d22488df9ff74d66c46bd2a1dab53f",
            ),
            b: from(
                "f53bc41fc49c9ac1451042321b0e3203f348f485897717edf3eb8f5b96abcb1694dc2f7031e1ac4049d2875d5d0eeb04905a70fde7e63b4dce4e395c3b1bb18c6ef58ea473887cda136d249c21276d0e8bf3c133c48a210f5ac547be727d6714d9c9d0fa581980e55b450ab6fba678960179f2f0637b79e71f8d7c2698561da3",
                "c11134334a4d46a43236f403cb431bddf239211c2e7aae97676afcd94c833667031a6ee829306b35b91b04359b9b969bd592f64c373e34ff3f2103820118e5248123a8525d485b7c2b8f5312e1e584d655f4ba0f904f03e4f5e689df3ec7cfbb891ea27a0bd67ebda662d632d151c33982f55ddbe81aa4a11de324569b258df9",
            ),
            small: from(
                "f4ce1417253a4741588dfdd04c1f0a72bb8d2424ebff54361cca1f0930ceda1edf7e200c3208a7acd439d53bedc0bc8b784ba01b7df312a95a749960b23d58b5",
                "ddeea1a784260c532cf8618ac923286b789aef9ba773d4866cb3bc75a025f744f29f7dc8db7a748498697193fb55683fb2217b443b57e4f3deb96a7ef910cd29",
            ),
        }
    });
    match which {
        Which::A => &keys.a,
        Which::B => &keys.b,
        Which::Small => &keys.small,
    }
}

fn jwk(kid: &str, which: Which) -> Value {
    let public = key(which).to_public_key();
    json!({
        "kty": "RSA", "use": "sig", "alg": "RS256", "kid": kid,
        "n": URL_SAFE_NO_PAD.encode(public.n().to_bytes_be()),
        "e": URL_SAFE_NO_PAD.encode(public.e().to_bytes_be()),
    })
}

fn sign_jwt(which: Which, header: &Value, claims: &Value) -> String {
    let input = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(header).unwrap()),
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims).unwrap())
    );
    let signature = SigningKey::<Sha256>::new(key(which).clone()).sign(input.as_bytes());
    format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature.to_bytes()))
}

// ── the scripted identity provider + API (behind the real chain) ─────────────────────────────

/// A clock that moves only when a test advances it: the wall clock starts at `T0_MS` and the
/// monotonic clock moves with it, so the transient cool-down never passes by itself.
struct TestClock {
    now_ms: AtomicU64,
    origin: Instant,
}

impl TestClock {
    fn new() -> Self {
        Self {
            now_ms: AtomicU64::new(T0_MS),
            origin: Instant::now(),
        }
    }

    fn advance(&self, by: Duration) {
        self.now_ms
            .fetch_add(by.as_millis() as u64, Ordering::SeqCst);
    }
}

impl SignInClock for TestClock {
    fn now_ms(&self) -> u64 {
        self.now_ms.load(Ordering::SeqCst)
    }

    fn monotonic_now(&self) -> Instant {
        self.origin + Duration::from_millis(self.now_ms().saturating_sub(T0_MS))
    }
}

struct Grant {
    code: String,
    client_id: String,
    nonce: String,
    challenge: String,
    redirect_uri: String,
}

enum Refresh {
    Rotate,
    Error(u16, &'static str),
    Status(u16),
    /// A scripted JSON body with the given status (the refresh token is not rotated).
    Json(u16, Value),
    /// A scripted raw body with the given status (the refresh token is not rotated).
    Raw(u16, &'static str),
    /// Rotate, with an access token carrying [`AWS_KEY_SHAPED`] and a refresh token carrying
    /// [`GITHUB_TOKEN_SHAPED`].
    CredentialShaped,
}

/// The shape of an AWS access key id, as random token text occasionally contains it. A content
/// leak scan blocks it in either direction.
const AWS_KEY_SHAPED: &str = "AKIAQWERTYUIOPASDFGH";
/// The shape of a GitHub token (`ghp_` and 36 alphanumerics); a content leak scan blocks it too.
const GITHUB_TOKEN_SHAPED: &str = "ghp_0123456789abcdefghijABCDEFGHIJklmnop";

type Tweak = Box<dyn Fn(&mut Value, &mut Value) + Send>;

struct IdpState {
    grant: Option<Grant>,
    client_id: String,
    serial: u32,
    access: Option<String>,
    refresh: Option<String>,
    /// Every token, code and ID token handed out (the custody witness looks for them).
    secrets: Vec<String>,
    granted_scope: &'static str,
    subject: &'static str,
    published: Vec<(&'static str, Which)>,
    /// What every JWKS fetch after the first serves (key rotation).
    rotated: Option<Vec<(&'static str, Which)>>,
    signer: (&'static str, Which),
    tweak: Option<Tweak>,
    corrupt_signature: bool,
    exchange_error: Option<(u16, &'static str)>,
    /// The code exchange answers only after this is notified.
    exchange_gate: Option<Arc<tokio::sync::Notify>>,
    /// The code exchange answers without a refresh token.
    exchange_without_refresh: bool,
    refresh_answers: VecDeque<Refresh>,
    refresh_scope: Option<&'static str>,
    refresh_delay: Duration,
    /// A renewal answers only after this is notified.
    refresh_gate: Option<Arc<tokio::sync::Notify>>,
    /// `earliest_refresh_at` carried by every rotating renewal answer.
    earliest_refresh_at: Option<Value>,
    revoke_statuses: VecDeque<u16>,
    revoke_delay: Duration,
    discovery_up: bool,
    /// Replaces the discovery document.
    discovery: Option<Value>,
    /// The model list answers only after this is notified.
    models_gate: Option<Arc<tokio::sync::Notify>>,
}

struct FakeIdp {
    clock: Arc<TestClock>,
    state: Mutex<IdpState>,
    /// Requests exactly as they reached the wire (after credential injection).
    wire: Mutex<Vec<HttpRequest>>,
    jwks_fetches: AtomicUsize,
}

impl FakeIdp {
    fn new(clock: Arc<TestClock>) -> Self {
        Self {
            clock,
            state: Mutex::new(IdpState {
                grant: None,
                client_id: ISSUED.into(),
                serial: 0,
                access: None,
                refresh: None,
                secrets: Vec::new(),
                granted_scope: FULL_SCOPE,
                subject: SUB,
                published: vec![("key-a", Which::A)],
                rotated: None,
                signer: ("key-a", Which::A),
                tweak: None,
                corrupt_signature: false,
                exchange_error: None,
                exchange_gate: None,
                exchange_without_refresh: false,
                refresh_answers: VecDeque::new(),
                refresh_scope: Some(FULL_SCOPE),
                refresh_delay: Duration::ZERO,
                refresh_gate: None,
                earliest_refresh_at: None,
                revoke_statuses: VecDeque::new(),
                revoke_delay: Duration::ZERO,
                discovery_up: true,
                discovery: None,
                models_gate: None,
            }),
            wire: Mutex::new(Vec::new()),
            jwks_fetches: AtomicUsize::new(0),
        }
    }

    fn with<R>(&self, f: impl FnOnce(&mut IdpState) -> R) -> R {
        f(&mut self.state.lock().unwrap())
    }

    fn register_grant(
        &self,
        client_id: &str,
        nonce: &str,
        challenge: &str,
        redirect: &str,
    ) -> String {
        self.with(|st| {
            st.serial += 1;
            let code = format!("AUTH-CODE-{:04}-zq", st.serial);
            st.secrets.push(code.clone());
            st.grant = Some(Grant {
                code: code.clone(),
                client_id: client_id.into(),
                nonce: nonce.into(),
                challenge: challenge.into(),
                redirect_uri: redirect.into(),
            });
            code
        })
    }

    fn set_session(&self, client_id: &str, access: &str, refresh: &str) {
        self.with(|st| {
            st.client_id = client_id.into();
            st.access = Some(access.into());
            st.refresh = Some(refresh.into());
            st.secrets.extend([access.to_string(), refresh.to_string()]);
        });
    }

    fn wire(&self) -> Vec<HttpRequest> {
        self.wire.lock().unwrap().clone()
    }

    fn to(&self, url: &str) -> Vec<HttpRequest> {
        self.wire().into_iter().filter(|r| r.url == url).collect()
    }

    fn token_forms(&self, grant_type: &str) -> Vec<HashMap<String, String>> {
        self.to(&token_endpoint())
            .iter()
            .map(|r| form_of(&r.body))
            .filter(|f| f.get("grant_type").map(String::as_str) == Some(grant_type))
            .collect()
    }

    fn secrets(&self) -> Vec<String> {
        self.with(|st| st.secrets.clone())
    }

    fn id_token(&self, st: &IdpState, client_id: &str, nonce: &str) -> String {
        let now_s = self.clock.now_ms() / 1000;
        let mut header = json!({"alg": "RS256", "typ": "JWT", "kid": st.signer.0});
        let mut claims = json!({
            "iss": ISSUER, "aud": client_id, "sub": st.subject, "email": EMAIL,
            "iat": now_s, "exp": now_s + 3600, "nonce": nonce,
        });
        if let Some(tweak) = &st.tweak {
            tweak(&mut header, &mut claims);
        }
        let token = sign_jwt(st.signer.1, &header, &claims);
        if !st.corrupt_signature {
            return token;
        }
        let (input, signature) = token.rsplit_once('.').unwrap();
        let mut bytes = URL_SAFE_NO_PAD.decode(signature).unwrap();
        bytes[10] ^= 0x01;
        format!("{input}.{}", URL_SAFE_NO_PAD.encode(bytes))
    }

    fn token(&self, req: &HttpRequest) -> HttpResponse {
        let form = form_of(&req.body);
        let mut guard = self.state.lock().unwrap();
        let st = &mut *guard;
        match form.get("grant_type").map(String::as_str) {
            Some("authorization_code") => {
                if let Some((status, code)) = st.exchange_error {
                    return oauth_error(status, code);
                }
                let Some(grant) = st.grant.take() else {
                    return oauth_error(400, "invalid_grant");
                };
                let pkce = form
                    .get("code_verifier")
                    .map(|v| URL_SAFE_NO_PAD.encode(Sha256::digest(v.as_bytes())));
                let ok = form.get("code") == Some(&grant.code)
                    && form.get("client_id") == Some(&grant.client_id)
                    && form.get("redirect_uri") == Some(&grant.redirect_uri)
                    && form.get("resource").map(String::as_str) == Some(RESOURCE)
                    && pkce.as_ref() == Some(&grant.challenge)
                    && !form.contains_key("client_secret");
                if !ok {
                    return oauth_error(400, "invalid_grant");
                }
                st.client_id = grant.client_id.clone();
                let (access, refresh) = mint(st);
                let id_token = self.id_token(st, &grant.client_id, &grant.nonce);
                st.secrets.push(id_token.clone());
                let mut body = json!({
                    "access_token": access, "refresh_token": refresh, "id_token": id_token,
                    "token_type": "Bearer", "expires_in": 3600, "scope": st.granted_scope,
                });
                if st.exchange_without_refresh {
                    body.as_object_mut().unwrap().remove("refresh_token");
                    st.refresh = None;
                }
                json_response(200, body)
            }
            Some("refresh_token") => {
                let ok = form.get("client_id") == Some(&st.client_id)
                    && form.get("resource").map(String::as_str) == Some(RESOURCE)
                    && !form.contains_key("scope");
                if !ok {
                    return oauth_error(400, "invalid_request");
                }
                if form.get("refresh_token") != st.refresh.as_ref() {
                    return oauth_error(400, "refresh_token_reused");
                }
                let rotation = |st: &mut IdpState, shaped: bool| {
                    let (mut access, mut refresh) = mint(st);
                    if shaped {
                        access = format!("{access}-{AWS_KEY_SHAPED}");
                        refresh = format!("{refresh}-{GITHUB_TOKEN_SHAPED}");
                        st.access = Some(access.clone());
                        st.refresh = Some(refresh.clone());
                        st.secrets.extend([access.clone(), refresh.clone()]);
                    }
                    let mut body = json!({
                        "access_token": access, "refresh_token": refresh,
                        "token_type": "Bearer", "expires_in": 3600,
                    });
                    if let Some(scope) = st.refresh_scope {
                        body["scope"] = json!(scope);
                    }
                    if let Some(at) = &st.earliest_refresh_at {
                        body["earliest_refresh_at"] = at.clone();
                    }
                    json_response(200, body)
                };
                match st.refresh_answers.pop_front().unwrap_or(Refresh::Rotate) {
                    Refresh::Rotate => rotation(st, false),
                    Refresh::CredentialShaped => rotation(st, true),
                    Refresh::Error(status, code) => oauth_error(status, code),
                    Refresh::Status(status) => HttpResponse {
                        status,
                        headers: Vec::new(),
                        body: br#"{"detail":"temporarily unavailable"}"#.to_vec(),
                    },
                    Refresh::Json(status, body) => json_response(status, body),
                    Refresh::Raw(status, body) => HttpResponse {
                        status,
                        headers: Vec::new(),
                        body: body.as_bytes().to_vec(),
                    },
                }
            }
            _ => oauth_error(400, "unsupported_grant_type"),
        }
    }

    fn jwks(&self) -> HttpResponse {
        let fetch = self.jwks_fetches.fetch_add(1, Ordering::SeqCst);
        self.with(|st| {
            let keys = match &st.rotated {
                Some(rotated) if fetch >= 1 => rotated.clone(),
                _ => st.published.clone(),
            };
            let keys: Vec<Value> = keys.iter().map(|(kid, which)| jwk(kid, *which)).collect();
            json_response(200, json!({ "keys": keys }))
        })
    }

    fn models(&self, req: &HttpRequest) -> HttpResponse {
        let presented = req
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("authorization"))
            .map(|(_, v)| v.clone());
        let expected = self.with(|st| st.access.as_ref().map(|a| format!("Bearer {a}")));
        if presented.is_none() || presented != expected {
            return json_response(401, json!({"error": {"code": "invalid_api_key"}}));
        }
        json_response(
            200,
            json!({"models": [
                {"slug": "gpt-6.1-sol", "display_name": "GPT 6.1 Sol", "visibility": "list"},
                {"slug": "internal-only", "display_name": "Hidden", "visibility": "hide"},
                {"slug": "gpt-6.1-mini", "visibility": "list"},
            ]}),
        )
    }
}

fn mint(st: &mut IdpState) -> (String, String) {
    st.serial += 1;
    let access = format!("ACCESS-{:04}-zq", st.serial);
    let refresh = format!("REFRESH-{:04}-zq", st.serial);
    st.access = Some(access.clone());
    st.refresh = Some(refresh.clone());
    st.secrets.extend([access.clone(), refresh.clone()]);
    (access, refresh)
}

#[async_trait]
impl HttpExecutor for FakeIdp {
    async fn execute(
        &self,
        req: &HttpRequest,
        _redirect_check: Arc<dyn RedirectCheck>,
    ) -> Result<HttpResponse, ExecutorError> {
        self.wire.lock().unwrap().push(req.clone());
        let url = req.url.as_str();
        let response = if url == format!("{ISSUER}/.well-known/openid-configuration") {
            let (up, replaced) = self.with(|st| (st.discovery_up, st.discovery.clone()));
            match (up, replaced) {
                (false, _) => json_response(503, json!({"detail": "down"})),
                (true, Some(document)) => json_response(200, document),
                (true, None) => json_response(200, discovery_document()),
            }
        } else if url == format!("{ISSUER}/discovered/jwks")
            || url == format!("{ISSUER}/fallback/jwks")
            || url == format!("{API}/jwks")
        {
            self.jwks()
        } else if url == token_endpoint() {
            let grant = form_of(&req.body).get("grant_type").cloned();
            let (delay, gate) = self.with(|st| match grant.as_deref() {
                Some("refresh_token") => (st.refresh_delay, st.refresh_gate.clone()),
                Some("authorization_code") => (Duration::ZERO, st.exchange_gate.clone()),
                _ => (Duration::ZERO, None),
            });
            if let Some(gate) = gate {
                gate.notified().await;
            }
            if !delay.is_zero() {
                tokio::time::sleep(delay).await;
            }
            self.token(req)
        } else if url == format!("{ISSUER}/discovered/revoke")
            || url == format!("{ISSUER}/fallback/revoke")
            || url == format!("{API}/revoke")
        {
            let delay = self.with(|st| st.revoke_delay);
            if !delay.is_zero() {
                tokio::time::sleep(delay).await;
            }
            self.with(|st| {
                let status = st.revoke_statuses.pop_front().unwrap_or(200);
                if status == 200 {
                    st.refresh = None;
                }
                HttpResponse {
                    status,
                    headers: Vec::new(),
                    body: Vec::new(),
                }
            })
        } else if url == models_endpoint() {
            let gate = self.with(|st| st.models_gate.clone());
            if let Some(gate) = gate {
                gate.notified().await;
            }
            self.models(req)
        } else {
            json_response(404, json!({}))
        };
        Ok(response)
    }
}

fn discovery_document() -> Value {
    json!({
        "issuer": ISSUER,
        "authorization_endpoint": format!("{ISSUER}/api/accounts/authorize"),
        "token_endpoint": token_endpoint(),
        "jwks_uri": format!("{ISSUER}/discovered/jwks"),
        "revocation_endpoint": format!("{ISSUER}/discovered/revoke"),
    })
}

fn json_response(status: u16, body: Value) -> HttpResponse {
    HttpResponse {
        status,
        headers: Vec::new(),
        body: serde_json::to_vec(&body).unwrap(),
    }
}

fn oauth_error(status: u16, code: &str) -> HttpResponse {
    json_response(
        status,
        json!({"error": code, "error_description": "scripted"}),
    )
}

fn form_of(body: &[u8]) -> HashMap<String, String> {
    url::form_urlencoded::parse(body)
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect()
}

/// The production sign-in chain, with scripted faults in front of it and a log of every
/// capability used.
struct FaultChain {
    inner: DefaultHttpSecurityChain,
    faults: Mutex<Vec<(String, HttpError)>>,
    seen: Mutex<Vec<(String, HttpCapability)>>,
}

impl FaultChain {
    fn fail_next(&self, url: &str, error: HttpError) {
        self.faults.lock().unwrap().push((url.to_string(), error));
    }

    fn attempts_to(&self, url: &str) -> usize {
        self.seen
            .lock()
            .unwrap()
            .iter()
            .filter(|(u, _)| u == url)
            .count()
    }
}

#[async_trait]
impl HttpSecurityChain for FaultChain {
    async fn execute(
        &self,
        agent_id: &str,
        req: HttpRequest,
        cap: &HttpCapability,
    ) -> Result<HttpResponse, HttpError> {
        self.seen
            .lock()
            .unwrap()
            .push((req.url.clone(), cap.clone()));
        let fault = {
            let mut faults = self.faults.lock().unwrap();
            faults
                .iter()
                .position(|(url, _)| *url == req.url)
                .map(|i| faults.remove(i).1)
        };
        if let Some(error) = fault {
            return Err(error);
        }
        self.inner.execute(agent_id, req, cap).await
    }
}

struct NoLimit;

impl RateLimiter for NoLimit {
    fn check(&self, _agent_id: &str, _host: &str) -> Result<(), u64> {
        Ok(())
    }
}

/// In-memory storage whose writes to names with a given suffix, and whose removals (all of them,
/// or those of one name), can be made to fail. Removal attempts are counted per name.
#[derive(Default)]
struct FlakyStorage {
    inner: InMemorySecretStorage,
    fail_puts_ending: Mutex<Option<String>>,
    fail_removes: Mutex<bool>,
    fail_removes_of: Mutex<Option<String>>,
    removal_attempts: Mutex<HashMap<String, usize>>,
}

impl FlakyStorage {
    fn fail_record_writes(&self, fail: bool) {
        *self.fail_puts_ending.lock().unwrap() = fail.then(|| ".chatgpt-oauth".to_string());
    }

    fn fail_removes(&self, fail: bool) {
        *self.fail_removes.lock().unwrap() = fail;
    }

    /// Fail every removal of `name` (`None`: none).
    fn fail_removes_of(&self, name: Option<&str>) {
        *self.fail_removes_of.lock().unwrap() = name.map(String::from);
    }

    fn removal_attempts(&self, name: &str) -> usize {
        self.removal_attempts
            .lock()
            .unwrap()
            .get(name)
            .copied()
            .unwrap_or(0)
    }
}

impl SecretStorage for FlakyStorage {
    fn put(&self, name: &str, stored: StoredSecret) -> Result<(), StorageError> {
        if let Some(suffix) = self.fail_puts_ending.lock().unwrap().as_deref() {
            if name.ends_with(suffix) {
                return Err(StorageError::Backend("scripted failure".into()));
            }
        }
        self.inner.put(name, stored)
    }
    fn get(&self, name: &str) -> Result<Option<StoredSecret>, StorageError> {
        self.inner.get(name)
    }
    fn exists(&self, name: &str) -> Result<bool, StorageError> {
        self.inner.exists(name)
    }
    fn remove(&self, name: &str) -> Result<bool, StorageError> {
        *self
            .removal_attempts
            .lock()
            .unwrap()
            .entry(name.to_string())
            .or_default() += 1;
        if *self.fail_removes.lock().unwrap()
            || self.fail_removes_of.lock().unwrap().as_deref() == Some(name)
        {
            return Err(StorageError::Backend("scripted failure".into()));
        }
        self.inner.remove(name)
    }
    fn names(&self) -> Vec<String> {
        self.inner.names()
    }
}

struct Harness {
    home: tempfile::TempDir,
    storage: Arc<FlakyStorage>,
    store: Arc<SecretStore>,
    idp: Arc<FakeIdp>,
    chain: Arc<FaultChain>,
    clock: Arc<TestClock>,
    sign_in: Arc<ChatGptSignIn>,
}

fn harness() -> Harness {
    harness_with(|_| {})
}

fn harness_with(tune: impl FnOnce(&mut ChatGptSignInConfig)) -> Harness {
    let home = tempfile::tempdir().unwrap();
    let storage = Arc::new(FlakyStorage::default());
    let store = Arc::new(SecretStore::new(
        Zeroizing::new([0x42; 32]),
        Arc::clone(&storage) as Arc<dyn SecretStorage>,
    ));
    let clock = Arc::new(TestClock::new());
    let idp = Arc::new(FakeIdp::new(Arc::clone(&clock)));
    let public = vec!["93.184.216.34".parse().unwrap()];
    let resolver = MockResolver::new()
        .with("auth.example.test", public.clone())
        .with("api.example.test", public);
    let production = sign_in_egress_chain(
        Arc::clone(&store),
        Arc::new(DefaultSsrfGuard::with_resolver(Box::new(resolver))),
        Arc::new(NoLimit),
        Arc::clone(&idp) as Arc<dyn HttpExecutor>,
    );
    let chain = Arc::new(FaultChain {
        inner: production,
        faults: Mutex::new(Vec::new()),
        seen: Mutex::new(Vec::new()),
    });
    let mut config = test_config();
    tune(&mut config);
    let sign_in = Arc::new(
        ChatGptSignIn::new(
            home.path(),
            Arc::clone(&store),
            Arc::clone(&chain) as Arc<dyn HttpSecurityChain>,
            APP,
            config,
        )
        .with_clock(Arc::clone(&clock) as Arc<dyn SignInClock>),
    );
    Harness {
        home,
        storage,
        store,
        idp,
        chain,
        clock,
        sign_in,
    }
}

impl Harness {
    fn record(&self) -> Option<Value> {
        self.store
            .resolve(RECORD)
            .ok()
            .map(|v| serde_json::from_str(v.expose_secret()).expect("record is JSON"))
    }

    fn record_text(&self) -> String {
        self.store
            .resolve(RECORD)
            .map(|v| v.expose_secret().clone())
            .unwrap_or_default()
    }

    fn stored_token(&self) -> Option<String> {
        self.store
            .resolve(NAME)
            .ok()
            .map(|v| v.expose_secret().clone())
    }

    fn host_id_file(&self) -> std::path::PathBuf {
        self.home.path().join(".advance").join(HOST_ID_FILE)
    }

    /// Write a stored sign-in record of THIS host directly, in the layout the module persists
    /// (saved at `T0_MS`), and make the identity provider hold the same tokens.
    fn seed_session(&self, expires_at_ms: u64, scope: &str) {
        let host = self.sign_in.host_id().expect("host id");
        self.seed_record(&host, expires_at_ms, scope);
    }

    fn seed_record(&self, host: &str, expires_at_ms: u64, scope: &str) {
        self.seed_record_with(host, expires_at_ms, scope, "REFRESH-SEED-zq");
    }

    fn seed_record_with(&self, host: &str, expires_at_ms: u64, scope: &str, refresh: &str) {
        let record = json!({
            "v": 1, "issuer": ISSUER, "client_id": ISSUED, "subject": SUB, "email": EMAIL,
            "ext_agent_host_id": host,
            "session": {
                "access_token": "ACCESS-SEED-zq", "refresh_token": refresh,
                "token_type": "Bearer",
                "scopes": scope.split(' ').collect::<Vec<_>>(),
                "expires_at_ms": expires_at_ms, "saved_at_ms": T0_MS,
            },
            "models": [],
        });
        self.store.store(RECORD, &record.to_string()).unwrap();
        self.store.store(NAME, "ACCESS-SEED-zq").unwrap();
        self.idp.set_session(ISSUED, "ACCESS-SEED-zq", refresh);
    }

    fn refreshes(&self) -> usize {
        self.idp.token_forms("refresh_token").len()
    }

    async fn ensure(&self) -> Result<(), CredentialFailure> {
        self.sign_in.ensure_fresh("chatgpt", NAME).await
    }
}

fn block<F: std::future::Future>(f: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(f)
}

// ── browser helpers ──────────────────────────────────────────────────────────────────────────

fn query_of(url: &str) -> HashMap<String, String> {
    url::Url::parse(url)
        .unwrap()
        .query_pairs()
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect()
}

fn port_of(started: &SignInStarted) -> u16 {
    url::Url::parse(&query_of(&started.authorize_url)["redirect_uri"])
        .unwrap()
        .port()
        .unwrap()
}

/// One raw HTTP request to the loopback listener, as a browser would send it; `None` when the
/// connection closes without an answer.
fn raw_answer(port: u16, request_line: &str) -> Option<(u16, String)> {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("listener accepts");
    stream
        .set_read_timeout(Some(Duration::from_secs(30)))
        .unwrap();
    write!(
        stream,
        "{request_line}\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    let mut raw = Vec::new();
    match stream.read_to_end(&mut raw) {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => return None,
        Err(e) => panic!("reading the answer: {e}"),
    }
    if raw.is_empty() {
        return None;
    }
    let raw = String::from_utf8(raw).expect("utf-8 answer");
    let status = raw
        .split(' ')
        .nth(1)
        .and_then(|s| s.parse().ok())
        .expect("status line");
    let body = raw
        .split_once("\r\n\r\n")
        .map(|(_, b)| b.to_string())
        .unwrap_or_default();
    Some((status, body))
}

fn raw_request(port: u16, request_line: &str) -> (u16, String) {
    raw_answer(port, request_line).expect("an answer")
}

fn callback_line(started: &SignInStarted, pairs: &[(&str, &str)]) -> String {
    let mut url = url::Url::parse(&query_of(&started.authorize_url)["redirect_uri"]).unwrap();
    url.query_pairs_mut().extend_pairs(pairs);
    let target = format!("{}?{}", url.path(), url.query().unwrap_or(""));
    format!("GET {target} HTTP/1.1")
}

fn visit_callback(started: &SignInStarted, pairs: &[(&str, &str)]) -> (u16, String) {
    raw_request(port_of(started), &callback_line(started, pairs))
}

fn try_visit(started: &SignInStarted, pairs: &[(&str, &str)]) -> Option<(u16, String)> {
    raw_answer(port_of(started), &callback_line(started, pairs))
}

/// Poll `done` (bounded) from a plain thread.
fn wait_until(what: &str, mut done: impl FnMut() -> bool) {
    let until = Instant::now() + Duration::from_secs(10);
    while !done() {
        assert!(Instant::now() < until, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// Poll `done` (bounded) from a task, yielding to the runtime between checks.
async fn wait_until_async(what: &str, mut done: impl FnMut() -> bool) {
    let until = Instant::now() + Duration::from_secs(10);
    while !done() {
        assert!(Instant::now() < until, "timed out waiting for {what}");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// The user approves: the identity provider records the grant for this attempt and the
/// browser comes back with `code`, `state` and, when given, a `client_id`.
fn approve(
    h: &Harness,
    started: &SignInStarted,
    callback_client_id: Option<&str>,
) -> (u16, String) {
    let q = query_of(&started.authorize_url);
    let client = callback_client_id.unwrap_or(&q["client_id"]).to_string();
    let code = h.idp.register_grant(
        &client,
        &q["nonce"],
        &q["code_challenge"],
        &q["redirect_uri"],
    );
    let mut pairs = vec![
        ("code", code.as_str()),
        ("scope", FULL_SCOPE),
        ("state", q["state"].as_str()),
    ];
    if let Some(id) = callback_client_id {
        pairs.push(("client_id", id));
    }
    visit_callback(started, &pairs)
}

fn sign_in_fully(h: &Harness) -> SignInStarted {
    let started = h.sign_in.start(NAME).expect("start");
    let (status, _) = approve(h, &started, Some(ISSUED));
    assert_eq!(status, 200);
    assert_eq!(h.sign_in.status(NAME).state, STATE_SIGNED_IN);
    started
}

fn closed_soon(port: u16) -> bool {
    let until = Instant::now() + Duration::from_secs(10);
    while Instant::now() < until {
        if TcpStream::connect(("127.0.0.1", port)).is_err() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    false
}

// ── the browser flow ─────────────────────────────────────────────────────────────────────────

#[test]
fn first_registration_end_to_end() {
    let h = harness();
    let started = h.sign_in.start(NAME).expect("start");
    let q = query_of(&started.authorize_url);

    assert!(started
        .authorize_url
        .starts_with(&format!("{ISSUER}/api/accounts/authorize?")));
    assert_eq!(q["response_type"], "code");
    assert_eq!(q["client_id"], "dynamic_agent_client");
    assert_eq!(q["agent_name_hint"], APP);
    assert_eq!(q["scope"], FULL_SCOPE);
    assert_eq!(q["resource"], RESOURCE);
    assert_eq!(q["code_challenge_method"], "S256");
    for absent in ["prompt", "id_token_hint", "login_hint"] {
        assert!(!q.contains_key(absent), "{absent} must not be sent");
    }
    assert!(q["state"].len() >= 43 && q["nonce"].len() >= 43);
    assert_ne!(q["state"], q["nonce"]);

    // The host id exists (0600) before the authorization and travels as `ext_agent_host_id`.
    let host = std::fs::read_to_string(h.host_id_file()).unwrap();
    assert_eq!(q["ext_agent_host_id"], host.trim_end());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(h.host_id_file())
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    let redirect = url::Url::parse(&q["redirect_uri"]).unwrap();
    assert_eq!(redirect.scheme(), "http");
    assert_eq!(redirect.host_str(), Some("127.0.0.1"));
    assert_eq!(redirect.path(), CALLBACK_PATH);
    let port = redirect.port().unwrap();
    // Bound before the URL was returned.
    drop(TcpStream::connect(("127.0.0.1", port)).expect("listener bound before the URL"));

    let pending = h.sign_in.status(NAME);
    assert_eq!(pending.state, STATE_PENDING);
    assert_eq!(pending.expires_at_ms, Some(T0_MS + 30_000));
    assert_eq!(started.expires_at_ms, T0_MS + 30_000);

    let (status, page) = approve(&h, &started, Some(ISSUED));
    assert_eq!(status, 200);

    let exchanges = h.idp.token_forms("authorization_code");
    assert_eq!(exchanges.len(), 1);
    let exchange = &exchanges[0];
    assert_eq!(
        exchange["client_id"], ISSUED,
        "the issued id, never the registration entrypoint"
    );
    assert_eq!(exchange["redirect_uri"], q["redirect_uri"]);
    assert_eq!(exchange["resource"], RESOURCE);
    assert!(!exchange.contains_key("client_secret"));
    // The verifier is 64 random bytes as unpadded base64url: 86 characters of that alphabet,
    // and the challenge is the base64url SHA-256 of it.
    let verifier = &exchange["code_verifier"];
    assert_eq!(verifier.len(), 86, "verifier length");
    assert!(
        verifier
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'),
        "the verifier uses the base64url alphabet without padding"
    );
    assert_eq!(
        URL_SAFE_NO_PAD.decode(verifier).ok().map(|raw| raw.len()),
        Some(64)
    );
    assert_eq!(
        URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes())),
        q["code_challenge"]
    );
    // The page reflects nothing from the request.
    assert!(!page.contains(&exchange["code"]) && !page.contains(&q["state"]));

    // The model list is fetched once the browser has its page.
    wait_until("the model list", || {
        h.sign_in.status(NAME).models.len() == 2
    });
    let status = h.sign_in.status(NAME);
    assert_eq!(status.state, STATE_SIGNED_IN);
    assert_eq!(status.reason, None);
    assert_eq!(status.account.as_deref(), Some(EMAIL));
    assert_eq!(status.plan_usage, Some(true));
    assert_eq!(status.expires_at_ms, Some(T0_MS + 3_600_000));
    assert_eq!(
        status.models,
        vec![
            SignInModel {
                id: "gpt-6.1-sol".into(),
                display_name: Some("GPT 6.1 Sol".into())
            },
            SignInModel {
                id: "gpt-6.1-mini".into(),
                display_name: None
            },
        ]
    );

    // Access token under the entry's name; the record beside it, without the ID token.
    let access = h.idp.with(|st| st.access.clone()).unwrap();
    let refresh = h.idp.with(|st| st.refresh.clone()).unwrap();
    assert_eq!(h.stored_token().as_deref(), Some(access.as_str()));
    let record = h.record().unwrap();
    assert_eq!(record["v"], 1);
    assert_eq!(record["issuer"], ISSUER);
    assert_eq!(record["client_id"], ISSUED);
    assert_eq!(record["subject"], SUB);
    assert_eq!(record["email"], EMAIL);
    assert_eq!(record["ext_agent_host_id"], host.trim_end());
    assert_eq!(record["session"]["access_token"], access);
    assert_eq!(record["session"]["refresh_token"], refresh);
    assert_eq!(record["session"]["token_type"], "Bearer");
    assert_eq!(record["session"]["expires_at_ms"], T0_MS + 3_600_000);
    assert_eq!(record["session"]["scopes"].as_array().unwrap().len(), 6);
    assert_eq!(record["models"][0]["id"], "gpt-6.1-sol");
    let id_token = h
        .idp
        .secrets()
        .into_iter()
        .find(|s| s.starts_with("eyJ"))
        .unwrap();
    let text = h.record_text();
    assert!(!text.contains("id_token") && !text.contains(&id_token));

    // The model list carried the access token as a bearer; keys came from discovery.
    let models = h.idp.to(&models_endpoint());
    assert!(models.iter().any(|r| r
        .headers
        .iter()
        .any(|(k, v)| k == "Authorization" && *v == format!("Bearer {access}"))));
    assert_eq!(h.idp.to(&format!("{ISSUER}/discovered/jwks")).len(), 1);

    // Every request: exactly the two origins, one fixed component, a credential binding only
    // on the model list.
    for (url, cap) in h.chain.seen.lock().unwrap().iter() {
        assert_eq!(
            cap.allowlist.patterns,
            vec![format!("{ISSUER}/"), format!("{API}/")]
        );
        assert_eq!(cap.component_id, "advance-home/chatgpt-sign-in");
        if *url == models_endpoint() {
            assert_eq!(cap.credentials.len(), 1);
            assert_eq!(cap.credentials[0].secret_name, NAME);
        } else {
            assert!(cap.credentials.is_empty(), "{url} must carry no credential");
        }
    }

    assert!(
        closed_soon(port),
        "the listener closes when the attempt ends"
    );
}

#[test]
fn the_listener_closes_and_the_page_is_answered_before_the_model_list() {
    let h = harness();
    let gate = Arc::new(tokio::sync::Notify::new());
    h.idp.with(|st| st.models_gate = Some(Arc::clone(&gate)));
    let started = h.sign_in.start(NAME).unwrap();
    // The page arrives while the model list is still held back.
    let (status, page) = approve(&h, &started, Some(ISSUED));
    assert_eq!(status, 200);
    assert!(page.contains("Signed in"), "{page}");
    assert_eq!(h.sign_in.status(NAME).state, STATE_SIGNED_IN);
    assert!(
        closed_soon(port_of(&started)),
        "the socket is closed while the model list is pending"
    );
    assert!(h.sign_in.status(NAME).models.is_empty());

    gate.notify_one();
    wait_until("the model list", || {
        h.sign_in.status(NAME).models.len() == 2
    });
}

#[test]
fn returning_flow_reuses_the_issued_client_without_a_name_hint() {
    let h = harness();
    let first = sign_in_fully(&h);
    let host = query_of(&first.authorize_url)["ext_agent_host_id"].clone();
    assert!(h.sign_in.sign_out(NAME).signed_out);

    let again = h.sign_in.start(NAME).expect("start");
    let q = query_of(&again.authorize_url);
    assert_eq!(q["client_id"], ISSUED);
    assert!(!q.contains_key("agent_name_hint"));
    assert!(
        !q.contains_key("prompt"),
        "no forced consent on an ordinary sign-in"
    );
    assert_eq!(q["ext_agent_host_id"], host);

    // The returning callback may omit the client id.
    let (status, _) = approve(&h, &again, None);
    assert_eq!(status, 200);
    let exchanges = h.idp.token_forms("authorization_code");
    assert_eq!(exchanges.len(), 2);
    assert_eq!(exchanges[1]["client_id"], ISSUED);
    assert_eq!(h.sign_in.status(NAME).state, STATE_SIGNED_IN);
    assert_eq!(h.record().unwrap()["client_id"], ISSUED);
}

#[test]
fn returning_flow_asks_consent_again_when_the_plan_scope_is_missing() {
    let h = harness();
    h.seed_session(T0_MS + 3_600_000, NO_PLAN_SCOPE);
    let status = h.sign_in.status(NAME);
    assert_eq!(status.state, STATE_SIGNED_IN);
    assert_eq!(status.plan_usage, Some(false));
    assert_eq!(status.reason, Some(REASON_PLAN_USAGE_NOT_GRANTED));

    let started = h.sign_in.start(NAME).expect("start");
    let q = query_of(&started.authorize_url);
    assert_eq!(q["client_id"], ISSUED);
    assert_eq!(q["prompt"], "consent");
    h.sign_in.cancel(NAME);
}

#[test]
fn plan_permission_comes_from_the_token_response_and_its_absence_keeps_the_sign_in() {
    let h = harness();
    h.idp.with(|st| st.granted_scope = NO_PLAN_SCOPE);
    let started = h.sign_in.start(NAME).unwrap();
    // The callback claims the plan scope; only the token response counts.
    let (status, _) = approve(&h, &started, Some(ISSUED));
    assert_eq!(status, 200);

    let status = h.sign_in.status(NAME);
    assert_eq!(status.state, STATE_SIGNED_IN);
    assert_eq!(status.plan_usage, Some(false));
    assert_eq!(status.reason, Some(REASON_PLAN_USAGE_NOT_GRANTED));
    assert_eq!(block(h.ensure()), Err(CredentialFailure::NotAuthorized));
    let verdict = h.sign_in.verify(NAME);
    assert!(!verdict.ok);
    assert_eq!(verdict.reason, Some(REASON_PLAN_USAGE_NOT_GRANTED));
}

#[test]
fn callback_failures_map_to_fixed_reasons_and_never_exchange_an_error() {
    struct Case {
        reason: &'static str,
        exchange_error: Option<(u16, &'static str)>,
        pairs: fn(&HashMap<String, String>, &str) -> Vec<(String, String)>,
        exchanges: usize,
        /// The callback named the issued client: the registration outlives the failure.
        keeps_registration: bool,
    }
    let cases = [
        Case {
            reason: REASON_ACCESS_DENIED,
            exchange_error: None,
            pairs: |q, code| {
                vec![
                    ("error".into(), "access_denied".into()),
                    ("code".into(), code.into()),
                    ("client_id".into(), ISSUED.into()),
                    ("state".into(), q["state"].clone()),
                ]
            },
            exchanges: 0,
            keeps_registration: false,
        },
        Case {
            reason: REASON_AUTHORIZATION_FAILED,
            exchange_error: None,
            pairs: |q, _| {
                vec![
                    ("error".into(), "server_error".into()),
                    ("state".into(), q["state"].clone()),
                ]
            },
            exchanges: 0,
            keeps_registration: false,
        },
        Case {
            reason: REASON_AUTHORIZATION_FAILED,
            exchange_error: None,
            pairs: |q, _| {
                vec![
                    ("client_id".into(), ISSUED.into()),
                    ("state".into(), q["state"].clone()),
                ]
            },
            exchanges: 0,
            keeps_registration: false,
        },
        Case {
            reason: REASON_REGISTRATION_INCOMPLETE,
            exchange_error: None,
            pairs: |q, code| {
                vec![
                    ("code".into(), code.into()),
                    ("state".into(), q["state"].clone()),
                ]
            },
            exchanges: 0,
            keeps_registration: false,
        },
        Case {
            reason: REASON_REGISTRATION_INCOMPLETE,
            exchange_error: None,
            pairs: |q, code| {
                vec![
                    ("code".into(), code.into()),
                    ("client_id".into(), "dynamic_agent_client".into()),
                    ("state".into(), q["state"].clone()),
                ]
            },
            exchanges: 0,
            keeps_registration: false,
        },
        Case {
            reason: REASON_EXCHANGE_FAILED,
            exchange_error: Some((400, "invalid_grant")),
            pairs: |q, code| {
                vec![
                    ("code".into(), code.into()),
                    ("client_id".into(), ISSUED.into()),
                    ("state".into(), q["state"].clone()),
                ]
            },
            exchanges: 1,
            keeps_registration: true,
        },
        // The token endpoint rejects the client just issued: that registration goes too.
        Case {
            reason: REASON_EXCHANGE_FAILED,
            exchange_error: Some((401, "invalid_client")),
            pairs: |q, code| {
                vec![
                    ("code".into(), code.into()),
                    ("client_id".into(), ISSUED.into()),
                    ("state".into(), q["state"].clone()),
                ]
            },
            exchanges: 1,
            keeps_registration: false,
        },
        Case {
            reason: REASON_STATE_MISMATCH,
            exchange_error: None,
            pairs: |q, code| {
                vec![
                    ("code".into(), code.into()),
                    ("client_id".into(), ISSUED.into()),
                    ("state".into(), q["state"].clone()),
                    ("state".into(), q["state"].clone()),
                ]
            },
            exchanges: 0,
            keeps_registration: false,
        },
    ];
    for case in cases {
        let h = harness();
        h.idp.with(|st| st.exchange_error = case.exchange_error);
        let started = h.sign_in.start(NAME).unwrap();
        let q = query_of(&started.authorize_url);
        let code = h.idp.register_grant(
            ISSUED,
            &q["nonce"],
            &q["code_challenge"],
            &q["redirect_uri"],
        );
        let pairs = (case.pairs)(&q, &code);
        let borrowed: Vec<(&str, &str)> = pairs
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        let (status, page) = visit_callback(&started, &borrowed);
        assert_eq!(status, 200, "{}", case.reason);
        assert!(!page.contains(&code) && !page.contains(&q["state"]));

        let status = h.sign_in.status(NAME);
        assert_eq!(status.state, STATE_FAILED, "{}", case.reason);
        assert_eq!(status.reason, Some(case.reason));
        assert_eq!(
            h.idp.token_forms("authorization_code").len(),
            case.exchanges,
            "{}",
            case.reason
        );
        assert!(h.stored_token().is_none(), "{}", case.reason);
        if case.keeps_registration {
            assert_registration_only(&h);
        } else {
            assert!(h.record().is_none(), "{}", case.reason);
        }
        assert!(closed_soon(port_of(&started)));
    }
}

/// The record holds the issued client id of this host and nothing else: no session, no
/// account.
fn assert_registration_only(h: &Harness) {
    let record = h.record().expect("the registration is kept");
    assert_eq!(record["client_id"], ISSUED);
    assert_eq!(
        record["ext_agent_host_id"],
        h.sign_in.host_id().unwrap().as_str()
    );
    assert!(record["session"].is_null());
    assert!(record.get("subject").is_none() && record.get("email").is_none());
    assert!(h.stored_token().is_none());
}

#[test]
fn a_first_registration_that_fails_after_its_callback_keeps_the_issued_client() {
    let h = harness();
    h.idp
        .with(|st| st.exchange_error = Some((400, "invalid_grant")));
    let started = h.sign_in.start(NAME).unwrap();
    let (status, _) = approve(&h, &started, Some(ISSUED));
    assert_eq!(status, 200);
    let status = h.sign_in.status(NAME);
    assert_eq!(status.state, STATE_FAILED);
    assert_eq!(status.reason, Some(REASON_EXCHANGE_FAILED));
    assert_registration_only(&h);

    // The retry is a returning sign-in with the issued client, not a second registration; it
    // also survives a restart.
    let restarted = ChatGptSignIn::new(
        h.home.path(),
        Arc::clone(&h.store),
        Arc::clone(&h.chain) as Arc<dyn HttpSecurityChain>,
        APP,
        test_config(),
    );
    for sign_in in [&*h.sign_in, &restarted] {
        let again = sign_in.start(NAME).unwrap();
        let q = query_of(&again.authorize_url);
        assert_eq!(q["client_id"], ISSUED);
        assert!(!q.contains_key("agent_name_hint"));
        assert!(!q.contains_key("prompt"));
        sign_in.cancel(NAME);
    }

    h.idp.with(|st| st.exchange_error = None);
    let again = h.sign_in.start(NAME).unwrap();
    let (status, _) = approve(&h, &again, None);
    assert_eq!(status, 200);
    assert_eq!(h.sign_in.status(NAME).state, STATE_SIGNED_IN);
    let record = h.record().unwrap();
    assert_eq!(record["client_id"], ISSUED);
    assert_eq!(record["subject"], SUB);
    assert_eq!(
        h.idp.token_forms("authorization_code")[1]["client_id"],
        ISSUED
    );
}

#[test]
fn a_returning_exchange_answered_invalid_client_drops_the_registration() {
    let h = harness();
    sign_in_fully(&h);
    h.sign_in.sign_out(NAME);
    h.idp
        .with(|st| st.exchange_error = Some((401, "invalid_client")));
    let started = h.sign_in.start(NAME).unwrap();
    let (status, _) = approve(&h, &started, None);
    assert_eq!(status, 200);
    let status = h.sign_in.status(NAME);
    assert_eq!(status.state, STATE_FAILED);
    assert_eq!(status.reason, Some(REASON_EXCHANGE_FAILED));
    assert!(h.record().is_none() && h.stored_token().is_none());

    let again = h.sign_in.start(NAME).unwrap();
    let q = query_of(&again.authorize_url);
    assert_eq!(q["client_id"], "dynamic_agent_client", "registers again");
    assert_eq!(q["agent_name_hint"], APP);
    h.sign_in.cancel(NAME);
}

#[test]
fn a_callback_error_fails_the_attempt_and_keeps_the_registration() {
    // `invalid_client` and `unauthorized_client` included: only the token endpoint can tell that
    // the client itself is refused.
    for error in ["server_error", "invalid_client", "unauthorized_client"] {
        let h = harness();
        sign_in_fully(&h);
        wait_until("the model list", || {
            h.sign_in.status(NAME).models.len() == 2
        });
        assert!(h.sign_in.sign_out(NAME).signed_out);
        let before = h.record_text();
        let started = h.sign_in.start(NAME).unwrap();
        let q = query_of(&started.authorize_url);
        let (status, page) = visit_callback(
            &started,
            &[("error", error), ("state", q["state"].as_str())],
        );
        assert_eq!(status, 200, "{error}");
        assert!(page.contains("did not complete"), "{error}");
        let status = h.sign_in.status(NAME);
        assert_eq!(status.state, STATE_FAILED, "{error}");
        assert_eq!(status.reason, Some(REASON_AUTHORIZATION_FAILED), "{error}");
        assert!(
            h.record_text() == before,
            "{error}: the registration is untouched"
        );
        assert_eq!(h.idp.token_forms("authorization_code").len(), 1, "{error}");

        let again = h.sign_in.start(NAME).unwrap();
        let q = query_of(&again.authorize_url);
        assert_eq!(q["client_id"], ISSUED, "{error}");
        assert!(!q.contains_key("agent_name_hint"), "{error}");
        h.sign_in.cancel(NAME);
    }
}

#[test]
fn a_callback_error_during_a_returning_sign_in_leaves_the_live_session_alone() {
    for error in ["unauthorized_client", "invalid_client"] {
        let h = harness();
        sign_in_fully(&h);
        wait_until("the model list", || {
            h.sign_in.status(NAME).models.len() == 2
        });
        let (record, token) = (h.record_text(), h.stored_token());
        assert!(token.is_some());
        let started = h.sign_in.start(NAME).unwrap();
        let q = query_of(&started.authorize_url);
        assert_eq!(q["client_id"], ISSUED, "a returning sign-in");
        let (status, page) = visit_callback(
            &started,
            &[("error", error), ("state", q["state"].as_str())],
        );

        // The attempt failed (with a session, the status reports the session; the attempt's
        // `authorization-failed` shows when no session exists, as above).
        assert_eq!(status, 200, "{error}");
        assert!(page.contains("did not complete"), "{error}");
        assert!(closed_soon(port_of(&started)), "{error}");
        let status = h.sign_in.status(NAME);
        assert_eq!(status.state, STATE_SIGNED_IN, "{error}");
        assert_eq!(status.reason, None, "{error}");
        assert_eq!(h.idp.token_forms("authorization_code").len(), 1, "{error}");

        // Nothing was dropped: the record and the access token are byte for byte as before,
        // and the session still serves.
        assert!(
            h.record_text() == record,
            "{error}: the record is untouched"
        );
        assert!(
            h.stored_token() == token,
            "{error}: the access token is untouched"
        );
        assert_eq!(block(h.ensure()), Ok(()), "{error}");
        assert!(
            h.record_text() == record,
            "{error}: the record is untouched"
        );
        assert!(h.idp.token_forms("refresh_token").is_empty(), "{error}");
    }
}

#[test]
fn returning_flow_rejects_a_different_client_id() {
    let h = harness();
    sign_in_fully(&h);
    h.sign_in.sign_out(NAME);
    let started = h.sign_in.start(NAME).unwrap();
    let q = query_of(&started.authorize_url);
    let (status, _) = visit_callback(
        &started,
        &[
            ("code", "AUTH-CODE-x"),
            ("client_id", "oaiapp_someone_else"),
            ("state", q["state"].as_str()),
        ],
    );
    assert_eq!(status, 200);
    let status = h.sign_in.status(NAME);
    assert_eq!(status.state, STATE_FAILED);
    assert_eq!(status.reason, Some(REASON_CLIENT_MISMATCH));
    assert_eq!(
        h.idp.token_forms("authorization_code").len(),
        1,
        "no second exchange"
    );
    assert_eq!(
        h.record().unwrap()["client_id"],
        ISSUED,
        "the registration is kept"
    );
}

#[test]
fn returning_flow_rejects_another_account_before_replacing_credentials() {
    let h = harness();
    sign_in_fully(&h);
    h.sign_in.sign_out(NAME);
    h.idp.with(|st| st.subject = "user-sub-other");
    let started = h.sign_in.start(NAME).unwrap();
    let (status, _) = approve(&h, &started, None);
    assert_eq!(status, 200);
    let status = h.sign_in.status(NAME);
    assert_eq!(status.state, STATE_FAILED);
    assert_eq!(status.reason, Some(REASON_ACCOUNT_MISMATCH));
    let record = h.record().unwrap();
    assert_eq!(record["subject"], SUB);
    assert!(record["session"].is_null(), "credentials were not replaced");
    assert!(h.stored_token().is_none());
}

// ── registration recovery ────────────────────────────────────────────────────────────────────
//
// The rule pinned here: an attempt started over a registration-only record (an issued client id
// kept from a first sign-in that never completed) counts when it ends with `timeout` or
// `authorization-failed`; the second count in a row drops that record. A code coming back, a
// completed sign-in, or a different stored record restarts the count. Declining (`access-denied`)
// and cancelling neither count nor restart it, so timeout, cancel, timeout drops the record.

/// The default test window (generous for every callback ending); a `timeout` ending ends the
/// window on demand instead of waiting it out.
fn recovery_harness() -> Harness {
    harness()
}

impl Harness {
    /// Write a registration-only record of THIS host: the issued `client_id` kept from a first
    /// sign-in that never completed (no account, no session).
    fn seed_registration_only(&self, client_id: &str) {
        let host = self.sign_in.host_id().expect("host id");
        let record = json!({
            "v": 1, "issuer": ISSUER, "client_id": client_id,
            "ext_agent_host_id": host, "session": null, "models": [],
        });
        self.store.store(RECORD, &record.to_string()).unwrap();
    }
}

/// How one sign-in attempt ends.
#[derive(Clone, Copy, Debug)]
enum Ending {
    /// The browser never comes back.
    Timeout,
    /// The browser comes back with this `error` (and the attempt's `state`).
    Error(&'static str),
    /// The browser comes back with the attempt's `state` and no code.
    NoCode,
    /// The browser comes back with a code whose exchange fails.
    Code,
    /// The attempt is cancelled.
    Cancel,
}

/// Start a sign-in, end it as `ending` and return the client id it asked for. Returns once the
/// attempt is over and its listener closed (so whatever its ending did to the record is done).
fn run_attempt(h: &Harness, ending: Ending) -> String {
    let started = h.sign_in.start(NAME).expect("start");
    let q = query_of(&started.authorize_url);
    let state = q["state"].as_str();
    let reason = match ending {
        Ending::Timeout => {
            h.sign_in.end_sign_in_window(NAME);
            REASON_TIMEOUT
        }
        Ending::Error(error) => {
            visit_callback(&started, &[("error", error), ("state", state)]);
            if error == "access_denied" {
                REASON_ACCESS_DENIED
            } else {
                REASON_AUTHORIZATION_FAILED
            }
        }
        Ending::NoCode => {
            visit_callback(&started, &[("state", state)]);
            REASON_AUTHORIZATION_FAILED
        }
        Ending::Code => {
            h.idp
                .with(|st| st.exchange_error = Some((400, "invalid_grant")));
            approve(h, &started, None);
            h.idp.with(|st| st.exchange_error = None);
            REASON_EXCHANGE_FAILED
        }
        Ending::Cancel => {
            h.sign_in.cancel(NAME);
            REASON_CANCELLED
        }
    };
    assert!(closed_soon(port_of(&started)), "{ending:?}");
    let status = h.sign_in.status(NAME);
    assert_eq!(status.state, STATE_FAILED, "{ending:?}");
    assert_eq!(status.reason, Some(reason), "{ending:?}");
    q["client_id"].clone()
}

/// The stored record is still `before`, and the next sign-in reuses its client.
fn assert_registration_kept(h: &Harness, before: &str, client_id: &str, case: &str) {
    assert!(
        h.record_text() == before,
        "{case}: the registration is kept"
    );
    let started = h.sign_in.start(NAME).unwrap();
    let q = query_of(&started.authorize_url);
    assert_eq!(q["client_id"], client_id, "{case}");
    assert!(!q.contains_key("agent_name_hint"), "{case}");
    h.sign_in.cancel(NAME);
}

/// No record and no access token are left, and the next sign-in registers again.
fn assert_registration_dropped(h: &Harness, case: &str) {
    assert!(h.record().is_none(), "{case}: the registration is dropped");
    assert!(h.stored_token().is_none(), "{case}");
    let started = h.sign_in.start(NAME).unwrap();
    let q = query_of(&started.authorize_url);
    assert_eq!(
        q["client_id"], "dynamic_agent_client",
        "{case}: registers again"
    );
    assert_eq!(q["agent_name_hint"], APP, "{case}");
    h.sign_in.cancel(NAME);
}

#[test]
fn a_registration_only_record_whose_last_two_attempts_ended_without_a_code_is_dropped() {
    let cases: [&[Ending]; 3] = [
        &[Ending::Timeout, Ending::Timeout],
        &[Ending::Error("unauthorized_client"), Ending::NoCode],
        &[Ending::Timeout, Ending::Error("invalid_client")],
    ];
    for endings in cases {
        let case = format!("{endings:?}");
        let h = recovery_harness();
        h.seed_registration_only(ISSUED);
        let before = h.record_text();
        let (last, earlier) = endings.split_last().unwrap();
        for ending in earlier {
            assert_eq!(run_attempt(&h, *ending), ISSUED, "{case}");
            assert!(
                h.record_text() == before,
                "{case}: one ending is not enough"
            );
        }
        assert_eq!(run_attempt(&h, *last), ISSUED, "{case}");
        assert_registration_dropped(&h, &case);
    }
}

#[test]
fn a_code_coming_back_restarts_the_count_of_endings_without_a_code() {
    // The registration-only record comes from a real first registration whose exchange failed.
    let h = recovery_harness();
    h.idp
        .with(|st| st.exchange_error = Some((400, "invalid_grant")));
    let started = h.sign_in.start(NAME).unwrap();
    assert_eq!(
        query_of(&started.authorize_url)["client_id"],
        "dynamic_agent_client"
    );
    approve(&h, &started, Some(ISSUED));
    h.idp.with(|st| st.exchange_error = None);
    assert_registration_only(&h);
    let before = h.record_text();

    for ending in [Ending::Timeout, Ending::Code, Ending::Timeout] {
        assert_eq!(run_attempt(&h, ending), ISSUED, "{ending:?}");
    }
    assert_registration_kept(&h, &before, ISSUED, "timeout, code, timeout");
    assert_eq!(h.idp.token_forms("authorization_code").len(), 2);

    // The timeout after the code and this one are two in a row.
    run_attempt(&h, Ending::Timeout);
    assert_registration_dropped(&h, "timeout, code, timeout, timeout");
}

#[test]
fn declining_or_cancelling_neither_counts_nor_restarts_the_count() {
    let h = recovery_harness();
    h.seed_registration_only(ISSUED);
    let before = h.record_text();
    for ending in [
        Ending::Error("access_denied"),
        Ending::Error("access_denied"),
    ] {
        run_attempt(&h, ending);
    }
    assert_registration_kept(&h, &before, ISSUED, "access-denied twice");

    for between in [Ending::Cancel, Ending::Error("access_denied")] {
        let case = format!("timeout, {between:?}, timeout");
        let h = recovery_harness();
        h.seed_registration_only(ISSUED);
        let before = h.record_text();
        run_attempt(&h, Ending::Timeout);
        run_attempt(&h, between);
        assert!(
            h.record_text() == before,
            "{case}: one counted ending so far"
        );
        run_attempt(&h, Ending::Timeout);
        assert_registration_dropped(&h, &case);
    }
}

#[test]
fn the_count_follows_one_stored_record_and_never_drops_another() {
    // Another registration-only record replaces the counted one: it starts its own count.
    let h = recovery_harness();
    h.seed_registration_only(ISSUED);
    assert_eq!(run_attempt(&h, Ending::Timeout), ISSUED);
    h.seed_registration_only("oaiapp_issued_0002");
    let replaced = h.record_text();
    assert_eq!(run_attempt(&h, Ending::Timeout), "oaiapp_issued_0002");
    assert_registration_kept(&h, &replaced, "oaiapp_issued_0002", "replaced record");

    // A sign-in of this host is stored while the second attempt is in flight: that attempt's
    // timeout leaves it alone.
    let h = recovery_harness();
    h.seed_registration_only(ISSUED);
    run_attempt(&h, Ending::Timeout);
    let started = h.sign_in.start(NAME).unwrap();
    assert_eq!(query_of(&started.authorize_url)["client_id"], ISSUED);
    h.seed_session(T0_MS + 3_600_000, FULL_SCOPE);
    let signed_in = h.record_text();
    h.sign_in.end_sign_in_window(NAME);
    assert!(closed_soon(port_of(&started)));
    assert!(h.record_text() == signed_in, "the stored sign-in is kept");
    assert!(h.stored_token().as_deref() == Some("ACCESS-SEED-zq"));
    assert_eq!(h.sign_in.status(NAME).state, STATE_SIGNED_IN);
    assert_eq!(block(h.ensure()), Ok(()));
}

#[test]
fn a_foreign_state_is_answered_and_ignored() {
    let h = harness();
    let started = h.sign_in.start(NAME).unwrap();
    let port = port_of(&started);
    let (status, page) = visit_callback(&started, &[("code", "AUTH-CODE-x"), ("state", "not-it")]);
    assert_eq!(status, 400);
    assert!(!page.contains("AUTH-CODE-x") && !page.contains("not-it"));
    // Other paths and methods do not touch the attempt either.
    assert_eq!(raw_request(port, "GET /favicon.ico HTTP/1.1").0, 404);
    assert_eq!(raw_request(port, "POST /auth/callback HTTP/1.1").0, 405);
    assert_eq!(h.sign_in.status(NAME).state, STATE_PENDING);
    assert!(h.idp.token_forms("authorization_code").is_empty());

    let (status, _) = approve(&h, &started, Some(ISSUED));
    assert_eq!(status, 200);
    assert_eq!(h.sign_in.status(NAME).state, STATE_SIGNED_IN);
}

#[test]
fn foreign_state_callbacks_never_end_the_attempt() {
    let h = harness_with(|c| c.max_stray_callbacks = 3);
    let started = h.sign_in.start(NAME).unwrap();
    for i in 0..10 {
        let answer = try_visit(&started, &[("code", "x"), ("state", "wrong")]);
        if i < 3 {
            assert_eq!(answer.map(|(status, _)| status), Some(400), "stray {i}");
        } else {
            assert!(
                answer.is_none(),
                "past the bound a stray is closed unanswered"
            );
        }
        assert_eq!(h.sign_in.status(NAME).state, STATE_PENDING, "stray {i}");
    }
    // No `state` at all is foreign too.
    assert!(try_visit(&started, &[("code", "x")]).is_none());
    assert_eq!(h.sign_in.status(NAME).state, STATE_PENDING);
    assert!(h.idp.token_forms("authorization_code").is_empty());

    let (status, _) = approve(&h, &started, Some(ISSUED));
    assert_eq!(status, 200);
    assert_eq!(h.sign_in.status(NAME).state, STATE_SIGNED_IN);
}

#[test]
fn foreign_requests_during_the_exchange_do_not_cancel_the_sign_in() {
    let h = Arc::new(harness_with(|c| c.max_stray_callbacks = 2));
    let gate = Arc::new(tokio::sync::Notify::new());
    h.idp.with(|st| st.exchange_gate = Some(Arc::clone(&gate)));
    let started = h.sign_in.start(NAME).unwrap();
    let approving = {
        let (h, started) = (Arc::clone(&h), started.clone());
        std::thread::spawn(move || approve(&h, &started, Some(ISSUED)))
    };
    wait_until("the code exchange", || {
        h.idp.token_forms("authorization_code").len() == 1
    });
    // The exchange is held, so the attempt and its listener are still open for every one of
    // these: the first two are answered, the rest closed unanswered.
    let answers: Vec<Option<u16>> = (0..6)
        .map(|_| try_visit(&started, &[("code", "x"), ("state", "wrong")]).map(|(s, _)| s))
        .collect();
    assert_eq!(answers, [Some(400), Some(400), None, None, None, None]);
    assert_eq!(h.sign_in.status(NAME).state, STATE_PENDING);
    assert_eq!(h.idp.token_forms("authorization_code").len(), 1);

    gate.notify_one();
    let (status, page) = approving.join().unwrap();
    assert_eq!(status, 200);
    assert!(page.contains("Signed in"), "{page}");
    assert_eq!(h.sign_in.status(NAME).state, STATE_SIGNED_IN);
    assert!(h.stored_token().is_some());
}

#[test]
fn a_repeated_right_state_callback_during_the_exchange_is_refused_and_one_exchange_runs() {
    let h = harness();
    let gate = Arc::new(tokio::sync::Notify::new());
    h.idp.with(|st| st.exchange_gate = Some(Arc::clone(&gate)));
    let started = h.sign_in.start(NAME).unwrap();
    let q = query_of(&started.authorize_url);
    let code = h.idp.register_grant(
        ISSUED,
        &q["nonce"],
        &q["code_challenge"],
        &q["redirect_uri"],
    );
    let line = callback_line(
        &started,
        &[
            ("code", code.as_str()),
            ("client_id", ISSUED),
            ("state", q["state"].as_str()),
        ],
    );
    let port = port_of(&started);
    let first = {
        let line = line.clone();
        std::thread::spawn(move || raw_request(port, &line))
    };
    wait_until("the code exchange", || {
        h.idp.token_forms("authorization_code").len() == 1
    });
    // The exchange is held, so the listener is still open and the attempt already claimed.
    assert_eq!(
        raw_request(port, &line).0,
        409,
        "the attempt is already claimed"
    );
    assert_eq!(h.sign_in.status(NAME).state, STATE_PENDING);

    gate.notify_one();
    assert_eq!(first.join().unwrap().0, 200);
    assert_eq!(h.sign_in.status(NAME).state, STATE_SIGNED_IN);
    assert_eq!(h.idp.token_forms("authorization_code").len(), 1);
}

#[test]
fn a_sign_in_that_cannot_be_stored_fails_with_store_failed() {
    let h = harness();
    h.storage.fail_record_writes(true);
    let started = h.sign_in.start(NAME).unwrap();
    let (status, _) = approve(&h, &started, Some(ISSUED));
    assert_eq!(status, 200);
    let status = h.sign_in.status(NAME);
    assert_eq!(status.state, STATE_FAILED);
    assert_eq!(status.reason, Some(REASON_STORE_FAILED));
    assert!(
        h.record().is_none() && h.stored_token().is_none(),
        "no access token without its record"
    );
    // The issued client is still remembered by this process.
    let again = h.sign_in.start(NAME).unwrap();
    assert_eq!(query_of(&again.authorize_url)["client_id"], ISSUED);
    h.sign_in.cancel(NAME);
}

#[test]
fn unreachable_signing_keys_fail_the_sign_in_as_unavailable() {
    let h = harness();
    h.chain.fail_next(
        &format!("{ISSUER}/discovered/jwks"),
        HttpError::Transport(TransportErrorKind::Other),
    );
    let started = h.sign_in.start(NAME).unwrap();
    let (status, _) = approve(&h, &started, Some(ISSUED));
    assert_eq!(status, 200);
    let status = h.sign_in.status(NAME);
    assert_eq!(status.state, STATE_FAILED);
    assert_eq!(status.reason, Some(REASON_UNAVAILABLE));
    assert_registration_only(&h);
}

#[test]
fn oversized_and_idle_callback_connections_are_dropped_without_ending_the_attempt() {
    let h = harness_with(|c| c.callback_read_timeout = Duration::from_millis(300));
    let started = h.sign_in.start(NAME).unwrap();
    let port = port_of(&started);

    let mut oversized = TcpStream::connect(("127.0.0.1", port)).unwrap();
    oversized
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let long = "a".repeat(16 * 1024);
    let _ = write!(
        oversized,
        "GET {CALLBACK_PATH}?state={long} HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"
    );
    let mut answer = Vec::new();
    let _ = oversized.read_to_end(&mut answer);
    assert!(answer.is_empty(), "an oversized request gets no answer");

    let mut idle = TcpStream::connect(("127.0.0.1", port)).unwrap();
    idle.set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let opened = Instant::now();
    let mut answer = Vec::new();
    let _ = idle.read_to_end(&mut answer);
    assert!(answer.is_empty());
    assert!(
        opened.elapsed() < Duration::from_secs(5),
        "an idle connection is closed at the read bound"
    );

    assert_eq!(h.sign_in.status(NAME).state, STATE_PENDING);
    let (status, _) = approve(&h, &started, Some(ISSUED));
    assert_eq!(status, 200);
}

#[test]
fn timeout_ends_the_attempt_and_closes_the_listener() {
    let h = harness_with(|c| c.sign_in_window = Duration::from_millis(300));
    let started = h.sign_in.start(NAME).unwrap();
    assert!(closed_soon(port_of(&started)));
    let status = h.sign_in.status(NAME);
    assert_eq!(status.state, STATE_FAILED);
    assert_eq!(status.reason, Some(REASON_TIMEOUT));
    assert!(h.idp.wire().is_empty());
}

#[test]
fn cancel_ends_the_attempt_and_releases_the_port() {
    let h = harness();
    let started = h.sign_in.start(NAME).unwrap();
    let status = h.sign_in.cancel(NAME);
    assert_eq!(status.state, STATE_FAILED);
    assert_eq!(status.reason, Some(REASON_CANCELLED));
    assert!(
        TcpStream::connect(("127.0.0.1", port_of(&started))).is_err(),
        "cancel returns after the listener is closed"
    );
}

#[test]
fn a_new_start_replaces_the_previous_attempt() {
    let h = harness();
    let old = h.sign_in.start(NAME).unwrap();
    let new = h.sign_in.start(NAME).unwrap();
    assert!(closed_soon(port_of(&old)));
    let old_state = query_of(&old.authorize_url)["state"].clone();
    let (status, _) = visit_callback(&new, &[("code", "x"), ("state", old_state.as_str())]);
    assert_eq!(status, 400, "the previous attempt's state is foreign now");
    let (status, _) = approve(&h, &new, Some(ISSUED));
    assert_eq!(status, 200);
    assert_eq!(h.sign_in.status(NAME).state, STATE_SIGNED_IN);
}

#[test]
fn a_taken_preferred_port_falls_back_to_an_os_assigned_port() {
    let taken = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let preferred = taken.local_addr().unwrap().port();
    let h = harness_with(|c| c.callback_port = preferred);
    let started = h.sign_in.start(NAME).unwrap();
    assert_ne!(port_of(&started), preferred);
    let (status, _) = approve(&h, &started, Some(ISSUED));
    assert_eq!(status, 200);
}

#[test]
fn reserved_and_empty_names_are_refused() {
    let h = harness();
    for name in [RECORD, ""] {
        assert_eq!(
            h.sign_in.start(name),
            Err(SignInRefusal(REASON_UNAVAILABLE))
        );
        assert_eq!(h.sign_in.status(name).state, STATE_SIGNED_OUT);
    }
}

#[test]
fn the_host_id_is_created_once_and_kept() {
    let h = harness();
    let id = h.sign_in.host_id().unwrap();
    let uuid = id.strip_prefix("urn:uuid:").expect("urn:uuid form");
    let parsed = uuid::Uuid::parse_str(uuid).unwrap();
    assert_eq!(parsed.get_version_num(), 4);
    assert_eq!(parsed.hyphenated().to_string(), uuid);
    assert_eq!(h.sign_in.host_id().unwrap(), id);
    sign_in_fully(&h);
    h.sign_in.sign_out(NAME);
    let fresh = ChatGptSignIn::new(
        h.home.path(),
        Arc::clone(&h.store),
        Arc::clone(&h.chain) as Arc<dyn HttpSecurityChain>,
        APP,
        test_config(),
    );
    assert_eq!(
        fresh.host_id().unwrap(),
        id,
        "kept across sign-out and restarts"
    );
}

/// The host id is read only from a regular file holding one `urn:uuid:<lower-case hyphenated
/// v4>` line. Anything else at the path is refused (`unavailable`) and left exactly as found:
/// never followed, adopted, overwritten or replaced.
#[test]
fn a_host_id_path_that_is_not_one_v4_line_in_a_regular_file_is_refused_and_left_alone() {
    let refused = |h: &Harness, case: &str| {
        assert_eq!(
            h.sign_in.host_id(),
            Err(SignInRefusal(REASON_UNAVAILABLE)),
            "{case}"
        );
        assert_eq!(
            h.sign_in.start(NAME),
            Err(SignInRefusal(REASON_UNAVAILABLE)),
            "{case}"
        );
        assert_eq!(
            block(h.ensure()),
            Err(CredentialFailure::Unavailable),
            "{case}"
        );
        let status = h.sign_in.status(NAME);
        assert_eq!(
            (status.state, status.reason),
            (STATE_SIGNED_OUT, Some(REASON_UNAVAILABLE)),
            "{case}"
        );
        assert!(h.idp.wire().is_empty(), "{case}");
    };

    // A symbolic link to a file holding a valid-looking line (another installation's id).
    #[cfg(unix)]
    {
        let h = harness();
        let elsewhere = h.home.path().join("another-installation-host-id");
        let foreign = format!("urn:uuid:{}\n", uuid::Uuid::new_v4().hyphenated());
        std::fs::write(&elsewhere, &foreign).unwrap();
        std::fs::create_dir_all(h.home.path().join(".advance")).unwrap();
        std::os::unix::fs::symlink(&elsewhere, h.host_id_file()).unwrap();
        refused(&h, "symlink");
        let meta = std::fs::symlink_metadata(h.host_id_file()).unwrap();
        assert!(meta.file_type().is_symlink(), "the link is left in place");
        assert_eq!(std::fs::read_to_string(&elsewhere).unwrap(), foreign);
    }

    // A directory.
    let h = harness();
    std::fs::create_dir_all(h.host_id_file()).unwrap();
    refused(&h, "directory");
    assert!(h.host_id_file().is_dir());

    // Malformed or non-v4 content.
    let v4 = uuid::Uuid::new_v4().hyphenated().to_string();
    let contents = [
        "not-a-host-id\n".to_string(),
        "urn:uuid:\n".to_string(),
        // A version-1 UUID.
        "urn:uuid:c232ab00-9414-11ec-b3c8-9f6bdeced846\n".to_string(),
        format!("urn:uuid:{}\n", v4.to_uppercase()),
        format!("{v4}\n"),
        format!("urn:uuid:{v4}\nurn:uuid:{v4}\n"),
    ];
    for content in contents {
        let h = harness();
        std::fs::create_dir_all(h.home.path().join(".advance")).unwrap();
        std::fs::write(h.host_id_file(), &content).unwrap();
        refused(&h, &content);
        assert_eq!(
            std::fs::read_to_string(h.host_id_file()).unwrap(),
            content,
            "left as found"
        );
    }
}

// ── ID-token validation ──────────────────────────────────────────────────────────────────────

/// Sign in with the identity provider configured by `setup`; the sign-in must fail with
/// `id-token-invalid` and store no session (only the issued client id).
fn assert_id_token_rejected(setup: impl FnOnce(&mut IdpState)) -> Harness {
    let h = harness();
    h.idp.with(setup);
    let started = h.sign_in.start(NAME).unwrap();
    let (status, _) = approve(&h, &started, Some(ISSUED));
    assert_eq!(status, 200);
    let status = h.sign_in.status(NAME);
    assert_eq!(status.state, STATE_FAILED);
    assert_eq!(status.reason, Some(REASON_ID_TOKEN_INVALID));
    assert_registration_only(&h);
    h
}

#[test]
fn id_token_with_a_bad_signature_is_rejected() {
    let h = assert_id_token_rejected(|st| st.corrupt_signature = true);
    assert_eq!(
        h.idp.jwks_fetches.load(Ordering::SeqCst),
        1,
        "a known key is not refetched"
    );
}

#[test]
fn id_token_with_another_algorithm_is_rejected() {
    assert_id_token_rejected(|st| {
        st.tweak = Some(Box::new(|header: &mut Value, _: &mut Value| {
            header["alg"] = json!("HS256")
        }));
    });
    assert_id_token_rejected(|st| {
        st.tweak = Some(Box::new(|header: &mut Value, _: &mut Value| {
            header["alg"] = json!("none")
        }));
    });
}

#[test]
fn id_token_from_another_issuer_is_rejected() {
    assert_id_token_rejected(|st| {
        st.tweak = Some(Box::new(|_: &mut Value, claims: &mut Value| {
            claims["iss"] = json!("https://auth.elsewhere.test")
        }));
    });
}

#[test]
fn id_token_for_another_audience_is_rejected() {
    assert_id_token_rejected(|st| {
        st.tweak = Some(Box::new(|_: &mut Value, claims: &mut Value| {
            claims["aud"] = json!("oaiapp_other")
        }));
    });
}

#[test]
fn id_token_with_another_nonce_is_rejected() {
    assert_id_token_rejected(|st| {
        st.tweak = Some(Box::new(|_: &mut Value, claims: &mut Value| {
            claims["nonce"] = json!("replayed")
        }));
    });
}

#[test]
fn expired_id_token_is_rejected() {
    assert_id_token_rejected(|st| {
        st.tweak = Some(Box::new(|_: &mut Value, claims: &mut Value| {
            let iat = claims["iat"].as_u64().unwrap();
            claims["exp"] = json!(iat - 60);
        }));
    });
}

#[test]
fn id_token_without_an_issue_time_is_rejected() {
    assert_id_token_rejected(|st| {
        st.tweak = Some(Box::new(|_: &mut Value, claims: &mut Value| {
            claims.as_object_mut().unwrap().remove("iat");
        }));
    });
}

#[test]
fn id_token_without_a_subject_is_rejected() {
    assert_id_token_rejected(|st| {
        st.tweak = Some(Box::new(|_: &mut Value, claims: &mut Value| {
            claims["sub"] = json!("")
        }));
    });
}

#[test]
fn id_token_signed_with_a_key_under_2048_bits_is_rejected() {
    assert_id_token_rejected(|st| {
        st.published = vec![("key-small", Which::Small)];
        st.signer = ("key-small", Which::Small);
    });
}

#[test]
fn id_token_with_an_unknown_key_id_is_rejected_after_one_refetch() {
    let h = assert_id_token_rejected(|st| st.signer = ("key-b", Which::B));
    assert_eq!(h.idp.jwks_fetches.load(Ordering::SeqCst), 2);
}

#[test]
fn a_rotated_signing_key_is_found_by_refetching_the_key_set_once() {
    let h = harness();
    h.idp.with(|st| {
        st.signer = ("key-b", Which::B);
        st.rotated = Some(vec![("key-a", Which::A), ("key-b", Which::B)]);
    });
    sign_in_fully(&h);
    assert_eq!(h.idp.jwks_fetches.load(Ordering::SeqCst), 2);
}

#[test]
fn without_discovery_the_documented_fallback_endpoints_are_used() {
    let h = harness();
    h.idp.with(|st| st.discovery_up = false);
    sign_in_fully(&h);
    assert_eq!(h.idp.to(&format!("{ISSUER}/fallback/jwks")).len(), 1);
    assert!(h.sign_in.sign_out(NAME).revocation_confirmed);
    assert_eq!(h.idp.to(&format!("{ISSUER}/fallback/revoke")).len(), 1);
}

#[test]
fn discovery_naming_another_issuer_or_leaving_the_issuer_origin_is_not_trusted() {
    // Another issuer, or a key set outside the issuer origin (the API origin is on the
    // allowlist too): the whole document is ignored.
    let documents = [
        {
            let mut document = discovery_document();
            document["issuer"] = json!("https://auth.elsewhere.test");
            document
        },
        {
            let mut document = discovery_document();
            document["jwks_uri"] = json!(format!("{API}/jwks"));
            document
        },
    ];
    for document in documents {
        let h = harness();
        h.idp.with(|st| st.discovery = Some(document.clone()));
        sign_in_fully(&h);
        assert_eq!(h.idp.to(&format!("{ISSUER}/fallback/jwks")).len(), 1);
        assert!(h.idp.to(&format!("{ISSUER}/discovered/jwks")).is_empty());
        assert!(h.idp.to(&format!("{API}/jwks")).is_empty());
        assert!(h.sign_in.sign_out(NAME).revocation_confirmed);
        assert_eq!(h.idp.to(&format!("{ISSUER}/fallback/revoke")).len(), 1);
    }

    // A revocation endpoint outside the issuer origin is replaced by the fallback alone.
    let h = harness();
    let mut document = discovery_document();
    document["revocation_endpoint"] = json!(format!("{API}/revoke"));
    h.idp.with(|st| st.discovery = Some(document));
    sign_in_fully(&h);
    assert_eq!(h.idp.to(&format!("{ISSUER}/discovered/jwks")).len(), 1);
    assert!(h.sign_in.sign_out(NAME).revocation_confirmed);
    assert_eq!(h.idp.to(&format!("{ISSUER}/fallback/revoke")).len(), 1);
    assert!(h.idp.to(&format!("{API}/revoke")).is_empty());
}

#[test]
fn the_callback_listener_is_bound_to_the_loopback_address_only() {
    let listener = bind_callback(0).unwrap();
    assert_eq!(
        listener.local_addr().unwrap().ip(),
        IpAddr::V4(Ipv4Addr::LOCALHOST)
    );
    drop(listener);

    // A started attempt is not reachable through this machine's other address.
    let h = harness();
    let started = h.sign_in.start(NAME).unwrap();
    if let Some(ip) = non_loopback_local_address() {
        let at = SocketAddr::new(ip, port_of(&started));
        assert!(
            TcpStream::connect_timeout(&at, Duration::from_secs(2)).is_err(),
            "reachable on {ip}"
        );
    }
    assert_eq!(h.sign_in.status(NAME).state, STATE_PENDING);
    h.sign_in.cancel(NAME);
}

/// The address this machine would use towards the network, when it has one (a UDP `connect`
/// sends nothing).
fn non_loopback_local_address() -> Option<IpAddr> {
    let socket = UdpSocket::bind(("0.0.0.0", 0)).ok()?;
    socket.connect(("192.0.2.1", 9)).ok()?;
    let ip = socket.local_addr().ok()?.ip();
    (!ip.is_loopback() && !ip.is_unspecified()).then_some(ip)
}

// ── renewal ──────────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn renewal_rotates_and_replaces_the_session_together() {
    let h = harness();
    // Two minutes left: inside the five-minute renewal margin.
    h.seed_session(T0_MS + 120_000, FULL_SCOPE);
    h.idp
        .with(|st| st.refresh_scope = Some("openid offline_access chatgpt.tokens.use.direct"));
    assert_eq!(h.ensure().await, Ok(()));

    let renewals = h.idp.token_forms("refresh_token");
    assert_eq!(renewals.len(), 1);
    let form = &renewals[0];
    assert_eq!(form["client_id"], ISSUED);
    assert_eq!(form["refresh_token"], "REFRESH-SEED-zq");
    assert_eq!(form["resource"], RESOURCE);
    assert!(
        !form.contains_key("scope"),
        "a renewal never narrows the grant"
    );

    let (access, refresh) = h
        .idp
        .with(|st| (st.access.clone().unwrap(), st.refresh.clone().unwrap()));
    assert_eq!(h.stored_token().as_deref(), Some(access.as_str()));
    let record = h.record().unwrap();
    assert_eq!(record["session"]["access_token"], access);
    assert_eq!(record["session"]["refresh_token"], refresh);
    assert_eq!(record["session"]["expires_at_ms"], T0_MS + 3_600_000);
    assert_eq!(
        record["session"]["scopes"],
        json!(["openid", "offline_access", "chatgpt.tokens.use.direct"])
    );

    // Fresh now: no further request.
    assert_eq!(h.ensure().await, Ok(()));
    assert_eq!(h.idp.token_forms("refresh_token").len(), 1);
}

#[tokio::test]
async fn a_renewal_without_scope_keeps_the_granted_scopes() {
    // The grant is narrower than the requested set, so keeping it is distinguishable from
    // falling back to the request.
    let granted = "openid offline_access chatgpt.tokens.use.direct";
    let h = harness();
    h.seed_session(T0_MS + 60_000, granted);
    h.idp.with(|st| st.refresh_scope = None);
    assert_eq!(h.ensure().await, Ok(()));
    assert_eq!(h.refreshes(), 1);
    assert_eq!(
        h.record().unwrap()["session"]["scopes"],
        json!(["openid", "offline_access", "chatgpt.tokens.use.direct"])
    );
}

#[tokio::test]
async fn a_renewal_that_drops_the_plan_scope_answers_not_authorized_at_once() {
    let h = harness();
    h.seed_session(T0_MS + 60_000, FULL_SCOPE);
    h.idp.with(|st| st.refresh_scope = Some(NO_PLAN_SCOPE));
    assert_eq!(h.ensure().await, Err(CredentialFailure::NotAuthorized));
    // The renewed session is still stored.
    let access = h.idp.with(|st| st.access.clone().unwrap());
    assert_eq!(h.stored_token().as_deref(), Some(access.as_str()));
    let record = h.record().unwrap();
    assert_eq!(record["session"]["access_token"], access);
    assert_eq!(record["session"]["scopes"].as_array().unwrap().len(), 5);
    let status = h.sign_in.status(NAME);
    assert_eq!(status.state, STATE_SIGNED_IN);
    assert_eq!(status.plan_usage, Some(false));
    assert_eq!(status.reason, Some(REASON_PLAN_USAGE_NOT_GRANTED));
    assert_eq!(h.ensure().await, Err(CredentialFailure::NotAuthorized));
    assert_eq!(h.refreshes(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_renewals_are_serialized_into_one_request() {
    let h = harness();
    h.seed_session(T0_MS + 60_000, FULL_SCOPE);
    h.idp
        .with(|st| st.refresh_delay = Duration::from_millis(150));
    let mut tasks = tokio::task::JoinSet::new();
    for _ in 0..8 {
        let sign_in = Arc::clone(&h.sign_in);
        tasks.spawn(async move { sign_in.ensure_fresh("chatgpt", NAME).await });
    }
    while let Some(result) = tasks.join_next().await {
        assert_eq!(result.unwrap(), Ok(()));
    }
    assert_eq!(h.idp.token_forms("refresh_token").len(), 1);
}

const TERMINAL_CODES: [&str; 6] = [
    "invalid_grant",
    "invalid_refresh_token",
    "token_expired",
    "refresh_token_expired",
    "refresh_token_invalidated",
    "refresh_token_reused",
];

/// The three error-body shapes a machine-readable code may arrive in.
fn error_bodies(code: &str) -> [Refresh; 3] {
    [
        Refresh::Json(400, json!({"error": code, "error_description": "scripted"})),
        Refresh::Json(400, json!({"error": {"code": code, "message": "scripted"}})),
        Refresh::Json(401, json!({"code": code, "detail": "scripted"})),
    ]
}

#[tokio::test]
async fn terminal_renewal_answers_end_the_session_and_keep_the_registration() {
    for code in TERMINAL_CODES {
        for (shape, answer) in error_bodies(code).into_iter().enumerate() {
            let h = harness();
            h.seed_session(T0_MS + 60_000, FULL_SCOPE);
            h.idp.with(|st| st.refresh_answers.push_back(answer));
            assert_eq!(
                h.ensure().await,
                Err(CredentialFailure::NotSignedIn),
                "{code} / shape {shape}"
            );
            assert!(h.stored_token().is_none(), "{code}: access token removed");
            let record = h.record().expect("registration kept");
            assert!(record["session"].is_null(), "{code} / shape {shape}");
            assert_eq!(record["client_id"], ISSUED);
            let status = h.sign_in.status(NAME);
            assert_eq!(status.state, STATE_SIGNED_OUT);
            assert_eq!(status.reason, Some(REASON_SESSION_ENDED), "{code}");
            assert_eq!(h.ensure().await, Err(CredentialFailure::NotSignedIn));
            assert_eq!(h.refreshes(), 1, "{code}: never retried");
        }
    }
}

#[test]
fn invalid_client_clears_the_registration_too() {
    for (shape, answer) in error_bodies("invalid_client").into_iter().enumerate() {
        let h = harness();
        h.seed_session(T0_MS + 60_000, FULL_SCOPE);
        h.idp.with(|st| st.refresh_answers.push_back(answer));
        assert_eq!(block(h.ensure()), Err(CredentialFailure::NotSignedIn));
        assert!(
            h.record().is_none() && h.stored_token().is_none(),
            "shape {shape}"
        );
        assert_eq!(h.sign_in.verify(NAME).reason, Some(REASON_SESSION_ENDED));
        let started = h.sign_in.start(NAME).unwrap();
        let q = query_of(&started.authorize_url);
        assert_eq!(q["client_id"], "dynamic_agent_client", "registers again");
        assert_eq!(q["agent_name_hint"], APP);
        h.sign_in.cancel(NAME);
    }
}

#[tokio::test]
async fn unknown_error_codes_rate_limits_and_unreadable_answers_keep_the_credentials() {
    let answers = [
        Refresh::Error(400, "invalid_request"),
        Refresh::Json(400, json!({"error": {"code": "something_new"}})),
        Refresh::Json(429, json!({"error": {"code": "rate_limit_exceeded"}})),
        Refresh::Status(429),
        Refresh::Raw(200, "not json"),
        Refresh::Raw(200, r#"{"token_type": "Bearer"}"#),
    ];
    for (i, answer) in answers.into_iter().enumerate() {
        let h = harness();
        h.seed_session(T0_MS + 60_000, FULL_SCOPE);
        let before = h.record_text();
        h.idp.with(|st| st.refresh_answers.push_back(answer));
        assert_eq!(
            h.ensure().await,
            Ok(()),
            "answer {i}: the token still works"
        );
        assert_eq!(h.refreshes(), 1, "answer {i}");
        assert_eq!(h.record_text(), before, "answer {i}: record unchanged");
        assert_eq!(h.stored_token().as_deref(), Some("ACCESS-SEED-zq"));
        assert_eq!(h.sign_in.status(NAME).state, STATE_SIGNED_IN);
    }
}

#[tokio::test]
async fn a_transient_renewal_failure_keeps_credentials_and_uses_a_valid_token() {
    // Without a cool-down, so every call below reaches the token endpoint.
    let h = harness_with(|c| c.transient_cooldown = Duration::ZERO);
    h.seed_session(T0_MS + 60_000, FULL_SCOPE);
    h.idp.with(|st| {
        st.refresh_answers.push_back(Refresh::Status(503));
        st.refresh_answers.push_back(Refresh::Status(503));
    });
    assert_eq!(
        h.ensure().await,
        Ok(()),
        "the current token has not expired"
    );
    assert_eq!(h.stored_token().as_deref(), Some("ACCESS-SEED-zq"));
    assert_eq!(
        h.record().unwrap()["session"]["refresh_token"],
        "REFRESH-SEED-zq"
    );

    h.clock.advance(Duration::from_secs(120));
    assert_eq!(h.ensure().await, Err(CredentialFailure::RefreshUnavailable));
    assert_eq!(
        h.stored_token().as_deref(),
        Some("ACCESS-SEED-zq"),
        "never erased"
    );
    let status = h.sign_in.status(NAME);
    assert_eq!(status.state, STATE_SIGNED_IN);
    assert_eq!(status.reason, Some(REASON_REFRESH_UNAVAILABLE));

    // The next renewal that gets through restores the session.
    assert_eq!(h.ensure().await, Ok(()));
    assert_eq!(h.sign_in.status(NAME).reason, None);
}

#[tokio::test]
async fn only_failures_that_never_left_are_retried() {
    let h = harness();
    h.seed_session(T0_MS + 60_000, FULL_SCOPE);
    h.chain.fail_next(
        &token_endpoint(),
        HttpError::Transport(TransportErrorKind::Dns),
    );
    h.chain.fail_next(
        &token_endpoint(),
        HttpError::Transport(TransportErrorKind::Dns),
    );
    assert_eq!(h.ensure().await, Ok(()));
    assert_eq!(h.chain.attempts_to(&token_endpoint()), 3);
    assert_eq!(h.idp.token_forms("refresh_token").len(), 1);

    // A failure that may have reached the server is not repeated (the refresh token could
    // already be rotated).
    let h = harness();
    h.seed_session(T0_MS + 60_000, FULL_SCOPE);
    h.chain.fail_next(
        &token_endpoint(),
        HttpError::Transport(TransportErrorKind::Other),
    );
    assert_eq!(h.ensure().await, Ok(()), "still valid: used as is");
    assert_eq!(h.chain.attempts_to(&token_endpoint()), 1);
    assert!(h.idp.token_forms("refresh_token").is_empty());
}

/// Past the refusal guard of a session saved at `T0_MS`.
const AFTER_GUARD: Duration = Duration::from_secs(61);

#[tokio::test]
async fn a_rejected_credential_is_renewed_regardless_of_expiry() {
    let h = harness();
    h.seed_session(T0_MS + 3_600_000, FULL_SCOPE);
    assert_eq!(h.ensure().await, Ok(()));
    assert!(h.idp.token_forms("refresh_token").is_empty());
    h.clock.advance(AFTER_GUARD);
    h.sign_in.credential_rejected("chatgpt", NAME).await;
    assert_eq!(h.ensure().await, Ok(()));
    assert_eq!(h.idp.token_forms("refresh_token").len(), 1);
    assert_eq!(h.ensure().await, Ok(()));
    assert_eq!(
        h.idp.token_forms("refresh_token").len(),
        1,
        "cleared by the renewal"
    );
}

#[tokio::test]
async fn a_refusal_reported_right_after_a_renewal_does_not_renew_again() {
    let h = harness();
    h.seed_session(T0_MS + 3_600_000, FULL_SCOPE);
    h.clock.advance(Duration::from_secs(120));
    h.sign_in.credential_rejected("chatgpt", NAME).await;
    assert_eq!(h.ensure().await, Ok(()));
    assert_eq!(h.refreshes(), 1);
    let renewed = h.stored_token();

    // A request sent with the previous token is refused after the renewal: the new token was
    // never refused, so it is kept.
    h.sign_in.credential_rejected("chatgpt", NAME).await;
    assert_eq!(h.ensure().await, Ok(()));
    assert_eq!(h.ensure().await, Ok(()));
    assert_eq!(h.refreshes(), 1, "the late refusal is dropped");
    assert_eq!(h.stored_token(), renewed);

    // A refusal once the guard has passed concerns the current token.
    h.clock.advance(AFTER_GUARD);
    h.sign_in.credential_rejected("chatgpt", NAME).await;
    assert_eq!(h.ensure().await, Ok(()));
    assert_eq!(h.refreshes(), 2);
}

#[tokio::test]
async fn a_transient_failure_after_a_refusal_still_uses_an_unexpired_token() {
    let h = harness_with(|c| c.transient_cooldown = Duration::ZERO);
    h.seed_session(T0_MS + 3_600_000, FULL_SCOPE);
    h.clock.advance(AFTER_GUARD);
    h.idp
        .with(|st| st.refresh_answers.push_back(Refresh::Status(503)));
    h.sign_in.credential_rejected("chatgpt", NAME).await;
    assert_eq!(h.ensure().await, Ok(()), "the token has not expired");
    assert_eq!(h.refreshes(), 1);
    assert_eq!(h.stored_token().as_deref(), Some("ACCESS-SEED-zq"));
    assert_eq!(
        h.record().unwrap()["session"]["refresh_token"],
        "REFRESH-SEED-zq"
    );
    // The refusal stays marked: the next call renews again.
    assert_eq!(h.ensure().await, Ok(()));
    assert_eq!(h.refreshes(), 2);
    let access = h.idp.with(|st| st.access.clone().unwrap());
    assert_eq!(h.stored_token().as_deref(), Some(access.as_str()));
    assert_eq!(h.ensure().await, Ok(()));
    assert_eq!(h.refreshes(), 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn callers_after_a_transient_renewal_failure_reuse_it_while_the_token_works() {
    let h = harness();
    h.seed_session(T0_MS + 60_000, FULL_SCOPE);
    h.idp.with(|st| {
        st.refresh_delay = Duration::from_millis(100);
        for _ in 0..12 {
            st.refresh_answers.push_back(Refresh::Status(503));
        }
    });
    let mut tasks = tokio::task::JoinSet::new();
    for _ in 0..8 {
        let sign_in = Arc::clone(&h.sign_in);
        tasks.spawn(async move { sign_in.ensure_fresh("chatgpt", NAME).await });
    }
    while let Some(result) = tasks.join_next().await {
        assert_eq!(result.unwrap(), Ok(()));
    }
    assert_eq!(
        h.refreshes(),
        1,
        "one token request for every queued caller"
    );
    assert_eq!(h.ensure().await, Ok(()));
    assert_eq!(h.refreshes(), 1, "a later caller inside the cool-down too");
    assert_eq!(h.stored_token().as_deref(), Some("ACCESS-SEED-zq"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_expired_token_inside_the_cool_down_is_refresh_unavailable_without_a_token_request() {
    // Measured on the test clock, which moves only when the test advances it.
    let cool_down = Duration::from_secs(30);
    let h = harness_with(|c| c.transient_cooldown = cool_down);
    h.seed_session(T0_MS + 60_000, FULL_SCOPE);
    h.clock.advance(Duration::from_secs(120));
    h.idp.with(|st| {
        st.refresh_delay = Duration::from_millis(100);
        for _ in 0..16 {
            st.refresh_answers.push_back(Refresh::Status(503));
        }
    });
    let mut tasks = tokio::task::JoinSet::new();
    for _ in 0..8 {
        let sign_in = Arc::clone(&h.sign_in);
        tasks.spawn(async move { sign_in.ensure_fresh("chatgpt", NAME).await });
    }
    while let Some(result) = tasks.join_next().await {
        assert_eq!(result.unwrap(), Err(CredentialFailure::RefreshUnavailable));
    }
    assert_eq!(
        h.refreshes(),
        1,
        "one token request for every queued caller"
    );
    for caller in 0..3 {
        assert_eq!(
            h.ensure().await,
            Err(CredentialFailure::RefreshUnavailable),
            "later caller {caller}"
        );
    }
    assert_eq!(h.refreshes(), 1, "later callers inside the cool-down too");
    assert!(
        h.stored_token().as_deref() == Some("ACCESS-SEED-zq"),
        "never erased"
    );
    assert!(
        h.record().unwrap()["session"]["refresh_token"] == "REFRESH-SEED-zq",
        "the refresh token is kept"
    );
    let status = h.sign_in.status(NAME);
    assert_eq!(status.state, STATE_SIGNED_IN);
    assert_eq!(status.reason, Some(REASON_REFRESH_UNAVAILABLE));

    // Just before its end the cool-down still holds ...
    h.clock.advance(cool_down - Duration::from_millis(1));
    assert_eq!(h.ensure().await, Err(CredentialFailure::RefreshUnavailable));
    assert_eq!(h.refreshes(), 1, "still inside the cool-down");

    // ... past it the next caller tries again, with exactly one request, and that failure
    // starts a new cool-down.
    h.clock.advance(Duration::from_millis(1));
    assert_eq!(h.ensure().await, Err(CredentialFailure::RefreshUnavailable));
    assert_eq!(h.refreshes(), 2, "one new token request");
    assert_eq!(h.ensure().await, Err(CredentialFailure::RefreshUnavailable));
    assert_eq!(h.refreshes(), 2, "inside the new cool-down");
}

#[tokio::test]
async fn a_renewal_runs_to_completion_when_its_caller_stops_waiting() {
    let h = harness();
    h.seed_session(T0_MS + 60_000, FULL_SCOPE);
    h.idp
        .with(|st| st.refresh_delay = Duration::from_millis(400));
    let gave_up = tokio::time::timeout(Duration::from_millis(50), h.ensure()).await;
    assert!(gave_up.is_err(), "the caller stopped waiting first");
    wait_until_async("the rotated session", || {
        let rotated = h.idp.with(|st| st.refresh.clone());
        rotated.as_deref() != Some("REFRESH-SEED-zq")
            && h.record().unwrap()["session"]["refresh_token"].as_str() == rotated.as_deref()
    })
    .await;
    let access = h.idp.with(|st| st.access.clone().unwrap());
    assert_eq!(h.stored_token().as_deref(), Some(access.as_str()));
    assert_eq!(h.refreshes(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_renewal_that_is_not_yet_required_never_holds_callers_past_a_short_wait() {
    let h = harness_with(|c| c.renewal_wait = Duration::from_millis(200));
    // Two minutes left: the renewal is due, the stored token still works.
    h.seed_session(T0_MS + 120_000, FULL_SCOPE);
    let gate = Arc::new(tokio::sync::Notify::new());
    h.idp.with(|st| st.refresh_gate = Some(Arc::clone(&gate)));
    let bound = Duration::from_secs(5);

    // The first caller starts the renewal, which hangs at the identity provider: after the short
    // wait it proceeds with the stored token.
    let started = Instant::now();
    let first = tokio::time::timeout(bound, h.ensure())
        .await
        .expect("the first caller is not held by the renewal");
    assert_eq!(first, Ok(()));
    // Callers that find the renewal running proceed at once.
    let mut tasks = tokio::task::JoinSet::new();
    for _ in 0..6 {
        let sign_in = Arc::clone(&h.sign_in);
        tasks.spawn(async move { sign_in.ensure_fresh("chatgpt", NAME).await });
    }
    let joined = tokio::time::timeout(bound, async {
        let mut answers = Vec::new();
        while let Some(answer) = tasks.join_next().await {
            answers.push(answer.unwrap());
        }
        answers
    })
    .await
    .expect("no caller waits on the renewal in flight");
    assert_eq!(joined, vec![Ok(()); 6]);
    assert!(started.elapsed() < Duration::from_secs(3));
    assert_eq!(h.refreshes(), 1, "one renewal, still in flight");
    assert_eq!(
        h.stored_token().as_deref(),
        Some("ACCESS-SEED-zq"),
        "the working token served them"
    );

    // Once the identity provider answers, the renewal persists on its own.
    gate.notify_one();
    wait_until_async("the rotated session", || {
        let access = h.idp.with(|st| st.access.clone());
        access.as_deref() != Some("ACCESS-SEED-zq") && h.stored_token() == access
    })
    .await;
    assert_eq!(h.refreshes(), 1);

    // A renewal the caller is not allowed to skip (the token expired) is still waited for.
    let h = harness_with(|c| c.renewal_wait = Duration::from_millis(200));
    h.seed_session(T0_MS + 60_000, FULL_SCOPE);
    h.clock.advance(Duration::from_secs(120));
    h.idp
        .with(|st| st.refresh_delay = Duration::from_millis(600));
    let started = Instant::now();
    assert_eq!(h.ensure().await, Ok(()));
    assert!(started.elapsed() >= Duration::from_millis(600));
    let access = h.idp.with(|st| st.access.clone().unwrap());
    assert_eq!(h.stored_token().as_deref(), Some(access.as_str()));
}

/// A stored token that would expire before a request sent after the short wait (or at once)
/// reaches the upstream is never handed out while its renewal runs: the caller that started
/// the renewal and every caller that finds it running wait for its answer and then carry the
/// renewed token.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_token_about_to_expire_is_not_handed_out_while_its_renewal_runs() {
    let h = harness_with(|c| c.renewal_wait = Duration::from_millis(200));
    assert_eq!(test_config().dispatch_margin, Duration::from_secs(30));
    // Two seconds left: the renewal is due and the stored token still works, but not for the
    // dispatch margin.
    h.seed_session(T0_MS + 2_000, FULL_SCOPE);
    let gate = Arc::new(tokio::sync::Notify::new());
    h.idp.with(|st| st.refresh_gate = Some(Arc::clone(&gate)));

    let sign_in = Arc::clone(&h.sign_in);
    let first = tokio::spawn(async move { sign_in.ensure_fresh("chatgpt", NAME).await });
    wait_until_async("the renewal at the identity provider", || {
        h.refreshes() == 1
    })
    .await;
    let mut tasks = tokio::task::JoinSet::new();
    for _ in 0..4 {
        let sign_in = Arc::clone(&h.sign_in);
        tasks.spawn(async move { sign_in.ensure_fresh("chatgpt", NAME).await });
    }
    // Well past the short wait, nobody has been answered with the old token.
    tokio::time::sleep(Duration::from_millis(800)).await;
    assert!(
        !first.is_finished(),
        "the first caller waits for the renewal"
    );
    assert!(
        tasks.try_join_next().is_none(),
        "callers that find the renewal running wait for it"
    );
    assert_eq!(h.stored_token().as_deref(), Some("ACCESS-SEED-zq"));

    gate.notify_one();
    let bound = Duration::from_secs(5);
    let first = tokio::time::timeout(bound, first)
        .await
        .expect("answered once the renewal ends")
        .unwrap();
    assert_eq!(first, Ok(()));
    let joined = tokio::time::timeout(bound, async {
        let mut answers = Vec::new();
        while let Some(answer) = tasks.join_next().await {
            answers.push(answer.unwrap());
        }
        answers
    })
    .await
    .expect("answered once the renewal ends");
    assert_eq!(joined, vec![Ok(()); 4]);
    let access = h.idp.with(|st| st.access.clone().unwrap());
    assert_ne!(access, "ACCESS-SEED-zq");
    assert_eq!(h.stored_token().as_deref(), Some(access.as_str()));
    assert_eq!(h.refreshes(), 1, "one renewal served them all");

    // Just past the margin and the wait, the short-cuts apply again.
    let h = harness_with(|c| c.renewal_wait = Duration::from_millis(200));
    h.seed_session(T0_MS + 30_201, FULL_SCOPE);
    let gate = Arc::new(tokio::sync::Notify::new());
    h.idp.with(|st| st.refresh_gate = Some(Arc::clone(&gate)));
    assert_eq!(
        tokio::time::timeout(bound, h.ensure())
            .await
            .expect("the first caller is not held by the renewal"),
        Ok(())
    );
    assert_eq!(h.stored_token().as_deref(), Some("ACCESS-SEED-zq"));
    gate.notify_one();
    wait_until_async("the rotated session", || {
        let access = h.idp.with(|st| st.access.clone());
        access.as_deref() != Some("ACCESS-SEED-zq") && h.stored_token() == access
    })
    .await;
}

#[tokio::test]
async fn earliest_refresh_at_from_a_token_response_is_stored_and_honoured() {
    let at_s = T0_MS / 1000 + 3_500;
    let cases = [
        (json!(at_s), Some(T0_MS + 3_500_000)),
        (json!(at_s.to_string()), Some(T0_MS + 3_500_000)),
        (json!(T0_MS + 3_500_000), Some(T0_MS + 3_500_000)),
        (json!("soon"), None),
    ];
    for (i, (value, expected)) in cases.into_iter().enumerate() {
        let h = harness();
        h.seed_session(T0_MS + 60_000, FULL_SCOPE);
        h.idp.with(|st| st.earliest_refresh_at = Some(value));
        assert_eq!(h.ensure().await, Ok(()));
        assert_eq!(h.refreshes(), 1);
        let stored = h.record().unwrap()["session"]["earliest_refresh_at_ms"].as_u64();
        assert_eq!(stored, expected, "case {i}");
        if i == 0 {
            // Inside the renewal margin but before `earliest_refresh_at`: postponed.
            h.clock.advance(Duration::from_secs(3_400));
            assert_eq!(h.ensure().await, Ok(()));
            assert_eq!(h.refreshes(), 1);
            h.clock.advance(Duration::from_secs(110));
            assert_eq!(h.ensure().await, Ok(()));
            assert_eq!(h.refreshes(), 2);
        }
    }
}

#[tokio::test]
async fn a_renewal_answer_carrying_credential_shaped_text_is_stored_and_rotates() {
    // The sign-in chain does not scan content: random token text that happens to look like
    // another service's credential is an ordinary token answer.
    let h = harness();
    h.seed_session(T0_MS + 60_000, FULL_SCOPE);
    h.idp
        .with(|st| st.refresh_answers.push_back(Refresh::CredentialShaped));
    assert_eq!(h.ensure().await, Ok(()));
    assert_eq!(h.refreshes(), 1);
    let (access, refresh) = h
        .idp
        .with(|st| (st.access.clone().unwrap(), st.refresh.clone().unwrap()));
    assert!(access.contains(AWS_KEY_SHAPED) && refresh.contains(GITHUB_TOKEN_SHAPED));
    assert_eq!(h.stored_token().as_deref(), Some(access.as_str()));
    let record = h.record().unwrap();
    assert_eq!(record["session"]["access_token"], access.as_str());
    assert_eq!(record["session"]["refresh_token"], refresh.as_str());
    assert_eq!(record["session"]["expires_at_ms"], T0_MS + 3_600_000);
    assert_eq!(h.sign_in.status(NAME).reason, None);

    // The next renewal presents the rotated refresh token, and the identity provider takes it.
    h.clock.advance(Duration::from_secs(3_400));
    assert_eq!(h.ensure().await, Ok(()));
    let renewals = h.idp.token_forms("refresh_token");
    assert_eq!(renewals.len(), 2);
    assert_eq!(renewals[1]["refresh_token"], refresh);
    let renewed = h.idp.with(|st| st.access.clone().unwrap());
    assert_eq!(h.stored_token().as_deref(), Some(renewed.as_str()));
    assert_ne!(renewed, access);
}

#[tokio::test]
async fn a_refresh_token_carrying_credential_shaped_text_is_sent_and_the_renewal_succeeds() {
    let h = harness();
    let host = h.sign_in.host_id().unwrap();
    let shaped = format!("REFRESH-SEED-{AWS_KEY_SHAPED}-{GITHUB_TOKEN_SHAPED}-zq");
    h.seed_record_with(&host, T0_MS + 60_000, FULL_SCOPE, &shaped);
    assert_eq!(h.ensure().await, Ok(()));
    assert_eq!(h.chain.attempts_to(&token_endpoint()), 1);
    let renewals = h.idp.token_forms("refresh_token");
    assert_eq!(
        renewals.len(),
        1,
        "the renewal reached the identity provider"
    );
    assert_eq!(renewals[0]["refresh_token"], shaped);

    let (access, refresh) = h
        .idp
        .with(|st| (st.access.clone().unwrap(), st.refresh.clone().unwrap()));
    assert_eq!(h.stored_token().as_deref(), Some(access.as_str()));
    let record = h.record().unwrap();
    assert_eq!(record["session"]["access_token"], access.as_str());
    assert_eq!(record["session"]["refresh_token"], refresh.as_str());
    assert_eq!(record["session"]["expires_at_ms"], T0_MS + 3_600_000);
    assert_eq!(h.sign_in.status(NAME).reason, None);
}

#[test]
fn a_grant_without_a_refresh_token_is_used_until_it_expires_then_ends() {
    let h = harness();
    h.idp.with(|st| st.exchange_without_refresh = true);
    sign_in_fully(&h);
    let record = h.record().unwrap();
    assert!(record["session"].get("refresh_token").is_none());
    assert_eq!(block(h.ensure()), Ok(()));

    // Inside the renewal margin: nothing to renew with, the token still works.
    h.clock.advance(Duration::from_secs(3_400));
    assert_eq!(block(h.ensure()), Ok(()));
    assert_eq!(h.sign_in.status(NAME).state, STATE_SIGNED_IN);

    h.clock.advance(Duration::from_secs(201));
    assert_eq!(block(h.ensure()), Err(CredentialFailure::NotSignedIn));
    let status = h.sign_in.status(NAME);
    assert_eq!(status.state, STATE_SIGNED_OUT);
    assert_eq!(status.reason, Some(REASON_SESSION_ENDED));
    assert!(h.stored_token().is_none());
    assert_eq!(h.refreshes(), 0, "no renewal was ever attempted");
    assert_eq!(
        h.record().unwrap()["client_id"],
        ISSUED,
        "registration kept"
    );
}

#[tokio::test]
async fn earliest_refresh_at_in_the_future_postpones_a_due_renewal() {
    let h = harness();
    h.seed_session(T0_MS + 60_000, FULL_SCOPE);
    let mut record = h.record().unwrap();
    record["session"]["earliest_refresh_at_ms"] = json!(T0_MS + 30_000);
    h.store.store(RECORD, &record.to_string()).unwrap();
    assert_eq!(h.ensure().await, Ok(()));
    assert!(h.idp.token_forms("refresh_token").is_empty());
    h.clock.advance(Duration::from_secs(31));
    assert_eq!(h.ensure().await, Ok(()));
    assert_eq!(h.idp.token_forms("refresh_token").len(), 1);
}

#[tokio::test]
async fn a_half_written_pair_is_repaired_from_the_record() {
    let h = harness();
    h.seed_session(T0_MS + 3_600_000, FULL_SCOPE);
    h.store.store(NAME, "ACCESS-STALE-zq").unwrap();
    assert_eq!(h.ensure().await, Ok(()));
    assert_eq!(h.stored_token().as_deref(), Some("ACCESS-SEED-zq"));
    h.store.remove(NAME).unwrap();
    assert_eq!(h.ensure().await, Ok(()));
    assert_eq!(h.stored_token().as_deref(), Some("ACCESS-SEED-zq"));
    assert!(h.idp.token_forms("refresh_token").is_empty());
}

#[tokio::test]
async fn a_rotated_session_that_cannot_be_written_is_kept_until_it_can() {
    let h = harness();
    h.seed_session(T0_MS + 60_000, FULL_SCOPE);
    *h.storage.fail_puts_ending.lock().unwrap() = Some(".chatgpt-oauth".into());
    assert_eq!(h.ensure().await, Ok(()));
    let (access, refresh) = h
        .idp
        .with(|st| (st.access.clone().unwrap(), st.refresh.clone().unwrap()));
    assert_eq!(h.stored_token().as_deref(), Some(access.as_str()));
    assert_eq!(
        h.record().unwrap()["session"]["refresh_token"],
        "REFRESH-SEED-zq",
        "the write failed"
    );
    assert_eq!(
        h.sign_in.status(NAME).expires_at_ms,
        Some(T0_MS + 3_600_000)
    );

    *h.storage.fail_puts_ending.lock().unwrap() = None;
    assert_eq!(h.ensure().await, Ok(()));
    assert_eq!(h.record().unwrap()["session"]["refresh_token"], refresh);
    assert_eq!(
        h.idp.token_forms("refresh_token").len(),
        1,
        "the dead refresh token was never presented again"
    );
}

#[test]
fn a_record_of_another_host_is_never_used_or_deleted() {
    let h = harness();
    h.sign_in.host_id().unwrap();
    let other = format!("urn:uuid:{}", uuid::Uuid::new_v4());
    h.seed_record(&other, T0_MS + 60_000, FULL_SCOPE);
    let before = h.record_text();

    // Not this host's session, and the status says why a sign-in is refused for the name.
    let status = h.sign_in.status(NAME);
    assert_eq!(status.state, STATE_SIGNED_OUT);
    assert_eq!(status.reason, Some(REASON_UNAVAILABLE));
    assert_eq!(status.account, None);
    assert_eq!(block(h.ensure()), Err(CredentialFailure::NotSignedIn));
    assert_eq!(h.sign_in.verify(NAME).reason, Some(REASON_NOT_SIGNED_IN));
    assert_eq!(
        h.sign_in.sign_out(NAME),
        SignOutOutcome {
            signed_out: true,
            revocation_confirmed: false
        }
    );
    h.sign_in.forget(NAME);
    assert_eq!(
        h.sign_in.start(NAME),
        Err(SignInRefusal(REASON_UNAVAILABLE))
    );
    assert_eq!(h.sign_in.status(NAME).reason, Some(REASON_UNAVAILABLE));
    assert!(h.idp.wire().is_empty(), "never renewed, revoked or listed");
    assert_eq!(h.record_text(), before);
    assert_eq!(h.stored_token().as_deref(), Some("ACCESS-SEED-zq"));

    // Before this installation has a host id any stored record is another one's: the same.
    let h = harness();
    h.seed_record(&other, T0_MS + 60_000, FULL_SCOPE);
    let status = h.sign_in.status(NAME);
    assert_eq!(
        (status.state, status.reason),
        (STATE_SIGNED_OUT, Some(REASON_UNAVAILABLE))
    );
    assert!(
        !h.host_id_file().exists(),
        "reading the status creates nothing"
    );
}

// ── sign-out / forget ────────────────────────────────────────────────────────────────────────

#[test]
fn sign_out_revokes_clears_the_session_and_keeps_the_registration() {
    let h = harness();
    sign_in_fully(&h);
    let refresh = h.idp.with(|st| st.refresh.clone().unwrap());
    let host = h.sign_in.host_id().unwrap();
    assert_eq!(
        h.sign_out_outcome(),
        SignOutOutcome {
            signed_out: true,
            revocation_confirmed: true
        }
    );
    let revocations = h.idp.to(&format!("{ISSUER}/discovered/revoke"));
    assert_eq!(revocations.len(), 1);
    let form = form_of(&revocations[0].body);
    assert_eq!(form["token"], refresh);
    assert_eq!(form["token_type_hint"], "refresh_token");
    assert_eq!(form["client_id"], ISSUED);

    assert!(h.stored_token().is_none());
    let record = h.record().unwrap();
    assert!(record["session"].is_null());
    assert_eq!(record["client_id"], ISSUED);
    assert_eq!(record["ext_agent_host_id"], host);
    let status = h.sign_in.status(NAME);
    assert_eq!(status.state, STATE_SIGNED_OUT);
    assert_eq!(status.reason, None);
    assert_eq!(block(h.ensure()), Err(CredentialFailure::NotSignedIn));
    assert_eq!(h.sign_in.host_id().unwrap(), host);
}

#[test]
fn sign_out_without_confirmed_revocation_still_clears_local_tokens() {
    let h = harness();
    sign_in_fully(&h);
    h.idp
        .with(|st| st.revoke_statuses.extend([503, 503, 503, 503]));
    assert_eq!(
        h.sign_out_outcome(),
        SignOutOutcome {
            signed_out: true,
            revocation_confirmed: false
        }
    );
    assert_eq!(
        h.idp.to(&format!("{ISSUER}/discovered/revoke")).len(),
        3,
        "bounded retries"
    );
    assert!(h.stored_token().is_none());
    assert!(h.record().unwrap()["session"].is_null());
}

#[test]
fn a_revocation_that_does_not_answer_is_bounded_as_a_whole() {
    let h = harness_with(|c| c.revocation_timeout = Duration::from_millis(300));
    sign_in_fully(&h);
    wait_until("the model list", || {
        h.sign_in.status(NAME).models.len() == 2
    });
    // Longer than the bound: the revocation endpoint accepts the request and stays silent.
    h.idp.with(|st| st.revoke_delay = Duration::from_secs(10));
    let started = Instant::now();
    let outcome = h.sign_out_outcome();
    let waited = started.elapsed();
    assert!(waited < Duration::from_secs(5), "{waited:?}");
    assert_eq!(
        outcome,
        SignOutOutcome {
            signed_out: true,
            revocation_confirmed: false
        }
    );
    assert_eq!(h.idp.to(&format!("{ISSUER}/discovered/revoke")).len(), 1);
    assert!(h.stored_token().is_none());
    assert!(h.record().unwrap()["session"].is_null());

    // `forget` is bounded the same way, and still removes what the sign-in wrote.
    let h = harness_with(|c| c.revocation_timeout = Duration::from_millis(300));
    sign_in_fully(&h);
    wait_until("the model list", || {
        h.sign_in.status(NAME).models.len() == 2
    });
    h.idp.with(|st| st.revoke_delay = Duration::from_secs(10));
    let started = Instant::now();
    h.sign_in.forget(NAME);
    assert!(started.elapsed() < Duration::from_secs(5));
    assert!(h.record().is_none() && h.stored_token().is_none());
}

#[test]
fn forget_revokes_and_removes_both_names() {
    let h = harness();
    sign_in_fully(&h);
    h.sign_in.forget(NAME);
    assert_eq!(h.idp.to(&format!("{ISSUER}/discovered/revoke")).len(), 1);
    assert!(h.record().is_none() && h.stored_token().is_none());
    assert!(h.host_id_file().exists());
    assert_eq!(h.sign_in.status(NAME).state, STATE_SIGNED_OUT);
}

#[test]
fn a_forget_whose_access_token_removal_fails_is_retried_by_the_next_call() {
    let h = harness();
    sign_in_fully(&h);
    wait_until("the model list", || {
        h.sign_in.status(NAME).models.len() == 2
    });
    h.storage.fail_removes_of(Some(NAME));
    let before = h.storage.removal_attempts(NAME);
    h.sign_in.forget(NAME);
    // The record goes only after the access token: it stays, without its session, so the
    // leftover access token is still known to be this sign-in's.
    let record = h.record().expect("the record outlives the access token");
    assert!(record["session"].is_null());
    assert_eq!(record["subject"], SUB);
    assert!(
        h.stored_token().is_some(),
        "the access-token removal failed"
    );
    assert_eq!(h.storage.removal_attempts(NAME), before + 1);
    assert_eq!(h.storage.removal_attempts(RECORD), 0);
    assert_eq!(h.sign_in.status(NAME).state, STATE_SIGNED_OUT);

    // The next call retries the removal while the store keeps refusing it ...
    assert_eq!(block(h.ensure()), Err(CredentialFailure::NotSignedIn));
    assert_eq!(
        h.storage.removal_attempts(NAME),
        before + 2,
        "the next call retries the removal"
    );
    assert!(h.stored_token().is_some() && h.record().is_some());

    // ... and once the store takes it the access token goes, then the record, and nothing is
    // retried.
    h.storage.fail_removes_of(None);
    assert_eq!(block(h.ensure()), Err(CredentialFailure::NotSignedIn));
    assert!(
        h.stored_token().is_none(),
        "the leftover access token is removed"
    );
    assert!(h.record().is_none(), "then the record");
    assert_eq!(h.storage.removal_attempts(NAME), before + 3);
    assert_eq!(block(h.ensure()), Err(CredentialFailure::NotSignedIn));
    assert_eq!(
        h.storage.removal_attempts(NAME),
        before + 3,
        "nothing left to retry"
    );
    assert!(h.idp.token_forms("refresh_token").is_empty());
}

#[test]
fn a_record_whose_removal_by_forget_failed_is_not_used_again() {
    let h = harness();
    sign_in_fully(&h);
    wait_until("the model list", || {
        h.sign_in.status(NAME).models.len() == 2
    });
    h.storage.fail_record_writes(true);
    h.storage.fail_removes(true);
    h.sign_in.forget(NAME);
    assert!(
        h.record().unwrap()["session"].is_object() && h.stored_token().is_some(),
        "neither the cleared record nor a removal reached the store"
    );

    // The record still in the store, with its unexpired session, is not this process's sign-in
    // any more.
    let status = h.sign_in.status(NAME);
    assert_eq!(status.state, STATE_SIGNED_OUT);
    assert_eq!(status.account, None);
    assert_eq!(block(h.ensure()), Err(CredentialFailure::NotSignedIn));
    assert_eq!(h.sign_in.verify(NAME).reason, Some(REASON_NOT_SIGNED_IN));
    let started = h.sign_in.start(NAME).unwrap();
    assert_eq!(
        query_of(&started.authorize_url)["client_id"],
        "dynamic_agent_client",
        "the forgotten registration is not reused"
    );
    h.sign_in.cancel(NAME);

    h.storage.fail_record_writes(false);
    h.storage.fail_removes(false);
    assert_eq!(block(h.ensure()), Err(CredentialFailure::NotSignedIn));
    assert!(h.record().is_none() && h.stored_token().is_none());
}

#[test]
fn a_sign_out_whose_clearing_writes_fail_is_not_reported_signed_out() {
    let h = harness();
    sign_in_fully(&h);
    wait_until("the model list", || {
        h.sign_in.status(NAME).models.len() == 2
    });
    h.storage.fail_record_writes(true);
    h.storage.fail_removes(true);
    assert_eq!(
        h.sign_in.sign_out(NAME),
        SignOutOutcome {
            signed_out: false,
            revocation_confirmed: true
        }
    );
    // This process never uses the session again ...
    assert_eq!(h.sign_in.status(NAME).state, STATE_SIGNED_OUT);
    assert_eq!(block(h.ensure()), Err(CredentialFailure::NotSignedIn));
    // ... although the store still holds what could not be cleared.
    assert!(h.record().unwrap()["session"].is_object());
    assert!(h.stored_token().is_some());

    h.storage.fail_record_writes(false);
    h.storage.fail_removes(false);
    assert_eq!(
        h.sign_in.sign_out(NAME),
        SignOutOutcome {
            signed_out: true,
            revocation_confirmed: false
        }
    );
    assert!(h.record().unwrap()["session"].is_null());
    assert!(h.stored_token().is_none());
}

#[tokio::test]
async fn a_session_ended_while_the_store_fails_stays_ended_and_heals() {
    let h = harness();
    h.seed_session(T0_MS + 60_000, FULL_SCOPE);
    h.idp.with(|st| {
        st.refresh_answers
            .push_back(Refresh::Error(400, "refresh_token_reused"))
    });
    h.storage.fail_record_writes(true);
    h.storage.fail_removes(true);
    assert_eq!(h.ensure().await, Err(CredentialFailure::NotSignedIn));
    assert!(
        h.record().unwrap()["session"].is_object(),
        "the write failed"
    );
    assert_eq!(h.ensure().await, Err(CredentialFailure::NotSignedIn));
    assert_eq!(
        h.refreshes(),
        1,
        "the dead refresh token is not presented again"
    );
    let status = h.sign_in.status(NAME);
    assert_eq!(status.state, STATE_SIGNED_OUT);
    assert_eq!(status.reason, Some(REASON_SESSION_ENDED));

    h.storage.fail_record_writes(false);
    h.storage.fail_removes(false);
    assert_eq!(h.ensure().await, Err(CredentialFailure::NotSignedIn));
    assert!(h.record().unwrap()["session"].is_null());
    assert!(
        h.stored_token().is_none(),
        "the leftover access token is removed"
    );
}

#[tokio::test]
async fn a_registration_dropped_while_removals_fail_is_not_renewed_again() {
    let h = harness();
    h.seed_session(T0_MS + 60_000, FULL_SCOPE);
    h.idp.with(|st| {
        st.refresh_answers
            .push_back(Refresh::Error(401, "invalid_client"))
    });
    h.storage.fail_removes(true);
    assert_eq!(h.ensure().await, Err(CredentialFailure::NotSignedIn));
    assert!(h.record().is_some(), "the removal failed");
    assert_eq!(h.ensure().await, Err(CredentialFailure::NotSignedIn));
    assert_eq!(h.refreshes(), 1, "the stored session is not used again");
    assert_eq!(h.sign_in.status(NAME).state, STATE_SIGNED_OUT);
    let started = h.sign_in.start(NAME).unwrap();
    assert_eq!(
        query_of(&started.authorize_url)["client_id"],
        "dynamic_agent_client"
    );
    h.sign_in.cancel(NAME);

    h.storage.fail_removes(false);
    assert_eq!(h.ensure().await, Err(CredentialFailure::NotSignedIn));
    assert!(h.record().is_none() && h.stored_token().is_none());
}

#[tokio::test]
async fn a_leftover_access_token_beside_a_cleared_session_is_removed() {
    let h = harness();
    h.seed_session(T0_MS + 3_600_000, FULL_SCOPE);
    let mut record = h.record().unwrap();
    record["session"] = Value::Null;
    h.store.store(RECORD, &record.to_string()).unwrap();
    assert_eq!(h.stored_token().as_deref(), Some("ACCESS-SEED-zq"));
    assert_eq!(h.ensure().await, Err(CredentialFailure::NotSignedIn));
    assert!(h.stored_token().is_none());
    assert_eq!(
        h.record_text(),
        record.to_string(),
        "the record is untouched"
    );
}

/// What the sign-in did not write is never removed: a value already stored under the entry's
/// name (another secret sharing it, such as an API key the entry used before) survives every
/// port method and every request while no sign-in of this host completed, and a completed
/// sign-in replaces it.
#[test]
fn a_value_under_the_name_that_the_sign_in_did_not_write_is_left_alone() {
    const OTHER: &str = "sk-proj-OTHER-SECRET-zq";
    let untouched = |h: &Harness, case: &str| {
        assert_eq!(h.stored_token().as_deref(), Some(OTHER), "{case}");
        assert_eq!(h.storage.removal_attempts(NAME), 0, "{case}");
    };

    // No record, with and without a host id.
    for with_host_id in [true, false] {
        let case = format!("no record, host id: {with_host_id}");
        let h = harness();
        if with_host_id {
            h.sign_in.host_id().unwrap();
        }
        h.store.store(NAME, OTHER).unwrap();
        assert_eq!(
            block(h.ensure()),
            Err(CredentialFailure::NotSignedIn),
            "{case}"
        );
        assert_eq!(h.sign_in.verify(NAME).reason, Some(REASON_NOT_SIGNED_IN));
        assert_eq!(
            h.sign_in.sign_out(NAME),
            SignOutOutcome {
                signed_out: true,
                revocation_confirmed: false
            },
            "{case}"
        );
        h.sign_in.forget(NAME);
        assert_eq!(
            block(h.ensure()),
            Err(CredentialFailure::NotSignedIn),
            "{case}"
        );
        untouched(&h, &case);
        assert!(h.record().is_none(), "{case}");
        assert!(h.idp.wire().is_empty(), "{case}");
    }

    // A registration that never completed a sign-in: its record goes with `forget`, the value
    // stays.
    let h = harness();
    h.seed_registration_only(ISSUED);
    h.store.store(NAME, OTHER).unwrap();
    assert_eq!(block(h.ensure()), Err(CredentialFailure::NotSignedIn));
    assert!(h.sign_in.sign_out(NAME).signed_out);
    untouched(&h, "registration only");
    assert_eq!(h.record().unwrap()["client_id"], ISSUED);
    h.sign_in.forget(NAME);
    assert!(h.record().is_none(), "the registration goes");
    untouched(&h, "registration forgotten");

    // A sign-in that completes owns the name from then on: its access token replaces the value,
    // and a sign-out removes it.
    let h = harness();
    h.store.store(NAME, OTHER).unwrap();
    sign_in_fully(&h);
    let access = h.idp.with(|st| st.access.clone().unwrap());
    assert_eq!(h.stored_token().as_deref(), Some(access.as_str()));
    assert!(h.sign_in.sign_out(NAME).signed_out);
    assert!(h.stored_token().is_none());
}

#[tokio::test]
async fn an_unreadable_record_leaves_both_names_alone_on_a_request() {
    // A record this version cannot read is not a missing one: both names are left alone, as
    // they are beside a record of another host (`a_record_of_another_host_is_never_used_or_deleted`).
    for unreadable in ["{not json", r#"{"v": 2}"#] {
        let h = harness();
        h.sign_in.host_id().unwrap();
        h.store.store(RECORD, unreadable).unwrap();
        h.store.store(NAME, "ACCESS-SEED-zq").unwrap();
        assert_eq!(
            h.ensure().await,
            Err(CredentialFailure::NotSignedIn),
            "{unreadable}"
        );
        assert!(
            h.stored_token().as_deref() == Some("ACCESS-SEED-zq"),
            "{unreadable}: the access token is left alone"
        );
        assert_eq!(h.record_text(), unreadable, "left alone");
    }
}

#[test]
fn forget_over_an_unreadable_record_removes_the_access_token_and_leaves_the_record() {
    for unreadable in ["{not json", r#"{"v": 2}"#] {
        let h = harness();
        h.sign_in.host_id().unwrap();
        h.store.store(RECORD, unreadable).unwrap();
        h.store.store(NAME, "ACCESS-SEED-zq").unwrap();
        h.sign_in.forget(NAME);
        assert!(h.stored_token().is_none(), "{unreadable}");
        assert_eq!(h.record_text(), unreadable, "left alone");
        assert!(h.idp.wire().is_empty());
    }
}

#[test]
fn sign_out_over_an_unreadable_record_removes_the_access_token_and_says_so() {
    for unreadable in ["{not json", r#"{"v": 2}"#] {
        let h = harness();
        h.sign_in.host_id().unwrap();
        h.store.store(RECORD, unreadable).unwrap();
        h.store.store(NAME, "ACCESS-SEED-zq").unwrap();
        assert_eq!(
            h.sign_in.sign_out(NAME),
            SignOutOutcome {
                signed_out: false,
                revocation_confirmed: false
            },
            "{unreadable}"
        );
        assert!(h.stored_token().is_none(), "{unreadable}");
        assert_eq!(h.record_text(), unreadable, "left alone");
        assert!(h.idp.wire().is_empty());
    }
}

#[test]
fn a_start_waiting_on_forget_continues_on_the_state_every_later_caller_sees() {
    let h = Arc::new(harness());
    sign_in_fully(&h);
    wait_until("the model list", || {
        h.sign_in.status(NAME).models.len() == 2
    });
    h.idp
        .with(|st| st.revoke_delay = Duration::from_millis(600));
    let forgetting = {
        let h = Arc::clone(&h);
        std::thread::spawn(move || h.sign_in.forget(NAME))
    };
    // `forget` holds the name for the whole revocation; this start waits for it.
    wait_until("the revocation", || {
        !h.idp.to(&format!("{ISSUER}/discovered/revoke")).is_empty()
    });
    let started = h.sign_in.start(NAME).expect("start after forget");
    forgetting.join().unwrap();
    assert!(h.record().is_none());

    let status = h.sign_in.status(NAME);
    assert_eq!(status.state, STATE_PENDING);
    assert_eq!(status.expires_at_ms, Some(started.expires_at_ms));
    let cancelled = h.sign_in.cancel(NAME);
    assert_eq!(cancelled.reason, Some(REASON_CANCELLED));
    assert!(TcpStream::connect(("127.0.0.1", port_of(&started))).is_err());
}

impl Harness {
    fn sign_out_outcome(&self) -> SignOutOutcome {
        self.sign_in.sign_out(NAME)
    }
}

// ── verify and the port's threading ──────────────────────────────────────────────────────────

#[test]
fn verify_renews_once_after_the_model_list_refuses_the_token() {
    let h = harness();
    h.seed_session(T0_MS + 3_600_000, FULL_SCOPE);
    // The API no longer accepts the stored token.
    h.idp
        .with(|st| st.access = Some("ACCESS-REVOKED-zq".into()));
    let verdict = h.sign_in.verify(NAME);
    assert!(verdict.ok, "{verdict:?}");
    assert_eq!(verdict.models.len(), 2);
    assert_eq!(h.idp.token_forms("refresh_token").len(), 1);
    assert_eq!(h.sign_in.status(NAME).models.len(), 2, "kept in the record");

    let none = harness();
    let verdict = none.sign_in.verify(NAME);
    assert_eq!(verdict.reason, Some(REASON_NOT_SIGNED_IN));
    assert!(none.idp.wire().is_empty());
}

#[tokio::test(flavor = "current_thread")]
async fn port_methods_work_on_a_current_thread_runtime_worker() {
    let h = harness();
    h.seed_session(T0_MS + 3_600_000, FULL_SCOPE);
    assert!(h.sign_in.verify(NAME).ok);
    assert!(h.sign_in.sign_out(NAME).revocation_confirmed);
    assert_eq!(h.sign_in.status(NAME).state, STATE_SIGNED_OUT);
}

#[test]
fn port_methods_on_a_current_thread_runtime_do_not_wait_on_its_renewals() {
    let h = harness();
    h.seed_session(T0_MS + 60_000, FULL_SCOPE);
    h.idp
        .with(|st| st.refresh_delay = Duration::from_millis(500));
    let (done, outcome) = std::sync::mpsc::channel();
    // The whole scenario runs on the single thread of a current-thread runtime: a renewal is in
    // flight (holding the name) when a sync port method blocks that thread.
    let scenario = std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let sign_in = Arc::clone(&h.sign_in);
            let renewal = tokio::spawn(async move { sign_in.ensure_fresh("chatgpt", NAME).await });
            wait_until_async("the first renewal", || h.refreshes() == 1).await;
            let verified = h.sign_in.verify(NAME);
            let first = renewal.await.unwrap();

            h.clock.advance(Duration::from_secs(3_500));
            let sign_in = Arc::clone(&h.sign_in);
            let renewal = tokio::spawn(async move { sign_in.ensure_fresh("chatgpt", NAME).await });
            wait_until_async("the second renewal", || h.refreshes() == 2).await;
            let signed_out = h.sign_in.sign_out(NAME);
            let second = renewal.await.unwrap();
            let _ = done.send((verified.ok, first, signed_out, second));
        });
    });
    let (verified, first, signed_out, second) = outcome
        .recv_timeout(Duration::from_secs(60))
        .expect("the port methods returned while a renewal was in flight");
    scenario.join().unwrap();
    assert!(verified);
    assert_eq!(first, Ok(()));
    assert_eq!(second, Ok(()));
    assert_eq!(
        signed_out,
        SignOutOutcome {
            signed_out: true,
            revocation_confirmed: true
        }
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn port_methods_work_on_a_multi_thread_runtime_worker() {
    let h = harness();
    h.seed_session(T0_MS + 3_600_000, FULL_SCOPE);
    assert!(h.sign_in.verify(NAME).ok);
    let started = h.sign_in.start(NAME).unwrap();
    assert_eq!(
        h.sign_in.cancel(NAME).reason,
        None,
        "a session still exists"
    );
    assert!(TcpStream::connect(("127.0.0.1", port_of(&started))).is_err());
    h.sign_in.forget(NAME);
    assert!(h.record().is_none());
}

// ── the sign-in as the gateway's credential source ───────────────────────────────────────────

const PLAN_RESPONSES_URL: &str = "https://api.openai.com/v1/responses";

/// The LLM side of the wire, behind a production `DefaultHttpSecurityChain` over the SAME live
/// store the sign-in writes: records every request exactly as it left the chain (credential
/// injected) and by which transport, and answers a streamed request with the scripted status
/// (a completed Responses stream for `200`).
struct LlmWire {
    seen: Mutex<Vec<(&'static str, HttpRequest)>>,
    status: Mutex<u16>,
}

impl LlmWire {
    fn streamed(&self) -> Vec<HttpRequest> {
        self.seen
            .lock()
            .unwrap()
            .iter()
            .filter(|(transport, _)| *transport == "streamed")
            .map(|(_, req)| req.clone())
            .collect()
    }

    fn buffered(&self) -> usize {
        self.seen
            .lock()
            .unwrap()
            .iter()
            .filter(|(transport, _)| *transport == "buffered")
            .count()
    }
}

#[async_trait]
impl HttpExecutor for LlmWire {
    async fn execute(
        &self,
        req: &HttpRequest,
        _redirect_check: Arc<dyn RedirectCheck>,
    ) -> Result<HttpResponse, ExecutorError> {
        self.seen.lock().unwrap().push(("buffered", req.clone()));
        Ok(json_response(500, json!({})))
    }
}

struct WireChunks(std::vec::IntoIter<Vec<u8>>);

#[async_trait]
impl cap_http::executor::WireChunkStream for WireChunks {
    async fn next(&mut self) -> Option<Result<Vec<u8>, ExecutorError>> {
        self.0.next().map(Ok)
    }
}

#[async_trait]
impl cap_http::executor::HttpStreamExecutor for LlmWire {
    async fn execute_stream(
        &self,
        req: &HttpRequest,
        _redirect_check: Arc<dyn RedirectCheck>,
    ) -> Result<
        (
            advance_shared_types::security_validator::HttpResponseHead,
            Box<dyn cap_http::executor::WireChunkStream>,
        ),
        ExecutorError,
    > {
        self.seen.lock().unwrap().push(("streamed", req.clone()));
        let status = *self.status.lock().unwrap();
        let chunks = if status == 200 {
            vec![
                b"event: response.output_text.delta\ndata: {\"type\":\"response.output_text.delta\",\"delta\":\"hello\"}\n\n".to_vec(),
                b"event: response.completed\ndata: {\"type\":\"response.completed\",\"response\":{\"usage\":{\"input_tokens\":3,\"output_tokens\":2}}}\n\n".to_vec(),
            ]
        } else {
            vec![br#"{"detail":"refused"}"#.to_vec()]
        };
        Ok((
            advance_shared_types::security_validator::HttpResponseHead {
                status,
                headers: vec![("content-type".into(), "text/event-stream".into())],
            },
            Box::new(WireChunks(chunks.into_iter())),
        ))
    }
}

const PLAN_GATEWAY_CONFIG: &str = r#"
wasm:
  max_memory_pages: 1024
  epoch_interruption_ms: 100
  fuel_enabled: false

llm-providers:
  - id: openai-plan
    endpoint: https://api.openai.com
    api-key-secret: openai-plan
    auth-source: chatgpt-oauth
    model-aliases:
      plan: gpt-5
    cost-per-mtoken-in: 1.25
    cost-per-mtoken-out: 10.0

cron:
  max_jitter_ratio: 0.1

git:
  gc_interval_hours: 24
  max_tracked_file_mb: 10

secrets:
  master-key-source: keychain
  env-var-name: SECRETS_MASTER_KEY

post-processor:
  llm-model: sonnet-light
  llm-failure-cooldown-seconds: 600
"#;

/// The bearer a recorded request carried.
fn bearer_of(req: &HttpRequest) -> Option<String> {
    req.headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("authorization"))
        .and_then(|(_, v)| v.strip_prefix("Bearer "))
        .map(String::from)
}

/// The production sign-in installed as the gateway's credential source, over ONE live store
/// shared with the LLM egress chain: a buffered call on the plan entry renews the session first
/// and the streamed request carries the access token the renewal just wrote; a refused request
/// makes the next one renew again and carry the newer token.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_sign_in_feeds_the_gateway_the_token_it_just_renewed() {
    // The renewal is always waited for here, so the request carries its result.
    let h = harness_with(|c| c.renewal_wait = Duration::from_secs(30));
    // Two minutes left: inside the renewal margin.
    h.seed_session(T0_MS + 120_000, FULL_SCOPE);

    let wire = Arc::new(LlmWire {
        seen: Mutex::new(Vec::new()),
        status: Mutex::new(200),
    });
    let resolver =
        MockResolver::new().with("api.openai.com", vec!["93.184.216.34".parse().unwrap()]);
    let llm_chain = Arc::new(
        DefaultHttpSecurityChain::new(
            Arc::clone(&h.store),
            Arc::new(cap_http::DefaultLeakDetector::new()),
            Arc::new(DefaultSsrfGuard::with_resolver(Box::new(resolver))),
            Arc::new(NoLimit),
            Arc::clone(&wire) as Arc<dyn HttpExecutor>,
        )
        .with_stream_executor(Arc::clone(&wire) as Arc<dyn cap_http::executor::HttpStreamExecutor>),
    );
    let config: advance_runtime::config::RuntimeConfig =
        serde_yml::from_str(PLAN_GATEWAY_CONFIG).expect("config parses");
    assert!(config.llm_providers[0].uses_chatgpt_sign_in());
    let gateway = cap_llm::LlmGateway::new(
        Arc::new(cap_llm::StaticConfig(Arc::new(config))),
        Arc::clone(&llm_chain) as Arc<dyn HttpSecurityChain>,
        Arc::new(cap_llm::PreflightAllowBudget),
        Arc::new(cap_llm::DiscardEventBus),
        Arc::new(cap_llm::NoopRepetition),
        "test-agent".into(),
    )
    .with_live_streaming(
        Arc::clone(&llm_chain)
            as Arc<dyn advance_shared_types::security_validator::HttpStreamingChain>,
        Arc::new(cap_http::DefaultLeakDetector::new()),
    )
    .with_credential_source(Arc::clone(&h.sign_in) as Arc<dyn ProviderCredentialSource>);
    let call = || {
        gateway.chat_for_run(
            vec![cap_llm::ChatMessage {
                role: cap_llm::ChatRole::User,
                content: "hi".into(),
            }],
            cap_llm::ChatParams {
                model: Some("plan".into()),
                temperature: Some(0.5),
                max_tokens: Some(64),
                ..cap_llm::ChatParams::default()
            },
            "run-1".into(),
        )
    };

    let answer = call().await.expect("a buffered call on the plan entry");
    assert_eq!(answer.text, "hello");
    assert_eq!(h.refreshes(), 1, "exactly one renewal");
    let rotated = h.idp.with(|st| st.access.clone().unwrap());
    assert_ne!(rotated, "ACCESS-SEED-zq");
    assert_eq!(h.stored_token().as_deref(), Some(rotated.as_str()));
    let streamed = wire.streamed();
    assert_eq!(streamed.len(), 1);
    assert_eq!(wire.buffered(), 0, "nothing unstreamed is ever sent");
    assert_eq!(streamed[0].url, PLAN_RESPONSES_URL);
    assert_eq!(
        bearer_of(&streamed[0]).as_deref(),
        Some(rotated.as_str()),
        "the request carries the token the renewal just wrote"
    );
    let body: Value = serde_json::from_slice(&streamed[0].body).unwrap();
    assert_eq!(body["stream"], json!(true));
    assert_eq!(body["store"], json!(false));
    assert!(body.get("temperature").is_none() && body.get("max_output_tokens").is_none());

    // The upstream refuses the (unexpired) token once the refusal guard has passed: the next
    // call renews regardless of the expiry and carries the newer token.
    h.clock.advance(Duration::from_secs(61));
    *wire.status.lock().unwrap() = 401;
    assert_eq!(
        call().await.unwrap_err(),
        cap_llm::LlmError::ProviderError("chatgpt-plan: sign-in rejected".into())
    );
    assert_eq!(h.refreshes(), 1, "a refusal itself sends no token request");
    *wire.status.lock().unwrap() = 200;
    assert_eq!(call().await.expect("renewed").text, "hello");
    assert_eq!(h.refreshes(), 2);
    let newer = h.idp.with(|st| st.access.clone().unwrap());
    assert_ne!(newer, rotated);
    let streamed = wire.streamed();
    assert_eq!(streamed.len(), 3);
    assert_eq!(bearer_of(&streamed[1]).as_deref(), Some(rotated.as_str()));
    assert_eq!(bearer_of(&streamed[2]).as_deref(), Some(newer.as_str()));
    assert_eq!(wire.buffered(), 0);
}

// ── custody ──────────────────────────────────────────────────────────────────────────────────

#[test]
fn no_token_code_or_verifier_reaches_debug_errors_or_returned_values() {
    let h = harness();
    let started = sign_in_fully(&h);
    let mut seen = vec![
        format!("{started:?}"),
        format!("{:?}", h.sign_in.status(NAME)),
        format!("{:?}", h.sign_in.verify(NAME)),
        format!("{:?}", h.sign_in),
        format!("{:?}", test_config()),
    ];
    h.clock.advance(Duration::from_secs(3_500));
    seen.push(format!("{:?}", block(h.ensure())));
    h.sign_in.credential_rejected_blocking();
    seen.push(format!("{:?}", h.sign_in.verify(NAME)));
    seen.push(format!("{:?}", h.sign_in.sign_out(NAME)));
    seen.push(format!("{:?}", block(h.ensure())));
    seen.push(format!("{:?}", h.sign_in.start(RECORD)));
    seen.push(format!("{:?}", h.sign_in.cancel(NAME)));
    let again = h.sign_in.start(NAME).unwrap();
    seen.push(format!("{again:?}"));
    let (_, page) = visit_callback(&again, &[("code", "AUTH-CODE-probe-zq"), ("state", "x")]);
    seen.push(page);

    let mut secrets = h.idp.secrets();
    let exchange = &h.idp.token_forms("authorization_code")[0];
    secrets.push(exchange["code_verifier"].clone());
    secrets.push("AUTH-CODE-probe-zq".into());
    assert!(secrets.len() >= 8, "{} secrets", secrets.len());
    for text in &seen {
        for secret in &secrets {
            assert!(
                !text.contains(secret.as_str()),
                "a secret leaked into {text}"
            );
        }
    }
    // The URL handed out never carries the verifier.
    assert!(!started.authorize_url.contains(&exchange["code_verifier"]));
}

impl ChatGptSignIn {
    fn credential_rejected_blocking(&self) {
        block(self.credential_rejected("chatgpt", NAME));
    }
}

// ── fixed vocabulary and production defaults ─────────────────────────────────────────────────

#[test]
fn the_wire_vocabulary_and_fixed_names_are_pinned() {
    let states = [
        (STATE_SIGNED_OUT, "signed-out"),
        (STATE_PENDING, "pending"),
        (STATE_SIGNED_IN, "signed-in"),
        (STATE_FAILED, "failed"),
    ];
    let reasons = [
        (REASON_TIMEOUT, "timeout"),
        (REASON_CANCELLED, "cancelled"),
        (REASON_ACCESS_DENIED, "access-denied"),
        (REASON_AUTHORIZATION_FAILED, "authorization-failed"),
        (REASON_STATE_MISMATCH, "state-mismatch"),
        (REASON_REGISTRATION_INCOMPLETE, "registration-incomplete"),
        (REASON_CLIENT_MISMATCH, "client-mismatch"),
        (REASON_ACCOUNT_MISMATCH, "account-mismatch"),
        (REASON_EXCHANGE_FAILED, "exchange-failed"),
        (REASON_ID_TOKEN_INVALID, "id-token-invalid"),
        (REASON_PLAN_USAGE_NOT_GRANTED, "plan-usage-not-granted"),
        (REASON_SESSION_ENDED, "session-ended"),
        (REASON_REFRESH_UNAVAILABLE, "refresh-unavailable"),
        (REASON_STORE_FAILED, "store-failed"),
        (REASON_UNAVAILABLE, "unavailable"),
        (REASON_NOT_SIGNED_IN, "not-signed-in"),
    ];
    for (constant, literal) in states.iter().chain(reasons.iter()) {
        assert_eq!(constant, literal);
    }
    let distinct: HashSet<&str> = reasons.iter().map(|(c, _)| *c).collect();
    assert_eq!(distinct.len(), reasons.len());
    assert_eq!(CALLBACK_PATH, "/auth/callback");
    assert_eq!(HOST_ID_FILE, "agent-host-id");
}

#[test]
fn production_defaults_are_the_documented_endpoints_and_bounds() {
    let c = ChatGptSignInConfig::default();
    assert_eq!(c.issuer, "https://auth.openai.com");
    assert_eq!(
        c.authorize_endpoint,
        "https://auth.openai.com/api/accounts/authorize"
    );
    assert_eq!(
        c.token_endpoint,
        "https://auth.openai.com/api/accounts/oauth/token"
    );
    assert_eq!(
        c.discovery_endpoint,
        "https://auth.openai.com/.well-known/openid-configuration"
    );
    assert_eq!(
        c.fallback_jwks_uri,
        "https://auth.openai.com/.well-known/jwks.json"
    );
    assert_eq!(
        c.fallback_revocation_endpoint,
        "https://auth.openai.com/api/accounts/oauth/revoke"
    );
    assert_eq!(c.resource, "https://api.openai.com/v1");
    assert_eq!(c.models_endpoint, "https://api.openai.com/v1/models");
    assert_eq!(c.registration_client_id, "dynamic_agent_client");
    assert_eq!(
        c.scopes,
        "openid profile email offline_access resource.invoke chatgpt.tokens.use.direct"
    );
    assert_eq!(c.plan_scope, "chatgpt.tokens.use.direct");
    assert_eq!(c.callback_port, 1455);
    assert_eq!(DEFAULT_CALLBACK_PORT, 1455);
    assert_eq!(c.sign_in_window, Duration::from_secs(10 * 60));
    assert_eq!(SIGN_IN_WINDOW, Duration::from_secs(10 * 60));
    assert_eq!(c.renew_before, Duration::from_secs(5 * 60));
    assert_eq!(RENEW_BEFORE, Duration::from_secs(5 * 60));
    assert_eq!(c.transient_cooldown, Duration::from_secs(30));
    assert_eq!(c.renewal_wait, Duration::from_secs(3));
    assert_eq!(c.dispatch_margin, Duration::from_secs(30));
    assert_eq!(c.revocation_timeout, Duration::from_secs(10));
}

#[test]
fn a_tls_handshake_failure_on_the_code_exchange_is_retried_and_signs_in() {
    // A flaky proxy resets the TLS handshake: no byte of the exchange reached the server, so
    // the one-time code is still unspent and the exchange is sent again.
    let h = harness();
    h.chain.fail_next(
        &token_endpoint(),
        HttpError::Transport(TransportErrorKind::Tls),
    );
    let started = h.sign_in.start(NAME).expect("start");
    let (status, _) = approve(&h, &started, Some(ISSUED));
    assert_eq!(status, 200);
    assert_eq!(h.sign_in.status(NAME).state, STATE_SIGNED_IN);
    assert_eq!(h.chain.attempts_to(&token_endpoint()), 2);
    assert_eq!(
        h.idp.token_forms("authorization_code").len(),
        1,
        "the identity provider saw the code exactly once"
    );
}

#[test]
fn a_failure_after_the_exchange_left_is_not_repeated() {
    // The request may have reached the server: repeating it could present a spent code.
    let h = harness();
    h.chain.fail_next(
        &token_endpoint(),
        HttpError::Transport(TransportErrorKind::Other),
    );
    let started = h.sign_in.start(NAME).expect("start");
    let (status, _) = approve(&h, &started, Some(ISSUED));
    assert_eq!(status, 200);
    let st = h.sign_in.status(NAME);
    assert_eq!(st.state, STATE_FAILED);
    assert_eq!(st.reason, Some(REASON_EXCHANGE_FAILED));
    assert_eq!(h.chain.attempts_to(&token_endpoint()), 1);
}

#[tokio::test]
async fn a_tls_handshake_failure_on_renewal_is_retried() {
    let h = harness();
    h.seed_session(T0_MS + 60_000, FULL_SCOPE);
    h.chain.fail_next(
        &token_endpoint(),
        HttpError::Transport(TransportErrorKind::Tls),
    );
    assert_eq!(h.ensure().await, Ok(()));
    assert_eq!(h.chain.attempts_to(&token_endpoint()), 2);
    assert_eq!(h.idp.token_forms("refresh_token").len(), 1);
}

// ── close (MODULE-001-AC-30 ordered shutdown) ───────────────────────────────────────────────

#[test]
fn module_001_ac30_chatgpt_sign_in_close_is_non_blocking() {
    let h = harness();
    let started = h.sign_in.start(NAME).expect("start");
    let port = port_of(&started);

    let begun = Instant::now();
    h.sign_in.close();
    assert!(
        begun.elapsed() < Duration::from_millis(200),
        "close returns at once, took {:?}",
        begun.elapsed()
    );
    wait_until("the attempt thread exited", || h.sign_in.threads_exited());
    // Its loopback listener is closed.
    assert!(
        TcpStream::connect(SocketAddr::from((Ipv4Addr::LOCALHOST, port))).is_err(),
        "the callback listener is closed"
    );
    // Nothing starts any more.
    assert_eq!(
        h.sign_in.start(NAME),
        Err(SignInRefusal(REASON_UNAVAILABLE)),
        "a sign-in after close is refused"
    );
    assert_eq!(block(h.ensure()), Err(CredentialFailure::Unavailable));
    // Idempotent.
    h.sign_in.close();
    assert!(h.sign_in.threads_exited());
}

#[tokio::test]
async fn module_001_ac30_chatgpt_sign_in_close_lets_the_inflight_renewal_finish_and_persist() {
    let h = harness();
    h.seed_session(T0_MS + 60_000, FULL_SCOPE);
    h.idp
        .with(|st| st.refresh_delay = Duration::from_millis(400));
    // The renewal starts on the renewal thread; this caller stops waiting.
    let gave_up = tokio::time::timeout(Duration::from_millis(50), h.ensure()).await;
    assert!(gave_up.is_err(), "the renewal is still in flight");

    let begun = Instant::now();
    h.sign_in.close();
    assert!(
        begun.elapsed() < Duration::from_millis(200),
        "close never waits"
    );
    assert!(
        !h.sign_in.threads_exited(),
        "the renewal thread finishes the renewal it started"
    );
    assert_eq!(h.ensure().await, Err(CredentialFailure::Unavailable));

    wait_until_async("the renewal thread exited", || h.sign_in.threads_exited()).await;
    // The renewal was neither aborted nor detached: the rotated session is persisted.
    let rotated = h.idp.with(|st| st.refresh.clone());
    assert_ne!(
        rotated.as_deref(),
        Some("REFRESH-SEED-zq"),
        "rotated upstream"
    );
    assert_eq!(
        h.record().unwrap()["session"]["refresh_token"].as_str(),
        rotated.as_deref(),
        "the rotated refresh token is stored"
    );
    assert_eq!(h.refreshes(), 1);
}

#[test]
fn module_001_ac30_chatgpt_sign_in_verify_after_close_starts_no_renewal() {
    // Control: the session is due, so an open sign-in renews on verify.
    let open = harness();
    open.seed_session(T0_MS + 60_000, FULL_SCOPE);
    assert!(open.sign_in.verify(NAME).ok);
    assert_eq!(open.refreshes(), 1, "verify renews a session that is due");

    let h = harness();
    h.seed_session(T0_MS + 60_000, FULL_SCOPE);
    h.sign_in.close();
    let verdict = h.sign_in.verify(NAME);
    assert!(!verdict.ok);
    assert_eq!(verdict.reason, Some(REASON_UNAVAILABLE));
    assert_eq!(h.refreshes(), 0, "no renewal starts after close");
    assert!(h.sign_in.threads_exited());
}

#[test]
fn module_001_ac30_chatgpt_sign_in_threads_exited_waits_for_a_renewal_verify_began() {
    let h = harness();
    h.seed_session(T0_MS + 60_000, FULL_SCOPE);
    let gate = Arc::new(tokio::sync::Notify::new());
    h.idp.with(|st| st.refresh_gate = Some(Arc::clone(&gate)));
    // verify renews on its caller's thread, not on the renewal thread; the identity provider
    // holds the token request.
    let sign_in = Arc::clone(&h.sign_in);
    let verifying = std::thread::spawn(move || sign_in.verify(NAME));
    wait_until(
        "the renewal verify began reached the identity provider",
        || h.refreshes() == 1,
    );

    h.sign_in.close();
    assert!(
        !h.sign_in.threads_exited(),
        "the renewal verify began is still in flight"
    );

    gate.notify_one();
    wait_until("the renewal finished", || h.sign_in.threads_exited());
    // It was awaited, not cut short: the rotated session is persisted.
    let rotated = h.idp.with(|st| st.refresh.clone());
    assert_ne!(
        rotated.as_deref(),
        Some("REFRESH-SEED-zq"),
        "rotated upstream"
    );
    assert_eq!(
        h.record().unwrap()["session"]["refresh_token"].as_str(),
        rotated.as_deref(),
        "the rotated refresh token is stored"
    );
    verifying.join().expect("verify returned");
    assert_eq!(h.refreshes(), 1);
}
