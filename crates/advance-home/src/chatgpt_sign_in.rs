//! Sign in with ChatGPT for a `cloud-http` provider entry whose `auth-source` is
//! `chatgpt-oauth`: an OpenID Connect authorization-code + PKCE client for a public client
//! (system browser, loopback redirect, no client secret) following OpenAI's documented flow for
//! open-source, locally hosted apps, plus the renewal and sign-out of the session it obtains.
//!
//! What a caller can rely on:
//! - **Two secret names per entry**, both in the daemon's live [`SecretStore`]: the CURRENT access
//!   token under the entry's `api-key-secret` (what the egress chain injects as
//!   `Authorization: Bearer`) and the sign-in record (issued client id, account, this host's id,
//!   the renewable session, the model list) under `<api-key-secret>.chatgpt-oauth`. Every change
//!   writes the record first and the access token second, and
//!   [`ProviderCredentialSource::ensure_fresh`] rewrites the access token from the record whenever
//!   the two disagree, so a crash between the two writes heals on the next request. The ID token
//!   is validated and dropped; it is never stored and never sent anywhere.
//! - **Only what it wrote is removed.** An access token is removed only when a record of this
//!   host that completed a sign-in claims the name, and a record is removed only after the access
//!   token, so an interruption never leaves this module's token under a name without such a
//!   record. A value already stored under the entry's name (another secret that happens to share
//!   it) is left untouched until a sign-in completes and replaces it.
//! - **Nothing sensitive is formatted.** Tokens, codes, verifiers, `state` and `nonce` never reach
//!   a `Debug` output, an error value, a returned struct or the callback page; every failure is one
//!   of the fixed `REASON_*` tokens and upstream bytes are never echoed.
//! - **One egress path.** Every outbound request goes through the injected [`HttpSecurityChain`]
//!   with an allowlist of exactly the issuer origin and the API origin; only the model list carries
//!   a credential binding. Only failures that guarantee the request never left (name resolution, a
//!   refused connection, the chain's own rate limit) are retried, except revocation, which is safe
//!   to repeat and is also retried after transport failures and `5xx` answers, within one overall
//!   bound (an unconfirmed revocation is reported as such). A renewal the
//!   egress path refuses, or whose answer is lost, is an ordinary transient failure: the stored
//!   credentials are kept and a later call renews again with the same refresh token (when the lost
//!   answer had rotated it, the authorization server refuses it and the session ends).
//! - **One inbound socket per attempt**: bound on `127.0.0.1` before the authorization URL is
//!   returned, serving only `GET` [`CALLBACK_PATH`] within size and time bounds, answering a static
//!   page that reflects nothing from the request, and closed as soon as the attempt ends (the
//!   model list of a new sign-in is fetched after the socket is closed). A request that does not
//!   carry the attempt's `state` never ends it.
//! - **A registration outlives a failed sign-in.** Once a first-registration callback with the
//!   attempt's `state` names the issued client id, the record keeps it (with no session and no
//!   account yet), so the next sign-in reuses that client instead of registering another. A
//!   callback `error` drops nothing. A registration is dropped, so the next sign-in registers
//!   again, only when the token endpoint rejects the client itself (`invalid_client`), or when it
//!   never completed a sign-in and its last two counted attempts both ended without a code
//!   (`timeout` or `authorization-failed`).
//! - **Renewals are serialized per secret name** and run on a thread this module owns, with its
//!   own runtime: their progress never depends on the caller's runtime, and a renewal that has
//!   started runs to completion even when its caller stops waiting, so a rotating refresh token
//!   is never raced and a rotated one is never dropped. A renewal that failed transiently is not
//!   repeated by callers that arrive within a short cool-down: they get its answer again (the
//!   access token while it still works, `RefreshUnavailable` once it has expired). While the
//!   stored access token still works, with a margin for the request it is about to carry, a
//!   caller does not wait long for a renewal that is not yet required: it uses that token and
//!   the renewal finishes in the background.
//! - The [`ChatGptSignInPort`] methods are sync and run their network work on a dedicated thread
//!   with its own current-thread runtime, so they work from a blocking-pool thread and from a tokio
//!   worker of either runtime flavour.

use std::collections::HashMap;
use std::fmt;
use std::future::Future;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};

use advance_runtime::config::{is_reserved_secret_name, CHATGPT_OAUTH_RECORD_SUFFIX};
use advance_shared_types::security_validator::{
    Allowlist, CredentialBinding, CredentialPosition, HttpCapability, HttpError, HttpMethod,
    HttpRequest, HttpResponse, HttpSecurityChain, TransportErrorKind,
};
use async_trait::async_trait;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use cap_llm::{CredentialFailure, ProviderCredentialSource};
use cap_secrets::{SecretError, SecretStore};
use rand::RngCore as _;
use rsa::pkcs1v15::{Signature as RsaSignature, VerifyingKey};
use rsa::signature::Verifier as _;
use rsa::traits::PublicKeyParts as _;
use rsa::{BigUint, RsaPublicKey};
use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use subtle::ConstantTimeEq as _;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::sync::Notify;
use zeroize::{Zeroize, Zeroizing};

// ── public vocabulary ────────────────────────────────────────────────────────────────────────

/// No sign-in of this installation exists for the secret name.
pub const STATE_SIGNED_OUT: &str = "signed-out";
/// A browser sign-in attempt is in flight.
pub const STATE_PENDING: &str = "pending";
/// A session of this installation exists (it may lack the plan permission; see `plan_usage`).
pub const STATE_SIGNED_IN: &str = "signed-in";
/// The last sign-in attempt failed and no session exists; `reason` says why.
pub const STATE_FAILED: &str = "failed";

/// The sign-in window elapsed before the browser came back.
pub const REASON_TIMEOUT: &str = "timeout";
/// The attempt was cancelled.
pub const REASON_CANCELLED: &str = "cancelled";
/// The user declined in the browser (`error=access_denied`).
pub const REASON_ACCESS_DENIED: &str = "access-denied";
/// The authorization server answered with another error, or without a code.
pub const REASON_AUTHORIZATION_FAILED: &str = "authorization-failed";
/// A callback carried the attempt's `state` more than once, so it cannot be attributed to one
/// authorization answer.
pub const REASON_STATE_MISMATCH: &str = "state-mismatch";
/// A first registration came back without an issued client id.
pub const REASON_REGISTRATION_INCOMPLETE: &str = "registration-incomplete";
/// A returning sign-in came back with a client id other than the registration's.
pub const REASON_CLIENT_MISMATCH: &str = "client-mismatch";
/// A returning sign-in authenticated a different account than the registration's.
pub const REASON_ACCOUNT_MISMATCH: &str = "account-mismatch";
/// The authorization code could not be exchanged for tokens.
pub const REASON_EXCHANGE_FAILED: &str = "exchange-failed";
/// The ID token failed validation (signature, algorithm, issuer, audience, expiry, nonce, subject).
pub const REASON_ID_TOKEN_INVALID: &str = "id-token-invalid";
/// The sign-in holds no permission to use the ChatGPT plan for inference.
pub const REASON_PLAN_USAGE_NOT_GRANTED: &str = "plan-usage-not-granted";
/// The renewable session ended (a terminal renewal answer); a new sign-in is needed.
pub const REASON_SESSION_ENDED: &str = "session-ended";
/// The access token expired and could not be renewed right now; the session is kept.
pub const REASON_REFRESH_UNAVAILABLE: &str = "refresh-unavailable";
/// The secret store could not be read or written.
pub const REASON_STORE_FAILED: &str = "store-failed";
/// The sign-in cannot be served (network, local resources, or a record of another host).
pub const REASON_UNAVAILABLE: &str = "unavailable";
/// No usable sign-in exists.
pub const REASON_NOT_SIGNED_IN: &str = "not-signed-in";

/// Path of the loopback redirect URI. It never changes: the authorization server binds the
/// registration to the redirect URI's scheme, host and path (only the port may vary).
pub const CALLBACK_PATH: &str = "/auth/callback";
/// The file under `<home>/.advance/` holding this installation's host id.
pub const HOST_ID_FILE: &str = "agent-host-id";
/// The preferred callback port; an OS-assigned port is used when it is taken.
pub const DEFAULT_CALLBACK_PORT: u16 = 1455;
/// How long a browser sign-in attempt waits for the callback.
pub const SIGN_IN_WINDOW: Duration = Duration::from_secs(10 * 60);
/// An access token is renewed when less than this much of its lifetime remains.
pub const RENEW_BEFORE: Duration = Duration::from_secs(5 * 60);

/// One model the signed-in account may use, as the model list reported it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignInModel {
    /// The value to pass as `model`.
    pub id: String,
    /// The name to show, when the list carries one.
    pub display_name: Option<String>,
}

/// A started browser sign-in. Carries nothing secret: the URL holds only the public PKCE
/// challenge and the per-attempt `state` / `nonce` the browser has to carry anyway.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignInStarted {
    /// The URL to open in the system browser.
    pub authorize_url: String,
    /// When the attempt stops waiting for the browser (ms since the Unix epoch).
    pub expires_at_ms: u64,
}

/// The sign-in state of one secret name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignInStatus {
    /// One of the `STATE_*` tokens.
    pub state: &'static str,
    /// One of the `REASON_*` tokens, when there is something to explain.
    pub reason: Option<&'static str>,
    /// The e-mail of the validated ID token (display only).
    pub account: Option<String>,
    /// `Some(..)` once signed in: whether the session may use the ChatGPT plan.
    pub plan_usage: Option<bool>,
    /// Pending: the attempt deadline; signed in: the access-token expiry (ms since the epoch).
    pub expires_at_ms: Option<u64>,
    /// Signed in: the models the account may use, as last listed.
    pub models: Vec<SignInModel>,
}

/// The result of a sign-out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SignOutOutcome {
    /// This installation holds no session for the name any more.
    pub signed_out: bool,
    /// The authorization server confirmed the revocation of the renewable session. `false` means
    /// the local tokens are gone but the user may want to disconnect the app in ChatGPT settings.
    pub revocation_confirmed: bool,
}

/// The result of a credential check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyOutcome {
    /// The access token is usable and the model list answered.
    pub ok: bool,
    /// One of the `REASON_*` tokens when `ok` is false.
    pub reason: Option<&'static str>,
    /// The models the account may use (empty when `ok` is false).
    pub models: Vec<SignInModel>,
}

/// A refusal to serve a request, as one fixed `REASON_*` token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SignInRefusal(pub &'static str);

impl fmt::Display for SignInRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}

impl std::error::Error for SignInRefusal {}

/// What the provider admin drives. Sync, object-safe, callable from a blocking-pool thread
/// and from a tokio worker thread alike (never `block_on` a captured handle).
///
/// `secret_name` is the entry's `api-key-secret`. A name that is empty or ends with the reserved
/// record suffix is refused (`unavailable`) or reported signed out.
pub trait ChatGptSignInPort: Send + Sync {
    /// Ensure and return this installation's host id (`urn:uuid:<v4>`), created once and kept
    /// across sign-out.
    fn host_id(&self) -> Result<String, SignInRefusal>;
    /// Start a browser sign-in. The loopback listener is bound before the URL is returned; a
    /// previous attempt for the same name is replaced. A name whose record belongs to another
    /// host is refused.
    fn start(&self, secret_name: &str) -> Result<SignInStarted, SignInRefusal>;
    /// The current state. Never touches the network. A name whose record belongs to another
    /// host reads `signed-out` with reason `unavailable` (a start is refused for it).
    fn status(&self, secret_name: &str) -> SignInStatus;
    /// End the in-flight attempt (if any) and return the resulting state.
    fn cancel(&self, secret_name: &str) -> SignInStatus;
    /// Revoke the renewable session, clear it and the access token, KEEP the registration
    /// (issued client id, account) for a later sign-in. The revocation is bounded as a whole;
    /// when it does not answer in time the local tokens still go and it is reported unconfirmed.
    fn sign_out(&self, secret_name: &str) -> SignOutOutcome;
    /// Renew the access token if needed, then list the models with it.
    fn verify(&self, secret_name: &str) -> VerifyOutcome;
    /// Best-effort revoke, then remove the record and the access token this sign-in wrote (the
    /// entry is gone). A value under the name that no completed sign-in of this host wrote is
    /// left alone, as is a record of another host; a record this version cannot read is left in
    /// place while the access token goes, as on sign-out.
    fn forget(&self, secret_name: &str);
}

/// Endpoints and bounds. [`Default`] is the production configuration; every field can be
/// replaced so tests never contact the network.
#[derive(Debug, Clone)]
pub struct ChatGptSignInConfig {
    /// The issuer: the exact `iss` an ID token must carry, and the origin of every identity
    /// request.
    pub issuer: String,
    /// Opened in the system browser.
    pub authorize_endpoint: String,
    /// Code exchange and renewal.
    pub token_endpoint: String,
    /// The OpenID discovery document (source of `jwks_uri` and `revocation_endpoint`).
    pub discovery_endpoint: String,
    /// Used when discovery cannot be fetched.
    pub fallback_jwks_uri: String,
    /// Used when discovery cannot be fetched or names no revocation endpoint.
    pub fallback_revocation_endpoint: String,
    /// The API the tokens are for (sent as `resource`; its origin is the second allowed origin).
    pub resource: String,
    /// The model list.
    pub models_endpoint: String,
    /// The client id of a first registration (never stored, never used for token requests).
    pub registration_client_id: String,
    /// The requested scopes, space separated.
    pub scopes: String,
    /// The scope that permits inference on the ChatGPT plan.
    pub plan_scope: String,
    /// Preferred callback port; `0` asks the OS for one.
    pub callback_port: u16,
    /// How long an attempt waits for the browser.
    pub sign_in_window: Duration,
    /// Renew when less than this much of the access token's lifetime remains.
    pub renew_before: Duration,
    /// Clock skew tolerated on ID-token time claims.
    pub id_token_leeway: Duration,
    /// How long discovery and the key set are reused before being fetched again.
    pub metadata_ttl: Duration,
    /// Attempts per outbound request (first try included).
    pub request_attempts: u32,
    /// Base delay between attempts (doubles per attempt).
    pub retry_backoff: Duration,
    /// Bound on reading a callback request and writing its page.
    pub callback_read_timeout: Duration,
    /// Callbacks with a foreign (or no) `state` an attempt answers with a page; later ones are
    /// closed unanswered. A foreign `state` never ends the attempt.
    pub max_stray_callbacks: u32,
    /// How long `cancel` (and a replacing `start`) waits for an attempt to release its socket.
    pub cancel_wait: Duration,
    /// A refusal reported less than this long after the session was saved may concern the
    /// access token it replaced: it is dropped without renewing. This also spaces renewals that
    /// refusals trigger.
    pub rejection_guard: Duration,
    /// After a renewal failed transiently, callers within this long (measured on a monotonic
    /// clock) reuse that answer instead of sending another token request: the access token while
    /// it still works, `RefreshUnavailable` once it has expired.
    pub transient_cooldown: Duration,
    /// How long a gateway caller whose stored access token still works waits for a renewal
    /// that is not yet required before it uses that token (the renewal finishes and persists in
    /// the background). Callers that find a renewal already running and the stored token still
    /// working do not wait at all. Both short-cuts need the token to keep working for
    /// `dispatch_margin` past any such wait; otherwise the caller waits for the renewal's answer.
    pub renewal_wait: Duration,
    /// How long the stored access token must still work after a caller stops waiting for a
    /// renewal and uses it, so the request it carries reaches the upstream before it expires.
    pub dispatch_margin: Duration,
    /// Bound on a whole revocation (discovery and every retry included); when it passes, the
    /// revocation counts as unconfirmed.
    pub revocation_timeout: Duration,
}

impl Default for ChatGptSignInConfig {
    fn default() -> Self {
        Self {
            issuer: "https://auth.openai.com".into(),
            authorize_endpoint: "https://auth.openai.com/api/accounts/authorize".into(),
            token_endpoint: "https://auth.openai.com/api/accounts/oauth/token".into(),
            discovery_endpoint: "https://auth.openai.com/.well-known/openid-configuration".into(),
            fallback_jwks_uri: "https://auth.openai.com/.well-known/jwks.json".into(),
            fallback_revocation_endpoint: "https://auth.openai.com/api/accounts/oauth/revoke"
                .into(),
            resource: "https://api.openai.com/v1".into(),
            models_endpoint: "https://api.openai.com/v1/models".into(),
            registration_client_id: "dynamic_agent_client".into(),
            scopes: "openid profile email offline_access resource.invoke chatgpt.tokens.use.direct"
                .into(),
            plan_scope: "chatgpt.tokens.use.direct".into(),
            callback_port: DEFAULT_CALLBACK_PORT,
            sign_in_window: SIGN_IN_WINDOW,
            renew_before: RENEW_BEFORE,
            id_token_leeway: Duration::from_secs(5),
            metadata_ttl: Duration::from_secs(60 * 60),
            request_attempts: 3,
            retry_backoff: Duration::from_millis(250),
            callback_read_timeout: Duration::from_secs(10),
            max_stray_callbacks: 8,
            cancel_wait: Duration::from_secs(5),
            rejection_guard: Duration::from_secs(60),
            transient_cooldown: Duration::from_secs(30),
            renewal_wait: Duration::from_secs(3),
            dispatch_margin: Duration::from_secs(30),
            revocation_timeout: Duration::from_secs(10),
        }
    }
}

/// Clock seam. The wall clock (ms since the Unix epoch) is read for token expiry, ID-token time
/// claims and the reported deadlines; the monotonic clock measures the transient cool-down. The
/// attempt timer itself is a monotonic duration.
pub trait SignInClock: Send + Sync {
    fn now_ms(&self) -> u64;

    /// The monotonic clock the transient cool-down is measured on.
    fn monotonic_now(&self) -> Instant {
        Instant::now()
    }
}

/// The system clock.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemSignInClock;

impl SignInClock for SystemSignInClock {
    fn now_ms(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0)
    }
}

// ── the production object ────────────────────────────────────────────────────────────────────

/// The production sign-in: implements [`ChatGptSignInPort`] (for the provider admin) and
/// [`ProviderCredentialSource`] (for the LLM gateway). Share ONE instance between the two so
/// renewals, sign-in completion and sign-out are serialized against each other.
pub struct ChatGptSignIn {
    inner: Arc<Inner>,
    worker: RenewalWorker,
}

impl ChatGptSignIn {
    /// `home` is the workspace home (the host id lives in `<home>/.advance/`), `store` the
    /// daemon's live secret store, `http` the egress chain identity and API requests go through,
    /// `app_name` the name shown to the user on first registration.
    pub fn new(
        home: impl Into<PathBuf>,
        store: Arc<SecretStore>,
        http: Arc<dyn HttpSecurityChain>,
        app_name: impl Into<String>,
        config: ChatGptSignInConfig,
    ) -> Self {
        Self {
            inner: Arc::new(Inner {
                home: home.into(),
                store,
                http,
                app_name: app_name.into(),
                config,
                clock: RwLock::new(Arc::new(SystemSignInClock)),
                names: Mutex::new(HashMap::new()),
                host_id: Mutex::new(None),
                metadata: Mutex::new(None),
                jwks: Mutex::new(None),
                generation: AtomicU64::new(0),
                closed: AtomicBool::new(false),
                closing: Mutex::new(Vec::new()),
                in_flight: AtomicUsize::new(0),
            }),
            worker: RenewalWorker::default(),
        }
    }

    /// Close the sign-in for an ordered shutdown, without blocking:
    ///
    /// - every sign-in attempt in flight is told to end (its thread closes its loopback
    ///   listener and exits);
    /// - the renewal thread gets no new work: the renewals it already started finish and
    ///   persist the rotated session (a renewal that reached the authorization server has
    ///   already rotated the refresh token), then the thread exits; nothing is aborted;
    /// - from now on no renewal starts: [`ChatGptSignInPort::start`],
    ///   [`ProviderCredentialSource::ensure_fresh`] and [`ChatGptSignInPort::verify`] answer
    ///   `unavailable`. A renewal `verify` began before (it runs on the caller's thread, not
    ///   on the renewal thread) also finishes and persists.
    ///
    /// [`Self::threads_exited`] tells when every such thread and renewal has ended; each is
    /// bounded by its own work (an attempt's model-list request, a renewal's token request).
    /// Idempotent.
    pub fn close(&self) {
        self.inner.closed.store(true, Ordering::SeqCst);
        let names: Vec<Arc<NameState>> = lock(&self.inner.names).values().cloned().collect();
        let mut exited = Vec::new();
        for ns in names {
            let slot = lock(&ns.state).attempt.take();
            if let Some(mut slot) = slot {
                slot.stop.notify_one();
                if let Some(rx) = slot.exited.take() {
                    exited.push(rx);
                }
            }
        }
        lock(&self.inner.closing).extend(exited);
        self.worker.close();
    }

    /// After [`Self::close`]: `true` once every attempt thread it ended and the renewal
    /// thread have exited (the renewal thread is joined then, which returns at once) and no
    /// renewal is running on a caller's thread any more. Non-blocking; an owner polls it.
    pub fn threads_exited(&self) -> bool {
        let attempts_done = {
            let mut closing = lock(&self.inner.closing);
            closing.retain(|exited| {
                !matches!(
                    exited.try_recv(),
                    Err(std::sync::mpsc::TryRecvError::Disconnected)
                )
            });
            closing.is_empty()
        };
        attempts_done
            && self.inner.in_flight.load(Ordering::SeqCst) == 0
            && self.worker.thread_exited()
    }

    /// Override the clock (tests / product composition roots).
    pub fn with_clock(self, clock: Arc<dyn SignInClock>) -> Self {
        *self.inner.clock.write().unwrap_or_else(|e| e.into_inner()) = clock;
        self
    }

    /// End the sign-in window of the attempt in flight for `secret_name` now, exactly as if it
    /// had elapsed.
    #[cfg(test)]
    pub(crate) fn end_sign_in_window(&self, secret_name: &str) {
        let ns = self.inner.name_state(secret_name);
        let st = lock(&ns.state);
        if let Some(slot) = st.attempt.as_ref() {
            slot.window_end.notify_one();
        }
    }
}

impl fmt::Debug for ChatGptSignIn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ChatGptSignIn")
            .field("app_name", &self.inner.app_name)
            .field("issuer", &self.inner.config.issuer)
            .finish_non_exhaustive()
    }
}

impl Drop for ChatGptSignIn {
    fn drop(&mut self) {
        // Attempt threads hold their own handle on the shared state; ending them closes their
        // loopback listeners.
        let names: Vec<Arc<NameState>> = lock(&self.inner.names).values().cloned().collect();
        for ns in names {
            if let Some(slot) = lock(&ns.state).attempt.take() {
                slot.stop.notify_one();
            }
        }
    }
}

impl ChatGptSignInPort for ChatGptSignIn {
    fn host_id(&self) -> Result<String, SignInRefusal> {
        self.inner
            .ensure_host_id()
            .map_err(|()| SignInRefusal(REASON_UNAVAILABLE))
    }

    fn start(&self, secret_name: &str) -> Result<SignInStarted, SignInRefusal> {
        Inner::start(&self.inner, secret_name)
    }

    fn status(&self, secret_name: &str) -> SignInStatus {
        self.inner.status(secret_name)
    }

    fn cancel(&self, secret_name: &str) -> SignInStatus {
        if valid_secret_name(secret_name) {
            let ns = self.inner.name_state(secret_name);
            let _control = lock(&ns.control);
            self.inner.stop_attempt(&ns, Some(REASON_CANCELLED));
        }
        self.inner.status(secret_name)
    }

    fn sign_out(&self, secret_name: &str) -> SignOutOutcome {
        if !valid_secret_name(secret_name) {
            return SignOutOutcome {
                signed_out: false,
                revocation_confirmed: false,
            };
        }
        let ns = self.inner.name_state(secret_name);
        let _control = lock(&ns.control);
        self.inner.stop_attempt(&ns, None);
        let inner = Arc::clone(&self.inner);
        let name = secret_name.to_string();
        let held = Arc::clone(&ns);
        crate::discovery::block_on_io(async move { inner.sign_out(&held, &name).await })
    }

    fn verify(&self, secret_name: &str) -> VerifyOutcome {
        let inner = Arc::clone(&self.inner);
        let name = secret_name.to_string();
        crate::discovery::block_on_io(async move { inner.verify(&name).await })
    }

    fn forget(&self, secret_name: &str) {
        if !valid_secret_name(secret_name) {
            return;
        }
        // The per-name state stays in the map (reset, not removed): a caller already waiting on
        // `control` continues on the same state every later caller sees.
        let ns = self.inner.name_state(secret_name);
        let _control = lock(&ns.control);
        self.inner.stop_attempt(&ns, None);
        let inner = Arc::clone(&self.inner);
        let name = secret_name.to_string();
        let held = Arc::clone(&ns);
        crate::discovery::block_on_io(async move { inner.forget(&held, &name).await });
    }
}

#[async_trait]
impl ProviderCredentialSource for ChatGptSignIn {
    /// `Ok` when the secret under `secret_name` holds an access token valid for the next
    /// request (renewed first when it is about to expire); `NotSignedIn` without a session of
    /// this host, `NotAuthorized` without the plan permission (also when a renewal just dropped
    /// it), `RefreshUnavailable` when an expired token cannot be renewed right now, `Unavailable`
    /// when the store cannot serve. When this host's record of a completed sign-in has no
    /// session, an access token still stored under the name is removed (a clearing interrupted
    /// between its two writes). A value under a name without such a record was not written by
    /// this sign-in and is left alone, as are the names of a record of another host or of one
    /// this version cannot read.
    ///
    /// The work runs on this object's renewal thread: a renewal that reached the authorization
    /// server has already rotated the refresh token, so it runs to completion (and persists)
    /// even when the caller stops waiting, and it never waits on the caller's runtime. While the
    /// stored access token still works for `renewal_wait` plus `dispatch_margin`, a renewal that
    /// is not yet required holds the caller for at most `renewal_wait` (then the caller uses that
    /// token); while it works for `dispatch_margin`, a caller that finds a renewal already
    /// running does not wait for it. A token closer to its expiry is never handed out while its
    /// renewal runs: the caller waits for the renewal's answer.
    async fn ensure_fresh(
        &self,
        _provider_id: &str,
        secret_name: &str,
    ) -> Result<(), CredentialFailure> {
        if self.inner.closed.load(Ordering::SeqCst) {
            return Err(CredentialFailure::Unavailable);
        }
        let inner = Arc::clone(&self.inner);
        let name = secret_name.to_string();
        let (reply, answer) = tokio::sync::oneshot::channel();
        let (usable_tx, usable) = tokio::sync::oneshot::channel();
        let job: Job = Box::pin(async move {
            let mut usable_tx = Some(usable_tx);
            let _ = reply.send(inner.ensure_fresh(&name, false, &mut usable_tx).await);
        });
        match self.worker.submit(job) {
            Ok(()) => {}
            // Closed in the meantime: the job never started.
            Err(Rejected::Closed) => return Err(CredentialFailure::Unavailable),
            // No renewal thread could be started: serve the call here.
            Err(Rejected::NoThread(job)) => job.await,
        }
        let unanswered = || Err(CredentialFailure::Unavailable);
        tokio::pin!(answer);
        tokio::select! {
            biased;
            answered = &mut answer => return answered.unwrap_or_else(|_| unanswered()),
            // Sent only when the stored access token works past the wait plus the dispatch
            // margin and a renewal that is not yet required has begun; a dropped sender
            // disables this branch.
            Ok(()) = usable => {}
        }
        match tokio::time::timeout(self.inner.config.renewal_wait, &mut answer).await {
            Ok(answered) => answered.unwrap_or_else(|_| unanswered()),
            Err(_) => Ok(()),
        }
    }

    /// The next [`Self::ensure_fresh`] renews regardless of the recorded expiry, unless the
    /// stored session was saved less than `rejection_guard` before the refusal was reported
    /// (the refused request may have carried the token that session replaced).
    async fn credential_rejected(&self, _provider_id: &str, secret_name: &str) {
        self.inner.mark_rejected(secret_name);
    }
}

// ── the renewal thread ───────────────────────────────────────────────────────────────────────

type Job = Pin<Box<dyn Future<Output = ()> + Send + 'static>>;

/// A thread owned by one [`ChatGptSignIn`], with its own current-thread runtime, that runs the
/// gateway's renewals. Started on first use; when its owner is dropped or closed it finishes the
/// renewals already started and exits.
#[derive(Default)]
struct RenewalWorker {
    jobs: Mutex<Option<tokio::sync::mpsc::UnboundedSender<Job>>>,
    /// The thread last started, for [`RenewalWorker::thread_exited`].
    thread: Mutex<Option<std::thread::JoinHandle<()>>>,
    /// Set (under the `jobs` lock) by [`RenewalWorker::close`]: no thread is started any more.
    closed: AtomicBool,
}

/// Why [`RenewalWorker::submit`] did not take a job.
enum Rejected {
    /// The worker was closed: the job must not run.
    Closed,
    /// No thread could be started: the caller may run the job itself.
    NoThread(Job),
}

impl RenewalWorker {
    /// Hand `job` to the thread (starting it when needed).
    fn submit(&self, job: Job) -> Result<(), Rejected> {
        let mut slot = lock(&self.jobs);
        if self.closed.load(Ordering::SeqCst) {
            return Err(Rejected::Closed);
        }
        let job = match slot.as_ref() {
            Some(jobs) => match jobs.send(job) {
                Ok(()) => return Ok(()),
                Err(tokio::sync::mpsc::error::SendError(job)) => job,
            },
            None => job,
        };
        let (jobs, queue) = tokio::sync::mpsc::unbounded_channel();
        let spawned = std::thread::Builder::new()
            .name("chatgpt-renewal".into())
            .spawn(move || run_renewal_worker(queue));
        let Ok(thread) = spawned else {
            return Err(Rejected::NoThread(job));
        };
        *lock(&self.thread) = Some(thread);
        let sent = jobs
            .send(job)
            .map_err(|tokio::sync::mpsc::error::SendError(job)| Rejected::NoThread(job));
        *slot = Some(jobs);
        sent
    }

    /// Stop handing work to the thread: the job queue is closed, so the thread runs what it
    /// already holds to completion and exits.
    fn close(&self) {
        let mut slot = lock(&self.jobs);
        self.closed.store(true, Ordering::SeqCst);
        drop(slot.take());
    }

    /// `true` when no renewal thread is running (none was started, or it has exited and is
    /// joined now).
    fn thread_exited(&self) -> bool {
        let mut thread = lock(&self.thread);
        match thread.as_ref() {
            None => true,
            Some(handle) if handle.is_finished() => {
                if let Some(handle) = thread.take() {
                    let _ = handle.join();
                }
                true
            }
            Some(_) => false,
        }
    }
}

fn run_renewal_worker(mut queue: tokio::sync::mpsc::UnboundedReceiver<Job>) {
    // Without a runtime the queued jobs are dropped: their callers answer `Unavailable`.
    let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    else {
        return;
    };
    runtime.block_on(async move {
        let mut running = tokio::task::JoinSet::new();
        loop {
            tokio::select! {
                job = queue.recv() => match job {
                    Some(job) => {
                        running.spawn(job);
                    }
                    None => break,
                },
                Some(_) = running.join_next(), if !running.is_empty() => {}
            }
        }
        // The owner is gone: renewals already started still finish and persist.
        while running.join_next().await.is_some() {}
    });
}

// ── shared state ─────────────────────────────────────────────────────────────────────────────

struct Inner {
    home: PathBuf,
    store: Arc<SecretStore>,
    http: Arc<dyn HttpSecurityChain>,
    app_name: String,
    config: ChatGptSignInConfig,
    clock: RwLock<Arc<dyn SignInClock>>,
    names: Mutex<HashMap<String, Arc<NameState>>>,
    host_id: Mutex<Option<String>>,
    metadata: Mutex<Option<IssuerMetadata>>,
    jwks: Mutex<Option<Arc<JwkSet>>>,
    generation: AtomicU64,
    /// Set by [`ChatGptSignIn::close`]: no attempt starts and no renewal is accepted any more.
    closed: AtomicBool,
    /// The exit receivers of the attempts `close` ended, until each thread has exited.
    closing: Mutex<Vec<std::sync::mpsc::Receiver<()>>>,
    /// Calls of [`Inner::ensure_fresh`] still running, wherever they run (the renewal thread,
    /// or the caller's thread for `verify`), so [`ChatGptSignIn::threads_exited`] also waits
    /// for a renewal that started before `close`.
    in_flight: AtomicUsize,
}

/// Counts one running [`Inner::ensure_fresh`] in [`Inner::in_flight`] until dropped.
struct InFlight<'a>(&'a AtomicUsize);

impl<'a> InFlight<'a> {
    fn enter(count: &'a AtomicUsize) -> Self {
        count.fetch_add(1, Ordering::SeqCst);
        Self(count)
    }
}

impl Drop for InFlight<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Everything kept per secret name. Lock order: `control` → `session` → `state`.
#[derive(Default)]
struct NameState {
    /// Serializes start / cancel / sign-out / forget (attempt replacement).
    control: Mutex<()>,
    /// Serializes every read-modify-write of the session (renewal, completion, sign-out).
    session: tokio::sync::Mutex<()>,
    state: Mutex<NameInner>,
}

#[derive(Default)]
struct NameInner {
    attempt: Option<AttemptSlot>,
    last_failure: Option<&'static str>,
    /// `session-ended` after a terminal renewal, `refresh-unavailable` after a transient one.
    note: Option<&'static str>,
    /// When the upstream last reported a refused access token (wall clock, ms): the next call
    /// renews, unless the stored session is too recent for the refusal to concern it.
    rejected_at_ms: Option<u64>,
    /// When a renewal last failed transiently.
    transient_at: Option<Instant>,
    /// A change the store did not take; it is the authoritative state until it does.
    unsaved: Option<Unsaved>,
    /// The issued client id of a registration-only record and how many attempts in a row over
    /// it ended without a code (see [`Attempt::count_codeless_ending`]). Kept in memory only: a
    /// restart starts the count again.
    codeless_endings: Option<(String, u8)>,
}

/// Attempts in a row that end without a code before a registration-only record is dropped.
const CODELESS_ENDINGS_BEFORE_DROP: u8 = 2;

#[derive(Clone)]
enum Unsaved {
    /// A record whose write failed.
    Record(Record),
    /// The record and the access token were to be removed and at least one removal failed: the
    /// name has no record.
    Removed,
}

struct AttemptSlot {
    generation: u64,
    expires_at_ms: u64,
    stop: Arc<Notify>,
    /// Ends the sign-in window early, exactly as if it had elapsed.
    #[cfg(test)]
    window_end: Arc<Notify>,
    /// Disconnected when the attempt thread has exited (its listener is closed by then).
    exited: Option<std::sync::mpsc::Receiver<()>>,
}

// ── the record ───────────────────────────────────────────────────────────────────────────────

const RECORD_VERSION: u32 = 1;

/// The stored sign-in. A record without `subject` holds only a registration: a first sign-in
/// whose callback named the issued client id but did not complete. It has no session, and the
/// next sign-in reuses its client id.
#[derive(Clone, Serialize, Deserialize)]
struct Record {
    v: u32,
    issuer: String,
    client_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    subject: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    email: Option<String>,
    ext_agent_host_id: String,
    session: Option<Session>,
    #[serde(default)]
    models: Vec<StoredModel>,
}

#[derive(Clone, Serialize, Deserialize)]
struct Session {
    access_token: String,
    /// Absent when the grant carried none (no `offline_access`) or when it can no longer be
    /// used; such a session ends when its access token expires.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    refresh_token: Option<String>,
    token_type: String,
    scopes: Vec<String>,
    expires_at_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    earliest_refresh_at_ms: Option<u64>,
    saved_at_ms: u64,
}

impl Record {
    /// Only a registration of `host` under `issuer` with `client_id`: no account, no session.
    fn is_registration_only(&self, issuer: &str, host: &str, client_id: &str) -> bool {
        self.subject.is_none()
            && self.session.is_none()
            && self.issuer == issuer
            && self.ext_agent_host_id == host
            && self.client_id == client_id
    }
}

impl Session {
    fn has_scope(&self, scope: &str) -> bool {
        self.scopes.iter().any(|s| s == scope)
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        self.access_token.zeroize();
        if let Some(refresh) = self.refresh_token.as_mut() {
            refresh.zeroize();
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
struct StoredModel {
    id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    display_name: Option<String>,
}

impl From<&StoredModel> for SignInModel {
    fn from(m: &StoredModel) -> Self {
        SignInModel {
            id: m.id.clone(),
            display_name: m.display_name.clone(),
        }
    }
}

impl From<&SignInModel> for StoredModel {
    fn from(m: &SignInModel) -> Self {
        StoredModel {
            id: m.id.clone(),
            display_name: m.display_name.clone(),
        }
    }
}

enum Loaded {
    Missing,
    /// Present but not a record this version understands.
    Unreadable,
    /// The store could not be read.
    Failed,
    Found(Record),
}

fn record_name(secret_name: &str) -> String {
    format!("{secret_name}{CHATGPT_OAUTH_RECORD_SUFFIX}")
}

fn valid_secret_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 256
        && !name.chars().any(char::is_control)
        && !is_reserved_secret_name(name)
}

/// Whether the value stored under the entry's name is this module's: `record` is a record of
/// `host` that completed a sign-in (it names an account or holds a session). A completed sign-in
/// writes its record before the access token, and the record is removed only after the access
/// token, so a value under a name that no such record claims was written by something else.
fn claims_access_token(record: &Record, host: Option<&str>) -> bool {
    Some(record.ext_agent_host_id.as_str()) == host
        && (record.subject.is_some() || record.session.is_some())
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

impl Inner {
    fn now_ms(&self) -> u64 {
        self.clock
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .now_ms()
    }

    fn name_state(&self, name: &str) -> Arc<NameState> {
        Arc::clone(lock(&self.names).entry(name.to_string()).or_default())
    }

    fn monotonic_now(&self) -> Instant {
        self.clock
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .monotonic_now()
    }

    fn load_record(&self, ns: &NameState, name: &str) -> Loaded {
        match lock(&ns.state).unsaved.clone() {
            Some(Unsaved::Record(record)) => return Loaded::Found(record),
            Some(Unsaved::Removed) => return Loaded::Missing,
            None => {}
        }
        self.read_stored(name)
    }

    /// The record as the store holds it (an unsaved in-memory change is not consulted).
    fn read_stored(&self, name: &str) -> Loaded {
        match self.store.resolve(&record_name(name)) {
            Ok(value) => match serde_json::from_str::<Record>(value.expose_secret()) {
                Ok(record) if record.v == RECORD_VERSION => Loaded::Found(record),
                _ => Loaded::Unreadable,
            },
            Err(SecretError::NotFound(_)) => Loaded::Missing,
            Err(SecretError::Crypto(_)) | Err(SecretError::InvalidUtf8) => Loaded::Unreadable,
            Err(_) => Loaded::Failed,
        }
    }

    fn write_record(&self, name: &str, record: &Record) -> Result<(), ()> {
        let json = Zeroizing::new(serde_json::to_string(record).map_err(|_| ())?);
        self.store
            .store(&record_name(name), json.as_str())
            .map_err(|_| ())
    }

    /// Write `record`. A failed write keeps it in memory as the authoritative copy (a rotated
    /// refresh token may exist nowhere else; a cleared session must not come back in this
    /// process), retried by the next call. `true` when the store took it.
    fn persist_record(&self, ns: &NameState, name: &str, record: Record) -> bool {
        let written = self.write_record(name, &record).is_ok();
        lock(&ns.state).unsaved = if written {
            None
        } else {
            Some(Unsaved::Record(record))
        };
        written
    }

    /// Remove the access token under `name`. `true` when nothing is stored there any more.
    fn clear_access_token(&self, name: &str) -> bool {
        self.store.remove(name).is_ok()
    }

    /// Remove an access token left under `name` without a session to back it. Nothing is
    /// written when the name holds nothing (this runs on every request of an entry that is not
    /// signed in). Callers have established that the value is this module's (see
    /// [`claims_access_token`]).
    fn remove_leftover_token(&self, name: &str) {
        if !matches!(self.store.exists(name), Ok(false)) {
            self.clear_access_token(name);
        }
    }

    /// Remove this host's record of `name` and, when a record shows the access token is this
    /// module's ([`claims_access_token`]), the access token. A stored record that still holds a
    /// session is first rewritten without it, the access token goes next and the record last,
    /// so an interruption at any step leaves either nothing of this sign-in or a record of this
    /// host without a session (whose leftover access token the next call removes). `known` is
    /// the record the caller acted on, which may be a change the store has not taken yet. A
    /// record of another host, or one this version cannot read, is left alone. `true` when
    /// every step reached the store.
    fn remove_names(&self, name: &str, known: Option<&Record>) -> bool {
        let Ok(host) = self.current_host_id() else {
            return false;
        };
        let stored = match self.read_stored(name) {
            Loaded::Failed => return false,
            Loaded::Found(record) if Some(&record.ext_agent_host_id) == host.as_ref() => {
                Some(record)
            }
            Loaded::Found(_) | Loaded::Missing | Loaded::Unreadable => None,
        };
        let token_is_ours = known
            .into_iter()
            .chain(stored.as_ref())
            .any(|record| claims_access_token(record, host.as_deref()));
        if let Some(record) = stored.as_ref().filter(|r| r.session.is_some()) {
            let mut cleared = record.clone();
            cleared.session = None;
            if self.write_record(name, &cleared).is_err() {
                return false;
            }
        }
        if token_is_ours && !self.clear_access_token(name) {
            return false;
        }
        match stored {
            Some(_) => self.store.remove(&record_name(name)).is_ok(),
            None => true,
        }
    }

    /// Remove the record and the access token this sign-in wrote (the registration is
    /// unusable). When a step fails the name keeps an in-memory tombstone: this process treats
    /// it as having no record and retries the removals on the next call.
    fn drop_registration(&self, ns: &NameState, name: &str, known: Option<&Record>) {
        let done = self.remove_names(name, known);
        lock(&ns.state).unsaved = (!done).then_some(Unsaved::Removed);
    }

    /// Retry a change the store did not take.
    fn flush_unsaved(&self, ns: &NameState, name: &str) {
        let pending = lock(&ns.state).unsaved.clone();
        let done = match pending {
            None => return,
            Some(Unsaved::Record(record)) => self.write_record(name, &record).is_ok(),
            Some(Unsaved::Removed) => self.remove_names(name, None),
        };
        if done {
            lock(&ns.state).unsaved = None;
        }
    }

    /// A tombstone whose removals have not reached the store yet.
    fn removal_pending(&self, ns: &NameState) -> bool {
        matches!(lock(&ns.state).unsaved, Some(Unsaved::Removed))
    }

    /// Make the value under `name` equal the session's access token.
    fn repair(&self, name: &str, session: &Session) -> Result<(), CredentialFailure> {
        let matches = match self.store.resolve(name) {
            Ok(value) => bool::from(
                value
                    .expose_secret()
                    .as_bytes()
                    .ct_eq(session.access_token.as_bytes()),
            ),
            Err(_) => false,
        };
        if matches {
            return Ok(());
        }
        self.store
            .store(name, &session.access_token)
            .map_err(|_| CredentialFailure::Unavailable)
    }

    fn mark_rejected(&self, name: &str) {
        if valid_secret_name(name) {
            let now = self.now_ms();
            lock(&self.name_state(name).state).rejected_at_ms = Some(now);
        }
    }

    /// Whether a reported refusal concerns `session`'s access token. A refusal reported less
    /// than `rejection_guard` after the session was saved may concern the token it replaced (a
    /// request sent before the renewal whose answer came after it): it is dropped unrenewed.
    fn rejection_applies(&self, ns: &NameState, session: &Session) -> bool {
        let guard = self.config.rejection_guard.as_millis() as u64;
        let mut st = lock(&ns.state);
        match st.rejected_at_ms {
            Some(at) if at >= session.saved_at_ms.saturating_add(guard) => true,
            Some(_) => {
                st.rejected_at_ms = None;
                false
            }
            None => false,
        }
    }

    /// Whether `session`'s access token still works `span` from now.
    fn works_for(&self, session: &Session, span: Duration) -> bool {
        self.now_ms().saturating_add(span.as_millis() as u64) < session.expires_at_ms
    }

    /// A renewal failed transiently less than `transient_cooldown` ago (monotonic clock).
    fn cooling_down(&self, ns: &NameState) -> bool {
        let now = self.monotonic_now();
        lock(&ns.state)
            .transient_at
            .is_some_and(|at| now.saturating_duration_since(at) < self.config.transient_cooldown)
    }

    /// Whether a caller that found the session busy (a renewal, a sign-in completion or a
    /// sign-out holds it) may proceed with the access token already stored, without writing
    /// anything: this host's session holds the plan permission, its access token still works
    /// for at least `dispatch_margin`, no refusal concerns it, and the value under the name is
    /// that token. Anything else waits for the session.
    fn usable_while_busy(&self, ns: &NameState, name: &str) -> bool {
        let Ok(Some(host)) = self.current_host_id() else {
            return false;
        };
        let Loaded::Found(record) = self.load_record(ns, name) else {
            return false;
        };
        let Some(session) = record.session.as_ref() else {
            return false;
        };
        if record.ext_agent_host_id != host
            || !session.has_scope(&self.config.plan_scope)
            || !self.works_for(session, self.config.dispatch_margin)
        {
            return false;
        }
        let guard = self.config.rejection_guard.as_millis() as u64;
        let refused = lock(&ns.state)
            .rejected_at_ms
            .is_some_and(|at| at >= session.saved_at_ms.saturating_add(guard));
        if refused {
            return false;
        }
        match self.store.resolve(name) {
            Ok(value) => bool::from(
                value
                    .expose_secret()
                    .as_bytes()
                    .ct_eq(session.access_token.as_bytes()),
            ),
            Err(_) => false,
        }
    }

    // ── host id ──────────────────────────────────────────────────────────────────────────────

    /// This installation's host id when it exists (`Ok(None)` before the first sign-in).
    fn current_host_id(&self) -> Result<Option<String>, ()> {
        if let Some(id) = lock(&self.host_id).clone() {
            return Ok(Some(id));
        }
        let read = read_host_id(&self.home)?;
        if let Some(id) = &read {
            *lock(&self.host_id) = Some(id.clone());
        }
        Ok(read)
    }

    fn ensure_host_id(&self) -> Result<String, ()> {
        let mut cached = lock(&self.host_id);
        if let Some(id) = cached.clone() {
            return Ok(id);
        }
        let id = match read_host_id(&self.home)? {
            Some(id) => id,
            None => create_host_id(&self.home)?,
        };
        *cached = Some(id.clone());
        Ok(id)
    }

    // ── status ───────────────────────────────────────────────────────────────────────────────

    fn status(&self, name: &str) -> SignInStatus {
        if !valid_secret_name(name) {
            return SignInStatus::signed_out(Some(REASON_UNAVAILABLE));
        }
        let ns = self.name_state(name);
        let (pending, last_failure, note) = {
            let st = lock(&ns.state);
            (
                st.attempt.as_ref().map(|a| a.expires_at_ms),
                st.last_failure,
                st.note,
            )
        };
        if let Some(expires_at_ms) = pending {
            return SignInStatus {
                state: STATE_PENDING,
                reason: None,
                account: None,
                plan_usage: None,
                expires_at_ms: Some(expires_at_ms),
                models: Vec::new(),
            };
        }
        let host = match self.current_host_id() {
            Ok(host) => host,
            Err(()) => return SignInStatus::signed_out(Some(REASON_UNAVAILABLE)),
        };
        match self.load_record(&ns, name) {
            Loaded::Found(record) if Some(&record.ext_agent_host_id) == host.as_ref() => {
                if let Some(session) = &record.session {
                    let plan = session.has_scope(&self.config.plan_scope);
                    let reason = if !plan {
                        Some(REASON_PLAN_USAGE_NOT_GRANTED)
                    } else if note == Some(REASON_REFRESH_UNAVAILABLE)
                        && self.now_ms() >= session.expires_at_ms
                    {
                        Some(REASON_REFRESH_UNAVAILABLE)
                    } else {
                        None
                    };
                    return SignInStatus {
                        state: STATE_SIGNED_IN,
                        reason,
                        account: record.email.clone(),
                        plan_usage: Some(plan),
                        expires_at_ms: Some(session.expires_at_ms),
                        models: record.models.iter().map(SignInModel::from).collect(),
                    };
                }
            }
            // Another installation's sign-in (or one stored before this host had an id): not
            // this host's session, and a start is refused for the name, so say why.
            Loaded::Found(_) => return SignInStatus::signed_out(Some(REASON_UNAVAILABLE)),
            Loaded::Failed => return SignInStatus::signed_out(Some(REASON_STORE_FAILED)),
            Loaded::Missing | Loaded::Unreadable => {}
        }
        match last_failure {
            Some(reason) => SignInStatus {
                state: STATE_FAILED,
                reason: Some(reason),
                account: None,
                plan_usage: None,
                expires_at_ms: None,
                models: Vec::new(),
            },
            None => SignInStatus::signed_out(note.filter(|n| *n == REASON_SESSION_ENDED)),
        }
    }

    // ── attempt lifecycle ────────────────────────────────────────────────────────────────────

    /// End the in-flight attempt of `ns` (recording `failure` as the last failure) and wait,
    /// bounded, for its thread to release the loopback socket.
    fn stop_attempt(&self, ns: &NameState, failure: Option<&'static str>) {
        let slot = {
            let mut st = lock(&ns.state);
            let slot = st.attempt.take();
            if slot.is_some() {
                st.last_failure = failure;
            }
            slot
        };
        if let Some(slot) = slot {
            slot.stop.notify_one();
            if let Some(exited) = slot.exited {
                let _ = exited.recv_timeout(self.config.cancel_wait);
            }
        }
    }

    fn start(self: &Arc<Self>, name: &str) -> Result<SignInStarted, SignInRefusal> {
        let refuse = SignInRefusal(REASON_UNAVAILABLE);
        if !valid_secret_name(name) || self.closed.load(Ordering::SeqCst) {
            return Err(refuse);
        }
        let host_id = self.ensure_host_id().map_err(|()| refuse)?;
        let ns = self.name_state(name);
        let _control = lock(&ns.control);
        self.stop_attempt(&ns, None);

        let flow = match self.load_record(&ns, name) {
            // Another installation's session: never replaced from here.
            Loaded::Found(record) if record.ext_agent_host_id != host_id => return Err(refuse),
            Loaded::Found(record) if record.issuer == self.config.issuer => {
                let consent = record
                    .session
                    .as_ref()
                    .is_some_and(|s| !s.has_scope(&self.config.plan_scope));
                Flow::Returning {
                    client_id: record.client_id.clone(),
                    subject: record.subject.clone(),
                    models: record.models.clone(),
                    consent,
                }
            }
            Loaded::Failed => return Err(refuse),
            _ => Flow::First,
        };

        let state = random_token(32);
        let nonce = random_token(32);
        let verifier = pkce_verifier();
        let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
        let listener = bind_callback(self.config.callback_port).map_err(|_| refuse)?;
        let port = listener.local_addr().map_err(|_| refuse)?.port();
        let redirect_uri = format!("http://127.0.0.1:{port}{CALLBACK_PATH}");
        let authorize_url = self
            .authorize_url(&flow, &redirect_uri, &state, &nonce, &challenge, &host_id)
            .ok_or(refuse)?;

        let expires_at_ms = self
            .now_ms()
            .saturating_add(self.config.sign_in_window.as_millis() as u64);
        let generation = self.generation.fetch_add(1, Ordering::SeqCst) + 1;
        let stop = Arc::new(Notify::new());
        let window_end = Arc::new(Notify::new());
        let (exited_tx, exited_rx) = std::sync::mpsc::channel::<()>();
        {
            let mut st = lock(&ns.state);
            // Checked under the state lock `close` takes the attempt slots with: an attempt is
            // either refused here or ended by `close`.
            if self.closed.load(Ordering::SeqCst) {
                return Err(refuse);
            }
            st.attempt = Some(AttemptSlot {
                generation,
                expires_at_ms,
                stop: Arc::clone(&stop),
                #[cfg(test)]
                window_end: Arc::clone(&window_end),
                exited: Some(exited_rx),
            });
            st.last_failure = None;
        }
        let attempt = Arc::new(Attempt {
            inner: Arc::clone(self),
            name_state: Arc::clone(&ns),
            secret_name: name.to_string(),
            generation,
            flow,
            host_id,
            redirect_uri,
            state,
            nonce,
            verifier,
            stray: AtomicU32::new(0),
            claimed: AtomicBool::new(false),
            committed: AtomicBool::new(false),
            stop,
            window_end,
            ended: Notify::new(),
        });
        let thread_attempt = Arc::clone(&attempt);
        let spawned = std::thread::Builder::new()
            .name("chatgpt-sign-in".into())
            .spawn(move || {
                run_attempt_thread(thread_attempt, listener);
                drop(exited_tx);
            });
        if spawned.is_err() {
            attempt.end(Some(REASON_UNAVAILABLE));
            return Err(refuse);
        }
        Ok(SignInStarted {
            authorize_url,
            expires_at_ms,
        })
    }

    fn authorize_url(
        &self,
        flow: &Flow,
        redirect_uri: &str,
        state: &str,
        nonce: &str,
        challenge: &str,
        host_id: &str,
    ) -> Option<String> {
        let mut url = url::Url::parse(&self.config.authorize_endpoint).ok()?;
        {
            let mut query = url.query_pairs_mut();
            query.append_pair("response_type", "code");
            match flow {
                Flow::First => {
                    query.append_pair("client_id", &self.config.registration_client_id);
                }
                Flow::Returning { client_id, .. } => {
                    query.append_pair("client_id", client_id);
                }
            }
            query.append_pair("redirect_uri", redirect_uri);
            query.append_pair("scope", &self.config.scopes);
            query.append_pair("state", state);
            query.append_pair("nonce", nonce);
            query.append_pair("code_challenge", challenge);
            query.append_pair("code_challenge_method", "S256");
            query.append_pair("resource", &self.config.resource);
            query.append_pair("ext_agent_host_id", host_id);
            match flow {
                // The registration's display name, only when registering.
                Flow::First => {
                    query.append_pair("agent_name_hint", &self.app_name);
                }
                // A stored session without the plan permission asks for consent again.
                Flow::Returning { consent: true, .. } => {
                    query.append_pair("prompt", "consent");
                }
                Flow::Returning { .. } => {}
            }
        }
        Some(url.into())
    }

    // ── renewal ──────────────────────────────────────────────────────────────────────────────

    /// `force` renews regardless of expiry, a reported refusal and the transient cool-down (the
    /// caller has just seen the stored token refused). `usable` is sent once the stored access
    /// token is known to work for `renewal_wait` plus `dispatch_margin` while a renewal that is
    /// not yet required begins.
    ///
    /// A caller that finds the session busy and is not forcing proceeds at once when the stored
    /// access token already works for `dispatch_margin` ([`Self::usable_while_busy`]); otherwise
    /// it waits its turn.
    async fn ensure_fresh(
        &self,
        name: &str,
        force: bool,
        usable: &mut Option<tokio::sync::oneshot::Sender<()>>,
    ) -> Result<(), CredentialFailure> {
        // Counted before `closed` is read: `close` followed by `threads_exited` either sees
        // this call, and waits for it, or this call sees `closed` and starts nothing.
        let _in_flight = InFlight::enter(&self.in_flight);
        if self.closed.load(Ordering::SeqCst) || !valid_secret_name(name) {
            return Err(CredentialFailure::Unavailable);
        }
        let ns = self.name_state(name);
        let _session = match ns.session.try_lock() {
            Ok(guard) => guard,
            Err(_) if !force && self.usable_while_busy(&ns, name) => return Ok(()),
            Err(_) => ns.session.lock().await,
        };
        // The wait for the session may have outlasted `close`: no renewal starts after it.
        if self.closed.load(Ordering::SeqCst) {
            return Err(CredentialFailure::Unavailable);
        }
        self.fresh_locked(&ns, name, force, usable).await
    }

    async fn fresh_locked(
        &self,
        ns: &NameState,
        name: &str,
        force: bool,
        usable: &mut Option<tokio::sync::oneshot::Sender<()>>,
    ) -> Result<(), CredentialFailure> {
        let host = self
            .current_host_id()
            .map_err(|()| CredentialFailure::Unavailable)?;
        self.flush_unsaved(ns, name);
        let mut record = match self.load_record(ns, name) {
            Loaded::Found(record) => record,
            Loaded::Failed => return Err(CredentialFailure::Unavailable),
            // No record: nothing under the name was written by this sign-in (a removal always
            // takes the access token before the record), so a value stored there is left alone.
            Loaded::Missing => return Err(CredentialFailure::NotSignedIn),
            // A record this version cannot read may be another installation's: the name is left
            // alone.
            Loaded::Unreadable => return Err(CredentialFailure::NotSignedIn),
        };
        if Some(&record.ext_agent_host_id) != host.as_ref() {
            // Not this installation's record (another host's, or this one has no host id yet):
            // never used, never touched.
            return Err(CredentialFailure::NotSignedIn);
        }
        let Some(session) = record.session.clone() else {
            // The session was cleared. After a completed sign-in an access token still stored
            // under the name is a leftover of a clearing interrupted between its two writes; a
            // registration that never completed one wrote nothing there.
            if claims_access_token(&record, host.as_deref()) {
                self.remove_leftover_token(name);
            }
            return Err(CredentialFailure::NotSignedIn);
        };
        if !session.has_scope(&self.config.plan_scope) {
            return Err(CredentialFailure::NotAuthorized);
        }
        let now = self.now_ms();
        let rejected = force || self.rejection_applies(ns, &session);
        let due = now.saturating_add(self.config.renew_before.as_millis() as u64)
            >= session.expires_at_ms;
        let valid = now < session.expires_at_ms;
        if !rejected && !due {
            return self.repair(name, &session);
        }
        if !rejected && valid && session.earliest_refresh_at_ms.is_some_and(|at| at > now) {
            // The authorization server asked not to renew yet and the token still works.
            return self.repair(name, &session);
        }
        if !force && self.cooling_down(ns) {
            // A renewal failed transiently moments ago: reuse that answer rather than repeating
            // the token request.
            return if valid {
                self.repair(name, &session)
            } else {
                Err(CredentialFailure::RefreshUnavailable)
            };
        }
        if !rejected
            && self.works_for(
                &session,
                self.config
                    .renewal_wait
                    .saturating_add(self.config.dispatch_margin),
            )
            && self.repair(name, &session).is_ok()
        {
            // The renewal is not required yet: the stored token, which outlasts the caller's
            // wait and its request, serves a caller that cannot wait for it.
            if let Some(usable) = usable.take() {
                let _ = usable.send(());
            }
        }
        match self.renew(&record, &session).await {
            Renewal::Renewed(renewed) => {
                let plan = renewed.has_scope(&self.config.plan_scope);
                let token = Zeroizing::new(renewed.access_token.clone());
                record.session = Some(renewed);
                self.persist_record(ns, name, record);
                let stored = self.store.store(name, token.as_str()).is_ok();
                {
                    let mut st = lock(&ns.state);
                    st.rejected_at_ms = None;
                    st.transient_at = None;
                    st.note = None;
                }
                if !stored {
                    Err(CredentialFailure::Unavailable)
                } else if !plan {
                    // The renewed grant no longer carries the plan permission.
                    Err(CredentialFailure::NotAuthorized)
                } else {
                    Ok(())
                }
            }
            Renewal::Ended => {
                self.end_session(ns, name, record);
                Err(CredentialFailure::NotSignedIn)
            }
            Renewal::ClientInvalid => {
                // The registration itself is gone: the next sign-in registers again.
                self.drop_registration(ns, name, Some(&record));
                let mut st = lock(&ns.state);
                st.rejected_at_ms = None;
                st.transient_at = None;
                st.note = Some(REASON_SESSION_ENDED);
                Err(CredentialFailure::NotSignedIn)
            }
            Renewal::Unrenewable => {
                // The session holds no refresh token: its access token serves until it expires
                // and the session then ends. No request was sent, so nothing failed and no
                // cool-down starts.
                if self.now_ms() >= session.expires_at_ms {
                    self.end_session(ns, name, record);
                    return Err(CredentialFailure::NotSignedIn);
                }
                self.repair(name, &session)
            }
            Renewal::Transient => {
                // Credentials are never erased on a transient failure; a reported refusal stays
                // marked so a later call renews again.
                self.note_transient(ns);
                if self.now_ms() < session.expires_at_ms {
                    self.repair(name, &session)
                } else {
                    Err(CredentialFailure::RefreshUnavailable)
                }
            }
        }
    }

    fn note_transient(&self, ns: &NameState) {
        let now = self.monotonic_now();
        let mut st = lock(&ns.state);
        st.note = Some(REASON_REFRESH_UNAVAILABLE);
        st.transient_at = Some(now);
    }

    /// Clear the session (keeping the registration), record first, then the access token. A
    /// record write that fails stays in memory, so this process never uses the session again;
    /// a leftover access token is removed by the next call.
    fn end_session(&self, ns: &NameState, name: &str, mut record: Record) {
        record.session = None;
        self.persist_record(ns, name, record);
        self.clear_access_token(name);
        let mut st = lock(&ns.state);
        st.rejected_at_ms = None;
        st.transient_at = None;
        st.note = Some(REASON_SESSION_ENDED);
    }

    async fn renew(&self, record: &Record, session: &Session) -> Renewal {
        let Some(refresh_token) = session.refresh_token.as_deref() else {
            // Nothing renewable: the session ends when its access token does.
            return Renewal::Unrenewable;
        };
        let request = form_request(
            &self.config.token_endpoint,
            &[
                ("grant_type", "refresh_token"),
                ("client_id", &record.client_id),
                ("refresh_token", refresh_token),
                ("resource", &self.config.resource),
            ],
        );
        let mut response = match self.send(request, None, Retry::NeverLeft).await {
            Ok(response) => response,
            Err(_) => return Renewal::Transient,
        };
        let renewal = if response.status == 200 {
            match parse_token_response(&response.body) {
                Some(tokens) => Renewal::Renewed(self.session_from(&tokens, Some(session))),
                None => Renewal::Transient,
            }
        } else {
            match oauth_error_code(&response.body).as_deref() {
                Some(code) if TERMINAL_REFRESH_ERRORS.contains(&code) => Renewal::Ended,
                Some("invalid_client") => Renewal::ClientInvalid,
                _ => Renewal::Transient,
            }
        };
        response.body.zeroize();
        renewal
    }

    /// A session from a token response. Fields the response omits keep the previous session's
    /// values (a refresh without `scope` retains the grant); a first grant without `scope` holds
    /// the requested set.
    fn session_from(&self, tokens: &TokenSet, previous: Option<&Session>) -> Session {
        let now = self.now_ms();
        Session {
            access_token: tokens.access_token.as_str().to_string(),
            refresh_token: tokens
                .refresh_token
                .as_ref()
                .map(|t| t.as_str().to_string())
                .or_else(|| previous.and_then(|p| p.refresh_token.clone())),
            token_type: "Bearer".into(),
            scopes: tokens
                .scopes
                .clone()
                .or_else(|| previous.map(|p| p.scopes.clone()))
                .unwrap_or_else(|| {
                    self.config
                        .scopes
                        .split_whitespace()
                        .map(String::from)
                        .collect()
                }),
            expires_at_ms: now.saturating_add(tokens.expires_in_s.saturating_mul(1000)),
            earliest_refresh_at_ms: tokens.earliest_refresh_at_ms,
            saved_at_ms: now,
        }
    }

    // ── verify / models ──────────────────────────────────────────────────────────────────────

    async fn verify(&self, name: &str) -> VerifyOutcome {
        let failed = |reason| VerifyOutcome {
            ok: false,
            reason: Some(reason),
            models: Vec::new(),
        };
        // One more round after the model list refused the token it just carried: that refusal
        // forces a renewal.
        for round in 0..2 {
            if let Err(failure) = self.ensure_fresh(name, round == 1, &mut None).await {
                return failed(self.reason_for(name, failure));
            }
            match self.refresh_models(name).await {
                Ok(models) => {
                    return VerifyOutcome {
                        ok: true,
                        reason: None,
                        models,
                    }
                }
                Err(ModelsError::Rejected) if round == 0 => {}
                Err(_) => return failed(REASON_UNAVAILABLE),
            }
        }
        failed(REASON_UNAVAILABLE)
    }

    fn reason_for(&self, name: &str, failure: CredentialFailure) -> &'static str {
        match failure {
            CredentialFailure::NotSignedIn => {
                if valid_secret_name(name)
                    && lock(&self.name_state(name).state).note == Some(REASON_SESSION_ENDED)
                {
                    REASON_SESSION_ENDED
                } else {
                    REASON_NOT_SIGNED_IN
                }
            }
            CredentialFailure::NotAuthorized => REASON_PLAN_USAGE_NOT_GRANTED,
            CredentialFailure::RefreshUnavailable => REASON_REFRESH_UNAVAILABLE,
            CredentialFailure::Unavailable => REASON_UNAVAILABLE,
        }
    }

    /// List the models with the access token stored under `name` and keep the list in the record.
    async fn refresh_models(&self, name: &str) -> Result<Vec<SignInModel>, ModelsError> {
        let request = HttpRequest {
            method: HttpMethod::Get,
            url: self.config.models_endpoint.clone(),
            headers: vec![
                ("Accept".into(), "application/json".into()),
                ("Authorization".into(), format!("Bearer {{{name}}}")),
            ],
            body: Vec::new(),
        };
        let response = self
            .send(request, Some(name), Retry::NeverLeft)
            .await
            .map_err(|_| ModelsError::Unavailable)?;
        if response.status == 401 {
            return Err(ModelsError::Rejected);
        }
        if response.status != 200 {
            return Err(ModelsError::Unavailable);
        }
        let models = parse_models(&response.body).ok_or(ModelsError::Unavailable)?;
        let ns = self.name_state(name);
        let _session = ns.session.lock().await;
        if let Loaded::Found(mut record) = self.load_record(&ns, name) {
            if record.session.is_some() {
                record.models = models.iter().map(StoredModel::from).collect();
                self.persist_record(&ns, name, record);
            }
        }
        Ok(models)
    }

    // ── sign-out / forget ────────────────────────────────────────────────────────────────────

    async fn sign_out(&self, ns: &NameState, name: &str) -> SignOutOutcome {
        let _session = ns.session.lock().await;
        self.flush_unsaved(ns, name);
        let host = self.current_host_id();
        let outcome = match (self.load_record(ns, name), host) {
            (Loaded::Failed, _) | (_, Err(())) => {
                return SignOutOutcome {
                    signed_out: false,
                    revocation_confirmed: false,
                }
            }
            // Another installation's session is not this one's to end.
            (Loaded::Found(record), Ok(host))
                if Some(&record.ext_agent_host_id) != host.as_ref() =>
            {
                return SignOutOutcome {
                    signed_out: true,
                    revocation_confirmed: false,
                }
            }
            (Loaded::Found(mut record), Ok(host)) => {
                let confirmed = match &record.session {
                    Some(session) => self.revoke(&record.client_id, session).await,
                    None => false,
                };
                // Local tokens go whether or not the revocation was confirmed; the
                // registration stays for a later sign-in. A cleared record the store did not
                // take stays in memory (this process never uses the session again), but the
                // outcome says the name is not clear yet, so the caller can retry. A
                // registration that never completed a sign-in wrote no access token, so a value
                // under the name is not its to remove.
                let claims = claims_access_token(&record, host.as_deref());
                record.session = None;
                let written = self.persist_record(ns, name, record);
                let cleared = !claims || self.clear_access_token(name);
                SignOutOutcome {
                    signed_out: written && cleared,
                    revocation_confirmed: confirmed,
                }
            }
            // No record (the removals of a dropped one were retried above): no session of this
            // sign-in exists, and a value under the name is not its to remove.
            (Loaded::Missing, Ok(_)) => SignOutOutcome {
                signed_out: !self.removal_pending(ns),
                revocation_confirmed: false,
            },
            // A record this version cannot read is left alone (it may be another installation's,
            // or hold a session it cannot revoke); the access token this installation would use
            // goes, and the outcome says the name is not known to be clear.
            (Loaded::Unreadable, Ok(_)) => {
                self.clear_access_token(name);
                SignOutOutcome {
                    signed_out: false,
                    revocation_confirmed: false,
                }
            }
        };
        let mut st = lock(&ns.state);
        st.rejected_at_ms = None;
        st.transient_at = None;
        st.note = None;
        st.last_failure = None;
        outcome
    }

    async fn forget(&self, ns: &NameState, name: &str) {
        let _session = ns.session.lock().await;
        let host = self.current_host_id();
        let complete = match (self.load_record(ns, name), host) {
            (Loaded::Found(record), Ok(Some(host))) if record.ext_agent_host_id == host => {
                if let Some(session) = &record.session {
                    let _ = self.revoke(&record.client_id, session).await;
                }
                self.remove_names(name, Some(&record))
            }
            // No record in this process: only the removals of a dropped one remain, if any. A
            // value under the name is not this sign-in's to remove.
            (Loaded::Missing, Ok(_)) => !self.removal_pending(ns) || self.remove_names(name, None),
            // A record this version cannot read is left alone (it may be another
            // installation's); the access token this installation would use goes, as on
            // sign-out.
            (Loaded::Unreadable, Ok(_)) => {
                self.clear_access_token(name);
                true
            }
            // A record of another host is left alone.
            _ => true,
        };
        // A removal the store did not take leaves a tombstone, so the sign-in does not come back
        // in this process and the removals are retried.
        *lock(&ns.state) = NameInner {
            unsaved: (!complete).then_some(Unsaved::Removed),
            ..NameInner::default()
        };
    }

    /// Revoke the renewable session. `true` only when the server answered `200` (an empty
    /// `200` is success, also for an already invalid token) within `revocation_timeout`, which
    /// bounds discovery and every retry together.
    async fn revoke(&self, client_id: &str, session: &Session) -> bool {
        let Some(refresh_token) = session.refresh_token.as_deref() else {
            return false;
        };
        let revocation = async {
            let endpoint = self.issuer_metadata().await.revocation_endpoint;
            let request = form_request(
                &endpoint,
                &[
                    ("token", refresh_token),
                    ("token_type_hint", "refresh_token"),
                    ("client_id", client_id),
                ],
            );
            matches!(
                self.send(request, None, Retry::Repeatable).await,
                Ok(response) if response.status == 200
            )
        };
        tokio::time::timeout(self.config.revocation_timeout, revocation)
            .await
            .unwrap_or(false)
    }

    // ── code exchange ────────────────────────────────────────────────────────────────────────

    async fn exchange_code(
        &self,
        client_id: &str,
        code: &str,
        verifier: &str,
        redirect_uri: &str,
    ) -> Result<TokenSet, ExchangeFailure> {
        let request = form_request(
            &self.config.token_endpoint,
            &[
                ("grant_type", "authorization_code"),
                ("client_id", client_id),
                ("code", code),
                ("code_verifier", verifier),
                ("redirect_uri", redirect_uri),
                ("resource", &self.config.resource),
            ],
        );
        let mut response = self
            .send(request, None, Retry::NeverLeft)
            .await
            .map_err(|_| ExchangeFailure::Failed)?;
        let outcome = if response.status == 200 {
            parse_token_response(&response.body).ok_or(ExchangeFailure::Failed)
        } else if oauth_error_code(&response.body).as_deref() == Some("invalid_client") {
            Err(ExchangeFailure::ClientInvalid)
        } else {
            Err(ExchangeFailure::Failed)
        };
        response.body.zeroize();
        outcome
    }

    // ── ID token ─────────────────────────────────────────────────────────────────────────────

    /// RS256 only, against the issuer's published keys; `iss`, `aud` (the issued client id),
    /// `exp`, `nonce` and `sub` are checked. An unfamiliar key id fetches the key set once more.
    async fn validate_id_token(
        &self,
        token: &str,
        client_id: &str,
        nonce: &str,
    ) -> Result<IdentityClaims, &'static str> {
        const INVALID: &str = REASON_ID_TOKEN_INVALID;
        if token.len() > MAX_TOKEN_BYTES {
            return Err(INVALID);
        }
        let mut parts = token.split('.');
        let (Some(header_part), Some(payload_part), Some(signature_part), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(INVALID);
        };
        let header = decode_json_segment(header_part).ok_or(INVALID)?;
        if header.get("alg").and_then(Value::as_str) != Some("RS256")
            || header.get("crit").is_some()
        {
            return Err(INVALID);
        }
        let kid = match header.get("kid") {
            None => None,
            Some(Value::String(kid)) => Some(kid.clone()),
            Some(_) => return Err(INVALID),
        };
        let signature = URL_SAFE_NO_PAD
            .decode(signature_part)
            .map_err(|_| INVALID)?;
        let signing_input = &token[..header_part.len() + 1 + payload_part.len()];
        self.verify_signature(kid.as_deref(), signing_input.as_bytes(), &signature)
            .await?;
        let claims = decode_json_segment(payload_part).ok_or(INVALID)?;
        check_id_claims(
            &claims,
            &self.config.issuer,
            client_id,
            nonce,
            self.now_ms(),
            self.config.id_token_leeway.as_millis() as u64,
        )
        .ok_or(INVALID)
    }

    async fn verify_signature(
        &self,
        kid: Option<&str>,
        signing_input: &[u8],
        signature: &[u8],
    ) -> Result<(), &'static str> {
        let keys = self.signing_keys(false).await.ok_or(REASON_UNAVAILABLE)?;
        if let Some(kid) = kid {
            if !keys.knows(kid) {
                // The issuer may have rotated its keys since they were fetched.
                let fresh = self.signing_keys(true).await.ok_or(REASON_UNAVAILABLE)?;
                return fresh.verify(Some(kid), signing_input, signature);
            }
        }
        keys.verify(kid, signing_input, signature)
    }

    async fn signing_keys(&self, refetch: bool) -> Option<Arc<JwkSet>> {
        let now = self.now_ms();
        let ttl = self.config.metadata_ttl.as_millis() as u64;
        if !refetch {
            if let Some(set) = lock(&self.jwks).clone() {
                if now.saturating_sub(set.fetched_at_ms) < ttl {
                    return Some(set);
                }
            }
        }
        let jwks_uri = self.issuer_metadata().await.jwks_uri;
        let request = get_request(&jwks_uri);
        let response = self.send(request, None, Retry::NeverLeft).await.ok()?;
        if response.status != 200 {
            return None;
        }
        let set = Arc::new(parse_jwks(&response.body, now)?);
        *lock(&self.jwks) = Some(Arc::clone(&set));
        Some(set)
    }

    /// Discovery (cached for `metadata_ttl`), or the documented fallbacks when it cannot be
    /// fetched, names another issuer, or points outside the issuer origin.
    async fn issuer_metadata(&self) -> IssuerMetadata {
        let now = self.now_ms();
        let ttl = self.config.metadata_ttl.as_millis() as u64;
        if let Some(metadata) = lock(&self.metadata).clone() {
            if now.saturating_sub(metadata.fetched_at_ms) < ttl {
                return metadata;
            }
        }
        match self.fetch_discovery(now).await {
            Some(metadata) => {
                *lock(&self.metadata) = Some(metadata.clone());
                metadata
            }
            None => IssuerMetadata {
                jwks_uri: self.config.fallback_jwks_uri.clone(),
                revocation_endpoint: self.config.fallback_revocation_endpoint.clone(),
                fetched_at_ms: now,
            },
        }
    }

    async fn fetch_discovery(&self, now: u64) -> Option<IssuerMetadata> {
        let request = get_request(&self.config.discovery_endpoint);
        let response = self.send(request, None, Retry::NeverLeft).await.ok()?;
        if response.status != 200 {
            return None;
        }
        let document = parse_json(&response.body)?;
        if document.get("issuer").and_then(Value::as_str) != Some(self.config.issuer.as_str()) {
            return None;
        }
        let jwks_uri = document
            .get("jwks_uri")
            .and_then(Value::as_str)
            .filter(|u| same_origin(u, &self.config.issuer))?
            .to_string();
        let revocation_endpoint = document
            .get("revocation_endpoint")
            .and_then(Value::as_str)
            .filter(|u| same_origin(u, &self.config.issuer))
            .map(String::from)
            .unwrap_or_else(|| self.config.fallback_revocation_endpoint.clone());
        Some(IssuerMetadata {
            jwks_uri,
            revocation_endpoint,
            fetched_at_ms: now,
        })
    }

    // ── transport ────────────────────────────────────────────────────────────────────────────

    /// Allowlist of exactly the issuer origin and the API origin; a credential binding only
    /// when `bearer` names the secret to inject.
    fn capability(&self, bearer: Option<&str>) -> HttpCapability {
        HttpCapability {
            allowlist: Allowlist {
                patterns: [&self.config.issuer, &self.config.resource]
                    .into_iter()
                    .filter_map(|u| origin_prefix(u.as_str()))
                    .collect(),
            },
            credentials: bearer
                .map(|name| {
                    vec![CredentialBinding {
                        position: CredentialPosition::BearerToken,
                        secret_name: name.to_string(),
                    }]
                })
                .unwrap_or_default(),
            component_id: COMPONENT_ID.into(),
        }
    }

    async fn send(
        &self,
        mut request: HttpRequest,
        bearer: Option<&str>,
        retry: Retry,
    ) -> Result<HttpResponse, HttpError> {
        let capability = self.capability(bearer);
        let attempts = self.config.request_attempts.max(1);
        let mut attempt = 1;
        let result = loop {
            let result = self
                .http
                .execute(COMPONENT_ID, request.clone(), &capability)
                .await;
            let again = attempt < attempts
                && match (&result, retry) {
                    (Err(e), _) if never_left(e) => true,
                    (Err(HttpError::Transport(_)), Retry::Repeatable) => true,
                    (Ok(r), Retry::Repeatable) => r.status >= 500,
                    _ => false,
                };
            if !again {
                break result;
            }
            let base = self
                .config
                .retry_backoff
                .saturating_mul(1 << (attempt - 1).min(4));
            let delay = match &result {
                Err(HttpError::RateLimited { retry_after_ms }) => {
                    base.max(Duration::from_millis((*retry_after_ms).min(2_000)))
                }
                _ => base,
            };
            tokio::time::sleep(delay).await;
            attempt += 1;
        };
        request.body.zeroize();
        result
    }
}

/// Failures after which the request certainly never reached the server: the connection was
/// never established (DNS, TCP connect, or the TLS handshake — HTTP writes nothing before the
/// handshake completes), or the local rate limiter held it back. A one-time authorization
/// code or a rotating refresh token is still unspent after any of these.
fn never_left(e: &HttpError) -> bool {
    matches!(
        e,
        HttpError::Transport(TransportErrorKind::Dns)
            | HttpError::Transport(TransportErrorKind::ConnectionRefused)
            | HttpError::Transport(TransportErrorKind::Tls)
            | HttpError::RateLimited { .. }
    )
}

#[derive(Clone, Copy)]
enum Retry {
    /// Retry only when the request certainly never left (token requests are not repeatable:
    /// a repeated renewal would present a refresh token that was already rotated).
    NeverLeft,
    /// Also retry transport failures and `5xx` answers (revocation is idempotent).
    Repeatable,
}

enum Renewal {
    Renewed(Session),
    /// A terminal answer: the renewable session is unusable.
    Ended,
    /// `invalid_client`: the registration itself is unusable.
    ClientInvalid,
    /// No refresh token: the access token serves until it expires.
    Unrenewable,
    /// Anything else: keep the credentials.
    Transient,
}

enum ExchangeFailure {
    /// `invalid_client`: the authorization server no longer accepts the client.
    ClientInvalid,
    /// Anything else.
    Failed,
}

enum ModelsError {
    Rejected,
    Unavailable,
}

const TERMINAL_REFRESH_ERRORS: [&str; 6] = [
    "invalid_grant",
    "invalid_refresh_token",
    "token_expired",
    "refresh_token_expired",
    "refresh_token_invalidated",
    "refresh_token_reused",
];

const COMPONENT_ID: &str = "advance-home/chatgpt-sign-in";
const MAX_JSON_BYTES: usize = 1024 * 1024;
const MAX_TOKEN_BYTES: usize = 16 * 1024;
const MAX_CALLBACK_REQUEST_BYTES: usize = 8 * 1024;
const MAX_CALLBACK_CONNECTIONS: usize = 16;
const MAX_MODELS: usize = 256;
const MAX_JWKS_KEYS: usize = 32;
const MIN_RSA_BITS: usize = 2048;
/// The documented access-token lifetime, assumed when a token response omits `expires_in`.
const DEFAULT_TOKEN_LIFETIME_S: u64 = 3600;
const MAX_TOKEN_LIFETIME_S: u64 = 7 * 24 * 3600;

// ── the browser attempt ──────────────────────────────────────────────────────────────────────

enum Flow {
    First,
    Returning {
        client_id: String,
        /// `None` for a registration whose first sign-in did not complete: any account the
        /// client accepts completes it.
        subject: Option<String>,
        models: Vec<StoredModel>,
        consent: bool,
    },
}

struct Attempt {
    inner: Arc<Inner>,
    name_state: Arc<NameState>,
    secret_name: String,
    generation: u64,
    flow: Flow,
    host_id: String,
    redirect_uri: String,
    state: Zeroizing<String>,
    nonce: Zeroizing<String>,
    verifier: Zeroizing<String>,
    stray: AtomicU32,
    claimed: AtomicBool,
    /// The sign-in was persisted: the model list is fetched once the listener is closed.
    committed: AtomicBool,
    stop: Arc<Notify>,
    window_end: Arc<Notify>,
    ended: Notify,
}

impl Attempt {
    fn is_current(&self) -> bool {
        lock(&self.name_state.state)
            .attempt
            .as_ref()
            .is_some_and(|a| a.generation == self.generation)
    }

    /// End this attempt unless something else already did. `true` when this call ended it.
    fn end(&self, failure: Option<&'static str>) -> bool {
        let mut st = lock(&self.name_state.state);
        if st
            .attempt
            .as_ref()
            .is_some_and(|a| a.generation == self.generation)
        {
            st.attempt = None;
            st.last_failure = failure;
            true
        } else {
            false
        }
    }

    fn fail(&self, reason: &'static str) -> Result<(), &'static str> {
        self.end(Some(reason));
        Err(reason)
    }

    /// End this attempt as `authorization-failed`: the browser came back without a code.
    async fn fail_without_code(&self) -> Result<(), &'static str> {
        if self.end(Some(REASON_AUTHORIZATION_FAILED)) {
            self.count_codeless_ending().await;
        }
        Err(REASON_AUTHORIZATION_FAILED)
    }

    /// Count an ending without a code (`timeout`, `authorization-failed`) of an attempt started
    /// over a registration-only record. The second such ending in a row drops that record, so
    /// the next sign-in registers again: a registration that never completed a sign-in and keeps
    /// coming back without a code is presumed unusable.
    ///
    /// The count follows one record: a code coming back, a completed sign-in, or a stored record
    /// other than the one the attempt started from resets it. Endings the user chose (declining,
    /// cancelling, starting another attempt) and the other failures neither count nor reset it.
    /// The record is dropped only while the stored record is still that registration-only
    /// record.
    async fn count_codeless_ending(&self) {
        let Flow::Returning {
            client_id,
            subject: None,
            ..
        } = &self.flow
        else {
            return;
        };
        let inner = &self.inner;
        let _session = self.name_state.session.lock().await;
        let same = match inner.load_record(&self.name_state, &self.secret_name) {
            Loaded::Found(record) => {
                record.is_registration_only(&inner.config.issuer, &self.host_id, client_id)
            }
            _ => false,
        };
        let mut st = lock(&self.name_state.state);
        if !same {
            st.codeless_endings = None;
            return;
        }
        let count = match &st.codeless_endings {
            Some((counted, n)) if counted == client_id => n.saturating_add(1),
            _ => 1,
        };
        if count < CODELESS_ENDINGS_BEFORE_DROP {
            st.codeless_endings = Some((client_id.clone(), count));
            return;
        }
        st.codeless_endings = None;
        drop(st);
        // A registration-only record wrote no access token: only the record goes.
        inner.drop_registration(&self.name_state, &self.secret_name, None);
    }

    /// One request to the callback path; `None` closes the connection unanswered. A request
    /// without this attempt's `state` never ends it: it is answered (up to the stray bound) and
    /// ignored. The first request with the right `state` decides the attempt.
    async fn callback(&self, query: &str) -> Option<(u16, &'static str)> {
        if !self.is_current() {
            return Some((400, PAGE_INACTIVE));
        }
        let params = CallbackParams::parse(query, &self.state);
        match params.state {
            StateCheck::Matches => {}
            StateCheck::Foreign => {
                let answered = self
                    .stray
                    .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| {
                        Some(n.saturating_add(1))
                    })
                    .unwrap_or(u32::MAX)
                    < self.inner.config.max_stray_callbacks;
                return answered.then_some((400, PAGE_INACTIVE));
            }
            StateCheck::Repeated => {
                // Only a party that knows the `state` can send this, and it cannot be tied to
                // one authorization answer.
                if self.claimed.swap(true, Ordering::SeqCst) {
                    return Some((409, PAGE_INACTIVE));
                }
                if self.end(Some(REASON_STATE_MISMATCH)) {
                    self.ended.notify_one();
                }
                return Some((200, PAGE_FAILED));
            }
        }
        if self.claimed.swap(true, Ordering::SeqCst) {
            return Some((409, PAGE_INACTIVE));
        }
        let outcome = self.complete(params).await;
        if outcome.is_ok() {
            self.committed.store(true, Ordering::SeqCst);
        }
        // Lets the listener close at once; the page is still written to this connection.
        self.ended.notify_one();
        Some(match outcome {
            Ok(()) => (200, PAGE_SIGNED_IN),
            Err(_) => (200, PAGE_FAILED),
        })
    }

    async fn complete(&self, params: CallbackParams) -> Result<(), &'static str> {
        match &params.error {
            Param::Absent => {}
            Param::One(error) if error.as_str() == "access_denied" => {
                return self.fail(REASON_ACCESS_DENIED)
            }
            // Any other error (`invalid_client` and `unauthorized_client` included) fails the
            // attempt and drops nothing: neither the registration nor a session.
            _ => return self.fail_without_code().await,
        }
        let code = match &params.code {
            Param::One(code) if is_token_text(code) => code,
            _ => return self.fail_without_code().await,
        };
        // A code came back: attempts that ended without one say nothing about the registration
        // any more.
        lock(&self.name_state.state).codeless_endings = None;
        let client_id = match (&self.flow, &params.client_id) {
            (Flow::First, Param::One(id))
                if is_client_id(id) && id.as_str() != self.inner.config.registration_client_id =>
            {
                id.as_str().to_string()
            }
            (Flow::First, _) => return self.fail(REASON_REGISTRATION_INCOMPLETE),
            (Flow::Returning { client_id, .. }, Param::Absent) => client_id.clone(),
            (Flow::Returning { client_id, .. }, Param::One(id))
                if bool::from(id.as_bytes().ct_eq(client_id.as_bytes())) =>
            {
                client_id.clone()
            }
            (Flow::Returning { .. }, _) => return self.fail(REASON_CLIENT_MISMATCH),
        };
        if matches!(self.flow, Flow::First) {
            // The issued client exists from here on, whatever happens next.
            self.retain_registration(&client_id).await;
        }
        let tokens = match self
            .inner
            .exchange_code(&client_id, code, &self.verifier, &self.redirect_uri)
            .await
        {
            Ok(tokens) => tokens,
            Err(ExchangeFailure::ClientInvalid) => {
                self.drop_dead_registration(&client_id).await;
                return self.fail(REASON_EXCHANGE_FAILED);
            }
            Err(ExchangeFailure::Failed) => return self.fail(REASON_EXCHANGE_FAILED),
        };
        let Some(id_token) = tokens.id_token.as_ref() else {
            return self.fail(REASON_ID_TOKEN_INVALID);
        };
        let identity = match self
            .inner
            .validate_id_token(id_token, &client_id, &self.nonce)
            .await
        {
            Ok(identity) => identity,
            Err(reason) => return self.fail(reason),
        };
        let models = match &self.flow {
            Flow::Returning {
                subject: Some(subject),
                ..
            } if *subject != identity.subject => return self.fail(REASON_ACCOUNT_MISMATCH),
            Flow::Returning { models, .. } => models.clone(),
            Flow::First => Vec::new(),
        };
        let record = Record {
            v: RECORD_VERSION,
            issuer: self.inner.config.issuer.clone(),
            client_id,
            subject: Some(identity.subject),
            email: identity.email,
            ext_agent_host_id: self.host_id.clone(),
            session: Some(self.inner.session_from(&tokens, None)),
            models,
        };
        let session_guard = self.name_state.session.lock().await;
        self.commit(record)?;
        drop(session_guard);
        Ok(())
    }

    /// Keep the client id a first-registration callback named, so a sign-in that fails after
    /// this point is retried with that client instead of registering another one. Written only
    /// when the name has no record; a write the store does not take is kept in memory.
    async fn retain_registration(&self, client_id: &str) {
        let inner = &self.inner;
        let _session = self.name_state.session.lock().await;
        if matches!(
            inner.load_record(&self.name_state, &self.secret_name),
            Loaded::Missing
        ) {
            let record = Record {
                v: RECORD_VERSION,
                issuer: inner.config.issuer.clone(),
                client_id: client_id.to_string(),
                subject: None,
                email: None,
                ext_agent_host_id: self.host_id.clone(),
                session: None,
                models: Vec::new(),
            };
            inner.persist_record(&self.name_state, &self.secret_name, record);
            lock(&self.name_state.state).codeless_endings = None;
        }
    }

    /// Drop the stored registration when it is the one the token endpoint just refused
    /// (`invalid_client`), so the next sign-in registers again.
    async fn drop_dead_registration(&self, client_id: &str) {
        let inner = &self.inner;
        let _session = self.name_state.session.lock().await;
        if let Loaded::Found(record) = inner.load_record(&self.name_state, &self.secret_name) {
            if record.ext_agent_host_id == self.host_id && record.client_id == client_id {
                inner.drop_registration(&self.name_state, &self.secret_name, Some(&record));
            }
        }
    }

    /// Persist the new sign-in unless the attempt ended meanwhile (cancel, timeout,
    /// replacement). Runs under the session lock, with no await between check and writes.
    fn commit(&self, record: Record) -> Result<(), &'static str> {
        let mut st = lock(&self.name_state.state);
        let current = st
            .attempt
            .as_ref()
            .is_some_and(|a| a.generation == self.generation);
        if !current {
            return Err(REASON_CANCELLED);
        }
        st.attempt = None;
        if self.inner.write_record(&self.secret_name, &record).is_err() {
            st.last_failure = Some(REASON_STORE_FAILED);
            return Err(REASON_STORE_FAILED);
        }
        if let Some(session) = &record.session {
            // A failed write here is repaired from the record by the next renewal check.
            let _ = self
                .inner
                .store
                .store(&self.secret_name, &session.access_token);
        }
        st.last_failure = None;
        st.note = None;
        st.rejected_at_ms = None;
        st.transient_at = None;
        st.unsaved = None;
        st.codeless_endings = None;
        Ok(())
    }
}

fn run_attempt_thread(attempt: Arc<Attempt>, listener: std::net::TcpListener) {
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(_) => {
            attempt.end(Some(REASON_UNAVAILABLE));
            return;
        }
    };
    runtime.block_on(serve_attempt(Arc::clone(&attempt), listener));
    if attempt.committed.load(Ordering::SeqCst) {
        // The listener is closed and the browser answered by now. The model list is
        // informative: a failure leaves the sign-in intact.
        let _ = runtime.block_on(attempt.inner.refresh_models(&attempt.secret_name));
    }
    runtime.shutdown_timeout(Duration::from_millis(500));
}

async fn serve_attempt(attempt: Arc<Attempt>, listener: std::net::TcpListener) {
    let Ok(listener) = tokio::net::TcpListener::from_std(listener) else {
        attempt.end(Some(REASON_UNAVAILABLE));
        return;
    };
    let mut connections = tokio::task::JoinSet::new();
    let window = tokio::time::sleep(attempt.inner.config.sign_in_window);
    let deadline = async {
        tokio::select! {
            _ = window => {}
            _ = attempt.window_end.notified() => {}
        }
    };
    tokio::pin!(deadline);
    let decided = loop {
        tokio::select! {
            _ = &mut deadline => {
                // A callback that claimed the attempt is still being decided: the browser came
                // back, so this is not an ending without a code.
                let claimed = attempt.claimed.load(Ordering::SeqCst);
                if attempt.end(Some(REASON_TIMEOUT)) && !claimed {
                    attempt.count_codeless_ending().await;
                }
                break false;
            }
            _ = attempt.stop.notified() => break false,
            _ = attempt.ended.notified() => break true,
            accepted = listener.accept() => {
                match accepted {
                    Ok((stream, _)) => {
                        if connections.len() < MAX_CALLBACK_CONNECTIONS {
                            connections.spawn(serve_connection(Arc::clone(&attempt), stream));
                        }
                    }
                    Err(_) => tokio::time::sleep(Duration::from_millis(50)).await,
                }
            }
            Some(_) = connections.join_next(), if !connections.is_empty() => {}
        }
    };
    drop(listener);
    if decided {
        // Let the deciding request (and any page in flight) finish writing.
        let bound = attempt.inner.config.callback_read_timeout;
        let _ = tokio::time::timeout(bound, async {
            while connections.join_next().await.is_some() {}
        })
        .await;
    }
    connections.abort_all();
}

async fn serve_connection(attempt: Arc<Attempt>, mut stream: tokio::net::TcpStream) {
    let bound = attempt.inner.config.callback_read_timeout;
    let Ok(Some(head)) = tokio::time::timeout(bound, read_request_head(&mut stream)).await else {
        return;
    };
    let answer = match request_target(&head) {
        Target::Callback(query) => attempt.callback(query).await,
        Target::NotFound => Some((404, PAGE_NOT_FOUND)),
        Target::MethodNotAllowed => Some((405, PAGE_NOT_FOUND)),
        Target::Malformed => Some((400, PAGE_NOT_FOUND)),
    };
    drop(head);
    if let Some((status, page)) = answer {
        let _ = tokio::time::timeout(bound, write_page(&mut stream, status, page)).await;
    }
}

/// The request head (up to the blank line), bounded by [`MAX_CALLBACK_REQUEST_BYTES`].
async fn read_request_head(stream: &mut tokio::net::TcpStream) -> Option<Zeroizing<Vec<u8>>> {
    let mut head = Zeroizing::new(Vec::with_capacity(MAX_CALLBACK_REQUEST_BYTES + 1024));
    let mut chunk = Zeroizing::new([0u8; 1024]);
    loop {
        let n = stream.read(&mut chunk[..]).await.ok()?;
        if n == 0 {
            return None;
        }
        head.extend_from_slice(&chunk[..n]);
        if head.windows(4).any(|w| w == b"\r\n\r\n") {
            return Some(head);
        }
        if head.len() > MAX_CALLBACK_REQUEST_BYTES {
            return None;
        }
    }
}

enum Target<'a> {
    Callback(&'a str),
    NotFound,
    MethodNotAllowed,
    Malformed,
}

fn request_target(head: &[u8]) -> Target<'_> {
    let Some(end) = head.windows(2).position(|w| w == b"\r\n") else {
        return Target::Malformed;
    };
    let Ok(line) = std::str::from_utf8(&head[..end]) else {
        return Target::Malformed;
    };
    let mut parts = line.split(' ');
    let (Some(method), Some(target), Some(version), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Target::Malformed;
    };
    if !version.starts_with("HTTP/1.") {
        return Target::Malformed;
    }
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    if path != CALLBACK_PATH {
        return Target::NotFound;
    }
    if method != "GET" {
        return Target::MethodNotAllowed;
    }
    Target::Callback(query)
}

async fn write_page(
    stream: &mut tokio::net::TcpStream,
    status: u16,
    body: &str,
) -> std::io::Result<()> {
    let (reason, extra) = match status {
        200 => ("OK", ""),
        404 => ("Not Found", ""),
        405 => ("Method Not Allowed", "Allow: GET\r\n"),
        409 => ("Conflict", ""),
        _ => ("Bad Request", ""),
    };
    let head = format!(
        "HTTP/1.1 {status} {reason}\r\n\
         Content-Type: text/html; charset=utf-8\r\n\
         Content-Length: {}\r\n\
         Cache-Control: no-store\r\n\
         Content-Security-Policy: default-src 'none'\r\n\
         Referrer-Policy: no-referrer\r\n\
         X-Content-Type-Options: nosniff\r\n\
         {extra}Connection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(head.as_bytes()).await?;
    stream.write_all(body.as_bytes()).await?;
    stream.flush().await?;
    stream.shutdown().await
}

const PAGE_SIGNED_IN: &str = "<!doctype html><html><head><meta charset=\"utf-8\"><title>Signed in</title></head><body><p>Signed in with ChatGPT. You can close this window and return to the app.</p></body></html>";
const PAGE_FAILED: &str = "<!doctype html><html><head><meta charset=\"utf-8\"><title>Sign-in did not complete</title></head><body><p>The sign-in did not complete. Return to the app to see why and try again.</p></body></html>";
const PAGE_INACTIVE: &str = "<!doctype html><html><head><meta charset=\"utf-8\"><title>Not active</title></head><body><p>This sign-in link is not active. Return to the app.</p></body></html>";
const PAGE_NOT_FOUND: &str = "<!doctype html><html><head><meta charset=\"utf-8\"><title>Not found</title></head><body><p>Not found.</p></body></html>";

/// One query parameter: absent, present once, or repeated (never trusted).
enum Param {
    Absent,
    One(Zeroizing<String>),
    Repeated,
}

impl Param {
    fn push(&mut self, value: Zeroizing<String>) {
        *self = match self {
            Param::Absent => Param::One(value),
            _ => Param::Repeated,
        };
    }
}

/// How a callback's `state` relates to the attempt's.
enum StateCheck {
    /// Present once, and equal.
    Matches,
    /// Equal at least once but present more than once.
    Repeated,
    /// Absent, or never equal.
    Foreign,
}

struct CallbackParams {
    state: StateCheck,
    code: Param,
    error: Param,
    client_id: Param,
}

impl CallbackParams {
    /// Every `state` value is compared (constant time) with `expected`.
    fn parse(query: &str, expected: &str) -> Self {
        let mut params = CallbackParams {
            state: StateCheck::Foreign,
            code: Param::Absent,
            error: Param::Absent,
            client_id: Param::Absent,
        };
        let (mut states, mut matching) = (0u32, 0u32);
        for (key, value) in url::form_urlencoded::parse(query.as_bytes()) {
            let value = Zeroizing::new(value.into_owned());
            let slot = match key.as_ref() {
                "state" => {
                    states = states.saturating_add(1);
                    if bool::from(value.as_bytes().ct_eq(expected.as_bytes())) {
                        matching = matching.saturating_add(1);
                    }
                    continue;
                }
                "code" => &mut params.code,
                "error" => &mut params.error,
                "client_id" => &mut params.client_id,
                _ => continue,
            };
            slot.push(value);
        }
        params.state = match (states, matching) {
            (1, 1) => StateCheck::Matches,
            (_, 0) => StateCheck::Foreign,
            _ => StateCheck::Repeated,
        };
        params
    }
}

/// The loopback listener of an attempt: `127.0.0.1` only, on `port` or, when that is taken, on
/// a port the OS assigns.
pub(crate) fn bind_callback(port: u16) -> std::io::Result<std::net::TcpListener> {
    let at = |port| std::net::SocketAddr::from(([127, 0, 0, 1], port));
    let listener = match std::net::TcpListener::bind(at(port)) {
        Ok(listener) => listener,
        Err(_) if port != 0 => std::net::TcpListener::bind(at(0))?,
        Err(e) => return Err(e),
    };
    listener.set_nonblocking(true)?;
    Ok(listener)
}

// ── keys and claims ──────────────────────────────────────────────────────────────────────────

#[derive(Clone)]
struct IssuerMetadata {
    jwks_uri: String,
    revocation_endpoint: String,
    fetched_at_ms: u64,
}

struct Jwk {
    kid: Option<String>,
    key: RsaPublicKey,
}

struct JwkSet {
    keys: Vec<Jwk>,
    fetched_at_ms: u64,
}

impl JwkSet {
    fn knows(&self, kid: &str) -> bool {
        self.keys.iter().any(|k| k.kid.as_deref() == Some(kid))
    }

    fn verify(
        &self,
        kid: Option<&str>,
        signing_input: &[u8],
        signature: &[u8],
    ) -> Result<(), &'static str> {
        let signature = RsaSignature::try_from(signature).map_err(|_| REASON_ID_TOKEN_INVALID)?;
        let verified = self
            .keys
            .iter()
            .filter(|k| kid.is_none() || k.kid.as_deref() == kid)
            .any(|k| {
                VerifyingKey::<Sha256>::new(k.key.clone())
                    .verify(signing_input, &signature)
                    .is_ok()
            });
        if verified {
            Ok(())
        } else {
            Err(REASON_ID_TOKEN_INVALID)
        }
    }
}

/// RSA signing keys of a JWK set; keys of another type or use, another algorithm, or under
/// 2048 bits are left out.
fn parse_jwks(body: &[u8], now: u64) -> Option<JwkSet> {
    let document = parse_json(body)?;
    let mut keys = Vec::new();
    for jwk in document.get("keys")?.as_array()?.iter().take(MAX_JWKS_KEYS) {
        if jwk.get("kty").and_then(Value::as_str) != Some("RSA") {
            continue;
        }
        if jwk.get("use").is_some_and(|u| u.as_str() != Some("sig")) {
            continue;
        }
        if jwk.get("alg").is_some_and(|a| a.as_str() != Some("RS256")) {
            continue;
        }
        let component = |name: &str| {
            jwk.get(name)
                .and_then(Value::as_str)
                .and_then(|s| URL_SAFE_NO_PAD.decode(s).ok())
                .map(|bytes| BigUint::from_bytes_be(&bytes))
        };
        let (Some(n), Some(e)) = (component("n"), component("e")) else {
            continue;
        };
        let Ok(key) = RsaPublicKey::new(n, e) else {
            continue;
        };
        if key.n().bits() < MIN_RSA_BITS {
            continue;
        }
        keys.push(Jwk {
            kid: jwk.get("kid").and_then(Value::as_str).map(String::from),
            key,
        });
    }
    Some(JwkSet {
        keys,
        fetched_at_ms: now,
    })
}

struct IdentityClaims {
    subject: String,
    email: Option<String>,
}

/// The claim checks of a signature-verified ID token. `None` when any check fails.
fn check_id_claims(
    claims: &Value,
    issuer: &str,
    client_id: &str,
    nonce: &str,
    now_ms: u64,
    leeway_ms: u64,
) -> Option<IdentityClaims> {
    if claims.get("iss").and_then(Value::as_str) != Some(issuer) {
        return None;
    }
    let audience_ok = match claims.get("aud")? {
        Value::String(aud) => aud == client_id,
        Value::Array(list) => {
            let names: Option<Vec<&str>> = list.iter().map(Value::as_str).collect();
            let names = names?;
            names.contains(&client_id)
                && (names.len() == 1
                    || claims.get("azp").and_then(Value::as_str) == Some(client_id))
        }
        _ => false,
    };
    if !audience_ok {
        return None;
    }
    let exp_ms = numeric_date_ms(claims.get("exp")?)?;
    if now_ms >= exp_ms.saturating_add(leeway_ms) {
        return None;
    }
    numeric_date_ms(claims.get("iat")?)?;
    if let Some(nbf) = claims.get("nbf") {
        if numeric_date_ms(nbf)? > now_ms.saturating_add(leeway_ms) {
            return None;
        }
    }
    let token_nonce = claims.get("nonce").and_then(Value::as_str)?;
    if !bool::from(token_nonce.as_bytes().ct_eq(nonce.as_bytes())) {
        return None;
    }
    let subject = claims
        .get("sub")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty() && s.len() <= 255 && !s.chars().any(char::is_control))?
        .to_string();
    let email = claims
        .get("email")
        .and_then(Value::as_str)
        .filter(|s| is_display_text(s, 320))
        .map(String::from);
    Some(IdentityClaims { subject, email })
}

/// A JWT NumericDate (seconds) in milliseconds.
fn numeric_date_ms(value: &Value) -> Option<u64> {
    if let Some(s) = value.as_u64() {
        return Some(s.saturating_mul(1000));
    }
    let f = value.as_f64()?;
    (f.is_finite() && f >= 0.0).then_some((f * 1000.0) as u64)
}

// ── token responses ──────────────────────────────────────────────────────────────────────────

struct TokenSet {
    access_token: Zeroizing<String>,
    refresh_token: Option<Zeroizing<String>>,
    id_token: Option<Zeroizing<String>>,
    expires_in_s: u64,
    scopes: Option<Vec<String>>,
    earliest_refresh_at_ms: Option<u64>,
}

fn parse_token_response(body: &[u8]) -> Option<TokenSet> {
    let mut document = parse_json(body)?;
    let tokens = token_set_of(&document);
    scrub_json(&mut document);
    tokens
}

fn token_set_of(document: &Value) -> Option<TokenSet> {
    let object = document.as_object()?;
    let token = |name: &str| -> Option<Option<Zeroizing<String>>> {
        match object.get(name) {
            None | Some(Value::Null) => Some(None),
            Some(Value::String(s)) if is_token_text(s) => Some(Some(Zeroizing::new(s.clone()))),
            Some(_) => None,
        }
    };
    let access_token = token("access_token")??;
    let refresh_token = token("refresh_token")?;
    let id_token = token("id_token")?;
    match object.get("token_type") {
        None | Some(Value::Null) => {}
        Some(Value::String(t)) if t.eq_ignore_ascii_case("bearer") => {}
        Some(_) => return None,
    }
    let expires_in_s = match object.get("expires_in") {
        None | Some(Value::Null) => DEFAULT_TOKEN_LIFETIME_S,
        Some(v) => integer_of(v)?.min(MAX_TOKEN_LIFETIME_S),
    };
    let scopes = match object.get("scope") {
        None | Some(Value::Null) => None,
        Some(Value::String(s)) => Some(s.split_whitespace().map(String::from).collect()),
        Some(_) => return None,
    };
    let earliest_refresh_at_ms = object.get("earliest_refresh_at").and_then(timestamp_ms);
    Some(TokenSet {
        access_token,
        refresh_token,
        id_token,
        expires_in_s,
        scopes,
        earliest_refresh_at_ms,
    })
}

/// A non-negative integer given as a JSON number or a decimal string.
fn integer_of(value: &Value) -> Option<u64> {
    match value {
        Value::Number(n) => n.as_u64().or_else(|| {
            n.as_f64()
                .filter(|f| f.is_finite() && *f >= 0.0)
                .map(|f| f as u64)
        }),
        Value::String(s) => s.trim().parse().ok(),
        _ => None,
    }
}

/// An absolute time as Unix seconds (or milliseconds when the value is that large), given as a
/// number or a decimal string. Anything else is ignored.
fn timestamp_ms(value: &Value) -> Option<u64> {
    let raw = integer_of(value)?;
    Some(if raw >= 100_000_000_000 {
        raw
    } else {
        raw.saturating_mul(1000)
    })
}

/// The machine-readable error code of an error body: `error`, `error.code` or `code`.
fn oauth_error_code(body: &[u8]) -> Option<String> {
    let document = parse_json(body)?;
    let code = match document.get("error") {
        Some(Value::String(code)) => Some(code.as_str()),
        Some(Value::Object(error)) => error.get("code").and_then(Value::as_str),
        _ => None,
    }
    .or_else(|| document.get("code").and_then(Value::as_str))?;
    (code.len() <= 64).then(|| code.to_string())
}

/// The models of a model-list answer (`models[]` with `slug`, or `data[]` with `id`), keeping
/// the server's order and only entries meant for display.
fn parse_models(body: &[u8]) -> Option<Vec<SignInModel>> {
    let document = parse_json(body)?;
    let list = document
        .get("models")
        .and_then(Value::as_array)
        .or_else(|| document.get("data").and_then(Value::as_array))?;
    let mut models = Vec::new();
    for entry in list.iter().take(MAX_MODELS) {
        if entry
            .get("visibility")
            .is_some_and(|v| v.as_str() != Some("list"))
        {
            continue;
        }
        let Some(id) = entry
            .get("slug")
            .or_else(|| entry.get("id"))
            .and_then(Value::as_str)
            .filter(|s| is_display_text(s, 128))
        else {
            continue;
        };
        models.push(SignInModel {
            id: id.to_string(),
            display_name: entry
                .get("display_name")
                .and_then(Value::as_str)
                .filter(|s| is_display_text(s, 128))
                .map(String::from),
        });
    }
    Some(models)
}

fn parse_json(body: &[u8]) -> Option<Value> {
    if body.len() > MAX_JSON_BYTES {
        return None;
    }
    serde_json::from_slice(body).ok()
}

fn decode_json_segment(segment: &str) -> Option<Value> {
    let bytes = Zeroizing::new(URL_SAFE_NO_PAD.decode(segment).ok()?);
    let value: Value = serde_json::from_slice(&bytes).ok()?;
    value.is_object().then_some(value)
}

/// Overwrite every string of a parsed document that held credentials.
fn scrub_json(value: &mut Value) {
    match value {
        Value::String(s) => s.zeroize(),
        Value::Array(items) => items.iter_mut().for_each(scrub_json),
        Value::Object(map) => map.values_mut().for_each(scrub_json),
        _ => {}
    }
}

/// A credential-shaped string: printable ASCII without spaces, bounded.
fn is_token_text(s: &str) -> bool {
    !s.is_empty() && s.len() <= MAX_TOKEN_BYTES && s.bytes().all(|b| (0x21..=0x7e).contains(&b))
}

fn is_client_id(s: &str) -> bool {
    !s.is_empty() && s.len() <= 256 && s.bytes().all(|b| (0x21..=0x7e).contains(&b))
}

fn is_display_text(s: &str, max: usize) -> bool {
    !s.trim().is_empty() && s.chars().count() <= max && !s.chars().any(char::is_control)
}

// ── requests ─────────────────────────────────────────────────────────────────────────────────

fn get_request(url: &str) -> HttpRequest {
    HttpRequest {
        method: HttpMethod::Get,
        url: url.to_string(),
        headers: vec![("Accept".into(), "application/json".into())],
        body: Vec::new(),
    }
}

fn form_request(url: &str, pairs: &[(&str, &str)]) -> HttpRequest {
    let body = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(pairs)
        .finish();
    HttpRequest {
        method: HttpMethod::Post,
        url: url.to_string(),
        headers: vec![
            (
                "Content-Type".into(),
                "application/x-www-form-urlencoded".into(),
            ),
            ("Accept".into(), "application/json".into()),
        ],
        body: body.into_bytes(),
    }
}

/// `scheme://host[:port]/` of `url` (an allowlist URL-prefix pattern).
fn origin_prefix(url: &str) -> Option<String> {
    let parsed = url::Url::parse(url).ok()?;
    let origin = parsed.origin();
    origin
        .is_tuple()
        .then(|| format!("{}/", origin.ascii_serialization()))
}

fn same_origin(a: &str, b: &str) -> bool {
    match (url::Url::parse(a), url::Url::parse(b)) {
        (Ok(a), Ok(b)) => a.origin().is_tuple() && a.origin() == b.origin(),
        _ => false,
    }
}

/// `bytes` CSPRNG bytes, base64url without padding.
fn random_token(bytes: usize) -> Zeroizing<String> {
    let mut raw = Zeroizing::new(vec![0u8; bytes]);
    rand::rngs::OsRng.fill_bytes(&mut raw);
    Zeroizing::new(URL_SAFE_NO_PAD.encode(&*raw))
}

/// A PKCE verifier: 64 CSPRNG bytes, base64url without padding (86 characters of the RFC 7636
/// alphabet).
fn pkce_verifier() -> Zeroizing<String> {
    random_token(64)
}

// ── host id file ─────────────────────────────────────────────────────────────────────────────

fn host_id_path(home: &Path) -> PathBuf {
    home.join(".advance").join(HOST_ID_FILE)
}

/// `Ok(None)` when absent; `Err` when present but not a regular file holding one
/// `urn:uuid:<lower-case hyphenated v4>` line.
fn read_host_id(home: &Path) -> Result<Option<String>, ()> {
    let path = host_id_path(home);
    match std::fs::symlink_metadata(&path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(()),
        Ok(meta) if !meta.file_type().is_file() => return Err(()),
        Ok(_) => {}
    }
    let raw = crate::scaffold::read_small_regular(&path, 256).ok_or(())?;
    let line = raw.strip_suffix('\n').unwrap_or(&raw);
    let uuid = line.strip_prefix("urn:uuid:").ok_or(())?;
    let parsed = uuid::Uuid::parse_str(uuid).map_err(|_| ())?;
    if parsed.get_version_num() != 4 || parsed.hyphenated().to_string() != uuid {
        return Err(());
    }
    Ok(Some(line.to_string()))
}

/// Create the host id once: written to a private temporary file, then linked into place so a
/// reader never sees a partial file and a concurrent creator's value wins over ours.
fn create_host_id(home: &Path) -> Result<String, ()> {
    let dir = home.join(".advance");
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    builder.mode(0o700);
    builder.create(&dir).map_err(|_| ())?;
    if !crate::recognize::is_real_dir(&dir) {
        return Err(());
    }
    let path = host_id_path(home);
    let value = format!("urn:uuid:{}\n", uuid::Uuid::new_v4().hyphenated());
    let mut suffix = [0u8; 8];
    rand::rngs::OsRng.fill_bytes(&mut suffix);
    let tmp = dir.join(format!(".{HOST_ID_FILE}.{}.tmp", hex::encode(suffix)));
    let placed = write_new_private(&tmp, value.as_bytes()).and_then(|()| {
        match std::fs::hard_link(&tmp, &path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
            // A file system without hard links: rename, unless a value appeared meanwhile.
            Err(_) if std::fs::symlink_metadata(&path).is_err() => std::fs::rename(&tmp, &path),
            Err(_) => Ok(()),
        }
    });
    let _ = std::fs::remove_file(&tmp);
    placed.map_err(|_| ())?;
    read_host_id(home)?.ok_or(())
}

fn write_new_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        options.mode(0o600);
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

impl SignInStatus {
    fn signed_out(reason: Option<&'static str>) -> Self {
        SignInStatus {
            state: STATE_SIGNED_OUT,
            reason,
            account: None,
            plan_usage: None,
            expires_at_ms: None,
            models: Vec::new(),
        }
    }
}
