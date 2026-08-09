//! `DefaultSsrfGuard` — implements `SsrfGuard` (CONTRACT-111 sub-component).
//!
//! Defends outbound HTTP from server-side request forgery to:
//!   - private IPv4 (10/8, 172.16/12, 192.168/16)
//!   - loopback (127/8, ::1/128)
//!   - link-local (169.254/16, fe80::/10)
//!   - IPv6 unique-local (fd00::/8)
//!   - cloud metadata pins (169.254.169.254/32, fd00:ec2::254/128)
//!
//! Iteration order is **first-match-wins, metadata pins FIRST** so 169.254.169.254
//! classifies as `CloudMetadata` rather than `LinkLocal` (T11c lock).
//!
//! Async path uses `tokio::net::lookup_host((host, 0))` (port 0 — DNS-only
//! lookup ignores port; previously hardcoded 80 was misleading) wrapped in
//! `tokio::time::timeout` bounded by the configured DNS timeout. Resolutions
//! are cached by lowercased+trailing-dot-stripped host with TTL + insertion-
//! ordered FIFO bound (NOT true LRU — entries are not promoted on read hit,
//! TTL handles freshness) to prevent unbounded memory growth.

use advance_shared_types::security_validator::{CidrClass, SsrfError, SsrfGuard};
use async_trait::async_trait;
use ipnet::IpNet;
use std::collections::HashMap;
use std::future::Future;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::time::timeout;

tokio::task_local! {
    /// Streaming-only absolute deadline inherited by the production SSRF
    /// compound stage. Buffered CONTRACT-111 calls deliberately leave it
    /// unset and preserve their historical behavior.
    static STREAM_SSRF_DEADLINE: tokio::time::Instant;
}

/// Run one SSRF check with CONTRACT-233's entry-anchored deadline available to
/// nested production collaborators, without changing the shared `SsrfGuard`
/// signature or leaking streaming policy into buffered callers.
pub(crate) async fn with_stream_ssrf_deadline<T>(
    deadline: tokio::time::Instant,
    future: impl Future<Output = T>,
) -> T {
    STREAM_SSRF_DEADLINE.scope(deadline, future).await
}

/// Current streaming SSRF deadline, if this call is inside the opt-in
/// CONTRACT-233 scope. The value is copied so a resolver can carry it into a
/// returned future even when the downstream library polls that future later.
pub(crate) fn current_stream_ssrf_deadline() -> Option<tokio::time::Instant> {
    STREAM_SSRF_DEADLINE.try_with(|deadline| *deadline).ok()
}

fn ensure_stream_ssrf_deadline() -> Result<(), SsrfError> {
    let live = current_stream_ssrf_deadline()
        .is_none_or(|deadline| tokio::time::Instant::now() < deadline);
    if live {
        Ok(())
    } else {
        Err(SsrfError::DnsTimeout)
    }
}

/// Default DNS timeout (`security.ssrf.dns_timeout_ms`).
pub const DEFAULT_DNS_TIMEOUT_MS: u64 = 50;

/// Default DNS cache TTL (`security.ssrf.dns_cache_ttl_seconds`).
pub const DEFAULT_DNS_CACHE_TTL_SECS: u64 = 300;

/// Live DNS-tunable source (Wave-16 Lane-4, MODULE-012 AC-17 hot-reload). The cli
/// composition root injects closures reading
/// `provider.current().security.ssrf.{dns_timeout_ms, dns_cache_ttl_seconds}`
/// (always `validate_config`-bounded), so a hot-reloaded value takes effect
/// without restart. cap-http stays `crates/runtime`-dep-free.
pub type DnsTunableSource = Arc<dyn Fn() -> u64 + Send + Sync>;

/// FIFO bound on the DNS cache to prevent unbounded growth from rotating hosts.
/// (R3-W rename: previously called "LRU"; the actual semantic is insertion-
/// ordered FIFO with TTL — entries are NOT promoted on read hit. Acceptable
/// for Slice C since TTL eviction handles freshness; a future slice could
/// promote to true LRU if hot-host eviction ever becomes a hotspot.)
pub const DNS_CACHE_MAX_ENTRIES: usize = 4096;

/// Resolver abstraction (real DNS via tokio in production; deterministic
/// `MockResolver` in tests). Returns the resolved IP set for a given host.
#[async_trait]
pub trait Resolver: Send + Sync {
    async fn resolve(&self, host: &str) -> Result<Vec<IpAddr>, SsrfError>;
}

/// Production resolver — uses `tokio::net::lookup_host`.
pub struct RealResolver {
    timeout_ms: u64,
    /// Optional live timeout source (MODULE-012 AC-17 hot-reload). `None` → the
    /// fixed `timeout_ms` field (prior behaviour).
    timeout_source: Option<DnsTunableSource>,
}

impl RealResolver {
    pub fn new() -> Self {
        Self {
            timeout_ms: DEFAULT_DNS_TIMEOUT_MS,
            timeout_source: None,
        }
    }

    pub fn with_timeout_ms(timeout_ms: u64) -> Self {
        Self {
            timeout_ms,
            timeout_source: None,
        }
    }

    /// Wire a live DNS-timeout source (MODULE-012 AC-17 hot-reload). Builder-style,
    /// additive — `new()` / `with_timeout_ms()` keep the fixed value.
    pub fn with_timeout_source(mut self, source: DnsTunableSource) -> Self {
        self.timeout_source = Some(source);
        self
    }

    /// Effective DNS timeout (ms): the live source if wired, else the fixed
    /// field. Read per-resolve so a hot-reloaded value applies without restart.
    fn effective_timeout_ms(&self) -> u64 {
        match &self.timeout_source {
            Some(f) => f(),
            None => self.timeout_ms,
        }
    }
}

impl Default for RealResolver {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Resolver for RealResolver {
    async fn resolve(&self, host: &str) -> Result<Vec<IpAddr>, SsrfError> {
        let timeout_ms = self.effective_timeout_ms();
        // A live synchronous source can begin before CONTRACT-233's deadline
        // and return after it. Check the task-scoped deadline before creating
        // or polling the network-capable lookup future.
        ensure_stream_ssrf_deadline()?;
        // Port 0 — DNS-only lookups ignore port (returns A/AAAA records).
        // We use `(host, 0)` as the conventional any-port signal.
        let lookup = tokio::net::lookup_host((host, 0u16));
        let result = match timeout(Duration::from_millis(timeout_ms), lookup).await {
            Ok(Ok(addrs)) => addrs.map(|sa| sa.ip()).collect::<Vec<_>>(),
            Ok(Err(_)) => return Err(SsrfError::DnsFailed),
            Err(_) => return Err(SsrfError::DnsTimeout),
        };
        if result.is_empty() {
            return Err(SsrfError::DnsFailed);
        }
        Ok(result)
    }
}

/// In-test mock resolver — deterministic host → IP mapping.
pub struct MockResolver {
    pub mapping: HashMap<String, Vec<IpAddr>>,
    pub fail_with: Mutex<Option<SsrfError>>,
}

impl MockResolver {
    pub fn new() -> Self {
        Self {
            mapping: HashMap::new(),
            fail_with: Mutex::new(None),
        }
    }

    pub fn with(mut self, host: &str, ips: Vec<IpAddr>) -> Self {
        self.mapping.insert(host.to_ascii_lowercase(), ips);
        self
    }

    pub fn fail_with(self, err: SsrfError) -> Self {
        *self.fail_with.lock().unwrap() = Some(err);
        self
    }
}

impl Default for MockResolver {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Resolver for MockResolver {
    async fn resolve(&self, host: &str) -> Result<Vec<IpAddr>, SsrfError> {
        if let Some(err) = self.fail_with.lock().unwrap().clone() {
            return Err(err);
        }
        let key = host.to_ascii_lowercase();
        match self.mapping.get(&key) {
            Some(ips) if !ips.is_empty() => Ok(ips.clone()),
            _ => Err(SsrfError::DnsFailed),
        }
    }
}

/// `DefaultSsrfGuard` — production-shape SSRF check with TTL + FIFO-bounded cache.
pub struct DefaultSsrfGuard {
    forbidden: Vec<(IpNet, CidrClass)>,
    resolver: Box<dyn Resolver>,
    cache: Mutex<DnsCache>,
    cache_ttl_secs: u64,
    /// Optional live cache-TTL source (MODULE-012 AC-17 hot-reload). `None` →
    /// the fixed `cache_ttl_secs` field (prior behaviour).
    cache_ttl_source: Option<DnsTunableSource>,
}

struct DnsCache {
    /// Insertion-ordered (host, ips, inserted_at) tuples. FIFO eviction by
    /// `Vec::remove(0)` when len > DNS_CACHE_MAX_ENTRIES (R3-W rename: not
    /// LRU — entries are not promoted on read hit. TTL-based freshness via
    /// `inserted_at`).
    entries: Vec<CacheEntry>,
}

struct CacheEntry {
    host: String,
    ips: Vec<IpAddr>,
    inserted_at: Instant,
}

impl DnsCache {
    fn new() -> Self {
        Self {
            entries: Vec::with_capacity(64),
        }
    }
}

impl DefaultSsrfGuard {
    pub fn new() -> Self {
        Self::with_resolver(Box::new(RealResolver::new()))
    }

    pub fn with_resolver(resolver: Box<dyn Resolver>) -> Self {
        Self {
            forbidden: build_forbidden_table(),
            resolver,
            cache: Mutex::new(DnsCache::new()),
            cache_ttl_secs: DEFAULT_DNS_CACHE_TTL_SECS,
            cache_ttl_source: None,
        }
    }

    pub fn with_cache_ttl_secs(mut self, secs: u64) -> Self {
        self.cache_ttl_secs = secs;
        self
    }

    /// Wire a live DNS cache-TTL source (MODULE-012 AC-17 hot-reload). Builder-style,
    /// additive — `new()` / `with_cache_ttl_secs()` keep the fixed value. The TTL is
    /// read per-lookup at the freshness check; `inserted_at` is stamped at insert, so
    /// a TTL change re-evaluates freshness of existing entries on their next lookup.
    pub fn with_cache_ttl_source(mut self, source: DnsTunableSource) -> Self {
        self.cache_ttl_source = Some(source);
        self
    }

    /// Effective DNS cache TTL (secs): the live source if wired, else the fixed
    /// field. Read per-lookup so a hot-reloaded value applies without restart.
    fn effective_cache_ttl_secs(&self) -> u64 {
        match &self.cache_ttl_source {
            Some(f) => f(),
            None => self.cache_ttl_secs,
        }
    }

    /// Lookup resolved IPs from cache (if fresh) or trigger a fresh resolve.
    /// Cache key is the lowercased host with trailing dot stripped (T11k lock).
    async fn resolve_cached(&self, host: &str) -> Result<Vec<IpAddr>, SsrfError> {
        let key = normalize_host(host);

        // Snapshot a matching entry without keeping the cache lock across the
        // live TTL callback or an async cancellation point.
        let cached = {
            let cache = self.cache.lock().unwrap();
            cache
                .entries
                .iter()
                .find(|e| e.host == key)
                .map(|entry| (entry.inserted_at.elapsed(), entry.ips.clone()))
        };
        if let Some((age, ips)) = cached {
            let ttl_secs = self.effective_cache_ttl_secs();
            // The live TTL source may have crossed CONTRACT-233's deadline.
            // Check inside this compound stage before either returning a late
            // cache result or continuing into the resolver future.
            ensure_stream_ssrf_deadline()?;
            if age < Duration::from_secs(ttl_secs) {
                return Ok(ips);
            }
        }

        // Cache miss / expired — resolve fresh.
        ensure_stream_ssrf_deadline()?;
        let ips = self.resolver.resolve(&key).await?;

        // Insert into cache, evicting FIFO (oldest-inserted) if over the bound.
        {
            let mut cache = self.cache.lock().unwrap();
            cache.entries.retain(|e| e.host != key); // remove stale entry if present
            cache.entries.push(CacheEntry {
                host: key,
                ips: ips.clone(),
                inserted_at: Instant::now(),
            });
            while cache.entries.len() > DNS_CACHE_MAX_ENTRIES {
                cache.entries.remove(0);
            }
        }

        Ok(ips)
    }

    /// Check the resolved IP set against the forbidden CIDR table; returns the
    /// first matching `CidrClass` per first-match-wins order, or Ok(()).
    /// IPv4-mapped IPv6 addresses are normalized back to v4 before the check
    /// (per `normalize_ip`) so attempts to bypass loopback/private/metadata
    /// blocks via the `::ffff:V.V.V.V` form fail.
    fn check_ips(&self, ips: &[IpAddr]) -> Result<(), SsrfError> {
        for ip in ips {
            let ip = normalize_ip(*ip);
            for (net, class) in &self.forbidden {
                if net.contains(&ip) {
                    return Err(SsrfError::Forbidden(class.clone()));
                }
            }
        }
        Ok(())
    }
}

impl Default for DefaultSsrfGuard {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl SsrfGuard for DefaultSsrfGuard {
    async fn check(&self, url: &str) -> Result<(), SsrfError> {
        let parsed = url::Url::parse(url).map_err(|_| SsrfError::InvalidUrl(url.to_string()))?;
        let host = parsed.host_str().ok_or(SsrfError::NoHost)?;
        let ips = self.resolve_cached(host).await?;
        self.check_ips(&ips)
    }
}

/// Build the forbidden CIDR table in **first-match-wins** order — metadata
/// pins FIRST so 169.254.169.254 classifies as `CloudMetadata` not `LinkLocal`.
///
/// `pub(crate)` so the `ReqwestHttpExecutor`'s connect-time SSRF DNS resolver
/// (executor.rs) reuses the EXACT same forbidden ranges as the chain's
/// `DefaultSsrfGuard` — single source of truth (closes the DNS-rebinding TOCTOU
/// where the guard validated a hostname's resolution the connecting client never honored).
pub(crate) fn build_forbidden_table() -> Vec<(IpNet, CidrClass)> {
    vec![
        // METADATA PINS FIRST (more-specific first-match-wins).
        (
            "169.254.169.254/32".parse().unwrap(),
            CidrClass::CloudMetadata,
        ),
        (
            "fd00:ec2::254/128".parse().unwrap(),
            CidrClass::CloudMetadata,
        ),
        // BROADER CIDRS NEXT.
        ("10.0.0.0/8".parse().unwrap(), CidrClass::PrivateIpv4),
        ("172.16.0.0/12".parse().unwrap(), CidrClass::PrivateIpv4),
        ("192.168.0.0/16".parse().unwrap(), CidrClass::PrivateIpv4),
        ("127.0.0.0/8".parse().unwrap(), CidrClass::Loopback),
        // 0.0.0.0/8 "this network" (RFC 1122) — never a valid destination; 0.0.0.0
        // routes to localhost on connect. Labeled Loopback (no Unspecified class in
        // the fixed `CidrClass` enum). Round-11 adversarial W3.
        ("0.0.0.0/8".parse().unwrap(), CidrClass::Loopback),
        ("169.254.0.0/16".parse().unwrap(), CidrClass::LinkLocal),
        ("::1/128".parse().unwrap(), CidrClass::Loopback),
        // ::/96 covers IPv6 unspecified (`::`), the loopback (`::1`, redundant with the
        // entry above), AND the deprecated RFC 4291 IPv4-COMPATIBLE form `::a.b.c.d`
        // (e.g. `::127.0.0.1`) that `to_ipv4_mapped()` does NOT fold. Distinct from the
        // IPv4-MAPPED `::ffff:0:0/96` range (segments[5]==0xffff), which `normalize_ip`
        // handles separately. Round-11 adversarial W3.
        ("::/96".parse().unwrap(), CidrClass::Loopback),
        // RFC 4193 IPv6 unique-local is /7 (`fc00::/7`), covering BOTH
        // `fc00::/8` (centrally-assigned, currently unused) AND `fd00::/8`
        // (locally-assigned). Adversarial R3 fix: previously only `fd00::/8`
        // was blocked. We now block the full `fc00::/7` range.
        ("fc00::/7".parse().unwrap(), CidrClass::UniqueLocalIpv6),
        ("fe80::/10".parse().unwrap(), CidrClass::LinkLocal),
    ]
}

/// Convert IPv6 transition embeddings to their underlying IPv4 form for
/// forbidden-CIDR matching. Adversarial R1+R2 fixes — handles:
///
/// 1. **IPv4-mapped** `::ffff:V.V.V.V` (RFC 4291) — most common; `to_ipv4_mapped()`.
/// 2. **6to4** `2002:V.V.V.V::/16` (RFC 3056) — embeds the v4 in segments
///    [1..3]. Deprecated by RFC 7526 but still routed on some kernels.
/// 3. **NAT64 well-known prefix** `64:ff9b::V.V.V.V/96` (RFC 6052) — embeds
///    the v4 in segments [6..8].
///
/// Without normalization, an attacker DNS returning `2002:7f00::1` (6to4
/// representation of 127.0.0.1) or `64:ff9b::7f00:1` (NAT64 of 127.0.0.1)
/// would pass both the v4 loopback (wrong family) and v6 loopback (different
/// address) checks; on hosts with 6to4 / NAT64 routing enabled the OS connect
/// path may translate back to v4 and reach the forbidden destination.
pub(crate) fn normalize_ip(ip: IpAddr) -> IpAddr {
    if let IpAddr::V6(v6) = ip {
        // RFC 4291 §2.5.5.2 IPv4-mapped — most common, covers `::ffff:V.V.V.V`.
        if let Some(v4) = v6.to_ipv4_mapped() {
            return IpAddr::V4(v4);
        }
        let segs = v6.segments();
        // RFC 3056 6to4: 2002:V.V.V.V::/16 — segments [1..3] are V.V.V.V.
        if segs[0] == 0x2002 {
            let v4 = std::net::Ipv4Addr::new(
                (segs[1] >> 8) as u8,
                (segs[1] & 0xff) as u8,
                (segs[2] >> 8) as u8,
                (segs[2] & 0xff) as u8,
            );
            return IpAddr::V4(v4);
        }
        // RFC 6052 NAT64 well-known prefix: 64:ff9b::/96 — segments [6..8] are V.V.V.V.
        if segs[0] == 0x0064
            && segs[1] == 0xff9b
            && segs[2] == 0
            && segs[3] == 0
            && segs[4] == 0
            && segs[5] == 0
        {
            let v4 = std::net::Ipv4Addr::new(
                (segs[6] >> 8) as u8,
                (segs[6] & 0xff) as u8,
                (segs[7] >> 8) as u8,
                (segs[7] & 0xff) as u8,
            );
            return IpAddr::V4(v4);
        }
    }
    ip
}

/// Normalize host: lowercase + strip trailing dot. T11k locks the requirement
/// that `EVIL.com.` and `evil.com` map to the same cache entry.
fn normalize_host(host: &str) -> String {
    let lc = host.to_ascii_lowercase();
    lc.strip_suffix('.').unwrap_or(&lc).to_string()
}
