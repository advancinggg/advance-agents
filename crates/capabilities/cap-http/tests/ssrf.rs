//! T11a-k — SSRF unit tests (AC-11). Use `MockResolver` to bypass real DNS.

use advance_shared_types::security_validator::{CidrClass, SsrfError, SsrfGuard};
use cap_http::{DefaultSsrfGuard, LoopbackExemptSsrfGuard, LoopbackExemptions, MockResolver};
use std::net::IpAddr;
use std::sync::Arc;

fn ipv4(s: &str) -> IpAddr {
    s.parse().unwrap()
}

fn ipv6(s: &str) -> IpAddr {
    s.parse().unwrap()
}

fn guard_with(host: &str, ips: Vec<IpAddr>) -> DefaultSsrfGuard {
    let resolver = MockResolver::new().with(host, ips);
    DefaultSsrfGuard::with_resolver(Box::new(resolver))
}

#[tokio::test]
async fn t11a_private_ipv4_rejected() {
    let g = guard_with("private.example.com", vec![ipv4("10.0.0.1")]);
    let r = g.check("https://private.example.com/").await;
    assert_eq!(r, Err(SsrfError::Forbidden(CidrClass::PrivateIpv4)));
}

#[tokio::test]
async fn t11b_loopback_ipv4_rejected() {
    let g = guard_with("loopback.example.com", vec![ipv4("127.0.0.1")]);
    let r = g.check("https://loopback.example.com/").await;
    assert_eq!(r, Err(SsrfError::Forbidden(CidrClass::Loopback)));
}

#[tokio::test]
async fn t11c_cloud_metadata_pin_matches_before_link_local() {
    // 169.254.169.254 falls in BOTH CloudMetadata pin AND LinkLocal block.
    // First-match-wins with metadata-pins-first declaration order should
    // classify as CloudMetadata.
    let g = guard_with("metadata.example.com", vec![ipv4("169.254.169.254")]);
    let r = g.check("https://metadata.example.com/").await;
    assert_eq!(r, Err(SsrfError::Forbidden(CidrClass::CloudMetadata)));
}

#[tokio::test]
async fn t11d_link_local_ipv4_rejected() {
    let g = guard_with("linklocal.example.com", vec![ipv4("169.254.1.2")]);
    let r = g.check("https://linklocal.example.com/").await;
    assert_eq!(r, Err(SsrfError::Forbidden(CidrClass::LinkLocal)));
}

#[tokio::test]
async fn t11e_public_ipv4_allowed() {
    let g = guard_with("public.example.com", vec![ipv4("8.8.8.8")]);
    let r = g.check("https://public.example.com/").await;
    assert_eq!(r, Ok(()));
}

#[tokio::test]
async fn t11f_ipv6_loopback_rejected() {
    let g = guard_with("v6loop.example.com", vec![ipv6("::1")]);
    let r = g.check("https://v6loop.example.com/").await;
    assert_eq!(r, Err(SsrfError::Forbidden(CidrClass::Loopback)));
}

#[tokio::test]
async fn t11g_ipv6_unique_local_rejected() {
    let g = guard_with("v6ula.example.com", vec![ipv6("fd00::1")]);
    let r = g.check("https://v6ula.example.com/").await;
    assert_eq!(r, Err(SsrfError::Forbidden(CidrClass::UniqueLocalIpv6)));
}

#[tokio::test]
async fn adv_r3_ipv6_ula_fc00_rejected() {
    // Adversarial R3 fix regression lock: RFC 4193 ULA is fc00::/7, covering
    // BOTH fc00::/8 and fd00::/8. Pre-fix, only fd00::/8 was blocked,
    // leaving fc00::/8 (centrally-assigned but reserved) reachable.
    let g = guard_with("v6ula-fc.example.com", vec![ipv6("fc00::1")]);
    let r = g.check("https://v6ula-fc.example.com/").await;
    assert_eq!(r, Err(SsrfError::Forbidden(CidrClass::UniqueLocalIpv6)));
}

#[tokio::test]
async fn t11h_ipv6_link_local_rejected() {
    let g = guard_with("v6ll.example.com", vec![ipv6("fe80::1")]);
    let r = g.check("https://v6ll.example.com/").await;
    assert_eq!(r, Err(SsrfError::Forbidden(CidrClass::LinkLocal)));
}

#[tokio::test]
async fn t11i_multi_ip_with_one_bad_rejected() {
    // Public + loopback in the same address set — partial-match rejection
    // (resolution-time DNS-rebinding defense).
    let g = guard_with(
        "mixed.example.com",
        vec![ipv4("8.8.8.8"), ipv4("127.0.0.1")],
    );
    let r = g.check("https://mixed.example.com/").await;
    assert_eq!(r, Err(SsrfError::Forbidden(CidrClass::Loopback)));
}

#[tokio::test]
async fn t11j_invalid_url() {
    let g = guard_with("anyhost.example.com", vec![ipv4("8.8.8.8")]);
    let r = g.check("not-a-url").await;
    assert!(matches!(r, Err(SsrfError::InvalidUrl(_))));
}

#[tokio::test]
async fn adv_ipv4_mapped_ipv6_loopback_rejected() {
    // Adversarial R1 fix regression lock: ::ffff:127.0.0.1 (IPv4-mapped IPv6
    // form of 127.0.0.1) MUST be rejected via the IPv4 loopback CIDR after
    // normalize_ip down-casts. Pre-fix, the v6 form bypassed both the v4
    // loopback (wrong family) and v6 loopback (different IPv6 address) checks.
    let g = guard_with("v4mapped.example.com", vec![ipv6("::ffff:127.0.0.1")]);
    let r = g.check("https://v4mapped.example.com/").await;
    assert_eq!(r, Err(SsrfError::Forbidden(CidrClass::Loopback)));
}

#[tokio::test]
async fn adv_ipv4_mapped_ipv6_metadata_rejected() {
    // Same defense for cloud metadata pin: ::ffff:169.254.169.254 normalizes
    // to v4 169.254.169.254, which hits the CloudMetadata pin first.
    let g = guard_with(
        "v4mapped-meta.example.com",
        vec![ipv6("::ffff:169.254.169.254")],
    );
    let r = g.check("https://v4mapped-meta.example.com/").await;
    assert_eq!(r, Err(SsrfError::Forbidden(CidrClass::CloudMetadata)));
}

#[tokio::test]
async fn adv_r2_6to4_ipv6_embedding_rejected() {
    // Adversarial R2 fix regression lock: 6to4 IPv6 (2002:V.V.V.V::) embeds
    // a v4 address; normalize_ip must extract it and check against forbidden
    // v4 CIDRs. 2002:7f00:1::/48 = 6to4 of 127.0.0.1.
    let g = guard_with("6to4loop.example.com", vec![ipv6("2002:7f00:0001::")]);
    let r = g.check("https://6to4loop.example.com/").await;
    assert_eq!(r, Err(SsrfError::Forbidden(CidrClass::Loopback)));
}

#[tokio::test]
async fn adv_r2_nat64_ipv6_embedding_rejected() {
    // RFC 6052 NAT64 well-known prefix: 64:ff9b::V.V.V.V — embeds v4 in last
    // 32 bits. 64:ff9b::7f00:1 = NAT64 of 127.0.0.1.
    let g = guard_with("nat64loop.example.com", vec![ipv6("64:ff9b::7f00:0001")]);
    let r = g.check("https://nat64loop.example.com/").await;
    assert_eq!(r, Err(SsrfError::Forbidden(CidrClass::Loopback)));
}

#[tokio::test]
async fn adv_r2_6to4_metadata_rejected() {
    // 6to4 of 169.254.169.254 = 2002:a9fe:a9fe:: — must classify as
    // CloudMetadata via normalize_ip → 169.254.169.254 → metadata pin.
    let g = guard_with("6to4meta.example.com", vec![ipv6("2002:a9fe:a9fe::")]);
    let r = g.check("https://6to4meta.example.com/").await;
    assert_eq!(r, Err(SsrfError::Forbidden(CidrClass::CloudMetadata)));
}

#[tokio::test]
async fn t11k_hostname_normalization_case_and_trailing_dot() {
    // Insert under lowercased no-trailing-dot key. MockResolver accepts only
    // lowercase keys; it should match BOTH `EVIL.com.` and `evil.com`.
    let resolver = MockResolver::new().with("example.com", vec![ipv4("8.8.8.8")]);
    let g = DefaultSsrfGuard::with_resolver(Box::new(resolver));
    let r1 = g.check("https://EVIL.com./").await;
    // EVIL is the host; not in MockResolver mapping (only example.com is).
    // Use example.com instead — the test verifies the normalization function.
    assert!(matches!(r1, Err(_)));

    // Now test that EVIL.com. and evil.com map to the same cache entry.
    let resolver2 = MockResolver::new().with("example.com", vec![ipv4("8.8.8.8")]);
    let g2 = DefaultSsrfGuard::with_resolver(Box::new(resolver2));
    let upper = g2.check("https://Example.COM./").await;
    let lower = g2.check("https://example.com/").await;
    assert_eq!(
        upper, lower,
        "case + trailing-dot must normalize identically"
    );
    assert_eq!(upper, Ok(()));
}

#[tokio::test]
async fn t11l_unspecified_ipv4_rejected() {
    // 0.0.0.0 ("this network", RFC 1122) routes to localhost on connect — must be blocked.
    // Round-11 adversarial W3 (0.0.0.0/8 added to the forbidden table, labeled Loopback).
    let g = guard_with("unspec.example.com", vec![ipv4("0.0.0.0")]);
    let r = g.check("https://unspec.example.com/").await;
    assert_eq!(r, Err(SsrfError::Forbidden(CidrClass::Loopback)));
}

#[tokio::test]
async fn t11m_ipv4_compatible_ipv6_rejected() {
    // Deprecated RFC 4291 IPv4-COMPATIBLE form `::a.b.c.d` (here `::127.0.0.1`) is NOT folded
    // by `to_ipv4_mapped()` and would otherwise slip past both the guard and the executor's
    // connect-time resolver. The `::/96` table entry blocks it. Round-11 adversarial W3.
    let g = guard_with("v4compat.example.com", vec![ipv6("::127.0.0.1")]);
    let r = g.check("https://v4compat.example.com/").await;
    assert_eq!(r, Err(SsrfError::Forbidden(CidrClass::Loopback)));
    // The IPv6 unspecified `::` is in the same `::/96` range.
    let g2 = guard_with("v6unspec.example.com", vec![ipv6("::")]);
    let r2 = g2.check("https://v6unspec.example.com/").await;
    assert_eq!(r2, Err(SsrfError::Forbidden(CidrClass::Loopback)));
}

// ─── Loopback exemptions ─────────────────────────────────────────────────────

fn exempting(urls: &[&str]) -> LoopbackExemptions {
    let mut exemptions = LoopbackExemptions::none();
    for url in urls {
        assert!(exemptions.allow_endpoint(url), "{url} can be exempt");
    }
    exemptions
}

// Only an http(s) URL without user info whose host is `localhost` or a loopback address
// literal can be exempt.
#[test]
fn only_loopback_endpoints_can_be_exempt() {
    for url in [
        "http://127.0.0.1:8931/mcp",
        "http://127.8.9.10/",
        "http://localhost:8931/mcp?x=1#frag",
        "http://LOCALHOST:8931/",
        "https://localhost/",
        "http://[::1]:9/",
        // A loopback address in another notation.
        "http://127.1:8931/",
        "https://2130706433/mcp",
        "https://0x7f.0.0.1/",
    ] {
        assert!(LoopbackExemptions::is_loopback_endpoint(url), "{url}");
        let mut exemptions = LoopbackExemptions::none();
        assert!(exemptions.allow_endpoint(url), "{url}");
        assert!(!exemptions.is_empty());
        assert!(exemptions.covers(url), "{url}");
    }
    for url in [
        "https://mcp.example.com/mcp",
        "http://10.0.0.1/",
        "http://192.168.1.1:8080/",
        "http://169.254.169.254/",
        "http://0.0.0.0:8931/",
        "http://[::ffff:127.0.0.1]:8931/",
        "http://[::]/",
        "http://localhost.example.com/",
        "http://localhost./",
        "http://user@127.0.0.1:8931/",
        "http://user:pw@localhost:8931/",
        "ftp://127.0.0.1/",
        "file:///etc/hosts",
        "127.0.0.1:8931",
        "not a url",
        "",
    ] {
        assert!(!LoopbackExemptions::is_loopback_endpoint(url), "{url}");
        let mut exemptions = LoopbackExemptions::none();
        assert!(!exemptions.allow_endpoint(url), "{url}");
        assert!(exemptions.is_empty(), "{url} exempts nothing");
        assert!(!exemptions.covers(url), "{url}");
    }
}

// An exemption is one host on one port: not another port, not the other name of the same
// machine, not a URL that only mentions the endpoint.
#[test]
fn an_exemption_covers_exactly_its_host_and_port() {
    let exemptions = exempting(&["http://127.0.0.1:8931/mcp", "https://localhost/mcp"]);

    for url in [
        "http://127.0.0.1:8931/",
        "http://127.0.0.1:8931/other/path?q=1",
        // The same address, written another way.
        "http://127.1:8931/mcp",
        "http://2130706433:8931/mcp",
        // The scheme's default port.
        "https://localhost/",
        "https://localhost:443/x",
        "http://localhost:443/x",
    ] {
        assert!(exemptions.covers(url), "{url}");
    }
    for url in [
        "http://127.0.0.1:8932/mcp",
        "http://127.0.0.1/mcp",
        "http://127.0.0.2:8931/mcp",
        "http://localhost:8931/mcp",
        "https://127.0.0.1/mcp",
        "http://localhost/mcp",
        "https://localhost:8443/mcp",
        "http://[::1]:8931/mcp",
        // The exempt endpoint as user info, a path or a query of another host.
        "http://127.0.0.1:8931@evil.example.com/",
        "http://evil.example.com/127.0.0.1:8931/",
        "http://evil.example.com/?next=http://127.0.0.1:8931/mcp",
        "http://user@127.0.0.1:8931/mcp",
        "ftp://127.0.0.1:8931/mcp",
    ] {
        assert!(!exemptions.covers(url), "{url}");
    }
    assert!(!LoopbackExemptions::none().covers("http://127.0.0.1:8931/mcp"));
}

// The guard lets an exempt endpoint through without asking the guard it wraps, and leaves
// every other URL to it.
#[tokio::test]
async fn the_exempting_guard_passes_exempt_endpoints_and_asks_the_inner_guard_otherwise() {
    // The inner guard knows no host, so any URL it is asked about fails.
    let unresolving = || -> Arc<dyn SsrfGuard> {
        Arc::new(DefaultSsrfGuard::with_resolver(Box::new(
            MockResolver::new(),
        )))
    };
    let guard = LoopbackExemptSsrfGuard::new(
        unresolving(),
        exempting(&["http://127.0.0.1:8931/mcp", "http://localhost:8931/mcp"]),
    );
    assert_eq!(guard.check("http://127.0.0.1:8931/mcp").await, Ok(()));
    assert_eq!(guard.check("http://localhost:8931/tools").await, Ok(()));
    assert_eq!(
        guard.check("http://127.0.0.1:8932/mcp").await,
        Err(SsrfError::DnsFailed),
        "another port is the inner guard's to decide"
    );

    // With a resolving inner guard, loopback outside the exemptions is still forbidden and a
    // public host still passes.
    let resolver = MockResolver::new()
        .with("127.0.0.1", vec![ipv4("127.0.0.1")])
        .with("localhost", vec![ipv4("127.0.0.1"), ipv6("::1")])
        .with("public.example.com", vec![ipv4("8.8.8.8")]);
    let guard = LoopbackExemptSsrfGuard::new(
        Arc::new(DefaultSsrfGuard::with_resolver(Box::new(resolver))),
        exempting(&["http://127.0.0.1:8931/mcp"]),
    );
    assert_eq!(guard.check("http://127.0.0.1:8931/mcp").await, Ok(()));
    for url in [
        "http://127.0.0.1:8932/mcp",
        "http://127.0.0.1/mcp",
        "http://localhost:8931/mcp",
    ] {
        assert_eq!(
            guard.check(url).await,
            Err(SsrfError::Forbidden(CidrClass::Loopback)),
            "{url}"
        );
    }
    assert_eq!(guard.check("https://public.example.com/").await, Ok(()));

    // No exemption: the guard is the inner guard.
    let plain = LoopbackExemptSsrfGuard::new(unresolving(), LoopbackExemptions::none());
    assert_eq!(
        plain.check("http://127.0.0.1:8931/mcp").await,
        Err(SsrfError::DnsFailed)
    );
}
