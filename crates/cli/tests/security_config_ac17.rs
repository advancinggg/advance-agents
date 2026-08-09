//! MODULE-012 AC-17 — END-TO-END hot-reload witness through the PRODUCTION
//! `live_security_components` helper (the exact path the cli composition root
//! wires into every HTTP security chain). A real swappable `RuntimeConfigProvider`
//! drives a real `DefaultLeakDetector` / `DefaultRateLimiter`: editing the live
//! config flips a real scan/limiter result with no rebuild — proving
//! `security.*` hot-reload applies without runtime restart.

use advance_cli::channels_boot::live_security_components;
use advance_runtime::config::{RuntimeConfig, RuntimeConfigProvider};
use advance_shared_types::security_validator::{LeakDetector, ScanContext, ScanResult};
use cap_http::RateLimiter;
use std::sync::{Arc, RwLock};

const BASE_YAML: &str = r#"
wasm:
  max_memory_pages: 512
  epoch_interruption_ms: 50
  fuel_enabled: true
llm-providers: []
cron:
  max_jitter_ratio: 0.05
git:
  gc_interval_hours: 12
  max_tracked_file_mb: 5
circuit-breakers: []
secrets:
  master-key-source: env-var
  env-var-name: MY_KEY
users: []
post-processor:
  llm-model: fast
  llm-failure-cooldown-seconds: 300
"#;

/// Swappable `RuntimeConfigProvider` — `set()` simulates a hot-reload by
/// replacing the live snapshot (the production `RuntimeConfigWatcher` does the
/// same on a file change). Shared via `Arc`, so the closures inside
/// `live_security_components` observe the swap.
struct SwapProvider {
    cfg: RwLock<Arc<RuntimeConfig>>,
}

impl SwapProvider {
    fn new(cfg: RuntimeConfig) -> Self {
        Self {
            cfg: RwLock::new(Arc::new(cfg)),
        }
    }
    fn set(&self, cfg: RuntimeConfig) {
        *self.cfg.write().unwrap() = Arc::new(cfg);
    }
}

impl RuntimeConfigProvider for SwapProvider {
    fn current(&self) -> Arc<RuntimeConfig> {
        Arc::clone(&self.cfg.read().unwrap())
    }
    fn subscribe(&self) -> tokio::sync::mpsc::Receiver<Arc<RuntimeConfig>> {
        let (_tx, rx) = tokio::sync::mpsc::channel(1);
        rx
    }
    fn last_error(&self) -> Option<String> {
        None
    }
}

fn base_config() -> RuntimeConfig {
    serde_yml::from_str(BASE_YAML).expect("base config parses")
}

/// E2E: the production helper's leak detector reads `max_scan_bytes` live —
/// editing the config flips a real over-cap scan `Blocked → Clean`.
#[test]
fn ac17_e2e_leak_detector_hot_reload_via_production_helper() {
    let mut small = base_config();
    small.security.leak_detector.max_scan_bytes = 10;
    let provider = Arc::new(SwapProvider::new(small.clone()));

    let (leak, _ssrf, _rate) =
        live_security_components(Some(provider.clone() as Arc<dyn RuntimeConfigProvider>));

    let text = "hello world this is a fine clean message"; // >10 bytes, no leak patterns
    assert!(
        matches!(
            leak.scan(&text, ScanContext::HttpOutbound),
            ScanResult::Blocked { .. }
        ),
        "over-cap scan Blocked at max_scan_bytes=10"
    );

    // Hot-reload: bump the cap. The SAME detector (already built) now passes.
    let mut big = base_config();
    big.security.leak_detector.max_scan_bytes = 1024 * 1024;
    provider.set(big);
    assert!(
        leak.scan(&text, ScanContext::HttpOutbound).is_clean(),
        "scan Clean after max_scan_bytes hot-reloaded to 1 MiB — no restart"
    );
}

/// E2E: the production helper's rate limiter reads `per_component_rps` live —
/// raising it admits a request that was throttled at the low value.
#[test]
fn ac17_e2e_rate_limit_hot_reload_via_production_helper() {
    let mut low = base_config();
    low.security.rate_limit.per_component_rps = 1.0;
    let provider = Arc::new(SwapProvider::new(low));

    let (_leak, _ssrf, rate) =
        live_security_components(Some(provider.clone() as Arc<dyn RuntimeConfigProvider>));

    // rps = 1.0 → 2nd immediate request on host-a throttled.
    assert!(rate.check("agent", "host-a").is_ok());
    assert!(
        rate.check("agent", "host-a").is_err(),
        "throttled at rps=1.0"
    );

    // Hot-reload rps up; a fresh cell (host-b) admits both requests.
    let mut high = base_config();
    high.security.rate_limit.per_component_rps = 1000.0;
    provider.set(high);
    assert!(rate.check("agent", "host-b").is_ok());
    assert!(
        rate.check("agent", "host-b").is_ok(),
        "admitted after per_component_rps hot-reloaded up — no restart"
    );
}
