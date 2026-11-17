//! Test doubles for the family's dependencies, shared by this crate's tests,
//! the conformance suite and product driver tests.

use std::sync::{Arc, Mutex};

use advance_runtime::host_registry::HostCallContext;
use advance_shared_types::capability::{CapParams, GrantDecision};
use advance_shared_types::event::Event;
use advance_shared_types::security_validator::{LeakDetector, ScanContext, ScanResult};
use advance_shared_types::traits::{EventBusEmit, GrantCheck};
use advance_shared_types::ui::{
    AllowRule, BrowserDriverPort, BrowserGrantPolicy, ScreenDriverPort, ScreenGrantPolicy,
    UiPolicyReader, BROWSER_CAPABILITY, SCREEN_CAPABILITY,
};
use serde_json::Value;

use crate::family::{UiDeps, UiDrivers, UiFamily, UiSurfaces};

/// The one place a test builds a `HostCallContext` (the dispatcher stamps
/// `capability` / `function` from the spec; `UiFamily::invoke` does the same).
pub fn ctx(agent_id: &str) -> HostCallContext {
    HostCallContext {
        agent_id: agent_id.to_string(),
        trace_id: "trace-ui-test".to_string(),
        turn_id: None,
        transcript_scope: None,
        capability: String::new(),
        function: String::new(),
        run_id: None,
        iteration: None,
    }
}

/// A fixed per-agent policy.
#[derive(Clone, Debug, Default)]
pub struct StaticUiPolicy {
    pub browser: Option<BrowserGrantPolicy>,
    pub screen: Option<ScreenGrantPolicy>,
}

impl UiPolicyReader for StaticUiPolicy {
    fn browser_policy(&self, _agent_id: &str) -> Option<BrowserGrantPolicy> {
        self.browser.clone()
    }

    fn screen_policy(&self, _agent_id: &str) -> Option<ScreenGrantPolicy> {
        self.screen.clone()
    }
}

/// One recorded `GrantCheck::check` call.
#[derive(Clone, Debug, PartialEq)]
pub struct GrantCall {
    pub agent_id: String,
    pub capability: String,
    pub function: String,
    pub params: Value,
}

/// An allowlist gate for tests of the family: capability-level checks (no
/// params) pass when the capability is granted; `{origins}` / `{targets}`
/// params are matched with the same rules as the policy's `AllowRule`
/// (`origin_covered` / exact app id). The real CONTRACT-122 rules live in
/// cap-grant and are tested there. Every call is recorded.
#[derive(Debug, Default)]
pub struct AllowlistGrant {
    pub browser: Option<AllowRule>,
    pub screen: Option<AllowRule>,
    calls: Mutex<Vec<GrantCall>>,
}

impl AllowlistGrant {
    pub fn new(browser: Option<AllowRule>, screen: Option<AllowRule>) -> Self {
        Self {
            browser,
            screen,
            calls: Mutex::new(Vec::new()),
        }
    }

    /// Mirror a static policy: granted surfaces with their allowlists.
    pub fn from_policy(policy: &StaticUiPolicy) -> Self {
        Self::new(
            policy.browser.as_ref().map(|p| p.origins.clone()),
            policy.screen.as_ref().map(|p| p.targets.clone()),
        )
    }

    pub fn allow_all() -> Self {
        Self::new(Some(AllowRule::Any), Some(AllowRule::Any))
    }

    pub fn calls(&self) -> Vec<GrantCall> {
        self.calls.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }
}

impl GrantCheck for AllowlistGrant {
    fn check(
        &self,
        agent_id: &str,
        capability: &str,
        function: &str,
        params: &CapParams,
    ) -> GrantDecision {
        self.calls
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(GrantCall {
                agent_id: agent_id.to_string(),
                capability: capability.to_string(),
                function: function.to_string(),
                params: params.as_value().clone(),
            });
        let (rule, key) = match capability {
            BROWSER_CAPABILITY => (&self.browser, "origins"),
            SCREEN_CAPABILITY => (&self.screen, "targets"),
            other => return GrantDecision::Deny(format!("no grant for capability {other}")),
        };
        let Some(rule) = rule else {
            return GrantDecision::Deny(format!("no active {capability} grant"));
        };
        let v = params.as_value();
        let empty = v.is_null() || v.as_object().is_some_and(|o| o.is_empty());
        if empty {
            return GrantDecision::Allow;
        }
        match v.get(key).and_then(Value::as_str) {
            Some(value) => {
                let covered = match capability {
                    BROWSER_CAPABILITY => rule.covers_origin(value),
                    _ => rule.covers_target(value),
                };
                if covered {
                    GrantDecision::Allow
                } else {
                    GrantDecision::Deny(format!("{value} is not covered by the grant's {key}"))
                }
            }
            None => GrantDecision::Deny(format!("unsupported params for {capability}: {v}")),
        }
    }
}

/// A scan that finds nothing.
#[derive(Debug, Default)]
pub struct NoScan;

impl LeakDetector for NoScan {
    fn scan(&self, _text: &str, _context: ScanContext) -> ScanResult {
        ScanResult::Clean
    }

    fn scan_headers(&self, _headers: &[(String, String)]) -> ScanResult {
        ScanResult::Clean
    }
}

/// Records every emitted event.
#[derive(Debug, Default)]
pub struct CaptureBus {
    events: Mutex<Vec<Event>>,
}

impl CaptureBus {
    pub fn events(&self) -> Vec<Event> {
        self.events
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    pub fn types(&self) -> Vec<String> {
        self.events().into_iter().map(|e| e.event_type).collect()
    }

    pub fn count(&self, event_type: &str) -> usize {
        self.events()
            .iter()
            .filter(|e| e.event_type == event_type)
            .count()
    }
}

impl EventBusEmit for CaptureBus {
    fn emit(&self, event: Event) {
        self.events
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(event);
    }
}

/// Dependencies with no scan, no SSRF guard and no injection pass.
pub fn deps(
    policy: Arc<dyn UiPolicyReader>,
    grant: Arc<dyn GrantCheck>,
    bus: Arc<CaptureBus>,
) -> UiDeps {
    UiDeps {
        grant,
        policy,
        leak: Arc::new(NoScan),
        events: bus,
        ssrf: None,
        injection: None,
    }
}

/// A browser family over `driver` with `policy` (grant mirrors the policy).
pub fn browser_family(
    driver: Arc<dyn BrowserDriverPort>,
    policy: BrowserGrantPolicy,
) -> (UiFamily, Arc<AllowlistGrant>, Arc<CaptureBus>) {
    let static_policy = StaticUiPolicy {
        browser: Some(policy),
        screen: None,
    };
    let grant = Arc::new(AllowlistGrant::from_policy(&static_policy));
    let bus = Arc::new(CaptureBus::default());
    let family = UiFamily::new(
        deps(Arc::new(static_policy), grant.clone(), bus.clone()),
        UiDrivers::browser(driver),
        UiSurfaces::BROWSER,
    );
    (family, grant, bus)
}

/// A screen family over `driver` with `policy` (grant mirrors the policy).
pub fn screen_family(
    driver: Arc<dyn ScreenDriverPort>,
    policy: ScreenGrantPolicy,
) -> (UiFamily, Arc<AllowlistGrant>, Arc<CaptureBus>) {
    let static_policy = StaticUiPolicy {
        browser: None,
        screen: Some(policy),
    };
    let grant = Arc::new(AllowlistGrant::from_policy(&static_policy));
    let bus = Arc::new(CaptureBus::default());
    let family = UiFamily::new(
        deps(Arc::new(static_policy), grant.clone(), bus.clone()),
        UiDrivers::screen(driver),
        UiSurfaces::SCREEN,
    );
    (family, grant, bus)
}
