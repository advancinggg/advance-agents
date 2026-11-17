//! The family: specs, handler plumbing and registration.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use advance_runtime::callable_registry::{
    CallableError, CallableHandler, CallableOutcome, CallableRegistry, CallableSpec,
};
use advance_runtime::host_registry::HostCallContext;
use advance_shared_types::security_validator::{LeakDetector, SsrfGuard};
use advance_shared_types::traits::{EventBusEmit, GrantCheck, PromptInjectionHelpers};
use advance_shared_types::ui::{BrowserDriverPort, ScreenDriverPort, UiPolicyReader, UiSurface};
use serde_json::Value;

use crate::{browser, callable_name, screen, BROWSER_NS, SCREEN_NS};

/// What the family needs from the composition.
pub struct UiDeps {
    /// The L1 gate; called with the request's `origins` / `targets` (CONTRACT-122).
    pub grant: Arc<dyn GrantCheck>,
    /// The agent's `browser` / `screen` grant knobs.
    pub policy: Arc<dyn UiPolicyReader>,
    /// Inbound content scan over every observation (`ScanContext::ToolOutput`).
    pub leak: Arc<dyn LeakDetector>,
    pub events: Arc<dyn EventBusEmit>,
    /// Top-level navigation URLs pass it unless the origin is named exactly by
    /// the grant (`policy::exactly_allowlisted`). `None` = no SSRF check (tests).
    pub ssrf: Option<Arc<dyn SsrfGuard>>,
    /// Prompt-injection neutralisation over observation bodies (the runtime's
    /// untrusted-content policy, as for fetched web pages): flagged Critical /
    /// High patterns are replaced and the body is wrapped as untrusted data.
    /// `None` = no injection pass (tests).
    pub injection: Option<Arc<dyn PromptInjectionHelpers>>,
}

/// The drivers the extensions registered. Either may be absent: the family's
/// callables then answer [`crate::NO_DRIVER_REASON`].
#[derive(Clone, Default)]
pub struct UiDrivers {
    pub browser: Option<Arc<dyn BrowserDriverPort>>,
    pub screen: Option<Arc<dyn ScreenDriverPort>>,
}

impl UiDrivers {
    pub fn none() -> Self {
        Self::default()
    }

    pub fn browser(driver: Arc<dyn BrowserDriverPort>) -> Self {
        Self {
            browser: Some(driver),
            screen: None,
        }
    }

    pub fn screen(driver: Arc<dyn ScreenDriverPort>) -> Self {
        Self {
            browser: None,
            screen: Some(driver),
        }
    }

    pub fn both(browser: Arc<dyn BrowserDriverPort>, screen: Arc<dyn ScreenDriverPort>) -> Self {
        Self {
            browser: Some(browser),
            screen: Some(screen),
        }
    }
}

/// Which families to register — the capabilities the home declares (L0).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UiSurfaces {
    pub browser: bool,
    pub screen: bool,
}

impl UiSurfaces {
    pub const BOTH: Self = Self {
        browser: true,
        screen: true,
    };
    pub const BROWSER: Self = Self {
        browser: true,
        screen: false,
    };
    pub const SCREEN: Self = Self {
        browser: false,
        screen: true,
    };

    pub fn any(self) -> bool {
        self.browser || self.screen
    }
}

/// One verb of a family, as the catalog sees it.
pub struct VerbSpec {
    pub verb: &'static str,
    pub description: String,
    pub idempotent: bool,
    pub parameters: Value,
}

/// The registered family: its specs and the shared handler state.
pub struct UiFamily {
    specs: Vec<CallableSpec>,
}

impl UiFamily {
    pub fn new(deps: UiDeps, drivers: UiDrivers, surfaces: UiSurfaces) -> Self {
        let deps = Arc::new(deps);
        let mut specs = Vec::new();
        if surfaces.browser {
            for v in browser::verbs() {
                specs.push(spec(UiSurface::Browser, BROWSER_NS, v, &deps, &drivers));
            }
        }
        if surfaces.screen {
            for v in screen::verbs() {
                specs.push(spec(UiSurface::Screen, SCREEN_NS, v, &deps, &drivers));
            }
        }
        Self { specs }
    }

    pub fn specs(&self) -> &[CallableSpec] {
        &self.specs
    }

    /// Catalog names in registration order.
    pub fn names(&self) -> Vec<String> {
        self.specs.iter().map(|s| s.name.clone()).collect()
    }

    pub fn register(&self, registry: &dyn CallableRegistry) {
        for spec in &self.specs {
            registry.register(spec.clone());
        }
    }

    /// Invoke one callable directly (tests and the conformance suite). The
    /// dispatcher's gates (grant at capability level, breaker, repetition,
    /// JSON-Schema validation) are NOT applied here; the family's own checks
    /// are. `ctx.capability` / `ctx.function` are set from the spec, as the
    /// dispatcher does.
    pub async fn invoke(
        &self,
        name: &str,
        mut ctx: HostCallContext,
        call_id: &str,
        arguments: Value,
    ) -> Result<CallableOutcome, CallableError> {
        let spec = self
            .specs
            .iter()
            .find(|s| s.name == name)
            .ok_or_else(|| CallableError::NotFound(name.to_string()))?;
        ctx.capability = spec.capability.clone();
        ctx.function = spec.original_function.clone();
        spec.handler.call(ctx, call_id.to_string(), arguments).await
    }
}

/// Build the family and register it with the Layer 3 registry.
pub fn register_ui_callables(
    registry: &dyn CallableRegistry,
    deps: UiDeps,
    drivers: UiDrivers,
    surfaces: UiSurfaces,
) -> UiFamily {
    let family = UiFamily::new(deps, drivers, surfaces);
    family.register(registry);
    family
}

fn spec(
    surface: UiSurface,
    namespace: &str,
    v: VerbSpec,
    deps: &Arc<UiDeps>,
    drivers: &UiDrivers,
) -> CallableSpec {
    CallableSpec {
        capability: surface.capability().to_string(),
        name: callable_name(surface, v.verb),
        description: v.description,
        parameters: v.parameters,
        idempotent: v.idempotent,
        original_function: format!("{namespace}::{}", v.verb),
        handler: Arc::new(UiHandler {
            surface,
            verb: v.verb,
            deps: Arc::clone(deps),
            drivers: drivers.clone(),
        }),
    }
}

struct UiHandler {
    surface: UiSurface,
    verb: &'static str,
    deps: Arc<UiDeps>,
    drivers: UiDrivers,
}

impl CallableHandler for UiHandler {
    fn call(
        &self,
        ctx: HostCallContext,
        call_id: String,
        arguments: Value,
    ) -> Pin<Box<dyn Future<Output = Result<CallableOutcome, CallableError>> + Send + 'static>>
    {
        let deps = Arc::clone(&self.deps);
        let drivers = self.drivers.clone();
        let surface = self.surface;
        let verb = self.verb;
        Box::pin(async move {
            match surface {
                UiSurface::Browser => {
                    browser::invoke(
                        &deps,
                        drivers.browser.as_ref(),
                        &ctx,
                        verb,
                        call_id,
                        arguments,
                    )
                    .await
                }
                UiSurface::Screen => {
                    screen::invoke(
                        &deps,
                        drivers.screen.as_ref(),
                        &ctx,
                        verb,
                        call_id,
                        arguments,
                    )
                    .await
                }
            }
        })
    }
}
