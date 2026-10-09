//! Host functions an extension registers onto the composition.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::{Arc, Mutex, PoisonError};

use advance_runtime::host_registry::{MAX_SPECS_PER_CAPABILITY, MAX_SPEC_STRING_LEN};

pub use advance_runtime::host_registry::{HostCallContext, HostCallError, HostFunctionHandler};
pub use wasmtime::component::types::ComponentFunc;
pub use wasmtime::component::Val;

use super::extension::ExtensionError;

/// Records the extension's host functions; validated at [`register`](Self::register),
/// replayed into the host registry after every extension's `host_functions` returned.
///
/// # Containment
///
/// Every registered handler runs behind a `catch_unwind` adapter, both while it builds
/// its future and while that future is polled. A panic is logged under
/// [`EXT_HOST_FUNCTION_PANICKED`](crate::api::log_keys::EXT_HOST_FUNCTION_PANICKED),
/// never with its payload, and becomes that call's typed error:
///
/// - **With an error slot** — the function's single result is `result<_, string>`
///   (answered `err("<HostFunctionFailure>")`), or its [`PanicAnswer`] returns values
///   of the guest's result types — the call answers in band: the guest's call returns
///   that value and the guest goes on.
/// - **Without one**, the call traps and the guest's export call fails. In an agent's
///   message turn, that turn ends with its typed error (the turn error any trap
///   gives), and the agent loop starts a fresh instance of the agent's component
///   (its `init` export runs again) before the agent's next turn, so that turn runs
///   normally. The instance's linear memory is not kept; the state the host carries
///   between turns is.
///
/// A handler that returns `Err(HostCallError)` has not panicked: the call traps as an
/// OSS host function's error does, and the agent loop does not replace the agent's
/// instance (its later turns fail until the runtime restarts). Give a function that
/// can fail an error slot in its WIT result.
pub struct HostFunctionRegistrar {
    extension: &'static str,
    declared: &'static [&'static str],
    taken: Arc<Mutex<BTreeMap<(String, String), &'static str>>>,
    counts: Arc<Mutex<BTreeMap<String, usize>>>,
    pending: Vec<PendingSpec>,
    refusals: Vec<HostFunctionRefusal>,
}

/// One accepted registration, wrapped into a contained handler at replay.
pub(crate) struct PendingSpec {
    pub capability: String,
    pub namespace: String,
    pub name: String,
    pub handler: Arc<dyn HostFunctionHandler>,
    pub idempotent: bool,
    pub panic_answer: Option<PanicAnswer>,
    pub extension: &'static str,
}

impl HostFunctionRegistrar {
    pub(crate) fn new(
        extension: &'static str,
        declared: &'static [&'static str],
        taken: Arc<Mutex<BTreeMap<(String, String), &'static str>>>,
        counts: Arc<Mutex<BTreeMap<String, usize>>>,
    ) -> Self {
        Self {
            extension,
            declared,
            taken,
            counts,
            pending: Vec::new(),
            refusals: Vec::new(),
        }
    }

    pub fn extension_id(&self) -> &'static str {
        self.extension
    }

    /// This extension's `capabilities()` (the composer's cached copy).
    pub fn declared_capabilities(&self) -> &[&'static str] {
        self.declared
    }

    /// Validates and records. Every refusal is also recorded: `compose` fails with
    /// the first one even if the extension ignores the `Err`.
    pub fn register(&mut self, def: HostFunctionDef) -> Result<(), HostFunctionRefusal> {
        if let Err(refusal) = self.check(&def) {
            self.refusals.push(refusal.clone());
            return Err(refusal);
        }
        {
            let mut taken = self.taken.lock().unwrap_or_else(PoisonError::into_inner);
            taken.insert((def.namespace.clone(), def.name.clone()), self.extension);
        }
        {
            let mut counts = self.counts.lock().unwrap_or_else(PoisonError::into_inner);
            *counts.entry(def.capability.clone()).or_insert(0) += 1;
        }
        self.pending.push(PendingSpec {
            capability: def.capability,
            namespace: def.namespace,
            name: def.name,
            handler: def.handler,
            idempotent: def.idempotent,
            panic_answer: def.panic_answer,
            extension: self.extension,
        });
        Ok(())
    }

    pub(crate) fn first_refusal(&self) -> Option<&HostFunctionRefusal> {
        self.refusals.first()
    }

    pub(crate) fn take_pending(&mut self) -> Vec<PendingSpec> {
        std::mem::take(&mut self.pending)
    }

    /// First declared capability that has no function in this registrar's pending.
    pub(crate) fn capability_without_function(&self) -> Option<&'static str> {
        self.declared
            .iter()
            .copied()
            .find(|cap| !self.pending.iter().any(|spec| spec.capability == *cap))
    }

    fn check(&self, def: &HostFunctionDef) -> Result<(), HostFunctionRefusal> {
        if def.namespace.starts_with("advance:") || def.namespace.starts_with("wasi:") {
            return Err(HostFunctionRefusal::ReservedNamespace {
                namespace: def.namespace.clone(),
            });
        }
        if let Err(reason) = check_namespace(&def.namespace) {
            return Err(HostFunctionRefusal::Malformed {
                namespace: def.namespace.clone(),
                name: def.name.clone(),
                reason,
            });
        }
        if let Err(reason) = check_function_name(&def.name) {
            return Err(HostFunctionRefusal::Malformed {
                namespace: def.namespace.clone(),
                name: def.name.clone(),
                reason,
            });
        }
        if !self.declared.iter().any(|cap| *cap == def.capability) {
            return Err(HostFunctionRefusal::UndeclaredCapability {
                capability: def.capability.clone(),
                namespace: def.namespace.clone(),
                name: def.name.clone(),
            });
        }
        {
            let taken = self.taken.lock().unwrap_or_else(PoisonError::into_inner);
            if let Some(owner) = taken.get(&(def.namespace.clone(), def.name.clone())) {
                return Err(HostFunctionRefusal::Duplicate {
                    namespace: def.namespace.clone(),
                    name: def.name.clone(),
                    owner: *owner,
                });
            }
        }
        {
            let counts = self.counts.lock().unwrap_or_else(PoisonError::into_inner);
            let n = counts.get(&def.capability).copied().unwrap_or(0);
            if n >= MAX_SPECS_PER_CAPABILITY {
                return Err(HostFunctionRefusal::TooMany {
                    capability: def.capability.clone(),
                    limit: MAX_SPECS_PER_CAPABILITY,
                });
            }
        }
        Ok(())
    }
}

fn check_namespace(namespace: &str) -> Result<(), &'static str> {
    if namespace.len() > MAX_SPEC_STRING_LEN {
        return Err("longer than 256 bytes");
    }
    let (body, version) = match namespace.rsplit_once('@') {
        Some((body, version)) => (body, Some(version)),
        None => (namespace, None),
    };
    if let Some(version) = version {
        if semver::Version::parse(version).is_err() {
            return Err("not <ns>:<pkg>/<iface>[@<semver>]");
        }
    }
    let Some((pkg_ns, iface)) = body.split_once('/') else {
        return Err("not <ns>:<pkg>/<iface>[@<semver>]");
    };
    if iface.contains('/') {
        return Err("not <ns>:<pkg>/<iface>[@<semver>]");
    }
    let Some((ns, pkg)) = pkg_ns.split_once(':') else {
        return Err("not <ns>:<pkg>/<iface>[@<semver>]");
    };
    if pkg.contains(':') || !is_wit_label(ns) || !is_wit_label(pkg) || !is_wit_label(iface) {
        return Err("not <ns>:<pkg>/<iface>[@<semver>]");
    }
    Ok(())
}

fn check_function_name(name: &str) -> Result<(), &'static str> {
    if name.len() > MAX_SPEC_STRING_LEN {
        return Err("longer than 256 bytes");
    }
    if !is_wit_label(name) {
        return Err("not a WIT label");
    }
    Ok(())
}

/// WIT kebab-case label: `[a-z][a-z0-9]*(-[a-z0-9]*)*`.
fn is_wit_label(s: &str) -> bool {
    let bytes = s.as_bytes();
    if bytes.is_empty() || !bytes[0].is_ascii_lowercase() {
        return false;
    }
    let mut i = 1;
    while i < bytes.len() && (bytes[i].is_ascii_lowercase() || bytes[i].is_ascii_digit()) {
        i += 1;
    }
    while i < bytes.len() {
        if bytes[i] != b'-' {
            return false;
        }
        i += 1;
        while i < bytes.len() && (bytes[i].is_ascii_lowercase() || bytes[i].is_ascii_digit()) {
            i += 1;
        }
    }
    true
}

/// One host function an extension wants to register.
#[non_exhaustive]
pub struct HostFunctionDef {
    pub capability: String,
    pub namespace: String,
    pub name: String,
    pub handler: Arc<dyn HostFunctionHandler>,
    pub idempotent: bool,
    pub panic_answer: Option<PanicAnswer>,
}

impl HostFunctionDef {
    pub fn new(
        capability: impl Into<String>,
        namespace: impl Into<String>,
        name: impl Into<String>,
        handler: Arc<dyn HostFunctionHandler>,
    ) -> Self {
        Self {
            capability: capability.into(),
            namespace: namespace.into(),
            name: name.into(),
            handler,
            idempotent: false,
            panic_answer: None,
        }
    }

    pub fn idempotent(mut self, idempotent: bool) -> Self {
        self.idempotent = idempotent;
        self
    }

    /// The value the guest receives when the handler panics. Optional: without one,
    /// a function whose single result is `result<T, string>` answers
    /// `err("<HostFunctionFailure Display>")` automatically; any other result shape
    /// traps the call (see [`HostFunctionRegistrar`], Containment).
    pub fn with_panic_answer(mut self, answer: PanicAnswer) -> Self {
        self.panic_answer = Some(answer);
        self
    }
}

/// The value a guest receives when the handler panics. Carries no panic payload.
#[derive(Clone)]
pub struct PanicAnswer(Arc<dyn Fn(&HostFunctionFailure) -> Vec<Val> + Send + Sync>);

impl PanicAnswer {
    pub fn new(answer: impl Fn(&HostFunctionFailure) -> Vec<Val> + Send + Sync + 'static) -> Self {
        Self(Arc::new(answer))
    }

    pub(crate) fn call(&self, failure: &HostFunctionFailure) -> Vec<Val> {
        (self.0)(failure)
    }
}

impl fmt::Debug for PanicAnswer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PanicAnswer")
    }
}

/// Passed to a [`PanicAnswer`] and used as the automatic in-band error text;
/// carries no panic payload.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostFunctionFailure {
    pub extension: &'static str,
    pub namespace: String,
    pub name: String,
}

impl fmt::Display for HostFunctionFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "extension {}: host function {}::{} failed",
            self.extension, self.namespace, self.name
        )
    }
}

/// Why [`HostFunctionRegistrar::register`] refused a function.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostFunctionRefusal {
    ReservedNamespace {
        namespace: String,
    },
    Malformed {
        namespace: String,
        name: String,
        reason: &'static str,
    },
    UndeclaredCapability {
        capability: String,
        namespace: String,
        name: String,
    },
    Duplicate {
        namespace: String,
        name: String,
        owner: &'static str,
    },
    TooMany {
        capability: String,
        limit: usize,
    },
    CapabilityWithoutFunction {
        capability: String,
    },
}

impl fmt::Display for HostFunctionRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HostFunctionRefusal::ReservedNamespace { namespace } => write!(
                f,
                "namespace {namespace:?} is reserved (advance:* and wasi:* belong to OSS)"
            ),
            HostFunctionRefusal::Malformed {
                namespace,
                name,
                reason,
            } => write!(f, "{namespace}::{name}: {reason}"),
            HostFunctionRefusal::UndeclaredCapability {
                capability,
                namespace,
                name,
            } => write!(
                f,
                "{namespace}::{name} is registered under {capability:?}, which this extension does not declare"
            ),
            HostFunctionRefusal::Duplicate {
                namespace,
                name,
                owner,
            } => write!(
                f,
                "{namespace}::{name} is already registered by extension {owner}"
            ),
            HostFunctionRefusal::TooMany { capability, limit } => {
                write!(
                    f,
                    "more than {limit} host functions under {capability:?}"
                )
            }
            HostFunctionRefusal::CapabilityWithoutFunction { capability } => {
                write!(f, "capability {capability:?} has no host function")
            }
        }
    }
}

impl std::error::Error for HostFunctionRefusal {}

impl From<HostFunctionRefusal> for ExtensionError {
    fn from(refusal: HostFunctionRefusal) -> Self {
        ExtensionError::new(refusal.to_string())
    }
}
