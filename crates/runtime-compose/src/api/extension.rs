//! What a host adds to the composition.

use std::fmt;

pub use futures::future::BoxFuture;

use super::error::ExtensionFailure;
use super::extension_cx::{ComposeCx, EmitError, SecretViewError, StartedCx, ViewError};
use super::host_functions::HostFunctionRegistrar;
use super::tools::ToolRegistrar;

/// A product (or test) addition to the composition. Trusted in-process code: the
/// registrars stop collisions and broken invariants; they are not a sandbox (ADR D2
/// trust model).
///
/// Order: `capabilities` → `inference` (only with `llm`) → `host_functions` → `tools`
/// (only with `tools`) → `client_families` → (Client API bind) → `on_started`
/// (spawned). `id`, `capabilities` and `needs_secret_store` are declarations, read
/// once before any side effect. `shutdown` runs in shutdown step 3, reverse
/// registration order, for every extension of a composition whose wiring started —
/// also when its other callbacks never ran (a startup failure); it must then be a
/// no-op.
pub trait ComposeExtension: Send + Sync + 'static {
    /// `[a-z][a-z0-9-]{0,31}`, not reserved, unique per compose.
    fn id(&self) -> &'static str;

    /// Extra capability names a guest may declare, each `<id>.<name>`.
    fn capabilities(&self) -> &'static [&'static str] {
        &[]
    }

    /// Host functions, after `inference` and before the host is built. Always
    /// called (independent of the home's declarations).
    fn host_functions(
        &self,
        cx: &ComposeCx,
        reg: &mut HostFunctionRegistrar,
    ) -> Result<(), ExtensionError> {
        let _ = (cx, reg);
        Ok(())
    }

    /// Native tools, after the OSS tools (skills, pack skill tools, `data`) and
    /// before pack tool-exposure reconciliation and the tool inventory snapshot.
    /// Called only when the home declares `tools`.
    fn tools<'a>(
        &'a self,
        cx: &'a ComposeCx,
        reg: &'a mut ToolRegistrar,
    ) -> BoxFuture<'a, Result<(), ExtensionError>> {
        let _ = (cx, reg);
        Box::pin(async { Ok(()) })
    }

    /// `true` asks for [`ComposeCx::secrets`](crate::api::ComposeCx::secrets), a view
    /// limited to `ext/<id>/…`.
    fn needs_secret_store(&self) -> bool {
        false
    }

    /// Spawned (never awaited by compose) after the Client API is bound and the
    /// discovery file is written. Failure or panic: logged, extension marked failed,
    /// runtime stays up. Cancelled (dropped at its next await) in shutdown step 3 if
    /// still running.
    fn on_started<'a>(&'a self, _cx: &'a StartedCx) -> BoxFuture<'a, Result<(), ExtensionError>> {
        Box::pin(async { Ok(()) })
    }

    /// Shutdown step 3: reverse registration order, `catch_unwind`, 5-second bound,
    /// then abandoned.
    fn shutdown<'a>(&'a self) -> BoxFuture<'a, ()> {
        Box::pin(async {})
    }
}

/// The failure an extension returns from a callback. Its text is logged / put in
/// [`ComposeError::Extension`](crate::api::ComposeError::Extension); it never reaches
/// the Client API wire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtensionError {
    message: String,
}

impl ExtensionError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for ExtensionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for ExtensionError {}

impl From<EmitError> for ExtensionError {
    fn from(error: EmitError) -> Self {
        Self::new(error.to_string())
    }
}

impl From<SecretViewError> for ExtensionError {
    fn from(error: SecretViewError) -> Self {
        Self::new(error.to_string())
    }
}

impl From<ViewError> for ExtensionError {
    fn from(error: ViewError) -> Self {
        Self::new(error.to_string())
    }
}

/// Health of one extension ([`ComposedRuntime::health`](crate::api::ComposedRuntime::health)
/// `.extensions`).
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExtensionHealth {
    pub id: &'static str,
    pub state: ExtensionState,
}

/// Where one extension is in its start.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExtensionState {
    /// From `compose` until `on_started` returns; also when shutdown cancelled it,
    /// or when it was never spawned because shutdown had already begun.
    Starting,
    Started,
    /// `on_started` returned `Err` (`Failed(sanitized message)`) or panicked
    /// (`Panicked(panic_text)`). Sticky; the extension's routes/ports keep serving.
    Failed(ExtensionFailure),
}
