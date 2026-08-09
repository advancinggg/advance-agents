//! Bootstrap construction surface — Slice AE (2026-05-09).
//!
//! [`RuntimeHost`] holds the full Arc graph that downstream modules
//! (M005/M006/M007/M014) consume to write their integration tests against the
//! runtime: a config watcher, host registry, circuit-breaker bus, grant check,
//! capability injector, sqlite index handle, component runtime, and workspace
//! root path.
//!
//! **What this module DOES**: stitch existing types together via
//! [`RuntimeHost::new`].
//!
//! **What this module does NOT do**: register production cap-* host functions,
//! load guest WASM, wire EventBus, or replace the [`AllowAllGrantCheck`] stub
//! with a real cap-grant implementation. The cap-grant production wiring is a
//! follow-on slice that ALSO wires cap-* host fns into the registry — see
//! MODULE-001 §3.6 Known Gaps.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use advance_database::{
    R2d2RecallImpl, R2d2SqliteIndexHandle, R2d2UnifiedSearchImpl, Recall, SqliteIndexHandle,
    Tunables, TunablesProvider, UnifiedSearch,
};
use advance_shared_types::capability::{CapParams, GrantDecision};
use advance_shared_types::traits::GrantCheck;

use crate::capability_injector::CapabilityInjector;
use crate::circuit_breaker::{
    BreakerState, CircuitBreaker, CircuitBreakerBus, DefaultCircuitBreakerBus,
};
use crate::component_loader::{ComponentLoadError, ComponentRuntime};
use crate::config::{ConfigError, RuntimeConfigProvider, RuntimeConfigWatcher};
use crate::host_registry::{HostRegistry, InMemoryHostRegistry};

// ---------------------------------------------------------------------------
// RuntimeConfigDatabaseTunables — Slice G adapter (CONTRACT-003 → CONTRACT-030/031)
// ---------------------------------------------------------------------------

/// Bridges a live `Arc<dyn RuntimeConfigProvider>` (the watcher) to the
/// database crate's `TunablesProvider` trait. `current()` reads through to
/// the underlying watcher's `RwLock<Arc<RuntimeConfig>>` snapshot —
/// read-through-snapshot design so the next `tunables.current()` call on
/// the database side picks up the latest yaml-reload automatically.
///
/// Manual `Debug` impl: the inner `Arc<dyn RuntimeConfigProvider>` does
/// NOT itself impl `Debug` (the trait at config.rs:317 has no `Debug`
/// super-trait), so `derive(Debug)` would fail to compile. We project the
/// current `Tunables` snapshot for diagnostic purposes.
#[derive(Clone)]
pub struct RuntimeConfigDatabaseTunables(pub Arc<dyn RuntimeConfigProvider>);

impl std::fmt::Debug for RuntimeConfigDatabaseTunables {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let t = self.current();
        f.debug_struct("RuntimeConfigDatabaseTunables")
            .field("embedding_dim", &t.embedding_dim)
            .field("recall_max_depth", &t.recall_max_depth)
            .field("wal_mode", &t.wal_mode)
            .finish()
    }
}

impl TunablesProvider for RuntimeConfigDatabaseTunables {
    fn current(&self) -> Tunables {
        let cfg = self.0.current();
        Tunables {
            embedding_dim: cfg.database.embedding_dim as usize,
            recall_max_depth: cfg.database.recall_max_depth,
            wal_mode: cfg.database.wal_mode,
        }
    }
}

// ---------------------------------------------------------------------------
// AllowAllGrantCheck — Slice AE construction-seam stub
// ---------------------------------------------------------------------------

/// Allow-everything `GrantCheck` stub. **Slice AG (2026-05-11)**: this stub
/// is now the **test-only default** used by [`RuntimeHost::new`] for backward
/// compatibility with Slice AE tests T64–T70. Production callers MUST use
/// [`RuntimeHostBuilder::build`] with a real `Arc<dyn GrantCheck>` (e.g. from
/// `cap_grant::register_cap_grant`); the canonical production entry point is
/// `advance_cli::wiring::wire_capabilities`, which threads cap-grant's
/// `GrantCheckImpl` through `RuntimeHostBuilder::build`.
///
/// **Hard rule for test-only callers**: do NOT register production cap-* host
/// functions into `InMemoryHostRegistry` while this stub is the `GrantCheck`
/// — agents would gain unconditional access to those functions. Slice AE tests
/// T64–T70 verify the construction surface but never invoke any host fn
/// through the injector, so the stub is safe in that scope; production
/// `advance start` runs through the builder + wire_capabilities path.
///
/// **Visibility (Adversarial R1 W3)**: this type is `pub(crate)` and
/// deliberately NOT re-exported from `lib.rs`. Downstream crates that need to
/// inject a `GrantCheck` for testing should construct their own no-op
/// implementer (the trait is defined in `advance-shared-types`); they MUST
/// NOT depend on or copy this stub into production code paths. The `pub(crate)`
/// gate ensures a future PR cannot accidentally instantiate this stub from
/// outside the runtime crate when wiring production cap-* host fns.
#[derive(Debug, Default)]
pub(crate) struct AllowAllGrantCheck;

impl GrantCheck for AllowAllGrantCheck {
    fn check(
        &self,
        _agent_id: &str,
        _capability: &str,
        _function: &str,
        _params: &CapParams,
    ) -> GrantDecision {
        GrantDecision::Allow
    }
}

// ---------------------------------------------------------------------------
// BootstrapError
// ---------------------------------------------------------------------------

/// Errors produced by [`RuntimeHost::new`].
///
/// Lock-acquisition errors are owned by the CLI's `start::run` (see
/// `crates/cli/src/commands/start.rs`); this enum covers only the failures
/// `RuntimeHost::new` itself can produce.
#[derive(Debug)]
pub enum BootstrapError {
    /// Config file load / parse / watcher-construction failure.
    Config(ConfigError),
    /// SQLite index handle construction failure (pool creation or migration).
    Database(advance_database::DbError),
    /// `ComponentRuntime::new` failure (Wasmtime engine construction error
    /// surfaced by the component loader).
    ComponentLoad(ComponentLoadError),
    /// `db_path` resolved to a symlink at bootstrap. Rejected eagerly so an
    /// attacker cannot swap the workspace's index.db for a symlink to a
    /// sensitive file. First-run NotFound passes through this check.
    DbPathSymlink(PathBuf),
    /// I/O error while inspecting `db_path`'s symlink-metadata (anything other
    /// than NotFound + valid file).
    DbPathIoError(PathBuf, std::io::Error),
    /// Failed to seed a circuit breaker from `runtime-config.yaml >
    /// circuit-breakers[]`. Propagates whatever the bus returned.
    CircuitBreaker(crate::circuit_breaker::BreakerError),
}

impl std::fmt::Display for BootstrapError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Adversarial R2 W1: paths embedded in this Display impl can be
        // attacker-influenced (db_path comes from runtime-config.yaml, which
        // validate_config gates on NUL but not on ANSI/control/BIDI bytes).
        // Use `{:?}` Debug formatting (which routes through `escape_debug`)
        // for any path, so escape sequences appear as literal escape text on
        // stderr rather than being interpreted by the operator's terminal.
        match self {
            BootstrapError::Config(e) => write!(f, "config load failed: {e}"),
            BootstrapError::Database(e) => write!(f, "database init failed: {e}"),
            BootstrapError::ComponentLoad(e) => write!(f, "component runtime init failed: {e:?}"),
            BootstrapError::DbPathSymlink(p) => write!(
                f,
                "db_path is a symlink and is rejected: {p:?} (move/replace with a regular file)"
            ),
            BootstrapError::DbPathIoError(p, e) => {
                write!(f, "db_path I/O error at {p:?}: {e}")
            }
            BootstrapError::CircuitBreaker(e) => {
                write!(f, "circuit breaker seed failed: {e}")
            }
        }
    }
}

impl std::error::Error for BootstrapError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            BootstrapError::Config(e) => Some(e),
            BootstrapError::Database(e) => Some(e),
            BootstrapError::ComponentLoad(_) => None, // ComponentLoadError doesn't impl std::error::Error

            BootstrapError::DbPathSymlink(_) => None,
            BootstrapError::DbPathIoError(_, e) => Some(e),
            BootstrapError::CircuitBreaker(e) => Some(e),
        }
    }
}

impl From<ConfigError> for BootstrapError {
    fn from(e: ConfigError) -> Self {
        BootstrapError::Config(e)
    }
}

impl From<advance_database::DbError> for BootstrapError {
    fn from(e: advance_database::DbError) -> Self {
        BootstrapError::Database(e)
    }
}

impl From<ComponentLoadError> for BootstrapError {
    fn from(e: ComponentLoadError) -> Self {
        BootstrapError::ComponentLoad(e)
    }
}

impl From<crate::circuit_breaker::BreakerError> for BootstrapError {
    fn from(e: crate::circuit_breaker::BreakerError) -> Self {
        BootstrapError::CircuitBreaker(e)
    }
}

// ---------------------------------------------------------------------------
// RuntimeHost
// ---------------------------------------------------------------------------

/// Owns the Arc graph constructed by [`RuntimeHost::new`].
///
/// All accessors return cheap `Arc<...>` clones, preserving Arc-pointer
/// identity across calls (verified by T65).
///
/// **Residual TOCTOU on `db_path`** (Audit R1 W2 acknowledgement): the symlink
/// rejection check in `RuntimeHost::new` (`symlink_metadata`) and the
/// subsequent `R2d2SqliteIndexHandle::new` open are non-atomic. A local
/// attacker with write access to the workspace's `.runtime/` directory between
/// the two operations can swap a regular file for a symlink targeting a
/// sensitive path. SQLite/rusqlite expose no `O_NOFOLLOW` equivalent, so the
/// gap is closed at the file-system-permissions layer (workspace mode 0o700)
/// rather than in this code path. Plan R-AE-3 documents the same residual.
pub struct RuntimeHost {
    config_watcher: Arc<RuntimeConfigWatcher>,
    sqlite: Arc<dyn SqliteIndexHandle>,
    /// Slice G: typed `Recall` impl pre-constructed at bootstrap with the
    /// live `RuntimeConfigDatabaseTunables` provider. Exposed via
    /// `recall()` accessor so callers (tests, downstream modules) get a
    /// typed surface without constructing `R2d2RecallImpl::with_tunables`
    /// from `Arc<dyn SqliteIndexHandle>` (the trait-object form does not
    /// satisfy the impl's `H: SqliteIndexHandle + Clone + 'static` bound).
    recall: Arc<dyn Recall>,
    /// Slice G: typed `UnifiedSearch` impl pre-constructed at bootstrap.
    /// Single-owner via inner `R2d2RecallImpl` — the unified_search delegates
    /// dim reads through `recall.current_embedding_dim()`.
    unified_search: Arc<dyn UnifiedSearch>,
    host_registry: Arc<dyn HostRegistry>,
    breaker: Arc<dyn CircuitBreakerBus>,
    grant_check: Arc<dyn GrantCheck>,
    injector: Arc<CapabilityInjector>,
    component_runtime: Arc<ComponentRuntime>,
    workspace_root: PathBuf,
}

impl std::fmt::Debug for RuntimeHost {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Custom impl: `Arc<dyn ...>` trait objects don't impl Debug uniformly.
        // Surface the workspace + a coarse "Arc graph populated" indicator for
        // operator diagnostics (audit R1 I1).
        f.debug_struct("RuntimeHost")
            .field("workspace_root", &self.workspace_root)
            .field("schema_version", &self.sqlite.schema_version())
            .finish_non_exhaustive()
    }
}

// ---------------------------------------------------------------------------
// RuntimeHostBuilder — Slice AG production-wiring seam (2026-05-11)
// ---------------------------------------------------------------------------

/// Partial-construction surface for [`RuntimeHost`]. Slice AG (2026-05-11)
/// adds this builder so external wiring code (e.g.
/// [`advance_cli::wiring::wire_capabilities`]) can construct dependencies
/// that need access to the bootstrap's intermediate state — most
/// importantly the live `Arc<dyn SqliteIndexHandle>` that
/// [`cap_grant::register_cap_grant`] requires BEFORE the [`CapabilityInjector`]
/// is built (the injector must be constructed with the real `GrantCheck`
/// to avoid the AllowAllGrantCheck stub reaching production).
///
/// **Construction order preserved verbatim from Slice AE**:
/// [`RuntimeHostBuilder::new`] runs steps 1–5 (config watcher, sqlite
/// handle with symlink rejection, recall + unified_search, host registry,
/// circuit-breaker bus seeded from config). [`RuntimeHostBuilder::build`]
/// runs steps 6–8 (accept injected grant_check → CapabilityInjector::new
/// → ComponentRuntime::new) in their original order. The 8th field
/// (`component_runtime`) is constructed inside `build()` rather than in
/// `new()` to keep the Slice AE 1→8 ordering exactly verbatim.
///
/// **Slice AE compatibility**: [`RuntimeHost::new`] thin-wraps
/// `RuntimeHostBuilder::new(...).await?.build(Arc::new(AllowAllGrantCheck))`,
/// so Slice AE tests T64–T70 continue to exercise the same construction
/// path byte-for-byte. The stub is retained as the test-only default;
/// production callers should use the builder directly.
pub struct RuntimeHostBuilder {
    config_watcher: Arc<RuntimeConfigWatcher>,
    sqlite: Arc<dyn SqliteIndexHandle>,
    recall: Arc<dyn Recall>,
    unified_search: Arc<dyn UnifiedSearch>,
    host_registry: Arc<dyn HostRegistry>,
    breaker: Arc<dyn CircuitBreakerBus>,
    workspace_root: PathBuf,
}

impl RuntimeHostBuilder {
    /// Run construction steps 1–5: open and watch the config file, resolve
    /// + symlink-reject the db_path, build the SQLite handle + tunables-aware
    /// Recall/UnifiedSearch, initialize the empty `InMemoryHostRegistry`,
    /// and seed the circuit-breaker bus from `config.circuit_breakers`.
    /// Steps 6–8 (grant_check, CapabilityInjector, ComponentRuntime) run in
    /// [`Self::build`].
    pub async fn new(config_path: &Path, workspace_root: &Path) -> Result<Self, BootstrapError> {
        // 1. Watch the config file (also performs initial parse + validate).
        let config_watcher = Arc::new(RuntimeConfigWatcher::new(config_path).await?);
        let config = config_watcher.current();

        // 2 + 3. Resolve db_path, reject leaf-symlink + ancestor-symlink swap,
        //         then construct the handle.
        // validate_config already rejects absolute paths + `..` traversal in
        // db-path (config.rs validate_config). Joining a relative db-path onto
        // workspace_root therefore stays under workspace_root.
        let resolved_db = workspace_root.join(&config.database.db_path);

        // Leaf-symlink check (covers existing-target + dangling-target).
        match std::fs::symlink_metadata(&resolved_db) {
            Ok(meta) if meta.file_type().is_symlink() => {
                return Err(BootstrapError::DbPathSymlink(resolved_db));
            }
            Ok(_) => {} // existing regular file → proceed (R2d2 will open it)
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {} // first run → R2d2 creates
            Err(e) => return Err(BootstrapError::DbPathIoError(resolved_db, e)),
        }

        // Ancestor-symlink check (Adversarial R1 W1): match config.rs's
        // hardening posture. Walk the existing parent chain and reject any
        // symlinked directory component. NotFound on a parent is benign for
        // first-run (R2d2 doesn't create parent dirs anyway, so this would
        // surface as an open error later — but reject here to produce a
        // clearer diagnostic).
        if let Err(e) = crate::config::check_no_ancestor_symlinks_parents(&resolved_db) {
            // The config-side helper returns ConfigError::IoError; map to
            // the bootstrap symlink variant for a clearer error type.
            return match e {
                ConfigError::IoError { path, source } if source.to_string().contains("symlink") => {
                    Err(BootstrapError::DbPathSymlink(path))
                }
                ConfigError::IoError { path, source } => {
                    Err(BootstrapError::DbPathIoError(path, source))
                }
                other => Err(BootstrapError::Config(other)),
            };
        }

        // Slice G (AC-19): build the live tunables adapter ONCE at bootstrap
        // and thread it into the SQLite handle + recall + unified_search.
        // Read-through-snapshot design — no spawned subscriber task; the
        // next `tunables.current()` call on the database side reads through
        // to the watcher's latest committed `Arc<RuntimeConfig>` snapshot.
        let provider: Arc<dyn RuntimeConfigProvider> = config_watcher.clone();
        let tunables: Arc<dyn TunablesProvider> = Arc::new(RuntimeConfigDatabaseTunables(provider));
        // Slice G adversarial R1 W1 fix: surface wal-mode=false as a stderr
        // warning at construction. PragmaCustomizer issues `PRAGMA journal_mode
        // = MEMORY` in this mode, which eliminates crash-recovery semantics
        // (committed transactions are NOT durable across power loss). Until
        // MODULE-019 ships the EventBus-driven structured logger, eprintln
        // matches the existing operator-diagnostic pattern in
        // `commands::start::run` + `commands::config::check`. The visible
        // warning closes the "silent footgun" surface — operators will see
        // it on stderr regardless of whether they read MODULE-001 §2.10.
        if !config.database.wal_mode {
            eprintln!(
                "warn: runtime-config.yaml database.wal-mode=false → \
                 PRAGMA journal_mode = MEMORY; SQLite crash-recovery is \
                 DISABLED for this workspace. Default `true` is recommended \
                 in production. (MODULE-001 §2.10)"
            );
        }

        // Slice G adversarial R2 W1 fix: hot-reload variant of the wal-mode
        // warning. The startup eprintln above only fires inside RuntimeHost::new;
        // an operator who hot-flips `wal-mode: true → false` post-startup would
        // otherwise see a silent snapshot-observable change on
        // `host.config().database.wal_mode` with no operator-visible signal.
        // Subscribe ONCE here and spawn a detached observer task that emits
        // the same warning on every `true → false` transition.
        //
        // Transition-only (not "every reload where wal_mode == false") avoids
        // log-spam when an operator chose `wal-mode: false` deliberately at
        // startup and triggers later reloads for unrelated fields.
        //
        // Lifecycle: the spawned task is detached. When the last
        // `Arc<RuntimeConfigWatcher>` is dropped, the watcher drops its
        // `_watcher` (closing the OS file-watch channel), the bridge task
        // exits, `WatcherInner` is dropped, the sender vec drops, and our
        // receiver sees EOF — the task exits cleanly. Same lifecycle posture
        // as the existing watcher bridge task.
        let mut wal_reload_rx = config_watcher.subscribe();
        let initial_wal_mode = config.database.wal_mode;
        tokio::spawn(async move {
            let mut prev_wal_mode = initial_wal_mode;
            while let Some(new_cfg) = wal_reload_rx.recv().await {
                let new_wal_mode = new_cfg.database.wal_mode;
                if prev_wal_mode && !new_wal_mode {
                    eprintln!(
                        "warn: runtime-config.yaml database.wal-mode hot-reloaded \
                         true → false. Existing pool connections retain their \
                         current journal_mode (no live PRAGMA flip is issued); \
                         the new MEMORY journal_mode applies only on next \
                         runtime restart, at which point SQLite crash-recovery \
                         is DISABLED for this workspace. Default `true` is \
                         recommended in production. (MODULE-001 §2.10)"
                    );
                }
                prev_wal_mode = new_wal_mode;
            }
        });

        let handle = R2d2SqliteIndexHandle::with_tunables(
            &resolved_db,
            config.database.pool_size,
            tunables.clone(),
        )?;
        // Slice G: pre-construct typed Recall + UnifiedSearch impls sharing
        // the same tunables. `handle.clone()` works because
        // R2d2SqliteIndexHandle keeps `#[derive(Clone)]` (plain Arc<dyn> in
        // the tunables field — no Mutex breaks).
        let recall: Arc<dyn Recall> = Arc::new(R2d2RecallImpl::with_tunables(
            handle.clone(),
            tunables.clone(),
        ));
        let unified_search: Arc<dyn UnifiedSearch> =
            Arc::new(R2d2UnifiedSearchImpl::with_tunables(
                handle.clone(),
                10, // default fan-out limit; matches existing R2d2UnifiedSearchImpl::new convention
                tunables.clone(),
            ));
        let sqlite: Arc<dyn SqliteIndexHandle> = Arc::new(handle);

        // 4. Host registry (empty — host fns registered by downstream slices).
        let host_registry: Arc<dyn HostRegistry> = Arc::new(InMemoryHostRegistry::new());

        // 5. Circuit-breaker bus, seeded with configured Open breakers.
        let breaker_concrete = Arc::new(DefaultCircuitBreakerBus::new());
        for spec in &config.circuit_breakers {
            // The bus's `open` method requires `state == Open`; seed only
            // configured-Open entries. Closed is the natural default; HalfOpen
            // is unusual at bootstrap.
            let cb = CircuitBreaker::from_config_spec(spec);
            if cb.state == BreakerState::Open {
                breaker_concrete.open(cb)?;
            }
        }
        let breaker: Arc<dyn CircuitBreakerBus> = breaker_concrete;

        // Steps 6–8 deferred to RuntimeHostBuilder::build (Slice AG split).
        Ok(Self {
            config_watcher,
            sqlite,
            recall,
            unified_search,
            host_registry,
            breaker,
            workspace_root: workspace_root.to_path_buf(),
        })
    }

    /// Finalize construction with the given `GrantCheck`. Runs steps 6–8
    /// of the Slice AE construction order:
    ///   6. Accept the injected `grant_check: Arc<dyn GrantCheck>`
    ///      (replaces the original `Arc::new(AllowAllGrantCheck)` stub).
    ///   7. Construct `CapabilityInjector::new(host_registry.clone(),
    ///      grant_check.clone(), breaker.clone())`.
    ///   8. Construct `ComponentRuntime::new(&config.wasm)` — may fail
    ///      with `ComponentLoadError` mapped to
    ///      [`BootstrapError::ComponentLoad`].
    ///
    /// Consumes the builder by value, moving the 7 builder fields into
    /// the resulting [`RuntimeHost`] (`component_runtime` is built here
    /// as the 8th field). Pointer-identity is preserved: tests can assert
    /// `Arc::ptr_eq(&grant_check, &host.grant_check())` and
    /// `Arc::ptr_eq(&builder_registry_clone, &host.host_registry())`.
    pub fn build(self, grant_check: Arc<dyn GrantCheck>) -> Result<RuntimeHost, BootstrapError> {
        let config = self.config_watcher.current();

        // 7. CapabilityInjector wraps the dependency triangle.
        let injector = Arc::new(CapabilityInjector::new(
            self.host_registry.clone(),
            grant_check.clone(),
            self.breaker.clone(),
        ));

        // 8. Wasmtime ComponentRuntime per the canonical wasm config block.
        let component_runtime = Arc::new(ComponentRuntime::new(&config.wasm)?);

        Ok(RuntimeHost {
            config_watcher: self.config_watcher,
            sqlite: self.sqlite,
            recall: self.recall,
            unified_search: self.unified_search,
            host_registry: self.host_registry,
            breaker: self.breaker,
            grant_check,
            injector,
            component_runtime,
            workspace_root: self.workspace_root,
        })
    }

    // ---------------- Pre-build accessors ----------------
    //
    // External wiring code (cli::wiring::wire_capabilities) calls these
    // before `build()` to thread the builder's intermediate state into
    // dependent constructors (e.g. cap-grant needs sqlite_index_handle()).
    // Arc::ptr_eq across the build boundary is preserved (verified by T73).

    /// Latest config snapshot. Equivalent to `config_watcher().current()`.
    pub fn config(&self) -> Arc<crate::config::RuntimeConfig> {
        self.config_watcher.current()
    }

    /// The config watcher (subscribe to hot reloads via `subscribe()`).
    pub fn config_watcher(&self) -> Arc<RuntimeConfigWatcher> {
        self.config_watcher.clone()
    }

    /// Per-workspace SQLite index handle (CONTRACT-030).
    pub fn sqlite_index_handle(&self) -> Arc<dyn SqliteIndexHandle> {
        self.sqlite.clone()
    }

    /// Typed `Recall` impl pre-constructed at bootstrap with the live
    /// tunables provider plumbed through.
    pub fn recall(&self) -> Arc<dyn Recall> {
        self.recall.clone()
    }

    /// Typed `UnifiedSearch` impl pre-constructed at bootstrap.
    pub fn unified_search(&self) -> Arc<dyn UnifiedSearch> {
        self.unified_search.clone()
    }

    /// Host-function registry (CONTRACT-001 partial). Empty at builder
    /// construction; external wiring code may populate via
    /// [`HostRegistry::register`] BEFORE calling [`Self::build`].
    pub fn host_registry(&self) -> Arc<dyn HostRegistry> {
        self.host_registry.clone()
    }

    /// Circuit-breaker bus (CONTRACT-002), seeded from
    /// `runtime-config.yaml > circuit-breakers[]`.
    pub fn circuit_breaker_bus(&self) -> Arc<dyn CircuitBreakerBus> {
        self.breaker.clone()
    }

    /// Workspace root path passed into [`Self::new`].
    pub fn workspace_root(&self) -> &Path {
        &self.workspace_root
    }
}

impl RuntimeHost {
    /// Construct a `RuntimeHost` from a runtime-config.yaml path and a
    /// workspace root. **Slice AE compatibility wrapper** — uses
    /// [`AllowAllGrantCheck`] as the test-only default. Production
    /// callers should use [`RuntimeHostBuilder`] directly and inject a
    /// real `GrantCheck` (see [`AllowAllGrantCheck`] rustdoc).
    ///
    /// Construction order (verbatim from Slice AE):
    /// 1. Open and watch the config file (`RuntimeConfigWatcher::new`).
    /// 2. Resolve `<workspace>/<config.database.db_path>` and reject symlinks
    ///    via `symlink_metadata` (existing or dangling). NotFound passes (the
    ///    next step creates the file).
    /// 3. `R2d2SqliteIndexHandle::new(&resolved_db, pool_size)` — runs schema
    ///    migrations internally.
    /// 4. `InMemoryHostRegistry::new()`.
    /// 5. `DefaultCircuitBreakerBus::new()` + seed Open breakers from
    ///    `config.circuit_breakers` via `CircuitBreaker::from_config_spec`.
    /// 6. `AllowAllGrantCheck` stub (see type rustdoc).
    /// 7. `CapabilityInjector::new(host_registry, grant_check, breaker)`.
    /// 8. `ComponentRuntime::new(&config.wasm)`.
    pub async fn new(config_path: &Path, workspace_root: &Path) -> Result<Self, BootstrapError> {
        let builder = RuntimeHostBuilder::new(config_path, workspace_root).await?;
        let stub: Arc<dyn GrantCheck> = Arc::new(AllowAllGrantCheck);
        builder.build(stub)
    }

    /// Returns the latest config snapshot. Equivalent to
    /// `self.config_watcher().current()`.
    pub fn config(&self) -> Arc<crate::config::RuntimeConfig> {
        self.config_watcher.current()
    }

    /// The config watcher (subscribe to hot reloads via `subscribe()`).
    pub fn config_watcher(&self) -> Arc<RuntimeConfigWatcher> {
        self.config_watcher.clone()
    }

    /// Per-workspace SQLite index handle (CONTRACT-030).
    pub fn sqlite_index_handle(&self) -> Arc<dyn SqliteIndexHandle> {
        self.sqlite.clone()
    }

    /// Slice G (AC-18 + AC-19): typed `Recall` impl pre-constructed at
    /// bootstrap with the live tunables provider plumbed through. Reads
    /// `tunables.current().recall_max_depth` and `embedding_dim` per call
    /// from the watcher's RuntimeConfig snapshot.
    pub fn recall(&self) -> Arc<dyn Recall> {
        self.recall.clone()
    }

    /// Slice G (AC-18 + AC-19): typed `UnifiedSearch` impl pre-constructed
    /// at bootstrap. Single-owner tunables via inner recall — no
    /// dual-ownership drift.
    pub fn unified_search(&self) -> Arc<dyn UnifiedSearch> {
        self.unified_search.clone()
    }

    /// Host-function registry (CONTRACT-001 partial). Empty at bootstrap;
    /// downstream slices populate via `HostRegistry::register`.
    pub fn host_registry(&self) -> Arc<dyn HostRegistry> {
        self.host_registry.clone()
    }

    /// Circuit-breaker bus (CONTRACT-002), seeded from
    /// `runtime-config.yaml > circuit-breakers[]`.
    pub fn circuit_breaker_bus(&self) -> Arc<dyn CircuitBreakerBus> {
        self.breaker.clone()
    }

    /// L1 grant-check trait object. Returns the [`AllowAllGrantCheck`] stub
    /// today — see the type's rustdoc for the production-wiring caveat.
    pub fn grant_check(&self) -> Arc<dyn GrantCheck> {
        self.grant_check.clone()
    }

    /// Capability injector wrapping the (registry, grant_check, breaker)
    /// triangle (CONTRACT-001).
    pub fn capability_injector(&self) -> Arc<CapabilityInjector> {
        self.injector.clone()
    }

    /// Wasmtime ComponentRuntime constructed from `config.wasm`.
    pub fn component_runtime(&self) -> Arc<ComponentRuntime> {
        self.component_runtime.clone()
    }

    /// Workspace root path passed into [`RuntimeHost::new`].
    pub fn workspace_root(&self) -> &Path {
        &self.workspace_root
    }
}
