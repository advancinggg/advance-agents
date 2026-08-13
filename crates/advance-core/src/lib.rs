//! # advance-core — the stable embedding façade for the advance-agents OSS core
//!
//! External consumers (the private product repo, third-party native hosts) pin **this
//! one crate** — `advance-core = { git = "<public-url>", tag = "vX.Y.Z" }` — instead of
//! naming the ~30 internal workspace crates. Internal crate renames/splits stay
//! non-breaking behind these façade module names.
//!
//! ## Surface contract
//!
//! The re-export set below is exactly the **supported embedding surface** enumerated in
//! `docs/OPEN-CORE-BOUNDARY.md` §5 "OSS public API surface". OSS-internal
//! harness crates (`advance-cli`, `build-agent`, `system-acceptance`,
//! `observability-xtask`) are deliberately NOT re-exported — the CLI is a *reference*
//! composition root, and per §7.4 its stray trait defs are to be hoisted into lib
//! crates, not consumed through the façade.
//!
//! ## Granularity (first-slice decision per OPEN-CORE-BOUNDARY §9)
//!
//! Re-exports are **crate-granular** (whole public module per crate) under stable,
//! `advance-`-prefix-free names. A later governance pass may additionally curate a
//! type-level prelude; *narrowing* the crate-granular surface after 1.0 would be
//! semver-breaking, so treat everything reachable here as supported-in-the-pre-1.0
//! sense and everything absent as internal.
//!
//! ## Composition pattern
//!
//! The product/embedder is *another composition root* (OPEN-CORE-BOUNDARY §1): construct
//! concrete impls, pass them as `Arc<dyn Trait>` through the seams in
//! [`shared_types`], and wire capabilities the way `advance-cli`'s `wiring.rs` does —
//! never fork a crate, only inject.

// ── seam layer (dependency-inversion home; ships OSS wholesale per IRON LAW §2) ──
pub use advance_shared_types as shared_types;

// ── runtime host (Wasmtime host, L0 injection, breaker bus) ──────────────────────
pub use advance_runtime as runtime;

// ── capability crates (11) ────────────────────────────────────────────────────────
pub use cap_channel;
pub use cap_fs;
pub use cap_grant;
pub use cap_http;
pub use cap_lifecycle;
pub use cap_llm;
pub use cap_mcp;
pub use cap_memory;
pub use cap_secrets;
pub use cap_skills;
pub use cap_tools;

// ── subsystem crates ──────────────────────────────────────────────────────────────
pub use advance_client_api as client_api;
pub use advance_genui as genui;
pub use advance_context_engine as context_engine;
pub use advance_cost_tracker as cost_tracker;
pub use advance_database as database;
pub use advance_event_bus as event_bus;
pub use advance_git as git;
pub use advance_messaging as messaging;
pub use advance_pack_manager as pack_manager;
pub use advance_reply_tracker as reply_tracker;
pub use advance_run_manager as run_manager;
pub use advance_scheduler as scheduler;
pub use advance_scheduler_auto_loop as auto_loop;
