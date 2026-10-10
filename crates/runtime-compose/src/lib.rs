//! `advance_runtime_compose` — the runtime composition behind `advance start`.
//!
//! Owns everything `advance start` composes: the capability wiring
//! ([`wiring::wire_capabilities`]), the agent loop and turn modules, the
//! bootstraps, channel boot, the Client API adapters, the pack runtime, the
//! data tool, and the daemon composition graph (`daemon`) behind [`compose`].
//! The `advance` binary's `start` command is a thin `main` over [`compose`]: it
//! owns the process (the runtime, the signals, the workspace it resolves, the
//! output and the exit code), so code in this crate never prints, installs no
//! signal handler, never reads the current directory and never exits the process.
//! `advance-cli` re-exports every public module here under its former
//! `advance_cli::<module>` path.

#![forbid(unsafe_code)]
#![deny(
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::dbg_macro,
    clippy::exit
)]

/// `probe_record!(probe, |record| update)`: record into the composition's test-support
/// probe (`test_support::ComposeProbe`), where `probe` is an
/// `Option<Arc<ComposeProbe>>`. Without the `test-support` feature the whole statement
/// is compiled out, its expressions included.
macro_rules! probe_record {
    ($probe:expr, |$record:ident| $update:expr) => {{
        #[cfg(feature = "test-support")]
        {
            if let Some(probe) = ($probe).as_ref() {
                probe.update(|$record| {
                    $update;
                });
            }
        }
    }};
}

// The composition API (`compose`, its options, output sink, errors and the composed
// runtime), re-exported at the crate root.
pub mod api;
pub use api::*;

// The handle every composition module emits its lines through.
pub mod compose_log;

// `compose()` itself, the composition's ordered teardown, and the one place it starts
// OS threads.
mod client_ingress;
mod compose;
mod composition;
mod threads;

#[doc(hidden)]
pub mod extension;

mod extension_families;
mod inference;

// Test-only seams of the composition: failpoints, the turn gate, the probe, the
// in-memory log.
#[cfg(feature = "test-support")]
#[doc(hidden)]
pub mod test_support;

// The process-local registry of homes a runtime is composed in (the embedded
// runtime bridge reserves through it too).
pub mod registry;

pub mod agent_config;
#[doc(hidden)]
pub mod effective_capabilities;
// Lane agent-llm-policy (2026-09-16) — the production `AgentLlmPolicySource`: resolves an
// agent's `.agent/config.yaml` `llm:` block (provider pin / default model / constraint) for the
// cap-llm gateway, cached by file mtime.
pub mod agent_llm_policy;
pub mod agent_loop;
// await-leg B-2 (2026-06-22) — production composition glue for the await-replies ↔
// M008 Run suspend/resume lifecycle: the RunManagerSuspendSink adapter +
// build_await_messaging_chain helper. Closes MODULE-007 §3.6 R9. cli-only.
pub mod auto_wiring;
pub mod await_wiring;
pub mod channel_egress;
// /dev Stage-D satellite (2026-06-19) — the SYS-AC-257 product seam: a NotifySink
// that routes the auto-loop degrade/halt notification through cap-channel OUTBOUND
// egress (OutboundTransport::send → channel.raw_sent), replacing the best-effort
// EventBusNotifySink (auto.notify). cli-only (cap-channel src untouched); flips ZERO SYS-AC.
pub mod breaker_gate;
pub mod capability_catalog;
pub mod channel_notify_sink;
pub mod channels_boot;
pub mod component_submit_bridge;
pub mod context_wiring;
pub mod data_wiring;
// Wave-25A Order-2 build-and-hold platform anchor.  This module is deliberately
// not wired into `advance start` until the later atomic composition lane.
pub mod client_api_adapters;
// CONTRACT-190 agents family: the production `AgentAdminProvider` over the shared agent tree
// (list/get/create/update/delete + template listing), its root-config persistence, and the
// production terminate-controller composition the family drives.
pub mod client_api_agents;
pub mod client_api_costs;
pub mod client_api_entities;
pub mod client_api_packs;
// CONTRACT-190 providers family (lane providers-family, 2026-09-16): the production
// `ProviderAdminProvider` over the shared `llm-providers` writer, the daemon's live
// `SecretStore`, the config watcher and the first-open preflight port.
pub mod client_api_providers;
// Secrets family: the production
// `SecretsAdminProvider` over the home's `secrets:` block (File vs keychain-sync).
pub mod client_api_secrets;
pub mod contract218_anchor;
pub mod contract218_bootstrap;
pub mod contract218_keyring;
pub mod contract218_marker;
pub mod contract218_roles;
pub mod grant_adapter;
pub mod observation_carriers;
pub mod observation_projection;
// Pack lane P1 — composition-root wiring of the MODULE-018 pack
// system: ONE rescanned InMemoryPackRegistry + the chained (built-in ∪ pack) template
// resolver + the PackEvaluatorResolver + a DefaultMaterializer, consumed by
// `wiring.rs`. The `advance pack install|list|uninstall` admin surface lives in
// `commands/pack.rs`.
pub mod pack_bridges;
pub mod pack_production;
pub mod pack_wiring;
// Pack lane P3 — the production HTTPS `RegistryClient`
// (`registry:name@version` sources; index GET + sha256-verified, bounded tarball
// download), wired by `commands/pack.rs` from `pack.registry-url`.
pub mod pack_registry_client;
pub mod pack_runtime;
pub mod reap;
pub mod webhook_listener;
// /dev Wave-20 Lane `search` (2026-06-27) — the cross-crate adapter bridging
// database::UnifiedSearch (dense+sparse FTS5) -> context_engine::UnifiedSearchPort.
pub mod dual_recall;
// /dev Wave-18 Lane 4 (2026-06-26) — the production CrashCascadeSink: bridges a child
// guest trap (scheduler handle_trap on Crash) to the cap-lifecycle handle_crash →
// notify_parent_crash parent-mailbox cascade across the colon/bare id-space seam.
// cli-only composition (cap-lifecycle untouched); witnessed via the harness, flips
// SYS-AC-030. W24 perchild-daemon-2: NOW wired into `advance start` (seam f — root + child
// loops on the messaging/lifecycle path).
pub mod crash_cascade;
// /dev Wave-19 Lane 4 — the production WorkspaceRollbackSink (child-trap workspace rollback,
// SYS-AC-028). cli-only composition (consumes CONTRACT-020/021/022); witnessed via the harness.
// NOT yet wired into `advance start` (the per-child serve loop landed Wave-23/24, but this
// rollback sink's own daemon wiring is a later lane).
pub mod workspace_rollback;
// /dev Stage-D satellite (2026-06-19) — the per-iteration crash-decision coordinator
// (SYS-AC-201/202 product seam): composes the BUILT auto-loop primitives
// (check_per_iteration_budget → budget_breach_to_fail_fast_trigger; guardrail via the
// ComponentMetricReader trait + predicate_breached) → IterationCloseCtx → close_iteration.
// cli-only (auto-loop src untouched); flips ZERO SYS-AC.
pub mod crash_coordinator;
// The daemon composition graph `compose` builds: the agent-loop spawn, the `POST /msg`
// listener, the post-processor, the tick loop and reconcile.
pub mod daemon;
// /dev Wave-14 Lane B (2026-06-24) — the SYS-AC-201 witness-floor seam: the concrete
// evaluator-executing ComponentMetricReader that RUNS a resolved evaluator runnable
// component over the runtime surface and reads its output_key metric (the value the
// crash_coordinator guardrail branch feeds to predicate_breached). cli-only adapter.
pub mod evaluator_reader;
pub(crate) mod execution_turn_ingress;
// /dev Wave-7 Lane B satellite (2026-06-22) — the SYS-AC-183/185 production caller:
// a SchedulerExtension that drives the AutoTickCoordinator's settle on each production
// tick (run_scheduler_tick_loop in advance start). Settle stays product-driven; flips
// ZERO SYS-AC (dormant until the harvest wires register_session).
pub mod auto_tick_extension;
// SAT-C (slice satC-l6): L6 production construction at the composition root —
// GitQueueL6Committer + L6DispatchAdapter + attach_l6 (cap-memory keeps no
// advance-git / advance-scheduler dep; those edges live here).
pub mod l6_wiring;
// slice wave6-laneB: production L6Classifier adapter (the L6 keystone, 069/216) —
// bridges the cap-memory `L6Classifier` seam to cap-llm CONTRACT-081, injected into
// `attach_l6` (the system-acceptance harness keeps StubL6Classifier).
pub mod l6_classifier;
// SAT-B (slice satB-postproc): production BatchExtractor adapter (AC-43) — bridges
// cap_memory::BatchExtractor → cap_llm CONTRACT-081 (cap-memory has no cap-llm dep).
pub mod memory_extractor;
// The MCP client of a root that declares `mcp`: the operator's server files
// (`<ws>/.advance/mcp-servers/*.yaml`), the client built from them and the gated
// `mcp-client` host functions, composed by `wiring.rs`.
pub mod mcp_wiring;
pub mod perchild_daemon;
pub(crate) mod progress_lifecycle_activation;
pub(crate) mod progress_lifecycle_bootstrap;
pub mod reply;
pub mod runnable_hook;
pub mod runnable_hook_factory;
pub mod runnable_walk;
pub mod sensitive_params;
pub mod vlm_indexer;
// /dev Wave-18 Lane 2 (2026-06-26) — the M015→M017 SkillRollback production bridge
// (MODULE-017-AC-06/07 + MODULE-003-AC-21): the composition-root adapters that wire
// the auto-loop iteration-discard SkillRollback trait + pre-activation observer to the
// cap-skills SkillPersistenceCoordinator on the Initiator::AutoLoop (micro) lane. Closes
// the Wave-17 strict-hold (no production `impl SkillRollback`). cli-only.
pub mod skill_rollback_bridge;
pub mod wiring;
