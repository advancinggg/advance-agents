//! `advance_cli` — library surface for the `advance` CLI binary.
//!
//! Slice AG (2026-05-11) adds this lib target so integration tests in
//! `crates/cli/tests/*.rs` can import wiring functions directly. The
//! `[[bin]]` target (`src/main.rs`) consumes the same library via
//! `use advance_cli::{commands, wiring};` — same code path, no
//! duplication.
//!
//! See MODULE-001 §3.6 "CLI `[lib]` target added in Slice AG" for the
//! design rationale.

#![forbid(unsafe_code)]

pub mod agent_config;
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
pub mod channel_notify_sink;
pub mod channels_boot;
pub mod commands;
pub mod component_submit_bridge;
pub mod context_wiring;
// Wave-25A Order-2 build-and-hold platform anchor.  This module is deliberately
// not wired into `advance start` until the later atomic composition lane.
pub mod client_api_adapters;
pub mod grant_adapter;
pub mod contract218_anchor;
pub mod contract218_bootstrap;
pub mod contract218_keyring;
pub mod contract218_marker;
pub mod contract218_roles;
pub mod observation_carriers;
pub mod observation_projection;
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
