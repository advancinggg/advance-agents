//! `advance_cli` — library surface for the `advance` CLI binary.
//!
//! Slice AG (2026-05-11) adds this lib target so integration tests in
//! `crates/cli/tests/*.rs` can import wiring functions directly. The
//! `[[bin]]` target (`src/main.rs`) consumes the same library via
//! `use advance_cli::commands;` — same code path, no duplication.
//!
//! The composition behind `advance start` lives in `advance_runtime_compose`;
//! every module it owns is re-exported here under its `advance_cli::<module>`
//! path so existing callers keep compiling. Only `commands` (the `init`,
//! `config`, `secrets`, `skill`, `pack` commands and the thin `start`) is
//! defined in this crate.

#![forbid(unsafe_code)]

pub mod commands;

pub use advance_runtime_compose::agent_config;
pub use advance_runtime_compose::agent_llm_policy;
pub use advance_runtime_compose::agent_loop;
pub use advance_runtime_compose::auto_tick_extension;
pub use advance_runtime_compose::auto_wiring;
pub use advance_runtime_compose::await_wiring;
pub use advance_runtime_compose::breaker_gate;
pub use advance_runtime_compose::channel_egress;
pub use advance_runtime_compose::channel_notify_sink;
pub use advance_runtime_compose::channels_boot;
pub use advance_runtime_compose::client_api_adapters;
pub use advance_runtime_compose::client_api_agents;
pub use advance_runtime_compose::client_api_costs;
pub use advance_runtime_compose::client_api_entities;
pub use advance_runtime_compose::client_api_packs;
pub use advance_runtime_compose::client_api_providers;
pub use advance_runtime_compose::client_api_secrets;
pub use advance_runtime_compose::component_submit_bridge;
pub use advance_runtime_compose::context_wiring;
pub use advance_runtime_compose::contract218_anchor;
pub use advance_runtime_compose::contract218_bootstrap;
pub use advance_runtime_compose::contract218_keyring;
pub use advance_runtime_compose::contract218_marker;
pub use advance_runtime_compose::contract218_roles;
pub use advance_runtime_compose::crash_cascade;
pub use advance_runtime_compose::crash_coordinator;
pub use advance_runtime_compose::data_wiring;
pub use advance_runtime_compose::dual_recall;
pub use advance_runtime_compose::evaluator_reader;
pub use advance_runtime_compose::grant_adapter;
pub use advance_runtime_compose::l6_classifier;
pub use advance_runtime_compose::l6_wiring;
pub use advance_runtime_compose::mcp_wiring;
pub use advance_runtime_compose::memory_extractor;
pub use advance_runtime_compose::observation_carriers;
pub use advance_runtime_compose::observation_projection;
pub use advance_runtime_compose::pack_bridges;
pub use advance_runtime_compose::pack_production;
pub use advance_runtime_compose::pack_registry_client;
pub use advance_runtime_compose::pack_runtime;
pub use advance_runtime_compose::pack_wiring;
pub use advance_runtime_compose::perchild_daemon;
pub use advance_runtime_compose::reap;
pub use advance_runtime_compose::reply;
pub use advance_runtime_compose::runnable_hook;
pub use advance_runtime_compose::runnable_hook_factory;
pub use advance_runtime_compose::runnable_walk;
pub use advance_runtime_compose::sensitive_params;
pub use advance_runtime_compose::skill_rollback_bridge;
pub use advance_runtime_compose::vlm_indexer;
pub use advance_runtime_compose::webhook_listener;
pub use advance_runtime_compose::wiring;
pub use advance_runtime_compose::workspace_rollback;
