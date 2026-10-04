//! MODULE-001-T111 (1) / MODULE-001-AC-30 — the route-table goldens of ADR 2026-10-03 D5:
//! method, path, exact / templated, session, mutation and scopes of the Client API composed
//! in-process on an `fs` + `llm` home (H1) and on a home declaring every `KNOWN_CAPABILITIES`
//! entry (H2), read through `ClientApi::route_table`.
//!
//! In its own test binary: the composition reads the master key from the process environment,
//! which this binary sets once (`std::env::set_var`); no other test of this binary calls into C
//! code that reads the environment concurrently (both homes are plain directories, no git).
//!
//! The goldens, their sha256 pins and the update mode are shared with
//! `runtime_compose_d5_goldens.rs` (see `runtime_compose_d5_common`).
#![cfg(unix)]

// Shared with `runtime_compose_d5_goldens.rs`; each binary uses a different part of it.
#[allow(dead_code)]
mod runtime_compose_d5_common;

use std::fmt::Write as _;
use std::sync::Once;

use advance_client_api::{RouteTableEntry, Scope};
use advance_runtime::bootstrap::RuntimeHostBuilder;
use runtime_compose_d5_common::{
    declares, describe, make_home, method_name, probe_route_table, Goldens, HomeSpec, CAPTURED_ON,
    H1, H2, MASTER_KEY_ENV, MASTER_KEY_HEX,
};

fn scope_name(scope: &Scope) -> String {
    serde_json::to_value(scope)
        .ok()
        .and_then(|v| v.as_str().map(str::to_string))
        .expect("scope serializes to a string")
}

fn render_route_table(title: &str, table: &[RouteTableEntry]) -> String {
    let mut out = format!(
        "# MODULE-001-T111 (1) route table of the Client API composed in-process (RuntimeHostBuilder::new + wire_capabilities) on {title}\n\
         # {CAPTURED_ON}\n\
         # method path | exact/templated session mutation scopes\n"
    );
    for entry in table {
        let scopes: Vec<String> = entry.required_scopes.iter().map(scope_name).collect();
        let _ = writeln!(
            out,
            "{} {} | {} session={} mutation={} scopes=[{}]",
            method_name(entry.method),
            entry.path,
            if entry.templated {
                "templated"
            } else {
                "exact"
            },
            entry.requires_session,
            entry.is_mutation,
            scopes.join(",")
        );
    }
    out
}

fn ensure_in_process_master_key() {
    static INIT: Once = Once::new();
    INIT.call_once(|| std::env::set_var(MASTER_KEY_ENV, MASTER_KEY_HEX));
}

/// Compose `spec`'s home in-process through the production path and read the route table from
/// the composed server (the same `ClientApi` instance the loopback transport serves).
async fn composed_route_table(spec: &HomeSpec) -> Vec<RouteTableEntry> {
    ensure_in_process_master_key();
    let home = make_home(spec);
    let config_path = home.ws.join(".advance/runtime-config.yaml");
    // LATER STEP (runtime-compose D1): this composes through `RuntimeHostBuilder::new` +
    // `wire_capabilities`, which is not the entry point `advance start` uses. Once the
    // composition is a library, switch this to the same entry point `advance start` calls
    // (compose with the daemon options), so the table read here is the binary's own table.
    let builder = RuntimeHostBuilder::new(&config_path, &home.ws)
        .await
        .expect("RuntimeHostBuilder::new");
    let (host, handles) = if declares(spec, "messaging") {
        // Progress-lifecycle state goes under the test HOME, never the process HOME.
        advance_cli::wiring::wire_capabilities_with_home_for_test(
            builder,
            &home.ws,
            &home.root.join("home"),
        )
        .await
        .expect("wire_capabilities_with_home_for_test")
    } else {
        advance_cli::wiring::wire_capabilities(builder, &home.ws)
            .await
            .expect("wire_capabilities")
    };
    let table = handles
        .client_api_server
        .as_ref()
        .expect("the composition binds the Client API")
        .api()
        .route_table();
    drop(handles);
    drop(host);
    table
}

/// The route-table golden is also checked to be home-independent: the composed table must equal
/// the default-constructed one the route probes walk.
async fn route_table_golden(spec: &HomeSpec) {
    let table = composed_route_table(spec).await;
    assert_eq!(
        table,
        probe_route_table(),
        "the composed route table equals the default-constructed one walked by the probes"
    );
    let mut goldens = Goldens::new();
    goldens.check(
        &format!("route_table.{}.golden", spec.label),
        &render_route_table(&describe(spec), &table),
    );
    goldens.finish();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn module_001_t111_ac30_route_table_h1_fs_llm() {
    route_table_golden(&H1).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn module_001_t111_ac30_route_table_h2_all_capabilities() {
    // Same declarations as the binary H2, minus the git repository: with `messaging` on a git
    // repository the composition's git commit worker outlives the runtime it was spawned on
    // (see `H2_SIGTERM_AFTER_READINESS`), which would hang this test's runtime drop. The route
    // table does not depend on the repository.
    route_table_golden(&HomeSpec { git: false, ..H2 }).await;
}
