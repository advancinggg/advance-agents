//! Secrets family over the PRODUCTION wiring (this lane):
//! boot a workspace through `RuntimeHostBuilder::new` → `wire_capabilities`, then drive the
//! daemon-composed `ClientApi` (`client_api_server.api()`, the instance the loopback
//! transport serves): `GET /client/secrets/mode` reflects the home's `secrets:` block,
//! `POST /client/secrets:set-mode` rewrites ONLY that block (validated, atomic) and answers
//! `restart_required`.
//!
//! Fixture discipline: fs-only `.agent/config.yaml` (no master key, no env mutation),
//! mirroring `client_api_agents_admin.rs`.

use std::path::{Path, PathBuf};

use advance_cli::wiring::{wire_capabilities, WiringHandles};
use advance_client_api::envelope::WARNING_RESTART_REQUIRED;
use advance_client_api::secrets_admin::ClientSecretsMode;
use advance_client_api::{
    ClientApi, ClientEnvelope, ClientErrorCode, ClientRequest, ClientSession, Platform, Principal,
    Scope,
};
use advance_runtime::bootstrap::RuntimeHostBuilder;
use serde_json::{json, Value};

fn runtime_yaml() -> String {
    r#"wasm:
  max_memory_pages: 1024
  epoch_interruption_ms: 100
  fuel_enabled: false

llm-providers: []

cron:
  max_jitter_ratio: 0.1

git:
  gc_interval_hours: 24
  max_tracked_file_mb: 10

secrets:
  master-key-source: env-var
  env-var-name: ADV_SECRETS_ADMIN_MK_UNUSED

post-processor:
  llm-model: sonnet-light
  llm-failure-cooldown-seconds: 600

database:
  db-path: ".runtime/index.db"
  pool-size: 4
"#
    .to_string()
}

fn fresh_workspace() -> (tempfile::TempDir, PathBuf, PathBuf) {
    let dir = tempfile::tempdir().expect("tempdir");
    let workspace = std::fs::canonicalize(dir.path()).expect("canonicalize");
    std::fs::create_dir_all(workspace.join(".advance")).unwrap();
    std::fs::create_dir_all(workspace.join(".runtime/events/jsonl")).unwrap();
    std::fs::create_dir_all(workspace.join(".agent")).unwrap();
    let config_path = workspace.join(".advance/runtime-config.yaml");
    std::fs::write(&config_path, runtime_yaml()).unwrap();
    std::fs::write(
        workspace.join(".agent/config.yaml"),
        "capabilities:\n  fs: true\n",
    )
    .unwrap();
    (dir, workspace, config_path)
}

async fn boot(ws: &Path, cfg: &Path) -> (advance_runtime::bootstrap::RuntimeHost, WiringHandles) {
    let builder = RuntimeHostBuilder::new(cfg, ws).await.expect("builder");
    wire_capabilities(builder, ws).await.expect("wire")
}

fn mint(api: &ClientApi, token: &str, scopes: Vec<Scope>) {
    api.sessions().insert(
        token.to_string(),
        ClientSession {
            session_id: format!("sess-{token}"),
            principal: Principal::operator("operator"),
            platform: Platform::Mac,
            scopes,
            csrf_token: None,
            expires_at: u64::MAX,
        },
        0,
    );
}

fn get(api: &ClientApi, path: &str) -> ClientEnvelope<Value> {
    api.handle(ClientRequest::get(path).with_session("tok"))
}

fn post(api: &ClientApi, path: &str, body: Value, key: &str) -> ClientEnvelope<Value> {
    api.handle(
        ClientRequest::post(path, body)
            .with_session("tok")
            .with_idempotency_key(key),
    )
}

fn mode(env: &ClientEnvelope<Value>) -> ClientSecretsMode {
    assert!(env.is_ok(), "expected ok, got {:?}", env.error);
    serde_json::from_value(env.data.clone().unwrap()).expect("mode parses")
}

#[tokio::test(flavor = "multi_thread")]
async fn secrets_mode_read_and_switch_over_production_wiring() {
    let (_g, ws, cfg) = fresh_workspace();
    let (_host, handles) = boot(&ws, &cfg).await;
    let server = handles
        .client_api_server
        .as_ref()
        .expect("EventBus up ⇒ Client API bound");
    let api = server.api();
    mint(&api, "tok", Scope::operator_default());

    // Read: the fixture's env-var File layout.
    let current = mode(&get(&api, "/client/secrets/mode"));
    assert_eq!(current.mode, "file");
    assert_eq!(current.master_key_source, "env-var");
    assert!(current.synchronizable);
    assert_eq!(current.namespace, "default");
    assert!(current.access_group.is_none());
    assert_eq!(
        current.platform_supported,
        cfg!(target_vendor = "apple"),
        "platform_supported follows the build target"
    );

    // Validation happens before any write.
    let raw_before = std::fs::read_to_string(&cfg).unwrap();
    let env = post(
        &api,
        "/client/secrets:set-mode",
        json!({ "mode": "keychain" }),
        "k-bad-mode",
    );
    assert_eq!(env.error_code(), Some(ClientErrorCode::InvalidRequest));
    assert_eq!(std::fs::read_to_string(&cfg).unwrap(), raw_before);

    let env = post(
        &api,
        "/client/secrets:set-mode",
        json!({ "mode": "keychain-sync", "namespace": "work", "synchronizable": false }),
        "k-to-keychain-sync",
    );
    #[cfg(target_vendor = "apple")]
    {
        let switched = mode(&env);
        assert_eq!(switched.mode, "keychain-sync");
        assert_eq!(switched.master_key_source, "keychain-sync");
        assert_eq!(switched.namespace, "work");
        assert!(!switched.synchronizable);
        assert!(
            env.warnings
                .iter()
                .any(|w| w.code == WARNING_RESTART_REQUIRED),
            "{:?}",
            env.warnings
        );
        let raw = std::fs::read_to_string(&cfg).unwrap();
        assert!(raw.contains("master-key-source: keychain-sync"), "{raw}");
        assert!(raw.contains("namespace: work"), "{raw}");
        assert!(raw.contains("synchronizable: false"), "{raw}");
        assert!(
            raw.contains("env-var-name: ADV_SECRETS_ADMIN_MK_UNUSED"),
            "{raw}"
        );
        assert!(raw.contains("llm-providers"), "{raw}");
        assert!(!cfg.with_extension("yaml.tmp").exists());
        assert!(!ws.join(".advance/runtime-config.yaml.tmp").exists());
        // The validating loader accepts the rewritten file, and a re-read reflects it.
        advance_runtime::config::load_config(&cfg).expect("rewritten config loads");
        let again = mode(&get(&api, "/client/secrets/mode"));
        assert_eq!(again, switched);

        // A rewrite the loader would reject never replaces the live file: namespace grammar is
        // caught by the handler, so drive an over-long namespace through the provider shape
        // via the handler bound (64) — the runtime bound is the same, so this is the handler.
        let env = post(
            &api,
            "/client/secrets:set-mode",
            json!({ "mode": "keychain-sync", "namespace": "n".repeat(65) }),
            "k-long-ns",
        );
        assert_eq!(env.error_code(), Some(ClientErrorCode::InvalidRequest));
        assert_eq!(mode(&get(&api, "/client/secrets/mode")), switched);

        // Back to the File layout: the scaffold `keychain` source, `keychain:` block dropped.
        let env = post(
            &api,
            "/client/secrets:set-mode",
            json!({ "mode": "file" }),
            "k-to-file",
        );
        let back = mode(&env);
        assert_eq!(back.mode, "file");
        assert_eq!(back.master_key_source, "keychain");
        assert!(back.synchronizable);
        assert_eq!(back.namespace, "default");
        let raw = std::fs::read_to_string(&cfg).unwrap();
        assert!(!raw.contains("keychain:"), "{raw}");
        assert!(raw.contains("master-key-source: keychain\n"), "{raw}");
    }
    #[cfg(not(target_vendor = "apple"))]
    {
        assert_eq!(env.error_code(), Some(ClientErrorCode::InvalidRequest));
        assert_eq!(
            env.error.as_ref().unwrap().details,
            vec!["platform_unsupported".to_string()]
        );
        assert_eq!(std::fs::read_to_string(&cfg).unwrap(), raw_before);
    }
}
