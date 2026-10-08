//! v2 start path: `start_with_extensions` → compose / host_only embed.

use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};

use advance_runtime::WasmBackend;
use advance_runtime_compose::{
    compose, Admission, ClientApiOptions, ComposeError, ComposeExtension, ComposeOptions,
    HostPlatform, WasmEngine,
};

use crate::config::BridgeConfig;
use crate::embed::{self, EmbedKnobs};
use crate::error::BridgeError;
use crate::handle::{
    default_lifecycle, BridgeHandle, BridgeInner, ComposedHandle, ModeState, V2Settings,
};
use crate::options::{BridgeClientApi, BridgeOptions};
use crate::profile::honesty_class;
use crate::types::{CompositionMode, CompositionProfile, EngineMode};
use crate::workspace::prepare_workspace;

pub(crate) async fn start(
    root: PathBuf,
    options: BridgeOptions,
    exts: Vec<Arc<dyn ComposeExtension>>,
) -> Result<BridgeHandle, BridgeError> {
    options.check(HostPlatform::compiled(), exts.len())?;
    let settings = settings_from_options(&options);
    match options.composition {
        CompositionProfile::Full => {
            let ws = prepare_workspace(&root)?;
            check_full_config_path(&ws, options.config_path.as_deref())?;
            start_full(ws, options, exts, settings).await
        }
        CompositionProfile::HostOnly => {
            embed::start_embed_with(&root, v1_config(&options), knobs(&options), Some(settings))
                .await
        }
    }
}

fn settings_from_options(o: &BridgeOptions) -> V2Settings {
    let client_api = match o.composition {
        CompositionProfile::Full => !matches!(o.client_api, Some(BridgeClientApi::Off)),
        CompositionProfile::HostOnly => {
            matches!(o.client_api, Some(BridgeClientApi::Loopback { .. }))
        }
    };
    V2Settings {
        platform: o.platform,
        composition: o.composition,
        client_api,
        session_platform: session_platform(o.platform),
    }
}

pub(crate) fn session_platform(platform: HostPlatform) -> advance_client_api::Platform {
    match platform {
        HostPlatform::MacOs => advance_client_api::Platform::Mac,
        HostPlatform::Ios => advance_client_api::Platform::Ios,
        HostPlatform::Android => advance_client_api::Platform::Android,
        HostPlatform::Windows => advance_client_api::Platform::Windows,
        HostPlatform::Linux => advance_client_api::Platform::Mac,
        _ => advance_client_api::Platform::Mac,
    }
}

fn compose_options(home: PathBuf, o: &BridgeOptions) -> ComposeOptions {
    let client_api = match o
        .client_api
        .unwrap_or(BridgeClientApi::Loopback { port: 0 })
    {
        BridgeClientApi::Loopback { port } => {
            ClientApiOptions::loopback(port, false, Admission::InProcessOnly)
        }
        BridgeClientApi::Off => ClientApiOptions::Off,
    };
    let opts = ComposeOptions::embedded(home, o.platform, Arc::clone(&o.log))
        .with_processes(o.resolved_processes())
        .with_wasm_engine(o.resolved_engine())
        .with_master_key(o.master_key.clone())
        .with_client_api(client_api);
    match &o.state_root {
        Some(root) => opts.with_state_root(root.clone()),
        None => opts,
    }
}

pub(crate) fn compose_error(e: ComposeError) -> BridgeError {
    match e {
        ComposeError::Unsupported(_) => BridgeError::Unsupported(e.to_string()),
        other => BridgeError::Compose(other.to_string()),
    }
}

fn check_full_config_path(ws: &Path, config_path: Option<&Path>) -> Result<(), BridgeError> {
    let Some(path) = config_path else {
        return Ok(());
    };
    let default = crate::config::confine_under_workspace(
        ws,
        Path::new(".advance").join("runtime-config.yaml").as_path(),
    );
    let got = crate::config::confine_under_workspace(ws, path);
    match (got, default) {
        (Ok(got), Ok(default)) if got == default => Ok(()),
        _ => Err(BridgeError::Unsupported(format!(
            r#"composition "full" reads only {}/.advance/runtime-config.yaml"#,
            ws.display()
        ))),
    }
}

fn v1_config(o: &BridgeOptions) -> BridgeConfig {
    BridgeConfig {
        platform: honesty_class(o.platform),
        engine_mode: if o.resolved_engine() == WasmEngine::Pulley {
            EngineMode::Interpreter
        } else {
            EngineMode::Jit
        },
        composition_mode: CompositionMode::Embed,
        config_path: o.config_path.clone(),
        ..BridgeConfig::default()
    }
}

fn v1_view_config(settings: &V2Settings) -> BridgeConfig {
    BridgeConfig {
        platform: honesty_class(settings.platform),
        engine_mode: EngineMode::Jit,
        composition_mode: CompositionMode::Embed,
        ..BridgeConfig::default()
    }
}

fn knobs(o: &BridgeOptions) -> EmbedKnobs {
    EmbedKnobs {
        backend: if o.resolved_engine() == WasmEngine::Pulley {
            WasmBackend::Pulley
        } else {
            WasmBackend::Native
        },
        lock_probe: o.resolved_processes(),
    }
}

async fn start_full(
    ws: PathBuf,
    options: BridgeOptions,
    exts: Vec<Arc<dyn ComposeExtension>>,
    settings: V2Settings,
) -> Result<BridgeHandle, BridgeError> {
    let rt = compose(compose_options(ws.clone(), &options), exts)
        .await
        .map_err(compose_error)?;
    let inner = Arc::new(BridgeInner {
        workspace: ws,
        config: v1_view_config(&settings),
        lifecycle: Mutex::new(default_lifecycle()),
        mode: Mutex::new(ModeState::Composed(Arc::new(ComposedHandle::new(
            rt,
            settings.clone(),
        )))),
        stopped: AtomicBool::new(false),
        reserved: AtomicBool::new(false),
        v2: Some(settings),
    });
    Ok(BridgeHandle::new(inner))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    use advance_client_api::audit::RecordingSink;
    use advance_client_api::clock::TestClock;
    use advance_client_api::ClientApi;
    use advance_runtime_compose::{ComposeError, LockFailure, Unsupported};

    use crate::handle::ComposedHandle;

    #[test]
    fn module_001_ac32_compose_lock_failures_answer_15() {
        let cases = [
            LockFailure::ActiveRuntime { pid: 7 },
            LockFailure::HeldInProcess,
            LockFailure::RegistryPoisoned,
            LockFailure::Io("disk".into()),
            LockFailure::Parse("bad".into()),
        ];
        for failure in cases {
            let text = ComposeError::Lock(failure.clone()).to_string();
            let err = compose_error(ComposeError::Lock(failure));
            assert_eq!(err.c_code(), 15, "{text}");
            assert_eq!(err.to_string(), text);
        }
    }

    #[test]
    fn module_001_ac32_compose_unsupported_answers_14() {
        let err = compose_error(ComposeError::Unsupported(Unsupported::EmbeddedAdmission));
        assert_eq!(err.c_code(), 14);
        assert_eq!(
            err.to_string(),
            ComposeError::Unsupported(Unsupported::EmbeddedAdmission).to_string()
        );
    }

    #[test]
    fn module_001_ac32_session_platform_mapping() {
        assert_eq!(
            session_platform(HostPlatform::MacOs),
            advance_client_api::Platform::Mac
        );
        assert_eq!(
            session_platform(HostPlatform::Ios),
            advance_client_api::Platform::Ios
        );
        assert_eq!(
            session_platform(HostPlatform::Android),
            advance_client_api::Platform::Android
        );
        assert_eq!(
            session_platform(HostPlatform::Windows),
            advance_client_api::Platform::Windows
        );
        assert_eq!(
            session_platform(HostPlatform::Linux),
            advance_client_api::Platform::Mac
        );
    }

    fn stand_in() -> (ClientApi, ComposedHandle) {
        let api = ClientApi::with_parts(
            advance_client_api::ClientApiConfig::default(),
            "op",
            Arc::new(TestClock::new(1_000_000)),
            Arc::new(RecordingSink::default()),
        );
        let handle = ComposedHandle::new_session_stand_in(V2Settings {
            platform: HostPlatform::MacOs,
            composition: CompositionProfile::Full,
            client_api: true,
            session_platform: advance_client_api::Platform::Mac,
        });
        (api, handle)
    }

    #[test]
    fn module_001_ac32_session_rotates_once_per_move() {
        let base_old = "http://127.0.0.1:1";
        let base_new = "http://127.0.0.1:2";

        let (api, handle) = stand_in();
        api.mint_in_process_session(advance_client_api::Platform::Mac);
        assert_eq!(api.sessions().len(), 1);
        handle.session_token(&api, base_old).expect("getter");
        assert_eq!(api.sessions().len(), 2);
        handle.rotate_after_move_on(&api, base_new);
        assert_eq!(api.sessions().len(), 1, "exactly one revoke_all then mint");
        assert_eq!(handle.stored_base().as_deref(), Some(base_new));
        handle.rotate_after_move_on(&api, base_new);
        assert_eq!(api.sessions().len(), 1, "second rotate is a no-op");

        let (api, handle) = stand_in();
        api.mint_in_process_session(advance_client_api::Platform::Mac);
        assert_eq!(api.sessions().len(), 1);
        handle.rotate_after_move_on(&api, base_new);
        assert_eq!(
            api.sessions().len(),
            1,
            "rotate with no session revokes then mints"
        );
        assert_eq!(handle.stored_base().as_deref(), Some(base_new));
        let token = handle
            .session_token(&api, base_new)
            .expect("getter after rotate");
        assert!(!token.is_empty());
        assert_eq!(api.sessions().len(), 1);
        handle.session_token(&api, base_new).expect("second getter");
        assert_eq!(api.sessions().len(), 1, "second getter is a no-op");
    }
}
