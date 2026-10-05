//! MODULE-001-AC-30 — the listener and Client API options: `POST /msg` and the EventBus
//! HTTP/WebSocket server can be left out (the event read surface still answers through the
//! Client API), a home whose config needs the channel `/hooks` listener refuses options
//! that disable it, and `ClientApiOptions::Off` binds no Client API and writes no discovery
//! file.
//!
//! The compositions of this binary run one at a time (`serial`).

#[path = "support/t111.rs"]
mod t111;

use std::sync::Arc;

use advance_client_api::ClientRequest;
use advance_runtime_compose::registry::reserved_homes_for_test;
use advance_runtime_compose::test_support::{ComposeFailpoints, ComposeProbe, MemoryComposeLog};
use advance_runtime_compose::{
    compose, log_keys, ClientApiOptions, ComposeError, ListenerOptions, Unsupported,
};
use t111::{mint_session, serial, T111Home};

#[tokio::test(flavor = "current_thread")]
async fn module_001_ac30_listener_options_post_msg_and_event_bus_ws_off() {
    let _serial = serial();
    let home = T111Home::new(&["fs", "llm", "lifecycle"], true);
    let log = MemoryComposeLog::new();
    let probe = Arc::new(ComposeProbe::new());
    let runtime = compose(
        home.options(Arc::new(log.clone()))
            .with_listeners(
                ListenerOptions::daemon()
                    .with_post_msg(false)
                    .with_event_bus_ws(false),
            )
            .with_failpoints(ComposeFailpoints {
                probe: Some(Arc::clone(&probe)),
                ..ComposeFailpoints::default()
            }),
        Vec::new(),
    )
    .await
    .expect("compose without POST /msg and the EventBus server");

    let record = probe.record();
    assert_eq!(
        log.count(log_keys::AGENT_LOOP_WIRED),
        1,
        "the driver serves"
    );
    assert_eq!(log.count(log_keys::MSG_LISTENER), 0, "no POST /msg line");
    assert_eq!(record.listener("post_msg"), None, "no POST /msg listener");
    assert_eq!(record.listener("event_bus"), None, "no EventBus server");
    assert!(record.event_bus.is_some(), "the EventBus itself exists");
    assert!(
        record.listener("client_api").is_some(),
        "the Client API is bound"
    );

    // The event read surface still answers through the Client API on a lifecycle home.
    let endpoint = runtime.client_api().expect("the Client API is bound");
    let token = mint_session(&endpoint);
    let api = endpoint.api.clone();
    let events = tokio::task::spawn_blocking(move || {
        api.upgrade()
            .expect("the Client API is alive")
            .handle(ClientRequest::get("/client/events").with_session(&token))
    })
    .await
    .expect("the request ran");
    assert!(
        events.is_ok(),
        "/client/events answers without the EventBus server: {:?}",
        events.error
    );

    runtime.shutdown().await.expect("shutdown");
}

#[tokio::test(flavor = "current_thread")]
async fn module_001_ac30_channel_hooks_off_with_channels_is_unsupported() {
    let _serial = serial();
    let home = T111Home::new(&["fs"], true);
    home.edit_runtime_config(|yaml| {
        yaml + r#"
channels:
  webhook-listen-addr: "127.0.0.1:0"
  channels:
    - name: t111-telegram
      adapter: telegram
      secret: t111-inbound-secret
      route: t111
      url-template: "https://api.telegram.org/bot123/sendMessage"
"#
    });

    let error = compose(
        home.options(Arc::new(MemoryComposeLog::new()))
            .with_listeners(ListenerOptions::daemon().with_channel_hooks(false)),
        Vec::new(),
    )
    .await
    .expect_err("the config needs the /hooks listener");
    match &error {
        ComposeError::Unsupported(refused) => {
            assert_eq!(refused, &Unsupported::ListenerRequired("channel /hooks"))
        }
        other => panic!("expected Unsupported, got {other:?}"),
    }
    assert!(!home.lock_path().exists(), "the runtime lock is released");
    assert!(!reserved_homes_for_test().contains(&home.home));
}

#[tokio::test(flavor = "current_thread")]
async fn module_001_ac30_client_api_off() {
    let _serial = serial();
    let home = T111Home::new(&["fs"], true);
    let log = MemoryComposeLog::new();
    let runtime = compose(
        home.options(Arc::new(log.clone()))
            .with_client_api(ClientApiOptions::Off),
        Vec::new(),
    )
    .await
    .expect("compose without a Client API");
    assert!(runtime.client_api().is_none(), "no Client API");
    assert_eq!(runtime.health().client_api_base, None);
    assert!(
        !home.home.join(".runtime/client-api").exists(),
        "no discovery file"
    );
    assert_eq!(log.count(log_keys::CLIENT_API_LISTENING), 0);
    assert!(home.lock_path().exists(), "the pid lock is still taken");
    runtime.shutdown().await.expect("shutdown");
}
