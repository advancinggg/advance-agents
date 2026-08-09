use std::fs;
use std::path::PathBuf;

fn asset(name: &str) -> String {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("assets/console");
    fs::read_to_string(root.join(name)).expect("Web Console asset")
}

#[test]
fn console_uses_only_public_client_api_and_safe_dom_writes() {
    let js = asset("app.js");
    for public_route in [
        "/client/session/login",
        "/client/grants/pending",
        "/client/grants/",
        "/client/events/stream",
        "/history",
    ] {
        assert!(
            js.contains(public_route),
            "missing public route {public_route}"
        );
    }
    for forbidden in [
        "/internal",
        "/runtime",
        "EventBus",
        "GrantStore",
        "innerHTML",
        "outerHTML",
        "insertAdjacentHTML",
    ] {
        assert!(
            !js.contains(forbidden),
            "console contains forbidden backdoor/DOM sink {forbidden}"
        );
    }
    assert!(js.contains("textContent"));
    assert!(js.contains("unicode-bidi") || asset("styles.css").contains("unicode-bidi: plaintext"));
    assert!(
        js.contains("\\u202a-\\u202e"),
        "Unicode Cf controls must be stripped"
    );
    assert!(asset("index.html").contains("Content-Security-Policy"));
}

#[test]
fn console_history_paths_are_task_or_run_only() {
    let html = asset("index.html");
    let js = asset("app.js");
    assert!(html.contains("value=\"tasks\"") && html.contains("value=\"runs\""));
    assert!(js.contains("`/client/${kind}/${id}/history`"));
}
