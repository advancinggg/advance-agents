//! Panic containment for extension callbacks.

use std::any::Any;
use std::panic::AssertUnwindSafe;

use futures::FutureExt;

use crate::api::{BoxFuture, ComposeError, ExtensionError, ExtensionFailure, ExtensionPhase};

const PANIC_TEXT_MAX: usize = 512;

/// `&str` / `String` payload, else `"non-string panic payload"`. Control
/// characters (including newlines) become spaces; the result is cut at a char
/// boundary to at most 512 bytes.
pub fn panic_text(payload: &(dyn Any + Send)) -> String {
    if let Some(text) = payload.downcast_ref::<String>() {
        sanitize_text(text)
    } else if let Some(text) = payload.downcast_ref::<&str>() {
        sanitize_text(text)
    } else {
        "non-string panic payload".to_owned()
    }
}

/// Control characters (including newlines) become spaces; cut at a char
/// boundary to at most 512 bytes.
pub fn sanitize_text(s: &str) -> String {
    let replaced: String = s
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    if replaced.len() <= PANIC_TEXT_MAX {
        return replaced;
    }
    let mut end = PANIC_TEXT_MAX;
    while end > 0 && !replaced.is_char_boundary(end) {
        end -= 1;
    }
    replaced[..end].to_owned()
}

/// Outcome of a guarded extension callback.
pub enum CallOutcome<T> {
    Ok(T),
    Failed(ExtensionError),
    Panicked(String),
}

pub fn call_guarded<T>(f: impl FnOnce() -> Result<T, ExtensionError>) -> CallOutcome<T> {
    match std::panic::catch_unwind(AssertUnwindSafe(f)) {
        Ok(Ok(value)) => CallOutcome::Ok(value),
        Ok(Err(error)) => CallOutcome::Failed(error),
        Err(payload) => CallOutcome::Panicked(panic_text(&*payload)),
    }
}

pub async fn call_guarded_async<'a, T>(
    make: impl FnOnce() -> BoxFuture<'a, Result<T, ExtensionError>>,
) -> CallOutcome<T> {
    let future = match std::panic::catch_unwind(AssertUnwindSafe(make)) {
        Ok(future) => future,
        Err(payload) => return CallOutcome::Panicked(panic_text(&*payload)),
    };
    match AssertUnwindSafe(future).catch_unwind().await {
        Ok(Ok(value)) => CallOutcome::Ok(value),
        Ok(Err(error)) => CallOutcome::Failed(error),
        Err(payload) => CallOutcome::Panicked(panic_text(&*payload)),
    }
}

/// `Err` is a panicked callback mapped to [`ComposeError::Extension`].
pub fn run_sync_callback<T>(
    extension: &'static str,
    phase: ExtensionPhase,
    f: impl FnOnce() -> Result<T, ExtensionError>,
) -> Result<Result<T, ExtensionError>, ComposeError> {
    match call_guarded(f) {
        CallOutcome::Ok(value) => Ok(Ok(value)),
        CallOutcome::Failed(error) => Ok(Err(error)),
        CallOutcome::Panicked(message) => Err(ComposeError::Extension {
            extension,
            phase,
            failure: ExtensionFailure::Panicked(message),
        }),
    }
}

/// `Err` is a panicked callback mapped to [`ComposeError::Extension`].
pub async fn run_async_callback<'a, T>(
    extension: &'static str,
    phase: ExtensionPhase,
    make: impl FnOnce() -> BoxFuture<'a, Result<T, ExtensionError>>,
) -> Result<Result<T, ExtensionError>, ComposeError> {
    match call_guarded_async(make).await {
        CallOutcome::Ok(value) => Ok(Ok(value)),
        CallOutcome::Failed(error) => Ok(Err(error)),
        CallOutcome::Panicked(message) => Err(ComposeError::Extension {
            extension,
            phase,
            failure: ExtensionFailure::Panicked(message),
        }),
    }
}

pub fn failed(extension: &'static str, phase: ExtensionPhase, e: &ExtensionError) -> ComposeError {
    ComposeError::Extension {
        extension,
        phase,
        failure: ExtensionFailure::Failed(sanitize_text(e.message())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn module_001_ac31_guards_precedence_and_panic_text() {
        match call_guarded(|| Ok::<_, ExtensionError>(7)) {
            CallOutcome::Ok(7) => {}
            _ => panic!("ok"),
        }
        match call_guarded(|| Err::<(), _>(ExtensionError::new("nope"))) {
            CallOutcome::Failed(error) if error.message() == "nope" => {}
            _ => panic!("failed"),
        }
        match call_guarded(|| -> Result<(), ExtensionError> { panic!("boom") }) {
            CallOutcome::Panicked(text) if text == "boom" => {}
            other => panic!("str panic: {other:?}"),
        }
        match call_guarded(|| -> Result<(), ExtensionError> { panic!("{}", "owned".to_owned()) }) {
            CallOutcome::Panicked(text) if text == "owned" => {}
            other => panic!("string panic: {other:?}"),
        }
        match call_guarded(|| -> Result<(), ExtensionError> {
            std::panic::panic_any(42u32);
        }) {
            CallOutcome::Panicked(text) if text == "non-string panic payload" => {}
            other => panic!("other panic: {other:?}"),
        }
        match call_guarded(|| -> Result<(), ExtensionError> { panic!("hello\nworld") }) {
            CallOutcome::Panicked(text) if text == "hello world" => {}
            other => panic!("newline: {other:?}"),
        }

        let payload = format!("{}é", "a".repeat(511));
        assert!(payload.len() > 512);
        let cut = panic_text(&payload);
        assert!(cut.len() <= 512);
        assert!(cut.is_char_boundary(cut.len()));
        assert!(cut.starts_with("aaa"));
        assert!(!cut.contains('é'));

        let panicked: Result<Result<(), ExtensionError>, ComposeError> =
            run_sync_callback("fixture", ExtensionPhase::Capabilities, || {
                panic!("in capabilities")
            });
        match panicked {
            Err(ComposeError::Extension {
                extension: "fixture",
                phase: ExtensionPhase::Capabilities,
                failure: ExtensionFailure::Panicked(ref message),
            }) if message == "in capabilities" => {}
            other => panic!("{other:?}"),
        }

        let error = failed(
            "fixture",
            ExtensionPhase::Tools,
            &ExtensionError::new("a\nb"),
        );
        match error {
            ComposeError::Extension {
                failure: ExtensionFailure::Failed(message),
                ..
            } if message == "a b" => {}
            other => panic!("{other:?}"),
        }
    }

    #[tokio::test]
    async fn module_001_ac31_guards_async_panic_building_polling_err_ok() {
        match call_guarded_async(|| Box::pin(async { Ok::<_, ExtensionError>(1) })).await {
            CallOutcome::Ok(1) => {}
            _ => panic!("ok"),
        }
        match call_guarded_async(|| {
            Box::pin(async { Err::<(), _>(ExtensionError::new("async-err")) })
        })
        .await
        {
            CallOutcome::Failed(error) if error.message() == "async-err" => {}
            _ => panic!("failed"),
        }
        match call_guarded_async(|| {
            panic!("building");
            #[allow(unreachable_code)]
            Box::pin(async { Ok(()) })
        })
        .await
        {
            CallOutcome::Panicked(text) if text == "building" => {}
            other => panic!("building: {other:?}"),
        }
        match call_guarded_async(|| {
            Box::pin(async {
                panic!("polling");
                #[allow(unreachable_code)]
                Ok(())
            }) as BoxFuture<'_, Result<(), ExtensionError>>
        })
        .await
        {
            CallOutcome::Panicked(text) if text == "polling" => {}
            other => panic!("polling: {other:?}"),
        }
    }
}

impl<T> std::fmt::Debug for CallOutcome<T>
where
    T: std::fmt::Debug,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CallOutcome::Ok(value) => f.debug_tuple("Ok").field(value).finish(),
            CallOutcome::Failed(error) => f.debug_tuple("Failed").field(error).finish(),
            CallOutcome::Panicked(text) => f.debug_tuple("Panicked").field(text).finish(),
        }
    }
}
