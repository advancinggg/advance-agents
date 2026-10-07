//! The handle the composition's modules emit lines through.
//!
//! Every object and task that reports something holds a [`LogHandle`] instead of
//! printing. Public constructors that predate it keep their signatures and start
//! with [`LogHandle::null`]; the composition installs its sink through each type's
//! `with_log` builder or a `*_with_log` sibling function.

use std::fmt;
use std::sync::Arc;

use crate::api::{log_keys, ComposeLog, ComposeLogLine, LogStream, NullComposeLog};

/// A cheap, cloneable reference to the composition's [`ComposeLog`].
#[derive(Clone)]
pub struct LogHandle(Arc<dyn ComposeLog>);

impl LogHandle {
    /// Emit through `log`.
    pub fn new(log: Arc<dyn ComposeLog>) -> Self {
        Self(log)
    }

    /// Discard every line ([`NullComposeLog`]).
    pub fn null() -> Self {
        Self(Arc::new(NullComposeLog))
    }

    pub(crate) fn sink(&self) -> Arc<dyn ComposeLog> {
        Arc::clone(&self.0)
    }

    /// A line `advance start` prints on stdout.
    pub fn out(&self, key: &'static str, text: impl Into<String>) {
        self.emit(LogStream::Stdout, key, text.into());
    }

    /// A line `advance start` prints on stderr.
    pub fn err(&self, key: &'static str, text: impl Into<String>) {
        self.emit(LogStream::Stderr, key, text.into());
    }

    /// The readiness line (stdout, [`log_keys::READY`]); the sink may refuse it.
    pub fn ready(&self, text: impl Into<String>) -> std::io::Result<()> {
        self.0.ready(&ComposeLogLine {
            stream: LogStream::Stdout,
            key: log_keys::READY,
            text: text.into(),
        })
    }

    fn emit(&self, stream: LogStream, key: &'static str, text: String) {
        self.0.line(&ComposeLogLine { stream, key, text });
    }
}

impl Default for LogHandle {
    fn default() -> Self {
        Self::null()
    }
}

impl fmt::Debug for LogHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("LogHandle")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    #[derive(Default)]
    struct Recording {
        lines: Mutex<Vec<ComposeLogLine>>,
        refuse_ready: bool,
    }

    impl ComposeLog for Recording {
        fn line(&self, line: &ComposeLogLine) {
            self.lines.lock().unwrap().push(line.clone());
        }

        fn ready(&self, line: &ComposeLogLine) -> std::io::Result<()> {
            self.lines.lock().unwrap().push(line.clone());
            if self.refuse_ready {
                Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe))
            } else {
                Ok(())
            }
        }
    }

    #[test]
    fn handle_routes_each_line_to_its_stream_with_its_key() {
        let sink = Arc::new(Recording::default());
        let log = LogHandle::new(sink.clone());
        log.out(log_keys::SHUTTING_DOWN, "advance: shutting down");
        log.err(log_keys::PACKS_WARN, format!("advance: WARN {}", "x"));
        log.ready("advance: runtime ready (workspace=\"/w\")")
            .unwrap();
        let lines = sink.lines.lock().unwrap().clone();
        assert_eq!(
            lines,
            vec![
                ComposeLogLine {
                    stream: LogStream::Stdout,
                    key: log_keys::SHUTTING_DOWN,
                    text: "advance: shutting down".into(),
                },
                ComposeLogLine {
                    stream: LogStream::Stderr,
                    key: log_keys::PACKS_WARN,
                    text: "advance: WARN x".into(),
                },
                ComposeLogLine {
                    stream: LogStream::Stdout,
                    key: log_keys::READY,
                    text: "advance: runtime ready (workspace=\"/w\")".into(),
                },
            ]
        );
    }

    #[test]
    fn a_refused_readiness_line_is_reported_and_null_accepts_everything() {
        let sink = Arc::new(Recording {
            refuse_ready: true,
            ..Recording::default()
        });
        let err = LogHandle::new(sink).ready("r").unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::BrokenPipe);

        let null = LogHandle::default();
        null.out(log_keys::MSG_LISTENER, "x");
        null.err(log_keys::PACKS_WARN, "y");
        assert!(null.ready("z").is_ok());
    }
}
