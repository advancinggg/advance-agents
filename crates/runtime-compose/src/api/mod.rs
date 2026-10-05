//! The composition API: the types an embedder names to compose the runtime and
//! receive its output.

mod compose_log;
mod error;

pub use compose_log::log_keys;
pub use compose_log::ComposeLog;
pub use compose_log::ComposeLogLine;
pub use compose_log::LogStream;
pub use compose_log::NullComposeLog;
pub use error::ComposeError;
pub use error::LockFailure;
