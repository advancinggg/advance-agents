//! What a host adds to the composition.

pub use futures::future::BoxFuture;

/// An extension composed with the runtime. It is identified by [`id`](Self::id); its
/// [`shutdown`](Self::shutdown) hook runs during the ordered shutdown, after the
/// loops have stopped and before the runtime's own holds are released.
pub trait ComposeExtension: Send + Sync + 'static {
    /// A stable identifier, used in the composition's lines and errors.
    fn id(&self) -> &'static str;

    /// Release what the extension holds. Hooks run in reverse registration order, each
    /// bounded (a hook that has not finished within 5 seconds is abandoned) and each
    /// isolated (a panic is reported and the shutdown continues).
    fn shutdown<'a>(&'a self) -> BoxFuture<'a, ()> {
        Box::pin(async {})
    }
}
