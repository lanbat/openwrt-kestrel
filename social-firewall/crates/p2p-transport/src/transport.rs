use crate::envelope::Envelope;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum TransportError {
    #[error("no route to peer {0} — unknown or unreachable")]
    Unreachable(String),
    #[error("transport closed")]
    Closed,
    #[error("transport error: {0}")]
    Other(String),
}

/// Mirrors `wg_tunnel::CommandRunner`'s shape: a small trait so the
/// send/receive/dispatch flow above this boundary is fully unit
/// testable without a real network. `to`/`from` are opaque peer
/// addresses (an Iroh node id as a string, in production) — this trait
/// doesn't know or care about Iroh specifically.
pub trait PeerTransport {
    fn send(&self, to: &str, envelope: &Envelope) -> Result<(), TransportError>;
    /// Blocks until one envelope arrives, returning the sender's address
    /// alongside it. A simple blocking single-item receive rather than a
    /// callback-based `listen` — `sf listen` (Task 5) wraps this in its
    /// own loop, keeping this trait's surface minimal.
    fn recv(&self) -> Result<(String, Envelope), TransportError>;
}
