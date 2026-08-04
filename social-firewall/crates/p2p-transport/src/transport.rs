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
    /// `Ok(())` means the peer's transport received and decoded the
    /// envelope — **not** that the peer's ingest logic accepted the
    /// statement inside it. See this crate's module docs: because
    /// `recv` below is a queue rather than a callback, dispatch happens
    /// after the sender has already been acked, so accept/reject cannot
    /// be reported back over the wire today.
    fn send(&self, to: &str, envelope: &Envelope) -> Result<(), TransportError>;
    /// Blocks until one envelope arrives, returning the sender's address
    /// alongside it. A simple blocking single-item receive rather than a
    /// callback-based `listen` — `sf listen` (Task 5) wraps this in its
    /// own loop, keeping this trait's surface minimal. The cost of that
    /// minimalism is that the transport acks a sender before anything
    /// has dispatched the envelope; changing this method to a callback
    /// is the prerequisite for real accept/reject acking.
    ///
    /// `from` is the sender's address, and for `IrohTransport` it is
    /// cryptographically authenticated by the QUIC/TLS handshake — safe
    /// for a caller to gate on, which `cli::tunnel::listen` does.
    fn recv(&self) -> Result<(String, Envelope), TransportError>;
}
