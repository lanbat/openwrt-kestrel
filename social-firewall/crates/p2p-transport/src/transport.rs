use crate::envelope::Envelope;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum TransportError {
    #[error("no route to peer {0} — unknown or unreachable")]
    Unreachable(String),
    #[error("transport closed")]
    Closed,
    #[error("application rejected the envelope: {0}")]
    ApplicationRejected(String),
    #[error("transport error: {0}")]
    Other(String),
}

pub type Dispatch<'a> = dyn Fn(&str, &Envelope) -> Result<Option<Envelope>, String> + 'a;

/// Mirrors `wg_tunnel::CommandRunner`'s shape: a small trait so the
/// send/receive/dispatch flow above this boundary is fully unit
/// testable without a real network. `to`/`from` are opaque peer
/// addresses (an Iroh node id as a string, in production) — this trait
/// doesn't know or care about Iroh specifically.
pub trait PeerTransport {
    /// `Ok(())` means the peer dispatched and accepted the envelope.
    /// Application rejection is returned as `ApplicationRejected`.
    fn send(&self, to: &str, envelope: &Envelope) -> Result<(), TransportError>;
    /// Sends an application request and returns the response produced by the
    /// receiver's dispatch callback.
    fn request(&self, to: &str, envelope: &Envelope) -> Result<Envelope, TransportError>;
    /// Blocks until one envelope arrives, dispatches it, and acknowledges
    /// the sender. `from` is authenticated by Iroh in production.
    fn recv_and_dispatch(&self, dispatch: &Dispatch<'_>) -> Result<(), TransportError>;
}
