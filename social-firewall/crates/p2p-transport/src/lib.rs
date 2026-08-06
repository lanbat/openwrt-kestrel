//! In-flight delivery of already-signed statements between social-firewall
//! nodes. Mirrors `wg-tunnel`'s shape: a small `PeerTransport` trait keeps
//! everything above the transport boundary testable without a real
//! network via `FakeTransport`; `IrohTransport` (Task 2) is the real
//! implementation. This crate never touches signing, sealing, or trust —
//! it moves bytes that were already fully prepared by `cli`.
//!
//! `send() -> Ok(())` means the peer dispatched and accepted the envelope.
//! A dispatch error is returned as `TransportError::ApplicationRejected`.
//! The callback-shaped receive side keeps the acknowledgment stream open
//! until signature verification, follow gating, and ingest have completed.

mod envelope;
mod fake_transport;
mod iroh_transport;
mod transport;

pub use envelope::{Envelope, EnvelopeError, StatementKind};
pub use fake_transport::FakeTransport;
pub use iroh_transport::IrohTransport;
pub use transport::{Dispatch, PeerTransport, TransportError};
