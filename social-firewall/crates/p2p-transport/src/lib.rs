//! In-flight delivery of already-signed statements between social-firewall
//! nodes. Mirrors `wg-tunnel`'s shape: a small `PeerTransport` trait keeps
//! everything above the transport boundary testable without a real
//! network via `FakeTransport`; `IrohTransport` (Task 2) is the real
//! implementation. This crate never touches signing, sealing, or trust —
//! it moves bytes that were already fully prepared by `cli`.

mod envelope;
mod fake_transport;
mod transport;

pub use envelope::{Envelope, EnvelopeError, StatementKind};
pub use fake_transport::FakeTransport;
pub use transport::{PeerTransport, TransportError};
