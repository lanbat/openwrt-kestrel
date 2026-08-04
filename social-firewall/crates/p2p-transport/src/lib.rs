//! In-flight delivery of already-signed statements between social-firewall
//! nodes. Mirrors `wg-tunnel`'s shape: a small `PeerTransport` trait keeps
//! everything above the transport boundary testable without a real
//! network via `FakeTransport`; `IrohTransport` (Task 2) is the real
//! implementation. This crate never touches signing, sealing, or trust —
//! it moves bytes that were already fully prepared by `cli`.
//!
//! **Delivery semantics — read before treating a successful `send()` as
//! "the peer accepted this".** The receive side is a queue, not a
//! request/response: `IrohTransport`'s accept loop decodes an envelope,
//! pushes it onto the channel `recv()` drains, acks the sender, and
//! closes the stream. The receiving router's `ingest_*` logic (signature
//! verification, follow gating, everything that can legitimately reject
//! a statement) runs *afterwards*, in `cli::tunnel::listen`, long after
//! the sender has been acked and disconnected.
//!
//! So `send() -> Ok(())` means **received and decoded by the peer's
//! transport**, not **accepted by the peer**. The original design called
//! for the ack to carry accept/reject; that is not implemented and would
//! require a callback-shaped receive side on `PeerTransport` so dispatch
//! could run while the stream is still open. Until then, a sender has no
//! way to learn that a delivered statement was rejected downstream.

mod envelope;
mod fake_transport;
mod iroh_transport;
mod transport;

pub use envelope::{Envelope, EnvelopeError, StatementKind};
pub use fake_transport::FakeTransport;
pub use iroh_transport::IrohTransport;
pub use transport::{PeerTransport, TransportError};
