# P2P Transport Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace "export a signed statement to a file, hand it to a human" with real network delivery over Iroh, for the statement types that already have a known recipient — without changing anything about how those statements are signed, sealed, or trusted.

**Architecture:** A new `p2p-transport` crate defines a `PeerTransport` trait (mirrors `wg-tunnel`'s `CommandRunner` pattern) with two implementations: `FakeTransport` (in-memory, used for nearly all tests) and `IrohTransport` (a real `iroh::Endpoint` wrapper). `cli` gains a new persistent `sf listen` command that accepts inbound envelopes and dispatches them to the *exact same* `ingest_X` functions the manual CLI path already calls, and the tunnel-request/accept send path attempts delivery via `PeerTransport::send` before falling back to today's file export.

**Tech Stack:** Rust, `iroh` 1.0.3 (QUIC-based P2P, `presets::N0`), `tokio` (new — this is the first async code in this codebase), existing `state-store`/`domain-types`/`crypto` crates unchanged.

## Global Constraints

- Zero changes to signing, sealing, storage, or trust semantics. The network envelope carries exactly the bytes `--out` already writes today (see spec's Goals).
- Automated delivery is additive, never a replacement: if a peer's `iroh_node_id` is unknown, or delivery fails for any reason, the existing `--out`/`--out-dir` file export must still happen exactly as it does today.
- Scope for *this* plan is deliberately narrower than the full spec's "automated in this phase" list: it covers the `TunnelConnectionRequest` → `TunnelConnectionAccept` flow only (the one flow the spec's own Testing section requires proven end-to-end). Group join requests, group publishes, party-line messages, and restricted exports get the *same* send-then-fallback pattern established here, as a mechanical follow-up once this one is proven — not built in this pass. This mirrors how item 8 in this project's own plan history ("Federation-scoped display names") scoped its first cut to the two highest-traffic call sites and left the rest for later, explicitly.
- No retry/queue logic. No changes to `follows`' privacy model. No discovery beyond a manually-entered `iroh_node_id`.

## Important finding from hands-on verification (read before Task 2)

The spec assumed "two Iroh endpoints can run fully in-process" makes real end-to-end testing trivial, the way it isn't for `nft`/`wg`. Hands-on verification during planning (a real `cargo add iroh`, real compiled probe code, run against the actual iroh 1.0.3 crate) found this to be optimistic: two `Endpoint`s bound in the same process, on the same host, using the exact pattern from iroh's own internal test suite (`Endpoint::builder(presets::N0)`, `.relay_mode(RelayMode::Disabled)`, dialing `server.addr()`), reliably **timed out after ~30s** rather than connecting — both with relay disabled (hole-punch negotiation, `do_holepunching`, never completed) and with relay enabled (real TLS handshakes against real n0 production relay servers succeeded, STUN-like network reports came back with a real public IP, but the QUIC connection itself still timed out, with `dropping unexpected packet` warnings suggesting multiple relay paths racing against each other in a same-host/same-process scenario).

This is not a sign the API calls in this plan are wrong — the code compiles clean against the real crate and matches iroh's own internal test pattern exactly. It's a sign that **same-process, same-host connectivity is itself an unreliable environment for validating Iroh**, likely because a single host normally never needs to hole-punch or relay to reach itself, so this exact scenario is a genuine edge case, not representative of two real separate routers on separate networks.

**Practical consequence for this plan**: `FakeTransport` (Task 1) is the *primary* test strategy for everything above the transport boundary — trait behavior, dispatch, error handling, CLI wiring. Real `IrohTransport`-to-`IrohTransport` connectivity (Task 2) gets its own dedicated, generously-timed task with real diagnostic steps below. If it continues to be unreliable in whatever environment Task 2 is executed in, that is itself useful information to report back, not a blocker to silently work around — the same "QEMU VM needed to truly verify real command-touching code" reality this project has already hit with `nft-enforcer`/`wg-tunnel` may turn out to apply here too (verify on two genuinely separate machines/VMs rather than one host).

Also worth knowing before Task 1: `iroh`'s default features pull in a large transitive dependency tree — `hickory-resolver`/`hickory-net` (a full DNS resolver), `reqwest`+`hyper`+`h2` (an HTTP client stack), `rustls`, `netlink-packet-route`, `portmapper`/`igd-next` (UPnP), `moka` (caching). This is a real build-time and binary-size cost on a flash-constrained OpenWrt router that the original spec didn't examine. Not a blocker — just something to be aware of, and worth trimming default features (`default-features = false`, keep `metrics`, `fast-apple-datapath`, `tls-ring`; drop `portmapper` unless UPnP turns out to matter) once the crate is in place.

---

## File Structure

```
crates/p2p-transport/
  Cargo.toml
  src/
    lib.rs           # module doc, re-exports
    envelope.rs       # Envelope, StatementKind, encode/decode
    transport.rs       # PeerTransport trait, TransportError
    fake_transport.rs   # FakeTransport (in-memory, primary test double)
    iroh_transport.rs    # IrohTransport (real, wraps iroh::Endpoint)

crates/state-store/
  migrations/0020_iroh_addressing.sql   # iroh_secret_seed on users, iroh_node_id on follows
  src/lib.rs           # +get/set_iroh_keypair_seed, LocalTrustRule.iroh_node_id, CRUD updates

crates/domain-types/
  src/trust.rs         # LocalTrustRule.iroh_node_id: Option<String>

crates/cli/
  src/main.rs          # add-follow --iroh-node-id, set-follow-node-id, `sf listen` command
  src/tunnel.rs         # bytes-based ingest core (refactor), send-then-fallback wiring, listen dispatch
  tests/cli.rs          # end-to-end delivery + fallback regression test
```

---

### Task 1: `p2p-transport` crate — `Envelope`, `PeerTransport`, `FakeTransport`

**Files:**
- Create: `crates/p2p-transport/Cargo.toml`
- Create: `crates/p2p-transport/src/lib.rs`
- Create: `crates/p2p-transport/src/envelope.rs`
- Create: `crates/p2p-transport/src/transport.rs`
- Create: `crates/p2p-transport/src/fake_transport.rs`
- Modify: `Cargo.toml` (workspace root) — add `crates/p2p-transport` to `members`

**Interfaces:**
- Produces: `StatementKind` enum, `Envelope { kind: StatementKind, payload: Vec<u8> }`, `Envelope::encode(&self) -> Vec<u8>` / `Envelope::decode(bytes: &[u8]) -> Result<Envelope, EnvelopeError>`, `TransportError` enum, `PeerTransport` trait (`fn send(&self, to: &str, envelope: &Envelope) -> Result<(), TransportError>`; `fn recv(&self) -> Result<(String, Envelope), TransportError>` — a blocking single-item receive, simpler than a callback-based `listen` for this phase's one-flow scope, matches `FakeCommandRunner`'s own "small, blocking, synchronous" shape), `FakeTransport::new() -> Self`, `FakeTransport::pair() -> (FakeTransport, FakeTransport)` (two instances wired to each other's inboxes, for two-sided tests).

- [ ] **Step 1: Create the crate skeleton**

```toml
# crates/p2p-transport/Cargo.toml
[package]
name = "p2p-transport"
version.workspace = true
edition.workspace = true

[dependencies]
thiserror = "2"

[dev-dependencies]
```

Add `"crates/p2p-transport"` to the `members` list in the workspace root `Cargo.toml` (alongside the other crates — follow the existing list's formatting exactly).

- [ ] **Step 2: Write the failing test for `Envelope` encode/decode**

```rust
// crates/p2p-transport/src/envelope.rs
use thiserror::Error;

/// Which existing `ingest_X` function a received envelope should be
/// dispatched to. Scoped to this plan's one proven flow for now — more
/// variants are added as more send paths get wired (see this plan's
/// Global Constraints).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatementKind {
    TunnelConnectionRequest,
    TunnelConnectionAccept,
}

impl StatementKind {
    fn tag(self) -> u8 {
        match self {
            StatementKind::TunnelConnectionRequest => 1,
            StatementKind::TunnelConnectionAccept => 2,
        }
    }

    fn from_tag(tag: u8) -> Option<Self> {
        match tag {
            1 => Some(StatementKind::TunnelConnectionRequest),
            2 => Some(StatementKind::TunnelConnectionAccept),
            _ => None,
        }
    }
}

/// One statement in transit: a `kind` tag plus the exact same JSON bytes
/// `--out` already writes today (see this plan's Global Constraints — no
/// new wire format for the payload itself, only a thin wrapper around it).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Envelope {
    pub kind: StatementKind,
    pub payload: Vec<u8>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum EnvelopeError {
    #[error("envelope too short to contain a kind tag")]
    TooShort,
    #[error("unrecognized statement kind tag {0}")]
    UnknownKind(u8),
}

impl Envelope {
    /// One tag byte followed by the raw payload — deliberately minimal,
    /// no length-prefixing needed since this is one envelope per QUIC
    /// stream (see the design spec's Wire shape section: the receiver
    /// reads to end-of-stream, not to a declared length).
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + self.payload.len());
        out.push(self.kind.tag());
        out.extend_from_slice(&self.payload);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Envelope, EnvelopeError> {
        let (tag, payload) = bytes.split_first().ok_or(EnvelopeError::TooShort)?;
        let kind = StatementKind::from_tag(*tag).ok_or(EnvelopeError::UnknownKind(*tag))?;
        Ok(Envelope { kind, payload: payload.to_vec() })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn envelope_round_trips_through_encode_decode() {
        let original = Envelope { kind: StatementKind::TunnelConnectionRequest, payload: b"{\"hello\":true}".to_vec() };
        let decoded = Envelope::decode(&original.encode()).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn envelope_decode_rejects_an_unknown_kind_tag() {
        let bytes = vec![99u8, b'{', b'}'];
        assert_eq!(Envelope::decode(&bytes), Err(EnvelopeError::UnknownKind(99)));
    }

    #[test]
    fn envelope_decode_rejects_an_empty_buffer() {
        assert_eq!(Envelope::decode(&[]), Err(EnvelopeError::TooShort));
    }
}
```

- [ ] **Step 3: Run the test to verify it passes**

Run: `cargo test -p p2p-transport --lib envelope`
Expected: 3 tests pass (this is pure logic with no external dependency, so it should pass immediately — this step confirms the crate itself is wired into the workspace correctly).

- [ ] **Step 4: Write the `PeerTransport` trait and `TransportError`**

```rust
// crates/p2p-transport/src/transport.rs
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
```

- [ ] **Step 5: Write the failing test for `FakeTransport`**

```rust
// crates/p2p-transport/src/fake_transport.rs
use crate::envelope::{Envelope, StatementKind};
use crate::transport::{PeerTransport, TransportError};
use std::collections::HashMap;
use std::sync::mpsc::{Receiver, Sender};
use std::sync::{Arc, Mutex};

/// An in-memory `PeerTransport` for tests — no network, no async
/// runtime. `pair()` wires two instances to each other so a test can
/// exercise a real two-sided send/recv without touching Iroh at all;
/// this is the primary test strategy for everything above the
/// transport boundary (see this plan's "Important finding" section on
/// why real Iroh connectivity is verified separately, not relied on for
/// routine testing).
pub struct FakeTransport {
    my_address: String,
    inbox: Arc<Mutex<Receiver<(String, Envelope)>>>,
    peers: Arc<Mutex<HashMap<String, Sender<(String, Envelope)>>>>,
}

impl FakeTransport {
    pub fn pair() -> (FakeTransport, FakeTransport) {
        let (tx_a, rx_a) = std::sync::mpsc::channel();
        let (tx_b, rx_b) = std::sync::mpsc::channel();
        let a = FakeTransport {
            my_address: "peer-a".to_string(),
            inbox: Arc::new(Mutex::new(rx_a)),
            peers: Arc::new(Mutex::new(HashMap::from([("peer-b".to_string(), tx_b)]))),
        };
        let b = FakeTransport {
            my_address: "peer-b".to_string(),
            inbox: Arc::new(Mutex::new(rx_b)),
            peers: Arc::new(Mutex::new(HashMap::from([("peer-a".to_string(), tx_a)]))),
        };
        (a, b)
    }
}

impl PeerTransport for FakeTransport {
    fn send(&self, to: &str, envelope: &Envelope) -> Result<(), TransportError> {
        let peers = self.peers.lock().unwrap();
        let sender = peers.get(to).ok_or_else(|| TransportError::Unreachable(to.to_string()))?;
        sender.send((self.my_address.clone(), envelope.clone())).map_err(|_| TransportError::Closed)
    }

    fn recv(&self) -> Result<(String, Envelope), TransportError> {
        self.inbox.lock().unwrap().recv().map_err(|_| TransportError::Closed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn two_fake_transports_exchange_an_envelope() {
        let (a, b) = FakeTransport::pair();
        let envelope = Envelope { kind: StatementKind::TunnelConnectionRequest, payload: b"hello".to_vec() };

        a.send("peer-b", &envelope).unwrap();

        let (from, received) = b.recv().unwrap();
        assert_eq!(from, "peer-a");
        assert_eq!(received, envelope);
    }

    #[test]
    fn sending_to_an_unknown_peer_is_a_typed_error_not_a_panic() {
        let (a, _b) = FakeTransport::pair();
        let envelope = Envelope { kind: StatementKind::TunnelConnectionAccept, payload: b"x".to_vec() };
        let err = a.send("nobody", &envelope).unwrap_err();
        assert!(matches!(err, TransportError::Unreachable(_)));
    }
}
```

- [ ] **Step 6: Wire up `lib.rs` and run the full test suite**

```rust
// crates/p2p-transport/src/lib.rs
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
```

Run: `cargo test -p p2p-transport`
Expected: 5 tests pass (3 envelope + 2 fake_transport).

- [ ] **Step 7: Commit**

```bash
git add crates/p2p-transport crates/Cargo.toml 2>/dev/null || git add crates/p2p-transport Cargo.toml
git commit -m "p2p-transport: Envelope, PeerTransport trait, FakeTransport"
```

---

### Task 2: `IrohTransport` — the real implementation

**Files:**
- Create: `crates/p2p-transport/src/iroh_transport.rs`
- Modify: `crates/p2p-transport/Cargo.toml` — add `iroh`, `tokio` dependencies
- Modify: `crates/p2p-transport/src/lib.rs` — export `IrohTransport`

**Interfaces:**
- Consumes: `PeerTransport`, `Envelope`, `TransportError` from Task 1.
- Produces: `IrohTransport::new(secret_key_bytes: [u8; 32], alpn: &'static [u8]) -> Result<IrohTransport, TransportError>` (blocking — internally owns a `tokio::runtime::Runtime` and calls `.block_on(...)`, so every other crate in this workspace stays synchronous; this is the *only* place `p2p-transport` exposes async machinery to its callers), `IrohTransport::node_id(&self) -> String`.

- [ ] **Step 1: Add dependencies**

```toml
# crates/p2p-transport/Cargo.toml — add to [dependencies]
iroh = { version = "1.0.3", default-features = false, features = ["metrics", "fast-apple-datapath", "tls-ring"] }
tokio = { version = "1", features = ["rt-multi-thread", "macros", "time"] }
anyhow = "1"
```

(`default-features = false` drops `portmapper`/UPnP, which this router's own `iptables`/`nft` setup already handles port exposure for — see this plan's "Important finding" section on iroh's dependency weight.)

- [ ] **Step 2: Write the failing real-connectivity test**

```rust
// crates/p2p-transport/src/iroh_transport.rs
use crate::envelope::Envelope;
use crate::transport::{PeerTransport, TransportError};
use iroh::endpoint::presets;
use iroh::{Endpoint, EndpointAddr, PublicKey, SecretKey};
use std::sync::mpsc::{Receiver, Sender};
use std::sync::Mutex;

pub struct IrohTransport {
    runtime: tokio::runtime::Runtime,
    endpoint: Endpoint,
    alpn: &'static [u8],
    inbox_tx: Sender<(String, Envelope)>,
    inbox_rx: Mutex<Receiver<(String, Envelope)>>,
}

impl IrohTransport {
    pub fn new(secret_key_bytes: [u8; 32], alpn: &'static [u8]) -> Result<Self, TransportError> {
        let runtime = tokio::runtime::Runtime::new().map_err(|e| TransportError::Other(e.to_string()))?;
        let secret_key = SecretKey::from_bytes(&secret_key_bytes);
        let endpoint = runtime
            .block_on(Endpoint::builder(presets::N0).secret_key(secret_key).alpns(vec![alpn.to_vec()]).bind())
            .map_err(|e| TransportError::Other(e.to_string()))?;
        let (inbox_tx, inbox_rx) = std::sync::mpsc::channel();
        let transport = IrohTransport { runtime, endpoint, alpn, inbox_tx, inbox_rx: Mutex::new(inbox_rx) };
        transport.spawn_accept_loop();
        Ok(transport)
    }

    pub fn node_id(&self) -> String {
        self.endpoint.id().to_string()
    }

    fn spawn_accept_loop(&self) {
        let endpoint = self.endpoint.clone();
        let tx = self.inbox_tx.clone();
        self.runtime.spawn(async move {
            loop {
                let Some(incoming) = endpoint.accept().await else { break };
                let tx = tx.clone();
                tokio::spawn(async move {
                    let Ok(conn) = incoming.await else { return };
                    // `Connection::remote_id() -> EndpointId` (not
                    // Option/Result — confirmed against the real crate
                    // source, `iroh-1.0.3/src/endpoint/connection.rs:1127`)
                    // and `EndpointId` is a type alias for `PublicKey`
                    // (`iroh-base-1.0.3/src/key.rs:70`), which implements
                    // `Display`.
                    let remote = conn.remote_id().to_string();
                    let Ok((mut send, mut recv)) = conn.accept_bi().await else { return };
                    let Ok(bytes) = recv.read_to_end(10 * 1024 * 1024).await else { return };
                    let Ok(envelope) = crate::envelope::Envelope::decode(&bytes) else { return };
                    let _ = tx.send((remote, envelope));
                    let _ = send.write_all(b"ok").await;
                    let _ = send.finish();
                });
            }
        });
    }
}

impl PeerTransport for IrohTransport {
    fn send(&self, to: &str, envelope: &Envelope) -> Result<(), TransportError> {
        let node_id: PublicKey = to.parse().map_err(|_| TransportError::Unreachable(to.to_string()))?;
        let addr = EndpointAddr::new(node_id);
        let bytes = envelope.encode();
        // `self.alpn` (stored at construction, Step 1's struct field) is
        // used directly here rather than reading it back off `Endpoint` —
        // `Endpoint` exposes no public `alpns()` getter in the real
        // crate, only `Builder::alpns(...)` as a setter, confirmed
        // against `iroh-1.0.3/src/endpoint.rs:535`.
        self.runtime.block_on(async {
            let conn = self.endpoint.connect(addr, self.alpn).await.map_err(|e| TransportError::Other(e.to_string()))?;
            let (mut send, mut recv) = conn.open_bi().await.map_err(|e| TransportError::Other(e.to_string()))?;
            send.write_all(&bytes).await.map_err(|e| TransportError::Other(e.to_string()))?;
            send.finish().map_err(|e| TransportError::Other(e.to_string()))?;
            let _ack = recv.read_to_end(1024).await;
            Ok(())
        })
    }

    fn recv(&self) -> Result<(String, Envelope), TransportError> {
        self.inbox_rx.lock().unwrap().recv().map_err(|_| TransportError::Closed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::StatementKind;

    const ALPN: &[u8] = b"social-firewall/1";

    /// **Environment-dependent — see this plan's "Important finding"
    /// section before assuming a failure here means the code is wrong.**
    /// Verified during planning to hang/timeout in at least one sandboxed
    /// dev environment despite matching iroh's own internal test pattern
    /// exactly (confirmed via a from-scratch `cargo add iroh` probe, not
    /// guessed). If this fails in your environment: (1) run with
    /// `RUST_LOG=debug` and look for `do_holepunching`/`net_report` lines
    /// to see how far it gets: candidate exchange succeeding but the
    /// connection still timing out is the same signature hit during
    /// planning; (2) try on two genuinely separate machines/VMs rather
    /// than one host, the same way `nft-enforcer`/`wg-tunnel`'s
    /// real-command-touching tests ultimately needed a QEMU VM instead of
    /// local execution; (3) if it's still unreliable, that's a real
    /// finding to report, not something to force past — `FakeTransport`
    /// (Task 1) is the primary test strategy for everything built on top
    /// of this trait, this one test is the whole point of isolating real
    /// Iroh behavior into its own task.
    #[test]
    #[ignore = "environment-dependent Iroh connectivity — run explicitly with `cargo test -p p2p-transport -- --ignored`, see doc comment"]
    fn two_iroh_transports_exchange_an_envelope() {
        let server = IrohTransport::new([7u8; 32], ALPN).unwrap();
        let client = IrohTransport::new([9u8; 32], ALPN).unwrap();
        let server_id = server.node_id();

        let envelope = Envelope { kind: StatementKind::TunnelConnectionRequest, payload: b"hello".to_vec() };
        client.send(&server_id, &envelope).unwrap();

        let (from, received) = server.recv().unwrap();
        assert_eq!(from, client.node_id());
        assert_eq!(received, envelope);
    }
}
```

- [ ] **Step 3: Run the ignored test explicitly and record the result**

Run: `RUST_LOG=debug cargo test -p p2p-transport --lib iroh_transport -- --ignored --nocapture 2>&1 | tail -100`

Expected: either it passes (great — real connectivity confirmed in this environment, keep the test `#[ignore]`d for routine `cargo test` runs since it needs a real network and is slower than the rest of the suite, but note in the task's own commit message that it was confirmed passing), or it times out (expected per this plan's "Important finding" section — do not spend more than one troubleshooting pass on it; record the outcome, keep the `#[ignore]` and its doc comment as-is, and move on to Task 3). Either outcome is an acceptable stopping point for this step — this task's deliverable is the real `IrohTransport` implementation compiling and matching the trait correctly, not a guaranteed-passing network test.

- [ ] **Step 4: Confirm the crate still builds and Task 1's tests still pass**

Run: `cargo build -p p2p-transport && cargo test -p p2p-transport --lib`
Expected: builds clean, the 5 non-ignored tests from Task 1 still pass.

- [ ] **Step 5: Commit**

```bash
git add crates/p2p-transport
git commit -m "p2p-transport: add IrohTransport, the real PeerTransport implementation"
```

---

### Task 3: state-store — Iroh keypair + `iroh_node_id` addressing

**Files:**
- Create: `crates/state-store/migrations/0020_iroh_addressing.sql`
- Modify: `crates/state-store/src/lib.rs` — migration registration, `set_iroh_keypair_seed`/`get_iroh_keypair_seed`, `upsert_follow`/`get_follow`/`list_follows`/`row_to_trust_rule` updated for `iroh_node_id`
- Modify: `crates/domain-types/src/trust.rs` — `LocalTrustRule.iroh_node_id: Option<String>`
- Test: inline in `crates/state-store/src/lib.rs`'s existing `mod tests`

**Interfaces:**
- Produces: `StateStore::set_iroh_keypair_seed(&self, seed: &[u8; 32]) -> Result<(), StoreError>`, `StateStore::get_iroh_keypair_seed(&self) -> Result<Option<[u8; 32]>, StoreError>` (exact mirror of `set_wg_keypair_seed`/`get_wg_keypair_seed` at `crates/state-store/src/lib.rs:699-716`). `LocalTrustRule.iroh_node_id: Option<String>` threaded through `upsert_follow`/`get_follow`/`list_follows`.

- [ ] **Step 1: Add the migration**

```sql
-- crates/state-store/migrations/0020_iroh_addressing.sql
-- This router's own Iroh keypair — a fourth, dedicated key alongside the
-- identity-signing (Ed25519), messaging (X25519), and WireGuard (X25519)
-- ones, following the exact same "generate on first use, persist the
-- seed" pattern as wg_secret_seed/messaging_secret_seed. Iroh's own
-- NodeId is itself an Ed25519 public key, so this is the fourth
-- application of an already-established principle here, not a new one.
ALTER TABLE users ADD COLUMN iroh_secret_seed BLOB;

-- A followed peer's Iroh node id (their public key, as returned by
-- IrohTransport::node_id — see p2p-transport), settable only via an
-- explicit operator action (`add-follow --iroh-node-id` /
-- `set-follow-node-id`), the same manually-confirmed, trust-on-first-use
-- pattern `display_name` already uses. Never learned or applied silently.
ALTER TABLE follows ADD COLUMN iroh_node_id TEXT;
```

- [ ] **Step 2: Register the migration**

In `crates/state-store/src/lib.rs`, find the `MIGRATIONS` constant (the line ending in `(19, include_str!("../migrations/0019_party_line_reply_target.sql")),`) and add directly after it:

```rust
    (20, include_str!("../migrations/0020_iroh_addressing.sql")),
```

- [ ] **Step 3: Write the failing test for the keypair methods**

Add to `crates/state-store/src/lib.rs`'s `mod tests`, near the existing `set_wg_keypair_seed_fails_loudly_with_no_self_identity_yet` test:

```rust
#[test]
fn iroh_keypair_seed_round_trips() {
    let store = StateStore::open_in_memory().unwrap();
    store.set_self_identity(user(1, 1), PublicKeyBytes([1; 32]), &[4; 32], None).unwrap();
    assert_eq!(store.get_iroh_keypair_seed().unwrap(), None);
    store.set_iroh_keypair_seed(&[8; 32]).unwrap();
    assert_eq!(store.get_iroh_keypair_seed().unwrap(), Some([8; 32]));
}

#[test]
fn set_iroh_keypair_seed_fails_loudly_with_no_self_identity_yet() {
    let store = StateStore::open_in_memory().unwrap();
    assert!(matches!(store.set_iroh_keypair_seed(&[8; 32]), Err(StoreError::NoSelfIdentity)));
}
```

- [ ] **Step 4: Run the tests to verify they fail**

Run: `cargo test -p state-store --lib -- iroh_keypair`
Expected: FAIL with "no method named `set_iroh_keypair_seed`" (or similar compile error) — the methods don't exist yet.

- [ ] **Step 5: Implement `set_iroh_keypair_seed`/`get_iroh_keypair_seed`**

In `crates/state-store/src/lib.rs`, immediately after `get_wg_keypair_seed` (ends around line 716), add:

```rust
    /// This router's own Iroh keypair seed — see
    /// `0020_iroh_addressing.sql`'s own doc on why this is a fourth,
    /// dedicated key rather than reusing an existing one.
    pub fn set_iroh_keypair_seed(&self, seed: &[u8; 32]) -> Result<(), StoreError> {
        let rows = self.conn.execute("UPDATE users SET iroh_secret_seed = ?1 WHERE is_self = 1", params![seed.as_slice()])?;
        if rows == 0 {
            return Err(StoreError::NoSelfIdentity);
        }
        Ok(())
    }

    pub fn get_iroh_keypair_seed(&self) -> Result<Option<[u8; 32]>, StoreError> {
        self.conn
            .query_row("SELECT iroh_secret_seed FROM users WHERE is_self = 1", [], |row| row.get::<_, Option<Vec<u8>>>(0))
            .optional()?
            .flatten()
            .map(|v| bytes_to_32(&v))
            .transpose()
    }
```

- [ ] **Step 6: Run the tests to verify they pass**

Run: `cargo test -p state-store --lib -- iroh_keypair`
Expected: 2 tests pass.

- [ ] **Step 7: Add `iroh_node_id` to `LocalTrustRule`**

In `crates/domain-types/src/trust.rs`, add a field to `LocalTrustRule` right after `display_name`:

```rust
    pub display_name: Option<String>,
    /// This peer's Iroh node id (see `p2p-transport::IrohTransport::node_id`),
    /// if known — set only via an explicit operator action, same
    /// trust-on-first-use posture as `display_name`. `None` means
    /// automated delivery to this peer isn't possible yet; the existing
    /// manual export/ingest path is unaffected either way.
    pub iroh_node_id: Option<String>,
    pub expires_at: Option<Timestamp>,
```

- [ ] **Step 8: Fix every `LocalTrustRule` construction site to compile**

Run: `cargo build --workspace --all-targets 2>&1 | grep "missing field \`iroh_node_id\`" -A 2`

For each reported site, add `iroh_node_id: None,` immediately after the existing `display_name: ...,` line (the same mechanical fix already done for `min_reciprocity_ratio` and `in_reply_to` earlier in this project — expect roughly 4-6 sites across `domain-types/src/trust.rs`'s own tests and `state-store/src/lib.rs`'s tests).

- [ ] **Step 9: Update `upsert_follow`, `get_follow`, `list_follows`, `row_to_trust_rule`**

In `crates/state-store/src/lib.rs`, `upsert_follow` (starts around line 234):

```rust
    pub fn upsert_follow(&self, rule: &LocalTrustRule) -> Result<(), StoreError> {
        self.conn.execute(
            "INSERT INTO follows (federation_id, local_id, allow_weight, deny_weight, advisory_only, excluded, category_filter, display_name, iroh_node_id, expires_at, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
             ON CONFLICT(federation_id, local_id) DO UPDATE SET
                allow_weight = excluded.allow_weight,
                deny_weight = excluded.deny_weight,
                advisory_only = excluded.advisory_only,
                excluded = excluded.excluded,
                category_filter = excluded.category_filter,
                display_name = excluded.display_name,
                iroh_node_id = excluded.iroh_node_id,
                expires_at = excluded.expires_at",
            params![
                rule.user.federation.0 .0.as_slice(),
                rule.user.local_id.0.as_slice(),
                rule.allow_weight,
                rule.deny_weight,
                rule.advisory_only,
                rule.excluded,
                rule.category_filter,
                rule.display_name,
                rule.iroh_node_id,
                rule.expires_at,
                rule.created_at,
            ],
        )?;
        Ok(())
    }
```

`get_follow` (around line 259) — add `iroh_node_id` to the `SELECT` column list, right after `display_name`:

```rust
    pub fn get_follow(&self, user: &UserId) -> Result<Option<LocalTrustRule>, StoreError> {
        self.conn
            .query_row(
                "SELECT allow_weight, deny_weight, advisory_only, excluded, category_filter, display_name, iroh_node_id, expires_at, created_at
                 FROM follows WHERE federation_id = ?1 AND local_id = ?2",
                params![user.federation.0 .0.as_slice(), user.local_id.0.as_slice()],
                |row| row_to_trust_rule(row, *user),
            )
            .optional()
            .map_err(Into::into)
    }
```

`list_follows` (around line 286) — same column addition:

```rust
    pub fn list_follows(&self) -> Result<Vec<LocalTrustRule>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT federation_id, local_id, allow_weight, deny_weight, advisory_only, excluded, category_filter, display_name, iroh_node_id, expires_at, created_at FROM follows",
        )?;
```

(the rest of `list_follows`'s body already calls `row_to_trust_rule`-equivalent inline construction — check it against `row_to_trust_rule`'s own field order below and keep both consistent.)

`row_to_trust_rule` (around line 3132) — add the new column in the same position:

```rust
fn row_to_trust_rule(row: &rusqlite::Row, user: UserId) -> rusqlite::Result<LocalTrustRule> {
    Ok(LocalTrustRule {
        user,
        allow_weight: row.get(0)?,
        deny_weight: row.get(1)?,
        advisory_only: row.get(2)?,
        excluded: row.get(3)?,
        category_filter: row.get(4)?,
        display_name: row.get(5)?,
        iroh_node_id: row.get(6)?,
        expires_at: row.get(7)?,
        created_at: row.get(8)?,
    })
}
```

- [ ] **Step 10: Write the failing round-trip test**

```rust
#[test]
fn follow_iroh_node_id_round_trips() {
    let store = StateStore::open_in_memory().unwrap();
    let alice = user(1, 1);
    let mut rule = follow(alice, 1.0, 1.0);
    rule.iroh_node_id = Some("deadbeef".repeat(8));
    store.upsert_follow(&rule).unwrap();
    assert_eq!(store.get_follow(&alice).unwrap().unwrap().iroh_node_id.as_deref(), Some(rule.iroh_node_id.unwrap().as_str()));
}
```

- [ ] **Step 11: Run all state-store and domain-types tests**

Run: `cargo test -p domain-types -p state-store --lib`
Expected: all pass, including the new `follow_iroh_node_id_round_trips` and the two `iroh_keypair_seed` tests from Step 6.

- [ ] **Step 12: Commit**

```bash
git add crates/state-store crates/domain-types
git commit -m "state-store: Iroh keypair storage and follow-scoped node_id addressing"
```

---

### Task 4: CLI — `add-follow --iroh-node-id`, `set-follow-node-id`

**Files:**
- Modify: `crates/cli/src/main.rs`

**Interfaces:**
- Consumes: `LocalTrustRule.iroh_node_id` from Task 3.
- Produces: CLI flags/commands only — no new library-level function signatures other crates depend on.

- [ ] **Step 1: Add `--iroh-node-id` to `add_follow`**

Find `fn add_follow` (around line 958) and its `AddFollow` clap variant. Add a new parameter and field mirroring how `name: Option<String>` already flows through both:

```rust
fn add_follow(
    store: &StateStore,
    federation: &str,
    user: &str,
    allow_weight: f64,
    deny_weight: f64,
    advisory: bool,
    exclude: bool,
    name: Option<String>,
    iroh_node_id: Option<String>,
) -> Result<()> {
    let federation = FederationId(parse_hash32(federation)?);
    let local_id = parse_hash32(user)?;
    let rule = LocalTrustRule {
        user: UserId { federation, local_id },
        allow_weight,
        deny_weight,
        advisory_only: advisory,
        excluded: exclude,
        category_filter: None,
        display_name: name,
        iroh_node_id,
        expires_at: None,
        created_at: now_unix(),
    };
    store.upsert_follow(&rule)?;
    println!("now following {}/{}", federation.0, local_id);
    Ok(())
}
```

In the `AddFollow` clap struct variant (find it near the `Command` enum definitions), add:

```rust
        /// This peer's Iroh node id, if known — enables automated
        /// delivery for statement types that have a known recipient (see
        /// docs/superpowers/specs/2026-08-04-p2p-transport-design.md).
        /// Omit if unknown; the existing manual export/ingest path is
        /// unaffected either way.
        #[arg(long)]
        iroh_node_id: Option<String>,
```

Update the matching `Command::AddFollow { ... }` dispatch arm in `main()` to destructure and pass the new field through.

- [ ] **Step 2: Add `set-follow-node-id`, mirroring `set_follow_name` exactly**

Find `fn set_follow_name` (around line 991) and add immediately after it:

```rust
fn set_follow_node_id(store: &StateStore, federation: &str, user: &str, node_id: Option<String>) -> Result<()> {
    let target_user = UserId { federation: FederationId(parse_hash32(federation)?), local_id: parse_hash32(user)? };
    let mut rule = store.get_follow(&target_user)?.context("not following this user yet — run `add-follow` first")?;
    rule.iroh_node_id = node_id.clone();
    store.upsert_follow(&rule)?;
    match node_id {
        Some(id) => println!("{}/{} is now reachable via Iroh node {id}", target_user.federation.0, target_user.local_id),
        None => println!("Iroh node id cleared for {}/{}", target_user.federation.0, target_user.local_id),
    }
    Ok(())
}
```

Add a matching `SetFollowNodeId { federation: String, user: String, node_id: Option<String> }` variant to the `Command` enum (right after `SetFollowName`, following its exact shape) and a dispatch arm in `main()`.

- [ ] **Step 3: Build and manually verify**

Run:
```bash
cargo build -p sf-cli
target/debug/sf --db /tmp/plan_verify.sqlite init-identity --display-name test
target/debug/sf --db /tmp/plan_verify.sqlite add-follow --federation "$(printf 'ab%.0s' {1..32})" --user "$(printf 'cd%.0s' {1..32})" --allow-weight 1.0 --deny-weight 1.0 --iroh-node-id "some-node-id"
target/debug/sf --db /tmp/plan_verify.sqlite set-follow-node-id --federation "$(printf 'ab%.0s' {1..32})" --user "$(printf 'cd%.0s' {1..32})" --node-id "updated-node-id"
rm -f /tmp/plan_verify.sqlite
```
Expected: both commands succeed and print confirmation lines; no crash.

- [ ] **Step 4: Commit**

```bash
git add crates/cli/src/main.rs
git commit -m "cli: add-follow --iroh-node-id and set-follow-node-id"
```

---

### Task 5: bytes-based ingest core + `sf listen`

**Files:**
- Modify: `crates/cli/src/tunnel.rs` — refactor `read_maybe_sealed`/`ingest_tunnel_request`/`ingest_tunnel_accept` to share a bytes-based core; add `dispatch_envelope`
- Modify: `crates/cli/src/main.rs` — new `Listen` command
- Modify: `crates/cli/Cargo.toml` — add `p2p-transport` path dependency

**Interfaces:**
- Consumes: `p2p_transport::{PeerTransport, IrohTransport, Envelope, StatementKind}` (Tasks 1-2), `StateStore::get_iroh_keypair_seed`/`set_iroh_keypair_seed` (Task 3).
- Produces: `pub(crate) fn parse_maybe_sealed_bytes(store: &StateStore, bytes: &[u8]) -> Result<serde_json::Value>`, `pub(crate) fn ingest_tunnel_request_bytes(store: &StateStore, bytes: &[u8]) -> Result<()>`, `pub(crate) fn ingest_tunnel_accept_bytes(store: &StateStore, bytes: &[u8]) -> Result<()>`, `pub fn dispatch_envelope(store: &StateStore, kind: p2p_transport::StatementKind, payload: &[u8]) -> Result<()>`.

- [ ] **Step 1: Refactor `read_maybe_sealed` into a bytes-based core**

In `crates/cli/src/tunnel.rs`, replace the existing `read_maybe_sealed` (around line 73) with:

```rust
pub(crate) fn parse_maybe_sealed_bytes(store: &StateStore, bytes: &[u8]) -> Result<serde_json::Value> {
    let json: serde_json::Value = serde_json::from_slice(bytes)?;
    if json.get("sealed").and_then(|v| v.as_bool()) == Some(true) {
        let ciphertext_hex = json.get("ciphertext_hex").and_then(|v| v.as_str()).context("missing `ciphertext_hex`")?;
        let ciphertext = hex::decode(ciphertext_hex)?;
        let kp = own_messaging_keypair(store)?;
        let plaintext = kp.unseal(&ciphertext).map_err(|_| anyhow::anyhow!("unsealing failed — not addressed to this router, or the file was tampered with"))?;
        Ok(serde_json::from_slice(&plaintext)?)
    } else {
        Ok(json)
    }
}

/// Reads `path`, unsealing first if it's a sealed envelope (using this
/// router's own messaging keypair — generated on first use, same as
/// elsewhere). Thin wrapper around `parse_maybe_sealed_bytes` — the file
/// I/O is the only thing this layer adds, so `sf listen` (which receives
/// bytes directly over the network, never a file) can share the same
/// parsing/unsealing core.
pub(crate) fn read_maybe_sealed(store: &StateStore, path: &Path) -> Result<serde_json::Value> {
    let bytes = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    parse_maybe_sealed_bytes(store, &bytes)
}
```

- [ ] **Step 2: Run the existing test suite to confirm the refactor didn't break anything**

Run: `cargo test -p sf-cli --bin sf`
Expected: all existing tests still pass (this refactor is behavior-preserving — `read_maybe_sealed`'s public signature and behavior are unchanged, only its internals moved).

- [ ] **Step 3: Refactor `ingest_tunnel_request` and `ingest_tunnel_accept` into bytes-based cores**

Replace `ingest_tunnel_request` (around line 536) — extract the body into a bytes-based function, keep the file-based one as a thin wrapper:

```rust
pub(crate) fn ingest_tunnel_request_bytes(store: &StateStore, bytes: &[u8]) -> Result<()> {
    let json = parse_maybe_sealed_bytes(store, bytes)?;
    let get_str = |key: &str| -> Result<&str> { json.get(key).and_then(|v| v.as_str()).with_context(|| format!("missing `{key}`")) };
    let requester = parse_user_ref(get_str("requester")?)?;
    let identity_pubkey = PublicKeyBytes(bytes32(get_str("identity_pubkey")?)?);
    let req = TunnelConnectionRequest {
        requester,
        sequence: json.get("sequence").and_then(|v| v.as_u64()).context("missing `sequence`")?,
        advertisement: parse_statement_ref(get_str("advertisement")?)?,
        requester_wg_pubkey: WgPublicKeyBytes(bytes32(get_str("requester_wg_pubkey")?)?),
        requester_messaging_pubkey: MessagingPublicKeyBytes(bytes32(get_str("requester_messaging_pubkey")?)?),
        requested_at: json.get("requested_at").and_then(|v| v.as_i64()).context("missing `requested_at`")?,
        signature: domain_types::SignatureBytes(bytes64(get_str("signature")?)?),
    };
    crypto::verify(&identity_pubkey, crypto::contexts::TUNNEL_CONNECTION_REQUEST, &req.signing_bytes(), &req.signature)
        .map_err(|_| anyhow::anyhow!("signature verification failed — refusing to ingest"))?;
    store.store_tunnel_connection_request(&req)?;
    println!("ingested tunnel connection request #{} from {} (pending review)", req.sequence, user_id_str(&req.requester));
    Ok(())
}

pub fn ingest_tunnel_request(store: &StateStore, file: &Path) -> Result<()> {
    let bytes = std::fs::read(file).with_context(|| format!("reading {}", file.display()))?;
    ingest_tunnel_request_bytes(store, &bytes)
}
```

Do the exact same split for `ingest_tunnel_accept` (around line 682): extract to `ingest_tunnel_accept_bytes(store: &StateStore, bytes: &[u8]) -> Result<()>`, keep `ingest_tunnel_accept(store, file)` as a two-line wrapper reading the file and delegating.

- [ ] **Step 4: Run the tests to confirm both refactors are behavior-preserving**

Run: `cargo test -p sf-cli --bin sf && cargo test -p sf-cli --test cli`
Expected: all tests still pass, including `full_tunnel_handshake_flow_reaches_a_selected_route` (the existing test that exercises `ingest_tunnel_request`/`ingest_tunnel_accept` via the CLI) — this proves the refactor changed nothing observable.

- [ ] **Step 5: Write `dispatch_envelope`**

Add to `crates/cli/src/tunnel.rs`:

```rust
/// The receive-side counterpart to Task 6's send-side wiring: dispatches
/// a decoded envelope's payload to the exact same `ingest_*_bytes`
/// function the file-based CLI path calls, so every signature check and
/// follow-gate runs completely unchanged regardless of how the bytes
/// arrived. A malformed or rejected payload returns `Err` — `sf listen`
/// (Step 7) logs and continues rather than propagating a failure that
/// would kill the whole listener.
pub fn dispatch_envelope(store: &StateStore, kind: p2p_transport::StatementKind, payload: &[u8]) -> Result<()> {
    match kind {
        p2p_transport::StatementKind::TunnelConnectionRequest => ingest_tunnel_request_bytes(store, payload),
        p2p_transport::StatementKind::TunnelConnectionAccept => ingest_tunnel_accept_bytes(store, payload),
    }
}
```

Add `p2p-transport = { path = "../p2p-transport" }` to `crates/cli/Cargo.toml`'s `[dependencies]`.

- [ ] **Step 6: Write the failing test for `dispatch_envelope`**

Add near `ingest_tunnel_request`'s existing tests in `crates/cli/src/tunnel.rs`'s test module:

```rust
#[test]
fn dispatch_envelope_routes_a_tunnel_connection_request_to_the_same_ingest_path() {
    let (store, self_user) = store_with_self_identity();
    let (_ad, _pubkey) = build_and_store_own_advertisement(&store, "self's own ad", None, vec![TargetSelector::Domain("example.com".into())], Vec::new(), None, None, Visibility::Public, None).unwrap();
    let bob = user(2);
    let req = TunnelConnectionRequest {
        requester: bob,
        sequence: 0,
        advertisement: StatementRef { author: self_user, sequence: 0 },
        requester_wg_pubkey: WgPublicKeyBytes([3; 32]),
        requester_messaging_pubkey: MessagingPublicKeyBytes([4; 32]),
        requested_at: 0,
        signature: domain_types::SignatureBytes([0; 64]),
    };
    // A real signature is required — dispatch_envelope must reject an
    // unsigned/garbage payload the same way ingest_tunnel_request does.
    let bob_kp = crypto::Keypair::generate();
    let mut signed_req = req.clone();
    signed_req.signature = bob_kp.sign(crypto::contexts::TUNNEL_CONNECTION_REQUEST, &req.signing_bytes());
    let json = connection_request_to_json(&signed_req, &bob_kp.public_key());
    let bytes = serde_json::to_vec(&json).unwrap();

    dispatch_envelope(&store, p2p_transport::StatementKind::TunnelConnectionRequest, &bytes).unwrap();

    assert_eq!(store.list_pending_tunnel_connection_requests().unwrap().len(), 1, "the request must have been stored via the normal ingest path");
}

#[test]
fn dispatch_envelope_rejects_a_tampered_payload_without_panicking() {
    let (store, _self_user) = store_with_self_identity();
    let result = dispatch_envelope(&store, p2p_transport::StatementKind::TunnelConnectionRequest, b"not even json");
    assert!(result.is_err());
}
```

- [ ] **Step 7: Run the tests to verify they pass**

Run: `cargo test -p sf-cli --bin sf -- dispatch_envelope`
Expected: 2 tests pass.

- [ ] **Step 8: Add `sf listen`**

Add to `crates/cli/src/tunnel.rs`:

```rust
/// The first genuinely persistent process in this codebase — accepts
/// inbound Iroh connections and dispatches each received envelope via
/// `dispatch_envelope`. A malformed envelope, a decode failure, or an
/// `ingest_*` rejection is logged and the loop continues; nothing here
/// can crash the listener or affect another connection (see the design
/// spec's Error handling section).
pub fn listen(store: &StateStore) -> Result<()> {
    let seed = match store.get_iroh_keypair_seed()? {
        Some(seed) => seed,
        None => {
            let seed: [u8; 32] = {
                use rand::RngCore;
                let mut s = [0u8; 32];
                rand::rngs::OsRng.fill_bytes(&mut s);
                s
            };
            store.set_iroh_keypair_seed(&seed)?;
            seed
        }
    };
    let transport = p2p_transport::IrohTransport::new(seed, b"social-firewall/1").map_err(|e| anyhow::anyhow!("failed to start Iroh transport: {e}"))?;
    println!("listening — this node's Iroh id: {}", transport.node_id());
    loop {
        match transport.recv() {
            Ok((from, envelope)) => match dispatch_envelope(store, envelope.kind, &envelope.payload) {
                Ok(()) => println!("dispatched {:?} from {from}", envelope.kind),
                Err(e) => eprintln!("rejected envelope from {from}: {e}"),
            },
            Err(e) => {
                eprintln!("transport closed: {e}");
                return Ok(());
            }
        }
    }
}
```

Check `crates/cli/Cargo.toml` for an existing `rand` dependency (`wg-tunnel`'s own keypair generation likely already pulls one in via `crypto_box`'s `OsRng` re-export — if `rand` isn't already a direct dependency here, add `rand = "0.8"`).

Add a `Listen` variant to the `Command` enum in `main.rs` (no arguments needed — it always uses this router's own identity) and a dispatch arm: `Command::Listen => tunnel::listen(&store)?,`.

- [ ] **Step 9: Manually verify the command starts and prints a node id**

Run:
```bash
cargo build -p sf-cli
target/debug/sf --db /tmp/plan_verify2.sqlite init-identity --display-name test
timeout 3 target/debug/sf --db /tmp/plan_verify2.sqlite listen || true
rm -f /tmp/plan_verify2.sqlite
```
Expected: prints `listening — this node's Iroh id: <hex>` before the 3-second timeout kills it (confirms `IrohTransport::new` and the accept-loop spawn both succeed — this does not require a peer to actually connect, just that binding works).

- [ ] **Step 10: Commit**

```bash
git add crates/cli
git commit -m "cli: bytes-based ingest core, dispatch_envelope, sf listen"
```

---

### Task 6: Wire the send side — tunnel request/accept delivery with fallback

**Files:**
- Modify: `crates/cli/src/tunnel.rs` — `request_tunnel`, `do_accept_tunnel_request`'s callers (`accept_tunnel_request`, `sync_tunnels`'s auto-accept loop)
- Test: `crates/cli/tests/cli.rs`

**Interfaces:**
- Consumes: `dispatch_envelope`, `p2p_transport::{IrohTransport, PeerTransport, Envelope, StatementKind}` from Task 5, `LocalTrustRule.iroh_node_id` from Task 3.
- Produces: `pub(crate) fn try_deliver(store: &StateStore, recipient: &UserId, kind: p2p_transport::StatementKind, payload: &[u8]) -> DeliveryOutcome` — a shared helper both `request_tunnel` and the accept path call.

- [ ] **Step 1: Write `try_deliver`, the shared send-with-fallback helper**

Add to `crates/cli/src/tunnel.rs`:

```rust
pub(crate) enum DeliveryOutcome {
    Delivered,
    NoKnownAddress,
    Failed(String),
}

/// Attempts real delivery via Iroh if `recipient`'s `iroh_node_id` is
/// known; the caller is responsible for writing the fallback file in
/// every case except `Delivered` — this function never writes to disk
/// itself, keeping "how to fall back" a caller decision (each call site
/// already has its own `--out`/`--out-dir` convention to preserve).
/// One Iroh keypair/endpoint is generated per call — acceptable for this
/// phase's request/accept cadence (a handful of sends per reconciliation
/// run, not a hot path); reusing a single long-lived endpoint across
/// sends is a reasonable future optimization once this is proven, not
/// built now.
pub(crate) fn try_deliver(store: &StateStore, recipient: &UserId, kind: p2p_transport::StatementKind, payload: &[u8]) -> DeliveryOutcome {
    let Ok(Some(rule)) = store.get_follow(recipient) else { return DeliveryOutcome::NoKnownAddress };
    let Some(node_id) = rule.iroh_node_id else { return DeliveryOutcome::NoKnownAddress };
    let seed = match store.get_iroh_keypair_seed() {
        Ok(Some(seed)) => seed,
        _ => return DeliveryOutcome::Failed("no local Iroh keypair yet — run `sf listen` once to generate one".to_string()),
    };
    let transport = match p2p_transport::IrohTransport::new(seed, b"social-firewall/1") {
        Ok(t) => t,
        Err(e) => return DeliveryOutcome::Failed(e.to_string()),
    };
    let envelope = p2p_transport::Envelope { kind, payload: payload.to_vec() };
    match transport.send(&node_id, &envelope) {
        Ok(()) => DeliveryOutcome::Delivered,
        Err(e) => DeliveryOutcome::Failed(e.to_string()),
    }
}
```

- [ ] **Step 2: Wire delivery into `request_tunnel`**

Modify `request_tunnel` (around line 518) — after building `plaintext`, attempt delivery before falling back to the file:

```rust
pub fn request_tunnel(store: &StateStore, advertisement: &str, out: Option<PathBuf>) -> Result<()> {
    let advertisement_ref = parse_statement_ref(advertisement)?;
    let ad = store
        .get_tunnel_advertisement(advertisement_ref.author, advertisement_ref.sequence)?
        .context("unknown advertisement — ingest it first")?;

    let (req, identity_pubkey) = build_and_store_connection_request(store, advertisement_ref)?;
    println!("requested tunnel #{} against {}/{}", req.sequence, user_id_str(&ad.provider), ad.sequence);

    let plaintext = serde_json::to_vec(&connection_request_to_json(&req, &identity_pubkey))?;
    match try_deliver(store, &ad.provider, p2p_transport::StatementKind::TunnelConnectionRequest, &plaintext) {
        DeliveryOutcome::Delivered => {
            println!("delivered to {}'s node", user_id_str(&ad.provider));
        }
        DeliveryOutcome::NoKnownAddress | DeliveryOutcome::Failed(_) => {
            if let Some(path) = &out {
                write_maybe_sealed(&plaintext, Some(&ad.messaging_pubkey), path)?;
                println!("{}'s node_id not known or unreachable — exported to {} for manual delivery", user_id_str(&ad.provider), path.display());
            }
        }
    }
    Ok(())
}
```

- [ ] **Step 3: Wire the manual `accept_tunnel_request` command**

In `crates/cli/src/tunnel.rs`, `accept_tunnel_request` (starts at line 656) currently ends with:

```rust
    if let Some(path) = out {
        // Always sealed — a connection accept is inherently pairwise.
        write_maybe_sealed(&serde_json::to_vec(&accept_to_json(&accept, &identity_pubkey))?, Some(&req.requester_messaging_pubkey), &path)?;
        println!("exported (sealed to requester) to {}", path.display());
    }
    Ok(())
}
```

Replace that block with:

```rust
    let plaintext = serde_json::to_vec(&accept_to_json(&accept, &identity_pubkey))?;
    match try_deliver(store, &requester_user, p2p_transport::StatementKind::TunnelConnectionAccept, &plaintext) {
        DeliveryOutcome::Delivered => {
            println!("delivered to {}'s node", user_id_str(&requester_user));
        }
        DeliveryOutcome::NoKnownAddress | DeliveryOutcome::Failed(_) => {
            if let Some(path) = out {
                // Always sealed — a connection accept is inherently pairwise.
                write_maybe_sealed(&plaintext, Some(&req.requester_messaging_pubkey), &path)?;
                println!("{}'s node_id not known or unreachable — exported (sealed to requester) to {}", user_id_str(&requester_user), path.display());
            }
        }
    }
    Ok(())
}
```

- [ ] **Step 4: Wire `sync_tunnels`'s auto-accept loop**

The auto-accept loop (around line 902-912) currently reads:

```rust
        if dry_run {
            println!("(dry-run) would auto-accept connection request #{} from {}", req.sequence, user_id_str(&req.requester));
            report.auto_accepts += 1;
            continue;
        }
        let (accept, identity_pubkey) = do_accept_tunnel_request(store, provider, &seed, &req)?;
        let path = out_dir.join(format!("tunnel-accept-{}-{}.json", user_id_str(&req.requester).replace('/', "_"), req.sequence));
        write_maybe_sealed(&serde_json::to_vec(&accept_to_json(&accept, &identity_pubkey))?, Some(&req.requester_messaging_pubkey), &path)?;
        println!("auto-accepted connection request #{} from {}: exported to {}", req.sequence, user_id_str(&req.requester), path.display());
        report.auto_accepts += 1;
```

Replace the last four lines (from `let (accept, ...)` through `report.auto_accepts += 1;`) with:

```rust
        let (accept, identity_pubkey) = do_accept_tunnel_request(store, provider, &seed, &req)?;
        let plaintext = serde_json::to_vec(&accept_to_json(&accept, &identity_pubkey))?;
        match try_deliver(store, &req.requester, p2p_transport::StatementKind::TunnelConnectionAccept, &plaintext) {
            DeliveryOutcome::Delivered => {
                println!("auto-accepted connection request #{} from {}: delivered to their node", req.sequence, user_id_str(&req.requester));
            }
            DeliveryOutcome::NoKnownAddress | DeliveryOutcome::Failed(_) => {
                let path = out_dir.join(format!("tunnel-accept-{}-{}.json", user_id_str(&req.requester).replace('/', "_"), req.sequence));
                write_maybe_sealed(&plaintext, Some(&req.requester_messaging_pubkey), &path)?;
                println!("auto-accepted connection request #{} from {}: node_id not known or unreachable — exported to {}", req.sequence, user_id_str(&req.requester), path.display());
            }
        }
        report.auto_accepts += 1;
```

- [ ] **Step 5: Run the full existing tunnel test suite**

Run: `cargo test -p sf-cli --bin sf -- tunnel && cargo test -p sf-cli --test cli`
Expected: all existing tests pass unchanged — every existing test has no `iroh_node_id` set on any follow, so every call hits `DeliveryOutcome::NoKnownAddress` and falls straight through to the exact file-export behavior already tested. This is the key regression check: delivery is additive, and this step proves it.

- [ ] **Step 6: Write the fallback-path regression test**

A real end-to-end test using two live `IrohTransport`s is out of scope for a CLI integration test — Task 2 found real connectivity isn't guaranteed in every environment, so a test that depends on it succeeding would be flaky by construction. This test instead proves the half that's fully deterministic: with no `iroh_node_id` configured, delivery must fall back to the file exactly as before.

Add to `crates/cli/tests/cli.rs`, near the existing tunnel-handshake tests. `offer-tunnel` takes repeatable `--target <kind>:<value>` (confirmed against `crates/cli/src/main.rs`'s current `OfferTunnel` clap variant, e.g. `--target domain:example.com`), not separate `--target-kind`/`--target-value` flags:

```rust
#[test]
fn request_tunnel_falls_back_to_file_export_when_no_iroh_node_id_is_known() {
    let alice_dir = tempfile::tempdir().unwrap();
    let bob_dir = tempfile::tempdir().unwrap();
    let alice = init_identity(alice_dir.path(), "alice.sqlite", "alice");
    init_identity(bob_dir.path(), "bob.sqlite", "bob");

    let ad_path = alice_dir.path().join("ad.json");
    let offer = sf(alice_dir.path(), "alice.sqlite", &["offer-tunnel", "--description", "d", "--target", "domain:example.com", "--visibility", "public", "--out", ad_path.to_str().unwrap()]);
    assert!(offer.status.success(), "offer-tunnel failed: {}", stderr(&offer));

    let bob_ad = bob_dir.path().join("ad.json");
    std::fs::copy(&ad_path, &bob_ad).unwrap();
    assert!(sf(bob_dir.path(), "bob.sqlite", &["ingest-tunnel-advertisement", "--file", bob_ad.to_str().unwrap()]).status.success());

    // No `set-follow-node-id` was ever run — bob has no known Iroh
    // address for alice, so delivery must fall back to the file.
    assert!(sf(bob_dir.path(), "bob.sqlite", &["add-follow", "--federation", &alice.federation, "--user", &alice.local_id, "--allow-weight", "1.0", "--deny-weight", "1.0"]).status.success());
    let out_path = bob_dir.path().join("request.json");
    let request = sf(bob_dir.path(), "bob.sqlite", &["request-tunnel", "--advertisement", &format!("{}/{}/0", alice.federation, alice.local_id), "--out", out_path.to_str().unwrap()]);
    assert!(request.status.success(), "request-tunnel failed: {}", stderr(&request));
    assert!(stdout(&request).contains("not known or unreachable") || stdout(&request).contains("exported"), "expected a fallback-to-file message, got:\n{}", stdout(&request));
    assert!(out_path.exists(), "the fallback file export must still happen when no Iroh address is known");
}
```

- [ ] **Step 7: Run the new test**

Run: `cargo test -p sf-cli --test cli request_tunnel_falls_back`
Expected: 1 test passes.

- [ ] **Step 8: Commit**

```bash
git add crates/cli
git commit -m "cli: attempt Iroh delivery for tunnel request/accept, fall back to file export"
```

---

### Task 7: Full verification and scope handoff

**Files:** none (verification only)

- [ ] **Step 1: Full workspace build and test**

Run: `cargo build --workspace --all-targets && timeout 300 cargo test --workspace`
Expected: builds clean, every test passes (the Task 2 real-Iroh test stays `#[ignore]`d and doesn't run in this pass — that's intentional, see its own doc comment).

- [ ] **Step 2: Clippy**

Run: `cargo clippy --workspace --all-targets 2>&1 | grep warning`
Expected: only the pre-existing warnings already known from this project's session history (doc-list indentation in `domain-types`, `type_complexity`/`manual_is_multiple_of` in `state-store`, `manual_div_ceil` in `wg-tunnel`, three `too_many_arguments` warnings in `cli`) — confirm no *new* warnings were introduced by this plan's changes.

- [ ] **Step 3: Manual end-to-end smoke test of the full flow (fallback path, since real two-node Iroh delivery isn't guaranteed in every environment per Task 2's finding)**

Run the same alice/bob flow as Task 6's new test, manually, confirming `request-tunnel` and the accept path both still work exactly as before when no `iroh_node_id` is configured (already covered by Task 6's automated test — this step is a final human sanity pass, not new coverage).

- [ ] **Step 4: Update the project plan file with what shipped and what's next**

Add a new numbered item to `/home/traph/.claude/plans/floofy-skipping-cerf.md`'s "Future work" list (following the exact style of items 13-15 already there), covering: what got built (the crate, the keypair, addressing, `sf listen`, request/accept delivery-with-fallback), the real finding about same-host Iroh connectivity being unreliable and why `FakeTransport` is this crate's primary test strategy, and the explicit remaining scope — group join requests, group publishes, party-line messages, and restricted exports all need the identical `try_deliver`-then-fallback pattern applied at their own call sites, mechanically, once this first flow has been used for real and proven out.

- [ ] **Step 5: Final commit**

```bash
git add -A -- ':!target'
git status
git commit -m "p2p-transport: verification pass and plan-file update"
```

(Review `git status` output before committing — confirm nothing unexpected is staged.)

---

## Self-Review Notes

- **Spec coverage**: Architecture (crate, keypair, addressing) — Tasks 1-4. Scope split (addressed vs. broadcast) — honored via Global Constraints, only the proven flow is wired. Data flow (send-with-fallback, receive-and-dispatch) — Tasks 5-6. Wire shape (envelope, ALPN) — Task 1, `b"social-firewall/1"` used consistently in Tasks 5-6. Error handling (unreachable falls back, malformed envelope logged not crashed) — Task 5 Step 8 (`listen`'s loop), Task 6 (`try_deliver`'s three outcomes). Testing (FakeTransport-driven unit tests, one real two-endpoint test, CLI regression) — Tasks 1, 2, 6. Future work (broadcast delivery, retry, discovery) — left exactly as the spec's own Future work section states, not touched by this plan.
- **Deviation from spec, called out explicitly**: the spec's Testing section asked for "a real two-`IrohTransport` integration test... feasible without root or a VM." Hands-on verification during planning found this to not reliably hold in at least one real environment; Task 2 keeps the test but marks it `#[ignore]` with a full explanation rather than silently deleting it or pretending it's guaranteed to pass.
- **Type consistency**: `StatementKind` (Task 1) is used identically in `dispatch_envelope` (Task 5) and `try_deliver` (Task 6). `DeliveryOutcome`'s three variants are handled exhaustively at both Task 6 call sites (Step 2's shown code, Step 3's described-but-not-shown code — flagged there as "apply the exact same pattern" rather than a placeholder, since the two call sites' surrounding code differs only in which existing export convention it preserves).
