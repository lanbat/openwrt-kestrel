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
