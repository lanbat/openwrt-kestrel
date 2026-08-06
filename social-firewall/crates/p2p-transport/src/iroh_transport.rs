use crate::envelope::Envelope;
use crate::transport::{Dispatch, PeerTransport, TransportError};
use iroh::endpoint::presets;
use iroh::{Endpoint, EndpointAddr, PublicKey, SecretKey};
use std::sync::mpsc::{Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::Semaphore;

/// Hard ceiling on one inbound envelope. Every statement kind this phase
/// carries is a small signed JSON document — a real tunnel connection
/// request/accept is under 2 KiB — so 64 KiB is already a generous
/// ceiling with room for growth, while keeping the memory an unknown
/// remote peer can make this process allocate bounded and small. This is
/// the first code in this codebase that reads untrusted, network-
/// reachable input, so the cap is deliberately tight rather than
/// "whatever seems big enough".
const MAX_ENVELOPE_BYTES: usize = 64 * 1024;

/// Applied separately to each stage of an inbound connection (handshake,
/// opening the stream, sending the envelope). Without it, a peer that
/// connects and then goes silent pins a spawned task — and one of the
/// concurrency permits below — forever.
const ACCEPT_STAGE_TIMEOUT: Duration = Duration::from_secs(30);

/// Cap on in-flight inbound connections. The accept loop acquires a
/// permit *before* taking the next connection, so exceeding this applies
/// backpressure at the endpoint rather than spawning unbounded tasks.
const MAX_CONCURRENT_ACCEPTS: usize = 16;

/// The ack byte string written back to a sender once its envelope has
/// been received and decoded. See `write_ack`'s doc comment for what
/// this does and does not promise.
const ACK_ACCEPTED: &[u8] = b"accepted";
const RESPONSE_PREFIX_BYTES: usize = 4;
type Inbound = (String, Envelope, Sender<Result<Option<Envelope>, String>>);

pub struct IrohTransport {
    runtime: tokio::runtime::Runtime,
    endpoint: Endpoint,
    alpn: &'static [u8],
    // Deliberately *no* `inbox_tx` field: the only `Sender`s in
    // existence live inside the spawned accept loop and its per-
    // connection child tasks. Keeping one alive here for the
    // transport's whole lifetime would mean the channel could never
    // disconnect, so `recv()` below could never return `Closed` even
    // after the accept loop had ended — leaving `sf listen` blocked
    // forever in a process that had silently stopped listening.
    inbox_rx: Mutex<Receiver<Inbound>>,
}

impl IrohTransport {
    pub fn new(secret_key_bytes: [u8; 32], alpn: &'static [u8]) -> Result<Self, TransportError> {
        let runtime =
            tokio::runtime::Runtime::new().map_err(|e| TransportError::Other(e.to_string()))?;
        let secret_key = SecretKey::from_bytes(&secret_key_bytes);
        let endpoint = runtime
            .block_on(
                Endpoint::builder(presets::N0)
                    .secret_key(secret_key)
                    .alpns(vec![alpn.to_vec()])
                    .bind(),
            )
            .map_err(|e| TransportError::Other(e.to_string()))?;
        let (inbox_tx, inbox_rx) = std::sync::mpsc::channel();
        let transport = IrohTransport {
            runtime,
            endpoint,
            alpn,
            inbox_rx: Mutex::new(inbox_rx),
        };
        transport.spawn_accept_loop(inbox_tx);
        Ok(transport)
    }

    pub fn node_id(&self) -> String {
        self.endpoint.id().to_string()
    }

    /// Takes `inbox_tx` **by value** rather than cloning it off a struct
    /// field: this task (plus the per-connection tasks it spawns, each
    /// holding a clone for its own lifetime) owns every `Sender` for the
    /// inbox channel. When `endpoint.accept()` returns `None` the loop
    /// breaks, this async block returns, its `tx` drops, and once the
    /// last in-flight connection task finishes and drops its clone the
    /// channel is disconnected — which is exactly what makes `recv()`
    /// return `TransportError::Closed` instead of blocking forever.
    ///
    /// Every failure path logs to stderr. An operator running
    /// `sf listen` has no other signal that inbound traffic is being
    /// rejected, so silent `return`s are not acceptable here.
    fn spawn_accept_loop(&self, inbox_tx: Sender<Inbound>) {
        let endpoint = self.endpoint.clone();
        let permits = Arc::new(Semaphore::new(MAX_CONCURRENT_ACCEPTS));
        self.runtime.spawn(async move {
            let tx = inbox_tx;
            loop {
                let Some(incoming) = endpoint.accept().await else {
                    eprintln!("listen: the Iroh endpoint stopped accepting connections — the accept loop is shutting down");
                    break;
                };
                // Acquired before the connection is handled at all, so
                // the loop itself stalls here (leaving connections
                // queued in the endpoint) rather than spawning an
                // unbounded number of tasks under load.
                let permit = match Arc::clone(&permits).acquire_owned().await {
                    Ok(permit) => permit,
                    Err(e) => {
                        eprintln!("listen: inbound-connection semaphore closed ({e}) — the accept loop is shutting down");
                        break;
                    }
                };
                let tx = tx.clone();
                tokio::spawn(async move {
                    // Held for the whole task; released on any exit path
                    // below, including the early `return`s.
                    let _permit = permit;

                    let conn = match tokio::time::timeout(ACCEPT_STAGE_TIMEOUT, incoming).await {
                        Ok(Ok(conn)) => conn,
                        Ok(Err(e)) => {
                            eprintln!("listen: an inbound connection failed to establish: {e}");
                            return;
                        }
                        Err(_) => {
                            eprintln!("listen: an inbound connection did not complete its handshake within {}s — dropping it", ACCEPT_STAGE_TIMEOUT.as_secs());
                            return;
                        }
                    };
                    // `Connection::remote_id() -> EndpointId` (not
                    // Option/Result — confirmed against the real crate
                    // source, `iroh-1.0.3/src/endpoint/connection.rs:1127`)
                    // and `EndpointId` is a type alias for `PublicKey`
                    // (`iroh-base-1.0.3/src/key.rs:70`), which implements
                    // `Display`. Iroh authenticates this as part of the
                    // QUIC/TLS handshake, so it is a genuine identity
                    // claim, not a self-reported one — `cli::tunnel::
                    // listen` gates on it.
                    let remote = conn.remote_id().to_string();
                    let (mut send, mut recv) = match tokio::time::timeout(ACCEPT_STAGE_TIMEOUT, conn.accept_bi()).await {
                        Ok(Ok(streams)) => streams,
                        Ok(Err(e)) => {
                            eprintln!("listen: failed to accept a stream from {remote}: {e}");
                            return;
                        }
                        Err(_) => {
                            eprintln!("listen: {remote} connected but opened no stream within {}s — dropping the connection", ACCEPT_STAGE_TIMEOUT.as_secs());
                            return;
                        }
                    };
                    let bytes = match tokio::time::timeout(ACCEPT_STAGE_TIMEOUT, recv.read_to_end(MAX_ENVELOPE_BYTES)).await {
                        Ok(Ok(bytes)) => bytes,
                        Ok(Err(e)) => {
                            eprintln!("listen: failed to read an envelope from {remote} (stream broke, or it exceeded the {MAX_ENVELOPE_BYTES}-byte cap): {e}");
                            return;
                        }
                        Err(_) => {
                            eprintln!("listen: {remote} did not finish sending its envelope within {}s — dropping the connection", ACCEPT_STAGE_TIMEOUT.as_secs());
                            return;
                        }
                    };
                    let envelope = match crate::envelope::Envelope::decode(&bytes) {
                        Ok(envelope) => envelope,
                        Err(e) => {
                            eprintln!("listen: undecodable envelope from {remote} ({} bytes): {e}", bytes.len());
                            return;
                        }
                    };
                    let (ack_tx, ack_rx) = std::sync::mpsc::channel();
                    if tx.send((remote.clone(), envelope, ack_tx)).is_err() {
                        eprintln!("listen: discarding an envelope from {remote} — nothing is receiving from this transport any more");
                        return;
                    }
                    match tokio::task::spawn_blocking(move || ack_rx.recv()).await {
                        Ok(Ok(Ok(response))) => {
                            let mut ack = ACK_ACCEPTED.to_vec();
                            if let Some(response) = response {
                                let encoded = response.encode();
                                ack.extend_from_slice(&(encoded.len() as u32).to_be_bytes());
                                ack.extend_from_slice(&encoded);
                            }
                            write_ack(&mut send, &ack, &remote).await
                        }
                        Ok(Ok(Err(reason))) => write_ack(&mut send, format!("rejected:{reason}").as_bytes(), &remote).await,
                        _ => write_ack(&mut send, b"rejected:dispatch unavailable", &remote).await,
                    }
                });
            }
        });
    }
}

/// Writes the sender's ack.
///
/// **What this ack means:** the envelope arrived intact, decoded into a
/// known `StatementKind`, and was handed to this router's receive queue.
/// That is all.
///
/// **What it does not mean:** it is *not* an acceptance by the receiving
/// router's ingest logic. Dispatch happens later and in a different call
/// frame — `cli::tunnel::listen` pulls the envelope off `recv()` and only
/// then calls `dispatch_envelope`, which is where the signature check,
/// the follow gate, and every other rejection reason live. By the time
/// any of that runs, this stream is already closed and the sender has
/// already been told "ok".
///
/// The original design intended the ack to distinguish "delivered and
/// accepted" from "delivered but rejected" (e.g. a statement from an
/// author the recipient does not follow). **That is not implemented.**
/// Doing it honestly requires dispatch to run inside this task, while
/// the QUIC stream is still open — i.e. a callback-shaped receive side
/// on `PeerTransport` (`listen(dispatch: impl Fn(..) -> Result<..>)`)
/// instead of today's blocking `recv() -> (String, Envelope)`. That is a
/// deliberate future change, not an oversight being papered over here.
///
/// Consequence for the sender: `send()` returning `Ok(())` means "the
/// peer's transport received and decoded this", never "the peer acted on
/// it". A statement can still be rejected downstream with the sender
/// none the wiser.
async fn write_ack(send: &mut iroh::endpoint::SendStream, bytes: &[u8], remote: &str) {
    if let Err(e) = send.write_all(bytes).await {
        eprintln!("listen: received an envelope from {remote} but failed to acknowledge it: {e}");
        return;
    }
    if let Err(e) = send.finish() {
        eprintln!("listen: failed to close the ack stream to {remote}: {e}");
    }
}

impl PeerTransport for IrohTransport {
    /// `Ok(())` means the peer's *transport* received and decoded this
    /// envelope and acked it — see `write_ack` for why that is strictly
    /// weaker than "the peer accepted the statement". Callers that treat
    /// `Ok(())` as "delivered, no fallback needed" (as
    /// `cli::tunnel::try_deliver` does) are relying on exactly that
    /// weaker guarantee.
    fn send(&self, to: &str, envelope: &Envelope) -> Result<(), TransportError> {
        self.send_inner(to, envelope, false).map(|_| ())
    }

    fn request(&self, to: &str, envelope: &Envelope) -> Result<Envelope, TransportError> {
        self.send_inner(to, envelope, true)?
            .ok_or_else(|| TransportError::Other("peer returned no response".into()))
    }

    fn recv_and_dispatch(&self, dispatch: &Dispatch<'_>) -> Result<(), TransportError> {
        let (from, envelope, ack) = self
            .inbox_rx
            .lock()
            .unwrap()
            .recv()
            .map_err(|_| TransportError::Closed)?;
        let result = dispatch(&from, &envelope);
        ack.send(result.clone())
            .map_err(|_| TransportError::Closed)?;
        result
            .map(|_| ())
            .map_err(TransportError::ApplicationRejected)
    }
}

impl IrohTransport {
    fn send_inner(
        &self,
        to: &str,
        envelope: &Envelope,
        expect_response: bool,
    ) -> Result<Option<Envelope>, TransportError> {
        let node_id: PublicKey = to
            .parse()
            .map_err(|_| TransportError::Unreachable(to.to_string()))?;
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
            // The ack read must *not* be discarded. If the receiver's
            // accept task bailed out (undecodable envelope, size cap,
            // timeout, a full inbox) it drops the stream, and this read
            // errors — which is the only evidence the sender ever gets
            // that the statement did not land. Swallowing it here would
            // make `send()` report success, which makes
            // `cli::tunnel::try_deliver` report `Delivered`, which makes
            // its call sites skip writing the fallback `--out` file: the
            // statement would vanish with no artifact anywhere.
            let ack = recv
                .read_to_end(MAX_ENVELOPE_BYTES + ACK_ACCEPTED.len() + RESPONSE_PREFIX_BYTES)
                .await
                .map_err(|e| TransportError::Other(format!("peer never acknowledged the envelope (it was not received or not decodable): {e}")))?;
            if ack == ACK_ACCEPTED {
                if expect_response {
                    Err(TransportError::Other("peer returned no response".to_string()))
                } else {
                    Ok(None)
                }
            } else if ack.starts_with(ACK_ACCEPTED) && expect_response {
                let length_start = ACK_ACCEPTED.len();
                let length_end = length_start + RESPONSE_PREFIX_BYTES;
                if ack.len() < length_end {
                    return Err(TransportError::Other("peer returned a truncated response".into()));
                }
                let length = u32::from_be_bytes(ack[length_start..length_end].try_into().unwrap()) as usize;
                if length > MAX_ENVELOPE_BYTES || ack.len() != length_end + length {
                    return Err(TransportError::Other("peer returned an invalid response frame".into()));
                }
                Ok(Some(Envelope::decode(&ack[length_end..]).map_err(|e| TransportError::Other(e.to_string()))?))
            } else if let Some(reason) = ack.strip_prefix(b"rejected:") {
                Err(TransportError::ApplicationRejected(String::from_utf8_lossy(reason).into_owned()))
            } else {
                Err(TransportError::Other("peer returned an invalid acknowledgment".to_string()))
            }
        })
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

        let envelope = Envelope {
            kind: StatementKind::TunnelConnectionRequest,
            payload: b"hello".to_vec(),
        };
        client.send(&server_id, &envelope).unwrap();

        server
            .recv_and_dispatch(&|from, received| {
                assert_eq!(from, client.node_id());
                assert_eq!(received, &envelope);
                Ok(None)
            })
            .unwrap();
    }

    /// Pins the fix for "`recv()` can never observe the transport
    /// closing". Closing the endpoint makes `endpoint.accept()` return
    /// `None`, which breaks the accept loop, which drops the only
    /// `Sender` for the inbox channel — so this `recv()` must return
    /// `Closed` rather than blocking forever in a process that has
    /// silently stopped listening.
    ///
    /// Needs only to *bind* an endpoint, never to connect one, so it is
    /// not subject to the environment-dependent connectivity problem
    /// that keeps the test above `#[ignore]`d.
    #[test]
    fn recv_reports_closed_once_the_accept_loop_has_ended() {
        let transport = IrohTransport::new([11u8; 32], ALPN).unwrap();
        transport.runtime.block_on(transport.endpoint.close());
        assert!(matches!(
            transport.recv_and_dispatch(&|_, _| Ok(None)),
            Err(TransportError::Closed)
        ));
    }

    /// The accept loop's per-connection tasks each hold a `Sender`
    /// clone, so the channel only disconnects once the loop *and* every
    /// in-flight connection have finished. This models that exact
    /// ownership shape without Iroh: a task owning the sender, which
    /// spawns a child holding a clone that outlives it.
    #[test]
    fn the_inbox_channel_disconnects_only_after_the_loop_and_its_children_end() {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let (tx, rx) = std::sync::mpsc::channel::<(String, Envelope)>();
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        runtime.spawn(async move {
            let tx = tx;
            let child_tx = tx.clone();
            tokio::spawn(async move {
                let _tx = child_tx;
                // Holds its clone until the test says otherwise, the way
                // a slow inbound connection would.
                let _ = tokio::task::spawn_blocking(move || release_rx.recv()).await;
            });
            // The outer loop ends here, dropping its own sender — but
            // the child's clone is still alive.
        });

        // Would have returned `Disconnected` already if the child's
        // clone were not keeping the channel open.
        assert!(matches!(
            rx.recv_timeout(Duration::from_millis(250)),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout)
        ));

        drop(release_tx);
        assert!(
            matches!(rx.recv(), Err(std::sync::mpsc::RecvError)),
            "with every sender dropped, the channel must disconnect"
        );
    }
}
