use crate::envelope::Envelope;
use crate::transport::{Dispatch, PeerTransport, TransportError};
use std::collections::HashMap;
use std::sync::mpsc::{Receiver, Sender};
use std::sync::{Arc, Mutex};

/// Peer address → that peer's inbox sender. Named rather than spelled
/// out inline so the struct field below stays readable (and clippy's
/// `type_complexity` stays quiet).
type PeerInboxes =
    HashMap<String, Sender<(String, Envelope, Sender<Result<Option<Envelope>, String>>)>>;
type Inbound = (String, Envelope, Sender<Result<Option<Envelope>, String>>);

/// An in-memory `PeerTransport` for tests — no network, no async
/// runtime. `pair()` wires two instances to each other so a test can
/// exercise a real two-sided send/recv without touching Iroh at all;
/// this is the primary test strategy for everything above the
/// transport boundary (see this plan's "Important finding" section on
/// why real Iroh connectivity is verified separately, not relied on for
/// routine testing).
pub struct FakeTransport {
    my_address: String,
    inbox: Arc<Mutex<Receiver<Inbound>>>,
    peers: Arc<Mutex<PeerInboxes>>,
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
        let sender = peers
            .get(to)
            .ok_or_else(|| TransportError::Unreachable(to.to_string()))?;
        let (ack_tx, ack_rx) = std::sync::mpsc::channel();
        sender
            .send((self.my_address.clone(), envelope.clone(), ack_tx))
            .map_err(|_| TransportError::Closed)?;
        match ack_rx.recv().map_err(|_| TransportError::Closed)? {
            Ok(None) => Ok(()),
            Ok(Some(_)) => Err(TransportError::Other(
                "peer returned a response to a send".into(),
            )),
            Err(e) => Err(TransportError::ApplicationRejected(e)),
        }
    }

    fn request(&self, to: &str, envelope: &Envelope) -> Result<Envelope, TransportError> {
        let peers = self.peers.lock().unwrap();
        let sender = peers
            .get(to)
            .ok_or_else(|| TransportError::Unreachable(to.to_string()))?;
        let (ack_tx, ack_rx) = std::sync::mpsc::channel();
        sender
            .send((self.my_address.clone(), envelope.clone(), ack_tx))
            .map_err(|_| TransportError::Closed)?;
        match ack_rx.recv().map_err(|_| TransportError::Closed)? {
            Ok(Some(response)) => Ok(response),
            Ok(None) => Err(TransportError::Other("peer returned no response".into())),
            Err(e) => Err(TransportError::ApplicationRejected(e)),
        }
    }

    fn recv_and_dispatch(&self, dispatch: &Dispatch<'_>) -> Result<(), TransportError> {
        let (from, envelope, ack) = self
            .inbox
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

#[cfg(test)]
mod tests {
    use super::*;
    // Only the tests construct envelopes, so this stays scoped to them —
    // importing it at module level made it an `unused_imports` warning on
    // every non-test build.
    use crate::envelope::StatementKind;

    #[test]
    fn two_fake_transports_exchange_an_envelope() {
        let (a, b) = FakeTransport::pair();
        let envelope = Envelope {
            kind: StatementKind::TunnelConnectionRequest,
            payload: b"hello".to_vec(),
        };

        std::thread::scope(|s| {
            s.spawn(|| a.send("peer-b", &envelope).unwrap());
            b.recv_and_dispatch(&|from, received| {
                assert_eq!(from, "peer-a");
                assert_eq!(received, &envelope);
                Ok(None)
            })
            .unwrap();
        });
    }

    #[test]
    fn sending_to_an_unknown_peer_is_a_typed_error_not_a_panic() {
        let (a, _b) = FakeTransport::pair();
        let envelope = Envelope {
            kind: StatementKind::TunnelConnectionAccept,
            payload: b"x".to_vec(),
        };
        let err = a.send("nobody", &envelope).unwrap_err();
        assert!(matches!(err, TransportError::Unreachable(_)));
    }

    #[test]
    fn rejected_dispatch_is_reported_to_sender() {
        let (a, b) = FakeTransport::pair();
        let envelope = Envelope {
            kind: StatementKind::Group,
            payload: b"x".to_vec(),
        };
        std::thread::scope(|s| {
            let send = s.spawn(|| a.send("peer-b", &envelope));
            b.recv_and_dispatch(&|_, _| Err("bad signature".to_string()))
                .unwrap_err();
            assert!(
                matches!(send.join().unwrap(), Err(TransportError::ApplicationRejected(message)) if message == "bad signature")
            );
        });
    }

    #[test]
    fn request_returns_the_application_response_after_dispatch() {
        let (a, b) = FakeTransport::pair();
        let request = Envelope {
            kind: StatementKind::SyncGroupRequest,
            payload: b"request".to_vec(),
        };
        let response = Envelope {
            kind: StatementKind::SyncGroupResponse,
            payload: b"response".to_vec(),
        };
        std::thread::scope(|s| {
            let request_thread = s.spawn(|| a.request("peer-b", &request));
            b.recv_and_dispatch(&|_, received| {
                assert_eq!(received, &request);
                Ok(Some(response.clone()))
            })
            .unwrap();
            assert_eq!(request_thread.join().unwrap().unwrap(), response);
        });
    }
}
