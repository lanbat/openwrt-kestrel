//! Infrastructure shared by every peer-published, discoverable thing this
//! crate defines — tunnel advertisements, tunnel service requests, and
//! shared rule lists all use the same visibility choice and the same
//! three-key-purpose separation. Designed once here, reused by all three
//! rather than each defining its own copy.

use crate::canonical::CanonicalEncode;
use crate::ids::UserId;

/// A reference to some other signed statement by `(author, sequence)` —
/// the same shape `OpinionRef` uses for opinions, generalized here since
/// tunnel advertisements, service requests, and connection requests/
/// accepts all need to reference each other the same way (an
/// advertisement's `in_response_to`, a connection request's
/// `advertisement`, a connection accept's `request_ref`). One type for
/// "point at some other statement by whoever published it and which
/// numbered thing it was," reused rather than three ad-hoc tuples.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct StatementRef {
    pub author: UserId,
    pub sequence: u64,
}

impl CanonicalEncode for StatementRef {
    fn canonical_encode(&self, out: &mut Vec<u8>) {
        self.author.canonical_encode(out);
        self.sequence.canonical_encode(out);
    }
}

/// Per-item choice, not a global setting: `Public` is exported as a
/// plaintext signed JSON file — anyone who receives it can read it, the
/// same model `PolicyOpinion` already uses, chosen so a tunnel/list can
/// actually be discovered. `Restricted` means the publisher seals one
/// copy per approved recipient (see `crypto::seal`) — no broadcast, no
/// discoverability past the explicit list. Either way the underlying
/// domain type is identical and stored as plain data once ingested;
/// encryption is purely an export/transport-format concern, the same
/// separation the CLI's own `opinion_to_json`/`opinion_from_json` already
/// draw between wire format and struct.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Visibility {
    Public,
    Restricted,
}

impl CanonicalEncode for Visibility {
    fn canonical_encode(&self, out: &mut Vec<u8>) {
        out.push(match self {
            Visibility::Public => 0,
            Visibility::Restricted => 1,
        });
    }
}

/// A WireGuard tunnel public key (X25519, same curve `crypto_box` uses,
/// but a deliberately distinct type — this key's purpose is establishing
/// a WireGuard tunnel, not encrypting messages between identities; using
/// one keypair for two different protocols' worth of key material is a
/// real anti-pattern even when the curve happens to match).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct WgPublicKeyBytes(pub [u8; 32]);

impl CanonicalEncode for WgPublicKeyBytes {
    fn canonical_encode(&self, out: &mut Vec<u8>) {
        self.0.canonical_encode(out);
    }
}

/// An identity's messaging public key (X25519) — used only for sealing
/// pairwise messages (restricted-visibility exports, tunnel connection
/// requests/accepts) to this identity, via `crypto::seal`/`unseal`. A
/// third keypair per identity, alongside the Ed25519 identity-signing
/// key (`PublicKeyBytes`) and any per-tunnel WireGuard key
/// (`WgPublicKeyBytes`) — three cryptographically distinct purposes,
/// three distinct types, on purpose.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MessagingPublicKeyBytes(pub [u8; 32]);

impl CanonicalEncode for MessagingPublicKeyBytes {
    fn canonical_encode(&self, out: &mut Vec<u8>) {
        self.0.canonical_encode(out);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canonical::encode;

    #[test]
    fn visibility_variants_encode_differently() {
        assert_ne!(encode(&Visibility::Public), encode(&Visibility::Restricted));
    }

    #[test]
    fn wg_and_messaging_keys_with_the_same_bytes_are_different_types() {
        // Not a runtime-observable test (the type system already prevents
        // mixing these up at compile time) — this exists purely so that
        // fact stays true if someone ever "simplifies" these into one type.
        let bytes = [7u8; 32];
        let wg = WgPublicKeyBytes(bytes);
        let msg = MessagingPublicKeyBytes(bytes);
        assert_eq!(wg.0, msg.0); // same bytes...
                                 // ...but `wg` and `msg` cannot be compared to each other or
                                 // substituted for one another — a compile-time guarantee, not
                                 // something this assertion could break.
    }
}
