//! Identifiers. Plain byte containers only — no crypto operations live
//! here (that's the `crypto` crate, which depends on this one, not the
//! other way around), so these types can be encoded/hashed/stored without
//! pulling a signing library into every consumer.

use crate::canonical::CanonicalEncode;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Hash32(pub [u8; 32]);

impl CanonicalEncode for Hash32 {
    fn canonical_encode(&self, out: &mut Vec<u8>) {
        self.0.canonical_encode(out);
    }
}

impl std::fmt::Display for Hash32 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for b in &self.0 {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PublicKeyBytes(pub [u8; 32]);

impl CanonicalEncode for PublicKeyBytes {
    fn canonical_encode(&self, out: &mut Vec<u8>) {
        self.0.canonical_encode(out);
    }
}

#[derive(Debug, Clone, Copy)]
pub struct SignatureBytes(pub [u8; 64]);

impl PartialEq for SignatureBytes {
    fn eq(&self, other: &Self) -> bool {
        self.0[..] == other.0[..]
    }
}
impl Eq for SignatureBytes {}

impl CanonicalEncode for SignatureBytes {
    fn canonical_encode(&self, out: &mut Vec<u8>) {
        self.0.canonical_encode(out);
    }
}

/// Derived from a hash of the federation's genesis (initial validator set
/// + chain parameters) — never chosen, never registered anywhere, so two
/// independently-run federations can never collide or impersonate each
/// other, even by accident.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct FederationId(pub Hash32);

impl CanonicalEncode for FederationId {
    fn canonical_encode(&self, out: &mut Vec<u8>) {
        self.0.canonical_encode(out);
    }
}

/// A user's identity is meaningless without knowing which federation's
/// registry is the authority for revoking it — see the cross-federation
/// following design. `local_id` is stable across key rotations (it's
/// derived from the user's original registration, not their current key).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct UserId {
    pub federation: FederationId,
    pub local_id: Hash32,
}

impl CanonicalEncode for UserId {
    fn canonical_encode(&self, out: &mut Vec<u8>) {
        self.federation.canonical_encode(out);
        self.local_id.canonical_encode(out);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct NodeId(pub Hash32);

impl CanonicalEncode for NodeId {
    fn canonical_encode(&self, out: &mut Vec<u8>) {
        self.0.canonical_encode(out);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canonical::encode;

    #[test]
    fn user_id_encodes_federation_then_local_id() {
        let uid = UserId { federation: FederationId(Hash32([1u8; 32])), local_id: Hash32([2u8; 32]) };
        let out = encode(&uid);
        assert_eq!(out.len(), 64);
        assert_eq!(&out[0..32], &[1u8; 32]);
        assert_eq!(&out[32..64], &[2u8; 32]);
    }

    #[test]
    fn hash32_display_is_lowercase_hex() {
        let h = Hash32([0xabu8; 32]);
        assert_eq!(h.to_string(), "ab".repeat(32));
    }
}
