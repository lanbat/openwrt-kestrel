//! Group-scoped, privacy-preserving fingerprint observations and comments.

use crate::canonical::CanonicalEncode;
use crate::group::GroupId;
use crate::ids::{Hash32, SignatureBytes, UserId};
use crate::opinion::Timestamp;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FingerprintObservation {
    pub group_id: GroupId,
    pub fingerprint_id: Hash32,
    pub fingerprint_revision: u64,
    pub observer: UserId,
    pub signal_family: String,
    /// Digest of normalized evidence. Raw packets, cookies, and headers never
    /// leave the observing router in this statement.
    pub evidence_digest: Hash32,
    pub confidence: u8,
    pub issued_at: Timestamp,
    pub expires_at: Option<Timestamp>,
    pub signature: SignatureBytes,
}

impl FingerprintObservation {
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.group_id.canonical_encode(&mut out);
        self.fingerprint_id.canonical_encode(&mut out);
        self.fingerprint_revision.canonical_encode(&mut out);
        self.observer.canonical_encode(&mut out);
        self.signal_family.canonical_encode(&mut out);
        self.evidence_digest.canonical_encode(&mut out);
        self.confidence.canonical_encode(&mut out);
        self.issued_at.canonical_encode(&mut out);
        self.expires_at.canonical_encode(&mut out);
        out
    }

    pub fn is_expired(&self, now: Timestamp) -> bool {
        matches!(self.expires_at, Some(expiry) if expiry <= now)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FingerprintComment {
    pub group_id: GroupId,
    pub fingerprint_id: Hash32,
    pub fingerprint_revision: u64,
    pub author: UserId,
    pub sequence: u64,
    pub body: String,
    pub issued_at: Timestamp,
    pub signature: SignatureBytes,
}

impl FingerprintComment {
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.group_id.canonical_encode(&mut out);
        self.fingerprint_id.canonical_encode(&mut out);
        self.fingerprint_revision.canonical_encode(&mut out);
        self.author.canonical_encode(&mut out);
        self.sequence.canonical_encode(&mut out);
        self.body.canonical_encode(&mut out);
        self.issued_at.canonical_encode(&mut out);
        out
    }
}
