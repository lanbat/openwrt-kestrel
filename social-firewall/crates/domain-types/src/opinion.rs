//! Opinions, local overrides, and federation statements — see the design
//! conversation this crate implements: a `PolicyOpinion` without a reason
//! isn't a thing that can exist; a reasonless stance is structurally a
//! `LocalOverride` instead, which never leaves the router it was made on.

use crate::canonical::CanonicalEncode;
use crate::group::GroupId;
use crate::ids::{FederationId, SignatureBytes, UserId};
use crate::target::TargetSelector;

/// Unix seconds. A type alias, not a newtype — every consumer needs to do
/// arithmetic on this (comparisons, expiry checks), and wrapping it would
/// just mean unwrapping it again everywhere.
pub type Timestamp = i64;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Stance {
    Allow,
    Deny,
    Ask,
}

impl CanonicalEncode for Stance {
    fn canonical_encode(&self, out: &mut Vec<u8>) {
        out.push(match self {
            Stance::Allow => 0,
            Stance::Deny => 1,
            Stance::Ask => 2,
        });
    }
}

/// A small, versioned, extensible vocabulary — deliberately not free text
/// alone, so "37% of Deny opinions cite Tracker" is a real, cheap
/// aggregate rather than unparseable prose. `note` on `Reason` still
/// allows free-text nuance alongside the code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ReasonCode {
    Malware,
    Phishing,
    Tracker,
    Surveillance,
    AbusiveContent,
    KnownGoodCdn,
    KnownGoodService,
    PersonalPreference,
    AbuseReport,
    Other,
}

impl CanonicalEncode for ReasonCode {
    fn canonical_encode(&self, out: &mut Vec<u8>) {
        out.push(match self {
            ReasonCode::Malware => 0,
            ReasonCode::Phishing => 1,
            ReasonCode::Tracker => 2,
            ReasonCode::Surveillance => 3,
            ReasonCode::AbusiveContent => 4,
            ReasonCode::KnownGoodCdn => 5,
            ReasonCode::KnownGoodService => 6,
            ReasonCode::PersonalPreference => 7,
            ReasonCode::AbuseReport => 8,
            ReasonCode::Other => 9,
        });
    }
}

/// Longest free-text note accepted — a reason should be a short pointer,
/// not an essay attached to a signed, permanently-replicated record.
pub const MAX_REASON_NOTE_LEN: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reason {
    pub code: ReasonCode,
    pub note: Option<String>,
    /// Content hashes of supporting evidence — orthogonal to having a
    /// reason at all; a reason doesn't require evidence to be valid.
    pub evidence: Vec<crate::ids::Hash32>,
}

impl CanonicalEncode for Reason {
    fn canonical_encode(&self, out: &mut Vec<u8>) {
        self.code.canonical_encode(out);
        self.note.canonical_encode(out);
        self.evidence.canonical_encode(out);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OpinionRef {
    pub author: UserId,
    pub sequence: u64,
}

impl CanonicalEncode for OpinionRef {
    fn canonical_encode(&self, out: &mut Vec<u8>) {
        self.author.canonical_encode(out);
        self.sequence.canonical_encode(out);
    }
}

/// A public, syncable, signed stance. Reason is required — not
/// `Option<Reason>` — because that's the entire point: a stance without a
/// reason is a different kind of record (`LocalOverride`), not this one
/// with an empty field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyOpinion {
    pub author: UserId,
    pub sequence: u64,
    pub target: TargetSelector,
    pub stance: Stance,
    pub reason: Reason,
    pub issued_at: Timestamp,
    pub expires_at: Option<Timestamp>,
    pub supersedes: Option<OpinionRef>,
    pub signature: SignatureBytes,
}

impl PolicyOpinion {
    /// The bytes that get signed — everything except the signature itself.
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.author.canonical_encode(&mut out);
        self.sequence.canonical_encode(&mut out);
        self.target.canonical_encode(&mut out);
        self.stance.canonical_encode(&mut out);
        self.reason.canonical_encode(&mut out);
        self.issued_at.canonical_encode(&mut out);
        self.expires_at.canonical_encode(&mut out);
        self.supersedes.canonical_encode(&mut out);
        out
    }

    pub fn is_expired(&self, now: Timestamp) -> bool {
        matches!(self.expires_at, Some(exp) if exp <= now)
    }
}

/// A reasonless, or intentionally private, stance. Never signed for
/// external consumption, never synced, never leaves the router it was
/// created on. On the owner's own router this beats *everything* else,
/// including the owner's own previously-published `PolicyOpinion` for the
/// same target — see the precedence order in `policy-engine`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalOverride {
    pub target: TargetSelector,
    pub stance: Stance,
    pub kind: OverrideKind,
    pub note: Option<String>,
    pub created_at: Timestamp,
    pub expires_at: Option<Timestamp>,
}

impl LocalOverride {
    pub fn is_expired(&self, now: Timestamp) -> bool {
        matches!(self.expires_at, Some(exp) if exp <= now)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OverrideKind {
    Normal,
    /// Distinguished from `Normal` so the UI can treat expiry differently —
    /// an emergency deny quietly reverting to "allow" without the owner
    /// noticing is a real failure mode, a routine preference lapsing isn't.
    Emergency,
}

/// Who authored a statement about a target — an individual user, or a
/// federation's own collective, governance-backed output. These are
/// deliberately different kinds of claims: one person's opinion vs. an
/// institution's official word, and the aggregation algorithm treats them
/// as two separately-weighted inputs, never with one automatically
/// outranking the other.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatementAuthor {
    User(UserId),
    Federation(FederationId),
    /// A group's own aggregate stance (see `crate::group`'s module doc) —
    /// a third kind of claim, distinct from either an individual's
    /// opinion or a federation's governance-backed statement.
    Group(GroupId),
}

/// The federation-level equivalent of `PolicyOpinion` — same shape, same
/// reason-required rule, but committed by the federation's own governance
/// (a validator-threshold signature, not one user's key) rather than an
/// individual. `sequence` is a federation-level counter, independent of
/// any single user's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FederationStatement {
    pub federation: FederationId,
    pub sequence: u64,
    pub target: TargetSelector,
    pub stance: Stance,
    pub reason: Reason,
    pub issued_at: Timestamp,
    pub expires_at: Option<Timestamp>,
    pub supersedes: Option<u64>,
    /// However the federation's governance commits this — a threshold of
    /// validator signatures over the same signing-bytes shape as
    /// `PolicyOpinion` uses. Left abstract here (raw bytes) since the
    /// commitment scheme is a consensus-layer concern, out of scope for
    /// this local-only skeleton.
    pub commitment: Vec<u8>,
}

impl FederationStatement {
    pub fn is_expired(&self, now: Timestamp) -> bool {
        matches!(self.expires_at, Some(exp) if exp <= now)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canonical::encode;

    fn sample_reason() -> Reason {
        Reason { code: ReasonCode::Tracker, note: Some("phones home".into()), evidence: vec![] }
    }

    #[test]
    fn signing_bytes_excludes_signature() {
        let opinion = PolicyOpinion {
            author: UserId { federation: FederationId(crate::ids::Hash32([1; 32])), local_id: crate::ids::Hash32([2; 32]) },
            sequence: 1,
            target: TargetSelector::Domain("ads.example".into()),
            stance: Stance::Deny,
            reason: sample_reason(),
            issued_at: 1000,
            expires_at: None,
            supersedes: None,
            signature: SignatureBytes([9; 64]),
        };
        let bytes = opinion.signing_bytes();
        // Signature bytes (all 9s) should not appear verbatim in the
        // signed payload — a weak but useful smoke check that we didn't
        // accidentally include it.
        assert!(!bytes.windows(64).any(|w| w == [9u8; 64]));
    }

    #[test]
    fn signing_bytes_are_deterministic() {
        let reason = sample_reason();
        let a = encode(&reason);
        let b = encode(&reason);
        assert_eq!(a, b);
    }

    #[test]
    fn expiry_check_is_inclusive_of_the_boundary() {
        let o = LocalOverride {
            target: TargetSelector::Domain("x".into()),
            stance: Stance::Deny,
            kind: OverrideKind::Normal,
            note: None,
            created_at: 0,
            expires_at: Some(100),
        };
        assert!(!o.is_expired(99));
        assert!(o.is_expired(100));
        assert!(o.is_expired(101));
    }
}
