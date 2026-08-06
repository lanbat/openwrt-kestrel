//! Signed, versioned configuration that can be replicated and reviewed by
//! groups before being materialized by a local router.

use crate::canonical::CanonicalEncode;
use crate::group::GroupId;
use crate::ids::{Hash32, SignatureBytes, UserId};
use crate::opinion::{Reason, Stance, Timestamp};
use crate::sharing::Visibility;
use crate::target::TargetSelector;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyAction {
    Block,
    Allow,
    Route {
        profile: String,
    },
    DnsBlock,
    DnsRedirect {
        address: String,
    },
    /// A complete DNS RR override in presentation format. Keeping the type
    /// and value generic lets every supported DNS record type be advertised
    /// without changing the signed policy schema.
    DnsRecord {
        record_type: String,
        value: String,
        ttl_seconds: u32,
    },
}

impl CanonicalEncode for PolicyAction {
    fn canonical_encode(&self, out: &mut Vec<u8>) {
        match self {
            Self::Block => out.push(0),
            Self::Allow => out.push(1),
            Self::Route { profile } => {
                out.push(2);
                profile.canonical_encode(out);
            }
            Self::DnsBlock => out.push(3),
            Self::DnsRedirect { address } => {
                out.push(4);
                address.canonical_encode(out);
            }
            Self::DnsRecord {
                record_type,
                value,
                ttl_seconds,
            } => {
                out.push(5);
                record_type.canonical_encode(out);
                value.canonical_encode(out);
                ttl_seconds.canonical_encode(out);
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyEntry {
    pub entry_id: Hash32,
    pub target: TargetSelector,
    pub action: PolicyAction,
    pub category: Option<String>,
    pub reason: Reason,
    pub expires_at: Option<Timestamp>,
}

impl PolicyEntry {
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.entry_id.canonical_encode(&mut out);
        self.target.canonical_encode(&mut out);
        self.action.canonical_encode(&mut out);
        self.category.canonical_encode(&mut out);
        self.reason.canonical_encode(&mut out);
        self.expires_at.canonical_encode(&mut out);
        out
    }

    pub fn is_expired(&self, now: Timestamp) -> bool {
        matches!(self.expires_at, Some(expiry) if expiry <= now)
    }
}

impl CanonicalEncode for PolicyEntry {
    fn canonical_encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.signing_bytes());
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SharedPolicy {
    pub policy_id: Hash32,
    pub author: UserId,
    pub sequence: u64,
    pub name: String,
    pub description: String,
    pub categories: Vec<String>,
    pub visibility: Visibility,
    pub entries: Vec<PolicyEntry>,
    pub issued_at: Timestamp,
    pub expires_at: Option<Timestamp>,
    pub supersedes: Option<u64>,
    pub signature: SignatureBytes,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalProfile {
    pub profile_id: Hash32,
    pub name: String,
    pub description: String,
    pub active: bool,
    pub policy_ids: Vec<Hash32>,
}

impl SharedPolicy {
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.policy_id.canonical_encode(&mut out);
        self.author.canonical_encode(&mut out);
        self.sequence.canonical_encode(&mut out);
        self.name.canonical_encode(&mut out);
        self.description.canonical_encode(&mut out);
        self.categories.canonical_encode(&mut out);
        self.visibility.canonical_encode(&mut out);
        self.entries.canonical_encode(&mut out);
        self.issued_at.canonical_encode(&mut out);
        self.expires_at.canonical_encode(&mut out);
        self.supersedes.canonical_encode(&mut out);
        out
    }

    pub fn is_expired(&self, now: Timestamp) -> bool {
        matches!(self.expires_at, Some(expiry) if expiry <= now)
    }

    pub fn entry(&self, entry_id: &Hash32) -> Option<&PolicyEntry> {
        self.entries
            .iter()
            .find(|entry| &entry.entry_id == entry_id)
    }
}

/// One group's voting member's signed stance on a specific shared-policy
/// entry. This is deliberately separate from `GroupVote`: policy votes are
/// about a versioned policy entry, not a group's general target poll.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyVote {
    pub policy_id: Hash32,
    pub entry_id: Hash32,
    pub policy_sequence: u64,
    pub group_id: GroupId,
    pub voter: UserId,
    pub sequence: u64,
    pub stance: Stance,
    pub reason: Reason,
    pub issued_at: Timestamp,
    pub expires_at: Option<Timestamp>,
    pub signature: SignatureBytes,
}

impl PolicyVote {
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.policy_id.canonical_encode(&mut out);
        self.entry_id.canonical_encode(&mut out);
        self.policy_sequence.canonical_encode(&mut out);
        self.group_id.canonical_encode(&mut out);
        self.voter.canonical_encode(&mut out);
        self.sequence.canonical_encode(&mut out);
        self.stance.canonical_encode(&mut out);
        self.reason.canonical_encode(&mut out);
        self.issued_at.canonical_encode(&mut out);
        self.expires_at.canonical_encode(&mut out);
        out
    }

    pub fn is_expired(&self, now: Timestamp) -> bool {
        matches!(self.expires_at, Some(expiry) if expiry <= now)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ids::{FederationId, Hash32};
    use crate::opinion::ReasonCode;

    fn user() -> UserId {
        UserId {
            federation: FederationId(Hash32([1; 32])),
            local_id: Hash32([2; 32]),
        }
    }

    fn entry() -> PolicyEntry {
        PolicyEntry {
            entry_id: Hash32([3; 32]),
            target: TargetSelector::Domain("example.com".into()),
            action: PolicyAction::DnsBlock,
            category: Some("ads".into()),
            reason: Reason {
                code: ReasonCode::Tracker,
                note: None,
                evidence: vec![],
            },
            expires_at: None,
        }
    }

    fn policy() -> SharedPolicy {
        SharedPolicy {
            policy_id: Hash32([4; 32]),
            author: user(),
            sequence: 1,
            name: "local policy".into(),
            description: "test".into(),
            categories: vec!["privacy".into()],
            visibility: Visibility::Public,
            entries: vec![entry()],
            issued_at: 10,
            expires_at: None,
            supersedes: None,
            signature: SignatureBytes([0; 64]),
        }
    }

    #[test]
    fn policy_signing_bytes_are_stable_and_exclude_signature() {
        let mut value = policy();
        value.signature = SignatureBytes([9; 64]);
        let bytes = value.signing_bytes();
        assert!(!bytes.windows(64).any(|window| window == [9; 64]));
        assert_eq!(bytes, value.signing_bytes());
    }

    #[test]
    fn entry_lookup_and_expiry_are_deterministic() {
        let mut value = policy();
        assert_eq!(
            value.entry(&Hash32([3; 32])).unwrap().target,
            TargetSelector::Domain("example.com".into())
        );
        value.entries[0].expires_at = Some(20);
        assert!(!value.entries[0].is_expired(19));
        assert!(value.entries[0].is_expired(20));
        assert!(!value.is_expired(20));
    }

    #[test]
    fn action_variants_have_distinct_canonical_bytes() {
        let block = PolicyAction::Block;
        let allow = PolicyAction::Allow;
        assert_ne!(
            crate::canonical::encode(&block),
            crate::canonical::encode(&allow)
        );
    }

    #[test]
    fn policy_vote_signing_bytes_exclude_signature() {
        let mut vote = PolicyVote {
            policy_id: Hash32([4; 32]),
            entry_id: Hash32([3; 32]),
            policy_sequence: 2,
            group_id: GroupId(Hash32([5; 32])),
            voter: user(),
            sequence: 1,
            stance: Stance::Deny,
            reason: Reason {
                code: ReasonCode::Tracker,
                note: Some("test".into()),
                evidence: vec![],
            },
            issued_at: 10,
            expires_at: Some(20),
            signature: SignatureBytes([9; 64]),
        };
        let bytes = vote.signing_bytes();
        vote.signature = SignatureBytes([1; 64]);
        assert_eq!(bytes, vote.signing_bytes());
        assert!(!vote.is_expired(20 - 1));
        assert!(vote.is_expired(20));
    }
}
