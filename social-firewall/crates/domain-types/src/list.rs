//! Shared rule lists: a curated, named, described, *categorized* bundle
//! of firewall rules an operator can publish, that other operators can
//! browse and subscribe to. A subscribed list's entries become
//! trust-weighted opinions through the exact same aggregation
//! `PolicyOpinion`-following already does (see `policy-engine`) — this is
//! not a second, competing, more-authoritative decision path, just a
//! bulk-publish shape for the same kind of signal.
//!
//! Categories are free-form tags (matching `split-routing`'s own
//! `DNS_CATS`/`RESOLVE_CATS` convention already in this repo), not a
//! fixed enum — a list author invents whatever categories make sense to
//! them, and a follower's `LocalTrustRule.category_filter` matches
//! against those tags at aggregation time.

use crate::canonical::CanonicalEncode;
use crate::ids::SignatureBytes;
use crate::opinion::{Reason, Stance, Timestamp};
use crate::sharing::Visibility;
use crate::target::TargetSelector;
use crate::ids::UserId;

/// One rule within a `SharedRuleList` — the same `target`/`stance`/
/// `reason` shape `PolicyOpinion` uses for a single signed statement,
/// just bundled many-at-once under one signed, versioned, named unit
/// instead of published individually. Deliberately has no `sequence` of
/// its own — see `SharedRuleList`'s own doc on why these were never
/// individually signed/sequenced statements and shouldn't be treated as
/// such.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SharedRuleEntry {
    pub target: TargetSelector,
    pub stance: Stance,
    pub reason: Reason,
}

impl CanonicalEncode for SharedRuleEntry {
    fn canonical_encode(&self, out: &mut Vec<u8>) {
        self.target.canonical_encode(out);
        self.stance.canonical_encode(out);
        self.reason.canonical_encode(out);
    }
}

/// A signed, versioned, named bundle of rules. A new published
/// `sequence` is a new *version* of the whole list — all current
/// entries, not a diff (matching how `split-routing`'s own local
/// blocklist files are wholesale-regenerated, not diffed) — so ingesting
/// a new version replaces the previous version's entries for that
/// author+list, never merges with them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SharedRuleList {
    pub author: UserId,
    pub sequence: u64,
    pub name: String,
    pub description: String,
    pub categories: Vec<String>,
    pub visibility: Visibility,
    pub entries: Vec<SharedRuleEntry>,
    pub issued_at: Timestamp,
    pub expires_at: Option<Timestamp>,
    pub supersedes: Option<u64>,
    pub signature: SignatureBytes,
}

impl SharedRuleList {
    /// The bytes that get signed — everything except the signature itself.
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
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
        matches!(self.expires_at, Some(exp) if exp <= now)
    }

    /// Whether any of this list's categories match `filter` — the
    /// operation `LocalTrustRule.category_filter` needs at aggregation
    /// time. An empty/absent filter is handled by the caller (it means
    /// "everything counts," not "nothing matches"), not here.
    pub fn matches_category(&self, filter: &str) -> bool {
        self.categories.iter().any(|c| c == filter)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ids::{FederationId, Hash32};
    use crate::opinion::{Reason, ReasonCode};

    fn user(byte: u8) -> UserId {
        UserId { federation: FederationId(Hash32([byte; 32])), local_id: Hash32([byte + 1; 32]) }
    }

    fn sample_list() -> SharedRuleList {
        SharedRuleList {
            author: user(1),
            sequence: 0,
            name: "known trackers".into(),
            description: "domains I've personally confirmed track users".into(),
            categories: vec!["privacy".into(), "ads".into()],
            visibility: Visibility::Public,
            entries: vec![SharedRuleEntry {
                target: TargetSelector::Domain("ads.example".into()),
                stance: Stance::Deny,
                reason: Reason { code: ReasonCode::Tracker, note: None, evidence: vec![] },
            }],
            issued_at: 1000,
            expires_at: None,
            supersedes: None,
            signature: SignatureBytes([0; 64]),
        }
    }

    #[test]
    fn signing_bytes_excludes_signature() {
        let mut list = sample_list();
        list.signature = SignatureBytes([9; 64]);
        let bytes = list.signing_bytes();
        assert!(!bytes.windows(64).any(|w| w == [9u8; 64]));
    }

    #[test]
    fn signing_bytes_are_deterministic() {
        let list = sample_list();
        assert_eq!(list.signing_bytes(), list.signing_bytes());
    }

    #[test]
    fn different_entries_produce_different_signing_bytes() {
        let a = sample_list();
        let mut b = sample_list();
        b.entries.push(SharedRuleEntry {
            target: TargetSelector::Domain("more-ads.example".into()),
            stance: Stance::Deny,
            reason: Reason { code: ReasonCode::Tracker, note: None, evidence: vec![] },
        });
        assert_ne!(a.signing_bytes(), b.signing_bytes());
    }

    #[test]
    fn matches_category_is_case_sensitive_exact_match() {
        let list = sample_list();
        assert!(list.matches_category("privacy"));
        assert!(!list.matches_category("Privacy"));
        assert!(!list.matches_category("security"));
    }

    #[test]
    fn expiry_check_is_inclusive_of_the_boundary() {
        let mut list = sample_list();
        list.expires_at = Some(100);
        assert!(!list.is_expired(99));
        assert!(list.is_expired(100));
    }
}
