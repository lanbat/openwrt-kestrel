//! Device-approval opinions — a signed, replicable signal about whether a
//! specific device (identified by its MAC address, the one identifier
//! that's actually stable and shareable across routers) should be trusted
//! to join a network.
//!
//! Deliberately **not** a bridge into kestreld's own join-approval tables
//! (`device_fingerprints`/`join_approved`/`join_history`, see
//! `networks/kestreld-rs/src/db`) — that boundary is intentionally left
//! alone for now. kestreld's own fingerprinting is fuzzy, scored, and
//! multi-signal (DHCP options, mDNS, WiFi capabilities) precisely because
//! it's suggesting a match to a human, never auto-applying one; a MAC
//! address is the only piece of that model stable and simple enough to
//! be worth signing and shipping to another router as a cross-network
//! claim. A future integration would read a trust-weighted aggregate of
//! these opinions (see `StateStore::device_approval_stance_for`) and feed
//! it as one more suggestion into kestreld's existing human-in-the-loop
//! approval UI — never write `join_approved`/`join_denied` directly from
//! this signal alone.
//!
//! Structurally this is `PolicyOpinion` shifted onto a different kind of
//! subject (a device instead of a network target) — same required-reason
//! rule, same per-author sequencing/supersede shape, same "just a signed
//! opinion, not an authoritative record" status.

use crate::canonical::CanonicalEncode;
use crate::ids::{SignatureBytes, UserId};
use crate::opinion::{Reason, Stance, Timestamp};

/// Longest free-text device label accepted — a hint for the human reading
/// the opinion (hostname, vendor, whatever the author happened to see),
/// never authoritative and never matched against automatically.
pub const MAX_DEVICE_LABEL_LEN: usize = 128;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceApprovalOpinion {
    pub author: UserId,
    pub sequence: u64,
    /// Lowercased, colon-separated MAC address — the one stable,
    /// cross-router identifier a device actually has. Privacy-randomized
    /// MACs mean this may only ever refer to one of several addresses a
    /// device answers to; that's a known, accepted limitation, not a bug
    /// to work around here.
    pub mac: String,
    /// Allow = safe to approve this device joining a network; Deny =
    /// known-bad/malicious device; Ask = flag for manual review — the
    /// same three-way vocabulary `PolicyOpinion` already uses, reused
    /// rather than inventing a device-specific one.
    pub stance: Stance,
    pub reason: Reason,
    /// Free-text hint only (hostname/vendor/label) — purely descriptive
    /// context for a human reviewing the opinion, never matched against
    /// or treated as part of the claim's identity.
    pub device_label: Option<String>,
    pub issued_at: Timestamp,
    pub expires_at: Option<Timestamp>,
    pub supersedes: Option<u64>,
    pub signature: SignatureBytes,
}

impl DeviceApprovalOpinion {
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.author.canonical_encode(&mut out);
        self.sequence.canonical_encode(&mut out);
        self.mac.canonical_encode(&mut out);
        self.stance.canonical_encode(&mut out);
        self.reason.canonical_encode(&mut out);
        self.device_label.canonical_encode(&mut out);
        self.issued_at.canonical_encode(&mut out);
        self.expires_at.canonical_encode(&mut out);
        self.supersedes.canonical_encode(&mut out);
        out
    }

    pub fn is_expired(&self, now: Timestamp) -> bool {
        matches!(self.expires_at, Some(exp) if exp <= now)
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.mac.trim().is_empty() {
            return Err("device approval opinion must name a non-empty MAC address".into());
        }
        if let Some(label) = &self.device_label {
            if label.len() > MAX_DEVICE_LABEL_LEN {
                return Err(format!("device_label exceeds {MAX_DEVICE_LABEL_LEN} bytes"));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ids::{FederationId, Hash32};
    use crate::opinion::ReasonCode;

    fn sample(mac: &str) -> DeviceApprovalOpinion {
        DeviceApprovalOpinion {
            author: UserId { federation: FederationId(Hash32([1; 32])), local_id: Hash32([2; 32]) },
            sequence: 1,
            mac: mac.to_string(),
            stance: Stance::Deny,
            reason: Reason { code: ReasonCode::Malware, note: Some("botnet C2 beacon".into()), evidence: vec![] },
            device_label: Some("shady-iot-cam".into()),
            issued_at: 1000,
            expires_at: None,
            supersedes: None,
            signature: SignatureBytes([9; 64]),
        }
    }

    #[test]
    fn signing_bytes_excludes_signature() {
        let opinion = sample("aa:bb:cc:dd:ee:ff");
        let bytes = opinion.signing_bytes();
        assert!(!bytes.windows(64).any(|w| w == [9u8; 64]));
    }

    #[test]
    fn signing_bytes_change_with_mac() {
        let a = sample("aa:bb:cc:dd:ee:ff").signing_bytes();
        let b = sample("11:22:33:44:55:66").signing_bytes();
        assert_ne!(a, b);
    }

    #[test]
    fn signing_bytes_change_with_stance() {
        let mut opinion = sample("aa:bb:cc:dd:ee:ff");
        let a = opinion.signing_bytes();
        opinion.stance = Stance::Allow;
        let b = opinion.signing_bytes();
        assert_ne!(a, b);
    }

    #[test]
    fn validate_rejects_empty_mac() {
        let mut opinion = sample("aa:bb:cc:dd:ee:ff");
        opinion.mac = "  ".into();
        assert!(opinion.validate().is_err());
    }

    #[test]
    fn validate_rejects_oversized_label() {
        let mut opinion = sample("aa:bb:cc:dd:ee:ff");
        opinion.device_label = Some("x".repeat(MAX_DEVICE_LABEL_LEN + 1));
        assert!(opinion.validate().is_err());
    }

    #[test]
    fn validate_accepts_a_well_formed_opinion() {
        assert!(sample("aa:bb:cc:dd:ee:ff").validate().is_ok());
    }

    #[test]
    fn expiry_check_is_inclusive_of_the_boundary() {
        let mut opinion = sample("aa:bb:cc:dd:ee:ff");
        opinion.expires_at = Some(100);
        assert!(!opinion.is_expired(99));
        assert!(opinion.is_expired(100));
        assert!(opinion.is_expired(101));
    }
}
