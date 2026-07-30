//! VPN tunnel advertising: a provider publishes a signed offer scoped to
//! specific traffic (`TunnelAdvertisement`); a consumer can solicit one
//! first instead (`TunnelServiceRequest`, the inverse — a want-ad, not a
//! response to anything specific); establishing an actual tunnel is then
//! a signed request/accept handshake (`TunnelConnectionRequest`/
//! `TunnelConnectionAccept`) since WireGuard is two-sided — a one-way
//! advertisement alone doesn't let anyone connect, the provider's own
//! interface has to authorize the consumer's key first.
//!
//! Deliberately out of scope here (per the request that introduced this):
//! full-tunnel ("route everything") mode — this repo has no such
//! mechanism anywhere yet, and it carries a much bigger blast radius than
//! anything below; only category/domain-scoped tunnels are modeled.

use crate::canonical::CanonicalEncode;
use crate::ids::{SignatureBytes, UserId};
use crate::opinion::Timestamp;
use crate::sharing::{MessagingPublicKeyBytes, StatementRef, Visibility, WgPublicKeyBytes};
use crate::target::TargetSelector;

/// Free-form discovery tags per advertisement, by symmetry with
/// `SharedRuleList.categories` — enforced by *rejection*, not silent
/// truncation, at both publish and ingest time (a peer's own client
/// can't be trusted to have applied the cap, so ingest has to check
/// regardless; rejecting at publish too is then free, and catches the
/// mistake immediately rather than at some other router's expense).
pub const MAX_TUNNEL_TAGS: usize = 5;

/// A provider's signed, published tunnel offer. `in_response_to` is
/// purely informational — set when this advertisement was published in
/// reply to someone's `TunnelServiceRequest`, but an advertisement is
/// always valid unprompted too, so it's optional, never required.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunnelAdvertisement {
    pub provider: UserId,
    pub sequence: u64,
    pub description: String,
    /// Free text — "500GB/month", "best-effort, no uptime guarantee" —
    /// no fixed taxonomy imposed on day one.
    pub limitations: Option<String>,
    pub visibility: Visibility,
    pub in_response_to: Option<StatementRef>,
    /// So a would-be requester knows how to seal a `TunnelConnectionRequest`
    /// back to this provider.
    pub messaging_pubkey: MessagingPublicKeyBytes,
    pub wg_pubkey: WgPublicKeyBytes,
    /// Opaque, transport-specific — same convention as
    /// `federation_bootstrap_nodes.endpoint_hint` in `state-store`.
    pub endpoint_hint: String,
    pub route_scope: Vec<TargetSelector>,
    /// Free-form discovery tags — capped at `MAX_TUNNEL_TAGS`, checked by
    /// `validate_tags`, never enforced by truncation. See that constant's
    /// own doc for why rejection, not truncation.
    pub tags: Vec<String>,
    /// Advertised, but only ever *enforced* by the consumer's own router
    /// against its own traffic through this tunnel — the provider has no
    /// local enforcement point for someone else's outbound rate/
    /// connection count. `None` means no limit advertised.
    pub max_connections: Option<u32>,
    /// Coarse rate cap in kbit/s, enforced via a real `nft limit rate`
    /// rule in the consumer's own per-peer mark chain — real
    /// fair-queuing bandwidth shaping (a `tc` qdisc) is a different
    /// mechanism/dependency, deliberately out of scope for this pass.
    pub max_bandwidth_kbps: Option<u64>,
    pub issued_at: Timestamp,
    pub expires_at: Option<Timestamp>,
    pub supersedes: Option<u64>,
    pub signature: SignatureBytes,
}

impl TunnelAdvertisement {
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.provider.canonical_encode(&mut out);
        self.sequence.canonical_encode(&mut out);
        self.description.canonical_encode(&mut out);
        self.limitations.canonical_encode(&mut out);
        self.visibility.canonical_encode(&mut out);
        self.in_response_to.canonical_encode(&mut out);
        self.messaging_pubkey.canonical_encode(&mut out);
        self.wg_pubkey.canonical_encode(&mut out);
        self.endpoint_hint.canonical_encode(&mut out);
        self.route_scope.canonical_encode(&mut out);
        self.tags.canonical_encode(&mut out);
        self.max_connections.canonical_encode(&mut out);
        self.max_bandwidth_kbps.canonical_encode(&mut out);
        self.issued_at.canonical_encode(&mut out);
        self.expires_at.canonical_encode(&mut out);
        self.supersedes.canonical_encode(&mut out);
        out
    }

    pub fn is_expired(&self, now: Timestamp) -> bool {
        matches!(self.expires_at, Some(exp) if exp <= now)
    }

    /// Rejects (never truncates) an advertisement with more than
    /// `MAX_TUNNEL_TAGS` tags — call at both publish time (before
    /// signing) and ingest time (a peer's own client can't be trusted to
    /// have applied the cap).
    pub fn validate_tags(&self) -> Result<(), String> {
        if self.tags.len() > MAX_TUNNEL_TAGS {
            return Err(format!("advertisement has {} tags, more than the maximum of {MAX_TUNNEL_TAGS}", self.tags.len()));
        }
        Ok(())
    }
}

/// The inverse of an advertisement: "I'm looking for a tunnel covering
/// X" published *before* any specific provider has offered one. Carries
/// no WireGuard or messaging key of its own — the requester isn't
/// offering anything at this stage, just describing a need.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunnelServiceRequest {
    pub requester: UserId,
    pub sequence: u64,
    pub description: String,
    pub desired_route_scope: Vec<TargetSelector>,
    pub visibility: Visibility,
    pub issued_at: Timestamp,
    pub expires_at: Option<Timestamp>,
    pub supersedes: Option<u64>,
    pub signature: SignatureBytes,
}

impl TunnelServiceRequest {
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.requester.canonical_encode(&mut out);
        self.sequence.canonical_encode(&mut out);
        self.description.canonical_encode(&mut out);
        self.desired_route_scope.canonical_encode(&mut out);
        self.visibility.canonical_encode(&mut out);
        self.issued_at.canonical_encode(&mut out);
        self.expires_at.canonical_encode(&mut out);
        self.supersedes.canonical_encode(&mut out);
        out
    }

    pub fn is_expired(&self, now: Timestamp) -> bool {
        matches!(self.expires_at, Some(exp) if exp <= now)
    }
}

/// A consumer's signed statement naming the advertisement it wants and
/// carrying the consumer's own WireGuard + messaging public keys — the
/// provider needs both to authorize the consumer as a WireGuard peer and
/// to seal a `TunnelConnectionAccept` back. Always exported sealed to the
/// provider's messaging key (see `sharing::Visibility`'s doc) —
/// inherently pairwise, never public.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunnelConnectionRequest {
    pub requester: UserId,
    /// Same author-scoped-sequence pattern every other signed statement
    /// here uses — needed so `TunnelConnectionAccept.request_ref` (a
    /// `StatementRef`) can actually identify *this* request, not just
    /// "some request from this requester."
    pub sequence: u64,
    pub advertisement: StatementRef,
    pub requester_wg_pubkey: WgPublicKeyBytes,
    pub requester_messaging_pubkey: MessagingPublicKeyBytes,
    pub requested_at: Timestamp,
    pub signature: SignatureBytes,
}

impl TunnelConnectionRequest {
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.requester.canonical_encode(&mut out);
        self.sequence.canonical_encode(&mut out);
        self.advertisement.canonical_encode(&mut out);
        self.requester_wg_pubkey.canonical_encode(&mut out);
        self.requester_messaging_pubkey.canonical_encode(&mut out);
        self.requested_at.canonical_encode(&mut out);
        out
    }
}

/// The provider's signed response, confirming a `TunnelConnectionRequest`
/// and carrying whatever the consumer's side needs to finish configuring
/// its interface. Always exported sealed to the requester's messaging
/// key, same as the request itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunnelConnectionAccept {
    pub provider: UserId,
    pub request_ref: StatementRef,
    pub assigned_tunnel_ip: String,
    pub accepted_at: Timestamp,
    pub signature: SignatureBytes,
}

impl TunnelConnectionAccept {
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.provider.canonical_encode(&mut out);
        self.request_ref.canonical_encode(&mut out);
        self.assigned_tunnel_ip.canonical_encode(&mut out);
        self.accepted_at.canonical_encode(&mut out);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ids::{FederationId, Hash32};

    fn user(n: u8) -> UserId {
        UserId { federation: FederationId(Hash32([1; 32])), local_id: Hash32([n; 32]) }
    }

    fn advertisement() -> TunnelAdvertisement {
        TunnelAdvertisement {
            provider: user(1),
            sequence: 0,
            description: "EU exit, low latency".into(),
            limitations: Some("500GB/month".into()),
            visibility: Visibility::Public,
            in_response_to: None,
            messaging_pubkey: MessagingPublicKeyBytes([2; 32]),
            wg_pubkey: WgPublicKeyBytes([3; 32]),
            endpoint_hint: "203.0.113.9:51820".into(),
            route_scope: vec![TargetSelector::Domain("example.com".into())],
            tags: vec!["streaming".into()],
            max_connections: None,
            max_bandwidth_kbps: None,
            issued_at: 100,
            expires_at: None,
            supersedes: None,
            signature: SignatureBytes([0; 64]),
        }
    }

    #[test]
    fn advertisement_signing_bytes_excludes_signature() {
        let mut a = advertisement();
        a.signature = SignatureBytes([9; 64]);
        let bytes = a.signing_bytes();
        assert!(!bytes.windows(64).any(|w| w == [9u8; 64]));
    }

    #[test]
    fn advertisement_signing_bytes_change_when_limitations_change() {
        let a = advertisement();
        let mut b = advertisement();
        b.limitations = Some("unlimited".into());
        assert_ne!(a.signing_bytes(), b.signing_bytes());
    }

    #[test]
    fn public_and_restricted_advertisements_have_different_signing_bytes() {
        let mut a = advertisement();
        a.visibility = Visibility::Public;
        let mut b = advertisement();
        b.visibility = Visibility::Restricted;
        assert_ne!(a.signing_bytes(), b.signing_bytes());
    }

    #[test]
    fn advertisement_signing_bytes_change_when_tags_change() {
        let a = advertisement();
        let mut b = advertisement();
        b.tags = vec!["gaming".into()];
        assert_ne!(a.signing_bytes(), b.signing_bytes());
    }

    #[test]
    fn advertisement_signing_bytes_change_when_max_connections_changes() {
        let a = advertisement();
        let mut b = advertisement();
        b.max_connections = Some(100);
        assert_ne!(a.signing_bytes(), b.signing_bytes());
    }

    #[test]
    fn advertisement_signing_bytes_change_when_max_bandwidth_changes() {
        let a = advertisement();
        let mut b = advertisement();
        b.max_bandwidth_kbps = Some(1000);
        assert_ne!(a.signing_bytes(), b.signing_bytes());
    }

    #[test]
    fn validate_tags_accepts_up_to_the_maximum() {
        let mut a = advertisement();
        a.tags = (0..MAX_TUNNEL_TAGS).map(|i| format!("tag{i}")).collect();
        assert!(a.validate_tags().is_ok());
    }

    #[test]
    fn validate_tags_rejects_more_than_the_maximum() {
        let mut a = advertisement();
        a.tags = (0..=MAX_TUNNEL_TAGS).map(|i| format!("tag{i}")).collect();
        assert!(a.validate_tags().is_err());
    }

    #[test]
    fn advertisement_expiry_is_inclusive_of_the_boundary() {
        let mut a = advertisement();
        a.expires_at = Some(100);
        assert!(!a.is_expired(99));
        assert!(a.is_expired(100));
    }

    #[test]
    fn service_request_signing_bytes_excludes_signature() {
        let req = TunnelServiceRequest {
            requester: user(2),
            sequence: 0,
            description: "need an EU exit".into(),
            desired_route_scope: vec![TargetSelector::Domain("example.com".into())],
            visibility: Visibility::Public,
            issued_at: 100,
            expires_at: None,
            supersedes: None,
            signature: SignatureBytes([9; 64]),
        };
        assert!(!req.signing_bytes().windows(64).any(|w| w == [9u8; 64]));
    }

    #[test]
    fn connection_request_references_the_correct_advertisement() {
        let req = TunnelConnectionRequest {
            requester: user(2),
            sequence: 0,
            advertisement: StatementRef { author: user(1), sequence: 0 },
            requester_wg_pubkey: WgPublicKeyBytes([4; 32]),
            requester_messaging_pubkey: MessagingPublicKeyBytes([5; 32]),
            requested_at: 200,
            signature: SignatureBytes([0; 64]),
        };
        assert_eq!(req.advertisement, StatementRef { author: user(1), sequence: 0 });
    }

    #[test]
    fn connection_request_signing_bytes_change_with_sequence() {
        let base = TunnelConnectionRequest {
            requester: user(2),
            sequence: 0,
            advertisement: StatementRef { author: user(1), sequence: 0 },
            requester_wg_pubkey: WgPublicKeyBytes([4; 32]),
            requester_messaging_pubkey: MessagingPublicKeyBytes([5; 32]),
            requested_at: 200,
            signature: SignatureBytes([0; 64]),
        };
        let mut next = base.clone();
        next.sequence = 1;
        assert_ne!(base.signing_bytes(), next.signing_bytes());
    }

    #[test]
    fn connection_accept_signing_bytes_excludes_signature() {
        let accept = TunnelConnectionAccept {
            provider: user(1),
            request_ref: StatementRef { author: user(2), sequence: 0 },
            assigned_tunnel_ip: "10.99.0.4".into(),
            accepted_at: 300,
            signature: SignatureBytes([9; 64]),
        };
        assert!(!accept.signing_bytes().windows(64).any(|w| w == [9u8; 64]));
    }
}
