//! The owner's private trust graph — never signed, never synced, never
//! leaves the router. Two orthogonal dimensions: trust in a specific
//! individual, and trust in a federation's own collective statements.

use crate::group::GroupId;
use crate::ids::{FederationId, UserId};
use crate::opinion::Timestamp;

/// Following one specific user. Allow/deny weights are separate — you
/// might trust someone's deny opinions much more than their allow
/// opinions (a cautious contact) or vice versa (an optimistic one).
#[derive(Debug, Clone, PartialEq)]
pub struct LocalTrustRule {
    pub user: UserId,
    pub allow_weight: f64,
    pub deny_weight: f64,
    /// `true` means this user's opinions are visible in explanations and
    /// statistics but never contribute to an automatic decision — always
    /// surfaced, never acted on without the owner looking at it.
    pub advisory_only: bool,
    /// Explicit "ignore this person" — distinct from simply never having
    /// added them, since it can override a federation-level default trust
    /// (see `FederationTrustRule`) that would otherwise apply to them.
    pub excluded: bool,
    pub category_filter: Option<String>,
    /// A locally-assigned label for this federation+local_id, chosen by
    /// *this router's owner* — never a self-asserted or broadcast name.
    /// Federation-scoped, not globally unique: the same name can be
    /// reused across two different federations (they're different
    /// namespaces), and two different routers can legitimately label the
    /// same peer differently — this is an address book, not a directory
    /// requiring a registry to arbitrate collisions (the same
    /// consensus/governance work this project defers everywhere else).
    /// Enforced unique *within one federation, on this router's own
    /// view* by a partial unique index in `state-store` — see
    /// `0006_follow_display_names.sql`.
    pub display_name: Option<String>,
    pub expires_at: Option<Timestamp>,
    pub created_at: Timestamp,
}

impl LocalTrustRule {
    pub fn is_expired(&self, now: Timestamp) -> bool {
        matches!(self.expires_at, Some(exp) if exp <= now)
    }
}

/// Following an entire federation rather than named individuals — see the
/// two-mechanism split: `via_relay_full_membership = false` means "trust
/// this federation's own `FederationStatement` stream" (cheap, one thing
/// to sync); `true` means "give every member of this federation a default
/// weight" (expensive at real scale, realistically routed through a
/// relay's aggregated view rather than direct per-user sync).
#[derive(Debug, Clone, PartialEq)]
pub struct FederationTrustRule {
    pub federation: FederationId,
    pub allow_weight: f64,
    pub deny_weight: f64,
    pub via_relay_full_membership: bool,
    pub category_filter: Option<String>,
    pub expires_at: Option<Timestamp>,
    pub created_at: Timestamp,
}

impl FederationTrustRule {
    pub fn is_expired(&self, now: Timestamp) -> bool {
        matches!(self.expires_at, Some(exp) if exp <= now)
    }
}

/// Trust specific to tunnel-sharing, deliberately *separate* from
/// `LocalTrustRule` (opinion-weighting trust) — trusting someone's
/// malware opinions doesn't imply trusting them enough to auto-route
/// traffic through their infrastructure, a distinct risk profile with its
/// own dial. Three genuinely independent auto-behavior switches on the
/// same per-peer row: trusting someone enough for one doesn't imply the
/// others.
#[derive(Debug, Clone, PartialEq)]
pub struct TunnelTrustRule {
    pub user: UserId,
    /// I'll let this trusted peer use *my* tunnel automatically (auto-
    /// accept their `TunnelConnectionRequest`s).
    pub auto_accept_requests: bool,
    /// I'll automatically request/use a tunnel *this* trusted peer
    /// advertises (auto-generate a `TunnelConnectionRequest` for their
    /// `TunnelAdvertisement`s).
    pub auto_consume_advertisements: bool,
    /// When this peer publishes a `TunnelServiceRequest` (a want-ad),
    /// I'll automatically respond with a matching `TunnelAdvertisement`
    /// if I have one.
    pub auto_respond_to_service_requests: bool,
    /// Explicit, permanent "never act on anything tunnel-related from
    /// this operator automatically" — mirrors `LocalTrustRule::excluded`'s
    /// same name and meaning. Distinct from simply never having added a
    /// rule for them (which just leaves their requests pending for manual
    /// review, the neutral default). Always wins over the three flags
    /// above if somehow both are set.
    pub excluded: bool,
    /// Mirrors `LocalTrustRule.category_filter` exactly, one dimension
    /// over: if set, `auto_consume_advertisements` only fires for an
    /// advertisement whose `tags` include this one — `None` (the
    /// default) means every advertisement from this trusted provider is
    /// eligible, unchanged from before this field existed.
    pub tag_filter: Option<String>,
    /// A minimum "given / taken" volume ratio (from
    /// `state_store::StateStore::list_tunnel_balances`) this peer must
    /// maintain for `auto_accept_requests` to keep firing — the tunnel
    /// free-riding guard: bandwidth has a real cost, unlike an opinion,
    /// so a peer who only ever consumes never earns an automatic reason
    /// to keep being served. `None` (the default) means no reciprocity
    /// requirement at all, unchanged from before this field existed.
    /// This only ever downgrades an auto-accept to the same manual-review
    /// queue every untrusted request already sits in — it never revokes
    /// an existing connection retroactively, and it's checked only past a
    /// minimum absolute volume so a brand-new relationship is never
    /// flagged on noise (see `sync_tunnels`' own doc on both floors).
    pub min_reciprocity_ratio: Option<f64>,
    pub expires_at: Option<Timestamp>,
    pub created_at: Timestamp,
}

impl TunnelTrustRule {
    pub fn is_expired(&self, now: Timestamp) -> bool {
        matches!(self.expires_at, Some(exp) if exp <= now)
    }
}

/// Trust in a *group's* aggregate stance (see `crate::group`'s module
/// doc on how that's computed) — a separate dimension from
/// `LocalTrustRule`, the same way `FederationTrustRule` is: trusting a
/// group's collective decision is a distinct kind of input from trusting
/// one person's opinion, weighted independently.
#[derive(Debug, Clone, PartialEq)]
pub struct GroupTrustRule {
    pub group_id: GroupId,
    pub allow_weight: f64,
    pub deny_weight: f64,
    /// Explicit "ignore this group's aggregate stance" — same meaning as
    /// `LocalTrustRule::excluded`.
    pub excluded: bool,
    pub expires_at: Option<Timestamp>,
    pub created_at: Timestamp,
}

impl GroupTrustRule {
    pub fn is_expired(&self, now: Timestamp) -> bool {
        matches!(self.expires_at, Some(exp) if exp <= now)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ids::Hash32;

    #[test]
    fn per_user_exclusion_is_a_distinct_flag_from_absence() {
        let rule = LocalTrustRule {
            user: UserId { federation: FederationId(Hash32([0; 32])), local_id: Hash32([1; 32]) },
            allow_weight: 0.0,
            deny_weight: 0.0,
            advisory_only: false,
            excluded: true,
            category_filter: None,
            display_name: None,
            expires_at: None,
            created_at: 0,
        };
        assert!(rule.excluded);
    }

    #[test]
    fn display_name_defaults_to_none_and_can_be_set() {
        let mut rule = LocalTrustRule {
            user: UserId { federation: FederationId(Hash32([0; 32])), local_id: Hash32([1; 32]) },
            allow_weight: 1.0,
            deny_weight: 1.0,
            advisory_only: false,
            excluded: false,
            category_filter: None,
            display_name: None,
            expires_at: None,
            created_at: 0,
        };
        assert_eq!(rule.display_name, None);
        rule.display_name = Some("alice".into());
        assert_eq!(rule.display_name.as_deref(), Some("alice"));
    }

    #[test]
    fn tunnel_trust_flags_are_independent_of_each_other() {
        let rule = TunnelTrustRule {
            user: UserId { federation: FederationId(Hash32([0; 32])), local_id: Hash32([1; 32]) },
            auto_accept_requests: true,
            auto_consume_advertisements: false,
            auto_respond_to_service_requests: false,
            excluded: false,
            tag_filter: None,
            min_reciprocity_ratio: None,
            expires_at: None,
            created_at: 0,
        };
        assert!(rule.auto_accept_requests);
        assert!(!rule.auto_consume_advertisements);
        assert!(!rule.auto_respond_to_service_requests);
    }

    #[test]
    fn tunnel_trust_expiry_is_inclusive_of_the_boundary() {
        let rule = TunnelTrustRule {
            user: UserId { federation: FederationId(Hash32([0; 32])), local_id: Hash32([1; 32]) },
            auto_accept_requests: false,
            auto_consume_advertisements: false,
            auto_respond_to_service_requests: false,
            excluded: false,
            tag_filter: None,
            min_reciprocity_ratio: None,
            expires_at: Some(100),
            created_at: 0,
        };
        assert!(!rule.is_expired(99));
        assert!(rule.is_expired(100));
    }

    #[test]
    fn group_trust_expiry_is_inclusive_of_the_boundary() {
        let rule = GroupTrustRule { group_id: GroupId(Hash32([1; 32])), allow_weight: 1.0, deny_weight: 1.0, excluded: false, expires_at: Some(100), created_at: 0 };
        assert!(!rule.is_expired(99));
        assert!(rule.is_expired(100));
    }
}
