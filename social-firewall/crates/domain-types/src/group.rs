//! Owner-controlled groups: a named collection of `UserId`s with one or
//! more owners (never zero — see `Group::validate`, and note there is
//! deliberately no ownerless/distributed-group model in this project —
//! someone is always in charge) who curate membership and grant/revoke
//! each member's voting right. A group's *aggregate* stance (a simple
//! majority among its current voting members' latest votes — see
//! `GroupVote`) becomes another weighted input to `policy-engine`'s
//! trust-weighted aggregation, structurally close to what
//! `FederationStatement` already is, just owner-curated and dynamic
//! rather than governance/consensus-committed.
//!
//! **Versioning**: a group is republished *wholesale* on every membership
//! change (every current owner/admin/member, not a diff) by any current
//! owner or admin — the same "supersedes, not merges" shape
//! `SharedRuleList` already uses, for the same reason (an event log would
//! be a second design to build and audit; a full snapshot is simpler and
//! matches this project's existing convention). `sequence` is a
//! per-*group* counter (not per-author, unlike everywhere else in this
//! crate) since any current owner/admin can publish the next version, not
//! just the group's original creator.
//!
//! **Membership is request-and-approve, never open self-add** — see
//! `GroupJoinRequest`, the same signed-statement-plus-decision shape this
//! crate already uses for tunnel requests/accepts and follows.

use crate::canonical::CanonicalEncode;
use crate::ids::{Hash32, SignatureBytes, UserId};
use crate::opinion::{Reason, Stance, Timestamp};
use crate::target::TargetSelector;

/// Longest join prompt an owner can set — a prompt should be a short,
/// specific ask ("please share a contact email and why you'd like to
/// join"), not an essay attached to a signed, permanently-replicated
/// record. Mirrors `MAX_REASON_NOTE_LEN`'s reasoning at a slightly more
/// generous length, since a prompt may reasonably pose more than one
/// short question.
pub const MAX_JOIN_PROMPT_LEN: usize = 512;

/// Stable identifier for a group, constant across every version of it —
/// generated once at creation (see the CLI's `create-group`), never
/// reused. Deliberately not derived from any single owner's identity, so
/// ownership can change hands without the group changing identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct GroupId(pub Hash32);

impl CanonicalEncode for GroupId {
    fn canonical_encode(&self, out: &mut Vec<u8>) {
        self.0.canonical_encode(out);
    }
}

/// A group's full membership snapshot at a point in time. `published_by`
/// must be one of the *previous* version's owners or admins to be
/// accepted on ingest (or, for a brand-new group, one of *this* version's
/// owners) — checked by `StateStore::ingest_group`, not here, since
/// checking against the previous version requires storage access this
/// pure domain type doesn't have.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Group {
    pub group_id: GroupId,
    pub published_by: UserId,
    pub sequence: u64,
    pub name: String,
    pub description: String,
    /// An optional prompt/question the owner wants every prospective
    /// member to answer when requesting to join (e.g. "please share a
    /// contact email and why you'd like to join") — free text, no fixed
    /// question taxonomy, same convention as `description`/`limitations`
    /// elsewhere in this crate. Checked by the CLI before publishing a
    /// `GroupJoinRequest` (it looks up the group's current prompt and
    /// requires `--answer` when one is set) — not enforced at the
    /// signature/ingest level, since judging whether an answer is
    /// *adequate* is inherently the owner's call at approval time, the
    /// same manual-review posture every other pending request already
    /// gets in this project.
    pub join_prompt: Option<String>,
    /// Full control, including adding/removing other owners. Never
    /// empty — see `validate`.
    pub owners: Vec<UserId>,
    /// Can manage membership/voting rights; cannot remove an owner or
    /// dissolve the group.
    pub admins: Vec<UserId>,
    /// Members whose votes (see `GroupVote`) count toward this group's
    /// aggregate stance.
    pub voting_members: Vec<UserId>,
    /// Members who belong to the group but whose votes don't count —
    /// the owner-controlled "voting is optional" distinction.
    pub non_voting_members: Vec<UserId>,
    /// When `true`, only owners/admins and members in `voiced_members`
    /// may post to the party line — the IRC `+m` "moderated channel"
    /// analogue. `false` (the default) means any current member may
    /// post, but never a non-member — see `can_post_party_line`.
    pub party_line_moderated: bool,
    /// Explicit posting allow-list, consulted only when
    /// `party_line_moderated` is `true` — the IRC `+v` analogue. Lets an
    /// owner/admin grant a specific member (or non-voting member)
    /// posting rights on the party line without promoting them to admin
    /// or granting a vote — a third, independent dial alongside voting
    /// rights, same "trusting someone for one thing doesn't imply
    /// another" philosophy `TunnelTrustRule`'s three flags already use.
    pub voiced_members: Vec<UserId>,
    pub issued_at: Timestamp,
    pub expires_at: Option<Timestamp>,
    pub supersedes: Option<u64>,
    pub signature: SignatureBytes,
}

impl Group {
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.group_id.canonical_encode(&mut out);
        self.published_by.canonical_encode(&mut out);
        self.sequence.canonical_encode(&mut out);
        self.name.canonical_encode(&mut out);
        self.description.canonical_encode(&mut out);
        self.join_prompt.canonical_encode(&mut out);
        self.owners.canonical_encode(&mut out);
        self.admins.canonical_encode(&mut out);
        self.voting_members.canonical_encode(&mut out);
        self.non_voting_members.canonical_encode(&mut out);
        self.party_line_moderated.canonical_encode(&mut out);
        self.voiced_members.canonical_encode(&mut out);
        self.issued_at.canonical_encode(&mut out);
        self.expires_at.canonical_encode(&mut out);
        self.supersedes.canonical_encode(&mut out);
        out
    }

    pub fn is_expired(&self, now: Timestamp) -> bool {
        matches!(self.expires_at, Some(exp) if exp <= now)
    }

    /// The one hard invariant: a group can never have zero owners. There
    /// is deliberately no escape hatch (no ownerless/distributed-group
    /// mode in this project) — the last owner must transfer ownership or
    /// promote a co-owner *before* stepping down, by publishing a version
    /// that still lists at least one owner.
    pub fn validate(&self) -> Result<(), String> {
        if self.owners.is_empty() {
            return Err("a group must have at least one owner".to_string());
        }
        if let Some(prompt) = &self.join_prompt {
            if prompt.len() > MAX_JOIN_PROMPT_LEN {
                return Err(format!("join_prompt exceeds {MAX_JOIN_PROMPT_LEN} bytes"));
            }
        }
        Ok(())
    }

    pub fn is_owner(&self, user: &UserId) -> bool {
        self.owners.contains(user)
    }

    pub fn is_admin(&self, user: &UserId) -> bool {
        self.admins.contains(user)
    }

    /// Owners and admins can both manage membership/voting rights;
    /// dissolving the group or removing an owner is owner-only (enforced
    /// by `StateStore::ingest_group`, not here — this type just
    /// describes membership).
    pub fn can_manage_membership(&self, user: &UserId) -> bool {
        self.is_owner(user) || self.is_admin(user)
    }

    pub fn is_member(&self, user: &UserId) -> bool {
        self.owners.contains(user) || self.admins.contains(user) || self.voting_members.contains(user) || self.non_voting_members.contains(user)
    }

    /// Owners and admins can always post, regardless of moderation.
    /// Otherwise: an unmoderated party line (the default) is open to any
    /// current member, never a non-member; a moderated one requires
    /// explicit voice (`voiced_members`).
    pub fn can_post_party_line(&self, user: &UserId) -> bool {
        if self.is_owner(user) || self.is_admin(user) {
            return true;
        }
        if self.party_line_moderated {
            self.voiced_members.contains(user)
        } else {
            self.is_member(user)
        }
    }
}

/// A prospective member's signed request to join a group — never open
/// self-add. An owner or admin must approve it (by republishing the
/// group with the requester added) before membership takes effect;
/// nobody can add themselves unilaterally. An owner/admin reviewing a
/// pending request can also reject it outright, or block the requester
/// from the group altogether (see `StateStore::block_group_user`) — a
/// permanent decision that auto-rejects any future request from that
/// same user, rather than making the owner reject the same person every
/// time they try again.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupJoinRequest {
    pub requester: UserId,
    pub group_id: GroupId,
    pub sequence: u64,
    /// Answer to the group's `Group::join_prompt`, if it has one at the
    /// time this request is built (the CLI looks it up and requires
    /// this when set); free-form otherwise. Not enforced at ingest —
    /// whether an answer is adequate is the owner's call at approval
    /// time, same as everything else in this review flow.
    pub answer: Option<String>,
    pub issued_at: Timestamp,
    pub signature: SignatureBytes,
}

impl GroupJoinRequest {
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.requester.canonical_encode(&mut out);
        self.group_id.canonical_encode(&mut out);
        self.sequence.canonical_encode(&mut out);
        self.answer.canonical_encode(&mut out);
        self.issued_at.canonical_encode(&mut out);
        out
    }
}

/// One voting member's signed stance on a target, cast on behalf of a
/// specific group — the input `policy-engine` majority-aggregates (see
/// the module doc) into that group's collective stance for the target.
/// Only the *latest*, non-expired vote from each currently-voting member
/// counts; an old vote from someone since removed from
/// `voting_members` doesn't.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupVote {
    pub group_id: GroupId,
    pub voter: UserId,
    pub sequence: u64,
    pub target: TargetSelector,
    pub stance: Stance,
    pub reason: Reason,
    pub issued_at: Timestamp,
    pub expires_at: Option<Timestamp>,
    pub signature: SignatureBytes,
}

impl GroupVote {
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.group_id.canonical_encode(&mut out);
        self.voter.canonical_encode(&mut out);
        self.sequence.canonical_encode(&mut out);
        self.target.canonical_encode(&mut out);
        self.stance.canonical_encode(&mut out);
        self.reason.canonical_encode(&mut out);
        self.issued_at.canonical_encode(&mut out);
        self.expires_at.canonical_encode(&mut out);
        out
    }

    pub fn is_expired(&self, now: Timestamp) -> bool {
        matches!(self.expires_at, Some(exp) if exp <= now)
    }
}

/// A signed, attributable report that one router has blocked a user from
/// a group, and why — the "surfaced, not silent" half of blocking (see
/// `StateStore::block_group_user`'s own doc for the purely local
/// enforcement half this pairs with). Exported/ingested the same manual
/// way every other signed statement in this crate is. Critically,
/// *ingesting* one of these is always informational only — it never
/// causes the ingesting router to enforce anything locally, it just
/// becomes one more data point an owner or reviewer can weigh (e.g. via
/// the CLI's `explain-group-vote`, which rolls these up per voter: a
/// voter independently reported by several unrelated routers, all citing
/// the same reason, is exactly the signal an owner needs to decide
/// whether to remove that voter, without requiring any new consensus
/// machinery or automatic global ban).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupBlockReport {
    pub group_id: GroupId,
    pub reporter: UserId,
    pub sequence: u64,
    pub blocked_user: UserId,
    /// Required, not optional — a block with no reason is just an
    /// opaque veto; a block with a reason is evidence, the same
    /// distinction `Reason` already draws for `PolicyOpinion`/`GroupVote`.
    pub reason: Reason,
    pub issued_at: Timestamp,
    pub signature: SignatureBytes,
}

impl GroupBlockReport {
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.group_id.canonical_encode(&mut out);
        self.reporter.canonical_encode(&mut out);
        self.sequence.canonical_encode(&mut out);
        self.blocked_user.canonical_encode(&mut out);
        self.reason.canonical_encode(&mut out);
        self.issued_at.canonical_encode(&mut out);
        out
    }
}

/// A group-scoped broadcast — the "party line": meant for every *current*
/// member (owners/admins/voting/non-voting alike) to see, not one
/// specific recipient, a third visibility mode alongside the existing
/// `Public`/`Restricted` (which fan out to an explicit, named recipient
/// list, not a standing group). Always sealed per current member at
/// publish time (membership is a point-in-time snapshot, same as
/// `Restricted`'s explicit recipient list already is) — reuses the exact
/// same `crypto::seal` machinery, just with group membership doing the
/// recipient lookup instead of a hand-typed `--recipient` list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartyLineMessage {
    pub group_id: GroupId,
    pub author: UserId,
    pub sequence: u64,
    pub body: String,
    pub issued_at: Timestamp,
    pub signature: SignatureBytes,
}

impl PartyLineMessage {
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.group_id.canonical_encode(&mut out);
        self.author.canonical_encode(&mut out);
        self.sequence.canonical_encode(&mut out);
        self.body.canonical_encode(&mut out);
        self.issued_at.canonical_encode(&mut out);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ids::{FederationId, Hash32};
    use crate::opinion::ReasonCode;

    fn user(n: u8) -> UserId {
        UserId { federation: FederationId(Hash32([1; 32])), local_id: Hash32([n; 32]) }
    }

    fn group_id() -> GroupId {
        GroupId(Hash32([42; 32]))
    }

    fn sample_group() -> Group {
        Group {
            group_id: group_id(),
            published_by: user(1),
            sequence: 0,
            name: "neighborhood watch".into(),
            description: "local trusted operators".into(),
            join_prompt: None,
            owners: vec![user(1)],
            admins: vec![],
            voting_members: vec![user(1), user(2)],
            non_voting_members: vec![],
            party_line_moderated: false,
            voiced_members: vec![],
            issued_at: 100,
            expires_at: None,
            supersedes: None,
            signature: SignatureBytes([0; 64]),
        }
    }

    #[test]
    fn validate_rejects_zero_owners() {
        let mut g = sample_group();
        g.owners.clear();
        assert!(g.validate().is_err());
    }

    #[test]
    fn validate_accepts_at_least_one_owner() {
        assert!(sample_group().validate().is_ok());
    }

    #[test]
    fn signing_bytes_excludes_signature() {
        let mut g = sample_group();
        g.signature = SignatureBytes([9; 64]);
        assert!(!g.signing_bytes().windows(64).any(|w| w == [9u8; 64]));
    }

    #[test]
    fn signing_bytes_change_when_owners_change() {
        let a = sample_group();
        let mut b = sample_group();
        b.owners.push(user(3));
        assert_ne!(a.signing_bytes(), b.signing_bytes());
    }

    #[test]
    fn signing_bytes_change_when_join_prompt_changes() {
        let a = sample_group();
        let mut b = sample_group();
        b.join_prompt = Some("please share a contact email".into());
        assert_ne!(a.signing_bytes(), b.signing_bytes());
    }

    #[test]
    fn validate_rejects_an_oversized_join_prompt() {
        let mut g = sample_group();
        g.join_prompt = Some("x".repeat(MAX_JOIN_PROMPT_LEN + 1));
        assert!(g.validate().is_err());
    }

    #[test]
    fn validate_accepts_a_well_sized_join_prompt() {
        let mut g = sample_group();
        g.join_prompt = Some("please share a contact email".into());
        assert!(g.validate().is_ok());
    }

    #[test]
    fn signing_bytes_change_when_party_line_moderation_changes() {
        let a = sample_group();
        let mut b = sample_group();
        b.party_line_moderated = true;
        assert_ne!(a.signing_bytes(), b.signing_bytes());
    }

    #[test]
    fn signing_bytes_change_when_voiced_members_change() {
        let a = sample_group();
        let mut b = sample_group();
        b.voiced_members.push(user(2));
        assert_ne!(a.signing_bytes(), b.signing_bytes());
    }

    #[test]
    fn can_post_party_line_owner_and_admin_always_can_regardless_of_moderation() {
        let mut g = sample_group();
        g.admins.push(user(3));
        g.party_line_moderated = true;
        assert!(g.can_post_party_line(&user(1))); // owner
        assert!(g.can_post_party_line(&user(3))); // admin
    }

    #[test]
    fn can_post_party_line_unmoderated_allows_any_member_never_a_non_member() {
        let g = sample_group();
        assert!(!g.party_line_moderated);
        assert!(g.can_post_party_line(&user(2))); // plain voting member
        assert!(!g.can_post_party_line(&user(99))); // not a member at all
    }

    #[test]
    fn can_post_party_line_moderated_requires_explicit_voice() {
        let mut g = sample_group();
        g.party_line_moderated = true;
        assert!(!g.can_post_party_line(&user(2)), "a plain member without voice must not be able to post while moderated");
        g.voiced_members.push(user(2));
        assert!(g.can_post_party_line(&user(2)), "an explicitly voiced member must be able to post");
    }

    #[test]
    fn can_manage_membership_true_for_owner_and_admin_not_plain_member() {
        let mut g = sample_group();
        g.admins.push(user(3));
        assert!(g.can_manage_membership(&user(1))); // owner
        assert!(g.can_manage_membership(&user(3))); // admin
        assert!(!g.can_manage_membership(&user(2))); // plain voting member
    }

    #[test]
    fn join_request_signing_bytes_excludes_signature() {
        let req = GroupJoinRequest {
            requester: user(2),
            group_id: group_id(),
            sequence: 0,
            answer: Some("please add me".into()),
            issued_at: 100,
            signature: SignatureBytes([9; 64]),
        };
        assert!(!req.signing_bytes().windows(64).any(|w| w == [9u8; 64]));
    }

    #[test]
    fn vote_expiry_is_inclusive_of_the_boundary() {
        let vote = GroupVote {
            group_id: group_id(),
            voter: user(2),
            sequence: 0,
            target: TargetSelector::Domain("ads.example".into()),
            stance: Stance::Deny,
            reason: Reason { code: ReasonCode::Tracker, note: None, evidence: vec![] },
            issued_at: 0,
            expires_at: Some(100),
            signature: SignatureBytes([0; 64]),
        };
        assert!(!vote.is_expired(99));
        assert!(vote.is_expired(100));
    }

    #[test]
    fn block_report_signing_bytes_excludes_signature() {
        let report = GroupBlockReport {
            group_id: group_id(),
            reporter: user(1),
            sequence: 0,
            blocked_user: user(2),
            reason: Reason { code: ReasonCode::AbuseReport, note: Some("spammed the party line".into()), evidence: vec![] },
            issued_at: 100,
            signature: SignatureBytes([9; 64]),
        };
        assert!(!report.signing_bytes().windows(64).any(|w| w == [9u8; 64]));
    }

    #[test]
    fn block_report_signing_bytes_change_with_blocked_user() {
        let base = GroupBlockReport {
            group_id: group_id(),
            reporter: user(1),
            sequence: 0,
            blocked_user: user(2),
            reason: Reason { code: ReasonCode::AbuseReport, note: None, evidence: vec![] },
            issued_at: 100,
            signature: SignatureBytes([0; 64]),
        };
        let mut other = base.clone();
        other.blocked_user = user(3);
        assert_ne!(base.signing_bytes(), other.signing_bytes());
    }

    #[test]
    fn party_line_signing_bytes_change_with_body() {
        let base = PartyLineMessage { group_id: group_id(), author: user(1), sequence: 0, body: "hello".into(), issued_at: 0, signature: SignatureBytes([0; 64]) };
        let mut other = base.clone();
        other.body = "goodbye".into();
        assert_ne!(base.signing_bytes(), other.signing_bytes());
    }
}
