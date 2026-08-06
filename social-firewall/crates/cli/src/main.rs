//! `sf` — a CLI that exercises the full local flow end to end: create an
//! identity, follow other users, set local overrides, publish signed
//! opinions (optionally exporting them to a file to simulate handing them
//! to a sync/relay transport), ingest opinions exported the same way by
//! someone else, and evaluate the effective policy for a target.
//!
//! **Known simplification**: opinion export/import here is a flat JSON
//! file carrying the author's public key alongside the signature
//! (trust-on-first-ingest), not a real federation identity registry
//! lookup — that registry (and the CometBFT-backed revocation/rotation
//! state behind it) is consensus-layer work, explicitly out of scope for
//! this local-only skeleton. `sf ingest-opinion` verifies the signature
//! against the embedded key; it does not verify that the embedded key is
//! actually the one the federation has on record for that user.

mod cgi;
mod device;
mod fingerprint;
mod group;
mod list;
mod notify;
mod ntfy;
mod profile;
mod shared_policy;
mod tunnel;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use domain_types::{
    Decision, FederationId, Hash32, LocalOverride, LocalTrustRule, OpinionRef, OverrideKind,
    PolicyAction, PolicyOpinion, PublicKeyBytes, Reason, ReasonCode, SignatureBytes, Stance,
    StatementAuthor, TargetSelector, UserId,
};
use nft_enforcer::{
    ApplyResult, CommandRunner, NftablesController, NftablesControllerConfig, PolicyEntry,
    ProtectedDestinations, SystemCommandRunner,
};
use policy_engine::PolicyInputs;
use state_store::StateStore;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "sf", about = "Social firewall local-node CLI")]
struct Cli {
    /// Path to the SQLite state database (created if it doesn't exist).
    #[arg(long, global = true, default_value = "social-firewall.sqlite")]
    db: PathBuf,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Generate a new signing identity for this router and store it.
    #[command(visible_alias = "init")]
    InitIdentity {
        #[arg(long)]
        display_name: Option<String>,
    },
    /// Set or clear this node's local nickname used in party-line displays.
    #[command(visible_alias = "nick")]
    SetIdentityName {
        #[arg(long)]
        name: Option<String>,
    },
    /// Set or clear this router's local nickname for its home federation.
    #[command(visible_alias = "fed-name")]
    SetFederationName {
        #[arg(long)]
        name: Option<String>,
    },
    /// Browse every followed router and its local trust settings.
    #[command(visible_alias = "follows")]
    ListFollows,
    /// Print the compact command reference used by the chat window.
    #[command(hide = true)]
    ChatHelp,
    /// Follow another user with allow/deny trust weights.
    #[command(visible_alias = "follow")]
    AddFollow {
        #[arg(long)]
        federation: String,
        #[arg(long)]
        user: String,
        #[arg(long, default_value_t = 1.0)]
        allow_weight: f64,
        #[arg(long, default_value_t = 1.0)]
        deny_weight: f64,
        #[arg(long)]
        advisory: bool,
        #[arg(long)]
        exclude: bool,
        /// A local label for this federation+user, e.g. "alice" — your
        /// own address-book entry, not a name they broadcast. Unique
        /// within this federation only; the same name can be reused
        /// across different federations. Once set, other commands accept
        /// `--user-name` instead of the raw hex `--user`.
        #[arg(long)]
        name: Option<String>,
        /// This peer's Iroh node id, if known — enables automated
        /// delivery for statement types that have a known recipient (see
        /// docs/superpowers/specs/2026-08-04-p2p-transport-design.md).
        /// Omit if unknown; the existing manual export/ingest path is
        /// unaffected either way.
        #[arg(long)]
        iroh_node_id: Option<String>,
    },
    /// Relabel an already-followed user without touching their trust
    /// weights — omit `--name` to clear the label.
    #[command(visible_alias = "rename")]
    SetFollowName {
        #[arg(long)]
        federation: String,
        #[arg(long)]
        user: String,
        #[arg(long)]
        name: Option<String>,
    },
    /// Set or clear an already-followed user's Iroh node id for p2p delivery.
    SetFollowNodeId {
        #[arg(long)]
        federation: String,
        #[arg(long)]
        user: String,
        #[arg(long)]
        node_id: Option<String>,
    },
    /// Set or clear the optional plain-HTTP ntfy notification topic.
    SetNtfyTopic {
        #[arg(long)]
        url: Option<String>,
    },
    /// Set a reasonless, private, local-only stance for a target.
    SetOverride {
        #[arg(long)]
        target_kind: String,
        #[arg(long)]
        target_value: String,
        #[arg(long)]
        stance: String,
        #[arg(long)]
        emergency: bool,
        #[arg(long)]
        note: Option<String>,
        #[arg(long)]
        ttl_seconds: Option<i64>,
    },
    /// Publish a signed, reasoned opinion under this router's own identity.
    #[command(visible_alias = "opinion")]
    PublishOpinion {
        #[arg(long)]
        target_kind: String,
        #[arg(long)]
        target_value: String,
        #[arg(long)]
        stance: String,
        #[arg(long)]
        reason_code: String,
        #[arg(long)]
        note: Option<String>,
        #[arg(long)]
        ttl_seconds: Option<i64>,
        /// Write the signed opinion out as JSON, to hand to a sync transport.
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Ingest a signed opinion previously exported by `publish-opinion --out`.
    IngestOpinion {
        #[arg(long)]
        file: PathBuf,
    },
    /// Compute and print the effective policy decision for a target.
    #[command(visible_alias = "check")]
    EvaluateTarget {
        #[arg(long)]
        target_kind: String,
        #[arg(long)]
        target_value: String,
        #[arg(long, default_value_t = 1.0)]
        threshold: f64,
    },
    /// Evaluate every locally-known target (anything with a local
    /// override, own opinion, ingested opinion, or federation statement)
    /// and enforce the result via nftables. Intended to be cron-driven —
    /// see `social-firewall/install.sh`.
    #[command(visible_alias = "enforce")]
    Apply {
        #[arg(long, default_value_t = 1.0)]
        threshold: f64,
        /// Address or CIDR range that must never be denied/quarantined,
        /// regardless of what any decision says — repeatable. Loopback
        /// and link-local are always protected in addition to these.
        #[arg(long)]
        protect_ip: Vec<String>,
        #[arg(long, default_value = "/etc/kestrel/social-firewall/nft")]
        scratch_dir: PathBuf,
        /// Show what would change without touching nftables.
        #[arg(long)]
        dry_run: bool,
    },
    /// Publish a signed tunnel offer, scoped to specific traffic.
    OfferTunnel {
        #[arg(long)]
        description: String,
        #[arg(long)]
        limitation: Option<String>,
        /// `<kind>:<value>`, e.g. `domain:example.com` — repeatable.
        #[arg(long = "target")]
        targets: Vec<String>,
        /// Free-form discovery tag, repeatable — capped at 5, rejected
        /// (not truncated) beyond that.
        #[arg(long = "tag")]
        tags: Vec<String>,
        /// Advertised only — enforced by the *consumer's* own router
        /// against its own traffic, since the provider has no local
        /// enforcement point for someone else's outbound rate/connections.
        #[arg(long)]
        max_connections: Option<u32>,
        /// Coarse rate cap in kbit/s (kilobits/second).
        #[arg(long)]
        max_bandwidth_kbps: Option<u64>,
        #[arg(long, default_value = "public")]
        visibility: String,
        /// `<federation>/<local-id>` — repeatable, required (and only
        /// meaningful) when `--visibility restricted`.
        #[arg(long)]
        recipient: Vec<String>,
        #[arg(long)]
        in_response_to: Option<String>,
        #[arg(long)]
        out: Option<PathBuf>,
        #[arg(long)]
        out_dir: Option<PathBuf>,
    },
    /// Ingest a tunnel advertisement previously exported by `offer-tunnel --out`.
    IngestTunnelAdvertisement {
        #[arg(long)]
        file: PathBuf,
    },
    /// Browse every known tunnel advertisement.
    ListTunnels,
    /// Publish a want-ad: "I'm looking for a tunnel covering X," before
    /// any specific provider has offered one.
    RequestService {
        #[arg(long)]
        description: String,
        #[arg(long = "target")]
        targets: Vec<String>,
        #[arg(long, default_value = "public")]
        visibility: String,
        #[arg(long)]
        recipient: Vec<String>,
        #[arg(long)]
        out: Option<PathBuf>,
        #[arg(long)]
        out_dir: Option<PathBuf>,
    },
    /// Ingest a service request previously exported by `request-service --out`.
    IngestTunnelServiceRequest {
        #[arg(long)]
        file: PathBuf,
    },
    /// Browse every known tunnel service request (want-ad).
    ListPendingServiceRequests,
    /// Request to use an advertised tunnel — `<provider-fed>/<local-id>/<sequence>`.
    RequestTunnel {
        #[arg(long)]
        advertisement: String,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Ingest a connection request previously exported by `request-tunnel --out`.
    IngestTunnelRequest {
        #[arg(long)]
        file: PathBuf,
    },
    /// Browse pending tunnel connection requests awaiting review/accept.
    ListPendingTunnelRequests,
    /// Scan and post notifications for pending decisions.
    Notify,
    /// Per-peer WireGuard transfer totals: how much this router has given
    /// (provided) vs. taken (consumed) — the substrate `set-tunnel-trust
    /// --min-reciprocity-ratio` gates auto-accept on.
    TunnelBalance,
    /// Manually accept a pending connection request — `<federation>/<local-id>`
    /// plus its sequence number. Kept alongside Phase E's auto-accept.
    AcceptTunnelRequest {
        #[arg(long)]
        requester: String,
        #[arg(long)]
        sequence: u64,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Ingest a connection accept previously exported by the provider.
    IngestTunnelAccept {
        #[arg(long)]
        file: PathBuf,
    },
    /// Opt specific targets into routing through an accepted tunnel — may
    /// be a subset of what the advertisement originally offered.
    SelectTunnel {
        #[arg(long)]
        advertisement: String,
        #[arg(long = "target")]
        targets: Vec<String>,
    },
    /// Set tunnel-specific trust for a peer — a separate dimension from
    /// `add-follow`'s opinion-weighting trust.
    SetTunnelTrust {
        #[arg(long)]
        federation: String,
        /// Raw hex local_id — mutually exclusive with `--user-name`.
        #[arg(long)]
        user: Option<String>,
        /// A name previously assigned via `add-follow --name`/
        /// `set-follow-name`, within `--federation` — mutually exclusive
        /// with `--user`.
        #[arg(long)]
        user_name: Option<String>,
        #[arg(long)]
        auto_accept_requests: bool,
        #[arg(long)]
        auto_consume_advertisements: bool,
        #[arg(long)]
        auto_respond_to_service_requests: bool,
        #[arg(long)]
        exclude: bool,
        /// Restrict `--auto-consume-advertisements` to advertisements
        /// carrying this tag — omit to consider every advertisement from
        /// this trusted provider, unchanged from the default.
        #[arg(long)]
        tag_filter: Option<String>,
        /// Minimum "given / taken" volume ratio this peer must maintain
        /// (see `sf tunnel-balance`) for `--auto-accept-requests` to keep
        /// firing — omit for no reciprocity requirement, unchanged from
        /// the default. Only downgrades auto-accept to manual review,
        /// never revokes an existing tunnel.
        #[arg(long)]
        min_reciprocity_ratio: Option<f64>,
    },
    /// Reconcile tunnel state: auto-respond/auto-accept/auto-consume per
    /// `TunnelTrustRule`, then apply real WireGuard peers and routing.
    /// Intended to be cron-driven alongside `sf apply`.
    SyncTunnels {
        /// Where auto-generated advertisements/requests/accepts are
        /// exported for a human to carry to the other side.
        #[arg(long, default_value = "/etc/kestrel/social-firewall/tunnel-out")]
        out_dir: PathBuf,
        #[arg(long, default_value = "sf_tun0")]
        interface_name: String,
        #[arg(long, default_value = "/etc/kestrel/social-firewall/nft")]
        wg_scratch_dir: PathBuf,
        #[arg(long, default_value = "/etc/dnsmasq.d")]
        dnsmasq_dir: PathBuf,
        /// Show what would change without touching WireGuard/nft/dnsmasq
        /// or exporting any files.
        #[arg(long)]
        dry_run: bool,
    },
    /// Accept inbound Iroh connections and dispatch each received
    /// envelope to the same ingest path `ingest-tunnel-request`/
    /// `ingest-tunnel-accept` use for a file. Runs until the transport
    /// closes — no arguments, always uses this router's own Iroh
    /// identity (generated on first use, same as `sf init-identity`'s
    /// signing keypair).
    Listen,
    /// Retry due real-time group and party-line deliveries. Full catch-up
    /// reconciliation is intentionally deferred to the next reliability slice.
    Sync,
    /// Request missing group-scoped party-line messages from configured
    /// members with known Iroh node ids.
    SyncGroup {
        #[arg(long)]
        group: String,
    },
    /// Publish a signed, named, categorized bundle of rules for other
    /// operators to subscribe to.
    PublishList {
        #[arg(long)]
        name: String,
        #[arg(long)]
        description: String,
        /// Free-form tag, repeatable — e.g. `--category privacy --category ads`.
        #[arg(long = "category")]
        categories: Vec<String>,
        /// Path to a JSON array of `{target_kind, target_value, stance,
        /// reason_code, reason_note, reason_evidence}` objects.
        #[arg(long)]
        entries_file: PathBuf,
        #[arg(long, default_value = "public")]
        visibility: String,
        #[arg(long)]
        recipient: Vec<String>,
        #[arg(long)]
        out: Option<PathBuf>,
        #[arg(long)]
        out_dir: Option<PathBuf>,
    },
    /// Publish a signed, versioned policy whose entries can be voted on and
    /// materialized locally as firewall, route, or DNS configuration.
    PublishPolicy {
        #[arg(long)]
        policy_id: String,
        #[arg(long)]
        name: String,
        #[arg(long)]
        description: String,
        #[arg(long)]
        entries_file: PathBuf,
        #[arg(long = "category")]
        categories: Vec<String>,
        #[arg(long, default_value = "public")]
        visibility: String,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Ingest a signed shared policy exported by `publish-policy`.
    IngestPolicy {
        #[arg(long)]
        file: PathBuf,
    },
    /// Browse all locally known shared policies.
    ListPolicies,
    /// Cast a signed group vote on a shared-policy entry.
    VotePolicyEntry {
        #[arg(long)]
        policy_id: String,
        #[arg(long)]
        entry_id: String,
        #[arg(long)]
        group: String,
        #[arg(long)]
        stance: String,
        #[arg(long)]
        reason_code: String,
        #[arg(long)]
        note: Option<String>,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Explain the current group result for a shared-policy entry.
    ExplainPolicyEntry {
        #[arg(long)]
        policy_id: String,
        #[arg(long)]
        entry_id: String,
        #[arg(long)]
        group: String,
    },
    /// Ingest a signed policy vote exported by `vote-policy-entry`.
    IngestPolicyVote {
        #[arg(long)]
        file: PathBuf,
    },
    /// Publish a privacy-preserving fingerprint observation to a group.
    PublishFingerprintObservation {
        #[arg(long)]
        group: String,
        #[arg(long)]
        fingerprint_id: String,
        #[arg(long)]
        revision: u64,
        #[arg(long)]
        signal_family: String,
        #[arg(long)]
        evidence_digest: String,
        #[arg(long)]
        confidence: u8,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Publish a group-scoped comment on a fingerprint revision.
    PublishFingerprintComment {
        #[arg(long)]
        group: String,
        #[arg(long)]
        fingerprint_id: String,
        #[arg(long)]
        revision: u64,
        #[arg(long)]
        body: String,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// List observations and comments for a group-scoped fingerprint revision.
    ListFingerprint {
        #[arg(long)]
        group: String,
        #[arg(long)]
        fingerprint_id: String,
        #[arg(long)]
        revision: u64,
    },
    /// Ingest a signed fingerprint observation.
    IngestFingerprintObservation {
        #[arg(long)]
        file: PathBuf,
    },
    /// Store a manually provisioned 32-byte group fingerprint key.
    SetFingerprintKey {
        #[arg(long)]
        group: String,
        #[arg(long)]
        key_hex: String,
    },
    /// Derive a group-scoped fingerprint ID from kestreld canonical material.
    DeriveFingerprintId {
        #[arg(long)]
        group: String,
        #[arg(long)]
        material_file: PathBuf,
    },
    /// Create a local profile for selecting policy collections.
    CreateProfile {
        #[arg(long)]
        name: String,
        #[arg(long, default_value = "")]
        description: String,
    },
    /// Add a shared policy collection to a local profile.
    AddProfilePolicy {
        #[arg(long)]
        profile_id: String,
        #[arg(long)]
        policy_id: String,
    },
    /// Select the active local profile.
    SelectProfile {
        #[arg(long)]
        profile_id: String,
    },
    /// List local profiles and their selected collections.
    ListProfiles,
    /// List policy collections selected by the active local profile.
    ListActivePolicies,
    /// Report materialization status for selected policy entries.
    ListProfileEffects,
    /// Register a local route profile used by shared route actions.
    AddRouteProfile {
        #[arg(long)] name: String,
        #[arg(long)] table: u32,
        #[arg(long)] interface: String,
        #[arg(long, default_value_t = false)] enabled: bool,
        #[arg(long, default_value_t = false)] vpn: bool,
    },
    /// List local route profiles.
    ListRouteProfiles,
    /// Preview validated IP/CIDR route effects without executing route commands.
    PreviewRoutes,
    /// Ingest a shared rule list previously exported by `publish-list --out`.
    IngestList {
        #[arg(long)]
        file: PathBuf,
    },
    /// Browse every known shared rule list.
    ListSubscribedLists,
    /// Restrict which of a followed person's subscribed-list categories
    /// count toward trust-weighted aggregation — never their
    /// individually-published opinions, which are always unaffected.
    /// Requires an existing `add-follow` for this user. Omit `--category`
    /// to clear the filter (every subscribed list counts again).
    SetFollowCategoryFilter {
        #[arg(long)]
        federation: String,
        /// Raw hex local_id — mutually exclusive with `--user-name`.
        #[arg(long)]
        user: Option<String>,
        /// A name previously assigned via `add-follow --name`/
        /// `set-follow-name`, within `--federation` — mutually exclusive
        /// with `--user`.
        #[arg(long)]
        user_name: Option<String>,
        #[arg(long)]
        category: Option<String>,
    },
    /// Show which peer/federation opinions justified a currently-enforced
    /// target's decision — the snapshot `sf apply` refreshes on every
    /// successful run.
    ExplainEnforced {
        #[arg(long)]
        target_kind: String,
        #[arg(long)]
        target_value: String,
    },
    /// Browse every currently-enforced target with its contributors, all
    /// at once.
    ListEnforcedDecisions,
    /// Create a new owner-controlled group — you become its sole owner
    /// and first voting member.
    #[command(visible_alias = "group-create")]
    CreateGroup {
        #[arg(long)]
        name: String,
        #[arg(long)]
        description: String,
        /// An optional prompt/question every prospective member must
        /// answer when requesting to join (e.g. a contact email, or why
        /// they want to join). Free text, no fixed taxonomy.
        #[arg(long)]
        join_prompt: Option<String>,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Ingest a group previously exported by `create-group`/
    /// `approve-group-join`/`set-group-voting-right --out`.
    IngestGroup {
        #[arg(long)]
        file: PathBuf,
    },
    /// Browse every known group.
    #[command(visible_alias = "groups")]
    ListGroups,
    /// Ask to join a group — never open self-add; an owner/admin must
    /// approve it.
    RequestGroupJoin {
        #[arg(long)]
        group: String,
        /// Answer to the group's join prompt, if it has one — required
        /// when this router's local copy of the group has a
        /// `join_prompt` set; free-form otherwise.
        #[arg(long)]
        answer: Option<String>,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Ingest a join request previously exported by `request-group-join --out`.
    IngestGroupJoinRequest {
        #[arg(long)]
        file: PathBuf,
    },
    /// Browse pending join requests for a group you own/admin.
    ListPendingGroupJoins {
        #[arg(long)]
        group: String,
    },
    /// Tally every join-request decision this router has recorded for a
    /// group (approved/rejected/blocked/pending) — a self-audit of
    /// admission quality, most meaningful run by the group's own owner.
    GroupJoinTrackRecord {
        #[arg(long)]
        group: String,
    },
    /// Approve a pending join request — requires this router's identity
    /// to already be an owner/admin of the group.
    ApproveGroupJoin {
        #[arg(long)]
        group: String,
        #[arg(long)]
        requester: String,
        #[arg(long)]
        sequence: u64,
        /// Grant voting rights immediately; omit to add as a non-voting
        /// member (the owner-controlled "voting is optional" choice —
        /// see `set-group-voting-right` to change this later).
        #[arg(long)]
        voting: bool,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Reject a pending join request.
    RejectGroupJoin {
        #[arg(long)]
        requester: String,
        #[arg(long)]
        sequence: u64,
    },
    /// Permanently block a user from a group — unlike `reject-group-join`,
    /// this also auto-rejects any future join request from them. Requires
    /// a reason (a block with no reason is just an opaque veto), and
    /// produces a signed, exportable `GroupBlockReport` the group's owner
    /// can ingest — see `ingest-group-block-report`.
    BlockGroupUser {
        #[arg(long)]
        group: String,
        #[arg(long)]
        user: String,
        #[arg(long)]
        reason_code: String,
        #[arg(long)]
        note: Option<String>,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Reverse a previous `block-group-user`.
    UnblockGroupUser {
        #[arg(long)]
        group: String,
        #[arg(long)]
        user: String,
    },
    /// List everyone currently blocked from a group, on this router's own
    /// local judgment.
    ListBlockedGroupUsers {
        #[arg(long)]
        group: String,
    },
    /// Ingest a block report exported by `block-group-user --out` —
    /// always purely informational, never triggers local enforcement.
    IngestGroupBlockReport {
        #[arg(long)]
        file: PathBuf,
    },
    /// Show every known report (from any reporter) that a user has been
    /// blocked from a group, and why.
    ListGroupBlockReports {
        #[arg(long)]
        group: String,
        #[arg(long)]
        user: String,
    },
    /// Set (or clear, by omitting `--join-prompt`) the prompt/question
    /// every prospective member must answer to join this group.
    SetGroupJoinPrompt {
        #[arg(long)]
        group: String,
        #[arg(long)]
        join_prompt: Option<String>,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Set the IRC-style topic shown above a group's party line.
    SetGroupTopic {
        /// A canonical group ID or an exact local group name.
        #[arg(long)]
        group: String,
        #[arg(long, visible_alias = "description")]
        topic: String,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Toggle the party line between open (any member may post) and
    /// moderated (only owners/admins and voiced members may post) — the
    /// IRC `+m`/`-m` analogue.
    SetGroupPartyLineModeration {
        #[arg(long)]
        group: String,
        #[arg(long)]
        moderated: bool,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Grant or revoke a member's voice on the party line — the IRC
    /// `+v`/`-v` analogue, only consulted while moderated.
    SetGroupVoice {
        #[arg(long)]
        group: String,
        #[arg(long)]
        user: String,
        #[arg(long)]
        voiced: bool,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Grant or revoke an existing member's voting rights.
    SetGroupVotingRight {
        #[arg(long)]
        group: String,
        #[arg(long)]
        user: String,
        #[arg(long)]
        voting: bool,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Cast your vote, on behalf of a group, on a target — only counts
    /// toward the group's aggregate stance while you're a current voting
    /// member (see `set-group-trust`).
    CastGroupVote {
        #[arg(long)]
        group: String,
        #[arg(long)]
        target_kind: String,
        #[arg(long)]
        target_value: String,
        #[arg(long)]
        stance: String,
        #[arg(long)]
        reason_code: String,
        #[arg(long)]
        note: Option<String>,
        /// Gives this vote a lifespan, after which it stops counting
        /// toward the group's aggregate stance without the owner needing
        /// to remove you. Omit for a vote that never expires on its own.
        #[arg(long)]
        ttl_seconds: Option<i64>,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Ingest a vote previously exported by `cast-group-vote --out`.
    IngestGroupVote {
        #[arg(long)]
        file: PathBuf,
    },
    /// Trust a group's aggregate stance, weighting it into trust-weighted
    /// aggregation the same way a followed user or federation is.
    SetGroupTrust {
        #[arg(long)]
        group: String,
        #[arg(long, default_value_t = 1.0)]
        allow_weight: f64,
        #[arg(long, default_value_t = 1.0)]
        deny_weight: f64,
        #[arg(long)]
        exclude: bool,
    },
    /// Publish a "party line" message to every current group member —
    /// sealed per member, the same way a `Restricted` export is.
    #[command(visible_aliases = ["say", "msg"])]
    PublishPartyLine {
        /// A canonical group ID or an exact local group name.
        #[arg(long)]
        group: String,
        #[arg(long)]
        body: String,
        /// Attach this message to a specific target's poll (see
        /// `explain-group-vote`) — e.g. a comment on why you voted the
        /// way you did, or a dissenting view on someone else's vote.
        /// Requires `--re-target-value` too, or neither.
        #[arg(long, requires = "re_target_value")]
        re_target_kind: Option<String>,
        #[arg(long, requires = "re_target_kind")]
        re_target_value: Option<String>,
        #[arg(long, default_value = "/tmp/social-firewall-chat-out")]
        out_dir: PathBuf,
    },
    /// Ingest a party-line message addressed to you.
    IngestPartyLine {
        #[arg(long)]
        file: PathBuf,
    },
    /// Browse a group's party-line history.
    #[command(visible_aliases = ["history", "log"])]
    ListPartyLine {
        /// A canonical group ID or an exact local group name.
        #[arg(long)]
        group: String,
    },
    /// Show the per-voter breakdown behind a group's aggregate stance
    /// for a target — an audit view, never consumed by policy-engine.
    ExplainGroupVote {
        #[arg(long)]
        group: String,
        #[arg(long)]
        target_kind: String,
        #[arg(long)]
        target_value: String,
    },
    /// Publish a signed opinion about whether a device (by MAC address)
    /// should be trusted to join a network — advisory only, see
    /// `domain_types::device`'s module doc on the deliberate stop-short
    /// of a real kestreld join-approval bridge.
    PublishDeviceApproval {
        #[arg(long)]
        mac: String,
        #[arg(long)]
        stance: String,
        #[arg(long)]
        reason_code: String,
        #[arg(long)]
        note: Option<String>,
        /// Free-text hint only (hostname/vendor/etc.) — never matched
        /// against, purely descriptive context for a human reader.
        #[arg(long)]
        label: Option<String>,
        #[arg(long)]
        ttl_seconds: Option<i64>,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Ingest a signed device-approval opinion exported by
    /// `publish-device-approval --out`. Rejected outright unless the
    /// author is already a followed user — same flood-resistance gate as
    /// tunnel advertisements.
    IngestDeviceApproval {
        #[arg(long)]
        file: PathBuf,
    },
    /// List every known opinion (from any author) about a MAC address.
    ListDeviceApprovals {
        #[arg(long)]
        mac: String,
    },
    /// Print this router's trust-weighted aggregate stance for a MAC
    /// address — an advisory signal only, never enforced.
    EvaluateDevice {
        #[arg(long)]
        mac: String,
        #[arg(long, default_value_t = 1.0)]
        threshold: f64,
    },
    /// Serve a minimal, read-only local web dashboard (tunnels, shared
    /// rule lists, groups, device-approval opinions). Blocks forever.
    ServeDashboard {
        #[arg(long, default_value = "127.0.0.1:8787")]
        addr: String,
    },
}

fn parse_target_flag(s: &str) -> Result<(String, String)> {
    let (kind, value) = s
        .split_once(':')
        .with_context(|| format!("expected `<kind>:<value>`, got `{s}`"))?;
    Ok((kind.to_string(), value.to_string()))
}

fn main() -> Result<()> {
    if cgi::is_cgi() {
        cgi::run_cgi();
        return Ok(());
    }
    let cli = Cli::parse();
    let store = StateStore::open(&cli.db).context("opening state store")?;

    match cli.command {
        Command::InitIdentity { display_name } => init_identity(&store, display_name)?,
        Command::SetIdentityName { name } => {
            store.set_self_display_name(name.as_deref())?;
            println!(
                "identity nickname {}",
                name.map(|n| format!("set to {n}"))
                    .unwrap_or_else(|| "cleared".to_string())
            );
        }
        Command::SetFederationName { name } => {
            store.set_home_federation_display_name(name.as_deref())?;
            println!(
                "home federation nickname {}",
                name.map(|n| format!("set to {n}"))
                    .unwrap_or_else(|| "cleared".to_string())
            );
        }
        Command::ListFollows => list_follows(&store)?,
        Command::ChatHelp => print_chat_help(),
        Command::AddFollow {
            federation,
            user,
            allow_weight,
            deny_weight,
            advisory,
            exclude,
            name,
            iroh_node_id,
        } => add_follow(
            &store,
            &federation,
            &user,
            allow_weight,
            deny_weight,
            advisory,
            exclude,
            name,
            iroh_node_id,
        )?,
        Command::SetFollowName {
            federation,
            user,
            name,
        } => set_follow_name(&store, &federation, &user, name)?,
        Command::SetFollowNodeId {
            federation,
            user,
            node_id,
        } => set_follow_node_id(&store, &federation, &user, node_id)?,
        Command::SetNtfyTopic { url } => {
            store.set_ntfy_topic_url(url.as_deref())?;
            match url {
                Some(url) => println!("ntfy notifications will be pushed to {url}"),
                None => println!("ntfy push disabled"),
            }
        }
        Command::SetOverride {
            target_kind,
            target_value,
            stance,
            emergency,
            note,
            ttl_seconds,
        } => set_override(
            &store,
            &target_kind,
            &target_value,
            &stance,
            emergency,
            note,
            ttl_seconds,
        )?,
        Command::PublishOpinion {
            target_kind,
            target_value,
            stance,
            reason_code,
            note,
            ttl_seconds,
            out,
        } => publish_opinion(
            &store,
            &target_kind,
            &target_value,
            &stance,
            &reason_code,
            note,
            ttl_seconds,
            out,
        )?,
        Command::IngestOpinion { file } => ingest_opinion(&store, &file)?,
        Command::EvaluateTarget {
            target_kind,
            target_value,
            threshold,
        } => evaluate_target(&store, &target_kind, &target_value, threshold)?,
        Command::Apply {
            threshold,
            protect_ip,
            scratch_dir,
            dry_run,
        } => {
            let mut protected = ProtectedDestinations::default().with_defaults();
            for ip in &protect_ip {
                protected.add(ip).map_err(|e| anyhow::anyhow!(e))?;
            }
            apply_all(
                &store,
                &SystemCommandRunner,
                protected,
                scratch_dir,
                threshold,
                dry_run,
                now_unix(),
            )?;
            profile::apply_dns(&store, dry_run)?;
            if dry_run {
                profile::route_preview(&store)?;
            }
        }
        Command::OfferTunnel {
            description,
            limitation,
            targets,
            tags,
            max_connections,
            max_bandwidth_kbps,
            visibility,
            recipient,
            in_response_to,
            out,
            out_dir,
        } => {
            let targets = targets
                .iter()
                .map(|s| parse_target_flag(s))
                .collect::<Result<Vec<_>>>()?;
            tunnel::offer_tunnel(
                &store,
                &description,
                limitation,
                &targets,
                tags,
                max_connections,
                max_bandwidth_kbps,
                &visibility,
                &recipient,
                in_response_to,
                out,
                out_dir,
            )?
        }
        Command::IngestTunnelAdvertisement { file } => {
            tunnel::ingest_tunnel_advertisement(&store, &file)?
        }
        Command::ListTunnels => tunnel::list_tunnels(&store)?,
        Command::RequestService {
            description,
            targets,
            visibility,
            recipient,
            out,
            out_dir,
        } => {
            let targets = targets
                .iter()
                .map(|s| parse_target_flag(s))
                .collect::<Result<Vec<_>>>()?;
            tunnel::request_service(
                &store,
                &description,
                &targets,
                &visibility,
                &recipient,
                out,
                out_dir,
            )?
        }
        Command::IngestTunnelServiceRequest { file } => {
            tunnel::ingest_tunnel_service_request(&store, &file)?
        }
        Command::ListPendingServiceRequests => tunnel::list_pending_service_requests(&store)?,
        Command::RequestTunnel { advertisement, out } => {
            tunnel::request_tunnel(&store, &advertisement, out)?
        }
        Command::IngestTunnelRequest { file } => tunnel::ingest_tunnel_request(&store, &file)?,
        Command::ListPendingTunnelRequests => tunnel::list_pending_tunnel_requests(&store)?,
        Command::Notify => {
            let report = notify::notify_pending_items(&store)?;
            println!("posted {} notification(s)", report.notifications_posted);
        }
        Command::TunnelBalance => tunnel::tunnel_balance(&store)?,
        Command::AcceptTunnelRequest {
            requester,
            sequence,
            out,
        } => tunnel::accept_tunnel_request(&store, &requester, sequence, out)?,
        Command::IngestTunnelAccept { file } => tunnel::ingest_tunnel_accept(&store, &file)?,
        Command::SelectTunnel {
            advertisement,
            targets,
        } => {
            let targets = targets
                .iter()
                .map(|s| parse_target_flag(s))
                .collect::<Result<Vec<_>>>()?;
            tunnel::select_tunnel(&store, &advertisement, &targets)?
        }
        Command::SetTunnelTrust {
            federation,
            user,
            user_name,
            auto_accept_requests,
            auto_consume_advertisements,
            auto_respond_to_service_requests,
            exclude,
            tag_filter,
            min_reciprocity_ratio,
        } => {
            let target_user =
                resolve_user(&store, &federation, user.as_deref(), user_name.as_deref())?;
            tunnel::set_tunnel_trust(
                &store,
                target_user,
                auto_accept_requests,
                auto_consume_advertisements,
                auto_respond_to_service_requests,
                exclude,
                tag_filter,
                min_reciprocity_ratio,
            )?
        }
        Command::SyncTunnels {
            out_dir,
            interface_name,
            wg_scratch_dir,
            dnsmasq_dir,
            dry_run,
        } => {
            let wg_config = wg_tunnel::WgTunnelConfig {
                interface_name,
                scratch_dir: wg_scratch_dir,
                dnsmasq_dir,
                ..wg_tunnel::WgTunnelConfig::default()
            };
            let report = tunnel::sync_tunnels(
                &store,
                &wg_tunnel::SystemCommandRunner,
                &out_dir,
                wg_config,
                dry_run,
            )?;
            println!(
                "sync-tunnels: {} auto-response(s), {} auto-accept(s), {} auto-consume(s), {} peer(s) added, {} peer(s) removed",
                report.auto_responses, report.auto_accepts, report.auto_consumes, report.peers_added, report.peers_removed
            );
        }
        Command::Listen => tunnel::listen(&store)?,
        Command::Sync => group::sync_outbox(&store)?,
        Command::SyncGroup { group } => group::sync_group(&store, &group)?,
        Command::PublishList {
            name,
            description,
            categories,
            entries_file,
            visibility,
            recipient,
            out,
            out_dir,
        } => list::publish_list(
            &store,
            &name,
            &description,
            &categories,
            &entries_file,
            &visibility,
            &recipient,
            out,
            out_dir,
        )?,
        Command::IngestList { file } => list::ingest_list(&store, &file)?,
        Command::ListSubscribedLists => list::list_subscribed_lists(&store)?,
        Command::PublishPolicy {
            policy_id,
            name,
            description,
            entries_file,
            categories,
            visibility,
            out,
        } => shared_policy::publish_policy(
            &store,
            &policy_id,
            &name,
            &description,
            &entries_file,
            &categories,
            &visibility,
            out,
        )?,
        Command::IngestPolicy { file } => shared_policy::ingest_policy(&store, &file)?,
        Command::ListPolicies => shared_policy::list_policies(&store)?,
        Command::VotePolicyEntry {
            policy_id,
            entry_id,
            group,
            stance,
            reason_code,
            note,
            out,
        } => shared_policy::vote_policy_entry(
            &store,
            &policy_id,
            &entry_id,
            &group,
            &stance,
            &reason_code,
            note,
            out,
        )?,
        Command::ExplainPolicyEntry {
            policy_id,
            entry_id,
            group,
        } => shared_policy::explain_policy_entry(&store, &policy_id, &entry_id, &group)?,
        Command::IngestPolicyVote { file } => shared_policy::ingest_policy_vote(&store, &file)?,
        Command::PublishFingerprintObservation {
            group,
            fingerprint_id,
            revision,
            signal_family,
            evidence_digest,
            confidence,
            out,
        } => fingerprint::publish_observation(
            &store,
            &group,
            &fingerprint_id,
            revision,
            &signal_family,
            &evidence_digest,
            confidence,
            out,
        )?,
        Command::PublishFingerprintComment {
            group,
            fingerprint_id,
            revision,
            body,
            out,
        } => fingerprint::publish_comment(&store, &group, &fingerprint_id, revision, &body, out)?,
        Command::ListFingerprint {
            group,
            fingerprint_id,
            revision,
        } => fingerprint::list_fingerprint(&store, &group, &fingerprint_id, revision)?,
        Command::IngestFingerprintObservation { file } => {
            fingerprint::ingest_observation(&store, &file)?
        }
        Command::SetFingerprintKey { group, key_hex } => {
            fingerprint::set_group_key(&store, &group, &key_hex)?
        }
        Command::DeriveFingerprintId { group, material_file } => {
            fingerprint::derive_shared_id(&store, &group, &material_file)?
        }
        Command::CreateProfile { name, description } => {
            profile::create(&store, &name, &description)?
        }
        Command::AddProfilePolicy {
            profile_id,
            policy_id,
        } => profile::add_policy(&store, &profile_id, &policy_id)?,
        Command::SelectProfile { profile_id } => profile::select(&store, &profile_id)?,
        Command::ListProfiles => profile::list(&store)?,
        Command::ListActivePolicies => profile::list_active_policies(&store)?,
        Command::ListProfileEffects => profile::effects(&store)?,
        Command::AddRouteProfile { name, table, interface, enabled, vpn } =>
            profile::add_route_profile(&store, &name, table, &interface, enabled, vpn)?,
        Command::ListRouteProfiles => profile::list_route_profiles(&store)?,
        Command::PreviewRoutes => profile::route_preview(&store)?,
        Command::SetFollowCategoryFilter {
            federation,
            user,
            user_name,
            category,
        } => {
            let target_user =
                resolve_user(&store, &federation, user.as_deref(), user_name.as_deref())?;
            list::set_follow_category_filter(&store, target_user, category)?
        }
        Command::ExplainEnforced {
            target_kind,
            target_value,
        } => explain_enforced(&store, &target_kind, &target_value)?,
        Command::ListEnforcedDecisions => list_enforced_decisions(&store)?,
        Command::CreateGroup {
            name,
            description,
            join_prompt,
            out,
        } => group::create_group(&store, &name, &description, join_prompt, out)?,
        Command::IngestGroup { file } => group::ingest_group(&store, &file)?,
        Command::ListGroups => group::list_groups(&store)?,
        Command::RequestGroupJoin { group, answer, out } => {
            group::request_group_join(&store, &group, answer, out)?
        }
        Command::IngestGroupJoinRequest { file } => {
            group::ingest_group_join_request(&store, &file)?
        }
        Command::ListPendingGroupJoins { group } => {
            group::list_pending_group_joins(&store, &group)?
        }
        Command::GroupJoinTrackRecord { group } => group::group_join_track_record(&store, &group)?,
        Command::ApproveGroupJoin {
            group,
            requester,
            sequence,
            voting,
            out,
        } => group::approve_group_join(&store, &group, &requester, sequence, voting, out)?,
        Command::RejectGroupJoin {
            requester,
            sequence,
        } => group::reject_group_join(&store, &requester, sequence)?,
        Command::BlockGroupUser {
            group,
            user,
            reason_code,
            note,
            out,
        } => group::block_group_user(&store, &group, &user, &reason_code, note, out)?,
        Command::UnblockGroupUser { group, user } => {
            group::unblock_group_user(&store, &group, &user)?
        }
        Command::ListBlockedGroupUsers { group } => {
            group::list_blocked_group_users(&store, &group)?
        }
        Command::IngestGroupBlockReport { file } => {
            group::ingest_group_block_report(&store, &file)?
        }
        Command::ListGroupBlockReports { group, user } => {
            group::list_group_block_reports(&store, &group, &user)?
        }
        Command::SetGroupJoinPrompt {
            group,
            join_prompt,
            out,
        } => group::set_group_join_prompt(&store, &group, join_prompt, out)?,
        Command::SetGroupTopic { group, topic, out } => {
            group::set_group_topic(&store, &group, topic, out)?
        }
        Command::SetGroupPartyLineModeration {
            group,
            moderated,
            out,
        } => group::set_group_party_line_moderation(&store, &group, moderated, out)?,
        Command::SetGroupVoice {
            group,
            user,
            voiced,
            out,
        } => group::set_group_voice(&store, &group, &user, voiced, out)?,
        Command::SetGroupVotingRight {
            group,
            user,
            voting,
            out,
        } => group::set_group_voting_right(&store, &group, &user, voting, out)?,
        Command::CastGroupVote {
            group,
            target_kind,
            target_value,
            stance,
            reason_code,
            note,
            ttl_seconds,
            out,
        } => group::cast_group_vote(
            &store,
            &group,
            &target_kind,
            &target_value,
            &stance,
            &reason_code,
            note,
            ttl_seconds,
            out,
        )?,
        Command::IngestGroupVote { file } => group::ingest_group_vote(&store, &file)?,
        Command::SetGroupTrust {
            group,
            allow_weight,
            deny_weight,
            exclude,
        } => group::set_group_trust(&store, &group, allow_weight, deny_weight, exclude)?,
        Command::PublishPartyLine {
            group,
            body,
            re_target_kind,
            re_target_value,
            out_dir,
        } => {
            let in_reply_to = match (re_target_kind, re_target_value) {
                (Some(kind), Some(value)) => Some((kind, value)),
                _ => None,
            };
            group::publish_party_line(&store, &group, &body, in_reply_to, &out_dir)?
        }
        Command::IngestPartyLine { file } => group::ingest_party_line(&store, &file)?,
        Command::ListPartyLine { group } => group::list_party_line(&store, &group)?,
        Command::ExplainGroupVote {
            group,
            target_kind,
            target_value,
        } => group::explain_group_vote(&store, &group, &target_kind, &target_value)?,
        Command::PublishDeviceApproval {
            mac,
            stance,
            reason_code,
            note,
            label,
            ttl_seconds,
            out,
        } => device::publish_device_approval(
            &store,
            &mac,
            &stance,
            &reason_code,
            note,
            label,
            ttl_seconds,
            out,
        )?,
        Command::IngestDeviceApproval { file } => device::ingest_device_approval(&store, &file)?,
        Command::ListDeviceApprovals { mac } => device::list_device_approvals(&store, &mac)?,
        Command::EvaluateDevice { mac, threshold } => {
            device::evaluate_device(&store, &mac, threshold)?
        }
        Command::ServeDashboard { addr } => dashboard::serve(store, &addr)?,
    }
    Ok(())
}

fn print_contribution(c: &domain_types::Contribution) {
    println!(
        "  {} weight={:.2} stance={:?} reason={:?}",
        format_source(&c.source),
        c.weight,
        c.stance,
        c.reason.code
    );
}

fn explain_enforced(store: &StateStore, target_kind: &str, target_value: &str) -> Result<()> {
    let target = parse_target(target_kind, target_value)?;
    let contributing = store.enforced_decision_contributors_for(&target)?;
    if contributing.is_empty() {
        println!("no known contributors for {target_kind} {target_value} — either it isn't currently enforced, or its decision came from a local override/owner opinion (which has no contributing peers)");
        return Ok(());
    }
    println!("{target_kind} {target_value} is enforced because:");
    for c in &contributing {
        print_contribution(c);
    }
    Ok(())
}

fn list_enforced_decisions(store: &StateStore) -> Result<()> {
    let all = store.list_all_enforced_decision_contributors()?;
    if all.is_empty() {
        println!("no enforced targets have any recorded contributors yet — run `sf apply` first");
        return Ok(());
    }
    let mut by_target: std::collections::BTreeMap<String, Vec<domain_types::Contribution>> =
        std::collections::BTreeMap::new();
    for (target, contribution) in all {
        by_target
            .entry(format!(
                "{} {}",
                target.kind_str(),
                target_value_str(&target)
            ))
            .or_default()
            .push(contribution);
    }
    for (target_label, contributing) in by_target {
        println!("{target_label}:");
        for c in &contributing {
            print_contribution(c);
        }
    }
    Ok(())
}

/// The real `sf apply` logic, factored out so tests can pass a
/// `FakeCommandRunner` and never touch a real `nft` — same testability
/// pattern `nft-enforcer`'s own controller tests use.
fn apply_all(
    store: &StateStore,
    runner: &dyn CommandRunner,
    protected: ProtectedDestinations,
    scratch_dir: PathBuf,
    threshold: f64,
    dry_run: bool,
    now: i64,
) -> Result<()> {
    let targets = store.list_evaluatable_targets()?;
    let mut entries = Vec::new();
    // Parallel to `entries` — which peer/federation opinions justified
    // each enforced target's decision, persisted (on success) so `sf
    // explain-enforced`/`list-enforced-decisions` can answer "why is this
    // rule active" without needing to know in advance which target to
    // ask about, and without re-deriving it from scratch by hand.
    let mut contributing_by_target = Vec::new();
    let mut skipped_no_signal = 0;
    let mut skipped_unenforceable_kind = 0;
    let mut selected_policy_blocks = 0;

    // Explicitly selected policy collections are local input. Only the
    // firewall block action is materialized in this slice; other action
    // families remain reported as not yet enforceable below.
    for policy in store.list_active_shared_policies()? {
        for policy_entry in policy.entries {
            if let PolicyAction::Block = policy_entry.action {
                selected_policy_blocks += 1;
                if matches!(
                    policy_entry.target,
                    TargetSelector::Ip(_) | TargetSelector::Cidr(_)
                ) {
                    entries.push(PolicyEntry {
                        target: policy_entry.target,
                        decision: Decision::Deny,
                    });
                } else {
                    skipped_unenforceable_kind += 1;
                }
            }
        }
    }

    for target in &targets {
        let local_overrides = store.get_local_overrides_for(target)?;
        let own_opinions = store.list_own_opinions_for(target)?;
        let followed_opinions = store.list_followed_opinions_for(target)?;
        let list_entries = store.list_entries_for(target, now)?;
        let group_contributions = store.list_group_contributions_for(target, now)?;
        let federation_statements = store.list_federation_statements_for(target)?;
        let inputs = PolicyInputs {
            target: target.clone(),
            local_overrides: &local_overrides,
            own_opinions: &own_opinions,
            followed_opinions: &followed_opinions,
            list_entries: &list_entries,
            group_contributions: &group_contributions,
            federation_statements: &federation_statements,
            threshold,
            now,
        };
        let result = policy_engine::evaluate(&inputs);

        if !matches!(result.decision, Decision::Deny | Decision::Ask) {
            skipped_no_signal += 1;
            continue;
        }
        if !matches!(target, TargetSelector::Ip(_) | TargetSelector::Cidr(_)) {
            // Domain/domain-suffix/service targets are recorded but not
            // yet enforceable — see nft-enforcer's own module doc.
            // Passing one to compile() would reject the *entire* batch
            // (`CompileError::UnsupportedTarget`), not just this entry, so
            // it's filtered out here rather than left for compile() to
            // reject.
            skipped_unenforceable_kind += 1;
            continue;
        }
        if !result.explanation.contributing.is_empty() {
            contributing_by_target.push((target.clone(), result.explanation.contributing.clone()));
        }
        entries.push(PolicyEntry {
            target: target.clone(),
            decision: result.decision,
        });
    }

    println!(
        "evaluated {} target(s): {} selected policy block(s), {} to enforce, {} allow/no-decision, {} not yet enforceable (domain/service or pending action backend)",
        targets.len(),
        selected_policy_blocks,
        entries.len(),
        skipped_no_signal,
        skipped_unenforceable_kind
    );

    let config = NftablesControllerConfig {
        protected,
        scratch_dir,
        ..NftablesControllerConfig::default()
    };
    let ctrl = NftablesController::new(runner, store, config);

    if dry_run {
        let report = ctrl.dry_run(&entries)?;
        println!("would_apply: {}", report.would_apply);
        println!("previous_digest: {:?}", report.previous_digest);
        println!("new_digest: {}", report.compiled.digest);
        println!("deny_v4: {:?}", report.compiled.deny_v4);
        println!("deny_v6: {:?}", report.compiled.deny_v6);
        println!("quarantine_v4: {:?}", report.compiled.quarantine_v4);
        println!("quarantine_v6: {:?}", report.compiled.quarantine_v6);
        return Ok(());
    }

    match ctrl.apply(&entries, now)? {
        ApplyResult::NoChange { digest } => {
            println!("no change (digest {digest})");
            refresh_enforced_decision_contributors(store, &contributing_by_target)?;
        }
        ApplyResult::Applied { digest, revision } => {
            println!("applied (digest {digest}, revision {revision})");
            refresh_enforced_decision_contributors(store, &contributing_by_target)?;
        }
        ApplyResult::Rejected { reason } => bail!("policy rejected before enforcement: {reason}"),
        ApplyResult::Failed { reason, rollback } => {
            bail!("apply failed: {reason} (rollback: {rollback:?})")
        }
    }
    Ok(())
}

/// Wholesale-replaces the "why is this rule active" snapshot — only
/// called after a *successful* apply (`NoChange` or `Applied`), never on
/// `Rejected`/`Failed`, so this data always reflects what's actually
/// live rather than an evaluation that never took effect. Refreshed on
/// `NoChange` too, not just `Applied`: the compiled nft digest can stay
/// identical while the underlying weighted inputs shift (a follow's
/// weight changed, an opinion expired) without the Allow/Deny/Ask
/// decision itself changing.
fn refresh_enforced_decision_contributors(
    store: &StateStore,
    contributing_by_target: &[(TargetSelector, Vec<domain_types::Contribution>)],
) -> Result<()> {
    store.clear_enforced_decision_contributors()?;
    for (target, contributing) in contributing_by_target {
        store.record_enforced_decision_contributors(target, contributing)?;
    }
    Ok(())
}

fn init_identity(store: &StateStore, display_name: Option<String>) -> Result<()> {
    if store.get_self_identity()?.is_some() {
        bail!("an identity already exists in this database — refusing to overwrite it");
    }
    let kp = crypto::Keypair::generate();
    let pubkey = kp.public_key();
    let federation_id = FederationId(crypto::hash(
        &[b"sf-genesis-v1".as_slice(), &pubkey.0].concat(),
    ));
    let local_id = crypto::hash(&[b"sf-local-id-v1".as_slice(), &pubkey.0].concat());
    let user = UserId {
        federation: federation_id,
        local_id,
    };

    store.set_self_identity(user, pubkey, &kp.seed_bytes(), display_name.as_deref())?;
    group::create_self_group(store, user, &pubkey)?;

    println!("identity created");
    println!("  federation : {}", federation_id.0);
    println!("  local_id   : {}", local_id);
    println!("  public_key : {}", hex::encode(pubkey.0));
    println!("share federation + local_id + public_key with people who want to follow you.");
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn add_follow(
    store: &StateStore,
    federation: &str,
    user: &str,
    allow_weight: f64,
    deny_weight: f64,
    advisory: bool,
    exclude: bool,
    name: Option<String>,
    iroh_node_id: Option<String>,
) -> Result<()> {
    let federation = FederationId(parse_hash32(federation)?);
    let local_id = parse_hash32(user)?;
    let rule = LocalTrustRule {
        user: UserId {
            federation,
            local_id,
        },
        allow_weight,
        deny_weight,
        advisory_only: advisory,
        excluded: exclude,
        category_filter: None,
        display_name: name,
        iroh_node_id,
        expires_at: None,
        created_at: now_unix(),
    };
    store.upsert_follow(&rule)?;
    println!("now following {}/{}", federation.0, local_id);
    Ok(())
}

fn list_follows(store: &StateStore) -> Result<()> {
    let follows = store.list_follows()?;
    if follows.is_empty() {
        println!("no followed routers");
        return Ok(());
    }
    for follow in follows {
        let label = follow
            .display_name
            .unwrap_or_else(|| follow.user.local_id.to_string()[..8].to_string());
        let mut flags = Vec::new();
        if follow.advisory_only {
            flags.push("advisory");
        }
        if follow.excluded {
            flags.push("excluded");
        }
        let suffix = if flags.is_empty() {
            String::new()
        } else {
            format!(" [{}]", flags.join(", "))
        };
        println!(
            "{label} ({}@{}) allow={} deny={}{}",
            follow.user.local_id.to_string()[..8].to_string(),
            follow.user.federation.0.to_string()[..8].to_string(),
            follow.allow_weight,
            follow.deny_weight,
            suffix
        );
    }
    Ok(())
}

fn print_chat_help() {
    println!("chat commands:");
    println!("  /nick [name]       set or clear your nickname");
    println!("  /join <group>      request to join a group");
    println!("  /list              list known groups");
    println!("  /names             list known groups and members");
    println!("  /topic [text]      show or set this group's topic");
    println!("  /msg <text>        send a party-line message");
    println!("  /me <action>       send an IRC-style action");
    println!("  /history           show this group's timeline");
    println!("  /help              show this reference");
    println!("  text               send text to this group");
    println!();
    println!("Full `sf` commands can also be entered after the leading slash.");
}

/// Relabels an already-followed user without touching their trust
/// weights/exclude flag — `upsert_follow` requires the full row, so this
/// reads the existing one first and bails with a clear error if it
/// doesn't exist yet, rather than silently creating a zero-weight follow
/// out of a rename command.
fn set_follow_name(
    store: &StateStore,
    federation: &str,
    user: &str,
    name: Option<String>,
) -> Result<()> {
    let target_user = UserId {
        federation: FederationId(parse_hash32(federation)?),
        local_id: parse_hash32(user)?,
    };
    let mut rule = store
        .get_follow(&target_user)?
        .context("not following this user yet — run `add-follow` first")?;
    rule.display_name = name.clone();
    store.upsert_follow(&rule)?;
    match name {
        Some(n) => println!(
            "{}/{} is now labeled \"{n}\"",
            target_user.federation.0, target_user.local_id
        ),
        None => println!(
            "label cleared for {}/{}",
            target_user.federation.0, target_user.local_id
        ),
    }
    Ok(())
}

fn set_follow_node_id(
    store: &StateStore,
    federation: &str,
    user: &str,
    node_id: Option<String>,
) -> Result<()> {
    let target_user = UserId {
        federation: FederationId(parse_hash32(federation)?),
        local_id: parse_hash32(user)?,
    };
    let mut rule = store
        .get_follow(&target_user)?
        .context("not following this user yet — run `add-follow` first")?;
    rule.iroh_node_id = node_id.clone();
    store.upsert_follow(&rule)?;
    match node_id {
        Some(id) => println!(
            "{}/{} is now reachable via Iroh node {id}",
            target_user.federation.0, target_user.local_id
        ),
        None => println!(
            "Iroh node id cleared for {}/{}",
            target_user.federation.0, target_user.local_id
        ),
    }
    Ok(())
}

/// Resolves either a raw hex `--user` or a locally-assigned `--user-name`
/// (mutually exclusive, `--user-name` requires an existing named follow
/// in this federation) to a `UserId` — the shared lookup behind every
/// command that accepts both forms.
pub(crate) fn resolve_user(
    store: &StateStore,
    federation: &str,
    user: Option<&str>,
    user_name: Option<&str>,
) -> Result<UserId> {
    let federation_id = FederationId(parse_hash32(federation)?);
    match (user, user_name) {
        (Some(_), Some(_)) => bail!("pass either --user or --user-name, not both"),
        (Some(hex), None) => Ok(UserId {
            federation: federation_id,
            local_id: parse_hash32(hex)?,
        }),
        (None, Some(name)) => store
            .resolve_user_by_name(&federation_id, name)?
            .with_context(|| {
                format!(
                    "no follow named \"{name}\" in federation {}",
                    federation_id.0
                )
            }),
        (None, None) => bail!("pass either --user or --user-name"),
    }
}

fn set_override(
    store: &StateStore,
    target_kind: &str,
    target_value: &str,
    stance: &str,
    emergency: bool,
    note: Option<String>,
    ttl_seconds: Option<i64>,
) -> Result<()> {
    let target = parse_target(target_kind, target_value)?;
    let now = now_unix();
    let o = LocalOverride {
        target,
        stance: parse_stance(stance)?,
        kind: if emergency {
            OverrideKind::Emergency
        } else {
            OverrideKind::Normal
        },
        note,
        created_at: now,
        expires_at: ttl_seconds.map(|s| now + s),
    };
    store.set_local_override(&o)?;
    println!(
        "local override set: {} {} -> {:?}",
        target_kind, target_value, o.stance
    );
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn publish_opinion(
    store: &StateStore,
    target_kind: &str,
    target_value: &str,
    stance: &str,
    reason_code: &str,
    note: Option<String>,
    ttl_seconds: Option<i64>,
    out: Option<PathBuf>,
) -> Result<()> {
    let (author, seed) = match (store.get_self_identity()?, store.get_self_seed()?) {
        (Some((user, _)), Some(seed)) => (user, seed),
        _ => bail!("no identity yet — run `sf init-identity` first"),
    };
    let kp = crypto::Keypair::from_seed(&seed);
    let target = parse_target(target_kind, target_value)?;
    let now = now_unix();
    let sequence = store.next_own_sequence()?;

    let mut opinion = PolicyOpinion {
        author,
        sequence,
        target,
        stance: parse_stance(stance)?,
        reason: Reason {
            code: parse_reason_code(reason_code)?,
            note,
            evidence: vec![],
        },
        issued_at: now,
        expires_at: ttl_seconds.map(|s| now + s),
        supersedes: None,
        signature: SignatureBytes([0; 64]),
    };
    let signing_bytes = opinion.signing_bytes();
    opinion.signature = kp.sign(crypto::contexts::POLICY_OPINION, &signing_bytes);

    store.append_own_opinion(&opinion)?;
    println!(
        "published opinion #{sequence}: {target_kind} {target_value} -> {:?}",
        opinion.stance
    );

    if let Some(path) = out {
        let pubkey = kp.public_key();
        let json = opinion_to_json(&opinion, &pubkey);
        std::fs::write(&path, serde_json::to_string_pretty(&json)?)
            .with_context(|| format!("writing {}", path.display()))?;
        println!("exported to {}", path.display());
    }
    Ok(())
}

fn ingest_opinion(store: &StateStore, file: &PathBuf) -> Result<()> {
    let text =
        std::fs::read_to_string(file).with_context(|| format!("reading {}", file.display()))?;
    let json: serde_json::Value = serde_json::from_str(&text)?;
    let (opinion, pubkey) = opinion_from_json(&json)?;

    crypto::verify(
        &pubkey,
        crypto::contexts::POLICY_OPINION,
        &opinion.signing_bytes(),
        &opinion.signature,
    )
    .map_err(|_| anyhow::anyhow!("signature verification failed — refusing to ingest"))?;

    store.ingest_opinion(&opinion)?;
    println!(
        "ingested opinion #{} from {}/{}: {:?}",
        opinion.sequence, opinion.author.federation.0, opinion.author.local_id, opinion.stance
    );
    Ok(())
}

fn evaluate_target(
    store: &StateStore,
    target_kind: &str,
    target_value: &str,
    threshold: f64,
) -> Result<()> {
    let target = parse_target(target_kind, target_value)?;
    let now = now_unix();

    let local_overrides = store.get_local_overrides_for(&target)?;
    let own_opinions = store.list_own_opinions_for(&target)?;
    let followed_opinions = store.list_followed_opinions_for(&target)?;
    let list_entries = store.list_entries_for(&target, now)?;
    let group_contributions = store.list_group_contributions_for(&target, now)?;
    let federation_statements = store.list_federation_statements_for(&target)?;

    let inputs = PolicyInputs {
        target: target.clone(),
        local_overrides: &local_overrides,
        own_opinions: &own_opinions,
        followed_opinions: &followed_opinions,
        list_entries: &list_entries,
        group_contributions: &group_contributions,
        federation_statements: &federation_statements,
        threshold,
        now,
    };
    let result = policy_engine::evaluate(&inputs);

    println!("target     : {target_kind} {target_value}");
    println!("decision   : {:?}", result.decision);
    println!("tier       : {:?}", result.explanation.tier);
    println!(
        "allow/deny : {:.2} / {:.2} (threshold {:.2})",
        result.explanation.allow_weight_total,
        result.explanation.deny_weight_total,
        result.explanation.threshold
    );
    if !result.explanation.contributing.is_empty() {
        println!("contributing:");
        for c in &result.explanation.contributing {
            println!(
                "  {} weight={:.2} stance={:?} reason={:?}",
                format_source(&c.source),
                c.weight,
                c.stance,
                c.reason.code
            );
        }
    }
    if !result.explanation.ignored.is_empty() {
        println!("ignored:");
        for i in &result.explanation.ignored {
            println!(
                "  {} stance={:?} why={:?}",
                format_source(&i.source),
                i.stance,
                i.why
            );
        }
    }
    Ok(())
}

// ── JSON export/import for opinions (sync simulation) ───────────────────

fn opinion_to_json(o: &PolicyOpinion, pubkey: &PublicKeyBytes) -> serde_json::Value {
    serde_json::json!({
        "author_federation": o.author.federation.0.to_string(),
        "author_local_id": o.author.local_id.to_string(),
        "author_pubkey": hex::encode(pubkey.0),
        "sequence": o.sequence,
        "target_kind": o.target.kind_str(),
        "target_value": target_value_str(&o.target),
        "stance": stance_str(o.stance),
        "reason_code": reason_code_str(o.reason.code),
        "reason_note": o.reason.note,
        "reason_evidence": o.reason.evidence.iter().map(|h| h.to_string()).collect::<Vec<_>>(),
        "issued_at": o.issued_at,
        "expires_at": o.expires_at,
        "supersedes_sequence": o.supersedes.map(|s| s.sequence),
        "signature": hex::encode(o.signature.0),
    })
}

fn opinion_from_json(json: &serde_json::Value) -> Result<(PolicyOpinion, PublicKeyBytes)> {
    let get_str = |key: &str| -> Result<&str> {
        json.get(key)
            .and_then(|v| v.as_str())
            .with_context(|| format!("missing/invalid field `{key}`"))
    };
    let federation = FederationId(parse_hash32(get_str("author_federation")?)?);
    let local_id = parse_hash32(get_str("author_local_id")?)?;
    let pubkey_bytes = hex::decode(get_str("author_pubkey")?)?;
    let pubkey = PublicKeyBytes(
        pubkey_bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("author_pubkey must be 32 bytes"))?,
    );

    let sequence = json
        .get("sequence")
        .and_then(|v| v.as_u64())
        .context("missing `sequence`")?;
    let target = parse_target(get_str("target_kind")?, get_str("target_value")?)?;
    let stance = parse_stance(get_str("stance")?)?;
    let reason_code = parse_reason_code(get_str("reason_code")?)?;
    let reason_note = json
        .get("reason_note")
        .and_then(|v| v.as_str())
        .map(String::from);
    let reason_evidence = json
        .get("reason_evidence")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str())
                .map(parse_hash32)
                .collect::<Result<Vec<_>>>()
        })
        .transpose()?
        .unwrap_or_default();
    let issued_at = json
        .get("issued_at")
        .and_then(|v| v.as_i64())
        .context("missing `issued_at`")?;
    let expires_at = json.get("expires_at").and_then(|v| v.as_i64());
    let supersedes_sequence = json.get("supersedes_sequence").and_then(|v| v.as_u64());
    let signature_bytes = hex::decode(get_str("signature")?)?;
    let signature = SignatureBytes(
        signature_bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("signature must be 64 bytes"))?,
    );

    let author = UserId {
        federation,
        local_id,
    };
    let opinion = PolicyOpinion {
        author,
        sequence,
        target,
        stance,
        reason: Reason {
            code: reason_code,
            note: reason_note,
            evidence: reason_evidence,
        },
        issued_at,
        expires_at,
        supersedes: supersedes_sequence.map(|s| OpinionRef {
            author,
            sequence: s,
        }),
        signature,
    };
    Ok((opinion, pubkey))
}

fn format_source(source: &StatementAuthor) -> String {
    match source {
        StatementAuthor::User(u) => format!("user {}/{}", u.federation.0, u.local_id),
        StatementAuthor::Federation(f) => format!("federation {}", f.0),
        StatementAuthor::Group(g) => format!("group {}", g.0),
    }
}

pub(crate) fn target_value_str(target: &TargetSelector) -> String {
    match target {
        TargetSelector::Domain(s)
        | TargetSelector::DomainSuffix(s)
        | TargetSelector::Ip(s)
        | TargetSelector::Cidr(s)
        | TargetSelector::Service(s) => s.clone(),
        TargetSelector::ProtoPort { .. } => String::new(),
    }
}

pub(crate) fn stance_str(s: Stance) -> &'static str {
    match s {
        Stance::Allow => "allow",
        Stance::Deny => "deny",
        Stance::Ask => "ask",
    }
}

pub(crate) fn parse_stance(s: &str) -> Result<Stance> {
    match s.to_ascii_lowercase().as_str() {
        "allow" => Ok(Stance::Allow),
        "deny" => Ok(Stance::Deny),
        "ask" => Ok(Stance::Ask),
        other => bail!("invalid stance `{other}` — expected allow|deny|ask"),
    }
}

pub(crate) fn reason_code_str(c: ReasonCode) -> &'static str {
    match c {
        ReasonCode::Malware => "malware",
        ReasonCode::Phishing => "phishing",
        ReasonCode::Tracker => "tracker",
        ReasonCode::Surveillance => "surveillance",
        ReasonCode::AbusiveContent => "abusive_content",
        ReasonCode::KnownGoodCdn => "known_good_cdn",
        ReasonCode::KnownGoodService => "known_good_service",
        ReasonCode::PersonalPreference => "personal_preference",
        ReasonCode::AbuseReport => "abuse_report",
        ReasonCode::Other => "other",
    }
}

pub(crate) fn parse_reason_code(s: &str) -> Result<ReasonCode> {
    match s.to_ascii_lowercase().as_str() {
        "malware" => Ok(ReasonCode::Malware),
        "phishing" => Ok(ReasonCode::Phishing),
        "tracker" => Ok(ReasonCode::Tracker),
        "surveillance" => Ok(ReasonCode::Surveillance),
        "abusive_content" => Ok(ReasonCode::AbusiveContent),
        "known_good_cdn" => Ok(ReasonCode::KnownGoodCdn),
        "known_good_service" => Ok(ReasonCode::KnownGoodService),
        "personal_preference" => Ok(ReasonCode::PersonalPreference),
        "abuse_report" => Ok(ReasonCode::AbuseReport),
        "other" => Ok(ReasonCode::Other),
        other => bail!("invalid reason code `{other}`"),
    }
}

pub(crate) fn parse_target(kind: &str, value: &str) -> Result<TargetSelector> {
    match kind.to_ascii_lowercase().as_str() {
        "domain" => Ok(TargetSelector::Domain(value.to_string())),
        "domain_suffix" => Ok(TargetSelector::DomainSuffix(value.to_string())),
        "ip" => Ok(TargetSelector::Ip(value.to_string())),
        "cidr" => Ok(TargetSelector::Cidr(value.to_string())),
        "service" => Ok(TargetSelector::Service(value.to_string())),
        other => {
            bail!("invalid target kind `{other}` — expected domain|domain_suffix|ip|cidr|service")
        }
    }
}

pub(crate) fn parse_hash32(s: &str) -> Result<Hash32> {
    let bytes = hex::decode(s).with_context(|| format!("`{s}` is not valid hex"))?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("`{s}` must decode to exactly 32 bytes"))?;
    Ok(Hash32(arr))
}

pub(crate) fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod apply_all_tests {
    use super::*;
    use nft_enforcer::FakeCommandRunner;

    fn store() -> StateStore {
        StateStore::open_in_memory().unwrap()
    }

    #[test]
    fn a_denied_ip_target_is_enforced() {
        let store = store();
        store
            .set_local_override(&LocalOverride {
                target: TargetSelector::Ip("203.0.113.9".into()),
                stance: Stance::Deny,
                kind: OverrideKind::Normal,
                note: None,
                created_at: 1,
                expires_at: None,
            })
            .unwrap();
        let runner = FakeCommandRunner::new_all_success();
        let dir = tempfile::tempdir().unwrap();

        apply_all(
            &store,
            &runner,
            ProtectedDestinations::default().with_defaults(),
            dir.path().to_path_buf(),
            1.0,
            false,
            1000,
        )
        .unwrap();

        assert!(
            runner.call_count() > 0,
            "an enforceable Deny target must actually reach nft"
        );
        assert!(store
            .get_applied_ruleset()
            .unwrap()
            .unwrap()
            .ruleset_text
            .contains("203.0.113.9"));
    }

    #[test]
    fn a_denied_domain_target_is_skipped_not_rejected() {
        let store = store();
        store
            .set_local_override(&LocalOverride {
                target: TargetSelector::Domain("ads.example".into()),
                stance: Stance::Deny,
                kind: OverrideKind::Normal,
                note: None,
                created_at: 1,
                expires_at: None,
            })
            .unwrap();
        let runner = FakeCommandRunner::new_all_success();
        let dir = tempfile::tempdir().unwrap();

        // Must succeed (not bail on CompileError::UnsupportedTarget) —
        // domain targets are filtered out before reaching nft-enforcer,
        // not passed through and rejected.
        apply_all(
            &store,
            &runner,
            ProtectedDestinations::default().with_defaults(),
            dir.path().to_path_buf(),
            1.0,
            false,
            1000,
        )
        .unwrap();
    }

    #[test]
    fn an_allowed_target_is_never_compiled_into_a_deny_entry() {
        let store = store();
        store
            .set_local_override(&LocalOverride {
                target: TargetSelector::Ip("203.0.113.9".into()),
                stance: Stance::Allow,
                kind: OverrideKind::Normal,
                note: None,
                created_at: 1,
                expires_at: None,
            })
            .unwrap();
        let runner = FakeCommandRunner::new_all_success();
        let dir = tempfile::tempdir().unwrap();

        // The very first apply still establishes the (empty) table for
        // real, so this isn't a zero-nft-calls assertion — the meaningful
        // check is that the allowed address never ends up in a deny set.
        apply_all(
            &store,
            &runner,
            ProtectedDestinations::default().with_defaults(),
            dir.path().to_path_buf(),
            1.0,
            false,
            1000,
        )
        .unwrap();
        assert!(!store
            .get_applied_ruleset()
            .unwrap()
            .unwrap()
            .ruleset_text
            .contains("203.0.113.9"));
    }

    #[test]
    fn dry_run_never_touches_the_runner() {
        let store = store();
        store
            .set_local_override(&LocalOverride {
                target: TargetSelector::Ip("203.0.113.9".into()),
                stance: Stance::Deny,
                kind: OverrideKind::Normal,
                note: None,
                created_at: 1,
                expires_at: None,
            })
            .unwrap();
        let runner = FakeCommandRunner::new_all_success();
        let dir = tempfile::tempdir().unwrap();

        apply_all(
            &store,
            &runner,
            ProtectedDestinations::default().with_defaults(),
            dir.path().to_path_buf(),
            1.0,
            true,
            1000,
        )
        .unwrap();

        assert_eq!(runner.call_count(), 0, "dry-run must never call nft");
        assert!(store.get_applied_ruleset().unwrap().is_none());
    }

    #[test]
    fn reapplying_unchanged_state_is_a_no_op() {
        let store = store();
        store
            .set_local_override(&LocalOverride {
                target: TargetSelector::Ip("203.0.113.9".into()),
                stance: Stance::Deny,
                kind: OverrideKind::Normal,
                note: None,
                created_at: 1,
                expires_at: None,
            })
            .unwrap();
        let runner = FakeCommandRunner::new_all_success();
        let dir = tempfile::tempdir().unwrap();

        apply_all(
            &store,
            &runner,
            ProtectedDestinations::default().with_defaults(),
            dir.path().to_path_buf(),
            1.0,
            false,
            1000,
        )
        .unwrap();
        let calls_after_first = runner.call_count();
        apply_all(
            &store,
            &runner,
            ProtectedDestinations::default().with_defaults(),
            dir.path().to_path_buf(),
            1.0,
            false,
            2000,
        )
        .unwrap();

        assert_eq!(
            runner.call_count(),
            calls_after_first,
            "identical state must not issue further nft calls on a second run"
        );
    }

    #[test]
    fn apply_records_contributors_for_a_trust_weighted_enforced_target() {
        let store = store();
        let alice = UserId {
            federation: FederationId(Hash32([1; 32])),
            local_id: Hash32([2; 32]),
        };
        store
            .upsert_follow(&LocalTrustRule {
                user: alice,
                allow_weight: 1.0,
                deny_weight: 1.0,
                advisory_only: false,
                excluded: false,
                category_filter: None,
                display_name: None,
                iroh_node_id: None,
                expires_at: None,
                created_at: 0,
            })
            .unwrap();
        store
            .ingest_opinion(&PolicyOpinion {
                author: alice,
                sequence: 0,
                target: TargetSelector::Ip("203.0.113.9".into()),
                stance: Stance::Deny,
                reason: Reason {
                    code: ReasonCode::Malware,
                    note: None,
                    evidence: vec![],
                },
                issued_at: 0,
                expires_at: None,
                supersedes: None,
                signature: SignatureBytes([0; 64]),
            })
            .unwrap();
        let runner = FakeCommandRunner::new_all_success();
        let dir = tempfile::tempdir().unwrap();

        apply_all(
            &store,
            &runner,
            ProtectedDestinations::default().with_defaults(),
            dir.path().to_path_buf(),
            1.0,
            false,
            1000,
        )
        .unwrap();

        let contributing = store
            .enforced_decision_contributors_for(&TargetSelector::Ip("203.0.113.9".into()))
            .unwrap();
        assert_eq!(contributing.len(), 1);
        assert_eq!(contributing[0].source, StatementAuthor::User(alice));
        assert_eq!(contributing[0].stance, Stance::Deny);
    }

    #[test]
    fn apply_never_records_contributors_for_a_local_override_decision() {
        // `LocalOverride`/owner-opinion tiers never populate `contributing`
        // — a local override beats everyone else precisely because it
        // doesn't need anyone else's agreement, so there's nothing to
        // attribute.
        let store = store();
        store
            .set_local_override(&LocalOverride {
                target: TargetSelector::Ip("203.0.113.9".into()),
                stance: Stance::Deny,
                kind: OverrideKind::Normal,
                note: None,
                created_at: 1,
                expires_at: None,
            })
            .unwrap();
        let runner = FakeCommandRunner::new_all_success();
        let dir = tempfile::tempdir().unwrap();

        apply_all(
            &store,
            &runner,
            ProtectedDestinations::default().with_defaults(),
            dir.path().to_path_buf(),
            1.0,
            false,
            1000,
        )
        .unwrap();

        assert!(store
            .enforced_decision_contributors_for(&TargetSelector::Ip("203.0.113.9".into()))
            .unwrap()
            .is_empty());
    }

    #[test]
    fn apply_dry_run_never_touches_the_contributor_snapshot() {
        let store = store();
        let alice = UserId {
            federation: FederationId(Hash32([1; 32])),
            local_id: Hash32([2; 32]),
        };
        store
            .upsert_follow(&LocalTrustRule {
                user: alice,
                allow_weight: 1.0,
                deny_weight: 1.0,
                advisory_only: false,
                excluded: false,
                category_filter: None,
                display_name: None,
                iroh_node_id: None,
                expires_at: None,
                created_at: 0,
            })
            .unwrap();
        store
            .ingest_opinion(&PolicyOpinion {
                author: alice,
                sequence: 0,
                target: TargetSelector::Ip("203.0.113.9".into()),
                stance: Stance::Deny,
                reason: Reason {
                    code: ReasonCode::Malware,
                    note: None,
                    evidence: vec![],
                },
                issued_at: 0,
                expires_at: None,
                supersedes: None,
                signature: SignatureBytes([0; 64]),
            })
            .unwrap();
        let runner = FakeCommandRunner::new_all_success();
        let dir = tempfile::tempdir().unwrap();

        apply_all(
            &store,
            &runner,
            ProtectedDestinations::default().with_defaults(),
            dir.path().to_path_buf(),
            1.0,
            true,
            1000,
        )
        .unwrap();

        assert!(
            store
                .enforced_decision_contributors_for(&TargetSelector::Ip("203.0.113.9".into()))
                .unwrap()
                .is_empty(),
            "dry-run must never persist the contributor snapshot"
        );
    }

    #[test]
    fn apply_refreshes_contributors_even_when_the_enforced_ruleset_digest_is_unchanged() {
        let store = store();
        let alice = UserId {
            federation: FederationId(Hash32([1; 32])),
            local_id: Hash32([2; 32]),
        };
        let bob = UserId {
            federation: FederationId(Hash32([3; 32])),
            local_id: Hash32([4; 32]),
        };
        store
            .upsert_follow(&LocalTrustRule {
                user: alice,
                allow_weight: 1.0,
                deny_weight: 1.0,
                advisory_only: false,
                excluded: false,
                category_filter: None,
                display_name: None,
                iroh_node_id: None,
                expires_at: None,
                created_at: 0,
            })
            .unwrap();
        store
            .ingest_opinion(&PolicyOpinion {
                author: alice,
                sequence: 0,
                target: TargetSelector::Ip("203.0.113.9".into()),
                stance: Stance::Deny,
                reason: Reason {
                    code: ReasonCode::Malware,
                    note: None,
                    evidence: vec![],
                },
                issued_at: 0,
                expires_at: None,
                supersedes: None,
                signature: SignatureBytes([0; 64]),
            })
            .unwrap();
        let runner = FakeCommandRunner::new_all_success();
        let dir = tempfile::tempdir().unwrap();
        apply_all(
            &store,
            &runner,
            ProtectedDestinations::default().with_defaults(),
            dir.path().to_path_buf(),
            1.0,
            false,
            1000,
        )
        .unwrap();

        // A second, agreeing contributor joins — the Deny decision stays
        // exactly the same (still crosses threshold, still Deny), so the
        // compiled nft digest is unchanged and `apply` reports `NoChange`
        // — but the set of *who* justified it has grown, and that must
        // still be reflected.
        store
            .upsert_follow(&LocalTrustRule {
                user: bob,
                allow_weight: 1.0,
                deny_weight: 1.0,
                advisory_only: false,
                excluded: false,
                category_filter: None,
                display_name: None,
                iroh_node_id: None,
                expires_at: None,
                created_at: 0,
            })
            .unwrap();
        store
            .ingest_opinion(&PolicyOpinion {
                author: bob,
                sequence: 0,
                target: TargetSelector::Ip("203.0.113.9".into()),
                stance: Stance::Deny,
                reason: Reason {
                    code: ReasonCode::Tracker,
                    note: None,
                    evidence: vec![],
                },
                issued_at: 0,
                expires_at: None,
                supersedes: None,
                signature: SignatureBytes([0; 64]),
            })
            .unwrap();
        apply_all(
            &store,
            &runner,
            ProtectedDestinations::default().with_defaults(),
            dir.path().to_path_buf(),
            1.0,
            false,
            2000,
        )
        .unwrap();

        let contributing = store
            .enforced_decision_contributors_for(&TargetSelector::Ip("203.0.113.9".into()))
            .unwrap();
        assert_eq!(
            contributing.len(),
            2,
            "a NoChange apply must still refresh who currently contributes, not just skip it"
        );
    }
}
