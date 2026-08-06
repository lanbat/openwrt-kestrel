# Shared Policy Replication Plan

**Goal:** Replicate useful, signed router configuration across social-firewall
nodes. Groups and trusted peers provide opinions on configuration entries;
each router computes its own aggregate decision and materializes only the
accepted result into local firewall, routing, and DNS configuration.

## Current Gap

The existing system can aggregate opinions about targets and automatically
apply an aggregate `deny` to the local `inet social_firewall` nftables table.
`SharedRuleList` can distribute named rule bundles, but it is not yet a
general configuration object. Group votes cannot currently create routes,
DNS filters, redirects, or record overrides.

This plan makes shared configuration, rather than isolated target opinions,
the primary replication model while retaining the existing signed statements,
group membership, trust weights, local overrides, and `sf apply` reconciliation
loop.

## Collections And Local Profiles

The user-facing unit is a **collection**: a named, signed set of related
configuration entries. A collection may contain ACLs, DNS filters and typed
record overrides, nftables mangle/mark rules, routing-table entries, and
references to locally available shared VPN tunnels.

The signed collection advertises intent and constraints, never arbitrary shell,
UCI, nft, `ip`, WireGuard, or resolver commands. Each entry has a typed
materializer and stable ID, so a user can select an entire collection while a
technical user can inspect or override individual entries.

A router maintains local **profiles** that select collections and individual
entries. Built-in profiles such as `Default`, `Privacy`, `Family`, and
`Travel`/`Work` make the normal path a simple toggle. Profiles are local, not
remotely authoritative: an advertised collection is never activated without
local selection.

Profile changes are transactional. The router calculates the complete desired
state, shows the diff, then materializes or rolls back as one operation.
Collections may depend on other collections by stable ID and version range;
cycles, unavailable dependencies, target conflicts, and unsupported local
capabilities are rejected before activation.

Every selected entry retains publisher, collection/version, entry ID,
group/vote result, contributing identities, local override, materializer state,
and generated-state digest as provenance.

## Scoped Reputation And Review

The system should have a useful equivalent of karma, but not one global score.
Reputation is a view over signed work and review outcomes, scoped by:

- group;
- capability or topic, such as DNS, routing, ACLs, fingerprints, or VPNs;
- role, such as publisher, observer, reviewer, or maintainer;
- time window and evidence quality.

An identity may therefore be highly trusted for DNS review in one group and
have no reputation for routing in another. Reputation helps discovery and
review prioritization; it never directly changes local enforcement weight.
Local trust weights remain an explicit operator decision.

### Contributions That Earn Credit

Credit is attached to verifiable outcomes, not message volume:

- A fingerprint observation later corroborated by independent members.
- A review that correctly identifies a bad, stale, or conflicting entry.
- A collection that remains enabled, useful, and low-rollback over time.
- A maintainer who responds to disputes and publishes a corrected version.
- A technical explanation that helps another reviewer reproduce a result.

Repetition has diminishing returns. Identical observations from the same
observer, rapid agreement rings, empty comments, and unreviewed publishing do
not create meaningful reputation.

### Accuracy And Decay

Reputation is computed from signed event history, not manually assigned points.
Positive evidence includes independent corroboration, successful review
resolution, and stable collection outcomes. Negative evidence includes
confirmed false observations, rejected unsafe entries, repeated rollbacks,
and unresolved maintainer failures.

Scores decay over time when work is not revisited. A recent accurate review is
more useful than a years-old approval. The system preserves the historical
record even when the displayed score decays.

Each score must show its inputs:

- sample count;
- independent observers;
- confirmation/dispute ratio;
- rollback and expiry history;
- time window;
- confidence interval or “insufficient evidence” state.

Do not display a precise-looking score when the sample is too small.

### Anti-Gaming And Sybil Resistance

- Group membership and voting eligibility remain explicit.
- Multiple identities controlled by one router do not count as independent
  corroboration when the transport or group can detect that relationship.
- A publisher cannot self-confirm its own observation or collection.
- Corroboration is weighted by independent routers, not raw vote count alone.
- Rate limits, cooldowns, and maximum daily reputation gains prevent farming.
- Coordinated groups can be flagged for review without silently deleting their
  historical work.
- Negative reputation is scoped and evidence-backed; it is never a global
  banlist.
- Users can appeal or annotate a reputation event, but cannot erase signed
  history.

### User Experience

Normal users see plain labels such as:

- `well reviewed`
- `new contributor`
- `mixed evidence`
- `recent disputes`
- `not enough history`

Technical users can open the underlying review graph, event history,
confidence calculation, group scope, and capability scope. Badges, milestones,
review streaks, and “helped routers” are opt-in secondary feedback only. They
must never gate safety features, hide dissent, or pressure a user to activate a
collection.

## Shared Fingerprints And Group Context

Device fingerprints are also shareable group data. A fingerprint is a signed,
versioned evidence bundle describing normalized DHCP/vendor signals, mDNS
identity, Wi-Fi capabilities, bounded protocol hints, or other
confidence-scored signals. MAC history is local-only and is never part of
shared fingerprint material. A shared fingerprint is not automatically
treated as a global identity or a firewall decision.

Fingerprint sharing is explicitly scoped:

- A fingerprint is published to one or more selected groups, with visibility
  and expiry set by the publisher.
- Each group keeps its own comments, confidence, votes, moderation, and
  provenance. A comment in one group does not silently become a global label.
- Comments reference the fingerprint ID and fingerprint revision, so later
  evidence cannot rewrite the historical context of an older comment.
- Members can mark a fingerprint as confirmed, disputed, stale, or unrelated,
  with a reason and optional evidence reference.
- A local router decides whether a group fingerprint is useful for local
  naming, device policy, or collection matching. Remote fingerprint data never
  directly changes enforcement.

The group membership model is many-to-many. A node may belong to multiple
groups, with independent roles and voting rights in each one. Group-scoped
trust and comments must never be collapsed into one global reputation score.
The UI shows the group context on every fingerprint, comment, vote, and
automated effect.

### Implemented Fingerprint Foundation

The current implementation preserves the local/shared separation above:

- `kestreld` has a per-network local `FingerprintRecord` with scored matching
  and explicit human confirmation.
- `social-firewall` has signed, group-scoped `FingerprintObservation` and
  `FingerprintComment` persistence, ingest, and transport types.
- Versioned, length-delimited shared material and group-keyed BLAKE3
  derivation live in `crates/crypto/src/shared_fingerprint.rs`.
- `kestreld` produces matching privacy-filtered material in
  `networks/kestreld-rs/src/data/shared_fingerprint.rs`.
- Group fingerprint keys are locally stored in SQLite and can be explicitly
  configured with `sf set-fingerprint-key`; `sf derive-fingerprint-id` derives
  an ID from bridge material.
- Automatic key agreement, material export from the kestreld UI, observation
  publication, and local identity merging are not implemented.

The complete field contract, key handling, UI integration, and current safety
boundaries are documented in `social-firewall/docs/fingerprints-and-ui.md`.
That document also records the technical decision rationale, evidence sources,
confidence levels, and known validation gaps; treat those distinctions as part
of the design rather than presenting untested assumptions as guarantees.

## Policy Model

Introduce a signed, versioned `SharedPolicy` statement. A policy contains:

- A stable policy ID and monotonically increasing publisher sequence.
- A human-readable name and description.
- A list of typed entries. DNS overrides are entries, not local-only settings,
  so they can be advertised, voted on, expired, revoked, and audited exactly
  like ACL and route entries.
- Visibility and optional explicit recipients, matching existing shared-list
  delivery rules.
- Publisher identity, signature, expiry, and provenance.

Each entry contains:

- A target selector: `domain`, `domain_suffix`, `ip`, `cidr`, `service`, or a
  future device/network selector.
- An action and action-specific parameters.
- Optional category, reason, note, TTL, and entry expiry.
- A stable entry ID so votes and audit records survive policy reordering.
- Optional typed constraints that limit what the entry permits or consumes.

Constraints are first-class, signed collection parameters. Initial constraint
families include:

- `max_connections` and `max_concurrent_connections`.
- `max_bandwidth_kbps` and `max_bytes` over a defined interval.
- `max_session_seconds` and `idle_timeout_seconds`.
- `rate_limit_per_second` and `burst`.
- DNS query/response size, query rate, and cache TTL limits.
- Per-device, per-target, per-group, and per-tunnel scopes.

Each constraint has an explicit unit, interval, scope, and failure behavior.
The materializer validates that the local backend can enforce it. A collection
may request a named local limit profile, but cannot publish arbitrary shell,
nft, UCI, route, or WireGuard commands. Unsupported constraints are rejected
or shown as unapplied before activation, never silently ignored.

Initial actions:

- `block`: deny the target through the local firewall.
- `allow`: an explicit positive policy input, never a bypass of protected
  destinations or local safety rules.
- `route`: send matching traffic through a named local route or VPN profile.
- `dns_block`: return the configured blocking response for a domain.
- `dns_redirect`: answer with a local IPv4/IPv6 address.
- `dns_record`: install a local override for any supported DNS RR type, with
  presentation-format value and TTL.

Do not permit arbitrary shell commands or arbitrary generated configuration
fragments in the shared policy format. DNS record type/value validation belongs
to the DNS materializer and must happen before any resolver configuration is
written or reloaded.

## Voting And Precedence

Votes target a policy entry, not an opaque file. A vote identifies:

- Policy ID and entry ID.
- The policy version being reviewed.
- `allow`, `deny`, or `ask` stance.
- Reason code, note, optional TTL, voter, sequence, and signature.

The local decision engine combines group votes and individually trusted
opinions using the existing trust weights. It must reject stale policy
versions and preserve the contributing identities for audit display.

Precedence is fixed and fail-safe:

1. Local emergency overrides.
2. Protected destinations and management addresses.
3. Explicit local policy.
4. Accepted group consensus and trusted peer policy.
5. Unresolved or conflicting proposals become `ask` and are not applied.

An accepted `deny` can block traffic. An accepted `route` or DNS action must
also pass local materializer validation. A remote policy never gets control of
an arbitrary local interface, route table, DNS listener, or executable.

## Materializers

`sf apply` remains the single local reconciliation entry point. It evaluates
the aggregate policy, compares the desired generated state with the previous
state, and updates only managed resources.

Materializers are capability-scoped adapters. A collection entry requests a
typed effect; only the local adapter decides whether that effect is supported
and how it is rendered. Each adapter reports `applied`, `skipped`, or
`rejected` with both a plain-language reason and technical detail.

### Firewall

Reuse `nft-enforcer` for `block` and validated IP/CIDR/service actions. Keep
the managed `inet social_firewall` table separate from fw4 and preserve the
existing protected-destination behavior.

### Routing

Map a policy route name to a locally configured route/VPN profile. The shared
policy may request `eu-vpn`, but it may not define the peer, endpoint,
WireGuard keys, interface commands, or arbitrary `ip` invocations.

Routing materialization must validate:

- The route profile exists locally and is enabled.
- The target kind is supported by the routing backend.
- Management, loopback, and protected destinations are excluded.
- Removal is deterministic when a vote expires or falls below threshold.
- A route failure does not silently turn into an unrestricted route.

### DNS

Generate a managed dnsmasq fragment from accepted DNS entries and reload
dnsmasq only when its generated digest changes.

Supported behavior:

- `dns_block`: NXDOMAIN, refusal, or configured sinkhole behavior.
- `dns_redirect`: return a validated local address.
- `dns_record`: typed record overrides for every DNS RR type supported by the
  selected local resolver backend, with explicit TTL and scope. The policy
  wire format itself must not be restricted to A/AAAA.

Record overrides must preserve local management and resolver safety. The
materializer must validate owner names, record types, presentation values,
TTL bounds, and resolver-specific constraints. The generated file must be
completely replaced rather than append-only. Unsupported records fail closed
and remain visible as unapplied policy with an explanation.

### Mangle And Policy Routing

Mangle entries use constrained typed fields such as match selectors,
connection mark, packet mark, DSCP, and priority. They may refer only to
locally declared chains and marks and cannot inject arbitrary nft syntax.

Routing entries use named local route profiles and validated table/rule
parameters. A collection may request `home-vpn` or `eu-vpn`, but cannot publish
an endpoint, private key, interface command, or arbitrary route mutation.

### Shared VPN Tunnels

Collections may reference an advertised tunnel by stable statement ID and
required capabilities. Tunnel negotiation, peer authorization, keys, and local
resource limits remain governed by existing tunnel trust and reciprocity rules.
Selecting a collection may request a tunnel but never automatically accepts an
unknown peer or grants it local control.

## CGI Interface

The CGI surface uses progressive disclosure. The simple view is a collection
browser with cards, clear status, and one primary action: **Select** or
**Remove**. Cards show publisher, review state, supported effects, required
capabilities, last update, and a plain-language safety summary.

Dedicated endpoints:

- `/cgi-bin/sf-collections`: browse, search, filter, and select collections.
- `/cgi-bin/sf-collection`: inspect one collection, dependencies, votes, and
  provenance.
- `/cgi-bin/sf-profiles`: create/select local profiles and preview diffs.
- `/cgi-bin/sf-rules`: inspect or override individual entries across rule
  families.
- `/cgi-bin/sf-fingerprints`: browse group-scoped fingerprints, evidence,
  confidence, and comments.
- `/cgi-bin/sf-fingerprint`: inspect one fingerprint revision, comment, vote,
  dispute, or mark it stale within a selected group.
- `/cgi-bin/sf-vote`: vote, explain aggregate decisions, and view dissent.
- `/cgi-bin/sf-effects`: show applied, skipped, and rejected effects.
- `/cgi-bin/sf-apply`: review and confirm a transactional local apply.
- `/cgi-bin/sf-reputation`: show scoped reputation, evidence, disputes, and
  contribution history for an identity.

The advanced view exposes exact targets, typed action parameters, generated
configuration, digests, and CLI/API equivalents. The simple view never
requires users to understand nftables, DNS RR syntax, route tables, or
WireGuard.

All mutation endpoints use POST plus redirect-after-POST, escaped output,
bounded inputs, explicit confirmation for activation, and reversible changes.
CGI is an operator surface; transport and reconciliation remain background
work, never a long-running operation inside one request.

The currently shipped subset is `/cgi-bin/sf-fingerprint`,
`/cgi-bin/sf-profiles`, and `/cgi-bin/sf-routes`; the broader collection,
effects, reputation, and transactional-apply endpoints remain planned.

## Balanced Incentives And Adoption

The system should be compelling without turning security decisions into a
popularity contest or using dark patterns:

- Reward useful, verifiable contributions, accurate explanations, and reviews
  that catch bad entries.
- Show reputation as evidence quality and review history, not one global
  popularity number.
- Separate discovery ranking from enforcement authority; popularity never
  increases local policy weight.
- Show dissent, uncertainty, expiry, and rollback prominently.
- Use opt-in badges, contribution milestones, review streaks, and helped-router
  counts only as secondary feedback. Never gate safety features or punish
  disabling a collection.
- Rate-limit publishing, voting, and notifications, and require explicit
  consent before enabling remote collections or tunnels.
- Make every automated change reversible and explainable before and after
  activation.

## Replication And Storage

- Add a dedicated transport statement kind for `SharedPolicy`, unless the
  existing `SharedRuleList` wire format can be extended without ambiguity.
- Reuse the established signed export, Iroh delivery, retry, and file fallback
  paths.
- Store policy versions, entries, votes, aggregate decisions, materializer
  digests, collection constraints, and contributing identities in SQLite.
- Store fingerprint revisions and comments with `(group_id, fingerprint_id,
  revision)` scope; never use a global comment or reputation row.
- Store signed contribution/review events and derived reputation snapshots with
  explicit group, capability, role, and time-window scope.
- Keep ingest signature validation and current-member/group trust checks
  separate from local application.
- Make ingestion idempotent and reject sequence rollback, malformed targets,
  unsupported actions, and overlong fields.

## CLI And Chat

Add commands for:

- Publishing and ingesting policies.
- Listing policy versions and entries.
- Voting on an entry and explaining its aggregate decision.
- Listing materialized firewall, route, and DNS effects.
- Dry-running `sf apply` with provenance.

Expose the same operations through the existing IRC-like chat command layer,
with command completion and inline documentation. Chat is an operator surface,
not a second policy implementation.

## Delivery Phases

- [ ] Define `SharedPolicy`, `PolicyEntry`, action validation, and stable entry
  IDs in `domain-types`.
- [ ] Add collection metadata, dependency constraints, capability requirements,
  and local profile selection above individual policies.
- [ ] Add SQLite migrations and signed publish/ingest/list commands.
- [ ] Add policy-entry voting and aggregate decision/provenance queries.
- [ ] Add collection selection, profile diff, conflict detection, and atomic
  activation/deactivation.
- [ ] Add signed contribution/review events, scoped reputation calculation,
  decay, confidence intervals, and dispute/appeal history.
- [ ] Add signed group-scoped fingerprint revisions, comments, disputes, and
  confidence votes with multi-group membership support.
- [ ] Generalize `SharedRuleList` trust and replication paths where safe.
- [ ] Materialize accepted `block` actions through the existing nft backend.
- [ ] Add local route-profile configuration and validated `route` materializer.
- [ ] Add managed resolver generation for `dns_block`, `dns_redirect`, and
  typed `dns_record` actions covering every supported DNS RR type.
- [ ] Add typed collection constraints, capability negotiation, and materializer
  reports for traffic, connection, session, rate, DNS, device, and tunnel
  limits.
- [ ] Add `sf apply --dry-run` output showing proposed changes and contributors.
- [ ] Add CLI, state-store, fake-transport, nft, routing, and DNS integration
  tests, including expiry, revocation, conflict, local override, protected
  destination, and generated-config replacement cases.
- [ ] Add browser scenarios for publishing, voting, explaining, and applying
  shared policy entries from chat.
- [ ] Add browser scenarios for simple collection selection plus advanced
  provenance, dependency, conflict, capability, rollback, and effect views.
- [ ] Add browser scenarios showing plain-language reputation labels and the
  technical evidence view without exposing a misleading global score.

## Explicit Non-Goals For The First Version

- No arbitrary remote shell or UCI execution.
- No automatic acceptance of a remote VPN peer or tunnel endpoint solely from
  a vote.
- No unvalidated DNS record values or resolver-specific configuration fragments.
- No silent application of unresolved or conflicting votes.
- No replacement of local operator controls with group consensus.
- No global fingerprint labels, comments, or reputation derived by merging
  unrelated groups.
- No popularity score used as an enforcement weight.
- No dark-pattern activation, irreversible apply, or hidden dissent.
