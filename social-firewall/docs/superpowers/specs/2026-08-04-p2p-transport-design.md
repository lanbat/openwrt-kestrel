# P2P transport: automated delivery of already-signed statements

## Context

Every feature built in social-firewall so far — opinions, tunnel
advertise/request/accept, shared rule lists, groups, group join requests,
group votes, block reports, party-line messages, device-approval opinions
— ends the same way: sign a statement, export it to a JSON file via
`--out`/`--out-dir`, and rely on a human to physically move that file to
the other router (scp, USB, whatever) before the recipient runs the
matching `ingest-*` command. This was a deliberate, repeatedly-confirmed
scope boundary ("no live P2P/Iroh in this pass"), not an oversight — but
it's now the single biggest piece of friction in the whole system.

This is a genuinely large feature — the first persistent background
service in this codebase (everything else so far is request/response CLI
invocations) and the first new network dependency. Scoped deliberately
narrow for a first increment: **automate delivery, change nothing about
what's already signed, stored, or trusted.**

## Goals

- Replace "a human copies a file" with a real network push, for the
  subset of statement types that already have a known recipient baked
  into their existing data model.
- Zero changes to signing, storage, or trust semantics. The wire format
  carries exactly the same bytes `--out` already writes today.
- Never regress: if a peer's address is unknown or unreachable, the
  existing manual export path keeps working exactly as it does today.

## Non-goals (explicitly deferred, not forgotten)

- **Broadcast-style statements with no recipient list** — plain
  `PolicyOpinion`s, `Public`-visibility tunnel ads/service
  requests/shared rule lists, `DeviceApprovalOpinion`s,
  `FederationStatement`s, `GroupVote`s, `GroupBlockReport`s. `follows` is
  explicitly private, one-directional, and never synced
  (`trust.rs`'s own module doc), and this project has already
  deliberately parked "should a followed peer learn who follows them" as
  an open privacy tradeoff. Automating delivery for these would decide
  that question by accident. Left on the manual path until that tradeoff
  is decided explicitly, as its own follow-up.
- Continuous/gossip-style sync (each node proactively reconciling
  everything it's entitled to see). This phase is push-on-publish only.
- A relay/rendezvous service operated by this project — Iroh's own
  public relays (or a self-hosted one) are used only to help two NAT'd
  nodes find each other; actual statement data still flows directly
  peer-to-peer once connected.

## Architecture

### New crate: `p2p-transport`

Mirrors `wg-tunnel`'s shape: small, single-purpose, built around a
`PeerTransport` trait so the whole send/receive/dispatch flow is unit
testable without a real network — the `CommandRunner`/`FakeCommandRunner`
pattern already used for `wg`/`nft`, applied here instead to Iroh.

```rust
trait PeerTransport {
    fn send(&self, to: IrohNodeId, envelope: &Envelope) -> Result<(), TransportError>;
    fn listen(&self, dispatch: impl Fn(Envelope) -> Result<(), DispatchError>) -> Result<(), TransportError>;
}
```

`IrohTransport` (production) wraps a real Iroh `Endpoint`. `FakeTransport`
(tests) is an in-memory queue between two instances — unlike `nft`/`wg`,
which need root and can only be exercised in a QEMU VM, two Iroh
endpoints can run fully in-process, so this crate should end up with
*better* real-transport test coverage than `wg-tunnel`/`nft-enforcer` get,
not worse.

### A fourth, dedicated keypair

This codebase already refuses to reuse keys across purposes (identity-
signing Ed25519, messaging X25519, WireGuard X25519 are three separate
keys for three separate security properties). Iroh's own `NodeId` is
itself an Ed25519 public key, so a new `iroh_secret_seed` column on the
`is_self` row, generated on first use, follows the exact same pattern as
`wg_secret_seed`/`messaging_secret_seed` — no new principle introduced,
just the fourth application of one already established here.

### Addressing

New `iroh_node_id: Option<String>` field wherever this project already
tracks "how do I reach this peer" — starting with `follows`
(`LocalTrustRule`), settable via `add-follow --iroh-node-id` /
`set-follow-node-id`, the same manually-confirmed, trust-on-first-use
pattern `display_name` already uses. No node_id is ever learned or
applied silently.

## Scope: which statement types get automated delivery

Split into two buckets by one test: **does the statement already carry
its recipient(s) in data this router already holds locally, with no new
lookup or registry needed?**

**Automated in this phase** (recipient already known):
- `TunnelConnectionRequest` → the advertisement's `provider`
- `TunnelConnectionAccept` → the request's `requester`
- `GroupJoinRequest` → the group's current `owners` ∪ `admins` (the
  requester already ingested the `Group` to build the request at all, so
  already has this roster)
- A `Group` version publish (create, membership change, moderation
  toggle, etc.) → current membership minus the publisher (the owner
  already has the full roster right there in the data being published)
- `PartyLineMessage` → already explicitly designed to seal one copy per
  current member; this phase just adds "and send it," no new addressing
  logic needed at all
- Any `Restricted`-visibility export (`TunnelAdvertisement`,
  `TunnelServiceRequest`, `SharedRuleList`) → the explicit `--recipient`
  list already used to produce one sealed file per recipient

**Left on the manual path** (no recipient list exists today — see
Non-goals): plain opinions, `Public`-visibility tunnel
ads/lists/requests, device-approval opinions, federation statements,
group votes, group block reports.

## Data flow

**Send**: unchanged up through signing/sealing — `X_to_json` still
produces exactly the bytes it does today. A new step wraps those bytes in
an `Envelope { statement_kind, payload }` and, for each resolved
recipient with a known `iroh_node_id`, calls `PeerTransport::send`. If
the node_id is unknown, or `send` fails (peer offline, NAT traversal
failed, connection refused), the existing `--out`/`--out-dir` file is
still written — delivery is a best-effort addition on top of the
existing path, never a replacement for it. A one-line status is printed
either way ("delivered to alice's node" vs. "alice's node_id not known /
unreachable — exported to <path> for manual delivery").

**Receive**: a new long-running piece, `sf listen` (cron/init-managed,
the first genuinely persistent process in this codebase). Accepts
inbound Iroh connections, reads one `Envelope` per stream, and dispatches
by `statement_kind` to the exact same `ingest_X` function the manual CLI
path already calls — so every existing signature check, follow-gate, and
auth rule runs completely unchanged. A malformed or tampered envelope is
logged and dropped; it can never crash the listener or affect other
connections.

## Wire shape

- ALPN: `b"social-firewall/1"`.
- One `Envelope` per QUIC bidirectional stream: sender opens the stream,
  writes a small length-prefixed frame (`statement_kind` tag + the JSON
  payload), closes the write side. Receiver reads to EOF, parses,
  dispatches, and may write a one-byte ack/error back on the same stream
  before closing — enough for the sender to distinguish "delivered and
  accepted" from "delivered but rejected" (e.g. an unfollowed author)
  without needing a second round trip.
- Exact Iroh API surface (`Endpoint`, connection accept loop, ALPN
  registration) will be confirmed against current Iroh docs during
  implementation — not pinned down further at design time.

## Error handling

- Peer unreachable/unknown node_id → fall back to file export, as above.
  Never a hard failure of the publishing command itself.
- Malformed envelope on receive → log, drop, keep serving.
- Signature/follow-gate rejection inside `ingest_X` → unchanged existing
  behavior, surfaced back to the sender via the one-byte ack if the
  connection is still open.
- No retry/queue in this phase — if delivery fails, the operator has the
  exported file as the existing fallback path; automatic retry is a
  reasonable future addition once this phase is proven, not built now.

## Testing

- `p2p-transport`: `FakeTransport`-driven unit tests for envelope
  encode/decode, dispatch-by-kind, and malformed-envelope resilience —
  same density as `wg-tunnel`'s `FakeCommandRunner` suite.
- A real two-`IrohTransport` integration test (in-process, two endpoints
  on localhost) sending a real envelope end-to-end — feasible without
  root or a VM, unlike the `nft`/`wg`-touching code elsewhere in this
  repo.
- CLI-level regression tests extending the existing two-node
  alice/bob pattern (`crates/cli/tests/cli.rs`) for at least one
  automated flow (tunnel request → accept) proving delivery plus fallback
  when no node_id is configured.

## Future work (explicitly out of scope here)

- Deciding the follower-visibility tradeoff and extending automated
  delivery to broadcast-style statements once that's resolved.
- Retry/queueing for failed deliveries.
- Discovery beyond a manually-entered `iroh_node_id` (e.g. learning a
  peer's node_id from their own signed statements automatically).
