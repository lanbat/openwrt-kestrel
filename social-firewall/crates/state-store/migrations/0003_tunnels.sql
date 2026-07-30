-- VPN tunnel advertising: a provider's signed offer (`tunnel_advertisements`),
-- a consumer's want-ad published first instead (`tunnel_service_requests`),
-- and the two-sided WireGuard handshake needed to actually connect
-- (`tunnel_connection_requests`/`tunnel_connection_accepts`) — see
-- `domain_types::tunnel`'s own module doc for why the handshake exists at
-- all (WireGuard is two-sided; a one-way advertisement doesn't let anyone
-- connect). `tunnel_trust_rules` is a trust dimension deliberately
-- separate from `follows` — see that table's own comment.

-- ── Advertisements ────────────────────────────────────────────────────────

CREATE TABLE tunnel_advertisements (
    provider_federation_id  BLOB NOT NULL,
    provider_local_id       BLOB NOT NULL,
    sequence                INTEGER NOT NULL,
    description             TEXT NOT NULL,
    limitations             TEXT,
    visibility              INTEGER NOT NULL,  -- 0=Public 1=Restricted
    -- Optional back-reference to a tunnel_service_requests row this
    -- advertisement was published in response to — purely informational,
    -- an advertisement is always valid unprompted too.
    in_response_to_federation_id BLOB,
    in_response_to_local_id      BLOB,
    in_response_to_sequence      INTEGER,
    messaging_pubkey        BLOB NOT NULL,
    wg_pubkey               BLOB NOT NULL,
    endpoint_hint           TEXT NOT NULL,
    issued_at               INTEGER NOT NULL,
    expires_at              INTEGER,
    supersedes_sequence     INTEGER,
    signature               BLOB NOT NULL,
    ingested_at             INTEGER NOT NULL,
    PRIMARY KEY (provider_federation_id, provider_local_id, sequence)
) STRICT, WITHOUT ROWID;

-- One row per `TargetSelector` in an advertisement's route scope — same
-- normalized-child-table shape this project already uses for anything
-- list-valued (mirrors how `opinions` itself is one row per single
-- target rather than embedding a list in a column).
CREATE TABLE tunnel_advertisement_targets (
    provider_federation_id  BLOB NOT NULL,
    provider_local_id       BLOB NOT NULL,
    sequence                INTEGER NOT NULL,
    target_kind             TEXT NOT NULL,
    target_value            TEXT NOT NULL,
    PRIMARY KEY (provider_federation_id, provider_local_id, sequence, target_kind, target_value),
    FOREIGN KEY (provider_federation_id, provider_local_id, sequence)
        REFERENCES tunnel_advertisements(provider_federation_id, provider_local_id, sequence)
        ON DELETE CASCADE
) STRICT, WITHOUT ROWID;

-- ── Service requests (want-ads) ───────────────────────────────────────────

CREATE TABLE tunnel_service_requests (
    requester_federation_id BLOB NOT NULL,
    requester_local_id      BLOB NOT NULL,
    sequence                INTEGER NOT NULL,
    description             TEXT NOT NULL,
    visibility              INTEGER NOT NULL,  -- 0=Public 1=Restricted
    issued_at               INTEGER NOT NULL,
    expires_at              INTEGER,
    supersedes_sequence     INTEGER,
    signature               BLOB NOT NULL,
    ingested_at             INTEGER NOT NULL,
    PRIMARY KEY (requester_federation_id, requester_local_id, sequence)
) STRICT, WITHOUT ROWID;

CREATE TABLE tunnel_service_request_targets (
    requester_federation_id BLOB NOT NULL,
    requester_local_id      BLOB NOT NULL,
    sequence                INTEGER NOT NULL,
    target_kind             TEXT NOT NULL,
    target_value            TEXT NOT NULL,
    PRIMARY KEY (requester_federation_id, requester_local_id, sequence, target_kind, target_value),
    FOREIGN KEY (requester_federation_id, requester_local_id, sequence)
        REFERENCES tunnel_service_requests(requester_federation_id, requester_local_id, sequence)
        ON DELETE CASCADE
) STRICT, WITHOUT ROWID;

-- ── Connection handshake ──────────────────────────────────────────────────

CREATE TABLE tunnel_connection_requests (
    requester_federation_id BLOB NOT NULL,
    requester_local_id      BLOB NOT NULL,
    sequence                INTEGER NOT NULL,
    advertisement_provider_federation_id BLOB NOT NULL,
    advertisement_provider_local_id      BLOB NOT NULL,
    advertisement_sequence               INTEGER NOT NULL,
    requester_wg_pubkey        BLOB NOT NULL,
    requester_messaging_pubkey BLOB NOT NULL,
    requested_at            INTEGER NOT NULL,
    signature               BLOB NOT NULL,
    ingested_at             INTEGER NOT NULL,
    -- 'pending' until the provider's reconciliation step accepts it (or an
    -- admin does manually); kept here rather than inferred from the
    -- presence of a matching tunnel_connection_accepts row so a rejected/
    -- ignored request is still distinguishable from a never-reviewed one.
    status                  TEXT NOT NULL DEFAULT 'pending',
    PRIMARY KEY (requester_federation_id, requester_local_id, sequence)
) STRICT, WITHOUT ROWID;

CREATE TABLE tunnel_connection_accepts (
    provider_federation_id  BLOB NOT NULL,
    provider_local_id       BLOB NOT NULL,
    request_requester_federation_id BLOB NOT NULL,
    request_requester_local_id      BLOB NOT NULL,
    request_sequence                INTEGER NOT NULL,
    assigned_tunnel_ip      TEXT NOT NULL,
    accepted_at             INTEGER NOT NULL,
    signature               BLOB NOT NULL,
    ingested_at             INTEGER NOT NULL,
    PRIMARY KEY (request_requester_federation_id, request_requester_local_id, request_sequence)
) STRICT, WITHOUT ROWID;

-- ── Tunnel-specific trust (separate dimension from `follows`) ────────────
-- Trusting someone's malware opinions doesn't imply trusting them enough
-- to auto-route traffic through their infrastructure, or to auto-grant
-- them access to this router's own tunnel — a distinct risk profile,
-- its own table, its own three independent auto-behavior flags.

CREATE TABLE tunnel_trust_rules (
    federation_id                     BLOB NOT NULL,
    local_id                          BLOB NOT NULL,
    auto_accept_requests             INTEGER NOT NULL DEFAULT 0 CHECK (auto_accept_requests IN (0, 1)),
    auto_consume_advertisements      INTEGER NOT NULL DEFAULT 0 CHECK (auto_consume_advertisements IN (0, 1)),
    auto_respond_to_service_requests INTEGER NOT NULL DEFAULT 0 CHECK (auto_respond_to_service_requests IN (0, 1)),
    excluded                          INTEGER NOT NULL DEFAULT 0 CHECK (excluded IN (0, 1)),
    expires_at                        INTEGER,
    created_at                        INTEGER NOT NULL,
    PRIMARY KEY (federation_id, local_id)
) STRICT, WITHOUT ROWID;

-- ── Locally-active tunnels ────────────────────────────────────────────────
-- Rebuildable-from-the-handshake-tables record of what this router has
-- actually provisioned, either providing or consuming — the `wg-tunnel`
-- crate's reconciliation target, the same role `applied_ruleset_state`
-- plays for `nft-enforcer`.

CREATE TABLE provisioned_tunnels (
    -- The other party in this tunnel relationship.
    peer_federation_id      BLOB NOT NULL,
    peer_local_id           BLOB NOT NULL,
    -- 'providing' = this router offered the tunnel; 'consuming' = this
    -- router is using someone else's.
    direction               TEXT NOT NULL CHECK (direction IN ('providing', 'consuming')),
    -- Needed to actually manage this peer via `wg` — reconciliation has
    -- no other way to know which live WireGuard peer this row is about.
    peer_wg_pubkey          BLOB NOT NULL,
    interface_name          TEXT NOT NULL,
    fwmark                  INTEGER NOT NULL,
    route_table             INTEGER NOT NULL,
    tunnel_ip               TEXT NOT NULL,
    status                  TEXT NOT NULL DEFAULT 'active',
    created_at              INTEGER NOT NULL,
    PRIMARY KEY (peer_federation_id, peer_local_id, direction)
) STRICT, WITHOUT ROWID;

-- One row per selected-for-routing target on a *consuming* provisioned
-- tunnel — may be a subset of what the advertisement originally offered.
CREATE TABLE provisioned_tunnel_selected_targets (
    peer_federation_id      BLOB NOT NULL,
    peer_local_id           BLOB NOT NULL,
    direction               TEXT NOT NULL,
    target_kind             TEXT NOT NULL,
    target_value            TEXT NOT NULL,
    PRIMARY KEY (peer_federation_id, peer_local_id, direction, target_kind, target_value),
    FOREIGN KEY (peer_federation_id, peer_local_id, direction)
        REFERENCES provisioned_tunnels(peer_federation_id, peer_local_id, direction)
        ON DELETE CASCADE
) STRICT, WITHOUT ROWID;

-- ── Resource allocator ────────────────────────────────────────────────────
-- `FWMARK`/`ROUTE_TABLE` are a single kernel-wide namespace, not a
-- per-package one (confirmed against `split-routing/install.sh`, which
-- hand-picks small integers like 100/0x1 with zero collision checking).
-- This router's own dynamically-provisioned tunnels draw from a disjoint,
-- documented, reserved range instead (see `wg-tunnel`'s own module doc for
-- the exact bounds) — this singleton row is the persisted high-water mark,
-- so a restart never double-assigns a slot a still-active tunnel is using.

CREATE TABLE tunnel_resource_allocator (
    id INTEGER PRIMARY KEY CHECK (id = 0),
    next_fwmark     INTEGER NOT NULL,
    next_route_table INTEGER NOT NULL
) STRICT;

-- ── Messaging and WireGuard keypairs ──────────────────────────────────────
-- This router's own X25519 messaging key (see `crypto::MessagingKeypair`)
-- and its own WireGuard key (see `wg_tunnel::WgKeypair`) — two distinct
-- keypairs for two distinct purposes (see both types' own module docs on
-- why reusing one keypair across purposes is a real anti-pattern), stored
-- the same way `users.secret_seed` already stores the Ed25519 identity
-- seed on the `is_self` row, same at-rest caveat noted on that column.

ALTER TABLE users ADD COLUMN messaging_secret_seed BLOB;
ALTER TABLE users ADD COLUMN wg_secret_seed BLOB;
