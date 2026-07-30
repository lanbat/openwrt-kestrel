-- Owner-controlled groups — see `domain_types::group`'s own module doc
-- for the full design (never-zero-owners invariant, wholesale
-- versioning, request-and-approve membership, majority-vote aggregate
-- stance, sealed party-line broadcasts).

CREATE TABLE groups (
    group_id             BLOB NOT NULL,
    sequence             INTEGER NOT NULL,
    published_by_federation_id BLOB NOT NULL,
    published_by_local_id      BLOB NOT NULL,
    name                 TEXT NOT NULL,
    description          TEXT NOT NULL,
    issued_at            INTEGER NOT NULL,
    expires_at           INTEGER,
    supersedes_sequence  INTEGER,
    signature            BLOB NOT NULL,
    ingested_at          INTEGER NOT NULL,
    PRIMARY KEY (group_id, sequence)
) STRICT, WITHOUT ROWID;

CREATE TABLE group_owners (
    group_id BLOB NOT NULL,
    sequence INTEGER NOT NULL,
    user_federation_id BLOB NOT NULL,
    user_local_id BLOB NOT NULL,
    PRIMARY KEY (group_id, sequence, user_federation_id, user_local_id),
    FOREIGN KEY (group_id, sequence) REFERENCES groups(group_id, sequence) ON DELETE CASCADE
) STRICT, WITHOUT ROWID;

CREATE TABLE group_admins (
    group_id BLOB NOT NULL,
    sequence INTEGER NOT NULL,
    user_federation_id BLOB NOT NULL,
    user_local_id BLOB NOT NULL,
    PRIMARY KEY (group_id, sequence, user_federation_id, user_local_id),
    FOREIGN KEY (group_id, sequence) REFERENCES groups(group_id, sequence) ON DELETE CASCADE
) STRICT, WITHOUT ROWID;

CREATE TABLE group_voting_members (
    group_id BLOB NOT NULL,
    sequence INTEGER NOT NULL,
    user_federation_id BLOB NOT NULL,
    user_local_id BLOB NOT NULL,
    PRIMARY KEY (group_id, sequence, user_federation_id, user_local_id),
    FOREIGN KEY (group_id, sequence) REFERENCES groups(group_id, sequence) ON DELETE CASCADE
) STRICT, WITHOUT ROWID;

CREATE TABLE group_non_voting_members (
    group_id BLOB NOT NULL,
    sequence INTEGER NOT NULL,
    user_federation_id BLOB NOT NULL,
    user_local_id BLOB NOT NULL,
    PRIMARY KEY (group_id, sequence, user_federation_id, user_local_id),
    FOREIGN KEY (group_id, sequence) REFERENCES groups(group_id, sequence) ON DELETE CASCADE
) STRICT, WITHOUT ROWID;

-- Join requests reference a group by its stable `group_id` only (not a
-- specific version) — they outlive any single membership snapshot, so
-- there's no FK to a specific `groups` row to cascade from.
CREATE TABLE group_join_requests (
    requester_federation_id BLOB NOT NULL,
    requester_local_id      BLOB NOT NULL,
    sequence                INTEGER NOT NULL,
    group_id                BLOB NOT NULL,
    message                 TEXT,
    issued_at               INTEGER NOT NULL,
    signature               BLOB NOT NULL,
    ingested_at             INTEGER NOT NULL,
    status                  TEXT NOT NULL DEFAULT 'pending',
    PRIMARY KEY (requester_federation_id, requester_local_id, sequence)
) STRICT, WITHOUT ROWID;

-- One voting member's signed stance on a target, cast on behalf of a
-- group — not follow-gated at ingest (same as `tunnel_connection_requests`:
-- anyone can send one), only the *aggregation* query
-- (`StateStore::group_stance_for`) filters to the group's *current*
-- voting members' latest votes.
CREATE TABLE group_votes (
    group_id           BLOB NOT NULL,
    voter_federation_id BLOB NOT NULL,
    voter_local_id      BLOB NOT NULL,
    sequence           INTEGER NOT NULL,
    target_kind        TEXT NOT NULL,
    target_value       TEXT NOT NULL,
    stance             INTEGER NOT NULL,
    reason_code        INTEGER NOT NULL,
    reason_note        TEXT,
    reason_evidence    BLOB NOT NULL,
    issued_at          INTEGER NOT NULL,
    expires_at         INTEGER,
    signature          BLOB NOT NULL,
    ingested_at        INTEGER NOT NULL,
    PRIMARY KEY (group_id, voter_federation_id, voter_local_id, sequence)
) STRICT, WITHOUT ROWID;

-- Trust in a group's aggregate stance — separate dimension from
-- `follows`/`tunnel_trust_rules`, same reasoning as those.
CREATE TABLE group_trust_rules (
    group_id     BLOB PRIMARY KEY,
    allow_weight REAL NOT NULL,
    deny_weight  REAL NOT NULL,
    excluded     INTEGER NOT NULL DEFAULT 0 CHECK (excluded IN (0, 1)),
    expires_at   INTEGER,
    created_at   INTEGER NOT NULL
) STRICT;

-- The "party line" — a group-scoped broadcast, always sealed per current
-- member at publish time (see the domain type's own doc). Stored as
-- plain data once ingested/decrypted, same separation every other
-- sealed statement in this crate already draws between wire format and
-- domain type.
CREATE TABLE party_line_messages (
    group_id            BLOB NOT NULL,
    author_federation_id BLOB NOT NULL,
    author_local_id      BLOB NOT NULL,
    sequence            INTEGER NOT NULL,
    body                TEXT NOT NULL,
    issued_at           INTEGER NOT NULL,
    signature           BLOB NOT NULL,
    ingested_at         INTEGER NOT NULL,
    PRIMARY KEY (group_id, author_federation_id, author_local_id, sequence)
) STRICT, WITHOUT ROWID;
