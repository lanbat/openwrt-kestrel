-- Initial schema. Forward-only: never edit a migration once it has shipped
-- to any router — add a new numbered file instead. All hash/key/signature
-- columns are stored as raw BLOBs (not hex text) to keep the DB small on
-- flash-constrained devices; encode/decode happens in Rust at the
-- state-store boundary, never in SQL.

-- `schema_migrations` itself is created by `StateStore::run_migrations`
-- before any migration file runs (it has to exist to know which
-- migrations are outstanding), so it is intentionally not declared here.

-- ── Federations & identity ──────────────────────────────────────────────

CREATE TABLE federations (
    federation_id   BLOB PRIMARY KEY,  -- Hash32, self-certifying from genesis
    display_name    TEXT NOT NULL,
    genesis_blob    BLOB NOT NULL,
    joined_at       INTEGER NOT NULL,
    -- Local trust in this federation's own FederationStatement stream /
    -- membership defaults — mirrors FederationTrustRule, one row per
    -- federation the owner has an opinion about (including their own).
    is_home         INTEGER NOT NULL DEFAULT 0 CHECK (is_home IN (0, 1))
) STRICT;

CREATE TABLE federation_bootstrap_nodes (
    federation_id   BLOB NOT NULL REFERENCES federations(federation_id) ON DELETE CASCADE,
    node_id         BLOB NOT NULL,      -- NodeId
    endpoint_hint   TEXT NOT NULL,      -- FederationEndpointHint, transport-specific
    added_at        INTEGER NOT NULL,
    PRIMARY KEY (federation_id, node_id)
) STRICT, WITHOUT ROWID;

CREATE TABLE users (
    federation_id       BLOB NOT NULL REFERENCES federations(federation_id) ON DELETE CASCADE,
    local_id            BLOB NOT NULL,   -- Hash32, stable across key rotation
    current_pubkey      BLOB NOT NULL,   -- PublicKeyBytes, latest known
    display_name        TEXT,
    is_self             INTEGER NOT NULL DEFAULT 0 CHECK (is_self IN (0, 1)),
    revoked_at          INTEGER,         -- NULL unless the federation revoked this identity
    compromised_since   INTEGER,         -- heuristic backdate for retroactive-opinion discounting; NULL = not flagged
    -- Ed25519 seed, only ever populated for the is_self row. Stored at
    -- rest with no additional encryption — there is no hardware keystore
    -- available uniformly across OpenWrt targets to bind this to; a real
    -- deployment should treat the whole DB file's filesystem permissions
    -- as the only protection, same documented limitation as `crypto::Keypair::from_seed`.
    secret_seed         BLOB,
    PRIMARY KEY (federation_id, local_id)
) STRICT, WITHOUT ROWID;

-- Every key this user has ever published, so an opinion signed under a
-- since-rotated key can still be verified against the key that was current
-- when it was issued.
CREATE TABLE user_key_history (
    federation_id   BLOB NOT NULL,
    local_id        BLOB NOT NULL,
    pubkey          BLOB NOT NULL,
    valid_from      INTEGER NOT NULL,
    valid_until     INTEGER,   -- NULL = still current
    PRIMARY KEY (federation_id, local_id, pubkey),
    FOREIGN KEY (federation_id, local_id) REFERENCES users(federation_id, local_id) ON DELETE CASCADE
) STRICT, WITHOUT ROWID;

-- ── The owner's private trust graph — never synced ──────────────────────

CREATE TABLE follows (
    federation_id       BLOB NOT NULL,
    local_id            BLOB NOT NULL,
    allow_weight        REAL NOT NULL,
    deny_weight         REAL NOT NULL,
    advisory_only       INTEGER NOT NULL DEFAULT 0 CHECK (advisory_only IN (0, 1)),
    excluded            INTEGER NOT NULL DEFAULT 0 CHECK (excluded IN (0, 1)),
    category_filter     TEXT,
    expires_at          INTEGER,
    created_at          INTEGER NOT NULL,
    PRIMARY KEY (federation_id, local_id)
) STRICT, WITHOUT ROWID;

CREATE TABLE federation_trust_rules (
    federation_id           BLOB PRIMARY KEY,
    allow_weight            REAL NOT NULL,
    deny_weight             REAL NOT NULL,
    via_relay_full_membership INTEGER NOT NULL DEFAULT 0 CHECK (via_relay_full_membership IN (0, 1)),
    category_filter         TEXT,
    expires_at              INTEGER,
    created_at               INTEGER NOT NULL
) STRICT;

-- ── Opinions (synced, signed) ────────────────────────────────────────────

-- Opinions ingested from users the owner follows.
CREATE TABLE opinions (
    author_federation_id    BLOB NOT NULL,
    author_local_id         BLOB NOT NULL,
    sequence                INTEGER NOT NULL,
    target_kind             TEXT NOT NULL,
    target_value            TEXT NOT NULL,
    stance                  INTEGER NOT NULL,   -- 0=Allow 1=Deny 2=Ask
    reason_code             INTEGER NOT NULL,
    reason_note             TEXT,
    reason_evidence         BLOB,               -- concatenated Hash32s, canonical-encoded
    issued_at               INTEGER NOT NULL,
    expires_at              INTEGER,
    supersedes_sequence     INTEGER,
    signature               BLOB NOT NULL,
    ingested_at             INTEGER NOT NULL,
    PRIMARY KEY (author_federation_id, author_local_id, sequence)
) STRICT, WITHOUT ROWID;

CREATE INDEX idx_opinions_target ON opinions(target_kind, target_value);

-- The owner's own published log — kept separate from `opinions` (rather
-- than a self-referential row there) so "what have I said" is never
-- accidentally conflated with "what I ingested from someone else," even
-- though the row shape is the same.
CREATE TABLE own_opinion_log (
    sequence                INTEGER PRIMARY KEY,
    target_kind             TEXT NOT NULL,
    target_value            TEXT NOT NULL,
    stance                  INTEGER NOT NULL,
    reason_code             INTEGER NOT NULL,
    reason_note             TEXT,
    reason_evidence         BLOB,
    issued_at               INTEGER NOT NULL,
    expires_at              INTEGER,
    supersedes_sequence     INTEGER,
    signature               BLOB NOT NULL
) STRICT;

CREATE INDEX idx_own_opinion_log_target ON own_opinion_log(target_kind, target_value);

CREATE TABLE federation_statements (
    federation_id           BLOB NOT NULL,
    sequence                INTEGER NOT NULL,
    target_kind             TEXT NOT NULL,
    target_value            TEXT NOT NULL,
    stance                  INTEGER NOT NULL,
    reason_code             INTEGER NOT NULL,
    reason_note             TEXT,
    reason_evidence         BLOB,
    issued_at               INTEGER NOT NULL,
    expires_at              INTEGER,
    supersedes_sequence     INTEGER,
    commitment              BLOB NOT NULL,   -- validator-threshold commitment, opaque here
    ingested_at             INTEGER NOT NULL,
    PRIMARY KEY (federation_id, sequence)
) STRICT, WITHOUT ROWID;

CREATE INDEX idx_federation_statements_target ON federation_statements(target_kind, target_value);

-- ── Local overrides — reasonless, never synced ───────────────────────────

-- Natural-key primary key: "set an override for this target" is an atomic
-- UPSERT, so there is never a window with two conflicting active overrides
-- for the same target.
CREATE TABLE local_overrides (
    target_kind     TEXT NOT NULL,
    target_value    TEXT NOT NULL,
    stance          INTEGER NOT NULL,
    kind            INTEGER NOT NULL,   -- 0=Normal 1=Emergency
    note            TEXT,
    created_at      INTEGER NOT NULL,
    expires_at      INTEGER,
    PRIMARY KEY (target_kind, target_value)
) STRICT, WITHOUT ROWID;

-- ── Approvals / pending transactions ─────────────────────────────────────

CREATE TABLE pending_transactions (
    tx_id           BLOB PRIMARY KEY,   -- Hash32 of the canonical tx bytes
    kind            TEXT NOT NULL,
    payload         BLOB NOT NULL,
    created_at      INTEGER NOT NULL,
    status          TEXT NOT NULL DEFAULT 'pending' -- pending|committed|rejected|expired
) STRICT;

CREATE TABLE approval_requests (
    request_id      BLOB PRIMARY KEY,
    device_mac      TEXT NOT NULL,
    target_kind     TEXT NOT NULL,
    target_value    TEXT NOT NULL,
    requested_at    INTEGER NOT NULL,
    expires_at      INTEGER,
    status          TEXT NOT NULL DEFAULT 'open' -- open|approved|denied|expired
) STRICT;

CREATE TABLE approval_responses (
    request_id      BLOB NOT NULL REFERENCES approval_requests(request_id) ON DELETE CASCADE,
    responder_federation_id BLOB NOT NULL,
    responder_local_id      BLOB NOT NULL,
    decision        INTEGER NOT NULL,   -- 0=Allow 1=Deny
    responded_at    INTEGER NOT NULL,
    signature       BLOB NOT NULL,
    PRIMARY KEY (request_id, responder_federation_id, responder_local_id)
) STRICT, WITHOUT ROWID;

-- ── Cached policy evaluation results ─────────────────────────────────────

-- Rebuildable cache: derivable at any time by rerunning policy-engine over
-- opinions/overrides/follows. Safe to truncate and repopulate wholesale
-- during a corruption-recovery quarantine-and-rebuild.
CREATE TABLE effective_policy (
    target_kind     TEXT NOT NULL,
    target_value    TEXT NOT NULL,
    decision        INTEGER NOT NULL,  -- 0=Allow 1=Deny 2=Ask 3=NoDecision
    tier            INTEGER NOT NULL,
    explanation_json TEXT NOT NULL,
    computed_at     INTEGER NOT NULL,
    PRIMARY KEY (target_kind, target_value)
) STRICT, WITHOUT ROWID;

-- The last decision that was actually enforced, kept separately from the
-- cache above so a nftables rollback has something authoritative to
-- revert to even if `effective_policy` gets wiped and is mid-rebuild.
CREATE TABLE last_known_good_policy (
    target_kind     TEXT NOT NULL,
    target_value    TEXT NOT NULL,
    decision        INTEGER NOT NULL,
    enforced_at     INTEGER NOT NULL,
    PRIMARY KEY (target_kind, target_value)
) STRICT, WITHOUT ROWID;

-- ── Presence / transport — rebuildable, ephemeral by nature ──────────────

CREATE TABLE presence_cache (
    federation_id   BLOB NOT NULL,
    local_id        BLOB NOT NULL,
    node_id         BLOB NOT NULL,
    last_seen_at    INTEGER NOT NULL,
    endpoint_hint   TEXT,
    PRIMARY KEY (federation_id, local_id, node_id)
) STRICT, WITHOUT ROWID;

CREATE TABLE relays (
    relay_id        BLOB PRIMARY KEY,
    endpoint_hint   TEXT NOT NULL,
    added_at        INTEGER NOT NULL,
    last_verified_at INTEGER
) STRICT;
