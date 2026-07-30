-- Device-approval opinions: a signed, replicable signal from a followed
-- peer about whether a specific MAC address should be trusted to join a
-- network. Same row shape/conventions as `opinions` (natural
-- author+sequence key, ON CONFLICT DO NOTHING dedup, no per-row FK to
-- `follows` since a signed statement always outlives any single trust
-- decision about its author) — just keyed by `mac` instead of a
-- `(target_kind, target_value)` pair, since this isn't a network-traffic
-- target at all.

CREATE TABLE device_approval_opinions (
    author_federation_id    BLOB NOT NULL,
    author_local_id         BLOB NOT NULL,
    sequence                INTEGER NOT NULL,
    mac                     TEXT NOT NULL,
    stance                  INTEGER NOT NULL,   -- 0=Allow 1=Deny 2=Ask
    reason_code             INTEGER NOT NULL,
    reason_note             TEXT,
    reason_evidence         BLOB,
    device_label            TEXT,
    issued_at               INTEGER NOT NULL,
    expires_at              INTEGER,
    supersedes_sequence     INTEGER,
    signature               BLOB NOT NULL,
    ingested_at             INTEGER NOT NULL,
    PRIMARY KEY (author_federation_id, author_local_id, sequence)
) STRICT, WITHOUT ROWID;

CREATE INDEX idx_device_approval_opinions_mac ON device_approval_opinions(mac);
