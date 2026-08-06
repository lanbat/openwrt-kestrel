-- Signed shared policies. Metadata is kept separate from the ordered child
-- tables so entries and action parameters remain queryable without a blob.
CREATE TABLE shared_policies (
    author_federation_id BLOB NOT NULL,
    author_local_id      BLOB NOT NULL,
    policy_id            BLOB NOT NULL,
    sequence             INTEGER NOT NULL,
    name                 TEXT NOT NULL,
    description          TEXT NOT NULL,
    visibility           INTEGER NOT NULL,
    issued_at            INTEGER NOT NULL,
    expires_at           INTEGER,
    supersedes_sequence  INTEGER,
    signature            BLOB NOT NULL,
    ingested_at          INTEGER NOT NULL,
    PRIMARY KEY (author_federation_id, author_local_id, policy_id, sequence)
) STRICT, WITHOUT ROWID;

CREATE TABLE shared_policy_categories (
    author_federation_id BLOB NOT NULL,
    author_local_id      BLOB NOT NULL,
    policy_id            BLOB NOT NULL,
    sequence             INTEGER NOT NULL,
    ordinal              INTEGER NOT NULL,
    category             TEXT NOT NULL,
    PRIMARY KEY (author_federation_id, author_local_id, policy_id, sequence, ordinal),
    FOREIGN KEY (author_federation_id, author_local_id, policy_id, sequence)
        REFERENCES shared_policies(author_federation_id, author_local_id, policy_id, sequence)
        ON DELETE CASCADE
) STRICT, WITHOUT ROWID;

CREATE TABLE shared_policy_entries (
    author_federation_id BLOB NOT NULL,
    author_local_id      BLOB NOT NULL,
    policy_id            BLOB NOT NULL,
    sequence             INTEGER NOT NULL,
    ordinal              INTEGER NOT NULL,
    entry_id             BLOB NOT NULL,
    target_kind          TEXT NOT NULL,
    target_value         TEXT NOT NULL,
    action_kind          TEXT NOT NULL,
    action_value         TEXT,
    action_ttl_seconds   INTEGER,
    category             TEXT,
    reason_code          INTEGER NOT NULL,
    reason_note          TEXT,
    reason_evidence      BLOB NOT NULL,
    expires_at           INTEGER,
    PRIMARY KEY (author_federation_id, author_local_id, policy_id, sequence, ordinal),
    UNIQUE (author_federation_id, author_local_id, policy_id, sequence, entry_id),
    FOREIGN KEY (author_federation_id, author_local_id, policy_id, sequence)
        REFERENCES shared_policies(author_federation_id, author_local_id, policy_id, sequence)
        ON DELETE CASCADE
) STRICT, WITHOUT ROWID;
