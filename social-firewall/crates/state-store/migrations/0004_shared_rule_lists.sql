-- Shared rule lists: a curated, named, versioned bundle of rules an
-- operator publishes and other operators can subscribe to. `sequence` is
-- a per-author counter shared across every list name that author
-- publishes (same convention `tunnel_advertisements` already uses for
-- "one monotonic id space, many logically-different things") — a new
-- version of an existing named list gets a new, higher sequence and
-- physically replaces the old version's row (see `supersedes_sequence`
-- and how `ingest_shared_rule_list`/`store_own_shared_rule_list` use it)
-- rather than accumulating full-entry-copy history forever, mirroring
-- `kestreld`'s own `replace_threat_feed`/`replace_oui` wholesale-replace
-- shape.

CREATE TABLE shared_rule_lists (
    author_federation_id BLOB NOT NULL,
    author_local_id      BLOB NOT NULL,
    sequence             INTEGER NOT NULL,
    name                 TEXT NOT NULL,
    description          TEXT NOT NULL,
    visibility           INTEGER NOT NULL, -- 0=Public 1=Restricted
    issued_at            INTEGER NOT NULL,
    expires_at           INTEGER,
    supersedes_sequence  INTEGER,
    signature            BLOB NOT NULL,
    ingested_at          INTEGER NOT NULL,
    PRIMARY KEY (author_federation_id, author_local_id, sequence)
) STRICT, WITHOUT ROWID;

-- Free-form tags (matching `split-routing`'s own `DNS_CATS`/`RESOLVE_CATS`
-- convention already in this repo) — one row per tag, the same
-- normalized-child-table shape every other list-valued field in this
-- crate already uses rather than a JSON-blob column.
CREATE TABLE shared_rule_list_categories (
    author_federation_id BLOB NOT NULL,
    author_local_id      BLOB NOT NULL,
    sequence             INTEGER NOT NULL,
    category             TEXT NOT NULL,
    PRIMARY KEY (author_federation_id, author_local_id, sequence, category),
    FOREIGN KEY (author_federation_id, author_local_id, sequence)
        REFERENCES shared_rule_lists(author_federation_id, author_local_id, sequence)
        ON DELETE CASCADE
) STRICT, WITHOUT ROWID;

-- One row per rule in the list — same target/stance/reason shape
-- `opinions` uses for a single signed statement, just scoped under a
-- list version instead of individually signed/sequenced. Deliberately
-- its own table, not folded into `opinions`: these entries were never
-- individually signed/sequenced by the author the way a real
-- `PolicyOpinion` was, and fabricating per-entry sequence numbers for
-- them would blur a real distinction that matters for auditability.
CREATE TABLE shared_rule_list_entries (
    author_federation_id BLOB NOT NULL,
    author_local_id      BLOB NOT NULL,
    sequence             INTEGER NOT NULL,
    target_kind          TEXT NOT NULL,
    target_value         TEXT NOT NULL,
    stance               INTEGER NOT NULL,
    reason_code          INTEGER NOT NULL,
    reason_note          TEXT,
    reason_evidence      BLOB NOT NULL,
    PRIMARY KEY (author_federation_id, author_local_id, sequence, target_kind, target_value),
    FOREIGN KEY (author_federation_id, author_local_id, sequence)
        REFERENCES shared_rule_lists(author_federation_id, author_local_id, sequence)
        ON DELETE CASCADE
) STRICT, WITHOUT ROWID;
