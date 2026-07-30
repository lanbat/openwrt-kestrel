-- "Why is this rule active" lookup: which peer/federation opinions
-- contributed to each currently-*enforced* target's trust-weighted
-- decision. A current-state snapshot, not a growing history —
-- `apply_log` already serves as the append-only audit trail for overall
-- apply outcomes; this table is entirely replaced on every real (never
-- dry-run) `sf apply` run, since `policy-engine`'s aggregation is
-- re-evaluated fresh every time regardless of whether the compiled nft
-- digest itself changed (the same weighted inputs can shift — a
-- follow's weight changed, someone's opinion expired — without the
-- Allow/Deny/Ask *decision*, and therefore the nft ruleset, changing at
-- all).
CREATE TABLE enforced_decision_contributors (
    id                   INTEGER PRIMARY KEY AUTOINCREMENT,
    target_kind          TEXT NOT NULL,
    target_value         TEXT NOT NULL,
    -- 'user' or 'federation' — mirrors `StatementAuthor`. Not a
    -- `WITHOUT ROWID` natural-keyed table because `source_local_id` is
    -- legitimately NULL for a federation-sourced contribution (a
    -- `FederationStatement` has no individual local_id), and SQLite
    -- forbids NULL in any column of a `WITHOUT ROWID` primary key.
    source_kind          TEXT NOT NULL CHECK (source_kind IN ('user', 'federation')),
    source_federation_id BLOB NOT NULL,
    source_local_id      BLOB,
    stance               INTEGER NOT NULL,
    weight               REAL NOT NULL,
    reason_code          INTEGER NOT NULL,
    reason_note          TEXT,
    reason_evidence      BLOB NOT NULL
) STRICT;

CREATE INDEX enforced_decision_contributors_by_target ON enforced_decision_contributors(target_kind, target_value);
