-- Applied-firewall-state metadata for the nft-enforcer crate. Kept in the
-- same local SQLite store as everything else rather than a second
-- database file — one node, one local store.

-- Singleton row (`id` always 0): the last ruleset this node actually
-- applied successfully — the idempotency comparison key (`digest`) and
-- the rollback-of-last-resort text (`ruleset_text`), independent of
-- whatever `nft list table` reports live (which is re-snapshotted fresh
-- on every apply attempt instead of trusting this row for rollback).
CREATE TABLE applied_ruleset_state (
    id INTEGER PRIMARY KEY CHECK (id = 0),
    digest TEXT NOT NULL,
    ruleset_text TEXT NOT NULL,
    revision INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
) STRICT;

-- Append-only audit trail: exactly which policy revision/digest produced
-- which outcome, for after-the-fact review.
CREATE TABLE apply_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    revision INTEGER NOT NULL,
    digest TEXT NOT NULL,
    decision_count INTEGER NOT NULL,
    summary TEXT NOT NULL,
    outcome TEXT NOT NULL,
    applied_at INTEGER NOT NULL
) STRICT;
