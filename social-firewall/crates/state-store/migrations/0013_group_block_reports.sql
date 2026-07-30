-- Reasoned, signed, attributable block reports — the "surfaced, not
-- silent" counterpart to `group_blocked_users` (0012), which stays the
-- purely local enforcement mechanism (see `StateStore::block_group_user`'s
-- own doc for how the two fit together: ingesting someone else's report
-- here is always informational only and never drives this router's own
-- enforcement — no automatic global ban).
CREATE TABLE group_block_reports (
    group_id                    BLOB NOT NULL,
    reporter_federation_id      BLOB NOT NULL,
    reporter_local_id           BLOB NOT NULL,
    sequence                    INTEGER NOT NULL,
    blocked_user_federation_id  BLOB NOT NULL,
    blocked_user_local_id       BLOB NOT NULL,
    reason_code                 INTEGER NOT NULL,
    reason_note                 TEXT,
    reason_evidence             BLOB,
    issued_at                   INTEGER NOT NULL,
    signature                   BLOB NOT NULL,
    ingested_at                 INTEGER NOT NULL,
    PRIMARY KEY (group_id, reporter_federation_id, reporter_local_id, sequence)
) STRICT, WITHOUT ROWID;

CREATE INDEX idx_group_block_reports_blocked_user ON group_block_reports(group_id, blocked_user_federation_id, blocked_user_local_id);

-- A local block now also requires a reason, matching the "a block with
-- no reason is just an opaque veto" principle applied to local
-- enforcement, not just the exportable report. Default only exists to
-- satisfy the NOT NULL constraint for the brand-new, still-empty table
-- from 0012 — nothing has ever actually relied on it.
ALTER TABLE group_blocked_users ADD COLUMN reason_code INTEGER NOT NULL DEFAULT 9;
ALTER TABLE group_blocked_users ADD COLUMN reason_note TEXT;
ALTER TABLE group_blocked_users ADD COLUMN reason_evidence BLOB;
