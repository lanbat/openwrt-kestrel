-- Widen `enforced_decision_contributors.source_kind` to also allow
-- 'group' (a group's aggregate stance, see `domain_types::group`, is now
-- a third possible contribution source alongside a user's opinion and a
-- federation's statement) — SQLite has no `ALTER TABLE ... DROP
-- CONSTRAINT`, so this recreates the table with the relaxed CHECK,
-- copying over anything already there.
CREATE TABLE enforced_decision_contributors_new (
    id                   INTEGER PRIMARY KEY AUTOINCREMENT,
    target_kind          TEXT NOT NULL,
    target_value         TEXT NOT NULL,
    source_kind          TEXT NOT NULL CHECK (source_kind IN ('user', 'federation', 'group')),
    source_federation_id BLOB NOT NULL,
    source_local_id      BLOB,
    stance               INTEGER NOT NULL,
    weight               REAL NOT NULL,
    reason_code          INTEGER NOT NULL,
    reason_note          TEXT,
    reason_evidence      BLOB NOT NULL
) STRICT;

INSERT INTO enforced_decision_contributors_new SELECT * FROM enforced_decision_contributors;
DROP TABLE enforced_decision_contributors;
ALTER TABLE enforced_decision_contributors_new RENAME TO enforced_decision_contributors;

CREATE INDEX enforced_decision_contributors_by_target ON enforced_decision_contributors(target_kind, target_value);
