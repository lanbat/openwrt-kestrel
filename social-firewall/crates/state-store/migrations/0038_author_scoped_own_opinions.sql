CREATE TABLE own_opinion_log_v2 (
    author_federation_id   BLOB NOT NULL,
    author_local_id        BLOB NOT NULL,
    sequence               INTEGER NOT NULL,
    target_kind            TEXT NOT NULL,
    target_value           TEXT NOT NULL,
    stance                 INTEGER NOT NULL,
    reason_code            INTEGER NOT NULL,
    reason_note            TEXT,
    reason_evidence        BLOB,
    issued_at              INTEGER NOT NULL,
    expires_at             INTEGER,
    supersedes_sequence    INTEGER,
    signature              BLOB NOT NULL,
    PRIMARY KEY (author_federation_id, author_local_id, sequence)
) STRICT, WITHOUT ROWID;

INSERT INTO own_opinion_log_v2 (
    author_federation_id, author_local_id, sequence, target_kind, target_value,
    stance, reason_code, reason_note, reason_evidence, issued_at, expires_at,
    supersedes_sequence, signature
)
SELECT u.federation_id, u.local_id, o.sequence, o.target_kind, o.target_value,
       o.stance, o.reason_code, o.reason_note, o.reason_evidence, o.issued_at,
       o.expires_at, o.supersedes_sequence, o.signature
FROM own_opinion_log o
JOIN users u ON u.is_self = 1;

DROP TABLE own_opinion_log;
ALTER TABLE own_opinion_log_v2 RENAME TO own_opinion_log;
CREATE INDEX idx_own_opinion_log_target ON own_opinion_log(target_kind, target_value);
