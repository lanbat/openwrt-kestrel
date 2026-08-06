-- Group-scoped signed observations and comments for one fingerprint revision.
CREATE TABLE fingerprint_observations (
    group_id              BLOB NOT NULL,
    fingerprint_id        BLOB NOT NULL,
    fingerprint_revision  INTEGER NOT NULL,
    observer_federation_id BLOB NOT NULL,
    observer_local_id     BLOB NOT NULL,
    signal_family         TEXT NOT NULL,
    evidence_digest       BLOB NOT NULL,
    confidence            INTEGER NOT NULL,
    issued_at             INTEGER NOT NULL,
    expires_at            INTEGER,
    signature             BLOB NOT NULL,
    PRIMARY KEY (group_id, fingerprint_id, fingerprint_revision,
                 observer_federation_id, observer_local_id, signal_family)
) STRICT, WITHOUT ROWID;

CREATE INDEX fingerprint_observations_by_revision
    ON fingerprint_observations(group_id, fingerprint_id, fingerprint_revision,
                                issued_at);

CREATE TABLE fingerprint_comments (
    group_id              BLOB NOT NULL,
    fingerprint_id        BLOB NOT NULL,
    fingerprint_revision  INTEGER NOT NULL,
    author_federation_id  BLOB NOT NULL,
    author_local_id       BLOB NOT NULL,
    sequence              INTEGER NOT NULL,
    body                  TEXT NOT NULL,
    issued_at             INTEGER NOT NULL,
    signature             BLOB NOT NULL,
    PRIMARY KEY (group_id, fingerprint_id, fingerprint_revision,
                 author_federation_id, author_local_id, sequence)
) STRICT, WITHOUT ROWID;

CREATE INDEX fingerprint_comments_by_revision
    ON fingerprint_comments(group_id, fingerprint_id, fingerprint_revision,
                            issued_at);
