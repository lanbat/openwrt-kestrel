-- Signed votes by a group's current voting members on shared-policy entries.
-- Membership is evaluated at read time, so votes remain useful evidence after
-- a member is removed from a group's current snapshot.
CREATE TABLE policy_votes (
    policy_id            BLOB NOT NULL,
    entry_id             BLOB NOT NULL,
    policy_sequence      INTEGER NOT NULL,
    group_id             BLOB NOT NULL,
    voter_federation_id  BLOB NOT NULL,
    voter_local_id       BLOB NOT NULL,
    sequence             INTEGER NOT NULL,
    stance               INTEGER NOT NULL,
    reason_code          INTEGER NOT NULL,
    reason_note          TEXT,
    reason_evidence      BLOB NOT NULL,
    issued_at            INTEGER NOT NULL,
    expires_at           INTEGER,
    signature            BLOB NOT NULL,
    ingested_at          INTEGER NOT NULL,
    PRIMARY KEY (policy_id, entry_id, policy_sequence, group_id,
                 voter_federation_id, voter_local_id, sequence)
) STRICT, WITHOUT ROWID;

CREATE INDEX policy_votes_by_poll
    ON policy_votes(policy_id, entry_id, group_id, issued_at);
