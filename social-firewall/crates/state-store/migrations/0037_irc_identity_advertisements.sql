CREATE TABLE irc_identity_advertisements (
    federation_id    BLOB NOT NULL,
    local_id         BLOB NOT NULL,
    sequence         INTEGER NOT NULL,
    messaging_pubkey BLOB NOT NULL,
    issued_at        INTEGER NOT NULL,
    signing_pubkey   BLOB NOT NULL,
    signature        BLOB NOT NULL,
    PRIMARY KEY (federation_id, local_id, sequence)
) STRICT, WITHOUT ROWID;
