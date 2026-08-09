-- Locally provisioned social identities used by authenticated IRC sessions.
-- Private seeds are protected by the database file permissions, like the
-- existing router identity seed.
CREATE TABLE local_irc_identities (
    federation_id       BLOB NOT NULL,
    local_id            BLOB NOT NULL,
    oidc_subject        TEXT NOT NULL UNIQUE,
    signing_secret_seed BLOB NOT NULL,
    messaging_secret_seed BLOB NOT NULL,
    created_at           INTEGER NOT NULL,
    PRIMARY KEY (federation_id, local_id),
    FOREIGN KEY (federation_id, local_id)
        REFERENCES users(federation_id, local_id) ON DELETE CASCADE
) STRICT, WITHOUT ROWID;
