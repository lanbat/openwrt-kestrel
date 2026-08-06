CREATE TABLE group_fingerprint_keys (
    group_id BLOB PRIMARY KEY,
    key BLOB NOT NULL
) STRICT, WITHOUT ROWID;
