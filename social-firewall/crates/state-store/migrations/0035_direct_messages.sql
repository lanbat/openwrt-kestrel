CREATE TABLE direct_messages (
    sender_federation_id BLOB NOT NULL,
    sender_local_id BLOB NOT NULL,
    recipient_federation_id BLOB NOT NULL,
    recipient_local_id BLOB NOT NULL,
    sequence INTEGER NOT NULL,
    body TEXT NOT NULL,
    issued_at INTEGER NOT NULL,
    signature BLOB NOT NULL,
    PRIMARY KEY (sender_federation_id, sender_local_id, sequence)
) STRICT, WITHOUT ROWID;

CREATE INDEX direct_messages_for_recipient
    ON direct_messages(recipient_federation_id, recipient_local_id, issued_at, sequence);
