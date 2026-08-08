CREATE TABLE local_irc_history (
    message_id INTEGER PRIMARY KEY AUTOINCREMENT,
    nickname TEXT NOT NULL,
    body TEXT NOT NULL,
    issued_at INTEGER NOT NULL,
    byte_len INTEGER NOT NULL
) STRICT;

CREATE INDEX local_irc_history_by_time
    ON local_irc_history(issued_at, message_id);
