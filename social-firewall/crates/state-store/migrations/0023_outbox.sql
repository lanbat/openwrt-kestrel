CREATE TABLE outbound_outbox (
    outbox_id INTEGER PRIMARY KEY AUTOINCREMENT,
    destination_node_id TEXT NOT NULL,
    statement_kind INTEGER NOT NULL,
    payload BLOB NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    next_retry INTEGER NOT NULL,
    last_error TEXT,
    delivered INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL
);

CREATE INDEX outbound_outbox_due ON outbound_outbox (delivered, next_retry);
