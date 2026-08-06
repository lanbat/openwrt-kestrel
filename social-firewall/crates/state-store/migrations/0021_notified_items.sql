-- Idempotency tracking for the background notifier.
CREATE TABLE notified_items (
    item_kind TEXT NOT NULL,
    item_key TEXT NOT NULL,
    notified_at INTEGER NOT NULL,
    PRIMARY KEY (item_kind, item_key)
) STRICT, WITHOUT ROWID;
