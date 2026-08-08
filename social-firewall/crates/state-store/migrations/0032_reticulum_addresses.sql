-- Reticulum has its own identity and destination namespace. Keep it separate
-- from Iroh addressing and from the application's signing/messaging keys.
ALTER TABLE users ADD COLUMN reticulum_secret_seed BLOB;

CREATE TABLE peer_transport_addresses (
    federation_id BLOB NOT NULL,
    local_id BLOB NOT NULL,
    transport TEXT NOT NULL,
    address TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    verified INTEGER NOT NULL DEFAULT 0 CHECK (verified IN (0, 1)),
    updated_at INTEGER NOT NULL,
    PRIMARY KEY (federation_id, local_id, transport)
) STRICT, WITHOUT ROWID;
