CREATE TABLE device_presence_observations (
    observation_id BLOB PRIMARY KEY CHECK(length(observation_id) = 32),
    device_id BLOB CHECK(device_id IS NULL OR length(device_id) = 32),
    observer_node_id BLOB NOT NULL CHECK(length(observer_node_id) = 32),
    network TEXT NOT NULL,
    source TEXT NOT NULL,
    first_seen INTEGER NOT NULL,
    last_seen INTEGER NOT NULL,
    expires_at INTEGER
) STRICT, WITHOUT ROWID;

CREATE INDEX device_presence_by_device
    ON device_presence_observations(device_id, last_seen);
