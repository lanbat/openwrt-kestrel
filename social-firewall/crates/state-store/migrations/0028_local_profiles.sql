CREATE TABLE local_profiles (
    profile_id BLOB PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL,
    active INTEGER NOT NULL DEFAULT 0
) STRICT, WITHOUT ROWID;

CREATE TABLE local_profile_policies (
    profile_id BLOB NOT NULL,
    policy_id BLOB NOT NULL,
    PRIMARY KEY (profile_id, policy_id),
    FOREIGN KEY (profile_id) REFERENCES local_profiles(profile_id) ON DELETE CASCADE
) STRICT, WITHOUT ROWID;
