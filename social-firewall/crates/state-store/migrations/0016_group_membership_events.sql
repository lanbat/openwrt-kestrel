-- IRC-style join/leave notices for the party line: a member entering or
-- leaving a group's membership union (owners ∪ admins ∪ voting_members ∪
-- non_voting_members) is recorded here, derived purely from diffing the
-- previous stored `Group` version against the new one inside
-- `StateStore::ingest_group` — no new signed-statement type needed, the
-- underlying `Group` version transition is already authorized/signed.
--
-- AUTOINCREMENT-keyed, not WITHOUT ROWID, same reasoning as
-- `enforced_decision_contributors`: this is an append-only local log, not
-- a natural-key table.
CREATE TABLE group_membership_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    group_id BLOB NOT NULL,
    user_federation_id BLOB NOT NULL,
    user_local_id BLOB NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('joined', 'left')),
    at INTEGER NOT NULL
) STRICT;

CREATE INDEX idx_group_membership_events_group ON group_membership_events(group_id);
