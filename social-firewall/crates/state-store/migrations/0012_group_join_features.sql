-- Two additions to the group join-request flow, requested after items
-- 1/9 above shipped: an owner-settable join prompt, and the ability to
-- block a user from a group altogether (not just reject one pending
-- request).

ALTER TABLE groups ADD COLUMN join_prompt TEXT;

-- Renamed from `message` now that its purpose is specifically "answer to
-- the group's `join_prompt`, if it has one" — see `domain_types::group`'s
-- doc on `GroupJoinRequest::answer`.
ALTER TABLE group_join_requests RENAME COLUMN message TO answer;

-- A group-scoped, router-local ban list — deliberately not part of the
-- signed `Group` state itself (blocking is a unilateral moderation
-- decision by whichever router is reviewing requests, not a group-wide
-- fact requiring republication/consensus, the same reasoning that
-- already keeps a plain "rejected" status local-only). Referenced by
-- `group_id` alone (no FK to a specific `groups` row) for the same
-- reason `group_join_requests` isn't: a block outlives any single
-- membership snapshot.
CREATE TABLE group_blocked_users (
    group_id           BLOB NOT NULL,
    user_federation_id BLOB NOT NULL,
    user_local_id      BLOB NOT NULL,
    blocked_at         INTEGER NOT NULL,
    PRIMARY KEY (group_id, user_federation_id, user_local_id)
) STRICT, WITHOUT ROWID;
