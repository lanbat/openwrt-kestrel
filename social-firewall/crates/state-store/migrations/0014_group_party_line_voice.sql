-- IRC-style party-line moderation: a group-wide `+m`-equivalent flag
-- plus an explicit `+v`-equivalent voice list, both part of the same
-- versioned `Group` snapshot every other membership field already is —
-- no new signed-statement type needed, see `domain_types::group::Group`'s
-- own doc on `party_line_moderated`/`voiced_members`.

ALTER TABLE groups ADD COLUMN party_line_moderated INTEGER NOT NULL DEFAULT 0 CHECK (party_line_moderated IN (0, 1));

CREATE TABLE group_voiced_members (
    group_id BLOB NOT NULL,
    sequence INTEGER NOT NULL,
    user_federation_id BLOB NOT NULL,
    user_local_id BLOB NOT NULL,
    PRIMARY KEY (group_id, sequence, user_federation_id, user_local_id),
    FOREIGN KEY (group_id, sequence) REFERENCES groups(group_id, sequence) ON DELETE CASCADE
) STRICT, WITHOUT ROWID;
