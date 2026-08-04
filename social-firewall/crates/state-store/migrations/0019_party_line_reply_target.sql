-- Optional structured reply target for a party-line message — see
-- `domain_types::group::PartyLineMessage::in_reply_to`'s own doc. A
-- comment about a specific poll (a group vote's target) is provably
-- about it, not just chronologically nearby chat. Both nullable
-- together: a plain message (no reply target) has both NULL.
ALTER TABLE party_line_messages ADD COLUMN in_reply_to_target_kind TEXT;
ALTER TABLE party_line_messages ADD COLUMN in_reply_to_target_value TEXT;
