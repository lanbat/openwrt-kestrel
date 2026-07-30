-- A locally-assigned label for a followed federation+local_id — the
-- address-book model, not a self-asserted/broadcast name (see
-- `LocalTrustRule::display_name`'s own doc for why: a real name registry
-- is exactly the consensus/governance work this project defers
-- everywhere else). Lives on `follows` (not `users`) because a label is
-- inherently part of the follow relationship — you don't need to name
-- someone you don't follow, and `follows` already has the natural
-- `(federation_id, local_id)` key this needs, unlike `users` (whose
-- `current_pubkey NOT NULL` column has no value to put there for a
-- followed peer this router has never actually ingested anything from).
ALTER TABLE follows ADD COLUMN display_name TEXT;

-- Federation-scoped, not globally unique: enforced only within one
-- federation, on this router's own local view — the same name string
-- can be reused across two different federations without conflict.
CREATE UNIQUE INDEX follows_display_name_per_federation
    ON follows(federation_id, display_name)
    WHERE display_name IS NOT NULL;
