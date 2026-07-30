-- Free-form discovery tags per tunnel advertisement, by symmetry with
-- `shared_rule_list_categories` — same normalized-child-table shape,
-- capped at `domain_types::tunnel::MAX_TUNNEL_TAGS` (enforced in Rust,
-- by rejection, not here — SQL has no easy way to reject an INSERT batch
-- based on a sibling row count without a trigger, and the reject-vs-
-- truncate decision belongs with the domain type's own validation).
CREATE TABLE tunnel_advertisement_tags (
    provider_federation_id  BLOB NOT NULL,
    provider_local_id       BLOB NOT NULL,
    sequence                INTEGER NOT NULL,
    tag                     TEXT NOT NULL,
    PRIMARY KEY (provider_federation_id, provider_local_id, sequence, tag),
    FOREIGN KEY (provider_federation_id, provider_local_id, sequence)
        REFERENCES tunnel_advertisements(provider_federation_id, provider_local_id, sequence)
        ON DELETE CASCADE
) STRICT, WITHOUT ROWID;

-- Mirrors `follows.category_filter`, one dimension over: restricts which
-- of a trusted provider's advertisements `auto_consume_advertisements`
-- acts on.
ALTER TABLE tunnel_trust_rules ADD COLUMN tag_filter TEXT;
