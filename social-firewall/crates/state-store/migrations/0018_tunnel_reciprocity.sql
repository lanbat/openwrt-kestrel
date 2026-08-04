-- Optional per-peer reciprocity floor for tunnel auto-accept — see
-- `domain_types::trust::TunnelTrustRule::min_reciprocity_ratio`'s own
-- doc. Nullable, defaulting to NULL (no requirement), so every existing
-- row's behavior is unchanged until an operator opts in.
ALTER TABLE tunnel_trust_rules ADD COLUMN min_reciprocity_ratio REAL;
