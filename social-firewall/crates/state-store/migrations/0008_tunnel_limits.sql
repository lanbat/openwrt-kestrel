-- Advertised (never provider-enforced — see both columns' own doc on
-- `domain_types::TunnelAdvertisement`) connection/bandwidth limits.
ALTER TABLE tunnel_advertisements ADD COLUMN max_connections INTEGER;
ALTER TABLE tunnel_advertisements ADD COLUMN max_bandwidth_kbps INTEGER;

-- Back-reference to the advertisement a *consuming* `provisioned_tunnels`
-- row came from, so reconciliation can look up that advertisement's
-- `max_connections`/`max_bandwidth_kbps` at `provision_routing` time —
-- only the consumer's own router can actually enforce a limit against
-- its own traffic, the provider has no local enforcement point for
-- someone else's outbound rate. NULL for a `providing` row (the provider
-- doesn't need this to manage the peer it's serving) and, defensively,
-- for any row that predates this column.
ALTER TABLE provisioned_tunnels ADD COLUMN advertisement_sequence INTEGER;
