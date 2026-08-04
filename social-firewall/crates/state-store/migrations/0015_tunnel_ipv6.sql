-- Every social-firewall-provisioned WireGuard tunnel is dual-stack
-- capable, but until now only ever got an IPv4 tunnel-internal address —
-- the nft mark-chain already marked IPv6 destinations too (see
-- `wg-tunnel::routing::compile_mark_script`), but with no IPv6 policy
-- route or WireGuard allowed-ips entry, that marked traffic silently
-- fell through to the normal default route instead of the tunnel.
-- Nullable since existing rows predate IPv6 support; a newly accepted
-- tunnel always populates both columns going forward.

ALTER TABLE tunnel_connection_accepts ADD COLUMN assigned_tunnel_ip6 TEXT;
ALTER TABLE provisioned_tunnels ADD COLUMN tunnel_ip6 TEXT;
