-- This router's own Iroh keypair — a fourth, dedicated key alongside the
-- identity-signing (Ed25519), messaging (X25519), and WireGuard (X25519)
-- ones, following the exact same "generate on first use, persist the
-- seed" pattern as wg_secret_seed/messaging_secret_seed. Iroh's own
-- NodeId is itself an Ed25519 public key, so this is the fourth
-- application of an already-established principle here, not a new one.
ALTER TABLE users ADD COLUMN iroh_secret_seed BLOB;

-- A followed peer's Iroh node id (their public key, as returned by
-- IrohTransport::node_id — see p2p-transport), settable only via an
-- explicit operator action (`add-follow --iroh-node-id` /
-- `set-follow-node-id`), the same manually-confirmed, trust-on-first-use
-- pattern `display_name` already uses. Never learned or applied silently.
ALTER TABLE follows ADD COLUMN iroh_node_id TEXT;
