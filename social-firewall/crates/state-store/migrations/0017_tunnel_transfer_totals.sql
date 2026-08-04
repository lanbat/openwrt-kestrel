-- Per-peer WireGuard transfer totals, sampled from `wg show <iface> dump`
-- (which already reports live rx/tx counters per peer — no new
-- measurement, just reading columns that were already being fetched and
-- discarded). Purely local bookkeeping, never signed or exported: this is
-- the substrate for the tunnel-reciprocity signal (see
-- `StateStore::list_tunnel_balances`), and unlike every other trust
-- signal in this crate it can't be spoofed by a peer, since it's read off
-- this router's own live interface.
--
-- `last_raw_*` is the raw counter value last observed, used only to
-- compute a delta on the next sample (WireGuard's counters are
-- cumulative-since-interface-creation, not since some fixed epoch).
-- `cumulative_*` is this crate's own running total, which survives an
-- interface recreation (reboot, peer re-added) resetting the raw counter
-- back to zero — see `record_transfer_sample`'s own doc.
CREATE TABLE tunnel_transfer_totals (
    peer_federation_id BLOB NOT NULL,
    peer_local_id BLOB NOT NULL,
    direction TEXT NOT NULL CHECK (direction IN ('providing', 'consuming')),
    last_raw_rx INTEGER NOT NULL DEFAULT 0,
    last_raw_tx INTEGER NOT NULL DEFAULT 0,
    cumulative_rx INTEGER NOT NULL DEFAULT 0,
    cumulative_tx INTEGER NOT NULL DEFAULT 0,
    updated_at INTEGER NOT NULL,
    PRIMARY KEY (peer_federation_id, peer_local_id, direction)
) STRICT, WITHOUT ROWID;
