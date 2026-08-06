-- Initial schema replacing kestreld's flat files under base_dir with one
-- SQLite database, `iface` as a normal column instead of one file per
-- network. Forward-only: never edit a shipped migration, add a new
-- numbered file instead.
--
-- `{iface}-notify.conf` is NOT modeled here — it's a human/install-time
-- config file re-parsed by install.sh itself, not kestreld-owned runtime
-- data; it stays a flat file, entirely out of scope for this migration.
--
-- The three join-state files (`-join-approved`, `-join-denied`,
-- `-join-pending`) are deliberately kept as three independent tables
-- rather than collapsed into one `status` column: today a denied MAC is
-- also re-added to pending ("to keep IP visible" per
-- `routes/approve_join.rs`'s `deny` action) — these are NOT mutually
-- exclusive states in the current behavior, and collapsing them would be
-- a silent behavior change, not a pure storage-format swap.

-- `schema_migrations` is created by `Store::run_migrations` itself before
-- any migration file runs, so it is intentionally not declared here.

CREATE TABLE device_labels (
    iface TEXT NOT NULL,
    mac TEXT NOT NULL,
    label TEXT NOT NULL,
    PRIMARY KEY (iface, mac)
) STRICT, WITHOUT ROWID;

-- Mirrors `data::fingerprint::FingerprintRecord`'s on-disk encoding
-- closely (comma-joined `macs`, `label@ts|label@ts`-joined
-- `label_history`) rather than normalizing into child tables — the
-- registry is always read/mutated/written as a whole `Vec<FingerprintRecord>`
-- today, never row-by-row, so keeping the same encoding lets
-- `data/fingerprint.rs`'s existing parse/format/scoring logic move over
-- almost unchanged in the later phase that touches call sites.
CREATE TABLE device_fingerprints (
    iface TEXT NOT NULL,
    id TEXT NOT NULL,
    label TEXT NOT NULL,
    dhcp_options TEXT NOT NULL DEFAULT '',
    dhcp_vendor TEXT NOT NULL DEFAULT '',
    wifi_caps TEXT NOT NULL DEFAULT '',
    mdns_name TEXT NOT NULL DEFAULT '',
    mdns_model TEXT NOT NULL DEFAULT '',
    macs TEXT NOT NULL DEFAULT '',
    last_seen INTEGER NOT NULL DEFAULT 0,
    first_seen INTEGER NOT NULL DEFAULT 0,
    label_history TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (iface, id)
) STRICT, WITHOUT ROWID;

CREATE TABLE device_ips (
    iface TEXT NOT NULL,
    mac TEXT NOT NULL,
    ip TEXT NOT NULL,
    PRIMARY KEY (iface, mac)
) STRICT, WITHOUT ROWID;

CREATE TABLE device_ip6s (
    iface TEXT NOT NULL,
    mac TEXT NOT NULL,
    ip6 TEXT NOT NULL,
    PRIMARY KEY (iface, mac)
) STRICT, WITHOUT ROWID;

CREATE TABLE device_limits (
    iface TEXT NOT NULL,
    mac TEXT NOT NULL,
    limit_mbps INTEGER NOT NULL,
    PRIMARY KEY (iface, mac)
) STRICT, WITHOUT ROWID;

-- Unique on (iface, mac, dst, port, proto) matching `write_ip_rule`'s
-- existing full-line dedup check; domain rules (`write_domain_rule`) are
-- always at most one per (iface, mac, dst) since that call site removes
-- any existing (mac, dst) rule before appending — enforced at the Store
-- method level (delete-then-insert), not by a narrower unique index, so
-- IP rules for the same dst on different ports can still coexist.
CREATE TABLE device_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    iface TEXT NOT NULL,
    mac TEXT NOT NULL,
    dst TEXT NOT NULL,
    action TEXT NOT NULL,
    port TEXT NOT NULL DEFAULT '',
    proto TEXT NOT NULL DEFAULT '',
    route TEXT NOT NULL DEFAULT ''
) STRICT;
CREATE UNIQUE INDEX idx_device_rules_dedup ON device_rules(iface, mac, dst, port, proto);

CREATE TABLE allowed_macs (
    iface TEXT NOT NULL,
    mac TEXT NOT NULL,
    ip TEXT NOT NULL DEFAULT '',
    label TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (iface, mac)
) STRICT, WITHOUT ROWID;

CREATE TABLE join_approved (
    iface TEXT NOT NULL,
    mac TEXT NOT NULL,
    PRIMARY KEY (iface, mac)
) STRICT, WITHOUT ROWID;

CREATE TABLE join_denied (
    iface TEXT NOT NULL,
    mac TEXT NOT NULL,
    PRIMARY KEY (iface, mac)
) STRICT, WITHOUT ROWID;

CREATE TABLE join_pending (
    iface TEXT NOT NULL,
    mac TEXT NOT NULL,
    ip TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (iface, mac)
) STRICT, WITHOUT ROWID;

-- `ip` empty for a pure-IPv6 approval, matching the flat file's `mac ip`
-- (space-separated, IPv4 slot blank) convention exactly.
CREATE TABLE join_approved_ips (
    iface TEXT NOT NULL,
    mac TEXT NOT NULL,
    ip TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (iface, mac)
) STRICT, WITHOUT ROWID;

-- Append-only. `when_str` is the pre-formatted "%d %b %H:%M" string
-- `cmd::append_join_history` already produces by shelling to `date` —
-- stored verbatim rather than reformatted from `ts` at read time, so
-- existing display code (`routes::status`/`routes::device`) needs no
-- date-formatting logic added in Rust.
CREATE TABLE join_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    iface TEXT NOT NULL,
    ts INTEGER NOT NULL,
    when_str TEXT NOT NULL,
    action TEXT NOT NULL,
    mac TEXT NOT NULL,
    ip4 TEXT NOT NULL DEFAULT '',
    ip6 TEXT NOT NULL DEFAULT '',
    hostname TEXT NOT NULL DEFAULT '',
    actor TEXT NOT NULL DEFAULT '',
    actor_ip4 TEXT NOT NULL DEFAULT '',
    actor_ip6 TEXT NOT NULL DEFAULT '',
    actor_mac TEXT NOT NULL DEFAULT ''
) STRICT;
CREATE INDEX idx_join_history_iface_mac ON join_history(iface, mac);

-- One row per (iface, mac, dst, port, proto) pending connection attempt —
-- was one flat file per device (`{iface}-pending-{mac_n}`); hot table,
-- pruned by age the same way the flat file was.
CREATE TABLE pending_connections (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    iface TEXT NOT NULL,
    mac TEXT NOT NULL,
    dst TEXT NOT NULL,
    port TEXT NOT NULL DEFAULT '',
    proto TEXT NOT NULL DEFAULT '',
    ts INTEGER NOT NULL DEFAULT 0
) STRICT;
CREATE INDEX idx_pending_connections_iface_mac ON pending_connections(iface, mac);

-- Was one flat file per device (`{iface}-dns-answers-{mac_n}`); hot,
-- pruned to `dns_answers::RETENTION_SECS`.
CREATE TABLE dns_answers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    iface TEXT NOT NULL,
    mac TEXT NOT NULL,
    ts INTEGER NOT NULL,
    domain TEXT NOT NULL,
    ip TEXT NOT NULL
) STRICT;
CREATE INDEX idx_dns_answers_iface_mac ON dns_answers(iface, mac);
CREATE INDEX idx_dns_answers_ip ON dns_answers(iface, mac, ip);

-- Was `{iface}-connection-history`, unbounded on disk — this migration
-- adds real retention (`DELETE WHERE ts < cutoff`) as an explicit,
-- flagged behavior improvement, not pure parity.
CREATE TABLE connection_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    iface TEXT NOT NULL,
    ts INTEGER NOT NULL,
    event TEXT NOT NULL,
    src TEXT NOT NULL,
    dst TEXT NOT NULL DEFAULT '',
    port TEXT NOT NULL DEFAULT '',
    proto TEXT NOT NULL DEFAULT ''
) STRICT;
CREATE INDEX idx_connection_history_iface ON connection_history(iface, ts);

-- Was the single shared `notified-attempts` file (not per-iface — the
-- iface is already embedded in `key` by the caller, e.g.
-- "deny:{iface}:{src}"). `seen_at` is an insertion-order surrogate
-- (autoincrement id) used to replicate `trim_seen`'s "keep the newest 400
-- once past 500" behavior via `ORDER BY seen_at`.
CREATE TABLE notified_attempts (
    seen_at INTEGER PRIMARY KEY AUTOINCREMENT,
    key TEXT NOT NULL UNIQUE
) STRICT;

CREATE TABLE plugin_notes (
    iface TEXT NOT NULL,
    mac TEXT NOT NULL,
    dst TEXT NOT NULL,
    plugin_name TEXT NOT NULL DEFAULT '',
    note TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (iface, mac, dst)
) STRICT, WITHOUT ROWID;

CREATE TABLE observation_windows (
    iface TEXT NOT NULL,
    mac TEXT NOT NULL,
    started_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    PRIMARY KEY (iface, mac)
) STRICT, WITHOUT ROWID;

CREATE TABLE bandwidth_alerted (
    iface TEXT NOT NULL,
    mac TEXT NOT NULL,
    PRIMARY KEY (iface, mac)
) STRICT, WITHOUT ROWID;

-- Singleton row (`id` always 0) — was `wan-state` + `wan-down-since`.
CREATE TABLE wan_state (
    id INTEGER PRIMARY KEY CHECK (id = 0),
    state TEXT NOT NULL,
    down_since INTEGER
) STRICT;

CREATE TABLE vpn_state (
    iface TEXT PRIMARY KEY,
    state TEXT NOT NULL
) STRICT, WITHOUT ROWID;

-- Bulk reference data (was `oui.txt`) — replaced wholesale on every
-- `--update-oui` run, same as the flat file was.
CREATE TABLE oui_entries (
    prefix TEXT PRIMARY KEY,
    vendor TEXT NOT NULL
) STRICT, WITHOUT ROWID;

-- Was `threat-domains.txt`, `domain\tfeed_id` per line — a domain can
-- appear under more than one feed, matching `threat_domains::lookup_domains`
-- returning every matching feed id, not just the first.
CREATE TABLE threat_domains (
    domain TEXT NOT NULL,
    feed_id TEXT NOT NULL,
    PRIMARY KEY (domain, feed_id)
) STRICT, WITHOUT ROWID;
