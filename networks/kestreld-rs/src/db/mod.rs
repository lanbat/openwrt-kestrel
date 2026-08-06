//! SQLite-backed replacement for `data::files`'s flat-file storage.
//!
//! `Store` wraps one `rusqlite::Connection` behind a `tokio::sync::Mutex` —
//! kestreld runs the same `base_dir` from several concurrent OS processes
//! (the daemon, per-CGI-request processes, cron one-shots) with **zero
//! cross-process locking today** beyond flat files' rename-based atomicity,
//! which only protects single writes, not read-modify-write cycles. SQLite
//! in WAL mode plus a busy timeout gives real cross-process safety for
//! free — the actual motivation for this migration, not just a style
//! change. Within one process, the mutex serializes access; `rusqlite`
//! calls are synchronous, so callers pay a short blocking window while
//! holding the lock — acceptable for this data volume on this hardware
//! class (matches the rest of this codebase's general tolerance for
//! blocking `std`-style calls in async code, e.g. `tokio::fs`).
//!
//! Structs here are plain data holders, independent of `data::files`'/
//! `data::fingerprint`'s identically-shaped types — this module has no
//! dependency on domain modules by design (see the migration plan's
//! `Store`-boundary decision), which also keeps a future non-SQLite
//! backend an additive change rather than a rewrite. Call sites convert at
//! their own boundary; deliberate short-term duplication until Phase C/D
//! wires each one over.
//!
//! **Deliberately out of scope here** (see the migration plan): `{iface}
//! -notify.conf` (human/install-time config), `/etc/dnsmasq.d/*.conf` and
//! `/etc/nftables.d/*` (generated artifacts for other daemons — still
//! generated as flat files, just sourced from here instead of from other
//! flat files), `/tmp/kestrel-joins`, `split_routing_dir`'s own files, and
//! the plugin framework's own small bookkeeping files.

use rusqlite::{params, Connection, OptionalExtension};
use std::collections::HashMap;
use std::path::Path;
use tokio::sync::Mutex;

const MIGRATIONS: &[(i64, &str)] = &[
    (1, include_str!("migrations/0001_init.sql")),
    (2, include_str!("migrations/0002_fingerprint_signals.sql")),
    (3, include_str!("migrations/0003_fingerprint_history.sql")),
];

pub struct Store(Mutex<Connection>);

impl Store {
    pub async fn open(base_dir: &Path) -> rusqlite::Result<Self> {
        let conn = Connection::open(base_dir.join("kestrel.sqlite"))?;
        Self::init(conn)
    }

    /// In-memory database — tests only, never real router state.
    pub fn open_in_memory() -> rusqlite::Result<Self> {
        let conn = Connection::open_in_memory()?;
        Self::init(conn)
    }

    fn init(conn: Connection) -> rusqlite::Result<Self> {
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = NORMAL;
             PRAGMA busy_timeout = 5000;
             PRAGMA foreign_keys = ON;",
        )?;
        run_migrations(&conn)?;
        Ok(Self(Mutex::new(conn)))
    }
}

fn run_migrations(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS schema_migrations (
             version INTEGER PRIMARY KEY,
             applied_at INTEGER NOT NULL
         );",
    )?;
    let current: i64 = conn.query_row(
        "SELECT COALESCE(MAX(version), 0) FROM schema_migrations",
        [],
        |r| r.get(0),
    )?;
    for (version, sql) in MIGRATIONS {
        if *version <= current {
            continue;
        }
        conn.execute_batch(sql)?;
        conn.execute(
            "INSERT INTO schema_migrations (version, applied_at) VALUES (?1, ?2)",
            params![version, now()],
        )?;
    }
    Ok(())
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

// ── Device labels ────────────────────────────────────────────────────────

impl Store {
    pub async fn get_label(&self, iface: &str, mac: &str) -> rusqlite::Result<Option<String>> {
        self.0
            .lock()
            .await
            .query_row(
                "SELECT label FROM device_labels WHERE iface = ?1 AND mac = ?2",
                params![iface, mac],
                |r| r.get(0),
            )
            .optional()
    }

    pub async fn remove_label(&self, iface: &str, mac: &str) -> rusqlite::Result<()> {
        self.0.lock().await.execute(
            "DELETE FROM device_labels WHERE iface = ?1 AND mac = ?2",
            params![iface, mac],
        )?;
        Ok(())
    }

    pub async fn set_label(&self, iface: &str, mac: &str, label: &str) -> rusqlite::Result<()> {
        self.0.lock().await.execute(
            "INSERT INTO device_labels (iface, mac, label) VALUES (?1, ?2, ?3)
             ON CONFLICT(iface, mac) DO UPDATE SET label = excluded.label",
            params![iface, mac, label],
        )?;
        Ok(())
    }

    pub async fn all_labels(&self, iface: &str) -> rusqlite::Result<HashMap<String, String>> {
        let conn = self.0.lock().await;
        let mut stmt = conn.prepare("SELECT mac, label FROM device_labels WHERE iface = ?1")?;
        let rows = stmt.query_map(params![iface], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
        })?;
        rows.collect()
    }
}

// ── Device fingerprints (whole-registry read/write, matching the
//    existing read-all/mutate/write-all granularity in data::fingerprint) ──

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FingerprintRow {
    pub id: String,
    pub label: String,
    pub dhcp_options: String,
    pub dhcp_vendor: String,
    pub wifi_caps: String,
    pub mdns_name: String,
    pub mdns_model: String,
    pub macs: String,
    pub last_seen: i64,
    pub first_seen: i64,
    pub label_history: String,
    pub browser_cookie: String,
    pub http_headers: String,
    pub tcp_syn: String,
    pub tls_clienthello: String,
    pub quic_initial: String,
    pub evidence_json: String,
}

impl Store {
    pub async fn read_fingerprint_registry(
        &self,
        iface: &str,
    ) -> rusqlite::Result<Vec<FingerprintRow>> {
        let conn = self.0.lock().await;
        let mut stmt = conn.prepare(
            "SELECT id, label, dhcp_options, dhcp_vendor, wifi_caps, mdns_name, mdns_model, macs, last_seen, first_seen, label_history, browser_cookie, http_headers, tcp_syn, tls_clienthello, quic_initial, evidence_json
             FROM device_fingerprints WHERE iface = ?1",
        )?;
        let rows = stmt.query_map(params![iface], |r| {
            Ok(FingerprintRow {
                id: r.get(0)?,
                label: r.get(1)?,
                dhcp_options: r.get(2)?,
                dhcp_vendor: r.get(3)?,
                wifi_caps: r.get(4)?,
                mdns_name: r.get(5)?,
                mdns_model: r.get(6)?,
                macs: r.get(7)?,
                last_seen: r.get(8)?,
                first_seen: r.get(9)?,
                label_history: r.get(10)?,
                browser_cookie: r.get(11)?,
                http_headers: r.get(12)?,
                tcp_syn: r.get(13)?,
                tls_clienthello: r.get(14)?,
                quic_initial: r.get(15)?,
                evidence_json: r.get(16)?,
            })
        })?;
        rows.collect()
    }

    pub async fn write_fingerprint_registry(
        &self,
        iface: &str,
        rows: &[FingerprintRow],
    ) -> rusqlite::Result<()> {
        let mut conn = self.0.lock().await;
        let tx = conn.transaction()?;
        tx.execute(
            "DELETE FROM device_fingerprints WHERE iface = ?1",
            params![iface],
        )?;
        for r in rows {
            tx.execute(
                "INSERT INTO device_fingerprints (iface, id, label, dhcp_options, dhcp_vendor, wifi_caps, mdns_name, mdns_model, macs, last_seen, first_seen, label_history, browser_cookie, http_headers, tcp_syn, tls_clienthello, quic_initial, evidence_json)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18)",
                params![iface, r.id, r.label, r.dhcp_options, r.dhcp_vendor, r.wifi_caps, r.mdns_name, r.mdns_model, r.macs, r.last_seen, r.first_seen, r.label_history, r.browser_cookie, r.http_headers, r.tcp_syn, r.tls_clienthello, r.quic_initial, r.evidence_json],
            )?;
        }
        tx.commit()
    }
}

// ── Device IPs / IP6s / limits ──────────────────────────────────────────

impl Store {
    pub async fn all_device_ips(&self, iface: &str) -> rusqlite::Result<HashMap<String, String>> {
        map_query(
            &self.0,
            "SELECT mac, ip FROM device_ips WHERE iface = ?1",
            iface,
        )
        .await
    }
    pub async fn set_device_ip(&self, iface: &str, mac: &str, ip: &str) -> rusqlite::Result<()> {
        self.0.lock().await.execute(
            "INSERT INTO device_ips (iface, mac, ip) VALUES (?1, ?2, ?3)
             ON CONFLICT(iface, mac) DO UPDATE SET ip = excluded.ip",
            params![iface, mac, ip],
        )?;
        Ok(())
    }

    pub async fn all_device_ip6s(&self, iface: &str) -> rusqlite::Result<HashMap<String, String>> {
        map_query(
            &self.0,
            "SELECT mac, ip6 FROM device_ip6s WHERE iface = ?1",
            iface,
        )
        .await
    }
    pub async fn set_device_ip6(&self, iface: &str, mac: &str, ip6: &str) -> rusqlite::Result<()> {
        self.0.lock().await.execute(
            "INSERT INTO device_ip6s (iface, mac, ip6) VALUES (?1, ?2, ?3)
             ON CONFLICT(iface, mac) DO UPDATE SET ip6 = excluded.ip6",
            params![iface, mac, ip6],
        )?;
        Ok(())
    }

    pub async fn all_device_limits(&self, iface: &str) -> rusqlite::Result<HashMap<String, u32>> {
        let conn = self.0.lock().await;
        let mut stmt =
            conn.prepare("SELECT mac, limit_mbps FROM device_limits WHERE iface = ?1")?;
        let rows = stmt.query_map(params![iface], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)? as u32))
        })?;
        rows.collect()
    }
    pub async fn set_device_limit(
        &self,
        iface: &str,
        mac: &str,
        limit_mbps: u32,
    ) -> rusqlite::Result<()> {
        self.0.lock().await.execute(
            "INSERT INTO device_limits (iface, mac, limit_mbps) VALUES (?1, ?2, ?3)
             ON CONFLICT(iface, mac) DO UPDATE SET limit_mbps = excluded.limit_mbps",
            params![iface, mac, limit_mbps],
        )?;
        Ok(())
    }

    pub async fn remove_device_ip(&self, iface: &str, mac: &str) -> rusqlite::Result<()> {
        self.0.lock().await.execute(
            "DELETE FROM device_ips WHERE iface = ?1 AND mac = ?2",
            params![iface, mac],
        )?;
        Ok(())
    }
    pub async fn remove_device_ip6(&self, iface: &str, mac: &str) -> rusqlite::Result<()> {
        self.0.lock().await.execute(
            "DELETE FROM device_ip6s WHERE iface = ?1 AND mac = ?2",
            params![iface, mac],
        )?;
        Ok(())
    }
    pub async fn remove_device_limit(&self, iface: &str, mac: &str) -> rusqlite::Result<()> {
        self.0.lock().await.execute(
            "DELETE FROM device_limits WHERE iface = ?1 AND mac = ?2",
            params![iface, mac],
        )?;
        Ok(())
    }
}

async fn map_query(
    mutex: &Mutex<Connection>,
    sql: &str,
    iface: &str,
) -> rusqlite::Result<HashMap<String, String>> {
    let conn = mutex.lock().await;
    let mut stmt = conn.prepare(sql)?;
    let rows = stmt.query_map(params![iface], |r| {
        Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
    })?;
    rows.collect()
}

// ── Device rules ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceRule {
    pub mac: String,
    pub dst: String,
    pub action: String,
    pub port: String,
    pub proto: String,
    pub route: String,
}

impl Store {
    pub async fn list_device_rules(&self, iface: &str) -> rusqlite::Result<Vec<DeviceRule>> {
        let conn = self.0.lock().await;
        let mut stmt = conn.prepare(
            "SELECT mac, dst, action, port, proto, route FROM device_rules WHERE iface = ?1",
        )?;
        let rows = stmt.query_map(params![iface], |r| {
            Ok(DeviceRule {
                mac: r.get(0)?,
                dst: r.get(1)?,
                action: r.get(2)?,
                port: r.get(3)?,
                proto: r.get(4)?,
                route: r.get(5)?,
            })
        })?;
        rows.collect()
    }

    /// Matches `write_domain_rule`'s existing semantics: replace any
    /// existing rule for this exact `(iface, mac, dst)`.
    pub async fn upsert_domain_rule(
        &self,
        iface: &str,
        mac: &str,
        dst: &str,
        route: &str,
    ) -> rusqlite::Result<()> {
        let conn = self.0.lock().await;
        conn.execute(
            "DELETE FROM device_rules WHERE iface = ?1 AND mac = ?2 AND dst = ?3",
            params![iface, mac, dst],
        )?;
        conn.execute(
            "INSERT INTO device_rules (iface, mac, dst, action, port, proto, route) VALUES (?1, ?2, ?3, 'allow', '', '', ?4)",
            params![iface, mac, dst, route],
        )?;
        Ok(())
    }

    /// Matches `write_ip_rule`'s existing semantics: a no-op if the exact
    /// `(iface, mac, dst, port, proto)` row already exists.
    pub async fn upsert_ip_rule(
        &self,
        iface: &str,
        mac: &str,
        dst_ip: &str,
        port: &str,
        proto: &str,
    ) -> rusqlite::Result<()> {
        self.0.lock().await.execute(
            "INSERT INTO device_rules (iface, mac, dst, action, port, proto, route) VALUES (?1, ?2, ?3, 'allow', ?4, ?5, '')
             ON CONFLICT(iface, mac, dst, port, proto) DO NOTHING",
            params![iface, mac, dst_ip, port, proto],
        )?;
        Ok(())
    }

    pub async fn remove_device_rule(
        &self,
        iface: &str,
        mac: &str,
        dst: &str,
    ) -> rusqlite::Result<()> {
        self.0.lock().await.execute(
            "DELETE FROM device_rules WHERE iface = ?1 AND mac = ?2 AND dst = ?3",
            params![iface, mac, dst],
        )?;
        Ok(())
    }

    /// Every rule for `mac`, regardless of destination — used when a
    /// device is deleted outright, unlike `remove_device_rule`'s
    /// single-destination removal.
    pub async fn remove_device_rules_for_mac(
        &self,
        iface: &str,
        mac: &str,
    ) -> rusqlite::Result<()> {
        self.0.lock().await.execute(
            "DELETE FROM device_rules WHERE iface = ?1 AND mac = ?2",
            params![iface, mac],
        )?;
        Ok(())
    }

    /// Inserts a rule exactly as read from the flat-file migration import
    /// (arbitrary `action`/`route`, unlike `upsert_domain_rule`/
    /// `upsert_ip_rule`, which hardcode `action = "allow"` and infer
    /// `route` from the call site's own semantics) — a bulk one-time load
    /// into an empty table has no "existing row" to replace or dedupe
    /// against, so it deliberately doesn't share those methods' upsert
    /// logic.
    #[allow(clippy::too_many_arguments)]
    pub async fn insert_device_rule_raw(
        &self,
        iface: &str,
        mac: &str,
        dst: &str,
        action: &str,
        port: &str,
        proto: &str,
        route: &str,
    ) -> rusqlite::Result<()> {
        self.0.lock().await.execute(
            "INSERT INTO device_rules (iface, mac, dst, action, port, proto, route) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(iface, mac, dst, port, proto) DO NOTHING",
            params![iface, mac, dst, action, port, proto, route],
        )?;
        Ok(())
    }
}

// ── Allowed MACs ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AllowedMac {
    pub mac: String,
    pub ip: String,
    pub label: String,
}

impl Store {
    pub async fn list_allowed_macs(&self, iface: &str) -> rusqlite::Result<Vec<AllowedMac>> {
        let conn = self.0.lock().await;
        let mut stmt = conn.prepare("SELECT mac, ip, label FROM allowed_macs WHERE iface = ?1")?;
        let rows = stmt.query_map(params![iface], |r| {
            Ok(AllowedMac {
                mac: r.get(0)?,
                ip: r.get(1)?,
                label: r.get(2)?,
            })
        })?;
        rows.collect()
    }

    pub async fn upsert_allowed_mac(
        &self,
        iface: &str,
        mac: &str,
        ip: &str,
        label: &str,
    ) -> rusqlite::Result<()> {
        self.0.lock().await.execute(
            "INSERT INTO allowed_macs (iface, mac, ip, label) VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(iface, mac) DO UPDATE SET ip = excluded.ip, label = excluded.label",
            params![iface, mac, ip, label],
        )?;
        Ok(())
    }

    pub async fn remove_allowed_mac(&self, iface: &str, mac: &str) -> rusqlite::Result<()> {
        self.0.lock().await.execute(
            "DELETE FROM allowed_macs WHERE iface = ?1 AND mac = ?2",
            params![iface, mac],
        )?;
        Ok(())
    }
}

// ── Join state: approved / denied / pending / approved-ips ─────────────
//
// Kept as four independent tables, not one status enum — see the
// migration's module doc: today a denied MAC is deliberately still kept
// in `join_pending` too ("to keep IP visible"), so these are genuinely
// independent, overlapping sets in current behavior.

impl Store {
    pub async fn join_approved_list(&self, iface: &str) -> rusqlite::Result<Vec<String>> {
        list_query(
            &self.0,
            "SELECT mac FROM join_approved WHERE iface = ?1",
            iface,
        )
        .await
    }
    pub async fn join_approved_add(&self, iface: &str, mac: &str) -> rusqlite::Result<()> {
        self.0.lock().await.execute(
            "INSERT INTO join_approved (iface, mac) VALUES (?1, ?2) ON CONFLICT DO NOTHING",
            params![iface, mac],
        )?;
        Ok(())
    }
    pub async fn join_approved_remove(&self, iface: &str, mac: &str) -> rusqlite::Result<()> {
        self.0.lock().await.execute(
            "DELETE FROM join_approved WHERE iface = ?1 AND mac = ?2",
            params![iface, mac],
        )?;
        Ok(())
    }

    pub async fn join_denied_list(&self, iface: &str) -> rusqlite::Result<Vec<String>> {
        list_query(
            &self.0,
            "SELECT mac FROM join_denied WHERE iface = ?1",
            iface,
        )
        .await
    }
    pub async fn join_denied_add(&self, iface: &str, mac: &str) -> rusqlite::Result<()> {
        self.0.lock().await.execute(
            "INSERT INTO join_denied (iface, mac) VALUES (?1, ?2) ON CONFLICT DO NOTHING",
            params![iface, mac],
        )?;
        Ok(())
    }
    pub async fn join_denied_remove(&self, iface: &str, mac: &str) -> rusqlite::Result<()> {
        self.0.lock().await.execute(
            "DELETE FROM join_denied WHERE iface = ?1 AND mac = ?2",
            params![iface, mac],
        )?;
        Ok(())
    }

    pub async fn join_pending_map(&self, iface: &str) -> rusqlite::Result<HashMap<String, String>> {
        map_query(
            &self.0,
            "SELECT mac, ip FROM join_pending WHERE iface = ?1",
            iface,
        )
        .await
    }
    pub async fn join_pending_set(&self, iface: &str, mac: &str, ip: &str) -> rusqlite::Result<()> {
        self.0.lock().await.execute(
            "INSERT INTO join_pending (iface, mac, ip) VALUES (?1, ?2, ?3)
             ON CONFLICT(iface, mac) DO UPDATE SET ip = excluded.ip",
            params![iface, mac, ip],
        )?;
        Ok(())
    }
    pub async fn join_pending_remove(&self, iface: &str, mac: &str) -> rusqlite::Result<()> {
        self.0.lock().await.execute(
            "DELETE FROM join_pending WHERE iface = ?1 AND mac = ?2",
            params![iface, mac],
        )?;
        Ok(())
    }

    pub async fn join_approved_ips_map(
        &self,
        iface: &str,
    ) -> rusqlite::Result<HashMap<String, String>> {
        map_query(
            &self.0,
            "SELECT mac, ip FROM join_approved_ips WHERE iface = ?1",
            iface,
        )
        .await
    }
    pub async fn join_approved_ips_set(
        &self,
        iface: &str,
        mac: &str,
        ip: &str,
    ) -> rusqlite::Result<()> {
        self.0.lock().await.execute(
            "INSERT INTO join_approved_ips (iface, mac, ip) VALUES (?1, ?2, ?3)
             ON CONFLICT(iface, mac) DO UPDATE SET ip = excluded.ip",
            params![iface, mac, ip],
        )?;
        Ok(())
    }
    pub async fn join_approved_ips_remove(&self, iface: &str, mac: &str) -> rusqlite::Result<()> {
        self.0.lock().await.execute(
            "DELETE FROM join_approved_ips WHERE iface = ?1 AND mac = ?2",
            params![iface, mac],
        )?;
        Ok(())
    }
}

async fn list_query(
    mutex: &Mutex<Connection>,
    sql: &str,
    iface: &str,
) -> rusqlite::Result<Vec<String>> {
    let conn = mutex.lock().await;
    let mut stmt = conn.prepare(sql)?;
    let rows = stmt.query_map(params![iface], |r| r.get::<_, String>(0))?;
    rows.collect()
}

// ── Join history (append-only) ──────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JoinHistoryRow {
    pub ts: i64,
    pub when_str: String,
    pub action: String,
    pub mac: String,
    pub ip4: String,
    pub ip6: String,
    pub hostname: String,
    pub actor: String,
    pub actor_ip4: String,
    pub actor_ip6: String,
    pub actor_mac: String,
}

impl Store {
    #[allow(clippy::too_many_arguments)]
    pub async fn append_join_history(
        &self,
        iface: &str,
        row: &JoinHistoryRow,
    ) -> rusqlite::Result<()> {
        self.0.lock().await.execute(
            "INSERT INTO join_history (iface, ts, when_str, action, mac, ip4, ip6, hostname, actor, actor_ip4, actor_ip6, actor_mac)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            params![iface, row.ts, row.when_str, row.action, row.mac, row.ip4, row.ip6, row.hostname, row.actor, row.actor_ip4, row.actor_ip6, row.actor_mac],
        )?;
        Ok(())
    }

    /// Newest first, capped — matches `read_join_history`'s callers, which
    /// reverse and truncate to the most recent 20.
    pub async fn recent_join_history(
        &self,
        iface: &str,
        limit: u32,
    ) -> rusqlite::Result<Vec<JoinHistoryRow>> {
        let conn = self.0.lock().await;
        let mut stmt = conn.prepare(
            "SELECT ts, when_str, action, mac, ip4, ip6, hostname, actor, actor_ip4, actor_ip6, actor_mac
             FROM join_history WHERE iface = ?1 ORDER BY id DESC LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![iface, limit], row_to_join_history)?;
        rows.collect()
    }

    /// Most recent history row for one specific MAC, if any — used by the
    /// join prompt's "you previously approved/denied this exact device"
    /// hint.
    pub async fn latest_join_history_for_mac(
        &self,
        iface: &str,
        mac: &str,
    ) -> rusqlite::Result<Option<JoinHistoryRow>> {
        self.0.lock().await
            .query_row(
                "SELECT ts, when_str, action, mac, ip4, ip6, hostname, actor, actor_ip4, actor_ip6, actor_mac
                 FROM join_history WHERE iface = ?1 AND mac = ?2 ORDER BY id DESC LIMIT 1",
                params![iface, mac],
                row_to_join_history,
            )
            .optional()
    }
}

fn row_to_join_history(r: &rusqlite::Row) -> rusqlite::Result<JoinHistoryRow> {
    Ok(JoinHistoryRow {
        ts: r.get(0)?,
        when_str: r.get(1)?,
        action: r.get(2)?,
        mac: r.get(3)?,
        ip4: r.get(4)?,
        ip6: r.get(5)?,
        hostname: r.get(6)?,
        actor: r.get(7)?,
        actor_ip4: r.get(8)?,
        actor_ip6: r.get(9)?,
        actor_mac: r.get(10)?,
    })
}

// ── Pending connections (hot, per-device today) ─────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingConn {
    pub dst: String,
    pub port: String,
    pub proto: String,
    pub ts: i64,
}

impl Store {
    pub async fn add_pending_connection(
        &self,
        iface: &str,
        mac: &str,
        dst: &str,
        port: &str,
        proto: &str,
        ts: i64,
    ) -> rusqlite::Result<()> {
        self.0.lock().await.execute(
            "INSERT INTO pending_connections (iface, mac, dst, port, proto, ts) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![iface, mac, dst, port, proto, ts],
        )?;
        Ok(())
    }

    pub async fn list_pending_connections(
        &self,
        iface: &str,
        mac: &str,
    ) -> rusqlite::Result<Vec<PendingConn>> {
        let conn = self.0.lock().await;
        let mut stmt = conn.prepare(
            "SELECT dst, port, proto, ts FROM pending_connections WHERE iface = ?1 AND mac = ?2",
        )?;
        let rows = stmt.query_map(params![iface, mac], |r| {
            Ok(PendingConn {
                dst: r.get(0)?,
                port: r.get(1)?,
                proto: r.get(2)?,
                ts: r.get(3)?,
            })
        })?;
        rows.collect()
    }

    pub async fn remove_pending_connection(
        &self,
        iface: &str,
        mac: &str,
        dst: &str,
        port: &str,
        proto: &str,
    ) -> rusqlite::Result<()> {
        self.0.lock().await.execute(
            "DELETE FROM pending_connections WHERE iface = ?1 AND mac = ?2 AND dst = ?3 AND port = ?4 AND lower(proto) = lower(?5)",
            params![iface, mac, dst, port, proto],
        )?;
        Ok(())
    }

    pub async fn prune_pending_connections(
        &self,
        iface: &str,
        mac: &str,
        cutoff_ts: i64,
    ) -> rusqlite::Result<()> {
        self.0.lock().await.execute(
            "DELETE FROM pending_connections WHERE iface = ?1 AND mac = ?2 AND ts < ?3",
            params![iface, mac, cutoff_ts],
        )?;
        Ok(())
    }
}

// ── DNS answers (hot, per-device today) ─────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsAnswer {
    pub ts: i64,
    pub domain: String,
    pub ip: String,
}

impl Store {
    pub async fn add_dns_answer(
        &self,
        iface: &str,
        mac: &str,
        ts: i64,
        domain: &str,
        ip: &str,
    ) -> rusqlite::Result<()> {
        self.0.lock().await.execute(
            "INSERT INTO dns_answers (iface, mac, ts, domain, ip) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![iface, mac, ts, domain, ip],
        )?;
        Ok(())
    }

    pub async fn list_dns_answers(
        &self,
        iface: &str,
        mac: &str,
    ) -> rusqlite::Result<Vec<DnsAnswer>> {
        let conn = self.0.lock().await;
        let mut stmt =
            conn.prepare("SELECT ts, domain, ip FROM dns_answers WHERE iface = ?1 AND mac = ?2")?;
        let rows = stmt.query_map(params![iface, mac], |r| {
            Ok(DnsAnswer {
                ts: r.get(0)?,
                domain: r.get(1)?,
                ip: r.get(2)?,
            })
        })?;
        rows.collect()
    }

    pub async fn prune_dns_answers(
        &self,
        iface: &str,
        mac: &str,
        cutoff_ts: i64,
    ) -> rusqlite::Result<()> {
        self.0.lock().await.execute(
            "DELETE FROM dns_answers WHERE iface = ?1 AND mac = ?2 AND ts < ?3",
            params![iface, mac, cutoff_ts],
        )?;
        Ok(())
    }
}

// ── Connection history (append-only, now with real retention) ──────────

impl Store {
    pub async fn append_connection_history(
        &self,
        iface: &str,
        ts: i64,
        event: &str,
        src: &str,
        dst: &str,
        port: &str,
        proto: &str,
    ) -> rusqlite::Result<()> {
        self.0.lock().await.execute(
            "INSERT INTO connection_history (iface, ts, event, src, dst, port, proto) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![iface, ts, event, src, dst, port, proto],
        )?;
        Ok(())
    }

    pub async fn prune_connection_history(&self, cutoff_ts: i64) -> rusqlite::Result<usize> {
        self.0.lock().await.execute(
            "DELETE FROM connection_history WHERE ts < ?1",
            params![cutoff_ts],
        )
    }
}

// ── Notified attempts (dedup key set, trimmed like the old 500/400 file) ─

impl Store {
    pub async fn notified_attempt_seen(&self, key: &str) -> rusqlite::Result<bool> {
        Ok(self
            .0
            .lock()
            .await
            .query_row(
                "SELECT 1 FROM notified_attempts WHERE key = ?1",
                params![key],
                |_| Ok(()),
            )
            .optional()?
            .is_some())
    }

    pub async fn notified_attempt_record(&self, key: &str) -> rusqlite::Result<()> {
        self.0.lock().await.execute(
            "INSERT INTO notified_attempts (key) VALUES (?1) ON CONFLICT DO NOTHING",
            params![key],
        )?;
        Ok(())
    }

    /// Matches `trim_seen`: once past 500 rows, keep only the newest 400.
    pub async fn trim_notified_attempts(&self) -> rusqlite::Result<()> {
        let conn = self.0.lock().await;
        let count: i64 =
            conn.query_row("SELECT COUNT(*) FROM notified_attempts", [], |r| r.get(0))?;
        if count > 500 {
            conn.execute(
                "DELETE FROM notified_attempts WHERE seen_at NOT IN (SELECT seen_at FROM notified_attempts ORDER BY seen_at DESC LIMIT 400)",
                [],
            )?;
        }
        Ok(())
    }
}

// ── Plugin notes ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PluginNote {
    pub mac: String,
    pub dst: String,
    pub plugin_name: String,
    pub note: String,
}

impl Store {
    pub async fn upsert_plugin_note(
        &self,
        iface: &str,
        mac: &str,
        dst: &str,
        plugin_name: &str,
        note: &str,
    ) -> rusqlite::Result<()> {
        self.0.lock().await.execute(
            "INSERT INTO plugin_notes (iface, mac, dst, plugin_name, note) VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(iface, mac, dst) DO UPDATE SET plugin_name = excluded.plugin_name, note = excluded.note",
            params![iface, mac, dst, plugin_name, note],
        )?;
        Ok(())
    }

    pub async fn list_plugin_notes(&self, iface: &str) -> rusqlite::Result<Vec<PluginNote>> {
        let conn = self.0.lock().await;
        let mut stmt =
            conn.prepare("SELECT mac, dst, plugin_name, note FROM plugin_notes WHERE iface = ?1")?;
        let rows = stmt.query_map(params![iface], |r| {
            Ok(PluginNote {
                mac: r.get(0)?,
                dst: r.get(1)?,
                plugin_name: r.get(2)?,
                note: r.get(3)?,
            })
        })?;
        rows.collect()
    }
}

// ── Observation windows ──────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObservationWindow {
    pub started_at: i64,
    pub expires_at: i64,
}

impl Store {
    pub async fn start_observation_window(
        &self,
        iface: &str,
        mac: &str,
        started_at: i64,
        expires_at: i64,
    ) -> rusqlite::Result<()> {
        self.0.lock().await.execute(
            "INSERT INTO observation_windows (iface, mac, started_at, expires_at) VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(iface, mac) DO UPDATE SET started_at = excluded.started_at, expires_at = excluded.expires_at",
            params![iface, mac, started_at, expires_at],
        )?;
        Ok(())
    }

    pub async fn expired_observation_windows(
        &self,
        now: i64,
    ) -> rusqlite::Result<Vec<(String, String, ObservationWindow)>> {
        let conn = self.0.lock().await;
        let mut stmt = conn.prepare("SELECT iface, mac, started_at, expires_at FROM observation_windows WHERE expires_at <= ?1")?;
        let rows = stmt.query_map(params![now], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                ObservationWindow {
                    started_at: r.get(2)?,
                    expires_at: r.get(3)?,
                },
            ))
        })?;
        rows.collect()
    }

    pub async fn remove_observation_window(&self, iface: &str, mac: &str) -> rusqlite::Result<()> {
        self.0.lock().await.execute(
            "DELETE FROM observation_windows WHERE iface = ?1 AND mac = ?2",
            params![iface, mac],
        )?;
        Ok(())
    }
}

// ── Bandwidth alerts ─────────────────────────────────────────────────────

impl Store {
    pub async fn bandwidth_alerted_macs(&self, iface: &str) -> rusqlite::Result<Vec<String>> {
        list_query(
            &self.0,
            "SELECT mac FROM bandwidth_alerted WHERE iface = ?1",
            iface,
        )
        .await
    }

    pub async fn bandwidth_alerted_add(&self, iface: &str, mac: &str) -> rusqlite::Result<()> {
        self.0.lock().await.execute(
            "INSERT INTO bandwidth_alerted (iface, mac) VALUES (?1, ?2) ON CONFLICT DO NOTHING",
            params![iface, mac],
        )?;
        Ok(())
    }

    /// Matches the flat file's own cleanup step: drop any MAC no longer
    /// present in the current byte-counter data.
    pub async fn bandwidth_alerted_retain(
        &self,
        iface: &str,
        still_present: &[String],
    ) -> rusqlite::Result<()> {
        let mut conn = self.0.lock().await;
        let tx = conn.transaction()?;
        tx.execute(
            "DELETE FROM bandwidth_alerted WHERE iface = ?1",
            params![iface],
        )?;
        for mac in still_present {
            tx.execute(
                "INSERT INTO bandwidth_alerted (iface, mac) VALUES (?1, ?2)",
                params![iface, mac],
            )?;
        }
        tx.commit()
    }
}

// ── WAN / VPN state ──────────────────────────────────────────────────────

impl Store {
    pub async fn get_wan_state(&self) -> rusqlite::Result<Option<(String, Option<i64>)>> {
        self.0
            .lock()
            .await
            .query_row(
                "SELECT state, down_since FROM wan_state WHERE id = 0",
                [],
                |r| Ok((r.get::<_, String>(0)?, r.get::<_, Option<i64>>(1)?)),
            )
            .optional()
    }

    pub async fn set_wan_state(
        &self,
        state: &str,
        down_since: Option<i64>,
    ) -> rusqlite::Result<()> {
        self.0.lock().await.execute(
            "INSERT INTO wan_state (id, state, down_since) VALUES (0, ?1, ?2)
             ON CONFLICT(id) DO UPDATE SET state = excluded.state, down_since = excluded.down_since",
            params![state, down_since],
        )?;
        Ok(())
    }

    pub async fn get_vpn_state(&self, iface: &str) -> rusqlite::Result<Option<String>> {
        self.0
            .lock()
            .await
            .query_row(
                "SELECT state FROM vpn_state WHERE iface = ?1",
                params![iface],
                |r| r.get(0),
            )
            .optional()
    }

    pub async fn set_vpn_state(&self, iface: &str, state: &str) -> rusqlite::Result<()> {
        self.0.lock().await.execute(
            "INSERT INTO vpn_state (iface, state) VALUES (?1, ?2) ON CONFLICT(iface) DO UPDATE SET state = excluded.state",
            params![iface, state],
        )?;
        Ok(())
    }
}

// ── OUI / threat-domain reference data (bulk-replaced by cron updaters) ──

impl Store {
    pub async fn all_oui(&self) -> rusqlite::Result<HashMap<String, String>> {
        let conn = self.0.lock().await;
        let mut stmt = conn.prepare("SELECT prefix, vendor FROM oui_entries")?;
        let rows = stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?;
        rows.collect()
    }

    /// Wholesale replace, matching `oui_update.rs`'s "merge sources, write
    /// one file" behavior — atomic via a transaction instead of a
    /// temp-file rename.
    pub async fn replace_oui(&self, entries: &HashMap<String, String>) -> rusqlite::Result<()> {
        let mut conn = self.0.lock().await;
        let tx = conn.transaction()?;
        tx.execute("DELETE FROM oui_entries", [])?;
        for (prefix, vendor) in entries {
            tx.execute(
                "INSERT INTO oui_entries (prefix, vendor) VALUES (?1, ?2)",
                params![prefix, vendor],
            )?;
        }
        tx.commit()
    }

    /// Every feed a domain matches, matching `threat_domains::lookup_domains`.
    pub async fn threat_domain_feeds(&self, domain: &str) -> rusqlite::Result<Vec<String>> {
        list_query(
            &self.0,
            "SELECT feed_id FROM threat_domains WHERE domain = ?1",
            domain,
        )
        .await
    }

    /// Total `(domain, feed)` row count across all feeds — a coarse
    /// "is this substantially populated" check for `threat_intel_update`'s
    /// own network-hitting test, since per-domain lookups don't give a
    /// total.
    pub async fn count_threat_domains(&self) -> rusqlite::Result<i64> {
        self.0
            .lock()
            .await
            .query_row("SELECT COUNT(*) FROM threat_domains", [], |r| r.get(0))
    }

    /// Wholesale replace of one named feed's rows, leaving other feeds
    /// untouched — matches `threat_intel_update.rs`'s per-feed,
    /// best-effort merge (a failing feed keeps its previous rows).
    pub async fn replace_threat_feed(
        &self,
        feed_id: &str,
        domains: &[String],
    ) -> rusqlite::Result<()> {
        let mut conn = self.0.lock().await;
        let tx = conn.transaction()?;
        tx.execute(
            "DELETE FROM threat_domains WHERE feed_id = ?1",
            params![feed_id],
        )?;
        for domain in domains {
            tx.execute("INSERT INTO threat_domains (domain, feed_id) VALUES (?1, ?2) ON CONFLICT DO NOTHING", params![domain, feed_id])?;
        }
        tx.commit()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn migrations_apply_cleanly_on_a_fresh_database() {
        let store = Store::open_in_memory().unwrap();
        let conn = store.0.lock().await;
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM schema_migrations", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 3);
    }

    #[tokio::test]
    async fn device_label_upsert_replaces_in_place() {
        let store = Store::open_in_memory().unwrap();
        store
            .set_label("guest", "aa:bb:cc:dd:ee:ff", "Old Label")
            .await
            .unwrap();
        store
            .set_label("guest", "aa:bb:cc:dd:ee:ff", "New Label")
            .await
            .unwrap();
        assert_eq!(
            store.get_label("guest", "aa:bb:cc:dd:ee:ff").await.unwrap(),
            Some("New Label".to_string())
        );
        assert_eq!(store.all_labels("guest").await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn labels_are_scoped_per_iface() {
        let store = Store::open_in_memory().unwrap();
        store
            .set_label("guest", "aa:bb:cc:dd:ee:ff", "Guest Device")
            .await
            .unwrap();
        store
            .set_label("untrusted", "aa:bb:cc:dd:ee:ff", "Untrusted Device")
            .await
            .unwrap();
        assert_eq!(
            store.get_label("guest", "aa:bb:cc:dd:ee:ff").await.unwrap(),
            Some("Guest Device".to_string())
        );
        assert_eq!(
            store
                .get_label("untrusted", "aa:bb:cc:dd:ee:ff")
                .await
                .unwrap(),
            Some("Untrusted Device".to_string())
        );
    }

    #[tokio::test]
    async fn fingerprint_registry_round_trips_whole_vec() {
        let store = Store::open_in_memory().unwrap();
        let rows = vec![FingerprintRow {
            id: "deadbeef".into(),
            label: "Phone".into(),
            macs: "02:aa:aa:aa:aa:aa".into(),
            last_seen: 1000,
            first_seen: 1000,
            ..Default::default()
        }];
        store
            .write_fingerprint_registry("guest", &rows)
            .await
            .unwrap();
        assert_eq!(
            store.read_fingerprint_registry("guest").await.unwrap(),
            rows
        );

        // A second write wholesale-replaces, matching write_registry's semantics.
        store
            .write_fingerprint_registry("guest", &[])
            .await
            .unwrap();
        assert!(store
            .read_fingerprint_registry("guest")
            .await
            .unwrap()
            .is_empty());
    }

    #[tokio::test]
    async fn domain_rule_upsert_replaces_existing_rule_for_same_mac_and_dst() {
        let store = Store::open_in_memory().unwrap();
        store
            .upsert_domain_rule("guest", "aa:bb:cc:dd:ee:ff", "example.com", "")
            .await
            .unwrap();
        store
            .upsert_domain_rule("guest", "aa:bb:cc:dd:ee:ff", "example.com", "wg0")
            .await
            .unwrap();
        let rules = store.list_device_rules("guest").await.unwrap();
        assert_eq!(
            rules.len(),
            1,
            "must replace, not duplicate, the rule for the same (mac, dst)"
        );
        assert_eq!(rules[0].route, "wg0");
    }

    #[tokio::test]
    async fn ip_rule_upsert_is_a_noop_for_an_identical_existing_row() {
        let store = Store::open_in_memory().unwrap();
        store
            .upsert_ip_rule("guest", "aa:bb:cc:dd:ee:ff", "1.2.3.4", "443", "tcp")
            .await
            .unwrap();
        store
            .upsert_ip_rule("guest", "aa:bb:cc:dd:ee:ff", "1.2.3.4", "443", "tcp")
            .await
            .unwrap();
        assert_eq!(store.list_device_rules("guest").await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn ip_rule_upsert_allows_different_ports_for_same_dst() {
        let store = Store::open_in_memory().unwrap();
        store
            .upsert_ip_rule("guest", "aa:bb:cc:dd:ee:ff", "1.2.3.4", "443", "tcp")
            .await
            .unwrap();
        store
            .upsert_ip_rule("guest", "aa:bb:cc:dd:ee:ff", "1.2.3.4", "80", "tcp")
            .await
            .unwrap();
        assert_eq!(store.list_device_rules("guest").await.unwrap().len(), 2);
    }

    #[tokio::test]
    async fn join_denied_and_join_pending_coexist_for_the_same_mac() {
        // Regression guard for the exact behavior that ruled out a single
        // `status` enum: approve_join.rs's "deny" action adds to denied
        // AND keeps the MAC in pending "to keep IP visible."
        let store = Store::open_in_memory().unwrap();
        store
            .join_denied_add("guest", "aa:bb:cc:dd:ee:ff")
            .await
            .unwrap();
        store
            .join_pending_set("guest", "aa:bb:cc:dd:ee:ff", "10.10.0.5")
            .await
            .unwrap();
        assert!(store
            .join_denied_list("guest")
            .await
            .unwrap()
            .contains(&"aa:bb:cc:dd:ee:ff".to_string()));
        assert_eq!(
            store
                .join_pending_map("guest")
                .await
                .unwrap()
                .get("aa:bb:cc:dd:ee:ff"),
            Some(&"10.10.0.5".to_string())
        );
    }

    #[tokio::test]
    async fn join_history_recent_is_newest_first_and_capped() {
        let store = Store::open_in_memory().unwrap();
        for i in 0..5 {
            let row = JoinHistoryRow {
                ts: i,
                when_str: format!("t{i}"),
                action: "approved".into(),
                mac: "aa:bb:cc:dd:ee:ff".into(),
                ip4: String::new(),
                ip6: String::new(),
                hostname: String::new(),
                actor: String::new(),
                actor_ip4: String::new(),
                actor_ip6: String::new(),
                actor_mac: String::new(),
            };
            store.append_join_history("guest", &row).await.unwrap();
        }
        let recent = store.recent_join_history("guest", 2).await.unwrap();
        assert_eq!(recent.len(), 2);
        assert_eq!(recent[0].ts, 4);
        assert_eq!(recent[1].ts, 3);
    }

    #[tokio::test]
    async fn latest_join_history_for_mac_finds_the_most_recent_entry() {
        let store = Store::open_in_memory().unwrap();
        let mk = |ts: i64, action: &str| JoinHistoryRow {
            ts,
            when_str: String::new(),
            action: action.into(),
            mac: "aa:bb:cc:dd:ee:ff".into(),
            ip4: String::new(),
            ip6: String::new(),
            hostname: String::new(),
            actor: String::new(),
            actor_ip4: String::new(),
            actor_ip6: String::new(),
            actor_mac: String::new(),
        };
        store
            .append_join_history("guest", &mk(100, "denied"))
            .await
            .unwrap();
        store
            .append_join_history("guest", &mk(200, "approved"))
            .await
            .unwrap();
        let latest = store
            .latest_join_history_for_mac("guest", "aa:bb:cc:dd:ee:ff")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(latest.action, "approved");
    }

    #[tokio::test]
    async fn pending_connections_prune_by_age() {
        let store = Store::open_in_memory().unwrap();
        store
            .add_pending_connection("guest", "aa:bb:cc:dd:ee:ff", "1.2.3.4", "443", "tcp", 100)
            .await
            .unwrap();
        store
            .add_pending_connection("guest", "aa:bb:cc:dd:ee:ff", "5.6.7.8", "80", "tcp", 2000)
            .await
            .unwrap();
        store
            .prune_pending_connections("guest", "aa:bb:cc:dd:ee:ff", 1000)
            .await
            .unwrap();
        let kept = store
            .list_pending_connections("guest", "aa:bb:cc:dd:ee:ff")
            .await
            .unwrap();
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].dst, "5.6.7.8");
    }

    #[tokio::test]
    async fn dns_answers_prune_by_age() {
        let store = Store::open_in_memory().unwrap();
        store
            .add_dns_answer("guest", "aabbccddeeff", 100, "old.example.com", "1.1.1.1")
            .await
            .unwrap();
        store
            .add_dns_answer("guest", "aabbccddeeff", 2000, "new.example.com", "2.2.2.2")
            .await
            .unwrap();
        store
            .prune_dns_answers("guest", "aabbccddeeff", 1000)
            .await
            .unwrap();
        let kept = store
            .list_dns_answers("guest", "aabbccddeeff")
            .await
            .unwrap();
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].domain, "new.example.com");
    }

    #[tokio::test]
    async fn connection_history_prune_removes_only_stale_rows() {
        let store = Store::open_in_memory().unwrap();
        store
            .append_connection_history("guest", 100, "deny", "1.2.3.4", "", "", "")
            .await
            .unwrap();
        store
            .append_connection_history("guest", 2000, "2lan", "1.2.3.4", "5.6.7.8", "443", "tcp")
            .await
            .unwrap();
        let removed = store.prune_connection_history(1000).await.unwrap();
        assert_eq!(removed, 1);
    }

    #[tokio::test]
    async fn notified_attempts_dedup_and_trim_to_400_past_500() {
        let store = Store::open_in_memory().unwrap();
        for i in 0..510 {
            let key = format!("deny:guest:10.0.0.{i}");
            store.notified_attempt_record(&key).await.unwrap();
        }
        store.trim_notified_attempts().await.unwrap();
        let conn = store.0.lock().await;
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM notified_attempts", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 400);
        drop(conn);
        // The newest keys must survive the trim.
        assert!(store
            .notified_attempt_seen("deny:guest:10.0.0.509")
            .await
            .unwrap());
        assert!(!store
            .notified_attempt_seen("deny:guest:10.0.0.0")
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn notified_attempt_record_is_idempotent() {
        let store = Store::open_in_memory().unwrap();
        store.notified_attempt_record("key-a").await.unwrap();
        store.notified_attempt_record("key-a").await.unwrap();
        let conn = store.0.lock().await;
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM notified_attempts", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 1);
    }

    #[tokio::test]
    async fn observation_window_expiry_lookup_and_removal() {
        let store = Store::open_in_memory().unwrap();
        store
            .start_observation_window("guest", "aa:bb:cc:dd:ee:ff", 0, 1000)
            .await
            .unwrap();
        store
            .start_observation_window("guest", "11:22:33:44:55:66", 0, 999_999_999)
            .await
            .unwrap();

        let expired = store.expired_observation_windows(1000).await.unwrap();
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0].1, "aa:bb:cc:dd:ee:ff");

        store
            .remove_observation_window("guest", "aa:bb:cc:dd:ee:ff")
            .await
            .unwrap();
        assert!(store
            .expired_observation_windows(1000)
            .await
            .unwrap()
            .is_empty());
    }

    #[tokio::test]
    async fn bandwidth_alerted_retain_drops_macs_no_longer_present() {
        let store = Store::open_in_memory().unwrap();
        store
            .bandwidth_alerted_add("guest", "aa:bb:cc:dd:ee:ff")
            .await
            .unwrap();
        store
            .bandwidth_alerted_add("guest", "11:22:33:44:55:66")
            .await
            .unwrap();
        store
            .bandwidth_alerted_retain("guest", &["aa:bb:cc:dd:ee:ff".to_string()])
            .await
            .unwrap();
        let remaining = store.bandwidth_alerted_macs("guest").await.unwrap();
        assert_eq!(remaining, vec!["aa:bb:cc:dd:ee:ff".to_string()]);
    }

    #[tokio::test]
    async fn wan_state_singleton_upserts_in_place() {
        let store = Store::open_in_memory().unwrap();
        store.set_wan_state("down", Some(1000)).await.unwrap();
        store.set_wan_state("up", None).await.unwrap();
        assert_eq!(
            store.get_wan_state().await.unwrap(),
            Some(("up".to_string(), None))
        );
    }

    #[tokio::test]
    async fn vpn_state_is_keyed_per_iface() {
        let store = Store::open_in_memory().unwrap();
        store.set_vpn_state("wg0", "up").await.unwrap();
        store.set_vpn_state("wg1", "down").await.unwrap();
        assert_eq!(
            store.get_vpn_state("wg0").await.unwrap(),
            Some("up".to_string())
        );
        assert_eq!(
            store.get_vpn_state("wg1").await.unwrap(),
            Some("down".to_string())
        );
    }

    #[tokio::test]
    async fn oui_replace_is_wholesale_not_merged() {
        let store = Store::open_in_memory().unwrap();
        store
            .replace_oui(&HashMap::from([(
                "AABBCC".to_string(),
                "Old Corp".to_string(),
            )]))
            .await
            .unwrap();
        store
            .replace_oui(&HashMap::from([(
                "112233".to_string(),
                "New Corp".to_string(),
            )]))
            .await
            .unwrap();
        let all = store.all_oui().await.unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all.get("112233"), Some(&"New Corp".to_string()));
    }

    #[tokio::test]
    async fn threat_feed_replace_only_touches_its_own_feed() {
        let store = Store::open_in_memory().unwrap();
        store
            .replace_threat_feed("urlhaus", &["bad.example".to_string()])
            .await
            .unwrap();
        store
            .replace_threat_feed(
                "openphish",
                &["bad.example".to_string(), "phish.example".to_string()],
            )
            .await
            .unwrap();

        let feeds = store.threat_domain_feeds("bad.example").await.unwrap();
        assert_eq!(
            feeds.len(),
            2,
            "a domain flagged by two feeds should list both"
        );

        // Refreshing urlhaus alone must not touch openphish's rows.
        store.replace_threat_feed("urlhaus", &[]).await.unwrap();
        let feeds = store.threat_domain_feeds("bad.example").await.unwrap();
        assert_eq!(feeds, vec!["openphish".to_string()]);
    }
}
