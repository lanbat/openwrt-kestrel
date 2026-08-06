//! Imports kestreld's legacy flat-file state into SQLite (see `db`), then
//! renames each imported file to `<name>.migrated` — never deletes,
//! matching this project's "quarantine, don't delete" recovery
//! philosophy used elsewhere (e.g. `data::fingerprint`'s never-merge-
//! without-confirmation rule). Idempotent: a file whose `.migrated`
//! sibling already exists is skipped entirely on a re-run, so running
//! this twice (via `kestreld --migrate-storage`, invoked by `install.sh`
//! on every run — the sole trigger; there is deliberately no in-process
//! auto-migration on daemon/CGI start, see `main.rs`'s own comment on
//! that subcommand) never double-imports rows.
//!
//! **Scope**: only kestreld-owned runtime state, per the migration plan.
//! `{iface}-notify.conf` (human/install-time config), `{iface}-allowed-macs`
//! (also hand-edited — see `state.rs`'s comment on why this one stays a
//! live flat-file read even though it looks like the same shape as the
//! other migrated per-iface tables: unlike those, it's never written by
//! kestreld itself, and the real enforcement path — the
//! `51-{iface}-macfilter` hotplug script — reads it directly, so renaming
//! it away here would make `install.sh` regenerate a *blank* one on its
//! next run, silently wiping a real allowlist), `/etc/dnsmasq.d/*`,
//! `/etc/nftables.d/*`, `/tmp/kestrel-joins`, `split_routing_dir`'s own
//! files, and the plugin framework's own bookkeeping are all
//! deliberately out of scope — see `db`'s module doc.
//!
//! **Incidental bug fix, flagged explicitly**: `{iface}-join-approved-ips`
//! is written space-separated (`"{mac} {ip}"`, see
//! `routes/approve_join.rs`) but `state.rs` reads it back with
//! `files::read_mac_ip_map`, which splits on a TAB — meaning this map has
//! been silently empty in production. This importer reads the file
//! correctly (space-separated, via `files::read_pending`, which already
//! parses that exact shape for `-join-pending`), so migrated routers gain
//! working `join_approved_ips` data they never actually had before. This
//! is a real, pre-existing behavior change, not a migration-format
//! artifact — worth independent QEMU VM verification.

use crate::data::{dns_answers, files, fingerprint};
use crate::db::{FingerprintRow, JoinHistoryRow, Store};
use std::path::Path;

pub async fn run(base_dir: &Path) -> i32 {
    match migrate(base_dir).await {
        Ok(summary) => {
            eprintln!("kestreld migration: {summary}");
            0
        }
        Err(e) => {
            eprintln!("kestreld migration failed: {e}");
            1
        }
    }
}

/// Runs the full import. Safe to call on every daemon/CGI start — see
/// `state::AppState::build`'s "only if `kestrel.sqlite` doesn't exist yet"
/// gate, which is what actually makes this a one-time-per-router event in
/// practice; this function's own idempotency (skip already-`.migrated`
/// files) is what makes an explicit re-run via `--migrate-storage` safe
/// too.
pub async fn migrate(base_dir: &Path) -> Result<String, String> {
    let store = Store::open(base_dir).await.map_err(|e| e.to_string())?;
    let mut imported = 0usize;

    let confs = files::read_all_network_confs(base_dir).await;
    for conf in &confs {
        let iface = &conf.iface;
        imported += migrate_labels(base_dir, iface, &store)
            .await
            .map_err(|e| e.to_string())?;
        imported += migrate_fingerprints(base_dir, iface, &store)
            .await
            .map_err(|e| e.to_string())?;
        imported += migrate_device_ips(base_dir, iface, &store)
            .await
            .map_err(|e| e.to_string())?;
        imported += migrate_device_ip6s(base_dir, iface, &store)
            .await
            .map_err(|e| e.to_string())?;
        imported += migrate_device_limits(base_dir, iface, &store)
            .await
            .map_err(|e| e.to_string())?;
        imported += migrate_device_rules(base_dir, iface, &store)
            .await
            .map_err(|e| e.to_string())?;
        // `{iface}-allowed-macs` is deliberately NOT migrated — see this
        // module's doc comment for why it must stay a live, hand-edited
        // flat file rather than being imported and renamed away.
        imported += migrate_join_approved(base_dir, iface, &store)
            .await
            .map_err(|e| e.to_string())?;
        imported += migrate_join_denied(base_dir, iface, &store)
            .await
            .map_err(|e| e.to_string())?;
        imported += migrate_join_pending(base_dir, iface, &store)
            .await
            .map_err(|e| e.to_string())?;
        imported += migrate_join_approved_ips(base_dir, iface, &store)
            .await
            .map_err(|e| e.to_string())?;
        imported += migrate_join_history(base_dir, iface, &store)
            .await
            .map_err(|e| e.to_string())?;
        imported += migrate_connection_history(base_dir, iface, &store)
            .await
            .map_err(|e| e.to_string())?;
        imported += migrate_plugin_notes(base_dir, iface, &store)
            .await
            .map_err(|e| e.to_string())?;
        imported += migrate_bw_alerted(base_dir, iface, &store)
            .await
            .map_err(|e| e.to_string())?;
    }

    imported += migrate_per_device_files(base_dir, &store)
        .await
        .map_err(|e| e.to_string())?;
    imported += migrate_vpn_state_files(base_dir, &store)
        .await
        .map_err(|e| e.to_string())?;
    imported += migrate_wan_state(base_dir, &store)
        .await
        .map_err(|e| e.to_string())?;
    imported += migrate_notified_attempts(base_dir, &store)
        .await
        .map_err(|e| e.to_string())?;
    imported += migrate_oui(base_dir, &store)
        .await
        .map_err(|e| e.to_string())?;
    imported += migrate_threat_domains(base_dir, &store)
        .await
        .map_err(|e| e.to_string())?;

    Ok(format!(
        "{imported} flat files imported and marked .migrated"
    ))
}

// ── Helpers ──────────────────────────────────────────────────────────────

/// `true` if `path` exists and hasn't already been migrated (no
/// `.migrated` sibling) — the idempotency gate every migrate_* function
/// checks before doing any work.
async fn pending_migration(path: &Path) -> bool {
    if tokio::fs::metadata(migrated_path(path)).await.is_ok() {
        return false;
    }
    tokio::fs::metadata(path).await.is_ok()
}

fn migrated_path(path: &Path) -> std::path::PathBuf {
    let mut s = path.as_os_str().to_os_string();
    s.push(".migrated");
    std::path::PathBuf::from(s)
}

async fn mark_migrated(path: &Path) -> std::io::Result<()> {
    tokio::fs::rename(path, migrated_path(path)).await
}

/// `{iface}-{tag}-{mac_n}` -> `(iface, mac_n)` — the shape shared by
/// `-pending-`, `-dns-answers-`, and `-observe-` per-device files (see
/// `observation::parse_observe_filename`, which this mirrors).
fn parse_tagged<'a>(name: &'a str, tag: &str) -> Option<(&'a str, &'a str)> {
    let idx = name.find(tag)?;
    let iface = &name[..idx];
    let mac_n = &name[idx + tag.len()..];
    if iface.is_empty() || mac_n.is_empty() {
        None
    } else {
        Some((iface, mac_n))
    }
}

fn colonize_mac(mac_n: &str) -> String {
    mac_n
        .as_bytes()
        .chunks(2)
        .map(|c| std::str::from_utf8(c).unwrap_or(""))
        .collect::<Vec<_>>()
        .join(":")
}

// ── Per-iface files ──────────────────────────────────────────────────────

async fn migrate_labels(
    base_dir: &Path,
    iface: &str,
    store: &Store,
) -> Result<usize, rusqlite::Error> {
    let path = base_dir.join(format!("{iface}-device-labels"));
    if !pending_migration(&path).await {
        return Ok(0);
    }
    for (mac, label) in files::read_labels(&path).await {
        store.set_label(iface, &mac, &label).await?;
    }
    let _ = mark_migrated(&path).await;
    Ok(1)
}

async fn migrate_fingerprints(
    base_dir: &Path,
    iface: &str,
    store: &Store,
) -> Result<usize, rusqlite::Error> {
    let path = base_dir.join(format!("{iface}-device-fingerprints"));
    if !pending_migration(&path).await {
        return Ok(0);
    }
    let records = fingerprint::read_registry_from_flat_file(&path).await;
    let rows: Vec<FingerprintRow> = records
        .into_iter()
        .map(|r| FingerprintRow {
            id: r.id,
            label: r.label,
            dhcp_options: r.dhcp_options,
            dhcp_vendor: r.dhcp_vendor,
            wifi_caps: r.wifi_caps,
            mdns_name: r.mdns_name,
            mdns_model: r.mdns_model,
            macs: r.macs.join(","),
            last_seen: r.last_seen as i64,
            first_seen: r.first_seen as i64,
            label_history: r
                .label_history
                .iter()
                .map(|(l, ts)| format!("{l}@{ts}"))
                .collect::<Vec<_>>()
                .join("|"),
            browser_cookie: r.browser_cookie,
            http_headers: r.http_headers,
            tcp_syn: r.tcp_syn,
            tls_clienthello: r.tls_clienthello,
            quic_initial: r.quic_initial,
            evidence_json: "[]".into(),
        })
        .collect();
    store.write_fingerprint_registry(iface, &rows).await?;
    let _ = mark_migrated(&path).await;
    Ok(1)
}

async fn migrate_device_ips(
    base_dir: &Path,
    iface: &str,
    store: &Store,
) -> Result<usize, rusqlite::Error> {
    let path = base_dir.join(format!("{iface}-device-ips"));
    if !pending_migration(&path).await {
        return Ok(0);
    }
    for (mac, ip) in files::read_mac_ip_map(&path).await {
        store.set_device_ip(iface, &mac, &ip).await?;
    }
    let _ = mark_migrated(&path).await;
    Ok(1)
}

async fn migrate_device_ip6s(
    base_dir: &Path,
    iface: &str,
    store: &Store,
) -> Result<usize, rusqlite::Error> {
    let path = base_dir.join(format!("{iface}-device-ip6s"));
    if !pending_migration(&path).await {
        return Ok(0);
    }
    for (mac, ip6) in files::read_mac_ip_map(&path).await {
        store.set_device_ip6(iface, &mac, &ip6).await?;
    }
    let _ = mark_migrated(&path).await;
    Ok(1)
}

async fn migrate_device_limits(
    base_dir: &Path,
    iface: &str,
    store: &Store,
) -> Result<usize, rusqlite::Error> {
    let path = base_dir.join(format!("{iface}-device-limits"));
    if !pending_migration(&path).await {
        return Ok(0);
    }
    for (mac, limit) in files::read_device_limits(&path).await {
        store.set_device_limit(iface, &mac, limit).await?;
    }
    let _ = mark_migrated(&path).await;
    Ok(1)
}

async fn migrate_device_rules(
    base_dir: &Path,
    iface: &str,
    store: &Store,
) -> Result<usize, rusqlite::Error> {
    let path = base_dir.join(format!("{iface}-device-rules"));
    if !pending_migration(&path).await {
        return Ok(0);
    }
    for rule in files::read_device_rules(&path).await {
        store
            .insert_device_rule_raw(
                iface,
                &rule.mac,
                &rule.dst,
                &rule.action,
                &rule.port,
                &rule.proto,
                &rule.route,
            )
            .await?;
    }
    let _ = mark_migrated(&path).await;
    Ok(1)
}

async fn migrate_join_approved(
    base_dir: &Path,
    iface: &str,
    store: &Store,
) -> Result<usize, rusqlite::Error> {
    let path = base_dir.join(format!("{iface}-join-approved"));
    if !pending_migration(&path).await {
        return Ok(0);
    }
    for mac in files::read_lines(&path).await {
        store.join_approved_add(iface, &mac.to_lowercase()).await?;
    }
    let _ = mark_migrated(&path).await;
    Ok(1)
}

async fn migrate_join_denied(
    base_dir: &Path,
    iface: &str,
    store: &Store,
) -> Result<usize, rusqlite::Error> {
    let path = base_dir.join(format!("{iface}-join-denied"));
    if !pending_migration(&path).await {
        return Ok(0);
    }
    for mac in files::read_lines(&path).await {
        store.join_denied_add(iface, &mac.to_lowercase()).await?;
    }
    let _ = mark_migrated(&path).await;
    Ok(1)
}

async fn migrate_join_pending(
    base_dir: &Path,
    iface: &str,
    store: &Store,
) -> Result<usize, rusqlite::Error> {
    let path = base_dir.join(format!("{iface}-join-pending"));
    if !pending_migration(&path).await {
        return Ok(0);
    }
    for (mac, ip) in files::read_pending(&path).await {
        store.join_pending_set(iface, &mac, &ip).await?;
    }
    let _ = mark_migrated(&path).await;
    Ok(1)
}

/// See this module's doc comment: read with `files::read_pending`
/// (space-separated `mac ip`, matching the actual writer in
/// `routes/approve_join.rs`), not `files::read_mac_ip_map` (tab-separated)
/// as `state.rs` currently — buggily — does.
async fn migrate_join_approved_ips(
    base_dir: &Path,
    iface: &str,
    store: &Store,
) -> Result<usize, rusqlite::Error> {
    let path = base_dir.join(format!("{iface}-join-approved-ips"));
    if !pending_migration(&path).await {
        return Ok(0);
    }
    for (mac, ip) in files::read_pending(&path).await {
        store.join_approved_ips_set(iface, &mac, &ip).await?;
    }
    let _ = mark_migrated(&path).await;
    Ok(1)
}

async fn migrate_join_history(
    base_dir: &Path,
    iface: &str,
    store: &Store,
) -> Result<usize, rusqlite::Error> {
    let path = base_dir.join(format!("{iface}-join-history"));
    if !pending_migration(&path).await {
        return Ok(0);
    }
    for row in files::read_join_history(&path).await {
        let get = |i: usize| row.get(i).cloned().unwrap_or_default();
        let ts: i64 = get(0).parse().unwrap_or(0);
        let history_row = JoinHistoryRow {
            ts,
            when_str: get(1),
            action: get(2),
            mac: get(3),
            ip4: get(4),
            ip6: get(5),
            hostname: get(6),
            actor: get(7),
            actor_ip4: get(8),
            actor_ip6: get(9),
            actor_mac: get(10),
        };
        store.append_join_history(iface, &history_row).await?;
    }
    let _ = mark_migrated(&path).await;
    Ok(1)
}

async fn migrate_connection_history(
    base_dir: &Path,
    iface: &str,
    store: &Store,
) -> Result<usize, rusqlite::Error> {
    let path = base_dir.join(format!("{iface}-connection-history"));
    if !pending_migration(&path).await {
        return Ok(0);
    }
    for line in files::read_lines(&path).await {
        let mut f = line.splitn(6, '\t');
        let (Some(ts), Some(event), Some(src)) = (f.next(), f.next(), f.next()) else {
            continue;
        };
        let dst = f.next().unwrap_or("");
        let port = f.next().unwrap_or("");
        let proto = f.next().unwrap_or("");
        let ts: i64 = ts.parse().unwrap_or(0);
        store
            .append_connection_history(iface, ts, event, src, dst, port, proto)
            .await?;
    }
    let _ = mark_migrated(&path).await;
    Ok(1)
}

async fn migrate_plugin_notes(
    base_dir: &Path,
    iface: &str,
    store: &Store,
) -> Result<usize, rusqlite::Error> {
    let path = base_dir.join(format!("{iface}-plugin-notes"));
    if !pending_migration(&path).await {
        return Ok(0);
    }
    for note in files::read_plugin_notes(&path).await {
        store
            .upsert_plugin_note(iface, &note.mac, &note.dst, &note.plugin_name, &note.note)
            .await?;
    }
    let _ = mark_migrated(&path).await;
    Ok(1)
}

async fn migrate_bw_alerted(
    base_dir: &Path,
    iface: &str,
    store: &Store,
) -> Result<usize, rusqlite::Error> {
    let path = base_dir.join(format!("{iface}-bw-alerted"));
    if !pending_migration(&path).await {
        return Ok(0);
    }
    for mac in files::read_lines(&path).await {
        store
            .bandwidth_alerted_add(iface, &mac.to_lowercase())
            .await?;
    }
    let _ = mark_migrated(&path).await;
    Ok(1)
}

// ── Per-device files (require a directory scan) + vpn-state ────────────

async fn migrate_per_device_files(
    base_dir: &Path,
    store: &Store,
) -> Result<usize, rusqlite::Error> {
    let Ok(mut dir) = tokio::fs::read_dir(base_dir).await else {
        return Ok(0);
    };
    let mut imported = 0usize;

    while let Ok(Some(entry)) = dir.next_entry().await {
        let name = entry.file_name();
        let name = name.to_string_lossy().into_owned();
        // Without this, a file already renamed to `*.migrated` on a prior
        // run still matches `parse_tagged`'s suffix-search below (the tag
        // just ends up embedded further into the "mac" portion), so it
        // gets re-"imported" under a mangled MAC and renamed again with
        // one more `.migrated` appended — forever, on every install.sh
        // re-run, both corrupting data and growing the filename without
        // bound. Caught via QEMU VM testing: real routers accumulated
        // `*.migrated.migrated.migrated...` files after a few re-runs.
        if name.ends_with(".migrated") {
            continue;
        }
        let path = entry.path();

        if let Some((iface, mac_n)) = parse_tagged(&name, "-pending-") {
            if pending_migration(&path).await {
                let mac = colonize_mac(mac_n);
                for c in files::read_pending_conns(&path).await {
                    store
                        .add_pending_connection(iface, &mac, &c.dst, &c.port, &c.proto, c.ts as i64)
                        .await?;
                }
                let _ = mark_migrated(&path).await;
                imported += 1;
            }
        } else if let Some((iface, mac_n)) = parse_tagged(&name, "-dns-answers-") {
            if pending_migration(&path).await {
                let mac = colonize_mac(mac_n);
                for a in dns_answers::read_dns_answers(&path).await {
                    store
                        .add_dns_answer(iface, &mac, a.ts as i64, &a.domain, &a.ip)
                        .await?;
                }
                let _ = mark_migrated(&path).await;
                imported += 1;
            }
        } else if let Some((iface, mac_n)) = parse_tagged(&name, "-observe-") {
            if pending_migration(&path).await {
                let mac = colonize_mac(mac_n);
                let content = tokio::fs::read_to_string(&path).await.unwrap_or_default();
                let mut fields = content.trim().splitn(2, '\t');
                if let (Some(start), Some(expiry)) = (
                    fields.next().and_then(|s| s.parse::<i64>().ok()),
                    fields.next().and_then(|s| s.parse::<i64>().ok()),
                ) {
                    store
                        .start_observation_window(iface, &mac, start, expiry)
                        .await?;
                }
                let _ = mark_migrated(&path).await;
                imported += 1;
            }
        }
    }
    Ok(imported)
}

async fn migrate_vpn_state_files(base_dir: &Path, store: &Store) -> Result<usize, rusqlite::Error> {
    let Ok(mut dir) = tokio::fs::read_dir(base_dir).await else {
        return Ok(0);
    };
    let mut imported = 0usize;

    while let Ok(Some(entry)) = dir.next_entry().await {
        let name = entry.file_name();
        let name = name.to_string_lossy().into_owned();
        // See the matching comment in `migrate_per_device_files`: without
        // this, an already-`.migrated` file matches `strip_prefix` again
        // (with `.migrated` embedded in the "iface" it extracts) and gets
        // re-imported under a corrupted iface name, then renamed again.
        if name.ends_with(".migrated") {
            continue;
        }
        let Some(iface) = name.strip_prefix("vpn-state-") else {
            continue;
        };
        let path = entry.path();
        if !pending_migration(&path).await {
            continue;
        }
        let state = tokio::fs::read_to_string(&path)
            .await
            .unwrap_or_default()
            .trim()
            .to_string();
        if !state.is_empty() {
            store.set_vpn_state(iface, &state).await?;
        }
        let _ = mark_migrated(&path).await;
        imported += 1;
    }
    Ok(imported)
}

// ── Global (non-per-iface) files ────────────────────────────────────────

async fn migrate_wan_state(base_dir: &Path, store: &Store) -> Result<usize, rusqlite::Error> {
    let state_path = base_dir.join("wan-state");
    let down_since_path = base_dir.join("wan-down-since");
    // Each file is gated on its own pending-migration check, not just
    // `wan-state`'s: `check_wan.rs` writes both independently (a "down"
    // transition writes `wan-down-since` before the next tick's
    // `wan-state` write), and an older, pre-Store build of this daemon may
    // have left just one of the two behind on disk. Gating both imports on
    // `state_path` alone meant an orphaned `wan-down-since` with no
    // sibling `wan-state` was silently skipped forever — never imported,
    // never renamed to `.migrated` — on every `install.sh` re-run.
    let state_pending = pending_migration(&state_path).await;
    let down_since_pending = pending_migration(&down_since_path).await;
    if !state_pending && !down_since_pending {
        return Ok(0);
    }
    let state = tokio::fs::read_to_string(&state_path)
        .await
        .unwrap_or_default()
        .trim()
        .to_string();
    let down_since: Option<i64> = tokio::fs::read_to_string(&down_since_path)
        .await
        .ok()
        .and_then(|s| s.trim().parse().ok());
    if !state.is_empty() {
        store.set_wan_state(&state, down_since).await?;
    }
    if state_pending {
        let _ = mark_migrated(&state_path).await;
    }
    if down_since_pending {
        let _ = mark_migrated(&down_since_path).await;
    }
    Ok(1)
}

async fn migrate_notified_attempts(
    base_dir: &Path,
    store: &Store,
) -> Result<usize, rusqlite::Error> {
    let path = base_dir.join("notified-attempts");
    if !pending_migration(&path).await {
        return Ok(0);
    }
    for key in files::read_lines(&path).await {
        store.notified_attempt_record(&key).await?;
    }
    store.trim_notified_attempts().await?;
    let _ = mark_migrated(&path).await;
    Ok(1)
}

async fn migrate_oui(base_dir: &Path, store: &Store) -> Result<usize, rusqlite::Error> {
    let path = base_dir.join("oui.txt");
    if !pending_migration(&path).await {
        return Ok(0);
    }
    let entries = files::read_oui(&path).await;
    store.replace_oui(&entries).await?;
    let _ = mark_migrated(&path).await;
    Ok(1)
}

async fn migrate_threat_domains(base_dir: &Path, store: &Store) -> Result<usize, rusqlite::Error> {
    let path = base_dir.join("threat-domains.txt");
    if !pending_migration(&path).await {
        return Ok(0);
    }
    let mut by_feed: std::collections::HashMap<String, Vec<String>> =
        std::collections::HashMap::new();
    for line in files::read_lines(&path).await {
        if line.starts_with('#') {
            continue;
        }
        let mut f = line.splitn(2, '\t');
        let (Some(domain), Some(feed)) = (f.next(), f.next()) else {
            continue;
        };
        by_feed
            .entry(feed.to_string())
            .or_default()
            .push(domain.to_string());
    }
    for (feed, domains) in by_feed {
        store.replace_threat_feed(&feed, &domains).await?;
    }
    let _ = mark_migrated(&path).await;
    Ok(1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn migrates_device_labels_and_marks_the_file_migrated() {
        let dir = tempfile::tempdir().unwrap();
        tokio::fs::write(dir.path().join("guest-notify.conf"), "IFACE_NAME=guest\n")
            .await
            .unwrap();
        tokio::fs::write(
            dir.path().join("guest-device-labels"),
            "aa:bb:cc:dd:ee:ff\tAlice's Phone\n",
        )
        .await
        .unwrap();

        let summary = migrate(dir.path()).await.unwrap();
        assert!(summary.contains("imported"));
        assert!(dir.path().join("guest-device-labels.migrated").exists());
        assert!(!dir.path().join("guest-device-labels").exists());

        let store = Store::open(dir.path()).await.unwrap();
        assert_eq!(
            store.get_label("guest", "aa:bb:cc:dd:ee:ff").await.unwrap(),
            Some("Alice's Phone".to_string())
        );
    }

    #[tokio::test]
    async fn rerunning_migration_is_idempotent_and_skips_already_migrated_files() {
        let dir = tempfile::tempdir().unwrap();
        tokio::fs::write(dir.path().join("guest-notify.conf"), "IFACE_NAME=guest\n")
            .await
            .unwrap();
        tokio::fs::write(
            dir.path().join("guest-device-labels"),
            "aa:bb:cc:dd:ee:ff\tAlice's Phone\n",
        )
        .await
        .unwrap();

        migrate(dir.path()).await.unwrap();
        // A second run must not error and must not touch the already-migrated file again.
        migrate(dir.path()).await.unwrap();

        let store = Store::open(dir.path()).await.unwrap();
        assert_eq!(
            store.get_label("guest", "aa:bb:cc:dd:ee:ff").await.unwrap(),
            Some("Alice's Phone".to_string())
        );
    }

    #[tokio::test]
    async fn migrates_per_device_pending_connections_and_dns_answers() {
        let dir = tempfile::tempdir().unwrap();
        tokio::fs::write(dir.path().join("guest-notify.conf"), "IFACE_NAME=guest\n")
            .await
            .unwrap();
        tokio::fs::write(
            dir.path().join("guest-pending-aabbccddeeff"),
            "203.0.113.9\t443\ttcp\t1000\n",
        )
        .await
        .unwrap();
        tokio::fs::write(
            dir.path().join("guest-dns-answers-aabbccddeeff"),
            "900\texample.com\t203.0.113.9\n",
        )
        .await
        .unwrap();

        migrate(dir.path()).await.unwrap();

        let store = Store::open(dir.path()).await.unwrap();
        let pending = store
            .list_pending_connections("guest", "aa:bb:cc:dd:ee:ff")
            .await
            .unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].dst, "203.0.113.9");

        let answers = store
            .list_dns_answers("guest", "aa:bb:cc:dd:ee:ff")
            .await
            .unwrap();
        assert_eq!(answers.len(), 1);
        assert_eq!(answers[0].domain, "example.com");
    }

    #[tokio::test]
    async fn already_migrated_per_device_and_vpn_state_files_are_never_rescanned() {
        // Regression test: `migrate_per_device_files`/`migrate_vpn_state_files`
        // scan the whole directory by filename pattern (per-MAC/per-VPN
        // files have no fixed name to gate a single `pending_migration`
        // check on). Before this fix, a file already renamed to
        // `*.migrated` on a prior run still matched the same tag search
        // (e.g. `-pending-`) with `.migrated` embedded in the extracted
        // MAC/iface, so every subsequent run re-imported it under a
        // mangled identity and appended yet another `.migrated` suffix —
        // observed on a real QEMU VM as
        // `guest-pending-aabbccddeeff.migrated.migrated.migrated...`.
        let dir = tempfile::tempdir().unwrap();
        tokio::fs::write(dir.path().join("guest-notify.conf"), "IFACE_NAME=guest\n")
            .await
            .unwrap();
        tokio::fs::write(
            dir.path().join("guest-pending-aabbccddeeff.migrated"),
            "203.0.113.9\t443\ttcp\t1000\n",
        )
        .await
        .unwrap();
        tokio::fs::write(dir.path().join("vpn-state-mv_bg.migrated"), "down\n")
            .await
            .unwrap();

        migrate(dir.path()).await.unwrap();

        // Neither file should have been touched at all — no second
        // `.migrated` suffix appended, no data imported under a mangled key.
        assert!(
            tokio::fs::metadata(dir.path().join("guest-pending-aabbccddeeff.migrated"))
                .await
                .is_ok()
        );
        assert!(tokio::fs::metadata(
            dir.path()
                .join("guest-pending-aabbccddeeff.migrated.migrated")
        )
        .await
        .is_err());
        assert!(
            tokio::fs::metadata(dir.path().join("vpn-state-mv_bg.migrated"))
                .await
                .is_ok()
        );
        assert!(
            tokio::fs::metadata(dir.path().join("vpn-state-mv_bg.migrated.migrated"))
                .await
                .is_err()
        );

        let store = Store::open(dir.path()).await.unwrap();
        assert!(store
            .list_pending_connections("guest", "aa:bb:cc:dd:ee:ff")
            .await
            .unwrap()
            .is_empty());
        assert_eq!(store.get_vpn_state("mv_bg").await.unwrap(), None);
    }

    #[tokio::test]
    async fn migrates_join_approved_ips_correctly_despite_the_space_vs_tab_bug() {
        let dir = tempfile::tempdir().unwrap();
        tokio::fs::write(dir.path().join("guest-notify.conf"), "IFACE_NAME=guest\n")
            .await
            .unwrap();
        // Space-separated, matching the real writer in routes/approve_join.rs.
        tokio::fs::write(
            dir.path().join("guest-join-approved-ips"),
            "aa:bb:cc:dd:ee:ff 10.0.0.5\n",
        )
        .await
        .unwrap();

        migrate(dir.path()).await.unwrap();

        let store = Store::open(dir.path()).await.unwrap();
        let map = store.join_approved_ips_map("guest").await.unwrap();
        assert_eq!(map.get("aa:bb:cc:dd:ee:ff"), Some(&"10.0.0.5".to_string()));
    }

    #[tokio::test]
    async fn migrates_join_denied_and_join_pending_as_independent_sets() {
        let dir = tempfile::tempdir().unwrap();
        tokio::fs::write(dir.path().join("guest-notify.conf"), "IFACE_NAME=guest\n")
            .await
            .unwrap();
        tokio::fs::write(dir.path().join("guest-join-denied"), "aa:bb:cc:dd:ee:ff\n")
            .await
            .unwrap();
        tokio::fs::write(
            dir.path().join("guest-join-pending"),
            "aa:bb:cc:dd:ee:ff 10.0.0.5\n",
        )
        .await
        .unwrap();

        migrate(dir.path()).await.unwrap();

        let store = Store::open(dir.path()).await.unwrap();
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
            Some(&"10.0.0.5".to_string())
        );
    }

    #[tokio::test]
    async fn migrates_device_rules_splitting_domain_and_ip_forms_correctly() {
        let dir = tempfile::tempdir().unwrap();
        tokio::fs::write(dir.path().join("guest-notify.conf"), "IFACE_NAME=guest\n")
            .await
            .unwrap();
        tokio::fs::write(
            dir.path().join("guest-device-rules"),
            "aa:bb:cc:dd:ee:ff\texample.com\tallow\t\t\twg0\naa:bb:cc:dd:ee:ff\t203.0.113.9\tallow\t443\ttcp\t\n",
        ).await.unwrap();

        migrate(dir.path()).await.unwrap();

        let store = Store::open(dir.path()).await.unwrap();
        let rules = store.list_device_rules("guest").await.unwrap();
        assert_eq!(rules.len(), 2);
        let domain_rule = rules.iter().find(|r| r.dst == "example.com").unwrap();
        assert_eq!(domain_rule.route, "wg0");
        let ip_rule = rules.iter().find(|r| r.dst == "203.0.113.9").unwrap();
        assert_eq!(ip_rule.port, "443");
    }

    #[tokio::test]
    async fn migrates_oui_and_threat_domains_reference_data() {
        let dir = tempfile::tempdir().unwrap();
        tokio::fs::write(dir.path().join("oui.txt"), "AABBCC\tGeneric Corp\n")
            .await
            .unwrap();
        tokio::fs::write(
            dir.path().join("threat-domains.txt"),
            "bad.example\turlhaus\nbad.example\topenphish\n",
        )
        .await
        .unwrap();

        migrate(dir.path()).await.unwrap();

        let store = Store::open(dir.path()).await.unwrap();
        assert_eq!(
            store.all_oui().await.unwrap().get("AABBCC"),
            Some(&"Generic Corp".to_string())
        );
        let feeds = store.threat_domain_feeds("bad.example").await.unwrap();
        assert_eq!(feeds.len(), 2);
    }

    #[tokio::test]
    async fn migrates_wan_state_and_notified_attempts() {
        let dir = tempfile::tempdir().unwrap();
        tokio::fs::write(dir.path().join("wan-state"), "down\n")
            .await
            .unwrap();
        tokio::fs::write(dir.path().join("wan-down-since"), "1000\n")
            .await
            .unwrap();
        tokio::fs::write(
            dir.path().join("notified-attempts"),
            "deny:guest:10.0.0.1\ndeny:guest:10.0.0.2\n",
        )
        .await
        .unwrap();

        migrate(dir.path()).await.unwrap();

        let store = Store::open(dir.path()).await.unwrap();
        assert_eq!(
            store.get_wan_state().await.unwrap(),
            Some(("down".to_string(), Some(1000)))
        );
        assert!(store
            .notified_attempt_seen("deny:guest:10.0.0.1")
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn orphaned_wan_down_since_without_wan_state_is_still_migrated_away() {
        // Regression test: a router that ran an older, pre-Store build of
        // check_wan.rs may have `wan-down-since` on disk with no sibling
        // `wan-state` file. The importer must not gate that file's
        // migration on `wan-state`'s presence, or it's skipped forever.
        let dir = tempfile::tempdir().unwrap();
        tokio::fs::write(dir.path().join("wan-down-since"), "1000\n")
            .await
            .unwrap();

        migrate(dir.path()).await.unwrap();

        assert!(
            tokio::fs::metadata(dir.path().join("wan-down-since.migrated"))
                .await
                .is_ok()
        );
        assert!(tokio::fs::metadata(dir.path().join("wan-down-since"))
            .await
            .is_err());

        // Re-running must not error or re-import.
        migrate(dir.path()).await.unwrap();
    }

    #[tokio::test]
    async fn missing_files_are_simply_skipped_not_errors() {
        let dir = tempfile::tempdir().unwrap();
        tokio::fs::write(dir.path().join("guest-notify.conf"), "IFACE_NAME=guest\n")
            .await
            .unwrap();
        let result = migrate(dir.path()).await;
        assert!(result.is_ok());
    }
}
