//! Port of `tools/bandwidth-check.sh`: alerts when a device on an
//! isolated network exceeds `BANDWIDTH_THRESHOLD_MB` in a session (the
//! nft byte counters reset on `fw4 reload` or after 24h of inactivity).
//! Combines IPv4+IPv6 bytes per device (matched by MAC). Invoked as
//! `kestreld --check-bandwidth` hourly via cron (see `install.sh`).
//! Alerts once per MAC per session — tracked in a `{iface}-bw-alerted`
//! file, pruned of any MAC no longer present in the current byte-counter
//! data (matches the shell version's own cleanup step).
//!
//! Reuses `data::nft::NftState::device_bytes` (already existed, unused
//! outside its own tests), `data::dhcp::fetch` (IPv4→MAC), and
//! `data::neigh::fetch` (IPv6→MAC) rather than re-parsing `nft list set`/
//! `ip neigh show` output again.

use std::collections::HashMap;
use std::path::Path;

use crate::cmd;
use crate::data::{dhcp, files, neigh, nft};

fn human_bytes(b: u64) -> String {
    let b = b as f64;
    if b >= 1_073_741_824.0 {
        format!("{:.1} GB", b / 1_073_741_824.0)
    } else if b >= 1_048_576.0 {
        format!("{:.1} MB", b / 1_048_576.0)
    } else if b >= 1024.0 {
        format!("{:.1} KB", b / 1024.0)
    } else {
        format!("{b:.0} B")
    }
}

/// Sums per-MAC bytes from IPv4 + IPv6 counter maps, resolving IPs to
/// MACs via the DHCP-lease-derived map (v4) and neighbor table (v6).
/// Keeps the first IP seen per MAC as the "representative" one for the
/// alert message and hostname lookup. IPs with no resolvable MAC are
/// dropped (matches the shell version silently skipping them).
fn combine_by_mac(
    v4: &HashMap<String, u64>,
    v6: &HashMap<String, u64>,
    ip_to_mac_v4: &HashMap<String, String>,
    neigh_table: &neigh::NeighTable,
) -> HashMap<String, (String, u64)> {
    let mut totals: HashMap<String, (String, u64)> = HashMap::new();
    for (ip, bytes) in v4 {
        let Some(mac) = ip_to_mac_v4.get(ip) else { continue };
        let entry = totals.entry(mac.clone()).or_insert_with(|| (ip.clone(), 0));
        entry.1 += bytes;
    }
    for (ip6, bytes) in v6 {
        let Some(mac) = neigh_table.mac_for_ip(ip6) else { continue };
        let entry = totals.entry(mac.to_string()).or_insert_with(|| (ip6.clone(), 0));
        entry.1 += bytes;
    }
    totals
}

pub async fn run(base_dir: &Path) -> i32 {
    let confs = files::read_all_network_confs(base_dir).await;
    let nft_state = nft::fetch().await;
    let leases = dhcp::fetch().await;
    let neigh_table = neigh::fetch().await;

    let ip_to_mac_v4: HashMap<String, String> =
        leases.iter().map(|l| (l.ip.clone(), l.mac.clone())).collect();
    let hostname_by_ip: HashMap<String, String> =
        leases.iter().map(|l| (l.ip.clone(), l.hostname.clone())).collect();

    for conf in confs {
        if conf.notify_url.is_empty() || conf.iface.is_empty() || conf.bandwidth_threshold_mb == 0 {
            continue;
        }
        let thresh_bytes = conf.bandwidth_threshold_mb * 1_048_576;
        let iface = &conf.iface;

        let v4 = nft_state.device_bytes(&format!("{iface}_device_bytes"));
        let v6 = nft_state.device_bytes(&format!("{iface}_device_bytes6"));
        if v4.is_empty() && v6.is_empty() {
            continue;
        }

        let combined = combine_by_mac(&v4, &v6, &ip_to_mac_v4, &neigh_table);
        if combined.is_empty() {
            continue;
        }

        let alerted_path = base_dir.join(format!("{iface}-bw-alerted"));
        let alerted: Vec<String> =
            files::read_lines(&alerted_path).await.into_iter().map(|l| l.to_lowercase()).collect();

        for (mac, (ip, bytes)) in &combined {
            if alerted.contains(&mac.to_lowercase()) || *bytes <= thresh_bytes {
                continue;
            }
            let label = match hostname_by_ip.get(ip) {
                Some(name) if !name.is_empty() => format!("{name} ({ip})"),
                _ => ip.clone(),
            };
            let _ = files::file_append(&alerted_path, mac).await;
            cmd::ntfy(
                &conf.notify_url,
                &format!("Bandwidth alert — {iface}"),
                "default",
                "warning",
                &format!(
                    "Type: Bandwidth alert\n\n{label} has used {} on {iface} (threshold: {} MB).",
                    human_bytes(*bytes), conf.bandwidth_threshold_mb
                ),
            ).await;
        }

        if tokio::fs::metadata(&alerted_path).await.is_ok() {
            let still_present: String = alerted.iter()
                .filter(|a| combined.keys().any(|m| &m.to_lowercase() == *a))
                .map(|a| format!("{a}\n"))
                .collect();
            let _ = tokio::fs::write(&alerted_path, still_present).await;
        }
    }

    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn human_bytes_picks_the_right_unit() {
        assert_eq!(human_bytes(500), "500 B");
        assert_eq!(human_bytes(2048), "2.0 KB");
        assert_eq!(human_bytes(5_242_880), "5.0 MB");
        assert_eq!(human_bytes(2_147_483_648), "2.0 GB");
    }

    fn neigh_with(ip: &str, mac: &str) -> neigh::NeighTable {
        let mut t = neigh::NeighTable::default();
        t.by_ip.insert(ip.to_string(), (mac.to_string(), "REACHABLE".to_string()));
        t
    }

    #[test]
    fn combines_v4_and_v6_bytes_for_the_same_mac() {
        let v4 = HashMap::from([("192.168.3.100".to_string(), 1000u64)]);
        let v6 = HashMap::from([("2001:db8::1".to_string(), 2000u64)]);
        let ip_to_mac = HashMap::from([("192.168.3.100".to_string(), "aa:bb:cc:dd:ee:ff".to_string())]);
        let neigh_table = neigh_with("2001:db8::1", "aa:bb:cc:dd:ee:ff");

        let combined = combine_by_mac(&v4, &v6, &ip_to_mac, &neigh_table);
        assert_eq!(combined.get("aa:bb:cc:dd:ee:ff").unwrap().1, 3000);
    }

    #[test]
    fn drops_ips_with_no_resolvable_mac() {
        let v4 = HashMap::from([("192.168.3.200".to_string(), 999u64)]);
        let combined = combine_by_mac(&v4, &HashMap::new(), &HashMap::new(), &neigh::NeighTable::default());
        assert!(combined.is_empty());
    }

    #[test]
    fn keeps_first_seen_ip_as_representative() {
        let v4 = HashMap::from([("192.168.3.100".to_string(), 1u64)]);
        let ip_to_mac = HashMap::from([("192.168.3.100".to_string(), "aa:bb:cc:dd:ee:ff".to_string())]);
        let combined = combine_by_mac(&v4, &HashMap::new(), &ip_to_mac, &neigh::NeighTable::default());
        assert_eq!(combined.get("aa:bb:cc:dd:ee:ff").unwrap().0, "192.168.3.100");
    }
}
