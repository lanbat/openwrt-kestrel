use tokio::process::Command;

#[derive(Default, Clone)]
pub struct WgServer {
    pub name: String,
    pub peers: Vec<WgPeer>,
}

#[derive(Clone)]
pub struct WgPeer {
    pub online: bool,
    pub label: String,
    pub endpoint: String,
    pub allowed_ips: String,
    pub last_seen: String,
    pub traffic: String,
    /// Raw last-handshake unix timestamp (0 if never) — kept alongside
    /// the dashboard's own `online` (180s threshold) and `last_seen`
    /// (formatted) fields so other callers, e.g. the daily digest's
    /// "active in the last 24h" count, can apply their own window
    /// instead of the dashboard's.
    pub handshake_ts: u64,
}

pub async fn fetch_servers(now_ts: u64) -> Vec<WgServer> {
    let uci_raw = Command::new("uci")
        .args(["show", "network"])
        .output()
        .await
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .unwrap_or_default();

    // Find WireGuard interfaces
    let mut wg_ifaces: Vec<String> = Vec::new();
    for line in uci_raw.lines() {
        if line.contains(".proto='wireguard'") {
            if let Some(section) = line.splitn(2, '.').next() {
                let iface = section.trim_start_matches("network.");
                wg_ifaces.push(iface.to_string());
            }
        }
    }

    let mut servers = Vec::new();

    for iface in wg_ifaces {
        // Only show server-mode interfaces (no endpoint_host on any peer)
        if !is_server(&iface, &uci_raw) {
            continue;
        }

        let dump = Command::new("wg")
            .args(["show", &iface, "dump"])
            .output()
            .await
            .ok()
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .unwrap_or_default();

        // Skip header line (the interface itself)
        let peer_lines: Vec<&str> = dump.lines().skip(1).collect();

        let mut peers = Vec::new();

        // Enumerate UCI peers
        let mut idx = 0;
        loop {
            let pk_key = format!("network.@wireguard_{iface}[{idx}].public_key");
            let pk = uci_get(&uci_raw, &pk_key);
            if pk.is_empty() {
                break;
            }
            let desc = uci_get(
                &uci_raw,
                &format!("network.@wireguard_{iface}[{idx}].description"),
            );
            let aips = uci_get(
                &uci_raw,
                &format!("network.@wireguard_{iface}[{idx}].allowed_ips"),
            );
            idx += 1;

            let label = if desc.is_empty() {
                format!("{}…", &pk[..8.min(pk.len())])
            } else {
                desc
            };

            // Find matching dump line by public key
            let peer_line = peer_lines.iter().find(|l| l.starts_with(&pk));

            let (online, endpoint, last_seen, traffic, handshake_ts) = if let Some(line) = peer_line
            {
                let cols: Vec<&str> = line.split('\t').collect();
                let ep = cols.get(2).copied().unwrap_or("").to_string();
                let ep = if ep == "(none)" { String::new() } else { ep };
                let hs: u64 = cols.get(4).and_then(|s| s.parse().ok()).unwrap_or(0);
                let rx: u64 = cols.get(5).and_then(|s| s.parse().ok()).unwrap_or(0);
                let tx: u64 = cols.get(6).and_then(|s| s.parse().ok()).unwrap_or(0);

                let online = hs > 0 && (now_ts.saturating_sub(hs) < 180);
                let last_seen = if hs == 0 {
                    "—".to_string()
                } else {
                    format_ago(now_ts.saturating_sub(hs))
                };
                let traffic = if rx > 0 || tx > 0 {
                    format!("{} / {}", human_bytes(rx), human_bytes(tx))
                } else {
                    "—".to_string()
                };
                (online, ep, last_seen, traffic, hs)
            } else {
                (false, String::new(), "—".to_string(), "—".to_string(), 0)
            };

            peers.push(WgPeer {
                online,
                label,
                endpoint,
                handshake_ts,
                allowed_ips: aips.replace(' ', ", "),
                last_seen,
                traffic,
            });
        }

        if !peers.is_empty() {
            servers.push(WgServer { name: iface, peers });
        }
    }

    servers
}

fn is_server(iface: &str, uci_raw: &str) -> bool {
    // Server if none of the peers have endpoint_host set
    let mut idx = 0;
    loop {
        let pk_key = format!("network.@wireguard_{iface}[{idx}].public_key");
        if uci_get(uci_raw, &pk_key).is_empty() {
            break;
        }
        let ep_key = format!("network.@wireguard_{iface}[{idx}].endpoint_host");
        if !uci_get(uci_raw, &ep_key).is_empty() {
            return false;
        }
        idx += 1;
    }
    true
}

fn uci_get(raw: &str, key: &str) -> String {
    // key format: network.section.option
    // uci show output: network.section.option='value'
    for line in raw.lines() {
        if let Some(rest) = line.strip_prefix(key) {
            if rest.starts_with('=') {
                return rest[1..].trim().trim_matches('\'').to_string();
            }
        }
    }
    String::new()
}

fn format_ago(secs: u64) -> String {
    if secs < 60 {
        format!("{secs}s ago")
    } else if secs < 3600 {
        format!("{}m ago", secs / 60)
    } else if secs < 86400 {
        format!("{}h ago", secs / 3600)
    } else {
        format!("{}d ago", secs / 86400)
    }
}

pub fn human_bytes(b: u64) -> String {
    if b >= 1_073_741_824 {
        format!("{:.1} GB", b as f64 / 1_073_741_824.0)
    } else if b >= 1_048_576 {
        format!("{:.1} MB", b as f64 / 1_048_576.0)
    } else if b >= 1024 {
        format!("{:.1} KB", b as f64 / 1024.0)
    } else {
        format!("{b} B")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── human_bytes ───────────────────────────────────────────────────────────

    #[test]
    fn human_bytes_bytes() {
        assert_eq!(human_bytes(0), "0 B");
        assert_eq!(human_bytes(512), "512 B");
        assert_eq!(human_bytes(1023), "1023 B");
    }

    #[test]
    fn human_bytes_kilobytes() {
        assert_eq!(human_bytes(1024), "1.0 KB");
        assert_eq!(human_bytes(2048), "2.0 KB");
    }

    #[test]
    fn human_bytes_megabytes() {
        assert_eq!(human_bytes(1_048_576), "1.0 MB");
        assert_eq!(human_bytes(5 * 1_048_576), "5.0 MB");
    }

    #[test]
    fn human_bytes_gigabytes() {
        assert_eq!(human_bytes(1_073_741_824), "1.0 GB");
        assert_eq!(human_bytes(2 * 1_073_741_824), "2.0 GB");
    }

    // ── format_ago ────────────────────────────────────────────────────────────

    #[test]
    fn format_ago_seconds() {
        assert_eq!(format_ago(0), "0s ago");
        assert_eq!(format_ago(45), "45s ago");
        assert_eq!(format_ago(59), "59s ago");
    }

    #[test]
    fn format_ago_minutes() {
        assert_eq!(format_ago(60), "1m ago");
        assert_eq!(format_ago(90), "1m ago");
        assert_eq!(format_ago(3599), "59m ago");
    }

    #[test]
    fn format_ago_hours() {
        assert_eq!(format_ago(3600), "1h ago");
        assert_eq!(format_ago(7200), "2h ago");
        assert_eq!(format_ago(86399), "23h ago");
    }

    #[test]
    fn format_ago_days() {
        assert_eq!(format_ago(86400), "1d ago");
        assert_eq!(format_ago(7 * 86400), "7d ago");
    }

    // ── uci_get ───────────────────────────────────────────────────────────────

    const UCI_RAW: &str = "\
network.wg0.proto='wireguard'
network.@wireguard_wg0[0].public_key='AAABBBCCC'
network.@wireguard_wg0[0].description='laptop'
network.@wireguard_wg0[0].allowed_ips='10.200.0.2/32'
network.@wireguard_wg0[1].public_key='DDDEEEFFF'
network.@wireguard_wg0[1].allowed_ips='10.200.0.3/32'
";

    #[test]
    fn uci_get_basic() {
        assert_eq!(
            uci_get(UCI_RAW, "network.@wireguard_wg0[0].public_key"),
            "AAABBBCCC"
        );
    }

    #[test]
    fn uci_get_description() {
        assert_eq!(
            uci_get(UCI_RAW, "network.@wireguard_wg0[0].description"),
            "laptop"
        );
    }

    #[test]
    fn uci_get_missing_returns_empty() {
        assert_eq!(uci_get(UCI_RAW, "network.@wireguard_wg0[2].public_key"), "");
    }

    #[test]
    fn uci_get_proto() {
        assert_eq!(uci_get(UCI_RAW, "network.wg0.proto"), "wireguard");
    }

    // ── is_server ─────────────────────────────────────────────────────────────

    #[test]
    fn is_server_true_when_no_endpoint_host() {
        // None of the peers have endpoint_host
        assert!(is_server("wg0", UCI_RAW));
    }

    #[test]
    fn is_server_false_when_peer_has_endpoint_host() {
        let uci = "\
network.@wireguard_wg0[0].public_key='AAABBBCCC'
network.@wireguard_wg0[0].endpoint_host='vpn.example.com'
";
        assert!(!is_server("wg0", uci));
    }

    #[test]
    fn is_server_true_when_no_peers() {
        // No peers means server with no clients
        assert!(is_server("wg0", "network.wg0.proto='wireguard'\n"));
    }
}
