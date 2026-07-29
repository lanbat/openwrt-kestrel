//! Inbound OpenVPN server peer visibility — the OpenVPN counterpart to
//! `data::wg`'s WireGuard peer panel (see also `data::vpn`, which is the
//! separate, already protocol-agnostic split-routing *egress* tier
//! machinery — this module is about *inbound* VPN-server clients, same
//! distinction as `wg.rs` vs `vpn.rs`).
//!
//! Parses each configured instance's `--status-version 2` status file
//! (path read straight from that instance's own UCI `status` option)
//! rather than querying OpenVPN's management socket — the status file
//! needs no open management port and is simpler to parse. Only named UCI
//! sections are considered (`config openvpn 'myserver'`), matching how
//! OpenWrt's openvpn package is normally configured; anonymous sections
//! have no natural display name and are skipped.

use tokio::process::Command;

#[derive(Default, Clone)]
pub struct OpenVpnServer {
    pub name: String,
    pub peers: Vec<OpenVpnPeer>,
}

#[derive(Clone)]
pub struct OpenVpnPeer {
    pub common_name: String,
    pub real_address: String,
    pub virtual_address: String,
    pub connected_since: String,
    /// "rx / tx" human-readable bytes, reusing `wg::human_bytes`.
    pub traffic: String,
}

pub async fn fetch_servers() -> Vec<OpenVpnServer> {
    let uci_raw = Command::new("uci")
        .args(["show", "openvpn"])
        .output()
        .await
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .unwrap_or_default();

    let mut servers = Vec::new();
    for name in instance_names(&uci_raw) {
        let status_path = uci_get(&uci_raw, &format!("openvpn.{name}.status"));
        if status_path.is_empty() {
            continue;
        }
        let Ok(content) = tokio::fs::read_to_string(&status_path).await else { continue };
        let peers = parse_status_v2(&content);
        if !peers.is_empty() {
            servers.push(OpenVpnServer { name, peers });
        }
    }
    servers
}

/// Named `config openvpn '<name>'` sections from `uci show openvpn`
/// (lines of the form `openvpn.<name>=openvpn`); anonymous sections
/// (`openvpn.@openvpn[N]=openvpn`) are skipped.
fn instance_names(uci_raw: &str) -> Vec<String> {
    uci_raw
        .lines()
        .filter_map(|line| {
            let rest = line.strip_prefix("openvpn.")?;
            let name = rest.strip_suffix("=openvpn")?;
            if name.starts_with('@') { None } else { Some(name.to_string()) }
        })
        .collect()
}

fn uci_get(raw: &str, key: &str) -> String {
    for line in raw.lines() {
        if let Some(rest) = line.strip_prefix(key) {
            if let Some(v) = rest.strip_prefix('=') {
                return v.trim().trim_matches('\'').to_string();
            }
        }
    }
    String::new()
}

/// Parses `--status-version 2` `CLIENT_LIST` lines:
/// `CLIENT_LIST,common_name,real_address,virtual_address,virtual_ipv6_address,bytes_received,bytes_sent,connected_since,...`
fn parse_status_v2(content: &str) -> Vec<OpenVpnPeer> {
    content
        .lines()
        .filter_map(|line| {
            let mut f = line.split(',');
            if f.next()? != "CLIENT_LIST" {
                return None;
            }
            let common_name = f.next()?.to_string();
            let real_address = f.next()?.to_string();
            let virtual_address = f.next()?.to_string();
            let _virtual_ipv6 = f.next()?;
            let rx: u64 = f.next()?.parse().unwrap_or(0);
            let tx: u64 = f.next()?.parse().unwrap_or(0);
            let connected_since = f.next().unwrap_or("").to_string();
            let traffic = format!("{} / {}", super::wg::human_bytes(rx), super::wg::human_bytes(tx));
            Some(OpenVpnPeer { common_name, real_address, virtual_address, connected_since, traffic })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const UCI_RAW: &str = "\
openvpn.myserver=openvpn
openvpn.myserver.enabled='1'
openvpn.myserver.status='/var/run/openvpn.myserver.status'
openvpn.@openvpn[0]=openvpn
openvpn.@openvpn[0].enabled='0'
";

    #[test]
    fn instance_names_skips_anonymous_sections() {
        assert_eq!(instance_names(UCI_RAW), vec!["myserver".to_string()]);
    }

    #[test]
    fn uci_get_reads_status_option() {
        assert_eq!(uci_get(UCI_RAW, "openvpn.myserver.status"), "/var/run/openvpn.myserver.status");
    }

    #[test]
    fn uci_get_missing_returns_empty() {
        assert_eq!(uci_get(UCI_RAW, "openvpn.myserver.missing"), "");
    }

    #[test]
    fn parse_status_v2_extracts_client_list_lines() {
        let content = "\
TITLE,OpenVPN 2.6.0
TIME,Mon Jan  1 12:00:00 2024,1704110400
HEADER,CLIENT_LIST,Common Name,Real Address,Virtual Address,Virtual IPv6 Address,Bytes Received,Bytes Sent,Connected Since,Connected Since (time_t),Username,Client ID,Peer ID,Data Channel Cipher
CLIENT_LIST,laptop,203.0.113.5:54321,10.8.0.2,,123456,654321,Mon Jan  1 12:00:00 2024,1704110400,UNDEF,0,0,AES-256-GCM
GLOBAL_STATS,Max bcast/mcast queue length,0
END
";
        let peers = parse_status_v2(content);
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].common_name, "laptop");
        assert_eq!(peers[0].real_address, "203.0.113.5:54321");
        assert_eq!(peers[0].virtual_address, "10.8.0.2");
        assert_eq!(peers[0].connected_since, "Mon Jan  1 12:00:00 2024");
        assert_eq!(peers[0].traffic, "120.6 KB / 639.0 KB");
    }

    #[test]
    fn parse_status_v2_ignores_non_client_list_lines() {
        let content = "TITLE,OpenVPN 2.6.0\nHEADER,CLIENT_LIST,...\n";
        assert!(parse_status_v2(content).is_empty());
    }
}
