use std::collections::HashMap;
use tokio::process::Command;

/// mac → list of IPs seen on that device
#[derive(Default, Clone)]
pub struct NeighTable {
    /// ip → (mac, state)
    pub by_ip: HashMap<String, (String, String)>,
    /// mac → [ipv6 global]
    pub ip6_by_mac: HashMap<String, Vec<String>>,
}

pub async fn fetch() -> NeighTable {
    let v4 = run_neigh(false).await;
    let v6 = run_neigh(true).await;

    let mut table = NeighTable::default();

    for line in v4.lines().chain(v6.lines()) {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 2 {
            continue;
        }
        let ip = parts[0];
        let state = parts.last().unwrap_or(&"").to_string();
        let mac = parts
            .windows(2)
            .find(|w| w[0] == "lladdr")
            .map(|w| w[1].to_lowercase());

        if let Some(mac) = mac {
            table.by_ip.insert(ip.to_string(), (mac.clone(), state));

            // Track IPv6 global addresses per MAC
            if ip.contains(':') && !ip.starts_with("fe80") {
                table
                    .ip6_by_mac
                    .entry(mac)
                    .or_default()
                    .push(ip.to_string());
            }
        } else {
            // Still track reachability even without MAC (for IPv6)
            table
                .by_ip
                .insert(ip.to_string(), (String::new(), state));
        }
    }

    table
}

async fn run_neigh(ipv6: bool) -> String {
    let mut cmd = Command::new("ip");
    if ipv6 {
        cmd.arg("-6");
    }
    cmd.args(["neigh", "show"]);
    cmd.output()
        .await
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .unwrap_or_default()
}

impl NeighTable {
    pub fn is_reachable(&self, ip: &str) -> bool {
        self.by_ip
            .get(ip)
            .map(|(_, state)| {
                matches!(state.as_str(), "REACHABLE" | "DELAY" | "PROBE")
            })
            .unwrap_or(false)
    }

    pub fn mac_for_ip(&self, ip: &str) -> Option<&str> {
        self.by_ip
            .get(ip)
            .map(|(mac, _)| mac.as_str())
            .filter(|s| !s.is_empty())
    }

    /// First global IPv6 for a MAC
    pub fn ip6_for_mac(&self, mac: &str) -> Option<&str> {
        self.ip6_by_mac
            .get(&mac.to_lowercase())
            .and_then(|v| v.first())
            .map(|s| s.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_table() -> NeighTable {
        let mut t = NeighTable::default();
        t.by_ip.insert("192.168.1.1".to_string(), ("aa:bb:cc:dd:ee:ff".to_string(), "REACHABLE".to_string()));
        t.by_ip.insert("192.168.1.2".to_string(), ("11:22:33:44:55:66".to_string(), "STALE".to_string()));
        t.by_ip.insert("192.168.1.3".to_string(), ("77:88:99:aa:bb:cc".to_string(), "DELAY".to_string()));
        t.by_ip.insert("192.168.1.4".to_string(), ("".to_string(), "REACHABLE".to_string()));
        t.ip6_by_mac.insert("aa:bb:cc:dd:ee:ff".to_string(), vec!["2001:db8::1".to_string()]);
        t
    }

    // ── is_reachable ──────────────────────────────────────────────────────────

    #[test]
    fn reachable_state_true() {
        let t = make_table();
        assert!(t.is_reachable("192.168.1.1"));
    }

    #[test]
    fn delay_state_is_reachable() {
        let t = make_table();
        assert!(t.is_reachable("192.168.1.3"));
    }

    #[test]
    fn stale_state_is_not_reachable() {
        let t = make_table();
        assert!(!t.is_reachable("192.168.1.2"));
    }

    #[test]
    fn unknown_ip_is_not_reachable() {
        let t = make_table();
        assert!(!t.is_reachable("10.0.0.99"));
    }

    // ── mac_for_ip ────────────────────────────────────────────────────────────

    #[test]
    fn mac_for_ip_found() {
        let t = make_table();
        assert_eq!(t.mac_for_ip("192.168.1.1"), Some("aa:bb:cc:dd:ee:ff"));
    }

    #[test]
    fn mac_for_ip_empty_mac_returns_none() {
        let t = make_table();
        // IP exists but mac is empty string
        assert_eq!(t.mac_for_ip("192.168.1.4"), None);
    }

    #[test]
    fn mac_for_ip_unknown_returns_none() {
        let t = make_table();
        assert_eq!(t.mac_for_ip("10.0.0.99"), None);
    }

    // ── ip6_for_mac ───────────────────────────────────────────────────────────

    #[test]
    fn ip6_for_mac_found() {
        let t = make_table();
        assert_eq!(t.ip6_for_mac("aa:bb:cc:dd:ee:ff"), Some("2001:db8::1"));
    }

    #[test]
    fn ip6_for_mac_case_insensitive() {
        let t = make_table();
        assert_eq!(t.ip6_for_mac("AA:BB:CC:DD:EE:FF"), Some("2001:db8::1"));
    }

    #[test]
    fn ip6_for_mac_unknown_returns_none() {
        let t = make_table();
        assert_eq!(t.ip6_for_mac("ff:ff:ff:ff:ff:ff"), None);
    }
}
