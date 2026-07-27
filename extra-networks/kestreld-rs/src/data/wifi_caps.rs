//! WiFi station-capability fingerprint via hostapd's own `ubus` interface
//! (`ubus call hostapd.<iface> get_clients`) — hostapd is already running
//! for the AP function itself, so this needs no packet capture, unlike
//! 802.11 information-element fingerprinting proper. Same granularity as
//! the DHCP fingerprint: identifies chipset/driver *family* (HT/VHT/HE
//! support, WMM, management-frame protection, ...), not a specific
//! physical unit — two units of the same phone model will report
//! identical capabilities.
//!
//! The exact JSON shape is hostapd/OpenWrt-version-dependent and hasn't
//! been verified against a live `ubus` response in this session (no
//! connected station was available to test against — same honesty
//! caveat as `data::dhcp_fingerprint`'s log format). This only reads a
//! handful of well-known boolean capability keys under `clients.<mac>`
//! and ignores everything else, so an unrecognized/renamed field in a
//! given hostapd version degrades to "no signal" rather than an error.

use crate::cmd;

/// Capability flags worth fingerprinting, in a fixed order so the
/// resulting string is deterministic regardless of the source JSON's own
/// key order.
const FLAGS: &[&str] = &["ht", "vht", "he", "wmm", "mfp"];

/// A normalized, comma-joined capability string for `mac` on network
/// `net` (e.g. "guest" — a bridge/network name, not a radio interface;
/// see `hostapd_iface_for`), or empty if hostapd isn't reachable, the
/// ubus object doesn't exist, or the MAC isn't currently associated.
pub async fn capabilities(net: &str, mac: &str) -> String {
    let Some(iface) = hostapd_iface_for(net).await else { return String::new() };
    let (ok, out) = cmd::run("ubus", &["call", &format!("hostapd.{iface}"), "get_clients"]).await;
    if !ok {
        return String::new();
    }
    parse_capabilities(&out, mac)
}

/// Resolves a network name (e.g. "guest") to the hostapd radio interface
/// serving its bridge, by scanning `/var/run/hostapd-*.conf` for one
/// whose config references `bridge=br-{net}` — the same technique
/// `routes::rotate_password` already uses to find the live config to
/// patch, just read-only here.
async fn hostapd_iface_for(net: &str) -> Option<String> {
    let mut dir = tokio::fs::read_dir("/var/run").await.ok()?;
    let needle = format!("bridge=br-{net}");
    while let Ok(Some(entry)) = dir.next_entry().await {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if !name.starts_with("hostapd-") || !name.ends_with(".conf") {
            continue;
        }
        let Ok(content) = tokio::fs::read_to_string(entry.path()).await else { continue };
        if content.contains(&needle) {
            return name.strip_prefix("hostapd-").and_then(|s| s.strip_suffix(".conf")).map(String::from);
        }
    }
    None
}

fn parse_capabilities(json_text: &str, mac: &str) -> String {
    let Ok(root) = serde_json::from_str::<serde_json::Value>(json_text) else { return String::new() };
    let Some(client) = root.get("clients").and_then(|c| c.get(mac)) else { return String::new() };
    FLAGS
        .iter()
        .filter(|&&flag| client.get(flag).and_then(|v| v.as_bool()).unwrap_or(false))
        .copied()
        .collect::<Vec<_>>()
        .join(",")
}

#[cfg(test)]
mod tests {
    use super::*;

    // Best-effort reconstruction of hostapd's ubus `get_clients` shape —
    // see the module docs for why this isn't verified against a live
    // response.
    const SAMPLE: &str = r#"{
        "freq": 2412,
        "clients": {
            "aa:bb:cc:dd:ee:ff": {
                "auth": true,
                "assoc": true,
                "authorized": true,
                "wmm": true,
                "ht": true,
                "vht": false,
                "he": false,
                "mfp": false,
                "aid": 1,
                "signal": -45
            },
            "11:22:33:44:55:66": {
                "auth": true,
                "assoc": true,
                "wmm": true,
                "ht": true,
                "vht": true,
                "he": true,
                "mfp": true
            }
        }
    }"#;

    #[test]
    fn parses_true_flags_in_fixed_order() {
        assert_eq!(parse_capabilities(SAMPLE, "aa:bb:cc:dd:ee:ff"), "ht,wmm");
    }

    #[test]
    fn newer_device_with_more_capabilities_reports_them_all() {
        assert_eq!(parse_capabilities(SAMPLE, "11:22:33:44:55:66"), "ht,vht,he,wmm,mfp");
    }

    #[test]
    fn unknown_mac_returns_empty() {
        assert_eq!(parse_capabilities(SAMPLE, "00:00:00:00:00:00"), "");
    }

    #[test]
    fn malformed_json_returns_empty_instead_of_panicking() {
        assert_eq!(parse_capabilities("not json", "aa:bb:cc:dd:ee:ff"), "");
    }

    #[test]
    fn missing_clients_key_returns_empty() {
        assert_eq!(parse_capabilities(r#"{"freq": 2412}"#, "aa:bb:cc:dd:ee:ff"), "");
    }
}
