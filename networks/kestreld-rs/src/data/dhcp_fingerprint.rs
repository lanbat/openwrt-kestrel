//! Extracts a per-MAC DHCP fingerprint from dnsmasq's `--log-dhcp` output
//! (enabled by `install.sh` via `dhcp.@dnsmasq[0].logdhcp=1`): the DHCP
//! option-request-list order and vendor class string a device sends when
//! it associates. These are a fairly stable signature of OS/device
//! *family* (this is the same idea behind fingerbank.org-style DHCP
//! fingerprint databases) — two units of the same phone model on the same
//! OS version will usually produce an identical fingerprint, so this
//! narrows down device class, not a specific physical unit. See
//! `data::fingerprint` for how it's combined with other signals into
//! something closer to unique-device identification.

use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DhcpFingerprint {
    /// Option numbers from the "requested options" line, in the order the
    /// device sent them (e.g. "1,3,6,15,119,252") — order is part of the
    /// signal, different OSes/stacks request the same options in
    /// different sequences.
    pub requested_options: String,
    /// The DHCP vendor class identifier (option 60), if the device sent
    /// one (e.g. "MSFT 5.0", "android-dhcp-14").
    pub vendor_class: String,
}

impl DhcpFingerprint {
    pub fn is_empty(&self) -> bool {
        self.requested_options.is_empty() && self.vendor_class.is_empty()
    }
}

/// Scans dnsmasq log lines — must be in chronological order, as
/// `data::logs::LogData.lines` already is — and returns the most recently
/// seen fingerprint for each MAC. dnsmasq logs "requested options"/"vendor
/// class" as separate lines immediately following the DHCPDISCOVER/
/// DHCPREQUEST/DHCPACK line that names the MAC, without repeating the MAC
/// on those lines themselves, so this has to track "whose transaction is
/// this" as it scans forward.
pub fn parse_all(lines: &[String]) -> HashMap<String, DhcpFingerprint> {
    let mut result: HashMap<String, DhcpFingerprint> = HashMap::new();
    let mut current_mac: Option<String> = None;

    for line in lines {
        if let Some(mac) = transaction_mac(line) {
            current_mac = Some(mac);
            continue;
        }
        let Some(mac) = current_mac.clone() else {
            continue;
        };
        if let Some(opts) = requested_options(line) {
            result.entry(mac).or_default().requested_options = opts;
        } else if let Some(vc) = vendor_class(line) {
            result.entry(mac).or_default().vendor_class = vc;
        }
    }
    result
}

fn transaction_mac(line: &str) -> Option<String> {
    if !line.contains("dnsmasq-dhcp") {
        return None;
    }
    let is_transaction_line = ["DHCPDISCOVER", "DHCPREQUEST", "DHCPACK", "DHCPOFFER"]
        .iter()
        .any(|kw| line.contains(kw));
    if !is_transaction_line {
        return None;
    }
    line.split_whitespace()
        .find(|tok| tok.len() == 17 && tok.matches(':').count() == 5)
        .map(|s| s.to_lowercase())
}

fn requested_options(line: &str) -> Option<String> {
    let rest = line.split("requested options:").nth(1)?;
    let nums: Vec<&str> = rest
        .split(',')
        .filter_map(|part| part.trim().split(':').next())
        .filter(|s| !s.is_empty() && s.chars().all(|c| c.is_ascii_digit()))
        .collect();
    if nums.is_empty() {
        None
    } else {
        Some(nums.join(","))
    }
}

fn vendor_class(line: &str) -> Option<String> {
    let rest = line.split("vendor class:").nth(1)?;
    let vc = rest.trim();
    if vc.is_empty() {
        None
    } else {
        Some(vc.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lines(raw: &[&str]) -> Vec<String> {
        raw.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn parses_requested_options_and_vendor_class_for_one_device() {
        let log = lines(&[
            "Mon Jul 27 09:00:00 2026 daemon.info dnsmasq-dhcp[123]: DHCPDISCOVER(br-guest) 02:11:22:33:44:55",
            "Mon Jul 27 09:00:00 2026 daemon.info dnsmasq-dhcp[123]: DHCPOFFER(br-guest) 192.168.3.105 02:11:22:33:44:55",
            "Mon Jul 27 09:00:00 2026 daemon.info dnsmasq-dhcp[123]: requested options: 1:netmask, 3:router, 6:dns-server, 119:domain-search",
            "Mon Jul 27 09:00:01 2026 daemon.info dnsmasq-dhcp[123]: DHCPREQUEST(br-guest) 192.168.3.105 02:11:22:33:44:55",
            "Mon Jul 27 09:00:01 2026 daemon.info dnsmasq-dhcp[123]: vendor class: android-dhcp-14",
            "Mon Jul 27 09:00:01 2026 daemon.info dnsmasq-dhcp[123]: DHCPACK(br-guest) 192.168.3.105 02:11:22:33:44:55 pixel-8",
        ]);
        let fps = parse_all(&log);
        let fp = fps.get("02:11:22:33:44:55").expect("fingerprint captured");
        assert_eq!(fp.requested_options, "1,3,6,119");
        assert_eq!(fp.vendor_class, "android-dhcp-14");
    }

    #[test]
    fn attributes_fingerprint_lines_to_the_correct_device_when_interleaved() {
        let log = lines(&[
            "dnsmasq-dhcp[1]: DHCPDISCOVER(br-guest) 02:aa:aa:aa:aa:aa",
            "dnsmasq-dhcp[1]: requested options: 1:netmask, 3:router",
            "dnsmasq-dhcp[2]: DHCPDISCOVER(br-guest) 02:bb:bb:bb:bb:bb",
            "dnsmasq-dhcp[2]: requested options: 1:netmask, 6:dns-server, 15:domain",
        ]);
        let fps = parse_all(&log);
        assert_eq!(
            fps.get("02:aa:aa:aa:aa:aa").unwrap().requested_options,
            "1,3"
        );
        assert_eq!(
            fps.get("02:bb:bb:bb:bb:bb").unwrap().requested_options,
            "1,6,15"
        );
    }

    #[test]
    fn later_transaction_for_same_mac_overwrites_the_earlier_fingerprint() {
        let log = lines(&[
            "dnsmasq-dhcp[1]: DHCPDISCOVER(br-guest) 02:11:22:33:44:55",
            "dnsmasq-dhcp[1]: requested options: 1:netmask",
            "dnsmasq-dhcp[2]: DHCPDISCOVER(br-guest) 02:11:22:33:44:55",
            "dnsmasq-dhcp[2]: requested options: 1:netmask, 3:router, 6:dns-server",
        ]);
        let fps = parse_all(&log);
        assert_eq!(
            fps.get("02:11:22:33:44:55").unwrap().requested_options,
            "1,3,6"
        );
    }

    #[test]
    fn unrelated_log_lines_and_other_daemons_are_ignored() {
        let log = lines(&[
            "daemon.notice dropbear[1]: Child connection from 192.168.1.2:1234",
            "dnsmasq-dhcp[1]: DHCPDISCOVER(br-guest) 02:11:22:33:44:55",
            "user.notice dnsmasq: query[A] example.com from 192.168.3.105",
            "dnsmasq-dhcp[1]: requested options: 1:netmask",
        ]);
        let fps = parse_all(&log);
        assert_eq!(fps.len(), 1);
        assert_eq!(fps.get("02:11:22:33:44:55").unwrap().requested_options, "1");
    }

    #[test]
    fn parse_all_returns_empty_map_for_no_dhcp_activity() {
        let log = lines(&["daemon.notice dropbear[1]: Child connection from 192.168.1.2:1234"]);
        assert!(parse_all(&log).is_empty());
    }

    #[test]
    fn dhcp_fingerprint_is_empty_when_no_fields_captured() {
        assert!(DhcpFingerprint::default().is_empty());
    }
}
