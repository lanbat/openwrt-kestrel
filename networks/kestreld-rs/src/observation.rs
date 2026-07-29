//! Time-boxed device "observation" windows: instead of approving or
//! denying each pending connection individually, a device can be put into
//! a mode where every new connection attempt is allowed and recorded for a
//! fixed duration, then turned into permanent rules automatically once the
//! window closes — preferring a domain-based rule over a raw-IP one
//! wherever `data::dns_answers::correlate` found a match, since a domain
//! rule keeps working if the destination's IP later changes.
//!
//! **Enforcement** is kernel-side and self-expiring: `start` adds the
//! device's IP(s) to a per-network `{iface}_observe_4`/`_6` nftables set
//! (declared and wired into the `{iface}_inspect` chain by
//! `regen_inspect.rs`) with an element `timeout` equal to the window
//! duration — nftables expires the membership itself, so there's no race
//! where a daemon timer has to remember to revoke a temporary allow.
//!
//! **Capture** needs no new code: `daemon.rs`'s `handle_new` already
//! records every new connection attempt to `{iface}-pending-{mac_n}`
//! regardless of allow/deny state, so an observed device's connections
//! land there exactly like any other pending connection would.
//!
//! **Materialization** (`materialize_expired`, polled by a `daemon.rs`
//! task) is what actually turns a closed window's pending entries into
//! permanent `DeviceRule`s. `write_domain_rule`/`write_ip_rule` are the
//! same rule-writing side effects `routes::device`'s `approve_domain`/
//! `approve_pending` HTTP handlers perform — factored out here so both
//! call sites share one implementation instead of two copies that could
//! drift apart. Materialized rules always use the WAN route (no VPN tier)
//! since observation never asked the user to choose one; a VPN route can
//! still be added afterward by re-approving the same domain from the
//! device page.

use std::path::Path;

use crate::cmd;
use crate::data::{dns_answers, files};
use crate::plugins::{Event, PluginManager};

fn mac_no_colons(mac: &str) -> String {
    mac.replace(':', "")
}

/// Reverses `mac_no_colons`: `"aabbccddeeff"` -> `"aa:bb:cc:dd:ee:ff"`.
fn colonize_mac(mac_n: &str) -> String {
    mac_n
        .as_bytes()
        .chunks(2)
        .map(|c| std::str::from_utf8(c).unwrap_or(""))
        .collect::<Vec<_>>()
        .join(":")
}

/// Starts an observation window for `mac` on `iface`: records the window's
/// start/expiry and adds the device's current IP(s) to the observe set
/// with a matching nft `timeout`. No `regen_inspect::run` call is needed
/// here — the `{iface}_observe_4`/`_6` sets and the chain rule that
/// accepts their members are declared unconditionally for any network
/// with at least one labeled device (see `regen_inspect.rs`), which must
/// already be true for `mac` to have reached the device page at all.
pub async fn start(base_dir: &Path, iface: &str, mac: &str, ip: Option<&str>, ip6: Option<&str>, duration_secs: u64, now: u64) {
    let mac_n = mac_no_colons(mac);
    let expiry = now + duration_secs;
    let observe_path = base_dir.join(format!("{iface}-observe-{mac_n}"));
    let _ = tokio::fs::write(&observe_path, format!("{now}\t{expiry}")).await;

    let timeout = format!("{duration_secs}s");
    if let Some(ip) = ip {
        cmd::nft_add_element(&format!("{iface}_observe_4"), ip, &timeout).await;
    }
    if let Some(ip6) = ip6 {
        cmd::nft_add_element(&format!("{iface}_observe_6"), ip6, &timeout).await;
    }
}

/// `{iface}-observe-{mac_n}` -> `(iface, mac_n)`.
pub fn parse_observe_filename(name: &str) -> Option<(&str, &str)> {
    let idx = name.find("-observe-")?;
    let iface = &name[..idx];
    let mac_n = &name[idx + "-observe-".len()..];
    if iface.is_empty() || mac_n.is_empty() { None } else { Some((iface, mac_n)) }
}

/// The same rule-writing side effects as `routes::device`'s
/// `approve_domain` handler: replace any existing mac+domain rule, wire
/// the domain into the device's dnsmasq `nftset=` line, create route sets
/// and regenerate the inspect chain when a VPN route is chosen.
///
/// Validates `iface`/`domain` itself (rather than trusting the caller)
/// since this is reachable from more than one place that isn't an
/// already-validated HTTP form: `materialize_window` below calls it with
/// a domain sourced from a device's own DNS query log, and
/// `plugins::handle_plugin_line`'s `add_rule` action calls it with an
/// `iface`/`domain` an external plugin supplied directly. Either would
/// otherwise land unescaped in a file path, a dnsmasq conf line, or nft
/// set names.
pub async fn write_domain_rule(base_dir: &Path, split_routing_dir: &Path, iface: &str, mac: &str, domain: &str, route: &str) {
    if !files::is_valid_iface(iface) || !files::is_valid_mac(mac) || !files::is_valid_domain(domain) {
        return;
    }
    let mac_n = mac_no_colons(mac);
    let rules_path = base_dir.join(format!("{iface}-device-rules"));
    let _ = files::file_remove_rule(&rules_path, mac, domain).await;
    let entry = format!("{mac}\t{domain}\tallow\t\t\t{route}");
    let _ = files::file_append(&rules_path, &entry).await;

    let dconf = format!("/etc/dnsmasq.d/{iface}-device-{mac_n}.conf");
    let mut nftset = format!("4#inet#fw4#{iface}_allow_{mac_n}_4,6#inet#fw4#{iface}_allow_{mac_n}_6");
    if !route.is_empty() {
        nftset.push_str(&format!(",4#inet#fw4#{iface}_route_{mac_n}_{route}_4,6#inet#fw4#{iface}_route_{mac_n}_{route}_6"));
    }
    let dentry = format!("nftset=/{domain}/{nftset}");
    let dexisting = tokio::fs::read_to_string(&dconf).await.unwrap_or_default();
    let filtered: String = dexisting
        .lines()
        .filter(|l| !l.starts_with(&format!("nftset=/{domain}/")))
        .flat_map(|l| [l, "\n"])
        .collect();
    let _ = tokio::fs::write(&dconf, format!("{filtered}{dentry}\n")).await;

    if !route.is_empty() {
        cmd::nft_add_set(&format!("{iface}_route_{mac_n}_{route}_4"), "4").await;
        cmd::nft_add_set(&format!("{iface}_route_{mac_n}_{route}_6"), "6").await;
    }
    cmd::reload_dnsmasq().await;
    if !route.is_empty() {
        crate::regen_inspect::run(base_dir, split_routing_dir, iface).await;
        cmd::spawn_macfilter(iface);
    }
}

/// The same rule-writing side effects as `routes::device`'s
/// `approve_pending` handler: append a `mac\tdst\tallow\tport\tproto` rule
/// (if not already present) and add the IP directly to the live nft
/// allow-set.
///
/// Validates `iface`/`dst_ip`/`port` itself for the same reason
/// `write_domain_rule` does — reachable both from `materialize_window`
/// below (values read back from the kernel-logged connection-history/
/// pending files) and from `plugins::handle_plugin_line`'s `add_rule`
/// action (values an external plugin supplied directly), neither of
/// which is a validated HTTP form.
pub async fn write_ip_rule(base_dir: &Path, iface: &str, mac: &str, dst_ip: &str, port: &str, proto: &str) {
    if !files::is_valid_iface(iface)
        || !files::is_valid_mac(mac)
        || dst_ip.parse::<std::net::IpAddr>().is_err()
        || port.is_empty()
        || !port.chars().all(|c| c.is_ascii_digit())
    {
        return;
    }
    let mac_n = mac_no_colons(mac);
    let rules_path = base_dir.join(format!("{iface}-device-rules"));
    let entry = format!("{mac}\t{dst_ip}\tallow\t{port}\t{proto}");
    let existing = tokio::fs::read_to_string(&rules_path).await.unwrap_or_default();
    if !existing.contains(&entry) {
        let _ = files::file_append(&rules_path, &entry).await;
    }
    if dst_ip.contains(':') {
        cmd::nft_add_element(&format!("{iface}_allow_{mac_n}_6"), dst_ip, "").await;
    } else {
        cmd::nft_add_element(&format!("{iface}_allow_{mac_n}_4"), dst_ip, "").await;
    }
}

/// Materializes one closed window: every pending connection recorded for
/// `mac` between `start` and `expiry` becomes a permanent rule — a domain
/// rule when `dns_answers::correlate` finds a match (one rule per distinct
/// domain, even if it covers several observed IPs), an IP rule otherwise.
/// The corresponding pending entries are removed either way, since they're
/// no longer "pending" once a rule covers them.
async fn materialize_window(base_dir: &Path, split_routing_dir: &Path, iface: &str, mac_n: &str, start: u64, expiry: u64, plugins: &PluginManager) {
    let mac = colonize_mac(mac_n);
    let pending_path = base_dir.join(format!("{iface}-pending-{mac_n}"));
    let entries = files::read_pending_conns(&pending_path).await;
    let in_window: Vec<_> = entries.into_iter().filter(|e| e.ts >= start && e.ts <= expiry).collect();

    let mut domains_written: std::collections::HashSet<String> = std::collections::HashSet::new();
    for entry in &in_window {
        let domain = dns_answers::correlate(base_dir, iface, mac_n, &entry.dst, entry.ts).await;
        match domain {
            Some(domain) => {
                if domains_written.insert(domain.clone()) {
                    write_domain_rule(base_dir, split_routing_dir, iface, &mac, &domain, "").await;
                    plugins.broadcast(&Event::DeviceApproved { iface: iface.to_string(), mac: mac.clone(), dst: domain, route: String::new() }).await;
                }
            }
            None => {
                write_ip_rule(base_dir, iface, &mac, &entry.dst, &entry.port, &entry.proto).await;
                plugins.broadcast(&Event::DeviceApproved { iface: iface.to_string(), mac: mac.clone(), dst: entry.dst.clone(), route: String::new() }).await;
            }
        }
        let _ = files::file_remove_pending(&pending_path, &entry.dst, &entry.port, &entry.proto).await;
    }
}

/// Polled by a `daemon.rs` task: scans `base_dir` for every
/// `{iface}-observe-{mac_n}` file, materializes and deletes the ones whose
/// window has closed.
pub async fn materialize_expired(base_dir: &Path, split_routing_dir: &Path, plugins: &PluginManager) {
    let Ok(mut dir) = tokio::fs::read_dir(base_dir).await else { return };
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();

    while let Ok(Some(entry)) = dir.next_entry().await {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        let Some((iface, mac_n)) = parse_observe_filename(&name) else { continue };

        let content = tokio::fs::read_to_string(entry.path()).await.unwrap_or_default();
        let mut fields = content.trim().splitn(2, '\t');
        let (Some(start), Some(expiry)) = (
            fields.next().and_then(|s| s.parse::<u64>().ok()),
            fields.next().and_then(|s| s.parse::<u64>().ok()),
        ) else {
            continue;
        };

        if expiry <= now {
            materialize_window(base_dir, split_routing_dir, iface, mac_n, start, expiry, plugins).await;
            let _ = tokio::fs::remove_file(entry.path()).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn no_plugins() -> PluginManager {
        PluginManager::discover(Path::new("/nonexistent"), std::path::PathBuf::from("/tmp"), std::path::PathBuf::from("/tmp"), Vec::new()).await
    }

    #[test]
    fn colonize_mac_reverses_mac_no_colons() {
        assert_eq!(colonize_mac("aabbccddeeff"), "aa:bb:cc:dd:ee:ff");
        assert_eq!(mac_no_colons(&colonize_mac("aabbccddeeff")), "aabbccddeeff");
    }

    #[test]
    fn parse_observe_filename_splits_iface_and_mac() {
        assert_eq!(parse_observe_filename("guest-observe-aabbccddeeff"), Some(("guest", "aabbccddeeff")));
    }

    #[test]
    fn parse_observe_filename_rejects_unrelated_names() {
        assert_eq!(parse_observe_filename("guest-device-rules"), None);
        assert_eq!(parse_observe_filename(""), None);
    }

    #[tokio::test]
    async fn start_writes_state_file_and_adds_nft_elements() {
        // nft_add_element shells out to the real `nft` binary, which will
        // just fail silently in this sandbox (no `inet fw4` table) — this
        // only exercises the state-file side, matching how other daemon
        // helpers (e.g. handle_new) aren't fully unit-tested either.
        let dir = tempfile::tempdir().unwrap();
        start(dir.path(), "guest", "aa:bb:cc:dd:ee:ff", Some("10.10.0.5"), None, 3600, 1000).await;
        let content = tokio::fs::read_to_string(dir.path().join("guest-observe-aabbccddeeff")).await.unwrap();
        assert_eq!(content, "1000\t4600");
    }

    #[tokio::test]
    async fn materialize_window_prefers_domain_when_correlated() {
        let dir = tempfile::tempdir().unwrap();
        let split_dir = tempfile::tempdir().unwrap();

        // A DNS answer resolving example.com -> 93.184.216.34 at ts=500,
        // and a pending connection to that IP at ts=600 (inside the
        // window), should materialize as a domain rule.
        tokio::fs::write(dir.path().join("guest-dns-answers-aabbccddeeff"), "500\texample.com\t93.184.216.34\n").await.unwrap();
        tokio::fs::write(dir.path().join("guest-pending-aabbccddeeff"), "93.184.216.34\t443\ttcp\t600\n").await.unwrap();

        materialize_window(dir.path(), split_dir.path(), "guest", "aabbccddeeff", 0, 1000, &no_plugins().await).await;

        let rules = tokio::fs::read_to_string(dir.path().join("guest-device-rules")).await.unwrap();
        assert_eq!(rules, "aa:bb:cc:dd:ee:ff\texample.com\tallow\t\t\t\n");

        // The now-covered pending entry should be gone.
        let pending = files::read_pending_conns(&dir.path().join("guest-pending-aabbccddeeff")).await;
        assert!(pending.is_empty());
    }

    #[tokio::test]
    async fn materialize_window_falls_back_to_ip_rule_without_correlation() {
        let dir = tempfile::tempdir().unwrap();
        let split_dir = tempfile::tempdir().unwrap();
        tokio::fs::write(dir.path().join("guest-pending-aabbccddeeff"), "203.0.113.9\t443\ttcp\t600\n").await.unwrap();

        materialize_window(dir.path(), split_dir.path(), "guest", "aabbccddeeff", 0, 1000, &no_plugins().await).await;

        let rules = tokio::fs::read_to_string(dir.path().join("guest-device-rules")).await.unwrap();
        assert_eq!(rules, "aa:bb:cc:dd:ee:ff\t203.0.113.9\tallow\t443\ttcp\n");
    }

    #[tokio::test]
    async fn materialize_window_ignores_entries_outside_the_window() {
        let dir = tempfile::tempdir().unwrap();
        let split_dir = tempfile::tempdir().unwrap();
        tokio::fs::write(dir.path().join("guest-pending-aabbccddeeff"), "203.0.113.9\t443\ttcp\t9999\n").await.unwrap();

        materialize_window(dir.path(), split_dir.path(), "guest", "aabbccddeeff", 0, 1000, &no_plugins().await).await;

        assert!(tokio::fs::read_to_string(dir.path().join("guest-device-rules")).await.is_err());
    }

    #[tokio::test]
    async fn materialize_expired_processes_and_removes_only_expired_windows() {
        let dir = tempfile::tempdir().unwrap();
        let split_dir = tempfile::tempdir().unwrap();
        tokio::fs::write(dir.path().join("guest-pending-aabbccddeeff"), "203.0.113.9\t443\ttcp\t600\n").await.unwrap();
        // Expired window (expiry in the past, but its [start,expiry] range
        // still covers the pending entry's ts=600).
        tokio::fs::write(dir.path().join("guest-observe-aabbccddeeff"), "0\t700").await.unwrap();
        // Not-yet-expired window for a different device
        let far_future = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() + 86400;
        tokio::fs::write(dir.path().join("guest-observe-112233445566"), format!("0\t{far_future}")).await.unwrap();

        materialize_expired(dir.path(), split_dir.path(), &no_plugins().await).await;

        assert!(!dir.path().join("guest-observe-aabbccddeeff").exists());
        assert!(dir.path().join("guest-observe-112233445566").exists());
        let rules = tokio::fs::read_to_string(dir.path().join("guest-device-rules")).await.unwrap();
        assert_eq!(rules, "aa:bb:cc:dd:ee:ff\t203.0.113.9\tallow\t443\ttcp\n");
    }
}
