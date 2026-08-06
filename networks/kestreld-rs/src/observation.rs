//! Time-boxed device "observation" windows: instead of approving or
//! denying each pending connection individually, a device can be put into
//! a mode where every new connection attempt is allowed and recorded for a
//! fixed duration, then turned into permanent rules automatically once the
//! window closes — preferring a domain-based rule over a raw-IP one
//! wherever a DNS answer correlates to the connection's IP (via
//! `data::dns_answers::correlate_ip` over `Store`-backed answers), since a
//! domain rule keeps working if the destination's IP later changes.
//!
//! **Enforcement** is kernel-side and self-expiring: `start` adds the
//! device's IP(s) to a per-network `{iface}_observe_4`/`_6` nftables set
//! (declared and wired into the `{iface}_inspect` chain by
//! `regen_inspect.rs`) with an element `timeout` equal to the window
//! duration — nftables expires the membership itself, so there's no race
//! where a daemon timer has to remember to revoke a temporary allow.
//!
//! **Capture** needs no new code: `daemon.rs`'s `handle_new` already
//! records every new connection attempt to the `pending_connections`
//! table regardless of allow/deny state, so an observed device's
//! connections land there exactly like any other pending connection would.
//!
//! **Materialization** (`materialize_expired`, polled by a `daemon.rs`
//! task) is what actually turns a closed window's pending entries into
//! permanent `DeviceRule`s, queried directly from `Store` rather than a
//! directory scan for `{iface}-observe-{mac}` files. `write_domain_rule`/
//! `write_ip_rule` are the same rule-writing side effects `routes::device`'s
//! `approve_domain`/`approve_pending` HTTP handlers perform — factored out
//! here so both call sites share one implementation instead of two copies
//! that could drift apart. Materialized rules always use the WAN route (no
//! VPN tier) since observation never asked the user to choose one; a VPN
//! route can still be added afterward by re-approving the same domain from
//! the device page.

use std::path::Path;

use crate::cmd;
use crate::data::{dns_answers, files};
use crate::db::Store;
use crate::plugins::{Event, PluginManager};

fn mac_no_colons(mac: &str) -> String {
    mac.replace(':', "")
}

/// Starts an observation window for `mac` on `iface`: records the window's
/// start/expiry and adds the device's current IP(s) to the observe set
/// with a matching nft `timeout`. No `regen_inspect::run` call is needed
/// here — the `{iface}_observe_4`/`_6` sets and the chain rule that
/// accepts their members are declared unconditionally for any network
/// with at least one labeled device (see `regen_inspect.rs`), which must
/// already be true for `mac` to have reached the device page at all.
pub async fn start(
    store: &Store,
    iface: &str,
    mac: &str,
    ip: Option<&str>,
    ip6: Option<&str>,
    duration_secs: u64,
    now: u64,
) {
    let expiry = now + duration_secs;
    let _ = store
        .start_observation_window(iface, mac, now as i64, expiry as i64)
        .await;

    let timeout = format!("{duration_secs}s");
    if let Some(ip) = ip {
        cmd::nft_add_element(&format!("{iface}_observe_4"), ip, &timeout).await;
    }
    if let Some(ip6) = ip6 {
        cmd::nft_add_element(&format!("{iface}_observe_6"), ip6, &timeout).await;
    }
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
pub async fn write_domain_rule(
    store: &Store,
    base_dir: &Path,
    split_routing_dir: &Path,
    iface: &str,
    mac: &str,
    domain: &str,
    route: &str,
) {
    if !files::is_valid_iface(iface) || !files::is_valid_mac(mac) || !files::is_valid_domain(domain)
    {
        return;
    }
    let mac_n = mac_no_colons(mac);
    let _ = store.upsert_domain_rule(iface, mac, domain, route).await;

    let dconf = format!("/etc/dnsmasq.d/{iface}-device-{mac_n}.conf");
    let mut nftset =
        format!("4#inet#fw4#{iface}_allow_{mac_n}_4,6#inet#fw4#{iface}_allow_{mac_n}_6");
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
        crate::regen_inspect::run(base_dir, split_routing_dir, store, iface).await;
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
pub async fn write_ip_rule(
    store: &Store,
    iface: &str,
    mac: &str,
    dst_ip: &str,
    port: &str,
    proto: &str,
) {
    if !files::is_valid_iface(iface)
        || !files::is_valid_mac(mac)
        || dst_ip.parse::<std::net::IpAddr>().is_err()
        || port.is_empty()
        || !port.chars().all(|c| c.is_ascii_digit())
    {
        return;
    }
    let mac_n = mac_no_colons(mac);
    let _ = store.upsert_ip_rule(iface, mac, dst_ip, port, proto).await;
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
async fn materialize_window(
    store: &Store,
    base_dir: &Path,
    split_routing_dir: &Path,
    iface: &str,
    mac: &str,
    start: u64,
    expiry: u64,
    plugins: &PluginManager,
) {
    let entries = store
        .list_pending_connections(iface, mac)
        .await
        .unwrap_or_default();
    let in_window: Vec<_> = entries
        .into_iter()
        .filter(|e| e.ts >= start as i64 && e.ts <= expiry as i64)
        .collect();

    let dns_entries: Vec<dns_answers::DnsAnswer> = store
        .list_dns_answers(iface, mac)
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|a| dns_answers::DnsAnswer {
            ts: a.ts as u64,
            domain: a.domain,
            ip: a.ip,
        })
        .collect();

    let mut domains_written: std::collections::HashSet<String> = std::collections::HashSet::new();
    for entry in &in_window {
        let domain = dns_answers::correlate_ip(&dns_entries, &entry.dst, entry.ts as u64);
        match domain {
            Some(domain) => {
                if domains_written.insert(domain.clone()) {
                    write_domain_rule(store, base_dir, split_routing_dir, iface, mac, &domain, "")
                        .await;
                    plugins
                        .broadcast(&Event::DeviceApproved {
                            iface: iface.to_string(),
                            mac: mac.to_string(),
                            dst: domain,
                            route: String::new(),
                        })
                        .await;
                }
            }
            None => {
                write_ip_rule(store, iface, mac, &entry.dst, &entry.port, &entry.proto).await;
                plugins
                    .broadcast(&Event::DeviceApproved {
                        iface: iface.to_string(),
                        mac: mac.to_string(),
                        dst: entry.dst.clone(),
                        route: String::new(),
                    })
                    .await;
            }
        }
        let _ = store
            .remove_pending_connection(iface, mac, &entry.dst, &entry.port, &entry.proto)
            .await;
    }
}

/// Polled by a `daemon.rs` task: queries `Store` for every observation
/// window whose expiry has passed, materializes and removes them.
pub async fn materialize_expired(
    base_dir: &Path,
    split_routing_dir: &Path,
    store: &Store,
    plugins: &PluginManager,
) {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let expired = store
        .expired_observation_windows(now as i64)
        .await
        .unwrap_or_default();

    for (iface, mac, window) in expired {
        materialize_window(
            store,
            base_dir,
            split_routing_dir,
            &iface,
            &mac,
            window.started_at as u64,
            window.expires_at as u64,
            plugins,
        )
        .await;
        let _ = store.remove_observation_window(&iface, &mac).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn no_plugins() -> PluginManager {
        PluginManager::discover(
            Path::new("/nonexistent"),
            std::path::PathBuf::from("/tmp"),
            std::path::PathBuf::from("/tmp"),
            std::sync::Arc::new(crate::db::Store::open_in_memory().unwrap()),
            Vec::new(),
        )
        .await
    }

    #[tokio::test]
    async fn start_persists_the_window_via_store() {
        // nft_add_element shells out to the real `nft` binary, which will
        // just fail silently in this sandbox (no `inet fw4` table) — this
        // only exercises the Store side, matching how other daemon
        // helpers (e.g. handle_new) aren't fully unit-tested either.
        let store = Store::open_in_memory().unwrap();
        start(
            &store,
            "guest",
            "aa:bb:cc:dd:ee:ff",
            Some("10.10.0.5"),
            None,
            3600,
            1000,
        )
        .await;
        let expired = store.expired_observation_windows(4600).await.unwrap();
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0].0, "guest");
        assert_eq!(expired[0].1, "aa:bb:cc:dd:ee:ff");
        assert_eq!(expired[0].2.started_at, 1000);
        assert_eq!(expired[0].2.expires_at, 4600);
    }

    #[tokio::test]
    async fn materialize_window_prefers_domain_when_correlated() {
        let dir = tempfile::tempdir().unwrap();
        let split_dir = tempfile::tempdir().unwrap();
        let store = Store::open_in_memory().unwrap();

        // A DNS answer resolving example.com -> 93.184.216.34 at ts=500,
        // and a pending connection to that IP at ts=600 (inside the
        // window), should materialize as a domain rule.
        store
            .add_dns_answer(
                "guest",
                "aa:bb:cc:dd:ee:ff",
                500,
                "example.com",
                "93.184.216.34",
            )
            .await
            .unwrap();
        store
            .add_pending_connection(
                "guest",
                "aa:bb:cc:dd:ee:ff",
                "93.184.216.34",
                "443",
                "tcp",
                600,
            )
            .await
            .unwrap();

        materialize_window(
            &store,
            dir.path(),
            split_dir.path(),
            "guest",
            "aa:bb:cc:dd:ee:ff",
            0,
            1000,
            &no_plugins().await,
        )
        .await;

        let rules = store.list_device_rules("guest").await.unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].dst, "example.com");
        assert_eq!(rules[0].action, "allow");

        // The now-covered pending entry should be gone.
        let pending = store
            .list_pending_connections("guest", "aa:bb:cc:dd:ee:ff")
            .await
            .unwrap();
        assert!(pending.is_empty());
    }

    #[tokio::test]
    async fn materialize_window_falls_back_to_ip_rule_without_correlation() {
        let dir = tempfile::tempdir().unwrap();
        let split_dir = tempfile::tempdir().unwrap();
        let store = Store::open_in_memory().unwrap();
        store
            .add_pending_connection(
                "guest",
                "aa:bb:cc:dd:ee:ff",
                "203.0.113.9",
                "443",
                "tcp",
                600,
            )
            .await
            .unwrap();

        materialize_window(
            &store,
            dir.path(),
            split_dir.path(),
            "guest",
            "aa:bb:cc:dd:ee:ff",
            0,
            1000,
            &no_plugins().await,
        )
        .await;

        let rules = store.list_device_rules("guest").await.unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].dst, "203.0.113.9");
        assert_eq!(rules[0].port, "443");
    }

    #[tokio::test]
    async fn materialize_window_ignores_entries_outside_the_window() {
        let dir = tempfile::tempdir().unwrap();
        let split_dir = tempfile::tempdir().unwrap();
        let store = Store::open_in_memory().unwrap();
        store
            .add_pending_connection(
                "guest",
                "aa:bb:cc:dd:ee:ff",
                "203.0.113.9",
                "443",
                "tcp",
                9999,
            )
            .await
            .unwrap();

        materialize_window(
            &store,
            dir.path(),
            split_dir.path(),
            "guest",
            "aa:bb:cc:dd:ee:ff",
            0,
            1000,
            &no_plugins().await,
        )
        .await;

        assert!(store.list_device_rules("guest").await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn materialize_expired_processes_and_removes_only_expired_windows() {
        let dir = tempfile::tempdir().unwrap();
        let split_dir = tempfile::tempdir().unwrap();
        let store = Store::open_in_memory().unwrap();
        store
            .add_pending_connection(
                "guest",
                "aa:bb:cc:dd:ee:ff",
                "203.0.113.9",
                "443",
                "tcp",
                600,
            )
            .await
            .unwrap();
        // Expired window (expiry in the past, but its [start,expiry] range
        // still covers the pending entry's ts=600).
        store
            .start_observation_window("guest", "aa:bb:cc:dd:ee:ff", 0, 700)
            .await
            .unwrap();
        // Not-yet-expired window for a different device
        let far_future = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
            + 86400;
        store
            .start_observation_window("guest", "11:22:33:44:55:66", 0, far_future)
            .await
            .unwrap();

        materialize_expired(dir.path(), split_dir.path(), &store, &no_plugins().await).await;

        assert!(store
            .expired_observation_windows(700)
            .await
            .unwrap()
            .iter()
            .all(|(_, mac, _)| mac != "aa:bb:cc:dd:ee:ff"));
        assert!(store
            .expired_observation_windows(far_future)
            .await
            .unwrap()
            .iter()
            .any(|(_, mac, _)| mac == "11:22:33:44:55:66"));
        let rules = store.list_device_rules("guest").await.unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].dst, "203.0.113.9");
    }
}
