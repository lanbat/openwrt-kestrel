//! The persistent kestreld daemon: `kestreld --daemon`, `procd`-supervised
//! with `respawn` (see the init.d service `install.sh` sets up). Runs
//! six concurrent tasks for the lifetime of the process:
//!
//! - Streams `logread -f` and dispatches `EXTNET-2LAN`/`EXTNET-DENY`/
//!   `EXTNET-{iface}-NEW` lines as they're logged, instead of a cron job
//!   re-scanning a bounded log buffer every minute. That distinction
//!   matters for more than latency: `logd`'s buffer is bounded, and a
//!   burst of events between two cron runs can evict older lines before
//!   the next scan ever sees them — a genuine silent-miss window, not
//!   just a delay. A streaming reader has no equivalent gap: it sees
//!   every line as it's written.
//! - Also captures `EXTNET-{iface}-NEW:` (device-control blocked new
//!   connections) into each device's pending-connections file —
//!   previously this only ever happened inline, in the original shell
//!   CGI's `device.cgi`, scraping `logread` on every device-page view.
//!   The Rust port never carried that over at all until now; nothing
//!   populated `{iface}-pending-{mac}` before this daemon existed.
//! - Runs `check_wan`/`check_vpn` on a short interval (20s) instead of
//!   their old 5-minute cron entries, for meaningfully faster detection
//!   of WAN/VPN state changes.
//! - Runs `bandwidth_check` on its original hourly interval — folded in
//!   for one less cron-spawned process, not for faster detection; there
//!   was no equivalent urgency argument for this one.
//! - Also pairs dnsmasq's `query[...]`/`reply ... is <ip>` log line pairs
//!   (matched by dnsmasq's own per-line transaction id) and persists
//!   resolved answers to `{iface}-dns-answers-{mac_n}` — see
//!   `data::dns_answers`. This is what lets a later IP-only connection
//!   attempt be attributed back to the domain that resolved to it.
//! - Polls for closed device-observation windows (`observation.rs`) and
//!   materializes their captured connections into permanent rules.
//! - At startup, discovers and spawns any executable in
//!   `/etc/kestrel/plugins/` (see `plugins.rs`) and broadcasts every
//!   `plugins::Event` to them (and to any compiled-in `RustPlugin`s) as
//!   they happen; re-scans that directory every 5 minutes so a newly
//!   dropped-in or re-enabled plugin doesn't need a daemon restart.
//!
//! All six tasks run concurrently in one multi-threaded tokio runtime
//! (see `main.rs`) since, unlike CGI mode's fresh-process-per-request
//! `current_thread` runtime, this genuinely is the long-running,
//! concurrent-work case that justifies worker threads. Every task loops
//! forever by construction (the log-follow loop restarts `logread -f`
//! itself if it ever exits); if any of the six still ends — a panic, most
//! likely — that's treated as fatal for the whole process, so `procd`'s
//! `respawn` brings it back rather than silently continuing with one
//! monitor dark.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;

use crate::data::{dhcp, dns_answers, files, logs};
use crate::db::Store;
use crate::packet_observer;
use crate::plugins::{DeviceApprovedNotifier, Event, PluginManager, RustPlugin};
use crate::{bandwidth_check, check_access_log, check_vpn, check_wan, observation};

const WAN_VPN_INTERVAL: Duration = Duration::from_secs(20);
const BANDWIDTH_INTERVAL: Duration = Duration::from_secs(3600);
const OBSERVE_INTERVAL: Duration = Duration::from_secs(60);
const PLUGIN_RESCAN_INTERVAL: Duration = Duration::from_secs(300);
const LOGREAD_RESTART_DELAY: Duration = Duration::from_secs(5);
const PLUGINS_DIR: &str = "/etc/kestrel/plugins";
/// How long an outstanding DNS query waits for its matching `reply` line
/// before being evicted from the in-memory pairing table. dnsmasq logs the
/// reply within milliseconds in practice; a query that never gets one
/// (upstream timeout) shouldn't accumulate in memory forever.
const DNS_PAIR_TIMEOUT: Duration = Duration::from_secs(10);

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub async fn run(base_dir: PathBuf, split_routing_dir: PathBuf) -> i32 {
    // First-party, compiled-in plugins ship here — external, dropped-in
    // scripts under PLUGINS_DIR are discovered separately by `discover`
    // below. See `plugins.rs`'s module doc for why these are two
    // different mechanisms.
    let rust_plugins: Vec<Arc<dyn RustPlugin>> = vec![Arc::new(DeviceApprovedNotifier)];
    // Shared across every task below (and given to PluginManager for its
    // own PluginContexts) — Store's own internal mutex already serializes
    // access, so one connection per process (not per task) is both
    // correct and lighter on SQLite's WAL/locking than N.
    let store = Arc::new(Store::open(&base_dir).await.unwrap_or_else(|e| {
        panic!(
            "daemon: failed to open {}: {e}",
            base_dir.join("kestrel.sqlite").display()
        )
    }));
    let plugins = Arc::new(
        PluginManager::discover(
            Path::new(PLUGINS_DIR),
            base_dir.clone(),
            split_routing_dir.clone(),
            store.clone(),
            rust_plugins,
        )
        .await,
    );

    let log_task = {
        let base_dir = base_dir.clone();
        let plugins = plugins.clone();
        let store = store.clone();
        tokio::spawn(async move { follow_log(&base_dir, &plugins, &store).await })
    };
    let wan_task = {
        let base_dir = base_dir.clone();
        let plugins = plugins.clone();
        let store = store.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(WAN_VPN_INTERVAL);
            loop {
                interval.tick().await;
                if let (_, Some(up)) = check_wan::run_and_report(&base_dir, &store).await {
                    plugins
                        .broadcast(&Event::WanStateChanged {
                            iface: "wan".to_string(),
                            up,
                        })
                        .await;
                }
            }
        })
    };
    let vpn_task = {
        let base_dir = base_dir.clone();
        let split_routing_dir = split_routing_dir.clone();
        let plugins = plugins.clone();
        let store = store.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(WAN_VPN_INTERVAL);
            loop {
                interval.tick().await;
                let (_, changed) =
                    check_vpn::run_and_report(&base_dir, &split_routing_dir, &store).await;
                for (tier, up) in changed {
                    plugins
                        .broadcast(&Event::VpnStateChanged { tier, up })
                        .await;
                }
            }
        })
    };
    let bw_task = {
        let base_dir = base_dir.clone();
        let plugins = plugins.clone();
        let store = store.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(BANDWIDTH_INTERVAL);
            loop {
                interval.tick().await;
                let (_, crossed) = bandwidth_check::run_and_report(&base_dir, &store).await;
                for (mac, bytes) in crossed {
                    plugins
                        .broadcast(&Event::BandwidthThresholdCrossed { mac, bytes })
                        .await;
                }
            }
        })
    };
    let observe_task = {
        let base_dir = base_dir.clone();
        let split_routing_dir = split_routing_dir.clone();
        let plugins = plugins.clone();
        let store = store.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(OBSERVE_INTERVAL);
            loop {
                interval.tick().await;
                observation::materialize_expired(&base_dir, &split_routing_dir, &store, &plugins)
                    .await;
            }
        })
    };
    let plugin_rescan_task = {
        let plugins = plugins.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(PLUGIN_RESCAN_INTERVAL);
            loop {
                interval.tick().await;
                plugins.rescan().await;
            }
        })
    };
    let packet_task = {
        let base_dir = base_dir.clone();
        let store = store.clone();
        tokio::spawn(async move { packet_observer::run_if_enabled(&base_dir, store).await })
    };

    // All six loop forever by construction and should never resolve;
    // whichever one does first (only possible via a panic) ends the
    // process so procd restarts the whole daemon.
    tokio::select! {
        result = log_task => eprintln!("log-follow task ended unexpectedly: {result:?}"),
        result = wan_task => eprintln!("WAN-check task ended unexpectedly: {result:?}"),
        result = vpn_task => eprintln!("VPN-check task ended unexpectedly: {result:?}"),
        result = bw_task  => eprintln!("bandwidth-check task ended unexpectedly: {result:?}"),
        result = observe_task => eprintln!("observation-materialize task ended unexpectedly: {result:?}"),
        result = plugin_rescan_task => eprintln!("plugin-rescan task ended unexpectedly: {result:?}"),
        result = packet_task => eprintln!("packet observer ended unexpectedly: {result:?}"),
    }
    1
}

async fn follow_log(base_dir: &Path, plugins: &PluginManager, store: &Store) {
    loop {
        let mut child = match Command::new("logread")
            .arg("-f")
            .stdout(std::process::Stdio::piped())
            .spawn()
        {
            Ok(c) => c,
            Err(e) => {
                eprintln!("failed to spawn `logread -f`: {e}");
                tokio::time::sleep(LOGREAD_RESTART_DELAY).await;
                continue;
            }
        };
        let Some(stdout) = child.stdout.take() else {
            tokio::time::sleep(LOGREAD_RESTART_DELAY).await;
            continue;
        };
        let mut lines = BufReader::new(stdout).lines();
        // dnsmasq id -> (src, domain, query_ts), awaiting the matching
        // `reply` line. Reset on every `logread -f` restart, which is fine —
        // ids are only ever compared within one dnsmasq log session anyway.
        let mut pending_dns: HashMap<String, (String, String, u64)> = HashMap::new();

        loop {
            match lines.next_line().await {
                Ok(Some(line)) => {
                    if line.contains("EXTNET-DENY") {
                        check_access_log::handle_deny(&line, base_dir, store).await;
                    } else if line.contains("EXTNET-2LAN") {
                        check_access_log::handle_2lan(&line, base_dir, store).await;
                    } else if line.contains("-NEW:") {
                        handle_new(&line, plugins, store).await;
                    } else if let Some((id, src, domain, qtype)) = logs::parse_dns_query_line(&line)
                    {
                        let now = now_secs();
                        pending_dns.retain(|_, (_, _, ts)| {
                            now.saturating_sub(*ts) < DNS_PAIR_TIMEOUT.as_secs()
                        });
                        pending_dns
                            .insert(id.to_string(), (src.to_string(), domain.to_string(), now));
                        if let Some(mac) = resolve_mac(src).await {
                            plugins
                                .broadcast(&Event::DnsQuery {
                                    mac,
                                    domain: domain.to_string(),
                                    qtype: qtype.to_string(),
                                })
                                .await;
                        }
                    } else if let Some((id, ip)) = logs::parse_dns_reply_line(&line) {
                        if let Some((src, domain, _)) = pending_dns.remove(id) {
                            handle_dns_answer(base_dir, &src, &domain, ip, plugins, store).await;
                        }
                    }
                }
                Ok(None) => break, // logread -f's stdout closed: it exited
                Err(e) => {
                    eprintln!("error reading `logread -f` output: {e}");
                    break;
                }
            }
        }

        eprintln!("`logread -f` exited; restarting it in {LOGREAD_RESTART_DELAY:?}");
        let _ = child.kill().await;
        tokio::time::sleep(LOGREAD_RESTART_DELAY).await;
    }
}

/// Extracts the iface from `...EXTNET-{iface}-NEW:...`. Unlike the
/// DENY/2LAN markers (fixed keywords, with the iface following), the
/// iface here is embedded *between* two fixed anchors.
fn extract_iface_new(line: &str) -> Option<&str> {
    let after_extnet = line.split("EXTNET-").nth(1)?;
    let end = after_extnet.find("-NEW:")?;
    let iface = &after_extnet[..end];
    if iface.is_empty() {
        None
    } else {
        Some(iface)
    }
}

/// Resolves a source IP to its MAC via a fresh DHCP lease lookup — the
/// same lookup `handle_new`/`handle_dns_answer` each already do, factored
/// out since firing a `DnsQuery` event needs it too.
async fn resolve_mac(src: &str) -> Option<String> {
    let leases = dhcp::fetch().await;
    leases.iter().find(|l| l.ip == src).map(|l| l.mac.clone())
}

/// Populates a device's pending-connections file for a newly seen
/// blocked connection attempt, and records it in the same persistent
/// history `check_access_log`'s DENY/2LAN handlers write to.
async fn handle_new(line: &str, plugins: &PluginManager, store: &Store) {
    let Some(iface) = extract_iface_new(line) else {
        return;
    };
    let Some(fields) = crate::data::logs::parse_nf_fields(line) else {
        return;
    };
    let (src, dst, proto, port) = (
        fields.src,
        fields.dst,
        fields.proto.to_lowercase(),
        fields.dpt,
    );
    if src.is_empty() || dst.is_empty() || proto.is_empty() || port.is_empty() {
        return;
    }

    let leases = dhcp::fetch().await;
    let Some(mac) = leases.iter().find(|l| l.ip == src).map(|l| l.mac.clone()) else {
        return;
    };

    plugins
        .broadcast(&Event::NewConnection {
            mac: mac.clone(),
            dst: dst.to_string(),
            port: port.to_string(),
            proto: proto.clone(),
        })
        .await;

    // Skip if an explicit allow/deny rule already covers this
    // destination for this device — it's not "pending" anymore, it's
    // already decided (matches the original shell CGI's same check
    // against its rules file before appending to pending).
    let rules = store.list_device_rules(iface).await.unwrap_or_default();
    if rules.iter().any(|r| r.mac == mac && r.dst == dst) {
        return;
    }

    let existing = store
        .list_pending_connections(iface, &mac)
        .await
        .unwrap_or_default();
    if existing
        .iter()
        .any(|p| p.dst == dst && p.port == port && p.proto == proto)
    {
        return;
    }

    let now = now_secs();
    let _ = store
        .add_pending_connection(iface, &mac, dst, &port, &proto, now as i64)
        .await;

    check_access_log::append_history(store, iface, "new", src, dst, &port, &proto).await;
}

/// Persists a resolved DNS answer (`domain` -> `ip`) for the device at
/// `src`, so a later IP-only connection to `ip` can be attributed back to
/// `domain` — see `data::dns_answers::correlate`.
async fn handle_dns_answer(
    base_dir: &Path,
    src: &str,
    domain: &str,
    ip: &str,
    plugins: &PluginManager,
    store: &Store,
) {
    let leases = dhcp::fetch().await;
    let Some(mac) = leases.iter().find(|l| l.ip == src).map(|l| l.mac.clone()) else {
        return;
    };

    let confs = files::read_all_network_confs(base_dir).await;
    let Some(iface) = files::iface_for_ip(&confs, src) else {
        return;
    };

    let now = now_secs();
    let _ = store
        .add_dns_answer(&iface, &mac, now as i64, domain, ip)
        .await;
    let _ = store
        .prune_dns_answers(
            &iface,
            &mac,
            now.saturating_sub(dns_answers::RETENTION_SECS) as i64,
        )
        .await;

    plugins
        .broadcast(&Event::DnsAnswer {
            mac,
            domain: domain.to_string(),
            ip: ip.to_string(),
        })
        .await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_iface_new_finds_iface_between_anchors() {
        let line = "... kernel: EXTNET-untrusted-NEW: IN=br-untrusted MAC=... SRC=192.168.4.50 DST=1.2.3.4 PROTO=TCP DPT=443";
        assert_eq!(extract_iface_new(line), Some("untrusted"));
    }

    #[test]
    fn extract_iface_new_missing_marker_returns_none() {
        assert_eq!(extract_iface_new("some unrelated line"), None);
    }

    #[test]
    fn extract_iface_new_does_not_confuse_with_deny_or_2lan_markers() {
        assert_eq!(extract_iface_new("EXTNET-DENY-guest: SRC=10.0.0.1"), None);
        assert_eq!(extract_iface_new("EXTNET-2LAN-guest SRC=10.0.0.1"), None);
    }
}
