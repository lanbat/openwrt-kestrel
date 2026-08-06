use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

use crate::data::{
    banip, dhcp, dns, files, ipsec_peers, iw, logs, neigh, nft, openvpn, system, vpn, wg,
};
use crate::db::{DeviceRule as DbDeviceRule, JoinHistoryRow, Store};

pub struct Snapshot {
    pub at: Instant,
    pub system: system::SystemInfo,
    pub iw: iw::IwState,
    pub vpn_tiers: Vec<vpn::VpnTier>,
    pub wg_servers: Vec<wg::WgServer>,
    /// Inbound OpenVPN server peer visibility — empty when no named
    /// `config openvpn` UCI section is configured. See `data::openvpn`.
    pub openvpn_servers: Vec<openvpn::OpenVpnServer>,
    /// Inbound IPsec (strongSwan) peer visibility — empty when `ipsec` is
    /// absent or no SA is established. See `data::ipsec_peers`.
    pub ipsec_peers: Vec<ipsec_peers::IpsecPeer>,
    pub nft: nft::NftState,
    /// banIP threat-feed membership (spamhaus, feodo, dshield, ...), parsed
    /// out of the same `nft.raw` dump above — no extra process spawned.
    pub banip: banip::BanipFeeds,
    pub leases: Vec<dhcp::Lease>,
    pub neigh: neigh::NeighTable,
    pub logs: logs::LogData,
    pub net_confs: Vec<files::NetworkConf>,
    pub dns_cache: dns::DnsCache,
    /// iface → (mac → label)
    pub labels: HashMap<String, HashMap<String, String>>,
    /// iface → [approved mac]
    pub join_approved: HashMap<String, Vec<String>>,
    /// iface → mac → pending_ip
    pub join_pending: HashMap<String, HashMap<String, String>>,
    /// iface → [denied mac]
    pub join_denied: HashMap<String, Vec<String>>,
    /// iface → join history rows (last 20, newest first)
    pub join_history: HashMap<String, Vec<Vec<String>>>,
    /// iface → (ssid, key, enc_type)
    pub wifi_keys: HashMap<String, (String, String, String)>,
    /// raw `uci show firewall` for rule/redirect parsing
    pub uci_firewall: String,
    /// raw `crontab -l` output
    pub crontab: String,
    /// iface → (wlan_iface, down_bytes, up_bytes)
    pub net_traffic: HashMap<String, (String, u64, u64)>,
    /// iface → (ip → bytes)
    pub dev_bytes4: HashMap<String, HashMap<String, u64>>,
    pub dev_bytes6: HashMap<String, HashMap<String, u64>>,
    /// mac (lowercase) → joined-timestamp string from /tmp/kestrel-joins
    pub joins: HashMap<String, String>,
    /// iface → global IPv6 prefixes on br-{iface} (e.g. "fd00::/64")
    pub ipv6_prefixes: HashMap<String, Vec<String>>,
    /// iface → whether br-{iface} has the UP flag
    pub iface_up: HashMap<String, bool>,
    /// iface → (mac → tracked IPv4) from device-ips
    pub device_ips: HashMap<String, HashMap<String, String>>,
    /// iface → (mac → tracked IPv6) from device-ip6s
    pub device_ip6s: HashMap<String, HashMap<String, String>>,
    /// iface → (mac → rate limit) from device-limits
    pub device_limits: HashMap<String, HashMap<String, u32>>,
    /// iface → rules list from device-rules
    pub device_rules: HashMap<String, Vec<files::DeviceRule>>,
    /// iface → (mac → ip) from join-approved-ips
    pub join_approved_ips: HashMap<String, HashMap<String, String>>,
    /// iface → allowlist entries from allowed-macs
    pub allowed_macs: HashMap<String, Vec<files::AllowedMac>>,
    /// local DNS domain suffix (e.g. "lan") from dnsmasq config
    pub local_domain: String,
}

pub struct AppState {
    pub snapshot: RwLock<Arc<Snapshot>>,
    pub base_dir: PathBuf,
    pub split_routing_dir: PathBuf,
    pub oui: HashMap<String, String>,
    /// SQLite-backed replacement for `data::files`'s flat-file reads —
    /// see `db`'s module doc. Opening this here is a hard dependency: if
    /// `kestrel.sqlite` can't be opened (disk full, permissions), the
    /// whole process fails fast rather than silently degrading to empty
    /// data, the same tradeoff `main.rs` already makes for a failed TCP
    /// bind. Note this does NOT run the flat-file migration itself —
    /// that only ever happens via the explicit `kestreld --migrate-storage`
    /// subcommand, invoked once by `install.sh` during upgrade (see
    /// `migrate`'s module doc for why an in-process auto-trigger here
    /// would be unsafe before every read call site is Store-backed).
    pub store: Store,
}

impl AppState {
    async fn build(base_dir: PathBuf, split_routing_dir: PathBuf) -> Arc<Self> {
        let store = Store::open(&base_dir).await.unwrap_or_else(|e| {
            panic!(
                "failed to open {}: {e}",
                base_dir.join("kestrel.sqlite").display()
            )
        });
        let snap = build_snapshot(&base_dir, &split_routing_dir, &store).await;
        let oui = store.all_oui().await.unwrap_or_default();
        Arc::new(Self {
            snapshot: RwLock::new(Arc::new(snap)),
            base_dir,
            split_routing_dir,
            oui,
            store,
        })
    }

    /// For the long-running standalone server: refreshes the snapshot every
    /// 5 seconds in the background so concurrent requests share one build.
    pub async fn new(base_dir: PathBuf, split_routing_dir: PathBuf) -> Arc<Self> {
        let state = Self::build(base_dir, split_routing_dir).await;
        let state2 = Arc::clone(&state);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(5)).await;
                let snap =
                    build_snapshot(&state2.base_dir, &state2.split_routing_dir, &state2.store)
                        .await;
                *state2.snapshot.write().await = Arc::new(snap);
            }
        });
        state
    }

    /// For CGI mode: a fresh process handles exactly one request and then
    /// exits, so there's no point spawning a background refresh loop that
    /// will never get to run.
    pub async fn new_once(base_dir: PathBuf, split_routing_dir: PathBuf) -> Arc<Self> {
        Self::build(base_dir, split_routing_dir).await
    }

    pub async fn snap(&self) -> Arc<Snapshot> {
        Arc::clone(&*self.snapshot.read().await)
    }
}

pub async fn build_snapshot(base_dir: &Path, split_routing_dir: &Path, store: &Store) -> Snapshot {
    let now_ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let (sys, iw_state, leases, neigh_table, log_data, nft_state, net_confs) = tokio::join!(
        system::fetch(),
        iw::fetch(),
        dhcp::fetch(),
        neigh::fetch(),
        logs::fetch(),
        nft::fetch(),
        files::read_all_network_confs(base_dir),
    );

    let (vpn_tiers, wg_servers, openvpn_servers, ipsec_peers_list) = tokio::join!(
        vpn::fetch_tiers(split_routing_dir),
        wg::fetch_servers(now_ts),
        openvpn::fetch_servers(),
        ipsec_peers::fetch_peers(),
    );

    // Parallel: reverse-DNS all leased IPs
    let all_ips: Vec<String> = leases.iter().map(|l| l.ip.clone()).collect();
    let dns_cache = dns::resolve_all(&all_ips, "127.0.0.1").await;

    // Per-network: labels, join state, wifi keys, traffic counters, device bytes
    let mut labels: HashMap<String, HashMap<String, String>> = HashMap::new();
    let mut join_approved: HashMap<String, Vec<String>> = HashMap::new();
    let mut join_pending: HashMap<String, HashMap<String, String>> = HashMap::new();
    let mut join_denied: HashMap<String, Vec<String>> = HashMap::new();
    let mut join_history: HashMap<String, Vec<Vec<String>>> = HashMap::new();
    let mut wifi_keys: HashMap<String, (String, String, String)> = HashMap::new();
    let mut net_traffic: HashMap<String, (String, u64, u64)> = HashMap::new();
    let mut dev_bytes4: HashMap<String, HashMap<String, u64>> = HashMap::new();
    let mut dev_bytes6: HashMap<String, HashMap<String, u64>> = HashMap::new();
    let mut device_ips: HashMap<String, HashMap<String, String>> = HashMap::new();
    let mut device_ip6s: HashMap<String, HashMap<String, String>> = HashMap::new();
    let mut device_limits: HashMap<String, HashMap<String, u32>> = HashMap::new();
    let mut device_rules: HashMap<String, Vec<files::DeviceRule>> = HashMap::new();
    let mut join_approved_ips: HashMap<String, HashMap<String, String>> = HashMap::new();
    let mut allowed_macs: HashMap<String, Vec<files::AllowedMac>> = HashMap::new();

    for conf in &net_confs {
        let iface = &conf.iface;

        labels.insert(
            iface.clone(),
            store.all_labels(iface).await.unwrap_or_default(),
        );

        if conf.join_approval {
            let approved = store.join_approved_list(iface).await.unwrap_or_default();
            let denied = store.join_denied_list(iface).await.unwrap_or_default();
            let pending_raw = store.join_pending_map(iface).await.unwrap_or_default();

            join_approved.insert(iface.clone(), approved);
            join_denied.insert(iface.clone(), denied);
            join_pending.insert(iface.clone(), pending_raw);

            // Already newest-first, capped at 20 by the query itself —
            // see `Store::recent_join_history` — unlike the old flat-file
            // read this replaces, which had to reverse+truncate a
            // whole-file read by hand.
            let hist = store
                .recent_join_history(iface, 20)
                .await
                .unwrap_or_default();
            join_history.insert(
                iface.clone(),
                hist.into_iter().map(join_history_row_to_columns).collect(),
            );
        }

        // WiFi key + SSID via uci
        let ssid = uci_get_one(iface, "ssid").await;
        let key = uci_get_one(iface, "key").await;
        let enc = uci_get_one(iface, "encryption").await;
        if !ssid.is_empty() {
            wifi_keys.insert(iface.clone(), (ssid, key, enc));
        }

        // WiFi interface on the bridge
        let wlan = wlan_iface_for(iface).await;

        // Counter chain bytes (iifname = rx = ↓ download, oifname = tx = ↑ upload)
        let chain = format!("{iface}_counter");
        let down = nft_state.chain_bytes(&chain, "in");
        let up = nft_state.chain_bytes(&chain, "out");
        net_traffic.insert(iface.clone(), (wlan, down, up));

        // Per-device byte counters
        dev_bytes4.insert(
            iface.clone(),
            nft_state.device_bytes(&format!("{iface}_device_bytes")),
        );
        dev_bytes6.insert(
            iface.clone(),
            nft_state.device_bytes(&format!("{iface}_device_bytes6")),
        );

        // Device control state
        if conf.device_control {
            device_ips.insert(
                iface.clone(),
                store.all_device_ips(iface).await.unwrap_or_default(),
            );
            device_ip6s.insert(
                iface.clone(),
                store.all_device_ip6s(iface).await.unwrap_or_default(),
            );
            device_limits.insert(
                iface.clone(),
                store.all_device_limits(iface).await.unwrap_or_default(),
            );
            let rules = store.list_device_rules(iface).await.unwrap_or_default();
            device_rules.insert(
                iface.clone(),
                rules.into_iter().map(db_rule_to_files_rule).collect(),
            );
        }
        // Correctly space-separated (see `Store::join_approved_ips_map` /
        // `migrate`'s module doc) — the flat-file read this replaces used
        // `read_mac_ip_map` (tab-separated) against a space-separated
        // file, so this map was silently always empty before the
        // migration importer fixed the read path.
        join_approved_ips.insert(
            iface.clone(),
            store.join_approved_ips_map(iface).await.unwrap_or_default(),
        );
        if conf.join_approval {
            // Deliberately still a direct flat-file read, NOT `Store` —
            // `{iface}-allowed-macs` is a hand-edited admin config file
            // (see its own `install.sh`-seeded header comment), never
            // written by kestreld itself, and read directly by the real
            // enforcement path (`51-{iface}-macfilter` hotplug script).
            // Importing it into `Store` once and reading it back from
            // there would show stale data forever after any hand edit —
            // this file is the same kind of "stays flat, out of scope"
            // config as `{iface}-notify.conf`, not migrated runtime state.
            let path = base_dir.join(format!("{iface}-allowed-macs"));
            allowed_macs.insert(iface.clone(), files::read_allowed_macs(&path).await);
        }
    }

    // uci show firewall + crontab + joins + local domain
    let (uci_firewall, crontab, joins, local_domain) = tokio::join!(
        run_cmd("uci", &["show", "firewall"]),
        run_cmd("crontab", &["-l"]),
        files::read_joins(),
        run_cmd("uci", &["-q", "get", "dhcp.@dnsmasq[0].domain"]),
    );
    let local_domain = local_domain.trim().to_string();

    // Per-interface bridge state and IPv6 prefixes
    let mut ipv6_prefixes: HashMap<String, Vec<String>> = HashMap::new();
    let mut iface_up: HashMap<String, bool> = HashMap::new();
    for conf in &net_confs {
        let iface = &conf.iface;
        let prefixes = fetch_ipv6_prefixes(iface).await;
        ipv6_prefixes.insert(iface.clone(), prefixes);
        let up = fetch_iface_up(iface).await;
        iface_up.insert(iface.clone(), up);
    }

    let banip_feeds = banip::BanipFeeds::parse(&nft_state.raw);

    Snapshot {
        at: Instant::now(),
        system: sys,
        iw: iw_state,
        vpn_tiers,
        wg_servers,
        openvpn_servers,
        ipsec_peers: ipsec_peers_list,
        nft: nft_state,
        banip: banip_feeds,
        leases,
        neigh: neigh_table,
        logs: log_data,
        net_confs,
        dns_cache,
        labels,
        join_approved,
        join_pending,
        join_denied,
        join_history,
        wifi_keys,
        uci_firewall,
        crontab,
        net_traffic,
        dev_bytes4,
        dev_bytes6,
        joins,
        ipv6_prefixes,
        iface_up,
        device_ips,
        device_ip6s,
        device_limits,
        device_rules,
        join_approved_ips,
        allowed_macs,
        local_domain,
    }
}

async fn fetch_ipv6_prefixes(iface: &str) -> Vec<String> {
    let out = run_cmd(
        "ip",
        &[
            "-6",
            "addr",
            "show",
            &format!("br-{iface}"),
            "scope",
            "global",
        ],
    )
    .await;
    out.lines()
        .filter_map(|l| {
            let t = l.trim();
            if t.starts_with("inet6 ") {
                t.split_whitespace().nth(1).map(|s| s.to_string())
            } else {
                None
            }
        })
        .collect()
}

async fn fetch_iface_up(iface: &str) -> bool {
    let out = run_cmd("ip", &["link", "show", &format!("br-{iface}")]).await;
    out.lines()
        .next()
        .map(|l| l.contains("UP"))
        .unwrap_or(false)
}

async fn uci_get_one(iface: &str, option: &str) -> String {
    tokio::process::Command::new("uci")
        .args(["-q", "get", &format!("wireless.{iface}.{option}")])
        .output()
        .await
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_default()
}

async fn wlan_iface_for(iface: &str) -> String {
    let brif_dir = format!("/sys/class/net/br-{iface}/brif");
    let mut entries = match tokio::fs::read_dir(&brif_dir).await {
        Ok(e) => e,
        Err(_) => return String::new(),
    };
    while let Ok(Some(entry)) = entries.next_entry().await {
        let n = entry.file_name();
        let name = n.to_string_lossy();
        if name.starts_with("phy") {
            return name.into_owned();
        }
    }
    String::new()
}

fn db_rule_to_files_rule(r: DbDeviceRule) -> files::DeviceRule {
    files::DeviceRule {
        mac: r.mac,
        dst: r.dst,
        action: r.action,
        port: r.port,
        proto: r.proto,
        route: r.route,
    }
}

/// Back to the original 11-column shape (`ts, when, action, mac, ip4,
/// ip6, hostname, actor, actor_ip4, actor_ip6, actor_mac`) that
/// `routes::status`/`routes::device`/`routes::approve_join` already parse
/// by fixed column index — keeps this Phase-C swap contained to
/// `state.rs` alone, with zero call-site changes elsewhere (that's
/// Phase D's job).
fn join_history_row_to_columns(r: JoinHistoryRow) -> Vec<String> {
    vec![
        r.ts.to_string(),
        r.when_str,
        r.action,
        r.mac,
        r.ip4,
        r.ip6,
        r.hostname,
        r.actor,
        r.actor_ip4,
        r.actor_ip6,
        r.actor_mac,
    ]
}

async fn run_cmd(cmd: &str, args: &[&str]) -> String {
    tokio::process::Command::new(cmd)
        .args(args)
        .output()
        .await
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .unwrap_or_default()
}
