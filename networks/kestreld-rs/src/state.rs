use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

use crate::data::{banip, dhcp, dns, files, iw, logs, neigh, nft, system, vpn, wg};

pub struct Snapshot {
    pub at: Instant,
    pub system: system::SystemInfo,
    pub iw: iw::IwState,
    pub vpn_tiers: Vec<vpn::VpnTier>,
    pub wg_servers: Vec<wg::WgServer>,
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
}

impl AppState {
    async fn build(base_dir: PathBuf, split_routing_dir: PathBuf) -> Arc<Self> {
        let snap = build_snapshot(&base_dir, &split_routing_dir).await;
        let oui = files::read_oui(&base_dir.join("oui.txt")).await;
        Arc::new(Self {
            snapshot: RwLock::new(Arc::new(snap)),
            base_dir,
            split_routing_dir,
            oui,
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
                let snap = build_snapshot(&state2.base_dir, &state2.split_routing_dir).await;
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

pub async fn build_snapshot(base_dir: &Path, split_routing_dir: &Path) -> Snapshot {
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

    let (vpn_tiers, wg_servers) = tokio::join!(
        vpn::fetch_tiers(split_routing_dir),
        wg::fetch_servers(now_ts),
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

        let label_path = base_dir.join(format!("{iface}-device-labels"));
        labels.insert(iface.clone(), files::read_labels(&label_path).await);

        if conf.join_approval {
            let app_path = base_dir.join(format!("{iface}-join-approved"));
            let den_path = base_dir.join(format!("{iface}-join-denied"));
            let pen_path = base_dir.join(format!("{iface}-join-pending"));
            let hist_path = base_dir.join(format!("{iface}-join-history"));

            let approved: Vec<String> = files::read_lines(&app_path)
                .await
                .into_iter()
                .map(|s| s.trim().to_lowercase())
                .collect();
            let denied: Vec<String> = files::read_lines(&den_path)
                .await
                .into_iter()
                .map(|s| s.trim().to_lowercase())
                .collect();
            let pending_raw = files::read_pending(&pen_path).await;

            join_approved.insert(iface.clone(), approved);
            join_denied.insert(iface.clone(), denied);
            join_pending.insert(iface.clone(), pending_raw);

            let mut hist = files::read_join_history(&hist_path).await;
            hist.reverse();
            hist.truncate(20);
            join_history.insert(iface.clone(), hist);
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
        dev_bytes4.insert(iface.clone(), nft_state.device_bytes(&format!("{iface}_device_bytes")));
        dev_bytes6.insert(iface.clone(), nft_state.device_bytes(&format!("{iface}_device_bytes6")));

        // Device control state
        if conf.device_control {
            device_ips.insert(iface.clone(),
                files::read_mac_ip_map(&base_dir.join(format!("{iface}-device-ips"))).await);
            device_ip6s.insert(iface.clone(),
                files::read_mac_ip_map(&base_dir.join(format!("{iface}-device-ip6s"))).await);
            device_limits.insert(iface.clone(),
                files::read_device_limits(&base_dir.join(format!("{iface}-device-limits"))).await);
            device_rules.insert(iface.clone(),
                files::read_device_rules(&base_dir.join(format!("{iface}-device-rules"))).await);
        }
        join_approved_ips.insert(iface.clone(),
            files::read_mac_ip_map(&base_dir.join(format!("{iface}-join-approved-ips"))).await);
        if conf.join_approval {
            allowed_macs.insert(iface.clone(),
                files::read_allowed_macs(&base_dir.join(format!("{iface}-allowed-macs"))).await);
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
    let out = run_cmd("ip", &["-6", "addr", "show", &format!("br-{iface}"), "scope", "global"]).await;
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

async fn run_cmd(cmd: &str, args: &[&str]) -> String {
    tokio::process::Command::new(cmd)
        .args(args)
        .output()
        .await
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .unwrap_or_default()
}
