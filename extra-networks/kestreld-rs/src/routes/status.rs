use axum::{extract::State, response::Html};
use std::sync::Arc;
use askama::Template;

use crate::data::wg;
use crate::state::{AppState, Snapshot};

// ── Template types ────────────────────────────────────────────────────────────

#[derive(Template)]
#[template(path = "status.html")]
struct StatusTmpl {
    hostname: String,
    now: String,
    uptime: String,
    memory: String,
    load: String,
    wan_ip: Option<String>,
    wan_ipv6: Option<String>,
    wifi: Vec<WifiRow>,
    vpn: Vec<VpnRow>,
    wg_sections: Vec<WgSection>,
    networks: Vec<NetworkTmpl>,
    port_forwards: Vec<PfwdRow>,
    show_ip6_col: bool,
    show_join_col: bool,
}

pub struct WifiRow {
    pub label: String,
    pub css: &'static str,
    pub value: String,
}

pub struct VpnRow {
    pub label: String,
    pub css: &'static str,
    pub value: &'static str,
}

pub struct WgSection {
    pub name: String,
    pub peers: Vec<WgPeerRow>,
}

pub struct WgPeerRow {
    pub online: bool,
    pub label: String,
    pub endpoint: String,
    pub allowed_ips: String,
    pub last_seen: String,
    pub traffic: String,
}

pub struct NetworkTmpl {
    pub iface: String,
    pub ssid: String,
    pub description: String,
    pub up: bool,
    pub subnet: String,
    pub ipv6_prefixes: Vec<(String, String)>,
    pub traffic_down: String,
    pub traffic_up: String,
    pub device_count: usize,
    pub dns_server: String,
    pub dns_server_v6: String,
    pub dot: bool,
    pub rate_limit: String,
    pub rate_limit_per_device: String,
    pub lan_access: bool,
    pub isolate: bool,
    pub notify_join: bool,
    pub bandwidth_threshold_mb: u64,
    pub wlan_label: String,
    pub wlan_ok: bool,
    pub show_qr: bool,
    pub qr_data: String,
    pub wifi_key: String,
    pub rotate_password: bool,
    pub join_approval: bool,
    pub devices: Vec<DeviceRow>,
    pub history: Vec<HistoryRow>,
    pub pending_access: Vec<PendingRow>,
    pub active_rules: Vec<ActiveRuleRow>,
    pub blocked: Vec<BlockedRow>,
    pub default_duration: String,
}

pub struct DeviceRow {
    pub online: bool,
    pub mac: String,
    pub ip: String,
    pub ipv6: String,
    pub dns: String,
    pub label: String,
    pub has_label: bool,
    pub joined: String,
    pub join_state: String,
    pub join_css: String,
    pub show_approve: bool,
    pub show_deny: bool,
    pub approve_ip: String,
    pub label_value: String,
    pub signal: String,
    pub bytes: String,
    pub lease_expires: String,
    pub hostname: String,
}

pub struct HistoryRow {
    pub when: String,
    pub action: String,
    pub css: String,
    pub mac: String,
    pub ip4: String,
    pub ip6: String,
    pub by: String,
    pub by_mac: String,
}

pub struct PendingRow {
    pub ts: String,
    pub src: String,
    pub dst: String,
    pub port: String,
    pub proto: String,
    pub src_name: String,
    pub dst_name: String,
}

pub struct ActiveRuleRow {
    pub device: String,
    pub port_proto: String,
    pub expires: String,
}

pub struct BlockedRow {
    pub ts: String,
    pub src: String,
    pub dst: String,
    pub port_proto: String,
}

pub struct PfwdRow {
    pub name: String,
    pub zone: String,
    pub port: String,
    pub dest: String,
    pub proto: String,
    pub expires: String,
}

// ── Handler ───────────────────────────────────────────────────────────────────

pub async fn render(snap: &Snapshot) -> String {
    let tmpl = build(snap).await;
    tmpl.render().unwrap_or_else(|e| format!("Template error: {e}"))
}

pub async fn get(State(state): State<Arc<AppState>>) -> Html<String> {
    let snap = state.snap().await;
    Html(render(&snap).await)
}

async fn build(snap: &Snapshot) -> StatusTmpl {
    let now = {
        let output = tokio::process::Command::new("date")
            .args(["+%H:%M:%S on %d/%m/%Y"])
            .output()
            .await
            .ok()
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .unwrap_or_default();
        output.trim().to_string()
    };

    let wifi = build_wifi(snap);
    let vpn = build_vpn(snap);
    let wg_sections = build_wg(snap);
    let (show_ip6_col, show_join_col) = global_col_flags(snap);
    let networks = build_networks(snap, show_ip6_col, show_join_col).await;
    let port_forwards = build_port_forwards(snap);

    StatusTmpl {
        hostname: snap.system.hostname.clone(),
        now,
        uptime: snap.system.uptime.clone(),
        memory: snap.system.memory.clone(),
        load: snap.system.load.clone(),
        wan_ip: snap.system.wan_ip.clone(),
        wan_ipv6: snap.system.wan_ipv6.clone(),
        wifi,
        vpn,
        wg_sections,
        networks,
        port_forwards,
        show_ip6_col,
        show_join_col,
    }
}

fn build_wifi(snap: &Snapshot) -> Vec<WifiRow> {
    snap.iw.phys.iter().map(|phy| {
        let label = if !phy.band.is_empty() {
            if phy.channel.is_empty() {
                phy.band.clone()
            } else {
                format!("{}, ch {}", phy.band, phy.channel)
            }
        } else {
            phy.name.clone()
        };
        let (css, value) = if !phy.status_ok {
            ("warn", phy.status_label.as_str())
        } else {
            ("ok", phy.status_label.as_str())
        };
        WifiRow { label, css, value: value.to_string() }
    }).collect()
}

fn build_vpn(snap: &Snapshot) -> Vec<VpnRow> {
    snap.vpn_tiers.iter().map(|t| {
        let label = format!("{} ({})", t.name.to_uppercase(), t.iface);
        VpnRow {
            label,
            css: t.state.css_class(),
            value: t.state.label(),
        }
    }).collect()
}

fn build_wg(snap: &Snapshot) -> Vec<WgSection> {
    snap.wg_servers.iter().map(|srv| {
        let peers = srv.peers.iter().map(|p| WgPeerRow {
            online: p.online,
            label: p.label.clone(),
            endpoint: p.endpoint.clone(),
            allowed_ips: p.allowed_ips.clone(),
            last_seen: p.last_seen.clone(),
            traffic: p.traffic.clone(),
        }).collect();
        WgSection { name: srv.name.clone(), peers }
    }).collect()
}

fn global_col_flags(snap: &Snapshot) -> (bool, bool) {
    let show_ip6 = snap.ipv6_prefixes.values().any(|v| !v.is_empty());
    let show_join = snap.net_confs.iter().any(|c| c.join_approval);
    (show_ip6, show_join)
}

async fn build_networks(snap: &Snapshot, show_ip6_col: bool, show_join_col: bool) -> Vec<NetworkTmpl> {
    let mut result = Vec::new();
    for conf in &snap.net_confs {
        let net = build_one_network(snap, conf, show_ip6_col, show_join_col).await;
        result.push(net);
    }
    result
}

async fn build_one_network(
    snap: &Snapshot,
    conf: &crate::data::files::NetworkConf,
    _show_ip6_col: bool,
    show_join_col: bool,
) -> NetworkTmpl {
    let iface = &conf.iface;
    let up = snap.iface_up.get(iface).copied().unwrap_or(false);

    let (ssid, wifi_key, wifi_enc) = snap.wifi_keys.get(iface)
        .map(|(s, k, e)| (s.clone(), k.clone(), e.clone()))
        .unwrap_or_default();

    let (wlan_iface, down_bytes, up_bytes) = snap.net_traffic.get(iface)
        .cloned()
        .unwrap_or_default();

    let traffic_down = wg::human_bytes(down_bytes);
    let traffic_up = wg::human_bytes(up_bytes);

    let prefixes = snap.ipv6_prefixes.get(iface).cloned().unwrap_or_default();
    let ipv6_prefixes: Vec<(String, String)> = prefixes.iter().map(|p| {
        let label = if p.starts_with("fd") || p.starts_with("fc") {
            "IPv6 prefix (ULA)".to_string()
        } else {
            "IPv6 prefix".to_string()
        };
        (label, p.clone())
    }).collect();

    let wlan_ch = if !wlan_iface.is_empty() {
        snap.iw.vap_info.get(wlan_iface.as_str()).map(|(ch, _)| ch.clone())
    } else { None };
    let wlan_band = if !wlan_iface.is_empty() {
        snap.iw.vap_info.get(wlan_iface.as_str()).map(|(_, b)| b.clone())
    } else { None };
    let wlan_ok = wlan_ch.is_some();
    let wlan_label = if wlan_iface.is_empty() {
        String::new()
    } else {
        let mut lbl = wlan_iface.clone();
        if let Some(ch) = &wlan_ch { lbl.push_str(&format!(", ch {ch}")); }
        if let Some(b) = &wlan_band { lbl.push_str(&format!(" ({b})")); }
        lbl
    };

    // QR code generation
    let qr_data = if conf.show_qr && !wifi_key.is_empty() && !ssid.is_empty() {
        let wtype = match wifi_enc.as_str() {
            e if e.starts_with("sae") || e.starts_with("psk") => "WPA",
            e if e.starts_with("wep") => "WEP",
            _ => "nopass",
        };
        let qr_str = format!("WIFI:S:{ssid};T:{wtype};P:{wifi_key};;");
        qrencode(&qr_str).await
    } else {
        String::new()
    };

    // Device rows
    let devices = build_device_rows(snap, conf, show_join_col);
    let device_count = devices.len();

    // Join history
    let history = build_history_rows(snap, conf);

    // Pending LAN access
    let pending_access = build_pending_access(snap, conf);

    // Active LAN access rules
    let active_rules = build_active_rules(snap, conf);

    // Recent blocked
    let blocked = build_blocked(snap, conf);

    NetworkTmpl {
        iface: iface.clone(),
        ssid,
        description: conf.description.clone(),
        up,
        subnet: conf.subnet.clone(),
        ipv6_prefixes,
        traffic_down,
        traffic_up,
        device_count,
        dns_server: conf.dns_server.clone(),
        dns_server_v6: conf.dns_server_v6.clone(),
        dot: conf.dot,
        rate_limit: conf.rate_limit.clone(),
        rate_limit_per_device: conf.rate_limit_per_device.clone(),
        lan_access: conf.lan_access,
        isolate: conf.isolate,
        notify_join: conf.notify_join,
        bandwidth_threshold_mb: conf.bandwidth_threshold_mb,
        wlan_label,
        wlan_ok,
        show_qr: conf.show_qr && !qr_data.is_empty(),
        qr_data,
        wifi_key,
        rotate_password: conf.rotate_password,
        join_approval: conf.join_approval,
        devices,
        history,
        pending_access,
        active_rules,
        blocked,
        default_duration: conf.default_duration.clone(),
    }
}

fn build_device_rows(
    snap: &Snapshot,
    conf: &crate::data::files::NetworkConf,
    show_join_col: bool,
) -> Vec<DeviceRow> {
    let iface = &conf.iface;
    let labels = snap.labels.get(iface);
    let approved = snap.join_approved.get(iface);
    let denied = snap.join_denied.get(iface);
    let pending = snap.join_pending.get(iface);
    let bytes4 = snap.dev_bytes4.get(iface);
    let bytes6 = snap.dev_bytes6.get(iface);
    let empty_map = std::collections::HashMap::new();
    let bytes4 = bytes4.unwrap_or(&empty_map);
    let bytes6 = bytes6.unwrap_or(&empty_map);

    // Collect DHCP leases for this subnet
    let prefix = if conf.subnet.is_empty() { String::new() } else { format!("{}.", conf.subnet) };

    let mut rows = Vec::new();
    let mut seen_macs: std::collections::HashSet<String> = std::collections::HashSet::new();

    for lease in &snap.leases {
        if !prefix.is_empty() && !lease.ip.starts_with(&prefix) {
            continue;
        }
        if prefix.is_empty() {
            continue; // skip if no subnet configured
        }

        let mac = lease.mac.to_lowercase();
        seen_macs.insert(mac.clone());

        let ipv6 = snap.neigh.ip6_for_mac(&mac).unwrap_or("").to_string();
        let online = snap.neigh.is_reachable(&lease.ip)
            || (!ipv6.is_empty() && snap.neigh.is_reachable(&ipv6));

        let dns = snap.dns_cache.lookup(&lease.ip)
            .map(|s| s.to_string())
            .unwrap_or_else(|| "—".to_string());

        let label_val = labels.and_then(|m| m.get(&mac)).cloned().unwrap_or_default();
        let has_label = !label_val.is_empty();

        let joined = snap.joins.get(&mac).cloned().unwrap_or_else(|| "—".to_string());

        let b4 = bytes4.get(&lease.ip).copied().unwrap_or(0);
        let b6 = if ipv6.is_empty() { 0 } else { bytes6.get(&ipv6).copied().unwrap_or(0) };
        let total_bytes = b4 + b6;
        let bytes = if total_bytes > 0 { wg::human_bytes(total_bytes) } else { "—".to_string() };

        let lease_expires = if lease.expiry == 0 {
            "—".to_string()
        } else {
            let now_ts = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let rem = lease.expiry.saturating_sub(now_ts);
            if rem == 0 { "expired".to_string() }
            else if rem > 86400 { format!("{}d", rem / 86400) }
            else if rem > 3600 { format!("{}h {}m", rem / 3600, (rem % 3600) / 60) }
            else { format!("{}m", rem / 60) }
        };

        let (join_state, join_css, show_approve, show_deny, approve_ip) = if show_join_col && conf.join_approval {
            let is_approved = approved.map(|v| v.iter().any(|m| m == &mac)).unwrap_or(false);
            let is_denied = denied.map(|v| v.iter().any(|m| m == &mac)).unwrap_or(false);
            let is_pending = pending.map(|m| m.contains_key(&mac)).unwrap_or(false);
            let (state, css) = if is_approved { ("Approved", "approved") }
                else if is_denied { ("Denied", "denied") }
                else if is_pending { ("Pending", "pending") }
                else { ("Untracked", "untracked") };
            let show_approve = !is_approved;
            let show_deny = !is_approved && !is_denied;
            let approve_ip = if lease.ip.is_empty() || lease.ip == "-" {
                ipv6.clone()
            } else {
                lease.ip.clone()
            };
            (state.to_string(), css.to_string(), show_approve, show_deny, approve_ip)
        } else {
            (String::new(), String::new(), false, false, String::new())
        };

        rows.push(DeviceRow {
            online,
            mac: mac.clone(),
            ip: lease.ip.clone(),
            ipv6,
            dns,
            label: label_val.clone(),
            has_label,
            joined,
            join_state,
            join_css,
            show_approve,
            show_deny,
            approve_ip,
            label_value: label_val,
            signal: "—".to_string(),
            bytes,
            lease_expires,
            hostname: if lease.hostname == "*" { String::new() } else { lease.hostname.clone() },
        });
    }

    // IPv6-only devices (in NDP, not in any DHCP lease for this subnet)
    for (ip6, (mac, _state)) in &snap.neigh.by_ip {
        if !ip6.contains(':') || ip6.starts_with("fe80") { continue; }
        let mac = mac.to_lowercase();
        if mac.is_empty() || seen_macs.contains(&mac) { continue; }
        // Check this MAC isn't in any lease
        if snap.leases.iter().any(|l| l.mac == mac) { continue; }

        let online = snap.neigh.is_reachable(ip6);
        let dns = snap.dns_cache.lookup(ip6).map(|s| s.to_string()).unwrap_or_else(|| "—".to_string());
        let label_val = labels.and_then(|m| m.get(&mac)).cloned().unwrap_or_default();
        let has_label = !label_val.is_empty();
        let joined = snap.joins.get(&mac).cloned().unwrap_or_else(|| "—".to_string());
        let b6 = bytes6.get(ip6.as_str()).copied().unwrap_or(0);
        let bytes = if b6 > 0 { wg::human_bytes(b6) } else { "—".to_string() };

        let (join_state, join_css, show_approve, show_deny, approve_ip) = if show_join_col && conf.join_approval {
            let is_approved = approved.map(|v| v.iter().any(|m| m == &mac)).unwrap_or(false);
            let is_denied = denied.map(|v| v.iter().any(|m| m == &mac)).unwrap_or(false);
            let is_pending = pending.map(|m| m.contains_key(&mac)).unwrap_or(false);
            let (state, css) = if is_approved { ("Approved", "approved") }
                else if is_denied { ("Denied", "denied") }
                else if is_pending { ("Pending", "pending") }
                else { ("Untracked", "untracked") };
            let show_approve = !is_approved;
            let show_deny = !is_approved && !is_denied;
            (state.to_string(), css.to_string(), show_approve, show_deny, ip6.clone())
        } else {
            (String::new(), String::new(), false, false, String::new())
        };

        rows.push(DeviceRow {
            online,
            mac: mac.clone(),
            ip: "—".to_string(),
            ipv6: ip6.clone(),
            dns,
            label: label_val.clone(),
            has_label,
            joined,
            join_state,
            join_css,
            show_approve,
            show_deny,
            approve_ip,
            label_value: label_val,
            signal: "—".to_string(),
            bytes,
            lease_expires: "—".to_string(),
            hostname: String::new(),
        });
    }

    rows
}

fn build_history_rows(snap: &Snapshot, conf: &crate::data::files::NetworkConf) -> Vec<HistoryRow> {
    if !conf.join_approval { return Vec::new(); }
    let history = match snap.join_history.get(&conf.iface) {
        Some(h) => h,
        None => return Vec::new(),
    };
    let action_map: &[(&str, &str, &str)] = &[
        ("approved",     "approved",     "Approved"),
        ("denied",       "denied",       "Denied"),
        ("revoked",      "revoked",      "Revoked"),
        ("connected",    "connected",    "Connected"),
        ("disconnected", "disconnected", "Disconnected"),
        ("deleted",      "deleted",      "Deleted"),
        ("labelled",     "labelled",     "Labelled"),
    ];

    history.iter().map(|cols| {
        let get = |i: usize| cols.get(i).cloned().unwrap_or_default();
        let when  = get(1);
        let act   = get(2);
        let mac   = get(3);
        let ip4   = get(4);
        let ip6   = get(5);
        let host  = get(6);
        let actor = get(7);
        let by_mac = get(10);

        let (css, action_lbl) = action_map.iter()
            .find(|(k, _, _)| *k == act.as_str())
            .map(|(_, css, lbl)| (*css, *lbl))
            .unwrap_or(("untracked", act.as_str()));

        let display_label = if !host.is_empty() && host != "unknown" { host } else { mac.clone() };
        let by = if !by_mac.is_empty() { by_mac.clone() } else if !actor.is_empty() { actor } else { "unknown".to_string() };

        HistoryRow {
            when,
            action: action_lbl.to_string(),
            css: css.to_string(),
            mac: display_label,
            ip4: if ip4.is_empty() { "—".to_string() } else { ip4 },
            ip6: if ip6.is_empty() { "—".to_string() } else { ip6 },
            by,
            by_mac: by_mac.clone(),
        }
    }).collect()
}

fn build_pending_access(snap: &Snapshot, conf: &crate::data::files::NetworkConf) -> Vec<PendingRow> {
    let iface = &conf.iface;
    let tag = format!("EXTNET-2LAN-{iface}:");
    let firewall = &snap.uci_firewall;

    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut rows = Vec::new();

    for line in snap.logs.grep(&tag) {
        let mut src = "";
        let mut dst = "";
        let mut proto = "";
        let mut dpt = "";
        let mut ts = "";
        for (i, tok) in line.split_whitespace().enumerate() {
            if i == 3 { ts = tok; }
            if let Some(v) = tok.strip_prefix("SRC=") { src = v; }
            if let Some(v) = tok.strip_prefix("DST=") { dst = v; }
            if let Some(v) = tok.strip_prefix("PROTO=") { proto = v; }
            if let Some(v) = tok.strip_prefix("DPT=") { dpt = v; }
        }
        if src.is_empty() || dst.is_empty() || dpt.is_empty() || proto.is_empty() { continue; }

        let key = format!("{dst}\t{dpt}\t{proto}");
        if !seen.insert(key.clone()) { continue; }
        if rows.len() >= 10 { break; }

        // Check if firewall rule already exists
        let dst_slug = dst.replace(['.', ':'], "_");
        let rule_key = format!("allow_{iface}_lan_{dst_slug}_{dpt}_{}", proto.to_lowercase());
        if firewall.contains(&format!("firewall.{rule_key}")) { continue; }

        let src_name = name_for_ip(snap, src);
        let dst_name = name_for_ip(snap, dst);

        rows.push(PendingRow {
            ts: ts.to_string(),
            src: src.to_string(),
            dst: dst.to_string(),
            port: dpt.to_string(),
            proto: proto.to_lowercase(),
            src_name,
            dst_name,
        });
    }
    rows
}

fn build_active_rules(snap: &Snapshot, conf: &crate::data::files::NetworkConf) -> Vec<ActiveRuleRow> {
    let iface = &conf.iface;
    let firewall = &snap.uci_firewall;
    let crontab = &snap.crontab;

    let mut rows = Vec::new();
    let mut seen_rules: std::collections::HashSet<String> = std::collections::HashSet::new();

    for line in firewall.lines() {
        // Match "firewall.allow_lan_{iface}..." or "firewall.allow_{iface}_lan..."
        let Some(section) = line.split('.').nth(1) else { continue };
        let rule_iface_match = section.starts_with(&format!("allow_lan_{iface}"))
            || section.starts_with(&format!("allow_{iface}_lan"));
        if !rule_iface_match { continue; }
        if !seen_rules.insert(section.to_string()) { continue; }

        let dest_ip = uci_val(firewall, section, "dest_ip");
        let dest_port = uci_val(firewall, section, "dest_port");
        let proto = uci_val(firewall, section, "proto");
        if dest_ip.is_empty() { continue; }

        let expires = crontab.lines()
            .find(|l| l.contains(&format!("# {section}")))
            .map(|l| {
                let parts: Vec<&str> = l.split_whitespace().collect();
                if parts.len() >= 5 {
                    format!("{}:{} {}/{}", parts[1], parts[0], parts[3], parts[2])
                } else {
                    "permanent".to_string()
                }
            })
            .unwrap_or_else(|| "permanent".to_string());

        let device = name_for_ip(snap, &dest_ip);
        let port_proto = format!("{dest_port}/{proto}");

        rows.push(ActiveRuleRow { device, port_proto, expires });
    }
    rows
}

fn build_blocked(snap: &Snapshot, conf: &crate::data::files::NetworkConf) -> Vec<BlockedRow> {
    let iface = &conf.iface;
    let tag = format!("EXTNET-DENY-{iface}:");

    snap.logs.grep(&tag).iter().rev().take(10).map(|line| {
        let mut src = "";
        let mut dst = "";
        let mut proto = "";
        let mut dpt = "";
        let mut ts = "";
        for (i, tok) in line.split_whitespace().enumerate() {
            if i == 3 { ts = tok; }
            if let Some(v) = tok.strip_prefix("SRC=") { src = v; }
            if let Some(v) = tok.strip_prefix("DST=") { dst = v; }
            if let Some(v) = tok.strip_prefix("PROTO=") { proto = v; }
            if let Some(v) = tok.strip_prefix("DPT=") { dpt = v; }
        }
        let src_name = name_for_ip(snap, src);
        let port_proto = if dpt.is_empty() { proto.to_lowercase() } else { format!("{dpt}/{}", proto.to_lowercase()) };
        BlockedRow {
            ts: ts.to_string(),
            src: if src_name != src { src_name } else { src.to_string() },
            dst: dst.to_string(),
            port_proto,
        }
    }).collect()
}

fn build_port_forwards(snap: &Snapshot) -> Vec<PfwdRow> {
    let firewall = &snap.uci_firewall;
    let crontab = &snap.crontab;
    let mut rows = Vec::new();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();

    for line in firewall.lines() {
        if !line.contains("=redirect") { continue; }
        let Some(section) = line.split('.').nth(1)
            .and_then(|s| s.split('=').next()) else { continue };
        if !seen.insert(section.to_string()) { continue; }

        let name = uci_val(firewall, section, "name");
        if name.is_empty() { continue; }
        let zone = uci_val(firewall, section, "src");
        let port = uci_val(firewall, section, "src_dport");
        let dest = uci_val(firewall, section, "dest_ip");
        let proto = uci_val(firewall, section, "proto");
        let expires = crontab.lines()
            .find(|l| l.contains(&format!("# {name}")))
            .map(|l| {
                let parts: Vec<&str> = l.split_whitespace().collect();
                if parts.len() >= 5 {
                    format!("{}:{} {}/{}", parts[1], parts[0], parts[3], parts[2])
                } else {
                    "permanent".to_string()
                }
            })
            .unwrap_or_else(|| "permanent".to_string());

        rows.push(PfwdRow { name, zone, port, dest, proto, expires });
    }
    rows
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn name_for_ip<'a>(snap: &'a Snapshot, ip: &str) -> String {
    if let Some(lease) = snap.leases.iter().find(|l| l.ip == ip) {
        if lease.hostname != "*" && !lease.hostname.is_empty() {
            return lease.hostname.clone();
        }
    }
    ip.to_string()
}

fn uci_val(raw: &str, section: &str, option: &str) -> String {
    let key = format!("firewall.{section}.{option}=");
    for line in raw.lines() {
        if let Some(rest) = line.trim().strip_prefix(&key) {
            return rest.trim_matches('\'').to_string();
        }
    }
    String::new()
}

async fn qrencode(data: &str) -> String {
    tokio::process::Command::new("qrencode")
        .args(["-t", "ASCII", "-m", "2", "-o", "-", data])
        .output()
        .await
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.lines().collect::<Vec<_>>().join("|"))
        .unwrap_or_default()
}
