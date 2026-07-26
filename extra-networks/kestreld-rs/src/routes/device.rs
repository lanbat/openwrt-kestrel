use axum::{
    extract::{Form, Query, State},
    http::HeaderMap,
    response::{Html, Json},
};
use askama::Template;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::data::files;
use crate::state::AppState;

// ── Template types ────────────────────────────────────────────────────────────

#[derive(Template)]
#[template(path = "device.html")]
struct DeviceTmpl {
    net: String,
    mac: String,
    display: String,
    label: String,
    manufacturer: String,
    online_css: String,
    online_text: String,
    dev_ip: String,
    dev_ip6: String,
    hostname: String,
    lease_status: String,
    join_approval: bool,
    join_state: String,
    join_ip: String,
    limit: u32,
    pending: Vec<PendingRow>,
    rules: Vec<RuleRow>,
    dns_queries: Vec<DnsRow>,
    history: Vec<HistRow>,
}

struct PendingRow {
    dst: String,
    port: String,
    proto: String,
}

struct RuleRow {
    dst: String,
    port: String,
    proto: String,
    action: String,
    css: String,
}

struct DnsRow {
    domain: String,
    qtype: String,
}

struct HistRow {
    when: String,
    action: String,
    css: String,
    net: String,
    ip4: String,
    ip6: String,
    by: String,
}

// ── Route types ───────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct DeviceQuery {
    pub net: Option<String>,
    pub mac: Option<String>,
}

#[derive(Deserialize)]
pub struct DeviceForm {
    pub net: Option<String>,
    pub mac: Option<String>,
    pub action: Option<String>,
    // set_label
    pub label: Option<String>,
    // set_limit
    pub limit: Option<String>,
    // approve_domain
    pub domain: Option<String>,
    // approve_pending / deny_pending
    pub dst_ip: Option<String>,
    pub dst_port: Option<String>,
    pub dst_proto: Option<String>,
    // revoke_rule
    pub dst: Option<String>,
    pub port: Option<String>,
    pub proto: Option<String>,
}

#[derive(Serialize)]
pub struct ApiResult {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redirect: Option<String>,
}

fn ok() -> Json<ApiResult> {
    Json(ApiResult { ok: true, error: None, redirect: None })
}

fn ok_redirect(url: impl Into<String>) -> Json<ApiResult> {
    Json(ApiResult { ok: true, error: None, redirect: Some(url.into()) })
}

fn err(msg: impl Into<String>) -> Json<ApiResult> {
    Json(ApiResult { ok: false, error: Some(msg.into()), redirect: None })
}

fn valid_mac(mac: &str) -> bool {
    mac.len() == 17
        && mac.chars().enumerate().all(|(i, c)| {
            if i % 3 == 2 { c == ':' } else { c.is_ascii_hexdigit() }
        })
}

fn valid_net(net: &str) -> bool {
    !net.is_empty() && net.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

fn valid_ip(s: &str) -> bool {
    if s.contains(':') {
        s.chars().all(|c| c.is_ascii_hexdigit() || c == ':') && s.len() >= 2 && s.len() <= 39
    } else {
        s.split('.').count() == 4 && s.split('.').all(|p| p.parse::<u8>().is_ok())
    }
}

fn is_private_origin(origin: &str) -> bool {
    if origin.is_empty() { return true; }
    let prefixes = ["http://192.168.", "http://10.", "http://172.1", "http://172.2",
        "http://172.30.", "http://172.31.", "http://[fd", "http://[fc",
        "http://[fe80", "http://[::1]"];
    prefixes.iter().any(|p| origin.starts_with(p))
}

fn mac_no_colons(mac: &str) -> String { mac.replace(':', "") }

fn lease_status(leases: &[crate::data::dhcp::Lease], mac: &str) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    if let Some(l) = leases.iter().find(|l| l.mac.to_lowercase() == mac.to_lowercase()) {
        if l.expiry == 0 {
            return "Static (no expiry)".into();
        }
        let diff = l.expiry as i64 - now as i64;
        if diff <= 0 { "Expired".into() }
        else if diff < 3600 { format!("Expires in {}m", diff / 60) }
        else if diff < 86400 { format!("Expires in {}h", diff / 3600) }
        else { format!("Expires in {}d", diff / 86400) }
    } else {
        "No lease".into()
    }
}

fn rel_time(ts: u64) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let diff = now.saturating_sub(ts);
    if diff < 60 { "just now".into() }
    else if diff < 3600 { format!("{} min ago", diff / 60) }
    else if diff < 86400 { format!("{}h ago", diff / 3600) }
    else { format!("{}d ago", diff / 86400) }
}

// ── GET handler ───────────────────────────────────────────────────────────────

pub async fn get(
    State(state): State<Arc<AppState>>,
    Query(params): Query<DeviceQuery>,
) -> Html<String> {
    let net = params.net.as_deref().unwrap_or("");
    let mac = params.mac.as_deref().unwrap_or("").to_lowercase();

    if !valid_net(net) {
        return Html("<h1>Invalid network</h1>".into());
    }
    if !valid_mac(&mac) {
        return Html("<h1>Invalid MAC</h1>".into());
    }

    let snap = state.snap().await;
    let conf = match snap.net_confs.iter().find(|c| c.iface == net) {
        Some(c) => c,
        None => return Html(format!("<h1>Network not found: {net}</h1>")),
    };

    let base_dir = &state.base_dir;
    let mac_n = mac_no_colons(&mac);

    // Device label
    let label = snap.labels.get(net)
        .and_then(|m| m.get(&mac))
        .cloned()
        .unwrap_or_default();

    // IPs
    let dev_ip = snap.device_ips.get(net)
        .and_then(|m| m.get(&mac))
        .cloned()
        .or_else(|| snap.join_approved_ips.get(net).and_then(|m| m.get(&mac)).cloned())
        .or_else(|| snap.leases.iter().find(|l| l.mac.to_lowercase() == mac).map(|l| l.ip.clone()))
        .unwrap_or_default();

    let dev_ip6 = snap.device_ip6s.get(net)
        .and_then(|m| m.get(&mac))
        .cloned()
        .or_else(|| snap.neigh.ip6_for_mac(&mac).map(|s| s.to_string()))
        .unwrap_or_default();

    // Online status
    let online = (!dev_ip.is_empty() && snap.neigh.is_reachable(&dev_ip))
        || (!dev_ip6.is_empty() && snap.neigh.is_reachable(&dev_ip6));
    let (online_css, online_text) = if online {
        ("ok".to_string(), "Online".to_string())
    } else {
        ("dim".to_string(), "Offline".to_string())
    };

    // Manufacturer
    let manufacturer = crate::data::files::oui_lookup(&state.oui, &mac).to_string();

    // DHCP hostname
    let hostname = snap.leases.iter()
        .find(|l| l.mac.to_lowercase() == mac)
        .and_then(|l| if l.hostname == "*" { None } else { Some(l.hostname.clone()) })
        .unwrap_or_default();

    // Lease status
    let lease_status = lease_status(&snap.leases, &mac);

    // Limit
    let limit = snap.device_limits.get(net)
        .and_then(|m| m.get(&mac))
        .copied()
        .unwrap_or(120);

    // Join state
    let join_state = if snap.join_approved.get(net).map(|v| v.contains(&mac)).unwrap_or(false) {
        "Approved"
    } else if snap.join_denied.get(net).map(|v| v.contains(&mac)).unwrap_or(false) {
        "Denied"
    } else if snap.join_pending.get(net).map(|m| m.contains_key(&mac)).unwrap_or(false) {
        "Pending"
    } else {
        "Untracked"
    }.to_string();

    // Display name
    let display = if !label.is_empty() {
        label.clone()
    } else if !hostname.is_empty() {
        format!("{hostname} (unlabelled)")
    } else {
        format!("{mac} (unlabelled)")
    };

    // Pending connections (per-device file, pruned to 24h)
    let pending_path = base_dir.join(format!("{net}-pending-{mac_n}"));
    let cutoff = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        .saturating_sub(86400);
    let raw_pending = files::prune_and_read_pending(&pending_path, cutoff).await;

    // Filter out already-ruled destinations
    let rules = snap.device_rules.get(net)
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .filter(|r| r.mac == mac)
        .collect::<Vec<_>>();

    let ruled_dsts: std::collections::HashSet<&str> = rules.iter().map(|r| r.dst.as_str()).collect();

    let pending: Vec<PendingRow> = raw_pending.into_iter()
        .filter(|p| !ruled_dsts.contains(p.dst.as_str()))
        .map(|p| PendingRow { dst: p.dst, port: p.port, proto: p.proto })
        .collect();

    let rules: Vec<RuleRow> = rules.into_iter()
        .map(|r| {
            let css = if r.action == "allow" { "tag-allow".into() } else { "tag-deny".into() };
            let action = if r.action == "allow" { "Allow".into() } else { "Deny".into() };
            RuleRow { dst: r.dst, port: r.port, proto: r.proto, action, css }
        })
        .collect();

    // DNS queries from logs
    let src_ip = if dev_ip.is_empty() { dev_ip6.clone() } else { dev_ip.clone() };
    let dns_queries: Vec<DnsRow> = if !src_ip.is_empty() {
        crate::data::logs::parse_dns_queries(&snap.logs.lines, &src_ip)
            .into_iter()
            .take(50)
            .map(|(d, t)| DnsRow { domain: d.to_string(), qtype: t.to_string() })
            .collect()
    } else {
        Vec::new()
    };

    // History from join-history files
    let hist_path = base_dir.join(format!("{net}-join-history"));
    let mut all_hist = files::read_join_history(&hist_path).await;
    all_hist.sort_by(|a, b| {
        let ta: u64 = a.first().and_then(|s| s.parse().ok()).unwrap_or(0);
        let tb: u64 = b.first().and_then(|s| s.parse().ok()).unwrap_or(0);
        tb.cmp(&ta)
    });

    fn badge_css(act: &str) -> &'static str {
        match act {
            "approved" => "approved",
            "denied" => "denied",
            "revoked" => "revoked",
            "connected" => "connected",
            "disconnected" => "disconnected",
            "deleted" => "deleted",
            "labelled" => "labelled",
            _ => "approved",
        }
    }
    fn badge_label(act: &str) -> &'static str {
        match act {
            "approved" => "Approved",
            "denied" => "Denied",
            "revoked" => "Revoked",
            "connected" => "Connected",
            "disconnected" => "Disconnected",
            "deleted" => "Deleted",
            "labelled" => "Labelled",
            _ => "Action",
        }
    }

    let history: Vec<HistRow> = all_hist.into_iter()
        .filter(|row| row.get(3).map(|m| m.to_lowercase() == mac).unwrap_or(false))
        .take(20)
        .map(|row| {
            let get = |i: usize| row.get(i).cloned().unwrap_or_default();
            let act = get(2);
            HistRow {
                when: get(1),
                css: badge_css(&act).to_string(),
                action: badge_label(&act).to_string(),
                net: net.to_string(),
                ip4: get(4),
                ip6: get(5),
                by: get(7),
            }
        })
        .collect();

    // join_ip: first non-empty IP for approve/deny action
    let join_ip = if !dev_ip.is_empty() { dev_ip.clone() } else { dev_ip6.clone() };

    let tmpl = DeviceTmpl {
        net: net.to_string(),
        mac,
        display,
        label,
        manufacturer: if manufacturer.is_empty() { "\u{2014}".into() } else { manufacturer },
        online_css,
        online_text,
        dev_ip: if dev_ip.is_empty() { "\u{2014}".into() } else { dev_ip },
        dev_ip6: if dev_ip6.is_empty() { "\u{2014}".into() } else { dev_ip6 },
        hostname: if hostname.is_empty() { "\u{2014}".into() } else { hostname },
        lease_status,
        join_approval: conf.join_approval,
        join_state,
        join_ip,
        limit,
        pending,
        rules,
        dns_queries,
        history,
    };

    Html(tmpl.render().unwrap_or_else(|e| format!("Template error: {e}")))
}

// ── POST handler ──────────────────────────────────────────────────────────────

pub async fn post(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(params): Query<DeviceQuery>,
    Form(form): Form<DeviceForm>,
) -> Json<ApiResult> {
    let origin = headers.get("origin")
        .or_else(|| headers.get("referer"))
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if !is_private_origin(origin) {
        return err("Forbidden");
    }

    // net/mac from query string first, then form
    let net = params.net.as_deref()
        .or(form.net.as_deref())
        .unwrap_or("");
    let mac = params.mac.as_deref()
        .or(form.mac.as_deref())
        .unwrap_or("")
        .to_lowercase();
    let action = form.action.as_deref().unwrap_or("");

    if !valid_net(net) { return err("Invalid network"); }
    if !valid_mac(&mac) { return err("Invalid MAC"); }

    let snap = state.snap().await;
    let conf = match snap.net_confs.iter().find(|c| c.iface == net) {
        Some(c) => c.clone(),
        None => return err("Network not found"),
    };

    let base_dir = state.base_dir.clone();
    let mac_n = mac_no_colons(&mac);

    let dev_ip = snap.device_ips.get(net).and_then(|m| m.get(&mac)).cloned()
        .or_else(|| snap.join_approved_ips.get(net).and_then(|m| m.get(&mac)).cloned())
        .unwrap_or_default();
    let dev_ip6 = snap.device_ip6s.get(net).and_then(|m| m.get(&mac)).cloned().unwrap_or_default();
    let dev_label = snap.labels.get(net).and_then(|m| m.get(&mac)).cloned().unwrap_or_default();
    let notify_url = conf.notify_url.clone();
    drop(snap);

    let back_url = format!("/cgi-bin/device?net={net}&mac={mac}");

    match action {
        "set_label" => {
            let new_label: String = form.label.as_deref().unwrap_or("").trim().chars().take(40).collect();
            if new_label.is_empty() { return ok(); }
            let lbl_path = base_dir.join(format!("{net}-device-labels"));
            let _ = files::file_upsert_by_mac(&lbl_path, &mac, &format!("{mac}\t{new_label}")).await;
            crate::cmd::write_device_dns(&base_dir, net, &mac, &new_label, "").await;
            if new_label != dev_label && !notify_url.is_empty() {
                let body = format!("MAC: {mac}{}\nNow: {new_label}",
                    if dev_label.is_empty() { String::new() } else { format!("\nWas: {dev_label}") });
                crate::cmd::ntfy(&notify_url, &format!("Label set — {net}"), "default", "pencil2", &body).await;
            }
            ok()
        }

        "set_limit" => {
            let lim: u32 = match form.limit.as_deref().unwrap_or("").parse() {
                Ok(n) if n >= 1 && n <= 9999 => n,
                _ => return err("Invalid limit"),
            };
            let limits_path = base_dir.join(format!("{net}-device-limits"));
            let _ = files::file_upsert_by_mac(&limits_path, &mac, &format!("{mac}\t{lim}")).await;
            crate::cmd::regen_inspect(net).await;
            ok()
        }

        "revoke_join_approval" => {
            let approved_path = base_dir.join(format!("{net}-join-approved"));
            let _ = files::file_remove_line(&approved_path, &mac).await;

            // Move to pending
            let pending_path = base_dir.join(format!("{net}-join-pending"));
            let _ = files::file_remove_space_prefix(&pending_path, &mac).await;
            if !dev_ip.is_empty() {
                let _ = files::file_append(&pending_path, &format!("{mac} {dev_ip}")).await;
                crate::cmd::nft_del_element(&format!("{net}_join_approved_ips"), &dev_ip).await;
                crate::cmd::nft_add_element(&format!("{net}_join_pending"), &dev_ip, "").await;
            }
            if !dev_ip6.is_empty() {
                let _ = files::file_append(&pending_path, &format!("{mac} {dev_ip6}")).await;
                crate::cmd::nft_del_element(&format!("{net}_join_approved_ips6"), &dev_ip6).await;
                crate::cmd::nft_add_element(&format!("{net}_join_pending6"), &dev_ip6, "").await;
            }

            // Remove from denied and approved-ips
            let _ = files::file_remove_line(&base_dir.join(format!("{net}-join-denied")), &mac).await;
            let _ = files::file_remove_space_prefix(&base_dir.join(format!("{net}-join-approved-ips")), &mac).await;

            if !notify_url.is_empty() {
                let body = format!("Type: Internet access revoked\n\nMAC: {mac}\nLabel: {dev_label}\nIPv4: {dev_ip}\nIPv6: {dev_ip6}");
                crate::cmd::ntfy(&notify_url, &format!("Access revoked — {net}"), "default", "no_entry", &body).await;
            }
            ok()
        }

        "approve_domain" => {
            let domain: String = form.domain.as_deref().unwrap_or("").trim().to_lowercase();
            let valid_domain = !domain.is_empty()
                && domain.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
                && !domain.starts_with('.')
                && !domain.ends_with('.');
            if !valid_domain { return err("Invalid domain"); }

            let rules_path = base_dir.join(format!("{net}-device-rules"));
            let entry = format!("{mac}\t{domain}\tallow\t\t");
            let existing = tokio::fs::read_to_string(&rules_path).await.unwrap_or_default();
            if !existing.contains(&entry) {
                let _ = files::file_append(&rules_path, &entry).await;
            }

            // Update dnsmasq per-device conf
            let dconf = format!("/etc/dnsmasq.d/{net}-device-{mac_n}.conf");
            let nftset = format!("4#inet#fw4#{net}_allow_{mac_n}_4,6#inet#fw4/{net}_allow_{mac_n}_6");
            let dentry = format!("nftset=/{domain}/{nftset}");
            let dexisting = tokio::fs::read_to_string(&dconf).await.unwrap_or_default();
            if !dexisting.contains(&dentry) {
                let _ = files::file_append(std::path::Path::new(&dconf), &dentry).await;
            }
            crate::cmd::reload_dnsmasq().await;

            if !notify_url.is_empty() {
                let body = format!("{}: {domain} allowed on {net}.\n\nLabel: {dev_label}", if dev_label.is_empty() { mac.as_str() } else { &dev_label });
                crate::cmd::ntfy(&notify_url, &format!("Rule added — {net}"), "default", "shield", &body).await;
            }
            ok()
        }

        "approve_pending" => {
            let dst_ip = form.dst_ip.as_deref().unwrap_or("");
            let dst_port = form.dst_port.as_deref().unwrap_or("");
            let dst_proto = form.dst_proto.as_deref().unwrap_or("").to_lowercase();

            if !valid_ip(dst_ip) { return err("Invalid IP"); }
            if !dst_port.chars().all(|c| c.is_ascii_digit()) || dst_port.is_empty() {
                return err("Invalid port");
            }
            if !matches!(dst_proto.as_str(), "tcp" | "udp" | "icmp") {
                return err("Invalid proto");
            }

            let rules_path = base_dir.join(format!("{net}-device-rules"));
            let entry = format!("{mac}\t{dst_ip}\tallow\t{dst_port}\t{dst_proto}");
            let existing = tokio::fs::read_to_string(&rules_path).await.unwrap_or_default();
            if !existing.contains(&entry) {
                let _ = files::file_append(&rules_path, &entry).await;
            }

            if dst_ip.contains(':') {
                crate::cmd::nft_add_element(&format!("{net}_allow_{mac_n}_6"), dst_ip, "").await;
            } else {
                crate::cmd::nft_add_element(&format!("{net}_allow_{mac_n}_4"), dst_ip, "").await;
            }

            let pending_path = base_dir.join(format!("{net}-pending-{mac_n}"));
            let _ = files::file_remove_pending(&pending_path, dst_ip, dst_port, &dst_proto).await;

            if !notify_url.is_empty() {
                let body = format!("{}: {dst_ip}:{dst_port}/{dst_proto} allowed on {net}.", if dev_label.is_empty() { mac.as_str() } else { &dev_label });
                crate::cmd::ntfy(&notify_url, &format!("Rule added — {net}"), "default", "shield", &body).await;
            }
            ok()
        }

        "deny_pending" => {
            let dst_ip = form.dst_ip.as_deref().unwrap_or("");
            let dst_port = form.dst_port.as_deref().unwrap_or("");
            let dst_proto = form.dst_proto.as_deref().unwrap_or("").to_lowercase();
            if !valid_ip(dst_ip) { return err("Invalid IP"); }
            let pending_path = base_dir.join(format!("{net}-pending-{mac_n}"));
            let _ = files::file_remove_pending(&pending_path, dst_ip, dst_port, &dst_proto).await;
            ok()
        }

        "revoke_rule" => {
            let dst = form.dst.as_deref().unwrap_or("");
            let port = form.port.as_deref().unwrap_or("");
            let proto = form.proto.as_deref().unwrap_or("").to_lowercase();
            if dst.is_empty() { return err("Missing dst"); }

            let rules_path = base_dir.join(format!("{net}-device-rules"));
            let _ = files::file_remove_rule(&rules_path, &mac, dst).await;

            if dst.contains(':') {
                crate::cmd::nft_del_element(&format!("{net}_allow_{mac_n}_6"), dst).await;
            } else if dst.split('.').count() == 4 {
                crate::cmd::nft_del_element(&format!("{net}_allow_{mac_n}_4"), dst).await;
            } else {
                // domain — remove from dnsmasq conf
                let dconf = format!("/etc/dnsmasq.d/{net}-device-{mac_n}.conf");
                if let Ok(content) = tokio::fs::read_to_string(&dconf).await {
                    let patched: String = content.lines()
                        .filter(|l| !l.contains(&format!("/{dst}/")))
                        .flat_map(|l| [l, "\n"])
                        .collect();
                    let _ = tokio::fs::write(&dconf, patched).await;
                }
                crate::cmd::reload_dnsmasq().await;
            }
            let _ = (port, proto); // suppress warnings
            ok()
        }

        "delete" => {
            crate::cmd::append_join_history(
                &base_dir, net, "deleted", &mac,
                &dev_ip, &dev_ip6, &dev_label,
                "system", "", "", "",
            ).await;

            // Remove from all state files
            for filename in &[
                format!("{net}-device-labels"),
                format!("{net}-device-ips"),
                format!("{net}-device-ip6s"),
                format!("{net}-device-limits"),
                format!("{net}-device-rules"),
            ] {
                let path = base_dir.join(filename);
                let _ = files::file_remove_by_mac(&path, &mac).await;
            }
            for filename in &[
                format!("{net}-join-approved"),
                format!("{net}-join-denied"),
            ] {
                let path = base_dir.join(filename);
                let _ = files::file_remove_line(&path, &mac).await;
            }
            let _ = files::file_remove_space_prefix(&base_dir.join(format!("{net}-join-pending")), &mac).await;
            let _ = files::file_remove_space_prefix(&base_dir.join(format!("{net}-join-approved-ips")), &mac).await;

            // NFT cleanup
            if !dev_ip.is_empty() {
                crate::cmd::nft_del_element(&format!("{net}_join_approved_ips"), &dev_ip).await;
                crate::cmd::nft_del_element(&format!("{net}_join_pending"), &dev_ip).await;
            }
            if !dev_ip6.is_empty() {
                crate::cmd::nft_del_element(&format!("{net}_join_approved_ips6"), &dev_ip6).await;
                crate::cmd::nft_del_element(&format!("{net}_join_pending6"), &dev_ip6).await;
            }

            // dnsmasq cleanup
            let _ = tokio::fs::remove_file(format!("/etc/dnsmasq.d/{net}-device-{mac_n}.conf")).await;
            let _ = tokio::fs::remove_file(format!("/etc/dnsmasq.d/{net}-dns-{mac_n}.conf")).await;
            crate::cmd::reload_dnsmasq().await;
            crate::cmd::regen_inspect(net).await;

            if !notify_url.is_empty() {
                let body = format!("{} has been removed from {net}.\n\nMAC: {mac}\nIPv4: {dev_ip}\nIPv6: {dev_ip6}", if dev_label.is_empty() { mac.as_str() } else { &dev_label });
                crate::cmd::ntfy(&notify_url, &format!("Device removed — {net}"), "default", "wastebasket", &body).await;
            }

            let _ = back_url; // suppress warning — we redirect to network page on delete
            ok_redirect(format!("/cgi-bin/network?net={net}"))
        }

        _ => err("Unknown action"),
    }
}
