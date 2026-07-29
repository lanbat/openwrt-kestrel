//! Port of `tools/check-access-log.sh`: scans the system log for blocked
//! LAN→isolated-network connection attempts and allowlist rejections,
//! sending ntfy push notifications for new ones. Invoked as
//! `kestreld --check-access-log` every minute via cron (see
//! `install.sh`).
//!
//! Reuses `data::logs::fetch`/`parse_nf_fields` (already existed for the
//! device page's DNS-query view) instead of re-implementing `logread`/
//! `SRC=`/`DST=`/`PROTO=`/`DPT=` parsing.
//!
//! Two simplifications from the shell version:
//! - No checkpoint file tracking exactly which log lines are "new" since
//!   the last run — this just rescans the same last-500-lines window
//!   `logs::fetch` always returns. The seen-file dedup below (identical
//!   key scheme to the shell version) already guarantees no duplicate
//!   notifications, so the checkpoint was a work-avoidance optimization,
//!   not a correctness requirement, and rescanning ≤500 lines every
//!   minute is cheap.
//! - Notifications use the plain `cmd::ntfy`/`cmd::ntfy_with_action`
//!   helpers already used everywhere else in this codebase, which don't
//!   auto-append a "Dashboard" link/button the way the shell tooling's
//!   `_ntfy` always did — that divergence predates this port (every
//!   other Rust-side notification already dropped it), so this keeps the
//!   same convention rather than reintroducing it for just this one case.

use std::collections::HashMap;
use std::path::Path;

use crate::cmd;
use crate::data::{dhcp, files, logs};

/// Everything after the *last* occurrence of `marker`, up to the first
/// `:` or space — matches the shell version's `${line##*MARKER}` +
/// `${_t%%[: ]*}`.
fn extract_iface<'a>(line: &'a str, marker: &str) -> Option<&'a str> {
    let after = line.rsplit_once(marker)?.1;
    let end = after.find([':', ' ']).unwrap_or(after.len());
    let iface = &after[..end];
    if iface.is_empty() { None } else { Some(iface) }
}

/// MAC address for an IP from `/proc/net/arp`'s "HW address" column.
fn arp_mac_for(arp_table: &str, ip: &str) -> Option<String> {
    arp_table.lines().skip(1).find_map(|l| {
        let mut f = l.split_whitespace();
        if f.next()? != ip {
            return None;
        }
        f.nth(2).map(|s| s.to_string()) // skip HW type, Flags → HW address
    })
}

async fn trim_seen(seen_path: &Path) {
    let lines = files::read_lines(seen_path).await;
    if lines.len() <= 500 {
        return;
    }
    let kept: String = lines[lines.len() - 400..].iter().map(|l| format!("{l}\n")).collect();
    let _ = tokio::fs::write(seen_path, kept).await;
}

async fn already_seen(seen_path: &Path, key: &str) -> bool {
    files::read_lines(seen_path).await.iter().any(|l| l == key)
}

pub async fn run(base_dir: &Path) -> i32 {
    let seen_path = base_dir.join("notified-attempts");
    let log = logs::fetch().await;

    let lines: Vec<&String> = log.lines.iter()
        .filter(|l| l.contains("EXTNET-2LAN") || l.contains("EXTNET-DENY"))
        .collect();
    if lines.is_empty() {
        return 0;
    }

    let confs = files::read_all_network_confs(base_dir).await;
    let notify_url_by_iface: HashMap<&str, &str> =
        confs.iter().map(|c| (c.iface.as_str(), c.notify_url.as_str())).collect();

    let leases = dhcp::fetch().await;
    let hostname_by_ip: HashMap<&str, &str> =
        leases.iter().map(|l| (l.ip.as_str(), l.hostname.as_str())).collect();
    let arp_table = tokio::fs::read_to_string("/proc/net/arp").await.unwrap_or_default();
    let router_ip = cmd::router_lan_ip().await;

    for line in lines {
        if line.contains("EXTNET-DENY") {
            handle_deny(line, base_dir, &seen_path, &notify_url_by_iface, &hostname_by_ip, &arp_table).await;
        } else {
            handle_2lan(line, &seen_path, &notify_url_by_iface, &hostname_by_ip, &router_ip).await;
        }
    }

    0
}

async fn handle_deny(
    line: &str,
    _base_dir: &Path,
    seen_path: &Path,
    notify_url_by_iface: &HashMap<&str, &str>,
    hostname_by_ip: &HashMap<&str, &str>,
    arp_table: &str,
) {
    let Some(iface) = extract_iface(line, "EXTNET-DENY-") else { return };
    let Some(&notify_url) = notify_url_by_iface.get(iface) else { return };
    if notify_url.is_empty() {
        return;
    }
    let Some(fields) = logs::parse_nf_fields(line) else { return };
    let src = fields.src;
    if src.is_empty() {
        return;
    }

    let key = format!("deny:{iface}:{src}");
    if already_seen(seen_path, &key).await {
        return;
    }
    let _ = files::file_append(seen_path, &key).await;
    trim_seen(seen_path).await;

    let src_mac = arp_mac_for(arp_table, src);
    let src_label = match hostname_by_ip.get(src) {
        Some(name) if !name.is_empty() => format!("{name} ({src})"),
        _ => src.to_string(),
    };
    let mac_suffix = src_mac.map(|m| format!(" [{m}]")).unwrap_or_default();

    cmd::ntfy(
        notify_url,
        &format!("Blocked device — {iface}"),
        "high",
        "no_entry",
        &format!(
            "Type: Allowlist rejection\n\n{src_label}{mac_suffix} tried to use the {iface} network but is not on the allowlist."
        ),
    ).await;
}

async fn handle_2lan(
    line: &str,
    seen_path: &Path,
    notify_url_by_iface: &HashMap<&str, &str>,
    hostname_by_ip: &HashMap<&str, &str>,
    router_ip: &str,
) {
    let Some(iface) = extract_iface(line, "EXTNET-2LAN-") else { return };
    let Some(&notify_url) = notify_url_by_iface.get(iface) else { return };
    if notify_url.is_empty() {
        return;
    }
    let Some(fields) = logs::parse_nf_fields(line) else { return };
    let (src, dst, proto, port) = (fields.src, fields.dst, fields.proto.to_lowercase(), fields.dpt);
    if src.is_empty() || dst.is_empty() || proto.is_empty() || port.is_empty() {
        return;
    }

    let key = format!("{iface}:{src}:{dst}:{proto}:{port}");
    if already_seen(seen_path, &key).await {
        return;
    }
    let _ = files::file_append(seen_path, &key).await;
    trim_seen(seen_path).await;

    let label = |ip: &str| match hostname_by_ip.get(ip) {
        Some(name) if !(*name).is_empty() => format!("{name} ({ip})"),
        _ => ip.to_string(),
    };
    let src_label = label(src);
    let dst_label = label(dst);

    let approve_url = format!(
        "http://{router_ip}/cgi-bin/approve-access?net={iface}&src={src}&dst={dst}&proto={proto}&port={port}"
    );
    cmd::ntfy_with_action(
        notify_url,
        &format!("Access request — {iface}"),
        "default",
        "lock",
        "Approve",
        &approve_url,
        &format!("Type: Access request\n\n{src_label} → {dst_label}:{port}/{proto}\nApprove: {approve_url}"),
    ).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_iface_from_deny_marker_stops_at_colon() {
        let line = "... EXTNET-DENY-untrusted: IN=br-untrusted SRC=192.168.4.5 ...";
        assert_eq!(extract_iface(line, "EXTNET-DENY-"), Some("untrusted"));
    }

    #[test]
    fn extract_iface_from_2lan_marker_stops_at_space() {
        let line = "... EXTNET-2LAN-guest SRC=192.168.3.5 DST=192.168.1.10 ...";
        assert_eq!(extract_iface(line, "EXTNET-2LAN-"), Some("guest"));
    }

    #[test]
    fn extract_iface_missing_marker_returns_none() {
        assert_eq!(extract_iface("some unrelated line", "EXTNET-DENY-"), None);
    }

    #[test]
    fn arp_mac_for_finds_matching_ip() {
        let table = "IP address       HW type     Flags       HW address            Mask     Device\n\
                      192.168.1.5      0x1         0x2         aa:bb:cc:dd:ee:ff      *        br-lan\n";
        assert_eq!(arp_mac_for(table, "192.168.1.5"), Some("aa:bb:cc:dd:ee:ff".to_string()));
    }

    #[test]
    fn arp_mac_for_unknown_ip_returns_none() {
        let table = "IP address       HW type     Flags       HW address            Mask     Device\n";
        assert_eq!(arp_mac_for(table, "10.0.0.99"), None);
    }
}
