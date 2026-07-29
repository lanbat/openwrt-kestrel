//! Port of `tools/check-access-log.sh`: scans the system log for blocked
//! LAN→isolated-network connection attempts and allowlist rejections,
//! sending ntfy push notifications for new ones.
//!
//! This module's `run()` (a one-shot batch scan of the last ~500 log
//! lines, matching the original cron-based design) is kept as a manual/
//! debug tool (`kestreld --check-access-log`) even though its cron entry
//! is gone — the ongoing job now belongs to `log_follower`, which reuses
//! `handle_deny`/`handle_2lan` below directly, calling them once per line
//! as `logread -f` streams them instead of once per batch. Both call
//! paths share identical logic; only how they get a line to look at
//! differs. See `log_follower`'s module doc for why the batch/cron
//! design had a real gap the follower closes (bounded log-buffer
//! eviction between scans, not just latency).
//!
//! Reuses `data::logs::parse_nf_fields` (already existed for the device
//! page's DNS-query view) instead of re-implementing
//! `SRC=`/`DST=`/`PROTO=`/`DPT=` parsing. Notifications use the plain
//! `cmd::ntfy`/`cmd::ntfy_with_action` helpers already used everywhere
//! else in this codebase, which don't auto-append a "Dashboard" link/
//! button the way the shell tooling's `_ntfy` always did — that
//! divergence predates this port (every other Rust-side notification
//! already dropped it), so this keeps the same convention rather than
//! reintroducing it for just this one case.

use std::path::Path;

use crate::cmd;
use crate::data::{dhcp, files, logs};

/// `{ts}\t{event}\t{src}\t{dst}\t{port}\t{proto}` — `dst`/`port`/`proto`
/// are empty for `deny` events (not applicable: an allowlist rejection
/// has no destination/port of its own). One file per network, matching
/// the existing `{iface}-join-history` convention. Durable regardless of
/// whether the ntfy delivery for a given sighting succeeds.
pub(crate) async fn append_history(base_dir: &Path, iface: &str, event: &str, src: &str, dst: &str, port: &str, proto: &str) {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();
    let path = base_dir.join(format!("{iface}-connection-history"));
    let _ = files::file_append(&path, &format!("{now}\t{event}\t{src}\t{dst}\t{port}\t{proto}")).await;
}

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

    for line in lines {
        if line.contains("EXTNET-DENY") {
            handle_deny(line, base_dir, &seen_path).await;
        } else {
            handle_2lan(line, base_dir, &seen_path).await;
        }
    }

    0
}

/// Fetches its own state (network confs, DHCP leases, ARP table) fresh
/// on every call rather than taking it as a pre-fetched parameter —
/// deliberately, so the same function works identically whether it's
/// called once per ~500-line batch (`run()`, above) or once per line as
/// `log_follower` streams them in. The extra per-event file/ARP reads
/// are cheap; a stale pre-fetched map spanning a long-running follower's
/// entire lifetime would not be.
pub(crate) async fn handle_deny(line: &str, base_dir: &Path, seen_path: &Path) {
    let Some(iface) = extract_iface(line, "EXTNET-DENY-") else { return };
    let confs = files::read_all_network_confs(base_dir).await;
    let Some(notify_url) = confs.iter().find(|c| c.iface == iface).map(|c| c.notify_url.clone()) else { return };
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
    append_history(base_dir, iface, "deny", src, "", "", "").await;

    if notify_url.is_empty() {
        return;
    }

    let leases = dhcp::fetch().await;
    let hostname = leases.iter().find(|l| l.ip == src).map(|l| l.hostname.clone()).unwrap_or_default();
    let arp_table = tokio::fs::read_to_string("/proc/net/arp").await.unwrap_or_default();
    let src_mac = arp_mac_for(&arp_table, src);
    let src_label = if hostname.is_empty() { src.to_string() } else { format!("{hostname} ({src})") };
    let mac_suffix = src_mac.map(|m| format!(" [{m}]")).unwrap_or_default();

    cmd::ntfy(
        &notify_url,
        &format!("Blocked device — {iface}"),
        "high",
        "no_entry",
        &format!(
            "Type: Allowlist rejection\n\n{src_label}{mac_suffix} tried to use the {iface} network but is not on the allowlist."
        ),
    ).await;
}

pub(crate) async fn handle_2lan(line: &str, base_dir: &Path, seen_path: &Path) {
    let Some(iface) = extract_iface(line, "EXTNET-2LAN-") else { return };
    let confs = files::read_all_network_confs(base_dir).await;
    let Some(notify_url) = confs.iter().find(|c| c.iface == iface).map(|c| c.notify_url.clone()) else { return };
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
    append_history(base_dir, iface, "2lan", src, dst, &port, &proto).await;

    if notify_url.is_empty() {
        return;
    }

    let leases = dhcp::fetch().await;
    let hostname_by_ip = |ip: &str| leases.iter().find(|l| l.ip == ip).map(|l| l.hostname.clone());
    let label = |ip: &str| match hostname_by_ip(ip) {
        Some(name) if !name.is_empty() => format!("{name} ({ip})"),
        _ => ip.to_string(),
    };
    let src_label = label(src);
    let dst_label = label(dst);
    let router_ip = cmd::router_lan_ip().await;

    let approve_url = format!(
        "http://{router_ip}/cgi-bin/approve-access?net={iface}&src={src}&dst={dst}&proto={proto}&port={port}"
    );
    cmd::ntfy_with_action(
        &notify_url,
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
