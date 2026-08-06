//! Port of `tools/digest.sh`: sends a daily status/traffic digest to
//! every unique `NOTIFY_URL` configured across all networks. Invoked as
//! `kestreld --digest` once a day via cron (see `install.sh`).
//!
//! Reuses `data::vpn::fetch_tiers` (VPN status), `data::wg::fetch_servers`
//! (WireGuard peer activity — extended with a raw handshake timestamp so
//! this can apply its own "active in the last 24h" window, distinct from
//! the dashboard's own "online in the last 180s" definition),
//! `data::nft::NftState::chain_bytes` (per-network traffic),
//! `data::dhcp::fetch` (device counts per subnet), and `data::logs::fetch`
//! (access-log counts) rather than re-parsing any of that. System-health
//! percentages, the Google Calendar ICS/weekly-RRULE section, routing-set
//! size reporting, and expiring-access-rule detection are ported fresh
//! below — nothing existing covered any of them.
//!
//! Known simplification: the calendar section's date-window math treats
//! "now" as UTC (no timezone database is linked in — this project avoids
//! adding a date/time crate, matching its existing dependency footprint).
//! On a router actually configured for a non-UTC timezone this can shift
//! which calendar day an event lands on by the UTC offset; `GCAL_TZ_OFFSET`
//! (already a manual, user-set correction in both versions) does not fix
//! this, since it only adjusts the displayed event *time*, not which day
//! bucket an event's occurrence falls into.

use std::collections::HashMap;
use std::path::Path;

use crate::cmd;
use crate::data::{dhcp, files, logs, nft, vpn, wg};

// ── system health ──────────────────────────────────────────────────────

fn format_uptime(secs: u64) -> String {
    let d = secs / 86400;
    let h = (secs % 86400) / 3600;
    if d > 0 {
        format!(
            "{d} day{} {h} hour{}",
            if d != 1 { "s" } else { "" },
            if h != 1 { "s" } else { "" }
        )
    } else {
        format!("{h} hour{}", if h != 1 { "s" } else { "" })
    }
}

async fn system_health_line() -> String {
    let uptime_secs: u64 = tokio::fs::read_to_string("/proc/uptime")
        .await
        .ok()
        .and_then(|s| s.split_whitespace().next().map(str::to_string))
        .and_then(|s| s.parse::<f64>().ok())
        .map(|f| f as u64)
        .unwrap_or(0);

    let mem_pct: Option<u64> = tokio::fs::read_to_string("/proc/meminfo")
        .await
        .ok()
        .and_then(|s| {
            let mut total = 0u64;
            let mut avail = 0u64;
            for line in s.lines() {
                if let Some(rest) = line.strip_prefix("MemTotal:") {
                    total = rest.split_whitespace().next()?.parse().ok()?;
                } else if let Some(rest) = line.strip_prefix("MemAvailable:") {
                    avail = rest.split_whitespace().next()?.parse().ok()?;
                }
            }
            if total == 0 {
                return None;
            }
            Some(((total - avail) as f64 * 100.0 / total as f64).round() as u64)
        });

    match mem_pct {
        Some(p) => format!("Router up {}, memory {p}% used", format_uptime(uptime_secs)),
        None => format!("Router up {}, memory ?% used", format_uptime(uptime_secs)),
    }
}

// ── calendar (Google Calendar ICS, weekly RRULE only — see module doc) ──

fn is_leap(y: i64) -> bool {
    (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
}

const MONTH_DAYS: [i64; 12] = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
const MONTH_NAMES: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];
// Epoch day 0 (1970-01-01) was a Thursday.
const WEEKDAY_NAMES: [&str; 7] = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];

fn ymd_epoch(y: i64, m: i64, d: i64) -> i64 {
    let mut days = 0i64;
    for yy in 1970..y {
        days += if is_leap(yy) { 366 } else { 365 };
    }
    let mut md = MONTH_DAYS;
    if is_leap(y) {
        md[1] = 29;
    }
    for mm in 0..(m - 1).max(0) {
        days += md[mm as usize];
    }
    (days + d - 1) * 86400
}

fn epoch_to_ymd(epoch: i64) -> (i64, i64, i64) {
    let mut days = epoch / 86400;
    let mut y = 1970i64;
    loop {
        let year_len = if is_leap(y) { 366 } else { 365 };
        if days < year_len {
            break;
        }
        days -= year_len;
        y += 1;
    }
    let mut md = MONTH_DAYS;
    if is_leap(y) {
        md[1] = 29;
    }
    let mut m = 1i64;
    for len in md {
        if days < len {
            break;
        }
        days -= len;
        m += 1;
    }
    (y, m, days + 1)
}

fn ymd_string(epoch: i64) -> String {
    let (y, m, d) = epoch_to_ymd(epoch);
    format!("{y:04}{m:02}{d:02}")
}

fn display_date(epoch: i64) -> String {
    let (_, m, d) = epoch_to_ymd(epoch);
    let day_idx = (epoch / 86400).rem_euclid(7) as usize;
    format!(
        "{} {:02} {}",
        WEEKDAY_NAMES[day_idx],
        d,
        MONTH_NAMES[(m - 1) as usize]
    )
}

/// Joins ICS continuation lines (a leading single space marks a folded
/// continuation of the previous line, per RFC 5545) and strips `\r`.
fn unfold_ics(raw: &str) -> Vec<String> {
    let mut lines: Vec<String> = Vec::new();
    for line in raw.replace('\r', "").lines() {
        if line.starts_with(' ') {
            if let Some(last) = lines.last_mut() {
                last.push_str(&line[1..]);
                continue;
            }
        }
        lines.push(line.to_string());
    }
    lines
}

fn rrule_field<'a>(rrule: &'a str, key: &str) -> Option<&'a str> {
    rrule.split(';').find_map(|part| part.strip_prefix(key))
}

/// Sort key (`HHMM`) and display (`HH:MM`) for an event's time of day.
/// `dt` shorter than 13 chars means an all-day event (date only, no
/// `T`-time component).
fn tparts(dt: &str, tz_offset: i64) -> (String, String) {
    if dt.len() < 13 {
        return ("0000".to_string(), "all day".to_string());
    }
    let mut h: i64 = dt[9..11].parse().unwrap_or(0);
    let m: i64 = dt[11..13].parse().unwrap_or(0);
    if dt.ends_with('Z') {
        h += tz_offset;
        if h >= 24 {
            h -= 24;
        }
        if h < 0 {
            h += 24;
        }
    }
    (format!("{h:02}{m:02}"), format!("{h:02}:{m:02}"))
}

#[derive(Default)]
struct VEvent {
    dtstart: String,
    rrule: String,
    summary: String,
}

/// For a weekly-recurring event, the calendar day (`YYYYMMDD`) of the
/// first occurrence at or after `win_start` — `None` if it never lands
/// within `dmap`'s 7 tracked days or falls after `UNTIL`. The event's
/// time-of-day comes from the original `DTSTART` regardless of which
/// week's occurrence this is, so the occurrence's own epoch isn't needed
/// by callers — only which day bucket it falls into.
fn weekly_occurrence(
    dpart: &str,
    rrule: &str,
    win_start: i64,
    dmap: &HashMap<String, String>,
) -> Option<String> {
    if dpart.len() != 8 {
        return None;
    }
    let until = rrule_field(rrule, "UNTIL=")
        .map(|u| u.chars().take(8).collect::<String>())
        .unwrap_or_default();
    let interval: i64 = rrule_field(rrule, "INTERVAL=")
        .and_then(|s| s.parse().ok())
        .unwrap_or(1)
        .max(1);
    let step = interval * 7 * 86400;

    let y: i64 = dpart[0..4].parse().ok()?;
    let m: i64 = dpart[4..6].parse().ok()?;
    let d: i64 = dpart[6..8].parse().ok()?;
    let base = ymd_epoch(y, m, d);

    let win_start_day = ymd_string(win_start);
    let diff = win_start - base;
    let k = if diff > 0 { diff / step } else { 0 };
    let mut occ = base + k * step;
    let mut occ_day = ymd_string(occ);
    if occ_day < win_start_day {
        occ += step;
        occ_day = ymd_string(occ);
    }

    if !dmap.contains_key(&occ_day) {
        return None;
    }
    if !until.is_empty() && occ_day > until {
        return None;
    }
    Some(occ_day)
}

/// Bullet lines for events in the next 7 days ("• Mon 05 Aug — Team sync
/// (14:00)"), or an empty vec if `gcal_url` is unset or the fetch fails.
async fn calendar_bullets(gcal_url: &str, tz_offset: i64) -> Vec<String> {
    if gcal_url.is_empty() {
        return Vec::new();
    }
    let (ok, ics) = cmd::run("curl", &["-sf", "--max-time", "15", gcal_url]).await;
    if !ok || ics.is_empty() {
        return Vec::new();
    }

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    let win_start = now + 86400;

    let mut dmap: HashMap<String, String> = HashMap::new();
    for i in 1..=7 {
        let ts = now + i * 86400;
        dmap.insert(ymd_string(ts), display_date(ts));
    }

    let lines = unfold_ics(&ics);
    let mut occurrences: Vec<(String, String)> = Vec::new(); // (sort_key, display)
    let mut current: Option<VEvent> = None;

    for line in &lines {
        if line.starts_with("BEGIN:VEVENT") {
            current = Some(VEvent::default());
        } else if line.starts_with("END:VEVENT") {
            if let Some(ev) = current.take() {
                if ev.summary.is_empty() {
                    continue;
                }
                let dpart: String = ev.dtstart.chars().take(8).collect();
                let (sort_hhmm, disp_hhmm) = tparts(&ev.dtstart, tz_offset);
                if !ev.rrule.is_empty() && rrule_field(&ev.rrule, "FREQ=") == Some("WEEKLY") {
                    if let Some(occ_day) = weekly_occurrence(&dpart, &ev.rrule, win_start, &dmap) {
                        occurrences.push((
                            format!("{occ_day}T{sort_hhmm}"),
                            format!("{} — {} ({disp_hhmm})", dmap[&occ_day], ev.summary),
                        ));
                    }
                } else if let Some(disp) = dmap.get(&dpart) {
                    occurrences.push((
                        format!("{dpart}T{sort_hhmm}"),
                        format!("{disp} — {} ({disp_hhmm})", ev.summary),
                    ));
                }
            }
        } else if let Some(ev) = current.as_mut() {
            if let Some(rest) = line.strip_prefix("DTSTART") {
                if let Some(val) = rest.rsplit(':').next() {
                    ev.dtstart = val
                        .chars()
                        .filter(|c| c.is_ascii_digit() || *c == 'T' || *c == 'Z')
                        .collect();
                }
            } else if let Some(rest) = line.strip_prefix("RRULE:") {
                ev.rrule = rest.to_string();
            } else if let Some(rest) = line.strip_prefix("SUMMARY:") {
                ev.summary = rest.replace("\\,", ",").replace("\\n", " ");
            }
        }
    }

    occurrences.sort_by(|a, b| a.0.cmp(&b.0));
    occurrences
        .into_iter()
        .map(|(_, disp)| format!("• {disp}"))
        .collect()
}

// ── VPN status ────────────────────────────────────────────────────────

async fn vpn_section(split_routing_dir: &Path) -> Vec<String> {
    vpn::fetch_tiers(split_routing_dir)
        .await
        .into_iter()
        .map(|t| {
            let state = if t.state == vpn::VpnState::Up {
                "running"
            } else {
                "offline"
            };
            format!("{} VPN: {state}", t.name.to_uppercase())
        })
        .collect()
}

// ── routing set sizes (parses /tmp/routing-sets.log) ─────────────────────

fn field_after<'a>(
    lines: &[&'a str],
    header: &str,
    within: usize,
    prefix: &str,
    idx: usize,
) -> Option<String> {
    let pos = lines.iter().position(|l| *l == header)?;
    lines.iter().skip(pos + 1).take(within).find_map(|l| {
        l.strip_prefix(prefix)?
            .split_whitespace()
            .nth(idx)
            .map(|s| s.to_string())
    })
}

async fn routing_sets_section(split_routing_dir: &Path) -> Option<String> {
    if tokio::fs::metadata(split_routing_dir).await.is_err() {
        return None;
    }
    let log = tokio::fs::read_to_string("/tmp/routing-sets.log")
        .await
        .unwrap_or_default();
    if log.is_empty() {
        return None;
    }
    let log_lines: Vec<&str> = log.lines().collect();

    let mut bullets = Vec::new();
    let mut entries = match tokio::fs::read_dir(split_routing_dir).await {
        Ok(e) => e,
        Err(_) => return None,
    };
    let mut conf_paths = Vec::new();
    while let Ok(Some(entry)) = entries.next_entry().await {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name.starts_with("vpn-") && name.ends_with(".conf") {
            conf_paths.push(entry.path());
        }
    }
    conf_paths.sort();

    for path in conf_paths {
        let content = tokio::fs::read_to_string(&path).await.unwrap_or_default();
        let vars = files::parse_sh_vars(&content);
        for cat in vars
            .get("DNS_CATS")
            .map(|s| s.split_whitespace())
            .into_iter()
            .flatten()
        {
            let header = format!("==> dns {cat}");
            let n: u64 = field_after(&log_lines, &header, 3, "Domains:", 0)
                .and_then(|s| s.parse().ok())
                .unwrap_or(0);
            if n > 0 {
                bullets.push(format!("• {cat}: {n} domains"));
            } else {
                bullets.push(format!("• {cat}: empty"));
            }
        }
        for cat in vars
            .get("RESOLVE_CATS")
            .map(|s| s.split_whitespace())
            .into_iter()
            .flatten()
        {
            let header = format!("==> resolve {cat}");
            let parsed: u64 = field_after(&log_lines, &header, 5, "Domains parsed:", 0)
                .and_then(|s| s.parse().ok())
                .unwrap_or(0);
            if parsed == 0 {
                continue;
            }
            let n: u64 = field_after(&log_lines, &header, 5, "IPv4 set", 2)
                .and_then(|s| s.parse().ok())
                .unwrap_or(0);
            if n > 0 {
                bullets.push(format!("• {cat}: {n} IPs"));
            } else {
                bullets.push(format!("• {cat}: empty"));
            }
        }
    }

    if bullets.is_empty() {
        return None;
    }

    let age = tokio::fs::metadata("/tmp/routing-sets.log")
        .await
        .ok()
        .and_then(|m| m.modified().ok())
        .and_then(|t| t.elapsed().ok())
        .map(|d| {
            let secs = d.as_secs();
            if secs < 3600 {
                format!(" (refreshed {} min ago)", secs / 60)
            } else {
                format!(" (refreshed {} h ago)", secs / 3600)
            }
        })
        .unwrap_or_default();

    Some(format!("Blocklists{age}:\n{}", bullets.join("\n")))
}

// ── WireGuard server peer activity (active = handshake within 24h) ──────

async fn wg_section() -> Vec<String> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    wg::fetch_servers(now)
        .await
        .into_iter()
        .filter(|s| !s.peers.is_empty())
        .map(|s| {
            let total = s.peers.len();
            let active = s
                .peers
                .iter()
                .filter(|p| p.handshake_ts > 0 && now.saturating_sub(p.handshake_ts) < 86400)
                .count();
            format!(
                "VPN server: {active} of {total} client{} connected today",
                if total == 1 { "" } else { "s" }
            )
        })
        .collect()
}

// ── monitor daemon health ────────────────────────────────────────────────

/// Warns if the persistent monitor daemon (`kestreld --daemon`, see
/// `daemon.rs`) should be installed but isn't actually running —
/// `procd`'s `respawn` handles ordinary crashes, but this catches the
/// rarer case of it never coming back (e.g. after a failed sysupgrade),
/// which would otherwise silently stop LAN-access/allowlist-rejection/
/// pending-connection capture and WAN/VPN/bandwidth checks with no other
/// symptom until someone happens to notice a stale dashboard.
async fn daemon_health_line() -> Option<String> {
    if tokio::fs::metadata("/etc/init.d/kestreld").await.is_err() {
        return None; // not installed on this router — nothing to check
    }
    let (running, _) = cmd::run("pgrep", &["-f", "kestreld --daemon"]).await;
    if running {
        None
    } else {
        Some("⚠ Monitor daemon (kestreld --daemon) is not running — LAN-access/pending-connection capture and WAN/VPN/bandwidth checks are not happening.".to_string())
    }
}

// ── expiring access rules (crontab `allow-service.sh remove` entries) ───

async fn expiring_rules_section() -> Option<String> {
    let (_, crontab) = cmd::run("crontab", &["-l"]).await;
    let today_d = cmd::run("date", &["+%d"]).await.1;
    let today_m = cmd::run("date", &["+%m"]).await.1;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let tomorrow_epoch = now + 86400;
    let tmrw_d = cmd::run("date", &["-d", &format!("@{tomorrow_epoch}"), "+%d"])
        .await
        .1;
    let tmrw_m = cmd::run("date", &["-d", &format!("@{tomorrow_epoch}"), "+%m"])
        .await
        .1;

    let mut bullets = Vec::new();
    for line in crontab
        .lines()
        .filter(|l| l.contains("allow-service.sh remove"))
    {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 4 {
            continue;
        }
        let (cmin, chour, cday, cmon) = (
            fields[0],
            fields[1],
            format!("{:0>2}", fields[2]),
            format!("{:0>2}", fields[3]),
        );
        let when = if cday == today_d && cmon == today_m {
            format!("today at {chour:0>2}:{cmin:0>2}")
        } else if cday == tmrw_d && cmon == tmrw_m {
            format!("tomorrow at {chour:0>2}:{cmin:0>2}")
        } else {
            continue;
        };
        let Some(rname) = line.rsplit_once("# ").map(|(_, r)| r.trim()) else {
            continue;
        };
        let dst = cmd::run("uci", &["-q", "get", &format!("firewall.{rname}.dest_ip")])
            .await
            .1;
        let dst = if dst.is_empty() { "?".to_string() } else { dst };
        let port = cmd::run(
            "uci",
            &["-q", "get", &format!("firewall.{rname}.dest_port")],
        )
        .await
        .1;
        let port = if port.is_empty() {
            "?".to_string()
        } else {
            port
        };
        bullets.push(format!("• Access for {dst} → port {port} — {when}"));
    }

    if bullets.is_empty() {
        None
    } else {
        Some(format!("Expiring soon:\n{}", bullets.join("\n")))
    }
}

// ── per-network traffic + device counts ──────────────────────────────────

async fn networks_section(
    confs: &[files::NetworkConf],
    nft_state: &nft::NftState,
    leases: &[dhcp::Lease],
) -> Vec<String> {
    let mut out = Vec::new();
    for conf in confs {
        if conf.iface.is_empty() {
            continue;
        }
        let down = nft_state.chain_bytes(&format!("{}_counter", conf.iface), "out");
        let up = nft_state.chain_bytes(&format!("{}_counter", conf.iface), "in");
        let subnet_prefix = format!("{}.", conf.subnet);
        let device_count = leases
            .iter()
            .filter(|l| l.ip.starts_with(&subnet_prefix))
            .count();
        let dc_str = if device_count == 1 {
            "1 device".to_string()
        } else {
            format!("{device_count} devices")
        };
        let display = if !conf.description.is_empty() {
            conf.description.clone()
        } else {
            let mut c = conf.iface.chars();
            match c.next() {
                Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
                None => conf.iface.clone(),
            }
        };
        out.push(format!(
            "{display} — {dc_str}\n↓ {}  ↑ {}",
            wg::human_bytes(down),
            wg::human_bytes(up)
        ));
    }
    out
}

// ── orchestration ─────────────────────────────────────────────────────

pub async fn run(base_dir: &Path, split_routing_dir: &Path) -> i32 {
    let confs = files::read_all_network_confs(base_dir).await;
    let notify_urls: Vec<String> = {
        let mut seen = std::collections::HashSet::new();
        confs
            .iter()
            .filter(|c| !c.notify_url.is_empty())
            .filter(|c| seen.insert(c.notify_url.clone()))
            .map(|c| c.notify_url.clone())
            .collect()
    };
    if notify_urls.is_empty() {
        return 0;
    }

    let hostname = tokio::fs::read_to_string("/proc/sys/kernel/hostname")
        .await
        .unwrap_or_else(|_| "router".to_string())
        .trim()
        .to_string();
    let dashboard_url = cmd::dashboard_url().await;

    let global_conf_content = tokio::fs::read_to_string(base_dir.join("config"))
        .await
        .unwrap_or_default();
    let global_vars = files::parse_sh_vars(&global_conf_content);
    let gcal_url = global_vars.get("GCAL_URL").cloned().unwrap_or_default();
    let gcal_tz: i64 = global_vars
        .get("GCAL_TZ_OFFSET")
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);

    let sys_line = system_health_line().await;
    let daemon_warning = daemon_health_line().await;
    let cal_bullets = calendar_bullets(&gcal_url, gcal_tz).await;
    let vpn_lines = vpn_section(split_routing_dir).await;
    let sets_section = routing_sets_section(split_routing_dir).await;
    let wg_lines = wg_section().await;
    let expiring = expiring_rules_section().await;

    let log = logs::fetch().await;
    let lan_reqs = log
        .lines
        .iter()
        .filter(|l| l.contains("EXTNET-2LAN"))
        .count();
    let denied = log
        .lines
        .iter()
        .filter(|l| l.contains("EXTNET-DENY"))
        .count();
    let mut activity_parts = Vec::new();
    if lan_reqs > 0 {
        activity_parts.push(format!(
            "{lan_reqs} access request{}",
            if lan_reqs == 1 { "" } else { "s" }
        ));
    }
    if denied > 0 {
        activity_parts.push(format!(
            "{denied} device{} blocked",
            if denied == 1 { "" } else { "s" }
        ));
    }
    let activity_line = if activity_parts.is_empty() {
        None
    } else {
        Some(format!("{} since last restart", activity_parts.join(", ")))
    };

    let nft_state = nft::fetch().await;
    let leases = dhcp::fetch().await;
    let networks = networks_section(&confs, &nft_state, &leases).await;

    let mut body_parts: Vec<String> = Vec::new();
    if !cal_bullets.is_empty() {
        body_parts.push(format!("This week:\n{}", cal_bullets.join("\n")));
    }
    body_parts.push(sys_line);
    if let Some(w) = &daemon_warning {
        body_parts.push(w.clone());
    }
    if !vpn_lines.is_empty() {
        body_parts.push(vpn_lines.join("\n"));
    }
    if !networks.is_empty() {
        body_parts.push(networks.join("\n\n"));
    }

    let mut meta_parts: Vec<String> = Vec::new();
    meta_parts.extend(wg_lines);
    if let Some(s) = &sets_section {
        meta_parts.push(s.clone());
    }
    if let Some(a) = &activity_line {
        meta_parts.push(a.clone());
    }
    if !meta_parts.is_empty() {
        body_parts.push(meta_parts.join("\n"));
    }

    let mut body = body_parts.join("\n\n");
    if let Some(e) = &expiring {
        body.push_str(&format!("\n\n{e}"));
    }
    body.push_str(&format!("\n\nDashboard: {dashboard_url}"));

    for url in &notify_urls {
        cmd::ntfy_with_action(
            url,
            &format!("Daily digest — {hostname}"),
            "low",
            "bar_chart",
            "Dashboard",
            &dashboard_url,
            &body,
        )
        .await;
    }

    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_uptime_shows_days_when_at_least_one() {
        assert_eq!(format_uptime(90_000), "1 day 1 hour");
        assert_eq!(format_uptime(3 * 86400 + 2 * 3600), "3 days 2 hours");
    }

    #[test]
    fn format_uptime_hours_only_under_a_day() {
        assert_eq!(format_uptime(3600), "1 hour");
        assert_eq!(format_uptime(7200), "2 hours");
    }

    #[test]
    fn ymd_epoch_and_epoch_to_ymd_round_trip() {
        let epoch = ymd_epoch(2026, 8, 5);
        assert_eq!(epoch_to_ymd(epoch), (2026, 8, 5));
    }

    #[test]
    fn ymd_epoch_handles_leap_year_day() {
        // 2024-02-29 is a real date; 2024-03-01 must be exactly one day later.
        let feb29 = ymd_epoch(2024, 2, 29);
        let mar1 = ymd_epoch(2024, 3, 1);
        assert_eq!(mar1 - feb29, 86400);
    }

    #[test]
    fn ymd_string_formats_zero_padded() {
        assert_eq!(ymd_string(ymd_epoch(2026, 1, 5)), "20260105");
    }

    #[test]
    fn display_date_known_reference_epoch_zero_is_thursday() {
        assert_eq!(display_date(0), "Thu 01 Jan");
    }

    #[test]
    fn unfold_ics_joins_continuation_lines() {
        let raw = "SUMMARY:Long title th\r\n at continues\r\nDTSTART:20260101\r\n";
        let lines = unfold_ics(raw);
        assert_eq!(
            lines,
            vec![
                "SUMMARY:Long title that continues".to_string(),
                "DTSTART:20260101".to_string()
            ]
        );
    }

    #[test]
    fn tparts_all_day_when_short() {
        assert_eq!(
            tparts("20260101", 0),
            ("0000".to_string(), "all day".to_string())
        );
    }

    #[test]
    fn tparts_applies_positive_tz_offset_to_z_suffixed_time() {
        // 14:00 UTC + 2h offset = 16:00
        assert_eq!(
            tparts("20260101T140000Z", 2),
            ("1600".to_string(), "16:00".to_string())
        );
    }

    #[test]
    fn tparts_wraps_around_midnight() {
        // 23:00 UTC + 2h = 01:00 next day (date part unaffected, matches shell version)
        assert_eq!(
            tparts("20260101T230000Z", 2),
            ("0100".to_string(), "01:00".to_string())
        );
    }

    #[test]
    fn tparts_no_offset_for_non_z_suffixed_time() {
        assert_eq!(
            tparts("20260101T140000", 5),
            ("1400".to_string(), "14:00".to_string())
        );
    }

    #[test]
    fn weekly_occurrence_finds_first_match_in_window() {
        let now = ymd_epoch(2026, 8, 1); // a Saturday
        let win_start = now + 86400;
        let mut dmap = HashMap::new();
        for i in 1..=7 {
            let ts = now + i * 86400;
            dmap.insert(ymd_string(ts), display_date(ts));
        }
        // Original event on 2026-07-04 (a Saturday), weekly — should recur
        // on the Saturday within [now+1, now+7].
        let occ_day = weekly_occurrence("20260704", "FREQ=WEEKLY", win_start, &dmap).unwrap();
        assert!(dmap.contains_key(&occ_day));
    }

    #[test]
    fn weekly_occurrence_handles_biweekly_interval() {
        // README claims "recurring weekly and biweekly events are expanded
        // correctly" — this is the only test that actually exercises
        // INTERVAL=2 rather than the implicit INTERVAL=1 default.
        let now = ymd_epoch(2026, 8, 15); // a Saturday
        let win_start = now + 86400;
        let mut dmap = HashMap::new();
        for i in 1..=7 {
            let ts = now + i * 86400;
            dmap.insert(ymd_string(ts), display_date(ts));
        }
        // Original event 2026-08-01 (a Saturday), biweekly — the next
        // occurrence after 2026-08-01 is 2026-08-15, then 2026-08-29.
        // Neither of those two occurrences falls inside this window
        // (now+1 .. now+7 starting 2026-08-16), so it should NOT match —
        // confirming the interval is actually being used, not silently
        // treated as weekly (which would incorrectly match 2026-08-22).
        let result = weekly_occurrence("20260801", "FREQ=WEEKLY;INTERVAL=2", win_start, &dmap);
        assert!(
            result.is_none(),
            "biweekly event should skip the in-between week, got {result:?}"
        );

        // A biweekly event anchored so its actual occurrence lands inside
        // the window should still be found.
        let now2 = ymd_epoch(2026, 8, 28);
        let win_start2 = now2 + 86400;
        let mut dmap2 = HashMap::new();
        for i in 1..=7 {
            let ts = now2 + i * 86400;
            dmap2.insert(ymd_string(ts), display_date(ts));
        }
        let occ = weekly_occurrence("20260801", "FREQ=WEEKLY;INTERVAL=2", win_start2, &dmap2);
        assert_eq!(occ, Some("20260829".to_string()));
    }

    #[test]
    fn weekly_occurrence_respects_until() {
        let now = ymd_epoch(2026, 8, 1);
        let win_start = now + 86400;
        let mut dmap = HashMap::new();
        for i in 1..=7 {
            let ts = now + i * 86400;
            dmap.insert(ymd_string(ts), display_date(ts));
        }
        // UNTIL before the window entirely — no occurrence should match.
        let result = weekly_occurrence("20260704", "FREQ=WEEKLY;UNTIL=20260710", win_start, &dmap);
        assert!(result.is_none());
    }

    #[test]
    fn rrule_field_extracts_named_value() {
        assert_eq!(
            rrule_field("FREQ=WEEKLY;INTERVAL=2;UNTIL=20260101T000000Z", "FREQ="),
            Some("WEEKLY")
        );
        assert_eq!(
            rrule_field("FREQ=WEEKLY;INTERVAL=2", "INTERVAL="),
            Some("2")
        );
        assert_eq!(rrule_field("FREQ=WEEKLY", "UNTIL="), None);
    }
}
