use std::collections::HashMap;
use std::path::Path;

/// Configuration loaded from `<base_dir>/<iface>-notify.conf`
#[derive(Default, Clone)]
pub struct NetworkConf {
    pub iface: String,
    pub notify_url: String,
    pub subnet: String,
    pub rate_limit: String,
    pub rate_limit_per_device: String,
    pub dns_server: String,
    pub dns_server_v6: String,
    pub dot: bool,
    pub lan_access: bool,
    pub isolate: bool,
    pub notify_join: bool,
    pub join_approval: bool,
    pub join_history_retention: String,
    pub rotate_password: bool,
    pub show_qr: bool,
    pub description: String,
    pub bandwidth_threshold_mb: u64,
    pub device_control: bool,
    pub default_duration: String,
    /// Whether the join-approval prompt tries to correlate a randomized
    /// MAC against already-labeled devices (see `data::fingerprint`) and
    /// show a suggestion. Never affects anything but that suggestion —
    /// approval itself always still works either way. Defaults on since
    /// it's non-destructive and always human-confirmed, but some
    /// households would rather it just not guess.
    pub fingerprint_suggest: bool,
    /// Passive packet metadata capture is opt-in because raw sockets require
    /// extra privileges and are not available on every OpenWrt build.
    pub fingerprint_packet_capture: bool,
}

pub async fn read_all_network_confs(base_dir: &Path) -> Vec<NetworkConf> {
    let mut entries = match tokio::fs::read_dir(base_dir).await {
        Ok(e) => e,
        Err(_) => return Vec::new(),
    };

    let mut confs = Vec::new();
    while let Ok(Some(entry)) = entries.next_entry().await {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if !name.ends_with("-notify.conf") {
            continue;
        }
        let content = match tokio::fs::read_to_string(entry.path()).await {
            Ok(c) => c,
            Err(_) => continue,
        };
        if let Some(conf) = parse_notify_conf(&name, &content) {
            confs.push(conf);
        }
    }

    confs.sort_by(|a, b| a.iface.cmp(&b.iface));
    confs
}

/// Given a set of network confs (each with an IPv4 `subnet` like
/// "10.10.0.0/24"), find which network's subnet contains `ip`. Used to
/// resolve which network a DNS query log line belongs to — unlike the
/// kernel netfilter `EXTNET-*` log lines, dnsmasq's own log lines carry no
/// interface/network tag, only the client's source IP.
pub fn iface_for_ip(confs: &[NetworkConf], ip: &str) -> Option<String> {
    let target: std::net::Ipv4Addr = ip.parse().ok()?;
    let target_bits = u32::from(target);
    for conf in confs {
        let mut parts = conf.subnet.splitn(2, '/');
        let Some(net_ip) = parts
            .next()
            .and_then(|s| s.parse::<std::net::Ipv4Addr>().ok())
        else {
            continue;
        };
        let Some(prefix) = parts.next().and_then(|s| s.parse::<u32>().ok()) else {
            continue;
        };
        if prefix > 32 {
            continue;
        }
        let mask: u32 = if prefix == 0 {
            0
        } else {
            u32::MAX << (32 - prefix)
        };
        if (target_bits & mask) == (u32::from(net_ip) & mask) {
            return Some(conf.iface.clone());
        }
    }
    None
}

fn parse_notify_conf(filename: &str, content: &str) -> Option<NetworkConf> {
    let vars = parse_sh_vars(content);
    let iface = vars
        .get("IFACE_NAME")
        .cloned()
        .or_else(|| filename.strip_suffix("-notify.conf").map(|s| s.to_string()))?;

    if iface.is_empty() {
        return None;
    }

    Some(NetworkConf {
        iface: iface.clone(),
        notify_url: vars.get("NOTIFY_URL").cloned().unwrap_or_default(),
        subnet: vars.get("SUBNET").cloned().unwrap_or_default(),
        rate_limit: vars.get("RATE_LIMIT").cloned().unwrap_or_default(),
        rate_limit_per_device: vars
            .get("RATE_LIMIT_PER_DEVICE")
            .cloned()
            .unwrap_or_default(),
        dns_server: vars.get("DNS_SERVER").cloned().unwrap_or_default(),
        dns_server_v6: vars.get("DNS_SERVER_V6").cloned().unwrap_or_default(),
        dot: vars.get("DOT").map(|v| v == "yes").unwrap_or(false),
        lan_access: vars.get("LAN_ACCESS").map(|v| v == "yes").unwrap_or(false),
        isolate: vars.get("ISOLATE").map(|v| v != "no").unwrap_or(true),
        notify_join: vars.get("NOTIFY_JOIN").map(|v| v == "yes").unwrap_or(false),
        join_approval: vars
            .get("JOIN_APPROVAL")
            .map(|v| v == "yes")
            .unwrap_or(false),
        join_history_retention: vars
            .get("JOIN_HISTORY_RETENTION")
            .cloned()
            .unwrap_or_else(|| "90d".to_string()),
        rotate_password: vars
            .get("ROTATE_PASSWORD")
            .map(|v| v == "yes")
            .unwrap_or(false),
        show_qr: if iface == "untrusted" {
            false
        } else {
            vars.get("SHOW_QR").map(|v| v == "yes").unwrap_or(false)
        },
        description: vars.get("DESCRIPTION").cloned().unwrap_or_default(),
        bandwidth_threshold_mb: vars
            .get("BANDWIDTH_THRESHOLD_MB")
            .and_then(|v| v.parse().ok())
            .unwrap_or(0),
        device_control: vars
            .get("DEVICE_CONTROL")
            .map(|v| v == "yes")
            .unwrap_or(false),
        default_duration: vars
            .get("DEFAULT_DURATION")
            .cloned()
            .unwrap_or_else(|| "24h".to_string()),
        fingerprint_suggest: vars
            .get("FINGERPRINT_SUGGEST")
            .map(|v| v != "no")
            .unwrap_or(true),
        fingerprint_packet_capture: vars
            .get("FINGERPRINT_PACKET_CAPTURE")
            .map(|v| v == "yes")
            .unwrap_or(false),
    })
}

/// Parse `KEY=value` or `KEY='value'` from a shell-style config file.
/// Handles comments and ignores lines that are not simple assignments.
pub fn parse_sh_vars(content: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for line in content.lines() {
        let line = line.trim();
        if line.starts_with('#') || line.is_empty() {
            continue;
        }
        if let Some(eq) = line.find('=') {
            let key = &line[..eq];
            if key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
                let val = line[eq + 1..]
                    .trim_matches('"')
                    .trim_matches('\'')
                    .to_string();
                map.insert(key.to_string(), val);
            }
        }
    }
    map
}

/// Read lines from a simple file (one entry per line, ignoring blanks).
pub async fn read_lines(path: &Path) -> Vec<String> {
    tokio::fs::read_to_string(path)
        .await
        .unwrap_or_default()
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| l.to_string())
        .collect()
}

/// Read a tab-separated labels file: `mac<TAB>label`
/// Returns mac → label map (lowercase MAC keys).
pub async fn read_labels(path: &Path) -> HashMap<String, String> {
    let lines = read_lines(path).await;
    lines
        .iter()
        .filter_map(|l| {
            let mut parts = l.splitn(2, '\t');
            let mac = parts.next()?.trim().to_lowercase();
            let label = parts.next()?.trim().to_string();
            if mac.is_empty() || label.is_empty() {
                None
            } else {
                Some((mac, label))
            }
        })
        .collect()
}

/// Read join-history file. Each line has tab-separated fields:
/// ts<TAB>action<TAB>mac<TAB>ip4<TAB>ip6<TAB>hostname<TAB>actor<TAB>actor_ip4<TAB>actor_ip6<TAB>actor_mac
pub async fn read_join_history(path: &Path) -> Vec<Vec<String>> {
    let lines = read_lines(path).await;
    lines
        .iter()
        .map(|l| l.split('\t').map(|s| s.to_string()).collect())
        .filter(|v: &Vec<String>| v.len() >= 3)
        .collect()
}

/// Check if a MAC is present in a simple list file (one MAC per line, case-insensitive).
pub async fn mac_in_file(path: &Path, mac: &str) -> bool {
    let mac_lc = mac.to_lowercase();
    read_lines(path)
        .await
        .iter()
        .any(|l| l.trim().to_lowercase() == mac_lc)
}

/// Read join-pending file: `mac ip` per line. Returns mac → ip map.
pub async fn read_pending(path: &Path) -> HashMap<String, String> {
    read_lines(path)
        .await
        .iter()
        .filter_map(|l| {
            let mut parts = l.splitn(2, ' ');
            let mac = parts.next()?.trim().to_lowercase();
            let ip = parts.next().unwrap_or("").trim().to_string();
            Some((mac, ip))
        })
        .collect()
}

// ── Additional data types ─────────────────────────────────────────────────────

/// One rule from `<iface>-device-rules`.
/// Format: `mac\tdst\tallow|deny\tport\tproto\troute`
#[derive(Clone, Debug)]
pub struct DeviceRule {
    pub mac: String,
    pub dst: String,
    pub action: String,
    pub port: String,
    pub proto: String,
    pub route: String,
}

/// One entry from `<iface>-allowed-macs`.
/// Format: `mac\tip\tlabel`
#[derive(Clone, Debug)]
pub struct AllowedMac {
    pub mac: String,
    pub ip: String,
    pub label: String,
}

/// One pending connection from `<iface>-pending-<mac_n>`.
/// Format: `dst\tport\tproto[\tts]`
#[derive(Clone, Debug)]
pub struct PendingConn {
    pub dst: String,
    pub port: String,
    pub proto: String,
    pub ts: u64,
}

pub async fn read_device_rules(path: &Path) -> Vec<DeviceRule> {
    read_lines(path)
        .await
        .into_iter()
        .filter_map(|l| {
            let mut f = l.splitn(6, '\t');
            let mac = f.next()?.trim().to_lowercase();
            let dst = f.next()?.trim().to_string();
            let action = f.next()?.trim().to_string();
            let port = f.next().unwrap_or("").trim().to_string();
            let proto = f.next().unwrap_or("").trim().to_string();
            let route = f.next().unwrap_or("").trim().to_string();
            if mac.is_empty() || dst.is_empty() {
                None
            } else {
                Some(DeviceRule {
                    mac,
                    dst,
                    action,
                    port,
                    proto,
                    route,
                })
            }
        })
        .collect()
}

/// Read `mac\tip` tab-separated file → mac (lower) → ip.
/// Covers device-ips, device-ip6s, join-approved-ips.
pub async fn read_mac_ip_map(path: &Path) -> HashMap<String, String> {
    read_lines(path)
        .await
        .into_iter()
        .filter_map(|l| {
            let mut parts = l.splitn(2, '\t');
            let mac = parts.next()?.trim().to_lowercase();
            let ip = parts.next()?.trim().to_string();
            if mac.is_empty() || ip.is_empty() {
                None
            } else {
                Some((mac, ip))
            }
        })
        .collect()
}

/// Read `mac\tlimit` tab-separated file → mac (lower) → limit.
pub async fn read_device_limits(path: &Path) -> HashMap<String, u32> {
    read_lines(path)
        .await
        .into_iter()
        .filter_map(|l| {
            let mut parts = l.splitn(2, '\t');
            let mac = parts.next()?.trim().to_lowercase();
            let limit: u32 = parts.next()?.trim().parse().ok()?;
            Some((mac, limit))
        })
        .collect()
}

/// This is a hand-edited file (`install.sh` seeds it with a `#`-commented
/// header and a commented example line, documenting a whitespace-separated
/// `mac ip description` format for an admin to add entries to directly —
/// see `install.sh`'s `MACEOF` heredoc). Real enforcement (the
/// `51-{iface}-macfilter` hotplug script `install.sh` also installs)
/// already parses it exactly this way (`while read -r mac ip rest; case
/// "$mac" in '#'*|'') continue ;; esac`) — this reader previously required
/// a literal tab and never skipped comment lines, so every comment/example
/// line in the file was silently ingested as a bogus "allowed MAC" in the
/// dashboard's own view (though never in real enforcement, which only ever
/// went through the shell parser above). Fixed to match the shell parser's
/// actual, real-world behavior.
pub async fn read_allowed_macs(path: &Path) -> Vec<AllowedMac> {
    read_lines(path)
        .await
        .into_iter()
        .filter_map(|l| {
            let l = l.trim();
            if l.is_empty() || l.starts_with('#') {
                return None;
            }
            // `split_whitespace` (not `splitn` on a `char::is_whitespace`
            // pattern, which would treat each run of multiple spaces as
            // several empty fields) so the file's human-typical
            // multi-space column alignment parses the same way the shell
            // `read -r mac ip rest` parser above already does.
            let mut words = l.split_whitespace();
            let mac = words.next()?.to_lowercase();
            let ip = words.next().unwrap_or("").to_string();
            let label = words.collect::<Vec<_>>().join(" ");
            if mac.is_empty() {
                None
            } else {
                Some(AllowedMac { mac, ip, label })
            }
        })
        .collect()
}

/// Read per-device pending connections from `<iface>-pending-<mac_n>`.
pub async fn read_pending_conns(path: &Path) -> Vec<PendingConn> {
    read_lines(path)
        .await
        .into_iter()
        .filter_map(|l| {
            let mut f = l.splitn(4, '\t');
            let dst = f.next()?.trim().to_string();
            let port = f.next().unwrap_or("").trim().to_string();
            let proto = f.next().unwrap_or("").trim().to_string();
            let ts: u64 = f.next().unwrap_or("0").trim().parse().unwrap_or(0);
            if dst.is_empty() {
                None
            } else {
                Some(PendingConn {
                    dst,
                    port,
                    proto,
                    ts,
                })
            }
        })
        .collect()
}

/// One plugin-contributed annotation from `<iface>-plugin-notes`, shown
/// next to a pending connection on the device page — see
/// `plugins::Action::Annotate`. Format: `mac\tdst\tnote`.
#[derive(Clone, Debug)]
pub struct PluginNote {
    pub mac: String,
    pub dst: String,
    /// Which plugin wrote this note — attributed by the framework itself
    /// (the name of the process/`RustPlugin` that sent the `annotate`
    /// action), never self-reported inside the note's own payload, so a
    /// plugin can't attribute its note to a different plugin's name.
    pub plugin_name: String,
    pub note: String,
}

pub async fn read_plugin_notes(path: &Path) -> Vec<PluginNote> {
    read_lines(path)
        .await
        .into_iter()
        .filter_map(|l| {
            let mut f = l.splitn(4, '\t');
            let mac = f.next()?.trim().to_lowercase();
            let dst = f.next()?.trim().to_string();
            let plugin_name = f.next().unwrap_or("").trim().to_string();
            let note = f.next().unwrap_or("").trim().to_string();
            if mac.is_empty() || dst.is_empty() {
                None
            } else {
                Some(PluginNote {
                    mac,
                    dst,
                    plugin_name,
                    note,
                })
            }
        })
        .collect()
}

/// Upsert a plugin annotation for `(mac, dst)` — same replace-or-append
/// shape as `file_upsert_by_mac`, just keyed on two fields instead of
/// one. An empty `note` still replaces/appends a (now-empty) line rather
/// than removing it — a plugin clearing its own note is a normal update,
/// not a delete a different mechanism needs to handle.
pub async fn upsert_plugin_note(
    path: &Path,
    mac: &str,
    dst: &str,
    plugin_name: &str,
    note: &str,
) -> std::io::Result<()> {
    let mac_lc = mac.to_lowercase();
    let new_line = format!("{mac_lc}\t{dst}\t{plugin_name}\t{note}");
    let existing = tokio::fs::read_to_string(path).await.unwrap_or_default();
    let mut out = String::with_capacity(existing.len() + new_line.len() + 1);
    let mut found = false;
    for line in existing.lines() {
        let mut f = line.splitn(4, '\t');
        let k_mac = f.next().unwrap_or("").trim().to_lowercase();
        let k_dst = f.next().unwrap_or("").trim();
        if k_mac == mac_lc && k_dst == dst {
            out.push_str(&new_line);
            out.push('\n');
            found = true;
        } else {
            out.push_str(line);
            out.push('\n');
        }
    }
    if !found {
        out.push_str(&new_line);
        out.push('\n');
    }
    write_atomic(path, out).await
}

/// Read OUI database: each line is `AABBCC\tVendor Name` (6/7/9 hex chars).
pub async fn read_oui(path: &Path) -> HashMap<String, String> {
    read_lines(path)
        .await
        .into_iter()
        .filter_map(|l| {
            let mut parts = l.splitn(2, '\t');
            let prefix = parts.next()?.trim().to_uppercase();
            let vendor = parts.next()?.trim().to_string();
            if prefix.is_empty() {
                None
            } else {
                Some((prefix, vendor))
            }
        })
        .collect()
}

/// Look up vendor for a MAC address in the OUI database.
/// Tries 9-digit, 7-digit, then 6-digit prefix (most-specific first).
pub fn oui_lookup<'a>(oui: &'a HashMap<String, String>, mac: &str) -> &'a str {
    let hex: String = mac.replace(':', "").to_uppercase();
    for len in [9, 7, 6] {
        if hex.len() >= len {
            if let Some(v) = oui.get(&hex[..len]) {
                return v.as_str();
            }
        }
    }
    ""
}

/// Whether `s` is safe to use as a domain rule: non-empty, only
/// alphanumeric/`.`/`-`, no leading/trailing `.`. Shared between
/// `routes::device`'s `approve_domain` HTTP handler and
/// `observation::write_domain_rule` — the latter is reachable from the
/// daemon's automatic observation-window materialization with a domain
/// sourced from a device's own DNS query log, not from an HTTP form, so it
/// needs the same validation at that entry point rather than trusting the
/// caller: an unvalidated domain gets embedded directly into a dnsmasq
/// conf line (`nftset=/{domain}/...`) and nft set names.
/// Whether `s` is safe to use as a network/interface name in a file path
/// or nft set name — non-empty, only alphanumeric/`_`. Shared with
/// `routes::device`'s own (private, identical) `valid_net` — used by
/// `plugins::handle_plugin_line`'s `add_rule` action for the same reason
/// `is_valid_domain` is: it's an external-plugin-supplied `iface`, not one
/// that arrived through an already-validated HTTP form, and it flows
/// straight into file paths (`{iface}-device-rules`) and nft set names
/// (`{iface}_allow_{mac}_4`) in `observation::write_domain_rule`/
/// `write_ip_rule` — an unvalidated value there is a path-traversal risk,
/// not just a cosmetic one.
pub fn is_valid_iface(s: &str) -> bool {
    !s.is_empty() && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Whether `s` is a well-formed `aa:bb:cc:dd:ee:ff` MAC address. Shared
/// with `routes::device`'s own (private, identical) `valid_mac` — used by
/// `plugins::handle_plugin_line`'s `add_rule` action, since that's an
/// external-plugin-supplied MAC, not one that arrived through the device
/// page's own validated form.
pub fn is_valid_mac(mac: &str) -> bool {
    mac.len() == 17
        && mac.chars().enumerate().all(|(i, c)| {
            if i % 3 == 2 {
                c == ':'
            } else {
                c.is_ascii_hexdigit()
            }
        })
}

pub fn is_valid_domain(s: &str) -> bool {
    !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
        && !s.starts_with('.')
        && !s.ends_with('.')
}

/// Whether `s` is safe to use as a plugin name in a file path
/// (`{plugins_dir}/{name}.info`) — non-empty, capped length, and not
/// exactly `.` or `..` (belt-and-suspenders: the `.info` suffix already
/// means the constructed path component can never literally equal `..`,
/// but this keeps the rule easy to state on its own). Covers both
/// external plugins (filenames like `log-everything.sh`, hence `.`
/// allowed) and compiled-in `RustPlugin` names (`device-approved-notifier`).
pub fn is_valid_plugin_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 100
        && s != "."
        && s != ".."
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
}

/// Whether `mac` has the locally-administered bit set (bit 1 of the first
/// octet) — the standard tell for a randomized "private" MAC address, which
/// iOS/Android/Windows all set when generating one per network. These have
/// no OUI entry by design: they were never allocated to any manufacturer,
/// so `oui_lookup` returning empty for one isn't "unknown vendor", it's
/// "this address was made up".
pub fn is_randomized_mac(mac: &str) -> bool {
    mac.split(':')
        .next()
        .and_then(|first| u8::from_str_radix(first, 16).ok())
        .map(|first_octet| first_octet & 0x02 != 0)
        .unwrap_or(false)
}

// ── File mutation helpers ─────────────────────────────────────────────────────

pub(crate) async fn write_atomic(path: &Path, content: String) -> std::io::Result<()> {
    let tmp = path.with_extension("tmp");
    tokio::fs::write(&tmp, &content).await?;
    tokio::fs::rename(&tmp, path).await
}

/// Upsert a line in a tab-separated file, keyed on the first tab field (MAC, lowercase).
/// If a line with this key exists, it is replaced; otherwise the new line is appended.
pub async fn file_upsert_by_mac(path: &Path, mac: &str, new_line: &str) -> std::io::Result<()> {
    let mac_lc = mac.to_lowercase();
    let existing = tokio::fs::read_to_string(path).await.unwrap_or_default();
    let mut out = String::with_capacity(existing.len() + new_line.len() + 1);
    let mut found = false;
    for line in existing.lines() {
        let key = line.split('\t').next().unwrap_or("").trim().to_lowercase();
        if key == mac_lc {
            out.push_str(new_line);
            out.push('\n');
            found = true;
        } else {
            out.push_str(line);
            out.push('\n');
        }
    }
    if !found {
        out.push_str(new_line);
        out.push('\n');
    }
    write_atomic(path, out).await
}

/// Remove all lines from a tab-separated file where the first tab field matches mac.
pub async fn file_remove_by_mac(path: &Path, mac: &str) -> std::io::Result<()> {
    let mac_lc = mac.to_lowercase();
    let existing = tokio::fs::read_to_string(path).await.unwrap_or_default();
    let out: String = existing
        .lines()
        .filter(|l| {
            let key = l.split('\t').next().unwrap_or("").trim().to_lowercase();
            key != mac_lc
        })
        .flat_map(|l| [l, "\n"])
        .collect();
    write_atomic(path, out).await
}

/// Remove lines from a tab-separated file matching mac (col 0) AND dst (col 1).
pub async fn file_remove_rule(path: &Path, mac: &str, dst: &str) -> std::io::Result<()> {
    let mac_lc = mac.to_lowercase();
    let existing = tokio::fs::read_to_string(path).await.unwrap_or_default();
    let out: String = existing
        .lines()
        .filter(|l| {
            let mut f = l.splitn(3, '\t');
            let k0 = f.next().unwrap_or("").trim().to_lowercase();
            let k1 = f.next().unwrap_or("").trim();
            !(k0 == mac_lc && k1 == dst)
        })
        .flat_map(|l| [l, "\n"])
        .collect();
    write_atomic(path, out).await
}

/// Remove a specific `dst\tport\tproto` entry from a pending-connections file.
pub async fn file_remove_pending(
    path: &Path,
    dst: &str,
    port: &str,
    proto: &str,
) -> std::io::Result<()> {
    let existing = tokio::fs::read_to_string(path).await.unwrap_or_default();
    let out: String = existing
        .lines()
        .filter(|l| {
            let mut f = l.splitn(4, '\t');
            let d = f.next().unwrap_or("").trim();
            let p = f.next().unwrap_or("").trim();
            let q = f.next().unwrap_or("").trim();
            !(d == dst && p == port && q.to_lowercase() == proto.to_lowercase())
        })
        .flat_map(|l| [l, "\n"])
        .collect();
    write_atomic(path, out).await
}

/// Remove a MAC from a simple one-per-line file.
pub async fn file_remove_line(path: &Path, value: &str) -> std::io::Result<()> {
    let val_lc = value.to_lowercase();
    let existing = tokio::fs::read_to_string(path).await.unwrap_or_default();
    let out: String = existing
        .lines()
        .filter(|l| l.trim().to_lowercase() != val_lc)
        .flat_map(|l| [l, "\n"])
        .collect();
    write_atomic(path, out).await
}

/// Remove lines from a space-separated file where the first field matches `prefix` (case-insensitive).
/// Used for files like join-pending (`mac ip`) and join-approved-ips (`mac ip`).
pub async fn file_remove_space_prefix(path: &Path, prefix: &str) -> std::io::Result<()> {
    let prefix_lc = prefix.to_lowercase();
    let existing = tokio::fs::read_to_string(path).await.unwrap_or_default();
    let out: String = existing
        .lines()
        .filter(|l| {
            let first = l.split_whitespace().next().unwrap_or("").to_lowercase();
            first != prefix_lc
        })
        .flat_map(|l| [l, "\n"])
        .collect();
    write_atomic(path, out).await
}

/// Append a line (with newline) to a file, creating it if necessary.
pub async fn file_append(path: &Path, line: &str) -> std::io::Result<()> {
    use tokio::io::AsyncWriteExt;
    let mut f = tokio::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .await?;
    f.write_all(line.as_bytes()).await?;
    if !line.ends_with('\n') {
        f.write_all(b"\n").await?;
    }
    Ok(())
}

/// Prune lines from a pending file older than `cutoff_ts`, then return the remaining entries.
pub async fn prune_and_read_pending(path: &Path, cutoff_ts: u64) -> Vec<PendingConn> {
    let conns = read_pending_conns(path).await;
    let kept: Vec<PendingConn> = conns.into_iter().filter(|c| c.ts >= cutoff_ts).collect();
    if !kept.is_empty() {
        let content: String = kept
            .iter()
            .map(|c| format!("{}\t{}\t{}\t{}\n", c.dst, c.port, c.proto, c.ts))
            .collect();
        let _ = write_atomic(path, content).await;
    } else if path.exists() {
        let _ = tokio::fs::remove_file(path).await;
    }
    kept
}

/// Read /tmp/kestrel-joins: `mac<TAB>timestamp`
pub async fn read_joins() -> HashMap<String, String> {
    let path = Path::new("/tmp/kestrel-joins");
    let lines = read_lines(path).await;
    lines
        .iter()
        .filter_map(|l| {
            let mut parts = l.splitn(2, '\t');
            let mac = parts.next()?.trim().to_lowercase();
            let ts = parts.next().unwrap_or("").trim().to_string();
            Some((mac, ts))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── parse_sh_vars ─────────────────────────────────────────────────────────

    #[test]
    fn sh_vars_basic_assignment() {
        let vars = parse_sh_vars("KEY=value\n");
        assert_eq!(vars.get("KEY").map(|s| s.as_str()), Some("value"));
    }

    #[test]
    fn sh_vars_double_quoted() {
        let vars = parse_sh_vars("KEY=\"hello world\"\n");
        assert_eq!(vars.get("KEY").map(|s| s.as_str()), Some("hello world"));
    }

    #[test]
    fn sh_vars_single_quoted() {
        let vars = parse_sh_vars("KEY='hello world'\n");
        assert_eq!(vars.get("KEY").map(|s| s.as_str()), Some("hello world"));
    }

    #[test]
    fn sh_vars_skips_comment_lines() {
        let vars = parse_sh_vars("# KEY=value\n");
        assert!(vars.is_empty());
    }

    #[test]
    fn sh_vars_skips_empty_lines() {
        let vars = parse_sh_vars("\nKEY=val\n\n");
        assert_eq!(vars.len(), 1);
    }

    #[test]
    fn sh_vars_skips_invalid_key() {
        // keys with spaces or hyphens are not valid shell identifiers
        let vars = parse_sh_vars("my-key=value\n");
        assert!(vars.is_empty());
    }

    #[test]
    fn sh_vars_multiple_keys() {
        let content = "IFACE_NAME=guest\nSUBNET=10.10.0.0/24\nDOT=yes\n";
        let vars = parse_sh_vars(content);
        assert_eq!(vars.get("IFACE_NAME").map(|s| s.as_str()), Some("guest"));
        assert_eq!(vars.get("SUBNET").map(|s| s.as_str()), Some("10.10.0.0/24"));
        assert_eq!(vars.get("DOT").map(|s| s.as_str()), Some("yes"));
    }

    #[test]
    fn sh_vars_value_with_equals_sign() {
        // Only the first '=' splits; the rest is part of the value
        let vars = parse_sh_vars("URL=https://example.com/path?a=1\n");
        assert_eq!(
            vars.get("URL").map(|s| s.as_str()),
            Some("https://example.com/path?a=1")
        );
    }

    // ── parse_notify_conf (via parse_sh_vars) ──────────────────────────────

    #[test]
    fn notify_conf_basic() {
        let content = "\
IFACE_NAME=guest
SUBNET=10.10.0.0/24
DOT=yes
LAN_ACCESS=no
SHOW_QR=yes
BANDWIDTH_THRESHOLD_MB=100
DEFAULT_DURATION=48h
JOIN_HISTORY_RETENTION=30d
";
        let vars = parse_sh_vars(content);
        assert_eq!(vars.get("IFACE_NAME").map(|s| s.as_str()), Some("guest"));
        assert_eq!(vars.get("DOT").map(|s| s.as_str()), Some("yes"));
        assert_eq!(vars.get("LAN_ACCESS").map(|s| s.as_str()), Some("no"));
        assert_eq!(
            vars.get("BANDWIDTH_THRESHOLD_MB").map(|s| s.as_str()),
            Some("100")
        );
    }

    #[test]
    fn fingerprint_suggest_defaults_to_enabled_when_absent() {
        let conf = parse_notify_conf("guest-notify.conf", "IFACE_NAME=guest\n").unwrap();
        assert!(conf.fingerprint_suggest);
    }

    #[test]
    fn fingerprint_suggest_can_be_disabled() {
        let conf = parse_notify_conf(
            "guest-notify.conf",
            "IFACE_NAME=guest\nFINGERPRINT_SUGGEST=no\n",
        )
        .unwrap();
        assert!(!conf.fingerprint_suggest);
    }

    #[test]
    fn packet_capture_defaults_to_disabled_and_is_explicit() {
        let conf = parse_notify_conf("guest-notify.conf", "IFACE_NAME=guest\n").unwrap();
        assert!(!conf.fingerprint_packet_capture);
        let conf = parse_notify_conf(
            "guest-notify.conf",
            "IFACE_NAME=guest\nFINGERPRINT_PACKET_CAPTURE=yes\n",
        )
        .unwrap();
        assert!(conf.fingerprint_packet_capture);
    }

    // ── iface_for_ip ──────────────────────────────────────────────────────────

    fn conf(iface: &str, subnet: &str) -> NetworkConf {
        NetworkConf {
            iface: iface.to_string(),
            subnet: subnet.to_string(),
            ..Default::default()
        }
    }

    #[test]
    fn iface_for_ip_matches_containing_subnet() {
        let confs = vec![
            conf("guest", "10.10.0.0/24"),
            conf("untrusted", "10.20.0.0/24"),
        ];
        assert_eq!(iface_for_ip(&confs, "10.10.0.5"), Some("guest".to_string()));
        assert_eq!(
            iface_for_ip(&confs, "10.20.0.5"),
            Some("untrusted".to_string())
        );
    }

    #[test]
    fn iface_for_ip_no_match_outside_any_subnet() {
        let confs = vec![conf("guest", "10.10.0.0/24")];
        assert_eq!(iface_for_ip(&confs, "192.168.1.5"), None);
    }

    #[test]
    fn iface_for_ip_ignores_conf_with_malformed_subnet() {
        let confs = vec![
            conf("broken", "not-a-subnet"),
            conf("guest", "10.10.0.0/24"),
        ];
        assert_eq!(iface_for_ip(&confs, "10.10.0.5"), Some("guest".to_string()));
    }

    // ── read_lines / read_labels / mac_in_file / read_pending ────────────────

    #[tokio::test]
    async fn read_lines_filters_blank_lines() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("f");
        tokio::fs::write(&path, "a\n\nb\n   \nc\n").await.unwrap();
        assert_eq!(read_lines(&path).await, vec!["a", "b", "c"]);
    }

    #[tokio::test]
    async fn read_lines_missing_file_returns_empty() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("missing");
        assert!(read_lines(&path).await.is_empty());
    }

    #[tokio::test]
    async fn read_labels_parses_tab_separated_mac_label() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("labels");
        tokio::fs::write(&path, "AA:BB:CC:DD:EE:FF\tAlice's Phone\n")
            .await
            .unwrap();
        let labels = read_labels(&path).await;
        assert_eq!(
            labels.get("aa:bb:cc:dd:ee:ff").map(|s| s.as_str()),
            Some("Alice's Phone")
        );
    }

    #[tokio::test]
    async fn read_labels_skips_missing_label() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("labels");
        tokio::fs::write(&path, "aa:bb:cc:dd:ee:ff\n")
            .await
            .unwrap();
        assert!(read_labels(&path).await.is_empty());
    }

    #[tokio::test]
    async fn mac_in_file_case_insensitive_match() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("macs");
        tokio::fs::write(&path, "AA:BB:CC:DD:EE:FF\n")
            .await
            .unwrap();
        assert!(mac_in_file(&path, "aa:bb:cc:dd:ee:ff").await);
        assert!(!mac_in_file(&path, "11:22:33:44:55:66").await);
    }

    #[tokio::test]
    async fn read_pending_parses_mac_space_ip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pending");
        tokio::fs::write(&path, "AA:BB:CC:DD:EE:FF 10.0.0.5\n")
            .await
            .unwrap();
        let pending = read_pending(&path).await;
        assert_eq!(
            pending.get("aa:bb:cc:dd:ee:ff").map(|s| s.as_str()),
            Some("10.0.0.5")
        );
    }

    // ── read_device_rules / read_mac_ip_map / read_device_limits ─────────────

    #[tokio::test]
    async fn read_device_rules_parses_full_row() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rules");
        tokio::fs::write(
            &path,
            "AA:BB:CC:DD:EE:FF\texample.com\tallow\t443\ttcp\troute1\n",
        )
        .await
        .unwrap();
        let rules = read_device_rules(&path).await;
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].mac, "aa:bb:cc:dd:ee:ff");
        assert_eq!(rules[0].dst, "example.com");
        assert_eq!(rules[0].action, "allow");
        assert_eq!(rules[0].port, "443");
        assert_eq!(rules[0].proto, "tcp");
        assert_eq!(rules[0].route, "route1");
    }

    #[tokio::test]
    async fn read_device_rules_skips_row_missing_dst() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rules");
        tokio::fs::write(&path, "aa:bb:cc:dd:ee:ff\n")
            .await
            .unwrap();
        assert!(read_device_rules(&path).await.is_empty());
    }

    #[tokio::test]
    async fn read_mac_ip_map_parses_two_fields() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ips");
        tokio::fs::write(&path, "AA:BB:CC:DD:EE:FF\t10.0.0.5\n")
            .await
            .unwrap();
        let map = read_mac_ip_map(&path).await;
        assert_eq!(
            map.get("aa:bb:cc:dd:ee:ff").map(|s| s.as_str()),
            Some("10.0.0.5")
        );
    }

    #[tokio::test]
    async fn read_device_limits_parses_numeric_limit() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("limits");
        tokio::fs::write(&path, "AA:BB:CC:DD:EE:FF\t250\n")
            .await
            .unwrap();
        let map = read_device_limits(&path).await;
        assert_eq!(map.get("aa:bb:cc:dd:ee:ff").copied(), Some(250));
    }

    #[tokio::test]
    async fn read_device_limits_skips_non_numeric_limit() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("limits");
        tokio::fs::write(&path, "aa:bb:cc:dd:ee:ff\tunlimited\n")
            .await
            .unwrap();
        assert!(read_device_limits(&path).await.is_empty());
    }

    #[tokio::test]
    async fn read_allowed_macs_parses_three_fields() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("allowed");
        tokio::fs::write(&path, "AA:BB:CC:DD:EE:FF\t10.0.0.5\tAlice\n")
            .await
            .unwrap();
        let macs = read_allowed_macs(&path).await;
        assert_eq!(macs.len(), 1);
        assert_eq!(macs[0].mac, "aa:bb:cc:dd:ee:ff");
        assert_eq!(macs[0].ip, "10.0.0.5");
        assert_eq!(macs[0].label, "Alice");
    }

    /// Matches the file's real, human-edited shape — see `install.sh`'s
    /// `MACEOF` heredoc: a `#`-commented header/example, then
    /// whitespace-(not tab-)separated real entries.
    #[tokio::test]
    async fn read_allowed_macs_skips_comments_and_blanks_and_handles_multi_space_columns() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("allowed");
        tokio::fs::write(
            &path,
            "# Devices allowed on the untrusted network.\n\
             # Format: mac  ip  description\n\
             \n\
             aa:bb:cc:dd:ee:02  192.168.4.232  My Test Device\n",
        )
        .await
        .unwrap();
        let macs = read_allowed_macs(&path).await;
        assert_eq!(
            macs.len(),
            1,
            "comment/blank lines must not be ingested as fake entries: {macs:?}"
        );
        assert_eq!(macs[0].mac, "aa:bb:cc:dd:ee:02");
        assert_eq!(macs[0].ip, "192.168.4.232");
        assert_eq!(macs[0].label, "My Test Device");
    }

    #[tokio::test]
    async fn read_pending_conns_parses_four_fields() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pending-conn");
        tokio::fs::write(&path, "1.2.3.4\t443\ttcp\t1000\n")
            .await
            .unwrap();
        let conns = read_pending_conns(&path).await;
        assert_eq!(conns.len(), 1);
        assert_eq!(conns[0].dst, "1.2.3.4");
        assert_eq!(conns[0].port, "443");
        assert_eq!(conns[0].proto, "tcp");
        assert_eq!(conns[0].ts, 1000);
    }

    #[tokio::test]
    async fn read_pending_conns_defaults_missing_ts_to_zero() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pending-conn");
        tokio::fs::write(&path, "1.2.3.4\t443\ttcp\n")
            .await
            .unwrap();
        let conns = read_pending_conns(&path).await;
        assert_eq!(conns[0].ts, 0);
    }

    // ── OUI lookup ────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn read_oui_and_lookup_prefers_most_specific_prefix() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("oui");
        // 6-char (MA-L) and 9-char (MA-S) prefixes, per oui_lookup's [9, 7, 6] search order.
        tokio::fs::write(&path, "AABBCC\tGeneric Corp\nAABBCCDDE\tSpecific Corp\n")
            .await
            .unwrap();
        let oui = read_oui(&path).await;
        assert_eq!(oui_lookup(&oui, "AA:BB:CC:DD:E0:00"), "Specific Corp");
        assert_eq!(oui_lookup(&oui, "AA:BB:CC:11:22:33"), "Generic Corp");
    }

    #[test]
    fn oui_lookup_unknown_mac_returns_empty() {
        let oui = HashMap::new();
        assert_eq!(oui_lookup(&oui, "AA:BB:CC:DD:EE:FF"), "");
    }

    // ── is_valid_iface ────────────────────────────────────────────────────────

    #[test]
    fn is_valid_iface_accepts_alphanumeric_and_underscore() {
        assert!(is_valid_iface("guest"));
        assert!(is_valid_iface("mv_bg"));
    }

    #[test]
    fn is_valid_iface_rejects_empty_and_path_traversal() {
        assert!(!is_valid_iface(""));
        assert!(!is_valid_iface("../../etc/cron.d/evil"));
        assert!(!is_valid_iface("guest/../../etc"));
        assert!(!is_valid_iface("guest\n evil"));
    }

    // ── is_valid_mac ──────────────────────────────────────────────────────────

    #[test]
    fn is_valid_mac_accepts_well_formed() {
        assert!(is_valid_mac("aa:bb:cc:dd:ee:ff"));
        assert!(is_valid_mac("AA:BB:CC:DD:EE:FF"));
    }

    #[test]
    fn is_valid_mac_rejects_wrong_length_and_separator() {
        assert!(!is_valid_mac("aa:bb:cc:dd:ee"));
        assert!(!is_valid_mac("aa-bb-cc-dd-ee-ff"));
        assert!(!is_valid_mac(""));
    }

    #[test]
    fn is_valid_mac_rejects_non_hex() {
        assert!(!is_valid_mac("zz:bb:cc:dd:ee:ff"));
    }

    // ── is_valid_domain ───────────────────────────────────────────────────────

    #[test]
    fn is_valid_domain_accepts_well_formed_hostnames() {
        assert!(is_valid_domain("example.com"));
        assert!(is_valid_domain("api-v2.example.co.uk"));
    }

    #[test]
    fn is_valid_domain_rejects_empty_and_leading_trailing_dot() {
        assert!(!is_valid_domain(""));
        assert!(!is_valid_domain(".example.com"));
        assert!(!is_valid_domain("example.com."));
    }

    #[test]
    fn is_valid_domain_rejects_shell_and_path_metacharacters() {
        assert!(!is_valid_domain("example.com/../../etc/passwd"));
        assert!(!is_valid_domain("example.com\ninjected"));
        assert!(!is_valid_domain("example.com;rm -rf /"));
        assert!(!is_valid_domain("example.com\t/etc"));
    }

    // ── is_randomized_mac ───────────────────────────────────────────────────

    #[test]
    fn is_randomized_mac_detects_locally_administered_bit() {
        assert!(is_randomized_mac("02:11:22:33:44:55"));
        assert!(is_randomized_mac("06:aa:bb:cc:dd:ee"));
        assert!(is_randomized_mac("0e:aa:bb:cc:dd:ee"));
    }

    #[test]
    fn is_randomized_mac_false_for_globally_unique_addresses() {
        assert!(!is_randomized_mac("00:11:22:33:44:55"));
        assert!(!is_randomized_mac("04:aa:bb:cc:dd:ee"));
    }

    #[test]
    fn is_randomized_mac_false_for_malformed_input() {
        assert!(!is_randomized_mac(""));
        assert!(!is_randomized_mac("not-a-mac"));
    }

    // ── File mutation helpers ─────────────────────────────────────────────────

    #[tokio::test]
    async fn file_upsert_by_mac_appends_when_absent() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("f");
        file_upsert_by_mac(&path, "aa:bb:cc:dd:ee:ff", "aa:bb:cc:dd:ee:ff\tAlice")
            .await
            .unwrap();
        let content = tokio::fs::read_to_string(&path).await.unwrap();
        assert_eq!(content, "aa:bb:cc:dd:ee:ff\tAlice\n");
    }

    #[tokio::test]
    async fn file_upsert_by_mac_replaces_existing_line() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("f");
        tokio::fs::write(
            &path,
            "aa:bb:cc:dd:ee:ff\tOldLabel\nbb:bb:bb:bb:bb:bb\tOther\n",
        )
        .await
        .unwrap();
        file_upsert_by_mac(&path, "AA:BB:CC:DD:EE:FF", "aa:bb:cc:dd:ee:ff\tNewLabel")
            .await
            .unwrap();
        let content = tokio::fs::read_to_string(&path).await.unwrap();
        assert_eq!(
            content,
            "aa:bb:cc:dd:ee:ff\tNewLabel\nbb:bb:bb:bb:bb:bb\tOther\n"
        );
    }

    #[tokio::test]
    async fn file_remove_by_mac_removes_matching_line_only() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("f");
        tokio::fs::write(&path, "aa:bb:cc:dd:ee:ff\tAlice\nbb:bb:bb:bb:bb:bb\tBob\n")
            .await
            .unwrap();
        file_remove_by_mac(&path, "AA:BB:CC:DD:EE:FF")
            .await
            .unwrap();
        let content = tokio::fs::read_to_string(&path).await.unwrap();
        assert_eq!(content, "bb:bb:bb:bb:bb:bb\tBob\n");
    }

    #[tokio::test]
    async fn file_remove_rule_matches_mac_and_dst_only() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rules");
        tokio::fs::write(
            &path,
            "aa:bb:cc:dd:ee:ff\texample.com\tallow\t\t\naa:bb:cc:dd:ee:ff\tother.com\tallow\t\t\n",
        )
        .await
        .unwrap();
        file_remove_rule(&path, "aa:bb:cc:dd:ee:ff", "example.com")
            .await
            .unwrap();
        let content = tokio::fs::read_to_string(&path).await.unwrap();
        assert_eq!(content, "aa:bb:cc:dd:ee:ff\tother.com\tallow\t\t\n");
    }

    #[tokio::test]
    async fn file_remove_pending_matches_dst_port_proto_case_insensitive() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pending-conn");
        tokio::fs::write(&path, "1.2.3.4\t443\tTCP\t1000\n1.2.3.4\t80\ttcp\t1000\n")
            .await
            .unwrap();
        file_remove_pending(&path, "1.2.3.4", "443", "tcp")
            .await
            .unwrap();
        let content = tokio::fs::read_to_string(&path).await.unwrap();
        assert_eq!(content, "1.2.3.4\t80\ttcp\t1000\n");
    }

    // ── plugin notes ──────────────────────────────────────────────────────────

    #[tokio::test]
    async fn read_plugin_notes_parses_four_fields() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("plugin-notes");
        tokio::fs::write(
            &path,
            "aa:bb:cc:dd:ee:ff\t1.2.3.4\tmy-plugin\tflagged by my feed\n",
        )
        .await
        .unwrap();
        let notes = read_plugin_notes(&path).await;
        assert_eq!(notes.len(), 1);
        assert_eq!(notes[0].mac, "aa:bb:cc:dd:ee:ff");
        assert_eq!(notes[0].dst, "1.2.3.4");
        assert_eq!(notes[0].plugin_name, "my-plugin");
        assert_eq!(notes[0].note, "flagged by my feed");
    }

    #[tokio::test]
    async fn upsert_plugin_note_appends_when_absent() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("plugin-notes");
        upsert_plugin_note(
            &path,
            "AA:BB:CC:DD:EE:FF",
            "1.2.3.4",
            "my-plugin",
            "note one",
        )
        .await
        .unwrap();
        let notes = read_plugin_notes(&path).await;
        assert_eq!(notes.len(), 1);
        assert_eq!(notes[0].note, "note one");
    }

    #[tokio::test]
    async fn upsert_plugin_note_replaces_existing_entry_for_same_mac_and_dst() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("plugin-notes");
        upsert_plugin_note(
            &path,
            "aa:bb:cc:dd:ee:ff",
            "1.2.3.4",
            "my-plugin",
            "old note",
        )
        .await
        .unwrap();
        upsert_plugin_note(
            &path,
            "aa:bb:cc:dd:ee:ff",
            "1.2.3.4",
            "my-plugin",
            "new note",
        )
        .await
        .unwrap();
        let notes = read_plugin_notes(&path).await;
        assert_eq!(notes.len(), 1);
        assert_eq!(notes[0].note, "new note");
    }

    #[tokio::test]
    async fn upsert_plugin_note_keeps_notes_for_other_destinations() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("plugin-notes");
        upsert_plugin_note(&path, "aa:bb:cc:dd:ee:ff", "1.2.3.4", "my-plugin", "note a")
            .await
            .unwrap();
        upsert_plugin_note(&path, "aa:bb:cc:dd:ee:ff", "5.6.7.8", "my-plugin", "note b")
            .await
            .unwrap();
        let notes = read_plugin_notes(&path).await;
        assert_eq!(notes.len(), 2);
    }

    // ── is_valid_plugin_name ──────────────────────────────────────────────────

    #[test]
    fn is_valid_plugin_name_accepts_filenames_and_rust_plugin_names() {
        assert!(is_valid_plugin_name("log-everything.sh"));
        assert!(is_valid_plugin_name("device-approved-notifier"));
    }

    #[test]
    fn is_valid_plugin_name_rejects_empty_dot_dotdot_and_path_separators() {
        assert!(!is_valid_plugin_name(""));
        assert!(!is_valid_plugin_name("."));
        assert!(!is_valid_plugin_name(".."));
        assert!(!is_valid_plugin_name("a/b"));
        assert!(!is_valid_plugin_name("../etc/passwd"));
    }

    #[tokio::test]
    async fn file_remove_line_case_insensitive() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("f");
        tokio::fs::write(&path, "AA:BB:CC:DD:EE:FF\nbb:bb:bb:bb:bb:bb\n")
            .await
            .unwrap();
        file_remove_line(&path, "aa:bb:cc:dd:ee:ff").await.unwrap();
        let content = tokio::fs::read_to_string(&path).await.unwrap();
        assert_eq!(content, "bb:bb:bb:bb:bb:bb\n");
    }

    #[tokio::test]
    async fn file_remove_space_prefix_matches_first_token_only() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("f");
        tokio::fs::write(
            &path,
            "AA:BB:CC:DD:EE:FF 10.0.0.5\nbb:bb:bb:bb:bb:bb 10.0.0.6\n",
        )
        .await
        .unwrap();
        file_remove_space_prefix(&path, "aa:bb:cc:dd:ee:ff")
            .await
            .unwrap();
        let content = tokio::fs::read_to_string(&path).await.unwrap();
        assert_eq!(content, "bb:bb:bb:bb:bb:bb 10.0.0.6\n");
    }

    #[tokio::test]
    async fn file_append_creates_file_and_adds_newline() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("f");
        file_append(&path, "first").await.unwrap();
        file_append(&path, "second\n").await.unwrap();
        let content = tokio::fs::read_to_string(&path).await.unwrap();
        assert_eq!(content, "first\nsecond\n");
    }

    #[tokio::test]
    async fn prune_and_read_pending_drops_entries_older_than_cutoff() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pending-conn");
        tokio::fs::write(&path, "1.2.3.4\t443\ttcp\t100\n1.2.3.4\t80\ttcp\t2000\n")
            .await
            .unwrap();
        let kept = prune_and_read_pending(&path, 1000).await;
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].port, "80");
        let content = tokio::fs::read_to_string(&path).await.unwrap();
        assert_eq!(content, "1.2.3.4\t80\ttcp\t2000\n");
    }

    #[tokio::test]
    async fn prune_and_read_pending_removes_file_when_all_stale() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pending-conn");
        tokio::fs::write(&path, "1.2.3.4\t443\ttcp\t100\n")
            .await
            .unwrap();
        let kept = prune_and_read_pending(&path, 1000).await;
        assert!(kept.is_empty());
        assert!(!path.exists());
    }
}
