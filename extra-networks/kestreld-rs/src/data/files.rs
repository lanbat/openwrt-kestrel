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

fn parse_notify_conf(filename: &str, content: &str) -> Option<NetworkConf> {
    let vars = parse_sh_vars(content);
    let iface = vars
        .get("IFACE_NAME")
        .cloned()
        .or_else(|| {
            filename.strip_suffix("-notify.conf").map(|s| s.to_string())
        })?;

    if iface.is_empty() {
        return None;
    }

    Some(NetworkConf {
        iface: iface.clone(),
        notify_url: vars.get("NOTIFY_URL").cloned().unwrap_or_default(),
        subnet: vars.get("SUBNET").cloned().unwrap_or_default(),
        rate_limit: vars.get("RATE_LIMIT").cloned().unwrap_or_default(),
        rate_limit_per_device: vars.get("RATE_LIMIT_PER_DEVICE").cloned().unwrap_or_default(),
        dns_server: vars.get("DNS_SERVER").cloned().unwrap_or_default(),
        dns_server_v6: vars.get("DNS_SERVER_V6").cloned().unwrap_or_default(),
        dot: vars.get("DOT").map(|v| v == "yes").unwrap_or(false),
        lan_access: vars.get("LAN_ACCESS").map(|v| v == "yes").unwrap_or(false),
        isolate: vars.get("ISOLATE").map(|v| v != "no").unwrap_or(true),
        notify_join: vars.get("NOTIFY_JOIN").map(|v| v == "yes").unwrap_or(false),
        join_approval: vars.get("JOIN_APPROVAL").map(|v| v == "yes").unwrap_or(false),
        join_history_retention: vars
            .get("JOIN_HISTORY_RETENTION")
            .cloned()
            .unwrap_or_else(|| "90d".to_string()),
        rotate_password: vars.get("ROTATE_PASSWORD").map(|v| v == "yes").unwrap_or(false),
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
        device_control: vars.get("DEVICE_CONTROL").map(|v| v == "yes").unwrap_or(false),
        default_duration: vars
            .get("DEFAULT_DURATION")
            .cloned()
            .unwrap_or_else(|| "24h".to_string()),
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
                let val = line[eq + 1..].trim_matches('"').trim_matches('\'').to_string();
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
            if mac.is_empty() || dst.is_empty() { None } else {
                Some(DeviceRule { mac, dst, action, port, proto, route })
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
            if mac.is_empty() || ip.is_empty() { None } else { Some((mac, ip)) }
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

pub async fn read_allowed_macs(path: &Path) -> Vec<AllowedMac> {
    read_lines(path)
        .await
        .into_iter()
        .filter_map(|l| {
            let mut f = l.splitn(3, '\t');
            let mac = f.next()?.trim().to_lowercase();
            let ip = f.next().unwrap_or("").trim().to_string();
            let label = f.next().unwrap_or("").trim().to_string();
            if mac.is_empty() { None } else { Some(AllowedMac { mac, ip, label }) }
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
            if dst.is_empty() { None } else { Some(PendingConn { dst, port, proto, ts }) }
        })
        .collect()
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
            if prefix.is_empty() { None } else { Some((prefix, vendor)) }
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

// ── File mutation helpers ─────────────────────────────────────────────────────

async fn write_atomic(path: &Path, content: String) -> std::io::Result<()> {
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
pub async fn file_remove_pending(path: &Path, dst: &str, port: &str, proto: &str) -> std::io::Result<()> {
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

/// Read /tmp/extra-networks-joins: `mac<TAB>timestamp`
pub async fn read_joins() -> HashMap<String, String> {
    let path = Path::new("/tmp/extra-networks-joins");
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
        assert_eq!(vars.get("URL").map(|s| s.as_str()), Some("https://example.com/path?a=1"));
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
        assert_eq!(vars.get("BANDWIDTH_THRESHOLD_MB").map(|s| s.as_str()), Some("100"));
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
        tokio::fs::write(&path, "AA:BB:CC:DD:EE:FF\tAlice's Phone\n").await.unwrap();
        let labels = read_labels(&path).await;
        assert_eq!(labels.get("aa:bb:cc:dd:ee:ff").map(|s| s.as_str()), Some("Alice's Phone"));
    }

    #[tokio::test]
    async fn read_labels_skips_missing_label() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("labels");
        tokio::fs::write(&path, "aa:bb:cc:dd:ee:ff\n").await.unwrap();
        assert!(read_labels(&path).await.is_empty());
    }

    #[tokio::test]
    async fn mac_in_file_case_insensitive_match() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("macs");
        tokio::fs::write(&path, "AA:BB:CC:DD:EE:FF\n").await.unwrap();
        assert!(mac_in_file(&path, "aa:bb:cc:dd:ee:ff").await);
        assert!(!mac_in_file(&path, "11:22:33:44:55:66").await);
    }

    #[tokio::test]
    async fn read_pending_parses_mac_space_ip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pending");
        tokio::fs::write(&path, "AA:BB:CC:DD:EE:FF 10.0.0.5\n").await.unwrap();
        let pending = read_pending(&path).await;
        assert_eq!(pending.get("aa:bb:cc:dd:ee:ff").map(|s| s.as_str()), Some("10.0.0.5"));
    }

    // ── read_device_rules / read_mac_ip_map / read_device_limits ─────────────

    #[tokio::test]
    async fn read_device_rules_parses_full_row() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rules");
        tokio::fs::write(&path, "AA:BB:CC:DD:EE:FF\texample.com\tallow\t443\ttcp\troute1\n").await.unwrap();
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
        tokio::fs::write(&path, "aa:bb:cc:dd:ee:ff\n").await.unwrap();
        assert!(read_device_rules(&path).await.is_empty());
    }

    #[tokio::test]
    async fn read_mac_ip_map_parses_two_fields() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ips");
        tokio::fs::write(&path, "AA:BB:CC:DD:EE:FF\t10.0.0.5\n").await.unwrap();
        let map = read_mac_ip_map(&path).await;
        assert_eq!(map.get("aa:bb:cc:dd:ee:ff").map(|s| s.as_str()), Some("10.0.0.5"));
    }

    #[tokio::test]
    async fn read_device_limits_parses_numeric_limit() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("limits");
        tokio::fs::write(&path, "AA:BB:CC:DD:EE:FF\t250\n").await.unwrap();
        let map = read_device_limits(&path).await;
        assert_eq!(map.get("aa:bb:cc:dd:ee:ff").copied(), Some(250));
    }

    #[tokio::test]
    async fn read_device_limits_skips_non_numeric_limit() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("limits");
        tokio::fs::write(&path, "aa:bb:cc:dd:ee:ff\tunlimited\n").await.unwrap();
        assert!(read_device_limits(&path).await.is_empty());
    }

    #[tokio::test]
    async fn read_allowed_macs_parses_three_fields() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("allowed");
        tokio::fs::write(&path, "AA:BB:CC:DD:EE:FF\t10.0.0.5\tAlice\n").await.unwrap();
        let macs = read_allowed_macs(&path).await;
        assert_eq!(macs.len(), 1);
        assert_eq!(macs[0].mac, "aa:bb:cc:dd:ee:ff");
        assert_eq!(macs[0].ip, "10.0.0.5");
        assert_eq!(macs[0].label, "Alice");
    }

    #[tokio::test]
    async fn read_pending_conns_parses_four_fields() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pending-conn");
        tokio::fs::write(&path, "1.2.3.4\t443\ttcp\t1000\n").await.unwrap();
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
        tokio::fs::write(&path, "1.2.3.4\t443\ttcp\n").await.unwrap();
        let conns = read_pending_conns(&path).await;
        assert_eq!(conns[0].ts, 0);
    }

    // ── OUI lookup ────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn read_oui_and_lookup_prefers_most_specific_prefix() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("oui");
        // 6-char (MA-L) and 9-char (MA-S) prefixes, per oui_lookup's [9, 7, 6] search order.
        tokio::fs::write(&path, "AABBCC\tGeneric Corp\nAABBCCDDE\tSpecific Corp\n").await.unwrap();
        let oui = read_oui(&path).await;
        assert_eq!(oui_lookup(&oui, "AA:BB:CC:DD:E0:00"), "Specific Corp");
        assert_eq!(oui_lookup(&oui, "AA:BB:CC:11:22:33"), "Generic Corp");
    }

    #[test]
    fn oui_lookup_unknown_mac_returns_empty() {
        let oui = HashMap::new();
        assert_eq!(oui_lookup(&oui, "AA:BB:CC:DD:EE:FF"), "");
    }

    // ── File mutation helpers ─────────────────────────────────────────────────

    #[tokio::test]
    async fn file_upsert_by_mac_appends_when_absent() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("f");
        file_upsert_by_mac(&path, "aa:bb:cc:dd:ee:ff", "aa:bb:cc:dd:ee:ff\tAlice").await.unwrap();
        let content = tokio::fs::read_to_string(&path).await.unwrap();
        assert_eq!(content, "aa:bb:cc:dd:ee:ff\tAlice\n");
    }

    #[tokio::test]
    async fn file_upsert_by_mac_replaces_existing_line() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("f");
        tokio::fs::write(&path, "aa:bb:cc:dd:ee:ff\tOldLabel\nbb:bb:bb:bb:bb:bb\tOther\n").await.unwrap();
        file_upsert_by_mac(&path, "AA:BB:CC:DD:EE:FF", "aa:bb:cc:dd:ee:ff\tNewLabel").await.unwrap();
        let content = tokio::fs::read_to_string(&path).await.unwrap();
        assert_eq!(content, "aa:bb:cc:dd:ee:ff\tNewLabel\nbb:bb:bb:bb:bb:bb\tOther\n");
    }

    #[tokio::test]
    async fn file_remove_by_mac_removes_matching_line_only() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("f");
        tokio::fs::write(&path, "aa:bb:cc:dd:ee:ff\tAlice\nbb:bb:bb:bb:bb:bb\tBob\n").await.unwrap();
        file_remove_by_mac(&path, "AA:BB:CC:DD:EE:FF").await.unwrap();
        let content = tokio::fs::read_to_string(&path).await.unwrap();
        assert_eq!(content, "bb:bb:bb:bb:bb:bb\tBob\n");
    }

    #[tokio::test]
    async fn file_remove_rule_matches_mac_and_dst_only() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rules");
        tokio::fs::write(&path,
            "aa:bb:cc:dd:ee:ff\texample.com\tallow\t\t\naa:bb:cc:dd:ee:ff\tother.com\tallow\t\t\n"
        ).await.unwrap();
        file_remove_rule(&path, "aa:bb:cc:dd:ee:ff", "example.com").await.unwrap();
        let content = tokio::fs::read_to_string(&path).await.unwrap();
        assert_eq!(content, "aa:bb:cc:dd:ee:ff\tother.com\tallow\t\t\n");
    }

    #[tokio::test]
    async fn file_remove_pending_matches_dst_port_proto_case_insensitive() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pending-conn");
        tokio::fs::write(&path, "1.2.3.4\t443\tTCP\t1000\n1.2.3.4\t80\ttcp\t1000\n").await.unwrap();
        file_remove_pending(&path, "1.2.3.4", "443", "tcp").await.unwrap();
        let content = tokio::fs::read_to_string(&path).await.unwrap();
        assert_eq!(content, "1.2.3.4\t80\ttcp\t1000\n");
    }

    #[tokio::test]
    async fn file_remove_line_case_insensitive() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("f");
        tokio::fs::write(&path, "AA:BB:CC:DD:EE:FF\nbb:bb:bb:bb:bb:bb\n").await.unwrap();
        file_remove_line(&path, "aa:bb:cc:dd:ee:ff").await.unwrap();
        let content = tokio::fs::read_to_string(&path).await.unwrap();
        assert_eq!(content, "bb:bb:bb:bb:bb:bb\n");
    }

    #[tokio::test]
    async fn file_remove_space_prefix_matches_first_token_only() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("f");
        tokio::fs::write(&path, "AA:BB:CC:DD:EE:FF 10.0.0.5\nbb:bb:bb:bb:bb:bb 10.0.0.6\n").await.unwrap();
        file_remove_space_prefix(&path, "aa:bb:cc:dd:ee:ff").await.unwrap();
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
        tokio::fs::write(&path, "1.2.3.4\t443\ttcp\t100\n1.2.3.4\t80\ttcp\t2000\n").await.unwrap();
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
        tokio::fs::write(&path, "1.2.3.4\t443\ttcp\t100\n").await.unwrap();
        let kept = prune_and_read_pending(&path, 1000).await;
        assert!(kept.is_empty());
        assert!(!path.exists());
    }
}
