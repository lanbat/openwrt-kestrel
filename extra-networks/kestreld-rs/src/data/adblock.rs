//! Checks queried domains against adblock's compiled dnsmasq blocklist
//! (`/etc/dnsmasq.d/adb_list.overall`) — one line per blocked domain, as
//! `local=/domain/` or `local=/domain/#`.
//!
//! Unlike banIP's feed sets (a few tens of thousands of IPs, parsed whole
//! into memory once per snapshot — see `data::banip`), this list is
//! merged from every enabled feed with no per-feed attribution left, and on
//! a real router runs into the millions of lines (46MB+). Loading that into
//! a HashSet on every snapshot refresh isn't worth it, so instead of
//! indexing the whole file we stream it once per call, checking membership
//! for only the handful of domains actually being displayed (a device
//! page's DNS query list, capped at 50 entries) and stopping early once
//! every one of them has been resolved either way.

use std::collections::{HashMap, HashSet};
use std::path::Path;
use tokio::io::{AsyncBufReadExt, BufReader};

pub const LIST_PATH: &str = "/etc/dnsmasq.d/adb_list.overall";

/// For each domain in `queried`, whether it (or a parent domain — adblock's
/// `local=/domain/` blocks the whole subtree) appears in the blocklist at
/// `list_path`. Domains not found (including when the file is missing,
/// e.g. adblock isn't installed) simply map to `false`.
pub async fn flag_domains(list_path: &Path, queried: &[String]) -> HashMap<String, bool> {
    let mut needed: HashSet<String> = HashSet::new();
    for d in queried {
        for suffix in suffixes(d) {
            needed.insert(suffix);
        }
    }
    if needed.is_empty() {
        return HashMap::new();
    }

    let mut matched: HashSet<String> = HashSet::new();
    if let Ok(file) = tokio::fs::File::open(list_path).await {
        let mut lines = BufReader::new(file).lines();
        while matched.len() < needed.len() {
            let Ok(Some(line)) = lines.next_line().await else { break };
            if let Some(dom) = parse_domain(&line) {
                if needed.contains(dom) {
                    matched.insert(dom.to_string());
                }
            }
        }
    }

    queried
        .iter()
        .map(|d| {
            let hit = suffixes(d).iter().any(|s| matched.contains(s));
            (d.clone(), hit)
        })
        .collect()
}

/// `example.com`'s subdomains block *it*; a domain blocks itself and every
/// parent up to (but not including) the bare TLD.
fn suffixes(domain: &str) -> Vec<String> {
    let labels: Vec<&str> = domain.trim_end_matches('.').split('.').collect();
    if labels.len() < 2 {
        return Vec::new();
    }
    (0..labels.len() - 1).map(|i| labels[i..].join(".")).collect()
}

/// Extracts the domain out of `local=/domain/` or `local=/domain/#`.
fn parse_domain(line: &str) -> Option<&str> {
    let rest = line.strip_prefix("local=/")?;
    let end = rest.find('/')?;
    Some(&rest[..end])
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn write_fixture(lines: &[&str]) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        tokio::fs::write(dir.path().join("adb_list.overall"), lines.join("\n")).await.unwrap();
        dir
    }

    #[test]
    fn parse_domain_handles_nxdomain_marker() {
        assert_eq!(parse_domain("local=/doubleclick.net/#"), Some("doubleclick.net"));
    }

    #[test]
    fn parse_domain_handles_bare_local_directive() {
        assert_eq!(parse_domain("local=/tracker.example.com/"), Some("tracker.example.com"));
    }

    #[test]
    fn parse_domain_rejects_unrelated_lines() {
        assert_eq!(parse_domain("address=/foo.com/0.0.0.0"), None);
    }

    #[test]
    fn suffixes_covers_domain_and_parents_but_not_bare_tld() {
        assert_eq!(
            suffixes("ads.tracker.example.com"),
            vec!["ads.tracker.example.com", "tracker.example.com", "example.com"]
        );
    }

    #[test]
    fn suffixes_of_bare_tld_is_empty() {
        assert!(suffixes("com").is_empty());
    }

    #[tokio::test]
    async fn flags_exact_match() {
        let dir = write_fixture(&["local=/doubleclick.net/#", "local=/other.example/#"]).await;
        let path = dir.path().join("adb_list.overall");
        let result = flag_domains(&path, &["doubleclick.net".to_string()]).await;
        assert_eq!(result.get("doubleclick.net"), Some(&true));
    }

    #[tokio::test]
    async fn flags_via_parent_domain_match() {
        let dir = write_fixture(&["local=/tracker.example.com/#"]).await;
        let path = dir.path().join("adb_list.overall");
        let result = flag_domains(&path, &["ads.tracker.example.com".to_string()]).await;
        assert_eq!(result.get("ads.tracker.example.com"), Some(&true));
    }

    #[tokio::test]
    async fn unflagged_domain_maps_to_false() {
        let dir = write_fixture(&["local=/doubleclick.net/#"]).await;
        let path = dir.path().join("adb_list.overall");
        let result = flag_domains(&path, &["google.com".to_string()]).await;
        assert_eq!(result.get("google.com"), Some(&false));
    }

    #[tokio::test]
    async fn missing_list_file_flags_everything_false() {
        let path = std::path::Path::new("/nonexistent/adb_list.overall");
        let result = flag_domains(path, &["doubleclick.net".to_string()]).await;
        assert_eq!(result.get("doubleclick.net"), Some(&false));
    }

    #[tokio::test]
    async fn empty_queried_list_short_circuits() {
        let result = flag_domains(Path::new("/nonexistent"), &[]).await;
        assert!(result.is_empty());
    }
}
