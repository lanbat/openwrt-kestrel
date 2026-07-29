//! Checks a handful of FQDNs against locally-cached domain threat-intel
//! feeds (`{base_dir}/threat-domains.txt`, refreshed by
//! `kestreld --update-threat-intel` — see `crate::threat_intel_update`).
//!
//! File format: `domain\tfeed_id` per line, one line per (domain, feed)
//! pair — a domain flagged by more than one feed appears once per feed, so
//! every match can be shown, not just the first. This mirrors
//! `data::banip`'s per-feed attribution for IPs, but for hostnames.
//!
//! Unlike `data::adblock::flag_domains` (which stops scanning as soon as
//! every queried domain has *a* match, since it only needs a yes/no), this
//! always scans the whole file, since a domain already matched by one feed
//! might still match another further down. That's an acceptable tradeoff
//! here — the feeds this project fetches (see `threat_intel_update.rs`) are
//! tens of thousands of lines, not adblock's tens of millions.

use std::collections::{HashMap, HashSet};
use std::path::Path;
use tokio::io::{AsyncBufReadExt, BufReader};

/// Short human description of a threat-feed id, for display next to a
/// flagged domain. Unrecognized ids still show the raw feed name.
pub fn describe(feed: &str) -> String {
    match feed {
        "urlhaus" => "Malware distribution host (abuse.ch URLhaus)".to_string(),
        "openphish" => "Phishing host (OpenPhish)".to_string(),
        other => format!("Flagged by threat feed \"{other}\""),
    }
}

/// For each domain in `queried`, the list of feed ids that flag it (or a
/// parent of it) — empty when not flagged by anything. Domains not found
/// (including when the file is missing, e.g. `--update-threat-intel` has
/// never run) simply map to an empty list.
pub async fn lookup_domains(list_path: &Path, queried: &[String]) -> HashMap<String, Vec<String>> {
    let mut needed: HashSet<String> = HashSet::new();
    for d in queried {
        for suffix in suffixes(d) {
            needed.insert(suffix);
        }
    }
    if needed.is_empty() {
        return HashMap::new();
    }

    let mut matched: HashMap<String, HashSet<String>> = HashMap::new();
    if let Ok(file) = tokio::fs::File::open(list_path).await {
        let mut lines = BufReader::new(file).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let mut f = line.splitn(2, '\t');
            let Some(dom) = f.next() else { continue };
            if !needed.contains(dom) {
                continue;
            }
            let feed = f.next().unwrap_or("unknown");
            matched.entry(dom.to_string()).or_default().insert(feed.to_string());
        }
    }

    queried
        .iter()
        .map(|d| {
            let mut feeds: Vec<String> = suffixes(d)
                .iter()
                .filter_map(|s| matched.get(s))
                .flat_map(|set| set.iter().cloned())
                .collect();
            feeds.sort();
            feeds.dedup();
            (d.clone(), feeds)
        })
        .collect()
}

/// A domain and all of its parents up to (but not including) the bare TLD —
/// same rationale as `adblock::suffixes`: a feed entry for `example.com`
/// should also flag `sub.example.com`.
fn suffixes(domain: &str) -> Vec<String> {
    let labels: Vec<&str> = domain.trim_end_matches('.').split('.').collect();
    if labels.len() < 2 {
        return Vec::new();
    }
    (0..labels.len() - 1).map(|i| labels[i..].join(".")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn write_fixture(lines: &[&str]) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        tokio::fs::write(dir.path().join("threat-domains.txt"), lines.join("\n")).await.unwrap();
        dir
    }

    #[test]
    fn suffixes_covers_domain_and_parents_but_not_bare_tld() {
        assert_eq!(
            suffixes("mal.evil.example.com"),
            vec!["mal.evil.example.com", "evil.example.com", "example.com"]
        );
    }

    #[test]
    fn suffixes_of_bare_tld_is_empty() {
        assert!(suffixes("com").is_empty());
    }

    #[tokio::test]
    async fn flags_exact_match_with_single_feed() {
        let dir = write_fixture(&["evil.example.com\turlhaus"]).await;
        let path = dir.path().join("threat-domains.txt");
        let result = lookup_domains(&path, &["evil.example.com".to_string()]).await;
        assert_eq!(result.get("evil.example.com"), Some(&vec!["urlhaus".to_string()]));
    }

    #[tokio::test]
    async fn flags_with_multiple_feeds_when_present_in_both() {
        let dir = write_fixture(&["evil.example.com\turlhaus", "evil.example.com\topenphish"]).await;
        let path = dir.path().join("threat-domains.txt");
        let result = lookup_domains(&path, &["evil.example.com".to_string()]).await;
        assert_eq!(result.get("evil.example.com"), Some(&vec!["openphish".to_string(), "urlhaus".to_string()]));
    }

    #[tokio::test]
    async fn flags_via_parent_domain_match() {
        let dir = write_fixture(&["evil.example.com\turlhaus"]).await;
        let path = dir.path().join("threat-domains.txt");
        let result = lookup_domains(&path, &["sub.evil.example.com".to_string()]).await;
        assert_eq!(result.get("sub.evil.example.com"), Some(&vec!["urlhaus".to_string()]));
    }

    #[tokio::test]
    async fn unflagged_domain_maps_to_empty() {
        let dir = write_fixture(&["evil.example.com\turlhaus"]).await;
        let path = dir.path().join("threat-domains.txt");
        let result = lookup_domains(&path, &["good.example.com".to_string()]).await;
        assert_eq!(result.get("good.example.com"), Some(&Vec::<String>::new()));
    }

    #[tokio::test]
    async fn missing_list_file_flags_everything_empty() {
        let path = Path::new("/nonexistent/threat-domains.txt");
        let result = lookup_domains(path, &["evil.example.com".to_string()]).await;
        assert_eq!(result.get("evil.example.com"), Some(&Vec::<String>::new()));
    }

    #[tokio::test]
    async fn empty_queried_list_short_circuits() {
        let result = lookup_domains(Path::new("/nonexistent"), &[]).await;
        assert!(result.is_empty());
    }

    #[test]
    fn describe_known_feeds() {
        assert_eq!(describe("urlhaus"), "Malware distribution host (abuse.ch URLhaus)");
        assert_eq!(describe("openphish"), "Phishing host (OpenPhish)");
    }

    #[test]
    fn describe_unknown_feed_falls_back_to_generic_label() {
        assert_eq!(describe("mystery"), "Flagged by threat feed \"mystery\"");
    }
}
