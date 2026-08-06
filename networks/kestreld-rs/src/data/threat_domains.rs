//! Checks a handful of FQDNs against locally-cached domain threat-intel
//! feeds (the `threat_domains` table in `Store`, refreshed by
//! `kestreld --update-threat-intel` — see `crate::threat_intel_update`).
//!
//! A domain flagged by more than one feed has one row per feed, so every
//! match can be shown, not just the first. This mirrors `data::banip`'s
//! per-feed attribution for IPs, but for hostnames.
//!
//! One indexed point lookup per candidate suffix, rather than a full
//! table/file scan — `data::adblock::flag_domains`'s "stop once every
//! queried domain has *a* match" shortcut doesn't apply here (a domain
//! already matched by one feed might still match another), but an indexed
//! lookup makes that moot: there's no full-scan cost to avoid in the first
//! place, unlike the flat-file version this replaced.

use crate::db::Store;
use std::collections::HashMap;

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
/// (including when `--update-threat-intel` has never run, so the table is
/// empty) simply map to an empty list.
pub async fn lookup_domains(store: &Store, queried: &[String]) -> HashMap<String, Vec<String>> {
    let mut out = HashMap::new();
    for d in queried {
        let mut feeds: Vec<String> = Vec::new();
        for suffix in suffixes(d) {
            feeds.extend(store.threat_domain_feeds(&suffix).await.unwrap_or_default());
        }
        feeds.sort();
        feeds.dedup();
        out.insert(d.clone(), feeds);
    }
    out
}

/// A domain and all of its parents up to (but not including) the bare TLD —
/// same rationale as `adblock::suffixes`: a feed entry for `example.com`
/// should also flag `sub.example.com`.
fn suffixes(domain: &str) -> Vec<String> {
    let labels: Vec<&str> = domain.trim_end_matches('.').split('.').collect();
    if labels.len() < 2 {
        return Vec::new();
    }
    (0..labels.len() - 1)
        .map(|i| labels[i..].join("."))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn flags_exact_match_with_single_feed() {
        let store = Store::open_in_memory().unwrap();
        store
            .replace_threat_feed("urlhaus", &["evil.example.com".to_string()])
            .await
            .unwrap();
        let result = lookup_domains(&store, &["evil.example.com".to_string()]).await;
        assert_eq!(
            result.get("evil.example.com"),
            Some(&vec!["urlhaus".to_string()])
        );
    }

    #[tokio::test]
    async fn flags_with_multiple_feeds_when_present_in_both() {
        let store = Store::open_in_memory().unwrap();
        store
            .replace_threat_feed("urlhaus", &["evil.example.com".to_string()])
            .await
            .unwrap();
        store
            .replace_threat_feed("openphish", &["evil.example.com".to_string()])
            .await
            .unwrap();
        let result = lookup_domains(&store, &["evil.example.com".to_string()]).await;
        assert_eq!(
            result.get("evil.example.com"),
            Some(&vec!["openphish".to_string(), "urlhaus".to_string()])
        );
    }

    #[tokio::test]
    async fn flags_via_parent_domain_match() {
        let store = Store::open_in_memory().unwrap();
        store
            .replace_threat_feed("urlhaus", &["evil.example.com".to_string()])
            .await
            .unwrap();
        let result = lookup_domains(&store, &["sub.evil.example.com".to_string()]).await;
        assert_eq!(
            result.get("sub.evil.example.com"),
            Some(&vec!["urlhaus".to_string()])
        );
    }

    #[tokio::test]
    async fn unflagged_domain_maps_to_empty() {
        let store = Store::open_in_memory().unwrap();
        store
            .replace_threat_feed("urlhaus", &["evil.example.com".to_string()])
            .await
            .unwrap();
        let result = lookup_domains(&store, &["good.example.com".to_string()]).await;
        assert_eq!(result.get("good.example.com"), Some(&Vec::<String>::new()));
    }

    #[tokio::test]
    async fn empty_feed_table_flags_everything_empty() {
        let store = Store::open_in_memory().unwrap();
        let result = lookup_domains(&store, &["evil.example.com".to_string()]).await;
        assert_eq!(result.get("evil.example.com"), Some(&Vec::<String>::new()));
    }

    #[tokio::test]
    async fn empty_queried_list_short_circuits() {
        let store = Store::open_in_memory().unwrap();
        let result = lookup_domains(&store, &[]).await;
        assert!(result.is_empty());
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

    #[test]
    fn describe_known_feeds() {
        assert_eq!(
            describe("urlhaus"),
            "Malware distribution host (abuse.ch URLhaus)"
        );
        assert_eq!(describe("openphish"), "Phishing host (OpenPhish)");
    }

    #[test]
    fn describe_unknown_feed_falls_back_to_generic_label() {
        assert_eq!(describe("mystery"), "Flagged by threat feed \"mystery\"");
    }
}
