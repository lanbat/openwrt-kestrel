//! `kestreld --update-threat-intel`: downloads domain threat-intel feeds
//! and writes them to `{base_dir}/threat-domains.txt` as `domain\tfeed_id`
//! lines (one line per domain/feed pair, so a domain flagged by more than
//! one feed keeps every match) for `data::threat_domains::lookup_domains`
//! to check DNS-query/resolved-domain entries against on the device page.
//!
//! Follows the exact shape of `oui_update.rs` rather than a live per-lookup
//! query: no HTTP client crate exists in this project, `curl` is already
//! the established way to pull remote data (see `cmd::run`), and a batch
//! fetch-to-local-file means the dashboard never blocks on a network call
//! to render a page. All sources are attempted regardless of individual
//! failures, same as `oui_update.rs`.
//!
//! Sources (both free, no API key required):
//!   1. abuse.ch URLhaus "hostfile" — a plain `/etc/hosts`-style list
//!      (`127.0.0.1 malicious.example`), domains already bare.
//!   2. OpenPhish's free feed — one full URL per line; the hostname is
//!      extracted from each.

use std::collections::HashSet;
use std::path::Path;

use crate::cmd;

const URLHAUS_HOSTFILE_URL: &str = "https://urlhaus.abuse.ch/downloads/hostfile/";
const OPENPHISH_FEED_URL: &str = "https://openphish.com/feed.txt";

async fn fetch(url: &str, timeout_secs: &str) -> Option<String> {
    let (ok, out) = cmd::run("curl", &["-sf", "--max-time", timeout_secs, url]).await;
    if ok {
        Some(out)
    } else {
        None
    }
}

/// Parses a `/etc/hosts`-style hostfile: `#`-comments and blank lines
/// skipped, domain is the second whitespace-separated field.
fn parse_hostfile(body: &str) -> Vec<String> {
    body.lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                return None;
            }
            let mut fields = line.split_whitespace();
            let _ip = fields.next()?;
            let domain = fields.next()?;
            if domain.is_empty() {
                None
            } else {
                Some(domain.to_lowercase())
            }
        })
        .collect()
}

/// Extracts the hostname from a URL, without a URL-parsing crate: strips
/// the scheme, takes everything up to the first `/`/`?`/`#`, strips any
/// userinfo (`user@`) and port (`:N`).
fn extract_host(url: &str) -> Option<String> {
    let rest = url
        .trim()
        .split_once("://")
        .map(|(_, r)| r)
        .unwrap_or(url.trim());
    let host = rest.split(['/', '?', '#']).next()?;
    let host = host.rsplit_once('@').map(|(_, h)| h).unwrap_or(host);
    let host = host.rsplit_once(':').map(|(h, _)| h).unwrap_or(host);
    if host.is_empty() {
        None
    } else {
        Some(host.to_lowercase())
    }
}

/// Runs the full update; returns the process exit code (0 at least one
/// source succeeded, 1 every source failed) — mirrors `oui_update::run`'s
/// shape. On total failure the existing on-disk file is left untouched.
pub async fn run(base_dir: &Path) -> i32 {
    println!("Updating domain threat-intel feeds...");

    let store = match crate::db::Store::open(base_dir).await {
        Ok(s) => s,
        Err(e) => {
            println!("ERROR: failed to open kestrel.sqlite: {e}");
            return 1;
        }
    };

    // Replaced per-feed rather than as one combined write — unlike the
    // flat file this replaced (a single whole-file overwrite every run,
    // which silently dropped a *failed* source's previously-fetched
    // domains the moment any other source succeeded), each feed's rows
    // are only touched when that specific fetch succeeds. A source that
    // fails this round keeps whatever it fetched last time, matching
    // this module's own "best-effort per-source" doc comment more
    // faithfully than the old implementation actually did.
    let mut ok_count = 0;

    match fetch(URLHAUS_HOSTFILE_URL, "60").await {
        Some(body) => {
            println!("  urlhaus hostfile : ok");
            ok_count += 1;
            let mut seen = HashSet::new();
            let domains: Vec<String> = parse_hostfile(&body)
                .into_iter()
                .filter(|d| seen.insert(d.clone()))
                .collect();
            let count = domains.len();
            if store
                .replace_threat_feed("urlhaus", &domains)
                .await
                .is_err()
            {
                println!("ERROR: failed to write urlhaus feed");
            } else {
                println!("    {count} domains");
            }
        }
        None => println!("  urlhaus hostfile : failed"),
    }

    match fetch(OPENPHISH_FEED_URL, "30").await {
        Some(body) => {
            println!("  openphish feed   : ok");
            ok_count += 1;
            let mut seen = HashSet::new();
            let domains: Vec<String> = body
                .lines()
                .filter_map(extract_host)
                .filter(|d| seen.insert(d.clone()))
                .collect();
            let count = domains.len();
            if store
                .replace_threat_feed("openphish", &domains)
                .await
                .is_err()
            {
                println!("ERROR: failed to write openphish feed");
            } else {
                println!("    {count} domains");
            }
        }
        None => println!("  openphish feed   : failed"),
    }

    if ok_count == 0 {
        println!("All sources failed — keeping existing database");
        return 1;
    }

    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_hostfile_skipping_comments_and_blanks() {
        let body = "# Abuse.ch URLhaus\n#\n\n127.0.0.1 evil.example.com\n127.0.0.1 bad.example\n";
        assert_eq!(
            parse_hostfile(body),
            vec!["evil.example.com", "bad.example"]
        );
    }

    #[test]
    fn lowercases_domains() {
        let body = "127.0.0.1 EVIL.EXAMPLE.COM\n";
        assert_eq!(parse_hostfile(body), vec!["evil.example.com"]);
    }

    #[test]
    fn skips_lines_missing_a_domain_field() {
        let body = "127.0.0.1\n";
        assert!(parse_hostfile(body).is_empty());
    }

    #[test]
    fn extract_host_strips_scheme_and_path() {
        assert_eq!(
            extract_host("https://evil.example.com/phish/login"),
            Some("evil.example.com".to_string())
        );
    }

    #[test]
    fn extract_host_strips_port_and_query() {
        assert_eq!(
            extract_host("http://evil.example.com:8080/x?y=1"),
            Some("evil.example.com".to_string())
        );
    }

    #[test]
    fn extract_host_strips_userinfo() {
        assert_eq!(
            extract_host("https://user:pass@evil.example.com/"),
            Some("evil.example.com".to_string())
        );
    }

    #[test]
    fn extract_host_lowercases() {
        assert_eq!(
            extract_host("https://EVIL.EXAMPLE.COM/"),
            Some("evil.example.com".to_string())
        );
    }

    #[test]
    fn extract_host_handles_bare_host_without_scheme() {
        assert_eq!(
            extract_host("evil.example.com/path"),
            Some("evil.example.com".to_string())
        );
    }
}

#[cfg(test)]
mod network_tests {
    use super::*;

    /// Hits the real network — not run by default. `cargo test --offline
    /// --lib -- --ignored threat_intel_update::network_tests` to run manually.
    #[tokio::test]
    #[ignore]
    async fn full_run_against_real_sources_writes_a_populated_file() {
        let dir = tempfile::tempdir().unwrap();
        let code = run(dir.path()).await;
        assert_eq!(code, 0);
        let store = crate::db::Store::open(dir.path()).await.unwrap();
        let count = store.count_threat_domains().await.unwrap();
        assert!(
            count > 100,
            "expected a substantial feed, got {count} entries"
        );
    }
}
