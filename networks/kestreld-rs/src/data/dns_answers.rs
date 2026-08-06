//! Persisted DNS query→answer log, per device: `{iface}-dns-answers-{mac_n}`,
//! `ts\tdomain\tip` per resolved (non-CNAME, non-NXDOMAIN) answer. Populated
//! by `daemon.rs`'s `logread -f` follower, which pairs a dnsmasq `query[...]`
//! line with the `reply ... is <ip>` line that answers it (see
//! `data::logs::parse_dns_query_line`/`parse_dns_reply_line`).
//!
//! This exists so a later IP-only connection attempt can be attributed back
//! to the domain that resolved to it — DNS answers and netfilter connection
//! events are otherwise two disconnected streams.

use std::path::Path;

use super::files;

/// A day, in seconds — how long `-dns-answers-*` files are pruned to.
pub const RETENTION_SECS: u64 = 7 * 24 * 3600;

/// How far back a connection may look for the DNS answer that "caused" it.
/// A resolver can reuse a cached answer well past the original query, so
/// this is generous rather than assuming near-simultaneous timing.
pub const CORRELATION_WINDOW_SECS: u64 = 6 * 3600;

#[derive(Clone, Debug)]
pub struct DnsAnswer {
    pub ts: u64,
    pub domain: String,
    pub ip: String,
}

pub async fn read_dns_answers(path: &Path) -> Vec<DnsAnswer> {
    files::read_lines(path)
        .await
        .into_iter()
        .filter_map(|l| {
            let mut f = l.splitn(3, '\t');
            let ts: u64 = f.next()?.trim().parse().ok()?;
            let domain = f.next()?.trim().to_string();
            let ip = f.next()?.trim().to_string();
            if domain.is_empty() || ip.is_empty() {
                None
            } else {
                Some(DnsAnswer { ts, domain, ip })
            }
        })
        .collect()
}

/// Prune entries older than `cutoff_ts`, rewrite the file, and return what's kept.
pub async fn prune_and_read(path: &Path, cutoff_ts: u64) -> Vec<DnsAnswer> {
    let answers = read_dns_answers(path).await;
    let kept: Vec<DnsAnswer> = answers.into_iter().filter(|a| a.ts >= cutoff_ts).collect();
    if !kept.is_empty() {
        let content: String = kept
            .iter()
            .map(|a| format!("{}\t{}\t{}\n", a.ts, a.domain, a.ip))
            .collect();
        let _ = files::write_atomic(path, content).await;
    } else if path.exists() {
        let _ = tokio::fs::remove_file(path).await;
    }
    kept
}

/// Given a device's already-read DNS-answer entries, find the domain most
/// recently resolved to `ip` at or before `ts` (a connection can only be
/// "caused" by an answer that happened before it), within
/// `CORRELATION_WINDOW_SECS`. Pure/testable — I/O lives in `correlate_ip`.
pub fn correlate_ip(entries: &[DnsAnswer], ip: &str, ts: u64) -> Option<String> {
    entries
        .iter()
        .filter(|a| a.ip == ip && a.ts <= ts && ts - a.ts <= CORRELATION_WINDOW_SECS)
        .max_by_key(|a| a.ts)
        .map(|a| a.domain.clone())
}

/// Given a device's already-read DNS-answer entries, find the most recent IP
/// a domain resolved to (regardless of when, since this is just "what did
/// this domain last resolve to for this device" for display purposes, not a
/// connection-timing correlation).
pub fn most_recent_ip_for_domain(entries: &[DnsAnswer], domain: &str) -> Option<String> {
    entries
        .iter()
        .filter(|a| a.domain == domain)
        .max_by_key(|a| a.ts)
        .map(|a| a.ip.clone())
}

/// Read (post-pruning) a device's DNS-answer file and correlate an IP back
/// to the domain that resolved to it, if any.
pub async fn correlate(
    base_dir: &Path,
    iface: &str,
    mac_n: &str,
    ip: &str,
    ts: u64,
) -> Option<String> {
    let path = base_dir.join(format!("{iface}-dns-answers-{mac_n}"));
    let cutoff = ts.saturating_sub(RETENTION_SECS);
    let entries = prune_and_read(&path, cutoff).await;
    correlate_ip(&entries, ip, ts)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn answer(ts: u64, domain: &str, ip: &str) -> DnsAnswer {
        DnsAnswer {
            ts,
            domain: domain.to_string(),
            ip: ip.to_string(),
        }
    }

    #[test]
    fn correlate_ip_finds_matching_domain_before_connection() {
        let entries = vec![answer(1000, "example.com", "93.184.216.34")];
        assert_eq!(
            correlate_ip(&entries, "93.184.216.34", 1100),
            Some("example.com".to_string())
        );
    }

    #[test]
    fn correlate_ip_ignores_answers_after_the_connection() {
        let entries = vec![answer(2000, "example.com", "93.184.216.34")];
        assert_eq!(correlate_ip(&entries, "93.184.216.34", 1000), None);
    }

    #[test]
    fn correlate_ip_ignores_answers_outside_the_window() {
        let entries = vec![answer(1000, "example.com", "93.184.216.34")];
        let ts = 1000 + CORRELATION_WINDOW_SECS + 1;
        assert_eq!(correlate_ip(&entries, "93.184.216.34", ts), None);
    }

    #[test]
    fn correlate_ip_prefers_most_recent_matching_answer() {
        let entries = vec![
            answer(1000, "old.example.com", "93.184.216.34"),
            answer(1500, "new.example.com", "93.184.216.34"),
        ];
        assert_eq!(
            correlate_ip(&entries, "93.184.216.34", 1600),
            Some("new.example.com".to_string())
        );
    }

    #[test]
    fn correlate_ip_no_match_for_different_ip() {
        let entries = vec![answer(1000, "example.com", "93.184.216.34")];
        assert_eq!(correlate_ip(&entries, "1.2.3.4", 1100), None);
    }

    #[test]
    fn most_recent_ip_for_domain_picks_latest() {
        let entries = vec![
            answer(1000, "example.com", "1.1.1.1"),
            answer(2000, "example.com", "2.2.2.2"),
        ];
        assert_eq!(
            most_recent_ip_for_domain(&entries, "example.com"),
            Some("2.2.2.2".to_string())
        );
    }

    #[tokio::test]
    async fn read_dns_answers_parses_three_fields() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("dns-answers");
        tokio::fs::write(&path, "1000\texample.com\t93.184.216.34\n")
            .await
            .unwrap();
        let answers = read_dns_answers(&path).await;
        assert_eq!(answers.len(), 1);
        assert_eq!(answers[0].ts, 1000);
        assert_eq!(answers[0].domain, "example.com");
        assert_eq!(answers[0].ip, "93.184.216.34");
    }

    #[tokio::test]
    async fn prune_and_read_drops_stale_entries() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("dns-answers");
        tokio::fs::write(
            &path,
            "100\told.example.com\t1.1.1.1\n2000\tnew.example.com\t2.2.2.2\n",
        )
        .await
        .unwrap();
        let kept = prune_and_read(&path, 1000).await;
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].domain, "new.example.com");
    }

    #[tokio::test]
    async fn correlate_reads_prunes_and_matches() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("guest-dns-answers-aabbccddeeff");
        tokio::fs::write(&path, "1000\texample.com\t93.184.216.34\n")
            .await
            .unwrap();
        let domain = correlate(dir.path(), "guest", "aabbccddeeff", "93.184.216.34", 1100).await;
        assert_eq!(domain, Some("example.com".to_string()));
    }
}
