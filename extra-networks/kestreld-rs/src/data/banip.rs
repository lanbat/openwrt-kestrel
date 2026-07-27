//! Reads banIP's already-fetched threat-intel feeds (spamhaus, feodo,
//! dshield, turris, urlhaus, cinsscore, ...) straight out of the same
//! `nft list ruleset` text kestreld already parses for everything else
//! (`data::nft`). banIP compiles each enabled feed into its own nft set,
//! named `<feed>.v4`/`<feed>.v6`, inside `table inet banIP` — the `allowlist`
//! and `blocklist` sets are banIP's own merged sets, not feeds, and are
//! excluded. No extra process is spawned and no external calls are made;
//! this is a plain text scan of data kestreld already has in memory.

use std::net::IpAddr;

#[derive(Default, Clone)]
pub struct BanipFeeds {
    // (feed name, inclusive lo, inclusive hi), same address family per range.
    ranges: Vec<(String, IpAddr, IpAddr)>,
}

impl BanipFeeds {
    pub fn parse(nft_raw: &str) -> Self {
        let Some(table_start) = nft_raw.find("table inet banIP {") else {
            return Self::default();
        };
        let table = braced_block(&nft_raw[table_start..]);

        let mut ranges = Vec::new();
        let mut rest = table;
        while let Some(set_kw) = rest.find("set ") {
            rest = &rest[set_kw + 4..];
            let Some(brace) = rest.find('{') else { break };
            let name = rest[..brace].trim();
            let set_body = braced_block(&rest[brace..]);
            rest = &rest[brace..];

            let Some((feed, _family)) = name.split_once('.') else { continue };
            if feed == "allowlist" || feed == "blocklist" {
                continue;
            }

            if let Some(elems_at) = set_body.find("elements = {") {
                let after = &set_body[elems_at + "elements = {".len()..];
                if let Some(end) = after.find('}') {
                    for token in after[..end].split(',') {
                        let token = token.trim();
                        if !token.is_empty() {
                            if let Some((lo, hi)) = parse_element(token) {
                                ranges.push((feed.to_string(), lo, hi));
                            }
                        }
                    }
                }
            }
        }
        Self { ranges }
    }

    /// The feed id an IP is flagged in, if any (first match wins — an IP
    /// showing up in more than one feed is rare enough not to matter here).
    pub fn lookup(&self, ip: &str) -> Option<&str> {
        let ip: IpAddr = ip.parse().ok()?;
        self.ranges
            .iter()
            .find(|(_, lo, hi)| in_range(&ip, lo, hi))
            .map(|(feed, ..)| feed.as_str())
    }
}

/// Text strictly between the first top-level `{` in `s` and its match.
fn braced_block(s: &str) -> &str {
    let mut depth = 0i32;
    let mut start = None;
    for (i, c) in s.char_indices() {
        match c {
            '{' => {
                depth += 1;
                if start.is_none() {
                    start = Some(i + 1);
                }
            }
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return &s[start.unwrap_or(0)..i];
                }
            }
            _ => {}
        }
    }
    start.map(|i| &s[i..]).unwrap_or(s)
}

/// Parses one nft set element: a bare IP, a CIDR (`ip/prefix`), or an
/// explicit range (`ip-ip`) — the three forms banIP's feeds actually use.
fn parse_element(token: &str) -> Option<(IpAddr, IpAddr)> {
    if let Some((lo, hi)) = token.split_once('-') {
        return Some((lo.trim().parse().ok()?, hi.trim().parse().ok()?));
    }
    if let Some((base, prefix)) = token.split_once('/') {
        let prefix: u32 = prefix.trim().parse().ok()?;
        return match base.trim().parse::<IpAddr>().ok()? {
            IpAddr::V4(ip) => {
                let bits = ip.to_bits();
                let mask = if prefix == 0 { 0 } else { u32::MAX << (32 - prefix) };
                Some((IpAddr::V4((bits & mask).into()), IpAddr::V4((bits | !mask).into())))
            }
            IpAddr::V6(ip) => {
                let bits = ip.to_bits();
                let mask = if prefix == 0 { 0 } else { u128::MAX << (128 - prefix) };
                Some((IpAddr::V6((bits & mask).into()), IpAddr::V6((bits | !mask).into())))
            }
        };
    }
    let ip: IpAddr = token.parse().ok()?;
    Some((ip, ip))
}

fn in_range(ip: &IpAddr, lo: &IpAddr, hi: &IpAddr) -> bool {
    match (ip, lo, hi) {
        (IpAddr::V4(ip), IpAddr::V4(lo), IpAddr::V4(hi)) => {
            (lo.to_bits()..=hi.to_bits()).contains(&ip.to_bits())
        }
        (IpAddr::V6(ip), IpAddr::V6(lo), IpAddr::V6(hi)) => {
            (lo.to_bits()..=hi.to_bits()).contains(&ip.to_bits())
        }
        _ => false,
    }
}

/// Short human description of a banIP feed id, for display next to a
/// flagged destination. Covers the feeds enabled on this project's
/// reference router; unrecognized ids still show the raw feed name.
pub fn describe(feed: &str) -> String {
    match feed {
        "spamhaus" => "Known spam/malware source (Spamhaus DROP/EDROP)".to_string(),
        "feodo" => "Active botnet C2 server (abuse.ch Feodo Tracker)".to_string(),
        "dshield" => "Top attacking IP (SANS DShield)".to_string(),
        "turris" => "Seen probing/scanning (Turris Sentinel honeypot network)".to_string(),
        "urlhaus" => "Malware distribution host (abuse.ch URLhaus)".to_string(),
        "cinsscore" => "Poor reputation history (CINS Army list)".to_string(),
        other => format!("Flagged by banIP feed \"{other}\""),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Captured verbatim (truncated) from a real router's
    // `nft list table inet banIP`.
    const SAMPLE: &str = "\
table inet banIP {
	set allowlist.v4 {
		type ipv4_addr
		policy memory
		flags interval
		auto-merge
		elements = { 194.164.226.58 }
	}

	set feodo.v4 {
		type ipv4_addr
		policy memory
		flags interval
		auto-merge
		elements = { 27.133.154.218, 34.204.119.63,
			     50.16.16.211, 162.243.103.246,
			     178.62.3.223 }
	}

	set spamhaus.v4 {
		type ipv4_addr
		policy memory
		flags interval
		auto-merge
		elements = { 1.10.16.0/20, 1.19.0.0/16,
			     14.128.32.0-14.128.55.255 }
	}

	set blocklist.v4 {
		type ipv4_addr
		policy memory
		flags interval,timeout
		auto-merge
	}
}
";

    #[test]
    fn parse_finds_exact_ip_in_feed() {
        let feeds = BanipFeeds::parse(SAMPLE);
        assert_eq!(feeds.lookup("34.204.119.63"), Some("feodo"));
    }

    #[test]
    fn parse_finds_ip_inside_cidr_range() {
        let feeds = BanipFeeds::parse(SAMPLE);
        // 1.10.16.0/20 covers 1.10.16.0 - 1.10.31.255
        assert_eq!(feeds.lookup("1.10.20.5"), Some("spamhaus"));
    }

    #[test]
    fn parse_finds_ip_inside_explicit_range() {
        let feeds = BanipFeeds::parse(SAMPLE);
        assert_eq!(feeds.lookup("14.128.40.1"), Some("spamhaus"));
    }

    #[test]
    fn parse_rejects_ip_outside_any_range() {
        let feeds = BanipFeeds::parse(SAMPLE);
        assert_eq!(feeds.lookup("8.8.8.8"), None);
    }

    #[test]
    fn parse_excludes_allowlist_and_blocklist_sets() {
        let feeds = BanipFeeds::parse(SAMPLE);
        // allowlist.v4's own element must never be attributed to a feed.
        assert_eq!(feeds.lookup("194.164.226.58"), None);
    }

    #[test]
    fn parse_returns_empty_when_no_banip_table_present() {
        let feeds = BanipFeeds::parse("table inet fw4 {\n}\n");
        assert_eq!(feeds.lookup("34.204.119.63"), None);
    }

    #[test]
    fn describe_covers_known_feeds_and_falls_back_for_unknown() {
        assert!(describe("feodo").contains("botnet"));
        assert!(describe("some_new_feed").contains("some_new_feed"));
    }
}
