use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

#[derive(Default)]
pub struct Classified {
    pub domains: Vec<String>,
    pub ip4:     Vec<String>,
    pub ip6:     Vec<String>,
}

const SKIP: &[&str] = &[
    "localhost", "localdomain", "broadcasthost",
    "0.0.0.0", "127.0.0.1", "::", "::1",
];

pub fn classify(candidates: &[String]) -> Classified {
    let mut c = Classified::default();
    for raw in candidates {
        let s = raw.trim().to_lowercase();
        let s = s.trim_end_matches('.');

        // unwrap IPv6 bracket notation
        let s = if s.starts_with('[') {
            s.trim_start_matches('[').split(']').next().unwrap_or(s)
        } else {
            s
        };

        // strip wildcard/leading dot
        let s = s.trim_start_matches("*.")
                  .trim_start_matches('.');

        // strip trailing port `host:1234`
        let s = strip_port(s);

        if s.is_empty() || SKIP.contains(&s) {
            continue;
        }

        if let Some(cat) = classify_one(s) {
            match cat {
                Cat::V4(v) => c.ip4.push(v),
                Cat::V6(v) => c.ip6.push(v),
                Cat::Domain(v) => c.domains.push(v),
            }
        }
    }
    c
}

enum Cat { V4(String), V6(String), Domain(String) }

fn classify_one(s: &str) -> Option<Cat> {
    // IPv4 or IPv4 CIDR
    if let Ok(_) = Ipv4Addr::from_str(s) {
        return Some(Cat::V4(s.to_string()));
    }
    if is_v4_cidr(s) {
        return Some(Cat::V4(s.to_string()));
    }

    // IPv6 or IPv6 CIDR
    if let Ok(_) = Ipv6Addr::from_str(s) {
        return Some(Cat::V6(s.to_string()));
    }
    if is_v6_cidr(s) {
        return Some(Cat::V6(s.to_string()));
    }

    // domain: only [a-z0-9_.-], must have a dot, must have a letter, no double-dot
    if s.contains('.')
        && !s.contains("..")
        && s.chars().any(|c| c.is_ascii_alphabetic())
        && s.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
    {
        return Some(Cat::Domain(s.to_string()));
    }

    None
}

fn is_v4_cidr(s: &str) -> bool {
    let Some((addr, prefix)) = s.split_once('/') else { return false };
    let Ok(p) = prefix.parse::<u8>() else { return false };
    p <= 32 && Ipv4Addr::from_str(addr).is_ok()
}

fn is_v6_cidr(s: &str) -> bool {
    let Some((addr, prefix)) = s.split_once('/') else { return false };
    let Ok(p) = prefix.parse::<u8>() else { return false };
    p <= 128 && Ipv6Addr::from_str(addr).is_ok()
}

fn strip_port(s: &str) -> &str {
    // only strip trailing `:digits` for non-IPv6
    if s.contains(':') && !s.contains("::") {
        if let Some(i) = s.rfind(':') {
            if s[i+1..].chars().all(|c| c.is_ascii_digit()) {
                return &s[..i];
            }
        }
    }
    s
}

/// Quick check: does this string look like an IPv4 address (used by parsers)?
pub fn looks_like_ip(s: &str) -> bool {
    Ipv4Addr::from_str(s).is_ok()
        || Ipv6Addr::from_str(s).is_ok()
        || is_v4_cidr(s)
        || is_v6_cidr(s)
        // heuristic: starts with digit and has dots (catches 0.0.0.0 etc.)
        || (s.starts_with(|c: char| c.is_ascii_digit()) && s.contains('.'))
        || s.starts_with('[')  // IPv6 bracket
}

pub fn dedup_sorted(v: &mut Vec<String>) {
    v.sort_unstable();
    v.dedup();
}
