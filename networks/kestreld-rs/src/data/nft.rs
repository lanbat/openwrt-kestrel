use std::collections::HashMap;
use tokio::process::Command;

#[derive(Default, Clone)]
pub struct NftState {
    pub raw: String,
}

pub async fn fetch() -> NftState {
    let raw = Command::new("nft")
        .args(["list", "ruleset"])
        .output()
        .await
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .unwrap_or_default();
    NftState { raw }
}

impl NftState {
    /// Bytes for a counter chain (in = iifname, out = oifname).
    pub fn chain_bytes(&self, chain: &str, direction: &str) -> u64 {
        let iface_kw = if direction == "in" { "iifname" } else { "oifname" };
        let header = format!("chain {chain} {{");
        let mut in_chain = false;
        let mut depth = 0usize;

        for line in self.raw.lines() {
            let t = line.trim();
            if !in_chain {
                if t.starts_with(&header) {
                    in_chain = true;
                    depth = 1;
                }
                continue;
            }
            depth += t.chars().filter(|&c| c == '{').count();
            depth = depth.saturating_sub(t.chars().filter(|&c| c == '}').count());
            if depth == 0 {
                break;
            }
            if t.contains(iface_kw) && t.contains("counter") {
                if let Some(b) = extract_bytes(t) {
                    return b;
                }
            }
        }
        0
    }

    /// Per-IP byte counters from a dynamic set. Returns ip → bytes.
    pub fn device_bytes(&self, set_name: &str) -> HashMap<String, u64> {
        let mut result = HashMap::new();
        let header = format!("set {set_name} {{");
        let mut in_set = false;
        let mut in_elements = false;

        for line in self.raw.lines() {
            let t = line.trim();
            if !in_set {
                if t.starts_with(&header) {
                    in_set = true;
                }
                continue;
            }
            if !in_elements {
                if t.starts_with("elements") {
                    in_elements = true;
                    parse_element_chunk(t, &mut result);
                    if t.ends_with('}') {
                        break;
                    }
                } else if t == "}" {
                    break;
                }
                continue;
            }
            parse_element_chunk(t, &mut result);
            if t.ends_with('}') {
                break;
            }
        }
        result
    }
}

fn parse_element_chunk(s: &str, result: &mut HashMap<String, u64>) {
    // Strip "elements = {" prefix and trailing "}"
    let s = s
        .trim_start_matches("elements")
        .trim()
        .trim_start_matches('=')
        .trim()
        .trim_start_matches('{')
        .trim_end_matches('}')
        .trim();
    for part in s.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if let Some(space) = part.find(' ') {
            let ip = &part[..space];
            if ip.contains('.') || ip.contains(':') {
                if let Some(bytes) = extract_bytes(part) {
                    result.insert(ip.to_string(), bytes);
                }
            }
        }
    }
}

fn extract_bytes(s: &str) -> Option<u64> {
    let parts: Vec<&str> = s.split_whitespace().collect();
    parts
        .windows(2)
        .find(|w| w[0] == "bytes")
        .and_then(|w| w[1].trim_end_matches(',').parse().ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── extract_bytes ─────────────────────────────────────────────────────────

    #[test]
    fn extract_bytes_basic() {
        assert_eq!(extract_bytes("packets 5 bytes 1234"), Some(1234));
    }

    #[test]
    fn extract_bytes_trailing_comma() {
        assert_eq!(extract_bytes("packets 5 bytes 999,"), Some(999));
    }

    #[test]
    fn extract_bytes_missing_returns_none() {
        assert_eq!(extract_bytes("iifname \"br-guest\" accept"), None);
    }

    // ── parse_element_chunk ───────────────────────────────────────────────────

    #[test]
    fn element_chunk_single_entry() {
        let mut result = std::collections::HashMap::new();
        parse_element_chunk("10.10.0.5 counter packets 3 bytes 4096", &mut result);
        assert_eq!(result.get("10.10.0.5"), Some(&4096));
    }

    #[test]
    fn element_chunk_multiple_entries_comma_separated() {
        let mut result = std::collections::HashMap::new();
        parse_element_chunk(
            "elements = { 10.10.0.1 counter packets 1 bytes 100, 10.10.0.2 counter packets 2 bytes 200 }",
            &mut result,
        );
        assert_eq!(result.get("10.10.0.1"), Some(&100));
        assert_eq!(result.get("10.10.0.2"), Some(&200));
    }

    #[test]
    fn element_chunk_ipv6_entry() {
        let mut result = std::collections::HashMap::new();
        parse_element_chunk("2001:db8::1 counter packets 1 bytes 512", &mut result);
        assert_eq!(result.get("2001:db8::1"), Some(&512));
    }

    // ── NftState::chain_bytes ─────────────────────────────────────────────────

    const NFT_RULESET: &str = "\
table inet fw4 {
\tchain EXTNET-ACCT-guest-in {
\t\tiifname \"br-guest\" counter packets 100 bytes 999000
\t}
\tchain EXTNET-ACCT-guest-out {
\t\toifname \"br-guest\" counter packets 50 bytes 123456
\t}
\tchain other {
\t\tiifname \"br-other\" counter packets 1 bytes 11
\t}
}
";

    #[test]
    fn chain_bytes_in_direction() {
        let state = NftState { raw: NFT_RULESET.to_string() };
        assert_eq!(state.chain_bytes("EXTNET-ACCT-guest-in", "in"), 999000);
    }

    #[test]
    fn chain_bytes_out_direction() {
        let state = NftState { raw: NFT_RULESET.to_string() };
        assert_eq!(state.chain_bytes("EXTNET-ACCT-guest-out", "out"), 123456);
    }

    #[test]
    fn chain_bytes_missing_chain_returns_zero() {
        let state = NftState { raw: NFT_RULESET.to_string() };
        assert_eq!(state.chain_bytes("EXTNET-ACCT-nonexistent", "in"), 0);
    }

    #[test]
    fn chain_bytes_wrong_direction_misses_counter() {
        // "in" rule won't match an "out" query
        let state = NftState { raw: NFT_RULESET.to_string() };
        assert_eq!(state.chain_bytes("EXTNET-ACCT-guest-in", "out"), 0);
    }

    // ── NftState::device_bytes ────────────────────────────────────────────────

    const NFT_WITH_SET_SINGLE_LINE: &str = "\
table inet fw4 {
\tset EXTNET-TRACK-guest {
\t\ttype ipv4_addr
\t\tflags dynamic,timeout
\t\telements = { 10.10.0.5 counter packets 3 bytes 4096, 10.10.0.6 counter packets 1 bytes 512 }
\t}
}
";

    const NFT_WITH_SET_MULTI_LINE: &str = "\
table inet fw4 {
\tset EXTNET-TRACK-guest {
\t\ttype ipv4_addr
\t\tflags dynamic,timeout
\t\telements = { 10.10.0.1 counter packets 10 bytes 10000,
\t\t             10.10.0.2 counter packets 5 bytes 5000,
\t\t             10.10.0.3 counter packets 1 bytes 100 }
\t}
}
";

    #[test]
    fn device_bytes_single_line_elements() {
        let state = NftState { raw: NFT_WITH_SET_SINGLE_LINE.to_string() };
        let map = state.device_bytes("EXTNET-TRACK-guest");
        assert_eq!(map.get("10.10.0.5"), Some(&4096));
        assert_eq!(map.get("10.10.0.6"), Some(&512));
    }

    #[test]
    fn device_bytes_multi_line_elements() {
        let state = NftState { raw: NFT_WITH_SET_MULTI_LINE.to_string() };
        let map = state.device_bytes("EXTNET-TRACK-guest");
        assert_eq!(map.get("10.10.0.1"), Some(&10000));
        assert_eq!(map.get("10.10.0.2"), Some(&5000));
        assert_eq!(map.get("10.10.0.3"), Some(&100));
    }

    #[test]
    fn device_bytes_missing_set_returns_empty() {
        let state = NftState { raw: NFT_WITH_SET_SINGLE_LINE.to_string() };
        let map = state.device_bytes("EXTNET-TRACK-nonexistent");
        assert!(map.is_empty());
    }
}
