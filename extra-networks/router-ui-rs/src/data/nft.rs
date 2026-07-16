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
        .trim_start_matches('=')
        .trim_matches(|c: char| c == '{' || c == '}')
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
