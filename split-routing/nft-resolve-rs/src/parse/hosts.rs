use super::{strip_crlf, trim_comment};
use crate::classify::looks_like_ip;

/// Hosts-file format: `0.0.0.0 example.com another.com`
/// The first field is an IP address; subsequent fields are domains.
pub fn parse_hosts(content: &str) -> Vec<String> {
    let mut out = Vec::new();
    for raw in content.lines() {
        let line = trim_comment(strip_crlf(raw)).trim();
        if line.is_empty() {
            continue;
        }
        let mut fields = line.split_whitespace();
        let Some(first) = fields.next() else { continue };
        if looks_like_ip(first) {
            out.extend(fields.map(|s| s.to_string()));
        }
    }
    out
}
