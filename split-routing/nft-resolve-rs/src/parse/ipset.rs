use super::{strip_crlf, trim_comment};

/// ipset save format: `add setname 1.2.3.4`
pub fn parse_ipset(content: &str) -> Vec<String> {
    let mut out = Vec::new();
    for raw in content.lines() {
        let line = trim_comment(strip_crlf(raw)).trim();
        if line.is_empty() {
            continue;
        }
        let mut fields = line.split_whitespace();
        if fields.next() == Some("add") {
            fields.next(); // set name
            if let Some(ip) = fields.next() {
                out.push(ip.to_string());
            }
        }
    }
    out
}
