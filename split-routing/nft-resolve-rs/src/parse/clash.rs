use super::{strip_crlf, trim_comment};

/// Clash/Surge rules: `DOMAIN,example.com` or `IP-CIDR,1.2.3.0/24`
pub fn parse_clash(content: &str) -> Vec<String> {
    let mut out = Vec::new();
    for raw in content.lines() {
        let line = trim_comment(strip_crlf(raw)).trim();
        if line.is_empty() {
            continue;
        }
        let line = line.strip_prefix("- ").unwrap_or(line);
        let mut parts = line.splitn(3, ',');
        let Some(kind) = parts.next() else { continue };
        let Some(val) = parts.next() else { continue };
        let val = val.trim();
        match kind.trim().to_uppercase().as_str() {
            "DOMAIN" | "DOMAIN-SUFFIX" | "DOMAIN-KEYWORD"
            | "IP-CIDR" | "IP-CIDR6" => {
                if !val.is_empty() {
                    out.push(val.to_string());
                }
            }
            _ => {}
        }
    }
    out
}
