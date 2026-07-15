use super::strip_crlf;

/// dnsmasq config: `address=/example.com/0.0.0.0`, `server=/domain/`, etc.
pub fn parse_dnsmasq(content: &str) -> Vec<String> {
    let mut out = Vec::new();
    for raw in content.lines() {
        let line = {
            let s = strip_crlf(raw);
            let s = match s.find('#') {
                Some(i) => s[..i].trim(),
                None    => s.trim(),
            };
            s
        };
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if !matches!(
            line.split('=').next(),
            Some("address" | "server" | "local" | "ipset" | "nftset")
        ) || !line.contains("=/") {
            continue;
        }
        extract_dnsmasq_domains(line, &mut out);
    }
    out
}

pub fn extract_dnsmasq_domains(line: &str, out: &mut Vec<String>) {
    // format: keyword=/domain1/domain2/.../value
    let parts: Vec<&str> = line.split('/').collect();
    for token in parts.iter().skip(1) {
        let t = token.trim();
        if t.chars().any(|c| c.is_ascii_alphabetic())
            && t.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
        {
            out.push(t.to_string());
        }
    }
}
