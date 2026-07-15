use super::strip_crlf;

/// URL/tracker format: `udp://tracker.example.org:1337/announce`
/// Extracts the host portion.
pub fn parse_url(content: &str) -> Vec<String> {
    let mut out = Vec::new();
    for raw in content.lines() {
        let line = {
            let s = strip_crlf(raw);
            // strip inline comment
            let s = match s.find(|c: char| c == '\t' || c == ' ') {
                Some(i) if s[i..].contains('#') => s[..s[i..].find('#').map(|j| i+j).unwrap_or(s.len())].trim(),
                _ => s.trim(),
            };
            s
        };
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        let first = line.split_whitespace().next().unwrap_or(line);
        if let Some(host) = extract_host(first) {
            if !host.is_empty() {
                out.push(host);
            }
        }
    }
    out
}

pub fn extract_host(s: &str) -> Option<String> {
    // strip scheme
    let s = if let Some(i) = s.find("://") {
        &s[i + 3..]
    } else {
        s
    };
    // strip path and query
    let s = s.split('/').next().unwrap_or(s);
    let s = s.split('?').next().unwrap_or(s);

    // IPv6 literal: [::1]:port
    if s.starts_with('[') {
        let end = s.find(']')?;
        return Some(s[1..end].to_string());
    }

    // strip userinfo
    let s = if let Some(i) = s.find('@') { &s[i+1..] } else { s };
    // strip port
    let s = if let Some(i) = s.rfind(':') {
        if s[i+1..].chars().all(|c| c.is_ascii_digit()) { &s[..i] } else { s }
    } else { s };

    Some(s.to_string())
}
