use super::strip_crlf;

/// Adblock/uBlock format: `||example.com^`, `|http://...`, cosmetic rules skipped.
pub fn parse_adblock(content: &str) -> Vec<String> {
    let mut out = Vec::new();
    for raw in content.lines() {
        let line = strip_crlf(raw).trim();
        if line.is_empty()
            || line.starts_with('!')
            || line.starts_with('[')
            || line.starts_with("@@")
            || line.contains("##")
            || line.contains("#@#")
            || line.contains("#?#")
        {
            continue;
        }

        let mut s: &str = line;
        if let Some(rest) = s.strip_prefix("||") {
            s = rest;
        } else if let Some(rest) = s.strip_prefix("|http://") {
            s = rest;
        } else if let Some(rest) = s.strip_prefix("|https://") {
            s = rest;
        } else if let Some(rest) = s.strip_prefix("http://") {
            s = rest;
        } else if let Some(rest) = s.strip_prefix("https://") {
            s = rest;
        } else if s.chars().next().map_or(false, |c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.') {
            // bare domain or domain with trailing anchor — keep as-is
        } else {
            continue;
        }

        // strip everything from the first anchor/option char
        let end = s.find(|c: char| matches!(c, '/' | '^' | '$' | ':' | ',' | '*'))
            .unwrap_or(s.len());
        let domain = s[..end].trim();
        if !domain.is_empty() {
            out.push(domain.to_string());
        }
    }
    out
}
