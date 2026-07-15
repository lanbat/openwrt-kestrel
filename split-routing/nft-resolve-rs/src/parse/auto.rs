use super::{strip_crlf, trim_comment};
use super::dnsmasq::extract_dnsmasq_domains;
use super::url::extract_host;
use crate::classify::looks_like_ip;

/// Auto-detect format per line, combining all known formats.
pub fn parse_auto(content: &str) -> Vec<String> {
    let mut out = Vec::new();
    for raw in content.lines() {
        let raw = strip_crlf(raw);
        let trimmed = raw.trim();
        if trimmed.is_empty()
            || trimmed.starts_with('!')
            || trimmed.starts_with('#')
            || trimmed.starts_with(';')
            || trimmed.starts_with('[')
            || trimmed.starts_with("@@")
        {
            continue;
        }

        // strip inline comment from a copy for field parsing
        let line = match trimmed.find(|c: char| c == '\t' || c == ' ') {
            Some(i) => match trimmed[i..].find('#') {
                Some(j) => trimmed[..i+j].trim(),
                None    => trimmed,
            },
            None => trimmed,
        };

        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.is_empty() { continue; }

        // hosts file: first field is IP, rest are domains
        if looks_like_ip(fields[0]) {
            if fields.len() > 1 {
                out.extend(fields[1..].iter().map(|s| s.to_string()));
            } else {
                out.push(fields[0].to_string());
            }
            continue;
        }

        // dnsmasq: address=/domain/ip
        if matches!(fields[0].split('=').next(), Some("address"|"server"|"local"|"ipset"|"nftset"))
            && line.contains("=/")
        {
            extract_dnsmasq_domains(line, &mut out);
            continue;
        }

        // unbound local-zone
        if let Some(rest) = line.strip_prefix("local-zone:") {
            let rest = rest.trim().trim_matches('"');
            if let Some(d) = rest.split_whitespace().next() {
                let d = d.trim_end_matches('.');
                if d.contains('.') && d.chars().any(|c| c.is_ascii_alphabetic()) {
                    out.push(d.to_string());
                }
            }
            continue;
        }

        // unbound local-data
        if let Some(rest) = line.strip_prefix("local-data:") {
            let rest = rest.trim().trim_start_matches('"');
            if let Some(d) = rest.split_whitespace().next() {
                let d = d.trim_end_matches('.');
                if d.contains('.') && d.chars().any(|c| c.is_ascii_alphabetic()) {
                    out.push(d.to_string());
                }
            }
            continue;
        }

        // ipset: add setname ip
        if fields[0] == "add" && fields.len() >= 3 {
            out.push(fields[2].to_string());
            continue;
        }

        // Clash: DOMAIN,val or IP-CIDR,val
        if let Some(comma) = line.find(',') {
            let kind = line[..comma].trim().to_uppercase();
            match kind.as_str() {
                "DOMAIN" | "DOMAIN-SUFFIX" | "DOMAIN-KEYWORD" | "IP-CIDR" | "IP-CIDR6" => {
                    let val = line[comma+1..].split(',').next().unwrap_or("").trim();
                    if !val.is_empty() {
                        out.push(val.to_string());
                    }
                    continue;
                }
                _ => {}
            }
        }

        // adblock ||domain^
        if line.starts_with("||") {
            let s = &line[2..];
            let end = s.find(|c: char| matches!(c, '/' | '^' | '$' | ':' | ',' | '*'))
                .unwrap_or(s.len());
            let d = s[..end].trim();
            if !d.is_empty() { out.push(d.to_string()); }
            continue;
        }

        // URL with scheme
        if line.contains("://") || line.starts_with("|http://") || line.starts_with("|https://") {
            let s = if line.starts_with('|') { &line[1..] } else { line };
            if let Some(h) = extract_host(s) {
                if !h.is_empty() { out.push(h); }
            }
            continue;
        }

        // bare domain or IP — strip comment and take first field
        let line = trim_comment(trimmed).trim();
        let first = line.split_whitespace().next().unwrap_or(line);
        if !first.is_empty() {
            out.push(first.to_string());
        }
    }
    out
}
