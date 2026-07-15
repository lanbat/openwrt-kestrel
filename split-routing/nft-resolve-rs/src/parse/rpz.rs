use super::strip_crlf;

/// BIND RPZ zone: `example.com CNAME .`
/// Only A, AAAA, CNAME record types; skip SOA, NS, etc.
pub fn parse_rpz(content: &str) -> Vec<String> {
    let mut out = Vec::new();
    for raw in content.lines() {
        let line = {
            let s = strip_crlf(raw);
            match s.find(';') {
                Some(i) => s[..i].trim(),
                None    => s.trim(),
            }
        };
        if line.is_empty()
            || line.starts_with('$')
            || line.starts_with('@')
            || line.starts_with('(')
            || line.starts_with(')')
        {
            continue;
        }

        let mut fields = line.split_whitespace();
        let Some(domain) = fields.next() else { continue };

        // find the record type, skipping IN and TTL numbers
        let rtype = fields
            .find(|f| {
                let u = f.to_uppercase();
                u != "IN" && !f.chars().all(|c| c.is_ascii_digit())
            })
            .map(|f| f.to_uppercase());

        let Some(rtype) = rtype else { continue };

        match rtype.as_str() {
            "SOA" | "NS" | "MX" | "TXT" | "PTR" | "SRV"
            | "DNSKEY" | "RRSIG" | "NSEC" | "CAA" => continue,
            "A" | "AAAA" | "CNAME" => {}
            _ => continue,
        }

        // strip wildcard prefix and trailing dot
        let d = domain
            .trim_end_matches('.')
            .trim_start_matches("*.")
            .trim_start_matches('.');

        if d.is_empty() || !d.contains('.') || !d.chars().any(|c| c.is_ascii_alphabetic()) {
            continue;
        }
        out.push(d.to_string());
    }
    out
}
