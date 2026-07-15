use super::{strip_crlf, trim_comment};

/// One entry per line: domain or IP, optional # comment. Takes the first field.
pub fn parse_oneper(content: &str) -> Vec<String> {
    let mut out = Vec::new();
    for raw in content.lines() {
        let line = trim_comment(strip_crlf(raw)).trim();
        if line.is_empty() || line.starts_with('!') || line.starts_with(';') {
            continue;
        }
        if let Some(first) = line.split_whitespace().next() {
            out.push(first.to_string());
        }
    }
    out
}
