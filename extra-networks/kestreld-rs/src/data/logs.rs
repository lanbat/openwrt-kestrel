use tokio::process::Command;

#[derive(Default, Clone)]
pub struct LogData {
    pub lines: Vec<String>,
}

pub async fn fetch() -> LogData {
    let output = Command::new("logread")
        .output()
        .await
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .unwrap_or_default();

    // Keep last 500 lines
    let lines: Vec<String> = output
        .lines()
        .rev()
        .take(500)
        .map(|s| s.to_string())
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();

    LogData { lines }
}

impl LogData {
    /// Lines containing the given prefix (e.g. "EXTNET-2LAN-guest:")
    pub fn grep(&self, prefix: &str) -> Vec<&str> {
        self.lines
            .iter()
            .filter(|l| l.contains(prefix))
            .map(|s| s.as_str())
            .collect()
    }

    /// Parse a log line's timestamp field (field index 3, e.g. "12:34:56")
    pub fn line_ts(line: &str) -> &str {
        line.split_whitespace().nth(3).unwrap_or("")
    }
}

/// Parse dnsmasq query log lines for a specific source IP.
/// Returns (domain, qtype) for each matching `query[A]` or `query[AAAA]` entry.
/// Log format: `... dnsmasq[N]: ID SRC/PORT query[A] domain from SRC`
pub fn parse_dns_queries<'a>(lines: &'a [String], src_ip: &str) -> Vec<(&'a str, &'a str)> {
    lines
        .iter()
        .filter_map(|line| {
            if !line.contains("query[") { return None; }
            let from_suffix = format!("from {src_ip}");
            if !line.ends_with(&from_suffix) { return None; }
            // Extract query type and domain
            let qi = line.find("query[")?;
            let rest = &line[qi + 6..];
            let close = rest.find(']')?;
            let qtype = &rest[..close];
            if qtype != "A" && qtype != "AAAA" { return None; }
            let after = rest[close + 1..].trim();
            let domain = after.split_whitespace().next()?;
            if domain.ends_with(".arpa") { return None; }
            Some((domain, &line[qi + 6..qi + 6 + close]))
        })
        .collect()
}

/// Parse kernel netfilter log fields (SRC=, DST=, PROTO=, DPT=) from a log line.
pub struct NfFields<'a> {
    pub src: &'a str,
    pub dst: &'a str,
    pub proto: &'a str,
    pub dpt: &'a str,
}

pub fn parse_nf_fields(line: &str) -> Option<NfFields<'_>> {
    let mut src = "";
    let mut dst = "";
    let mut proto = "";
    let mut dpt = "";

    for tok in line.split_whitespace() {
        if let Some(v) = tok.strip_prefix("SRC=") {
            src = v;
        } else if let Some(v) = tok.strip_prefix("DST=") {
            dst = v;
        } else if let Some(v) = tok.strip_prefix("PROTO=") {
            proto = v;
        } else if let Some(v) = tok.strip_prefix("DPT=") {
            dpt = v;
        }
    }

    if src.is_empty() || dst.is_empty() || proto.is_empty() {
        return None;
    }
    Some(NfFields { src, dst, proto, dpt })
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_LOG_LINE: &str =
        "Fri Jan  5 12:34:56 2024 kern.warn kernel: [123.456] EXTNET-DENY-guest: \
         IN=br-guest OUT= MAC=aa:bb:cc:dd:ee:ff SRC=10.10.0.5 DST=192.168.1.1 \
         PROTO=TCP SPT=44123 DPT=80";

    // ── parse_nf_fields ───────────────────────────────────────────────────────

    #[test]
    fn nf_fields_basic() {
        let f = parse_nf_fields(SAMPLE_LOG_LINE).unwrap();
        assert_eq!(f.src, "10.10.0.5");
        assert_eq!(f.dst, "192.168.1.1");
        assert_eq!(f.proto, "TCP");
        assert_eq!(f.dpt, "80");
    }

    #[test]
    fn nf_fields_missing_src_returns_none() {
        let line = "DST=1.2.3.4 PROTO=UDP DPT=53";
        assert!(parse_nf_fields(line).is_none());
    }

    #[test]
    fn nf_fields_missing_proto_returns_none() {
        let line = "SRC=1.2.3.4 DST=5.6.7.8 DPT=80";
        assert!(parse_nf_fields(line).is_none());
    }

    #[test]
    fn nf_fields_no_dpt_is_empty_string() {
        let line = "SRC=10.0.0.1 DST=10.0.0.2 PROTO=ICMP";
        let f = parse_nf_fields(line).unwrap();
        assert_eq!(f.dpt, "");
    }

    // ── LogData::grep ─────────────────────────────────────────────────────────

    #[test]
    fn grep_finds_matching_lines() {
        let log = LogData {
            lines: vec![
                "some random line".to_string(),
                "EXTNET-2LAN-guest: MAC=aa SRC=10.10.0.5".to_string(),
                "another line".to_string(),
                "EXTNET-2LAN-guest: MAC=bb SRC=10.10.0.6".to_string(),
            ],
        };
        let hits = log.grep("EXTNET-2LAN-guest:");
        assert_eq!(hits.len(), 2);
        assert!(hits[0].contains("MAC=aa"));
        assert!(hits[1].contains("MAC=bb"));
    }

    #[test]
    fn grep_returns_empty_when_no_match() {
        let log = LogData { lines: vec!["unrelated line".to_string()] };
        assert!(log.grep("EXTNET-DENY-guest:").is_empty());
    }

    // ── LogData::line_ts ──────────────────────────────────────────────────────

    #[test]
    fn line_ts_extracts_fourth_field() {
        // logread format: "Mon Jan  1 12:34:56 2024 ..."
        let line = "Mon Jan  1 12:34:56 2024 daemon.info dnsmasq";
        assert_eq!(LogData::line_ts(line), "12:34:56");
    }

    #[test]
    fn line_ts_empty_for_short_line() {
        assert_eq!(LogData::line_ts("a b c"), "");
    }
}
