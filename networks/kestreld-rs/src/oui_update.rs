//! Port of `tools/oui-update.sh`: downloads OUI prefix databases from
//! multiple sources and merges them into `{base_dir}/oui.txt` for the
//! manufacturer lookups `data::files::oui_lookup` does on the device page.
//! Invoked as `kestreld --update-oui` (see `main.rs`), replacing the old
//! `sh tools/oui-update.sh` cron entry — same output format, same sources,
//! same priority order, just no separate shell script to keep in sync.
//!
//! Sources (tried in priority order; all are attempted regardless of
//! failures):
//!   1. Wireshark manuf  — community-maintained, most complete, all prefix lengths
//!   2. IEEE MA-L        — 24-bit OUI assignments
//!   3. IEEE MA-M        — 28-bit OUI assignments (large vendors, more specific)
//!   4. IEEE MA-S        — 36-bit OUI assignments (product-level blocks)
//!
//! Output format: PREFIX<TAB>NAME, where PREFIX is 6, 7, or 9 uppercase hex
//! chars (no colons) corresponding to 24-, 28-, and 36-bit blocks
//! respectively. Longer prefixes take precedence over shorter ones at
//! lookup time (see `data::files::oui_lookup`).

use std::collections::HashSet;
use std::path::Path;

use crate::cmd;

const WIRESHARK_URL: &str = "https://www.wireshark.org/download/automated/data/manuf";

const IEEE_SOURCES: &[(&str, &str)] = &[
    ("https://standards-oui.ieee.org/oui/oui.csv", "ieee MA-L (24-bit)"),
    ("https://standards-oui.ieee.org/oui28/mam.csv", "ieee MA-M (28-bit)"),
    ("https://standards-oui.ieee.org/oui36/oui36.csv", "ieee MA-S (36-bit)"),
];

/// Strips a leading/trailing run of whitespace-or-`"` characters — matches
/// the shell version's `gsub(/^[[:space:]"]+|[[:space:]"]+$/, "", name)`.
fn trim_space_quote(s: &str) -> &str {
    s.trim_matches(|c: char| c.is_whitespace() || c == '"')
}

/// Parses the Wireshark `manuf` file: tab-separated, `#`-comments skipped,
/// prefix in field 1 (optionally suffixed `/N` for a non-24-bit block),
/// long name in field 3 if present and non-empty, else the short name in
/// field 2.
fn parse_wireshark(body: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for line in body.lines() {
        if line.starts_with('#') {
            continue;
        }
        let fields: Vec<&str> = line.split('\t').collect();
        if fields.len() < 2 {
            continue;
        }
        let mut raw = fields[0].to_string();
        if let Some(pos) = raw.rfind('/') {
            if !raw[pos + 1..].is_empty() && raw[pos + 1..].chars().all(|c| c.is_ascii_digit()) {
                raw.truncate(pos);
            }
        }
        let raw = raw.replace(':', "").to_uppercase();
        let name = if fields.len() >= 3 && !fields[2].trim().is_empty() { fields[2] } else { fields[1] };
        let name = trim_space_quote(name);
        if raw.len() >= 6 && !name.is_empty() {
            out.push((raw, name.to_string()));
        }
    }
    out
}

/// Parses an IEEE registry CSV (`Registry,Assignment,Organization Name,...`):
/// naive comma-split (matches the shell version's `awk -F','`, which is
/// equally not CSV-quote-aware — an org name with an embedded comma gets
/// truncated the same way in both versions), header row skipped, prefix in
/// field 2, name in field 3.
fn parse_ieee(body: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for (i, line) in body.lines().enumerate() {
        if i == 0 {
            continue;
        }
        let fields: Vec<&str> = line.split(',').collect();
        if fields.len() < 3 {
            continue;
        }
        let prefix = fields[1].trim();
        if prefix.is_empty() {
            continue;
        }
        let name = trim_space_quote(fields[2].trim());
        if !name.is_empty() {
            out.push((prefix.to_string(), name.to_string()));
        }
    }
    out
}

async fn fetch(url: &str, timeout_secs: &str) -> Option<String> {
    let (ok, out) = cmd::run("curl", &["-sf", "--max-time", timeout_secs, url]).await;
    if ok { Some(out) } else { None }
}

/// Runs the full update; returns the process exit code (0 success, 1 all
/// sources failed or the output file couldn't be written) — mirrors the
/// shell script's `exit 1` on total failure.
pub async fn run(base_dir: &Path) -> i32 {
    println!("Updating OUI database...");

    let mut entries: Vec<(String, String)> = Vec::new();
    let mut ok_count = 0;

    match fetch(WIRESHARK_URL, "60").await {
        Some(body) => {
            println!("  wireshark manuf : ok");
            ok_count += 1;
            entries.extend(parse_wireshark(&body));
        }
        None => println!("  wireshark manuf : failed"),
    }

    for (url, label) in IEEE_SOURCES {
        match fetch(url, "30").await {
            Some(body) => {
                println!("  {label:<24}: ok");
                ok_count += 1;
                entries.extend(parse_ieee(&body));
            }
            None => println!("  {label:<24}: failed"),
        }
    }

    if ok_count == 0 {
        println!("All sources failed — keeping existing database");
        return 1;
    }

    // Deduplicate by prefix — first occurrence wins (Wireshark entries were
    // extended first, so they take priority over raw IEEE data).
    let mut seen = HashSet::new();
    let mut deduped = Vec::new();
    for (prefix, name) in entries {
        if seen.insert(prefix.clone()) {
            deduped.push((prefix, name));
        }
    }

    let out_path = base_dir.join("oui.txt");
    let body: String = deduped.iter().map(|(p, n)| format!("{p}\t{n}\n")).collect();
    if tokio::fs::write(&out_path, &body).await.is_err() {
        println!("ERROR: failed to write {}", out_path.display());
        return 1;
    }

    println!("Done: {} entries", deduped.len());
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wireshark_strips_prefix_length_suffix_and_colons() {
        let body = "AA:BB:CC:00:00:00/28\tShort\tLong Name\n";
        let out = parse_wireshark(body);
        assert_eq!(out, vec![("AABBCC000000".to_string(), "Long Name".to_string())]);
    }

    #[test]
    fn wireshark_falls_back_to_short_name_when_long_name_absent() {
        let body = "AA:BB:CC\tShortName\n";
        let out = parse_wireshark(body);
        assert_eq!(out, vec![("AABBCC".to_string(), "ShortName".to_string())]);
    }

    #[test]
    fn wireshark_skips_comments_and_short_lines() {
        let body = "# comment\nAA:BB:CC\n";
        assert!(parse_wireshark(body).is_empty());
    }

    #[test]
    fn wireshark_trims_quotes_and_whitespace_from_name() {
        let body = "AA:BB:CC\tShort\t  \"Quoted Name\"  \n";
        let out = parse_wireshark(body);
        assert_eq!(out, vec![("AABBCC".to_string(), "Quoted Name".to_string())]);
    }

    #[test]
    fn ieee_skips_header_row() {
        let body = "Registry,Assignment,Organization Name\nMA-L,AABBCC,Example Corp\n";
        let out = parse_ieee(body);
        assert_eq!(out, vec![("AABBCC".to_string(), "Example Corp".to_string())]);
    }

    #[test]
    fn ieee_skips_rows_with_empty_prefix_or_name() {
        let body = "Registry,Assignment,Organization Name\nMA-L,,Example Corp\nMA-L,AABBCC,\n";
        assert!(parse_ieee(body).is_empty());
    }

    #[test]
    fn dedup_prefers_first_occurrence() {
        // Simulates wireshark entries (extended first) taking priority over IEEE.
        let mut entries = vec![
            ("AABBCC".to_string(), "Wireshark Name".to_string()),
            ("AABBCC".to_string(), "IEEE Name".to_string()),
        ];
        let mut seen = HashSet::new();
        let mut deduped = Vec::new();
        for (prefix, name) in entries.drain(..) {
            if seen.insert(prefix.clone()) {
                deduped.push((prefix, name));
            }
        }
        assert_eq!(deduped, vec![("AABBCC".to_string(), "Wireshark Name".to_string())]);
    }
}

#[cfg(test)]
mod network_tests {
    use super::*;

    /// Hits the real network — not run by default. `cargo test --offline
    /// --lib -- --ignored oui_update::network_tests` to run manually.
    #[tokio::test]
    #[ignore]
    async fn full_run_against_real_sources_writes_a_populated_file() {
        let dir = tempfile::tempdir().unwrap();
        let code = run(dir.path()).await;
        assert_eq!(code, 0);
        let contents = tokio::fs::read_to_string(dir.path().join("oui.txt")).await.unwrap();
        let lines: Vec<&str> = contents.lines().collect();
        assert!(lines.len() > 10_000, "expected a substantial merged database, got {} lines", lines.len());
        for line in lines.iter().take(20) {
            assert!(line.contains('\t'), "line missing tab separator: {line:?}");
        }
    }
}
