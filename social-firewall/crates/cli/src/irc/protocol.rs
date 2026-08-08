use anyhow::{Context, Result};
use std::time::{SystemTime, UNIX_EPOCH};

pub(crate) const MAX_LINE_BYTES: usize = 510;

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct IrcLine {
    pub(crate) tags: Vec<(String, Option<String>)>,
    pub(crate) command: String,
    pub(crate) params: Vec<String>,
}

pub(crate) fn parse_line(raw: &str) -> Result<IrcLine> {
    let mut input = raw;
    let mut tags = Vec::new();
    if let Some(rest) = input.strip_prefix('@') {
        let (tag_text, remaining) = rest.split_once(' ').context("invalid IRC tags")?;
        tags = tag_text
            .split(';')
            .map(|tag| {
                let (key, value) = tag
                    .split_once('=')
                    .map(|(key, value)| (key, Some(value.to_string())))
                    .unwrap_or((tag, None));
                (key.to_string(), value)
            })
            .collect();
        input = remaining.trim_start();
    }
    if input.is_empty() {
        anyhow::bail!("empty IRC command");
    }
    let mut parts = input.splitn(2, ' ');
    let command = parts.next().unwrap().to_string();
    let rest = parts.next().unwrap_or("").trim_start();
    let mut params = Vec::new();
    let mut remaining = rest;
    while !remaining.is_empty() {
        if let Some(trailing) = remaining.strip_prefix(':') {
            params.push(trailing.to_string());
            break;
        }
        let (param, tail) = remaining.split_once(' ').unwrap_or((remaining, ""));
        params.push(param.to_string());
        remaining = tail.trim_start();
    }
    Ok(IrcLine {
        tags,
        command,
        params,
    })
}

pub(crate) fn server_time() -> String {
    format_time(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64,
    )
}

pub(crate) fn format_time(seconds: i64) -> String {
    let days = seconds.div_euclid(86_400);
    let day_seconds = seconds.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.000Z",
        day_seconds / 3600,
        (day_seconds % 3600) / 60,
        day_seconds % 60
    )
}

fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = mp + if mp < 10 { 3 } else { -9 };
    (y + if m <= 2 { 1 } else { 0 }, m, d)
}
