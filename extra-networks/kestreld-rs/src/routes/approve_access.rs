use axum::{
    extract::{Query, State},
    http::HeaderMap,
    response::{Html, Json},
    Form,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::state::AppState;

#[derive(Deserialize)]
pub struct AccessQuery {
    pub net: Option<String>,
    pub src: Option<String>,
    pub dst: Option<String>,
    pub proto: Option<String>,
    pub port: Option<String>,
}

#[derive(Deserialize)]
pub struct AccessForm {
    pub net: Option<String>,
    pub src: Option<String>,
    pub dst: Option<String>,
    pub proto: Option<String>,
    pub port: Option<String>,
    pub duration: Option<String>,
    pub reason: Option<String>,
    pub dest_zone: Option<String>,
    pub redirect: Option<String>,
}

#[derive(Serialize)]
pub struct ApiResult {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redirect: Option<String>,
}

fn dur_secs(d: &str) -> u64 {
    if let Some(n) = d.strip_suffix('d') { n.parse::<u64>().unwrap_or(0) * 86400 }
    else if let Some(n) = d.strip_suffix('h') { n.parse::<u64>().unwrap_or(0) * 3600 }
    else if let Some(n) = d.strip_suffix('m') { n.parse::<u64>().unwrap_or(0) * 60 }
    else { 0 }
}

fn valid_ip(s: &str) -> bool {
    if s.contains(':') {
        s.chars().all(|c| c.is_ascii_hexdigit() || c == ':') && s.len() >= 2 && s.len() <= 39
    } else {
        s.split('.').count() == 4 && s.split('.').all(|p| p.parse::<u8>().is_ok())
    }
}

fn valid_port(s: &str) -> bool {
    s.parse::<u16>().map(|p| p >= 1).unwrap_or(false)
}

fn is_private_origin(origin: &str) -> bool {
    if origin.is_empty() { return true; }
    let prefixes = [
        "http://192.168.", "http://10.", "http://172.1", "http://172.2",
        "http://172.30.", "http://172.31.", "http://[fd", "http://[fc",
        "http://[fe80", "http://[::1]",
    ];
    prefixes.iter().any(|p| origin.starts_with(p))
}

/// Only honor same-origin, same-app redirect targets requested by the caller.
fn safe_redirect(redirect: Option<&str>) -> Option<String> {
    redirect
        .map(str::trim)
        .filter(|s| s.starts_with("/cgi-bin/"))
        .map(str::to_string)
}

pub async fn get(
    State(state): State<Arc<AppState>>,
    Query(params): Query<AccessQuery>,
) -> Html<String> {
    let net = params.net.as_deref().unwrap_or("");
    let src = params.src.as_deref().unwrap_or("");
    let dst = params.dst.as_deref().unwrap_or("");
    let proto = params.proto.as_deref().unwrap_or("");
    let port = params.port.as_deref().unwrap_or("");

    if !net.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') || net.is_empty() {
        return Html("<h1>Invalid network</h1>".into());
    }
    if !valid_ip(src) || !valid_ip(dst) {
        return Html("<h1>Invalid IP</h1>".into());
    }
    if !valid_port(port) {
        return Html("<h1>Invalid port</h1>".into());
    }
    if proto != "tcp" && proto != "udp" {
        return Html("<h1>Invalid protocol</h1>".into());
    }

    let snap = state.snap().await;
    let conf = match snap.net_confs.iter().find(|c| c.iface == net) {
        Some(c) => c,
        None => return Html(format!("<h1>Unknown network: {}</h1>", net)),
    };

    let max_secs = dur_secs("30d");
    let default_dur = &conf.default_duration;

    let reason_required = false; // TODO: add to NetworkConf when needed

    let src_label = src;
    let dst_label = dst;
    let qs = format!("net={net}&src={src}&dst={dst}&proto={proto}&port={port}");

    let options: Vec<(&str, &str)> = vec![
        ("1h", "1 hour"),
        ("6h", "6 hours"),
        ("12h", "12 hours"),
        ("24h", "24 hours"),
        ("2d", "2 days"),
        ("7d", "1 week"),
        ("30d", "30 days"),
    ];

    let mut opts_html = String::new();
    for (val, label) in &options {
        if dur_secs(val) <= max_secs {
            let sel = if val == &default_dur.as_str() { " selected" } else { "" };
            opts_html.push_str(&format!("<option value=\"{val}\"{sel}>{label}</option>\n"));
        }
    }

    let req_attr = if reason_required { " required" } else { "" };
    let req_mark = if reason_required { "<span style=\"color:#c62828\"> *</span>" } else { "" };

    Html(format!(r#"<!DOCTYPE html><html><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Approve access — {net}</title>
<style>
body{{font-family:system-ui,sans-serif;max-width:480px;margin:4rem auto;padding:1rem;color:#111}}
h1{{font-size:1.3rem;margin-bottom:1.5rem}}
.card{{background:#f5f5f5;border-radius:8px;padding:1rem;margin:.75rem 0}}
.label{{font-size:.75rem;text-transform:uppercase;letter-spacing:.05em;color:#888;margin-bottom:.25rem}}
.value{{font-weight:600}}
select,textarea{{font-size:1rem;padding:.5rem .75rem;border-radius:6px;border:1px solid #ccc;
       display:block;width:100%;margin:.5rem 0;box-sizing:border-box}}
textarea{{resize:vertical;min-height:4rem}}
button{{font-size:1rem;padding:.65rem 1rem;border-radius:6px;border:none;cursor:pointer;
       background:#1976d2;color:#fff;width:100%;margin-top:.5rem}}
button:active{{background:#1565c0}}
.note{{background:#fff8e1;border-radius:8px;padding:.75rem;font-size:.85rem;margin:1rem 0}}
</style></head><body>
<h1>Access request — {net}</h1>
<div class="card">
  <div class="label">From (LAN)</div>
  <div class="value">{src_label}</div>
</div>
<div class="card">
  <div class="label">To ({net})</div>
  <div class="value">{dst_label}:{port}/{proto}</div>
</div>
<div class="note">This page is only accessible from your home LAN.</div>
<form id="access-form" method="POST" action="/cgi-bin/approve-access?{qs}">
  <input type="hidden" name="redirect" value="/cgi-bin/status">
  <div class="label" style="margin-top:1.25rem">Allow for</div>
  <select name="duration">{opts_html}</select>
  <div class="label" style="margin-top:1.25rem">Reason{req_mark}</div>
  <textarea name="reason" placeholder="Why is this access needed?"{req_attr}></textarea>
  <button type="submit">Allow access</button>
</form>
<script>
(function(){{
  var form = document.getElementById('access-form');
  form.addEventListener('submit', function(e) {{
    e.preventDefault();
    var data = new URLSearchParams(new FormData(form));
    fetch(form.action, {{method:'POST', headers:{{'Content-Type':'application/x-www-form-urlencoded'}}, body: data.toString()}})
      .then(r => r.json())
      .then(j => {{ if (j.ok) location.href = j.redirect || '/cgi-bin/status';
                    else alert(j.error || 'Error'); }})
      .catch(() => form.submit());
  }});
}})();
</script>
</body></html>"#))
}

pub async fn post(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Form(form): Form<AccessForm>,
) -> Json<ApiResult> {
    let origin = headers.get("origin")
        .or_else(|| headers.get("referer"))
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if !is_private_origin(origin) {
        return Json(ApiResult { ok: false, error: Some("Forbidden".into()), redirect: None });
    }

    let net = form.net.as_deref().unwrap_or("");
    let src = form.src.as_deref().unwrap_or("");
    let dst = form.dst.as_deref().unwrap_or("");
    let proto = form.proto.as_deref().unwrap_or("");
    let port = form.port.as_deref().unwrap_or("");
    let duration = form.duration.as_deref().unwrap_or("");
    let reason = form.reason.as_deref().unwrap_or("").trim();
    let dest_zone = if form.dest_zone.as_deref() == Some("lan") { "lan" } else { "" };

    if !net.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') || net.is_empty() {
        return Json(ApiResult { ok: false, error: Some("Invalid network".into()), redirect: None });
    }
    if !valid_ip(src) || !valid_ip(dst) {
        return Json(ApiResult { ok: false, error: Some("Invalid IP".into()), redirect: None });
    }
    if !valid_port(port) {
        return Json(ApiResult { ok: false, error: Some("Invalid port".into()), redirect: None });
    }
    if proto != "tcp" && proto != "udp" {
        return Json(ApiResult { ok: false, error: Some("Invalid protocol".into()), redirect: None });
    }

    let allowed_durations = ["1h", "6h", "12h", "24h", "2d", "7d", "30d"];
    if !allowed_durations.contains(&duration) {
        return Json(ApiResult { ok: false, error: Some("Invalid duration".into()), redirect: None });
    }

    let snap = state.snap().await;
    let conf = match snap.net_confs.iter().find(|c| c.iface == net) {
        Some(c) => c,
        None => return Json(ApiResult { ok: false, error: Some("Network not found".into()), redirect: None }),
    };

    let ok = crate::cmd::allow_service(net, dst, proto, port, duration, dest_zone).await;

    if ok && !conf.notify_url.is_empty() {
        let body = format!(
            "Type: Access approved\n\nFrom: {src}\nTo: {dst}:{port}/{proto}\nDuration: {duration}{reason_line}",
            reason_line = if reason.is_empty() { String::new() } else { format!("\nReason: {reason}") }
        );
        crate::cmd::ntfy(&conf.notify_url, &format!("Approved — {net}"), "default", "white_check_mark", &body).await;
    }

    if ok {
        Json(ApiResult { ok: true, error: None, redirect: safe_redirect(form.redirect.as_deref()) })
    } else {
        Json(ApiResult { ok: false, error: Some("allow-service.sh failed".into()), redirect: None })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dur_secs_converts_days_hours_minutes() {
        assert_eq!(dur_secs("2d"), 172800);
        assert_eq!(dur_secs("6h"), 21600);
        assert_eq!(dur_secs("30m"), 1800);
    }

    #[test]
    fn dur_secs_unknown_suffix_returns_zero() {
        assert_eq!(dur_secs("30s"), 0);
        assert_eq!(dur_secs(""), 0);
    }

    #[test]
    fn valid_ip_accepts_ipv4_and_ipv6() {
        assert!(valid_ip("192.168.1.1"));
        assert!(valid_ip("fe80::1"));
    }

    #[test]
    fn valid_ip_rejects_out_of_range_octet() {
        assert!(!valid_ip("10.0.0.256"));
    }

    #[test]
    fn valid_port_accepts_in_range() {
        assert!(valid_port("1"));
        assert!(valid_port("65535"));
    }

    #[test]
    fn valid_port_rejects_zero_and_out_of_range() {
        assert!(!valid_port("0"));
        assert!(!valid_port("65536"));
        assert!(!valid_port("not-a-port"));
    }

    #[test]
    fn is_private_origin_allows_empty_and_lan_prefixes() {
        assert!(is_private_origin(""));
        assert!(is_private_origin("http://192.168.0.1"));
    }

    #[test]
    fn is_private_origin_rejects_non_lan() {
        assert!(!is_private_origin("http://attacker.example.com"));
    }

    #[test]
    fn safe_redirect_accepts_cgi_bin_path() {
        assert_eq!(safe_redirect(Some("/cgi-bin/status")), Some("/cgi-bin/status".to_string()));
    }

    #[test]
    fn safe_redirect_rejects_absolute_url() {
        assert_eq!(safe_redirect(Some("http://evil.example.com")), None);
    }

    #[test]
    fn safe_redirect_none_when_absent() {
        assert_eq!(safe_redirect(None), None);
    }
}
