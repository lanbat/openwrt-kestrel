use axum::{
    extract::{Query, State},
    http::HeaderMap,
    response::{Html, Json},
    Form,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::data::files;
use crate::state::AppState;

#[derive(Deserialize)]
pub struct JoinQuery {
    pub net: Option<String>,
    pub ip: Option<String>,
    pub mac: Option<String>,
    pub host: Option<String>,
}

#[derive(Deserialize)]
pub struct JoinForm {
    pub net: Option<String>,
    pub ip: Option<String>,
    pub mac: Option<String>,
    pub host: Option<String>,
    pub action: Option<String>,
    pub label: Option<String>,
}

#[derive(Serialize)]
pub struct ApiResult {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redirect: Option<String>,
}

fn valid_ip(s: &str) -> bool {
    if s.contains(':') {
        s.chars().all(|c| c.is_ascii_hexdigit() || c == ':') && s.len() >= 2 && s.len() <= 39
    } else {
        s.split('.').count() == 4 && s.split('.').all(|p| p.parse::<u8>().is_ok())
    }
}

fn valid_mac(mac: &str) -> bool {
    mac.len() == 17
        && mac.chars().enumerate().all(|(i, c)| {
            if i % 3 == 2 { c == ':' } else { c.is_ascii_hexdigit() }
        })
}

fn is_private_origin(origin: &str) -> bool {
    if origin.is_empty() { return true; }
    let prefixes = ["http://192.168.", "http://10.", "http://172.1", "http://172.2",
        "http://172.30.", "http://172.31.", "http://[fd", "http://[fc",
        "http://[fe80", "http://[::1]"];
    prefixes.iter().any(|p| origin.starts_with(p))
}

pub async fn get(
    State(state): State<Arc<AppState>>,
    Query(params): Query<JoinQuery>,
) -> Html<String> {
    let net = params.net.as_deref().unwrap_or("");
    let ip = params.ip.as_deref().unwrap_or("");
    let mac = params.mac.as_deref().unwrap_or("").to_lowercase();
    let host = params.host.as_deref().unwrap_or("");

    if !net.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') || net.is_empty() {
        return Html("<h1>Invalid network</h1>".into());
    }
    if !valid_mac(&mac) {
        return Html("<h1>Invalid MAC</h1>".into());
    }
    if !ip.is_empty() && !valid_ip(ip) {
        return Html("<h1>Invalid IP</h1>".into());
    }

    let snap = state.snap().await;
    let existing_label = snap.labels.get(net)
        .and_then(|m| m.get(&mac))
        .cloned()
        .unwrap_or_default();

    let device_display = if host.is_empty() {
        ip.to_string()
    } else {
        format!("{host} ({ip})")
    };
    let qs = format!("net={net}&ip={ip}&mac={mac}&host={host}");

    let label_esc = html_escape(&existing_label);
    let device_esc = html_escape(&device_display);

    Html(format!(r#"<!DOCTYPE html><html><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Join request — {net}</title>
<style>
body{{font-family:system-ui,sans-serif;max-width:480px;margin:4rem auto;padding:1rem;color:#111}}
h1{{font-size:1.3rem;margin-bottom:1.5rem}}
.card{{background:#f5f5f5;border-radius:8px;padding:1rem;margin:.75rem 0}}
.lbl{{font-size:.75rem;text-transform:uppercase;letter-spacing:.05em;color:#888;margin-bottom:.25rem}}
.value{{font-weight:600}}
input[type=text]{{width:100%;box-sizing:border-box;padding:.5rem .75rem;font-size:1rem;border:1px solid #ccc;border-radius:6px;margin-top:.25rem}}
button{{font-size:1rem;padding:.65rem 1rem;border-radius:6px;border:none;cursor:pointer;width:100%;margin-top:.5rem}}
.btn-ok{{background:#1976d2;color:#fff}}.btn-ok:active{{background:#1565c0}}
.btn-deny{{background:#c62828;color:#fff}}.btn-deny:active{{background:#b71c1c}}
.note{{background:#fff8e1;border-radius:8px;padding:.75rem;font-size:.85rem;margin:1rem 0}}
</style></head><body>
<h1>Join request — {net}</h1>
<div class="card">
  <div class="lbl">Device</div>
  <div class="value">{device_esc}</div>
</div>
<div class="card">
  <div class="lbl">MAC address</div>
  <div class="value">{mac}</div>
</div>
<div class="note">This device joined <strong>{net}</strong> and is waiting for internet access approval. Give it a label, then approve or deny.</div>
<form id="approve-form" method="POST" action="/cgi-bin/approve-join?{qs}">
  <input type="hidden" name="action" value="approve">
  <div class="lbl" style="margin-top:1rem">Label <span style="color:#c62828">*</span></div>
  <input type="text" id="label-input" name="label" value="{label_esc}" placeholder="e.g. Alice's Phone" required maxlength="40">
  <button class="btn-ok" type="submit">Approve internet access</button>
</form>
<form id="deny-form" method="POST" action="/cgi-bin/approve-join?{qs}">
  <input type="hidden" name="action" value="deny">
  <button class="btn-deny" type="submit">Deny internet access</button>
</form>
<script>
(function(){{
  function submitJson(form, extraData) {{
    form.addEventListener('submit', function(e) {{
      e.preventDefault();
      var data = new URLSearchParams(new FormData(form));
      if (extraData) Object.entries(extraData).forEach(([k,v]) => data.set(k, v));
      fetch(form.action, {{method:'POST', headers:{{'Content-Type':'application/x-www-form-urlencoded'}}, body: data.toString()}})
        .then(r => r.json())
        .then(j => {{ if (j.ok) location.href = j.redirect || '/cgi-bin/status';
                      else alert(j.error || 'Error'); }})
        .catch(() => form.submit());
    }});
  }}
  submitJson(document.getElementById('approve-form'));
  submitJson(document.getElementById('deny-form'));
}})();
</script>
</body></html>"#))
}

pub async fn post(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Form(form): Form<JoinForm>,
) -> Json<ApiResult> {
    let origin = headers.get("origin")
        .or_else(|| headers.get("referer"))
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if !is_private_origin(origin) {
        return Json(ApiResult { ok: false, error: Some("Forbidden".into()), redirect: None });
    }

    let net = form.net.as_deref().unwrap_or("");
    let mac = form.mac.as_deref().unwrap_or("").to_lowercase();
    let ip = form.ip.as_deref().unwrap_or("");
    let host = form.host.as_deref().unwrap_or("");
    let action = form.action.as_deref().unwrap_or("");

    if !net.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') || net.is_empty() {
        return Json(ApiResult { ok: false, error: Some("Invalid network".into()), redirect: None });
    }
    if !valid_mac(&mac) {
        return Json(ApiResult { ok: false, error: Some("Invalid MAC".into()), redirect: None });
    }

    let snap = state.snap().await;
    let conf = match snap.net_confs.iter().find(|c| c.iface == net) {
        Some(c) => c,
        None => return Json(ApiResult { ok: false, error: Some("Network not found".into()), redirect: None }),
    };

    let base_dir = &state.base_dir;
    let remote_ip = headers.get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("unknown")
        .split(',').next().unwrap_or("unknown")
        .trim()
        .to_string();

    // set_label action
    if action == "set_label" {
        let label = form.label.as_deref().unwrap_or("").trim().chars().take(40).collect::<String>();
        if label.is_empty() {
            return Json(ApiResult { ok: false, error: Some("Label is required".into()), redirect: None });
        }
        let lbl_path = base_dir.join(format!("{net}-device-labels"));
        let _ = files::file_upsert_by_mac(&lbl_path, &mac, &format!("{mac}\t{label}")).await;
        crate::cmd::write_device_dns(base_dir, net, &mac, &label, "").await;

        if !conf.notify_url.is_empty() {
            let body = format!("MAC: {mac}\nNow: {label}\n\nBy: {remote_ip}");
            crate::cmd::ntfy(&conf.notify_url, &format!("Label set — {net}"), "default", "pencil2", &body).await;
        }
        return Json(ApiResult { ok: true, error: None, redirect: Some("/cgi-bin/status".into()) });
    }

    if !valid_ip(ip) {
        return Json(ApiResult { ok: false, error: Some("Invalid IP".into()), redirect: None });
    }

    match action {
        "approve" => {
            let label = form.label.as_deref().unwrap_or("").trim().chars().take(40).collect::<String>();
            let label = if label.is_empty() {
                snap.labels.get(net).and_then(|m| m.get(&mac)).cloned().unwrap_or_default()
            } else { label };
            if label.is_empty() {
                return Json(ApiResult { ok: false, error: Some("Label is required to approve a device".into()), redirect: None });
            }

            let is_ipv6 = ip.contains(':');
            let pending_set = if is_ipv6 { format!("{net}_join_pending6") } else { format!("{net}_join_pending") };

            // Update approved file
            let approved_path = base_dir.join(format!("{net}-join-approved"));
            let _ = files::file_remove_line(&approved_path, &mac).await;
            let _ = files::file_append(&approved_path, &mac).await;

            // Remove from pending and denied
            let _ = files::file_remove_space_prefix(&base_dir.join(format!("{net}-join-pending")), &mac).await;
            let _ = files::file_remove_line(&base_dir.join(format!("{net}-join-denied")), &mac).await;

            // NFT: remove from pending set, add to approved
            crate::cmd::nft_del_element(&pending_set, ip).await;
            let approved_set = if is_ipv6 {
                format!("{net}_join_approved_ips6")
            } else {
                format!("{net}_join_approved_ips")
            };
            crate::cmd::nft_add_element(&approved_set, ip, "").await;

            // Save approved IP (space-separated: mac ip)
            let ips_file = base_dir.join(format!("{net}-join-approved-ips"));
            let ip4 = if is_ipv6 { String::new() } else { ip.to_string() };
            let stored_ip = if is_ipv6 { "" } else { ip };
            let _ = files::file_remove_space_prefix(&ips_file, &mac).await;
            let _ = files::file_append(&ips_file, &format!("{mac} {stored_ip}")).await;

            // Device control state
            if conf.device_control {
                let ip_store = if is_ipv6 {
                    base_dir.join(format!("{net}-device-ip6s"))
                } else {
                    base_dir.join(format!("{net}-device-ips"))
                };
                let _ = files::file_upsert_by_mac(&ip_store, &mac, &format!("{mac}\t{ip}")).await;
                crate::cmd::regen_inspect(net).await;
            }

            // Save label
            let lbl_path = base_dir.join(format!("{net}-device-labels"));
            let _ = files::file_upsert_by_mac(&lbl_path, &mac, &format!("{mac}\t{label}")).await;
            crate::cmd::write_device_dns(base_dir, net, &mac, &label, "").await;

            // ntfy
            if !conf.notify_url.is_empty() {
                let body = format!("Type: Internet access approved\n\nDevice:\nIP: {ip}\nMAC: {mac}\nHostname: {}\n\nBy: {remote_ip}", if host.is_empty() { "unknown" } else { host });
                crate::cmd::ntfy(&conf.notify_url, &format!("Access approved — {net}"), "default", "white_check_mark", &body).await;
            }

            crate::cmd::append_join_history(base_dir, net, "approved", &mac, &ip4, if is_ipv6 { ip } else { "" },
                host, &remote_ip, &remote_ip, "", "").await;

            Json(ApiResult { ok: true, error: None, redirect: Some("/cgi-bin/status".into()) })
        }

        "deny" => {
            let is_ipv6 = ip.contains(':');
            let pending_set = if is_ipv6 { format!("{net}_join_pending6") } else { format!("{net}_join_pending") };

            // Add to denied
            let denied_path = base_dir.join(format!("{net}-join-denied"));
            let _ = files::file_remove_line(&denied_path, &mac).await;
            let _ = files::file_append(&denied_path, &mac).await;

            // Update pending (re-add/keep to keep IP visible)
            let pending_path = base_dir.join(format!("{net}-join-pending"));
            let _ = files::file_remove_space_prefix(&pending_path, &mac).await;
            let _ = files::file_append(&pending_path, &format!("{mac} {ip}")).await;

            crate::cmd::nft_add_element(&pending_set, ip, "").await;

            if !conf.notify_url.is_empty() {
                let body = format!("Type: Internet access denied\n\nDevice:\nIP: {ip}\nMAC: {mac}\nHostname: {}\n\nBy: {remote_ip}", if host.is_empty() { "unknown" } else { host });
                crate::cmd::ntfy(&conf.notify_url, &format!("Access denied — {net}"), "default", "no_entry", &body).await;
            }

            let ip4 = if is_ipv6 { String::new() } else { ip.to_string() };
            crate::cmd::append_join_history(base_dir, net, "denied", &mac, &ip4, if is_ipv6 { ip } else { "" },
                host, &remote_ip, &remote_ip, "", "").await;

            Json(ApiResult { ok: true, error: None, redirect: Some("/cgi-bin/status".into()) })
        }

        _ => Json(ApiResult { ok: false, error: Some("Invalid action".into()), redirect: None }),
    }
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}
