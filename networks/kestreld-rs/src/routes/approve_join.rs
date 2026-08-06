use axum::{
    extract::{Query, State},
    http::HeaderMap,
    response::{Html, Json},
    Form,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::data::files;
use crate::routes::safe_redirect;
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
    pub redirect: Option<String>,
    // Carried through from the fingerprint gathered when the join prompt
    // (GET) was rendered — see `crate::data::fingerprint`. Present only
    // when the MAC was randomized; empty/absent otherwise. Kept as plain
    // hidden form fields rather than re-querying mDNS/DHCP logs on POST,
    // so approving a device never itself triggers a network round-trip.
    pub dhcp_options: Option<String>,
    pub dhcp_vendor: Option<String>,
    pub wifi_caps: Option<String>,
    pub mdns_name: Option<String>,
    pub mdns_model: Option<String>,
    // Set only when this approval came from clicking a fingerprint-match
    // suggestion button — tells the "approve" handler to fold this MAC
    // into that *existing* identity (`fingerprint::merge_into`) instead of
    // registering a brand-new one (`fingerprint::create`).
    pub identity_id: Option<String>,
    pub browser_cookie: Option<String>,
    pub http_headers: Option<String>,
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
            if i % 3 == 2 {
                c == ':'
            } else {
                c.is_ascii_hexdigit()
            }
        })
}

fn is_private_origin(origin: &str) -> bool {
    if origin.is_empty() {
        return true;
    }
    let prefixes = [
        "http://192.168.",
        "http://10.",
        "http://172.1",
        "http://172.2",
        "http://172.30.",
        "http://172.31.",
        "http://127.",
        "http://[fd",
        "http://[fc",
        "http://[fe80",
        "http://[::1]",
    ];
    prefixes.iter().any(|p| origin.starts_with(p))
}

pub async fn get(
    State(state): State<Arc<AppState>>,
    Query(params): Query<JoinQuery>,
    headers: HeaderMap,
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
    let conf = snap.net_confs.iter().find(|c| c.iface == net);
    let existing_label = snap
        .labels
        .get(net)
        .and_then(|m| m.get(&mac))
        .cloned()
        .unwrap_or_default();

    // Vendor hint from the MAC's OUI prefix — cheap context for the actual
    // decision moment (this page, reached from the push notification, is
    // where approve/deny actually happens; the OUI database was already
    // loaded for the status/device pages but never used here). Unreliable
    // against randomized MACs (iOS/Android default to it now), but still
    // useful for most IoT/embedded gear.
    let manufacturer = crate::data::files::oui_lookup(&state.oui, &mac).to_string();
    let is_randomized = crate::data::files::is_randomized_mac(&mac);

    // Most recent past decision for this exact MAC on this network, if
    // any — most relevant when it was previously denied or deleted: did
    // the same device just try again?
    let history = state
        .store
        .recent_join_history(net, 5000)
        .await
        .unwrap_or_default();
    let prior = history
        .iter()
        .find(|row| row.mac.eq_ignore_ascii_case(&mac)) // newest-first: first match is most recent
        .map(|row| (row.action.clone(), row.when_str.clone()));

    let device_display = if host.is_empty() {
        ip.to_string()
    } else {
        format!("{host} ({ip})")
    };
    let qs = format!("net={net}&ip={ip}&mac={mac}&host={host}");

    let label_esc = html_escape(&existing_label);
    let device_esc = html_escape(&device_display);
    let manufacturer_esc = html_escape(&manufacturer);
    let manufacturer_row = if !manufacturer.is_empty() {
        format!(
            r#"<div class="card"><div class="lbl">Manufacturer</div><div class="value">{manufacturer_esc}</div></div>"#
        )
    } else if is_randomized {
        r#"<div class="card"><div class="lbl">Manufacturer</div><div class="value dim">Randomized MAC</div></div>"#.to_string()
    } else {
        String::new()
    };
    let prior_note = prior_note_html(prior.as_ref());

    // Fingerprint-based "is this a device we already know, just on a new
    // randomized MAC" suggestion — see `data::fingerprint`. Only worth
    // the ~1.2s mDNS round-trip when the MAC is actually randomized, the
    // network is known, and this network hasn't opted out
    // (FINGERPRINT_SUGGEST=no) of the guesswork; fixed MACs already
    // identify a device permanently on their own.
    let fingerprint_enabled = is_randomized && conf.is_some_and(|c| c.fingerprint_suggest);
    let observed = if let (true, Some(c)) = (fingerprint_enabled, conf) {
        let bridge_ip = format!("{}.1", c.subnet);
        crate::data::fingerprint::Observed::gather(&snap.logs.lines, net, &mac, ip, &bridge_ip)
            .await
    } else {
        crate::data::fingerprint::Observed::default()
    };
    let mut observed = observed;
    if let Some(cookie) = headers
        .get("cookie")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| crate::data::fingerprint_signals::parse_cookie(v, "kestrel_identity"))
    {
        observed.browser_cookie = cookie;
    }
    let h = [
        "user-agent",
        "accept-language",
        "accept-encoding",
        "sec-ch-ua",
        "sec-ch-ua-mobile",
        "sec-ch-ua-platform",
    ];
    let pairs: Vec<_> = h
        .iter()
        .filter_map(|n| {
            headers
                .get(*n)
                .and_then(|v| v.to_str().ok())
                .map(|v| (*n, v))
        })
        .collect();
    observed.http_headers = crate::data::fingerprint_signals::header_fingerprint_string(
        &crate::data::fingerprint_signals::normalize_headers(&pairs),
    );
    let fp_hidden_fields = format!(
        r#"<input type="hidden" name="dhcp_options" value="{}"><input type="hidden" name="dhcp_vendor" value="{}"><input type="hidden" name="wifi_caps" value="{}"><input type="hidden" name="mdns_name" value="{}"><input type="hidden" name="mdns_model" value="{}"><input type="hidden" name="browser_cookie" value="{}"><input type="hidden" name="http_headers" value="{}">"#,
        html_escape(&observed.dhcp.requested_options),
        html_escape(&observed.dhcp.vendor_class),
        html_escape(&observed.wifi_caps),
        html_escape(&observed.mdns.name),
        html_escape(&observed.mdns.model),
        html_escape(&observed.browser_cookie),
        html_escape(&observed.http_headers),
    );
    let suggestion_html = if fingerprint_enabled {
        let records = crate::data::fingerprint::read_registry(&state.store, net).await;
        use crate::data::fingerprint::MatchResult;
        match crate::data::fingerprint::best_match(&observed, &records) {
            MatchResult::None => String::new(),
            MatchResult::Confident(matched, _score) => {
                let seen_as = matched.macs.len();
                let button = suggestion_button_html(
                    &qs,
                    &fp_hidden_fields,
                    &matched.id,
                    &matched.label,
                    "Yes — approve as",
                );
                format!(
                    r#"<div class="note match">
  <div>💡 This might be a device you already know: <strong>{}</strong> (seen on {seen_as} other MAC address{} before).</div>
  {button}
</div>"#,
                    html_escape(&matched.label),
                    if seen_as == 1 { "" } else { "es" },
                )
            }
            MatchResult::Ambiguous(candidates) => {
                let buttons: String = candidates
                    .iter()
                    .map(|(r, _)| {
                        suggestion_button_html(
                            &qs,
                            &fp_hidden_fields,
                            &r.id,
                            &r.label,
                            "Could be — approve as",
                        )
                    })
                    .collect();
                format!(
                    r#"<div class="note match">
  <div>💡 This could be a device you already know — but it scores similarly close to more than one, so pick carefully rather than trusting a single guess:</div>
  {buttons}
</div>"#
                )
            }
        }
    } else {
        String::new()
    };

    Html(format!(
        r#"<!DOCTYPE html><html><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Join request — {net}</title>
<style>
body{{font-family:system-ui,sans-serif;max-width:480px;margin:4rem auto;padding:1rem;color:#111}}
h1{{font-size:1.3rem;margin-bottom:1.5rem}}
.card{{background:#f5f5f5;border-radius:8px;padding:1rem;margin:.75rem 0}}
.lbl{{font-size:.75rem;text-transform:uppercase;letter-spacing:.05em;color:#888;margin-bottom:.25rem}}
.value{{font-weight:600}}
.value.dim{{font-weight:400;color:#888}}
input[type=text]{{width:100%;box-sizing:border-box;padding:.5rem .75rem;font-size:1rem;border:1px solid #ccc;border-radius:6px;margin-top:.25rem}}
button{{font-size:1rem;padding:.65rem 1rem;border-radius:6px;border:none;cursor:pointer;width:100%;margin-top:.5rem}}
.btn-ok{{background:#1976d2;color:#fff}}.btn-ok:active{{background:#1565c0}}
.btn-deny{{background:#c62828;color:#fff}}.btn-deny:active{{background:#b71c1c}}
.note{{background:#fff8e1;border-radius:8px;padding:.75rem;font-size:.85rem;margin:1rem 0}}
.note.warn{{background:#ffebee;color:#b71c1c}}
.note.match{{background:#e3f2fd;color:#0d47a1}}
.note.match form{{margin-top:.5rem}}
.note.match button{{margin-top:0}}
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
{manufacturer_row}
{prior_note}
{suggestion_html}
<div class="note">This device joined <strong>{net}</strong> and is waiting for internet access approval. Give it a label, then approve or deny.</div>
<form id="approve-form" method="POST" action="/cgi-bin/approve-join?{qs}">
  <input type="hidden" name="action" value="approve">
  <input type="hidden" name="redirect" value="/cgi-bin/status">
  {fp_hidden_fields}
  <div class="lbl" style="margin-top:1rem">Label <span style="color:#c62828">*</span></div>
  <input type="text" id="label-input" name="label" value="{label_esc}" placeholder="e.g. Alice's Phone" required maxlength="40">
  <button class="btn-ok" type="submit">Approve internet access</button>
</form>
<form id="deny-form" method="POST" action="/cgi-bin/approve-join?{qs}">
  <input type="hidden" name="action" value="deny">
  <input type="hidden" name="redirect" value="/cgi-bin/status">
  <button class="btn-deny" type="submit">Deny internet access</button>
</form>
<script>
(function(){{
  function submitJson(form) {{
    form.addEventListener('submit', function(e) {{
      e.preventDefault();
      var data = new URLSearchParams(new FormData(form));
      fetch(form.action, {{method:'POST', headers:{{'Content-Type':'application/x-www-form-urlencoded'}}, body: data.toString()}})
        .then(r => r.json())
        .then(j => {{ if (j.ok) location.href = j.redirect || '/cgi-bin/status';
                      else alert(j.error || 'Error'); }})
        .catch(() => form.submit());
    }});
  }}
  submitJson(document.getElementById('approve-form'));
  submitJson(document.getElementById('deny-form'));
  document.querySelectorAll('.suggestion-form').forEach(function(f) {{ submitJson(f); }});
}})();
</script>
</body></html>"#
    ))
}

pub async fn post(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Form(form): Form<JoinForm>,
) -> Json<ApiResult> {
    let origin = headers
        .get("origin")
        .or_else(|| headers.get("referer"))
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if !is_private_origin(origin) {
        return Json(ApiResult {
            ok: false,
            error: Some("Forbidden".into()),
            redirect: None,
        });
    }

    let net = form.net.as_deref().unwrap_or("");
    let mac = form.mac.as_deref().unwrap_or("").to_lowercase();
    let ip = form.ip.as_deref().unwrap_or("");
    let host = form.host.as_deref().unwrap_or("");
    let action = form.action.as_deref().unwrap_or("");

    if !net.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') || net.is_empty() {
        return Json(ApiResult {
            ok: false,
            error: Some("Invalid network".into()),
            redirect: None,
        });
    }
    // bulk_approve_labeled acts on every pending device with a saved label
    // at once, so — unlike every other action here — it has no single MAC
    // of its own to validate.
    if action != "bulk_approve_labeled" && !valid_mac(&mac) {
        return Json(ApiResult {
            ok: false,
            error: Some("Invalid MAC".into()),
            redirect: None,
        });
    }

    let snap = state.snap().await;
    let conf = match snap.net_confs.iter().find(|c| c.iface == net) {
        Some(c) => c,
        None => {
            return Json(ApiResult {
                ok: false,
                error: Some("Network not found".into()),
                redirect: None,
            })
        }
    };

    let base_dir = &state.base_dir;
    let remote_ip = headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("unknown")
        .split(',')
        .next()
        .unwrap_or("unknown")
        .trim()
        .to_string();
    let actor_mac = snap.neigh.mac_for_ip(&remote_ip).unwrap_or("").to_string();
    let redirect = safe_redirect(form.redirect.as_deref());

    // Approve every currently-pending device on this network that already
    // has a saved label, in one click — for the common case of several
    // known devices reconnecting at once (e.g. after a reboot), where
    // clicking Approve individually on each is pure friction. Devices
    // without a label are left pending, same as a single approve would
    // refuse them.
    if action == "bulk_approve_labeled" {
        let pending = snap.join_pending.get(net).cloned().unwrap_or_default();
        let labels = snap.labels.get(net).cloned().unwrap_or_default();
        for (pending_mac, pending_ip) in &pending {
            if let Some(label) = labels.get(pending_mac) {
                approve_device(
                    &state.store,
                    base_dir,
                    &state.split_routing_dir,
                    conf,
                    net,
                    pending_mac,
                    pending_ip,
                    "",
                    label,
                    &remote_ip,
                    &actor_mac,
                )
                .await;
            }
        }
        return Json(ApiResult {
            ok: true,
            error: None,
            redirect,
        });
    }

    // set_label action
    if action == "set_label" {
        let label = form
            .label
            .as_deref()
            .unwrap_or("")
            .trim()
            .chars()
            .take(40)
            .collect::<String>();
        if label.is_empty() {
            return Json(ApiResult {
                ok: false,
                error: Some("Label is required".into()),
                redirect: None,
            });
        }
        let _ = state.store.set_label(net, &mac, &label).await;
        crate::cmd::write_device_dns(base_dir, net, &mac, &label, "").await;

        crate::data::fingerprint::rename_if_known(&state.store, net, &mac, &label).await;

        if !conf.notify_url.is_empty() {
            let body = format!("MAC: {mac}\nNow: {label}\n\nBy: {remote_ip}");
            crate::cmd::ntfy(
                &conf.notify_url,
                &format!("Label set — {net}"),
                "default",
                "pencil2",
                &body,
            )
            .await;
        }
        return Json(ApiResult {
            ok: true,
            error: None,
            redirect,
        });
    }

    if !valid_ip(ip) {
        return Json(ApiResult {
            ok: false,
            error: Some("Invalid IP".into()),
            redirect: None,
        });
    }

    match action {
        "approve" => {
            let label = form
                .label
                .as_deref()
                .unwrap_or("")
                .trim()
                .chars()
                .take(40)
                .collect::<String>();
            let label = if label.is_empty() {
                snap.labels
                    .get(net)
                    .and_then(|m| m.get(&mac))
                    .cloned()
                    .unwrap_or_default()
            } else {
                label
            };
            if label.is_empty() {
                return Json(ApiResult {
                    ok: false,
                    error: Some("Label is required to approve a device".into()),
                    redirect: None,
                });
            }

            approve_device(
                &state.store,
                base_dir,
                &state.split_routing_dir,
                conf,
                net,
                &mac,
                ip,
                host,
                &label,
                &remote_ip,
                &actor_mac,
            )
            .await;

            // Opportunistically learn/refresh this identity's fingerprint —
            // using only whatever the join prompt already gathered and
            // carried through as hidden fields, never a fresh lookup here,
            // so approving a device never itself does network I/O. Only
            // relevant for randomized MACs; a fixed MAC already identifies
            // a device permanently on its own.
            if files::is_randomized_mac(&mac) {
                let observed = crate::data::fingerprint::Observed {
                    dhcp: crate::data::dhcp_fingerprint::DhcpFingerprint {
                        requested_options: form.dhcp_options.clone().unwrap_or_default(),
                        vendor_class: form.dhcp_vendor.clone().unwrap_or_default(),
                    },
                    wifi_caps: form.wifi_caps.clone().unwrap_or_default(),
                    mdns: crate::data::mdns::MdnsInfo {
                        name: form.mdns_name.clone().unwrap_or_default(),
                        model: form.mdns_model.clone().unwrap_or_default(),
                    },
                    browser_cookie: form.browser_cookie.clone().unwrap_or_default(),
                    http_headers: form.http_headers.clone().unwrap_or_default(),
                    tcp_syn: String::new(),
                    tls_clienthello: String::new(),
                    quic_initial: String::new(),
                };
                let now_ts = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();

                match form.identity_id.as_deref().filter(|id| !id.is_empty()) {
                    // A suggestion was confirmed: fold this MAC into that
                    // *existing* identity rather than starting a new one.
                    Some(id) => {
                        crate::data::fingerprint::merge_into(
                            &state.store,
                            net,
                            id,
                            &mac,
                            &observed,
                            now_ts,
                        )
                        .await;
                    }
                    // No suggestion was confirmed — only worth registering
                    // a brand-new identity if something was actually
                    // observed; an empty one would just be noise.
                    None if !observed.dhcp.is_empty()
                        || !observed.wifi_caps.is_empty()
                        || !observed.mdns.name.is_empty()
                        || !observed.mdns.model.is_empty() =>
                    {
                        crate::data::fingerprint::create(
                            &state.store,
                            net,
                            &label,
                            &mac,
                            &observed,
                            now_ts,
                        )
                        .await;
                    }
                    None => {}
                }
            }

            Json(ApiResult {
                ok: true,
                error: None,
                redirect,
            })
        }

        "deny" => {
            let is_ipv6 = ip.contains(':');
            let pending_set = if is_ipv6 {
                format!("{net}_join_pending6")
            } else {
                format!("{net}_join_pending")
            };

            // Add to denied
            let _ = state.store.join_denied_add(net, &mac).await;

            // Update pending (re-add/keep to keep IP visible — denied and
            // pending are deliberately independent sets, see db's module doc)
            let _ = state.store.join_pending_set(net, &mac, ip).await;

            crate::cmd::nft_add_element(&pending_set, ip, "").await;

            if !conf.notify_url.is_empty() {
                let body = format!("Type: Internet access denied\n\nDevice:\nIP: {ip}\nMAC: {mac}\nHostname: {}\n\nBy: {remote_ip}", if host.is_empty() { "unknown" } else { host });
                crate::cmd::ntfy(
                    &conf.notify_url,
                    &format!("Access denied — {net}"),
                    "default",
                    "no_entry",
                    &body,
                )
                .await;
            }

            let ip4 = if is_ipv6 {
                String::new()
            } else {
                ip.to_string()
            };
            crate::cmd::append_join_history(
                &state.store,
                net,
                "denied",
                &mac,
                &ip4,
                if is_ipv6 { ip } else { "" },
                host,
                &remote_ip,
                &remote_ip,
                "",
                &actor_mac,
            )
            .await;

            Json(ApiResult {
                ok: true,
                error: None,
                redirect,
            })
        }

        _ => Json(ApiResult {
            ok: false,
            error: Some("Invalid action".into()),
            redirect: None,
        }),
    }
}

/// The full state transition for approving one device: nft sets, the
/// approved/pending/denied files, device-control IP tracking, the label,
/// the ntfy push, and the join-history entry. Shared by the single-device
/// `"approve"` action and `"bulk_approve_labeled"`.
#[allow(clippy::too_many_arguments)]
async fn approve_device(
    store: &crate::db::Store,
    base_dir: &std::path::Path,
    split_routing_dir: &std::path::Path,
    conf: &crate::data::files::NetworkConf,
    net: &str,
    mac: &str,
    ip: &str,
    host: &str,
    label: &str,
    remote_ip: &str,
    actor_mac: &str,
) {
    let is_ipv6 = ip.contains(':');
    let pending_set = if is_ipv6 {
        format!("{net}_join_pending6")
    } else {
        format!("{net}_join_pending")
    };

    let _ = store.join_approved_add(net, mac).await;
    let _ = store.join_pending_remove(net, mac).await;
    let _ = store.join_denied_remove(net, mac).await;

    // NFT: remove from pending set, add to approved
    crate::cmd::nft_del_element(&pending_set, ip).await;
    let approved_set = if is_ipv6 {
        format!("{net}_join_approved_ips6")
    } else {
        format!("{net}_join_approved_ips")
    };
    crate::cmd::nft_add_element(&approved_set, ip, "").await;

    // Save approved IP
    let ip4 = if is_ipv6 {
        String::new()
    } else {
        ip.to_string()
    };
    let stored_ip = if is_ipv6 { "" } else { ip };
    let _ = store.join_approved_ips_set(net, mac, stored_ip).await;

    // Device control state
    if conf.device_control {
        if is_ipv6 {
            let _ = store.set_device_ip6(net, mac, ip).await;
        } else {
            let _ = store.set_device_ip(net, mac, ip).await;
        }
    }

    // Save label
    let _ = store.set_label(net, mac, label).await;
    crate::cmd::write_device_dns(base_dir, net, mac, label, "").await;

    // regen_inspect reads both the label and (for DEVICE_CONTROL networks)
    // the device-ip data it was just given above — it must run *after*
    // both are written, or a device's very first approval regenerates the
    // inspect chain from stale (empty) label/IP data and never gets its
    // per-device allow/observe sets until something else happens to
    // trigger another regen. Confirmed against a real QEMU VM: approving
    // a brand-new device produced an inspect chain with no per-device
    // rules at all until this was fixed.
    if conf.device_control {
        crate::regen_inspect::run(base_dir, split_routing_dir, store, net).await;
    }

    // ntfy
    if !conf.notify_url.is_empty() {
        let body = format!("Type: Internet access approved\n\nDevice:\nIP: {ip}\nMAC: {mac}\nHostname: {}\n\nBy: {remote_ip}", if host.is_empty() { "unknown" } else { host });
        crate::cmd::ntfy(
            &conf.notify_url,
            &format!("Access approved — {net}"),
            "default",
            "white_check_mark",
            &body,
        )
        .await;
    }

    crate::cmd::append_join_history(
        store,
        net,
        "approved",
        mac,
        &ip4,
        if is_ipv6 { ip } else { "" },
        host,
        remote_ip,
        remote_ip,
        "",
        actor_mac,
    )
    .await;
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// One "approve as this suggested identity" button — used for both the
/// single-candidate (`Confident`) and multi-candidate (`Ambiguous`) cases,
/// so there can be more than one on the page; JS binds all of them by
/// class (`.suggestion-form`), not by a single element id.
fn suggestion_button_html(
    qs: &str,
    fp_hidden_fields: &str,
    id: &str,
    label: &str,
    verb: &str,
) -> String {
    let label_esc = html_escape(label);
    let id_esc = html_escape(id);
    format!(
        r#"<form class="suggestion-form" method="POST" action="/cgi-bin/approve-join?{qs}">
    <input type="hidden" name="action" value="approve">
    <input type="hidden" name="redirect" value="/cgi-bin/status">
    <input type="hidden" name="label" value="{label_esc}">
    <input type="hidden" name="identity_id" value="{id_esc}">
    {fp_hidden_fields}
    <button class="btn-ok" type="submit">{verb} "{label_esc}"</button>
  </form>"#
    )
}

/// Renders the "this MAC was seen before" hint on the join prompt from its
/// most recent past decision, if any. Denied/deleted get a warning
/// treatment — a repeat appearance of a MAC you already turned away is the
/// single most decision-relevant signal this page can show.
fn prior_note_html(prior: Option<&(String, String)>) -> String {
    match prior {
        Some((action, when)) if action == "denied" || action == "deleted" => format!(
            r#"<div class="note warn">⚠ You previously <strong>{action}</strong> this exact device ({}).</div>"#,
            html_escape(when)
        ),
        Some((action, when)) => format!(
            r#"<div class="note">This device was previously <strong>{action}</strong> ({}).</div>"#,
            html_escape(when)
        ),
        None => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_ip_accepts_ipv4_and_rejects_bad_octet() {
        assert!(valid_ip("192.168.1.1"));
        assert!(!valid_ip("192.168.1.999"));
    }

    #[test]
    fn valid_ip_accepts_ipv6() {
        assert!(valid_ip("fe80::1"));
    }

    #[test]
    fn valid_ip_rejects_wrong_ipv4_segment_count() {
        assert!(!valid_ip("1.2.3"));
    }

    #[test]
    fn valid_mac_accepts_well_formed_and_rejects_bad_length() {
        assert!(valid_mac("aa:bb:cc:dd:ee:ff"));
        assert!(!valid_mac("aa:bb:cc:dd:ee"));
    }

    #[test]
    fn valid_mac_rejects_wrong_separator() {
        assert!(!valid_mac("aabbccddeeff"));
    }

    #[test]
    fn is_private_origin_allows_empty_and_lan() {
        assert!(is_private_origin(""));
        assert!(is_private_origin("http://10.0.0.5"));
        assert!(is_private_origin("http://[fd00::1]"));
    }

    #[test]
    fn is_private_origin_allows_ipv4_loopback() {
        assert!(is_private_origin("http://127.0.0.1:8080"));
    }

    #[test]
    fn is_private_origin_rejects_non_lan() {
        assert!(!is_private_origin("http://example.com"));
    }

    #[test]
    fn html_escape_escapes_all_special_chars() {
        assert_eq!(
            html_escape(r#"<script>alert("x")&y</script>"#),
            "&lt;script&gt;alert(&quot;x&quot;)&amp;y&lt;/script&gt;"
        );
    }

    #[test]
    fn html_escape_leaves_plain_text_untouched() {
        assert_eq!(html_escape("Alice's Phone"), "Alice's Phone");
    }

    #[test]
    fn prior_note_html_empty_when_no_prior_decision() {
        assert_eq!(prior_note_html(None), "");
    }

    #[test]
    fn prior_note_html_warns_on_prior_denial() {
        let prior = ("denied".to_string(), "26 Jul 23:32".to_string());
        let html = prior_note_html(Some(&prior));
        assert!(html.contains("note warn"));
        assert!(html.contains("denied"));
        assert!(html.contains("26 Jul 23:32"));
    }

    #[test]
    fn prior_note_html_warns_on_prior_deletion() {
        let prior = ("deleted".to_string(), "1 Jan 00:00".to_string());
        assert!(prior_note_html(Some(&prior)).contains("note warn"));
    }

    #[test]
    fn prior_note_html_neutral_on_prior_approval() {
        let prior = ("approved".to_string(), "1 Jan 00:00".to_string());
        let html = prior_note_html(Some(&prior));
        assert!(!html.contains("warn"));
        assert!(html.contains("approved"));
    }
}
