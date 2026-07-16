use axum::{
    extract::{Form, Query, State},
    response::{Html, Redirect},
};
use serde::Deserialize;
use std::sync::Arc;

use crate::state::AppState;

#[derive(Deserialize)]
pub struct DeviceQuery {
    pub net: Option<String>,
    pub mac: Option<String>,
}

pub fn render(net: &str, mac: &str) -> String {
    format!(r#"<!DOCTYPE html><html><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Device — {mac}</title>
<style>body{{font-family:system-ui,sans-serif;max-width:760px;margin:2rem auto;padding:1rem}}
h1{{font-size:1.4rem}}.sub{{color:#888;font-size:.85rem;margin-bottom:2rem}}
</style></head><body>
<h1>{mac}</h1>
<div class="sub">{net} &nbsp;·&nbsp; <a href="/cgi-bin/status">Dashboard</a></div>
<p><a href="/cgi-bin/device-shell?net={net}&amp;mac={mac}">Full device page (shell CGI)</a></p>
</body></html>"#)
}

pub async fn get(
    State(_state): State<Arc<AppState>>,
    Query(params): Query<DeviceQuery>,
) -> Html<String> {
    let net = params.net.as_deref().unwrap_or("lan");
    let mac = params.mac.as_deref().unwrap_or("");
    if !net.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') || net.is_empty() {
        return Html("<h1>Invalid network</h1>".to_string());
    }
    let mac_valid = mac.len() == 17
        && mac.chars().enumerate().all(|(i, c)| {
            if i % 3 == 2 { c == ':' } else { c.is_ascii_hexdigit() }
        });
    if !mac_valid {
        return Html("<h1>Invalid MAC</h1>".to_string());
    }
    Html(render(net, mac))
}

#[derive(Deserialize)]
pub struct DeviceForm {
    pub net: Option<String>,
    pub mac: Option<String>,
    pub action: Option<String>,
}

pub async fn post(
    State(_state): State<Arc<AppState>>,
    Form(form): Form<DeviceForm>,
) -> Redirect {
    // POST actions not yet implemented in Rust — delegate to shell CGI
    let net = form.net.as_deref().unwrap_or("lan");
    let mac = form.mac.as_deref().unwrap_or("");
    Redirect::to(&format!("/cgi-bin/device?net={net}&mac={mac}"))
}
