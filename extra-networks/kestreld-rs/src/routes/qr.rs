use axum::{extract::{Query, State}, response::Response};
use axum::http::{header, StatusCode};
use serde::Deserialize;
use std::sync::Arc;
use tokio::process::Command;

use crate::state::AppState;

#[derive(Deserialize)]
pub struct QrQuery {
    pub net: Option<String>,
}

pub async fn get(
    State(state): State<Arc<AppState>>,
    Query(params): Query<QrQuery>,
) -> Response<String> {
    let net = params.net.as_deref().unwrap_or("");
    if net.is_empty() || !net.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return err(StatusCode::BAD_REQUEST, "Invalid network");
    }

    let snap = state.snap().await;
    let conf = match snap.net_confs.iter().find(|c| c.iface == net) {
        Some(c) => c,
        None => return err(StatusCode::NOT_FOUND, "Network not found"),
    };

    if !conf.show_qr {
        return err(StatusCode::FORBIDDEN, "QR not enabled for this network");
    }

    let (ssid, key, enc) = match snap.wifi_keys.get(net) {
        Some(t) => t.clone(),
        None => return err(StatusCode::NOT_FOUND, "WiFi not configured"),
    };

    if ssid.is_empty() || key.is_empty() {
        return err(StatusCode::NOT_FOUND, "SSID or key missing");
    }

    let wtype = if enc.starts_with("sae") || enc.starts_with("psk") {
        "WPA"
    } else if enc.starts_with("wep") {
        "WEP"
    } else {
        "nopass"
    };

    let wifi_str = format!("WIFI:S:{ssid};T:{wtype};P:{key};;");

    let out = Command::new("qrencode")
        .args(["-t", "SVG", "-s", "4", "-m", "2", "-o", "-", &wifi_str])
        .output()
        .await;

    match out {
        Ok(o) if o.status.success() => {
            Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, "image/svg+xml")
                .header(header::CACHE_CONTROL, "no-store")
                .body(String::from_utf8_lossy(&o.stdout).into_owned())
                .unwrap()
        }
        _ => err(StatusCode::INTERNAL_SERVER_ERROR, "qrencode failed"),
    }
}

fn err(status: StatusCode, msg: &str) -> Response<String> {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "text/plain")
        .body(msg.to_string())
        .unwrap()
}
