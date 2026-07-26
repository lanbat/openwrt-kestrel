use axum::{extract::State, response::Json, Form};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::io::AsyncReadExt;
use tokio::process::Command;

use crate::state::AppState;

#[derive(Deserialize)]
pub struct RotateForm {
    pub net: Option<String>,
}

#[derive(Serialize)]
pub struct ApiResult {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

pub async fn post(
    State(state): State<Arc<AppState>>,
    Form(form): Form<RotateForm>,
) -> Json<ApiResult> {
    let net = form.net.as_deref().unwrap_or("");
    if net.is_empty() || !net.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return Json(ApiResult { ok: false, error: Some("Invalid network".into()) });
    }

    let snap = state.snap().await;
    let conf = match snap.net_confs.iter().find(|c| c.iface == net) {
        Some(c) => c,
        None => return Json(ApiResult { ok: false, error: Some("Network not found".into()) }),
    };

    if !conf.rotate_password {
        return Json(ApiResult { ok: false, error: Some("rotate_password not enabled".into()) });
    }

    // Verify wireless section exists
    let uci_check = Command::new("uci")
        .args(["-q", "get", &format!("wireless.{net}")])
        .status().await;
    if !uci_check.map(|s| s.success()).unwrap_or(false) {
        return Json(ApiResult { ok: false, error: Some("Wireless section not found".into()) });
    }

    // Generate 20-char alphanumeric password from /dev/urandom
    let newpw = gen_password(20).await;

    // Set key in UCI
    let _ = Command::new("uci")
        .args(["set", &format!("wireless.{net}.key={newpw}")])
        .status().await;
    // Also set extra interface if it exists
    let _ = Command::new("uci")
        .args(["set", &format!("wireless.{net}_extra.key={newpw}")])
        .status().await;
    let _ = Command::new("uci").args(["commit", "wireless"]).status().await;

    // Prune join files: keep only MACs that have labels
    let base_dir = &state.base_dir;
    let labels = crate::data::files::read_labels(&base_dir.join(format!("{net}-device-labels"))).await;
    let approved_path = base_dir.join(format!("{net}-join-approved"));
    let content = tokio::fs::read_to_string(&approved_path).await.unwrap_or_default();
    let kept: String = content.lines()
        .filter(|l| labels.contains_key(&l.trim().to_lowercase()))
        .flat_map(|l| [l, "\n"])
        .collect();
    let _ = tokio::fs::write(&approved_path, kept).await;
    let _ = tokio::fs::remove_file(base_dir.join(format!("{net}-join-pending"))).await;
    let _ = tokio::fs::remove_file(base_dir.join(format!("{net}-join-denied"))).await;

    // Patch live hostapd configs and reload via ubus (deferred 5s)
    patch_hostapd_and_reload(net, &newpw);

    // Send ntfy notification
    if !conf.notify_url.is_empty() {
        crate::cmd::ntfy(
            &conf.notify_url,
            &format!("Password rotated — {}", conf.iface),
            "default",
            "key",
            &format!("New WiFi password for {}: {}", conf.iface, newpw),
        ).await;
    }

    Json(ApiResult { ok: true, error: None })
}

async fn gen_password(len: usize) -> String {
    let mut f = tokio::fs::File::open("/dev/urandom").await
        .expect("open /dev/urandom");
    let charset: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let mut buf = vec![0u8; len * 4];
    let _ = f.read_exact(&mut buf).await;
    buf.iter()
        .filter_map(|&b| {
            let idx = (b as usize) % charset.len();
            Some(charset[idx] as char)
        })
        .take(len)
        .collect()
}

fn patch_hostapd_and_reload(iface: &str, newpw: &str) {
    let iface = iface.to_string();
    let newpw = newpw.to_string();
    tokio::spawn(async move {
        tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
        // Find hostapd configs for this interface
        let mut dir = match tokio::fs::read_dir("/var/run").await {
            Ok(d) => d,
            Err(_) => return,
        };
        while let Ok(Some(entry)) = dir.next_entry().await {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if !name.starts_with("hostapd-") || !name.ends_with(".conf") { continue; }
            let path = entry.path();
            let content = match tokio::fs::read_to_string(&path).await {
                Ok(c) => c,
                Err(_) => continue,
            };
            if !content.contains(&format!("bridge=br-{iface}")) { continue; }
            // Patch wpa_passphrase
            let patched: String = content.lines()
                .map(|l| {
                    if l.starts_with("wpa_passphrase=") {
                        format!("wpa_passphrase={newpw}")
                    } else {
                        l.to_string()
                    }
                })
                .flat_map(|l| [l, "\n".to_string()])
                .collect();
            let _ = tokio::fs::write(&path, &patched).await;
            // Reload via ubus
            let phy = path.file_stem()
                .map(|s| s.to_string_lossy().replace("hostapd-", ""))
                .unwrap_or_default();
            if !phy.is_empty() {
                let prev = path.with_extension("prev");
                let _ = tokio::fs::write(&prev, &patched).await;
                let _ = Command::new("ubus")
                    .args(["call", "hostapd", "config_set",
                        &format!("{{\"phy\":\"{phy}\",\"radio\":-1,\"config\":\"{}\",\"prev_config\":\"{}\"}}",
                            path.display(), prev.display())])
                    .status().await;
            }
        }
    });
}
