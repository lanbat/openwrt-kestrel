use axum::{extract::State, response::Json, Form};
use serde::{Deserialize, Serialize};
use std::process::Stdio;
use std::sync::Arc;
use tokio::io::AsyncReadExt;
use tokio::process::Command;

use crate::cmd::silent;
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
        return Json(ApiResult {
            ok: false,
            error: Some("Invalid network".into()),
        });
    }

    let snap = state.snap().await;
    let conf = match snap.net_confs.iter().find(|c| c.iface == net) {
        Some(c) => c,
        None => {
            return Json(ApiResult {
                ok: false,
                error: Some("Network not found".into()),
            })
        }
    };

    if !conf.rotate_password {
        return Json(ApiResult {
            ok: false,
            error: Some("rotate_password not enabled".into()),
        });
    }

    // Verify wireless section exists
    let uci_check = silent(Command::new("uci").args(["-q", "get", &format!("wireless.{net}")]))
        .status()
        .await;
    if !uci_check.map(|s| s.success()).unwrap_or(false) {
        return Json(ApiResult {
            ok: false,
            error: Some("Wireless section not found".into()),
        });
    }

    // Generate 20-char alphanumeric password from /dev/urandom
    let newpw = gen_password(20).await;

    // Set key in UCI
    let _ = silent(Command::new("uci").args(["set", &format!("wireless.{net}.key={newpw}")]))
        .status()
        .await;
    // Also set extra interface if it exists
    let _ = silent(Command::new("uci").args(["set", &format!("wireless.{net}_extra.key={newpw}")]))
        .status()
        .await;
    let _ = silent(Command::new("uci").args(["commit", "wireless"]))
        .status()
        .await;

    // Prune join state: keep only MACs that have labels
    let labels = state.store.all_labels(net).await.unwrap_or_default();
    for mac in state
        .store
        .join_approved_list(net)
        .await
        .unwrap_or_default()
    {
        if !labels.contains_key(&mac) {
            let _ = state.store.join_approved_remove(net, &mac).await;
        }
    }
    for mac in state
        .store
        .join_pending_map(net)
        .await
        .unwrap_or_default()
        .into_keys()
    {
        let _ = state.store.join_pending_remove(net, &mac).await;
    }
    for mac in state.store.join_denied_list(net).await.unwrap_or_default() {
        let _ = state.store.join_denied_remove(net, &mac).await;
    }

    // Patch live hostapd configs and reload via ubus, 5s from now so this
    // response reaches the client before their own WiFi session drops.
    //
    // This can't be a `tokio::spawn`'d task (as it once was): in CGI mode
    // — the only mode this actually runs in on a real router — the process
    // exits within milliseconds of returning the response below, which
    // drops the runtime and aborts any still-pending task before its sleep
    // ever finishes. The password was already committed to UCI above, but
    // the running hostapd would silently go on using the old one until
    // some unrelated future reload — a real WiFi/state split, not just a
    // cosmetic delay. A genuine detached child process, decoupled from the
    // tokio runtime, survives the parent's exit the same way
    // `cmd::spawn_macfilter` already relies on elsewhere in this codebase.
    if let Err(e) = spawn_delayed_apply(net, &newpw).await {
        eprintln!("rotate-password: failed to schedule hostapd reload: {e}");
    }

    // Send ntfy notification
    if !conf.notify_url.is_empty() {
        crate::cmd::ntfy(
            &conf.notify_url,
            &format!("Password rotated — {}", conf.iface),
            "default",
            "key",
            &format!("New WiFi password for {}: {}", conf.iface, newpw),
        )
        .await;
    }

    Json(ApiResult {
        ok: true,
        error: None,
    })
}

async fn gen_password(len: usize) -> String {
    let mut f = tokio::fs::File::open("/dev/urandom")
        .await
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

/// Marker argv this binary re-execs itself with (see `main.rs`) to run
/// `apply_password_change` as a real detached OS process instead of a
/// tokio task, so it survives the CGI parent exiting.
pub const ROTATE_APPLY_ARG: &str = "--rotate-apply";

/// Writes `newpw` to a private temp file and re-execs this same binary
/// (detached — its own stdin/stdout/stderr are all `/dev/null`, so it
/// can't inherit anything and doesn't hold the CGI response open) with
/// `ROTATE_APPLY_ARG iface pwfile`, which sleeps 5s then calls
/// `apply_password_change` and deletes the temp file. Fire-and-forget:
/// this function returns as soon as the child is spawned.
async fn spawn_delayed_apply(iface: &str, newpw: &str) -> std::io::Result<()> {
    let pwfile =
        std::env::temp_dir().join(format!("kestreld-rotate-{iface}-{}.pw", std::process::id()));
    tokio::fs::write(&pwfile, newpw).await?;

    let exe = std::env::current_exe()?;
    silent(
        Command::new(exe)
            .arg(ROTATE_APPLY_ARG)
            .arg(iface)
            .arg(&pwfile),
    )
    .stdin(Stdio::null())
    .spawn()?;
    Ok(())
}

/// The `ROTATE_APPLY_ARG` entry point, called directly from `main.rs`.
pub async fn run_delayed_apply(iface: &str, pwfile: &str) {
    tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
    let newpw = tokio::fs::read_to_string(pwfile).await.unwrap_or_default();
    let _ = tokio::fs::remove_file(pwfile).await;
    if !newpw.is_empty() {
        apply_password_change(iface, newpw.trim()).await;
    }
}

async fn apply_password_change(iface: &str, newpw: &str) {
    // Find hostapd configs for this interface
    let mut dir = match tokio::fs::read_dir("/var/run").await {
        Ok(d) => d,
        Err(_) => return,
    };
    while let Ok(Some(entry)) = dir.next_entry().await {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if !name.starts_with("hostapd-") || !name.ends_with(".conf") {
            continue;
        }
        let path = entry.path();
        let content = match tokio::fs::read_to_string(&path).await {
            Ok(c) => c,
            Err(_) => continue,
        };
        if !content.contains(&format!("bridge=br-{iface}")) {
            continue;
        }
        // Patch wpa_passphrase
        let patched: String = content
            .lines()
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
        let phy = path
            .file_stem()
            .map(|s| s.to_string_lossy().replace("hostapd-", ""))
            .unwrap_or_default();
        if !phy.is_empty() {
            let prev = path.with_extension("prev");
            let _ = tokio::fs::write(&prev, &patched).await;
            let _ = silent(Command::new("ubus").args([
                "call",
                "hostapd",
                "config_set",
                &format!(
                    "{{\"phy\":\"{phy}\",\"radio\":-1,\"config\":\"{}\",\"prev_config\":\"{}\"}}",
                    path.display(),
                    prev.display()
                ),
            ]))
            .status()
            .await;
        }
    }
}
