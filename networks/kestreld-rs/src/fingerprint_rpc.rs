//! Local device-fingerprint lookup for processes that observe a LAN source IP.

use crate::data::{dhcp, files, fingerprint, shared_fingerprint};
use crate::db::Store;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};

pub const DEFAULT_SOCKET: &str = "/var/run/kestreld/fingerprint.sock";

#[derive(Debug, Deserialize)]
struct LookupRequest {
    source_ip: String,
}

#[derive(Debug, Serialize)]
struct LookupResponse {
    record_id: String,
    network: String,
    material_hex: String,
    last_seen: u64,
}

#[derive(Debug, Serialize)]
struct ErrorResponse {
    error: String,
}

pub async fn run(base_dir: PathBuf, store: Arc<Store>, socket_path: PathBuf) -> Result<()> {
    if let Some(parent) = socket_path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    if tokio::fs::try_exists(&socket_path).await? {
        tokio::fs::remove_file(&socket_path).await?;
    }
    let listener = UnixListener::bind(&socket_path)?;
    #[cfg(unix)]
    std::fs::set_permissions(
        &socket_path,
        std::os::unix::fs::PermissionsExt::from_mode(0o660),
    )?;
    loop {
        let (stream, _) = listener.accept().await?;
        let base_dir = base_dir.clone();
        let store = Arc::clone(&store);
        tokio::spawn(async move {
            if let Err(error) = handle(stream, &base_dir, &store).await {
                eprintln!("fingerprint lookup failed: {error}");
            }
        });
    }
}

async fn handle(mut stream: UnixStream, base_dir: &Path, store: &Store) -> Result<()> {
    let mut line = String::new();
    BufReader::new(&mut stream).read_line(&mut line).await?;
    let request: LookupRequest = serde_json::from_str(line.trim())?;
    let result = lookup(base_dir, store, &request.source_ip).await;
    let body = match result {
        Ok(Some(response)) => serde_json::to_string(&response)?,
        Ok(None) => serde_json::to_string(&ErrorResponse {
            error: "device fingerprint not found".into(),
        })?,
        Err(error) => serde_json::to_string(&ErrorResponse {
            error: error.to_string(),
        })?,
    };
    stream.write_all(body.as_bytes()).await?;
    stream.write_all(b"\n").await?;
    Ok(())
}

async fn lookup(base_dir: &Path, store: &Store, source_ip: &str) -> Result<Option<LookupResponse>> {
    let lease = dhcp::fetch()
        .await
        .into_iter()
        .find(|lease| lease.ip == source_ip);
    let Some(lease) = lease else {
        return Ok(None);
    };
    let networks = files::read_all_network_confs(base_dir).await;
    for network in networks {
        let records = fingerprint::read_registry(store, &network.iface).await;
        if let Some(record) = records
            .iter()
            .find(|record| record.macs.iter().any(|mac| mac == &lease.mac))
        {
            return Ok(Some(LookupResponse {
                record_id: record.id.clone(),
                network: network.iface,
                material_hex: hex::encode(shared_fingerprint::canonical_material(record)),
                last_seen: record.last_seen,
            }));
        }
    }
    Ok(None)
}
