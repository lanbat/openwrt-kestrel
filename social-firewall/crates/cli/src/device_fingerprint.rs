use anyhow::{Context, Result};
use serde::Deserialize;
use std::io::{Read, Write};
use std::net::IpAddr;
use std::os::unix::net::UnixStream;
use std::path::Path;

#[derive(Debug, Deserialize)]
struct LookupResponse {
    record_id: String,
    network: String,
    material_hex: String,
    last_seen: u64,
}

pub(crate) struct DeviceFingerprint {
    pub(crate) record_id: String,
    pub(crate) network: String,
    pub(crate) material: Vec<u8>,
    pub(crate) last_seen: u64,
}

pub(crate) fn lookup(socket_path: &Path, source_ip: IpAddr) -> Result<Option<DeviceFingerprint>> {
    let mut stream = UnixStream::connect(socket_path)
        .with_context(|| format!("connecting to {}", socket_path.display()))?;
    stream.write_all(
        serde_json::json!({"source_ip": source_ip.to_string()})
            .to_string()
            .as_bytes(),
    )?;
    stream.write_all(b"\n")?;
    let mut body = String::new();
    stream.read_to_string(&mut body)?;
    let value: serde_json::Value = serde_json::from_str(body.trim())?;
    if value.get("error").is_some() {
        return Ok(None);
    }
    let response: LookupResponse = serde_json::from_value(value)?;
    Ok(Some(DeviceFingerprint {
        record_id: response.record_id,
        network: response.network,
        material: hex::decode(response.material_hex)?,
        last_seen: response.last_seen,
    }))
}
