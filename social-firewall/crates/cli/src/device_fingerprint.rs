use anyhow::{Context, Result};
use serde::Deserialize;
use std::io::{Read, Write};
use std::net::IpAddr;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

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
    stream.set_read_timeout(Some(Duration::from_millis(250)))?;
    stream.set_write_timeout(Some(Duration::from_millis(250)))?;
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

#[cfg(test)]
mod tests {
    use super::lookup;
    use std::io::{BufRead, Write};
    use std::os::unix::net::UnixListener;
    use std::thread;

    #[test]
    fn lookup_decodes_a_device_response() {
        let directory = tempfile::tempdir().unwrap();
        let socket = directory.path().join("fingerprint.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let thread = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = String::new();
            std::io::BufReader::new(&mut stream)
                .read_line(&mut request)
                .unwrap();
            assert!(request.contains("192.0.2.10"));
            stream
                .write_all(
                    br#"{"record_id":"device-1","network":"lan","material_hex":"0102","last_seen":42}
"#,
                )
                .unwrap();
        });

        let result = lookup(&socket, "192.0.2.10".parse().unwrap())
            .unwrap()
            .unwrap();
        thread.join().unwrap();
        assert_eq!(result.record_id, "device-1");
        assert_eq!(result.network, "lan");
        assert_eq!(result.material, vec![1, 2]);
        assert_eq!(result.last_seen, 42);
    }

    #[test]
    fn lookup_treats_a_not_found_response_as_empty() {
        let directory = tempfile::tempdir().unwrap();
        let socket = directory.path().join("fingerprint.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let thread = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = String::new();
            std::io::BufReader::new(&mut stream)
                .read_line(&mut request)
                .unwrap();
            stream
                .write_all(
                    br#"{"error":"device fingerprint not found"}
"#,
                )
                .unwrap();
        });

        assert!(lookup(&socket, "192.0.2.11".parse().unwrap())
            .unwrap()
            .is_none());
        thread.join().unwrap();
    }
}
