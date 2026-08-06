//! Optional Linux AF_PACKET observer. It is intentionally a best-effort
//! metadata collector: no payload is retained and encrypted TLS/QUIC content
//! is not decrypted. OpenWrt builds without AF_PACKET support simply skip it.

use crate::data::{files, fingerprint_signals};
use crate::db::Store;
use std::path::Path;
use std::sync::Arc;

pub fn enabled(confs: &[files::NetworkConf]) -> bool {
    confs.iter().any(|c| c.fingerprint_packet_capture)
}

pub fn classify(packet: &[u8]) -> Option<String> {
    if let Some(x) = fingerprint_signals::parse_tcp_syn(packet) {
        return Some(format!(
            "tcp;ttl={};win={};opts={}",
            x.ttl, x.window, x.options
        ));
    }
    if let Some(x) = fingerprint_signals::parse_tls_client_hello(packet) {
        return Some(format!(
            "tls;v={};c={};e={};a={}",
            x.version, x.ciphers, x.extensions, x.alpn
        ));
    }
    fingerprint_signals::parse_quic_initial(packet)
        .map(|x| format!("quic;v={};{}", x.version, x.transport))
}

/// Starts capture only after an explicit network setting enables it. The
/// parser is exposed separately so builds/tests can exercise it without root.
pub async fn run_if_enabled(base_dir: &Path, store: Arc<Store>) {
    let confs = files::read_all_network_confs(base_dir).await;
    if !enabled(&confs) {
        return;
    }
    #[cfg(target_os = "linux")]
    for conf in confs.into_iter().filter(|c| c.fingerprint_packet_capture) {
        let store = Arc::clone(&store);
        tokio::task::spawn_blocking(move || capture_loop(conf, store));
    }
}

#[cfg(target_os = "linux")]
fn capture_loop(conf: files::NetworkConf, store: Arc<Store>) {
    use socket2::{Domain, Protocol, Socket, Type};
    let Ok(socket) = Socket::new(Domain::PACKET, Type::RAW, Some(Protocol::from(3))) else {
        return;
    };
    let bridge = format!("br-{}", conf.iface);
    if socket.bind_device(Some(bridge.as_bytes())).is_err() {
        return;
    }
    let mut buf = vec![std::mem::MaybeUninit::<u8>::uninit(); 65536];
    loop {
        let Ok(n) = socket.recv(&mut buf) else { return };
        // Only the bounded parser sees the packet; no raw bytes leave this scope.
        let initialized = unsafe { std::slice::from_raw_parts(buf.as_ptr() as *const u8, n) };
        if n >= 12 {
            let mac = initialized[6..12]
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<Vec<_>>()
                .join(":");
            if classify(initialized).is_some() {
                let handle = tokio::runtime::Handle::current();
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                handle.block_on(crate::data::fingerprint::ingest_packet(
                    &store,
                    &conf.iface,
                    &mac,
                    initialized,
                    now,
                ));
            }
        }
    }
}
