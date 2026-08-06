use super::fingerprint::FingerprintRecord;

pub const SHARED_FINGERPRINT_VERSION: u8 = 1;

/// Produces the versioned, privacy-filtered material consumed by the
/// social-firewall group-scoped derivation. MACs, IPs, cookies, HTTP headers,
/// labels, and timestamps are deliberately excluded.
pub fn canonical_material(record: &FingerprintRecord) -> Vec<u8> {
    let mut material = Vec::new();
    material.push(SHARED_FINGERPRINT_VERSION);
    for value in [
        record.dhcp_options.as_str(),
        record.dhcp_vendor.as_str(),
        record.wifi_caps.as_str(),
        record.mdns_name.as_str(),
        record.mdns_model.as_str(),
        record.tls_clienthello.as_str(),
        record.quic_initial.as_str(),
    ] {
        material.extend_from_slice(&(value.len() as u32).to_be_bytes());
        material.extend_from_slice(value.as_bytes());
    }
    material
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shared_material_excludes_local_and_sensitive_fields() {
        let record = FingerprintRecord {
            id: "local-id".into(),
            label: "Alice's phone".into(),
            dhcp_options: "1,3,6".into(),
            dhcp_vendor: "phone".into(),
            wifi_caps: "he".into(),
            mdns_name: "phone.local".into(),
            mdns_model: "model".into(),
            macs: vec!["aa:bb:cc:dd:ee:ff".into()],
            last_seen: 99,
            first_seen: 1,
            label_history: vec![("old label".into(), 2)],
            browser_cookie: "cookie".into(),
            http_headers: "raw headers".into(),
            tcp_syn: "syn".into(),
            tls_clienthello: "tls".into(),
            quic_initial: "quic".into(),
            evidence: vec![],
        };
        let material = canonical_material(&record);
        assert!(!material.windows("Alice's phone".len()).any(|w| w == b"Alice's phone"));
        assert!(!material.windows("cookie".len()).any(|w| w == b"cookie"));
        assert!(!material.windows("raw headers".len()).any(|w| w == b"raw headers"));
        assert!(material.ends_with(b"quic"));
    }
}
