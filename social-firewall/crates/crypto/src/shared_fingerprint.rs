use domain_types::Hash32;

pub const SHARED_FINGERPRINT_VERSION: u8 = 1;

/// Only normalized, non-router-specific signals belong in a shared fingerprint.
/// MACs, IPs, cookies, raw headers, labels, and timestamps are intentionally
/// not represented here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SharedFingerprintSignals<'a> {
    pub dhcp_options: &'a str,
    pub dhcp_vendor: &'a str,
    pub wifi_caps: &'a str,
    pub mdns_name: &'a str,
    pub mdns_model: &'a str,
    pub tls_clienthello: &'a str,
    pub quic_initial: &'a str,
}

pub fn derive_shared_fingerprint(
    group_key: &[u8; 32],
    signals: &SharedFingerprintSignals<'_>,
) -> Hash32 {
    derive_shared_fingerprint_from_material(group_key, &canonical_material(signals))
}

pub fn derive_shared_fingerprint_from_material(
    group_key: &[u8; 32],
    material: &[u8],
) -> Hash32 {
    Hash32(*blake3::keyed_hash(group_key, material).as_bytes())
}

pub fn canonical_material(signals: &SharedFingerprintSignals<'_>) -> Vec<u8> {
    let mut message = Vec::new();
    message.push(SHARED_FINGERPRINT_VERSION);
    for value in [
        signals.dhcp_options,
        signals.dhcp_vendor,
        signals.wifi_caps,
        signals.mdns_name,
        signals.mdns_model,
        signals.tls_clienthello,
        signals.quic_initial,
    ] {
        message.extend_from_slice(&(value.len() as u32).to_be_bytes());
        message.extend_from_slice(value.as_bytes());
    }
    message
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signals() -> SharedFingerprintSignals<'static> {
        SharedFingerprintSignals {
            dhcp_options: "1,3,6,15",
            dhcp_vendor: "vendor",
            wifi_caps: "he,160mhz",
            mdns_name: "living-room-tv",
            mdns_model: "tv-model",
            tls_clienthello: "clienthello-v1",
            quic_initial: "",
        }
    }

    #[test]
    fn same_group_and_signals_produce_the_same_id() {
        let a = derive_shared_fingerprint(&[7; 32], &signals());
        let b = derive_shared_fingerprint(&[7; 32], &signals());
        assert_eq!(a, b);
    }

    #[test]
    fn different_group_keys_produce_different_ids() {
        assert_ne!(
            derive_shared_fingerprint(&[7; 32], &signals()),
            derive_shared_fingerprint(&[8; 32], &signals())
        );
    }

    #[test]
    fn stable_signal_changes_produce_different_ids() {
        let mut changed = signals();
        changed.mdns_model = "other-model";
        assert_ne!(
            derive_shared_fingerprint(&[7; 32], &signals()),
            derive_shared_fingerprint(&[7; 32], &changed)
        );
    }

    #[test]
    fn canonical_encoding_is_length_delimited() {
        let mut first = signals();
        first.dhcp_options = "ab";
        first.dhcp_vendor = "c";
        let mut second = signals();
        second.dhcp_options = "a";
        second.dhcp_vendor = "bc";
        assert_ne!(
            derive_shared_fingerprint(&[7; 32], &first),
            derive_shared_fingerprint(&[7; 32], &second)
        );
    }
}
