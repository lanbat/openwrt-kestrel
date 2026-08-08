//! Local device presence observations.

use crate::ids::{DeviceId, Hash32, NodeId};
use crate::opinion::Timestamp;

pub const MAX_PRESENCE_NETWORK_LEN: usize = 128;
pub const MAX_PRESENCE_SOURCE_LEN: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DevicePresenceObservation {
    /// Router-local observation identity. It is not a global device identity.
    pub observation_id: Hash32,
    /// Present only when the router has a confirmed or explicitly shareable
    /// cross-network device identity.
    pub device_id: Option<DeviceId>,
    pub observer: NodeId,
    pub network: String,
    pub source: String,
    pub first_seen: Timestamp,
    pub last_seen: Timestamp,
    pub expires_at: Option<Timestamp>,
}

impl DevicePresenceObservation {
    pub fn validate(&self) -> Result<(), String> {
        if self.network.trim().is_empty() || self.network.len() > MAX_PRESENCE_NETWORK_LEN {
            return Err(format!(
                "presence network must be 1-{MAX_PRESENCE_NETWORK_LEN} bytes"
            ));
        }
        if self.source.trim().is_empty() || self.source.len() > MAX_PRESENCE_SOURCE_LEN {
            return Err(format!(
                "presence source must be 1-{MAX_PRESENCE_SOURCE_LEN} bytes"
            ));
        }
        if self.first_seen > self.last_seen {
            return Err("presence first_seen must not be after last_seen".into());
        }
        Ok(())
    }

    pub fn is_expired(&self, now: Timestamp) -> bool {
        matches!(self.expires_at, Some(expiry) if expiry <= now)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> DevicePresenceObservation {
        DevicePresenceObservation {
            observation_id: Hash32([1; 32]),
            device_id: Some(DeviceId(Hash32([2; 32]))),
            observer: NodeId(Hash32([3; 32])),
            network: "guest".into(),
            source: "dhcp".into(),
            first_seen: 10,
            last_seen: 20,
            expires_at: Some(30),
        }
    }

    #[test]
    fn presence_validates_and_expires() {
        let observation = sample();
        assert!(observation.validate().is_ok());
        assert!(!observation.is_expired(29));
        assert!(observation.is_expired(30));
    }

    #[test]
    fn presence_rejects_invalid_time_order() {
        let mut observation = sample();
        observation.first_seen = 21;
        assert!(observation.validate().is_err());
    }
}
