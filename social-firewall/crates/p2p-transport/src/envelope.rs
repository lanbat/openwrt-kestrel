use thiserror::Error;

/// Which existing `ingest_X` function a received envelope should be
/// dispatched to. Every variant maps to an already-supported signed
/// statement ingest path; the transport only moves its bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatementKind {
    TunnelConnectionRequest,
    TunnelConnectionAccept,
    GroupJoinRequest,
    Group,
    PartyLineMessage,
    RestrictedTunnelAdvertisement,
    RestrictedTunnelServiceRequest,
    RestrictedSharedRuleList,
    SyncGroupRequest,
    SyncGroupResponse,
    SharedPolicy,
    PolicyVote,
    FingerprintObservation,
    FingerprintComment,
    DirectMessage,
}

impl StatementKind {
    pub fn wire_tag(self) -> u8 {
        match self {
            StatementKind::TunnelConnectionRequest => 1,
            StatementKind::TunnelConnectionAccept => 2,
            StatementKind::GroupJoinRequest => 3,
            StatementKind::Group => 4,
            StatementKind::PartyLineMessage => 5,
            StatementKind::RestrictedTunnelAdvertisement => 6,
            StatementKind::RestrictedTunnelServiceRequest => 7,
            StatementKind::RestrictedSharedRuleList => 8,
            StatementKind::SyncGroupRequest => 9,
            StatementKind::SyncGroupResponse => 10,
            StatementKind::SharedPolicy => 11,
            StatementKind::PolicyVote => 12,
            StatementKind::FingerprintObservation => 13,
            StatementKind::FingerprintComment => 14,
            StatementKind::DirectMessage => 15,
        }
    }

    fn from_tag(tag: u8) -> Option<Self> {
        match tag {
            1 => Some(StatementKind::TunnelConnectionRequest),
            2 => Some(StatementKind::TunnelConnectionAccept),
            3 => Some(StatementKind::GroupJoinRequest),
            4 => Some(StatementKind::Group),
            5 => Some(StatementKind::PartyLineMessage),
            6 => Some(StatementKind::RestrictedTunnelAdvertisement),
            7 => Some(StatementKind::RestrictedTunnelServiceRequest),
            8 => Some(StatementKind::RestrictedSharedRuleList),
            9 => Some(StatementKind::SyncGroupRequest),
            10 => Some(StatementKind::SyncGroupResponse),
            11 => Some(StatementKind::SharedPolicy),
            12 => Some(StatementKind::PolicyVote),
            13 => Some(StatementKind::FingerprintObservation),
            14 => Some(StatementKind::FingerprintComment),
            15 => Some(StatementKind::DirectMessage),
            _ => None,
        }
    }
}

/// One statement in transit: a `kind` tag plus the exact same JSON bytes
/// `--out` already writes today (see this plan's Global Constraints — no
/// new wire format for the payload itself, only a thin wrapper around it).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Envelope {
    pub kind: StatementKind,
    pub payload: Vec<u8>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum EnvelopeError {
    #[error("envelope too short to contain a kind tag")]
    TooShort,
    #[error("unrecognized statement kind tag {0}")]
    UnknownKind(u8),
}

impl Envelope {
    /// One tag byte followed by the raw payload — deliberately minimal,
    /// no length-prefixing needed since this is one envelope per QUIC
    /// stream (see the design spec's Wire shape section: the receiver
    /// reads to end-of-stream, not to a declared length).
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + self.payload.len());
        out.push(self.kind.wire_tag());
        out.extend_from_slice(&self.payload);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Envelope, EnvelopeError> {
        let (tag, payload) = bytes.split_first().ok_or(EnvelopeError::TooShort)?;
        let kind = StatementKind::from_tag(*tag).ok_or(EnvelopeError::UnknownKind(*tag))?;
        Ok(Envelope {
            kind,
            payload: payload.to_vec(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn envelope_round_trips_through_encode_decode() {
        let original = Envelope {
            kind: StatementKind::TunnelConnectionRequest,
            payload: b"{\"hello\":true}".to_vec(),
        };
        let decoded = Envelope::decode(&original.encode()).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn envelope_decode_rejects_an_unknown_kind_tag() {
        let bytes = vec![99u8, b'{', b'}'];
        assert_eq!(
            Envelope::decode(&bytes),
            Err(EnvelopeError::UnknownKind(99))
        );
    }

    #[test]
    fn envelope_decode_rejects_an_empty_buffer() {
        assert_eq!(Envelope::decode(&[]), Err(EnvelopeError::TooShort));
    }
}
