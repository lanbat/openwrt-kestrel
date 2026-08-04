use thiserror::Error;

/// Which existing `ingest_X` function a received envelope should be
/// dispatched to. Scoped to this plan's one proven flow for now — more
/// variants are added as more send paths get wired (see this plan's
/// Global Constraints).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatementKind {
    TunnelConnectionRequest,
    TunnelConnectionAccept,
}

impl StatementKind {
    fn tag(self) -> u8 {
        match self {
            StatementKind::TunnelConnectionRequest => 1,
            StatementKind::TunnelConnectionAccept => 2,
        }
    }

    fn from_tag(tag: u8) -> Option<Self> {
        match tag {
            1 => Some(StatementKind::TunnelConnectionRequest),
            2 => Some(StatementKind::TunnelConnectionAccept),
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
        out.push(self.kind.tag());
        out.extend_from_slice(&self.payload);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Envelope, EnvelopeError> {
        let (tag, payload) = bytes.split_first().ok_or(EnvelopeError::TooShort)?;
        let kind = StatementKind::from_tag(*tag).ok_or(EnvelopeError::UnknownKind(*tag))?;
        Ok(Envelope { kind, payload: payload.to_vec() })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn envelope_round_trips_through_encode_decode() {
        let original = Envelope { kind: StatementKind::TunnelConnectionRequest, payload: b"{\"hello\":true}".to_vec() };
        let decoded = Envelope::decode(&original.encode()).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn envelope_decode_rejects_an_unknown_kind_tag() {
        let bytes = vec![99u8, b'{', b'}'];
        assert_eq!(Envelope::decode(&bytes), Err(EnvelopeError::UnknownKind(99)));
    }

    #[test]
    fn envelope_decode_rejects_an_empty_buffer() {
        assert_eq!(Envelope::decode(&[]), Err(EnvelopeError::TooShort));
    }
}
