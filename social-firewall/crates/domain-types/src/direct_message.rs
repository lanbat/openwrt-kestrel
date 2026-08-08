use crate::canonical::CanonicalEncode;
use crate::ids::{SignatureBytes, UserId};
use crate::opinion::Timestamp;

pub const MAX_DIRECT_MESSAGE_LEN: usize = 4096;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectMessage {
    pub sender: UserId,
    pub recipient: UserId,
    pub sequence: u64,
    pub body: String,
    pub issued_at: Timestamp,
    pub signature: SignatureBytes,
}

impl DirectMessage {
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.sender.canonical_encode(&mut out);
        self.recipient.canonical_encode(&mut out);
        self.sequence.canonical_encode(&mut out);
        self.body.canonical_encode(&mut out);
        self.issued_at.canonical_encode(&mut out);
        out
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.body.is_empty() || self.body.len() > MAX_DIRECT_MESSAGE_LEN {
            return Err(format!(
                "direct message body must be 1-{MAX_DIRECT_MESSAGE_LEN} bytes"
            ));
        }
        if self.sender == self.recipient {
            return Err("direct message sender and recipient must differ".into());
        }
        Ok(())
    }
}
