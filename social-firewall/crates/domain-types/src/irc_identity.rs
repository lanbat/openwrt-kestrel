use crate::canonical::CanonicalEncode;
use crate::ids::{SignatureBytes, UserId};
use crate::opinion::Timestamp;
use crate::sharing::MessagingPublicKeyBytes;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IrcIdentityAdvertisement {
    pub user: UserId,
    pub sequence: u64,
    pub messaging_pubkey: MessagingPublicKeyBytes,
    pub issued_at: Timestamp,
    pub signature: SignatureBytes,
}

impl IrcIdentityAdvertisement {
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.user.canonical_encode(&mut out);
        self.sequence.canonical_encode(&mut out);
        self.messaging_pubkey.canonical_encode(&mut out);
        self.issued_at.canonical_encode(&mut out);
        out
    }
}
