//! Signing, verification, and hashing over the canonical encodings from
//! `domain-types`. Ed25519 (small, fast, well-audited, fine for an
//! embedded router) via `ed25519-dalek`; BLAKE3 for content hashing.
//!
//! **Domain separation**: every signature is over `len(context) ||
//! context || message`, never the bare message. Without this, a
//! signature made for one message *kind* (say, an `ApprovalResponse`)
//! could potentially be replayed as if it were valid for a different kind
//! whose canonical encoding happens to produce the same bytes for some
//! input — length-prefixing the context makes `(context, message)` pairs
//! unambiguous, so a signature for one context can never be
//! reinterpreted as valid for another.

use crypto_box::{
    aead::rand_core::OsRng as BoxOsRng, PublicKey as BoxPublicKey, SecretKey as BoxSecretKey,
};
use domain_types::{
    DeviceId, GlobalFingerprintId, Hash32, IdentityId, MessagingPublicKeyBytes, PublicKeyBytes,
    SignatureBytes,
};
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use rand_core::OsRng;

pub mod contexts {
    pub const POLICY_OPINION: &[u8] = b"social-firewall.policy-opinion.v1";
    pub const LOCAL_OVERRIDE: &[u8] = b"social-firewall.local-override.v1"; // never actually published, but kept for symmetry/tests
    pub const APPROVAL_RESPONSE: &[u8] = b"social-firewall.approval-response.v1";
    pub const FEDERATION_STATEMENT: &[u8] = b"social-firewall.federation-statement.v1";
    pub const PRESENCE_BEACON: &[u8] = b"social-firewall.presence-beacon.v1";
    pub const TUNNEL_ADVERTISEMENT: &[u8] = b"social-firewall.tunnel-advertisement.v1";
    pub const TUNNEL_SERVICE_REQUEST: &[u8] = b"social-firewall.tunnel-service-request.v1";
    pub const TUNNEL_CONNECTION_REQUEST: &[u8] = b"social-firewall.tunnel-connection-request.v1";
    pub const TUNNEL_CONNECTION_ACCEPT: &[u8] = b"social-firewall.tunnel-connection-accept.v1";
    pub const SHARED_RULE_LIST: &[u8] = b"social-firewall.shared-rule-list.v1";
    pub const SHARED_POLICY: &[u8] = b"social-firewall.shared-policy.v1";
    pub const GROUP: &[u8] = b"social-firewall.group.v1";
    pub const GROUP_JOIN_REQUEST: &[u8] = b"social-firewall.group-join-request.v1";
    pub const GROUP_VOTE: &[u8] = b"social-firewall.group-vote.v1";
    pub const POLICY_VOTE: &[u8] = b"social-firewall.policy-vote.v1";
    pub const FINGERPRINT_OBSERVATION: &[u8] = b"social-firewall.fingerprint-observation.v1";
    pub const FINGERPRINT_COMMENT: &[u8] = b"social-firewall.fingerprint-comment.v1";
    pub const PARTY_LINE_MESSAGE: &[u8] = b"social-firewall.party-line-message.v1";
    pub const DIRECT_MESSAGE: &[u8] = b"social-firewall.direct-message.v1";
    pub const DEVICE_APPROVAL_OPINION: &[u8] = b"social-firewall.device-approval-opinion.v1";
    pub const GROUP_BLOCK_REPORT: &[u8] = b"social-firewall.group-block-report.v1";
}

pub mod shared_fingerprint;

#[derive(thiserror::Error, Debug)]
pub enum CryptoError {
    #[error("invalid public key bytes")]
    InvalidPublicKey,
    #[error("signature verification failed")]
    VerificationFailed,
    #[error("sealing failed")]
    SealFailed,
    #[error("unsealing failed — wrong recipient key, or the ciphertext was tampered with")]
    UnsealFailed,
}

pub struct Keypair {
    signing_key: SigningKey,
}

impl Keypair {
    pub fn generate() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        Self { signing_key }
    }

    /// Reconstructs a keypair from raw seed bytes — for loading a
    /// previously-generated key back from storage. Callers are
    /// responsible for keeping these bytes secret; this crate doesn't
    /// implement secure-at-rest storage itself (there's no reliable
    /// hardware keystore to target uniformly across OpenWrt devices —
    /// documented as a known limitation, not solved here).
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self {
            signing_key: SigningKey::from_bytes(seed),
        }
    }

    pub fn seed_bytes(&self) -> [u8; 32] {
        self.signing_key.to_bytes()
    }

    pub fn public_key(&self) -> PublicKeyBytes {
        PublicKeyBytes(self.signing_key.verifying_key().to_bytes())
    }

    pub fn sign(&self, context: &[u8], message: &[u8]) -> SignatureBytes {
        let payload = domain_separated(context, message);
        let sig = self.signing_key.sign(&payload);
        SignatureBytes(sig.to_bytes())
    }
}

/// This identity's messaging keypair (X25519) — deliberately a separate
/// type from `Keypair` (Ed25519 identity signing), not a second
/// constructor on the same struct: the two exist for genuinely different
/// cryptographic purposes (signing vs. sealing pairwise messages) and
/// keeping them separate types makes it a compile error to reach for the
/// wrong one.
pub struct MessagingKeypair {
    secret_key: BoxSecretKey,
}

impl MessagingKeypair {
    pub fn generate() -> Self {
        Self {
            secret_key: BoxSecretKey::generate(&mut BoxOsRng),
        }
    }

    /// See `Keypair::from_seed`'s doc comment — the same at-rest-storage
    /// caveat applies here verbatim.
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self {
            secret_key: BoxSecretKey::from_bytes(*seed),
        }
    }

    pub fn seed_bytes(&self) -> [u8; 32] {
        self.secret_key.to_bytes()
    }

    pub fn public_key(&self) -> MessagingPublicKeyBytes {
        MessagingPublicKeyBytes(*self.secret_key.public_key().as_bytes())
    }

    /// Decrypts a blob sealed to this identity's public key via `seal`
    /// below. Fails closed on a wrong recipient key or a tampered
    /// ciphertext alike (the underlying AEAD tag check doesn't
    /// distinguish the two, and doesn't need to — either way the answer
    /// is "don't trust this blob").
    pub fn unseal(&self, ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        self.secret_key
            .unseal(ciphertext)
            .map_err(|_| CryptoError::UnsealFailed)
    }
}

/// Encrypts `plaintext` so only the holder of `recipient`'s matching
/// `MessagingKeypair` can read it (a NaCl/libsodium-style sealed box:
/// X25519 ECDH between a fresh ephemeral key and `recipient`, then an
/// AEAD cipher — via the well-audited `crypto_box` crate, not hand-rolled
/// crypto). The sender's own identity isn't part of this layer at all —
/// callers sign the plaintext first (see `contexts`) and seal the
/// already-signed bytes, so encryption only ever hides *who can read*
/// a statement, never *who's accountable* for it.
pub fn seal(recipient: &MessagingPublicKeyBytes, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let public_key = BoxPublicKey::from_bytes(recipient.0);
    public_key
        .seal(&mut BoxOsRng, plaintext)
        .map_err(|_| CryptoError::SealFailed)
}

pub fn verify(
    pubkey: &PublicKeyBytes,
    context: &[u8],
    message: &[u8],
    signature: &SignatureBytes,
) -> Result<(), CryptoError> {
    let verifying_key =
        VerifyingKey::from_bytes(&pubkey.0).map_err(|_| CryptoError::InvalidPublicKey)?;
    let sig = ed25519_dalek::Signature::from_bytes(&signature.0);
    let payload = domain_separated(context, message);
    verifying_key
        .verify(&payload, &sig)
        .map_err(|_| CryptoError::VerificationFailed)
}

fn domain_separated(context: &[u8], message: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(4 + context.len() + message.len());
    buf.extend_from_slice(&(context.len() as u32).to_be_bytes());
    buf.extend_from_slice(context);
    buf.extend_from_slice(message);
    buf
}

pub fn hash(data: &[u8]) -> Hash32 {
    Hash32(*blake3::hash(data).as_bytes())
}

pub fn derive_identity_id(public_key: &PublicKeyBytes) -> IdentityId {
    IdentityId(hash(
        &[b"kestrel-identity-v1".as_slice(), &public_key.0].concat(),
    ))
}

pub fn derive_device_id(public_key: &PublicKeyBytes) -> DeviceId {
    DeviceId(hash(
        &[b"kestrel-device-v1".as_slice(), &public_key.0].concat(),
    ))
}

pub fn derive_global_fingerprint_id(material: &[u8]) -> GlobalFingerprintId {
    GlobalFingerprintId(hash(
        &[b"kestrel-fingerprint-v1".as_slice(), material].concat(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_then_verify_round_trips() {
        let kp = Keypair::generate();
        let sig = kp.sign(contexts::POLICY_OPINION, b"deny ads.example");
        assert!(verify(
            &kp.public_key(),
            contexts::POLICY_OPINION,
            b"deny ads.example",
            &sig
        )
        .is_ok());
    }

    #[test]
    fn stable_subject_derivation_is_deterministic_and_domain_separated() {
        let key = Keypair::from_seed(&[3; 32]).public_key();
        assert_eq!(derive_identity_id(&key), derive_identity_id(&key));
        assert_eq!(derive_device_id(&key), derive_device_id(&key));
        assert_ne!(derive_identity_id(&key).0, derive_device_id(&key).0);
        assert_eq!(
            derive_global_fingerprint_id(b"signals"),
            derive_global_fingerprint_id(b"signals")
        );
        assert_ne!(
            derive_global_fingerprint_id(b"signals").0,
            derive_global_fingerprint_id(b"other-signals").0
        );
    }

    #[test]
    fn verification_fails_for_wrong_context() {
        let kp = Keypair::generate();
        let sig = kp.sign(contexts::POLICY_OPINION, b"deny ads.example");
        let result = verify(
            &kp.public_key(),
            contexts::APPROVAL_RESPONSE,
            b"deny ads.example",
            &sig,
        );
        assert!(result.is_err());
    }

    #[test]
    fn verification_fails_for_tampered_message() {
        let kp = Keypair::generate();
        let sig = kp.sign(contexts::POLICY_OPINION, b"deny ads.example");
        let result = verify(
            &kp.public_key(),
            contexts::POLICY_OPINION,
            b"allow ads.example",
            &sig,
        );
        assert!(result.is_err());
    }

    #[test]
    fn verification_fails_for_wrong_signer() {
        let kp_a = Keypair::generate();
        let kp_b = Keypair::generate();
        let sig = kp_a.sign(contexts::POLICY_OPINION, b"deny ads.example");
        let result = verify(
            &kp_b.public_key(),
            contexts::POLICY_OPINION,
            b"deny ads.example",
            &sig,
        );
        assert!(result.is_err());
    }

    #[test]
    fn seed_round_trip_reproduces_the_same_keypair() {
        let kp = Keypair::generate();
        let seed = kp.seed_bytes();
        let restored = Keypair::from_seed(&seed);
        assert_eq!(kp.public_key(), restored.public_key());
    }

    #[test]
    fn seal_then_unseal_round_trips() {
        let recipient = MessagingKeypair::generate();
        let sealed = seal(&recipient.public_key(), b"assigned_tunnel_ip=10.99.0.4").unwrap();
        let opened = recipient.unseal(&sealed).unwrap();
        assert_eq!(opened, b"assigned_tunnel_ip=10.99.0.4");
    }

    #[test]
    fn unseal_fails_for_the_wrong_recipient() {
        let recipient = MessagingKeypair::generate();
        let eavesdropper = MessagingKeypair::generate();
        let sealed = seal(&recipient.public_key(), b"secret").unwrap();
        assert!(eavesdropper.unseal(&sealed).is_err());
    }

    #[test]
    fn unseal_fails_for_a_tampered_ciphertext() {
        let recipient = MessagingKeypair::generate();
        let mut sealed = seal(&recipient.public_key(), b"secret").unwrap();
        let last = sealed.len() - 1;
        sealed[last] ^= 0xFF;
        assert!(recipient.unseal(&sealed).is_err());
    }

    #[test]
    fn messaging_seed_round_trip_reproduces_the_same_public_key() {
        let kp = MessagingKeypair::generate();
        let seed = kp.seed_bytes();
        let restored = MessagingKeypair::from_seed(&seed);
        assert_eq!(kp.public_key(), restored.public_key());
    }

    #[test]
    fn hash_is_deterministic() {
        assert_eq!(hash(b"hello"), hash(b"hello"));
        assert_ne!(hash(b"hello"), hash(b"world"));
    }

    /// Context length-prefixing means (context, message) pairs are
    /// unambiguous — a shorter context with message-prefix data appended
    /// must not collide with a longer context whose bytes happen to
    /// start the same way.
    #[test]
    fn domain_separated_payload_is_unambiguous_across_context_message_splits() {
        let a = domain_separated(b"ctx", b"XYZmessage");
        let b = domain_separated(b"ctxXYZ", b"message");
        assert_ne!(a, b);
    }
}
