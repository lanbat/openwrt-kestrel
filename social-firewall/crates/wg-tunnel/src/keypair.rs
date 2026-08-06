//! This router's own WireGuard keypair (X25519 — the curve WireGuard
//! itself uses). Deliberately its own small helper, not a reuse of
//! `crypto::MessagingKeypair` even though both wrap the same curve: one
//! key authenticates this router to a real network tunnel, the other
//! seals application-level messages between identities — using one
//! keypair for two protocols' worth of key material is the same
//! anti-pattern `domain_types::sharing`'s own module doc already flags for
//! `WgPublicKeyBytes` vs `MessagingPublicKeyBytes`.

use crypto_box::{aead::rand_core::OsRng, SecretKey};
use domain_types::WgPublicKeyBytes;

pub struct WgKeypair {
    secret_key: SecretKey,
}

impl WgKeypair {
    pub fn generate() -> Self {
        Self {
            secret_key: SecretKey::generate(&mut OsRng),
        }
    }

    /// Reconstructs a keypair from raw seed bytes previously returned by
    /// `seed_bytes` — same at-rest-storage caveat as `crypto::Keypair`'s
    /// own `from_seed`: callers are responsible for keeping these secret.
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self {
            secret_key: SecretKey::from_bytes(*seed),
        }
    }

    pub fn seed_bytes(&self) -> [u8; 32] {
        self.secret_key.to_bytes()
    }

    pub fn public_key(&self) -> WgPublicKeyBytes {
        WgPublicKeyBytes(*self.secret_key.public_key().as_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seed_round_trip_reproduces_the_same_public_key() {
        let kp = WgKeypair::generate();
        let seed = kp.seed_bytes();
        let restored = WgKeypair::from_seed(&seed);
        assert_eq!(kp.public_key(), restored.public_key());
    }

    #[test]
    fn two_generated_keypairs_are_different() {
        let a = WgKeypair::generate();
        let b = WgKeypair::generate();
        assert_ne!(a.public_key(), b.public_key());
    }
}
