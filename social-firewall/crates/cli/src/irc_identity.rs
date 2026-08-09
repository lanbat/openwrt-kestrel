use anyhow::{Context, Result};
use domain_types::{
    IrcIdentityAdvertisement, MessagingPublicKeyBytes, PublicKeyBytes, SignatureBytes,
};
use state_store::StateStore;
use std::path::Path;

pub(crate) fn publish(store: &StateStore, oidc_subject: &str, out: &Path) -> Result<()> {
    let identity = store
        .get_local_irc_identity_by_subject(oidc_subject)?
        .context("no provisioned IRC identity for OIDC subject")?;
    let keypair = crypto::Keypair::from_seed(&identity.signing_secret_seed);
    let known_key = store
        .get_user_public_key(&identity.user)?
        .context("cannot publish an IRC identity advertisement for an unknown social identity")?;
    if known_key != keypair.public_key() {
        anyhow::bail!("provisioned signing key does not match the known social identity key");
    }
    let messaging = crypto::MessagingKeypair::from_seed(&identity.messaging_secret_seed);
    let mut advertisement = IrcIdentityAdvertisement {
        user: identity.user,
        sequence: store.next_irc_identity_advertisement_sequence(&identity.user)?,
        messaging_pubkey: messaging.public_key(),
        issued_at: crate::now_unix(),
        signature: SignatureBytes([0; 64]),
    };
    advertisement.signature = keypair.sign(
        crypto::contexts::IRC_IDENTITY_ADVERTISEMENT,
        &advertisement.signing_bytes(),
    );
    let json = to_json(&advertisement, &keypair.public_key());
    let payload = serde_json::to_vec_pretty(&json)?;
    std::fs::write(out, &payload)?;
    store.store_irc_identity_advertisement(&advertisement, keypair.public_key())?;
    if crate::tunnel::needs_file_fallback(
        crate::tunnel::try_deliver(
            store,
            &identity.user,
            p2p_transport::StatementKind::IrcIdentityAdvertisement,
            &payload,
        ),
        &identity.user,
    ) {
        println!(
            "no live destination; retained advertisement at {}",
            out.display()
        );
    }
    println!(
        "published IRC identity advertisement for {}",
        crate::tunnel::user_id_str(&identity.user)
    );
    Ok(())
}

pub(crate) fn ingest(store: &StateStore, file: &Path) -> Result<()> {
    let bytes = std::fs::read(file)?;
    ingest_bytes(store, &bytes)
}

pub(crate) fn ingest_bytes(store: &StateStore, bytes: &[u8]) -> Result<()> {
    let json: serde_json::Value = serde_json::from_slice(bytes)?;
    let advertisement = from_json(&json)?;
    let signing_pubkey = PublicKeyBytes(crate::tunnel::bytes32(
        json.get("signing_pubkey")
            .and_then(|value| value.as_str())
            .context("missing signing_pubkey")?,
    )?);
    let known_key = store
        .get_user_public_key(&advertisement.user)?
        .context("cannot ingest an IRC identity advertisement for an unknown social identity")?;
    if known_key != signing_pubkey {
        anyhow::bail!(
            "IRC identity advertisement signing key does not match the known social identity key"
        );
    }
    crypto::verify(
        &signing_pubkey,
        crypto::contexts::IRC_IDENTITY_ADVERTISEMENT,
        &advertisement.signing_bytes(),
        &advertisement.signature,
    )
    .map_err(|_| anyhow::anyhow!("IRC identity advertisement signature verification failed"))?;
    store.store_irc_identity_advertisement(&advertisement, signing_pubkey)?;
    Ok(())
}

fn to_json(
    advertisement: &IrcIdentityAdvertisement,
    signing_pubkey: &PublicKeyBytes,
) -> serde_json::Value {
    serde_json::json!({
        "user": crate::tunnel::user_id_str(&advertisement.user),
        "sequence": advertisement.sequence,
        "messaging_pubkey": hex::encode(advertisement.messaging_pubkey.0),
        "issued_at": advertisement.issued_at,
        "signing_pubkey": hex::encode(signing_pubkey.0),
        "signature": hex::encode(advertisement.signature.0),
    })
}

fn from_json(json: &serde_json::Value) -> Result<IrcIdentityAdvertisement> {
    let text = |name: &str| {
        json.get(name)
            .and_then(|value| value.as_str())
            .with_context(|| format!("missing {name}"))
    };
    Ok(IrcIdentityAdvertisement {
        user: crate::tunnel::parse_user_ref(text("user")?)?,
        sequence: json
            .get("sequence")
            .and_then(|value| value.as_u64())
            .context("missing sequence")?,
        messaging_pubkey: MessagingPublicKeyBytes(crate::tunnel::bytes32(text(
            "messaging_pubkey",
        )?)?),
        issued_at: json
            .get("issued_at")
            .and_then(|value| value.as_i64())
            .context("missing issued_at")?,
        signature: SignatureBytes(crate::tunnel::bytes64(text("signature")?)?),
    })
}

#[cfg(test)]
mod tests {
    use super::{ingest, publish};
    use domain_types::PublicKeyBytes;
    use state_store::StateStore;
    use std::path::PathBuf;

    fn user() -> domain_types::UserId {
        domain_types::UserId {
            federation: domain_types::FederationId(domain_types::Hash32([1; 32])),
            local_id: domain_types::Hash32([2; 32]),
        }
    }

    #[test]
    fn published_identity_advertisement_is_ingestable_and_discoverable() {
        let source = StateStore::open_in_memory().unwrap();
        let target = StateStore::open_in_memory().unwrap();
        let signing = crypto::Keypair::from_seed(&[7; 32]);
        source
            .set_self_identity(user(), signing.public_key(), &[7; 32], None)
            .unwrap();
        source
            .provision_local_irc_identity(user(), "alice", &[7; 32], &[8; 32])
            .unwrap();
        target
            .set_self_identity(
                user(),
                PublicKeyBytes(signing.public_key().0),
                &[7; 32],
                None,
            )
            .unwrap();

        let path = PathBuf::from(format!(
            "/tmp/sf-irc-identity-test-{}.json",
            std::process::id()
        ));
        publish(&source, "alice", &path).unwrap();
        ingest(&target, &path).unwrap();
        std::fs::remove_file(path).unwrap();

        assert_eq!(
            target.get_irc_identity_messaging_pubkey(&user()).unwrap(),
            Some(crypto::MessagingKeypair::from_seed(&[8; 32]).public_key())
        );
    }

    #[test]
    fn tampered_identity_advertisement_is_rejected() {
        let source = StateStore::open_in_memory().unwrap();
        let target = StateStore::open_in_memory().unwrap();
        let signing = crypto::Keypair::from_seed(&[7; 32]);
        source
            .set_self_identity(user(), signing.public_key(), &[7; 32], None)
            .unwrap();
        source
            .provision_local_irc_identity(user(), "alice", &[7; 32], &[8; 32])
            .unwrap();
        target
            .set_self_identity(user(), signing.public_key(), &[7; 32], None)
            .unwrap();

        let path = PathBuf::from(format!(
            "/tmp/sf-irc-identity-tampered-{}.json",
            std::process::id()
        ));
        publish(&source, "alice", &path).unwrap();
        let mut json: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        json["messaging_pubkey"] = serde_json::Value::String("00".repeat(32));
        std::fs::write(&path, serde_json::to_vec(&json).unwrap()).unwrap();
        assert!(ingest(&target, &path).is_err());
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn mismatched_provisioned_signing_key_cannot_be_published() {
        let store = StateStore::open_in_memory().unwrap();
        let signing = crypto::Keypair::from_seed(&[7; 32]);
        store
            .set_self_identity(user(), signing.public_key(), &[7; 32], None)
            .unwrap();
        store
            .provision_local_irc_identity(user(), "alice", &[9; 32], &[8; 32])
            .unwrap();
        let path = PathBuf::from(format!(
            "/tmp/sf-irc-identity-mismatch-{}.json",
            std::process::id()
        ));
        assert!(publish(&store, "alice", &path).is_err());
        assert!(!path.exists());
    }
}
