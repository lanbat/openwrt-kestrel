use anyhow::{bail, Context, Result};
use domain_types::{FingerprintComment, FingerprintObservation, SignatureBytes};
use state_store::StateStore;
use std::path::{Path, PathBuf};

use crate::tunnel::{bytes32, bytes64, self_identity, user_id_str};
use crate::{now_unix, parse_hash32};

pub fn set_group_key(store: &StateStore, group: &str, key_hex: &str) -> Result<()> {
    let group_id = crate::group::resolve_group_id(store, group)?;
    let bytes = hex::decode(key_hex).context("fingerprint key is not valid hex")?;
    let key: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("fingerprint key must be exactly 32 bytes"))?;
    store.set_group_fingerprint_key(group_id, &key)?;
    println!("stored fingerprint key for group {}", group_id.0);
    Ok(())
}

pub fn derive_shared_id(store: &StateStore, group: &str, material_file: &Path) -> Result<()> {
    let group_id = crate::group::resolve_group_id(store, group)?;
    let key = store
        .group_fingerprint_key(group_id)?
        .ok_or_else(|| anyhow::anyhow!("no fingerprint key configured for group {group}"))?;
    let material = std::fs::read(material_file)?;
    let fingerprint_id =
        crypto::shared_fingerprint::derive_shared_fingerprint_from_material(&key, &material);
    println!("{fingerprint_id}");
    Ok(())
}

fn observation_json(
    observation: &FingerprintObservation,
    public_key: &[u8; 32],
) -> serde_json::Value {
    serde_json::json!({
        "group_id": observation.group_id.0.to_string(), "fingerprint_id": observation.fingerprint_id.to_string(),
        "fingerprint_revision": observation.fingerprint_revision, "observer": user_id_str(&observation.observer),
        "signal_family": observation.signal_family, "evidence_digest": observation.evidence_digest.to_string(),
        "confidence": observation.confidence, "issued_at": observation.issued_at, "expires_at": observation.expires_at,
        "identity_pubkey": hex::encode(public_key), "signature": hex::encode(observation.signature.0),
    })
}

#[allow(clippy::too_many_arguments)]
pub fn publish_observation(
    store: &StateStore,
    group: &str,
    fingerprint_id: &str,
    revision: u64,
    signal_family: &str,
    evidence_digest: &str,
    confidence: u8,
    out: Option<PathBuf>,
) -> Result<()> {
    validate_confidence(u64::from(confidence))?;
    let group_id = crate::group::resolve_group_id(store, group)?;
    let (observer, seed) = self_identity(store)?;
    let keypair = crypto::Keypair::from_seed(&seed);
    let mut observation = FingerprintObservation {
        group_id,
        fingerprint_id: parse_hash32(fingerprint_id)?,
        fingerprint_revision: revision,
        observer,
        signal_family: signal_family.into(),
        evidence_digest: parse_hash32(evidence_digest)?,
        confidence,
        issued_at: now_unix(),
        expires_at: None,
        signature: SignatureBytes([0; 64]),
    };
    observation.signature = keypair.sign(
        crypto::contexts::FINGERPRINT_OBSERVATION,
        &observation.signing_bytes(),
    );
    store.store_fingerprint_observation(&observation)?;
    if let Some(path) = out {
        std::fs::write(
            &path,
            serde_json::to_vec_pretty(&observation_json(&observation, &keypair.public_key().0))?,
        )?;
    }
    println!(
        "published fingerprint observation for {}",
        observation.fingerprint_id
    );
    Ok(())
}

pub fn publish_comment(
    store: &StateStore,
    group: &str,
    fingerprint_id: &str,
    revision: u64,
    body: &str,
    out: Option<PathBuf>,
) -> Result<()> {
    if body.is_empty() || body.len() > 4096 {
        bail!("comment must be 1-4096 bytes");
    }
    let group_id = crate::group::resolve_group_id(store, group)?;
    let (author, seed) = self_identity(store)?;
    let keypair = crypto::Keypair::from_seed(&seed);
    let mut comment = FingerprintComment {
        group_id,
        fingerprint_id: parse_hash32(fingerprint_id)?,
        fingerprint_revision: revision,
        author,
        sequence: store.next_fingerprint_comment_sequence(
            group_id,
            parse_hash32(fingerprint_id)?,
            revision,
            &author,
        )?,
        body: body.into(),
        issued_at: now_unix(),
        signature: SignatureBytes([0; 64]),
    };
    comment.signature = keypair.sign(
        crypto::contexts::FINGERPRINT_COMMENT,
        &comment.signing_bytes(),
    );
    store.store_fingerprint_comment(&comment)?;
    if let Some(path) = out {
        let json = serde_json::json!({"group_id": comment.group_id.0.to_string(), "fingerprint_id": comment.fingerprint_id.to_string(), "fingerprint_revision": comment.fingerprint_revision, "author": user_id_str(&comment.author), "sequence": comment.sequence, "body": comment.body, "issued_at": comment.issued_at, "identity_pubkey": hex::encode(keypair.public_key().0), "signature": hex::encode(comment.signature.0)});
        std::fs::write(path, serde_json::to_vec_pretty(&json)?)?;
    }
    println!(
        "published fingerprint comment for {}",
        comment.fingerprint_id
    );
    Ok(())
}

pub fn list_fingerprint(
    store: &StateStore,
    group: &str,
    fingerprint_id: &str,
    revision: u64,
) -> Result<()> {
    let group_id = crate::group::resolve_group_id(store, group)?;
    let fingerprint_id = parse_hash32(fingerprint_id)?;
    for observation in store.list_fingerprint_observations(group_id, fingerprint_id, revision)? {
        println!(
            "observation {} {} confidence {}",
            user_id_str(&observation.observer),
            observation.signal_family,
            observation.confidence
        );
    }
    for comment in store.list_fingerprint_comments(group_id, fingerprint_id, revision)? {
        println!("comment {}: {}", user_id_str(&comment.author), comment.body);
    }
    Ok(())
}

pub fn ingest_observation(store: &StateStore, file: &Path) -> Result<()> {
    ingest_observation_bytes(store, &std::fs::read(file)?)
}

pub fn ingest_observation_bytes(store: &StateStore, payload: &[u8]) -> Result<()> {
    let value: serde_json::Value = serde_json::from_slice(payload)?;
    let get = |key: &str| {
        value
            .get(key)
            .and_then(|v| v.as_str())
            .with_context(|| format!("missing {key}"))
    };
    let confidence = validate_confidence(
        value
            .get("confidence")
            .and_then(|v| v.as_u64())
            .context("missing confidence")?,
    )?;
    let observation = FingerprintObservation {
        group_id: crate::group::parse_group_id(get("group_id")?)?,
        fingerprint_id: parse_hash32(get("fingerprint_id")?)?,
        fingerprint_revision: value
            .get("fingerprint_revision")
            .and_then(|v| v.as_u64())
            .context("missing fingerprint_revision")?,
        observer: crate::tunnel::parse_user_ref(get("observer")?)?,
        signal_family: get("signal_family")?.into(),
        evidence_digest: parse_hash32(get("evidence_digest")?)?,
        confidence,
        issued_at: value
            .get("issued_at")
            .and_then(|v| v.as_i64())
            .context("missing issued_at")?,
        expires_at: value.get("expires_at").and_then(|v| v.as_i64()),
        signature: SignatureBytes(bytes64(get("signature")?)?),
    };
    let key = domain_types::PublicKeyBytes(bytes32(get("identity_pubkey")?)?);
    crypto::verify(
        &key,
        crypto::contexts::FINGERPRINT_OBSERVATION,
        &observation.signing_bytes(),
        &observation.signature,
    )
    .map_err(|_| anyhow::anyhow!("fingerprint observation signature verification failed"))?;
    Ok(store.store_fingerprint_observation(&observation)?)
}

fn validate_confidence(value: u64) -> Result<u8> {
    u8::try_from(value)
        .ok()
        .filter(|confidence| *confidence <= 100)
        .ok_or_else(|| anyhow::anyhow!("confidence must be between 0 and 100"))
}

pub fn ingest_comment_bytes(store: &StateStore, payload: &[u8]) -> Result<()> {
    let value: serde_json::Value = serde_json::from_slice(payload)?;
    let get = |key: &str| {
        value
            .get(key)
            .and_then(|v| v.as_str())
            .with_context(|| format!("missing {key}"))
    };
    let comment = FingerprintComment {
        group_id: crate::group::parse_group_id(get("group_id")?)?,
        fingerprint_id: parse_hash32(get("fingerprint_id")?)?,
        fingerprint_revision: value
            .get("fingerprint_revision")
            .and_then(|v| v.as_u64())
            .context("missing fingerprint_revision")?,
        author: crate::tunnel::parse_user_ref(get("author")?)?,
        sequence: value
            .get("sequence")
            .and_then(|v| v.as_u64())
            .context("missing sequence")?,
        body: get("body")?.into(),
        issued_at: value
            .get("issued_at")
            .and_then(|v| v.as_i64())
            .context("missing issued_at")?,
        signature: SignatureBytes(bytes64(get("signature")?)?),
    };
    let key = domain_types::PublicKeyBytes(bytes32(get("identity_pubkey")?)?);
    crypto::verify(
        &key,
        crypto::contexts::FINGERPRINT_COMMENT,
        &comment.signing_bytes(),
        &comment.signature,
    )
    .map_err(|_| anyhow::anyhow!("fingerprint comment signature verification failed"))?;
    Ok(store.store_fingerprint_comment(&comment)?)
}

#[cfg(test)]
mod tests {
    use super::validate_confidence;

    #[test]
    fn confidence_accepts_inclusive_zero_to_hundred_range() {
        assert_eq!(validate_confidence(0).unwrap(), 0);
        assert_eq!(validate_confidence(100).unwrap(), 100);
    }

    #[test]
    fn confidence_rejects_values_above_hundred() {
        assert!(validate_confidence(101).is_err());
        assert!(validate_confidence(u64::from(u8::MAX) + 1).is_err());
    }
}
