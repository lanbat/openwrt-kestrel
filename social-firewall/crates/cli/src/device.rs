//! CLI implementation for device-approval opinions — a signed,
//! replicable signal from a followed peer about whether a specific MAC
//! address should be trusted to join a network. See
//! `domain_types::device`'s module doc for why this deliberately stops
//! short of writing into kestreld's own join-approval tables.
//!
//! Wire format mirrors `PolicyOpinion`'s plain-JSON export in
//! `main.rs::opinion_to_json`/`opinion_from_json` exactly (no
//! `Visibility` choice — a device-approval opinion, like a `PolicyOpinion`,
//! is meant to be discoverable by anyone who follows the author, not
//! pairwise-sealed).

use crate::{now_unix, parse_reason_code, parse_stance, reason_code_str, stance_str};
use anyhow::{Context, Result};
use domain_types::{
    DeviceApprovalOpinion, FederationId, Hash32, PublicKeyBytes, Reason, SignatureBytes, UserId,
    MAX_DEVICE_LABEL_LEN,
};
use state_store::StateStore;
use std::path::{Path, PathBuf};

fn parse_hash32(s: &str) -> Result<Hash32> {
    let bytes = hex::decode(s).with_context(|| format!("`{s}` is not valid hex"))?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("expected exactly 32 bytes"))?;
    Ok(Hash32(arr))
}

fn user_id_str(u: &UserId) -> String {
    format!("{}/{}", u.federation.0, u.local_id)
}

/// Normalizes a MAC address to the lowercase, colon-separated form
/// kestreld itself already stores it in — so a MAC hand-typed with
/// uppercase hex or dashes still matches an opinion published about the
/// same device by a peer who typed it differently.
pub(crate) fn normalize_mac(mac: &str) -> String {
    mac.trim().to_lowercase().replace('-', ":")
}

#[allow(clippy::too_many_arguments)]
pub fn publish_device_approval(
    store: &StateStore,
    mac: &str,
    stance: &str,
    reason_code: &str,
    note: Option<String>,
    label: Option<String>,
    ttl_seconds: Option<i64>,
    out: Option<PathBuf>,
) -> Result<()> {
    let (author, seed) = crate::tunnel::self_identity(store)?;
    let kp = crypto::Keypair::from_seed(&seed);
    let mac = normalize_mac(mac);
    if let Some(label) = &label {
        if label.len() > MAX_DEVICE_LABEL_LEN {
            anyhow::bail!("device label exceeds {MAX_DEVICE_LABEL_LEN} bytes");
        }
    }
    let sequence = store.next_device_approval_opinion_sequence(&author)?;
    let now = now_unix();

    let mut opinion = DeviceApprovalOpinion {
        author,
        sequence,
        mac: mac.clone(),
        stance: parse_stance(stance)?,
        reason: Reason {
            code: parse_reason_code(reason_code)?,
            note,
            evidence: vec![],
        },
        device_label: label,
        issued_at: now,
        expires_at: ttl_seconds.map(|s| now + s),
        supersedes: None,
        signature: SignatureBytes([0; 64]),
    };
    let signing_bytes = opinion.signing_bytes();
    opinion.signature = kp.sign(crypto::contexts::DEVICE_APPROVAL_OPINION, &signing_bytes);
    store.store_own_device_approval_opinion(&opinion)?;
    println!(
        "published device-approval opinion #{sequence} for {mac}: {:?}",
        opinion.stance
    );

    if let Some(path) = out {
        let json = device_approval_to_json(&opinion, &kp.public_key());
        std::fs::write(&path, serde_json::to_string_pretty(&json)?)
            .with_context(|| format!("writing {}", path.display()))?;
        println!("exported to {}", path.display());
    }
    Ok(())
}

pub fn ingest_device_approval(store: &StateStore, file: &Path) -> Result<()> {
    let text =
        std::fs::read_to_string(file).with_context(|| format!("reading {}", file.display()))?;
    let json: serde_json::Value = serde_json::from_str(&text)?;
    let (opinion, pubkey) = device_approval_from_json(&json)?;

    crypto::verify(
        &pubkey,
        crypto::contexts::DEVICE_APPROVAL_OPINION,
        &opinion.signing_bytes(),
        &opinion.signature,
    )
    .map_err(|_| anyhow::anyhow!("signature verification failed — refusing to ingest"))?;

    store.ingest_device_approval_opinion(&opinion)?;
    println!(
        "ingested device-approval opinion #{} from {} for {}: {:?}",
        opinion.sequence,
        user_id_str(&opinion.author),
        opinion.mac,
        opinion.stance
    );
    Ok(())
}

pub fn list_device_approvals(store: &StateStore, mac: &str) -> Result<()> {
    let mac = normalize_mac(mac);
    let opinions = store.list_device_approval_opinions_for(&mac)?;
    if opinions.is_empty() {
        println!("no known device-approval opinions for {mac}");
        return Ok(());
    }
    for (opinion, trust) in opinions {
        let followed = if trust.is_some() {
            "followed"
        } else {
            "not followed"
        };
        println!(
            "#{} from {} ({followed}): {:?} — {}{}",
            opinion.sequence,
            user_id_str(&opinion.author),
            opinion.stance,
            reason_code_str(opinion.reason.code),
            opinion
                .device_label
                .map(|l| format!(" [{l}]"))
                .unwrap_or_default()
        );
    }
    Ok(())
}

/// Prints this router's own trust-weighted aggregate stance for `mac` —
/// an advisory signal only, never itself enforced (see
/// `StateStore::device_approval_stance_for`'s own doc on why this stops
/// short of a real kestreld bridge).
pub fn evaluate_device(store: &StateStore, mac: &str, threshold: f64) -> Result<()> {
    let mac = normalize_mac(mac);
    let now = now_unix();
    let (decision, allow_total, deny_total) =
        store.device_approval_stance_for(&mac, now, threshold)?;
    println!("mac        : {mac}");
    println!("decision   : {decision:?}");
    println!("allow_total: {allow_total:.2}");
    println!("deny_total : {deny_total:.2}");
    println!("threshold  : {threshold:.2}");
    println!("(advisory only — not written to any kestreld join-approval table)");
    Ok(())
}

fn device_approval_to_json(
    o: &DeviceApprovalOpinion,
    pubkey: &PublicKeyBytes,
) -> serde_json::Value {
    serde_json::json!({
        "author_federation": o.author.federation.0.to_string(),
        "author_local_id": o.author.local_id.to_string(),
        "author_pubkey": hex::encode(pubkey.0),
        "sequence": o.sequence,
        "mac": o.mac,
        "stance": stance_str(o.stance),
        "reason_code": reason_code_str(o.reason.code),
        "reason_note": o.reason.note,
        "device_label": o.device_label,
        "issued_at": o.issued_at,
        "expires_at": o.expires_at,
        "supersedes_sequence": o.supersedes,
        "signature": hex::encode(o.signature.0),
    })
}

fn device_approval_from_json(
    json: &serde_json::Value,
) -> Result<(DeviceApprovalOpinion, PublicKeyBytes)> {
    let get_str = |key: &str| -> Result<&str> {
        json.get(key)
            .and_then(|v| v.as_str())
            .with_context(|| format!("missing/invalid field `{key}`"))
    };
    let federation = FederationId(parse_hash32(get_str("author_federation")?)?);
    let local_id = parse_hash32(get_str("author_local_id")?)?;
    let pubkey_bytes = hex::decode(get_str("author_pubkey")?)?;
    let pubkey = PublicKeyBytes(
        pubkey_bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("author_pubkey must be 32 bytes"))?,
    );

    let sequence = json
        .get("sequence")
        .and_then(|v| v.as_u64())
        .context("missing `sequence`")?;
    let mac = get_str("mac")?.to_string();
    let stance = parse_stance(get_str("stance")?)?;
    let reason_code = parse_reason_code(get_str("reason_code")?)?;
    let reason_note = json
        .get("reason_note")
        .and_then(|v| v.as_str())
        .map(String::from);
    let device_label = json
        .get("device_label")
        .and_then(|v| v.as_str())
        .map(String::from);
    let issued_at = json
        .get("issued_at")
        .and_then(|v| v.as_i64())
        .context("missing `issued_at`")?;
    let expires_at = json.get("expires_at").and_then(|v| v.as_i64());
    let supersedes = json.get("supersedes_sequence").and_then(|v| v.as_u64());
    let signature_bytes = hex::decode(get_str("signature")?)?;
    let signature = SignatureBytes(
        signature_bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("signature must be 64 bytes"))?,
    );

    let opinion = DeviceApprovalOpinion {
        author: UserId {
            federation,
            local_id,
        },
        sequence,
        mac,
        stance,
        reason: Reason {
            code: reason_code,
            note: reason_note,
            evidence: vec![],
        },
        device_label,
        issued_at,
        expires_at,
        supersedes,
        signature,
    };
    opinion.validate().map_err(|e| anyhow::anyhow!(e))?;
    Ok((opinion, pubkey))
}
