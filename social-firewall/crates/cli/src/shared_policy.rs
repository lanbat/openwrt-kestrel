use anyhow::{bail, Context, Result};
use domain_types::{
    CanonicalEncode, PolicyAction, PolicyEntry, PolicyVote, Reason, SharedPolicy, SignatureBytes,
    Visibility,
};
use state_store::{LocalIrcIdentity, StateStore};
use std::path::{Path, PathBuf};

use crate::tunnel::{
    bytes32, bytes64, parse_user_ref, parse_visibility, self_identity, user_id_str,
};
use crate::{
    now_unix, parse_hash32, parse_reason_code, parse_target, reason_code_str, target_value_str,
};

fn action_from_json(value: &serde_json::Value) -> Result<PolicyAction> {
    let kind = value
        .get("action")
        .and_then(|v| v.as_str())
        .context("missing action")?;
    match kind {
        "block" => Ok(PolicyAction::Block),
        "allow" => Ok(PolicyAction::Allow),
        "route" => Ok(PolicyAction::Route {
            profile: value
                .get("profile")
                .and_then(|v| v.as_str())
                .context("route requires profile")?
                .into(),
        }),
        "dns_block" => Ok(PolicyAction::DnsBlock),
        "dns_redirect" => Ok(PolicyAction::DnsRedirect {
            address: value
                .get("address")
                .and_then(|v| v.as_str())
                .context("dns_redirect requires address")?
                .into(),
        }),
        "dns_record" => Ok(PolicyAction::DnsRecord {
            record_type: value
                .get("record_type")
                .and_then(|v| v.as_str())
                .context("dns_record requires record_type")?
                .into(),
            value: value
                .get("value")
                .and_then(|v| v.as_str())
                .context("dns_record requires value")?
                .into(),
            ttl_seconds: value
                .get("ttl_seconds")
                .and_then(|v| v.as_u64())
                .unwrap_or(300)
                .try_into()
                .context("dns_record TTL is out of range")?,
        }),
        other => bail!("invalid policy action `{other}`"),
    }
}

fn entry_from_json(value: &serde_json::Value) -> Result<PolicyEntry> {
    let get = |key: &str| {
        value
            .get(key)
            .and_then(|v| v.as_str())
            .with_context(|| format!("missing {key}"))
    };
    let target = parse_target(get("target_kind")?, get("target_value")?)?;
    let action = action_from_json(value)?;
    let category = value
        .get("category")
        .and_then(|v| v.as_str())
        .map(str::to_owned);
    let reason = Reason {
        code: parse_reason_code(get("reason_code")?)?,
        note: value
            .get("reason_note")
            .and_then(|v| v.as_str())
            .map(str::to_owned),
        evidence: value
            .get("reason_evidence")
            .and_then(|v| v.as_array())
            .map(|items| {
                items
                    .iter()
                    .filter_map(|v| v.as_str())
                    .map(parse_hash32)
                    .collect::<Result<Vec<_>>>()
            })
            .transpose()?
            .unwrap_or_default(),
    };
    let mut identity = Vec::new();
    target.canonical_encode(&mut identity);
    action.canonical_encode(&mut identity);
    category.canonical_encode(&mut identity);
    reason.canonical_encode(&mut identity);
    let entry_id = value
        .get("entry_id")
        .and_then(|v| v.as_str())
        .map(parse_hash32)
        .transpose()?
        .unwrap_or_else(|| crypto::hash(&identity));
    Ok(PolicyEntry {
        entry_id,
        target,
        action,
        category,
        reason,
        expires_at: value.get("expires_at").and_then(|v| v.as_i64()),
    })
}

fn action_to_json(action: &PolicyAction) -> serde_json::Value {
    match action {
        PolicyAction::Block => serde_json::json!({"action":"block"}),
        PolicyAction::Allow => serde_json::json!({"action":"allow"}),
        PolicyAction::Route { profile } => serde_json::json!({"action":"route","profile":profile}),
        PolicyAction::DnsBlock => serde_json::json!({"action":"dns_block"}),
        PolicyAction::DnsRedirect { address } => {
            serde_json::json!({"action":"dns_redirect","address":address})
        }
        PolicyAction::DnsRecord {
            record_type,
            value,
            ttl_seconds,
        } => {
            serde_json::json!({"action":"dns_record","record_type":record_type,"value":value,"ttl_seconds":ttl_seconds})
        }
    }
}

fn entry_to_json(entry: &PolicyEntry) -> serde_json::Value {
    serde_json::json!({
        "entry_id": entry.entry_id.to_string(),
        "target_kind": entry.target.kind_str(),
        "target_value": target_value_str(&entry.target),
        "category": entry.category,
        "reason_code": reason_code_str(entry.reason.code),
        "reason_note": entry.reason.note,
        "reason_evidence": entry.reason.evidence.iter().map(ToString::to_string).collect::<Vec<_>>(),
        "expires_at": entry.expires_at,
        "action": action_to_json(&entry.action),
    })
}

fn policy_to_json(policy: &SharedPolicy, public_key: &[u8; 32]) -> serde_json::Value {
    serde_json::json!({
        "policy_id": policy.policy_id.to_string(), "author": user_id_str(&policy.author), "sequence": policy.sequence,
        "name": policy.name, "description": policy.description, "categories": policy.categories,
        "visibility": if policy.visibility == Visibility::Public { "public" } else { "restricted" },
        "identity_pubkey": hex::encode(public_key), "entries": policy.entries.iter().map(entry_to_json).collect::<Vec<_>>(),
        "issued_at": policy.issued_at, "expires_at": policy.expires_at, "supersedes": policy.supersedes,
        "signature": hex::encode(policy.signature.0),
    })
}

fn policy_from_json(value: &serde_json::Value) -> Result<(SharedPolicy, [u8; 32])> {
    let get = |key: &str| {
        value
            .get(key)
            .and_then(|v| v.as_str())
            .with_context(|| format!("missing {key}"))
    };
    let entries = value
        .get("entries")
        .and_then(|v| v.as_array())
        .context("missing entries")?
        .iter()
        .map(entry_from_json)
        .collect::<Result<Vec<_>>>()?;
    let policy = SharedPolicy {
        policy_id: parse_hash32(get("policy_id")?)?,
        author: parse_user_ref(get("author")?)?,
        sequence: value
            .get("sequence")
            .and_then(|v| v.as_u64())
            .context("missing sequence")?,
        name: get("name")?.into(),
        description: get("description")?.into(),
        categories: value
            .get("categories")
            .and_then(|v| v.as_array())
            .context("missing categories")?
            .iter()
            .filter_map(|v| v.as_str().map(str::to_owned))
            .collect(),
        visibility: parse_visibility(get("visibility")?)?,
        entries,
        issued_at: value
            .get("issued_at")
            .and_then(|v| v.as_i64())
            .context("missing issued_at")?,
        expires_at: value.get("expires_at").and_then(|v| v.as_i64()),
        supersedes: value.get("supersedes").and_then(|v| v.as_u64()),
        signature: SignatureBytes(bytes64(get("signature")?)?),
    };
    Ok((policy, bytes32(get("identity_pubkey")?)?))
}

#[allow(clippy::too_many_arguments)]
pub fn publish_policy(
    store: &StateStore,
    policy_id: &str,
    name: &str,
    description: &str,
    entries_file: &Path,
    categories: &[String],
    visibility: &str,
    out: Option<PathBuf>,
) -> Result<()> {
    let policy_id = parse_hash32(policy_id)?;
    let entries: Vec<PolicyEntry> =
        serde_json::from_str::<serde_json::Value>(&std::fs::read_to_string(entries_file)?)?
            .as_array()
            .context("entries file must contain an array")?
            .iter()
            .map(entry_from_json)
            .collect::<Result<_>>()?;
    let (author, seed) = self_identity(store)?;
    let kp = crypto::Keypair::from_seed(&seed);
    let mut policy = SharedPolicy {
        policy_id,
        author,
        sequence: store.next_shared_policy_sequence(&author, &policy_id)?,
        name: name.into(),
        description: description.into(),
        categories: categories.to_vec(),
        visibility: parse_visibility(visibility)?,
        entries,
        issued_at: now_unix(),
        expires_at: None,
        supersedes: None,
        signature: SignatureBytes([0; 64]),
    };
    policy.signature = kp.sign(crypto::contexts::SHARED_POLICY, &policy.signing_bytes());
    store.store_own_shared_policy(&policy)?;
    if let Some(path) = out {
        std::fs::write(
            &path,
            serde_json::to_vec_pretty(&policy_to_json(&policy, &kp.public_key().0))?,
        )?;
        println!("exported to {}", path.display());
    }
    println!(
        "published shared policy {} sequence {}",
        policy.policy_id, policy.sequence
    );
    Ok(())
}

pub fn ingest_policy(store: &StateStore, file: &Path) -> Result<()> {
    ingest_policy_bytes(store, &std::fs::read(file)?)?;
    println!("ingested shared policy from {}", file.display());
    Ok(())
}

pub fn ingest_policy_bytes(store: &StateStore, payload: &[u8]) -> Result<()> {
    let (policy, public_key) = policy_from_json(&serde_json::from_slice(payload)?)?;
    crypto::verify(
        &domain_types::PublicKeyBytes(public_key),
        crypto::contexts::SHARED_POLICY,
        &policy.signing_bytes(),
        &policy.signature,
    )
    .map_err(|_| anyhow::anyhow!("shared policy signature verification failed"))?;
    store.ingest_shared_policy(&policy)?;
    println!(
        "ingested shared policy {} sequence {}",
        policy.policy_id, policy.sequence
    );
    Ok(())
}

pub fn list_policies(store: &StateStore) -> Result<()> {
    for policy in store.list_shared_policies()? {
        println!(
            "{} #{} {} ({} entries)",
            policy.policy_id,
            policy.sequence,
            policy.name,
            policy.entries.len()
        );
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub fn vote_policy_entry(
    store: &StateStore,
    policy_id: &str,
    entry_id: &str,
    group: &str,
    stance: &str,
    reason_code: &str,
    note: Option<String>,
    out: Option<PathBuf>,
) -> Result<()> {
    let policy_id = parse_hash32(policy_id)?;
    let entry_id = parse_hash32(entry_id)?;
    let group_id = crate::group::resolve_group_id(store, group)?;
    let (voter, seed) = self_identity(store)?;
    let group_state = store.get_group(group_id)?.context("unknown group")?;
    if !group_state.voting_members.contains(&voter) {
        bail!("this identity is not a voting member of the group");
    }
    let policy = store
        .list_shared_policies()?
        .into_iter()
        .find(|policy| policy.policy_id == policy_id && policy.entry(&entry_id).is_some())
        .context("unknown policy or entry")?;
    let kp = crypto::Keypair::from_seed(&seed);
    let mut vote = PolicyVote {
        policy_id,
        entry_id,
        policy_sequence: policy.sequence,
        group_id,
        voter,
        sequence: store.next_policy_vote_sequence(
            policy_id,
            entry_id,
            policy.sequence,
            group_id,
            &voter,
        )?,
        stance: crate::parse_stance(stance)?,
        reason: Reason {
            code: crate::parse_reason_code(reason_code)?,
            note,
            evidence: vec![],
        },
        issued_at: now_unix(),
        expires_at: None,
        signature: SignatureBytes([0; 64]),
    };
    vote.signature = kp.sign(crypto::contexts::POLICY_VOTE, &vote.signing_bytes());
    store.store_policy_vote(&vote)?;
    if let Some(path) = out {
        let json = serde_json::json!({
            "policy_id": vote.policy_id.to_string(), "entry_id": vote.entry_id.to_string(),
            "policy_sequence": vote.policy_sequence, "group_id": vote.group_id.0.to_string(),
            "voter": user_id_str(&vote.voter), "sequence": vote.sequence,
            "stance": crate::stance_str(vote.stance), "reason_code": crate::reason_code_str(vote.reason.code),
            "reason_note": vote.reason.note, "issued_at": vote.issued_at, "expires_at": vote.expires_at,
            "identity_pubkey": hex::encode(kp.public_key().0), "signature": hex::encode(vote.signature.0),
        });
        std::fs::write(path, serde_json::to_vec_pretty(&json)?)?;
    }
    println!(
        "voted {} on policy {} entry {}",
        crate::stance_str(vote.stance),
        policy_id,
        entry_id
    );
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub fn vote_policy_entry_as_identity(
    store: &StateStore,
    identity: &LocalIrcIdentity,
    policy_id: &str,
    entry_id: &str,
    group: &str,
    stance: &str,
    reason_code: &str,
    note: Option<String>,
    out: Option<PathBuf>,
) -> Result<()> {
    let policy_id = parse_hash32(policy_id)?;
    let entry_id = parse_hash32(entry_id)?;
    let group_id = crate::group::resolve_group_id(store, group)?;
    let group_state = store.get_group(group_id)?.context("unknown group")?;
    if !group_state.voting_members.contains(&identity.user) {
        bail!("this identity is not a voting member of the group");
    }
    let policy = store
        .list_shared_policies()?
        .into_iter()
        .find(|policy| policy.policy_id == policy_id && policy.entry(&entry_id).is_some())
        .context("unknown policy or entry")?;
    let kp = crypto::Keypair::from_seed(&identity.signing_secret_seed);
    let mut vote = PolicyVote {
        policy_id,
        entry_id,
        policy_sequence: policy.sequence,
        group_id,
        voter: identity.user,
        sequence: store.next_policy_vote_sequence(
            policy_id,
            entry_id,
            policy.sequence,
            group_id,
            &identity.user,
        )?,
        stance: crate::parse_stance(stance)?,
        reason: Reason {
            code: crate::parse_reason_code(reason_code)?,
            note,
            evidence: vec![],
        },
        issued_at: now_unix(),
        expires_at: None,
        signature: SignatureBytes([0; 64]),
    };
    vote.signature = kp.sign(crypto::contexts::POLICY_VOTE, &vote.signing_bytes());
    store.store_policy_vote(&vote)?;
    if let Some(path) = out {
        let json = serde_json::json!({
            "policy_id": vote.policy_id.to_string(), "entry_id": vote.entry_id.to_string(),
            "policy_sequence": vote.policy_sequence, "group_id": vote.group_id.0.to_string(),
            "voter": user_id_str(&vote.voter), "sequence": vote.sequence,
            "stance": crate::stance_str(vote.stance), "reason_code": crate::reason_code_str(vote.reason.code),
            "reason_note": vote.reason.note, "issued_at": vote.issued_at, "expires_at": vote.expires_at,
            "identity_pubkey": hex::encode(kp.public_key().0), "signature": hex::encode(vote.signature.0),
        });
        std::fs::write(path, serde_json::to_vec_pretty(&json)?)?;
    }
    Ok(())
}

pub fn explain_policy_entry(
    store: &StateStore,
    policy_id: &str,
    entry_id: &str,
    group: &str,
) -> Result<()> {
    let policy_id = parse_hash32(policy_id)?;
    let entry_id = parse_hash32(entry_id)?;
    let group_id = crate::group::resolve_group_id(store, group)?;
    let policy = store
        .list_shared_policies()?
        .into_iter()
        .find(|policy| policy.policy_id == policy_id && policy.entry(&entry_id).is_some())
        .context("unknown policy or entry")?;
    match store.policy_stance_for(policy_id, entry_id, policy.sequence, group_id, now_unix())? {
        Some((stance, allow, deny)) => println!(
            "{} (allow votes: {allow}, deny votes: {deny})",
            crate::stance_str(stance)
        ),
        None => println!("ask (tie or no active votes)"),
    }
    for (voter, vote, counts) in store.policy_vote_breakdown_for(
        policy_id,
        entry_id,
        policy.sequence,
        group_id,
        now_unix(),
    )? {
        println!(
            "{}: {}{}",
            user_id_str(&voter),
            vote.as_ref()
                .map(|v| crate::stance_str(v.stance))
                .unwrap_or("no vote"),
            if counts { "" } else { " (not counting)" }
        );
    }
    Ok(())
}

pub fn ingest_policy_vote(store: &StateStore, file: &Path) -> Result<()> {
    ingest_policy_vote_bytes(store, &std::fs::read(file)?)
}

pub fn ingest_policy_vote_bytes(store: &StateStore, payload: &[u8]) -> Result<()> {
    let value: serde_json::Value = serde_json::from_slice(payload)?;
    let get = |key: &str| {
        value
            .get(key)
            .and_then(|v| v.as_str())
            .with_context(|| format!("missing {key}"))
    };
    let vote = PolicyVote {
        policy_id: parse_hash32(get("policy_id")?)?,
        entry_id: parse_hash32(get("entry_id")?)?,
        policy_sequence: value
            .get("policy_sequence")
            .and_then(|v| v.as_u64())
            .context("missing policy_sequence")?,
        group_id: crate::group::parse_group_id(get("group_id")?)?,
        voter: parse_user_ref(get("voter")?)?,
        sequence: value
            .get("sequence")
            .and_then(|v| v.as_u64())
            .context("missing sequence")?,
        stance: crate::parse_stance(get("stance")?)?,
        reason: Reason {
            code: crate::parse_reason_code(get("reason_code")?)?,
            note: value
                .get("reason_note")
                .and_then(|v| v.as_str())
                .map(str::to_owned),
            evidence: vec![],
        },
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
        crypto::contexts::POLICY_VOTE,
        &vote.signing_bytes(),
        &vote.signature,
    )
    .map_err(|_| anyhow::anyhow!("policy vote signature verification failed"))?;
    store.store_policy_vote(&vote)?;
    println!("ingested policy vote for {}", vote.entry_id);
    Ok(())
}
